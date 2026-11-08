"""Shared TLS client and protocol checks for nginx integration tests."""

import socket
import ssl

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

class TLSClient:
    def __init__(self, context, port, session=None, hostname='localhost'):
        self.socket = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing,
                                   server_hostname=hostname, session=session)
        self.wire = bytearray()
        while True:
            try:
                self.tls.do_handshake()
                self.flush()
                break
            except ssl.SSLWantReadError:
                self.flush()
                self.receive()

    def flush(self):
        data = self.outgoing.read()
        self.wire.extend(data)
        self.socket.sendall(data)

    def receive(self):
        data = self.socket.recv(65536)
        if not data:
            raise EOFError('Server closed the connection')
        self.incoming.write(data)

    def write(self, data):
        self.tls.write(data)
        self.flush()

    def read(self):
        while True:
            try:
                data = self.tls.read(65536)
                self.flush()
                return data
            except ssl.SSLWantReadError:
                self.flush()
                self.receive()

    def client_hello(self):
        wire = bytes(self.wire)
        handshake = b''
        while len(wire) >= 5:
            n = int.from_bytes(wire[3:5], 'big')
            if wire[0] == 22:
                handshake += wire[5:5+n]
                if len(handshake) >= 4:
                    size = 4 + int.from_bytes(handshake[1:4], 'big')
                    if len(handshake) >= size:
                        return handshake[:size]
            wire = wire[5+n:]
        raise AssertionError('No complete ClientHello sent')

    def request(self, host='localhost'):
        self.write(f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n'.encode())
        response = b''
        while b'\r\n\r\n' not in response:
            response += self.read()
        head, body = response.split(b'\r\n\r\n', 1)
        lines = head.decode().split('\r\n')
        headers = dict(line.lower().split(': ', 1) for line in lines[1:])
        while len(body) < int(headers['content-length']):
            body += self.read()
        return lines[0], headers, body

    def close(self):
        self.socket.close()

class TLSChecks:
    def context(self, version=None, alpn=('http/1.1',)):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(list(alpn))
            if version:
                ctx.minimum_version = ctx.maximum_version = version
            return ctx

    def test_sni_and_no_sni(self):
            for hostname, flag in [('second.local', 'd'), (None, 'i')]:
                client = TLSClient(self.context(), self.port, hostname=hostname)
                try:
                    _, headers, _ = client.request(host=hostname or 'localhost')
                    self.assertEqual(headers['x-ja4'][3], flag)
                    if hostname:
                        self.assertEqual(headers['x-vhost'], 'second')
                finally:
                    client.close()

    def test_session_resumption(self):
            context = self.context(ssl.TLSVersion.TLSv1_2)
            client = TLSClient(context, self.port)
            try:
                client.request()
                session = client.tls.session
            finally:
                client.close()
            client = TLSClient(context, self.port, session=session)
            try:
                self.assertTrue(client.tls.session_reused)
                _, headers, _ = client.request()
                self.assertEqual(headers['x-ja4'], self.compute(client.client_hello())[0])
            finally:
                client.close()

    def test_hello_retry_request_keeps_initial_fingerprint(self):
            client = TLSClient(self.context(ssl.TLSVersion.TLSv1_3), self.port, hostname='hrr.local')
            try:
                wire = bytes(client.wire)
                hellos = []
                while len(wire) >= 5:
                    n = int.from_bytes(wire[3:5], 'big')
                    if wire[0] == 22 and wire[5] == 1:
                        hellos.append(wire[5:5+n])
                    wire = wire[5+n:]
                self.assertEqual(len(hellos), 2, 'Server must trigger HelloRetryRequest')
                _, headers, _ = client.request(host='hrr.local')
                self.assertEqual(headers['x-ja4'], self.compute(hellos[0])[0])
                self.assertEqual(headers['x-ja4-raw'], self.compute(hellos[0])[1])
            finally:
                client.close()

    def test_http2_multiple_streams(self):
            if not self.have_h2:
                self.skipTest('Python h2 required')
            from h2.connection import H2Connection
            from h2.events import ResponseReceived, StreamEnded
            client = TLSClient(self.context(alpn=['h2', 'http/1.1']), self.port)
            try:
                self.assertEqual(client.tls.selected_alpn_protocol(), 'h2')
                expected = self.compute(client.client_hello())
                h2 = H2Connection()
                h2.initiate_connection()
                for stream in [1, 3]:
                    h2.send_headers(stream, [(':method', 'GET'), (':scheme', 'https'),
                                            (':authority', 'localhost'), (':path', '/')], end_stream=True)
                client.write(h2.data_to_send())
                ended, received = set(), set()
                while len(ended) < 2:
                    for event in h2.receive_data(client.read()):
                        if isinstance(event, ResponseReceived):
                            headers = dict(event.headers)
                            self.assertEqual(headers[b':status'], b'200')
                            self.assertEqual(headers[b'x-ja4'].decode(), expected[0])
                            self.assertEqual(headers[b'x-ja4-raw'].decode(), expected[1])
                            received.add(event.stream_id)
                        elif isinstance(event, StreamEnded):
                            ended.add(event.stream_id)
                    pending = h2.data_to_send()
                    if pending:
                        client.write(pending)
                self.assertEqual(received, {1, 3})
            finally:
                client.close()
