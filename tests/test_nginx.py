"""Isolated nginx integration tests. Supply NGINX_BINARY and JA4_MODULE paths."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest

from test_ja4 import ParserHarness
import tls_support
from tls_support import TLSClient, free_port


class NginxTests(ParserHarness):
    context = tls_support.TLSChecks.context
    test_sni_and_no_sni = tls_support.TLSChecks.test_sni_and_no_sni
    test_session_resumption = tls_support.TLSChecks.test_session_resumption
    test_hello_retry_request_keeps_initial_fingerprint = tls_support.TLSChecks.test_hello_retry_request_keeps_initial_fingerprint
    test_http2_multiple_streams = tls_support.TLSChecks.test_http2_multiple_streams

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        (root / 'logs').mkdir()
        cls.port, cls.plain_port = free_port(), free_port()
        cls.have_h2 = importlib.util.find_spec('h2') is not None
        binary = str(Path(os.environ['NGINX_BINARY']).resolve())
        module = str(Path(os.environ['JA4_MODULE']).resolve())
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                        '-nodes', '-keyout', str(root / 'key.pem'),
                        '-out', str(root / 'cert.pem'), '-days', '1',
                        '-subj', '/CN=localhost'], check=True, capture_output=True)
        servers = ''
        for name, extra, label in [('localhost', '', 'first'),
                                    ('second.local', '', 'second'),
                                    ('hrr.local', 'ssl_ecdh_curve P-256;', 'hrr')]:
            servers += f'''
            server {{
                listen 127.0.0.1:{cls.port} ssl;
                http2 on;
                server_name {name};
                ssl_certificate "{root}/cert.pem";
                ssl_certificate_key "{root}/key.pem";
                ssl_protocols TLSv1.2 TLSv1.3;
                ssl_session_cache shared:ja4:1m;
                {extra}
                add_header X-JA4 $ja4;
                add_header X-JA4-RAW $ja4_raw;
                add_header X-Vhost {label};
                location / {{ return 200 "ok\\n"; }}
            }}
            '''
        (root / 'nginx.conf').write_text(f'''
            load_module "{module}";
            daemon off;
            master_process off;
            pid "{root}/nginx.pid";
            error_log "{root}/error.log" info;
            events {{ worker_connections 64; }}
            http {{
                access_log off;
                # Group selection uses the default SSL context before SNI.
                ssl_ecdh_curve P-256;
                {servers}
                server {{
                    listen 127.0.0.1:{cls.plain_port};
                    add_header X-JA4 "[$ja4]";
                    add_header X-JA4-RAW "[$ja4_raw]";
                    return 200 "ok\\n";
                }}
            }}
        ''')
        cls.process = subprocess.Popen([binary, '-p', str(root), '-c',
                                        str(root / 'nginx.conf')])
        cls.addClassCleanup(cls.stop)
        for _ in range(100):
            if cls.process.poll() is not None:
                raise RuntimeError('nginx exited during startup; see stderr')
            try:
                with socket.create_connection(('127.0.0.1', cls.plain_port), timeout=.1):
                    return
            except OSError:
                time.sleep(.05)
        raise RuntimeError('nginx did not start')

    @classmethod
    def stop(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)

    def test_https_and_keepalive(self):
        import ssl
        for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
            client = TLSClient(self.context(version), self.port)
            try:
                expected = self.compute(client.client_hello())
                for _ in range(2):
                    status, headers, body = client.request()
                    self.assertIn('200', status)
                    self.assertEqual(body, b'ok\n')
                    self.assertEqual((headers['x-ja4'], headers['x-ja4-raw']), expected)
            finally:
                client.close()

    def test_plain_http_has_no_fingerprint(self):
        with socket.create_connection(('127.0.0.1', self.plain_port), timeout=5) as s:
            s.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\nJA4: forged\r\n\r\n')
            response = b''
            while data := s.recv(65536):
                response += data
        self.assertIn(b'X-JA4: []', response)
        self.assertIn(b'X-JA4-RAW: []', response)


if __name__ == '__main__':
    unittest.main()
