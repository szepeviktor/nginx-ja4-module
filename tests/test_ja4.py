"""Known JA4 spec vector, edge cases and malformed ClientHello coverage."""
import ctypes
import hashlib
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


def word(n):
    return struct.pack('!H', n)


def words(items):
    return b''.join(word(x) for x in items)


def vec(data, width=2):
    return len(data).to_bytes(width, 'big') + data


def hello(ciphers=(0x1301,), extensions=(), version=0x0303):
    body = word(version) + bytes(32) + b'\x00'
    body += vec(words(ciphers)) + b'\x01\x00'
    if extensions is not None:
        body += vec(b''.join(word(n) + vec(data) for n, data in extensions))
    return b'\x01' + len(body).to_bytes(3, 'big') + body


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


class Result(ctypes.Structure):
    _fields_ = [('fingerprint', ctypes.c_char * 37), ('raw', ctypes.c_void_p)]


class ParserHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        lib = Path(cls.temp.name) / 'ja4.so'
        subprocess.run([os.environ.get('CC', 'cc'), '-shared', '-fPIC',
                        '-Wall', '-Wextra', '-Werror', '-O2', str(ROOT / 'ja4.c'),
                        '-lcrypto', '-o', str(lib)], check=True)
        cls.lib = ctypes.CDLL(str(lib))
        cls.lib.ja4_compute.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.POINTER(Result)]
        cls.lib.ja4_compute.restype = ctypes.c_int
        cls.libc = ctypes.CDLL(None)
        cls.libc.free.argtypes = [ctypes.c_void_p]

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def compute(self, data):
        result = Result()
        if not self.lib.ja4_compute(data, len(data), ctypes.byref(result)):
            return None
        try:
            return result.fingerprint.decode(), ctypes.string_at(result.raw).decode()
        finally:
            self.libc.free(result.raw)


class ParserTests(ParserHarness):
    def test_published_spec_vector(self):
        # FoxIO technical_details/JA4.md, full worked example.
        ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                   0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
        types = [0x001b, 0, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
                 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015]
        sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
        values = {43: vec(words([0x0304, 0x0303]), 1),
                  16: vec(vec(b'h2', 1)), 13: vec(words(sigs))}
        exts = [(n, values.get(n, b'')) for n in types]
        result = self.compute(hello(ciphers, exts))
        self.assertEqual(result[0], 't13d1516h2_8daaf6152771_e5627efa2ab1')
        self.assertTrue(result[1].endswith('_0403,0804,0401,0503,0805,0501,0806,0601'))
        # GREASE and extension/cipher permutations must not change the result.
        self.assertEqual(self.compute(hello([0x0a0a] + ciphers[::-1],
                         [(0x1a1a, b'')] + exts[::-1])), result)

    def test_signature_order_is_preserved(self):
        a = self.compute(hello(extensions=[(13, vec(words([0x0804, 0x0403])))]))
        b = self.compute(hello(extensions=[(13, vec(words([0x0403, 0x0804])))]))
        self.assertNotEqual(a[0], b[0])
        self.assertEqual(a[0].split('_')[2], digest('000d_0804,0403'))

    def test_alpn(self):
        for protocol, expected in [(b'http/1.1', 'h1'), (b'h2', 'h2'), (b'x', 'xx'),
                                   (b'\xab\xcd', 'ad'), (b'0\xab\xcd1', '01'), (b'', '00')]:
            with self.subTest(protocol=protocol):
                result = self.compute(hello(extensions=[(16, vec(vec(protocol, 1)))]))
                self.assertEqual(result[0][8:10], expected)
                self.assertTrue(result[0].endswith('_000000000000'))

    def test_legacy_versions_and_absent_extensions(self):
        for version, expected in [(0x0301, '10'), (0x0302, '11'), (0x0303, '12'),
                                   (0x0300, 's3'), (0x9999, '00')]:
            self.assertTrue(self.compute(hello(version=version, extensions=None))[0]
                            .startswith('t' + expected + 'i010000'))
        self.assertEqual(self.compute(hello(ciphers=[0x0a0a], extensions=[]))[0],
                         't12i000000_000000000000_000000000000')

    def test_counts_saturate(self):
        data = hello(ciphers=list(range(100)), extensions=[(n + 100, b'') for n in range(100)])
        self.assertEqual(self.compute(data)[0][4:8], '9999')

    def test_malformed(self):
        valid = hello(extensions=[(43, vec(words([0x0304]), 1))])
        for n in range(len(valid)):
            self.assertIsNone(self.compute(valid[:n]))
        for exts in [[(13, b'\x00\x03abc')], [(43, b'\x03abc')],
                     [(16, b'\x00\x02\x03a')], [(13, b''), (13, b'')]]:
            self.assertIsNone(self.compute(hello(extensions=exts)))
        self.assertIsNone(self.compute(valid + b'\x00'))

    def test_random_inputs(self):
        rng = random.Random(413)
        for _ in range(4000):
            n = rng.randrange(4, 512)
            data = b'\x01' + (n - 4).to_bytes(3, 'big') + rng.randbytes(n - 4)
            self.compute(data)


if __name__ == '__main__':
    unittest.main()
