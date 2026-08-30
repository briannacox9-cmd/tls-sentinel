import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import LocalTLSServer, write_certificate

from tls_sentinel.config import Endpoint, Thresholds
from tls_sentinel.scanner import TLSScanner


class ScannerIntegrationTests(unittest.TestCase):
    def test_real_local_tls_handshake_reports_certificate(self):
        with TemporaryDirectory() as directory:
            cert, key = write_certificate(Path(directory), "localhost", 20)
            with LocalTLSServer(cert, key) as server:
                result = TLSScanner(2).scan(Endpoint("local", "localhost", server.port, Thresholds()))
        self.assertIsNone(result.scan_error)
        self.assertTrue(result.hostname_valid)
        self.assertIn("localhost", result.sans)
        self.assertGreater(result.days_remaining or 0, 19)
        self.assertEqual(len(result.sha256_fingerprint or ""), 64)
        self.assertTrue(result.issuer)
        self.assertTrue(result.subject)
        self.assertTrue(result.serial_number)

    def test_hostname_mismatch_is_reported_without_losing_certificate(self):
        with TemporaryDirectory() as directory:
            cert, key = write_certificate(Path(directory), "wrong.local", 20)
            with LocalTLSServer(cert, key) as server:
                result = TLSScanner(2).scan(Endpoint("local", "localhost", server.port, Thresholds()))
        self.assertIsNone(result.scan_error)
        self.assertFalse(result.hostname_valid)
        self.assertIn("wrong.local", result.hostname_error or "")
        self.assertIsNotNone(result.expires_at)
