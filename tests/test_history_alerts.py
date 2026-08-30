import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tls_sentinel.alerts import evaluate
from tls_sentinel.config import Endpoint, Thresholds
from tls_sentinel.history import HistoryStore
from tls_sentinel.models import ScanResult


def result(fingerprint: str, days: float = 5, **changes) -> ScanResult:
    values = dict(
        name="api",
        hostname="localhost",
        port=443,
        scanned_at="2026-01-01T00:00:00+00:00",
        expires_at="2026-01-06T00:00:00+00:00",
        days_remaining=days,
        sha256_fingerprint=fingerprint,
        hostname_valid=True,
    )
    values.update(changes)
    return ScanResult(**values)


class HistoryAlertTests(unittest.TestCase):
    def test_detects_change_and_unchanged_near_expiration(self):
        endpoint = Endpoint("api", "localhost", 443, Thresholds(30, 7, 14))
        with TemporaryDirectory() as directory:
            store = HistoryStore(Path(directory) / "history.jsonl")
            store.apply_and_append([result("aaa")], (endpoint,))
            unchanged = store.apply_and_append([result("aaa")], (endpoint,))[0]
            changed = store.apply_and_append([result("bbb")], (endpoint,))[0]
        self.assertTrue(unchanged.unchanged_near_expiry)
        self.assertFalse(unchanged.fingerprint_changed)
        self.assertTrue(changed.fingerprint_changed)
        self.assertFalse(changed.unchanged_near_expiry)

    def test_alerts_cover_failures_hostname_expiry_and_unchanged(self):
        endpoint = Endpoint("api", "localhost", 443, Thresholds(30, 7, 14))
        expiring = result("aaa", hostname_valid=False, hostname_error="mismatch", unchanged_near_expiry=True)
        failed = result("", scan_error="connection refused", days_remaining=None)
        types = [event.type for event in evaluate([expiring, failed], (endpoint,))]
        self.assertEqual(types.count("hostname_invalid"), 1)
        self.assertEqual(types.count("certificate_expiring"), 1)
        self.assertEqual(types.count("certificate_unchanged"), 1)
        self.assertEqual(types.count("scan_failed"), 1)
