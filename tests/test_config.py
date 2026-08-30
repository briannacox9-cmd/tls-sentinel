import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tls_sentinel.config import ConfigError, load


class ConfigTests(unittest.TestCase):
    def test_defaults_and_overrides(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text("""
defaults:
  warning_days: 40
  critical_days: 9
endpoints:
  - name: local
    hostname: localhost
    port: 8443
    thresholds:
      warning_days: 20
""")
            config = load(path)
        self.assertEqual(config.endpoints[0].thresholds.warning_days, 20)
        self.assertEqual(config.endpoints[0].thresholds.critical_days, 9)
        self.assertEqual(config.timeout_seconds, 5)

    def test_rejects_duplicate_names(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text("endpoints:\n  - {name: same, hostname: one}\n  - {name: same, hostname: two}\n")
            with self.assertRaisesRegex(ConfigError, "duplicate"):
                load(path)
