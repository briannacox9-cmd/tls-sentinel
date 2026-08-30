from __future__ import annotations

import threading

from .models import ScanResult


def _escape(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"') + '"'


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._results: list[ScanResult] = []
        self._changes: dict[str, int] = {}

    @property
    def ready(self) -> bool:
        with self._lock:
            return bool(self._results)

    def update(self, results: list[ScanResult]) -> None:
        with self._lock:
            self._results = list(results)
            for result in results:
                if result.fingerprint_changed:
                    self._changes[result.name] = self._changes.get(result.name, 0) + 1

    def render(self) -> str:
        with self._lock:
            results = list(self._results)
            changes = dict(self._changes)
        lines = [
            "# HELP tls_sentinel_scan_success Whether the latest TLS scan succeeded.",
            "# TYPE tls_sentinel_scan_success gauge",
            "# HELP tls_sentinel_hostname_valid Whether the certificate matches the configured hostname.",
            "# TYPE tls_sentinel_hostname_valid gauge",
            "# HELP tls_sentinel_certificate_days_remaining Days until the leaf certificate expires.",
            "# TYPE tls_sentinel_certificate_days_remaining gauge",
            "# HELP tls_sentinel_certificate_expiry_timestamp_seconds Leaf certificate expiration as a Unix timestamp.",
            "# TYPE tls_sentinel_certificate_expiry_timestamp_seconds gauge",
            "# HELP tls_sentinel_certificate_changes_total Fingerprint changes observed by this process.",
            "# TYPE tls_sentinel_certificate_changes_total counter",
            "# HELP tls_sentinel_certificate_fingerprint_info Latest leaf certificate SHA-256 fingerprint.",
            "# TYPE tls_sentinel_certificate_fingerprint_info gauge",
        ]
        for result in results:
            labels = f"name={_escape(result.name)},hostname={_escape(result.hostname)},port={_escape(str(result.port))}"
            lines.append(f"tls_sentinel_scan_success{{{labels}}} {0 if result.scan_error else 1}")
            lines.append(f"tls_sentinel_hostname_valid{{{labels}}} {1 if result.hostname_valid else 0}")
            if not result.scan_error and result.days_remaining is not None and result.expires_at:
                from datetime import datetime

                expiry = datetime.fromisoformat(result.expires_at).timestamp()
                lines.append(f"tls_sentinel_certificate_days_remaining{{{labels}}} {result.days_remaining:.6f}")
                lines.append(f"tls_sentinel_certificate_expiry_timestamp_seconds{{{labels}}} {expiry:.0f}")
                fingerprint = _escape(result.sha256_fingerprint or "")
                lines.append(f"tls_sentinel_certificate_fingerprint_info{{{labels},fingerprint={fingerprint}}} 1")
            lines.append(f"tls_sentinel_certificate_changes_total{{{labels}}} {changes.get(result.name, 0)}")
        return "\n".join(lines) + "\n"
