from __future__ import annotations

import json
import urllib.error
import urllib.request

from .config import Endpoint
from .models import AlertEvent, ScanResult


def evaluate(results: list[ScanResult], endpoints: tuple[Endpoint, ...]) -> list[AlertEvent]:
    configured = {endpoint.name: endpoint for endpoint in endpoints}
    events: list[AlertEvent] = []
    for result in results:
        if result.scan_error:
            events.append(_event(result, "scan_failed", "critical", result.scan_error))
            continue
        if not result.hostname_valid:
            events.append(
                _event(result, "hostname_invalid", "critical", result.hostname_error or "hostname validation failed")
            )
        assert result.days_remaining is not None
        threshold = configured[result.name].thresholds
        if result.days_remaining <= threshold.critical_days:
            events.append(
                _event(
                    result,
                    "certificate_expiring",
                    "critical",
                    f"certificate has {result.days_remaining:.1f} days remaining",
                )
            )
        elif result.days_remaining <= threshold.warning_days:
            events.append(
                _event(
                    result,
                    "certificate_expiring",
                    "warning",
                    f"certificate has {result.days_remaining:.1f} days remaining",
                )
            )
        if result.unchanged_near_expiry:
            events.append(
                _event(
                    result,
                    "certificate_unchanged",
                    "warning",
                    "certificate fingerprint remains unchanged near expiration",
                )
            )
    return events


def _event(result: ScanResult, kind: str, severity: str, message: str) -> AlertEvent:
    return AlertEvent(kind, severity, message, result.name, result.scanned_at, result.to_dict())


def send_webhook(url: str, timeout_seconds: float, events: list[AlertEvent]) -> None:
    if not url or not events:
        return
    payload = json.dumps({"source": "tls-sentinel", "events": [event.to_dict() for event in events]}).encode()
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "tls-sentinel/0.1"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"webhook returned HTTP {response.status}")
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"webhook delivery failed: {exc}") from exc
