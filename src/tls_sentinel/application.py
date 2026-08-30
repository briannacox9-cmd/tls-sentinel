from __future__ import annotations

import logging

from .alerts import evaluate, send_webhook
from .config import Config
from .history import HistoryStore
from .metrics import MetricsRegistry
from .models import AlertEvent, ScanResult
from .scanner import TLSScanner


class Application:
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.scanner = TLSScanner(config.timeout_seconds)
        self.history = HistoryStore(config.history_file)
        self.metrics = MetricsRegistry()

    def run_scan(self) -> tuple[list[ScanResult], list[AlertEvent]]:
        self.logger.info("scan_started", extra={"fields": {"endpoint_count": len(self.config.endpoints)}})
        results = self.scanner.scan_all(self.config.endpoints)
        results = self.history.apply_and_append(results, self.config.endpoints)
        self.metrics.update(results)
        events = evaluate(results, self.config.endpoints)
        try:
            send_webhook(self.config.webhook_url, self.config.webhook_timeout_seconds, events)
        except RuntimeError as exc:
            self.logger.error(
                "webhook_delivery_failed", extra={"fields": {"error": str(exc), "alert_count": len(events)}}
            )
        for result in results:
            self.logger.info(
                "endpoint_scanned",
                extra={
                    "fields": {
                        "name": result.name,
                        "hostname": result.hostname,
                        "days_remaining": result.days_remaining,
                        "hostname_valid": result.hostname_valid,
                        "fingerprint_changed": result.fingerprint_changed,
                        "scan_error": result.scan_error,
                    }
                },
            )
        self.logger.info(
            "scan_completed",
            extra={
                "fields": {
                    "endpoint_count": len(results),
                    "alert_count": len(events),
                    "failures": sum(bool(r.scan_error) for r in results),
                }
            },
        )
        return results, events
