import json
import logging
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler

from tls_sentinel.alerts import send_webhook
from tls_sentinel.application import Application
from tls_sentinel.config import Config, Endpoint
from tls_sentinel.metrics import MetricsRegistry
from tls_sentinel.models import AlertEvent, ScanResult
from tls_sentinel.server import SentinelHTTPServer, make_handler


class WebhookHandler(BaseHTTPRequestHandler):
    payload = None

    def do_POST(self):
        type(self).payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_):
        pass


class SurfaceTests(unittest.TestCase):
    def test_generic_webhook_payload(self):
        server = SentinelHTTPServer(("127.0.0.1", 0), WebhookHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        event = AlertEvent("scan_failed", "critical", "failed", "api", "now", {})
        try:
            send_webhook(f"http://127.0.0.1:{server.server_port}/hook", 2, [event])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(WebhookHandler.payload["source"], "tls-sentinel")
        self.assertEqual(WebhookHandler.payload["events"][0]["type"], "scan_failed")

    def test_prometheus_and_health_surface(self):
        metrics = MetricsRegistry()
        metrics.update(
            [
                ScanResult(
                    "api",
                    "localhost",
                    443,
                    "2026-01-01T00:00:00+00:00",
                    expires_at="2026-02-01T00:00:00+00:00",
                    days_remaining=31,
                    sha256_fingerprint="abc",
                    hostname_valid=True,
                )
            ]
        )
        self.assertIn('tls_sentinel_scan_success{name="api"', metrics.render())
        app = Application(Config((Endpoint("api", "localhost"),)), logging.getLogger("test"))
        app.metrics = metrics
        server = SentinelHTTPServer(("127.0.0.1", 0), make_handler(app))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/readyz") as response:
                self.assertEqual(json.load(response)["status"], "ready")
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/metrics") as response:
                self.assertIn(b"tls_sentinel_certificate_days_remaining", response.read())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
