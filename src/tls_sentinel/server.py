from __future__ import annotations

import json
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .application import Application


class SentinelHTTPServer(ThreadingHTTPServer):
    """HTTP server that avoids a reverse-DNS lookup while binding."""

    daemon_threads = True

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


def _split_listen(value: str) -> tuple[str, int]:
    try:
        host, raw_port = value.rsplit(":", 1)
        return host, int(raw_port)
    except ValueError as exc:
        raise ValueError("server.listen must use host:port format") from exc


def make_handler(application: Application) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._json(200, {"status": "ok"})
            elif self.path == "/readyz":
                self._json(
                    200 if application.metrics.ready else 503,
                    {"status": "ready" if application.metrics.ready else "not_ready"},
                )
            elif self.path == "/metrics":
                body = application.metrics.render().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._json(404, {"error": "not_found"})

        def _json(self, status: int, payload: dict[str, str]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            application.logger.info(
                "http_request", extra={"fields": {"client": self.client_address[0], "request": format % args}}
            )

    return Handler


def serve(application: Application, stop: threading.Event) -> None:
    application.run_scan()
    address = _split_listen(application.config.listen)
    httpd = SentinelHTTPServer(address, make_handler(application))
    httpd.timeout = 0.5
    application.logger.info("http_server_started", extra={"fields": {"listen": application.config.listen}})

    def scans() -> None:
        while not stop.wait(application.config.scan_interval_seconds):
            try:
                application.run_scan()
            except Exception:
                application.logger.exception("scheduled_scan_failed")

    scan_thread = threading.Thread(target=scans, name="scan-scheduler", daemon=True)
    scan_thread.start()
    try:
        while not stop.is_set():
            httpd.handle_request()
    finally:
        httpd.server_close()
        stop.set()
        scan_thread.join(timeout=2)
