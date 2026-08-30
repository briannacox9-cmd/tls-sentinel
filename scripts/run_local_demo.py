#!/usr/bin/env python3
"""Run TLS Sentinel against an ephemeral local TLS endpoint for interactive viewing."""

from __future__ import annotations

import signal
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from helpers import LocalTLSServer, write_certificate  # noqa: E402

from tls_sentinel.application import Application  # noqa: E402
from tls_sentinel.config import Config, Endpoint, Thresholds  # noqa: E402
from tls_sentinel.logging import configure  # noqa: E402
from tls_sentinel.server import serve  # noqa: E402


def main() -> int:
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        cert, key = write_certificate(root, "localhost", 20)
        with LocalTLSServer(cert, key) as tls_server:
            config = Config(
                endpoints=(Endpoint("local-demo", "localhost", tls_server.port, Thresholds()),),
                history_file=root / "history.jsonl",
                listen="127.0.0.1:8080",
                scan_interval_seconds=30,
            )
            print("TLS Sentinel demo: http://127.0.0.1:8080/metrics", flush=True)
            serve(Application(config, configure()), stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
