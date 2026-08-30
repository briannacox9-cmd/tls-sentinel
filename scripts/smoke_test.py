#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from helpers import LocalTLSServer, write_certificate  # noqa: E402


def main() -> int:
    executable = Path(sys.executable).parent / "tls-sentinel"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        cert, key = write_certificate(root, "localhost", 20)
        with LocalTLSServer(cert, key) as tls_server:
            config = root / "config.yaml"
            config.write_text(f"""
history_file: {root / "history.jsonl"}
server:
  listen: 127.0.0.1:18080
  scan_interval: 1h
endpoints:
  - name: local-smoke
    hostname: localhost
    port: {tls_server.port}
""")
            scan = subprocess.run(
                [str(executable), "scan", "--config", str(config), "--json"], text=True, capture_output=True, timeout=10
            )
            if scan.returncode != 0:
                raise RuntimeError(scan.stderr)
            payload = json.loads(scan.stdout)
            assert payload["results"][0]["hostname_valid"] is True
            service = subprocess.Popen(
                [str(executable), "serve", "--config", str(config)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                for _ in range(30):
                    try:
                        with urllib.request.urlopen("http://127.0.0.1:18080/metrics", timeout=1) as response:
                            body = response.read().decode()
                        break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("HTTP surface did not become ready")
                assert "tls_sentinel_scan_success" in body
                with urllib.request.urlopen("http://127.0.0.1:18080/readyz", timeout=1) as response:
                    assert json.load(response)["status"] == "ready"
            finally:
                service.terminate()
                service.wait(timeout=5)
    print("smoke test passed: local TLS scan, history, readiness, and metrics")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
