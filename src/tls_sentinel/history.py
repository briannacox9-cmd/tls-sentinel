from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .config import Endpoint
from .models import ScanResult


class HistoryError(RuntimeError):
    pass


class HistoryStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def apply_and_append(self, results: list[ScanResult], endpoints: tuple[Endpoint, ...]) -> list[ScanResult]:
        with self._lock:
            latest = self._load_latest()
            thresholds = {endpoint.name: endpoint.thresholds for endpoint in endpoints}
            for result in results:
                previous = latest.get(result.name)
                if previous and result.sha256_fingerprint and previous.get("sha256_fingerprint"):
                    result.fingerprint_changed = previous["sha256_fingerprint"] != result.sha256_fingerprint
                    result.unchanged_near_expiry = (
                        not result.fingerprint_changed
                        and result.days_remaining is not None
                        and result.days_remaining <= thresholds[result.name].unchanged_days
                    )
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
                descriptor = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
                with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
                    for result in results:
                        stream.write(json.dumps(result.to_dict(), separators=(",", ":")) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as exc:
                raise HistoryError(f"cannot persist scan history: {exc}") from exc
        return results

    def _load_latest(self) -> dict[str, dict]:
        latest: dict[str, dict] = {}
        try:
            with self.path.open(encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, 1):
                    try:
                        row = json.loads(line)
                        latest[row["name"]] = row
                    except (json.JSONDecodeError, KeyError) as exc:
                        raise HistoryError(f"invalid history record on line {line_number}: {exc}") from exc
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise HistoryError(f"cannot read scan history: {exc}") from exc
        return latest
