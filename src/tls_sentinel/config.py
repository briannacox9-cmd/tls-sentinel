from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Raised when configuration is unsafe or incomplete."""


@dataclass(frozen=True)
class Thresholds:
    warning_days: int = 30
    critical_days: int = 7
    unchanged_days: int = 14


@dataclass(frozen=True)
class Endpoint:
    name: str
    hostname: str
    port: int = 443
    thresholds: Thresholds = field(default_factory=Thresholds)


@dataclass(frozen=True)
class Config:
    endpoints: tuple[Endpoint, ...]
    timeout_seconds: float = 5.0
    history_file: Path = Path("./data/history.jsonl")
    webhook_url: str = ""
    webhook_timeout_seconds: float = 5.0
    listen: str = "0.0.0.0:8080"
    scan_interval_seconds: float = 300.0


def _duration(value: Any, field_name: str) -> float:
    if isinstance(value, (int, float)):
        seconds = float(value)
    elif isinstance(value, str):
        multipliers = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}
        suffix = next((item for item in multipliers if value.endswith(item)), None)
        try:
            seconds = float(value[: -len(suffix)]) * multipliers[suffix] if suffix else float(value)
        except ValueError as exc:
            raise ConfigError(f"{field_name} must be a duration such as 5s or 5m") from exc
    else:
        raise ConfigError(f"{field_name} must be a duration")
    if seconds <= 0:
        raise ConfigError(f"{field_name} must be greater than zero")
    return seconds


def _thresholds(raw: dict[str, Any] | None, base: Thresholds) -> Thresholds:
    raw = raw or {}
    result = Thresholds(
        warning_days=int(raw.get("warning_days", base.warning_days)),
        critical_days=int(raw.get("critical_days", base.critical_days)),
        unchanged_days=int(raw.get("unchanged_days", base.unchanged_days)),
    )
    if min(result.warning_days, result.critical_days, result.unchanged_days) < 0:
        raise ConfigError("thresholds cannot be negative")
    if result.critical_days > result.warning_days:
        raise ConfigError("critical_days must be less than or equal to warning_days")
    return result


def load(path: str | Path) -> Config:
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read configuration: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("configuration root must be a mapping")
    defaults = _thresholds(raw.get("defaults"), Thresholds())
    endpoint_rows = raw.get("endpoints")
    if not isinstance(endpoint_rows, list) or not endpoint_rows:
        raise ConfigError("at least one endpoint is required")
    endpoints: list[Endpoint] = []
    names: set[str] = set()
    for index, row in enumerate(endpoint_rows):
        if not isinstance(row, dict) or not row.get("hostname"):
            raise ConfigError(f"endpoints[{index}].hostname is required")
        hostname = str(row["hostname"]).strip()
        name = str(row.get("name") or hostname).strip()
        port = int(row.get("port", 443))
        if not 1 <= port <= 65535:
            raise ConfigError(f"endpoint {name!r} has an invalid port")
        if name in names:
            raise ConfigError(f"duplicate endpoint name {name!r}")
        names.add(name)
        endpoints.append(Endpoint(name, hostname, port, _thresholds(row.get("thresholds"), defaults)))
    webhook = raw.get("webhook") or {}
    server = raw.get("server") or {}
    return Config(
        endpoints=tuple(endpoints),
        timeout_seconds=_duration(raw.get("timeout", "5s"), "timeout"),
        history_file=Path(raw.get("history_file", "./data/history.jsonl")),
        webhook_url=str(webhook.get("url", "")),
        webhook_timeout_seconds=_duration(webhook.get("timeout", "5s"), "webhook.timeout"),
        listen=str(server.get("listen", "0.0.0.0:8080")),
        scan_interval_seconds=_duration(server.get("scan_interval", "5m"), "server.scan_interval"),
    )
