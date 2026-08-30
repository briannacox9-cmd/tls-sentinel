from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ScanResult:
    name: str
    hostname: str
    port: int
    scanned_at: str
    expires_at: str | None = None
    days_remaining: float | None = None
    issuer: str | None = None
    subject: str | None = None
    sans: list[str] = field(default_factory=list)
    serial_number: str | None = None
    sha256_fingerprint: str | None = None
    hostname_valid: bool = False
    hostname_error: str | None = None
    scan_error: str | None = None
    fingerprint_changed: bool = False
    unchanged_near_expiry: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AlertEvent:
    type: str
    severity: str
    message: str
    endpoint: str
    observed_at: str
    result: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
