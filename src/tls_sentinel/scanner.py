from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from .config import Endpoint
from .models import ScanResult


class TLSScanner:
    def __init__(self, timeout_seconds: float = 5.0, now: Callable[[], datetime] | None = None):
        self.timeout_seconds = timeout_seconds
        self.now = now or (lambda: datetime.now(UTC))

    def scan_all(self, endpoints: tuple[Endpoint, ...]) -> list[ScanResult]:
        workers = min(len(endpoints), 32)
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tls-scan") as pool:
            futures = {pool.submit(self.scan, endpoint): endpoint for endpoint in endpoints}
            results = [future.result() for future in as_completed(futures)]
        return sorted(results, key=lambda result: result.name)

    def scan(self, endpoint: Endpoint) -> ScanResult:
        observed = self.now().astimezone(UTC)
        result = ScanResult(endpoint.name, endpoint.hostname, endpoint.port, observed.isoformat())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((endpoint.hostname, endpoint.port), timeout=self.timeout_seconds) as raw:
                with context.wrap_socket(raw, server_hostname=endpoint.hostname) as tls_socket:
                    der = tls_socket.getpeercert(binary_form=True)
            if not der:
                raise ssl.SSLError("server returned no peer certificate")
            cert = x509.load_der_x509_certificate(der)
            expires = cert.not_valid_after_utc
            result.expires_at = expires.isoformat()
            result.days_remaining = (expires - observed).total_seconds() / 86400
            result.issuer = cert.issuer.rfc4514_string()
            result.subject = cert.subject.rfc4514_string()
            result.sans = _dns_sans(cert)
            result.serial_number = format(cert.serial_number, "x")
            result.sha256_fingerprint = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
            result.hostname_valid, result.hostname_error = _verify_hostname(cert, endpoint.hostname)
        except (OSError, ssl.SSLError, ValueError) as exc:
            result.scan_error = f"{type(exc).__name__}: {exc}"
        return result


def _dns_sans(cert: x509.Certificate) -> list[str]:
    try:
        return cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName
        )
    except x509.ExtensionNotFound:
        return []


def _verify_hostname(cert: x509.Certificate, hostname: str) -> tuple[bool, str | None]:
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if ip is not None:
            candidates = san.get_values_for_type(x509.IPAddress)
            valid = ip in candidates
        else:
            candidates = san.get_values_for_type(x509.DNSName)
            valid = any(_dns_matches(hostname, pattern) for pattern in candidates)
    except x509.ExtensionNotFound:
        candidates = [attribute.value for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        valid = ip is None and any(_dns_matches(hostname, pattern) for pattern in candidates)
    if valid:
        return True, None
    return (
        False,
        f"certificate is not valid for {hostname!r}; presented names: {', '.join(map(str, candidates)) or 'none'}",
    )


def _dns_matches(hostname: str, pattern: str) -> bool:
    host = hostname.rstrip(".").lower().encode("idna").decode("ascii")
    candidate = pattern.rstrip(".").lower().encode("idna").decode("ascii")
    if candidate.startswith("*."):
        return host.count(".") == candidate.count(".") and host.endswith(candidate[1:])
    return host == candidate
