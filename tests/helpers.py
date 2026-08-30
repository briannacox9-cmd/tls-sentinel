from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def write_certificate(directory: Path, hostname: str = "localhost", days: int = 20) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(UTC)
    san_names: list[x509.GeneralName] = [x509.DNSName(hostname)]
    if hostname == "localhost":
        san_names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
    )
    return cert_path, key_path


class LocalTLSServer:
    def __init__(self, cert_path: Path, key_path: Path):
        self.cert_path, self.key_path = cert_path, key_path
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=2)

    def _run(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_path, self.key_path)
        while not self.stop.is_set():
            try:
                connection, _ = self.socket.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with context.wrap_socket(connection, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass
