"""
Módulo de Certificate Pinning / TOFU (Trust On First Use) con verificación de huella SHA-256 (CWE-295).
Genera y gestiona el certificado TLS autofirmado del Host y valida huellas criptográficas
en tiempo constante (hmac.compare_digest) para impedir ataques Man-in-the-Middle (MitM).
"""

import datetime
import hashlib
import hmac
import ipaddress
import logging
import re
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from host.core.storage.dpapi import protect_bytes, unprotect_bytes

logger = logging.getLogger("RemoteControler.TLSPinning")


class CertificatePinningError(Exception):
    """Excepción lanzada cuando la huella SHA-256 del certificado TLS no coincide."""
    pass


def normalize_fingerprint(fp: str) -> str:
    """Normaliza una huella SHA-256 eliminando separadores (':', espacios) y pasando a minúsculas."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", fp.strip()).lower()
    if len(cleaned) != 64:
        raise ValueError(f"Huella SHA-256 inválida (se esperaban 64 caracteres hex): {fp}")
    return cleaned


def compute_cert_sha256_fingerprint(cert_der_or_pem: bytes) -> str:
    """
    Calcula la huella SHA-256 (64 caracteres hex en minúsculas) de un certificado X.509
    en formato DER o PEM.
    """
    if not cert_der_or_pem:
        raise ValueError("El certificado no puede estar vacío.")

    if cert_der_or_pem.strip().startswith(b"-----BEGIN"):
        cert_obj = x509.load_pem_x509_certificate(cert_der_or_pem)
        der_bytes = cert_obj.public_bytes(serialization.Encoding.DER)
    else:
        der_bytes = bytes(cert_der_or_pem)

    return hashlib.sha256(der_bytes).hexdigest().lower()


def verify_certificate_fingerprint(
    presented_cert_or_fingerprint: bytes | str,
    expected_fingerprint: str,
) -> bool:
    """
    Verifica en tiempo constante (CWE-208 / CWE-295) si el certificado presentado
    coincide exactamente con la huella SHA-256 fijada (Pinned Fingerprint).
    """
    if not expected_fingerprint or not presented_cert_or_fingerprint:
        return False

    try:
        clean_expected = normalize_fingerprint(expected_fingerprint)
        if isinstance(presented_cert_or_fingerprint, (bytes, bytearray)):
            actual_fp = compute_cert_sha256_fingerprint(bytes(presented_cert_or_fingerprint))
        else:
            actual_fp = normalize_fingerprint(str(presented_cert_or_fingerprint))

        return hmac.compare_digest(actual_fp.encode("ascii"), clean_expected.encode("ascii"))
    except Exception as e:
        logger.warning("Fallo en validación de Certificate Pinning: %s", e)
        return False


def ensure_host_tls_certificate(
    vault_dir: Path,
    host_device_id: str = "securedeck_host",
    secondary_entropy: Optional[bytes] = None,
) -> Tuple[Path, bytes, str]:
    """
    Asegura que el Host cuente con un certificado X.509 autofirmado persistido en `vault_dir`.
    La clave privada del certificado se almacena cifrada con Windows DPAPI.
    Retorna (cert_pem_path, cert_der_bytes, cert_sha256_fingerprint).
    """
    vault_dir.mkdir(parents=True, exist_ok=True)
    cert_pem_path = vault_dir / "host_tls_cert.pem"
    key_dpapi_path = vault_dir / "host_tls_key.dat"

    if cert_pem_path.exists() and key_dpapi_path.exists():
        try:
            pem_bytes = cert_pem_path.read_bytes()
            cert_obj = x509.load_pem_x509_certificate(pem_bytes)
            der_bytes = cert_obj.public_bytes(serialization.Encoding.DER)
            fp = compute_cert_sha256_fingerprint(der_bytes)
            return cert_pem_path, der_bytes, fp
        except Exception as e:
            logger.warning("Regenerando certificado TLS del Host tras error de lectura: %s", e)

    # Generar nuevo certificado X.509 autofirmado válido por 10 años
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureDeck Zero-Trust Host"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"securedeck-{host_device_id[:16]}"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    encrypted_priv = protect_bytes(priv_pem, optional_entropy=secondary_entropy, description="SecureDeck Host TLS Key")
    cert_pem_path.write_bytes(cert_pem)
    key_dpapi_path.write_bytes(encrypted_priv)

    fingerprint = compute_cert_sha256_fingerprint(cert_der)
    return cert_pem_path, cert_der, fingerprint
