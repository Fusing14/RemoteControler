"""
Módulo de verificación criptográfica de firmas Ed25519.
Garantiza autenticidad e integridad de cada mensaje recibido antes de su despacho.
"""

import base64
from typing import Any, Dict
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from host.core.crypto.canonical import canonicalize
from host.core.crypto.exceptions import InvalidSignatureError


def load_public_key_from_raw_bytes(raw_bytes: bytes) -> ed25519.Ed25519PublicKey:
    """Carga una clave pública Ed25519 desde sus 32 bytes crudos."""
    if len(raw_bytes) != 32:
        raise ValueError(f"Longitud incorrecta para clave pública Ed25519: {len(raw_bytes)} bytes (se requieren 32)")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)


def verify_canonical_signature(
    public_key: ed25519.Ed25519PublicKey,
    data: Dict[str, Any],
    signature_b64: str
) -> None:
    """
    Verifica la firma Ed25519 contra el payload canonicalizado bajo RFC 8785.
    
    Mitigación de Vectores de Ataque:
    - Tampering: Impide cualquier alteración de valores o campos en tránsito.
    
    Lanza:
        InvalidSignatureError: Si la firma no coincide o está corrupta.
    """
    try:
        raw_signature = base64.b64decode(signature_b64, validate=True)
        if len(raw_signature) != 64:
            raise InvalidSignatureError("Longitud de firma inválida (debe ser de 64 bytes)")
    except Exception as e:
        raise InvalidSignatureError(f"Error al decodificar firma Base64: {e}") from e

    canonical_bytes = canonicalize(data)

    try:
        public_key.verify(raw_signature, canonical_bytes)
    except InvalidSignature as e:
        raise InvalidSignatureError("Firma Ed25519 inválida para el contenido canónico") from e
