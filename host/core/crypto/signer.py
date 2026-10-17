"""
Módulo de generación de claves y firma criptográfica Ed25519.
Utiliza la biblioteca de bajo nivel 'cryptography' (Hazmat).
"""

import base64
import hashlib
from typing import Any, Dict, Tuple, Union
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from host.core.crypto.canonical import canonicalize


def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Genera un nuevo par de claves asimétricas Ed25519."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_raw_bytes(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Extrae los 32 bytes crudos de la clave pública Ed25519."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def compute_device_id(public_key: Union[ed25519.Ed25519PublicKey, bytes]) -> str:
    """
    Calcula el fingerprint determinista SHA-256 (64 hex chars) de la clave pública.
    Este valor sirve como 'device_id' inmutable en la lista blanca (Allowlist).
    """
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        raw_bytes = public_key_to_raw_bytes(public_key)
    elif isinstance(public_key, bytes):
        if len(public_key) != 32:
            raise ValueError(f"Longitud de clave pública Ed25519 inválida: {len(public_key)} bytes (esperados 32)")
        raw_bytes = public_key
    else:
        raise TypeError("public_key debe ser Ed25519PublicKey o bytes crudos de 32 bytes")
    
    return hashlib.sha256(raw_bytes).hexdigest().lower()


def sign_canonical(private_key: ed25519.Ed25519PrivateKey, data: Dict[str, Any]) -> str:
    """
    Canonicaliza los datos según RFC 8785 y genera una firma Ed25519 codificada en Base64.
    
    Mitigación de Vectores de Ataque:
    - Asegura que cualquier alteración de campos o valores resulte en una firma inválida.
    """
    canonical_bytes = canonicalize(data)
    signature_bytes = private_key.sign(canonical_bytes)
    return base64.b64encode(signature_bytes).decode("ascii")
