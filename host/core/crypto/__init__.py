"""Módulo de primitivas criptográficas y esquemas de serialización determinista."""

from host.core.crypto.canonical import canonicalize
from host.core.crypto.signer import (
    generate_ed25519_keypair,
    public_key_to_raw_bytes,
    compute_device_id,
    sign_canonical,
)
from host.core.crypto.verifier import (
    load_public_key_from_raw_bytes,
    verify_canonical_signature,
)
from host.core.crypto.exceptions import (
    SecurityProtocolError,
    InvalidSignatureError,
    UntrustedDeviceError,
    ClockSkewError,
    ReplayAttackDetectedError,
    InvalidPayloadError,
)

__all__ = [
    "canonicalize",
    "generate_ed25519_keypair",
    "public_key_to_raw_bytes",
    "compute_device_id",
    "sign_canonical",
    "load_public_key_from_raw_bytes",
    "verify_canonical_signature",
    "SecurityProtocolError",
    "InvalidSignatureError",
    "UntrustedDeviceError",
    "ClockSkewError",
    "ReplayAttackDetectedError",
    "InvalidPayloadError",
]
