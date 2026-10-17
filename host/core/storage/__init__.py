"""Módulo de persistencia segura bajo Windows DPAPI y gestión de dispositivos de confianza."""

from host.core.storage.dpapi import protect_bytes, unprotect_bytes, DPAPIError
from host.core.storage.device_store import TrustedDeviceStore
from host.core.storage.pairing import PairingManager, PairingChallengeModel

__all__ = [
    "protect_bytes",
    "unprotect_bytes",
    "DPAPIError",
    "TrustedDeviceStore",
    "PairingManager",
    "PairingChallengeModel",
]
