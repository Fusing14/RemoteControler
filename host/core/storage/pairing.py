"""
Módulo de emparejamiento seguro fuera de banda (Out-of-band Pairing).
Genera tokens de emparejamiento efímeros con firma del Host para su lectura vía código QR.
"""

import time
import secrets
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from pydantic import BaseModel, Field, ConfigDict

from host.core.crypto.signer import sign_canonical
from host.core.crypto.canonical import canonicalize
from host.core.storage.device_store import TrustedDeviceStore


class PairingChallengeModel(BaseModel):
    """
    Modelo del payload emitido por el Host para ser leído por el dispositivo móvil vía QR.
    
    Mitigación de Vectores de Ataque:
    1. Spoofing del Host: El móvil verifica la firma del Host antes de confiar en la IP/endpoint.
    2. Ventana de Oportunidad Limitada: Token efímero con TTL de 3 minutos.
    3. One-Time Use: El token de emparejamiento se invalida inmediatamente tras el primer uso.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(default=1)
    host_device_id: str = Field(..., description="Fingerprint SHA-256 de la clave pública del Host")
    host_public_key_hex: str = Field(..., description="Clave pública Ed25519 del Host en hexadecimal (32 bytes)")
    tailscale_endpoint: str = Field(..., description="Dirección y puerto del servicio en la red Tailscale (ej. 100.x.y.z:8443)")
    pairing_token: str = Field(..., description="Token de desafío de un solo uso generado por CSPRNG")
    expires_at: int = Field(..., description="Unix timestamp de expiración del token (TTL: 180s)")
    signature: str = Field(..., description="Firma Ed25519 del Host sobre los datos canónicos del desafío")

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Extrae el diccionario canónico para firmar/verificar, omitiendo la firma."""
        return {
            "expires_at": self.expires_at,
            "host_device_id": self.host_device_id,
            "host_public_key_hex": self.host_public_key_hex,
            "pairing_token": self.pairing_token,
            "tailscale_endpoint": self.tailscale_endpoint,
            "version": self.version,
        }


class PairingManager:
    """
    Gestor del ciclo de vida de tokens de emparejamiento efímeros en el Host.
    """

    def __init__(self, device_store: TrustedDeviceStore, default_ttl_seconds: int = 180) -> None:
        self.device_store = device_store
        self.default_ttl_seconds = default_ttl_seconds
        self._active_challenge: Optional[PairingChallengeModel] = None

    def create_pairing_challenge(self, tailscale_endpoint: str, ttl_seconds: Optional[int] = None) -> PairingChallengeModel:
        """
        Genera un nuevo desafío criptográfico firmado para vincular un dispositivo.
        Cualquier desafío previo no consumido queda automáticamente revocado.
        """
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        expires_at = int(time.time()) + ttl
        token = secrets.token_hex(16)  # 128 bits de entropía CSPRNG

        priv_key, pub_key = self.device_store.get_host_keypair()
        host_device_id = self.device_store.get_host_device_id()
        host_pub_hex = self.device_store.get_host_public_key_bytes().hex()

        canonical_dict = {
            "expires_at": expires_at,
            "host_device_id": host_device_id,
            "host_public_key_hex": host_pub_hex,
            "pairing_token": token,
            "tailscale_endpoint": tailscale_endpoint,
            "version": 1,
        }

        signature = sign_canonical(priv_key, canonical_dict)

        challenge = PairingChallengeModel(
            version=1,
            host_device_id=host_device_id,
            host_public_key_hex=host_pub_hex,
            tailscale_endpoint=tailscale_endpoint,
            pairing_token=token,
            expires_at=expires_at,
            signature=signature,
        )

        self._active_challenge = challenge
        return challenge

    def verify_and_consume_token(self, received_token: str, current_time: Optional[float] = None) -> bool:
        """
        Valida que el token coincida con el desafío activo, no haya expirado y lo consume.
        Retorna True si es válido y fue consumido exitosamente.
        Retorna False si el token no coincide, no hay desafío activo o ya caducó.
        """
        if not self._active_challenge:
            return False

        now = current_time if current_time is not None else time.time()

        # Comprobar expiración
        if now > self._active_challenge.expires_at:
            self._active_challenge = None  # Limpiar token expirado
            return False

        # Comparación en tiempo constante para mitigar ataques de temporización
        is_valid = secrets.compare_digest(self._active_challenge.pairing_token, received_token)

        if is_valid:
            # Consumir inmediatamente el token (One-Time Token)
            self._active_challenge = None
            return True

        return False

    def get_qr_payload(self) -> str:
        """Retorna el JSON serializado canónico listo para renderizarse en código QR."""
        if not self._active_challenge:
            raise RuntimeError("No hay ningún desafío de emparejamiento activo.")
        return canonicalize(self._active_challenge.model_dump()).decode("utf-8")
