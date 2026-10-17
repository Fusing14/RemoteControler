"""
Módulo de emparejamiento seguro fuera de banda (Out-of-band Pairing).
Genera tokens de emparejamiento efímeros con firma del Host para su lectura vía código QR.
Persiste el desafío en disco protegido con Windows DPAPI para sincronización inter-proceso
entre el comando de emisión ('host.main pair') y el daemon en ejecución ('host.main run').
"""

import os
import json
import time
import secrets
import logging
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from host.core.crypto.signer import sign_canonical
from host.core.crypto.canonical import canonicalize
from host.core.storage.device_store import TrustedDeviceStore
from host.core.storage.dpapi import protect_bytes, unprotect_bytes

logger = logging.getLogger("RemoteControler.Pairing")


class PairingChallengeModel(BaseModel):
    """
    Modelo del payload emitido por el Host para ser leído por el dispositivo móvil vía QR.
    
    Mitigación de Vectores de Ataque:
    1. Spoofing del Host: El móvil verifica la firma del Host antes de confiar en la IP/endpoint.
    2. Ventana de Oportunidad Limitada: Token efímero con TTL configurable (por defecto 300s).
    3. One-Time Use: El token de emparejamiento se invalida inmediatamente tras el primer uso.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(default=1)
    host_device_id: str = Field(..., description="Fingerprint SHA-256 de la clave pública del Host")
    host_public_key_hex: str = Field(..., description="Clave pública Ed25519 del Host en hexadecimal (32 bytes)")
    tailscale_endpoint: str = Field(..., description="Dirección y puerto del servicio en la red Tailscale (ej. 100.x.y.z:8443)")
    pairing_token: str = Field(..., description="Token de desafío de un solo uso generado por CSPRNG")
    expires_at: int = Field(..., description="Unix timestamp de expiración del token")
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
    
    Arquitectura de Sincronización Inter-Proceso:
    Permite que 'python -m host.main pair' (Proceso CLI emisor) guarde el desafío
    cifrado con Windows DPAPI en el vault seguro del usuario, y que 'python -m host.main run'
    (Proceso Daemon servidor) lo lea, valide y consuma de forma atómica.
    """

    CHALLENGE_FILENAME = "pairing_challenge.dat"

    def __init__(self, device_store: TrustedDeviceStore, default_ttl_seconds: int = 300) -> None:
        self.device_store = device_store
        self.default_ttl_seconds = default_ttl_seconds
        self.challenge_path = self.device_store.vault_dir / self.CHALLENGE_FILENAME
        self._active_challenge: Optional[PairingChallengeModel] = None
        self.last_rejection_reason: Optional[str] = None

    def _save_challenge(self, challenge: PairingChallengeModel) -> None:
        """Serializa y persiste atómicamente el desafío en disco cifrado con DPAPI."""
        try:
            self.device_store.vault_dir.mkdir(parents=True, exist_ok=True)
            plaintext = json.dumps(challenge.model_dump()).encode("utf-8")
            encrypted = protect_bytes(plaintext, optional_entropy=self.device_store.secondary_entropy)
            temp_path = self.challenge_path.with_suffix(".tmp")
            with open(temp_path, "wb") as f:
                f.write(encrypted)
                f.flush()
                os.fsync(f.fileno())
            temp_path.replace(self.challenge_path)
            logger.debug("Desafío de emparejamiento guardado cifrado en: %s", self.challenge_path)
        except Exception as e:
            logger.error("Error al persistir desafío de emparejamiento cifrado en disco: %s", e)

    def _load_active_challenge(self, current_time: Optional[float] = None) -> Optional[PairingChallengeModel]:
        """
        Carga el desafío activo desde disco (o memoria en entornos de test sin persistencia).
        Si el desafío ha expirado, lo purga de inmediato y retorna None.
        """
        challenge = None

        # 1. Intentar cargar desde el archivo protegido en disco
        if self.challenge_path.exists():
            try:
                encrypted = self.challenge_path.read_bytes()
                decrypted = unprotect_bytes(encrypted, optional_entropy=self.device_store.secondary_entropy)
                data = json.loads(decrypted.decode("utf-8"))
                challenge = PairingChallengeModel.model_validate(data)
                self._active_challenge = challenge
            except Exception as e:
                logger.warning("Fallo al descifrar o leer el desafío de emparejamiento en disco: %s", e)
                challenge = None

        # 2. Fallback a memoria si existe
        if challenge is None and self._active_challenge is not None:
            challenge = self._active_challenge

        # 3. Comprobación estricta de tiempo de expiración
        if challenge is not None:
            now = current_time if current_time is not None else time.time()
            if now > challenge.expires_at:
                logger.info(
                    "Desafío de emparejamiento caducado (expiró en timestamp %d, tiempo actual %d). Purgando.",
                    challenge.expires_at, int(now)
                )
                self.clear_active_challenge()
                return None

        return challenge

    def clear_active_challenge(self) -> None:
        """Elimina el desafío activo de la memoria y purga el archivo cifrado en disco."""
        self._active_challenge = None
        if self.challenge_path.exists():
            try:
                self.challenge_path.unlink(missing_ok=True)
            except OSError as e:
                logger.warning("No se pudo eliminar el archivo de desafío de emparejamiento: %s", e)

    def create_pairing_challenge(self, tailscale_endpoint: str, ttl_seconds: Optional[int] = None) -> PairingChallengeModel:
        """
        Genera un nuevo desafío criptográfico firmado para vincular un dispositivo.
        Invalida y sobreescribe cualquier desafío previo no consumido.
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
        self._save_challenge(challenge)
        self.last_rejection_reason = None
        logger.info(
            "Nuevo desafío de emparejamiento generado para %s (TTL: %ds, Expira: %d). Guardado en %s",
            tailscale_endpoint, ttl, expires_at, self.challenge_path
        )
        return challenge

    def verify_and_consume_token(self, received_token: str, current_time: Optional[float] = None) -> bool:
        """
        Valida que el token coincida con el desafío activo en disco/memoria, no haya expirado y lo consume.
        Retorna True si es válido y fue consumido exitosamente.
        Retorna False si el token no coincide, no hay desafío activo o ya caducó.
        """
        challenge = self._load_active_challenge(current_time=current_time)
        if not challenge:
            self.last_rejection_reason = "No hay ningún desafío de emparejamiento activo en el Host (ejecuta primero 'python -m host.main pair')"
            logger.warning("Rechazo de emparejamiento: %s", self.last_rejection_reason)
            return False

        now = current_time if current_time is not None else time.time()

        # Comprobar expiración
        if now > challenge.expires_at:
            delta = int(now - challenge.expires_at)
            self.last_rejection_reason = f"El token de emparejamiento ha expirado (hace {delta} segundos)"
            logger.warning("Rechazo de emparejamiento: %s", self.last_rejection_reason)
            self.clear_active_challenge()
            return False

        # Comparación en tiempo constante para mitigar ataques de temporización
        clean_received = received_token.strip()
        is_valid = secrets.compare_digest(challenge.pairing_token, clean_received)

        if is_valid:
            # Consumir inmediatamente el token (One-Time Token)
            self.clear_active_challenge()
            self.last_rejection_reason = None
            logger.info("Token de emparejamiento verificado y consumido exitosamente (One-Time).")
            return True

        self.last_rejection_reason = "El token de emparejamiento recibido no coincide con el token activo en el Host"
        logger.warning("Rechazo de emparejamiento: %s", self.last_rejection_reason)
        return False

    def get_qr_payload(self) -> str:
        """Retorna el JSON serializado canónico listo para renderizarse en código QR."""
        challenge = self._load_active_challenge()
        if not challenge:
            raise RuntimeError("No hay ningún desafío de emparejamiento activo.")
        return canonicalize(challenge.model_dump()).decode("utf-8")
