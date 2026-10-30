"""
Módulo de emparejamiento seguro fuera de banda (Out-of-band Pairing).
Genera tokens de emparejamiento efímeros con firma del Host para su lectura vía código QR.
Incluye:
- Certificate Pinning SHA-256 (cert_fingerprint) contra ataques MitM (CWE-295).
- Datos multi-ruta para Wake-on-LAN (mac_address, broadcast_ip, lan_ip).
- Comparación en tiempo constante con hmac.compare_digest (CWE-208).
- Rotación/invalidación automática tras intentos fallidos contra Fuerza Bruta (CWE-307).
"""

import os
import json
import time
import hmac
import secrets
import logging
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from host.core.crypto.signer import sign_canonical
from host.core.crypto.canonical import canonicalize
from host.core.storage.device_store import TrustedDeviceStore
from host.core.storage.dpapi import protect_bytes, unprotect_bytes
from host.core.security.path_security import enforce_restrictive_acls

logger = logging.getLogger("RemoteControler.Pairing")


class PairingChallengeModel(BaseModel):
    """
    Modelo del payload emitido por el Host para ser leído por el dispositivo móvil vía QR.
    
    Mitigación de Vectores de Ataque:
    1. Spoofing del Host: El móvil verifica la firma Ed25519 del Host antes de confiar en la IP/endpoint.
    2. Certificate Pinning (CWE-295): Incluye cert_fingerprint (SHA-256) para validación TLS TOFU.
    3. Multi-Ruta Wake-on-LAN: Incluye mac_address, broadcast_ip y lan_ip física.
    4. Ventana de Oportunidad Limitada: Token efímero con TTL acotado y rotación tras fallos.
    5. One-Time Use: El token de emparejamiento se invalida inmediatamente tras el primer uso.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(default=1)
    host_device_id: str = Field(..., description="Fingerprint SHA-256 de la clave pública del Host")
    host_public_key_hex: str = Field(..., description="Clave pública Ed25519 del Host en hexadecimal (32 bytes)")
    tailscale_endpoint: str = Field(..., description="Dirección y puerto del servicio en la red Tailscale (ej. 100.x.y.z:8443)")
    pairing_token: str = Field(..., description="Token de desafío de un solo uso generado por CSPRNG")
    expires_at: int = Field(..., description="Unix timestamp de expiración del token")
    signature: str = Field(..., description="Firma Ed25519 del Host sobre los datos canónicos del desafío")
    mac_address: Optional[str] = Field(default=None, description="Dirección MAC física para Wake-on-LAN")
    broadcast_ip: Optional[str] = Field(default=None, description="IP de difusión de la subred LAN para Wake-on-LAN")
    lan_ip: Optional[str] = Field(default=None, description="IP LAN física local del PC para Wake-on-LAN multi-ruta")
    cert_fingerprint: Optional[str] = Field(default=None, description="Huella SHA-256 del certificado TLS del Host (Pinning)")

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

    def __init__(
        self,
        device_store: TrustedDeviceStore,
        default_ttl_seconds: int = 300,
        max_failed_attempts: int = 3,
    ) -> None:
        self.device_store = device_store
        self.default_ttl_seconds = default_ttl_seconds
        self.max_failed_attempts = max_failed_attempts
        self.challenge_path = self.device_store.vault_dir / self.CHALLENGE_FILENAME
        self._active_challenge: Optional[PairingChallengeModel] = None
        self._failed_attempts: int = 0
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
            enforce_restrictive_acls(self.challenge_path)
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
        self._failed_attempts = 0
        if self.challenge_path.exists():
            try:
                self.challenge_path.unlink(missing_ok=True)
            except OSError as e:
                logger.warning("No se pudo eliminar el archivo de desafío de emparejamiento: %s", e)

    def rotate_pairing_challenge(self, ttl_seconds: Optional[int] = None) -> Optional[PairingChallengeModel]:
        """
        Rota inmediatamente el token de emparejamiento activo generando uno nuevo
        para el mismo endpoint (mitigación CWE-307 contra enumeración de QR).
        """
        current = self._active_challenge or self._load_active_challenge()
        endpoint = current.tailscale_endpoint if current else "127.0.0.1:8443"
        return self.create_pairing_challenge(
            tailscale_endpoint=endpoint,
            ttl_seconds=ttl_seconds or 60,
        )

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
        cert_fp = self.device_store.get_host_cert_fingerprint()

        canonical_dict = {
            "expires_at": expires_at,
            "host_device_id": host_device_id,
            "host_public_key_hex": host_pub_hex,
            "pairing_token": token,
            "tailscale_endpoint": tailscale_endpoint,
            "version": 1,
        }

        signature = sign_canonical(priv_key, canonical_dict)

        try:
            from host.core.network.wol import get_primary_adapter_info
            adapter_info = get_primary_adapter_info()
            detected_mac = adapter_info.get("mac")
            detected_bcast = adapter_info.get("broadcast_ip")
            detected_lan_ip = adapter_info.get("lan_ip") or adapter_info.get("ipv4")
        except Exception as e:
            logger.debug("No se pudo autodetectar información de red física para WoL: %s", e)
            detected_mac = None
            detected_bcast = None
            detected_lan_ip = None

        challenge = PairingChallengeModel(
            version=1,
            host_device_id=host_device_id,
            host_public_key_hex=host_pub_hex,
            tailscale_endpoint=tailscale_endpoint,
            pairing_token=token,
            expires_at=expires_at,
            signature=signature,
            mac_address=detected_mac,
            broadcast_ip=detected_bcast,
            lan_ip=detected_lan_ip,
            cert_fingerprint=cert_fp,
        )

        self._active_challenge = challenge
        self._failed_attempts = 0
        self._save_challenge(challenge)
        self.last_rejection_reason = None
        logger.info(
            "Nuevo desafío de emparejamiento generado para %s (TTL: %ds, Expira: %d). Guardado en %s",
            tailscale_endpoint, ttl, expires_at, self.challenge_path
        )
        return challenge

    def verify_and_consume_token(
        self,
        received_token: str,
        current_time: Optional[float] = None,
        rotate_on_failure: bool = False,
    ) -> bool:
        """
        Valida en tiempo constante (hmac.compare_digest) que el token coincida con el desafío activo,
        no haya expirado y lo consume.
        Si se supera max_failed_attempts o rotate_on_failure=True, rota/invalida el token de inmediato (CWE-307).
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

        # Comparación en tiempo constante (CWE-208) usando hmac.compare_digest
        clean_received = received_token.strip()
        is_valid = hmac.compare_digest(
            challenge.pairing_token.encode("utf-8"),
            clean_received.encode("utf-8"),
        )

        if is_valid:
            # Consumir inmediatamente el token (One-Time Token)
            self.clear_active_challenge()
            self.last_rejection_reason = None
            logger.info("Token de emparejamiento verificado y consumido exitosamente (One-Time).")
            return True

        self._failed_attempts += 1
        if rotate_on_failure or self._failed_attempts >= self.max_failed_attempts:
            self.rotate_pairing_challenge(ttl_seconds=60)
            self.last_rejection_reason = (
                "El token de emparejamiento recibido no coincide con el token activo en el Host "
                "(Token rotado por seguridad tras fallos reiterados)"
            )
            logger.warning("Rechazo de emparejamiento y rotación automática de token QR.")
            return False

        self.last_rejection_reason = "El token de emparejamiento recibido no coincide con el token activo en el Host"
        logger.warning("Rechazo de emparejamiento: %s", self.last_rejection_reason)
        return False

    def get_qr_payload(self) -> str:
        """Retorna el JSON serializado canónico listo para renderizarse en código QR."""
        challenge = self._load_active_challenge()
        if not challenge:
            raise RuntimeError("No hay ningún desafío de emparejamiento activo.")
        return canonicalize(challenge.model_dump()).decode("utf-8")
