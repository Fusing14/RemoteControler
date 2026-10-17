"""
Almacén seguro de claves del Host y Allowlist de dispositivos de confianza (Device Pinning).
Todos los datos sensibles en disco se cifran exclusivamente mediante Windows DPAPI.
"""

import os
import json
import time
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from host.core.storage.dpapi import protect_bytes, unprotect_bytes
from host.core.crypto.signer import (
    generate_ed25519_keypair,
    public_key_to_raw_bytes,
    compute_device_id,
)
from host.core.crypto.verifier import load_public_key_from_raw_bytes
from host.core.crypto.exceptions import UntrustedDeviceError


class TrustedDeviceStore:
    """
    Gestor criptográfico de identidad del Host y lista blanca de clientes autorizados.
    
    Mitigación de Vectores de Ataque:
    1. Zero-Trust Device Pinning: Solo clientes cuya clave pública esté expresamente
       registrada en la allowlist son autorizados para emitir comandos.
    2. Exposición de Claves en Disco: La clave privada del Host y la base de datos de
       dispositivos autorizados se cifran con Windows DPAPI (sin texto plano en el FS).
    3. Corrupción Atómica de Archivos: Las escrituras usan el patrón temporal + replace
       para evitar archivos corruptos en caso de apagón o corte de energía.
    """

    VAULT_FILENAME = "secure_vault.dat"

    def __init__(
        self,
        vault_dir: Optional[Path | str] = None,
        secondary_entropy: Optional[bytes] = None
    ) -> None:
        """
        :param vault_dir: Ruta al directorio de configuración protegida.
                          Por defecto: %APPDATA%\\RemoteControler.
        :param secondary_entropy: Entropía adicional obligatoria para DPAPI.
        """
        if vault_dir is None:
            appdata = os.environ.get("APPDATA")
            if not appdata:
                appdata = str(Path.home() / "AppData" / "Roaming")
            self.vault_dir = Path(appdata) / "RemoteControler"
        else:
            self.vault_dir = Path(vault_dir)

        self.vault_path = self.vault_dir / self.VAULT_FILENAME
        self.secondary_entropy = secondary_entropy

        self._host_private_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._host_public_key: Optional[ed25519.Ed25519PublicKey] = None
        # Mapeo: device_id -> {"device_id": str, "public_key_hex": str, "label": str, "registered_at": int}
        self._trusted_devices: Dict[str, dict] = {}

        self._load_or_initialize()

    def _load_or_initialize(self) -> None:
        """Carga y descifra el almacén si existe, o genera un nuevo par de claves si es la primera vez."""
        self.vault_dir.mkdir(parents=True, exist_ok=True)

        if not self.vault_path.exists():
            # Inicialización por primera vez: Generación de par de claves Ed25519 del Host
            self._host_private_key, self._host_public_key = generate_ed25519_keypair()
            self._trusted_devices = {}
            self._save_to_disk()
            return

        # Cargar y descifrar mediante DPAPI
        encrypted_blob = self.vault_path.read_bytes()
        decrypted_json_bytes = unprotect_bytes(encrypted_blob, optional_entropy=self.secondary_entropy)
        vault_data = json.loads(decrypted_json_bytes.decode("utf-8"))

        # Recuperar clave privada del Host (formato PKCS#8 DER en hex)
        host_priv_bytes = bytes.fromhex(vault_data["host_private_key_der_hex"])
        self._host_private_key = serialization.load_der_private_key(host_priv_bytes, password=None)
        self._host_public_key = self._host_private_key.public_key()

        # Recuperar Allowlist
        self._trusted_devices = vault_data.get("trusted_devices", {})

    def _save_to_disk(self) -> None:
        """Serializa, cifra con DPAPI y guarda atómicamente el almacén en disco."""
        if not self._host_private_key:
            raise RuntimeError("Imposible persistir almacén: clave privada del host no inicializada")

        # Serializar clave privada a PKCS#8 DER
        priv_der = self._host_private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        vault_data = {
            "version": 1,
            "host_device_id": self.get_host_device_id(),
            "host_private_key_der_hex": priv_der.hex(),
            "trusted_devices": self._trusted_devices,
            "updated_at": int(time.time()),
        }

        plaintext_json = json.dumps(vault_data, indent=2).encode("utf-8")
        encrypted_blob = protect_bytes(plaintext_json, optional_entropy=self.secondary_entropy)

        # Escritura atómica para prevenir corrupción de archivos
        temp_path = self.vault_path.with_suffix(".tmp")
        with open(temp_path, "wb") as f:
            f.write(encrypted_blob)
            f.flush()
            os.fsync(f.fileno())

        temp_path.replace(self.vault_path)

    def get_host_keypair(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Retorna las claves criptográficas Ed25519 del Host."""
        if not self._host_private_key or not self._host_public_key:
            raise RuntimeError("Claves del host no cargadas")
        return self._host_private_key, self._host_public_key

    def get_host_device_id(self) -> str:
        """Retorna el fingerprint SHA-256 del Host."""
        _, pub = self.get_host_keypair()
        return compute_device_id(pub)

    def get_host_public_key_bytes(self) -> bytes:
        """Retorna los 32 bytes crudos de la clave pública del Host."""
        _, pub = self.get_host_keypair()
        return public_key_to_raw_bytes(pub)

    def register_device(self, device_id: str, public_key_bytes: bytes, label: str) -> None:
        """
        Registra un nuevo dispositivo móvil en la lista blanca (Device Pinning).
        
        Mitigación de Vectores de Ataque:
        - Verifica que device_id sea exactamente igual al SHA-256 de public_key_bytes,
          impidiendo registros fraudulentos o desalineados.
        """
        if len(public_key_bytes) != 32:
            raise ValueError(f"Longitud de clave pública inválida: {len(public_key_bytes)} (esperados 32)")

        clean_device_id = device_id.strip().lower()
        if not re.match(r"^[a-f0-9]{64}$", clean_device_id):
            raise ValueError("device_id debe ser un hash SHA-256 en hexadecimal (64 caracteres)")

        expected_id = compute_device_id(public_key_bytes)
        if clean_device_id != expected_id:
            raise ValueError(f"device_id no coincide con la huella de la clave pública suministrada")

        clean_label = label.strip()
        if not clean_label or len(clean_label) > 64:
            raise ValueError("La etiqueta (label) debe tener entre 1 y 64 caracteres")

        # Almacenar en la Allowlist
        self._trusted_devices[clean_device_id] = {
            "device_id": clean_device_id,
            "public_key_hex": public_key_bytes.hex(),
            "label": clean_label,
            "registered_at": int(time.time()),
        }

        self._save_to_disk()

    def revoke_device(self, device_id: str) -> bool:
        """
        Revoca inmediatamente el acceso a un dispositivo previamente registrado.
        Retorna True si el dispositivo existía y fue revocado, False en caso contrario.
        """
        clean_device_id = device_id.strip().lower()
        if clean_device_id in self._trusted_devices:
            del self._trusted_devices[clean_device_id]
            self._save_to_disk()
            return True
        return False

    def is_device_trusted(self, device_id: str) -> bool:
        """Comprueba en O(1) si un dispositivo está registrado en la Allowlist."""
        clean_device_id = device_id.strip().lower()
        return clean_device_id in self._trusted_devices

    def get_device_public_key(self, device_id: str) -> bytes:
        """
        Recupera la clave pública (32 bytes) del dispositivo autorizado.
        Lanza UntrustedDeviceError si el dispositivo no está en la Allowlist.
        """
        clean_device_id = device_id.strip().lower()
        device_entry = self._trusted_devices.get(clean_device_id)
        if not device_entry:
            raise UntrustedDeviceError(f"Dispositivo no autorizado: {clean_device_id}")

        return bytes.fromhex(device_entry["public_key_hex"])

    def get_device_public_key_object(self, device_id: str) -> ed25519.Ed25519PublicKey:
        """Retorna el objeto Ed25519PublicKey listo para verificación criptográfica."""
        raw_bytes = self.get_device_public_key(device_id)
        return load_public_key_from_raw_bytes(raw_bytes)

    def list_trusted_devices(self) -> List[dict]:
        """Retorna la lista de dispositivos autorizados (información no sensible: id, label, fecha)."""
        return [
            {
                "device_id": entry["device_id"],
                "label": entry["label"],
                "registered_at": entry["registered_at"],
            }
            for entry in self._trusted_devices.values()
        ]
