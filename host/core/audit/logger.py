"""
Registro de auditoría local inmutable y encadenado criptográficamente (Tamper-Evident Audit Log).
Mitigación de Repudio y Manipulación Post-Incidente mediante encadenamiento HMAC-SHA256 y Windows DPAPI.
"""

import os
import json
import time
import hmac
import hashlib
import secrets
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from host.core.storage.dpapi import protect_bytes, unprotect_bytes
from host.core.crypto.canonical import canonicalize

GENESIS_PREV_HASH = "0" * 64


class AuditLogger:
    """
    Gestor de registro de auditoría con encadenamiento criptográfico.
    
    Mitigación de Vectores de Ataque:
    1. Repudio: Registro inmutable de cada comando, estado de ejecución, timestamp e IP.
    2. Manipulación de Logs (Log Tampering): Cada línea incluye el hash de la línea previa
       y un HMAC-SHA256 sellado con una clave simétrica protegida por DPAPI. Cualquier
       eliminación, reordenamiento o alteración de registros invalida la cadena completa.
    """

    AUDIT_FILENAME = "audit.log"
    KEY_FILENAME = "audit_key.dat"

    def __init__(
        self,
        audit_dir: Optional[Path | str] = None,
        secondary_entropy: Optional[bytes] = None,
    ) -> None:
        if audit_dir is None:
            appdata = os.environ.get("APPDATA")
            if not appdata:
                appdata = str(Path.home() / "AppData" / "Roaming")
            self.audit_dir = Path(appdata) / "RemoteControler"
        else:
            self.audit_dir = Path(audit_dir)

        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.audit_dir / self.AUDIT_FILENAME
        self.key_path = self.audit_dir / self.KEY_FILENAME
        self.secondary_entropy = secondary_entropy

        self._hmac_key = self._load_or_create_hmac_key()
        self._last_index, self._last_hash = self._get_tail_state()

    def _load_or_create_hmac_key(self) -> bytes:
        """Carga la clave simétrica de auditoría o genera una nueva protegida por DPAPI."""
        if not self.key_path.exists():
            key = secrets.token_bytes(32)  # Clave de 256 bits para HMAC-SHA256
            encrypted = protect_bytes(key, optional_entropy=self.secondary_entropy)
            self.key_path.write_bytes(encrypted)
            return key

        encrypted = self.key_path.read_bytes()
        return unprotect_bytes(encrypted, optional_entropy=self.secondary_entropy)

    def _get_tail_state(self) -> Tuple[int, str]:
        """Lee la última línea del log para reanudar el índice y el prev_hash."""
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return -1, GENESIS_PREV_HASH

        last_line = None
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    last_line = line_str

        if not last_line:
            return -1, GENESIS_PREV_HASH

        try:
            entry = json.loads(last_line)
            idx = entry["index"]
            canonical_bytes = canonicalize(entry)
            curr_hash = hashlib.sha256(canonical_bytes).hexdigest()
            return idx, curr_hash
        except Exception:
            return -1, GENESIS_PREV_HASH

    def log_event(
        self,
        event_type: str,
        result_status: str,
        device_id: Optional[str] = None,
        command_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Registra un evento atómicamente al final del archivo de auditoría.
        """
        now = int(time.time())
        next_index = self._last_index + 1
        prev_hash = self._last_hash

        entry_data = {
            "client_ip": client_ip or "UNKNOWN",
            "command_id": command_id or "NONE",
            "details": details or {},
            "device_id": device_id or "ANONYMOUS",
            "event_type": event_type,
            "index": next_index,
            "prev_hash": prev_hash,
            "result_status": result_status,
            "timestamp_utc": now,
        }

        # 1. Canonicalizar según RFC 8785
        canonical_bytes = canonicalize(entry_data)

        # 2. Firmar con HMAC-SHA256
        mac = hmac.new(self._hmac_key, canonical_bytes, hashlib.sha256).hexdigest()
        entry_data["entry_hmac"] = mac

        # 3. Escribir append-only y forzar flush al disco
        line = json.dumps(entry_data, separators=(",", ":"), ensure_ascii=False) + "\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

        # 4. Actualizar estado en memoria
        full_canonical = canonicalize(entry_data)
        self._last_index = next_index
        self._last_hash = hashlib.sha256(full_canonical).hexdigest()

    def get_hmac_key(self) -> bytes:
        """Retorna la clave HMAC activa (para propósitos de verificación o testing)."""
        return self._hmac_key


def verify_audit_log_integrity(
    log_path: Path | str,
    hmac_key: bytes
) -> Tuple[bool, str]:
    """
    Verifica matemáticamente la integridad de toda la cadena de auditoría.
    
    Comprueba:
    1. Que la secuencia de índices sea estrictamente creciente (0, 1, 2, ...).
    2. Que el primer registro referencie el hash Génesis.
    3. Que cada registro apunte al hash SHA-256 canónico exacto del registro previo.
    4. Que el HMAC-SHA256 de cada línea sea matemáticamente válido con la clave DPAPI.
    """
    path = Path(log_path)
    if not path.exists():
        return True, "El archivo de log no existe aún (cadena vacía)."

    expected_index = 0
    expected_prev_hash = GENESIS_PREV_HASH

    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                entry = json.loads(line_str)
            except json.JSONDecodeError:
                return False, f"Línea {line_num}: JSON corrupto o malformado."

            # Comprobar índice secuencial
            if entry.get("index") != expected_index:
                return False, f"Línea {line_num}: Índice inconsistente (esperado {expected_index}, obtenido {entry.get('index')})."

            # Comprobar encadenamiento de hash previo
            if entry.get("prev_hash") != expected_prev_hash:
                return False, (
                    f"Línea {line_num}: Rotura de cadena criptográfica (prev_hash alterado o registros eliminados). "
                    f"Esperado: {expected_prev_hash}, Obtenido: {entry.get('prev_hash')}"
                )

            # Extraer y comprobar HMAC
            recorded_hmac = entry.get("entry_hmac")
            if not recorded_hmac:
                return False, f"Línea {line_num}: Falta el campo entry_hmac."

            entry_to_verify = dict(entry)
            del entry_to_verify["entry_hmac"]
            canonical_bytes = canonicalize(entry_to_verify)
            computed_hmac = hmac.new(hmac_key, canonical_bytes, hashlib.sha256).hexdigest()

            if not hmac.compare_digest(recorded_hmac, computed_hmac):
                return False, f"Línea {line_num}: HMAC inválido. Datos alterados o manipulados con posterioridad."

            # Calcular el hash que debe tener la siguiente línea como su prev_hash
            full_canonical = canonicalize(entry)
            expected_prev_hash = hashlib.sha256(full_canonical).hexdigest()
            expected_index += 1

    return True, f"Integridad validada exitosamente: {expected_index} registros verificados sin alteraciones."
