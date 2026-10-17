"""
Pruebas de integridad criptográfica y resistencia ante manipulación del Audit Log (HMAC-SHA256).
"""

import json
from pathlib import Path
import pytest

from host.core.audit.logger import AuditLogger, verify_audit_log_integrity


def test_audit_log_normal_flow(tmp_path: Path):
    """Verifica la generación y validación de una cadena legítima de registros."""
    audit = AuditLogger(audit_dir=tmp_path)

    # Registrar varios eventos
    audit.log_event("AUTH_ATTEMPT", "SUCCESS", client_ip="100.64.1.2")
    audit.log_event("COMMAND", "SUCCESS", device_id="abc12345", command_id="MEDIA")
    audit.log_event("POWER_ACTION", "SUCCESS", device_id="abc12345", command_id="SYS_POWER")

    # Verificar integridad de la cadena
    is_valid, msg = verify_audit_log_integrity(audit.log_path, audit.get_hmac_key())
    assert is_valid is True
    assert "3 registros verificados" in msg


def test_audit_log_tamper_entry_data(tmp_path: Path):
    """Verifica detección inmediata si un atacante altera un campo en un registro existente."""
    audit = AuditLogger(audit_dir=tmp_path)
    audit.log_event("EVENT_1", "SUCCESS", client_ip="100.64.1.1")
    audit.log_event("EVENT_2", "REJECTED", client_ip="100.64.1.2")

    # Leer archivo y alterar el segundo registro (cambiar REJECTED por SUCCESS sin actualizar HMAC)
    lines = audit.log_path.read_text(encoding="utf-8").strip().split("\n")
    entry2 = json.loads(lines[1])
    entry2["result_status"] = "SUCCESS"  # Modificación no autorizada
    lines[1] = json.dumps(entry2, separators=(",", ":"))
    audit.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # La verificación matemática del HMAC debe fallar
    is_valid, msg = verify_audit_log_integrity(audit.log_path, audit.get_hmac_key())
    assert is_valid is False
    assert "HMAC inválido" in msg or "alterados" in msg


def test_audit_log_tamper_delete_entry(tmp_path: Path):
    """Verifica detección de rotura de cadena si un atacante elimina un registro intermedio."""
    audit = AuditLogger(audit_dir=tmp_path)
    audit.log_event("EVENT_1", "SUCCESS")
    audit.log_event("EVENT_2", "SUCCESS")
    audit.log_event("EVENT_3", "SUCCESS")

    # Eliminar el evento 2
    lines = audit.log_path.read_text(encoding="utf-8").strip().split("\n")
    del lines[1]  # Elimina el registro del medio
    audit.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # La verificación de prev_hash e índice debe fallar
    is_valid, msg = verify_audit_log_integrity(audit.log_path, audit.get_hmac_key())
    assert is_valid is False
    assert "Rotura de cadena" in msg or "Índice inconsistente" in msg


def test_audit_log_tail_resumption(tmp_path: Path):
    """Verifica que una nueva instancia del logger retoma correctamente el índice y hash previo."""
    audit1 = AuditLogger(audit_dir=tmp_path)
    audit1.log_event("INIT", "SUCCESS")
    audit1.log_event("SHUTDOWN", "SUCCESS")

    # Nueva instancia tras simular reinicio del servicio
    audit2 = AuditLogger(audit_dir=tmp_path)
    audit2.log_event("RESTART", "SUCCESS")

    is_valid, _ = verify_audit_log_integrity(audit2.log_path, audit2.get_hmac_key())
    assert is_valid is True
