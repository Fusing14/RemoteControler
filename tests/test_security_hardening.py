"""
Pruebas de endurecimiento de seguridad (Security Hardening) y mitigación de vulnerabilidades:
1. Regresión WebSocket + CommandCatalog (MIC_AUDIO_CHUNK y HOST_INFO sin NameError).
2. Mitigación de DoS por Payload Gigante (>64 KB).
3. Anti-Bypass de Rate-Limit con MIC_AUDIO_CHUNK (bloqueo/ban tras firmas falsas o device_id no autorizado).
4. Protección contra Timing Attacks y Fuerza Bruta en /pair (HTTP 429 tras fallos reiterados).
5. Inyección y Escalada en APP_CLOSE (rechazo estricto de PIDs 0, 4, getpid y getppid con APP_CLOSE_FORBIDDEN).
"""

import base64
import json
import os
import secrets
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from starlette.testclient import TestClient

from host.core.audit.logger import AuditLogger
from host.core.crypto.signer import (
    generate_ed25519_keypair,
    public_key_to_raw_bytes,
    compute_device_id,
    sign_canonical,
)
from host.core.security.anti_replay import AntiReplayValidator
from host.core.security.rate_limiter import RateLimiter
from host.core.storage.device_store import TrustedDeviceStore
from host.core.storage.pairing import PairingManager
from host.engine.contracts.commands import CommandCatalog
from host.engine.contracts.envelope import SignedEnvelope
from host.engine.dispatcher import CommandDispatcher, ExecutionStatus
from host.transport.server import create_app


@pytest.fixture
def security_test_env(tmp_path: Path):
    """Configura un entorno de servidor aislado para pruebas de penetración y seguridad."""
    vault_dir = tmp_path / "security_vault"
    device_store = TrustedDeviceStore(vault_dir=vault_dir)
    anti_replay = AntiReplayValidator(max_clock_skew_seconds=30, nonce_ttl_seconds=60)
    dispatcher = CommandDispatcher(device_store=device_store, anti_replay_validator=anti_replay)
    pairing_mgr = PairingManager(device_store=device_store, default_ttl_seconds=300)
    rate_limiter = RateLimiter(max_rate_per_second=10.0, bucket_capacity=15.0, max_failures=3, base_ban_duration_seconds=60.0)
    audit_logger = AuditLogger(audit_dir=tmp_path / "security_audit")

    # Registrar dispositivo móvil legítimo
    client_priv, client_pub = generate_ed25519_keypair()
    client_pub_bytes = public_key_to_raw_bytes(client_pub)
    device_id = compute_device_id(client_pub_bytes)
    device_store.register_device(device_id, client_pub_bytes, label="Cliente Móvil Seguro")

    app = create_app(
        dispatcher=dispatcher,
        device_store=device_store,
        pairing_manager=pairing_mgr,
        rate_limiter=rate_limiter,
        audit_logger=audit_logger,
        allow_loopback=True,
    )

    return {
        "app": app,
        "dispatcher": dispatcher,
        "store": device_store,
        "pairing_mgr": pairing_mgr,
        "rate_limiter": rate_limiter,
        "audit": audit_logger,
        "client_priv": client_priv,
        "client_pub": client_pub,
        "device_id": device_id,
    }


def make_signed_envelope(env, command_id: CommandCatalog, payload: dict, custom_priv=None, custom_dev_id=None):
    """Construye un envelope firmado válido."""
    priv = custom_priv or env["client_priv"]
    dev_id = custom_dev_id or env["device_id"]
    ts = int(time.time())
    nonce = secrets.token_hex(16)

    canon = {
        "device_id": dev_id,
        "timestamp_utc": ts,
        "nonce": nonce,
        "command_id": command_id.value,
        "payload": payload,
    }
    sig = sign_canonical(priv, canon)

    return {
        "device_id": dev_id,
        "timestamp_utc": ts,
        "nonce": nonce,
        "command_id": command_id.value,
        "payload": payload,
        "signature": sig,
    }


# =====================================================================
# 1. Regresión WebSocket + CommandCatalog (MIC_AUDIO_CHUNK y HOST_INFO)
# =====================================================================

def test_websocket_command_catalog_regression(security_test_env):
    """
    Verifica que la conexión WebSocket procese tanto comandos estándar
    como MIC_AUDIO_CHUNK y HOST_INFO sin lanzar NameError ni romper el bucle.
    """
    app = security_test_env["app"]
    client = TestClient(app)

    with client.websocket_connect("/ws/control") as ws:
        # 1. Enviar HOST_INFO
        host_info_env = make_signed_envelope(
            security_test_env,
            command_id=CommandCatalog.HOST_INFO,
            payload={},
        )
        ws.send_text(json.dumps(host_info_env))
        resp1 = json.loads(ws.receive_text())
        assert resp1["status"] == "SUCCESS"
        assert resp1["command_id"] == "HOST_INFO"
        assert "mac_address" in resp1["data"]

        # 2. Enviar MIC_AUDIO_CHUNK legítimo desde dispositivo emparejado
        audio_pcm = b"\x00\x00" * 400
        audio_b64 = base64.b64encode(audio_pcm).decode("ascii")
        audio_env = make_signed_envelope(
            security_test_env,
            command_id=CommandCatalog.MIC_AUDIO_CHUNK,
            payload={"audio_b64": audio_b64, "sample_rate": 16000, "channels": 1},
        )
        ws.send_text(json.dumps(audio_env))
        resp2 = json.loads(ws.receive_text())
        assert resp2["status"] == "SUCCESS"
        assert resp2["command_id"] == "MIC_AUDIO_CHUNK"
        assert resp2["data"] == {"played": True}


# =====================================================================
# 2. Mitigación de DoS por Payload Gigante (>64 KB)
# =====================================================================

def test_websocket_oversized_payload_dos_mitigation(security_test_env):
    """
    Verifica que el servidor WebSocket rechace de inmediato cualquier trama
    que exceda MAX_WS_MESSAGE_SIZE (64 KB) devolviendo MESSAGE_TOO_LARGE sin colapsar la memoria.
    """
    app = security_test_env["app"]
    client = TestClient(app)

    with client.websocket_connect("/ws/control") as ws:
        # Generar trama raw > 64 KB (ej. 75 KB)
        giant_message = "A" * 75000
        ws.send_text(giant_message)

        resp = json.loads(ws.receive_text())
        assert resp["status"] == "REJECTED"
        assert resp["error_code"] == "MESSAGE_TOO_LARGE"
        assert "64 KB" in resp["message"]

        # La conexión sigue viva y puede procesar comandos legítimos subsiguientes
        valid_env = make_signed_envelope(
            security_test_env,
            command_id=CommandCatalog.HOST_INFO,
            payload={},
        )
        ws.send_text(json.dumps(valid_env))
        resp2 = json.loads(ws.receive_text())
        assert resp2["status"] == "SUCCESS"


# =====================================================================
# 3. Anti-Bypass de Rate-Limit con MIC_AUDIO_CHUNK
# =====================================================================

def test_websocket_anti_bypass_rate_limit_mic_audio(security_test_env):
    """
    Verifica que un atacante no pueda usar MIC_AUDIO_CHUNK para evadir el rate limiter:
    si envía paquetes con firma manipulada o device_id no emparejado, se penaliza
    inmediatamente su IP y queda bloqueado tras superar max_failures.
    """
    app = security_test_env["app"]
    rate_limiter: RateLimiter = security_test_env["rate_limiter"]
    client = TestClient(app)

    # Identidad de atacante no registrado
    bad_priv, bad_pub = generate_ed25519_keypair()
    bad_dev_id = compute_device_id(public_key_to_raw_bytes(bad_pub))

    audio_pcm = b"\x00\x00" * 400
    audio_b64 = base64.b64encode(audio_pcm).decode("ascii")

    with client.websocket_connect("/ws/control") as ws:
        # Enviar 3 intentos con firma o device_id inválido (max_failures = 3)
        for i in range(3):
            forged_env = make_signed_envelope(
                security_test_env,
                command_id=CommandCatalog.MIC_AUDIO_CHUNK,
                payload={"audio_b64": audio_b64, "sample_rate": 16000, "channels": 1},
                custom_priv=bad_priv,
                custom_dev_id=bad_dev_id,
            )
            ws.send_text(json.dumps(forged_env))
            resp = json.loads(ws.receive_text())
            assert resp["status"] == "REJECTED"

        # La IP debe estar ahora baneada en el rate limiter
        is_banned, _ = rate_limiter.is_banned("testclient")
        assert is_banned is True

        # El 4º intento debe ser rechazado inmediatamente con IP_BANNED
        forged_env = make_signed_envelope(
            security_test_env,
            command_id=CommandCatalog.MIC_AUDIO_CHUNK,
            payload={"audio_b64": audio_b64, "sample_rate": 16000, "channels": 1},
            custom_priv=bad_priv,
            custom_dev_id=bad_dev_id,
        )
        ws.send_text(json.dumps(forged_env))
        final_resp = json.loads(ws.receive_text())
        assert final_resp["status"] == "REJECTED"
        assert final_resp["error_code"] == "IP_BANNED"


# =====================================================================
# 4. Protección contra Timing Attack y Fuerza Bruta en /pair
# =====================================================================

def test_pair_endpoint_brute_force_and_timing_protection(security_test_env):
    """
    Verifica que intentos repetidos de emparejamiento con tokens falsos
    registren fallos por IP y sean bloqueados por el RateLimiter con HTTP 429.
    """
    app = security_test_env["app"]
    rate_limiter: RateLimiter = security_test_env["rate_limiter"]
    client = TestClient(app)

    # Identidad efímera para la petición
    _, phone_pub = generate_ed25519_keypair()
    pub_bytes = public_key_to_raw_bytes(phone_pub)
    phone_id = compute_device_id(pub_bytes)

    # 3 intentos con tokens incorrectos agotan max_failures
    for i in range(3):
        bad_req = {
            "pairing_token": f"attacker_guess_{i}_{secrets.token_hex(8)}",
            "client_public_key_hex": pub_bytes.hex(),
            "client_device_id": phone_id,
            "label": "Attacker Phone",
        }
        res = client.post("/pair", json=bad_req)
        assert res.status_code == 401
        assert "Token de emparejamiento inválido o expirado" in res.json()["detail"]

    # El 4º intento debe ser rechazado por rate limit / baneo con HTTP 429
    blocked_req = {
        "pairing_token": "another_guess",
        "client_public_key_hex": pub_bytes.hex(),
        "client_device_id": phone_id,
        "label": "Attacker Phone",
    }
    blocked_res = client.post("/pair", json=blocked_req)
    assert blocked_res.status_code == 429
    assert "bloqueada" in blocked_res.json()["detail"] or "Tasa" in blocked_res.json()["detail"]


# =====================================================================
# 5. Inyección y Escalada en APP_CLOSE
# =====================================================================

def test_app_close_injection_and_privilege_escalation(security_test_env):
    """
    Verifica que el dispatcher rechace tajantemente intentos de cerrar:
    - PID del host actual (os.getpid())
    - PID del proceso padre (os.getppid())
    - PIDs reservados del kernel (0 y 4)
    - PIDs negativos o inválidos
    devolviendo siempre ExecutionStatus.ERROR y error_code='APP_CLOSE_FORBIDDEN'.
    """
    dispatcher = security_test_env["dispatcher"]

    forbidden_pids = [
        os.getpid(),
        os.getppid() if hasattr(os, "getppid") else 999999,
        0,
        4,
        -1,
    ]

    for forbidden_pid in forbidden_pids:
        envelope_data = make_signed_envelope(
            security_test_env,
            command_id=CommandCatalog.APP_CLOSE,
            payload={"pid": forbidden_pid, "force": True},
        )
        envelope = SignedEnvelope.model_validate(envelope_data)
        result = dispatcher.dispatch(envelope)

        assert result.status == ExecutionStatus.ERROR, f"PID {forbidden_pid} debió ser rechazado"
        assert result.error_code == "APP_CLOSE_FORBIDDEN", f"PID {forbidden_pid} debió devolver APP_CLOSE_FORBIDDEN"
        assert "Operación denegada" in result.message
