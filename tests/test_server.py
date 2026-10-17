"""
Pruebas para el Servidor Daemon, Red, Rate Limiting y WebSocket.
"""

import time
import json
import secrets
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from starlette.testclient import TestClient

from host.transport.network_utils import (
    validate_bind_address,
    is_tailscale_ip,
    is_allowed_source_ip,
    SecurityConfigurationError,
)
from host.core.security.rate_limiter import RateLimiter
from host.core.storage.device_store import TrustedDeviceStore
from host.core.storage.pairing import PairingManager
from host.core.security.anti_replay import AntiReplayValidator
from host.core.audit.logger import AuditLogger
from host.engine.dispatcher import CommandDispatcher, ExecutionStatus
from host.engine.contracts.commands import CommandCatalog, MediaAction
from host.engine.contracts.envelope import SignedEnvelope
from host.core.crypto.signer import (
    generate_ed25519_keypair,
    public_key_to_raw_bytes,
    compute_device_id,
    sign_canonical,
)
from host.transport.server import create_app


# ==========================================
# Pruebas de Red y Restricciones de Binding
# ==========================================

def test_bind_address_0000_strictly_forbidden():
    """El intento de enlazar a 0.0.0.0 o comodines debe fallar siempre."""
    with pytest.raises(SecurityConfigurationError):
        validate_bind_address("0.0.0.0")

    with pytest.raises(SecurityConfigurationError):
        validate_bind_address("::")

    with pytest.raises(SecurityConfigurationError):
        validate_bind_address("")


def test_bind_address_loopback_permission():
    """El enlace a 127.0.0.1 solo debe autorizarse si allow_loopback=True."""
    with pytest.raises(SecurityConfigurationError):
        validate_bind_address("127.0.0.1", allow_loopback=False)

    assert validate_bind_address("127.0.0.1", allow_loopback=True) == "127.0.0.1"


def test_bind_address_tailscale_cgnat():
    """Cualquier IP en 100.64.0.0/10 es válida y permitida para binding."""
    ts_ip = "100.85.12.34"
    assert is_tailscale_ip(ts_ip) is True
    assert validate_bind_address(ts_ip, allow_loopback=False) == ts_ip

    # IP de LAN común (192.168.1.1) debe ser rechazada
    with pytest.raises(SecurityConfigurationError):
        validate_bind_address("192.168.1.50")


# ==========================================
# Pruebas del Rate Limiter
# ==========================================

def test_rate_limiter_token_exhaustion():
    """Verifica el agotamiento del Token Bucket ante una ráfaga que excede la capacidad."""
    limiter = RateLimiter(max_rate_per_second=2.0, bucket_capacity=3.0)
    ident = "test_client_1"

    assert limiter.check_rate_limit(ident) is True  # Token 1
    assert limiter.check_rate_limit(ident) is True  # Token 2
    assert limiter.check_rate_limit(ident) is True  # Token 3
    assert limiter.check_rate_limit(ident) is False  # Agotado


def test_rate_limiter_ban_after_consecutive_failures():
    """Verifica que 3 fallos consecutivos activan automáticamente el baneo de 5 minutos."""
    limiter = RateLimiter(max_failures=3, base_ban_duration_seconds=300.0)
    ident = "attacker_ip"

    banned, _ = limiter.is_banned(ident)
    assert banned is False

    limiter.record_failure(ident)
    limiter.record_failure(ident)
    banned, _ = limiter.is_banned(ident)
    assert banned is False

    # Tercer fallo activa el baneo
    limiter.record_failure(ident)
    banned, rem = limiter.is_banned(ident)
    assert banned is True
    assert rem > 250.0  # Ban activo por cerca de 300 segundos

    # Si está baneado, check_rate_limit debe devolver False de inmediato
    assert limiter.check_rate_limit(ident) is False


# ==========================================
# Pruebas de Integración FastAPI / WebSocket
# ==========================================

@pytest.fixture
def server_environment(tmp_path: Path):
    """Configura un servidor completo en directorio temporal para pruebas."""
    vault_dir = tmp_path / "vault"
    audit_dir = tmp_path / "audit"

    device_store = TrustedDeviceStore(vault_dir=vault_dir)
    anti_replay = AntiReplayValidator(max_clock_skew_seconds=30, nonce_ttl_seconds=60)
    dispatcher = CommandDispatcher(device_store, anti_replay)
    pairing_mgr = PairingManager(device_store)
    rate_limiter = RateLimiter(max_rate_per_second=20.0, bucket_capacity=30.0, max_failures=3)
    audit_logger = AuditLogger(audit_dir=audit_dir)

    # Cliente legítimo registrado
    client_priv, client_pub = generate_ed25519_keypair()
    client_pub_bytes = public_key_to_raw_bytes(client_pub)
    device_id = compute_device_id(client_pub_bytes)
    device_store.register_device(device_id, client_pub_bytes, label="Cliente Móvil Test")

    app = create_app(
        dispatcher=dispatcher,
        device_store=device_store,
        pairing_manager=pairing_mgr,
        rate_limiter=rate_limiter,
        audit_logger=audit_logger,
        allow_loopback=True,  # Para TestClient
    )

    return {
        "app": app,
        "store": device_store,
        "pairing_mgr": pairing_mgr,
        "rate_limiter": rate_limiter,
        "audit": audit_logger,
        "client_priv": client_priv,
        "client_pub": client_pub,
        "device_id": device_id,
    }


def test_http_health_endpoint(server_environment):
    """Verifica endpoint /health con TestClient."""
    app = server_environment["app"]
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "OK"


def test_http_pair_endpoint_flow(server_environment):
    """Verifica el flujo de emparejamiento HTTP con canje de token efímero."""
    app = server_environment["app"]
    pairing_mgr = server_environment["pairing_mgr"]
    store = server_environment["store"]
    client = TestClient(app)

    # 1. Crear desafío en el Host
    challenge = pairing_mgr.create_pairing_challenge(tailscale_endpoint="127.0.0.1:8443", ttl_seconds=60)

    # 2. Generar nueva identidad de teléfono para emparejar
    new_priv, new_pub = generate_ed25519_keypair()
    new_pub_bytes = public_key_to_raw_bytes(new_pub)
    new_device_id = compute_device_id(new_pub_bytes)

    # 3. Petición con token inválido debe fallar
    bad_req = {
        "pairing_token": "wrong_token_12345",
        "client_public_key_hex": new_pub_bytes.hex(),
        "client_device_id": new_device_id,
        "label": "Nuevo Telefono"
    }
    bad_resp = client.post("/pair", json=bad_req)
    assert bad_resp.status_code == 401

    # 4. Petición con token legítimo debe registrar el dispositivo
    good_req = {
        "pairing_token": challenge.pairing_token,
        "client_public_key_hex": new_pub_bytes.hex(),
        "client_device_id": new_device_id,
        "label": "Nuevo Telefono"
    }
    good_resp = client.post("/pair", json=good_req)
    assert good_resp.status_code == 200
    assert good_resp.json()["status"] == "SUCCESS"

    # Verificar que el nuevo dispositivo quedó registrado en la Allowlist
    assert store.is_device_trusted(new_device_id)


@patch("host.engine.handlers.media.send_virtual_key")
def test_websocket_control_successful_command(mock_send_vk, server_environment):
    """Verifica intercambio de comando exitoso a través del WebSocket /ws/control."""
    app = server_environment["app"]
    client = TestClient(app)

    env_dict = {
        "device_id": server_environment["device_id"],
        "timestamp_utc": int(time.time()),
        "nonce": secrets.token_hex(16),
        "command_id": CommandCatalog.MEDIA.value,
        "payload": {"action": MediaAction.VOLUME_MUTE.value},
    }
    sig = sign_canonical(server_environment["client_priv"], env_dict)
    env_dict["signature"] = sig

    with client.websocket_connect("/ws/control") as websocket:
        websocket.send_text(json.dumps(env_dict))
        response_data = websocket.receive_text()
        result = json.loads(response_data)

        assert result["status"] == "SUCCESS"
        assert result["command_id"] == "MEDIA"
        assert mock_send_vk.called


def test_websocket_control_tampered_signature_rejected(server_environment):
    """Verifica que un paquete WebSocket con firma inválida es rechazado y registrado."""
    app = server_environment["app"]
    client = TestClient(app)

    env_dict = {
        "device_id": server_environment["device_id"],
        "timestamp_utc": int(time.time()),
        "nonce": secrets.token_hex(16),
        "command_id": CommandCatalog.MEDIA.value,
        "payload": {"action": MediaAction.PLAY_PAUSE.value},
    }
    # Firma corrupta
    env_dict["signature"] = "A" * 86 + "=="

    with client.websocket_connect("/ws/control") as websocket:
        websocket.send_text(json.dumps(env_dict))
        response_data = websocket.receive_text()
        result = json.loads(response_data)

        assert result["status"] == "REJECTED"
        assert result["error_code"] == "INVALID_SIGNATURE"
