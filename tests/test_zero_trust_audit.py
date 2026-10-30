"""
Suite exhaustiva de verificación de Auditoría Ofensiva/Defensiva Zero-Trust,
Wake-on-LAN Multi-Ruta, Desbloqueo de Sesión Windows 11 y Actualizador Resiliente.

Verifica explícitamente las 12 vulnerabilidades clásicas de herramientas de control remoto (Fase 1),
el encendido en frío Wake-on-LAN (Fase 2), la secuencia de desbloqueo Winlogon en 5 pasos (Fase 3)
y la auto-reparación de actualizaciones ante falta de '.git' (error 128) o Zip Slip (Fase 4).
"""

import io
import json
import logging
import os
import secrets
import time
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from host.core.audit.logger import (
    AuditLogger,
    SensitiveDataRedactingFilter,
    redact_sensitive_dict,
    redact_sensitive_text,
)
from host.core.autostart import create_desktop_shortcut, enable_autostart
from host.core.crypto.signer import (
    compute_device_id,
    generate_ed25519_keypair,
    public_key_to_raw_bytes,
    sign_canonical,
)
from host.core.discovery.app_scanner import launch_system_app
from host.core.network.wol import (
    _is_ethernet_adapter,
    _is_virtual_adapter,
    configure_windows_wol,
    get_primary_adapter_info,
    normalize_mac_address,
    send_magic_packet,
)
from host.core.security.anti_replay import AntiReplayValidator
from host.core.security.path_security import (
    enforce_restrictive_acls,
    quote_executable_path,
    resolve_system_binary,
)
from host.core.security.rate_limiter import RateLimiter
from host.core.security.tls_pinning import (
    compute_cert_sha256_fingerprint,
    ensure_host_tls_certificate,
    verify_certificate_fingerprint,
)
from host.core.storage.device_store import TrustedDeviceStore
from host.core.storage.pairing import PairingManager
from host.core.updater import (
    UpdateSecurityError,
    extract_zip_safely,
    perform_resilient_update,
    repair_and_update_git_repo,
    update_via_https_zip,
    validate_https_github_url,
)
from host.engine.contracts.commands import (
    AppLaunchPayload,
    AppPlatform,
    CommandCatalog,
    UnlockPcPayload,
)
from host.engine.dispatcher import CommandDispatcher, ExecutionStatus
from host.engine.handlers.media import (
    MediaExecutionError,
    VK_MEDIA_PLAY_PAUSE,
    send_virtual_key,
)
from host.engine.handlers.unlock import (
    UnlockAuthenticationError,
    clear_unlock_pin,
    execute_unlock_pc,
    get_stored_unlock_pin,
    sanitize_unlock_credential,
    set_unlock_pin,
    verify_unlock_pin,
)
from host.transport.server import create_app


# =====================================================================
# FASE 1 - VULNERABILIDAD #1: Prevención de OS Command Injection (CWE-78)
# =====================================================================

def test_cwe78_no_command_injection_in_app_launcher(tmp_path: Path):
    """Rechaza rutas con Path Traversal ('..'), rutas UNC ('\\\\') y metacaracteres de shell."""
    with pytest.raises(ValidationError):
        AppLaunchPayload(platform=AppPlatform.SYSTEM, target_path="..\\..\\Windows\\System32\\cmd.exe")

    with pytest.raises(ValidationError):
        AppLaunchPayload(platform=AppPlatform.SYSTEM, target_path="\\\\evil-server\\share\\payload.exe")

    with pytest.raises(ValidationError):
        AppLaunchPayload(platform=AppPlatform.SYSTEM, target_path="C:\\app.exe & calc.exe")

    with pytest.raises(ValueError):
        launch_system_app(target_path="C:\\Users\\..\\Windows\\System32\\cmd.exe")

    with pytest.raises(ValueError):
        launch_system_app(target_path="\\\\192.168.1.99\\malware\\run.exe")


def test_cwe78_desktop_shortcut_uses_env_vars_without_interpolation(monkeypatch, tmp_path: Path):
    """Verifica que create_desktop_shortcut pase las rutas por variables de entorno sin interpolar en PowerShell."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env", {})
        return MagicMock(returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("host.core.autostart.get_desktop_path", lambda: tmp_path)

    lnk_path = create_desktop_shortcut()
    assert lnk_path.endswith("SecureDeck Host.lnk")
    if "cmd" in captured:
        ps_command_str = " ".join(captured["cmd"])
        # El script de PowerShell usa $env:SD_SHORTCUT_PATH en lugar de interpolar la ruta
        assert "$env:SD_SHORTCUT_PATH" in ps_command_str
        assert "SD_SHORTCUT_PATH" in captured["env"]


# =====================================================================
# FASE 1 - VULNERABILIDAD #2: CSWSH y Revocación en Caliente (CWE-306)
# =====================================================================

@pytest.fixture
def zero_trust_server(tmp_path: Path):
    vault_dir = tmp_path / "zt_vault"
    audit_dir = tmp_path / "zt_audit"
    store = TrustedDeviceStore(vault_dir=vault_dir)
    anti_replay = AntiReplayValidator(max_clock_skew_seconds=30, nonce_ttl_seconds=60)
    dispatcher = CommandDispatcher(store, anti_replay)
    pairing_mgr = PairingManager(store)
    limiter = RateLimiter(max_rate_per_second=30.0, bucket_capacity=40.0, max_failures=3, base_ban_duration_seconds=60.0)
    audit = AuditLogger(audit_dir=audit_dir)

    priv, pub = generate_ed25519_keypair()
    pub_bytes = public_key_to_raw_bytes(pub)
    dev_id = compute_device_id(pub_bytes)
    store.register_device(dev_id, pub_bytes, label="ZeroTrust Phone")

    app = create_app(
        dispatcher=dispatcher,
        device_store=store,
        pairing_manager=pairing_mgr,
        rate_limiter=limiter,
        audit_logger=audit,
        allow_loopback=True,
    )
    return {
        "app": app,
        "store": store,
        "pairing_mgr": pairing_mgr,
        "limiter": limiter,
        "audit": audit,
        "priv": priv,
        "dev_id": dev_id,
    }


def _sign_cmd(env, command_id: CommandCatalog, payload: dict):
    ts = int(time.time())
    nonce = secrets.token_hex(16)
    canon = {
        "device_id": env["dev_id"],
        "timestamp_utc": ts,
        "nonce": nonce,
        "command_id": command_id.value,
        "payload": payload,
    }
    sig = sign_canonical(env["priv"], canon)
    return {**canon, "signature": sig}


def test_cwe306_cswsh_browser_origin_rejected(zero_trust_server):
    """Rechaza conexiones WebSocket y peticiones HTTP con cabecera Origin de navegador malicioso."""
    client = TestClient(zero_trust_server["app"])

    # Petición HTTP con Origin de navegador debe recibir 403 Forbidden
    res = client.get("/health", headers={"Origin": "https://evil-site.example.com"})
    assert res.status_code == 403
    assert "Origin" in res.json()["error"]

    # Handshake WebSocket con Origin de navegador debe cerrarse con 1008 Policy Violation
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws/control", headers={"Origin": "http://localhost:3000"}) as ws:
            ws.receive_text()
    assert exc_info.value.code == 1008


def test_cwe306_hot_revocation_closes_websocket_immediately(zero_trust_server):
    """Si un dispositivo conectado es revocado en caliente, la siguiente trama cierra el socket con 1008."""
    client = TestClient(zero_trust_server["app"])
    store: TrustedDeviceStore = zero_trust_server["store"]
    dev_id = zero_trust_server["dev_id"]

    with client.websocket_connect("/ws/control") as ws:
        # 1. Primer comando legítimo funciona
        msg1 = _sign_cmd(zero_trust_server, CommandCatalog.HOST_INFO, {})
        ws.send_text(json.dumps(msg1))
        resp1 = json.loads(ws.receive_text())
        assert resp1["status"] == "SUCCESS"

        # 2. Revocar dispositivo en caliente desde el Host
        store.revoke_device(dev_id)

        # 3. Enviar otro comando: debe recibir UNTRUSTED_DEVICE y cerrarse el socket con 1008
        msg2 = _sign_cmd(zero_trust_server, CommandCatalog.HOST_INFO, {})
        ws.send_text(json.dumps(msg2))
        resp2 = json.loads(ws.receive_text())
        assert resp2["status"] == "REJECTED"
        assert resp2["error_code"] == "UNTRUSTED_DEVICE"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_text()
        assert exc_info.value.code == 1008


# =====================================================================
# FASE 1 - VULNERABILIDAD #3, #4, #5: Anti-Replay, Timing y Backoff Exponencial
# =====================================================================

def test_cwe294_anti_replay_session_hmac_and_bounded_cache():
    """Valida firma HMAC de sesión en tiempo constante y límite máximo de caché de nonces."""
    validator = AntiReplayValidator(max_clock_skew_seconds=30, nonce_ttl_seconds=60, max_cache_size=100)
    secret = secrets.token_bytes(32)
    now = int(time.time())

    payload_bytes = b'{"command_id":"UNLOCK_PC","device_id":"dev1","nonce":"nonce_abc12345"}'
    tampered_bytes = b'{"command_id":"SYS_POWER","device_id":"dev1","nonce":"nonce_abc12345"}'
    mac = validator.compute_session_hmac(secret, payload_bytes)
    assert validator.verify_session_hmac(secret, payload_bytes, mac) is True
    assert validator.verify_session_hmac(secret, tampered_bytes, mac) is False

    # Llenar caché por encima de max_cache_size y verificar que sigue acotada
    for i in range(120):
        validator.validate(now, f"nonce_flood_{i:04d}_xxxx")
    assert validator.active_nonces_count <= 100


def test_cwe307_exponential_backoff_and_qr_token_rotation(tmp_path: Path):
    """Verifica Exponential Backoff en RateLimiter y rotación automática del QR tras intentos fallidos."""
    limiter = RateLimiter(max_failures=2, base_ban_duration_seconds=10.0, max_ban_duration_seconds=160.0)
    ip = "100.64.99.99"

    # Primer bloqueo: 10s (2^0 * 10)
    limiter.record_failure(ip)
    limiter.record_failure(ip)
    banned, rem1 = limiter.is_banned(ip)
    assert banned is True
    assert 8.0 <= rem1 <= 10.5

    # Simular expiración del primer baneo y reincidencia -> Segundo bloqueo: 20s (2^1 * 10)
    limiter._banned_until[ip] = time.time() - 1.0
    limiter.record_failure(ip)
    limiter.record_failure(ip)
    banned2, rem2 = limiter.is_banned(ip)
    assert banned2 is True
    assert 18.0 <= rem2 <= 20.5

    # Rotación de QR en PairingManager tras fallos o con rotate_on_failure=True
    store = TrustedDeviceStore(vault_dir=tmp_path / "pair_vault")
    pm = PairingManager(store)
    ch1 = pm.create_pairing_challenge(tailscale_endpoint="100.64.1.1:8443", ttl_seconds=120)
    old_token = ch1.pairing_token

    assert pm.verify_and_consume_token("wrong_token_attempt", rotate_on_failure=True) is False
    # El token original ya fue invalidado y rotado por uno nuevo
    assert pm.verify_and_consume_token(old_token) is False
    new_qr = json.loads(pm.get_qr_payload())
    assert new_qr["pairing_token"] != old_token


# =====================================================================
# FASE 1 - VULNERABILIDAD #6, #7, #8: TLS Pinning, ACLs/Paths y Redacción DPAPI
# =====================================================================

def test_cwe295_tls_certificate_generation_and_fingerprint_pinning(tmp_path: Path):
    """Genera certificado X.509 autofirmado y valida huella SHA-256 en tiempo constante."""
    cert_path, cert_der, fp = ensure_host_tls_certificate(tmp_path / "tls_vault", "test_host_device_id")
    assert len(fp) == 64

    cert_pem = Path(cert_path).read_bytes()
    assert compute_cert_sha256_fingerprint(cert_pem) == fp
    assert compute_cert_sha256_fingerprint(cert_der) == fp
    assert verify_certificate_fingerprint(cert_pem, fp) is True
    assert verify_certificate_fingerprint(cert_pem, "0" * 64) is False


def test_cwe426_system32_binary_resolution_and_quoting():
    """Verifica resolución estricta desde System32 y entrecomillado de rutas con espacios."""
    quoted = quote_executable_path(r"C:\Program Files\Remote Controler\python.exe")
    assert quoted == r'"C:\Program Files\Remote Controler\python.exe"'

    cmd_bin = resolve_system_binary("cmd.exe")
    assert os.path.isabs(cmd_bin)
    if os.name == "nt":
        assert "system32" in cmd_bin.lower()


def test_cwe532_log_redaction_and_dpapi_entropy(tmp_path: Path, monkeypatch):
    """Verifica enmascarado de PINs/tokens en logs y cifrado DPAPI con entropía de aplicación."""
    raw_msg = 'Recibido {"password": "MySecretPin999", "pairing_token": "tok_1234567890"} de cliente'
    redacted = redact_sensitive_text(raw_msg)
    assert "MySecretPin999" not in redacted
    assert "tok_1234567890" not in redacted
    assert "***REDACTED***" in redacted

    raw_dict = {"user": "marco", "pin": "123456", "nested": {"private_key": "deadbeef"}}
    clean_dict = redact_sensitive_dict(raw_dict)
    assert clean_dict["pin"] == "***REDACTED***"
    assert clean_dict["nested"]["private_key"] == "***REDACTED***"

    # Ciclo DPAPI con entropía
    pin_file = tmp_path / "unlock_pin.dat"
    monkeypatch.setattr("host.engine.handlers.unlock.get_pin_file_path", lambda: pin_file)
    set_unlock_pin("482910")
    assert b"482910" not in pin_file.read_bytes() or os.name != "nt"
    assert verify_unlock_pin("482910") is True
    assert get_stored_unlock_pin() == "482910"
    clear_unlock_pin()
    assert get_stored_unlock_pin() is None


# =====================================================================
# FASE 1 - VULNERABILIDAD #9, #10, #11, #12: DoS, Zip Slip, VK Allowlist, Error Sanitization
# =====================================================================

def test_cwe400_http_payload_bomb_and_ws_ping_pong(zero_trust_server):
    """Rechaza cuerpos HTTP > 64 KB con 413 y soporta PING/PONG en WebSocket."""
    client = TestClient(zero_trust_server["app"])
    huge_body = "x" * 70000
    res = client.post("/pair", content=huge_body, headers={"Content-Type": "application/json"})
    assert res.status_code == 413

    with client.websocket_connect("/ws/control") as ws:
        ws.send_text('{"type":"PING"}')
        pong = json.loads(ws.receive_text())
        assert pong["type"] == "PONG"


def test_cwe22_zip_slip_blocked_and_safe_extraction(tmp_path: Path):
    """Bloquea archivos ZIP con rutas '../../evil.dll' (Zip Slip) y extrae archivos legítimos."""
    malicious_zip = tmp_path / "malicious.zip"
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("../../Windows/System32/evil.dll", b"pwned")

    target_dir = tmp_path / "extract_target"
    with pytest.raises(UpdateSecurityError):
        extract_zip_safely(malicious_zip, target_dir)

    # URL HTTP o dominio ajeno a GitHub debe ser rechazado (CWE-494)
    with pytest.raises(UpdateSecurityError):
        validate_https_github_url("http://github.com/marcosat03/RemoteControler.git")
    with pytest.raises(UpdateSecurityError):
        validate_https_github_url("https://attacker.example.com/RemoteControler.zip")


def test_cwe20_keystroke_injection_abuse_blocked():
    """Bloquea códigos VK arbitrarios en media.py y caracteres de control en el PIN de desbloqueo."""
    with pytest.raises(MediaExecutionError):
        send_virtual_key(0x41)  # Tecla 'A' no pertenece al catálogo multimedia

    with pytest.raises(ValueError):
        sanitize_unlock_credential("1234\r\n56")

    with pytest.raises(ValidationError):
        UnlockPcPayload(password="1234\x0056")


# =====================================================================
# FASE 2 & FASE 3 & FASE 4: WoL Multi-Ruta, Secuencia Unlock Win11 y Updater Resiliente
# =====================================================================

def test_phase2_virtual_adapter_filtering_and_multiroute_wol(monkeypatch):
    """Filtra adaptadores virtuales (Tailscale, ZeroTier, WSL, Docker) y envía por puertos 7, 9 y 40000."""
    assert _is_virtual_adapter("Tailscale Tunnel", "100.80.1.2") is True
    assert _is_virtual_adapter("ZeroTier One Virtual Port", "192.168.192.1") is True
    assert _is_virtual_adapter("Hyper-V Virtual Ethernet Adapter", "172.20.0.1") is True
    assert _is_virtual_adapter("Realtek PCIe GbE Family Controller", "192.168.1.50") is False
    assert _is_ethernet_adapter("Realtek PCIe GbE Family Controller") is True
    assert _is_ethernet_adapter("Intel(R) Wi-Fi 6 AX200 160MHz") is False

    mock_sock = MagicMock()
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: mock_sock)
    with patch("host.core.network.wol.time.sleep"):
        ok = send_magic_packet(
            "30:56:0F:23:15:2C",
            broadcast_ip="192.168.1.255",
            unicast_ips=["192.168.1.50", "100.85.10.20"],
        )
        assert ok is True

    sent_targets = {call[0][1] for call in mock_sock.sendto.call_args_list}
    for port in (7, 9, 40000):
        assert ("255.255.255.255", port) in sent_targets
        assert ("192.168.1.255", port) in sent_targets
        assert ("192.168.1.50", port) in sent_targets
        assert ("100.85.10.20", port) in sent_targets


def test_phase3_windows11_unlock_5step_sequence_and_stored_pin(tmp_path: Path, monkeypatch):
    """Verifica el desbloqueo en 1 toque con PIN DPAPI y la secuencia de 5 pasos en Winlogon."""
    pin_file = tmp_path / "unlock_pin.dat"
    monkeypatch.setattr("host.engine.handlers.unlock.get_pin_file_path", lambda: pin_file)
    set_unlock_pin("2580")

    mock_user32 = MagicMock()
    mock_user32.OpenInputDesktop.return_value = 101
    mock_user32.VkKeyScanW.side_effect = lambda code: code
    mock_user32.MapVirtualKeyW.side_effect = lambda vk, _: vk
    mock_user32.SendInput.return_value = 1

    import ctypes
    if hasattr(ctypes, "windll"):
        monkeypatch.setattr(ctypes.windll, "user32", mock_user32)
    monkeypatch.setattr("host.engine.handlers.unlock.is_workstation_locked", lambda: False)

    with patch("host.engine.handlers.unlock.time.sleep"):
        res = execute_unlock_pc(use_stored_pin=True)

    assert res["unlock_status"] == "UNLOCK_SUCCESS"
    assert res["locked"] is False
    if hasattr(ctypes, "windll"):
        assert mock_user32.SendMessageW.called
        assert mock_user32.OpenInputDesktop.called
        assert mock_user32.SetThreadDesktop.called
        assert mock_user32.SendInput.call_count >= 10


def test_phase4_resilient_updater_git_error128_and_zip_fallback(tmp_path: Path, monkeypatch):
    """Verifica que si Git no está disponible o no hay '.git' (error 128), el actualizador usa HTTPS ZIP seguro."""
    project_dir = tmp_path / "RemoteControlerInstall"
    project_dir.mkdir()
    (project_dir / "host").mkdir()
    (project_dir / "host" / "old_file.py").write_text("# v1", encoding="utf-8")

    # Crear paquete ZIP simulando estructura de GitHub (RemoteControler-main/...)
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("RemoteControler-main/host/new_feature.py", "VERSION = 2\n")
        zf.writestr("RemoteControler-main/Iniciar_SecureDeck.bat", "@echo off\n")
    zip_bytes = zip_buffer.getvalue()

    class FakeHttpResponse:
        def __init__(self, data: bytes):
            self._stream = io.BytesIO(data)
        def read(self, size: int = -1) -> bytes:
            return self._stream.read(size)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    # Simular que Git no está instalado -> fallback automático a update_via_https_zip
    monkeypatch.setattr("host.core.updater._find_git_executable", lambda: None)
    monkeypatch.setattr("urllib.request.urlopen", lambda req, context=None, timeout=45: FakeHttpResponse(zip_bytes))

    res = perform_resilient_update(repo_root=project_dir, install_dependencies=False)
    assert res["method"] == "https_zip"
    assert res["updated"] is True
    assert (project_dir / "host" / "new_feature.py").exists()
