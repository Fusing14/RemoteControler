"""
Pruebas de integración del Command Dispatcher:
Verifica el flujo integral desde la recepción del SignedEnvelope firmado hasta
el despacho seguro o el rechazo criptográfico/estructural.
"""

import time
import secrets
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from host.engine.contracts.commands import (
    CommandCatalog,
    MediaAction,
    PowerAction,
    AppPlatform,
)
from host.engine.contracts.envelope import SignedEnvelope
from host.engine.dispatcher import CommandDispatcher, ExecutionStatus
from host.core.storage.device_store import TrustedDeviceStore
from host.core.security.anti_replay import AntiReplayValidator
from host.core.crypto.signer import (
    generate_ed25519_keypair,
    public_key_to_raw_bytes,
    compute_device_id,
    sign_canonical,
)
from host.core.crypto.exceptions import (
    UntrustedDeviceError,
    InvalidSignatureError,
    ClockSkewError,
    ReplayAttackDetectedError,
    InvalidPayloadError,
)


@pytest.fixture
def test_setup(tmp_path: Path):
    """Inicializa la infraestructura del Host con un cliente emparejado de confianza."""
    vault_dir = tmp_path / "dispatcher_vault"
    device_store = TrustedDeviceStore(vault_dir=vault_dir)
    anti_replay = AntiReplayValidator(max_clock_skew_seconds=30, nonce_ttl_seconds=60)
    dispatcher = CommandDispatcher(device_store=device_store, anti_replay_validator=anti_replay)

    # Cliente legítimo
    client_priv, client_pub = generate_ed25519_keypair()
    client_pub_bytes = public_key_to_raw_bytes(client_pub)
    device_id = compute_device_id(client_pub_bytes)
    device_store.register_device(device_id, client_pub_bytes, label="Cliente Autorizado")

    return {
        "store": device_store,
        "anti_replay": anti_replay,
        "dispatcher": dispatcher,
        "client_priv": client_priv,
        "client_pub": client_pub,
        "device_id": device_id,
    }


def create_envelope(setup, command_id: CommandCatalog, payload: dict, timestamp: int = None, nonce: str = None):
    """Crea un SignedEnvelope firmado por el cliente legítimo."""
    ts = timestamp if timestamp is not None else int(time.time())
    n = nonce if nonce is not None else secrets.token_hex(16)
    dev_id = setup["device_id"]

    canonical_data = {
        "device_id": dev_id,
        "timestamp_utc": ts,
        "nonce": n,
        "command_id": command_id.value,
        "payload": payload,
    }

    sig_b64 = sign_canonical(setup["client_priv"], canonical_data)

    return SignedEnvelope(
        device_id=dev_id,
        timestamp_utc=ts,
        nonce=n,
        command_id=command_id,
        payload=payload,
        signature=sig_b64,
    )


@patch("host.engine.dispatcher.execute_media_command")
def test_dispatcher_success_flow(mock_media, test_setup):
    """Prueba de flujo exitoso completo para un comando multimedia."""
    dispatcher = test_setup["dispatcher"]
    payload = {"action": MediaAction.PLAY_PAUSE.value}

    envelope = create_envelope(test_setup, CommandCatalog.MEDIA, payload)
    result = dispatcher.dispatch(envelope)

    assert result.status == ExecutionStatus.SUCCESS
    assert result.command_id == CommandCatalog.MEDIA.value
    assert mock_media.called


@patch("host.engine.dispatcher.execute_power_command")
def test_dispatcher_success_power_flow(mock_power, test_setup):
    """Prueba de flujo exitoso completo para un comando de energía."""
    dispatcher = test_setup["dispatcher"]
    payload = {"action": PowerAction.LOCK.value, "force": False}

    envelope = create_envelope(test_setup, CommandCatalog.SYS_POWER, payload)
    result = dispatcher.dispatch(envelope)

    assert result.status == ExecutionStatus.SUCCESS
    assert mock_power.called


def test_dispatcher_reject_untrusted_device(test_setup):
    """Petición firmada por una clave no registrada en el DeviceStore debe ser rechazada."""
    dispatcher = test_setup["dispatcher"]
    rogue_priv, rogue_pub = generate_ed25519_keypair()
    rogue_pub_bytes = public_key_to_raw_bytes(rogue_pub)
    rogue_device_id = compute_device_id(rogue_pub_bytes)

    canonical_data = {
        "device_id": rogue_device_id,
        "timestamp_utc": int(time.time()),
        "nonce": secrets.token_hex(16),
        "command_id": CommandCatalog.MEDIA.value,
        "payload": {"action": MediaAction.VOLUME_MUTE.value},
    }
    sig = sign_canonical(rogue_priv, canonical_data)

    rogue_envelope = SignedEnvelope(
        device_id=rogue_device_id,
        timestamp_utc=canonical_data["timestamp_utc"],
        nonce=canonical_data["nonce"],
        command_id=CommandCatalog.MEDIA,
        payload=canonical_data["payload"],
        signature=sig,
    )

    with pytest.raises(UntrustedDeviceError):
        dispatcher.dispatch(rogue_envelope)

    # Probar que dispatch_safe captura y responde sin trazas
    safe_res = dispatcher.dispatch_safe(rogue_envelope)
    assert safe_res.status == ExecutionStatus.REJECTED
    assert safe_res.error_code == "UNTRUSTED_DEVICE"


def test_dispatcher_reject_tampered_payload(test_setup):
    """Payload alterado en tránsito debe ser rechazado por firma inválida."""
    dispatcher = test_setup["dispatcher"]
    envelope = create_envelope(test_setup, CommandCatalog.MEDIA, {"action": MediaAction.PLAY_PAUSE.value})

    # Manipular el payload sin regenerar la firma
    tampered_envelope = SignedEnvelope(
        device_id=envelope.device_id,
        timestamp_utc=envelope.timestamp_utc,
        nonce=envelope.nonce,
        command_id=envelope.command_id,
        payload={"action": MediaAction.VOLUME_DOWN.value},
        signature=envelope.signature,
    )

    with pytest.raises(InvalidSignatureError):
        dispatcher.dispatch(tampered_envelope)

    safe_res = dispatcher.dispatch_safe(tampered_envelope)
    assert safe_res.status == ExecutionStatus.REJECTED
    assert safe_res.error_code == "INVALID_SIGNATURE"


@patch("host.engine.dispatcher.execute_media_command")
def test_dispatcher_reject_replay_attack(mock_media, test_setup):
    """Comando reenviado con el mismo nonce debe ser rechazado por Anti-Replay."""
    dispatcher = test_setup["dispatcher"]
    envelope = create_envelope(test_setup, CommandCatalog.MEDIA, {"action": MediaAction.PLAY_PAUSE.value})

    # Primer envío exitoso
    res1 = dispatcher.dispatch(envelope)
    assert res1.status == ExecutionStatus.SUCCESS

    # Segundo envío idéntico (Replay Attack)
    with pytest.raises(ReplayAttackDetectedError):
        dispatcher.dispatch(envelope)

    safe_res = dispatcher.dispatch_safe(envelope)
    assert safe_res.status == ExecutionStatus.REJECTED
    assert safe_res.error_code == "REPLAY_DETECTED"


def test_dispatcher_reject_clock_skew(test_setup):
    """Comando con timestamp fuera de la ventana de sincronización debe ser rechazado."""
    dispatcher = test_setup["dispatcher"]
    old_ts = int(time.time()) - 50  # 50 segundos en el pasado
    envelope = create_envelope(
        test_setup,
        CommandCatalog.MEDIA,
        {"action": MediaAction.PLAY_PAUSE.value},
        timestamp=old_ts
    )

    with pytest.raises(ClockSkewError):
        dispatcher.dispatch(envelope)

    safe_res = dispatcher.dispatch_safe(envelope)
    assert safe_res.status == ExecutionStatus.REJECTED
    assert safe_res.error_code == "CLOCK_SKEW"


def test_dispatcher_reject_malformed_payload(test_setup):
    """Payload que viola el contrato del comando debe ser rechazado."""
    dispatcher = test_setup["dispatcher"]
    # Intentar enviar un SET_VOLUME sin el parámetro volume_percent
    invalid_payload = {"action": MediaAction.SET_VOLUME.value}
    envelope = create_envelope(test_setup, CommandCatalog.MEDIA, invalid_payload)

    with pytest.raises(InvalidPayloadError):
        dispatcher.dispatch(envelope)

    envelope2 = create_envelope(test_setup, CommandCatalog.MEDIA, invalid_payload)
    safe_res = dispatcher.dispatch_safe(envelope2)
    assert safe_res.status == ExecutionStatus.REJECTED
    assert safe_res.error_code == "INVALID_PAYLOAD"
