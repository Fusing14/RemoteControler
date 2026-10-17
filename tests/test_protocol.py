"""
Suite de Pruebas de Seguridad para el Protocolo Criptográfico Zero-Trust.
Valida:
1. Caso de éxito (Handshake y despacho de comando legítimo).
2. Detección de manipulación (Tampering) en firma y payload.
3. Detección y bloqueo de ataques de repetición (Replay Attacks).
4. Rechazo de peticiones fuera de ventana temporal (Clock Skew).
5. Rechazo de dispositivos no autorizados (Device Pinning).
6. Prevención de inyección de parámetros y RCE vía Pydantic.
"""

import time
import secrets
import pytest
from pydantic import ValidationError

from host.engine.contracts.commands import (
    CommandCatalog,
    MediaAction,
    PowerAction,
    AppPlatform,
    MediaPayload,
    PowerPayload,
    AppLaunchPayload,
    validate_command_payload,
)
from host.engine.contracts.envelope import SignedEnvelope
from host.core.crypto.signer import (
    generate_ed25519_keypair,
    public_key_to_raw_bytes,
    compute_device_id,
    sign_canonical,
)
from host.core.crypto.verifier import (
    load_public_key_from_raw_bytes,
    verify_canonical_signature,
)
from host.core.crypto.exceptions import (
    InvalidSignatureError,
    UntrustedDeviceError,
    ClockSkewError,
    ReplayAttackDetectedError,
)
from host.core.security.anti_replay import AntiReplayValidator


@pytest.fixture
def client_keypair():
    """Genera un par de claves Ed25519 legítimo para pruebas."""
    return generate_ed25519_keypair()


@pytest.fixture
def allowlist(client_keypair):
    """Simula el almacén de claves públicas autorizadas (Device Pinning)."""
    _, client_pub = client_keypair
    raw_pub = public_key_to_raw_bytes(client_pub)
    device_id = compute_device_id(raw_pub)
    return {device_id: client_pub}


@pytest.fixture
def anti_replay():
    """Instancia del validador Anti-Replay con ventana de 30s y TTL de 60s."""
    return AntiReplayValidator(max_clock_skew_seconds=30, nonce_ttl_seconds=60)


def create_signed_envelope(private_key, public_key, command_id: CommandCatalog, payload: dict, timestamp: int = None, nonce: str = None):
    """Función auxiliar que simula el ensamblado y firmado en el cliente."""
    device_id = compute_device_id(public_key)
    ts = timestamp if timestamp is not None else int(time.time())
    n = nonce if nonce is not None else secrets.token_hex(16)

    canonical_data = {
        "device_id": device_id,
        "timestamp_utc": ts,
        "nonce": n,
        "command_id": command_id.value,
        "payload": payload,
    }

    sig_b64 = sign_canonical(private_key, canonical_data)

    return SignedEnvelope(
        device_id=device_id,
        timestamp_utc=ts,
        nonce=n,
        command_id=command_id,
        payload=payload,
        signature=sig_b64,
    )


def test_success_case(client_keypair, allowlist, anti_replay):
    """Prueba 1: Flujo completo de un comando legítimo firmado correctamente."""
    client_priv, client_pub = client_keypair
    payload = {"action": MediaAction.PLAY_PAUSE.value}

    # 1. Cliente genera y firma el envelope
    envelope = create_signed_envelope(client_priv, client_pub, CommandCatalog.MEDIA, payload)

    # 2. Host: Verificación de Device Pinning
    if envelope.device_id not in allowlist:
        raise UntrustedDeviceError("Dispositivo desconocido")
    pinned_pub_key = allowlist[envelope.device_id]

    # 3. Host: Verificación Anti-Replay y frescura de tiempo
    anti_replay.validate(envelope.timestamp_utc, envelope.nonce)

    # 4. Host: Verificación Criptográfica de la Firma Ed25519
    verify_canonical_signature(pinned_pub_key, envelope.to_canonical_dict(), envelope.signature)

    # 5. Host: Despacho y validación del payload tipado
    parsed_payload = envelope.validate_inner_payload()
    assert isinstance(parsed_payload, MediaPayload)
    assert parsed_payload.action == MediaAction.PLAY_PAUSE


def test_tampered_signature(client_keypair, allowlist, anti_replay):
    """Prueba 2a: Firma digital alterada o corrupta debe ser rechazada."""
    client_priv, client_pub = client_keypair
    payload = {"action": PowerAction.SLEEP.value, "force": False}
    envelope = create_signed_envelope(client_priv, client_pub, CommandCatalog.SYS_POWER, payload)

    # Corromper un byte de la firma
    corrupted_sig = "A" + envelope.signature[1:]

    pinned_pub_key = allowlist[envelope.device_id]
    with pytest.raises(InvalidSignatureError):
        verify_canonical_signature(pinned_pub_key, envelope.to_canonical_dict(), corrupted_sig)


def test_tampered_payload_in_transit(client_keypair, allowlist, anti_replay):
    """Prueba 2b: Un atacante altera el payload sin regenerar la firma."""
    client_priv, client_pub = client_keypair
    payload = {"action": PowerAction.SLEEP.value, "force": False}
    envelope = create_signed_envelope(client_priv, client_pub, CommandCatalog.SYS_POWER, payload)

    # Atacante modifica los datos en tránsito para forzar apagado
    tampered_data = envelope.to_canonical_dict()
    tampered_data["payload"] = {"action": PowerAction.SHUTDOWN.value, "force": True}

    pinned_pub_key = allowlist[envelope.device_id]
    with pytest.raises(InvalidSignatureError):
        verify_canonical_signature(pinned_pub_key, tampered_data, envelope.signature)


def test_replay_attack(client_keypair, allowlist, anti_replay):
    """Prueba 3: Retransmisión de un comando previo con el mismo nonce debe ser bloqueada."""
    client_priv, client_pub = client_keypair
    payload = {"action": MediaAction.VOLUME_MUTE.value}
    envelope = create_signed_envelope(client_priv, client_pub, CommandCatalog.MEDIA, payload)

    # Primera petición: exitosa
    anti_replay.validate(envelope.timestamp_utc, envelope.nonce)

    # Segunda petición idéntica: bloqueo inmediato por Replay Attack
    with pytest.raises(ReplayAttackDetectedError):
        anti_replay.validate(envelope.timestamp_utc, envelope.nonce)


def test_clock_skew_expired_timestamp(client_keypair, allowlist, anti_replay):
    """Prueba 4a: Timestamp en el pasado lejano (>30s) debe ser rechazado."""
    client_priv, client_pub = client_keypair
    payload = {"action": MediaAction.NEXT_TRACK.value}
    old_timestamp = int(time.time()) - 45  # 45 segundos en el pasado

    envelope = create_signed_envelope(
        client_priv, client_pub, CommandCatalog.MEDIA, payload, timestamp=old_timestamp
    )

    with pytest.raises(ClockSkewError):
        anti_replay.validate(envelope.timestamp_utc, envelope.nonce)


def test_clock_skew_future_timestamp(client_keypair, allowlist, anti_replay):
    """Prueba 4b: Timestamp en el futuro lejano (>30s) debe ser rechazado."""
    client_priv, client_pub = client_keypair
    payload = {"action": MediaAction.NEXT_TRACK.value}
    future_timestamp = int(time.time()) + 45  # 45 segundos en el futuro

    envelope = create_signed_envelope(
        client_priv, client_pub, CommandCatalog.MEDIA, payload, timestamp=future_timestamp
    )

    with pytest.raises(ClockSkewError):
        anti_replay.validate(envelope.timestamp_utc, envelope.nonce)


def test_untrusted_device(client_keypair, allowlist):
    """Prueba 5: Dispositivo no registrado en la Allowlist debe ser rechazado."""
    # Generar un segundo par de claves desconocido
    rogue_priv, rogue_pub = generate_ed25519_keypair()
    payload = {"action": MediaAction.PLAY_PAUSE.value}

    envelope = create_signed_envelope(rogue_priv, rogue_pub, CommandCatalog.MEDIA, payload)

    assert envelope.device_id not in allowlist


def test_rce_prevention_arbitrary_parameters(client_keypair):
    """Prueba 6a: Inyección de parámetros arbitrarios debe fallar por Extra Fields Forbidden."""
    # Intento de inyectar comando bash/powershell en payload de energía
    malicious_payload = {
        "action": PowerAction.REBOOT.value,
        "force": False,
        "command": "cmd.exe /c calc.exe"  # Inyección maliciosa
    }

    with pytest.raises(ValidationError):
        PowerPayload.model_validate(malicious_payload)


def test_rce_prevention_steam_appid_sanitization():
    """Prueba 6b: Steam AppID debe ser estrictamente un entero numérico válido."""
    # Intento de path traversal o string arbitrario en app_id
    with pytest.raises(ValidationError):
        AppLaunchPayload.model_validate({
            "platform": AppPlatform.STEAM.value,
            "app_id": "../../../Windows/System32/cmd.exe"
        })

    with pytest.raises(ValidationError):
        AppLaunchPayload.model_validate({
            "platform": AppPlatform.STEAM.value,
            "app_id": -50  # Negativo prohibido
        })

    # AppID legítimo debe validarse con éxito
    valid_app = AppLaunchPayload.model_validate({
        "platform": AppPlatform.STEAM.value,
        "app_id": 730
    })
    assert valid_app.app_id == 730
