"""
Pruebas unitarias para las nuevas funcionalidades del Host:
1. Escáner de juegos (Steam ACF y Epic Games Manifests).
2. Captura de pantalla en memoria (Live Screen).
3. Desbloqueo remoto con contraseña (LogonUserW).
4. Despacho seguro de los nuevos comandos en CommandDispatcher.
"""

import base64
import json
import secrets
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from host.core.discovery.game_scanner import (
    scan_steam_games,
    scan_epic_games,
    scan_installed_games,
)
from host.engine.contracts.commands import (
    CommandCatalog,
    GamePlatform,
    GamesListPayload,
    GameLaunchPayload,
    ScreenFramePayload,
    UnlockPcPayload,
)
from host.engine.contracts.envelope import SignedEnvelope
from host.engine.dispatcher import CommandDispatcher, ExecutionStatus
from host.engine.handlers.screen import capture_screen_jpeg
from host.engine.handlers.unlock import (
    verify_windows_password,
    execute_unlock_pc,
    UnlockAuthenticationError,
)
from host.core.storage.device_store import TrustedDeviceStore
from host.core.security.anti_replay import AntiReplayValidator
from host.core.crypto.signer import (
    generate_ed25519_keypair,
    public_key_to_raw_bytes,
    compute_device_id,
    sign_canonical,
)


@pytest.fixture
def test_setup(tmp_path: Path):
    """Inicializa la infraestructura del Host con un cliente emparejado de confianza."""
    vault_dir = tmp_path / "dispatcher_vault"
    device_store = TrustedDeviceStore(vault_dir=vault_dir)
    anti_replay = AntiReplayValidator(max_clock_skew_seconds=30, nonce_ttl_seconds=60)
    dispatcher = CommandDispatcher(device_store=device_store, anti_replay_validator=anti_replay)

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


def create_envelope(setup, command_id: CommandCatalog, payload: dict):
    """Crea un SignedEnvelope firmado por el cliente legítimo."""
    ts = int(time.time())
    n = secrets.token_hex(16)
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


# ==========================================
# 1. Tests del Escáner de Juegos
# ==========================================

def test_steam_acf_parsing(tmp_path):
    steamapps = tmp_path / "steamapps"
    steamapps.mkdir()

    # Juego normal
    game_acf = steamapps / "appmanifest_730.acf"
    game_acf.write_text(
        '"AppState"\n{\n\t"appid"\t\t"730"\n\t"name"\t\t"Counter-Strike 2"\n}\n',
        encoding="utf-8"
    )

    # Herramienta excluida
    tool_acf = steamapps / "appmanifest_228980.acf"
    tool_acf.write_text(
        '"AppState"\n{\n\t"appid"\t\t"228980"\n\t"name"\t\t"Steamworks Common Redistributables"\n}\n',
        encoding="utf-8"
    )

    # libraryfolders.vdf
    vdf = steamapps / "libraryfolders.vdf"
    vdf.write_text(f'"libraryfolders"\n{{\n\t"0"\n\t{{\n\t\t"path"\t\t"{str(tmp_path)}"\n\t}}\n}}\n', encoding="utf-8")

    games = scan_steam_games(custom_steam_path=str(tmp_path))
    assert len(games) == 1
    assert games[0]["game_id"] == "730"
    assert games[0]["name"] == "Counter-Strike 2"
    assert games[0]["platform"] == "steam"
    assert games[0]["launch_cmd"] == "steam://rungameid/730"


def test_epic_games_item_parsing(tmp_path):
    # Juego principal
    main_game = tmp_path / "GTA5.item"
    main_game.write_text(json.dumps({
        "DisplayName": "Grand Theft Auto V",
        "AppName": "GTA5",
        "CatalogNamespace": "0584d13d4f714881a0f269616e434432",
        "CatalogItemId": "b3b723a1a9a444a19b2a1a8c0d9e8f7a",
        "MainGameAppName": "GTA5"
    }), encoding="utf-8")

    # DLC o complemento secundario (debe filtrarse)
    dlc_item = tmp_path / "GTA5_DLC.item"
    dlc_item.write_text(json.dumps({
        "DisplayName": "GTA5 Criminal Enterprise Starter Pack",
        "AppName": "GTA5_DLC_Starter",
        "CatalogNamespace": "0584d13d4f714881a0f269616e434432",
        "CatalogItemId": "c4d723a1a9a444a19b2a1a8c0d9e8f7b",
        "MainGameAppName": "GTA5"
    }), encoding="utf-8")

    games = scan_epic_games(manifests_dir=str(tmp_path))
    assert len(games) == 1
    assert games[0]["game_id"] == "GTA5"
    assert games[0]["name"] == "Grand Theft Auto V"
    assert games[0]["platform"] == "epic"
    assert "com.epicgames.launcher://apps/" in games[0]["launch_cmd"]


# ==========================================
# 2. Tests de Captura de Pantalla
# ==========================================

def test_screen_capture_jpeg():
    res = capture_screen_jpeg(max_width=640, max_height=360, quality=60)
    assert "frame" in res
    assert "width" in res
    assert "height" in res
    assert res["width"] <= 640
    assert res["height"] <= 360

    # Decodificar JPEG y verificar magic header
    frame_bytes = base64.b64decode(res["frame"])
    assert len(frame_bytes) > 100
    assert frame_bytes.startswith(b"\xff\xd8")  # JPEG Start of Image


# ==========================================
# 3. Tests de Desbloqueo de Windows
# ==========================================

def test_unlock_pc_logic(monkeypatch):
    # Mock verify_windows_password
    monkeypatch.setattr("host.engine.handlers.unlock.verify_windows_password", lambda pwd, user=None: pwd == "secret123")

    # Contraseña correcta
    with patch("time.sleep"):
        execute_unlock_pc("secret123")

    # Contraseña incorrecta
    with pytest.raises(UnlockAuthenticationError):
        execute_unlock_pc("wrong_password")


# ==========================================
# 4. Tests de Despacho de Nuevos Comandos
# ==========================================

def test_dispatcher_games_list(test_setup):
    dispatcher = test_setup["dispatcher"]
    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.GAMES_LIST,
        payload={}
    )

    result = dispatcher.dispatch(envelope)
    assert result.status == ExecutionStatus.SUCCESS
    assert result.command_id == "GAMES_LIST"
    assert result.data is not None
    assert "games" in result.data
    assert isinstance(result.data["games"], list)


def test_dispatcher_screen_frame(test_setup):
    dispatcher = test_setup["dispatcher"]
    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.SCREEN_FRAME,
        payload={"max_width": 800, "max_height": 600, "quality": 65}
    )

    result = dispatcher.dispatch(envelope)
    assert result.status == ExecutionStatus.SUCCESS
    assert result.command_id == "SCREEN_FRAME"
    assert result.data is not None
    assert "frame" in result.data
    assert result.data["width"] <= 800


def test_dispatcher_unlock_pc_success(test_setup, monkeypatch):
    dispatcher = test_setup["dispatcher"]
    monkeypatch.setattr("host.engine.handlers.unlock.verify_windows_password", lambda pwd, user=None: True)

    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.UNLOCK_PC,
        payload={"password": "valid_password"}
    )

    with patch("time.sleep"):
        result = dispatcher.dispatch(envelope)

    assert result.status == ExecutionStatus.SUCCESS
    assert result.command_id == "UNLOCK_PC"
    assert "PC desbloqueado" in result.message


def test_dispatcher_unlock_pc_invalid_password(test_setup, monkeypatch):
    dispatcher = test_setup["dispatcher"]
    monkeypatch.setattr("host.engine.handlers.unlock.verify_windows_password", lambda pwd, user=None: False)

    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.UNLOCK_PC,
        payload={"password": "bad_password"}
    )

    result = dispatcher.dispatch(envelope)
    assert result.status == ExecutionStatus.ERROR
    assert result.error_code == "INVALID_PASSWORD"
    assert "incorrecta" in result.message
