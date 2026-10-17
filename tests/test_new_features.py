"""
Pruebas unitarias para las nuevas funcionalidades del Host:
1. Escáner de juegos (Steam ACF y Epic Games Manifests).
2. Captura de pantalla en memoria (Live Screen).
3. Desbloqueo remoto con contraseña y PIN de Windows Hello (DPAPI).
4. Configuración persistente de Host y auto-arranque.
5. Escáner y lanzador de aplicaciones del sistema Windows.
6. Validación y apertura remota de URLs en el navegador.
7. Despacho seguro de comandos en CommandDispatcher.
"""

import base64
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from pydantic import ValidationError

from host.core.discovery.game_scanner import (
    scan_steam_games,
    scan_epic_games,
    scan_installed_games,
)
from host.core.discovery.app_scanner import (
    scan_installed_apps,
    launch_system_app,
    is_app_excluded,
)
from host.core.storage.host_config import HostConfig
from host.engine.contracts.commands import (
    CommandCatalog,
    GamePlatform,
    AppPlatform,
    GamesListPayload,
    GameLaunchPayload,
    ScreenFramePayload,
    CameraFramePayload,
    MicAudioChunkPayload,
    UnlockPcPayload,
    AppsListPayload,
    OpenUrlPayload,
    AppLaunchPayload,
    RunningAppsListPayload,
    AppClosePayload,
    HostInfoPayload,
)
from host.core.network.wol import (
    build_magic_packet,
    get_primary_physical_mac,
    get_broadcast_ip,
    get_primary_adapter_info,
)
from host.engine.contracts.envelope import SignedEnvelope
from host.engine.dispatcher import CommandDispatcher, ExecutionStatus
from host.engine.handlers.screen import capture_screen_jpeg
from host.engine.handlers.camera import capture_camera_jpeg, release_camera, CameraManager
from host.engine.handlers.audio_stream import play_audio_chunk, AudioStreamError, AudioPlayerWorker
from host.core.discovery.process_manager import (
    list_running_apps,
    close_running_app,
    AppCloseError,
    AppCloseSecurityError,
)
from host.engine.handlers.apps import execute_open_url, execute_app_command
from host.engine.handlers.unlock import (
    verify_windows_password,
    execute_unlock_pc,
    set_unlock_pin,
    verify_unlock_pin,
    has_unlock_pin,
    clear_unlock_pin,
    get_pin_file_path,
    UnlockAuthenticationError,
    is_elevated_admin,
    get_current_session_id,
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

    game_acf = steamapps / "appmanifest_730.acf"
    game_acf.write_text(
        '"AppState"\n{\n\t"appid"\t\t"730"\n\t"name"\t\t"Counter-Strike 2"\n}\n',
        encoding="utf-8"
    )

    tool_acf = steamapps / "appmanifest_228980.acf"
    tool_acf.write_text(
        '"AppState"\n{\n\t"appid"\t\t"228980"\n\t"name"\t\t"Steamworks Common Redistributables"\n}\n',
        encoding="utf-8"
    )

    vdf = steamapps / "libraryfolders.vdf"
    vdf.write_text(f'"libraryfolders"\n{{\n\t"0"\n\t{{\n\t\t"path"\t\t"{str(tmp_path)}"\n\t}}\n}}\n', encoding="utf-8")

    games = scan_steam_games(custom_steam_path=str(tmp_path))
    assert len(games) == 1
    assert games[0]["game_id"] == "730"
    assert games[0]["name"] == "Counter-Strike 2"
    assert games[0]["platform"] == "steam"
    assert games[0]["launch_cmd"] == "steam://rungameid/730"


def test_epic_games_item_parsing(tmp_path):
    main_game = tmp_path / "GTA5.item"
    main_game.write_text(json.dumps({
        "DisplayName": "Grand Theft Auto V",
        "AppName": "GTA5",
        "CatalogNamespace": "0584d13d4f714881a0f269616e434432",
        "CatalogItemId": "b3b723a1a9a444a19b2a1a8c0d9e8f7a",
        "MainGameAppName": "GTA5"
    }), encoding="utf-8")

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

    frame_bytes = base64.b64decode(res["frame"])
    assert len(frame_bytes) > 100
    assert frame_bytes.startswith(b"\xff\xd8")  # JPEG Start of Image


# ==========================================
# 3. Tests de Desbloqueo de Windows y PIN DPAPI
# ==========================================

def test_unlock_pc_logic(monkeypatch):
    monkeypatch.setattr("host.engine.handlers.unlock.verify_windows_password", lambda pwd, user=None: pwd == "secret123")
    monkeypatch.setattr("host.engine.handlers.unlock.verify_unlock_pin", lambda pwd: False)

    with patch("time.sleep"):
        execute_unlock_pc("secret123")

    with pytest.raises(UnlockAuthenticationError):
        execute_unlock_pc("wrong_password")


def test_unlock_pin_dpapi_lifecycle(tmp_path, monkeypatch):
    test_pin_path = tmp_path / "unlock_pin.dat"
    monkeypatch.setattr("host.engine.handlers.unlock.get_pin_file_path", lambda: test_pin_path)

    assert not has_unlock_pin()

    # Configurar PIN
    set_unlock_pin("987654")
    assert has_unlock_pin()
    assert verify_unlock_pin("987654")
    assert not verify_unlock_pin("000000")

    # Ejecutar desbloqueo con PIN correcto
    with patch("time.sleep"):
        execute_unlock_pc("987654")

    # Eliminar PIN
    clear_unlock_pin()
    assert not has_unlock_pin()
    assert not verify_unlock_pin("987654")


# ==========================================
# 4. Tests de Configuración Persistente (HostConfig)
# ==========================================

def test_host_config_defaults_and_mutation(tmp_path):
    config_file = tmp_path / "host_config.json"
    cfg = HostConfig(config_file=config_file)

    assert cfg.keep_session_open is True
    assert cfg.get("port") == 8443

    # Modificar y persistir
    cfg.keep_session_open = False
    cfg.set("port", 9000)

    # Recargar desde disco
    cfg2 = HostConfig(config_file=config_file)
    assert cfg2.keep_session_open is False
    assert cfg2.get("port") == 9000


# ==========================================
# 5. Tests del Escáner y Lanzador de Aplicaciones
# ==========================================

def test_app_scanner_filtering(tmp_path):
    # Crear accesos directos simulados
    calc = tmp_path / "Calculadora.lnk"
    calc.write_bytes(b"lnk_data")

    notepad = tmp_path / "Notepad.lnk"
    notepad.write_bytes(b"lnk_data")

    uninstaller = tmp_path / "Uninstall App.lnk"
    uninstaller.write_bytes(b"lnk_data")

    readme = tmp_path / "README.lnk"
    readme.write_bytes(b"lnk_data")

    apps = scan_installed_apps(custom_dirs=[tmp_path])
    app_names = [a["name"] for a in apps]

    assert "Calculadora" in app_names
    assert "Notepad" in app_names
    assert "Uninstall App" not in app_names
    assert "README" not in app_names


def test_is_app_excluded():
    assert is_app_excluded("Desinstalar Programa")
    assert is_app_excluded("App Uninstall")
    assert is_app_excluded("Guía de Ayuda")
    assert is_app_excluded("License Agreement")
    assert not is_app_excluded("Spotify")
    assert not is_app_excluded("Discord")


def test_launch_system_app_validation(tmp_path):
    valid_file = tmp_path / "test_app.lnk"
    valid_file.write_bytes(b"dummy")

    with patch("os.startfile", create=True) as mock_startfile:
        res = launch_system_app(target_path=str(valid_file))
        assert res is True

    # Archivo inexistente
    with pytest.raises(FileNotFoundError):
        launch_system_app(target_path=str(tmp_path / "non_existent.lnk"))

    # Extensión no permitida
    bad_ext = tmp_path / "script.bat"
    bad_ext.write_bytes(b"dummy")
    with pytest.raises(ValueError):
        launch_system_app(target_path=str(bad_ext))


# ==========================================
# 6. Tests de Validación y Apertura de URLs
# ==========================================

def test_open_url_payload_normalization():
    p1 = OpenUrlPayload.model_validate({"url": "https://github.com"})
    assert p1.url == "https://github.com"

    # Prepend automático de https://
    p2 = OpenUrlPayload.model_validate({"url": "youtube.com/watch?v=123"})
    assert p2.url == "https://youtube.com/watch?v=123"

    p3 = OpenUrlPayload.model_validate({"url": "http://localhost:8080"})
    assert p3.url == "http://localhost:8080"


def test_open_url_payload_rejections():
    # Esquemas peligrosos prohibidos
    with pytest.raises(ValidationError):
        OpenUrlPayload.model_validate({"url": "file:///C:/Windows/cmd.exe"})

    with pytest.raises(ValidationError):
        OpenUrlPayload.model_validate({"url": "javascript:alert(1)"})

    # Inyección de nueva línea
    with pytest.raises(ValidationError):
        OpenUrlPayload.model_validate({"url": "https://example.com\r\nInjected"})

    # URL vacía
    with pytest.raises(ValidationError):
        OpenUrlPayload.model_validate({"url": "   "})


def test_execute_open_url():
    with patch("webbrowser.open") as mock_open:
        res = execute_open_url("github.com")
        assert res == "https://github.com"
        mock_open.assert_called_once_with("https://github.com", new=2)


# ==========================================
# 7. Tests de Despacho de Nuevos Comandos
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
    monkeypatch.setattr("host.engine.handlers.unlock.verify_unlock_pin", lambda pwd: False)

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
    monkeypatch.setattr("host.engine.handlers.unlock.verify_unlock_pin", lambda pwd: False)

    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.UNLOCK_PC,
        payload={"password": "bad_password"}
    )

    result = dispatcher.dispatch(envelope)
    assert result.status == ExecutionStatus.ERROR
    assert result.error_code == "INVALID_PASSWORD"
    assert "incorrecta" in result.message


def test_dispatcher_apps_list(test_setup, monkeypatch):
    dispatcher = test_setup["dispatcher"]
    monkeypatch.setattr(
        "host.engine.dispatcher.scan_installed_apps",
        lambda: [{"app_id": "app1", "name": "Calculator", "target_path": "C:\\calc.lnk"}]
    )

    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.APPS_LIST,
        payload={}
    )

    result = dispatcher.dispatch(envelope)
    assert result.status == ExecutionStatus.SUCCESS
    assert result.command_id == "APPS_LIST"
    assert "apps" in result.data
    assert len(result.data["apps"]) == 1
    assert result.data["apps"][0]["name"] == "Calculator"


def test_dispatcher_open_url(test_setup, monkeypatch):
    dispatcher = test_setup["dispatcher"]
    monkeypatch.setattr("webbrowser.open", lambda url, new=2: True)

    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.OPEN_URL,
        payload={"url": "https://google.com"}
    )

    result = dispatcher.dispatch(envelope)
    assert result.status == ExecutionStatus.SUCCESS
    assert result.command_id == "OPEN_URL"
    assert "url" in result.data
    assert result.data["url"] == "https://google.com"


def test_camera_frame_payload_validation():
    payload = CameraFramePayload()
    assert payload.camera_index == 0
    assert payload.max_width == 854
    assert payload.max_height == 480
    assert payload.quality == 65

    custom = CameraFramePayload(camera_index=1, max_width=640, max_height=360, quality=50)
    assert custom.camera_index == 1
    assert custom.max_width == 640
    assert custom.max_height == 360
    assert custom.quality == 50


def test_camera_frame_payload_invalid():
    with pytest.raises(ValidationError):
        CameraFramePayload(camera_index=-1)
    with pytest.raises(ValidationError):
        CameraFramePayload(quality=20)
    with pytest.raises(ValidationError):
        CameraFramePayload(quality=105)


def test_capture_camera_jpeg_and_release():
    data = capture_camera_jpeg(camera_index=0, max_width=640, max_height=480, quality=60)
    assert "frame" in data
    assert "width" in data
    assert "height" in data
    assert "camera_index" in data
    assert data["camera_index"] == 0
    assert isinstance(data["frame"], str)
    decoded = base64.b64decode(data["frame"])
    assert len(decoded) > 0
    release_camera()


def test_dispatcher_camera_frame(test_setup):
    dispatcher = test_setup["dispatcher"]
    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.CAMERA_FRAME,
        payload={"camera_index": 0, "max_width": 640, "max_height": 480, "quality": 60}
    )

    result = dispatcher.dispatch(envelope)
    assert result.status == ExecutionStatus.SUCCESS
    assert result.command_id == "CAMERA_FRAME"
    assert "frame" in result.data
    assert "width" in result.data
    assert "height" in result.data
    assert result.data["camera_index"] == 0
    release_camera()


def test_mic_audio_chunk_payload_valid():
    # Payload válido por defecto (16000Hz, mono)
    raw_bytes = b"\x00\x00" * 1600  # 100ms de silencio
    b64_audio = base64.b64encode(raw_bytes).decode("ascii")

    payload = MicAudioChunkPayload(audio_b64=b64_audio)
    assert payload.audio_b64 == b64_audio
    assert payload.sample_rate == 16000
    assert payload.channels == 1

    custom_payload = MicAudioChunkPayload(audio_b64=b64_audio, sample_rate=44100, channels=2)
    assert custom_payload.sample_rate == 44100
    assert custom_payload.channels == 2


def test_mic_audio_chunk_payload_invalid():
    # Campo vacío
    with pytest.raises(ValidationError):
        MicAudioChunkPayload(audio_b64="")

    # sample_rate fuera de rango
    with pytest.raises(ValidationError):
        MicAudioChunkPayload(audio_b64="AA==", sample_rate=4000)
    with pytest.raises(ValidationError):
        MicAudioChunkPayload(audio_b64="AA==", sample_rate=96000)

    # canales fuera de rango
    with pytest.raises(ValidationError):
        MicAudioChunkPayload(audio_b64="AA==", channels=0)
    with pytest.raises(ValidationError):
        MicAudioChunkPayload(audio_b64="AA==", channels=3)


def test_play_audio_chunk_success():
    raw_bytes = b"\x00\x00" * 800  # 50ms de audio
    b64_audio = base64.b64encode(raw_bytes).decode("ascii")

    # Encolar y procesar fragmento sin excepciones
    play_audio_chunk(b64_audio, sample_rate=16000, channels=1)


def test_play_audio_chunk_invalid_base64():
    with pytest.raises(AudioStreamError):
        play_audio_chunk("not-valid-base64!@#$%", sample_rate=16000, channels=1)


def test_dispatcher_mic_audio_chunk(test_setup):
    dispatcher = test_setup["dispatcher"]
    raw_bytes = b"\x00\x00" * 800
    b64_audio = base64.b64encode(raw_bytes).decode("ascii")

    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.MIC_AUDIO_CHUNK,
        payload={"audio_b64": b64_audio, "sample_rate": 16000, "channels": 1}
    )

    result = dispatcher.dispatch(envelope)
    assert result.status == ExecutionStatus.SUCCESS
    assert result.command_id == "MIC_AUDIO_CHUNK"
    assert result.data == {"played": True}


def test_screen_frame_multi_monitor(test_setup):
    dispatcher = test_setup["dispatcher"]

    # Probar captura de monitor 1
    data1 = capture_screen_jpeg(max_width=640, max_height=360, quality=60, monitor_index=1)
    assert "frame" in data1
    assert "monitor_count" in data1
    assert data1["monitor_count"] >= 1
    assert data1["monitor_index"] == 1
    assert isinstance(data1["monitors"], list)

    # Probar captura de todas las pantallas combinadas (índice 0)
    data0 = capture_screen_jpeg(max_width=640, max_height=360, quality=60, monitor_index=0)
    assert "frame" in data0
    assert data0["monitor_index"] == 0

    # Despacho mediante dispatcher
    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.SCREEN_FRAME,
        payload={"max_width": 640, "max_height": 360, "quality": 60, "monitor_index": 1}
    )
    result = dispatcher.dispatch(envelope)
    assert result.status == ExecutionStatus.SUCCESS
    assert result.command_id == "SCREEN_FRAME"
    assert "monitor_count" in result.data
    assert result.data["monitor_index"] == 1


def test_running_apps_list(test_setup):
    dispatcher = test_setup["dispatcher"]

    apps = list_running_apps()
    assert isinstance(apps, list)

    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.RUNNING_APPS_LIST,
        payload={}
    )
    result = dispatcher.dispatch(envelope)
    assert result.status == ExecutionStatus.SUCCESS
    assert result.command_id == "RUNNING_APPS_LIST"
    assert "apps" in result.data
    assert isinstance(result.data["apps"], list)


def test_app_close_security_protection(test_setup):
    dispatcher = test_setup["dispatcher"]
    current_pid = os.getpid()

    # Intentar cerrar el propio proceso del servidor Host debe fallar por seguridad
    with pytest.raises(AppCloseSecurityError):
        close_running_app(current_pid, force=False)

    envelope_self = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.APP_CLOSE,
        payload={"pid": current_pid, "force": False}
    )
    result_self = dispatcher.dispatch(envelope_self)
    assert result_self.status == ExecutionStatus.ERROR
    assert result_self.error_code == "APP_CLOSE_FORBIDDEN"

    # Intentar cerrar PID del sistema (PID <= 4)
    with pytest.raises(AppCloseSecurityError):
        close_running_app(4, force=True)

    envelope_sys = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.APP_CLOSE,
        payload={"pid": 4, "force": True}
    )
    result_sys = dispatcher.dispatch(envelope_sys)
    assert result_sys.status == ExecutionStatus.ERROR
    assert result_sys.error_code == "APP_CLOSE_FORBIDDEN"


def test_app_close_success(test_setup):
    dispatcher = test_setup["dispatcher"]

    # Lanzar proceso temporal inocuo
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(15)"])
    try:
        assert proc.poll() is None

        envelope = create_envelope(
            setup=test_setup,
            command_id=CommandCatalog.APP_CLOSE,
            payload={"pid": proc.pid, "force": True}
        )
        result = dispatcher.dispatch(envelope)
        assert result.status == ExecutionStatus.SUCCESS
        assert result.command_id == "APP_CLOSE"
        assert result.data["closed"] is True

        # Esperar a que el proceso termine
        time.sleep(0.5)
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.kill()


def test_wol_magic_packet_generation():
    """Valida la generación de paquetes mágicos Wake-on-LAN estándar de 102 bytes."""
    mac_colon = "30:56:0F:23:15:2C"
    mac_dash = "30-56-0F-23-15-2C"

    pkt1 = build_magic_packet(mac_colon)
    pkt2 = build_magic_packet(mac_dash)

    assert len(pkt1) == 102
    assert len(pkt2) == 102
    assert pkt1 == pkt2

    # Primeros 6 bytes son 0xFF
    assert pkt1[:6] == b"\xff" * 6

    # 16 repeticiones de la MAC (6 bytes cada una)
    expected_mac_bytes = bytes.fromhex("30560F23152C")
    for i in range(16):
        start = 6 + i * 6
        assert pkt1[start:start + 6] == expected_mac_bytes

    # Formato inválido lanza ValueError
    with pytest.raises(ValueError):
        build_magic_packet("invalid_mac")

    with pytest.raises(ValueError):
        build_magic_packet("00:11:22")


def test_wol_adapter_detection():
    """Valida la detección de adaptador físico y cálculo de broadcast IP para WoL."""
    mac = get_primary_physical_mac()
    assert isinstance(mac, str)
    assert len(mac.split(":")) == 6

    bcast = get_broadcast_ip()
    assert isinstance(bcast, str)
    assert len(bcast.split(".")) == 4

    info = get_primary_adapter_info()
    assert "mac" in info
    assert "broadcast_ip" in info
    assert "ipv4" in info
    assert "description" in info


def test_host_info_command(test_setup):
    """Valida el despacho del comando HOST_INFO devolviendo MAC y datos del equipo."""
    dispatcher = test_setup["dispatcher"]
    envelope = create_envelope(
        setup=test_setup,
        command_id=CommandCatalog.HOST_INFO,
        payload={}
    )
    result = dispatcher.dispatch(envelope)
    assert result.status == ExecutionStatus.SUCCESS
    assert result.command_id == "HOST_INFO"
    assert "mac_address" in result.data
    assert "broadcast_ip" in result.data
    assert "device_name" in result.data
    assert len(result.data["mac_address"].split(":")) == 6


def test_running_apps_categorization():
    """Valida la clasificación de procesos en primary y background y deduplicación estricta."""
    apps = list_running_apps()
    assert isinstance(apps, list)
    assert len(apps) > 0

    categories = {a.get("category") for a in apps}
    assert categories.issubset({"primary", "background"})
    assert "primary" in categories

    # Verificar deduplicación estricta por nombre en apps principales
    primary_apps = [a for a in apps if a.get("category") == "primary"]
    primary_names = [a["name"].lower() for a in primary_apps]
    assert len(primary_names) == len(set(primary_names)), "No deben existir nombres de ejecutable duplicados en primary"

    for app in apps:
        assert "pid" in app
        assert "name" in app
        assert "title" in app
        assert "category" in app
        assert app["pid"] > 0
        assert isinstance(app["name"], str)
        if app.get("category") == "primary":
            assert "overlay" not in app["title"].lower()


def test_wol_send_magic_packet_dual_burst(monkeypatch):
    """Valida que send_magic_packet transmita dos ráfagas multi-puerto y multi-destino."""
    from host.core.network.wol import send_magic_packet
    mock_sock = MagicMock()
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: mock_sock)

    with patch("host.core.network.wol.time.sleep") as mock_sleep:
        success = send_magic_packet("30:56:0F:23:15:2C", broadcast_ip="192.168.1.255", port=9)
        assert success is True
        # Debe haber llamado a sleep(0.1) entre ráfagas
        mock_sleep.assert_called_with(0.1)

    # Debe haber enviado paquetes a (192.168.1.255, 9), (255.255.255.255, 9),
    # y también al puerto 7 en ambas ráfagas (2 ráfagas * 2 destinos * 2 puertos = 8 llamadas sendto)
    assert mock_sock.sendto.call_count >= 4
    sent_destinations = [call[0][1] for call in mock_sock.sendto.call_args_list]
    assert ("192.168.1.255", 9) in sent_destinations
    assert ("255.255.255.255", 9) in sent_destinations


def test_unlock_elevation_and_session_helpers():
    """Valida los inspectores de privilegios UAC y sesión de Windows."""
    is_admin = is_elevated_admin()
    assert isinstance(is_admin, bool)

    session_id = get_current_session_id()
    assert isinstance(session_id, int)
    assert session_id >= 0



