"""
Pruebas unitarias para los manejadores nativos Win32 (Media, Power, Apps).
Se utiliza mocking de las APIs del sistema para garantizar pruebas deterministas y seguras
sin alterar el estado del PC de desarrollo durante la ejecución.
"""

import pytest
from unittest.mock import MagicMock, patch
import ctypes

from host.engine.contracts.commands import (
    MediaAction,
    MediaPayload,
    PowerAction,
    PowerPayload,
    AppPlatform,
    AppLaunchPayload,
    MouseClickPayload,
)
from host.engine.handlers.mouse import (
    map_normalized_to_screen_pixel,
    execute_mouse_click,
    get_monitor_geometry,
    make_process_dpi_aware,
    MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP,
)
from pydantic import ValidationError
from host.engine.handlers.media import (
    execute_media_command,
    send_virtual_key,
    VK_MEDIA_PLAY_PAUSE,
    VK_MEDIA_NEXT_TRACK,
    VK_MEDIA_PREV_TRACK,
    VK_VOLUME_UP,
    VK_VOLUME_DOWN,
    media_next,
    media_previous,
    MediaHandler,
)
from host.engine.handlers.power import (
    execute_power_command,
    PowerExecutionError,
)
from host.engine.handlers.apps import (
    execute_app_command,
    AppLaunchError,
)


# ==========================================
# Pruebas de Media Handler
# ==========================================

@patch("host.engine.handlers.media._get_user32")
def test_media_play_pause(mock_get_user32):
    """Verifica que PLAY_PAUSE despacha el Virtual Key Code correspondiente."""
    mock_u32 = MagicMock()
    mock_u32.SendInput.return_value = 2  # Indica que los 2 inputs fueron enviados
    mock_get_user32.return_value = mock_u32

    payload = MediaPayload(action=MediaAction.PLAY_PAUSE)
    execute_media_command(payload)

    assert mock_u32.SendInput.called
    assert mock_u32.SendInput.call_count == 1


@patch("host.engine.handlers.media.send_virtual_key")
def test_media_set_volume_bounded(mock_send_vk):
    """Verifica que SET_VOLUME está estrictamente acotado y no genera bucles infinitos."""
    payload = MediaPayload(action=MediaAction.SET_VOLUME, volume_percent=60)
    execute_media_command(payload)

    # 50 pasos hacia abajo + (60 // 2 = 30) pasos hacia arriba = 80 llamadas
    assert mock_send_vk.call_count == 80


@patch("host.engine.handlers.media._get_user32")
def test_media_next(mock_get_user32):
    """Verifica que media_next simula pulsación y liberación de VK_MEDIA_NEXT_TRACK."""
    mock_u32 = MagicMock()
    mock_get_user32.return_value = mock_u32

    res = media_next()
    assert res == {"status": "success"}
    assert mock_u32.keybd_event.call_count == 2
    mock_u32.keybd_event.assert_any_call(VK_MEDIA_NEXT_TRACK, 0, 0, 0)
    mock_u32.keybd_event.assert_any_call(VK_MEDIA_NEXT_TRACK, 0, 2, 0)


@patch("host.engine.handlers.media._get_user32")
def test_media_previous(mock_get_user32):
    """Verifica que media_previous simula pulsación y liberación de VK_MEDIA_PREV_TRACK."""
    mock_u32 = MagicMock()
    mock_get_user32.return_value = mock_u32

    res = media_previous()
    assert res == {"status": "success"}
    assert mock_u32.keybd_event.call_count == 2
    mock_u32.keybd_event.assert_any_call(VK_MEDIA_PREV_TRACK, 0, 0, 0)
    mock_u32.keybd_event.assert_any_call(VK_MEDIA_PREV_TRACK, 0, 2, 0)


@patch("host.engine.handlers.media.media_next")
@patch("host.engine.handlers.media.media_previous")
def test_media_handler_class(mock_prev, mock_next):
    """Verifica que MediaHandler despacha correctamente a media_next y media_previous."""
    mock_next.return_value = {"status": "success"}
    mock_prev.return_value = {"status": "success"}

    handler = MediaHandler()
    assert handler.media_next() == {"status": "success"}
    assert handler.media_previous() == {"status": "success"}
    assert mock_next.called
    assert mock_prev.called


# ==========================================
# Pruebas de Power Handler
# ==========================================

@patch("ctypes.windll.user32.LockWorkStation")
def test_power_lock_workstation(mock_lock):
    """Verifica llamada a user32.LockWorkStation sin parámetros ni subshell."""
    mock_lock.return_value = 1  # TRUE en Win32

    payload = PowerPayload(action=PowerAction.LOCK)
    execute_power_command(payload)

    assert mock_lock.called


@patch("ctypes.windll.powrprof.SetSuspendState")
def test_power_sleep_and_hibernate(mock_suspend):
    """Verifica llamadas directas a PowrProf.dll para suspensión e hibernación."""
    mock_suspend.return_value = 1

    # Suspensión (bHibernate = 0)
    execute_power_command(PowerPayload(action=PowerAction.SLEEP, force=False))
    mock_suspend.assert_called_with(0, 0, 0)

    # Hibernación (bHibernate = 1)
    execute_power_command(PowerPayload(action=PowerAction.HIBERNATE, force=True))
    mock_suspend.assert_called_with(1, 1, 0)


@patch("host.engine.handlers.power._acquire_shutdown_privilege")
@patch("ctypes.windll.advapi32.InitiateSystemShutdownExW")
def test_power_shutdown_and_reboot(mock_shutdown, mock_priv):
    """Verifica adquisición de privilegios y llamada a InitiateSystemShutdownExW."""
    mock_shutdown.return_value = 1

    # Reinicio
    execute_power_command(PowerPayload(action=PowerAction.REBOOT, force=False))
    assert mock_priv.called
    assert mock_shutdown.called
    # bRebootAfterShutdown = True (quinto argumento)
    assert mock_shutdown.call_args[0][4] is True

    # Apagado
    mock_priv.reset_mock()
    mock_shutdown.reset_mock()
    execute_power_command(PowerPayload(action=PowerAction.SHUTDOWN, force=True))
    assert mock_priv.called
    # bRebootAfterShutdown = False
    assert mock_shutdown.call_args[0][4] is False


@patch("ctypes.windll.user32.LockWorkStation")
def test_power_win32_error_handling(mock_lock):
    """Verifica que los errores de las APIs de Windows se encapsulan en PowerExecutionError."""
    mock_lock.return_value = 0  # Fallo en Win32

    with pytest.raises(PowerExecutionError):
        execute_power_command(PowerPayload(action=PowerAction.LOCK))


# ==========================================
# Pruebas de Apps Handler (Steam)
# ==========================================

@patch("ctypes.windll.shell32.ShellExecuteW")
def test_steam_launch_success(mock_shell_exec):
    """Verifica delegación exclusiva a la URI oficial steam://rungameid/<id>."""
    # Retornar HINSTANCE válido (> 32)
    mock_shell_exec.return_value = ctypes.c_void_p(42)

    payload = AppLaunchPayload(platform=AppPlatform.STEAM, app_id=730)
    execute_app_command(payload)

    mock_shell_exec.assert_called_once()
    args = mock_shell_exec.call_args[0]
    assert args[1] == "open"
    assert args[2] == "steam://rungameid/730"
    assert args[3] is None  # Sin argumentos de comando libres


@patch("ctypes.windll.shell32.ShellExecuteW")
def test_steam_launch_failure_code(mock_shell_exec):
    """Verifica que un código de retorno <= 32 levanta AppLaunchError sin filtrar rutas."""
    # Retornar código de error (ej: 2 = ERROR_FILE_NOT_FOUND)
    mock_shell_exec.return_value = ctypes.c_void_p(2)

    payload = AppLaunchPayload(platform=AppPlatform.STEAM, app_id=999999)
    with pytest.raises(AppLaunchError):
        execute_app_command(payload)


# ==========================================
# Pruebas de Mouse Handler (Touch-to-Mouse 1:1)
# ==========================================

def test_mouse_coordinate_mapping_corners_and_center():
    """Verifica el mapeo matemático de esquinas y centro en monitor estándar."""
    # Monitor 1920x1080 en origen (0, 0)
    # (0.0, 0.0) -> (0, 0)
    tx, ty = map_normalized_to_screen_pixel(0.0, 0.0, 0, 0, 1920, 1080)
    assert tx == 0
    assert ty == 0

    # (1.0, 1.0) -> (1919, 1079)
    tx, ty = map_normalized_to_screen_pixel(1.0, 1.0, 0, 0, 1920, 1080)
    assert tx == 1919
    assert ty == 1079

    # (0.5, 0.5) -> (960, 540)
    tx, ty = map_normalized_to_screen_pixel(0.5, 0.5, 0, 0, 1920, 1080)
    assert tx == 960
    assert ty == 540


def test_mouse_coordinate_mapping_multimonitor_offsets():
    """Verifica el cálculo de píxeles con offsets de multimonitor (monitor secundario desplazado)."""
    # Monitor secundario: left=2560, top=165, width=1920, height=1080
    tx, ty = map_normalized_to_screen_pixel(0.0, 0.0, 2560, 165, 1920, 1080)
    assert tx == 2560
    assert ty == 165

    tx, ty = map_normalized_to_screen_pixel(1.0, 1.0, 2560, 165, 1920, 1080)
    assert tx == 2560 + 1919
    assert ty == 165 + 1079

    tx, ty = map_normalized_to_screen_pixel(0.5, 0.5, 2560, 165, 1920, 1080)
    assert tx == 2560 + 960
    assert ty == 165 + 540


def test_mouse_coordinate_mapping_negative_offset():
    """Verifica el mapeo con monitor ubicado a la izquierda de la pantalla principal (offset negativo)."""
    # Monitor secundario a la izquierda: left=-1920, top=0, width=1920, height=1080
    tx, ty = map_normalized_to_screen_pixel(0.0, 0.0, -1920, 0, 1920, 1080)
    assert tx == -1920
    assert ty == 0

    tx, ty = map_normalized_to_screen_pixel(1.0, 1.0, -1920, 0, 1920, 1080)
    assert tx == -1
    assert ty == 1079


def test_mouse_coordinate_clamping():
    """Verifica que valores fuera de [0.0, 1.0] se clampean defensivamente."""
    tx, ty = map_normalized_to_screen_pixel(-0.5, 1.5, 0, 0, 1920, 1080)
    assert tx == 0
    assert ty == 1079


def test_mouse_payload_validation():
    """Verifica la validación estricta de esquemas Pydantic y rangos [0.0, 1.0]."""
    # Válido
    p = MouseClickPayload(x=0.25, y=0.75, button="left", monitor_index=1)
    assert p.x == 0.25
    assert p.y == 0.75
    assert p.button == "left"

    # Coordenadas fuera de rango -> ValidationError
    with pytest.raises(ValidationError):
        MouseClickPayload(x=1.01, y=0.5)

    with pytest.raises(ValidationError):
        MouseClickPayload(x=-0.01, y=0.5)

    with pytest.raises(ValidationError):
        MouseClickPayload(x=0.5, y=1.5)

    # Botón no permitido -> ValidationError
    with pytest.raises(ValidationError):
        MouseClickPayload(x=0.5, y=0.5, button="triple_click")

    # Extra fields prohibidos (CWE-20 Zero-Trust) -> ValidationError
    with pytest.raises(ValidationError):
        MouseClickPayload(x=0.5, y=0.5, button="left", extra_arbitrary="payload")


@patch("host.engine.handlers.mouse.get_monitor_geometry")
@patch("host.engine.handlers.mouse._send_mouse_event")
@patch("ctypes.windll.user32.SetCursorPos", create=True)
def test_execute_mouse_click_actions(mock_set_cursor, mock_send_event, mock_geom):
    """Verifica la ejecución de clics 'left', 'right', 'double_left' y 'move'."""
    mock_geom.return_value = {"left": 0, "top": 0, "width": 1920, "height": 1080}

    # Clic izquierdo
    res_left = execute_mouse_click(0.5, 0.5, button="left", monitor_index=1)
    assert res_left["status"] == "success"
    assert res_left["target_x"] == 960
    assert res_left["target_y"] == 540
    assert mock_set_cursor.called
    assert mock_send_event.call_count == 2  # DOWN + UP

    # Clic derecho
    mock_send_event.reset_mock()
    res_right = execute_mouse_click(0.0, 0.0, button="right", monitor_index=1)
    assert res_right["status"] == "success"
    assert res_right["target_x"] == 0
    assert res_right["target_y"] == 0
    assert mock_send_event.call_count == 2

    # Doble clic izquierdo
    mock_send_event.reset_mock()
    res_double = execute_mouse_click(1.0, 1.0, button="double_left", monitor_index=1)
    assert res_double["status"] == "success"
    assert res_double["target_x"] == 1919
    assert res_double["target_y"] == 1079
    assert mock_send_event.call_count == 4  # (DOWN + UP) * 2

    # Movimiento sin clic
    mock_send_event.reset_mock()
    res_move = execute_mouse_click(0.2, 0.8, button="move", monitor_index=1)
    assert res_move["status"] == "success"
    assert mock_send_event.call_count == 0
