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
)
from host.engine.handlers.media import (
    execute_media_command,
    send_virtual_key,
    VK_MEDIA_PLAY_PAUSE,
    VK_VOLUME_UP,
    VK_VOLUME_DOWN,
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
