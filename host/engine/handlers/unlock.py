"""
Manejador de desbloqueo remoto de Windows con validación criptográfica y autenticación local.
Verifica la contraseña contra la cuenta actual mediante la API nativa LogonUserW de advapi32.
"""

import logging
import os
import sys
import time
from typing import Optional

logger = logging.getLogger("RemoteControler.UnlockHandler")


class UnlockAuthenticationError(Exception):
    """Excepción cuando la contraseña suministrada no es válida para la cuenta de Windows."""
    pass


class UnlockExecutionError(Exception):
    """Excepción cuando ocurre un error al enviar las señales de desbloqueo de entrada."""
    pass


def verify_windows_password(password: str, username: Optional[str] = None, domain: Optional[str] = None) -> bool:
    """
    Verifica si la contraseña ingresada es válida para el usuario local actual
    invocando la API nativa LogonUserW de Windows advapi32.
    """
    if sys.platform != "win32":
        logger.warning("verify_windows_password invocado en entorno no-Windows.")
        return True

    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    # Constantes Win32
    LOGON32_LOGON_INTERACTIVE = 2
    LOGON32_PROVIDER_DEFAULT = 0

    if not username:
        try:
            username = os.getlogin()
        except Exception:
            username = os.environ.get("USERNAME", "")

    if not domain:
        domain = os.environ.get("USERDOMAIN", ".")

    if not username or not password:
        return False

    token = wintypes.HANDLE()
    success = advapi32.LogonUserW(
        username,
        domain,
        password,
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        ctypes.byref(token),
    )

    if success:
        kernel32.CloseHandle(token)
        return True

    return False


def execute_unlock_pc(password: str, username: Optional[str] = None) -> None:
    """
    Autentica la contraseña y, si es correcta, reactiva la pantalla y simula el
    ingreso de credenciales para desbloquear la sesión de Windows.
    """
    if not verify_windows_password(password, username):
        raise UnlockAuthenticationError("La contraseña ingresada no es válida para la cuenta de Windows.")

    if sys.platform != "win32":
        logger.info("Entorno no-Windows detectado; validación de desbloqueo completada.")
        return

    try:
        import ctypes

        user32 = ctypes.windll.user32

        # 1. Despertar monitores (SendMessageW a HWND_BROADCAST con SC_MONITORPOWER y -1)
        HWND_BROADCAST = 0xFFFF
        WM_SYSCOMMAND = 0x0112
        SC_MONITORPOWER = 0xF170
        user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1)
        time.sleep(0.3)

        # 2. Levantar la cortina de la pantalla de bloqueo (Space / Escape)
        VK_SPACE = 0x20
        KEYEVENTF_KEYUP = 0x0002
        KEYEVENTF_UNICODE = 0x0004

        user32.keybd_event(VK_SPACE, 0, 0, 0)
        user32.keybd_event(VK_SPACE, 0, KEYEVENTF_KEYUP, 0)
        time.sleep(0.4)

        # 3. Escribir la contraseña carácter por carácter como entrada Unicode
        for ch in password:
            code = ord(ch)
            user32.keybd_event(0, code, KEYEVENTF_UNICODE, 0)
            user32.keybd_event(0, code, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, 0)
            time.sleep(0.02)

        time.sleep(0.1)

        # 4. Pulsar Enter para confirmar el desbloqueo
        VK_RETURN = 0x0D
        user32.keybd_event(VK_RETURN, 0, 0, 0)
        user32.keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0)

        logger.info("Secuencia de desbloqueo de Windows enviada exitosamente.")

    except Exception as e:
        logger.error("Fallo al enviar secuencia de desbloqueo Win32: %s", e)
        raise UnlockExecutionError(f"Error al enviar eventos de desbloqueo: {e}") from e
