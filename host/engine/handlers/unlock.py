"""
Manejador de desbloqueo remoto de Windows con validación criptográfica y autenticación local.
Soporta tanto contraseña estándar de Windows (mediante advapi32.LogonUserW) como
PIN de Windows Hello (cifrado en reposo con Windows DPAPI en %APPDATA%\\RemoteControler\\unlock_pin.dat).
"""

import logging
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("RemoteControler.UnlockHandler")


def is_elevated_admin() -> bool:
    """Comprueba si el proceso actual cuenta con privilegios de Administrador (UAC elevado)."""
    if sys.platform != "win32":
        return os.getuid() == 0 if hasattr(os, "getuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_current_session_id() -> int:
    """Obtiene el ID de sesión de Windows del proceso actual."""
    if sys.platform != "win32":
        return 1
    try:
        import ctypes
        from ctypes import wintypes
        session_id = wintypes.DWORD()
        if ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session_id)):
            return session_id.value
    except Exception as e:
        logger.debug("Error obteniendo session_id: %s", e)
    return 1


def relaunch_as_admin() -> bool:
    """Solicita elevación UAC y relanza el proceso actual con privilegios de Administrador."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        params = " ".join(f'"{arg}"' for arg in sys.argv[1:])
        cmd_file = sys.argv[0]
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            f'"{cmd_file}" {params}'.strip(),
            None,
            1,
        )
        return ret > 32
    except Exception as e:
        logger.error("Error al solicitar elevación UAC: %s", e)
        return False


class UnlockAuthenticationError(Exception):
    """Excepción cuando la contraseña o PIN suministrado no es válido para la cuenta de Windows."""
    pass


class UnlockExecutionError(Exception):
    """Excepción cuando ocurre un error al enviar las señales de desbloqueo de entrada."""
    pass


def get_pin_file_path() -> Path:
    """Retorna la ruta al archivo con el PIN de Windows Hello cifrado."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        if base:
            p = Path(base) / "RemoteControler"
        else:
            p = Path.home() / "AppData" / "Roaming" / "RemoteControler"
    else:
        p = Path.home() / ".config" / "RemoteControler"

    p.mkdir(parents=True, exist_ok=True)
    return p / "unlock_pin.dat"


def has_unlock_pin() -> bool:
    """Comprueba si existe un PIN configurado en disco."""
    path = get_pin_file_path()
    return path.exists() and path.stat().st_size > 0


def set_unlock_pin(pin: str) -> None:
    """
    Cifra y almacena el PIN de Windows Hello usando Windows DPAPI (o simulación en tests).
    """
    clean_pin = pin.strip()
    if not clean_pin:
        raise ValueError("El PIN no puede estar vacío.")

    path = get_pin_file_path()
    pin_bytes = clean_pin.encode("utf-8")

    if sys.platform == "win32":
        from host.core.storage.dpapi import protect_bytes
        encrypted = protect_bytes(pin_bytes, description="RemoteControler Hello PIN")
    else:
        # Fallback para pruebas unitarias fuera de Windows
        encrypted = b"MOCK_DPAPI:" + pin_bytes

    temp_path = path.with_suffix(".tmp")
    temp_path.write_bytes(encrypted)
    temp_path.replace(path)
    logger.info("PIN de desbloqueo almacenado de forma segura.")


def clear_unlock_pin() -> None:
    """Elimina el PIN almacenado."""
    path = get_pin_file_path()
    if path.exists():
        path.unlink(missing_ok=True)
        logger.info("PIN de desbloqueo eliminado.")


def verify_unlock_pin(pin: str) -> bool:
    """
    Comprueba si el PIN ingresado coincide con el PIN cifrado en unlock_pin.dat.
    """
    path = get_pin_file_path()
    if not path.exists():
        return False

    try:
        raw_data = path.read_bytes()
        if not raw_data:
            return False

        if sys.platform == "win32":
            from host.core.storage.dpapi import unprotect_bytes
            decrypted = unprotect_bytes(raw_data)
        else:
            if raw_data.startswith(b"MOCK_DPAPI:"):
                decrypted = raw_data[len(b"MOCK_DPAPI:"):]
            else:
                return False

        stored_pin = decrypted.decode("utf-8")
        return secrets.compare_digest(stored_pin, pin.strip())
    except Exception as e:
        logger.warning("Fallo al verificar el PIN de desbloqueo: %s", e)
        return False


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


def execute_unlock_pc(password_or_pin: str, username: Optional[str] = None) -> None:
    """
    Autentica la credencial ingresada (PIN de Windows Hello o contraseña de Windows)
    y, si es correcta, reactiva la pantalla, levanta la cortina con Escape + Espacio
    y simula el ingreso mediante scan codes de teclado.
    """
    is_valid = False

    # 1. Probar primero si coincide con el PIN configurado
    if verify_unlock_pin(password_or_pin):
        is_valid = True
        logger.info("Autenticación exitosa mediante PIN de Windows Hello.")
    elif verify_windows_password(password_or_pin, username):
        is_valid = True
        logger.info("Autenticación exitosa mediante contraseña de Windows LogonUserW.")

    if not is_valid:
        raise UnlockAuthenticationError("La contraseña o PIN ingresado no es válido para la cuenta de Windows.")

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

        # 2. Mecanismo primario: Desbloqueo directo de sesión mediante tscon.exe (si tiene privilegios de admin/SYSTEM)
        session_id = get_current_session_id()
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        tscon_path = os.path.join(system_root, "System32", "tscon.exe")
        tscon_success = False

        if os.path.exists(tscon_path):
            try:
                logger.info("Intentando desbloqueo rápido de sesión mediante tscon.exe (Sesión %d)...", session_id)
                res = subprocess.run([tscon_path, str(session_id), "/dest:console"], capture_output=True, timeout=5)
                if res.returncode == 0:
                    logger.info("Sesión desbloqueada exitosamente mediante tscon.exe.")
                    tscon_success = True
                else:
                    logger.debug("tscon devolvió código %d: %s", res.returncode, res.stderr.decode(errors="ignore"))
            except Exception as ex:
                logger.debug("Fallo al invocar tscon.exe: %s", ex)

        if tscon_success:
            return

        # 3. Mecanismo secundario: Acoplar hilo a escritorio Winlogon / InputDesktop y simular teclado
        h_desk = None
        GENERIC_ALL = 0x10000000
        try:
            h_desk = user32.OpenInputDesktop(0, False, GENERIC_ALL)
            if not h_desk:
                h_desk = user32.OpenDesktopW("Winlogon", 0, False, GENERIC_ALL)
            if h_desk:
                user32.SetThreadDesktop(h_desk)
        except Exception as ex:
            logger.debug("No se pudo acoplar el hilo al escritorio Winlogon: %s", ex)

        try:
            # Levantar la cortina de la pantalla de bloqueo (Escape + Space, esperar 900ms para Win 11)
            VK_ESCAPE = 0x1B
            VK_SPACE = 0x20
            VK_RETURN = 0x0D
            KEYEVENTF_KEYUP = 0x0002
            KEYEVENTF_UNICODE = 0x0004

            # Escape
            sc_esc = user32.MapVirtualKeyW(VK_ESCAPE, 0)
            user32.keybd_event(VK_ESCAPE, sc_esc, 0, 0)
            user32.keybd_event(VK_ESCAPE, sc_esc, KEYEVENTF_KEYUP, 0)
            time.sleep(0.15)

            # Space
            sc_space = user32.MapVirtualKeyW(VK_SPACE, 0)
            user32.keybd_event(VK_SPACE, sc_space, 0, 0)
            user32.keybd_event(VK_SPACE, sc_space, KEYEVENTF_KEYUP, 0)

            # Esperar a que la cortina suba completamente y el campo de PIN adquiera foco (950ms en Windows 11/10)
            time.sleep(0.95)

            # Inyectar caracteres de credencial usando scan codes de hardware
            for ch in password_or_pin:
                vk_scan = user32.VkKeyScanW(ord(ch))
                vk = vk_scan & 0xFF
                shift = (vk_scan >> 8) & 1

                if vk != 0xFF and vk != 0:
                    sc = user32.MapVirtualKeyW(vk, 0)
                    VK_SHIFT = 0x10
                    sc_shift = user32.MapVirtualKeyW(VK_SHIFT, 0)

                    if shift:
                        user32.keybd_event(VK_SHIFT, sc_shift, 0, 0)

                    user32.keybd_event(vk, sc, 0, 0)
                    user32.keybd_event(vk, sc, KEYEVENTF_KEYUP, 0)

                    if shift:
                        user32.keybd_event(VK_SHIFT, sc_shift, KEYEVENTF_KEYUP, 0)
                else:
                    # Fallback Unicode para caracteres exóticos
                    code = ord(ch)
                    user32.keybd_event(0, code, KEYEVENTF_UNICODE, 0)
                    user32.keybd_event(0, code, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, 0)

                time.sleep(0.02)

            time.sleep(0.1)

            # Pulsar Enter para confirmar
            sc_return = user32.MapVirtualKeyW(VK_RETURN, 0)
            user32.keybd_event(VK_RETURN, sc_return, 0, 0)
            user32.keybd_event(VK_RETURN, sc_return, KEYEVENTF_KEYUP, 0)

            logger.info("Secuencia de desbloqueo de Windows enviada exitosamente.")
        finally:
            if h_desk:
                try:
                    user32.CloseDesktop(h_desk)
                except Exception:
                    pass

    except Exception as e:
        logger.error("Fallo al enviar secuencia de desbloqueo Win32: %s", e)
        raise UnlockExecutionError(f"Error al enviar eventos de desbloqueo: {e}") from e
