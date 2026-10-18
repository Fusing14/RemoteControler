"""
Módulo de gestión del auto-arranque con Windows y creación de accesos directos.
Configura el inicio automático mediante Registro de Windows (HKCU\\...\\Run) y
mediante el Programador de Tareas (schtasks con elevación de privilegios /RL HIGHEST).
"""

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger("RemoteControler.Autostart")


def get_project_root() -> Path:
    """Devuelve la ruta absoluta al directorio raíz del proyecto RemoteControler."""
    return Path(__file__).resolve().parent.parent.parent


def get_desktop_path() -> Path:
    """Obtiene la ruta a la carpeta Escritorio del usuario actual."""
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        desktop = Path(user_profile) / "Desktop"
        if desktop.exists():
            return desktop
    return Path.home() / "Desktop"


def create_desktop_shortcut() -> str:
    """
    Crea o actualiza un acceso directo en el Escritorio llamado 'SecureDeck Host.lnk'
    que apunta a Iniciar_SecureDeck.bat fijando el directorio de trabajo correcto.
    """
    project_root = get_project_root()
    bat_path = project_root / "Iniciar_SecureDeck.bat"
    desktop = get_desktop_path()
    shortcut_path = desktop / "SecureDeck Host.lnk"

    target = str(bat_path) if bat_path.exists() else sys.executable
    args = "" if bat_path.exists() else "-m host.main gui"

    if sys.platform == "win32":
        try:
            ps_script = f"""
            $ws = New-Object -ComObject WScript.Shell
            $s = $ws.CreateShortcut('{str(shortcut_path)}')
            $s.TargetPath = '{target}'
            $s.Arguments = '{args}'
            $s.WorkingDirectory = '{str(project_root)}'
            $s.Description = 'SecureDeck Host - Control Remoto Seguro para Windows 11'
            $s.Save()
            """
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                check=True,
                capture_output=True,
                timeout=10,
            )
            logger.info("Acceso directo creado exitosamente en: %s", shortcut_path)
            return str(shortcut_path)
        except Exception as e:
            logger.error("Error al crear acceso directo mediante PowerShell COM: %s", e)
            raise RuntimeError(f"Fallo al crear acceso directo en el escritorio: {e}") from e
    else:
        # Fallback simulado para entornos fuera de Windows
        shortcut_path.write_text(f"[Desktop Entry]\nExec={target}\nPath={project_root}\n")
        return str(shortcut_path)


def is_autostart_enabled() -> bool:
    """
    Comprueba si el inicio automático está configurado en el Registro de Windows
    o en el Programador de Tareas.
    """
    if sys.platform != "win32":
        return False

    # 1. Comprobar Registro HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_READ,
        )
        try:
            val, _ = winreg.QueryValueEx(key, "SecureDeckHost")
            if val:
                return True
        finally:
            winreg.CloseKey(key)
    except Exception:
        pass

    # 2. Comprobar Programador de Tareas
    try:
        res = subprocess.run(
            ["schtasks", "/Query", "/TN", "SecureDeckHostAutoStart"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            return True
    except Exception:
        pass

    return False


def enable_autostart(minimized: bool = True) -> bool:
    """
    Registra el inicio automático con Windows fijando siempre el directorio del proyecto:
    1. Registro HKCU Run (ejecución al iniciar sesión).
    2. Si es Administrador, registra una tarea programada con /RL HIGHEST para elevación automática.
    """
    if sys.platform != "win32":
        return True

    project_root = get_project_root()
    bat_path = project_root / "Iniciar_SecureDeck.bat"
    arg_min = "--minimized" if minimized else ""

    # Comando seguro fijando el directorio de trabajo
    if bat_path.exists():
        run_cmd = f'cmd.exe /c "cd /d ""{project_root}"" && ""{bat_path}"" {arg_min}"'
    else:
        py_exe = sys.executable
        run_cmd = f'cmd.exe /c "cd /d ""{project_root}"" && ""{py_exe}"" -m host.main gui {arg_min}"'

    success = False

    # 1. Escribir en Registro de Windows HKCU
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE,
        )
        try:
            winreg.SetValueEx(key, "SecureDeckHost", 0, winreg.REG_SZ, run_cmd)
            success = True
            logger.info("Auto-arranque configurado en Registro HKCU\\...\\Run")
        finally:
            winreg.CloseKey(key)
    except Exception as e:
        logger.error("Error al registrar auto-arranque en Registro HKCU: %s", e)

    # 2. Si cuenta con permisos de administrador, registrar tarea programada elevada
    try:
        from host.engine.handlers.unlock import is_elevated_admin
        if is_elevated_admin():
            task_target = str(bat_path) if bat_path.exists() else f'"{sys.executable}" -m host.main gui'
            task_cmd = f'"{task_target}" {arg_min}'.strip()
            res = subprocess.run(
                [
                    "schtasks",
                    "/Create",
                    "/TN",
                    "SecureDeckHostAutoStart",
                    "/TR",
                    f'cmd.exe /c "cd /d ""{project_root}"" && {task_cmd}"',
                    "/SC",
                    "ONLOGON",
                    "/RL",
                    "HIGHEST",
                    "/F",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res.returncode == 0:
                logger.info("Tarea programada SecureDeckHostAutoStart registrada con privilegios HIGHEST.")
                success = True
            else:
                logger.warning("Fallo al registrar tarea programada: %s", res.stderr)
    except Exception as ex:
        logger.debug("No se pudo registrar la tarea programada elevada: %s", ex)

    return success


def disable_autostart() -> bool:
    """
    Elimina el inicio automático tanto del Registro como del Programador de Tareas.
    """
    if sys.platform != "win32":
        return True

    # 1. Eliminar del Registro HKCU
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE,
        )
        try:
            winreg.DeleteValue(key, "SecureDeckHost")
            logger.info("Entrada SecureDeckHost eliminada de HKCU\\...\\Run")
        finally:
            winreg.CloseKey(key)
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.debug("Error al eliminar entrada del Registro HKCU: %s", e)

    # 2. Eliminar Tarea Programada si existe
    try:
        subprocess.run(
            ["schtasks", "/Delete", "/TN", "SecureDeckHostAutoStart", "/F"],
            capture_output=True,
            timeout=5,
        )
        logger.info("Tarea programada SecureDeckHostAutoStart eliminada.")
    except Exception:
        pass

    return True
