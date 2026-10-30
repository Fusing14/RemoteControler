"""
Módulo de gestión del auto-arranque con Windows y creación de accesos directos.
Configura el inicio automático mediante:
1. Registro de Windows (HKCU\\...\\Run) con rutas absolutas entrecomilladas.
2. Programador de Tareas (schtasks con elevación /RL HIGHEST en ONLOGON y ONSTART pre-login)
   para que el Host escuche peticiones de desbloqueo tanto en sesión iniciada como tras
   un arranque en frío (Wake-on-LAN pre-login).
Mitiga CWE-78 (sin interpolación de rutas en PowerShell) y CWE-426/427 (Unquoted Service Paths).
"""

import logging
import os
import subprocess
import sys
from pathlib import Path

from host.core.security.path_security import quote_executable_path, resolve_system_binary

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
    Pasa las rutas mediante variables de entorno del proceso hijo para evitar CWE-78.
    """
    project_root = get_project_root()
    bat_path = project_root / "Iniciar_SecureDeck.bat"
    desktop = get_desktop_path()
    shortcut_path = desktop / "SecureDeck Host.lnk"

    target = str(bat_path) if bat_path.exists() else sys.executable
    args = "" if bat_path.exists() else "-m host.main gui"

    if sys.platform == "win32":
        try:
            ps_bin = resolve_system_binary("powershell.exe")
            ps_script = (
                "$ws = New-Object -ComObject WScript.Shell; "
                "$s = $ws.CreateShortcut($env:SD_SHORTCUT_PATH); "
                "$s.TargetPath = $env:SD_TARGET_PATH; "
                "$s.Arguments = $env:SD_ARGS; "
                "$s.WorkingDirectory = $env:SD_WORK_DIR; "
                "$s.Description = 'SecureDeck Host - Control Remoto Zero-Trust para Windows 11'; "
                "$s.IconLocation = 'shell32.dll,15'; "
                "$s.Save()"
            )
            env = os.environ.copy()
            env["SD_SHORTCUT_PATH"] = str(shortcut_path)
            env["SD_TARGET_PATH"] = str(target)
            env["SD_ARGS"] = str(args)
            env["SD_WORK_DIR"] = str(project_root)

            subprocess.run(
                [ps_bin, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                check=True,
                capture_output=True,
                env=env,
                timeout=10,
            )
            logger.info("Acceso directo creado exitosamente en: %s", shortcut_path)
            return str(shortcut_path)
        except Exception as e:
            logger.error("Error al crear acceso directo mediante PowerShell COM: %s", e)
            raise RuntimeError(f"Fallo al crear acceso directo en el escritorio: {e}") from e
    else:
        shortcut_path.parent.mkdir(parents=True, exist_ok=True)
        shortcut_path.write_text(f"[Desktop Entry]\nExec={target}\nPath={project_root}\n", encoding="utf-8")
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
        schtasks_bin = resolve_system_binary("schtasks.exe")
        res = subprocess.run(
            [schtasks_bin, "/Query", "/TN", "SecureDeckHostAutoStart"],
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
    Registra el inicio automático con Windows fijando siempre el directorio del proyecto
    con rutas absolutas entrecomilladas (mitigación CWE-426 / CWE-427):
    1. Registro HKCU Run (ejecución al iniciar sesión).
    2. Si es Administrador:
       - Tarea programada 'SecureDeckHostAutoStart' (/SC ONLOGON /RL HIGHEST) para sesión interactiva elevada.
       - Tarea programada 'SecureDeckHostBootStart' (/SC ONSTART /RU SYSTEM /RL HIGHEST) para escuchar
         en la pantalla de pre-login tras encender el PC por Wake-on-LAN.
    """
    if sys.platform != "win32":
        return True

    project_root = get_project_root()
    bat_path = project_root / "Iniciar_SecureDeck.bat"
    cmd_bin = resolve_system_binary("cmd.exe")
    arg_min = "--minimized" if minimized else ""

    quoted_cmd = quote_executable_path(cmd_bin)
    if bat_path.exists():
        run_cmd = f'{quoted_cmd} /c "cd /d ""{project_root}"" && ""{bat_path}"" {arg_min}"'
    else:
        py_exe = sys.executable
        run_cmd = f'{quoted_cmd} /c "cd /d ""{project_root}"" && ""{py_exe}"" -m host.main gui {arg_min}"'

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

    # 2. Si cuenta con permisos de administrador, registrar tareas programadas elevadas
    try:
        from host.engine.handlers.unlock import is_elevated_admin
        if is_elevated_admin():
            schtasks_bin = resolve_system_binary("schtasks.exe")
            if bat_path.exists():
                task_action = f'{quoted_cmd} /c "cd /d ""{project_root}"" && ""{bat_path}"" {arg_min}"'
            else:
                task_action = f'{quoted_cmd} /c "cd /d ""{project_root}"" && ""{sys.executable}"" -m host.main gui {arg_min}"'

            # 2a. Tarea ONLOGON con privilegios HIGHEST para tener acceso a Winlogon sin prompt UAC
            res_logon = subprocess.run(
                [
                    schtasks_bin,
                    "/Create",
                    "/TN",
                    "SecureDeckHostAutoStart",
                    "/TR",
                    task_action,
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
            if res_logon.returncode == 0:
                logger.info("Tarea programada SecureDeckHostAutoStart (ONLOGON /RL HIGHEST) registrada.")
                success = True
            else:
                logger.warning("Fallo al registrar SecureDeckHostAutoStart: %s", res_logon.stderr)

            # 2b. Tarea ONSTART (pre-login tras Cold Boot / Wake-on-LAN) en modo headless
            boot_action = f'{quoted_cmd} /c "cd /d ""{project_root}"" && ""{sys.executable}"" -m host.main"'
            res_boot = subprocess.run(
                [
                    schtasks_bin,
                    "/Create",
                    "/TN",
                    "SecureDeckHostBootStart",
                    "/TR",
                    boot_action,
                    "/SC",
                    "ONSTART",
                    "/RU",
                    "NT AUTHORITY\\SYSTEM",
                    "/RL",
                    "HIGHEST",
                    "/F",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res_boot.returncode == 0:
                logger.info("Tarea programada SecureDeckHostBootStart (ONSTART pre-login) registrada.")
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

    # 2. Eliminar Tareas Programadas si existen
    try:
        schtasks_bin = resolve_system_binary("schtasks.exe")
        for task_name in ("SecureDeckHostAutoStart", "SecureDeckHostBootStart"):
            subprocess.run(
                [schtasks_bin, "/Delete", "/TN", task_name, "/F"],
                capture_output=True,
                timeout=5,
            )
        logger.info("Tareas programadas de auto-arranque eliminadas.")
    except Exception:
        pass

    return True
