"""
Gestor de configuración persistente del Host de RemoteControler.
Almacena opciones de sesión y preferencias en %APPDATA%\\RemoteControler\\host_config.json
y gestiona la clave de inicio automático en el Registro de Windows (HKCU\\...\\Run).
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger("RemoteControler.HostConfig")

REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_APP_NAME = "RemoteControlerHost"


def get_app_data_dir() -> Path:
    """Retorna la ruta al directorio de datos de la aplicación en %APPDATA% o ~/.config."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        if base:
            path = Path(base) / "RemoteControler"
        else:
            path = Path.home() / "AppData" / "Roaming" / "RemoteControler"
    else:
        path = Path.home() / ".config" / "RemoteControler"

    path.mkdir(parents=True, exist_ok=True)
    return path


def get_config_file_path() -> Path:
    """Retorna la ruta completa al archivo host_config.json."""
    return get_app_data_dir() / "host_config.json"


class HostConfig:
    """Manejador seguro de lectura y escritura de configuración persistente del Host."""

    DEFAULT_CONFIG: Dict[str, Any] = {
        "keep_session_open": True,
        "auto_start": False,
        "port": 8443,
        "dev_mode": False,
    }

    def __init__(self, config_file: Path | None = None) -> None:
        self.config_path = config_file or get_config_file_path()
        self._data: Dict[str, Any] = {}
        self.load()

    def load(self) -> Dict[str, Any]:
        """Carga la configuración desde el archivo JSON si existe, o aplica los valores por defecto."""
        if self.config_path.exists():
            try:
                content = self.config_path.read_text(encoding="utf-8")
                loaded = json.loads(content)
                if isinstance(loaded, dict):
                    self._data = {**self.DEFAULT_CONFIG, **loaded}
                    return self._data
            except Exception as e:
                logger.warning("Error leyendo host_config.json, usando valores por defecto: %s", e)

        self._data = dict(self.DEFAULT_CONFIG)
        self.save()
        return self._data

    def save(self) -> None:
        """Guarda la configuración actual en disco de forma atómica."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self.config_path.with_suffix(".tmp")
            temp_path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            temp_path.replace(self.config_path)
        except Exception as e:
            logger.error("Error guardando host_config.json: %s", e)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value
        self.save()

    @property
    def keep_session_open(self) -> bool:
        return bool(self._data.get("keep_session_open", True))

    @keep_session_open.setter
    def keep_session_open(self, value: bool) -> None:
        self.set("keep_session_open", bool(value))

    @property
    def auto_start(self) -> bool:
        """Verifica si el auto-inicio está habilitado (comprobando registro en Windows si aplica)."""
        if sys.platform == "win32":
            return is_windows_auto_start_enabled()
        return bool(self._data.get("auto_start", False))

    @auto_start.setter
    def auto_start(self, value: bool) -> None:
        val = bool(value)
        self.set("auto_start", val)
        if sys.platform == "win32":
            set_windows_auto_start(val)


def is_windows_auto_start_enabled() -> bool:
    """Consulta el Registro de Windows (HKCU\\...\\Run) para ver si RemoteControlerHost está configurado."""
    if sys.platform != "win32":
        return False

    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_READ) as key:
            try:
                val, _ = winreg.QueryValueEx(key, REG_APP_NAME)
                return bool(val)
            except FileNotFoundError:
                return False
    except Exception as e:
        logger.warning("Error consultando clave Run del Registro: %s", e)
        return False


def set_windows_auto_start(enabled: bool) -> bool:
    """Configura o elimina la clave de inicio automático en el Registro de Windows."""
    if sys.platform != "win32":
        return False

    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                # Construir comando con pythonw si está disponible para evitar ventana de consola
                py_exe = sys.executable
                if "python.exe" in py_exe.lower():
                    pyw_exe = py_exe.lower().replace("python.exe", "pythonw.exe")
                    if os.path.exists(pyw_exe):
                        py_exe = pyw_exe

                cmd = f'"{py_exe}" -m host.main gui --minimized'
                winreg.SetValueEx(key, REG_APP_NAME, 0, winreg.REG_SZ, cmd)
                logger.info("Auto-arranque en Windows registrado: %s", cmd)
            else:
                try:
                    winreg.DeleteValue(key, REG_APP_NAME)
                    logger.info("Auto-arranque en Windows eliminado.")
                except FileNotFoundError:
                    pass
        return True
    except Exception as e:
        logger.error("Error modificando clave Run del Registro: %s", e)
        return False
