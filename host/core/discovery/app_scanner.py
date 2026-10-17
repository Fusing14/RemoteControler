"""
Módulo de autodetección y lanzamiento seguro de aplicaciones instaladas en Windows.
Escanea accesos directos (.lnk) en el Menú Inicio de usuario y sistema,
filtrando utilidades de desinstalación, documentación y componentes auxiliares.
"""

import hashlib
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("RemoteControler.AppScanner")

# Palabras clave excluidas para filtrar desinstaladores y documentación
EXCLUDED_KEYWORDS = (
    "uninstall",
    "desinstal",
    "remove",
    "help",
    "ayuda",
    "documentation",
    "documentaci",
    "readme",
    "leeme",
    "license",
    "licencia",
    "configur",
    "settings",
    "update",
    "actualiz",
    "installer",
    "setup",
    "repair",
    "reparar",
    "crash",
    "report",
)


def get_start_menu_directories() -> List[Path]:
    """Retorna las rutas a los directorios del Menú Inicio en Windows."""
    dirs: List[Path] = []
    if sys.platform != "win32":
        return dirs

    appdata = os.environ.get("APPDATA")
    if appdata:
        user_programs = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
        if user_programs.exists():
            dirs.append(user_programs)

    progdata = os.environ.get("ProgramData") or os.environ.get("ALLUSERSPROFILE")
    if progdata:
        sys_programs = Path(progdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
        if sys_programs.exists():
            dirs.append(sys_programs)

    return dirs


def _generate_app_id(target_path: Path) -> str:
    """Genera un identificador alfanumérico seguro para la aplicación basado en su ruta."""
    path_str = str(target_path.resolve()).lower()
    return hashlib.sha256(path_str.encode("utf-8")).hexdigest()[:16]


def is_app_excluded(name: str) -> bool:
    """Determina si el nombre de la aplicación corresponde a un desinstalador o documentación."""
    lower = name.lower()
    for kw in EXCLUDED_KEYWORDS:
        if kw in lower:
            return True
    return False


def scan_installed_apps(custom_dirs: Optional[List[Path | str]] = None) -> List[Dict[str, Any]]:
    """
    Escanea las aplicaciones instaladas en el Menú Inicio de Windows.
    Retorna una lista ordenada de diccionarios:
    [{"app_id": str, "name": str, "target_path": str}]
    """
    search_dirs: List[Path] = []
    if custom_dirs is not None:
        search_dirs = [Path(d) for d in custom_dirs if Path(d).exists()]
    else:
        search_dirs = get_start_menu_directories()

    discovered_apps: Dict[str, Dict[str, Any]] = {}

    for base_dir in search_dirs:
        try:
            for item in base_dir.rglob("*.lnk"):
                name = item.stem.strip()
                if not name or is_app_excluded(name):
                    continue

                norm_key = name.lower()
                if norm_key in discovered_apps:
                    continue

                app_id = _generate_app_id(item)
                discovered_apps[norm_key] = {
                    "app_id": app_id,
                    "name": name,
                    "target_path": str(item.resolve()),
                }
        except Exception as e:
            logger.warning("Error explorando directorio de inicio %s: %s", base_dir, e)

    # Ordenar alfabéticamente por nombre
    apps_list = sorted(discovered_apps.values(), key=lambda a: a["name"].lower())
    logger.info("Escáner de aplicaciones completado: %d aplicaciones encontradas.", len(apps_list))
    return apps_list


def launch_system_app(target_path: Optional[str] = None, app_id: Optional[str] = None) -> bool:
    """
    Lanza de forma segura una aplicación del sistema usando ShellExecuteW o os.startfile.
    Verifica que el archivo exista y sea un acceso directo o ejecutable.
    """
    resolved_path: Optional[str] = target_path

    if not resolved_path and app_id:
        apps = scan_installed_apps()
        found = next((a for a in apps if a["app_id"] == app_id), None)
        if found:
            resolved_path = found["target_path"]

    if not resolved_path:
        raise ValueError("No se especificó una aplicación válida para iniciar.")

    path_obj = Path(resolved_path)
    if not path_obj.exists():
        raise FileNotFoundError(f"La aplicación solicitada no existe en disco: {resolved_path}")

    ext = path_obj.suffix.lower()
    if ext not in (".lnk", ".exe"):
        raise ValueError(f"Extensión no permitida para ejecución segura: {ext}")

    if sys.platform == "win32":
        try:
            os.startfile(str(path_obj.resolve()))
            logger.info("Aplicación iniciada exitosamente: %s", path_obj.name)
            return True
        except Exception as e:
            logger.error("Error al iniciar aplicación con os.startfile: %s", e)
            raise RuntimeError(f"Fallo al ejecutar la aplicación: {e}") from e
    else:
        logger.info("Entorno no-Windows; lanzamiento de aplicación simulado (%s).", path_obj.name)
        return True
