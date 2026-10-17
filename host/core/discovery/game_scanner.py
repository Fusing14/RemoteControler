"""
Escáner y detector de juegos instalados (Steam y Epic Games Launcher).
Permite listar títulos instalados y construir URIs seguras de lanzamiento.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger("RemoteControler.GameScanner")

# Títulos de soporte o redistribuibles que no son juegos interactivos
EXCLUDED_STEAM_NAMES = (
    "steamworks common redistributables",
    "steam linux runtime",
    "proton",
    "dedicated server",
    "steamvr",
    "software development kit",
    "soundtrack",
    "artbook",
)

EXCLUDED_STEAM_APPIDS = {
    228980,  # Steamworks Common Redistributables
    250820,  # SteamVR
}


def get_steam_install_path() -> Optional[Path]:
    """
    Localiza la ruta base de instalación de Steam en Windows.
    Consulta el Registro y rutas estándar de sistema.
    """
    # 1. Intentar Registro de Windows
    try:
        import winreg  # type: ignore

        # HKCU\Software\Valve\Steam -> SteamPath
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as key:
                val, _ = winreg.QueryValueEx(key, "SteamPath")
                if val and os.path.isdir(val):
                    return Path(val)
        except OSError:
            pass

        # HKLM\SOFTWARE\WOW6432Node\Valve\Steam -> InstallPath
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam") as key:
                val, _ = winreg.QueryValueEx(key, "InstallPath")
                if val and os.path.isdir(val):
                    return Path(val)
        except OSError:
            pass
    except ImportError:
        pass

    # 2. Rutas estándar en discos del sistema
    candidates = [
        Path(r"C:\Program Files (x86)\Steam"),
        Path(r"C:\Program Files\Steam"),
        Path(r"D:\Steam"),
        Path(r"E:\Steam"),
    ]
    for c in candidates:
        if c.is_dir():
            return c

    return None


def get_steam_library_folders(steam_path: Path) -> List[Path]:
    """
    Parsea libraryfolders.vdf para localizar todas las bibliotecas de Steam
    distribuidas a lo largo de los discos.
    """
    folders = [steam_path]
    vdf_candidates = [
        steam_path / "steamapps" / "libraryfolders.vdf",
        steam_path / "config" / "libraryfolders.vdf",
    ]

    for vdf_file in vdf_candidates:
        if vdf_file.is_file():
            try:
                content = vdf_file.read_text(encoding="utf-8", errors="ignore")
                matches = re.findall(r'"path"\s+"([^"]+)"', content)
                for raw_path in matches:
                    clean_path = Path(raw_path.replace(r"\\", os.sep))
                    if clean_path.is_dir() and clean_path not in folders:
                        folders.append(clean_path)
            except Exception as e:
                logger.warning("Error al leer %s: %s", vdf_file, e)

    return folders


def parse_acf_manifest(acf_file: Path) -> Optional[Dict[str, Any]]:
    """
    Extrae la información de juego de un archivo appmanifest_*.acf de Steam.
    """
    try:
        content = acf_file.read_text(encoding="utf-8", errors="ignore")
        appid_match = re.search(r'"appid"\s+"(\d+)"', content)
        name_match = re.search(r'"name"\s+"([^"]+)"', content)

        if not appid_match or not name_match:
            return None

        appid = int(appid_match.group(1))
        name = name_match.group(1).strip()

        if appid <= 0 or not name:
            return None

        if appid in EXCLUDED_STEAM_APPIDS:
            return None

        name_lower = name.lower()
        if any(exc in name_lower for exc in EXCLUDED_STEAM_NAMES):
            return None

        return {
            "id": f"steam_{appid}",
            "game_id": str(appid),
            "name": name,
            "platform": "steam",
            "launch_cmd": f"steam://rungameid/{appid}",
        }
    except Exception as e:
        logger.debug("Error procesando manifiesto %s: %s", acf_file, e)
        return None


def scan_steam_games(custom_steam_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Escanea y retorna todos los juegos instalados en Steam.
    """
    steam_path = Path(custom_steam_path) if custom_steam_path else get_steam_install_path()
    if not steam_path or not steam_path.is_dir():
        return []

    games: Dict[str, Dict[str, Any]] = {}
    libraries = get_steam_library_folders(steam_path)

    for lib in libraries:
        steamapps_dir = lib / "steamapps"
        if not steamapps_dir.is_dir():
            continue

        for acf in steamapps_dir.glob("appmanifest_*.acf"):
            game_data = parse_acf_manifest(acf)
            if game_data and game_data["game_id"] not in games:
                games[game_data["game_id"]] = game_data

    return list(games.values())


def scan_epic_games(manifests_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Escanea y retorna todos los juegos instalados a través de Epic Games Launcher.
    """
    target_dir = Path(manifests_dir) if manifests_dir else Path(r"C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests")
    if not target_dir.is_dir():
        return []

    games: List[Dict[str, Any]] = []

    for item_file in target_dir.glob("*.item"):
        try:
            content = item_file.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(content)

            display_name = data.get("DisplayName", "").strip()
            app_name = data.get("AppName", "").strip()
            catalog_ns = data.get("CatalogNamespace", "").strip()
            catalog_item_id = data.get("CatalogItemId", "").strip()
            main_game = data.get("MainGameAppName", "").strip()

            if not display_name or not app_name:
                continue

            # Si MainGameAppName existe y no coincide con AppName, es un DLC o complemento
            if main_game and main_game != app_name:
                continue

            # Omitir herramientas internas del motor
            if display_name.lower() in ("unreal engine", "epic games launcher"):
                continue

            uri = f"com.epicgames.launcher://apps/{catalog_ns}%3A{catalog_item_id}%3A{app_name}?action=launch&silent=true"

            games.append({
                "id": f"epic_{app_name}",
                "game_id": app_name,
                "name": display_name,
                "platform": "epic",
                "launch_cmd": uri,
                "catalog_namespace": catalog_ns,
                "catalog_item_id": catalog_item_id,
            })
        except Exception as e:
            logger.debug("Error procesando archivo Epic %s: %s", item_file, e)

    return games


def scan_installed_games(
    steam_path: Optional[str] = None,
    epic_manifests_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Escanea todos los juegos de Steam y Epic Games, devolviéndolos ordenados
    alfabéticamente por nombre.
    """
    all_games: List[Dict[str, Any]] = []
    all_games.extend(scan_steam_games(steam_path))
    all_games.extend(scan_epic_games(epic_manifests_dir))

    all_games.sort(key=lambda g: g["name"].lower())
    return all_games
