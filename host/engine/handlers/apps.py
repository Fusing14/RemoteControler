"""
Manejador seguro de lanzamiento de aplicaciones y apertura de URLs.
Principio rector: Cero rutas a binarios arbitrarios. Ejecución delegada a protocolos oficiales
y accesos directos descubiertos del sistema.
"""

import sys
import ctypes
import webbrowser
import urllib.parse
from ctypes import wintypes
from typing import Optional

from host.engine.contracts.commands import AppPlatform, AppLaunchPayload

SW_SHOWNORMAL = 1


class AppLaunchError(Exception):
    """Excepción para errores al despachar la ejecución de una aplicación o URL."""
    pass


def launch_uri_safely(uri: str, error_context: str = "URI") -> None:
    """
    Invoca ShellExecuteW de forma segura sobre una URI de protocolo registrada.
    """
    if sys.platform != "win32":
        raise RuntimeError("El lanzador de aplicaciones solo es compatible con Windows.")

    shell32 = ctypes.windll.shell32
    shell32.ShellExecuteW.argtypes = [
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    ]
    shell32.ShellExecuteW.restype = wintypes.HINSTANCE

    h_inst = shell32.ShellExecuteW(
        None,
        "open",
        uri,
        None,
        None,
        SW_SHOWNORMAL,
    )

    h_inst_val = ctypes.cast(h_inst, ctypes.c_void_p).value or 0
    if h_inst_val <= 32:
        raise AppLaunchError(
            f"ShellExecuteW falló al invocar {error_context}. Código Win32: {h_inst_val}"
        )


def execute_game_launch(platform: str, game_id: str) -> None:
    """
    Lanza un juego de Steam o Epic Games a través de su protocolo registrado.
    """
    plat = platform.lower().strip()
    clean_id = game_id.strip()

    if plat == "steam":
        if not clean_id.isdigit() or not (1 <= int(clean_id) <= 2147483647):
            raise AppLaunchError(f"Steam AppID no válido: {game_id}")
        steam_uri = f"steam://rungameid/{clean_id}"
        launch_uri_safely(steam_uri, "URI de Steam")

    elif plat == "epic":
        from host.core.discovery.game_scanner import scan_epic_games

        epic_games = scan_epic_games()
        target_game = next((g for g in epic_games if g["game_id"].lower() == clean_id.lower()), None)
        if target_game and "launch_cmd" in target_game:
            uri = target_game["launch_cmd"]
        else:
            uri = f"com.epicgames.launcher://apps/{clean_id}?action=launch&silent=true"
        launch_uri_safely(uri, "URI de Epic Games")

    else:
        raise AppLaunchError(f"Plataforma de juego desconocida: {platform}")


def execute_app_command(payload: AppLaunchPayload) -> None:
    """
    Lanza una aplicación mediante el protocolo del sistema registrado o acceso directo.
    """
    if payload.platform == AppPlatform.STEAM:
        if payload.app_id is None:
            raise AppLaunchError("Falta app_id para plataforma STEAM.")
        execute_game_launch("steam", str(payload.app_id))
    elif payload.platform == AppPlatform.SYSTEM:
        from host.core.discovery.app_scanner import launch_system_app
        launch_system_app(target_path=payload.target_path, app_id=str(payload.app_id) if payload.app_id else None)
    else:
        raise AppLaunchError(f"Plataforma de aplicación no soportada: {payload.platform}")


def execute_open_url(url: str) -> str:
    """
    Abre una URL estrictamente validada en el navegador web predeterminado del sistema.
    Retorna la URL abierta.
    """
    raw = url.strip()
    if not (raw.startswith("http://") or raw.startswith("https://")):
        raw = f"https://{raw}"

    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise AppLaunchError(f"Esquema o formato de URL inválido: {url}")

    try:
        webbrowser.open(raw, new=2)
        return raw
    except Exception as e:
        raise AppLaunchError(f"Error al abrir la URL en el navegador: {e}") from e
