"""
Manejador seguro de lanzamiento de aplicaciones mediante identificadores registrados.
Principio rector: Cero rutas a binarios arbitrarios. Ejecución delegada a protocolos oficiales.
"""

import sys
import ctypes
from ctypes import wintypes
from typing import Optional

from host.engine.contracts.commands import AppPlatform, AppLaunchPayload

SW_SHOWNORMAL = 1


class AppLaunchError(Exception):
    """Excepción para errores al despachar la ejecución de una aplicación."""
    pass


def execute_app_command(payload: AppLaunchPayload) -> None:
    """
    Lanza una aplicación mediante el protocolo del sistema registrado.
    
    Mitigación de Vectores de Ataque:
    1. Previene Path Traversal y Arbitrary Binary Execution:
       - Se prohíbe la carga de rutas como 'C:\\...\\malicious.exe'.
       - Solo se acepta un app_id numérico de Steam que se traduce a la URI oficial
         'steam://rungameid/<id>'.
    2. Zero Subshells:
       - No se invoca 'cmd /c start ...' ni PowerShell.
       - Se invoca directamente ShellExecuteW de shell32.dll.
    """
    if sys.platform != "win32":
        raise RuntimeError("El lanzador de aplicaciones solo es compatible con Windows.")

    if payload.platform != AppPlatform.STEAM:
        raise AppLaunchError(f"Plataforma de aplicación no soportada: {payload.platform}")

    # Validación redundante de integridad sobre el AppID (entero positivo acotado)
    if not (1 <= payload.app_id <= 2147483647):
        raise AppLaunchError(f"Steam AppID fuera del rango válido: {payload.app_id}")

    steam_uri = f"steam://rungameid/{payload.app_id}"

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

    # Invocación directa a ShellExecuteW
    # Valor de retorno: Mayor a 32 si fue exitoso. Menor o igual a 32 representa código de error.
    h_inst = shell32.ShellExecuteW(
        None,           # hwnd
        "open",         # lpOperation
        steam_uri,      # lpFile (URI registrada de protocolo)
        None,           # lpParameters
        None,           # lpDirectory
        SW_SHOWNORMAL   # nShowCmd
    )

    h_inst_val = ctypes.cast(h_inst, ctypes.c_void_p).value or 0
    if h_inst_val <= 32:
        raise AppLaunchError(
            f"ShellExecuteW falló al invocar URI de Steam. Código Win32: {h_inst_val} "
            "(Verifique que el cliente de Steam esté instalado en el Host)"
        )
