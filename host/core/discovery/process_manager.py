"""
Gestor de procesos y aplicaciones activas en Windows (Running Apps Manager).
Permite enumerar las ventanas visibles de aplicaciones de usuario en el escritorio
y cerrarlas de forma ordenada (WM_CLOSE) o forzada (TerminateProcess/taskkill).
Incluye protecciones estrictas para evitar el cierre accidental de procesos críticos del sistema.
"""

import ctypes
from ctypes import wintypes
import logging
import os
import subprocess
import sys
import time
from typing import List, Dict, Any, Optional

logger = logging.getLogger("RemoteControler.ProcessManager")

# Procesos críticos del sistema operativo o componentes del entorno que nunca deben cerrarse
PROTECTED_PROCESS_NAMES = {
    "system",
    "idle",
    "explorer.exe",
    "csrss.exe",
    "winlogon.exe",
    "svchost.exe",
    "lsass.exe",
    "smss.exe",
    "services.exe",
    "dwm.exe",
    "spoolsv.exe",
    "sihost.exe",
    "fontdrvhost.exe",
}

# Procesos o ventanas internas de Windows a ignorar en el listado de aplicaciones de usuario
IGNORED_WINDOW_NAMES = {
    "textinputhost.exe",
    "shellexperiencehost.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "lockapp.exe",
}

IGNORED_WINDOW_TITLES = {
    "program manager",
    "start",
    "msctfime ui",
    "default ime",
    "cortana",
    "windows input experience",
}


class AppCloseError(Exception):
    """Error al intentar cerrar un proceso."""
    pass


class AppCloseSecurityError(AppCloseError):
    """Error cuando se intenta cerrar un proceso crítico o no autorizado."""
    pass


def get_process_name_by_pid(pid: int) -> str:
    """Obtiene el nombre del ejecutable a partir de su Process ID."""
    if sys.platform != "win32":
        return "mock_app.exe"

    kernel32 = ctypes.windll.kernel32
    # PROCESS_QUERY_LIMITED_INFORMATION (0x1000) funciona incluso sin privilegios de administrador
    h_proc = kernel32.OpenProcess(0x1000, False, pid)
    if not h_proc:
        return "Unknown"

    try:
        buf = ctypes.create_unicode_buffer(512)
        size = wintypes.DWORD(512)
        if kernel32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value)
        return "Unknown"
    finally:
        kernel32.CloseHandle(h_proc)


def list_running_apps() -> List[Dict[str, Any]]:
    """
    Enumera las aplicaciones reales que el usuario tiene abiertas con ventanas visibles en Windows.
    Filtra procesos en segundo plano, ventanas invisibles o herramientas de sistema.
    """
    if sys.platform != "win32":
        return [
            {"pid": 1234, "name": "Code.exe", "title": "VS Code - RemoteControler", "hwnd": 1001},
            {"pid": 5678, "name": "chrome.exe", "title": "Google Chrome", "hwnd": 1002},
        ]

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    dwmapi = ctypes.windll.dwmapi

    # Intentar obtener el escritorio interactivo activo
    h_input = user32.OpenInputDesktop(0, False, 0x0100)
    if not h_input:
        h_input = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())

    raw_apps = []

    def enum_cb(hwnd: int, lParam: int) -> bool:
        try:
            if not user32.IsWindowVisible(hwnd):
                return True

            length = user32.GetWindowTextLengthW(hwnd)
            if length == 0:
                return True

            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            title = buff.value.strip()
            if not title:
                return True

            # Filtrar títulos internos
            if title.lower() in IGNORED_WINDOW_TITLES:
                return True

            # Filtrar ventanas UWP 'cloaked' (suspendidas/ocultas en Windows 10/11)
            DWMWA_CLOAKED = 14
            cloaked = wintypes.DWORD(0)
            dwmapi.DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, ctypes.byref(cloaked), ctypes.sizeof(cloaked))
            if cloaked.value != 0:
                return True

            # Filtrar tooltips o barras de herramientas flotantes que no sean ventanas de app
            GWL_EXSTYLE = -20
            WS_EX_TOOLWINDOW = 0x00000080
            WS_EX_APPWINDOW = 0x00040000
            ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            if (ex_style & WS_EX_TOOLWINDOW) and not (ex_style & WS_EX_APPWINDOW):
                return True

            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value <= 4:
                return True

            name = get_process_name_by_pid(pid.value)
            if name.lower() in IGNORED_WINDOW_NAMES:
                return True

            # Ignorar el explorador de Windows si solo tiene el Program Manager
            if name.lower() == "explorer.exe" and title in ("Program Manager", ""):
                return True

            raw_apps.append({
                "pid": int(pid.value),
                "name": name,
                "title": title,
                "hwnd": int(hwnd),
            })
        except Exception as ex:
            logger.debug("Error procesando ventana %s: %s", hwnd, ex)

        return True

    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    cb_func = WNDENUMPROC(enum_cb)

    if h_input:
        user32.EnumDesktopWindows(h_input, cb_func, 0)
    else:
        user32.EnumWindows(cb_func, 0)

    # Deduplicar por PID manteniendo la ventana más descriptiva/larga
    by_pid: Dict[int, Dict[str, Any]] = {}
    for app in raw_apps:
        pid = app["pid"]
        if pid not in by_pid:
            by_pid[pid] = app
        else:
            # Si ya existe, preferir títulos más descriptivos o ventanas principales
            if len(app["title"]) > len(by_pid[pid]["title"]):
                by_pid[pid] = app

    result = list(by_pid.values())
    result.sort(key=lambda a: a["name"].lower())
    return result


def close_running_app(pid: int, force: bool = False) -> Dict[str, Any]:
    """
    Cierra una aplicación activa por su Process ID (PID).
    Protege ante el cierre del propio host o procesos del núcleo del sistema.
    """
    current_pid = os.getpid()
    if pid == current_pid:
        raise AppCloseSecurityError("Operación denegada: No es posible cerrar el proceso del propio servidor Host.")

    if pid <= 4:
        raise AppCloseSecurityError("Operación denegada: Proceso protegido del sistema operativo.")

    proc_name = get_process_name_by_pid(pid).lower()
    if proc_name in PROTECTED_PROCESS_NAMES:
        raise AppCloseSecurityError(f"Operación denegada: El proceso '{proc_name}' es crítico para el sistema.")

    if sys.platform != "win32":
        # Simulación segura para pruebas multiplataforma / CI
        return {"pid": pid, "name": proc_name, "closed": True, "force": force}

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    WM_CLOSE = 0x0010

    if not force:
        # 1. Cierre elegante: enviar mensaje WM_CLOSE a todas las ventanas asociadas
        hwnds_to_close = []

        def find_windows_cb(hwnd: int, lParam: int) -> bool:
            w_pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(w_pid))
            if w_pid.value == pid:
                hwnds_to_close.append(hwnd)
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user32.EnumWindows(WNDENUMPROC(find_windows_cb), 0)

        for hwnd in hwnds_to_close:
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)

        # Esperar brevemente a que el proceso termine por las buenas
        time.sleep(0.3)

        # Comprobar si aún sigue vivo
        h_proc = kernel32.OpenProcess(0x1000, False, pid)
        if not h_proc:
            return {"pid": pid, "name": proc_name, "closed": True, "force": False}
        kernel32.CloseHandle(h_proc)

        # Enviar taskkill sin /F como segundo intento limpio si tenía ventanas ocultas
        try:
            subprocess.run(["taskkill", "/PID", str(pid)], capture_output=True, text=True, timeout=3)
        except Exception as e:
            logger.debug("taskkill suave devolvió: %s", e)

        return {"pid": pid, "name": proc_name, "closed": True, "force": False}

    else:
        # 2. Cierre forzado: TerminateProcess / taskkill /F
        h_proc = kernel32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE = 0x0001
        terminated = False
        if h_proc:
            try:
                res = kernel32.TerminateProcess(h_proc, 1)
                terminated = bool(res)
            finally:
                kernel32.CloseHandle(h_proc)

        if not terminated:
            try:
                res = subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True, timeout=3)
                if res.returncode != 0 and "no encontrado" not in res.stderr.lower():
                    raise AppCloseError(f"Fallo al forzar el cierre del PID {pid}: {res.stderr.strip()}")
            except Exception as e:
                raise AppCloseError(f"Error al terminar proceso: {e}") from e

        return {"pid": pid, "name": proc_name, "closed": True, "force": True}
