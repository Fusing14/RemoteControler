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


TH32CS_SNAPPROCESS = 0x00000002


if sys.platform == "win32":
    class RECT(ctypes.Structure):
        _fields_ = [
            ("left", wintypes.LONG),
            ("top", wintypes.LONG),
            ("right", wintypes.LONG),
            ("bottom", wintypes.LONG),
        ]

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]
else:
    RECT = None  # type: ignore
    PROCESSENTRY32 = None  # type: ignore


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
    Enumera las aplicaciones en ejecución clasificadas en:
    1. 'primary': Ventanas principales interactivas en la barra de tareas (GW_OWNER == 0, visibles, no-cloaked, dimensiones válidas).
       Deduplicadas estrictamente por nombre de ejecutable para mostrar una única entrada representativa por aplicación.
       Ordena la ventana en primer plano (GetForegroundWindow) en primer lugar.
    2. 'background': Procesos secundarios de usuario en la misma sesión de Windows (sin ventana interactiva de barra de tareas).
    """
    if sys.platform != "win32":
        return [
            {"pid": 1234, "name": "Code.exe", "title": "VS Code - RemoteControler", "hwnd": 1001, "category": "primary", "is_foreground": True},
            {"pid": 5678, "name": "chrome.exe", "title": "Google Chrome", "hwnd": 1002, "category": "primary", "is_foreground": False},
            {"pid": 9012, "name": "spotify.exe", "title": "Spotify Free", "hwnd": 0, "category": "background", "is_foreground": False},
            {"pid": 3456, "name": "discord.exe", "title": "Discord Background", "hwnd": 0, "category": "background", "is_foreground": False},
        ]

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    dwmapi = ctypes.windll.dwmapi

    fg_hwnd = user32.GetForegroundWindow()

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

            lower_title = title.lower()

            # Filtrar títulos internos y overlays
            if lower_title in IGNORED_WINDOW_TITLES:
                return True

            if "overlay" in lower_title or "remotecontroler" in lower_title:
                return True

            # Filtrar ventanas UWP 'cloaked' (suspendidas/ocultas en Windows 10/11)
            DWMWA_CLOAKED = 14
            cloaked = wintypes.DWORD(0)
            dwmapi.DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, ctypes.byref(cloaked), ctypes.sizeof(cloaked))
            if cloaked.value != 0:
                return True

            # Filtrar tooltips, barras flotantes y overlays transparentes
            GWL_EXSTYLE = -20
            WS_EX_TOOLWINDOW = 0x00000080
            WS_EX_APPWINDOW = 0x00040000
            WS_EX_TRANSPARENT = 0x00000020
            ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            if (ex_style & WS_EX_TOOLWINDOW) and not (ex_style & WS_EX_APPWINDOW):
                return True
            if ex_style & WS_EX_TRANSPARENT:
                return True

            # Comprobar ventana propietaria (GW_OWNER = 4)
            GW_OWNER = 4
            owner = user32.GetWindow(hwnd, GW_OWNER)
            if owner != 0 and not (ex_style & WS_EX_APPWINDOW):
                # Es una ventana modal o popup secundario, no la ventana principal de la barra de tareas
                return True

            # Comprobar dimensiones mínimas de ventana (> 50x50 píxeles para ignorar elementos invisibles/ocultos)
            rect = RECT()
            if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                width = rect.right - rect.left
                height = rect.bottom - rect.top
                if width <= 50 or height <= 50:
                    return True

            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value <= 4 or pid.value == os.getpid():
                return True

            name = get_process_name_by_pid(pid.value)
            if not name or name == "Unknown":
                return True

            lower_name = name.lower()
            if lower_name in IGNORED_WINDOW_NAMES or lower_name in PROTECTED_PROCESS_NAMES:
                return True

            # Ignorar el explorador de Windows si solo tiene el Program Manager
            if lower_name == "explorer.exe" and title in ("Program Manager", ""):
                return True

            is_fg = bool(hwnd == fg_hwnd)
            raw_apps.append({
                "pid": int(pid.value),
                "name": name,
                "title": title,
                "hwnd": int(hwnd),
                "category": "primary",
                "is_foreground": is_fg,
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

    # Deduplicar estrictamente por nombre de ejecutable (name.lower())
    # manteniendo la ventana en primer plano o la que tenga el título más descriptivo
    by_name: Dict[str, Dict[str, Any]] = {}
    for app in raw_apps:
        key = app["name"].lower()
        if key not in by_name:
            by_name[key] = app
        else:
            if app.get("is_foreground") or (
                not by_name[key].get("is_foreground")
                and len(app["title"]) > len(by_name[key]["title"])
            ):
                by_name[key] = app

    primary_apps = list(by_name.values())
    # Ordenar: primero la ventana en primer plano si existe, luego orden alfabético
    primary_apps.sort(key=lambda a: (not a.get("is_foreground", False), a["name"].lower()))
    primary_pids = set(a["pid"] for a in primary_apps)
    primary_names = set(by_name.keys())

    # Enumerar procesos en segundo plano de la sesión de usuario
    background_apps: List[Dict[str, Any]] = []
    my_pid = os.getpid()
    my_sid = wintypes.DWORD()
    kernel32.ProcessIdToSessionId(my_pid, ctypes.byref(my_sid))

    h_snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h_snap and h_snap != -1:
        try:
            pe = PROCESSENTRY32()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
            if kernel32.Process32FirstW(h_snap, ctypes.byref(pe)):
                while True:
                    p_id = int(pe.th32ProcessID)
                    exe_name = str(pe.szExeFile)
                    lower_name = exe_name.lower()

                    if (
                        p_id > 4
                        and p_id != my_pid
                        and lower_name not in PROTECTED_PROCESS_NAMES
                        and lower_name not in IGNORED_WINDOW_NAMES
                        and p_id not in primary_pids
                        and lower_name not in primary_names
                    ):
                        proc_sid = wintypes.DWORD()
                        if kernel32.ProcessIdToSessionId(p_id, ctypes.byref(proc_sid)):
                            if proc_sid.value == my_sid.value:
                                background_apps.append({
                                    "pid": p_id,
                                    "name": exe_name,
                                    "title": exe_name,
                                    "hwnd": 0,
                                    "category": "background",
                                    "is_foreground": False,
                                })

                    if not kernel32.Process32NextW(h_snap, ctypes.byref(pe)):
                        break
        finally:
            kernel32.CloseHandle(h_snap)

    by_bg_name: Dict[str, Dict[str, Any]] = {}
    for bg_app in background_apps:
        k = bg_app["name"].lower()
        if k not in by_bg_name:
            by_bg_name[k] = bg_app
    background_apps = list(by_bg_name.values())
    background_apps.sort(key=lambda a: a["name"].lower())
    return primary_apps + background_apps


def close_running_app(pid: int, force: bool = False) -> Dict[str, Any]:
    """
    Cierra una aplicación activa por su Process ID (PID).
    Protege ante el cierre del propio host, proceso padre, procesos del núcleo
    o procesos pertenecientes a la sesión del sistema (Session 0).
    """
    if pid <= 0 or pid == 4:
        raise AppCloseSecurityError("Operación denegada: Proceso protegido del sistema operativo.")

    current_pid = os.getpid()
    if pid == current_pid:
        raise AppCloseSecurityError("Operación denegada: No es posible cerrar el proceso del propio servidor Host.")

    parent_pid = os.getppid() if hasattr(os, "getppid") else None
    if parent_pid is not None and pid == parent_pid:
        raise AppCloseSecurityError("Operación denegada: No es posible cerrar el proceso padre del servidor Host.")

    proc_name = get_process_name_by_pid(pid).lower()
    if proc_name in PROTECTED_PROCESS_NAMES:
        raise AppCloseSecurityError(f"Operación denegada: El proceso '{proc_name}' es crítico para el sistema.")

    if sys.platform != "win32":
        # Simulación segura para pruebas multiplataforma / CI
        return {"pid": pid, "name": proc_name, "closed": True, "force": force}

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    WM_CLOSE = 0x0010

    # Comprobar pertenencia de sesión en Windows
    my_sid = wintypes.DWORD()
    proc_sid = wintypes.DWORD()
    if kernel32.ProcessIdToSessionId(current_pid, ctypes.byref(my_sid)):
        if kernel32.ProcessIdToSessionId(pid, ctypes.byref(proc_sid)):
            if proc_sid.value == 0 and my_sid.value != 0:
                raise AppCloseSecurityError("Operación denegada: El proceso pertenece a la sesión de servicios del sistema (Session 0).")
            if proc_sid.value != my_sid.value:
                raise AppCloseSecurityError("Operación denegada: El proceso pertenece a otra sesión de usuario.")

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
