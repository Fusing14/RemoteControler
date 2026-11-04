"""
Manejador de interacción de ratón con precisión milimétrica (1:1 Touch-to-Mouse Mapping).
Soporte para escalado DPI, múltiples monitores e inyección mediante APIs nativas de Win32.
"""

import sys
import time
import ctypes
import logging
from ctypes import wintypes
from typing import Dict, Any, Tuple

logger = logging.getLogger("RemoteControler.MouseHandler")

# Constantes de Input de Win32
INPUT_MOUSE = 0
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_VIRTUALDESK = 0x4000

# Caché de DPI Awareness
_DPI_AWARE_CONFIGURED = False


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class INPUT_UNION(ctypes.Union):
    _fields_ = [
        ("mi", MOUSEINPUT),
    ]


class INPUT(ctypes.Structure):
    _fields_ = [
        ("type", wintypes.DWORD),
        ("union", INPUT_UNION),
    ]


class MouseExecutionError(Exception):
    """Excepción para errores al posicionar o inyectar eventos de ratón."""
    pass


def make_process_dpi_aware() -> bool:
    """
    Configura el proceso como Per-Monitor DPI Aware para que Windows no
    virtualice ni desvíe las coordenadas físicas al usar escalados de pantalla (125%, 150%, etc.).
    """
    global _DPI_AWARE_CONFIGURED
    if _DPI_AWARE_CONFIGURED or sys.platform != "win32":
        return True

    try:
        # Windows 10 Creators Update (1703) en adelante: Per-Monitor V2 (-4)
        u32 = ctypes.windll.user32
        res = u32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        if res:
            _DPI_AWARE_CONFIGURED = True
            return True
    except Exception:
        pass

    try:
        # Windows 8.1 / Windows 10: PROCESS_PER_MONITOR_DPI_AWARE = 2
        shcore = ctypes.windll.shcore
        res = shcore.SetProcessDpiAwareness(2)
        if res == 0:
            _DPI_AWARE_CONFIGURED = True
            return True
    except Exception:
        pass

    try:
        # Fallback Windows Vista / 7
        u32 = ctypes.windll.user32
        res = u32.SetProcessDPIAware()
        if res:
            _DPI_AWARE_CONFIGURED = True
            return True
    except Exception:
        pass

    _DPI_AWARE_CONFIGURED = True
    return False


def get_monitor_geometry(monitor_index: int = 1) -> Dict[str, int]:
    """
    Obtiene el rectángulo físico (left, top, width, height) del monitor solicitado.
    - monitor_index = 0: Todo el escritorio combinado multimonitor.
    - monitor_index >= 1: Monitor físico individual correspondiente.
    """
    make_process_dpi_aware()

    # 1. Intentar con MSS
    try:
        import mss
        with mss.MSS() as sct:
            total = len(sct.monitors)
            if monitor_index == 0:
                m = sct.monitors[0]
            elif 1 <= monitor_index < total:
                m = sct.monitors[monitor_index]
            else:
                m = sct.monitors[1 if total > 1 else 0]

            return {
                "left": int(m["left"]),
                "top": int(m["top"]),
                "width": int(m["width"]),
                "height": int(m["height"]),
            }
    except Exception as e:
        logger.debug("Error obteniendo geometría de monitores con MSS: %s", e)

    # 2. Fallback a Win32 GetSystemMetrics
    if sys.platform == "win32":
        try:
            u32 = ctypes.windll.user32
            # SM_XVIRTUALSCREEN = 76, SM_YVIRTUALSCREEN = 77, SM_CXVIRTUALSCREEN = 78, SM_CYVIRTUALSCREEN = 79
            # SM_CXSCREEN = 0, SM_CYSCREEN = 1
            if monitor_index == 0:
                left = int(u32.GetSystemMetrics(76))
                top = int(u32.GetSystemMetrics(77))
                width = int(u32.GetSystemMetrics(78))
                height = int(u32.GetSystemMetrics(79))
            else:
                left = 0
                top = 0
                width = int(u32.GetSystemMetrics(0))
                height = int(u32.GetSystemMetrics(1))
            return {"left": left, "top": top, "width": width, "height": height}
        except Exception as e:
            logger.debug("Error en fallback Win32 GetSystemMetrics: %s", e)

    # 3. Default seguro para pruebas / CI / headless
    return {"left": 0, "top": 0, "width": 1920, "height": 1080}


def map_normalized_to_screen_pixel(
    x_norm: float,
    y_norm: float,
    monitor_left: int,
    monitor_top: int,
    monitor_width: int,
    monitor_height: int,
) -> Tuple[int, int]:
    """
    Mapea coordenadas normalizadas [0.0, 1.0] al píxel físico exacto del monitor
    dentro del espacio global de coordenadas de Windows.
    Aplica clamping defensivo y redondeo exacto.
    """
    x_clamped = max(0.0, min(1.0, float(x_norm)))
    y_clamped = max(0.0, min(1.0, float(y_norm)))

    w_span = max(1, int(monitor_width) - 1)
    h_span = max(1, int(monitor_height) - 1)

    target_x = int(monitor_left) + int(round(x_clamped * w_span))
    target_y = int(monitor_top) + int(round(y_clamped * h_span))

    return target_x, target_y


def _sync_input_desktop() -> bool:
    """
    Sincroniza el hilo actual con el escritorio de entrada activo de Windows (Default o Winlogon)
    para evitar bloqueos o rechazos de permisos al inyectar eventos de ratón, sin bloquear el servidor.
    """
    if sys.platform != "win32":
        return True

    try:
        u32 = ctypes.windll.user32
        # GENERIC_ALL (0x10000000) o DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP (0x0180)
        h_desk = u32.OpenInputDesktop(0, False, 0x10000000)
        if not h_desk:
            h_desk = u32.OpenInputDesktop(0, False, 0x0180)
        if h_desk:
            try:
                u32.SetThreadDesktop(h_desk)
            finally:
                u32.CloseDesktop(h_desk)
            return True
    except Exception as e:
        logger.debug("Aviso no bloqueante sincronizando escritorio de entrada: %s", e)

    return False


def _send_mouse_event(flags: int, dx: int = 0, dy: int = 0, data: int = 0) -> None:
    """Envía un evento de ratón mediante SendInput (con dx=0, dy=0 tras SetCursorPos) y fallback a mouse_event."""
    if sys.platform != "win32":
        return

    u32 = ctypes.windll.user32
    try:
        inp = INPUT()
        inp.type = INPUT_MOUSE
        inp.union.mi.dx = int(dx)
        inp.union.mi.dy = int(dy)
        inp.union.mi.mouseData = int(data)
        inp.union.mi.dwFlags = int(flags)
        inp.union.mi.time = 0
        inp.union.mi.dwExtraInfo = 0

        sent = u32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
        if sent == 1:
            return
    except Exception as e:
        logger.debug("SendInput falló o no soportado, probando mouse_event: %s", e)

    # Fallback seguro a mouse_event sin bloquear el hilo en caso de restricción UIPI/Winlogon
    try:
        u32.mouse_event(int(flags), int(dx), int(dy), int(data), 0)
    except Exception as e:
        logger.warning("Fallo controlado al inyectar mouse_event (%#x): %s", flags, e)
        raise MouseExecutionError(f"Fallo al inyectar mouse_event ({flags:#x}): {e}") from e


def execute_mouse_click(
    x_norm: float,
    y_norm: float,
    button: str = "left",
    monitor_index: int = 1,
) -> Dict[str, Any]:
    """
    Posiciona el cursor con SetCursorPos y ejecuta la acción de ratón solicitada
    con precisión 1:1 en el píxel real del monitor capturado.

    Acciones soportadas:
    - 'left': Clic izquierdo.
    - 'right': Clic derecho.
    - 'middle': Clic central.
    - 'double_left': Doble clic izquierdo.
    - 'move': Desplazamiento del cursor sin clic.
    """
    make_process_dpi_aware()
    geom = get_monitor_geometry(monitor_index)
    target_x, target_y = map_normalized_to_screen_pixel(
        x_norm=x_norm,
        y_norm=y_norm,
        monitor_left=geom["left"],
        monitor_top=geom["top"],
        monitor_width=geom["width"],
        monitor_height=geom["height"],
    )

    btn = button.lower().strip()
    if btn not in ("left", "right", "middle", "double_left", "move"):
        raise ValueError(f"Acción de botón de ratón no reconocida: '{button}'")

    if sys.platform == "win32":
        _sync_input_desktop()
        u32 = ctypes.windll.user32

        # 1. Posicionar el cursor exactamente en el píxel físico calculado
        try:
            u32.SetCursorPos(int(target_x), int(target_y))
        except Exception as e:
            logger.warning("Error llamando a SetCursorPos(%d, %d): %s", target_x, target_y, e)

        # 2. Inyectar eventos de botón con dx=0, dy=0 (sin desplazamiento relativo adicional)
        if btn == "left":
            _send_mouse_event(MOUSEEVENTF_LEFTDOWN, dx=0, dy=0)
            _send_mouse_event(MOUSEEVENTF_LEFTUP, dx=0, dy=0)
        elif btn == "double_left":
            _send_mouse_event(MOUSEEVENTF_LEFTDOWN, dx=0, dy=0)
            _send_mouse_event(MOUSEEVENTF_LEFTUP, dx=0, dy=0)
            time.sleep(0.015)  # Pausa nativa corta (15ms) para reconocimiento en File Explorer
            _send_mouse_event(MOUSEEVENTF_LEFTDOWN, dx=0, dy=0)
            _send_mouse_event(MOUSEEVENTF_LEFTUP, dx=0, dy=0)
        elif btn == "right":
            _send_mouse_event(MOUSEEVENTF_RIGHTDOWN, dx=0, dy=0)
            _send_mouse_event(MOUSEEVENTF_RIGHTUP, dx=0, dy=0)
        elif btn == "middle":
            _send_mouse_event(MOUSEEVENTF_MIDDLEDOWN, dx=0, dy=0)
            _send_mouse_event(MOUSEEVENTF_MIDDLEUP, dx=0, dy=0)
        elif btn == "move":
            pass

    return {
        "status": "success",
        "target_x": target_x,
        "target_y": target_y,
        "button": btn,
        "monitor_index": monitor_index,
        "monitor_geometry": geom,
    }
