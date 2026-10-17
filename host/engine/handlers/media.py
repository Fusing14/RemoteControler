"""
Manejador multimedia nativo para Windows mediante Win32 user32.dll!SendInput.
Principio rector: Cero subshells. Los eventos se inyectan a nivel de hardware/kernel.
"""

import sys
import ctypes
from ctypes import wintypes
from typing import Optional

from host.engine.contracts.commands import MediaAction, MediaPayload

# Constantes de Virtual Key Codes de Windows
VK_VOLUME_MUTE = 0xAD
VK_VOLUME_DOWN = 0xAE
VK_VOLUME_UP = 0xAF
VK_MEDIA_NEXT_TRACK = 0xB0
VK_MEDIA_PREV_TRACK = 0xB1
VK_MEDIA_STOP = 0xB2
VK_MEDIA_PLAY_PAUSE = 0xB3

# Constantes de Input
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002

ACTION_TO_VK = {
    MediaAction.PLAY_PAUSE: VK_MEDIA_PLAY_PAUSE,
    MediaAction.NEXT_TRACK: VK_MEDIA_NEXT_TRACK,
    MediaAction.PREV_TRACK: VK_MEDIA_PREV_TRACK,
    MediaAction.VOLUME_UP: VK_VOLUME_UP,
    MediaAction.VOLUME_DOWN: VK_VOLUME_DOWN,
    MediaAction.VOLUME_MUTE: VK_VOLUME_MUTE,
}


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    ]


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
        ("ki", KEYBDINPUT),
        ("mi", MOUSEINPUT),
        ("hi", HARDWAREINPUT),
    ]


class INPUT(ctypes.Structure):
    _anonymous_ = ("_u",)
    _fields_ = [
        ("type", wintypes.DWORD),
        ("_u", INPUT_UNION),
    ]


class MediaExecutionError(Exception):
    """Excepción para errores en la emisión de inputs multimedia."""
    pass


def _get_user32():
    """Carga y configura user32.dll de forma segura."""
    if sys.platform != "win32":
        raise RuntimeError("El manejador de medios solo es compatible con Windows.")
    user32 = ctypes.windll.user32
    user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
    user32.SendInput.restype = wintypes.UINT
    user32.keybd_event.argtypes = [wintypes.BYTE, wintypes.BYTE, wintypes.DWORD, ctypes.c_size_t]
    user32.keybd_event.restype = None
    return user32


def send_virtual_key(vk_code: int) -> None:
    """
    Envía un evento de pulsación y liberación atómica de una tecla virtual mediante SendInput.
    Si SendInput es bloqueado o retorna 0, usa keybd_event como fallback seguro.
    
    Mitigación de Vectores de Ataque:
    - Previene inyecciones de comandos: No se generan cadenas de teclado de texto,
      solo códigos de tecla física predefinidos en una lista blanca inmutable.
    """
    user32 = _get_user32()

    # Preparar pulsación (Key Down)
    inp_down = INPUT()
    inp_down.type = INPUT_KEYBOARD
    inp_down.ki.wVk = vk_code
    inp_down.ki.wScan = 0
    inp_down.ki.dwFlags = 0
    inp_down.ki.time = 0
    inp_down.ki.dwExtraInfo = 0

    # Preparar liberación (Key Up)
    inp_up = INPUT()
    inp_up.type = INPUT_KEYBOARD
    inp_up.ki.wVk = vk_code
    inp_up.ki.wScan = 0
    inp_up.ki.dwFlags = KEYEVENTF_KEYUP
    inp_up.ki.time = 0
    inp_up.ki.dwExtraInfo = 0

    inputs = (INPUT * 2)(inp_down, inp_up)
    sent = user32.SendInput(2, inputs, ctypes.sizeof(INPUT))

    if sent != 2:
        # Fallback a keybd_event si SendInput fue interceptado por privilegios de UIPI
        user32.keybd_event(vk_code, 0, 0, 0)
        user32.keybd_event(vk_code, 0, KEYEVENTF_KEYUP, 0)


def execute_media_command(payload: MediaPayload) -> None:
    """
    Despacha un comando multimedia validado.
    
    Mitigación de Vectores de Ataque:
    - Control de saturación (Input Flooding / DoS): Para SET_VOLUME se impone un límite
      estricto e infranqueable de 50 pasos para evitar bucles infinitos de simulación de teclas.
    """
    if payload.action in ACTION_TO_VK:
        vk = ACTION_TO_VK[payload.action]
        send_virtual_key(vk)
        return

    if payload.action == MediaAction.SET_VOLUME:
        if payload.volume_percent is None:
            raise MediaExecutionError("volume_percent es obligatorio para SET_VOLUME")

        # Windows altera el volumen típicamente en saltos del 2%.
        # 1. Llevar a 0% emitiendo 50 pulsaciones de VOLUME_DOWN
        MAX_STEPS = 50
        for _ in range(MAX_STEPS):
            send_virtual_key(VK_VOLUME_DOWN)

        # 2. Subir hasta el nivel aproximado requerido
        target_steps = min(MAX_STEPS, max(0, payload.volume_percent // 2))
        for _ in range(target_steps):
            send_virtual_key(VK_VOLUME_UP)
        return

    raise MediaExecutionError(f"Acción multimedia no reconocida: {payload.action}")
