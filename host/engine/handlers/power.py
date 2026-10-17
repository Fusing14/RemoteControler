"""
Manejador de control de energía del sistema para Windows mediante APIs Win32 directas.
Principio rector: Cero subshells. Prohibido terminantemente invocar 'shutdown.exe'.

APIs utilizadas:
- user32.dll!LockWorkStation
- powrprof.dll!SetSuspendState
- advapi32.dll!OpenProcessToken, LookupPrivilegeValueW, AdjustTokenPrivileges
- advapi32.dll!InitiateSystemShutdownExW
"""

import sys
import ctypes
from ctypes import wintypes
from typing import Optional

from host.engine.contracts.commands import PowerAction, PowerPayload


class PowerExecutionError(Exception):
    """Excepción lanzada ante fallos en las APIs nativas de control de energía."""
    pass


# Constantes de Privilegios y Seguridad Win32
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

# Constantes de Motivo de Apagado (Shutdown Reason)
SHTDN_REASON_MAJOR_APPLICATION = 0x00040000
SHTDN_REASON_MINOR_OTHER = 0x00000001
SHTDN_REASON_FLAG_PLANNED = 0x40000000


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


def _acquire_shutdown_privilege() -> None:
    """
    Habilita el privilegio SeShutdownPrivilege en el token del proceso actual.
    Requisito indispensable de Windows para invocar InitiateSystemShutdownExW.
    """
    if sys.platform != "win32":
        raise RuntimeError("Solo ejecutable en entornos Windows.")

    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL

    advapi32.LookupPrivilegeValueW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.POINTER(LUID),
    ]
    advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL

    advapi32.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.POINTER(TOKEN_PRIVILEGES),
        wintypes.DWORD,
        ctypes.POINTER(TOKEN_PRIVILEGES),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

    h_token = wintypes.HANDLE()
    curr_proc = kernel32.GetCurrentProcess()

    if not advapi32.OpenProcessToken(curr_proc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
        err = ctypes.GetLastError()
        raise PowerExecutionError(f"No se pudo abrir el token del proceso. Código: {err}")

    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeShutdownPrivilege", ctypes.byref(luid)):
            err = ctypes.GetLastError()
            raise PowerExecutionError(f"Fallo al resolver SeShutdownPrivilege. Código: {err}")

        tp = TOKEN_PRIVILEGES(1, (LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED),))
        if not advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), 0, None, None):
            err = ctypes.GetLastError()
            raise PowerExecutionError(f"Fallo al ajustar privilegios del token. Código: {err}")

        err = ctypes.GetLastError()
        if err != 0:
            # Si el token no poseía el privilegio asignado en su policy, GetLastError retorna ERROR_NOT_ALL_ASSIGNED (1300)
            raise PowerExecutionError(f"Privilegio SeShutdownPrivilege no disponible para este usuario. Código: {err}")
    finally:
        kernel32.CloseHandle(h_token)


def execute_power_command(payload: PowerPayload) -> None:
    """
    Ejecuta una acción de energía validada mediante llamadas Win32 directas.
    
    Mitigación de Vectores de Ataque:
    - Sin inyección de argumentos: No se concatena ningún parámetro en líneas de comando.
    - Se elimina el vector de secuestro de ruta (Path Hijacking) de shutdown.exe.
    """
    if sys.platform != "win32":
        raise RuntimeError("El manejador de energía solo es compatible con Windows.")

    action = payload.action

    if action == PowerAction.LOCK:
        user32 = ctypes.windll.user32
        user32.LockWorkStation.argtypes = []
        user32.LockWorkStation.restype = wintypes.BOOL
        success = user32.LockWorkStation()
        if not success:
            err = ctypes.GetLastError()
            raise PowerExecutionError(f"Fallo en LockWorkStation. Código Win32: {err}")
        return

    if action in (PowerAction.SLEEP, PowerAction.HIBERNATE):
        powrprof = ctypes.windll.powrprof
        powrprof.SetSuspendState.argtypes = [wintypes.BOOLEAN, wintypes.BOOLEAN, wintypes.BOOLEAN]
        powrprof.SetSuspendState.restype = wintypes.BOOLEAN

        b_hibernate = 1 if action == PowerAction.HIBERNATE else 0
        b_force = 1 if payload.force else 0
        success = powrprof.SetSuspendState(b_hibernate, b_force, 0)
        if not success:
            err = ctypes.GetLastError()
            raise PowerExecutionError(f"Fallo en SetSuspendState. Código Win32: {err}")
        return

    if action in (PowerAction.REBOOT, PowerAction.SHUTDOWN):
        # Requiere adquirir SeShutdownPrivilege antes de invocar InitiateSystemShutdownExW
        _acquire_shutdown_privilege()

        advapi32 = ctypes.windll.advapi32
        advapi32.InitiateSystemShutdownExW.argtypes = [
            wintypes.LPWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        advapi32.InitiateSystemShutdownExW.restype = wintypes.BOOL

        b_reboot = (action == PowerAction.REBOOT)
        reason = SHTDN_REASON_MAJOR_APPLICATION | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED

        success = advapi32.InitiateSystemShutdownExW(
            None,           # Equipo local
            None,           # Sin mensaje mostrado en pantalla
            0,              # Timeout inmediato (0 segundos)
            payload.force,  # Forzar cierre si fue especificado en contrato
            b_reboot,       # True para reiniciar, False para apagar
            reason,         # Código estructurado de motivo
        )

        if not success:
            err = ctypes.GetLastError()
            raise PowerExecutionError(f"Fallo en InitiateSystemShutdownExW. Código Win32: {err}")
        return

    raise PowerExecutionError(f"Acción de energía no soportada: {action}")
