"""
Adaptador nativo de Windows Data Protection API (DPAPI) mediante ctypes.
Garantiza el cifrado seguro de secretos en reposo sin almacenar claves simétricas en disco.

APIs utilizadas:
- Crypt32.dll!CryptProtectData
- Crypt32.dll!CryptUnprotectData
- Kernel32.dll!LocalFree
"""

import sys
import ctypes
from ctypes import wintypes
from typing import Optional

# Validación de plataforma: DPAPI es exclusivo de Microsoft Windows
if sys.platform != "win32":
    raise RuntimeError("El módulo host.core.storage.dpapi solo es compatible con entornos Windows.")

# Carga de bibliotecas del sistema
_crypt32 = ctypes.windll.crypt32
_kernel32 = ctypes.windll.kernel32

# Flags de DPAPI
CRYPTPROTECT_UI_FORBIDDEN = 0x01       # Impide diálogo de interfaz de usuario (esencial para servicios/daemons)
CRYPTPROTECT_LOCAL_MACHINE = 0x04      # Ámbito máquina (SYSTEM) en lugar de usuario actual


class DATA_BLOB(ctypes.Structure):
    """Estructura de datos Win32 para transporte de buffers binarios."""
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char))
    ]


# Firma de CryptProtectData
_crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),          # pDataIn
    wintypes.LPCWSTR,                   # szDataDescr
    ctypes.POINTER(DATA_BLOB),          # pOptionalEntropy
    wintypes.LPVOID,                    # pvReserved
    wintypes.LPVOID,                    # pPromptStruct
    wintypes.DWORD,                     # dwFlags
    ctypes.POINTER(DATA_BLOB)           # pDataOut
]
_crypt32.CryptProtectData.restype = wintypes.BOOL

# Firma de CryptUnprotectData
_crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),          # pDataIn
    ctypes.POINTER(wintypes.LPWSTR),    # ppszDataDescr
    ctypes.POINTER(DATA_BLOB),          # pOptionalEntropy
    wintypes.LPVOID,                    # pvReserved
    wintypes.LPVOID,                    # pPromptStruct
    wintypes.DWORD,                     # dwFlags
    ctypes.POINTER(DATA_BLOB)           # pDataOut
]
_crypt32.CryptUnprotectData.restype = wintypes.BOOL

# Firma de LocalFree
_kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
_kernel32.LocalFree.restype = wintypes.HLOCAL


class DPAPIError(Exception):
    """Excepción lanzada cuando una operación criptográfica de DPAPI falla."""
    pass


def _zero_buffer(buf: ctypes.Array) -> None:
    """Sobrescribe un buffer de memoria con ceros para mitigar recuperación en volcados de memoria."""
    ctypes.memset(buf, 0, ctypes.sizeof(buf))


def protect_bytes(
    data: bytes,
    optional_entropy: Optional[bytes] = None,
    scope_local_machine: bool = False,
    description: str = "RemoteControler Protected Secret"
) -> bytes:
    """
    Cifra un buffer de bytes utilizando Windows DPAPI.
    
    Mitigación de Vectores de Ataque:
    1. Secretos en Reposo: Los datos se cifran con la clave maestra de Windows ligada
       al usuario actual (o máquina), haciendo inviable su lectura desde disco sin sesión válida.
    2. Movimiento Lateral del Mismo Usuario: La entropía secundaria (salt) opcional evita que
       otros programas que corran bajo el mismo usuario puedan descifrar los datos a menos
       que conozcan dicha entropía adicional.
    
    :param data: Datos planos a cifrar.
    :param optional_entropy: Salting adicional obligatorio para el descifrado.
    :param scope_local_machine: Si True, usa CRYPTPROTECT_LOCAL_MACHINE (apto para servicios SYSTEM).
                                Si False (recomendado), usa el contexto del usuario actual.
    :param description: Descripción visible en herramientas de depuración de Windows.
    :return: Payload cifrado por DPAPI.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Los datos a cifrar deben ser bytes o bytearray")

    flags = CRYPTPROTECT_UI_FORBIDDEN
    if scope_local_machine:
        flags |= CRYPTPROTECT_LOCAL_MACHINE

    # Crear buffer nativo para data
    data_buffer = ctypes.create_string_buffer(bytes(data))
    in_blob = DATA_BLOB(len(data), ctypes.cast(data_buffer, ctypes.POINTER(ctypes.c_char)))

    # Entropía opcional
    ent_blob_ptr = None
    entropy_buffer = None
    if optional_entropy:
        entropy_buffer = ctypes.create_string_buffer(bytes(optional_entropy))
        ent_blob = DATA_BLOB(len(optional_entropy), ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_char)))
        ent_blob_ptr = ctypes.byref(ent_blob)

    out_blob = DATA_BLOB()

    try:
        success = _crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            description,
            ent_blob_ptr,
            None,
            None,
            flags,
            ctypes.byref(out_blob)
        )

        if not success:
            err_code = ctypes.GetLastError()
            raise DPAPIError(f"Fallo en CryptProtectData. Código de error Win32: {err_code}")

        # Extraer los bytes cifrados de la memoria asignada por Windows
        encrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return encrypted_bytes

    finally:
        # Liberar la memoria asignada por CryptProtectData
        if out_blob.pbData:
            _kernel32.LocalFree(out_blob.pbData)
        # Limpieza (zeroing) de memoria de entrada
        _zero_buffer(data_buffer)
        if entropy_buffer:
            _zero_buffer(entropy_buffer)


def unprotect_bytes(
    encrypted_data: bytes,
    optional_entropy: Optional[bytes] = None
) -> bytes:
    """
    Descifra un buffer protegido previamente con protect_bytes.
    
    Mitigación de Vectores de Ataque:
    - Control de Integridad y Autenticidad: Si los datos o la entropía fueron alterados,
      la API de Windows rechaza el descifrado con error de datos inválidos (ERROR_INVALID_DATA).
    """
    if not isinstance(encrypted_data, (bytes, bytearray)):
        raise TypeError("Los datos cifrados deben ser bytes o bytearray")

    flags = CRYPTPROTECT_UI_FORBIDDEN

    data_buffer = ctypes.create_string_buffer(bytes(encrypted_data))
    in_blob = DATA_BLOB(len(encrypted_data), ctypes.cast(data_buffer, ctypes.POINTER(ctypes.c_char)))

    ent_blob_ptr = None
    entropy_buffer = None
    if optional_entropy:
        entropy_buffer = ctypes.create_string_buffer(bytes(optional_entropy))
        ent_blob = DATA_BLOB(len(optional_entropy), ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_char)))
        ent_blob_ptr = ctypes.byref(ent_blob)

    out_blob = DATA_BLOB()

    try:
        success = _crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            ent_blob_ptr,
            None,
            None,
            flags,
            ctypes.byref(out_blob)
        )

        if not success:
            err_code = ctypes.GetLastError()
            raise DPAPIError(
                f"Fallo en CryptUnprotectData. Datos corruptos o entropía incorrecta. Código Win32: {err_code}"
            )

        decrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return decrypted_bytes

    finally:
        if out_blob.pbData:
            # Limpiar memoria sensible en el buffer de salida de Windows antes de liberar
            ctypes.memset(out_blob.pbData, 0, out_blob.cbData)
            _kernel32.LocalFree(out_blob.pbData)
        _zero_buffer(data_buffer)
        if entropy_buffer:
            _zero_buffer(entropy_buffer)
