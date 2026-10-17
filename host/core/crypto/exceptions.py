"""
Excepciones de seguridad para el protocolo criptográfico Zero-Trust.
Permite una gestión de errores estricta y sin filtrado de información sensible.
"""


class SecurityProtocolError(Exception):
    """Clase base para todos los errores de protocolo de seguridad."""
    pass


class InvalidSignatureError(SecurityProtocolError):
    """
    Lanzado cuando la firma Ed25519 no coincide con el payload canónico.
    Indica posible intento de manipulación (Tampering) o corrupción de datos.
    """
    pass


class UntrustedDeviceError(SecurityProtocolError):
    """
    Lanzado cuando el device_id o la clave pública no se encuentran en la Allowlist local.
    Indica intento de acceso por dispositivo no emparejado/autorizado.
    """
    pass


class ClockSkewError(SecurityProtocolError):
    """
    Lanzado cuando la marca de tiempo (timestamp_utc) difiere en más de la tolerancia
    permitida con respecto al reloj UTC del host.
    Indica desfase de reloj o intento tardío de ejecución.
    """
    pass


class ReplayAttackDetectedError(SecurityProtocolError):
    """
    Lanzado cuando un nonce ya fue recibido y procesado dentro de la ventana de validez.
    Indica ataque de repetición (Replay Attack).
    """
    pass


class InvalidPayloadError(SecurityProtocolError):
    """
    Lanzado cuando el payload interno viola las reglas estrictas del contrato Pydantic.
    """
    pass
