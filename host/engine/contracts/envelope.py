"""
Modelo del Signed Envelope para el protocolo Zero-Trust.
Define la estructura criptográfica que encapsula cada comando transmitido.
"""

import base64
import re
from typing import Any, Dict
from pydantic import BaseModel, Field, field_validator, ConfigDict

from host.engine.contracts.commands import CommandCatalog, validate_command_payload


class SignedEnvelope(BaseModel):
    """
    Envoltorio criptográfico de comandos.
    
    Mitigación de Vectores de Ataque:
    1. Tampering: Protegido por el campo 'signature' sobre los campos canónicos.
    2. Replay: Protegido por 'timestamp_utc' y 'nonce'.
    3. Untrusted Device: Protegido por 'device_id' verificado contra Allowlist.
    4. Argument Injection: Protegido por validación estricta de 'payload' según 'command_id'.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: str = Field(
        ...,
        description="Huella SHA-256 en minúsculas (64 hex chars) de la clave pública del dispositivo cliente."
    )
    timestamp_utc: int = Field(
        ...,
        description="Unix timestamp (segundos) generado por el cliente al momento del envío."
    )
    nonce: str = Field(
        ...,
        description="Cadena hexadecimal única de 32 caracteres (16 bytes CSPRNG) para mitigar repeticiones."
    )
    command_id: CommandCatalog = Field(
        ...,
        description="Identificador del comando dentro del catálogo seguro."
    )
    payload: Dict[str, Any] = Field(
        ...,
        description="Parámetros estructurados correspondientes al command_id."
    )
    signature: str = Field(
        ...,
        description="Firma digital Ed25519 en Base64 estándar generada sobre el JSON canónico."
    )

    @field_validator("device_id")
    @classmethod
    def validate_device_id(cls, v: str) -> str:
        v_clean = v.strip().lower()
        if not re.match(r"^[a-f0-9]{64}$", v_clean):
            raise ValueError("device_id debe ser un hash SHA-256 válido en hexadecimal (64 caracteres [0-9a-f])")
        return v_clean

    @field_validator("nonce")
    @classmethod
    def validate_nonce(cls, v: str) -> str:
        v_clean = v.strip().lower()
        if not re.match(r"^[a-f0-9]{32}$", v_clean):
            raise ValueError("nonce debe ser una cadena hexadecimal de 32 caracteres (16 bytes)")
        return v_clean

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, v: str) -> str:
        v_clean = v.strip()
        try:
            raw_sig = base64.b64decode(v_clean, validate=True)
            if len(raw_sig) != 64:
                raise ValueError(f"Longitud de firma Ed25519 inválida: se esperaban 64 bytes, se obtuvieron {len(raw_sig)}")
        except Exception as e:
            raise ValueError(f"Firma Ed25519 no válida en Base64: {e}")
        return v_clean

    def to_canonical_dict(self) -> Dict[str, Any]:
        """
        Retorna la representación canónica del diccionario a ser firmado/verificado.
        Excluye expresamente el campo 'signature'.
        """
        return {
            "device_id": self.device_id,
            "timestamp_utc": self.timestamp_utc,
            "nonce": self.nonce,
            "command_id": self.command_id.value,
            "payload": self.payload,
        }

    def validate_inner_payload(self) -> BaseModel:
        """
        Valida que el contenido del diccionario 'payload' coincida exactamente
        con el contrato tipado de 'command_id'.
        """
        return validate_command_payload(self.command_id, self.payload)
