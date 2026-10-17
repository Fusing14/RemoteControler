"""
Contratos y esquemas de comandos fuertemente tipados.
Principio: Prevención estricta de inyección de comandos y RCE.
Queda terminantemente prohibido el paso de strings arbitrarios de ejecución.
"""

from enum import Enum
from typing import Optional, Union, Dict, Any
from pydantic import BaseModel, Field, model_validator, ConfigDict


class CommandCatalog(str, Enum):
    """Catálogo cerrado de tipos de comandos admitidos por el Host."""
    MEDIA = "MEDIA"
    SYS_POWER = "SYS_POWER"
    APP_LAUNCH = "APP_LAUNCH"
    GAMES_LIST = "GAMES_LIST"
    GAME_LAUNCH = "GAME_LAUNCH"
    SCREEN_FRAME = "SCREEN_FRAME"
    UNLOCK_PC = "UNLOCK_PC"


class MediaAction(str, Enum):
    """Acciones multimedia mapeadas directamente a Virtual Key Codes de Win32."""
    PLAY_PAUSE = "PLAY_PAUSE"
    NEXT_TRACK = "NEXT_TRACK"
    PREV_TRACK = "PREV_TRACK"
    VOLUME_UP = "VOLUME_UP"
    VOLUME_DOWN = "VOLUME_DOWN"
    VOLUME_MUTE = "VOLUME_MUTE"
    SET_VOLUME = "SET_VOLUME"


class PowerAction(str, Enum):
    """Acciones de control de energía mapeadas a APIs nativas de Win32."""
    LOCK = "LOCK"
    SLEEP = "SLEEP"
    HIBERNATE = "HIBERNATE"
    REBOOT = "REBOOT"
    SHUTDOWN = "SHUTDOWN"


class AppPlatform(str, Enum):
    """Plataformas seguras de lanzamiento de aplicaciones mediante identificadores internos."""
    STEAM = "STEAM"


class GamePlatform(str, Enum):
    """Plataformas de juegos soportadas para autodetección y lanzamiento."""
    STEAM = "steam"
    EPIC = "epic"


class MediaPayload(BaseModel):
    """
    Payload para comandos multimedia.
    Mitigación: Los valores numéricos de volumen están estrictamente acotados entre 0 y 100.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: MediaAction
    volume_percent: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description="Porcentaje de volumen deseado (0-100). Obligatorio solo si action es SET_VOLUME."
    )

    @model_validator(mode="after")
    def validate_volume_payload(self) -> "MediaPayload":
        if self.action == MediaAction.SET_VOLUME and self.volume_percent is None:
            raise ValueError("volume_percent es obligatorio cuando action es SET_VOLUME")
        if self.action != MediaAction.SET_VOLUME and self.volume_percent is not None:
            raise ValueError("volume_percent solo está permitido cuando action es SET_VOLUME")
        return self


class PowerPayload(BaseModel):
    """
    Payload para control de energía.
    Mitigación: No se aceptan tiempos de espera arbitrarios ni flags de línea de comandos.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: PowerAction
    force: bool = Field(default=False, description="Forzar cierre de aplicaciones sin aviso.")


class AppLaunchPayload(BaseModel):
    """
    Payload para lanzamiento de aplicaciones (Compatibilidad retroactiva).
    Mitigación contra RCE y Path Traversal:
    - Se prohíben absolutamente rutas a ejecutables (ej. 'C:\\...').
    - Solo se admiten identificadores numéricos verificados de Steam (1 a 2,147,483,647).
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: AppPlatform = Field(default=AppPlatform.STEAM)
    app_id: int = Field(
        ...,
        ge=1,
        le=2147483647,
        description="ID numérico de la aplicación en Steam (ej: 730 para CS2). Prohibido texto libre."
    )


class GamesListPayload(BaseModel):
    """
    Payload para consulta de juegos instalados (Steam y Epic Games).
    """
    model_config = ConfigDict(extra="forbid", frozen=True)
    platform: Optional[GamePlatform] = Field(
        default=None,
        description="Filtro opcional de plataforma ('steam' o 'epic')."
    )


class GameLaunchPayload(BaseModel):
    """
    Payload para lanzamiento seguro de juegos autodetectados.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: GamePlatform = Field(..., description="Plataforma del juego ('steam' o 'epic').")
    game_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="Identificador validado del juego (AppID numérico o AppName alfanumérico)."
    )


class ScreenFramePayload(BaseModel):
    """
    Payload para solicitud de fotograma de pantalla en vivo.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_width: int = Field(default=1280, ge=320, le=1920)
    max_height: int = Field(default=720, ge=240, le=1080)
    quality: int = Field(default=70, ge=30, le=95)


class UnlockPcPayload(BaseModel):
    """
    Payload para desbloqueo remoto autenticado de la sesión de Windows.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    password: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Contraseña de la cuenta de Windows a autenticar mediante LogonUserW."
    )
    username: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Nombre de usuario de Windows (por defecto el usuario actual de la sesión)."
    )


CommandPayloadType = Union[
    MediaPayload,
    PowerPayload,
    AppLaunchPayload,
    GamesListPayload,
    GameLaunchPayload,
    ScreenFramePayload,
    UnlockPcPayload,
]

COMMAND_PAYLOAD_SCHEMA_MAP: Dict[CommandCatalog, type[BaseModel]] = {
    CommandCatalog.MEDIA: MediaPayload,
    CommandCatalog.SYS_POWER: PowerPayload,
    CommandCatalog.APP_LAUNCH: AppLaunchPayload,
    CommandCatalog.GAMES_LIST: GamesListPayload,
    CommandCatalog.GAME_LAUNCH: GameLaunchPayload,
    CommandCatalog.SCREEN_FRAME: ScreenFramePayload,
    CommandCatalog.UNLOCK_PC: UnlockPcPayload,
}


def validate_command_payload(command_id: CommandCatalog, raw_payload: Dict[str, Any]) -> BaseModel:
    """
    Valida un payload crudo contra el esquema cerrado correspondiente al command_id.
    Lanza ValueError si el command_id no es reconocido o si la validación de Pydantic falla.
    """
    schema_cls = COMMAND_PAYLOAD_SCHEMA_MAP.get(command_id)
    if not schema_cls:
        raise ValueError(f"Comando no soportado en el catálogo: {command_id}")
    return schema_cls.model_validate(raw_payload)
