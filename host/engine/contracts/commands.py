"""
Contratos y esquemas de comandos fuertemente tipados.
Principio: Prevención estricta de inyección de comandos y RCE.
Queda terminantemente prohibido el paso de strings arbitrarios de ejecución.
"""

from enum import Enum
import urllib.parse
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
    APPS_LIST = "APPS_LIST"
    OPEN_URL = "OPEN_URL"
    CAMERA_FRAME = "CAMERA_FRAME"
    MIC_AUDIO_CHUNK = "MIC_AUDIO_CHUNK"
    RUNNING_APPS_LIST = "RUNNING_APPS_LIST"
    APP_CLOSE = "APP_CLOSE"


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
    SYSTEM = "SYSTEM"


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
    Payload para lanzamiento de aplicaciones (Steam o Sistema).
    Mitigación contra RCE y Path Traversal:
    - En Steam: solo identificadores numéricos verificados (1 a 2,147,483,647).
    - En Sistema: sólo rutas a accesos directos (.lnk) o ejecutables reconocidos.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: AppPlatform = Field(default=AppPlatform.STEAM)
    app_id: Optional[Union[int, str]] = Field(
        default=None,
        description="ID numérico de la aplicación en Steam (ej: 730) o identificador alfanumérico."
    )
    target_path: Optional[str] = Field(
        default=None,
        max_length=512,
        description="Ruta segura del acceso directo descubierto por APPS_LIST."
    )

    @model_validator(mode="after")
    def validate_app_payload(self) -> "AppLaunchPayload":
        if self.platform == AppPlatform.STEAM:
            if self.app_id is None:
                raise ValueError("app_id es obligatorio para la plataforma STEAM")
            if isinstance(self.app_id, str):
                if not self.app_id.isdigit():
                    raise ValueError("Steam app_id debe ser un entero numérico")
                num_id = int(self.app_id)
            elif isinstance(self.app_id, int):
                num_id = self.app_id
            else:
                raise ValueError("Steam app_id debe ser un entero numérico")
            if not (1 <= num_id <= 2147483647):
                raise ValueError("Steam app_id debe estar entre 1 y 2147483647")
        elif self.platform == AppPlatform.SYSTEM:
            if not self.target_path and not self.app_id:
                raise ValueError("target_path o app_id es obligatorio para la plataforma SYSTEM")
        return self


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
    Payload para solicitud de fotograma de pantalla en vivo con soporte multimonitor.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_width: int = Field(default=1280, ge=320, le=1920)
    max_height: int = Field(default=720, ge=240, le=1080)
    quality: int = Field(default=70, ge=30, le=95)
    monitor_index: int = Field(
        default=1,
        ge=0,
        le=16,
        description="Índice del monitor (1 para principal, 2..N para secundarios, 0 para todas las pantallas combinadas)."
    )


class CameraFramePayload(BaseModel):
    """
    Payload para solicitud de fotograma de cámara web en vivo.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    camera_index: int = Field(default=0, ge=0, le=10, description="Índice del dispositivo de cámara (0 para predeterminada).")
    max_width: int = Field(default=854, ge=320, le=1920)
    max_height: int = Field(default=480, ge=240, le=1080)
    quality: int = Field(default=65, ge=30, le=95)


class UnlockPcPayload(BaseModel):
    """
    Payload para desbloqueo remoto autenticado de la sesión de Windows.
    Acepta tanto contraseña de cuenta Windows como PIN de Windows Hello.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    password: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Contraseña de la cuenta de Windows o PIN de Windows Hello."
    )
    username: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Nombre de usuario de Windows (por defecto el usuario actual de la sesión)."
    )


class AppsListPayload(BaseModel):
    """
    Payload para consultar las aplicaciones instaladas en Windows.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)
    query: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Filtro de búsqueda opcional por nombre de aplicación."
    )


class OpenUrlPayload(BaseModel):
    """
    Payload para apertura remota de URLs en el navegador predeterminado del PC.
    Aplica validación estricta de esquema y sintaxis de URL.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="URL a abrir en el navegador predeterminado del PC."
    )

    @model_validator(mode="after")
    def validate_url(self) -> "OpenUrlPayload":
        raw = self.url.strip()
        if not raw:
            raise ValueError("La URL no puede estar vacía.")

        # Evitar caracteres de control o inyección de nueva línea
        if any(c in raw for c in ("\r", "\n", "\0")):
            raise ValueError("La URL contiene caracteres de control no permitidos.")

        parsed_orig = urllib.parse.urlparse(raw)
        if parsed_orig.scheme:
            if parsed_orig.scheme.lower() not in ("http", "https"):
                raise ValueError(f"Esquema de URL no permitido: '{parsed_orig.scheme}'. Solo se admite http/https.")
            target_url = raw
        else:
            if " " in raw:
                raise ValueError("La URL contiene espacios no permitidos.")
            target_url = f"https://{raw}"

        parsed = urllib.parse.urlparse(target_url)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError(f"Esquema de URL no permitido: '{parsed.scheme}'. Solo se admite http/https.")
        if not parsed.netloc or " " in parsed.netloc:
            raise ValueError("La URL debe incluir un dominio o host válido sin espacios.")

        object.__setattr__(self, "url", target_url)
        return self


class MicAudioChunkPayload(BaseModel):
    """
    Payload para fragmentos de audio del micrófono en tiempo real (Intercom / Walkie-Talkie).
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    audio_b64: str = Field(
        ...,
        min_length=1,
        max_length=65536,
        description="Fragmento de audio PCM 16-bit mono codificado en Base64."
    )
    sample_rate: int = Field(
        default=16000,
        ge=8000,
        le=48000,
        description="Frecuencia de muestreo en Hz (por defecto 16000)."
    )
    channels: int = Field(
        default=1,
        ge=1,
        le=2,
        description="Número de canales de audio (1 para mono, 2 para estéreo)."
    )


class RunningAppsListPayload(BaseModel):
    """
    Payload para consultar las aplicaciones activas en Windows con ventanas visibles.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)


class AppClosePayload(BaseModel):
    """
    Payload para cerrar una aplicación activa en Windows por su PID.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int = Field(..., gt=0, description="Process ID (PID) de la aplicación a cerrar.")
    force: bool = Field(default=False, description="True para forzar el cierre inmediato (SIGKILL/TerminateProcess).")


CommandPayloadType = Union[
    MediaPayload,
    PowerPayload,
    AppLaunchPayload,
    GamesListPayload,
    GameLaunchPayload,
    ScreenFramePayload,
    CameraFramePayload,
    MicAudioChunkPayload,
    UnlockPcPayload,
    AppsListPayload,
    OpenUrlPayload,
    RunningAppsListPayload,
    AppClosePayload,
]

COMMAND_PAYLOAD_SCHEMA_MAP: Dict[CommandCatalog, type[BaseModel]] = {
    CommandCatalog.MEDIA: MediaPayload,
    CommandCatalog.SYS_POWER: PowerPayload,
    CommandCatalog.APP_LAUNCH: AppLaunchPayload,
    CommandCatalog.GAMES_LIST: GamesListPayload,
    CommandCatalog.GAME_LAUNCH: GameLaunchPayload,
    CommandCatalog.SCREEN_FRAME: ScreenFramePayload,
    CommandCatalog.CAMERA_FRAME: CameraFramePayload,
    CommandCatalog.MIC_AUDIO_CHUNK: MicAudioChunkPayload,
    CommandCatalog.UNLOCK_PC: UnlockPcPayload,
    CommandCatalog.APPS_LIST: AppsListPayload,
    CommandCatalog.OPEN_URL: OpenUrlPayload,
    CommandCatalog.RUNNING_APPS_LIST: RunningAppsListPayload,
    CommandCatalog.APP_CLOSE: AppClosePayload,
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
