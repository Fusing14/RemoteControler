"""
Motor de despacho seguro (Command Dispatcher).
Orquestador central que verifica autenticidad, frescura y rutea hacia los handlers nativos Win32.
"""

import time
import logging
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, ValidationError

from host.engine.contracts.commands import (
    CommandCatalog,
    GamePlatform,
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
)
from host.engine.contracts.envelope import SignedEnvelope
from host.core.storage.device_store import TrustedDeviceStore
from host.core.security.anti_replay import AntiReplayValidator
from host.core.crypto.verifier import verify_canonical_signature
from host.core.crypto.exceptions import (
    SecurityProtocolError,
    InvalidSignatureError,
    UntrustedDeviceError,
    ClockSkewError,
    ReplayAttackDetectedError,
    InvalidPayloadError,
)
from host.core.discovery.game_scanner import (
    scan_installed_games,
    scan_steam_games,
    scan_epic_games,
)
from host.core.discovery.app_scanner import scan_installed_apps
from host.core.discovery.process_manager import (
    list_running_apps,
    close_running_app,
    AppCloseError,
    AppCloseSecurityError,
)
from host.engine.handlers.media import execute_media_command, MediaExecutionError
from host.engine.handlers.power import execute_power_command, PowerExecutionError
from host.engine.handlers.apps import (
    execute_app_command,
    execute_game_launch,
    execute_open_url,
    AppLaunchError,
)
from host.engine.handlers.screen import capture_screen_jpeg, ScreenCaptureError
from host.engine.handlers.camera import capture_camera_jpeg, CameraCaptureError
from host.engine.handlers.audio_stream import play_audio_chunk, AudioStreamError
from host.engine.handlers.unlock import (
    execute_unlock_pc,
    UnlockAuthenticationError,
    UnlockExecutionError,
)

logger = logging.getLogger("RemoteControler.Dispatcher")


class ExecutionStatus(str, Enum):
    """Estado del resultado de ejecución de un comando."""
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    ERROR = "ERROR"


class ExecutionResult(BaseModel):
    """
    Resultado devuelto al cliente tras procesar una petición.
    
    Mitigación de Fuga de Información:
    - Jamás expone trazas de la pila (stack traces), rutas locales de Windows
      ni detalles internos de la memoria o drivers.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: ExecutionStatus
    command_id: Optional[str] = None
    timestamp_utc: int = Field(default_factory=lambda: int(time.time()))
    message: str
    error_code: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


class CommandDispatcher:
    """
    Despachador central de ejecución con política de Zero-Trust.
    """

    def __init__(
        self,
        device_store: TrustedDeviceStore,
        anti_replay_validator: AntiReplayValidator,
    ) -> None:
        self.device_store = device_store
        self.anti_replay = anti_replay_validator

    def dispatch(self, envelope: SignedEnvelope) -> ExecutionResult:
        """
        Punto de entrada principal para el procesamiento de peticiones:
        1. Verificación de Device Pinning (Allowlist).
        2. Validación de ventana temporal y Anti-Replay.
        3. Verificación criptográfica Ed25519 sobre JSON canónico (RFC 8785).
        4. Validación del esquema del payload fuertemente tipado.
        5. Ejecución del handler nativo correspondiente.
        """
        # Paso 1: Device Pinning
        if not self.device_store.is_device_trusted(envelope.device_id):
            logger.warning("Petición rechazada: Dispositivo no autorizado '%s'", envelope.device_id)
            raise UntrustedDeviceError("Dispositivo no autorizado en la lista blanca local.")

        public_key = self.device_store.get_device_public_key_object(envelope.device_id)

        # Paso 2: Frescura temporal y comprobación previa de replay
        self.anti_replay.validate_timestamp(envelope.timestamp_utc)
        self.anti_replay.check_nonce(envelope.nonce)

        # Paso 3: Verificación criptográfica de firma digital Ed25519
        verify_canonical_signature(
            public_key=public_key,
            data=envelope.to_canonical_dict(),
            signature_b64=envelope.signature
        )

        # Confirmar el nonce en la caché una vez validada la firma criptográfica
        self.anti_replay.commit_nonce(envelope.nonce)

        # Paso 4: Validación estricta del contrato del payload
        try:
            parsed_payload = envelope.validate_inner_payload()
        except (ValueError, ValidationError) as e:
            logger.warning("Payload malformado recibido para command_id=%s: %s", envelope.command_id, e)
            raise InvalidPayloadError("El payload no cumple con las restricciones del contrato seguro.") from e

        # Paso 5: Despacho a Handlers nativos Win32 (Sin Subshells)
        try:
            extra_data = None

            if envelope.command_id == CommandCatalog.MEDIA:
                assert isinstance(parsed_payload, MediaPayload)
                execute_media_command(parsed_payload)
            elif envelope.command_id == CommandCatalog.SYS_POWER:
                assert isinstance(parsed_payload, PowerPayload)
                execute_power_command(parsed_payload)
            elif envelope.command_id == CommandCatalog.APP_LAUNCH:
                assert isinstance(parsed_payload, AppLaunchPayload)
                execute_app_command(parsed_payload)
            elif envelope.command_id == CommandCatalog.GAMES_LIST:
                assert isinstance(parsed_payload, GamesListPayload)
                if parsed_payload.platform == GamePlatform.STEAM:
                    games = scan_steam_games()
                elif parsed_payload.platform == GamePlatform.EPIC:
                    games = scan_epic_games()
                else:
                    games = scan_installed_games()
                extra_data = {"games": games}
            elif envelope.command_id == CommandCatalog.GAME_LAUNCH:
                assert isinstance(parsed_payload, GameLaunchPayload)
                execute_game_launch(parsed_payload.platform.value, parsed_payload.game_id)
            elif envelope.command_id == CommandCatalog.SCREEN_FRAME:
                assert isinstance(parsed_payload, ScreenFramePayload)
                extra_data = capture_screen_jpeg(
                    max_width=parsed_payload.max_width,
                    max_height=parsed_payload.max_height,
                    quality=parsed_payload.quality,
                    monitor_index=parsed_payload.monitor_index,
                )
            elif envelope.command_id == CommandCatalog.CAMERA_FRAME:
                assert isinstance(parsed_payload, CameraFramePayload)
                extra_data = capture_camera_jpeg(
                    camera_index=parsed_payload.camera_index,
                    max_width=parsed_payload.max_width,
                    max_height=parsed_payload.max_height,
                    quality=parsed_payload.quality
                )
            elif envelope.command_id == CommandCatalog.MIC_AUDIO_CHUNK:
                assert isinstance(parsed_payload, MicAudioChunkPayload)
                play_audio_chunk(
                    audio_b64=parsed_payload.audio_b64,
                    sample_rate=parsed_payload.sample_rate,
                    channels=parsed_payload.channels
                )
                extra_data = {"played": True}
            elif envelope.command_id == CommandCatalog.UNLOCK_PC:
                assert isinstance(parsed_payload, UnlockPcPayload)
                execute_unlock_pc(parsed_payload.password, parsed_payload.username)
            elif envelope.command_id == CommandCatalog.APPS_LIST:
                apps = scan_installed_apps()
                if parsed_payload.query:
                    q = parsed_payload.query.lower().strip()
                    apps = [a for a in apps if q in a["name"].lower()]
                extra_data = {"apps": apps}
            elif envelope.command_id == CommandCatalog.RUNNING_APPS_LIST:
                assert isinstance(parsed_payload, RunningAppsListPayload)
                apps = list_running_apps()
                extra_data = {"apps": apps}
            elif envelope.command_id == CommandCatalog.APP_CLOSE:
                assert isinstance(parsed_payload, AppClosePayload)
                close_res = close_running_app(parsed_payload.pid, parsed_payload.force)
                extra_data = close_res
            elif envelope.command_id == CommandCatalog.OPEN_URL:
                assert isinstance(parsed_payload, OpenUrlPayload)
                opened = execute_open_url(parsed_payload.url)
                extra_data = {"url": opened}
            else:
                raise ValueError(f"Comando no soportado: {envelope.command_id}")

            if envelope.command_id == CommandCatalog.UNLOCK_PC:
                success_msg = "PC desbloqueado exitosamente."
            elif envelope.command_id == CommandCatalog.OPEN_URL:
                success_msg = f"URL abierta en el navegador: {extra_data.get('url', '')}"
            elif envelope.command_id == CommandCatalog.APPS_LIST:
                success_msg = f"{len(extra_data.get('apps', []))} aplicaciones detectadas en el sistema."
            elif envelope.command_id == CommandCatalog.RUNNING_APPS_LIST:
                success_msg = f"{len(extra_data.get('apps', []))} aplicaciones activas detectadas."
            elif envelope.command_id == CommandCatalog.APP_CLOSE:
                success_msg = f"Aplicación PID {extra_data.get('pid')} cerrada exitosamente."
            elif envelope.command_id == CommandCatalog.MIC_AUDIO_CHUNK:
                success_msg = "Fragmento de audio procesado."
            else:
                success_msg = f"Comando {envelope.command_id.value} ejecutado exitosamente."

            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                command_id=envelope.command_id.value,
                message=success_msg,
                data=extra_data
            )

        except UnlockAuthenticationError as e:
            logger.warning("Fallo de autenticación en UNLOCK_PC: %s", e)
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                command_id=envelope.command_id.value,
                message="Contraseña o PIN de Windows incorrecta.",
                error_code="INVALID_PASSWORD"
            )
        except AppCloseSecurityError as e:
            logger.warning("Intento de cerrar proceso protegido: %s", e)
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                command_id=envelope.command_id.value,
                message=str(e),
                error_code="APP_CLOSE_FORBIDDEN"
            )
        except AppCloseError as e:
            logger.error("Error al cerrar aplicación: %s", e)
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                command_id=envelope.command_id.value,
                message=str(e),
                error_code="APP_CLOSE_FAILED"
            )
        except (MediaExecutionError, PowerExecutionError, AppLaunchError, ScreenCaptureError, CameraCaptureError, AudioStreamError, UnlockExecutionError) as e:
            logger.error("Error durante la ejecución del handler Win32: %s", e)
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                command_id=envelope.command_id.value,
                message="Error interno al ejecutar la acción en el sistema operativo.",
                error_code="WIN32_HANDLER_ERROR"
            )

    def dispatch_safe(self, envelope: SignedEnvelope) -> ExecutionResult:
        """
        Envoltura segura de conveniencia para la capa de transporte:
        Captura excepciones de seguridad y devuelve un ExecutionResult normalizado
        sin propagar trazas al cliente remoto.
        """
        try:
            return self.dispatch(envelope)
        except UntrustedDeviceError:
            return ExecutionResult(
                status=ExecutionStatus.REJECTED,
                command_id=envelope.command_id.value if envelope else None,
                message="Acceso denegado: Dispositivo no autorizado.",
                error_code="UNTRUSTED_DEVICE"
            )
        except ClockSkewError:
            return ExecutionResult(
                status=ExecutionStatus.REJECTED,
                command_id=envelope.command_id.value if envelope else None,
                message="Petición caducada o fuera de sincronía horaria.",
                error_code="CLOCK_SKEW"
            )
        except ReplayAttackDetectedError:
            return ExecutionResult(
                status=ExecutionStatus.REJECTED,
                command_id=envelope.command_id.value if envelope else None,
                message="Petición rechazada: Ataque de repetición detectado.",
                error_code="REPLAY_DETECTED"
            )
        except InvalidSignatureError:
            return ExecutionResult(
                status=ExecutionStatus.REJECTED,
                command_id=envelope.command_id.value if envelope else None,
                message="Firma criptográfica inválida o datos manipulados.",
                error_code="INVALID_SIGNATURE"
            )
        except InvalidPayloadError:
            return ExecutionResult(
                status=ExecutionStatus.REJECTED,
                command_id=envelope.command_id.value if envelope else None,
                message="Payload malformado o violación del esquema de seguridad.",
                error_code="INVALID_PAYLOAD"
            )
