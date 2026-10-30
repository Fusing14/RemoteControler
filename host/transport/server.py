"""
Servidor asíncrono WebSocket y HTTP para RemoteControler Host.
Endurecido bajo arquitectura Zero-Trust:
- Restringido a la interfaz de Tailscale (100.64.0.0/10) o loopback en modo dev.
- Anti-CSWSH (Cross-Site WebSocket Hijacking - CWE-306): rechazo de cabeceras Origin de navegadores.
- Revalidación continua por trama y cierre inmediato (1008 Policy Violation) ante revocación en caliente.
- Límite de tamaño de payload (64 KB en WS y HTTP) y límite de clientes concurrentes contra DoS (CWE-400).
- Respuestas de error estandarizadas sin fuga de stack traces ni rutas del sistema (CWE-209).
"""

import asyncio
import json
import logging
from typing import Dict, Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from host.transport.network_utils import is_allowed_source_ip
from host.engine.contracts.commands import CommandCatalog
from host.engine.contracts.envelope import SignedEnvelope
from host.engine.dispatcher import CommandDispatcher, ExecutionResult, ExecutionStatus
from host.core.storage.device_store import TrustedDeviceStore
from host.core.storage.pairing import PairingManager
from host.core.security.rate_limiter import RateLimiter
from host.core.audit.logger import AuditLogger, install_log_redaction_filter

install_log_redaction_filter()
logger = logging.getLogger("RemoteControler.Server")

MAX_WS_MESSAGE_SIZE = 65536     # Límite máximo de trama WebSocket (64 KB) contra DoS por memoria
MAX_HTTP_BODY_SIZE = 65536      # Límite máximo de cuerpo HTTP (64 KB) contra Payload Bomb (CWE-400)
MAX_CONCURRENT_WS_CLIENTS = 10  # Límite máximo de conexiones WebSocket simultáneas
WS_IDLE_TIMEOUT_SECONDS = 120.0 # Timeout de inactividad de socket


class PairRequestBody(BaseModel):
    """Cuerpo de la petición HTTP para emparejar un nuevo dispositivo."""
    pairing_token: str = Field(..., min_length=1, max_length=256, description="Token de desafío de un solo uso escaneado del QR")
    client_public_key_hex: str = Field(..., min_length=64, max_length=64, description="Clave pública Ed25519 del cliente (64 caracteres hex)")
    client_device_id: str = Field(..., min_length=64, max_length=64, description="Huella SHA-256 de la clave pública del cliente")
    label: str = Field(..., min_length=1, max_length=64, description="Etiqueta identificativa del dispositivo móvil")


def _is_unauthorized_browser_origin(origin: str | None) -> bool:
    """
    Detecta cabeceras Origin enviadas por navegadores web para prevenir
    Cross-Site WebSocket Hijacking (CSWSH - CWE-306) y CSRF local.
    """
    if not origin:
        return False
    cleaned = origin.strip().lower()
    if cleaned in ("null", "file://") or cleaned.startswith(("http://", "https://", "ws://", "wss://", "chrome-extension://", "moz-extension://")):
        return True
    return True


def create_app(
    dispatcher: CommandDispatcher,
    device_store: TrustedDeviceStore,
    pairing_manager: PairingManager,
    rate_limiter: RateLimiter,
    audit_logger: AuditLogger,
    allow_loopback: bool = False,
    max_concurrent_ws: int = MAX_CONCURRENT_WS_CLIENTS,
    ws_idle_timeout: float = WS_IDLE_TIMEOUT_SECONDS,
) -> FastAPI:
    """
    Factoría de la aplicación FastAPI / Starlette con hardening Zero-Trust.
    """
    app = FastAPI(title="RemoteControler Daemon", docs_url=None, redoc_url=None, openapi_url=None)

    active_websockets: Set[WebSocket] = set()
    device_websockets: Dict[str, Set[WebSocket]] = {}
    revoked_device_ids: Set[str] = set()

    def _on_device_revoked(revoked_id: str) -> None:
        revoked_device_ids.add(revoked_id)
        sockets = list(device_websockets.get(revoked_id, set()))
        for ws in sockets:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(ws.close(code=status.WS_1008_POLICY_VIOLATION))
            except RuntimeError:
                pass

    device_store.register_revocation_callback(_on_device_revoked)

    # Rate Limiter específico para streaming de audio (hasta 25 pkts/seg para dispositivos autorizados)
    stream_rate_limiter = RateLimiter(
        max_rate_per_second=25.0,
        bucket_capacity=30.0,
        max_failures=rate_limiter.max_failures,
        base_ban_duration_seconds=rate_limiter.base_ban_duration,
    )

    @app.middleware("http")
    async def zero_trust_http_middleware(request: Request, call_next):
        # 1. Mitigación CWE-400: rechazar cuerpos HTTP excesivos (> 64 KB)
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_HTTP_BODY_SIZE:
                    return JSONResponse(
                        status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                        content={"error": "Payload Too Large", "detail": "El cuerpo de la petición excede el límite de 64 KB."},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "Bad Request", "detail": "Cabecera Content-Length inválida."},
                )

        # 2. Mitigación CWE-306: rechazar peticiones cross-origin desde navegadores hacia endpoints sensibles
        origin = request.headers.get("origin")
        if origin and _is_unauthorized_browser_origin(origin):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Forbidden Origin", "detail": "Origen de navegador no autorizado."},
            )

        try:
            response = await call_next(request)
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Cache-Control"] = "no-store"
            return response
        except Exception as exc:
            # Mitigación CWE-209: jamás filtrar stack traces ni rutas locales al cliente
            logger.error("Excepción no controlada en servidor HTTP: %s", exc)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"error": "Internal Server Error", "detail": "Error interno del servidor."},
            )

    @app.get("/health")
    async def health_check(request: Request):
        client_ip = request.client.host if request.client else "UNKNOWN"
        if not is_allowed_source_ip(client_ip, allow_loopback=allow_loopback):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado a nivel de red.")
        return {"status": "OK", "service": "RemoteControler Host"}

    @app.post("/pair")
    async def pair_device(body: PairRequestBody, request: Request):
        """
        Canjea un token de emparejamiento efímero para registrar la clave pública del móvil.
        Protegido contra fuerza bruta (Exponential Backoff + rotación QR), timing attacks y DoS.
        """
        client_ip = request.client.host if request.client else "UNKNOWN"
        logger.info(
            "Recibida petición POST /pair desde %s para dispositivo '%s' (Device ID: %s...)",
            client_ip, body.label, body.client_device_id[:12]
        )

        if not is_allowed_source_ip(client_ip, allow_loopback=allow_loopback):
            logger.warning(
                "Petición POST /pair rechazada: IP de origen '%s' fuera del rango permitido Tailscale (100.64.0.0/10).",
                client_ip
            )
            audit_logger.log_event(
                event_type="PAIR_ATTEMPT",
                result_status="NETWORK_FORBIDDEN",
                client_ip=client_ip
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso de red no autorizado.")

        # Rate limiter check por IP y por device_id (bloqueo con Exponential Backoff)
        is_banned, remaining = rate_limiter.is_banned(client_ip)
        if is_banned:
            logger.warning("Petición POST /pair rechazada: IP %s bloqueada tras fallos reiterados (restan %.1fs)", client_ip, remaining)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"IP temporalmente bloqueada tras fallos reiterados ({int(remaining)}s restantes)."
            )

        is_dev_banned, dev_rem = rate_limiter.is_banned(body.client_device_id)
        if is_dev_banned:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Dispositivo temporalmente bloqueado tras fallos reiterados ({int(dev_rem)}s restantes)."
            )

        if not rate_limiter.check_rate_limit(client_ip):
            logger.warning("Petición POST /pair rechazada: Rate limit excedido para IP %s", client_ip)
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Tasa de peticiones excedida.")

        # Verificar y consumir token de un solo uso (con hmac.compare_digest en tiempo constante)
        is_token_valid = pairing_manager.verify_and_consume_token(body.pairing_token)
        if not is_token_valid:
            reason = pairing_manager.last_rejection_reason or "Token de emparejamiento inválido o expirado"
            logger.warning(
                "Petición POST /pair RECHAZADA para IP %s ('%s'): %s",
                client_ip, body.label, reason
            )
            rate_limiter.record_failure(client_ip)
            rate_limiter.record_failure(body.client_device_id)
            audit_logger.log_event(
                event_type="PAIR_ATTEMPT",
                result_status="INVALID_OR_EXPIRED_TOKEN",
                client_ip=client_ip,
                details={"reason": reason}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de emparejamiento inválido o expirado."
            )

        try:
            raw_pub_bytes = bytes.fromhex(body.client_public_key_hex)
            device_store.register_device(
                device_id=body.client_device_id,
                public_key_bytes=raw_pub_bytes,
                label=body.label
            )
            revoked_device_ids.discard(body.client_device_id)
            rate_limiter.record_success(client_ip)
            rate_limiter.record_success(body.client_device_id)
            logger.info(
                "¡ÉXITO! Dispositivo '%s' (%s) registrado y emparejado correctamente desde %s",
                body.label, body.client_device_id[:12], client_ip
            )
            audit_logger.log_event(
                event_type="PAIR_SUCCESS",
                result_status="REGISTERED",
                device_id=body.client_device_id,
                client_ip=client_ip,
                details={"label": body.label}
            )
            return {
                "status": "SUCCESS",
                "message": "Dispositivo emparejado y registrado exitosamente.",
                "host_device_id": device_store.get_host_device_id(),
                "cert_fingerprint": device_store.get_host_cert_fingerprint(),
            }
        except Exception as e:
            logger.error("Error al registrar dispositivo '%s': %s", body.label, e)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Datos de dispositivo inválidos.")

    @app.websocket("/ws/control")
    async def websocket_control_endpoint(websocket: WebSocket):
        """
        Canal de comunicación bidireccional en tiempo real para despacho de comandos.
        """
        client_ip = websocket.client.host if websocket.client else "UNKNOWN"

        # 1. Mitigación CSWSH (CWE-306): rechazar conexiones con cabecera Origin de navegador no autorizado
        origin = websocket.headers.get("origin")
        if origin and _is_unauthorized_browser_origin(origin):
            logger.warning("Conexión WebSocket rechazada por cabecera Origin no autorizada (%s) desde %s", origin, client_ip)
            audit_logger.log_event(
                event_type="WS_CONNECTION_REJECTED",
                result_status="CSWSH_ORIGIN_REJECTED",
                client_ip=client_ip,
                details={"origin": origin}
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        # 2. Filtro de IP a nivel de transporte (Zero-Trust)
        if not is_allowed_source_ip(client_ip, allow_loopback=allow_loopback):
            logger.warning("Conexión WebSocket rechazada desde IP no autorizada: %s", client_ip)
            audit_logger.log_event(
                event_type="WS_CONNECTION_REJECTED",
                result_status="IP_NOT_ALLOWED",
                client_ip=client_ip
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        # 3. Comprobar si la IP del cliente está en lista de castigo (Banned)
        is_banned, remaining = rate_limiter.is_banned(client_ip)
        if is_banned:
            logger.warning("Conexión WebSocket rechazada por IP suspendida: %s (restan %.1fs)", client_ip, remaining)
            audit_logger.log_event(
                event_type="WS_CONNECTION_REJECTED",
                result_status="IP_BANNED",
                client_ip=client_ip
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        # 4. Límite de clientes concurrentes contra agotamiento de hilos/descriptores (CWE-400)
        if len(active_websockets) >= max_concurrent_ws:
            logger.warning("Conexión WebSocket rechazada: límite de clientes simultáneos (%d) alcanzado", max_concurrent_ws)
            await websocket.close(code=status.WS_1013_TRY_AGAIN_LATER)
            return

        await websocket.accept()
        active_websockets.add(websocket)
        authenticated_device_id: str | None = None
        logger.info("Conexión WebSocket establecida desde: %s", client_ip)

        try:
            while True:
                try:
                    raw_text = await asyncio.wait_for(websocket.receive_text(), timeout=ws_idle_timeout)
                except asyncio.TimeoutError:
                    logger.info("Cerrando WebSocket inactivo desde %s tras %.0fs", client_ip, ws_idle_timeout)
                    await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)
                    return

                # A. Protección Anti-DoS: Rechazo inmediato de mensajes de tamaño excesivo (>64 KB)
                if len(raw_text) > MAX_WS_MESSAGE_SIZE:
                    logger.warning(
                        "Mensaje WebSocket rechazado por exceder el tamaño máximo permitido (%d bytes) desde %s",
                        len(raw_text), client_ip
                    )
                    rate_limiter.record_failure(client_ip)
                    audit_logger.log_event(
                        event_type="PAYLOAD_OVERSIZE",
                        result_status="MESSAGE_TOO_LARGE",
                        client_ip=client_ip,
                        details={"length": len(raw_text)}
                    )
                    await websocket.send_text(json.dumps({
                        "status": ExecutionStatus.REJECTED.value,
                        "message": "Mensaje excede el tamaño máximo permitido (64 KB).",
                        "error_code": "MESSAGE_TOO_LARGE"
                    }))
                    continue

                # Soporte de Heartbeat Ping/Pong ligero para medición de latencia y keep-alive
                if raw_text == '{"type":"PING"}' or raw_text == "PING":
                    if authenticated_device_id and not device_store.is_device_trusted(authenticated_device_id):
                        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                        return
                    await websocket.send_text(json.dumps({"type": "PONG", "timestamp_utc": int(asyncio.get_running_loop().time())}))
                    continue

                # B. Verificación de ban continuo por IP
                is_ip_banned, ip_remaining = rate_limiter.is_banned(client_ip)
                if is_ip_banned:
                    logger.warning("Conexión WebSocket cerrada: IP %s bloqueada tras fallos (restan %.1fs)", client_ip, ip_remaining)
                    await websocket.send_text(json.dumps({
                        "status": ExecutionStatus.REJECTED.value,
                        "message": f"IP temporalmente bloqueada tras fallos reiterados ({int(ip_remaining)}s restantes).",
                        "error_code": "IP_BANNED"
                    }))
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    return

                # C. Parsear SignedEnvelope
                try:
                    envelope = SignedEnvelope.model_validate_json(raw_text)
                except Exception:
                    rate_limiter.record_failure(client_ip)
                    audit_logger.log_event(
                        event_type="MALFORMED_ENVELOPE",
                        result_status="SCHEMA_VALIDATION_ERROR",
                        client_ip=client_ip
                    )
                    await websocket.send_text(json.dumps({
                        "status": ExecutionStatus.REJECTED.value,
                        "message": "Formato de SignedEnvelope inválido.",
                        "error_code": "INVALID_ENVELOPE"
                    }))
                    continue

                dev_id = envelope.device_id

                # C2. Revalidación de revocación en caliente (Hot Revocation -> cierre inmediato 1008)
                if (
                    dev_id in revoked_device_ids
                    or (authenticated_device_id is not None and not device_store.is_device_trusted(dev_id))
                ):
                    logger.warning("Dispositivo revocado en caliente (%s); cerrando WebSocket con 1008 Policy Violation", dev_id[:12])
                    audit_logger.log_event(
                        event_type="WS_REVOKED_TERMINATED",
                        result_status="DEVICE_REVOKED",
                        device_id=dev_id,
                        client_ip=client_ip
                    )
                    await websocket.send_text(json.dumps({
                        "status": ExecutionStatus.REJECTED.value,
                        "message": "Dispositivo revocado por el administrador del Host.",
                        "error_code": "UNTRUSTED_DEVICE"
                    }))
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    return

                # D. Control de Tasa y Ban por device_id
                is_dev_banned, dev_remaining = rate_limiter.is_banned(dev_id)
                if is_dev_banned:
                    await websocket.send_text(json.dumps({
                        "status": ExecutionStatus.REJECTED.value,
                        "message": f"Dispositivo temporalmente bloqueado tras fallos reiterados ({int(dev_remaining)}s restantes).",
                        "error_code": "DEVICE_BANNED"
                    }))
                    continue

                # E. Control de Tasa inteligente: exención de streaming solo para dispositivos ya autorizados
                is_audio_chunk = bool(envelope.command_id == CommandCatalog.MIC_AUDIO_CHUNK)
                is_trusted_device = device_store.is_device_trusted(dev_id)

                if is_audio_chunk and is_trusted_device:
                    if not stream_rate_limiter.check_rate_limit(dev_id):
                        await websocket.send_text(json.dumps({
                            "status": ExecutionStatus.REJECTED.value,
                            "message": "Tasa máxima de streaming de audio excedida.",
                            "error_code": "RATE_LIMITED"
                        }))
                        continue
                else:
                    if not rate_limiter.check_rate_limit(client_ip) or not rate_limiter.check_rate_limit(dev_id):
                        await websocket.send_text(json.dumps({
                            "status": ExecutionStatus.REJECTED.value,
                            "message": "Tasa máxima por dispositivo excedida.",
                            "error_code": "RATE_LIMITED"
                        }))
                        continue

                # F. Despacho Seguro (Validación Ed25519, Anti-Replay y Ejecución)
                result: ExecutionResult = dispatcher.dispatch_safe(envelope)

                # G. Registrar auditoría y penalizaciones inmediatas
                if result.status == ExecutionStatus.SUCCESS:
                    authenticated_device_id = dev_id
                    device_websockets.setdefault(dev_id, set()).add(websocket)
                    rate_limiter.record_success(dev_id)
                    rate_limiter.record_success(client_ip)
                    audit_logger.log_event(
                        event_type="COMMAND_EXECUTED",
                        result_status="SUCCESS",
                        device_id=dev_id,
                        command_id=result.command_id,
                        client_ip=client_ip
                    )
                else:
                    rate_limiter.record_failure(dev_id)
                    rate_limiter.record_failure(client_ip)
                    audit_logger.log_event(
                        event_type="COMMAND_REJECTED",
                        result_status=result.error_code or "REJECTED",
                        device_id=dev_id,
                        command_id=result.command_id,
                        client_ip=client_ip,
                        details={"message": result.message}
                    )

                # Enviar resultado al cliente
                await websocket.send_text(result.model_dump_json())

        except WebSocketDisconnect:
            logger.info("Cliente WebSocket desconectado: %s", client_ip)
        except Exception as e:
            logger.error("Error inesperado en loop WebSocket: %s", e)
        finally:
            active_websockets.discard(websocket)
            if authenticated_device_id and authenticated_device_id in device_websockets:
                device_websockets[authenticated_device_id].discard(websocket)

    return app
