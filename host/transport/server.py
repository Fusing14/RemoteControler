"""
Servidor asíncrono WebSocket y HTTP para RemoteControler Host.
Restringido a la interfaz de Tailscale con Rate Limiting y Auditoría criptográfica.
"""

import json
import logging
from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, status
from pydantic import BaseModel, Field

from host.transport.network_utils import is_allowed_source_ip
from host.engine.contracts.envelope import SignedEnvelope
from host.engine.dispatcher import CommandDispatcher, ExecutionResult, ExecutionStatus
from host.core.storage.device_store import TrustedDeviceStore
from host.core.storage.pairing import PairingManager
from host.core.security.rate_limiter import RateLimiter
from host.core.audit.logger import AuditLogger

logger = logging.getLogger("RemoteControler.Server")


class PairRequestBody(BaseModel):
    """Cuerpo de la petición HTTP para emparejar un nuevo dispositivo."""
    pairing_token: str = Field(..., description="Token de desafío de un solo uso escaneado del QR")
    client_public_key_hex: str = Field(..., description="Clave pública Ed25519 del cliente (64 caracteres hex)")
    client_device_id: str = Field(..., description="Huella SHA-256 de la clave pública del cliente")
    label: str = Field(..., max_length=64, description="Etiqueta identificativa del dispositivo móvil")


def create_app(
    dispatcher: CommandDispatcher,
    device_store: TrustedDeviceStore,
    pairing_manager: PairingManager,
    rate_limiter: RateLimiter,
    audit_logger: AuditLogger,
    allow_loopback: bool = False,
) -> FastAPI:
    """
    Factoría de la aplicación FastAPI / Starlette con hardening de seguridad.
    """
    app = FastAPI(title="RemoteControler Daemon", docs_url=None, redoc_url=None)

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

        # Rate limiter check por IP
        if not rate_limiter.check_rate_limit(client_ip):
            logger.warning("Petición POST /pair rechazada: Rate limit excedido para IP %s", client_ip)
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Tasa de peticiones excedida.")

        # Verificar y consumir token de un solo uso
        is_token_valid = pairing_manager.verify_and_consume_token(body.pairing_token)
        if not is_token_valid:
            reason = pairing_manager.last_rejection_reason or "Token de emparejamiento inválido o expirado"
            logger.warning(
                "Petición POST /pair RECHAZADA para IP %s ('%s'): %s",
                client_ip, body.label, reason
            )
            rate_limiter.record_failure(client_ip)
            audit_logger.log_event(
                event_type="PAIR_ATTEMPT",
                result_status="INVALID_OR_EXPIRED_TOKEN",
                client_ip=client_ip,
                details={"reason": reason}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token de emparejamiento inválido o expirado: {reason}"
            )

        try:
            raw_pub_bytes = bytes.fromhex(body.client_public_key_hex)
            device_store.register_device(
                device_id=body.client_device_id,
                public_key_bytes=raw_pub_bytes,
                label=body.label
            )
            rate_limiter.record_success(client_ip)
            logger.info(
                "¡ÉXITO! Dispositivo '%s' (%s) registrado y emparejado correctamente desde %s",
                body.label, body.client_device_id, client_ip
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
                "host_device_id": device_store.get_host_device_id()
            }
        except Exception as e:
            logger.error("Error al registrar dispositivo '%s': %s", body.label, e)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    @app.websocket("/ws/control")
    async def websocket_control_endpoint(websocket: WebSocket):
        """
        Canal de comunicación bidireccional en tiempo real para despacho de comandos.
        """
        client_ip = websocket.client.host if websocket.client else "UNKNOWN"

        # 1. Filtro de IP a nivel de transporte (Zero-Trust)
        if not is_allowed_source_ip(client_ip, allow_loopback=allow_loopback):
            logger.warning("Conexión WebSocket rechazada desde IP no autorizada: %s", client_ip)
            audit_logger.log_event(
                event_type="WS_CONNECTION_REJECTED",
                result_status="IP_NOT_ALLOWED",
                client_ip=client_ip
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        # 2. Comprobar si la IP del cliente está en lista de castigo (Banned)
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

        await websocket.accept()
        logger.info("Conexión WebSocket establecida desde: %s", client_ip)

        try:
            while True:
                raw_text = await websocket.receive_text()

                # Control de Tasa (Rate Limiting) por IP
                if not rate_limiter.check_rate_limit(client_ip):
                    await websocket.send_text(json.dumps({
                        "status": ExecutionStatus.REJECTED.value,
                        "message": "Tasa máxima de peticiones excedida.",
                        "error_code": "RATE_LIMITED"
                    }))
                    continue

                # Parsear SignedEnvelope
                try:
                    envelope = SignedEnvelope.model_validate_json(raw_text)
                except Exception as e:
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

                # Control de Tasa y Ban por device_id
                dev_id = envelope.device_id
                is_dev_banned, dev_remaining = rate_limiter.is_banned(dev_id)
                if is_dev_banned:
                    await websocket.send_text(json.dumps({
                        "status": ExecutionStatus.REJECTED.value,
                        "message": f"Dispositivo temporalmente bloqueado tras fallos reiterados ({int(dev_remaining)}s restantes).",
                        "error_code": "DEVICE_BANNED"
                    }))
                    continue

                if envelope.command_id != CommandCatalog.MIC_AUDIO_CHUNK and not rate_limiter.check_rate_limit(dev_id):
                    await websocket.send_text(json.dumps({
                        "status": ExecutionStatus.REJECTED.value,
                        "message": "Tasa máxima por dispositivo excedida.",
                        "error_code": "RATE_LIMITED"
                    }))
                    continue

                # Despacho Seguro
                result: ExecutionResult = dispatcher.dispatch_safe(envelope)

                # Registrar auditoría y actualizar penalizaciones
                if result.status == ExecutionStatus.SUCCESS:
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

    return app
