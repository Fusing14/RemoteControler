"""
Punto de entrada principal (CLI Daemon y GUI) de RemoteControler Host.
Manejo de subcomandos: 'gui', 'run', 'pair', 'verify-audit', 'set-pin'.
"""

import sys
import os
import argparse
import getpass
import logging
import uvicorn
import qrcode

# Asegurar codificación UTF-8 en consola de Windows para renderizado del QR
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from host.core.storage.device_store import TrustedDeviceStore
from host.core.storage.pairing import PairingManager
from host.core.security.anti_replay import AntiReplayValidator
from host.core.security.rate_limiter import RateLimiter
from host.core.audit.logger import AuditLogger, verify_audit_log_integrity
from host.engine.dispatcher import CommandDispatcher
from host.engine.handlers.unlock import set_unlock_pin, has_unlock_pin
from host.transport.network_utils import (
    get_tailscale_ip,
    validate_bind_address,
    SecurityConfigurationError,
)
from host.transport.server import create_app
from host.ui.gui import launch_gui

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("RemoteControler.Main")


def cmd_pair(args):
    """Subcomando 'pair': Genera desafío efímero y muestra código QR para la app móvil."""
    device_store = TrustedDeviceStore()
    pairing_mgr = PairingManager(device_store, default_ttl_seconds=args.ttl)

    endpoint = args.endpoint
    if not endpoint:
        tailscale_ip = get_tailscale_ip()
        if tailscale_ip:
            endpoint = f"{tailscale_ip}:{args.port}"
        elif args.dev:
            endpoint = f"127.0.0.1:{args.port}"
        else:
            print("[-] ERROR: No se detectó ninguna IP de Tailscale activa.")
            print("    Asegúrate de que Tailscale esté conectado o usa '--dev' para pruebas locales.")
            sys.exit(1)

    challenge = pairing_mgr.create_pairing_challenge(tailscale_endpoint=endpoint, ttl_seconds=args.ttl)
    qr_payload = pairing_mgr.get_qr_payload()

    print("\n" + "=" * 65)
    print("      REMOTECONTROLER - EMPAREJAMIENTO DE DISPOSITIVO MÓVIL")
    print("=" * 65)
    print(f"[*] Host Device ID : {challenge.host_device_id}")
    print(f"[*] Endpoint       : {challenge.tailscale_endpoint}")
    print(f"[*] Token Efímero  : {challenge.pairing_token}")
    print(f"[*] Válido por     : {args.ttl} segundos (Token de un solo uso)")
    print(f"[*] Estado Vault   : Guardado seguro en disco ('{pairing_mgr.challenge_path.name}')")
    print("=" * 65)
    print("\nEscanea el siguiente código QR desde la App Móvil de RemoteControler:\n")

    qr = qrcode.QRCode()
    qr.add_data(qr_payload)
    qr.make(fit=True)
    qr.print_ascii(invert=True)

    print("\nPayload crudo (si no puedes escanear):")
    print(qr_payload)
    print("\n" + "=" * 65 + "\n")


def cmd_run(args):
    """Subcomando 'run': Inicia el servidor daemon en la interfaz segura."""
    bind_ip = args.bind_ip
    if not bind_ip:
        bind_ip = get_tailscale_ip()
        if not bind_ip:
            if args.dev:
                bind_ip = "127.0.0.1"
                logger.warning("Modo DEV activo: Enlazando a interfaz local 127.0.0.1")
            else:
                logger.critical("No se detectó la interfaz de Tailscale. Abortando por política Zero-Trust.")
                print("[-] ERROR: No se encontró la interfaz de Tailscale (100.64.0.0/10).")
                print("    El servidor se niega a iniciar para evitar exposición indebida.")
                print("    (Para pruebas locales sin Tailscale, ejecuta con el flag '--dev')")
                sys.exit(1)

    try:
        validated_ip = validate_bind_address(bind_ip, allow_loopback=args.dev)
    except SecurityConfigurationError as e:
        logger.critical("Violación de configuración de seguridad: %s", e)
        sys.exit(1)

    device_store = TrustedDeviceStore()
    anti_replay = AntiReplayValidator(max_clock_skew_seconds=30, nonce_ttl_seconds=60)
    dispatcher = CommandDispatcher(device_store, anti_replay)
    pairing_mgr = PairingManager(device_store)
    rate_limiter = RateLimiter(max_rate_per_second=10.0, base_ban_duration_seconds=300.0)
    audit_logger = AuditLogger()

    is_audit_ok, audit_msg = verify_audit_log_integrity(audit_logger.log_path, audit_logger.get_hmac_key())
    if not is_audit_ok:
        logger.critical("¡ALERTA CRÍTICA DE SEGURIDAD! El registro de auditoría local ha sido manipulado:")
        logger.critical(audit_msg)
        print("[-] FALLO DE INTEGRIDAD: El log de auditoría está corrupto o alterado.")
        sys.exit(1)
    else:
        logger.info("Verificación de integridad de auditoría: OK (%s)", audit_msg)

    audit_logger.log_event(
        event_type="DAEMON_STARTUP",
        result_status="INITIALIZED",
        details={"bind_ip": validated_ip, "port": args.port, "dev_mode": args.dev}
    )

    app = create_app(
        dispatcher=dispatcher,
        device_store=device_store,
        pairing_manager=pairing_mgr,
        rate_limiter=rate_limiter,
        audit_logger=audit_logger,
        allow_loopback=args.dev,
    )

    logger.info("Iniciando RemoteControler Host en %s:%d (Tailscale/Restringido)", validated_ip, args.port)
    uvicorn.run(app, host=validated_ip, port=args.port, log_level="info")


def cmd_verify_audit(args):
    """Subcomando 'verify-audit': Audita la cadena criptográfica de logs."""
    audit_logger = AuditLogger()
    is_ok, msg = verify_audit_log_integrity(audit_logger.log_path, audit_logger.get_hmac_key())
    print("\n" + "=" * 65)
    print("      AUDITORÍA DE INTEGRIDAD CRIPTOGRÁFICA (HMAC-SHA256)")
    print("=" * 65)
    print(f"[*] Archivo de Log: {audit_logger.log_path}")
    if is_ok:
        print("[+] ESTADO: ÍNTEGRO (Válido)")
        print(f"[+] Detalle: {msg}")
    else:
        print("[-] ESTADO: ¡MANIPULACIÓN O CORRUPCIÓN DETECTADA!")
        print(f"[-] Detalle: {msg}")
    print("=" * 65 + "\n")
    if not is_ok:
        sys.exit(1)


def cmd_set_pin(args):
    """Subcomando 'set-pin': Configura el PIN de Windows Hello protegido por DPAPI."""
    pin = args.pin
    if not pin:
        pin = getpass.getpass("Introduce el nuevo PIN de Windows Hello: ").strip()
        confirm = getpass.getpass("Confirma el PIN de Windows Hello: ").strip()
        if pin != confirm:
            print("[-] ERROR: Los PINs ingresados no coinciden.")
            sys.exit(1)

    if not pin:
        print("[-] ERROR: El PIN no puede estar vacío.")
        sys.exit(1)

    try:
        set_unlock_pin(pin)
        print("[+] ÉXITO: PIN de Windows Hello cifrado y guardado con DPAPI.")
    except Exception as e:
        print(f"[-] ERROR al guardar el PIN: {e}")
        sys.exit(1)


def main():
    # Si se invoca sin argumentos o con flag --gui, abrir interfaz gráfica
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ("--gui", "-g")):
        launch_gui(minimized=False)
        return

    parser = argparse.ArgumentParser(
        description="RemoteControler Host - Sistema de Control Remoto Zero-Trust para Windows"
    )
    subparsers = parser.add_subparsers(dest="command", required=False)

    # Subcomando gui
    p_gui = subparsers.add_parser("gui", help="Inicia la interfaz gráfica de usuario de escritorio")
    p_gui.add_argument("--minimized", action="store_true", help="Inicia la GUI minimizada en segundo plano")
    p_gui.add_argument("--dev", action="store_true", help="Habilita modo desarrollo local (127.0.0.1)")

    # Subcomando run
    p_run = subparsers.add_parser("run", help="Inicia el servidor daemon en la interfaz segura")
    p_run.add_argument("--bind-ip", type=str, default=None, help="IP específica de enlace (debe ser Tailscale)")
    p_run.add_argument("--port", type=int, default=8443, help="Puerto de escucha (default: 8443)")
    p_run.add_argument("--dev", action="store_true", help="Habilita modo desarrollo local (permite 127.0.0.1)")

    # Subcomando pair
    p_pair = subparsers.add_parser("pair", help="Genera código QR efímero para emparejar cliente móvil")
    p_pair.add_argument("--endpoint", type=str, default=None, help="Endpoint host:puerto a publicitar")
    p_pair.add_argument("--port", type=int, default=8443, help="Puerto a publicitar si no se pasa --endpoint")
    p_pair.add_argument("--ttl", type=int, default=300, help="TTL del token de emparejamiento en segundos (default: 300)")
    p_pair.add_argument("--dev", action="store_true", help="Permite endpoint en localhost para pruebas locales")

    # Subcomando verify-audit
    subparsers.add_parser("verify-audit", help="Verifica la integridad de la cadena de auditoría HMAC")

    # Subcomando set-pin
    p_pin = subparsers.add_parser("set-pin", help="Configura el PIN de Windows Hello cifrado con DPAPI")
    p_pin.add_argument("pin", nargs="?", default=None, help="PIN de desbloqueo (opcional, se solicita si no se pasa)")

    args = parser.parse_args()

    if args.command == "gui" or not args.command:
        minimized = getattr(args, "minimized", False)
        dev = getattr(args, "dev", False)
        launch_gui(minimized=minimized, dev_mode=dev)
    elif args.command == "run":
        cmd_run(args)
    elif args.command == "pair":
        cmd_pair(args)
    elif args.command == "verify-audit":
        cmd_verify_audit(args)
    elif args.command == "set-pin":
        cmd_set_pin(args)


if __name__ == "__main__":
    main()
