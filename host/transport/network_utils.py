"""
Utilidades de red y validación estricta de interfaces para la política Zero-Trust.
Principio: Prohibición absoluta de exposición pública y binding a 0.0.0.0.
"""

import socket
import ipaddress
import logging
from typing import Optional, List
import psutil

logger = logging.getLogger("RemoteControler.Network")

# Rango oficial Carrier-Grade NAT (CGNAT) utilizado por Tailscale (RFC 6598)
TAILSCALE_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


class SecurityConfigurationError(Exception):
    """Excepción lanzada cuando una configuración de red viola las políticas Zero-Trust."""
    pass


def is_tailscale_ip(ip_str: str) -> bool:
    """Verifica si una dirección IP pertenece al rango CGNAT de Tailscale (100.64.0.0/10)."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip in TAILSCALE_CGNAT_NETWORK
    except ValueError:
        return False


def is_loopback_ip(ip_str: str) -> bool:
    """Verifica si una dirección IP es de loopback (127.0.0.1 o ::1)."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_loopback
    except ValueError:
        return False


def is_allowed_source_ip(ip_str: str, allow_loopback: bool = True) -> bool:
    """
    Verifica si una IP de origen está autorizada a nivel de socket/transporte.
    Solo se permiten paquetes provenientes de la malla Tailscale o de localhost en modo desarrollo.
    """
    if is_tailscale_ip(ip_str):
        return True
    if allow_loopback and (ip_str == "testclient" or is_loopback_ip(ip_str)):
        return True
    return False


def get_tailscale_ip() -> Optional[str]:
    """
    Escanea las interfaces de red locales para detectar la IP asignada por Tailscale.
    Retorna la primera dirección IPv4 en el rango 100.64.0.0/10, o None si no se encuentra.
    """
    try:
        adapters = psutil.net_if_addrs()
        for iface_name, snics in adapters.items():
            for snic in snics:
                if snic.family == socket.AF_INET:
                    addr = snic.address
                    if is_tailscale_ip(addr):
                        logger.info("Interfaz Tailscale detectada: %s con IP %s", iface_name, addr)
                        return addr
    except Exception as e:
        logger.error("Error al enumerar interfaces de red: %s", e)

    return None


def validate_bind_address(bind_ip: str, allow_loopback: bool = False) -> str:
    """
    Valida la dirección IP a la que se enlazará el servidor daemon.
    
    Mitigación de Vectores de Ataque:
    1. Prohibición de 0.0.0.0: Impide exponer accidentalmente el daemon a LAN pública o Internet.
    2. Enlace Exclusivo a Tailscale: El socket solo escucha peticiones autenticadas de la malla WireGuard.
    """
    clean_ip = bind_ip.strip()

    # VETO ABSOLUTO de 0.0.0.0 o comodines universales
    if clean_ip in ("0.0.0.0", "::", "", "*"):
        raise SecurityConfigurationError(
            "PROHIBICIÓN ESTRICTA: El binding a 0.0.0.0 o comodines está terminantemente vetado por política Zero-Trust. "
            "El daemon solo puede escuchar en la IP privada de Tailscale o en 127.0.0.1 (modo dev)."
        )

    # Permitir Tailscale
    if is_tailscale_ip(clean_ip):
        return clean_ip

    # Permitir Loopback solo si fue concedido explícitamente
    if is_loopback_ip(clean_ip):
        if allow_loopback:
            logger.warning("ALERTA DE SEGURIDAD: Daemon enlazado a interfaz local (127.0.0.1) en modo desarrollo.")
            return clean_ip
        raise SecurityConfigurationError(
            "El enlace a localhost (127.0.0.1) requiere la activación explícita de allow_loopback=True."
        )

    # Cualquier otra IP (ej. LAN 192.168.x.x o WAN pública) se rechaza
    raise SecurityConfigurationError(
        f"IP de enlace no autorizada: '{clean_ip}'. "
        "Bajo la arquitectura Zero-Trust, el servidor solo puede operar sobre interfaces Tailscale (100.64.0.0/10)."
    )
