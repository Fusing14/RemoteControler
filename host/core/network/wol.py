"""
Módulo de soporte Wake-on-LAN (WoL) para encendido remoto en frío de la máquina.
Detecta la dirección MAC física del adaptador de red principal (omitiendo adaptadores
virtuales de Tailscale, Docker, Hyper-V, vEthernet, etc.) y calcula la IP de difusión.
"""

import ipaddress
import json
import logging
import re
import socket
import subprocess
import sys
from typing import Optional, Dict, Any, List

logger = logging.getLogger("RemoteControler.WoL")

VIRTUAL_ADAPTER_KEYWORDS = [
    "tailscale",
    "virtual",
    "docker",
    "hyper-v",
    "vethernet",
    "vpn",
    "loopback",
    "wsl",
    "bluetooth",
    "vmware",
    "tap",
    "pseudo",
]


def normalize_mac_address(mac: str) -> str:
    """Normaliza una dirección MAC al formato estándar XX:XX:XX:XX:XX:XX en mayúsculas."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(cleaned) != 12:
        raise ValueError(f"Dirección MAC no válida (se esperaban 12 dígitos hexadecimales): {mac}")
    return ":".join(cleaned[i:i + 2].upper() for i in range(0, 12, 2))


def build_magic_packet(mac_address: str) -> bytes:
    """
    Construye un paquete mágico Wake-on-LAN estándar de 102 bytes:
    6 bytes de 0xFF seguidos de 16 repeticiones de la dirección MAC de 6 bytes.
    """
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac_address)
    if len(cleaned) != 12:
        raise ValueError(f"Dirección MAC no válida: {mac_address}")

    mac_bytes = bytes.fromhex(cleaned)
    if len(mac_bytes) != 6:
        raise ValueError("Longitud de bytes MAC errónea.")

    return (b"\xff" * 6) + (mac_bytes * 16)


def _detect_adapters_windows() -> List[Dict[str, Any]]:
    """Consulta adaptadores activos en Windows vía WMI / PowerShell."""
    adapters = []
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object IPEnabled -eq $true | "
            "Select-Object Description, MACAddress, IPAddress, IPSubnet, DefaultIPGateway | ConvertTo-Json",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            raw_data = json.loads(res.stdout)
            if isinstance(raw_data, dict):
                raw_data = [raw_data]

            for item in raw_data:
                desc = item.get("Description") or ""
                mac = item.get("MACAddress")
                if not mac:
                    continue

                ip_list = item.get("IPAddress") or []
                if isinstance(ip_list, str):
                    ip_list = [ip_list]

                subnets = item.get("IPSubnet") or []
                if isinstance(subnets, str):
                    subnets = [subnets]

                gateways = item.get("DefaultIPGateway") or []
                if isinstance(gateways, str):
                    gateways = [gateways]

                # Buscar primera IPv4 válida
                ipv4 = None
                mask = "255.255.255.0"
                for i, ip_str in enumerate(ip_list):
                    if "." in ip_str and not ip_str.startswith("127."):
                        ipv4 = ip_str
                        if i < len(subnets) and "." in subnets[i]:
                            mask = subnets[i]
                        break

                has_gateway = any("." in g for g in gateways)

                adapters.append({
                    "description": desc,
                    "mac": mac,
                    "ipv4": ipv4,
                    "subnet": mask,
                    "has_gateway": has_gateway,
                })
    except Exception as e:
        logger.debug("Error consultando WMI PowerShell para adaptadores: %s", e)

    # Fallback ipconfig /all
    if not adapters:
        try:
            res = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, errors="ignore", timeout=5)
            if res.returncode == 0:
                cur_desc = ""
                cur_mac = None
                cur_ip = None
                cur_mask = "255.255.255.0"
                cur_gateway = False

                for line in res.stdout.splitlines():
                    trimmed = line.strip()
                    if "adapter" in line.lower() and not line.startswith(" "):
                        if cur_mac:
                            adapters.append({
                                "description": cur_desc,
                                "mac": cur_mac,
                                "ipv4": cur_ip,
                                "subnet": cur_mask,
                                "has_gateway": cur_gateway,
                            })
                        cur_desc = trimmed
                        cur_mac = None
                        cur_ip = None
                        cur_gateway = False

                    if ("direcci" in line.lower() and "sica" in line.lower()) or "physical address" in line.lower():
                        parts = line.split(":")
                        if len(parts) > 1:
                            cand = parts[1].strip()
                            if len(re.sub(r"[^0-9a-fA-F]", "", cand)) == 12:
                                cur_mac = cand
                    elif "ipv4" in line.lower() and ":" in line:
                        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                        if m:
                            cur_ip = m.group(1)
                    elif ("m" in line.lower() and "scara" in line.lower()) or "subnet mask" in line.lower():
                        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                        if m:
                            cur_mask = m.group(1)
                    elif ("puerta" in line.lower() and "enlace" in line.lower()) or "default gateway" in line.lower():
                        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line):
                            cur_gateway = True

                if cur_mac:
                    adapters.append({
                        "description": cur_desc,
                        "mac": cur_mac,
                        "ipv4": cur_ip,
                        "subnet": cur_mask,
                        "has_gateway": cur_gateway,
                    })
        except Exception as ex:
            logger.debug("Error ejecutando ipconfig /all: %s", ex)

    return adapters


def get_primary_adapter_info() -> Dict[str, Any]:
    """
    Obtiene la información del adaptador físico primario adecuado para Wake-on-LAN.
    Descarta adaptadores virtuales como Tailscale, VPNs y Docker.
    """
    if sys.platform == "win32":
        adapters = _detect_adapters_windows()
        # Filtrar adaptadores virtuales
        filtered = []
        for ad in adapters:
            desc_lower = ad.get("description", "").lower()
            if any(k in desc_lower for k in VIRTUAL_ADAPTER_KEYWORDS):
                continue
            # Ignorar IPs de Tailscale 100.64.0.0/10
            ipv4 = ad.get("ipv4")
            if ipv4 and ipv4.startswith("100."):
                continue
            filtered.append(ad)

        # Priorizar adaptador con puerta de enlace configurada
        selected = None
        for ad in filtered:
            if ad.get("has_gateway") and ad.get("ipv4"):
                selected = ad
                break

        if not selected and filtered:
            selected = filtered[0]

        if selected:
            norm_mac = normalize_mac_address(selected["mac"])
            ipv4 = selected.get("ipv4") or "192.168.1.1"
            subnet = selected.get("subnet") or "255.255.255.0"
            bcast = "255.255.255.255"
            try:
                net = ipaddress.IPv4Network(f"{ipv4}/{subnet}", strict=False)
                bcast = str(net.broadcast_address)
            except Exception:
                pass

            return {
                "mac": norm_mac,
                "broadcast_ip": bcast,
                "ipv4": ipv4,
                "description": selected.get("description", "Adaptador Físico"),
            }

    # Fallback genérico para entornos no-Windows o pruebas unitarias
    return {
        "mac": "00:11:22:33:44:55",
        "broadcast_ip": "255.255.255.255",
        "ipv4": "127.0.0.1",
        "description": "Adaptador de prueba",
    }


def get_primary_physical_mac() -> str:
    """Devuelve la dirección MAC física del adaptador primario para WoL."""
    info = get_primary_adapter_info()
    return info["mac"]


def get_broadcast_ip() -> str:
    """Devuelve la dirección IP de difusión de la subred local."""
    info = get_primary_adapter_info()
    return info["broadcast_ip"]


def send_magic_packet(mac_address: str, broadcast_ip: str = "255.255.255.255", port: int = 9) -> bool:
    """Envía un paquete mágico Wake-on-LAN por difusión UDP."""
    try:
        packet = build_magic_packet(mac_address)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.sendto(packet, (broadcast_ip, port))
            return True
        finally:
            sock.close()
    except Exception as e:
        logger.error("Error al enviar paquete Wake-on-LAN: %s", e)
        return False
