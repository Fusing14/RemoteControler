"""
Módulo de soporte Wake-on-LAN (WoL) para encendido remoto en frío de la máquina.
Detecta la dirección MAC física del adaptador de red principal (omitiendo adaptadores
virtuales de Tailscale, ZeroTier, Docker, Hyper-V, WSL, vEthernet, VMware, VirtualBox, etc.),
calcula la IP LAN y dirección de broadcast de subred, y autoconfigura Windows 10/11
(desactivando Inicio Rápido / Hiberboot y habilitando Wake on Magic Packet en la NIC).
"""

import ipaddress
import json
import logging
import re
import socket
import subprocess
import sys
import time
from typing import Optional, Dict, Any, List

from host.core.security.path_security import resolve_system_binary

logger = logging.getLogger("RemoteControler.WoL")

VIRTUAL_ADAPTER_KEYWORDS = [
    "tailscale",
    "zerotier",
    "virtual",
    "docker",
    "hyper-v",
    "vethernet",
    "vpn",
    "loopback",
    "wsl",
    "bluetooth",
    "vmware",
    "virtualbox",
    "vbox",
    "npcap",
    "tap",
    "tun",
    "wireguard",
    "pseudo",
    "wan miniport",
    "teredo",
    "isatap",
    "hamachi",
    "radmin",
]

WIFI_ADAPTER_KEYWORDS = [
    "wi-fi",
    "wifi",
    "wireless",
    "wlan",
    "802.11",
    "inalámbric",
    "inalambric",
]


def normalize_mac_address(mac: str) -> str:
    """Normaliza una dirección MAC al formato estándar XX:XX:XX:XX:XX:XX en mayúsculas."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(cleaned) != 12:
        raise ValueError(f"Dirección MAC no válida (se esperaban 12 dígitos hexadecimales): {mac}")
    if cleaned.upper() in ("000000000000", "FFFFFFFFFFFF"):
        raise ValueError(f"Dirección MAC reservada o nula no válida: {mac}")
    return ":".join(cleaned[i:i + 2].upper() for i in range(0, 12, 2))


def build_magic_packet(mac_address: str) -> bytes:
    """
    Construye un paquete mágico Wake-on-LAN estándar de 102 bytes:
    6 bytes de 0xFF seguidos de 16 repeticiones de la dirección MAC de 6 bytes.
    """
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac_address or "")
    if len(cleaned) != 12:
        raise ValueError(f"Dirección MAC no válida: {mac_address}")

    mac_bytes = bytes.fromhex(cleaned)
    if len(mac_bytes) != 6:
        raise ValueError("Longitud de bytes MAC errónea.")

    return (b"\xff" * 6) + (mac_bytes * 16)


def _is_virtual_adapter(description: str, ipv4: Optional[str] = None) -> bool:
    """Determina si un adaptador de red corresponde a una interfaz virtual o túnel VPN."""
    desc_lower = (description or "").lower()
    if any(k in desc_lower for k in VIRTUAL_ADAPTER_KEYWORDS):
        return True
    if ipv4:
        # Ignorar rango CGNAT/Tailscale 100.64.0.0/10, loopback 127.0.0.0/8 y APIPA 169.254.0.0/16
        if ipv4.startswith("100.") or ipv4.startswith("127.") or ipv4.startswith("169.254."):
            return True
    return False


def _is_ethernet_adapter(description: str) -> bool:
    """Indica si el adaptador es cableado (Ethernet PCIe/Integrado) frente a Wi-Fi."""
    desc_lower = (description or "").lower()
    if any(w in desc_lower for w in WIFI_ADAPTER_KEYWORDS):
        return False
    return True


def _detect_adapters_windows() -> List[Dict[str, Any]]:
    """Consulta adaptadores activos en Windows vía WMI / PowerShell con ruta absoluta segura."""
    adapters: List[Dict[str, Any]] = []
    try:
        ps_bin = resolve_system_binary("powershell.exe")
        cmd = [
            ps_bin,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object IPEnabled -eq $true | "
            "Select-Object Description, MACAddress, IPAddress, IPSubnet, DefaultIPGateway | ConvertTo-Json",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
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
                    "is_ethernet": _is_ethernet_adapter(desc),
                })
    except Exception as e:
        logger.debug("Error consultando WMI PowerShell para adaptadores: %s", e)

    # Fallback ipconfig /all
    if not adapters:
        try:
            ipconfig_bin = resolve_system_binary("ipconfig.exe")
            res = subprocess.run([ipconfig_bin, "/all"], capture_output=True, text=True, errors="ignore", timeout=5)
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
                                "is_ethernet": _is_ethernet_adapter(cur_desc),
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
                        "is_ethernet": _is_ethernet_adapter(cur_desc),
                    })
        except Exception as ex:
            logger.debug("Error ejecutando ipconfig /all: %s", ex)

    return adapters


def get_primary_adapter_info() -> Dict[str, Any]:
    """
    Obtiene la información del adaptador físico primario adecuado para Wake-on-LAN.
    Descarta adaptadores virtuales (Tailscale, ZeroTier, VPNs, Docker, WSL, Hyper-V)
    y prioriza adaptadores Ethernet físicos con puerta de enlace activa sobre Wi-Fi.
    """
    if sys.platform == "win32":
        adapters = _detect_adapters_windows()
        filtered = []
        for ad in adapters:
            if _is_virtual_adapter(ad.get("description", ""), ad.get("ipv4")):
                continue
            filtered.append(ad)

        # Ordenar por prioridad:
        # 1) Tiene puerta de enlace (default gateway) y IPv4
        # 2) Es Ethernet cableado frente a Wi-Fi
        filtered.sort(
            key=lambda a: (
                bool(a.get("has_gateway") and a.get("ipv4")),
                bool(a.get("is_ethernet", True)),
                bool(a.get("ipv4")),
            ),
            reverse=True,
        )

        selected = filtered[0] if filtered else None

        if selected:
            try:
                norm_mac = normalize_mac_address(selected["mac"])
            except ValueError:
                norm_mac = "00:11:22:33:44:55"
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
                "lan_ip": ipv4,
                "subnet": subnet,
                "is_ethernet": bool(selected.get("is_ethernet", True)),
                "description": selected.get("description", "Adaptador Físico"),
            }

    # Fallback genérico para entornos no-Windows o pruebas unitarias
    return {
        "mac": "00:11:22:33:44:55",
        "broadcast_ip": "255.255.255.255",
        "ipv4": "127.0.0.1",
        "lan_ip": "127.0.0.1",
        "subnet": "255.255.255.0",
        "is_ethernet": True,
        "description": "Adaptador de prueba",
    }


def diagnose_wol_status() -> Dict[str, Any]:
    """
    Ejecuta un diagnóstico completo del estado de Wake-on-LAN en Windows:
    - Comprueba si Fast Startup (HiberbootEnabled) está desactivado (0).
    - Identifica el adaptador físico primario (MAC, IP LAN, Broadcast, Ethernet vs Wi-Fi).
    """
    adapter_info = get_primary_adapter_info()
    if sys.platform != "win32":
        return {
            "ready": True,
            "hiberboot_disabled": True,
            "adapter": adapter_info,
        }

    hiberboot_disabled = False
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
            0,
            winreg.KEY_READ,
        ) as key:
            val, _ = winreg.QueryValueEx(key, "HiberbootEnabled")
            hiberboot_disabled = int(val) == 0
    except Exception:
        pass

    return {
            "ready": bool(hiberboot_disabled and adapter_info.get("mac") != "00:11:22:33:44:55"),
            "hiberboot_disabled": hiberboot_disabled,
            "adapter": adapter_info,
    }


def configure_windows_wol() -> Dict[str, Any]:
    """
    Configura Windows 10/11 para soportar Wake-on-LAN en frío (Cold Boot / S5):
    1. Deshabilita Inicio Rápido (HiberbootEnabled = 0) en el Registro HKLM, evitando que
       el apagado híbrido S4 corte la escucha de Magic Packets en la tarjeta de red.
    2. Habilita 'Wake on Magic Packet' y propiedades avanzadas (*WakeOnMagicPacket,
       *PMARPOffload, *WakeOnPattern) en los adaptadores físicos de red mediante PowerShell.
    """
    if sys.platform != "win32":
        return {
            "success": True,
            "hiberboot_disabled": True,
            "adapters_configured": True,
            "message": "Configuración simulada para entorno no-Windows.",
        }

    hiber_ok = False
    adapters_ok = False
    messages = []

    # 1. Deshabilitar Fast Startup en Registro HKLM usando ruta absoluta de System32
    try:
        reg_bin = resolve_system_binary("reg.exe")
        reg_cmd = [
            reg_bin,
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power",
            "/v",
            "HiberbootEnabled",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ]
        res = subprocess.run(reg_cmd, capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            hiber_ok = True
            messages.append("Inicio Rápido (Fast Startup / Hiberboot) deshabilitado (HiberbootEnabled=0).")
        else:
            messages.append(f"No se pudo deshabilitar Fast Startup (requiere Administrador): {res.stderr.strip()}")
    except Exception as e:
        messages.append(f"Error al modificar HiberbootEnabled: {e}")

    # 2. Configurar adaptadores de red físicos con Enable-NetAdapterPowerManagement y propiedades avanzadas
    try:
        ps_bin = resolve_system_binary("powershell.exe")
        ps_code = (
            "Get-NetAdapter | Where-Object { "
            "$_.Status -eq 'Up' -and "
            "$_.InterfaceDescription -notmatch 'Virtual|Tailscale|ZeroTier|VPN|Hyper-V|Loopback|Docker|vEthernet|WSL|VMware|VirtualBox|Bluetooth|TAP|WireGuard' "
            "} | ForEach-Object { "
            "Enable-NetAdapterPowerManagement -Name $_.Name -WakeOnMagicPacket -ErrorAction SilentlyContinue; "
            "Set-NetAdapterPowerManagement -Name $_.Name -WakeOnMagicPacket Enabled -WakeOnPattern Enabled -ArpOffload Enabled -ErrorAction SilentlyContinue; "
            "Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword '*WakeOnMagicPacket' -RegistryValue 1 -ErrorAction SilentlyContinue; "
            "Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword '*PMARPOffload' -RegistryValue 1 -ErrorAction SilentlyContinue; "
            "Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword '*WakeOnPattern' -RegistryValue 1 -ErrorAction SilentlyContinue; "
            "Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName '*Wake*' -DisplayValue 'Enabled' -ErrorAction SilentlyContinue "
            "}"
        )
        res = subprocess.run(
            [ps_bin, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_code],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if res.returncode == 0:
            adapters_ok = True
            messages.append("Wake-on-Magic-Packet y ARP Offload activados en adaptadores físicos.")
        else:
            messages.append(f"Fallo al configurar adaptadores de red: {res.stderr.strip()}")
    except Exception as e:
        messages.append(f"Error ejecutando PowerShell para adaptadores WoL: {e}")

    overall_success = hiber_ok or adapters_ok
    return {
        "success": overall_success,
        "hiberboot_disabled": hiber_ok,
        "adapters_configured": adapters_ok,
        "message": " | ".join(messages),
    }


def get_primary_physical_mac() -> str:
    """Devuelve la dirección MAC física del adaptador primario para WoL."""
    info = get_primary_adapter_info()
    return info["mac"]


def get_broadcast_ip() -> str:
    """Devuelve la dirección IP de difusión de la subred local."""
    info = get_primary_adapter_info()
    return info["broadcast_ip"]


def get_lan_ip() -> str:
    """Devuelve la dirección IPv4 física de la red local (LAN) del Host."""
    info = get_primary_adapter_info()
    return info.get("lan_ip") or info.get("ipv4") or "127.0.0.1"


def send_magic_packet(
    mac_address: str,
    broadcast_ip: str = "255.255.255.255",
    port: int = 9,
    unicast_ips: Optional[List[str]] = None,
) -> bool:
    """
    Envía ráfagas multi-ruta de paquetes mágicos Wake-on-LAN por difusión y unicast UDP.
    Transmite a:
      - 255.255.255.255 (Broadcast global LAN)
      - broadcast_ip (Broadcast dirigido de subred local, ej. 192.168.1.255)
      - unicast_ips opcionales (IP LAN física / IP Tailscale)
    en los puertos estándar de WoL (7, 9 y 40000), realizando dos ráfagas separadas por 100ms.
    """
    try:
        packet = build_magic_packet(mac_address)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        targets = {broadcast_ip, "255.255.255.255"}
        if unicast_ips:
            for ip in unicast_ips:
                if ip and ip.strip():
                    targets.add(ip.strip())

        ports = {port, 7, 9, 40000}

        try:
            for attempt in range(2):
                for p in sorted(ports):
                    for target in sorted(targets):
                        try:
                            sock.sendto(packet, (target, p))
                        except Exception:
                            pass
                if attempt == 0:
                    time.sleep(0.1)
            return True
        finally:
            sock.close()
    except Exception as e:
        logger.error("Error al enviar paquete Wake-on-LAN: %s", e)
        return False
