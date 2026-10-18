"""
Pruebas unitarias para las funcionalidades de la gran actualización (Major Update):
- Auto-arranque de Windows, accesos directos y lanzador (.bat / .lnk).
- Gestor de procesos 64-bit y clasificación en Primary (ventanas reales) / Background.
- Desbloqueo seguro de Windows y detección de elevación UAC.
- Soporte Wake-on-LAN para encendido en frío con IP LAN física y configuración de adaptadores.
"""

import os
import sys
from pathlib import Path
import pytest

from host.core.autostart import (
    get_project_root,
    get_desktop_path,
    create_desktop_shortcut,
    is_autostart_enabled,
    enable_autostart,
    disable_autostart,
)
from host.core.discovery.process_manager import (
    list_running_apps,
    close_running_app,
    AppCloseSecurityError,
    PROTECTED_PROCESS_NAMES,
)
from host.engine.handlers.unlock import (
    is_elevated_admin,
    relaunch_as_admin,
    set_unlock_pin,
    verify_unlock_pin,
    clear_unlock_pin,
    execute_unlock_pc,
    UnlockAuthenticationError,
)
from host.core.network.wol import (
    get_primary_adapter_info,
    configure_windows_wol,
    build_magic_packet,
    send_magic_packet,
)


def test_project_root_and_desktop_path():
    root = get_project_root()
    assert (root / "host").exists()
    assert (root / "requirements.txt").exists()

    desktop = get_desktop_path()
    assert desktop.exists() or sys.platform != "win32"


def test_create_desktop_shortcut():
    shortcut_path = create_desktop_shortcut()
    assert shortcut_path is not None
    assert Path(shortcut_path).exists()


def test_autostart_lifecycle():
    # Comprobar que las funciones de auto-arranque ejecutan de forma segura sin excepciones no controladas
    enabled_initial = is_autostart_enabled()
    assert isinstance(enabled_initial, bool)

    ok_enable = enable_autostart(minimized=True)
    assert isinstance(ok_enable, bool)

    ok_disable = disable_autostart()
    assert isinstance(ok_disable, bool)


def test_process_manager_listing():
    apps = list_running_apps()
    assert isinstance(apps, list)

    primary_apps = [a for a in apps if a.get("category") == "primary"]
    background_apps = [a for a in apps if a.get("category") == "background"]

    # En Windows interactivo deben encontrarse tanto apps primarias como secundarias
    if sys.platform == "win32":
        assert len(background_apps) > 0

    for app in primary_apps:
        assert "pid" in app
        assert "name" in app
        assert "title" in app
        assert "hwnd" in app
        assert app["pid"] > 0
        assert app["name"].lower() not in PROTECTED_PROCESS_NAMES


def test_process_manager_security_rejections():
    # Intento de cerrar PID de sistema o protegido
    with pytest.raises(AppCloseSecurityError):
        close_running_app(4)

    # Intento de cerrar el propio proceso del host
    with pytest.raises(AppCloseSecurityError):
        close_running_app(os.getpid())

    # Intento de cerrar svchost.exe o csrss.exe
    with pytest.raises(AppCloseSecurityError):
        close_running_app(0)


def test_unlock_pin_lifecycle():
    clear_unlock_pin()
    assert not verify_unlock_pin("1234")

    set_unlock_pin("987654")
    assert verify_unlock_pin("987654")
    assert not verify_unlock_pin("000000")

    clear_unlock_pin()
    assert not verify_unlock_pin("987654")


def test_unlock_authentication_rejection():
    with pytest.raises(UnlockAuthenticationError):
        execute_unlock_pc("clave_incorrecta_de_prueba_invalida_999999")


def test_wol_adapter_info():
    info = get_primary_adapter_info()
    assert "mac" in info
    assert "broadcast_ip" in info
    assert "ipv4" in info
    assert "lan_ip" in info
    assert len(info["mac"].split(":")) == 6
    assert info["broadcast_ip"].endswith(".255") or info["broadcast_ip"] == "255.255.255.255"


def test_wol_configure_windows():
    res = configure_windows_wol()
    assert isinstance(res, dict)
    assert "success" in res
    assert "message" in res


def test_wol_magic_packet_structure():
    mac = "30:56:0F:23:15:2C"
    packet = build_magic_packet(mac)
    assert len(packet) == 102
    assert packet.startswith(b"\xff" * 6)

    # El envío UDP local no debe generar errores fatales
    sent = send_magic_packet(mac, broadcast_ip="127.0.0.1", port=9)
    assert sent is True
