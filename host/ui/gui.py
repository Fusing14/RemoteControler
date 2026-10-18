"""
Panel de control de escritorio gráfico (GUI) para RemoteControler Host.
Construido con Tkinter nativo y Pillow, estilizado en modo oscuro.
Permite gestionar la sesión, vincular dispositivos móviles mediante QR,
configurar el PIN de desbloqueo, y activar el auto-arranque con Windows.
"""

import logging
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional

from PIL import Image, ImageTk
import qrcode
import uvicorn

from host.core.storage.device_store import TrustedDeviceStore
from host.core.storage.pairing import PairingManager
from host.core.storage.host_config import HostConfig
from host.core.security.anti_replay import AntiReplayValidator
from host.core.security.rate_limiter import RateLimiter
from host.core.audit.logger import AuditLogger
from host.engine.dispatcher import CommandDispatcher
from host.engine.handlers.unlock import (
    has_unlock_pin,
    set_unlock_pin,
    clear_unlock_pin,
    is_elevated_admin,
    relaunch_as_admin,
)
from host.core.autostart import (
    is_autostart_enabled,
    enable_autostart,
    disable_autostart,
    create_desktop_shortcut,
)
from host.core.network.wol import (
    get_primary_physical_mac,
    get_broadcast_ip,
    configure_windows_wol,
)
from host.transport.network_utils import get_tailscale_ip, validate_bind_address
from host.transport.server import create_app

logger = logging.getLogger("RemoteControler.GUI")

# Paleta de colores Dark Theme
BG_COLOR = "#090A0F"
CARD_BG = "#11141C"
CARD_BORDER = "#1E2230"
ACCENT_PRIMARY = "#6366F1"  # Indigo
ACCENT_HOVER = "#4F46E5"
TEXT_PRIMARY = "#F8FAFC"
TEXT_SECONDARY = "#94A3B8"
COLOR_SUCCESS = "#10B981"  # Esmeralda
COLOR_DANGER = "#EF4444"   # Rojo
COLOR_WARNING = "#F59E0B"  # Ámbar


class HostDashboardApp:
    """Ventana principal del panel de control de RemoteControler."""

    def __init__(self, root: tk.Tk, minimized: bool = False, dev_mode: bool = False) -> None:
        self.root = root
        self.minimized = minimized
        self.dev_mode = dev_mode

        self.config = HostConfig()
        self.device_store = TrustedDeviceStore()
        self.pairing_manager = PairingManager(self.device_store)

        # Variables de estado del servidor
        self.server_thread: Optional[threading.Thread] = None
        self.uvicorn_server: Optional[uvicorn.Server] = None
        self.is_running = False
        self.server_ip = "127.0.0.1" if dev_mode else (get_tailscale_ip() or "127.0.0.1")
        self.server_port = int(self.config.get("port", 8443))

        self.is_admin = is_elevated_admin()
        try:
            self.mac_address = get_primary_physical_mac()
            self.broadcast_ip = get_broadcast_ip()
        except Exception:
            self.mac_address = "No detectado"
            self.broadcast_ip = "255.255.255.255"

        self._qr_image_ref = None  # Evitar recolección de basura en Tkinter

        self._setup_window()
        self._build_ui()
        self._start_server()

        if self.minimized:
            self.root.iconify()

    def _setup_window(self) -> None:
        self.root.title("RemoteControler - Panel de Control Host")
        self.root.geometry("680x760")
        self.root.minsize(620, 680)
        self.root.configure(bg=BG_COLOR)

        # Configurar estilos ttk oscuros
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=BG_COLOR, foreground=TEXT_PRIMARY)
        style.configure("TFrame", background=BG_COLOR)
        style.configure("Card.TFrame", background=CARD_BG, relief="flat")
        style.configure("TLabel", background=BG_COLOR, foreground=TEXT_PRIMARY, font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=CARD_BG, foreground=TEXT_PRIMARY, font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background=CARD_BG, foreground=TEXT_PRIMARY, font=("Segoe UI", 12, "bold"))
        style.configure("CardMuted.TLabel", background=CARD_BG, foreground=TEXT_SECONDARY, font=("Segoe UI", 9))

        # Botones personalizados
        style.configure(
            "Primary.TButton",
            background=ACCENT_PRIMARY,
            foreground="#FFFFFF",
            font=("Segoe UI", 10, "bold"),
            padding=(12, 6),
            borderwidth=0,
        )
        style.map("Primary.TButton", background=[("active", ACCENT_HOVER)])

        style.configure(
            "Danger.TButton",
            background=COLOR_DANGER,
            foreground="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            padding=(8, 4),
            borderwidth=0,
        )
        style.map("Danger.TButton", background=[("active", "#DC2626")])

        # Checkbuttons oscuros
        style.configure(
            "Card.TCheckbutton",
            background=CARD_BG,
            foreground=TEXT_PRIMARY,
            font=("Segoe UI", 10),
            focuscolor=CARD_BG,
        )

        # Treeview oscuro para dispositivos vinculados
        style.configure(
            "Treeview",
            background="#0F1117",
            foreground=TEXT_PRIMARY,
            fieldbackground="#0F1117",
            font=("Segoe UI", 9),
            rowheight=26,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#1E2230",
            foreground=TEXT_PRIMARY,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )
        style.map("Treeview.Heading", background=[("active", "#2D3446")])

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        main_container = ttk.Frame(self.root, padding=20)
        main_container.pack(fill="both", expand=True)

        # 1. Cabecera principal
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill="x", pady=(0, 16))

        title_lbl = tk.Label(
            header_frame,
            text="RemoteControler Host",
            font=("Segoe UI", 18, "bold"),
            fg=TEXT_PRIMARY,
            bg=BG_COLOR,
        )
        title_lbl.pack(side="left")

        self.status_badge = tk.Label(
            header_frame,
            text="Iniciando...",
            font=("Segoe UI", 9, "bold"),
            fg=COLOR_WARNING,
            bg="#231B0A",
            padx=10,
            pady=4,
            relief="flat",
        )
        self.status_badge.pack(side="right")

        # 2. Tarjeta: Estado del Servidor
        server_card = self._create_card(main_container, "Servidor y Conexión")

        info_grid = ttk.Frame(server_card, style="Card.TFrame")
        info_grid.pack(fill="x", padx=14, pady=(6, 12))

        ttk.Label(info_grid, text="Endpoint de red:", style="CardMuted.TLabel").grid(row=0, column=0, sticky="w", pady=2)
        self.lbl_endpoint = ttk.Label(info_grid, text=f"{self.server_ip}:{self.server_port}", style="Card.TLabel", font=("Consolas", 10, "bold"))
        self.lbl_endpoint.grid(row=0, column=1, sticky="w", padx=10, pady=2)

        ttk.Label(info_grid, text="Modo de red:", style="CardMuted.TLabel").grid(row=1, column=0, sticky="w", pady=2)
        mode_text = "Tailscale Zero-Trust" if not self.dev_mode else "Modo Desarrollo Local (127.0.0.1)"
        ttk.Label(info_grid, text=mode_text, style="Card.TLabel").grid(row=1, column=1, sticky="w", padx=10, pady=2)

        ttk.Label(info_grid, text="PIN de desbloqueo:", style="CardMuted.TLabel").grid(row=2, column=0, sticky="w", pady=2)
        self.lbl_pin_status = ttk.Label(info_grid, text="Comprobando...", style="Card.TLabel")
        self.lbl_pin_status.grid(row=2, column=1, sticky="w", padx=10, pady=2)
        self._update_pin_status_label()

        ttk.Label(info_grid, text="Wake-on-LAN (MAC):", style="CardMuted.TLabel").grid(row=3, column=0, sticky="w", pady=2)
        mac_text = f"{self.mac_address} (Listo)" if self.mac_address and self.mac_address != "No detectado" else "No detectado"
        self.lbl_wol = ttk.Label(info_grid, text=mac_text, style="Card.TLabel", font=("Consolas", 10))
        self.lbl_wol.grid(row=3, column=1, sticky="w", padx=10, pady=2)

        ttk.Label(info_grid, text="Permisos de Windows:", style="CardMuted.TLabel").grid(row=4, column=0, sticky="w", pady=2)
        perm_text = "Administrador (Elevado - Desbloqueo Total)" if self.is_admin else "Usuario Estándar (Sin elevación)"
        perm_color = COLOR_SUCCESS if self.is_admin else COLOR_WARNING
        self.lbl_perms = tk.Label(info_grid, text=perm_text, fg=perm_color, bg=CARD_BG, font=("Segoe UI", 9, "bold"))
        self.lbl_perms.grid(row=4, column=1, sticky="w", padx=10, pady=2)

        # Botonera de acciones de servidor
        btn_row = ttk.Frame(server_card, style="Card.TFrame")
        btn_row.pack(fill="x", padx=14, pady=(0, 12))

        self.btn_toggle_server = tk.Button(
            btn_row,
            text="Detener Servidor",
            command=self._toggle_server,
            bg=COLOR_DANGER,
            fg="#FFFFFF",
            activebackground="#DC2626",
            activeforeground="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2",
        )
        self.btn_toggle_server.pack(side="left", padx=(0, 8))

        btn_qr = tk.Button(
            btn_row,
            text="Vincular nuevo teléfono (Mostrar QR)",
            command=self._show_pairing_qr_dialog,
            bg=ACCENT_PRIMARY,
            fg="#FFFFFF",
            activebackground=ACCENT_HOVER,
            activeforeground="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2",
        )
        btn_qr.pack(side="left", padx=4)

        btn_pin = tk.Button(
            btn_row,
            text="Configurar PIN",
            command=self._show_pin_dialog,
            bg="#2E384D",
            fg="#FFFFFF",
            activebackground="#3D4B66",
            activeforeground="#FFFFFF",
            font=("Segoe UI", 9),
            relief="flat",
            padx=10,
            pady=6,
            cursor="hand2",
        )
        btn_pin.pack(side="left", padx=4)

        self.btn_update = tk.Button(
            btn_row,
            text="Actualizar Servidor",
            command=self._on_update_server_clicked,
            bg="#0D9488",
            fg="#FFFFFF",
            activebackground="#0F766E",
            activeforeground="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=10,
            pady=6,
            cursor="hand2",
        )
        self.btn_update.pack(side="left", padx=4)

        if not self.is_admin:
            self.btn_elevate = tk.Button(
                btn_row,
                text="🛡️ Ejecutar como Admin",
                command=self._relaunch_admin,
                bg="#D97706",
                fg="#FFFFFF",
                activebackground="#B45309",
                activeforeground="#FFFFFF",
                font=("Segoe UI", 9, "bold"),
                relief="flat",
                padx=10,
                pady=6,
                cursor="hand2",
            )
            self.btn_elevate.pack(side="left", padx=4)

        # 3. Tarjeta: Preferencias y Persistencia
        prefs_card = self._create_card(main_container, "Preferencias de Sesión y Arranque")

        self.var_keep_session = tk.BooleanVar(value=self.config.keep_session_open)
        chk_keep = ttk.Checkbutton(
            prefs_card,
            text="Mantener sesión abierta permanentemente (Reconexión automática instantánea)",
            variable=self.var_keep_session,
            command=self._on_keep_session_toggle,
            style="Card.TCheckbutton",
        )
        chk_keep.pack(anchor="w", padx=14, pady=6)

        self.var_auto_start = tk.BooleanVar(value=is_autostart_enabled() or self.config.auto_start)
        chk_autostart = ttk.Checkbutton(
            prefs_card,
            text="Iniciar automáticamente al encender el PC (Inicio minimizado)",
            variable=self.var_auto_start,
            command=self._on_auto_start_toggle,
            style="Card.TCheckbutton",
        )
        chk_autostart.pack(anchor="w", padx=14, pady=(0, 10))

        prefs_btn_row = ttk.Frame(prefs_card, style="Card.TFrame")
        prefs_btn_row.pack(fill="x", padx=14, pady=(0, 12))

        btn_shortcut = tk.Button(
            prefs_btn_row,
            text="📌 Crear Acceso Directo en Escritorio",
            command=self._create_desktop_shortcut,
            bg="#1E2230",
            fg=TEXT_PRIMARY,
            activebackground="#2A3144",
            activeforeground="#FFFFFF",
            font=("Segoe UI", 9),
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
        )
        btn_shortcut.pack(side="left", padx=(0, 8))

        btn_wol = tk.Button(
            prefs_btn_row,
            text="⚡ Configurar Placa/Red (WoL)",
            command=self._configure_wol,
            bg="#1E2230",
            fg=TEXT_PRIMARY,
            activebackground="#2A3144",
            activeforeground="#FFFFFF",
            font=("Segoe UI", 9),
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
        )
        btn_wol.pack(side="left")

        # 4. Tarjeta: Dispositivos Móviles Autorizados
        devices_card = self._create_card(main_container, "Teléfonos y Dispositivos Vinculados")

        table_frame = ttk.Frame(devices_card, style="Card.TFrame")
        table_frame.pack(fill="both", expand=True, padx=14, pady=(6, 10))

        columns = ("label", "device_id", "registered_at")
        self.device_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=5)
        self.device_tree.heading("label", text="Nombre / Teléfono")
        self.device_tree.heading("device_id", text="Device ID")
        self.device_tree.heading("registered_at", text="Fecha de Vinculación")

        self.device_tree.column("label", width=160, anchor="w")
        self.device_tree.column("device_id", width=220, anchor="w")
        self.device_tree.column("registered_at", width=140, anchor="center")
        self.device_tree.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        dev_btn_row = ttk.Frame(devices_card, style="Card.TFrame")
        dev_btn_row.pack(fill="x", padx=14, pady=(0, 12))

        btn_revoke = tk.Button(
            dev_btn_row,
            text="Revocar Dispositivo Seleccionado",
            command=self._revoke_selected_device,
            bg="#7F1D1D",
            fg="#FCA5A5",
            activebackground="#991B1B",
            activeforeground="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
        )
        btn_revoke.pack(side="left")

        btn_refresh = tk.Button(
            dev_btn_row,
            text="Actualizar Lista",
            command=self._refresh_device_list,
            bg="#1E2230",
            fg=TEXT_SECONDARY,
            activebackground="#2A3144",
            activeforeground=TEXT_PRIMARY,
            font=("Segoe UI", 9),
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
        )
        btn_refresh.pack(side="right")

        self._refresh_device_list()

    def _create_card(self, parent: ttk.Frame, title: str) -> ttk.Frame:
        """Genera un contenedor tipo tarjeta con borde sutil."""
        card = tk.Frame(parent, bg=CARD_BG, highlightbackground=CARD_BORDER, highlightthickness=1)
        card.pack(fill="x", pady=6)

        title_lbl = tk.Label(card, text=title, font=("Segoe UI", 11, "bold"), fg=TEXT_PRIMARY, bg=CARD_BG)
        title_lbl.pack(anchor="w", padx=14, pady=(10, 4))
        return card

    def _update_pin_status_label(self) -> None:
        if has_unlock_pin():
            self.lbl_pin_status.config(text="Configurado y Cifrado (DPAPI)", foreground=COLOR_SUCCESS)
        else:
            self.lbl_pin_status.config(text="Sin configurar (usa contraseña de Windows)", foreground=TEXT_SECONDARY)

    def _refresh_device_list(self) -> None:
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)

        devices = self.device_store.list_devices()
        for dev in devices:
            ts = dev.get("registered_at_utc") or dev.get("registered_at", 0)
            time_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "Desconocida"
            self.device_tree.insert(
                "",
                "end",
                iid=dev["device_id"],
                values=(dev.get("label", "Móvil"), dev["device_id"], time_str),
            )

    def _revoke_selected_device(self) -> None:
        selected = self.device_tree.selection()
        if not selected:
            messagebox.showinfo("Selección requerida", "Por favor selecciona un dispositivo de la lista.")
            return

        device_id = selected[0]
        if messagebox.askyesno("Confirmar revocación", f"¿Revocar el acceso del dispositivo {device_id}?\nDeberá emparejarse nuevamente."):
            self.device_store.revoke_device(device_id)
            self._refresh_device_list()
            messagebox.showinfo("Dispositivo revocado", "El dispositivo ha sido revocado exitosamente.")

    def _on_keep_session_toggle(self) -> None:
        val = self.var_keep_session.get()
        self.config.keep_session_open = val
        logger.info("Opción 'keep_session_open' actualizada a %s", val)

    def _on_auto_start_toggle(self) -> None:
        val = self.var_auto_start.get()
        self.config.auto_start = val
        if val:
            ok = enable_autostart(minimized=True)
            if ok:
                logger.info("Auto-arranque de Windows habilitado correctamente.")
            else:
                logger.warning("No se pudo configurar completamente el auto-arranque.")
        else:
            disable_autostart()
            logger.info("Auto-arranque de Windows deshabilitado.")

    def _create_desktop_shortcut(self) -> None:
        try:
            lnk = create_desktop_shortcut()
            messagebox.showinfo(
                "Acceso Directo Creado",
                f"Se ha creado el acceso directo exitosamente en el Escritorio:\n\n{lnk}\n\nPuedes iniciar SecureDeck con permisos elevados haciendo doble clic en él.",
                parent=self.root,
            )
        except Exception as e:
            messagebox.showerror(
                "Error al Crear Acceso Directo",
                f"Ocurrió un error al crear el acceso directo:\n{e}",
                parent=self.root,
            )

    def _configure_wol(self) -> None:
        try:
            res = configure_windows_wol()
            if res.get("success"):
                messagebox.showinfo(
                    "Configuración Wake-on-LAN",
                    f"Configuración completada exitosamente:\n\n{res.get('message')}",
                    parent=self.root,
                )
            else:
                messagebox.showwarning(
                    "Configuración Wake-on-LAN Parcial",
                    f"Atención:\n\n{res.get('message')}\n\nPara deshabilitar el Inicio Rápido (Fast Startup), ejecuta RemoteControler como Administrador.",
                    parent=self.root,
                )
        except Exception as e:
            messagebox.showerror(
                "Error en Configuración WoL",
                f"Ocurrió un error al configurar la tarjeta de red:\n{e}",
                parent=self.root,
            )

    def _show_pin_dialog(self) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title("Configuración de PIN de Desbloqueo")
        dlg.geometry("380x280")
        dlg.configure(bg=CARD_BG)
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(
            dlg,
            text="PIN de Windows Hello",
            font=("Segoe UI", 12, "bold"),
            fg=TEXT_PRIMARY,
            bg=CARD_BG,
        ).pack(anchor="w", padx=20, pady=(16, 4))

        tk.Label(
            dlg,
            text="Introduce el PIN que usas para iniciar sesión en tu PC.\nSe almacenará protegido con Windows DPAPI.",
            font=("Segoe UI", 9),
            fg=TEXT_SECONDARY,
            bg=CARD_BG,
            justify="left",
        ).pack(anchor="w", padx=20, pady=(0, 12))

        lbl_p1 = tk.Label(dlg, text="Nuevo PIN:", font=("Segoe UI", 9, "bold"), fg=TEXT_PRIMARY, bg=CARD_BG)
        lbl_p1.pack(anchor="w", padx=20, pady=(4, 2))
        entry_p1 = tk.Entry(dlg, show="•", font=("Segoe UI", 12), bg="#0F1117", fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY)
        entry_p1.pack(fill="x", padx=20, pady=(0, 8))

        lbl_p2 = tk.Label(dlg, text="Confirmar PIN:", font=("Segoe UI", 9, "bold"), fg=TEXT_PRIMARY, bg=CARD_BG)
        lbl_p2.pack(anchor="w", padx=20, pady=(4, 2))
        entry_p2 = tk.Entry(dlg, show="•", font=("Segoe UI", 12), bg="#0F1117", fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY)
        entry_p2.pack(fill="x", padx=20, pady=(0, 16))

        btn_box = tk.Frame(dlg, bg=CARD_BG)
        btn_box.pack(fill="x", padx=20, pady=(0, 16))

        def save_pin():
            p1 = entry_p1.get().strip()
            p2 = entry_p2.get().strip()
            if not p1:
                messagebox.showerror("Error", "El PIN no puede estar vacío.", parent=dlg)
                return
            if p1 != p2:
                messagebox.showerror("Error", "Los PINs no coinciden.", parent=dlg)
                return
            try:
                set_unlock_pin(p1)
                self._update_pin_status_label()
                messagebox.showinfo("PIN Guardado", "El PIN ha sido cifrado y configurado correctamente.", parent=dlg)
                dlg.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar el PIN: {e}", parent=dlg)

        def remove_pin():
            if messagebox.askyesno("Eliminar PIN", "¿Deseas eliminar el PIN configurado?", parent=dlg):
                clear_unlock_pin()
                self._update_pin_status_label()
                messagebox.showinfo("PIN Eliminado", "El PIN ha sido eliminado.", parent=dlg)
                dlg.destroy()

        btn_save = tk.Button(btn_box, text="Guardar PIN", command=save_pin, bg=ACCENT_PRIMARY, fg="#FFFFFF", font=("Segoe UI", 9, "bold"), relief="flat", padx=12, pady=5)
        btn_save.pack(side="left")

        if has_unlock_pin():
            btn_del = tk.Button(btn_box, text="Eliminar", command=remove_pin, bg="#7F1D1D", fg="#FCA5A5", font=("Segoe UI", 9), relief="flat", padx=10, pady=5)
            btn_del.pack(side="left", padx=8)

        btn_cancel = tk.Button(btn_box, text="Cancelar", command=dlg.destroy, bg="#1E2230", fg=TEXT_SECONDARY, font=("Segoe UI", 9), relief="flat", padx=10, pady=5)
        btn_cancel.pack(side="right")

    def _show_pairing_qr_dialog(self) -> None:
        endpoint = f"{self.server_ip}:{self.server_port}"
        challenge = self.pairing_manager.create_pairing_challenge(tailscale_endpoint=endpoint, ttl_seconds=300)
        qr_payload = self.pairing_manager.get_qr_payload()

        dlg = tk.Toplevel(self.root)
        dlg.title("Vincular Dispositivo Móvil")
        dlg.geometry("420x540")
        dlg.configure(bg=CARD_BG)
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(
            dlg,
            text="Escanea este Código QR",
            font=("Segoe UI", 14, "bold"),
            fg=TEXT_PRIMARY,
            bg=CARD_BG,
        ).pack(pady=(16, 4))

        tk.Label(
            dlg,
            text="Abre SecureDeck en tu teléfono Android y escanea el código.\nVálido durante 5 minutos.",
            font=("Segoe UI", 9),
            fg=TEXT_SECONDARY,
            bg=CARD_BG,
            justify="center",
        ).pack(pady=(0, 12))

        # Generar imagen QR
        qr = qrcode.QRCode(box_size=7, border=2)
        qr.add_data(qr_payload)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        self._qr_image_ref = ImageTk.PhotoImage(img)
        qr_lbl = tk.Label(dlg, image=self._qr_image_ref, bg="white", padx=6, pady=6)
        qr_lbl.pack(pady=6)

        tk.Label(
            dlg,
            text=f"Endpoint: {endpoint}",
            font=("Consolas", 10, "bold"),
            fg=COLOR_SUCCESS,
            bg=CARD_BG,
        ).pack(pady=4)

        btn_close = tk.Button(
            dlg,
            text="Cerrar",
            command=dlg.destroy,
            bg=ACCENT_PRIMARY,
            fg="#FFFFFF",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=16,
            pady=6,
        )
        btn_close.pack(pady=(12, 16))

    def _start_server(self) -> None:
        if self.is_running:
            return

        try:
            device_store = self.device_store
            anti_replay = AntiReplayValidator(max_clock_skew_seconds=30, nonce_ttl_seconds=60)
            dispatcher = CommandDispatcher(device_store, anti_replay)
            rate_limiter = RateLimiter(max_rate_per_second=10.0, base_ban_duration_seconds=300.0)
            audit_logger = AuditLogger()

            app = create_app(
                dispatcher=dispatcher,
                device_store=device_store,
                pairing_manager=self.pairing_manager,
                rate_limiter=rate_limiter,
                audit_logger=audit_logger,
                allow_loopback=self.dev_mode,
            )

            bind_addr = validate_bind_address(self.server_ip, allow_loopback=self.dev_mode)
            cfg = uvicorn.Config(app=app, host=bind_addr, port=self.server_port, log_level="warning")
            self.uvicorn_server = uvicorn.Server(cfg)

            def run():
                try:
                    self.uvicorn_server.run()
                except Exception as ex:
                    logger.error("Error en el servidor ASGI uvicorn: %s", ex)

            self.server_thread = threading.Thread(target=run, daemon=True)
            self.server_thread.start()

            self.is_running = True
            self.status_badge.config(text="● Servidor Activo", fg=COLOR_SUCCESS, bg="#062817")
            self.btn_toggle_server.config(text="Detener Servidor", bg=COLOR_DANGER)
            logger.info("Servidor iniciado en segundo plano en %s:%s", bind_addr, self.server_port)

        except Exception as e:
            logger.error("Fallo al iniciar el servidor: %s", e)
            self.status_badge.config(text="● Error al Iniciar", fg=COLOR_DANGER, bg="#2A0B0B")

    def _stop_server(self) -> None:
        if not self.is_running or not self.uvicorn_server:
            return

        self.uvicorn_server.should_exit = True
        self.is_running = False
        self.status_badge.config(text="● Servidor Detenido", fg=COLOR_WARNING, bg="#231B0A")
        self.btn_toggle_server.config(text="Iniciar Servidor", bg=COLOR_SUCCESS)
        logger.info("Servidor detenido por el usuario.")

    def _toggle_server(self) -> None:
        if self.is_running:
            self._stop_server()
        else:
            self._start_server()

    def _on_close(self) -> None:
        self._stop_server()
        self.root.destroy()

    def _on_update_server_clicked(self) -> None:
        """Lanza la verificación y actualización del servidor en un hilo secundario."""
        def run_update():
            repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            try:
                self.btn_update.config(state="disabled", text="Comprobando...")

                # 1. Fetch de cambios en origin main
                subprocess.run(
                    ["git", "fetch", "origin", "main"],
                    capture_output=True,
                    text=True,
                    check=True,
                    cwd=repo_root,
                )

                # 2. Comprobar si HEAD local difiere de origin/main
                res = subprocess.run(
                    ["git", "rev-list", "HEAD..origin/main", "--count"],
                    capture_output=True,
                    text=True,
                    check=True,
                    cwd=repo_root,
                )
                pending_commits = int(res.stdout.strip() or "0")

                if pending_commits == 0:
                    self.root.after(
                        0,
                        lambda: messagebox.showinfo(
                            "Actualización",
                            "El servidor ya está en la última versión.",
                        ),
                    )
                    return

                # 3. Descargar commits e instalar dependencias
                self.btn_update.config(text="Descargando...")
                subprocess.run(["git", "pull", "origin", "main"], check=True, cwd=repo_root)

                self.btn_update.config(text="Instalando...")
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"],
                    check=True,
                    cwd=repo_root,
                )

                # 4. Confirmar y reiniciar aplicación
                def restart():
                    messagebox.showinfo(
                        "Actualización Exitosa",
                        "El servidor ha sido actualizado exitosamente.\nLa aplicación se reiniciará ahora.",
                    )
                    self._stop_server()
                    subprocess.Popen([sys.executable] + sys.argv, cwd=repo_root)
                    self.root.destroy()

                self.root.after(0, restart)

            except Exception as e:
                logger.error("Error durante la actualización del servidor: %s", e)
                self.root.after(
                    0,
                    lambda err=str(e): messagebox.showerror(
                        "Error de Actualización",
                        f"Ocurrió un error al actualizar el servidor:\n{err}",
                    ),
                )
            finally:
                self.root.after(0, lambda: self.btn_update.config(state="normal", text="Actualizar Servidor"))

        threading.Thread(target=run_update, daemon=True).start()

    def _relaunch_admin(self) -> None:
        """Solicita elevación UAC y relanza la GUI con permisos de Administrador."""
        if messagebox.askyesno(
            "Elevar Privilegios UAC",
            "¿Deseas reiniciar RemoteControler Host con permisos de Administrador?\n\n"
            "Esto activa el desbloqueo real de Windows en Winlogon (tscon) y control total de procesos.",
            parent=self.root,
        ):
            self._stop_server()
            if relaunch_as_admin():
                self.root.destroy()
            else:
                messagebox.showerror(
                    "Error de Elevación",
                    "No se pudo elevar a Administrador. Verifica los permisos de usuario de Windows.",
                    parent=self.root,
                )
                self._start_server()



def launch_gui(minimized: bool = False, dev_mode: bool = False) -> None:
    """Punto de entrada para ejecutar la interfaz gráfica de usuario de RemoteControler."""
    root = tk.Tk()
    app = HostDashboardApp(root, minimized=minimized, dev_mode=dev_mode)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
