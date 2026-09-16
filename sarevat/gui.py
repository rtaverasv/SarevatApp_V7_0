"""Interfaz grafica alpha, separada de la interfaz de PowerShell."""

from __future__ import annotations

import re
import threading
import tkinter as tk
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from sarevat.backup_crypto import BackupCipher
from sarevat.baselines import BaselineStore, ConfigurationBaseline, compare_with_baseline
from sarevat.batches import BatchHistoryStore, BatchPreview
from sarevat.cisco.executor import CiscoExecutor
from sarevat.cisco.services import (
    SERVICE_CATALOG,
    build_aaa_local_plan,
    build_basic_hardening_plan,
    build_initial_setup_plan,
    build_interface_ip_plan,
    build_serial_bootstrap_plan,
    build_service_plan,
    build_site_observability_plan,
    build_snmpv3_plan,
    service_is_configured,
)
from sarevat.compliance import ComplianceStatus, audit_running_config, export_compliance_json
from sarevat.drafts import DraftStore
from sarevat.inventory import ConnectionProfile, InventoryStore
from sarevat.juniper.services import (
    build_existing_vlan_access_candidate,
    build_existing_vlan_trunk_candidate,
    build_management_candidate,
    build_vlan_access_candidate,
    preferred_management_interface,
)
from sarevat.juniper.transaction import (
    JUNOS_LAB_ACCEPTANCE,
    JunosExecutor,
    JunosPrecheckReport,
    run_prechecks,
)
from sarevat.logging_utils import AuditLogger
from sarevat.models import CommandPlan, DeviceFacts, DeviceKind, ExecutionReport, NetworkPlatform
from sarevat.platforms import adapter_for, detect_ssh_platform, detection_from_netmiko, device_type_for
from sarevat.reporting import export_execution_report_csv, export_execution_report_json
from sarevat.scanner import (
    ScanPolicy,
    export_scan_csv,
    export_scan_json,
    ping_sweep,
    scan_tcp_ports,
)
from sarevat.security import dangerous_reasons, find_ios_errors, plan_dangerous_reasons, redact_text
from sarevat.validators import ValidationError, validate_ipv4, validate_ipv4_network
from sarevat.vlsm import (
    SubnetRequest,
    VLSMPlan,
    automatic_gateway_policy,
    calculate_vlsm,
    export_plan_csv,
    export_plan_json,
)

VLSM_MASK_OPTIONS = tuple(f"/{prefix}" for prefix in range(33))


def junos_lab_checkbox_acceptance(accepted: bool) -> str | None:
    """Convierte la aceptacion explicita de la UI en el guardia del ejecutor."""
    return JUNOS_LAB_ACCEPTANCE if accepted else None


def widget_exists(widget: tk.Misc) -> bool:
    """Evita que un callback asíncrono actualice un control ya destruido."""
    try:
        return bool(widget.winfo_exists())
    except tk.TclError:
        return False


def inventory_overview(facts: DeviceFacts) -> dict[str, tuple[tuple[str, ...], ...] | tuple[str, ...]]:
    """Convierte el descubrimiento en filas seguras para la vista de inventario."""
    interfaces = tuple(
        (
            item.name,
            ", ".join(item.ip_addresses) if item.ip_addresses else item.ip_address or "-",
            item.status,
            item.protocol,
        )
        for _, item in sorted(facts.interfaces.items())
    )
    vlans = tuple((str(vlan_id), name) for vlan_id, name in sorted(facts.vlans.items()))
    return {
        "capabilities": tuple(sorted(facts.capabilities)),
        "interfaces": interfaces,
        "vlans": vlans,
        "warnings": tuple(facts.warnings),
    }


def format_junos_prechecks(report: JunosPrecheckReport) -> str:
    """Presenta evidencia de consultas Junos sin revelar secretos."""
    lines = ["PRECHECKS JUNOS · SOLO LECTURA"]
    if report.errors:
        lines.extend(f"ERROR: {redact_text(error)}" for error in report.errors)
    else:
        lines.append("Resultado: aprobado; no se detectaron diagnósticos Junos.")
    for command, output in report.outputs.items():
        lines.extend(("", f"> {command}", redact_text(output).strip() or "(sin salida)"))
    return "\n".join(lines)


def build_vlsm_base_network(address: str, prefix: str) -> str:
    """Combina los controles de red y mascara en una red IPv4 valida."""
    value = address.strip()
    if not value:
        raise ValidationError("Indica la Red Base.")
    if "/" in value:
        raise ValidationError("En Red Base escribe solo la IPv4; elige la mascara aparte.")
    normalized_address = str(validate_ipv4(value))
    normalized_prefix = prefix.strip().removeprefix("/")
    if not normalized_prefix.isdecimal() or not 0 <= int(normalized_prefix) <= 32:
        raise ValidationError("Selecciona una mascara IPv4 valida.")
    try:
        return str(validate_ipv4_network(f"{normalized_address}/{normalized_prefix}"))
    except ValidationError as exc:
        raise ValidationError(
            "La Red Base debe coincidir con el inicio de la mascara seleccionada."
        ) from exc


def build_vlsm_requests(rows: list[tuple[str, str, str]]) -> list[SubnetRequest]:
    """Valida las filas VLSM con mensajes breves y accionables para la GUI."""
    requests: list[SubnetRequest] = []
    for index, (name, hosts, kind) in enumerate(rows, start=1):
        normalized_name = name.strip()
        if not normalized_name:
            raise ValidationError(f"Subred {index}: falta el nombre.")
        normalized_hosts = hosts.strip()
        if not normalized_hosts:
            raise ValidationError(f"Subred {index}: indica la cantidad de hosts.")
        try:
            requested_hosts = int(normalized_hosts)
        except ValueError as exc:
            raise ValidationError(f"Subred {index}: hosts debe ser un numero.") from exc
        if requested_hosts < 1:
            raise ValidationError(f"Subred {index}: hosts debe ser mayor que cero.")
        requests.append(
            SubnetRequest(
                normalized_name,
                requested_hosts,
                kind,
                automatic_gateway_policy(kind),
            )
        )
    return requests


def build_connection_params(
    transport: str,
    target: str,
    baudrate: str,
    username: str | None = None,
    password: str | None = None,
    secret: str | None = None,
    platform: NetworkPlatform | str = NetworkPlatform.CISCO_IOS,
) -> dict[str, Any]:
    """Valida datos de una conexion temporal sin persistir secretos."""
    normalized_username = (username or "").strip()
    current_password = password or ""
    current_secret = secret or ""
    try:
        selected_platform = NetworkPlatform(platform)
    except ValueError as exc:
        raise ValidationError("La plataforma seleccionada no es valida.") from exc
    if transport == "ssh":
        host = str(validate_ipv4(target.strip()))
        if not normalized_username or not current_password:
            raise ValidationError("SSH requiere usuario y password.")
        return {
            "device_type": device_type_for(selected_platform, transport),
            "host": host,
            "username": normalized_username,
            "password": current_password,
            "secret": current_secret,
        }
    if transport == "serial":
        if not target.strip():
            raise ValidationError("Indica el puerto serial, por ejemplo COM3.")
        try:
            speed = int(baudrate)
        except ValueError as exc:
            raise ValidationError("El baudrate debe ser un numero entero.") from exc
        if speed <= 0:
            raise ValidationError("El baudrate debe ser positivo.")
        if not selected_platform.is_cisco:
            raise ValidationError(
                "La consola serial multi-fabricante aun no esta certificada; usa SSH o selecciona Cisco."
            )
        params: dict[str, Any] = {
            "device_type": device_type_for(selected_platform, transport),
            "serial_settings": {"port": target.strip(), "baudrate": speed},
        }
        if current_password:
            params.update(
                {"username": normalized_username, "password": current_password, "secret": current_secret}
            )
        return params
    raise ValidationError("Metodo de conexion no reconocido.")


def network_summary(network_text: str) -> dict[str, str]:
    """Resumen IPv4 simple, sin valores inventados ni configuracion de equipos."""
    network = validate_ipv4_network(network_text)
    if network.prefixlen == 32:
        first = last = network.network_address
        gateway = "No aplica"
    elif network.prefixlen == 31:
        first, last = network.network_address, network.broadcast_address
        gateway = "No aplica"
    else:
        first, last = network.network_address + 1, network.broadcast_address - 1
        gateway = str(first)
    return {
        "Red": str(network),
        "Mascara": str(network.netmask),
        "Hosts utilizables": str(
            network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
        ),
        "Primer host": str(first),
        "Ultimo host": str(last),
        "Gateway automatico": gateway,
        "Broadcast": str(network.broadcast_address),
    }


def export_vlsm_outputs(
    plan: VLSMPlan,
    reports_directory: Path,
    *,
    stamp: str | None = None,
) -> tuple[Path, Path]:
    """Exporta un plan VLSM localmente en formatos interoperables con nombres únicos."""
    suffix = stamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    return (
        export_plan_json(plan, reports_directory / f"vlsm_{suffix}.json"),
        export_plan_csv(plan, reports_directory / f"vlsm_{suffix}.csv"),
    )


def profile_connection_target(profile: ConnectionProfile | None) -> str:
    """Devuelve el objetivo visible sin acceder a un perfil inexistente."""
    if profile is None:
        return ""
    return profile.host if profile.transport == "ssh" else profile.serial_port or ""


@dataclass(slots=True)
class DeviceSession:
    """Conexion abierta para una sesion GUI; se cierra al desconectar."""

    connection: Any
    executor: CiscoExecutor | JunosExecutor | None
    facts: DeviceFacts
    device_kind: DeviceKind
    audit: AuditLogger
    platform: NetworkPlatform
    transport: str
    profile_id: str | None = None
    reconnect_params: dict[str, Any] | None = None


class SarevatGui(tk.Tk):
    """Ventana alpha: operaciones de lectura y planificacion con navegacion segura."""

    def __init__(self) -> None:
        super().__init__()
        self.title("SarevatApp 7.0")
        self.minsize(1080, 680)
        self.geometry("1220x760")
        self.configure(bg="#f6f8fb")
        self.runtime = Path(__file__).resolve().parent.parent / "runtime"
        self.runtime.mkdir(exist_ok=True)
        self.inventory = InventoryStore(self.runtime / "inventory.json")
        self.pending_profile: ConnectionProfile | None = None
        self.session: DeviceSession | None = None
        self._session_tasks = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sarevat-gui")
        self.protocol("WM_DELETE_WINDOW", self._close_application)
        self.current_page = "menu"
        self._configure_style()
        self._build_shell()
        self.show_menu()

    def _close_application(self) -> None:
        if self.session:
            self._close_session_connection(self.session)
            self.session = None
        self._session_tasks.shutdown(wait=False, cancel_futures=True)
        self.destroy()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("App.TFrame", background="#f6f8fb")
        style.configure("Side.TFrame", background="#102a43")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure(
            "Title.TLabel", background="#f6f8fb", foreground="#102a43", font=("Segoe UI", 22, "bold")
        )
        style.configure("Body.TLabel", background="#f6f8fb", foreground="#526777", font=("Segoe UI", 10))
        style.configure(
            "Side.TButton", background="#102a43", foreground="#dce8f2", padding=(14, 11), anchor="w"
        )
        style.map("Side.TButton", background=[("active", "#1d4e67")])
        style.configure(
            "Primary.TButton",
            background="#197278",
            foreground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            padding=(15, 10),
        )
        style.map(
            "Primary.TButton",
            background=[("disabled", "#8bb9bc"), ("active", "#125c61"), ("!disabled", "#197278")],
            foreground=[("disabled", "#e8f2f3"), ("!disabled", "#ffffff")],
        )
        style.configure("Back.TButton", background="#f6f8fb", foreground="#197278", padding=(0, 3))
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_shell(self) -> None:
        header = ttk.Frame(self, style="App.TFrame", padding=(28, 18))
        header.pack(fill="x")
        ttk.Label(header, text="Sarevat", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="App", style="Title.TLabel", foreground="#197278").pack(side="left")
        ttk.Label(header, text="Escritorio local · Sesión segura", style="Body.TLabel").pack(side="right")
        ttk.Separator(self).pack(fill="x")
        body = ttk.Frame(self, style="App.TFrame")
        body.pack(fill="both", expand=True)
        self.sidebar = ttk.Frame(body, style="Side.TFrame", width=260, padding=(14, 22))
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        ttk.Label(
            self.sidebar,
            text="OPERACIONES",
            background="#102a43",
            foreground="#9db7c9",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", padx=10, pady=(0, 9))
        for number, name, page in (
            ("01", "Conexiones", "connect"),
            ("02", "Planificador VLSM", "vlsm"),
            ("03", "Escáner autorizado", "scan"),
            ("04", "Equipos e inventario", "inventory"),
        ):
            ttk.Button(
                self.sidebar,
                text=f"{number}   {name}",
                style="Side.TButton",
                command=lambda item=page: self.show_page(item),
            ).pack(fill="x", pady=2)
        ttk.Separator(self.sidebar).pack(fill="x", padx=2, pady=16)
        ttk.Label(
            self.sidebar,
            text="EQUIPO ACTIVO",
            background="#102a43",
            foreground="#9db7c9",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=10, pady=(0, 6))
        self.connected_tools_button = ttk.Button(
            self.sidebar,
            text="Abrir herramientas",
            style="Side.TButton",
            command=self._device_tools_page,
            state="disabled",
        )
        self.connected_tools_button.pack(fill="x", pady=2)
        ttk.Label(
            self.sidebar,
            text="Motor Sarevat 7.0\nSSH, serial y datos locales.",
            background="#102a43",
            foreground="#9db7c9",
            justify="left",
        ).pack(anchor="w", padx=10)
        self.content = ttk.Frame(body, style="App.TFrame", padding=(42, 34))
        self.content.pack(side="left", fill="both", expand=True)

    def _clear(self) -> None:
        for child in self.content.winfo_children():
            child.destroy()

    def _update_session_navigation(self) -> None:
        """Mantiene visible el acceso a las herramientas de una sesión abierta."""
        if self.session:
            self.connected_tools_button.state(["!disabled"])
        else:
            self.connected_tools_button.state(["disabled"])

    def _page_header(self, title: str, subtitle: str, *, back: bool = True) -> None:
        if back:
            ttk.Button(
                self.content, text="←  Volver al menu principal", style="Back.TButton", command=self.show_menu
            ).pack(anchor="w")
        ttk.Label(self.content, text=title, style="Title.TLabel").pack(anchor="w", pady=(8 if back else 0, 4))
        ttk.Label(self.content, text=subtitle, style="Body.TLabel", wraplength=690).pack(
            anchor="w", pady=(0, 20)
        )

    def show_menu(self) -> None:
        self.current_page = "menu"
        self._clear()
        self._page_header(
            "Centro de operaciones",
            "Control local de red con evidencia, no con suposiciones.",
            back=False,
        )
        actions = ttk.Frame(self.content, style="App.TFrame")
        actions.pack(fill="x", pady=(14, 18))
        for title, detail, page in (
            ("Conectar equipo", "SSH o consola serial; credenciales temporales.", "connect"),
            ("Diseñar VLSM", "Subredes IPv4 con resultados separados y verificables.", "vlsm"),
            ("Inventario", "Perfiles, grupos, borradores y lotes locales.", "inventory"),
        ):
            card = ttk.Frame(actions, style="Card.TFrame", padding=(18, 16))
            card.pack(side="left", fill="both", expand=True, padx=(0, 10))
            ttk.Label(
                card, text=title, background="#ffffff", foreground="#102a43", font=("Segoe UI", 11, "bold")
            ).pack(anchor="w")
            ttk.Label(
                card, text=detail, background="#ffffff", foreground="#526777", wraplength=190
            ).pack(anchor="w", pady=(6, 12))
            ttk.Button(
                card, text="Abrir", style="Primary.TButton", command=lambda item=page: self.show_page(item)
            ).pack(anchor="w")
        ttk.Label(
            self.content,
            text=(
                "Todos los cambios Cisco conservan vista previa, dry-run, respaldo cifrado, "
                "checkpoint, postchecks y rollback confirmado."
            ),
            style="Body.TLabel",
            wraplength=760,
        ).pack(anchor="w", pady=(8, 0))

    def show_page(self, page: str) -> None:
        self.current_page = page
        self._clear()
        {
            "connect": self._connect_page,
            "vlsm": self._vlsm_page,
            "scan": self._scan_page,
            "inventory": self._inventory_page,
        }[page]()

    def _connect_page(self) -> None:
        profile = self.pending_profile
        self.pending_profile = None
        self._page_header(
            "Nueva conexión de red",
            (
                f"Perfil seleccionado: {profile.name}. Las credenciales se piden al conectar y no se guardan."
                if profile
                else "Las credenciales se usan una sola vez para descubrir el equipo y nunca se guardan."
            ),
        )
        viewport = ttk.Frame(self.content, style="App.TFrame")
        viewport.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(viewport, orient="vertical")
        canvas = tk.Canvas(viewport, background="#f6f8fb", highlightthickness=0)
        scrollbar.configure(command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        form = ttk.Frame(canvas, style="Card.TFrame", padding=(22, 20))
        form_window = canvas.create_window((0, 0), window=form, anchor="nw")

        def update_scroll_region(_: tk.Event[tk.Misc]) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_form(event: tk.Event[tk.Misc]) -> None:
            canvas.itemconfigure(form_window, width=event.width)

        form.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", resize_form)
        ttk.Label(
            form,
            text="Conexión temporal",
            background="#ffffff",
            foreground="#102a43",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            form,
            text="Los secretos solo existen durante esta sesión y se eliminan antes de guardar un perfil.",
            background="#ffffff",
            foreground="#526777",
            wraplength=720,
        ).pack(anchor="w", pady=(4, 18))
        transport = tk.StringVar(value=profile.transport if profile else "ssh")
        kind = tk.StringVar(value=profile.device_kind.value if profile else "router")
        platform = tk.StringVar(
            value=(profile.platform.value if profile else NetworkPlatform.UNKNOWN.value)
        )
        target = tk.StringVar(value=profile_connection_target(profile))
        baudrate = tk.StringVar(value=str(profile.baudrate) if profile and profile.baudrate else "9600")
        username = tk.StringVar(value=profile.username if profile and profile.username else "")
        password = tk.StringVar()
        secret = tk.StringVar()
        console_auth = tk.BooleanVar(value=False)
        selectors = ttk.Frame(form, style="Card.TFrame")
        selectors.pack(fill="x")
        for column in range(3):
            selectors.columnconfigure(column, weight=1)
        ttk.Label(selectors, text="Tipo de equipo", style="Body.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 10)
        )
        ttk.Label(selectors, text="Metodo de conexion", style="Body.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Label(selectors, text="Plataforma", style="Body.TLabel").grid(row=0, column=2, sticky="w")
        ttk.Combobox(selectors, textvariable=kind, values=("router", "switch"), state="readonly").grid(
            row=1, column=0, sticky="ew", padx=(0, 10), pady=(3, 13)
        )
        mode_box = ttk.Combobox(selectors, textvariable=transport, values=("ssh", "serial"), state="readonly")
        mode_box.grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=(3, 13))
        platform_box = ttk.Combobox(
            selectors,
            textvariable=platform,
            values=tuple(item.value for item in NetworkPlatform),
            state="readonly",
        )
        platform_box.grid(row=1, column=2, sticky="ew", pady=(3, 13))
        dynamic = ttk.Frame(form, style="Card.TFrame")
        dynamic.pack(fill="x")
        status = tk.StringVar(value="Listo para conectar y descubrir en modo lectura.")

        def primary_action(parent: tk.Misc, text: str, command: Callable[[], None]) -> tk.Button:
            return tk.Button(
                parent,
                text=text,
                command=command,
                background="#197278",
                foreground="#ffffff",
                activebackground="#125c61",
                activeforeground="#ffffff",
                disabledforeground="#e8f2f3",
                font=("Segoe UI", 10, "bold"),
                borderwidth=0,
                highlightthickness=0,
                padx=15,
                pady=10,
            )

        def render_fields(*_: object) -> None:
            for child in dynamic.winfo_children():
                child.destroy()
            is_serial = transport.get() == "serial"
            label = "Puerto serial" if is_serial else "Direccion IPv4 del equipo"
            ttk.Label(dynamic, text=label, style="Body.TLabel").pack(anchor="w")
            ttk.Entry(dynamic, textvariable=target).pack(fill="x", pady=(3, 10))
            if is_serial:
                ttk.Label(dynamic, text="Baudrate", style="Body.TLabel").pack(anchor="w")
                ttk.Entry(dynamic, textvariable=baudrate).pack(fill="x", pady=(3, 10))
                ttk.Checkbutton(
                    dynamic,
                    text="La consola solicita autenticacion",
                    variable=console_auth,
                    command=render_fields,
                ).pack(anchor="w", pady=(0, 4))
                if console_auth.get():
                    self._credential_fields(dynamic, username, password, secret, allow_empty_username=True)
            else:
                self._credential_fields(dynamic, username, password, secret, allow_empty_username=False)

        def connect() -> None:
            if self.session:
                status.set("Desconecta primero la sesion actual antes de conectar otro equipo.")
                return
            if transport.get() == "serial" and console_auth.get() and not password.get():
                status.set("Indica el password de consola o desmarca la autenticacion de consola.")
                return
            try:
                params = build_connection_params(
                    transport.get(),
                    target.get(),
                    baudrate.get(),
                    username.get(),
                    password.get(),
                    secret.get(),
                    platform.get(),
                )
            except ValidationError as exc:
                status.set(str(exc))
                return
            device_kind = DeviceKind(kind.get())
            profile_id = profile.id if profile else None
            password.set("")
            secret.set("")
            status.set("Conectando y consultando el estado del equipo...")
            button.configure(state="disabled")
            self._run_session_worker(
                lambda: self._open_session(params, device_kind, profile_id),
                lambda result: done(result, button, status),
            )

        def done(result: object, button: tk.Button, text: tk.StringVar) -> None:
            if not widget_exists(button):
                if not isinstance(result, Exception):
                    self._run_session_worker(
                        lambda: self._close_session_connection(result), lambda _: None
                    )
                return
            button.configure(state="normal")
            if isinstance(result, Exception):
                text.set(self._connection_error(result))
                return
            self.session = result
            self._update_session_navigation()
            facts = result.facts
            if result.profile_id:
                with suppress(OSError, ValueError):
                    self.inventory.update_discovery(result.profile_id, facts)
            text.set(
                f"Conectado a {facts.hostname} ({result.platform.value}). "
                "La sesion permanece abierta hasta que pulses Desconectar."
            )
            self._show_facts(facts)
            primary_action(
                form,
                "Abrir herramientas del equipo conectado",
                self._device_tools_page,
            ).pack(fill="x", pady=(12, 0))

        mode_box.bind("<<ComboboxSelected>>", render_fields)
        platform_box.bind("<<ComboboxSelected>>", render_fields)
        render_fields()
        button = primary_action(form, "Conectar y descubrir", connect)
        button.pack(fill="x", pady=(15, 8))
        ttk.Label(form, textvariable=status, style="Body.TLabel", wraplength=680).pack(anchor="w")

    def _credential_fields(
        self,
        parent: ttk.Frame,
        username: tk.StringVar,
        password: tk.StringVar,
        secret: tk.StringVar,
        *,
        allow_empty_username: bool,
    ) -> None:
        username_label = (
            "Usuario (vacio si la consola solo pide password)" if allow_empty_username else "Usuario"
        )
        ttk.Label(parent, text=username_label, style="Body.TLabel").pack(anchor="w", pady=(8, 0))
        ttk.Entry(parent, textvariable=username).pack(fill="x", pady=(3, 8))
        ttk.Label(parent, text="Password", style="Body.TLabel").pack(anchor="w")
        ttk.Entry(parent, textvariable=password, show="*").pack(fill="x", pady=(3, 8))
        ttk.Label(parent, text="Enable secret (opcional)", style="Body.TLabel").pack(anchor="w")
        ttk.Entry(parent, textvariable=secret, show="*").pack(fill="x", pady=(3, 8))

    def _open_session(
        self, params: dict[str, Any], device_kind: DeviceKind, profile_id: str | None = None
    ) -> DeviceSession:
        connection_params = dict(params)
        detection = detection_from_netmiko(str(connection_params.get("device_type")))
        if connection_params.get("device_type") == "autodetect":
            detection = detect_ssh_platform(connection_params)
            if detection.requires_confirmation or not detection.netmiko_device_type:
                raise ValidationError(
                    "No se pudo identificar con seguridad la plataforma. "
                    "Selecciona una plataforma certificada."
                )
            connection_params["device_type"] = detection.netmiko_device_type
        connection = ConnectHandler(**connection_params)
        try:
            if detection.platform.is_cisco and params.get("secret") and not connection.check_enable_mode():
                connection.enable()
            adapter = adapter_for(detection.platform)
            facts = adapter.discover(connection)
            audit = AuditLogger(self.runtime / "logs")
            executor: CiscoExecutor | JunosExecutor | None = None
            if detection.platform.is_cisco:
                executor = CiscoExecutor(connection, audit=audit, backup_directory=self.runtime / "backups")
            elif detection.platform is NetworkPlatform.JUNIPER_JUNOS:
                executor = JunosExecutor(connection, audit=audit)
            audit.event("gui_connection_opened", target=params.get("host", params.get("serial_settings")))
            transport = "serial" if "serial_settings" in params else "ssh"
            reconnect_params = dict(connection_params) if transport == "ssh" else None
            return DeviceSession(
                connection,
                executor,
                facts,
                device_kind,
                audit,
                facts.platform,
                transport,
                profile_id,
                reconnect_params,
            )
        except Exception:
            disconnect = getattr(connection, "disconnect", None)
            if callable(disconnect):
                disconnect()
            raise

    @staticmethod
    def _close_session_connection(session: DeviceSession) -> None:
        try:
            disconnect = getattr(session.connection, "disconnect", None)
            if callable(disconnect):
                disconnect()
        finally:
            session.audit.close()

    @staticmethod
    def _connection_error(error: Exception) -> str:
        if isinstance(error, NetmikoAuthenticationException):
            return "Autenticacion rechazada. Verifica las credenciales o la linea de consola."
        if isinstance(error, NetmikoTimeoutException):
            return "Timeout de conexion. Verifica IP, puerto COM, cable, baudrate y acceso."
        return f"No se pudo conectar: {error}"

    def _show_facts(self, facts: Any) -> None:
        overview = inventory_overview(facts)
        details = ttk.Frame(self.content, style="Card.TFrame", padding=(18, 15))
        details.pack(anchor="w", fill="x", pady=(16, 0))
        ttk.Label(
            details,
            text="Equipo descubierto",
            background="#ffffff",
            foreground="#102a43",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w")
        for label, value in (
            ("Plataforma", facts.platform.value),
            ("Hostname", facts.hostname),
            ("Modelo", facts.model),
            ("Version", facts.version),
            ("Serial", facts.serial),
        ):
            ttk.Label(
                details, text=f"{label}: {value}", background="#ffffff", foreground="#526777"
            ).pack(anchor="w", pady=1)

        capabilities = overview["capabilities"]
        if capabilities:
            ttk.Label(
                details,
                text=f"Capacidades detectadas: {', '.join(capabilities)}",
                background="#ffffff",
                foreground="#526777",
                wraplength=820,
            ).pack(anchor="w", pady=(7, 0))

        def add_table(title: str, columns: tuple[str, ...], rows: tuple[tuple[str, ...], ...]) -> None:
            if not rows:
                return
            ttk.Label(
                details,
                text=title,
                background="#ffffff",
                foreground="#102a43",
                font=("Segoe UI", 10, "bold"),
            ).pack(anchor="w", pady=(12, 4))
            tree = ttk.Treeview(details, columns=columns, show="headings", height=min(len(rows), 8))
            for column in columns:
                tree.heading(column, text=column)
                tree.column(column, anchor="w", width=150, stretch=True)
            for row in rows:
                tree.insert("", "end", values=row)
            tree.pack(anchor="w", fill="x")

        add_table(
            "Interfaces descubiertas",
            ("Interfaz", "IPv4", "Estado", "Protocolo"),
            overview["interfaces"],
        )
        add_table("VLAN descubiertas", ("ID", "Nombre"), overview["vlans"])

        warnings = overview["warnings"]
        if warnings:
            ttk.Label(
                details,
                text="Advertencias: " + " | ".join(warnings),
                background="#ffffff",
                foreground="#9c2f19",
                wraplength=820,
            ).pack(anchor="w", pady=(12, 0))

    def _device_tools_page(self) -> None:
        if not self.session:
            messagebox.showwarning(
                "Sesion", "Conecta un equipo antes de abrir estas herramientas.", parent=self
            )
            return
        self._clear()
        self._page_header(
            f"Configuración · {self.session.facts.hostname}",
            "Cada cambio conserva vista previa, dry-run, respaldo cifrado, checkpoint y confirmación.",
        )
        if not self.session.platform.is_cisco:
            card = ttk.Frame(self.content, style="Card.TFrame", padding=(18, 16))
            card.pack(fill="x")
            ttk.Label(
                card,
                text=f"{self.session.platform.value}: modo de inventario seguro",
                background="#ffffff",
                foreground="#102a43",
                font=("Segoe UI", 11, "bold"),
            ).pack(anchor="w")
            ttk.Label(
                card,
                text=(
                    "Esta plataforma tiene inventario de lectura y candidatos Junos certificados. "
                    "Los cambios solo se habilitan despues de prechecks y aceptacion explicita."
                ),
                background="#ffffff",
                foreground="#526777",
                wraplength=720,
            ).pack(anchor="w", pady=(6, 12))
            ttk.Button(card, text="Actualizar estado e inventario", command=self._refresh_session_facts).pack(
                anchor="w"
            )
            if self.session.platform is NetworkPlatform.JUNIPER_JUNOS:
                ttk.Button(
                    card,
                    text="Preparar candidato de gestión (vista previa)",
                    command=self._junos_management_candidate_page,
                ).pack(anchor="w", pady=(8, 0))
                ttk.Button(
                    card,
                    text="Preparar VLAN y puerto access (vista previa)",
                    command=self._junos_vlan_access_candidate_page,
                ).pack(anchor="w", pady=(8, 0))
                ttk.Button(
                    card,
                    text="Asignar VLAN existente a puerto access (vista previa)",
                    command=self._junos_existing_vlan_access_page,
                ).pack(anchor="w", pady=(8, 0))
                ttk.Button(
                    card,
                    text="Agregar VLAN existente a puerto trunk (vista previa)",
                    command=self._junos_existing_vlan_trunk_page,
                ).pack(anchor="w", pady=(8, 0))
            ttk.Button(self.content, text="Desconectar sesión", command=self._disconnect_session).pack(
                anchor="w", pady=(16, 0)
            )
            return
        groups = (
            (
                "Operación y configuración",
                (
                    ("Estado e inventario", self._refresh_session_facts),
                    ("Protocolos y servicios", self._service_catalog_page),
                    ("IPv4 en interfaz", self._interface_ipv4_page),
                    ("Configuración inicial", self._initial_setup_page),
                    ("Equipo nuevo por serial", self._serial_bootstrap_page),
                ),
            ),
            (
                "Seguridad y observabilidad",
                (
                    ("NTP y syslog", self._observability_page),
                    ("SNMPv3 seguro", self._snmpv3_page),
                    ("AAA con recuperación", self._aaa_page),
                    ("Endurecimiento básico", self._hardening),
                    ("Revisión de seguridad", self._compliance_page),
                ),
            ),
            (
                "Evidencia y mantenimiento",
                (
                    ("Guardar configuración", self._write_memory),
                    ("Comparar con archivo", self._compare_file),
                    ("Guardar referencia segura", self._save_baseline),
                    ("Cambios desde referencia", self._show_drift),
                    ("Consola libre", self._free_console_page),
                ),
            ),
        )
        grid = ttk.Frame(self.content, style="App.TFrame")
        grid.pack(fill="x")
        for column in range(2):
            grid.columnconfigure(column, weight=1)
        for index, (title, options) in enumerate(groups):
            card = ttk.Frame(grid, style="Card.TFrame", padding=(18, 16))
            card.grid(
                row=index // 2,
                column=index % 2,
                sticky="nsew",
                padx=(0, 12) if index % 2 == 0 else 0,
                pady=6,
            )
            ttk.Label(
                card, text=title, background="#ffffff", foreground="#102a43", font=("Segoe UI", 11, "bold")
            ).pack(anchor="w", pady=(0, 8))
            for label, action in options:
                ttk.Button(card, text=label, command=action).pack(fill="x", pady=2)
        ttk.Button(self.content, text="Desconectar sesión", command=self._disconnect_session).pack(
            anchor="w", pady=(16, 0)
        )

    def _disconnect_session(self) -> None:
        if not self.session:
            return
        current = self.session
        self.session = None
        self._update_session_navigation()
        self._run_session_worker(lambda: self._close_session_connection(current), lambda _: self.show_menu())

    def _refresh_session_facts(self) -> None:
        if not self.session:
            return
        self._run_session_worker(
            lambda: adapter_for(self.session.platform).discover(self.session.connection),
            self._finish_refresh_facts,
        )

    def _finish_refresh_facts(self, result: object) -> None:
        if isinstance(result, Exception):
            messagebox.showwarning("Estado no disponible", redact_text(str(result)), parent=self)
            return
        if self.session:
            self.session.facts = result
        self._clear()
        self._page_header("Estado descubierto", "Consulta de solo lectura completada.")
        self._show_facts(result)

    def _service_catalog_page(self) -> None:
        if not self.session:
            return
        self._clear()
        self._page_header(
            "Protocolos y servicios",
            "Selecciona un servicio compatible. Se validan datos y dependencias antes de preparar el plan.",
        )
        form = ttk.Frame(self.content, style="Card.TFrame", padding=(22, 20))
        form.pack(fill="x")
        ttk.Label(
            form,
            text="Plan de configuración",
            background="#ffffff",
            foreground="#102a43",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 10))
        available = [
            item
            for item in SERVICE_CATALOG.items()
            if self.session and self.session.device_kind in item[1].devices
        ]
        default_selection = f"{available[0][0]} | {available[0][1].name}" if available else ""
        selected = tk.StringVar(value=default_selection)
        selector = ttk.Combobox(
            form,
            textvariable=selected,
            values=[f"{key} | {spec.name}" for key, spec in available],
            state="readonly",
        )
        selector.pack(fill="x")
        fields = ttk.Frame(form, style="Card.TFrame")
        fields.pack(fill="x", pady=(14, 0))
        values: dict[str, tk.StringVar] = {}

        def render(*_: object) -> None:
            for child in fields.winfo_children():
                child.destroy()
            values.clear()
            key = selected.get().split(" | ", 1)[0]
            spec = SERVICE_CATALOG[key]
            if spec.depends_on:
                missing = [
                    item for item in spec.depends_on if not service_is_configured(item, self.session.facts)
                ]
                ttk.Label(
                    fields,
                    text=(
                        "Dependencia pendiente: " + ", ".join(missing)
                        if missing
                        else "Dependencias verificadas en la configuracion actual."
                    ),
                    style="Body.TLabel",
                ).pack(anchor="w", pady=(0, 8))
            for field, kind, label in spec.fields:
                ttk.Label(fields, text=label, style="Body.TLabel").pack(anchor="w")
                variable = tk.StringVar()
                ttk.Entry(fields, textvariable=variable, show="*" if kind == "secret" else "").pack(
                    fill="x", pady=(2, 8)
                )
                values[field] = variable

        def prepare() -> None:
            if not self.session:
                return
            key = selected.get().split(" | ", 1)[0]
            spec = SERVICE_CATALOG[key]
            missing = [
                item for item in spec.depends_on if not service_is_configured(item, self.session.facts)
            ]
            if missing:
                messagebox.showwarning(
                    "Dependencia pendiente",
                    "Configura primero: " + ", ".join(missing) + ". Luego actualiza el estado del equipo.",
                    parent=self,
                )
                return
            try:
                plan = build_service_plan(
                    key,
                    {name: value.get() for name, value in values.items()},
                    self.session.facts,
                    self.session.device_kind,
                )
            except ValidationError as exc:
                messagebox.showwarning("Datos por corregir", str(exc), parent=self)
                return
            self._review_and_execute_plan(plan)

        selector.bind("<<ComboboxSelected>>", render)
        render()
        ttk.Button(form, text="Preparar plan seguro", style="Primary.TButton", command=prepare).pack(
            fill="x", pady=(14, 0)
        )

    def _interface_ipv4_page(self) -> None:
        self._simple_plan_form(
            "Configurar IPv4 en interfaz",
            (("Interfaz", "interface"), ("Direccion IPv4", "address"), ("Mascara", "netmask")),
            lambda data: build_interface_ip_plan(
                data["interface"], data["address"], data["netmask"], self.session.facts
            ),
        )

    def _initial_setup_page(self) -> None:
        self._simple_plan_form(
            "Configuracion inicial segura",
            (
                ("Hostname", "hostname"),
                ("Dominio", "domain"),
                ("Usuario administrador", "username"),
                ("Password", "password"),
                ("RSA", "rsa_bits"),
            ),
            build_initial_setup_plan,
            hidden={"password"},
        )

    def _observability_page(self) -> None:
        self._simple_plan_form(
            "Plantilla NTP y syslog",
            (
                ("Sitio (sucursal/nucleo)", "role"),
                ("Servidor NTP IPv4", "ntp"),
                ("Servidor syslog IPv4", "syslog"),
            ),
            lambda data: build_site_observability_plan(
                data["role"] or "sucursal", data["ntp"], data["syslog"]
            ),
        )

    def _snmpv3_page(self) -> None:
        self._simple_plan_form(
            "SNMPv3 seguro",
            (
                ("Grupo", "group"),
                ("Usuario", "username"),
                ("Clave de autenticacion", "auth"),
                ("Clave de privacidad", "privacy"),
            ),
            lambda data: build_snmpv3_plan(data["group"], data["username"], data["auth"], data["privacy"]),
            hidden={"auth", "privacy"},
        )

    def _aaa_page(self) -> None:
        self._simple_plan_form(
            "AAA local con recuperacion por consola",
            (("Usuario local existente", "username"), ("Confirmacion exacta", "console")),
            lambda data: build_aaa_local_plan(
                data["username"], self.session.facts, data["console"] == "CONSOLA_LISTA"
            ),
            notice="AAA es de alto impacto. Mantén una consola física probada y escribe CONSOLA_LISTA.",
        )

    def _hardening(self) -> None:
        if not self.session:
            return
        try:
            self._review_and_execute_plan(build_basic_hardening_plan(self.session.facts))
        except ValidationError as exc:
            messagebox.showinfo("Endurecimiento", str(exc), parent=self)

    def _junos_management_candidate_page(self) -> None:
        if not self.session or self.session.platform is not NetworkPlatform.JUNIPER_JUNOS:
            return
        session = self.session
        self._clear()
        self._page_header(
            "Candidato de gestión Junos",
            "Se valida y muestra un candidato. La aplicación remota aún permanece bloqueada.",
        )
        form = ttk.Frame(self.content, style="Card.TFrame", padding=(22, 20))
        form.pack(fill="x")
        initial_hostname = session.facts.hostname if session.facts.hostname != "desconocido" else ""
        hostname = tk.StringVar(value=initial_hostname)
        interface = tk.StringVar(value=preferred_management_interface(session.facts))
        address = tk.StringVar()
        netmask = tk.StringVar(value="255.255.255.0")
        fields = (
            ("Hostname", hostname),
            ("Interfaz descubierta", interface),
            ("IPv4 de gestión", address),
            ("Máscara IPv4", netmask),
        )
        for label, value in fields:
            ttk.Label(
                form, text=label, background="#ffffff", foreground="#526777", font=("Segoe UI", 10)
            ).pack(anchor="w")
            if value is interface:
                ttk.Combobox(
                    form,
                    textvariable=value,
                    values=tuple(session.facts.interfaces),
                    state="readonly",
                ).pack(fill="x", pady=(2, 8))
            else:
                ttk.Entry(form, textvariable=value).pack(fill="x", pady=(2, 8))

        ttk.Label(
            form,
            text=(
                "El candidato no será enviado ni guardado. La futura ejecución requerirá una "
                "prueba autorizada con commit confirmed."
            ),
            background="#ffffff",
            foreground="#526777",
            wraplength=680,
        ).pack(anchor="w", pady=(4, 8))

        def prepare() -> None:
            try:
                self._review_and_execute_plan(
                    build_management_candidate(
                        {
                            "hostname": hostname.get(),
                            "interface": interface.get(),
                            "address": address.get(),
                            "netmask": netmask.get(),
                        },
                        session.facts,
                    )
                )
            except ValidationError as exc:
                messagebox.showwarning("Datos por corregir", str(exc), parent=self)

        ttk.Button(
            form, text="Validar y preparar candidato", style="Primary.TButton", command=prepare
        ).pack(fill="x", pady=(8, 0))

    def _junos_vlan_access_candidate_page(self) -> None:
        if not self.session or self.session.platform is not NetworkPlatform.JUNIPER_JUNOS:
            return
        session = self.session
        self._clear()
        self._page_header(
            "VLAN nueva y puerto access Junos",
            "Crea solamente una VLAN nueva y asigna un puerto fisico. No uses un uplink o trunk.",
        )
        form = ttk.Frame(self.content, style="Card.TFrame", padding=(22, 20))
        form.pack(fill="x")
        vlan_name = tk.StringVar()
        vlan_id = tk.StringVar()
        ports = tuple(
            name
            for name in session.facts.interfaces
            if re.fullmatch(r"(?:ge|xe|et)-\d+/\d+/\d+", name, re.I)
        )
        interface = tk.StringVar(value=ports[0] if ports else "")
        for label, value in (("Nombre de VLAN", vlan_name), ("ID de VLAN (2-4094)", vlan_id)):
            ttk.Label(form, text=label, background="#ffffff", foreground="#526777").pack(anchor="w")
            ttk.Entry(form, textvariable=value).pack(fill="x", pady=(2, 8))
        ttk.Label(form, text="Puerto fisico access", background="#ffffff", foreground="#526777").pack(
            anchor="w"
        )
        ttk.Combobox(form, textvariable=interface, values=ports, state="readonly").pack(
            fill="x", pady=(2, 8)
        )
        ttk.Label(
            form,
            text=(
                "El puerto seleccionado dejara de pertenecer a su VLAN access actual. "
                "Confirma su uso fisico antes de aplicar."
            ),
            background="#ffffff",
            foreground="#9c2f19",
            wraplength=680,
        ).pack(anchor="w", pady=(4, 8))

        def prepare() -> None:
            try:
                management_address = (
                    str(session.reconnect_params.get("host", "")) if session.reconnect_params else ""
                )
                self._review_and_execute_plan(
                    build_vlan_access_candidate(
                        {
                            "vlan_name": vlan_name.get(),
                            "vlan_id": vlan_id.get(),
                            "interface": interface.get(),
                        },
                        session.facts,
                        management_address,
                    )
                )
            except ValidationError as exc:
                messagebox.showwarning("Datos por corregir", str(exc), parent=self)

        ttk.Button(form, text="Validar y preparar candidato", style="Primary.TButton", command=prepare).pack(
            fill="x", pady=(8, 0)
        )

    def _junos_existing_vlan_access_page(self) -> None:
        if not self.session or self.session.platform is not NetworkPlatform.JUNIPER_JUNOS:
            return
        session = self.session
        self._clear()
        self._page_header(
            "Asignar VLAN existente a puerto access",
            "Usa una VLAN descubierta. Este flujo nunca crea, borra ni renombra una VLAN.",
        )
        form = ttk.Frame(self.content, style="Card.TFrame", padding=(22, 20))
        form.pack(fill="x")
        vlan_options = {f"{vlan_id} · {name}": name for vlan_id, name in sorted(session.facts.vlans.items())}
        if not vlan_options:
            ttk.Label(
                form,
                text="No hay VLANs descubiertas. Actualiza el inventario antes de continuar.",
                background="#ffffff",
                foreground="#9c2f19",
            ).pack(anchor="w")
            return
        ports = tuple(
            name
            for name in session.facts.interfaces
            if re.fullmatch(r"(?:ge|xe|et)-\d+/\d+/\d+", name, re.I)
        )
        selected_vlan = tk.StringVar(value=next(iter(vlan_options)))
        interface = tk.StringVar(value=ports[0] if ports else "")
        ttk.Label(form, text="VLAN existente", background="#ffffff", foreground="#526777").pack(anchor="w")
        ttk.Combobox(
            form, textvariable=selected_vlan, values=tuple(vlan_options), state="readonly"
        ).pack(fill="x", pady=(2, 8))
        ttk.Label(form, text="Puerto fisico access", background="#ffffff", foreground="#526777").pack(
            anchor="w"
        )
        ttk.Combobox(form, textvariable=interface, values=ports, state="readonly").pack(
            fill="x", pady=(2, 8)
        )
        ttk.Label(
            form,
            text="Confirma que el puerto no es un uplink o trunk antes de aplicar el candidato.",
            background="#ffffff",
            foreground="#9c2f19",
            wraplength=680,
        ).pack(anchor="w", pady=(4, 8))

        def prepare() -> None:
            try:
                management_address = (
                    str(session.reconnect_params.get("host", "")) if session.reconnect_params else ""
                )
                self._review_and_execute_plan(
                    build_existing_vlan_access_candidate(
                        {
                            "vlan_name": vlan_options[selected_vlan.get()],
                            "interface": interface.get(),
                        },
                        session.facts,
                        management_address,
                    )
                )
            except ValidationError as exc:
                messagebox.showwarning("Datos por corregir", str(exc), parent=self)

        ttk.Button(form, text="Validar y preparar candidato", style="Primary.TButton", command=prepare).pack(
            fill="x", pady=(8, 0)
        )

    def _junos_existing_vlan_trunk_page(self) -> None:
        if not self.session or self.session.platform is not NetworkPlatform.JUNIPER_JUNOS:
            return
        session = self.session
        self._clear()
        self._page_header(
            "Agregar VLAN existente a puerto trunk",
            "Añade una VLAN a un enlace entre equipos y establece el puerto en modo trunk.",
        )
        form = ttk.Frame(self.content, style="Card.TFrame", padding=(22, 20))
        form.pack(fill="x")
        vlan_options = {f"{vlan_id} · {name}": name for vlan_id, name in sorted(session.facts.vlans.items())}
        if not vlan_options:
            ttk.Label(
                form,
                text="No hay VLANs descubiertas. Actualiza el inventario antes de continuar.",
                background="#ffffff",
                foreground="#9c2f19",
            ).pack(anchor="w")
            return
        ports = tuple(
            name
            for name in session.facts.interfaces
            if re.fullmatch(r"(?:ge|xe|et)-\d+/\d+/\d+", name, re.I)
        )
        selected_vlan = tk.StringVar(value=next(iter(vlan_options)))
        interface = tk.StringVar(value=ports[0] if ports else "")
        ttk.Label(form, text="VLAN existente", background="#ffffff", foreground="#526777").pack(anchor="w")
        ttk.Combobox(
            form, textvariable=selected_vlan, values=tuple(vlan_options), state="readonly"
        ).pack(fill="x", pady=(2, 8))
        ttk.Label(form, text="Puerto fisico trunk", background="#ffffff", foreground="#526777").pack(
            anchor="w"
        )
        ttk.Combobox(form, textvariable=interface, values=ports, state="readonly").pack(
            fill="x", pady=(2, 8)
        )
        ttk.Label(
            form,
            text=(
                "Solo úsalo para un enlace a otro switch, router o hipervisor "
                "configurado para VLAN etiquetada."
            ),
            background="#ffffff",
            foreground="#9c2f19",
            wraplength=680,
        ).pack(anchor="w", pady=(4, 8))

        def prepare() -> None:
            try:
                management_address = (
                    str(session.reconnect_params.get("host", "")) if session.reconnect_params else ""
                )
                self._review_and_execute_plan(
                    build_existing_vlan_trunk_candidate(
                        {
                            "vlan_name": vlan_options[selected_vlan.get()],
                            "interface": interface.get(),
                        },
                        session.facts,
                        management_address,
                    )
                )
            except ValidationError as exc:
                messagebox.showwarning("Datos por corregir", str(exc), parent=self)

        ttk.Button(form, text="Validar y preparar candidato", style="Primary.TButton", command=prepare).pack(
            fill="x", pady=(8, 0)
        )

    def _simple_plan_form(
        self,
        title: str,
        fields: tuple[tuple[str, str], ...],
        builder: Callable[[dict[str, str]], CommandPlan],
        *,
        hidden: set[str] | None = None,
        notice: str = "",
    ) -> None:
        self._clear()
        self._page_header(title, "Los datos se validan antes de mostrar cualquier comando.")
        form = ttk.Frame(self.content, style="Card.TFrame", padding=(22, 20))
        form.pack(fill="x")
        values: dict[str, tk.StringVar] = {}
        for label, key in fields:
            ttk.Label(
                form, text=label, background="#ffffff", foreground="#526777", font=("Segoe UI", 10)
            ).pack(anchor="w")
            value = tk.StringVar(value="2048" if key == "rsa_bits" else "")
            ttk.Entry(form, textvariable=value, show="*" if hidden and key in hidden else "").pack(
                fill="x", pady=(2, 8)
            )
            values[key] = value
        if notice:
            ttk.Label(
                form, text=notice, background="#ffffff", foreground="#526777", wraplength=680
            ).pack(
                anchor="w", pady=(4, 8)
            )

        def prepare() -> None:
            try:
                self._review_and_execute_plan(builder({key: value.get() for key, value in values.items()}))
            except ValidationError as exc:
                messagebox.showwarning("Datos por corregir", str(exc), parent=self)

        ttk.Button(form, text="Validar y preparar plan", style="Primary.TButton", command=prepare).pack(
            fill="x", pady=(8, 0)
        )

    @staticmethod
    def _verify_junos_management_session(session: DeviceSession, plan: CommandPlan) -> bool:
        """Abre una segunda sesion SSH efimera antes del commit final de Junos."""
        if session.transport != "ssh" or not session.reconnect_params:
            return False
        address = str(plan.metadata.get("management_address", ""))
        if not address or not plan.postchecks:
            return False
        params = dict(session.reconnect_params)
        params["host"] = address
        second_connection: Any | None = None
        try:
            second_connection = ConnectHandler(**params)
            for command in plan.postchecks:
                output = str(second_connection.send_command(command))
                expected = plan.postcheck_expectations.get(command, ())
                if not all(value.casefold() in output.casefold() for value in expected):
                    session.audit.event(
                        "junos_second_session_postcheck_failed",
                        command=command,
                        expected=expected,
                    )
                    return False
            return True
        except Exception as exc:
            session.audit.event("junos_second_session_failed", error=redact_text(str(exc)))
            return False
        finally:
            disconnect = getattr(second_connection, "disconnect", None)
            if callable(disconnect):
                disconnect()

    def _confirm_junos_lab_apply(self, parent: tk.Misc) -> str | None:
        """Solicita una confirmacion afirmativa sin obligar a transcribir una frase."""
        dialog = tk.Toplevel(self)
        dialog.title("Aceptacion de laboratorio")
        dialog.transient(parent)
        dialog.resizable(False, False)
        dialog.configure(background="#f6f8fb", padx=22, pady=18)
        accepted = tk.BooleanVar(value=False)
        response: dict[str, str | None] = {"value": None}

        ttk.Label(
            dialog,
            text="Prueba Junos autorizada",
            background="#f6f8fb",
            foreground="#102a43",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            dialog,
            text=(
                "Se aplicara un commit confirmed de 5 minutos. Debes conservar una consola "
                "fisica recuperable; SarevatApp verificara una segunda sesion SSH antes del commit final."
            ),
            background="#f6f8fb",
            foreground="#526777",
            wraplength=500,
            justify="left",
        ).pack(anchor="w", pady=(8, 12))
        ttk.Checkbutton(
            dialog,
            text="Confirmo que es un laboratorio autorizado y tengo consola recuperable.",
            variable=accepted,
        ).pack(anchor="w")
        actions = ttk.Frame(dialog, style="Card.TFrame")
        actions.pack(fill="x", pady=(16, 0))
        actions.columnconfigure((0, 1), weight=1)

        def cancel() -> None:
            dialog.destroy()

        def apply() -> None:
            response["value"] = junos_lab_checkbox_acceptance(accepted.get())
            dialog.destroy()

        apply_button = ttk.Button(actions, text="Aplicar prueba", style="Primary.TButton", command=apply)
        apply_button.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ttk.Button(actions, text="Cancelar", command=cancel).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        def sync_apply_button(*_: object) -> None:
            apply_button.state(["!disabled"] if accepted.get() else ["disabled"])

        accepted.trace_add("write", sync_apply_button)
        sync_apply_button()
        dialog.protocol("WM_DELETE_WINDOW", cancel)
        dialog.grab_set()
        dialog.wait_window()
        return response["value"]

    def _review_and_execute_plan(self, plan: CommandPlan) -> None:
        if not self.session:
            return
        session = self.session
        with suppress(OSError, ValueError):
            DraftStore(self.runtime / "drafts.json").add_plan(plan)
        review = tk.Toplevel(self)
        review.title(f"Plan seguro: {plan.name}")
        review.transient(self)
        review.configure(background="#f6f8fb", padx=24, pady=22)
        ttk.Label(
            review,
            text="VISTA PREVIA SEGURA",
            background="#f6f8fb",
            foreground="#197278",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            review,
            text=plan.name,
            background="#f6f8fb",
            foreground="#102a43",
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w", pady=(3, 0))
        if plan.warnings:
            ttk.Label(
                review,
                text="\n".join(plan.warnings),
                background="#f6f8fb",
                foreground="#a05132",
                wraplength=700,
            ).pack(anchor="w", pady=(8, 0))
        commands = tk.Text(
            review,
            height=min(16, max(5, len(plan.commands) + 2)),
            width=88,
            wrap="word",
            background="#102a43",
            foreground="#e5f0f5",
            relief="flat",
            padx=12,
            pady=10,
        )
        commands.insert("1.0", "\n".join(redact_text(command) for command in plan.commands))
        commands.config(state="disabled")
        commands.pack(fill="both", expand=True, pady=(12, 0))
        manual_workflow = plan.metadata.get("manual_workflow")
        if manual_workflow:
            ttk.Label(
                review,
                text="Flujo planificado: " + "  →  ".join(manual_workflow),
                background="#f6f8fb",
                foreground="#526777",
                wraplength=700,
            ).pack(anchor="w", pady=(10, 0))
        status = tk.StringVar(value="Validando con dry-run: no se enviarán comandos.")
        ttk.Label(
            review, textvariable=status, background="#f6f8fb", foreground="#526777", wraplength=700
        ).pack(anchor="w", pady=(10, 0))

        if plan.metadata.get("preview_only"):
            status.set(
                "Candidato validado. La aplicación Junos está bloqueada hasta completar la prueba autorizada."
            )
            evidence = tk.Text(
                review,
                height=9,
                width=88,
                wrap="word",
                background="#ffffff",
                foreground="#102a43",
                relief="solid",
                padx=10,
                pady=8,
            )
            evidence.config(state="disabled")

            def finish_prechecks(result: object) -> None:
                if not widget_exists(review):
                    return
                precheck_button.state(["!disabled"])
                if isinstance(result, Exception):
                    status.set(f"No se pudieron consultar los prechecks: {redact_text(str(result))}")
                    return
                if not isinstance(result, JunosPrecheckReport):
                    status.set("Resultado de prechecks no reconocido.")
                    return
                session.audit.event(
                    "junos_prechecks",
                    result="approved" if result.ok else "errors",
                    commands=tuple(result.outputs),
                )
                status.set(
                    "Prechecks aprobados: solo se ejecutaron consultas."
                    if result.ok
                    else "Prechecks con advertencias: revisa la evidencia antes de continuar."
                )
                evidence.config(state="normal")
                evidence.delete("1.0", "end")
                evidence.insert("1.0", format_junos_prechecks(result))
                evidence.config(state="disabled")
                evidence.pack(fill="both", expand=True, pady=(10, 0))
                if result.ok:
                    apply_junos_button.state(["!disabled"])

            def start_prechecks() -> None:
                precheck_button.state(["disabled"])
                status.set("Consultando prechecks Junos de solo lectura...")
                self._run_session_worker(
                    lambda: run_prechecks(session.connection, plan), finish_prechecks
                )

            def apply_junos() -> None:
                if not isinstance(session.executor, JunosExecutor):
                    status.set("No se encontro un ejecutor Junos para esta sesion.")
                    return
                acceptance = self._confirm_junos_lab_apply(review)
                if acceptance is None:
                    status.set("Aplicacion Junos cancelada: falta la aceptacion del laboratorio.")
                    return
                apply_junos_button.state(["disabled"])
                status.set("Aplicando commit confirmed y verificando una segunda sesion SSH...")

                def finish_apply(result: object) -> None:
                    if not widget_exists(review):
                        return
                    if isinstance(result, Exception):
                        status.set(f"Aplicacion Junos detenida: {redact_text(str(result))}")
                        return
                    if not isinstance(result, ExecutionReport):
                        status.set("Resultado de aplicacion Junos no reconocido.")
                        return
                    self._save_report(result)
                    status.set(result.message)
                    if result.success and self.session is session:
                        self._run_session_worker(
                            lambda: adapter_for(session.platform).discover(session.connection),
                            self._update_session_facts,
                        )

                self._run_session_worker(
                    lambda: session.executor.execute(
                        plan,
                        dry_run=False,
                        lab_acceptance=acceptance,
                        confirm=lambda _: True,
                        verify_management=lambda: self._verify_junos_management_session(session, plan),
                    ),
                    finish_apply,
                )

            precheck_button = ttk.Button(
                review,
                text="Ejecutar prechecks de solo lectura",
                style="Primary.TButton",
                command=start_prechecks,
            )
            precheck_button.pack(fill="x", pady=(12, 0))
            apply_junos_button = ttk.Button(
                review,
                text="Aplicación remota no habilitada",
                style="Primary.TButton",
                command=apply_junos,
            )
            apply_junos_button.pack(fill="x", pady=(12, 0))
            apply_junos_button.configure(text="Aplicar prueba Junos tras prechecks aprobados")
            apply_junos_button.state(["disabled"])
            return

        def after_dry(result: object) -> None:
            if isinstance(result, Exception):
                status.set(f"No se pudo validar: {redact_text(str(result))}")
                return
            self._save_report(result)
            status.set(result.message)
            apply_button.state(["!disabled"])

        def apply() -> None:
            if not messagebox.askyesno(
                "Aplicar plan", f"Aplicar '{plan.name}' en el equipo conectado?", parent=review
            ):
                return
            dangerous = plan_dangerous_reasons(plan.commands)
            if dangerous:
                reasons = sorted({reason for items in dangerous.values() for reason in items})
                if not messagebox.askyesno(
                    "Confirmacion reforzada",
                    "Este plan puede: " + "; ".join(reasons) + ".\n\nConfirmas aplicarlo nuevamente?",
                    parent=review,
                ):
                    status.set("Plan cancelado antes de aplicar comandos de alto impacto.")
                    return
            if plan.service == "aaa_local":
                phrase_aaa = simpledialog.askstring(
                    "Confirmacion AAA",
                    "Escribe AAA_APLICAR para confirmar el cambio de acceso:",
                    parent=review,
                )
                if phrase_aaa != "AAA_APLICAR":
                    status.set("AAA no se aplico: confirmacion no completada.")
                    return
            if plan.metadata.get("interactive_commands") and not messagebox.askyesno(
                "Clave RSA",
                "El plan puede solicitar reemplazar una clave RSA existente. Continuar?",
                parent=review,
            ):
                return
            allow_rollback = messagebox.askyesno(
                "Rollback automatico",
                "Si IOS rechaza el plan despues de crear el checkpoint, autorizar restaurar ese checkpoint?",
                parent=review,
            )
            phrase = simpledialog.askstring(
                "Respaldo cifrado",
                "Frase para cifrar el respaldo (mínimo 12 caracteres):",
                show="*",
                parent=review,
            )
            try:
                session.executor.backup_cipher = BackupCipher(phrase or "")
            except ValueError as exc:
                status.set(str(exc))
                return
            status.set("Aplicando con checkpoint, respaldo y postchecks...")
            apply_button.state(["disabled"])
            self._run_session_worker(
                lambda: session.executor.execute(
                    plan,
                    dry_run=False,
                    confirm=lambda message: allow_rollback if message.startswith("Rollback:") else True,
                    create_checkpoint=True,
                    rollback_on_error=allow_rollback,
                ),
                after_apply,
            )

        def after_apply(result: object) -> None:
            if isinstance(result, Exception):
                status.set(f"Aplicacion detenida: {redact_text(str(result))}")
                return
            self._save_report(result)
            status.set(result.message)
            if self.session is session:
                self._run_session_worker(
                    lambda: adapter_for(session.platform).discover(session.connection),
                    self._update_session_facts,
                )

        apply_button = ttk.Button(
            review, text="Aplicar tras dry-run validado", style="Primary.TButton", command=apply
        )
        apply_button.pack(fill="x", pady=(12, 0))
        apply_button.state(["disabled"])
        self._run_session_worker(lambda: session.executor.execute(plan, dry_run=True), after_dry)

    def _save_report(self, report: ExecutionReport) -> None:
        safe_name = "".join(item if item.isalnum() else "_" for item in report.plan_name)[:50]
        stamp = report.started_at.strftime("%Y%m%d_%H%M%S")
        base = self.runtime / "reports" / f"ejecucion_{safe_name}_{stamp}_{report.status.value}"
        try:
            export_execution_report_json(report, base.with_suffix(".json"))
            export_execution_report_csv(report, base.with_suffix(".csv"))
        except OSError:
            pass

    def _update_session_facts(self, result: object) -> None:
        if self.session and not isinstance(result, Exception):
            self.session.facts = result

    def _free_console_page(self) -> None:
        if not self.session:
            return
        session = self.session
        self._clear()
        self._page_header(
            "Consola libre controlada",
            "Los comandos se envían uno a uno, se auditan y requieren confirmación si son de alto impacto.",
        )
        form = ttk.Frame(self.content, style="Card.TFrame", padding=(18, 16))
        form.pack(fill="x")
        ttk.Label(
            form,
            text="Comando IOS",
            background="#ffffff",
            foreground="#102a43",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w")
        command = tk.StringVar()
        output = tk.Text(
            self.content,
            height=16,
            wrap="word",
            state="disabled",
            font=("Consolas", 10),
            background="#102a43",
            foreground="#e5f0f5",
            relief="flat",
            padx=12,
            pady=10,
        )
        ttk.Entry(form, textvariable=command).pack(fill="x", pady=(4, 10))

        def send() -> None:
            value = command.get().strip()
            if not value:
                return
            reasons = dangerous_reasons(value)
            if reasons and not messagebox.askyesno(
                "Comando de alto impacto", "; ".join(reasons), parent=self
            ):
                session.audit.event(
                    "free_command_cancelled", command=redact_text(value), reasons=reasons
                )
                return
            command.set("")

            def run_command() -> str:
                response = str(session.executor.connection.send_command_timing(value, read_timeout=30))
                session.audit.event(
                    "free_command",
                    command=redact_text(value),
                    output=redact_text(response),
                    errors=find_ios_errors(response),
                )
                return response

            self._run_session_worker(
                run_command, done
            )

        def done(result: object) -> None:
            output.config(state="normal")
            output.insert(
                "end", redact_text(str(result)) + "\n"
            )
            output.config(state="disabled")

        ttk.Button(form, text="Enviar comando", style="Primary.TButton", command=send).pack(fill="x")
        output.pack(fill="both", expand=True, pady=(12, 0))

    def _write_memory(self) -> None:
        if not self.session or not messagebox.askyesno(
            "Guardar configuracion", "Guardar running-config en startup-config?", parent=self
        ):
            return
        session = self.session
        def done(result: object) -> None:
            if isinstance(result, Exception):
                messagebox.showwarning("Guardar configuracion", redact_text(str(result)), parent=self)
                return
            if self.session is session:
                session.audit.event("write_memory", output=redact_text(str(result)))
            messagebox.showinfo("Guardar configuracion", redact_text(str(result)), parent=self)

        self._run_session_worker(
            lambda: session.executor.connection.send_command_timing("write memory", read_timeout=30),
            done,
        )

    def _compare_file(self) -> None:
        if not self.session:
            return
        path = filedialog.askopenfilename(parent=self, title="Configuracion propuesta")
        if not path:
            return
        try:
            proposed = Path(path).read_text(encoding="utf-8")
            from sarevat.drafts import configuration_diff

            diff = (
                configuration_diff(self.session.facts.running_config, proposed)
                or "No se detectaron diferencias."
            )
        except (OSError, ValueError) as exc:
            messagebox.showwarning("Comparacion", str(exc), parent=self)
            return
        self._show_records(
            "Diferencias de configuracion", diff.splitlines()[:120], "No se detectaron diferencias."
        )

    def _compliance_page(self) -> None:
        if not self.session:
            return
        findings = audit_running_config(self.session.facts.running_config)
        with suppress(OSError):
            export_compliance_json(findings, self.runtime / "reports" / "cumplimiento_gui.json")
        lines = [
            f"{'OK' if item.status is ComplianceStatus.COMPLIANT else 'PENDIENTE'}: {item.title}"
            for item in findings
        ]
        self._show_records("Revision de seguridad", lines, "No hay configuracion disponible.")

    def _save_baseline(self) -> None:
        if not self.session:
            return
        store = BaselineStore(self.runtime / "referencia_configuracion.json")
        if store.exists() and not messagebox.askyesno(
            "Reemplazar referencia", "Reemplazar la referencia local anterior?", parent=self
        ):
            return
        try:
            store.save(
                ConfigurationBaseline.from_config(
                    self.session.facts.hostname, self.session.facts.running_config
                )
            )
            messagebox.showinfo(
                "Referencia", "Referencia segura guardada sin secretos visibles.", parent=self
            )
        except ValueError as exc:
            messagebox.showwarning("Referencia", str(exc), parent=self)

    def _show_drift(self) -> None:
        if not self.session:
            return
        try:
            baseline = BaselineStore(self.runtime / "referencia_configuracion.json").load()
            diff = compare_with_baseline(baseline, self.session.facts.running_config)
        except ValueError as exc:
            messagebox.showwarning("Cambios", str(exc), parent=self)
            return
        self._show_records(
            "Cambios desde la referencia",
            diff.splitlines()[:120],
            "No hay cambios frente a la referencia guardada.",
        )

    def _vlsm_page(self) -> None:
        self._page_header(
            "Planificador VLSM IPv4",
            (
                "Cada solicitud se calcula como una red separada; valida el resultado antes de "
                "preparar interfaces."
            ),
        )

        viewport = ttk.Frame(self.content, style="App.TFrame")
        viewport.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(viewport, orient="vertical")
        canvas = tk.Canvas(viewport, background="#ffffff", highlightthickness=0)
        scrollbar.configure(command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        form = ttk.Frame(canvas, style="Card.TFrame", padding=(22, 20))
        form_window = canvas.create_window((0, 0), window=form, anchor="nw")

        def update_scroll_region(_: tk.Event[tk.Misc]) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_form(event: tk.Event[tk.Misc]) -> None:
            canvas.itemconfigure(form_window, width=event.width)

        form.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", resize_form)
        base, mask, excluded = tk.StringVar(), tk.StringVar(value="/24"), tk.StringVar()
        use_subnets, count = tk.StringVar(value="No"), tk.StringVar(value="1")
        rows: list[tuple[tk.StringVar, tk.StringVar, tk.StringVar]] = []
        allocations: list[Any] = []
        current_plan: VLSMPlan | None = None
        ttk.Label(form, text="Introducir Red Base", style="Body.TLabel").pack(anchor="w")
        base_controls = ttk.Frame(form, style="Card.TFrame")
        base_controls.pack(anchor="w", pady=(3, 10))
        ttk.Entry(base_controls, textvariable=base, width=26).pack(side="left")
        ttk.Combobox(
            base_controls,
            textvariable=mask,
            values=VLSM_MASK_OPTIONS,
            width=7,
            state="readonly",
        ).pack(side="left", padx=(8, 0))
        ttk.Label(form, text="Excluir IP", style="Body.TLabel").pack(anchor="w")
        ttk.Label(form, text="(opcional, separadas por coma)", style="Body.TLabel").pack(anchor="w")
        ttk.Entry(form, textvariable=excluded).pack(fill="x", pady=(3, 10))
        ttk.Label(form, text="Trabajar con subredes", style="Body.TLabel").pack(anchor="w")
        choice = ttk.Combobox(form, textvariable=use_subnets, values=("No", "Si"), state="readonly")
        choice.pack(fill="x", pady=(3, 10))
        subnets_frame = ttk.Frame(form, style="Card.TFrame")
        results = ttk.Frame(form, style="Card.TFrame", padding=(14, 12))

        def render_subnets(*_: object) -> None:
            for child in subnets_frame.winfo_children():
                child.destroy()
            rows.clear()
            if use_subnets.get() == "No":
                subnets_frame.pack_forget()
                return
            subnets_frame.pack(fill="x", pady=(0, 10))
            ttk.Label(subnets_frame, text="Cantidad de subredes", style="Body.TLabel").grid(
                row=0, column=0, sticky="w"
            )
            ttk.Entry(subnets_frame, textvariable=count, width=8).grid(row=0, column=1, padx=8, sticky="w")
            ttk.Button(subnets_frame, text="Preparar campos", command=prepare_rows).grid(row=0, column=2)

        def prepare_rows() -> None:
            try:
                quantity = int(count.get())
                if not 1 <= quantity <= 64:
                    raise ValueError
            except ValueError:
                messagebox.showwarning(
                    "Cantidad invalida", "Cantidad: usa un numero entre 1 y 64.", parent=self
                )
                return
            for widget in subnets_frame.grid_slaves():
                if int(widget.grid_info().get("row", 0)) > 0:
                    widget.destroy()
            rows.clear()
            for column, label in enumerate(("Interfaz o nombre", "Hosts", "Tipo"), start=1):
                ttk.Label(subnets_frame, text=label, style="Body.TLabel").grid(
                    row=1, column=column, sticky="w", padx=8 if column > 1 else 0, pady=(8, 2)
                )
            for index in range(quantity):
                name, hosts, kind = tk.StringVar(), tk.StringVar(), tk.StringVar(value="lan")
                ttk.Label(subnets_frame, text=f"Subred {index + 1}", style="Body.TLabel").grid(
                    row=index + 2, column=0, sticky="w", pady=(5, 0)
                )
                ttk.Entry(subnets_frame, textvariable=name).grid(row=index + 2, column=1, padx=8, sticky="ew")
                ttk.Entry(subnets_frame, textvariable=hosts, width=8).grid(
                    row=index + 2, column=2, padx=(0, 8)
                )
                ttk.Combobox(
                    subnets_frame,
                    textvariable=kind,
                    values=("lan", "point_to_point", "loopback"),
                    width=16,
                    state="readonly",
                ).grid(row=index + 2, column=3)
                rows.append((name, hosts, kind))
            subnets_frame.columnconfigure(1, weight=1)

        def export_current_plan(plan: VLSMPlan) -> None:
            try:
                json_path, csv_path = export_vlsm_outputs(plan, self.runtime / "reports")
            except OSError as exc:
                messagebox.showwarning("Exportacion VLSM", str(exc), parent=self)
                return
            messagebox.showinfo(
                "Exportacion VLSM",
                f"Resultados guardados localmente:\n{json_path.name}\n{csv_path.name}",
                parent=self,
            )

        def calculate() -> None:
            nonlocal current_plan
            try:
                for child in results.winfo_children():
                    child.destroy()
                allocations.clear()
                current_plan = None
                base_network = build_vlsm_base_network(base.get(), mask.get())
                if use_subnets.get() == "No":
                    values = network_summary(base_network)
                    if excluded.get().strip():
                        values["Excluir IP"] = "Solo se aplica cuando trabajas con subredes."
                    lines = [f"{key}: {value}" for key, value in values.items()]
                else:
                    if not rows:
                        raise ValidationError("Primero prepara los campos de las subredes.")
                    requests = build_vlsm_requests(
                        [(name.get(), hosts.get(), kind.get()) for name, hosts, kind in rows]
                    )
                    reserved = tuple(item.strip() for item in excluded.get().split(",") if item.strip())
                    current_plan = calculate_vlsm(base_network, requests, reserved=reserved)
                    allocations.extend(current_plan.allocations)
                    lines = []
                results.pack(fill="x", pady=(14, 0))
                if allocations:
                    ttk.Label(
                        results,
                        text=(
                            f"Red base: {current_plan.base_network} · "
                            f"{len(allocations)} asignación(es)"
                        ),
                        style="Body.TLabel",
                    ).pack(anchor="w", pady=(0, 8))
                    for allocation in allocations:
                        card = ttk.Frame(results, style="Card.TFrame", padding=(14, 12))
                        card.pack(fill="x", pady=3)
                        ttk.Label(
                            card,
                            text=allocation.name,
                            background="#ffffff",
                            foreground="#102a43",
                            font=("Segoe UI", 10, "bold"),
                        ).pack(anchor="w")
                        ttk.Label(
                            card,
                            text=(
                                f"{allocation.network} · gateway: {allocation.gateway or 'No aplica'} · "
                                f"broadcast: {allocation.broadcast}"
                            ),
                            background="#ffffff",
                            foreground="#526777",
                        ).pack(anchor="w", pady=(2, 6))
                        if self.session:
                            ttk.Button(
                                card,
                                text="Preparar IPv4 para esta interfaz",
                                command=lambda item=allocation: self._prepare_vlsm_interface(item),
                            ).pack(anchor="w")
                    plan_to_export = current_plan

                    def export_current_plan() -> None:
                        try:
                            json_path, csv_path = export_vlsm_outputs(
                                plan_to_export, self.runtime / "reports"
                            )
                        except OSError as exc:
                            messagebox.showwarning("Exportación VLSM", str(exc), parent=self)
                            return
                        messagebox.showinfo(
                            "Exportación VLSM",
                            f"Resultados guardados localmente:\n{json_path.name}\n{csv_path.name}",
                            parent=self,
                        )

                    ttk.Button(
                        results,
                        text="Exportar resultados JSON y CSV",
                        command=export_current_plan,
                    ).pack(anchor="w", pady=(8, 0))
                ttk.Label(results, text="Resultado", style="Body.TLabel", font=("Segoe UI", 10, "bold")).pack(
                    anchor="w"
                )
                if allocations:
                    ttk.Label(
                        results,
                        text=f"Red base: {current_plan.base_network}",
                        style="Body.TLabel",
                        justify="left",
                    ).pack(anchor="w", pady=(3, 6))
                    columns = ("nombre", "red", "mascara", "gateway", "broadcast")
                    table = ttk.Treeview(
                        results, columns=columns, show="headings", height=min(8, len(allocations))
                    )
                    headings = {
                        "nombre": "Nombre",
                        "red": "Red",
                        "mascara": "Mascara",
                        "gateway": "Gateway",
                        "broadcast": "Broadcast",
                    }
                    widths = {"nombre": 130, "red": 140, "mascara": 125, "gateway": 120, "broadcast": 120}
                    for column in columns:
                        table.heading(column, text=headings[column])
                        table.column(column, width=widths[column], minwidth=90, stretch=True)
                    for item in allocations:
                        table.insert(
                            "",
                            "end",
                            values=(
                                item.name,
                                item.network,
                                item.netmask,
                                item.gateway or "No aplica",
                                item.broadcast,
                            ),
                        )
                    table.pack(fill="x", anchor="w")
                    ttk.Button(
                        results,
                        text="Exportar resultados JSON y CSV",
                        command=lambda plan=current_plan: export_current_plan(plan),
                    ).pack(anchor="w", pady=(8, 0))
                else:
                    ttk.Label(results, text="\n".join(lines), style="Body.TLabel", justify="left").pack(
                        anchor="w"
                    )
                if allocations and self.session:
                    ttk.Label(
                        results,
                        text=(
                            "Cada interfaz usa la primera IPv4 utilizable calculada. "
                            "Revisa y aplica una por una para conservar el control."
                        ),
                        style="Body.TLabel",
                        wraplength=680,
                    ).pack(anchor="w", pady=(10, 5))
            except (ValidationError, ValueError) as exc:
                messagebox.showwarning("Corrige los datos", str(exc), parent=self)

        choice.bind("<<ComboboxSelected>>", render_subnets)
        ttk.Button(form, text="Validar y calcular", style="Primary.TButton", command=calculate).pack(fill="x")

    def _serial_bootstrap_page(self) -> None:
        if not self.session or not self.session.platform.is_cisco:
            messagebox.showwarning(
                "Bootstrap serial",
                "Esta herramienta requiere una sesión Cisco IOS abierta por consola serial.",
                parent=self,
            )
            return
        if self.session.transport != "serial":
            messagebox.showwarning(
                "Bootstrap serial",
                "Desconecta la sesión SSH y abre una conexión serial para preparar un equipo nuevo.",
                parent=self,
            )
            return
        self._simple_plan_form(
            "Equipo nuevo Cisco por serial",
            (
                ("Hostname", "hostname"),
                ("Dominio", "domain"),
                ("Usuario administrador", "username"),
                ("Password", "password"),
                ("Enable secret", "enable_secret"),
                ("Interfaz de gestion", "interface"),
                ("IPv4 de gestion", "address"),
                ("Mascara IPv4", "netmask"),
                ("RSA (2048/3072/4096)", "rsa_bits"),
            ),
            build_serial_bootstrap_plan,
            hidden={"password", "enable_secret"},
            notice=(
                "Vista previa obligatoria. El plan configura IP y SSH en memoria; "
                "no guarda startup-config automaticamente."
            ),
        )

    def _prepare_vlsm_interface(self, allocation: Any) -> None:
        if not self.session:
            return
        try:
            self._review_and_execute_plan(
                build_interface_ip_plan(
                    allocation.name, str(allocation.first_usable), str(allocation.netmask), self.session.facts
                )
            )
        except ValidationError as exc:
            messagebox.showwarning("Interfaz por corregir", str(exc), parent=self)

    def _scan_page(self) -> None:
        self._page_header(
            "Escáner IPv4 autorizado",
            "Disponible solo para redes que administras o tienes permiso explícito de evaluar.",
        )
        safety = ttk.Frame(self.content, style="Card.TFrame", padding=(16, 13))
        safety.pack(fill="x", pady=(0, 14))
        ttk.Label(
            safety,
            text="Control de alcance",
            background="#ffffff",
            foreground="#102a43",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            safety,
            text="Escribe AUTORIZO, revisa el objetivo y confirma una segunda vez antes de iniciar.",
            background="#ffffff",
            foreground="#526777",
        ).pack(anchor="w", pady=(3, 0))
        target_value = tk.StringVar()
        mode = tk.StringVar(value="Ping sweep IPv4")
        authorization = tk.StringVar()
        export_results = tk.BooleanVar(value=False)
        resolve_dns = tk.BooleanVar(value=False)
        resolve_mac = tk.BooleanVar(value=False)
        status = tk.StringVar()
        prepared_target: list[tuple[str, str]] = []
        ttk.Label(self.content, text="Tipo de escaneo", style="Body.TLabel").pack(anchor="w")
        mode_box = ttk.Combobox(
            self.content,
            textvariable=mode,
            values=("Ping sweep IPv4", "Puertos TCP de una IPv4"),
            state="readonly",
        )
        mode_box.pack(fill="x", pady=(3, 10))
        target_label = ttk.Label(self.content, text="Red a evaluar", style="Body.TLabel")
        target_label.pack(anchor="w")
        ttk.Entry(self.content, textvariable=target_value).pack(fill="x", pady=(3, 10))
        ttk.Label(self.content, text="Confirmacion de autorizacion", style="Body.TLabel").pack(anchor="w")
        ttk.Entry(self.content, textvariable=authorization).pack(fill="x", pady=(3, 10))
        ttk.Checkbutton(self.content, text="Guardar resultado en JSON y CSV", variable=export_results).pack(
            anchor="w", pady=(0, 10)
        )
        dns_control = ttk.Checkbutton(
            self.content, text="Resolver nombre DNS inverso", variable=resolve_dns
        )
        dns_control.pack(anchor="w")
        mac_control = ttk.Checkbutton(
            self.content, text="Consultar MAC en cache ARP", variable=resolve_mac
        )
        mac_control.pack(anchor="w", pady=(0, 10))
        action_frame = ttk.Frame(self.content, style="App.TFrame")
        action_frame.pack(fill="x")
        notice = ttk.Label(action_frame, text="", style="Body.TLabel", wraplength=680, justify="left")
        result = tk.Text(self.content, height=12, wrap="none", state="disabled", font=("Consolas", 10))

        def prepare() -> None:
            if authorization.get().strip() != "AUTORIZO":
                status.set("Escribe AUTORIZO para habilitar el escaneo.")
                return
            try:
                target = str(
                    validate_ipv4_network(target_value.get().strip())
                    if mode.get() == "Ping sweep IPv4"
                    else validate_ipv4(target_value.get().strip())
                )
            except ValidationError as exc:
                status.set(str(exc))
                return
            prepared_target[:] = [(mode.get(), target)]
            notice.config(
                text=(
                    f"Escaneo preparado para {target}. No comenzara hasta que confirmes "
                    "el inicio en el siguiente paso."
                )
            )
            start_button.pack(fill="x", pady=(10, 0))
            status.set("Revisa la red y confirma el inicio cuando estes listo.")

        def scan() -> None:
            if not prepared_target:
                return
            scan_type, target = prepared_target[0]
            if not messagebox.askyesno(
                "Iniciar escaneo", f"Se evaluara {target}. Confirmas que tienes autorizacion?", parent=self
            ):
                status.set("Escaneo cancelado antes de iniciar.")
                return
            status.set("Escaneando en segundo plano...")
            start_button.state(["disabled"])
            use_dns, use_mac = resolve_dns.get(), resolve_mac.get()
            self._run_worker(
                lambda: (
                    ping_sweep(
                        target,
                        policy=ScanPolicy(),
                        resolve_dns=use_dns,
                        resolve_mac=use_mac,
                    )
                    if scan_type == "Ping sweep IPv4"
                    else scan_tcp_ports(target, policy=ScanPolicy())
                ),
                lambda data: done(data, start_button, status, scan_type),
            )

        def done(data: object, button: ttk.Button, text: tk.StringVar, scan_type: str) -> None:
            button.state(["!disabled"])
            if isinstance(data, Exception):
                text.set(f"Escaneo detenido: {data}")
                return
            if scan_type == "Ping sweep IPv4":
                active = [host for host in data if host.alive]
                lines = [f"{host.ip}\t{host.hostname or ''}\t{host.mac or ''}" for host in active]
                summary = f"Escaneo terminado: {len(active)} host(s) activo(s)."
            else:
                lines = [
                    f"{item.port}/{item.service}: {item.state.value} ({item.latency_ms} ms)" for item in data
                ]
                summary = "Escaneo de puertos terminado."
            result.config(state="normal")
            result.delete("1.0", "end")
            result.insert("1.0", "\n".join(lines) or "No se detectaron resultados activos.")
            result.config(state="disabled")
            if export_results.get():
                try:
                    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    base = self.runtime / "reports" / f"scan_{stamp}"
                    export_scan_json(data, base.with_suffix(".json"))
                    export_scan_csv(data, base.with_suffix(".csv"))
                except (OSError, ValidationError) as exc:
                    summary += f" No se pudo exportar: {exc}"
            text.set(summary)

        def update_label(*_: object) -> None:
            target_label.config(text="Red a evaluar" if mode.get() == "Ping sweep IPv4" else "IPv4 objetivo")
            state = ["!disabled"] if mode.get() == "Ping sweep IPv4" else ["disabled"]
            dns_control.state(state)
            mac_control.state(state)

        mode_box.bind("<<ComboboxSelected>>", update_label)
        ttk.Button(action_frame, text="Preparar escaneo", style="Primary.TButton", command=prepare).pack(
            fill="x"
        )
        start_button = ttk.Button(action_frame, text="Iniciar escaneo ahora", command=scan)
        ttk.Label(action_frame, textvariable=status, style="Body.TLabel", wraplength=680).pack(
            anchor="w", pady=(8, 0)
        )
        notice.pack(anchor="w", pady=(12, 0))
        result.pack(fill="both", expand=True, pady=(14, 0))

    def _inventory_page(self) -> None:
        # Esta pagina tambien se vuelve a mostrar despues de guardar o eliminar
        # un perfil. Limpiarla aqui evita que se apilen dos copias de la vista.
        self._clear()
        viewport = ttk.Frame(self.content, style="App.TFrame")
        viewport.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(viewport, orient="vertical")
        canvas = tk.Canvas(viewport, background="#f6f8fb", highlightthickness=0)
        scrollbar.configure(command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        page = ttk.Frame(canvas, style="App.TFrame")
        page_window = canvas.create_window((0, 0), window=page, anchor="nw")

        def update_scroll_region(_: tk.Event[tk.Misc]) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_page(event: tk.Event[tk.Misc]) -> None:
            canvas.itemconfigure(page_window, width=event.width)

        page.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", resize_page)
        ttk.Button(
            page,
            text="←  Volver al menu principal",
            style="Back.TButton",
            command=self.show_menu,
        ).pack(anchor="w")
        ttk.Label(page, text="Equipos e inventario", style="Title.TLabel").pack(
            anchor="w", pady=(8, 4)
        )
        ttk.Label(
            page,
            text="Organiza perfiles locales, grupos, borradores y lotes sin guardar contraseñas.",
            style="Body.TLabel",
            wraplength=690,
        ).pack(anchor="w", pady=(0, 20))
        groups = (
            (
                "Perfiles de equipos",
                (
                    ("Ver equipos guardados", self._show_profiles),
                    ("Guardar nuevo perfil", self._new_profile),
                    ("Conectar usando un perfil", self._choose_profile_to_connect),
                    ("Eliminar un perfil", self._choose_profile_to_delete),
                ),
            ),
            (
                "Planificación y evidencia",
                (
                    ("Ver borradores seguros", self._show_drafts),
                    ("Ver equipos de un grupo", self._show_group),
                    ("Preparar lote gradual", self._prepare_batch),
                    ("Ver historial de lotes", self._show_batch_history),
                ),
            ),
        )
        grid = ttk.Frame(page, style="App.TFrame")
        grid.pack(fill="x", anchor="w")
        for column in range(2):
            grid.columnconfigure(column, weight=1)
        for index, (title, options) in enumerate(groups):
            card = ttk.Frame(grid, style="Card.TFrame", padding=(18, 16))
            card.grid(row=0, column=index, sticky="nsew", padx=(0, 12) if index == 0 else 0)
            ttk.Label(
                card, text=title, background="#ffffff", foreground="#102a43", font=("Segoe UI", 11, "bold")
            ).pack(anchor="w", pady=(0, 8))
            for label, action in options:
                ttk.Button(card, text=label, command=action).pack(fill="x", pady=2)
        ttk.Label(
            page,
            text=(
                "Aqui se muestran equipos y grupos cuando existan; "
                "no se inventan datos en la pantalla inicial."
            ),
            style="Body.TLabel",
            wraplength=670,
            padding=(14, 13),
        ).pack(anchor="w", pady=(16, 0))

    def _show_profiles(self, *, action: str | None = None) -> None:
        self._clear()
        title = "Equipos guardados" if not action else "Seleccionar perfil"
        self._page_header(title, "Los perfiles no contienen passwords ni enable secrets.")
        columns = ("nombre", "tipo", "plataforma", "conexion", "objetivo", "visto")
        tree = ttk.Treeview(self.content, columns=columns, show="headings", height=11)
        for column, text, width in (
            ("nombre", "Nombre", 150),
            ("tipo", "Tipo", 80),
            ("plataforma", "Plataforma", 130),
            ("conexion", "Conexion", 80),
            ("objetivo", "IPv4 o puerto", 170),
            ("visto", "Ultima conexion", 180),
        ):
            tree.heading(column, text=text)
            tree.column(column, width=width, anchor="w")
        tree.pack(fill="both", expand=True)

        for profile in self.inventory.list_profiles():
            target = profile.host if profile.transport == "ssh" else profile.serial_port
            tree.insert(
                "",
                "end",
                iid=profile.id,
                values=(
                    profile.name,
                    profile.device_kind.value,
                    profile.platform.value,
                    profile.transport.upper(),
                    target,
                    profile.last_seen_at or "Sin conexion",
                ),
            )

        def use() -> None:
            selected = tree.selection()
            if not selected:
                messagebox.showinfo("Inventario", "Selecciona un perfil.", parent=self)
                return
            profile = next(item for item in self.inventory.list_profiles() if item.id == selected[0])
            if action == "connect":
                self.pending_profile = profile
                self.show_page("connect")
            elif action == "delete" and messagebox.askyesno(
                "Eliminar perfil", f"Eliminar {profile.name}?", parent=self
            ):
                self.inventory.remove(selected[0])
                self._inventory_page()

        if action:
            label = "Usar este perfil" if action == "connect" else "Eliminar perfil seleccionado"
            ttk.Button(self.content, text=label, style="Primary.TButton", command=use).pack(
                anchor="w", pady=(12, 0)
            )

    def _new_profile(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Guardar nuevo perfil")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(padx=18, pady=18)
        name, mode, device, platform = (
            tk.StringVar(),
            tk.StringVar(value="ssh"),
            tk.StringVar(value="router"),
            tk.StringVar(value=NetworkPlatform.UNKNOWN.value),
        )
        target, speed, user, groups = (
            tk.StringVar(),
            tk.StringVar(value="9600"),
            tk.StringVar(),
            tk.StringVar(),
        )
        fields = (
            ("Nombre", name),
            ("Conexion (ssh o serial)", mode),
            ("Equipo (router o switch)", device),
            ("Plataforma (o unknown para detectar por SSH)", platform),
            ("IPv4 o puerto COM", target),
            ("Baudrate para serial", speed),
            ("Usuario SSH", user),
            ("Grupos (separados por coma)", groups),
        )
        for index, (label, variable) in enumerate(fields):
            ttk.Label(dialog, text=label).grid(row=index, column=0, sticky="w", pady=3)
            ttk.Entry(dialog, textvariable=variable).grid(row=index, column=1, sticky="ew", pady=3)

        def save() -> None:
            try:
                kind = DeviceKind(device.get().strip().lower())
                selected_platform = NetworkPlatform(platform.get().strip().lower())
                profile = (
                    ConnectionProfile.create_ssh(name.get(), target.get(), user.get(), kind)
                    if mode.get().strip().lower() == "ssh"
                    else ConnectionProfile.create_serial(name.get(), target.get(), int(speed.get()), kind)
                )
                if profile.transport == "serial" and not selected_platform.is_cisco:
                    raise ValidationError(
                        "Los perfiles seriales solo estan certificados para Cisco por ahora."
                    )
                profile = replace(profile, platform=selected_platform)
                self.inventory.add(profile.with_groups(groups.get()))
            except (ValueError, ValidationError) as exc:
                messagebox.showwarning("Perfil no guardado", str(exc), parent=dialog)
                return
            dialog.destroy()
            self._inventory_page()

        ttk.Button(dialog, text="Guardar perfil", style="Primary.TButton", command=save).grid(
            row=len(fields), column=0, columnspan=2, sticky="ew", pady=(10, 0)
        )
        dialog.columnconfigure(1, weight=1)

    def _choose_profile_to_connect(self) -> None:
        self._show_profiles(action="connect")

    def _choose_profile_to_delete(self) -> None:
        self._show_profiles(action="delete")

    def _show_drafts(self) -> None:
        self._show_records(
            "Borradores seguros",
            [
                f"{item.name} | {item.service} | {item.created_at}"
                for item in DraftStore(self.runtime / "drafts.json").list_drafts()
            ],
            "Aun no hay borradores seguros.",
        )

    def _show_group(self) -> None:
        group = simpledialog.askstring("Grupo", "Nombre del grupo:", parent=self)
        if not group:
            return
        profiles = self.inventory.profiles_in_group(group)
        self._show_records(
            f"Grupo: {group}",
            [f"{item.name} | {item.device_kind.value}" for item in profiles],
            "No hay equipos en este grupo.",
        )

    def _prepare_batch(self) -> None:
        group = simpledialog.askstring("Preparar lote", "Grupo de equipos:", parent=self)
        if not group:
            return
        profiles = tuple(self.inventory.profiles_in_group(group))
        if not profiles:
            messagebox.showinfo("Lote gradual", "No hay equipos en ese grupo.", parent=self)
            return
        concurrent = simpledialog.askinteger(
            "Lote gradual",
            f"Equipos maximos a la vez (1 a {len(profiles)}):",
            initialvalue=1,
            minvalue=1,
            maxvalue=len(profiles),
            parent=self,
        )
        if concurrent is None:
            return
        initial = simpledialog.askinteger(
            "Lote gradual",
            f"Equipos de prueba inicial (1 a {len(profiles)}):",
            initialvalue=1,
            minvalue=1,
            maxvalue=len(profiles),
            parent=self,
        )
        if initial is None:
            return
        try:
            preview = BatchPreview(group, profiles, concurrent, initial)
        except ValueError as exc:
            messagebox.showwarning("Lote gradual", str(exc), parent=self)
            return
        self._show_records(
            "Lote preparado, sin ejecutar",
            [
                f"Grupo: {preview.group}",
                f"Equipos: {len(preview.profiles)} | Maximo simultaneo: {preview.max_concurrent}",
                f"Primer paso: {', '.join(item.name for item in preview.first_stage)}",
                f"Despues: {', '.join(item.name for item in preview.remaining) or 'No aplica'}",
                "El lote se pausaria ante un fallo cuando se habilite su ejecucion.",
            ],
            "",
        )

    def _show_batch_history(self) -> None:
        records = BatchHistoryStore(self.runtime / "batch_history.json").list()
        self._show_records(
            "Historial de lotes",
            [f"{item['timestamp']} | {item['group']} | pausado: {item['paused']}" for item in records],
            "Aun no hay lotes ejecutados.",
        )

    def _show_records(self, title: str, lines: list[str], empty: str) -> None:
        self._clear()
        self._page_header(title, "Evidencia local generada por SarevatApp.")
        if not lines:
            ttk.Label(self.content, text=empty, style="Body.TLabel", wraplength=680).pack(anchor="w")
            return
        records = ttk.Frame(self.content, style="App.TFrame")
        records.pack(fill="x")
        for line in lines:
            card = ttk.Frame(records, style="Card.TFrame", padding=(14, 11))
            card.pack(fill="x", pady=3)
            ttk.Label(
                card, text=line, background="#ffffff", foreground="#526777", justify="left", wraplength=740
            ).pack(anchor="w")

    def _run_worker(self, work: Callable[[], object], finish: Callable[[object], None]) -> None:
        def target() -> None:
            try:
                value: object = work()
            except Exception as exc:  # La interfaz muestra el error sin detener la ventana.
                value = exc
            self.after(0, lambda: finish(value))

        threading.Thread(target=target, daemon=True).start()

    def _run_session_worker(self, work: Callable[[], object], finish: Callable[[object], None]) -> None:
        """Serializa comandos de una misma sesión Netmiko para evitar cruces de comandos."""
        future = self._session_tasks.submit(work)

        def deliver(done: Any) -> None:
            try:
                result: object = done.result()
            except Exception as exc:
                result = exc
            self.after(0, lambda: finish(result))

        future.add_done_callback(deliver)


def main() -> int:
    app = SarevatGui()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
