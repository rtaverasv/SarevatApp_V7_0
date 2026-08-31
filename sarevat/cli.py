"""Interfaz CLI de SarevatApp 7.0."""

from __future__ import annotations

import getpass
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from colorama import Fore, Style, init
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from sarevat import __version__
from sarevat.backup_crypto import BackupCipher
from sarevat.baselines import BaselineStore, ConfigurationBaseline, compare_with_baseline
from sarevat.batches import BatchPreview
from sarevat.cisco.discovery import discover_device
from sarevat.cisco.executor import CiscoExecutor
from sarevat.cisco.services import (
    SERVICE_CATALOG,
    build_aaa_local_plan,
    build_basic_hardening_plan,
    build_initial_setup_plan,
    build_interface_ip_plan,
    build_service_plan,
    build_site_observability_plan,
    build_snmpv3_plan,
    service_is_configured,
)
from sarevat.compliance import ComplianceStatus, audit_running_config, export_compliance_json
from sarevat.drafts import DraftStore, PlanDraft, configuration_diff
from sarevat.inventory import ConnectionProfile, InventoryStore
from sarevat.logging_utils import AuditLogger
from sarevat.models import CommandPlan, DeviceFacts, DeviceKind, ExecutionReport
from sarevat.reporting import export_execution_report_csv, export_execution_report_json
from sarevat.scanner import (
    PortState,
    ScanPolicy,
    export_scan_csv,
    export_scan_json,
    ping_sweep,
    scan_tcp_ports,
)
from sarevat.security import dangerous_reasons, find_ios_errors, redact_text
from sarevat.validators import ValidationError, validate_ipv4, validate_ipv4_network
from sarevat.vlsm import (
    SubnetRequest,
    automatic_gateway_policy,
    calculate_vlsm,
    export_plan_csv,
    export_plan_json,
)


@dataclass(frozen=True, slots=True)
class AppPaths:
    root: Path
    logs: Path
    backups: Path
    reports: Path

    @classmethod
    def create(cls, root: Path) -> AppPaths:
        resolved = root.resolve()
        paths = cls(resolved, resolved / "logs", resolved / "backups", resolved / "reports")
        for path in (paths.logs, paths.backups, paths.reports):
            path.mkdir(parents=True, exist_ok=True)
        return paths


def _confirm(message: str, keyword: str = "CONFIRMAR") -> bool:
    print(Fore.RED + Style.BRIGHT + f"\nADVERTENCIA: {message}")
    return input(Fore.RED + f"Escribe {keyword} para continuar: ").strip() == keyword


def _yes(message: str) -> bool:
    return input(Fore.CYAN + f"{message} (si/no): ").strip().lower() in {"si", "s"}


def _print_report(report: ExecutionReport) -> None:
    color = Fore.GREEN if report.success else Fore.YELLOW
    print(color + Style.BRIGHT + f"\nEstado: {report.status.value}")
    print(color + report.message)
    if report.backup_path:
        print(Fore.BLUE + f"Respaldo local redactado: {report.backup_path}")
    if report.checkpoint:
        print(Fore.BLUE + f"Checkpoint en equipo: flash:{report.checkpoint}")
    for result in report.results:
        if result.errors:
            print(Fore.RED + "Errores IOS: " + "; ".join(result.errors))


def _preview_plan(plan: CommandPlan) -> None:
    print(Fore.MAGENTA + Style.BRIGHT + f"\n=== {plan.name} ===")
    for warning in plan.warnings:
        print(Fore.YELLOW + f"AVISO: {warning}")
    from sarevat.security import redact_command

    for command in plan.commands:
        print(Fore.WHITE + "  " + redact_command(command))


def _execute_interactive(
    executor: CiscoExecutor,
    plan: CommandPlan,
    draft_store: DraftStore | None = None,
    reports_directory: Path | None = None,
) -> None:
    if draft_store:
        try:
            draft_store.add_plan(plan)
            print(Fore.BLUE + "Vista segura del plan guardada en borradores.")
        except (OSError, ValueError) as exc:
            print(Fore.YELLOW + f"No se pudo guardar el borrador: {exc}")
    _preview_plan(plan)
    dry_report = executor.execute(plan, dry_run=True)
    _print_report(dry_report)
    _save_execution_reports(dry_report, reports_directory)
    if not _yes("¿Aplicar realmente este plan?"):
        return
    if isinstance(executor, CiscoExecutor) and executor.backup_cipher is None:
        try:
            passphrase = getpass.getpass("Frase para cifrar respaldos (minimo 12 caracteres): ")
            executor.backup_cipher = BackupCipher(passphrase)
        except ValueError as exc:
            print(Fore.YELLOW + f"Aplicacion cancelada: {exc}")
            return
    report = executor.execute(
        plan,
        dry_run=False,
        confirm=_confirm,
        create_checkpoint=True,
        rollback_on_error=True,
    )
    _print_report(report)
    _save_execution_reports(report, reports_directory)


def _save_execution_reports(report: ExecutionReport, reports_directory: Path | None) -> None:
    if not reports_directory:
        return
    safe_name = "".join(character if character.isalnum() else "_" for character in report.plan_name)[:50]
    stamp = report.started_at.strftime("%Y%m%d_%H%M%S")
    base = reports_directory / f"ejecucion_{safe_name}_{stamp}_{report.status.value}"
    try:
        json_path = export_execution_report_json(report, base.with_suffix(".json"))
        csv_path = export_execution_report_csv(report, base.with_suffix(".csv"))
        print(Fore.BLUE + f"Reporte guardado: {json_path.name} y {csv_path.name}")
    except OSError as exc:
        print(Fore.YELLOW + f"No se pudo guardar el reporte: {exc}")


def _execute_with_draft(
    executor: CiscoExecutor,
    plan: CommandPlan,
    draft_store: DraftStore | None,
    reports_directory: Path | None = None,
) -> None:
    if draft_store or reports_directory:
        _execute_interactive(executor, plan, draft_store, reports_directory)
    else:
        _execute_interactive(executor, plan)


def _collect_service_data(service: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key, kind, label in SERVICE_CATALOG[service].fields:
        suffix = {
            "ipv4": " [IPv4]",
            "network": " [CIDR IPv4]",
            "wildcard": " [wildcard]",
            "netmask": " [mascara]",
            "interfaces": " [separadas por coma]",
        }.get(kind, "")
        if kind == "secret":
            suffix = " [entrada oculta]"
            data[key] = getpass.getpass(f"{label}{suffix}: ")
        else:
            data[key] = input(Fore.CYAN + f"{label}{suffix}: ").strip()
    return data


def _service_menu(
    executor: CiscoExecutor,
    facts: DeviceFacts,
    device_kind: DeviceKind,
    draft_store: DraftStore | None = None,
    reports_directory: Path | None = None,
) -> None:
    available = [(key, spec) for key, spec in SERVICE_CATALOG.items() if device_kind in spec.devices]
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n=== Protocolos y servicios ===")
        for index, (_, spec) in enumerate(available, 1):
            requirement = " [requiere L3 up/up]" if spec.requires_l3 else ""
            print(f"  {index}) {spec.name}{requirement}")
        print("  0) Volver")
        selection = input("> ").strip()
        if selection == "0":
            return
        try:
            service = available[int(selection) - 1][0]
        except (ValueError, IndexError):
            print(Fore.YELLOW + "Seleccion invalida.")
            continue
        try:
            spec = SERVICE_CATALOG[service]
            if spec.depends_on:
                missing = [item for item in spec.depends_on if not service_is_configured(item, facts)]
                for dependency in missing:
                    print(Fore.YELLOW + f"Se preparara primero la dependencia: {dependency}")
                    dependency_plan = build_service_plan(
                        dependency,
                        _collect_service_data(dependency),
                        facts,
                        device_kind,
                    )
                    _execute_with_draft(executor, dependency_plan, draft_store, reports_directory)
                    facts = discover_device(executor.connection)
                    if not service_is_configured(dependency, facts):
                        print(Fore.YELLOW + "La dependencia no quedo confirmada; servicio cancelado.")
                        break
                else:
                    plan = build_service_plan(
                        service,
                        _collect_service_data(service),
                        facts,
                        device_kind,
                    )
                    _execute_with_draft(executor, plan, draft_store, reports_directory)
                    facts = discover_device(executor.connection)
                continue
            plan = build_service_plan(service, _collect_service_data(service), facts, device_kind)
            _execute_with_draft(executor, plan, draft_store, reports_directory)
            facts = discover_device(executor.connection)
        except ValidationError as exc:
            print(Fore.YELLOW + f"Datos invalidos: {exc}")
        except Exception as exc:
            print(Fore.RED + f"No se pudo preparar o ejecutar el plan: {redact_text(str(exc))}")


def _show_facts(facts: DeviceFacts) -> None:
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Estado descubierto ===")
    print(f"Hostname: {facts.hostname}")
    print(f"Modelo: {facts.model}")
    print(f"Version: {facts.version}")
    print(f"Serial: {facts.serial}")
    print(f"Capacidades: {', '.join(sorted(facts.capabilities)) or '(sin confirmar)'}")
    print(f"Interfaces L3 up/up: {', '.join(sorted(facts.active_l3_interfaces)) or '(ninguna)'}")
    print(f"Trunks: {', '.join(sorted(facts.trunks)) or '(ninguno)'}")
    if facts.warnings:
        print(Fore.YELLOW + "Consultas no disponibles:")
        for warning in facts.warnings:
            print(Fore.YELLOW + f"  - {warning}")


def _free_console(connection: Any, audit: AuditLogger) -> None:
    print(Fore.BLUE + "Consola libre. 'salir' regresa; no usa send_config_set.")
    while True:
        command = input(Fore.CYAN + f"{connection.find_prompt()} ").strip()
        if command.lower() in {"salir", "exit", "quit"}:
            return
        if not command:
            continue
        reasons = dangerous_reasons(command)
        if reasons and not _confirm("; ".join(reasons)):
            audit.event("free_command_cancelled", command=command, reasons=reasons)
            continue
        output = str(connection.send_command_timing(command, read_timeout=30))
        errors = find_ios_errors(output)
        print(output)
        audit.event("free_command", command=command, output=output, errors=errors)
        if errors:
            print(Fore.RED + "IOS rechazo o cuestiono el comando.")


def _device_vlsm(
    executor: CiscoExecutor,
    facts: DeviceFacts,
    draft_store: DraftStore | None = None,
    reports_directory: Path | None = None,
) -> None:
    base = str(validate_ipv4_network(input(Fore.CYAN + "Introducir Red Base: ").strip()))
    if not _yes("¿Trabajar con subredes?"):
        _show_network_calculation(base)
        return
    count = int(input("Cantidad de subredes: ").strip())
    if count < 1:
        raise ValidationError("Indica al menos una subred.")
    requests: list[SubnetRequest] = []
    print("Indica cada interfaz y hosts. Gateway y loopback se calculan automaticamente.")
    while len(requests) < count:
        interface = input(Fore.CYAN + "Interfaz: ").strip()
        hosts = int(input("Hosts: ").strip())
        kind = input("Tipo [lan/point_to_point/loopback] (lan): ").strip() or "lan"
        candidate = SubnetRequest(interface, hosts, kind=kind, gateway_policy=automatic_gateway_policy(kind))
        try:
            calculate_vlsm(base, [*requests, candidate])
        except ValidationError as exc:
            print(Fore.YELLOW + f"Corrige esta subred antes de continuar: {exc}")
            continue
        requests.append(candidate)
    plan = calculate_vlsm(base, requests)
    for allocation in plan.allocations:
        interface_plan = build_interface_ip_plan(
            allocation.name,
            allocation.first_usable,
            allocation.netmask,
            facts,
        )
        _execute_with_draft(executor, interface_plan, draft_store, reports_directory)


def _compare_configuration_file(facts: DeviceFacts) -> None:
    if not facts.running_config:
        print(Fore.YELLOW + "No hay configuracion actual disponible para comparar.")
        return
    raw_path = input("Archivo de configuracion propuesta: ").strip()
    if not raw_path:
        return
    try:
        proposed = Path(raw_path).read_text(encoding="utf-8")
    except OSError as exc:
        print(Fore.YELLOW + f"No se pudo leer el archivo: {exc}")
        return
    diff = configuration_diff(facts.running_config, proposed)
    if not diff:
        print(Fore.GREEN + "No se detectaron diferencias.")
        return
    lines = diff.splitlines()
    visible_lines = lines[:120]
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Diferencias de configuracion ===")
    for line in visible_lines:
        color = Fore.GREEN if line.startswith("+") else Fore.RED if line.startswith("-") else Fore.WHITE
        print(color + line)
    if len(lines) > len(visible_lines):
        print(Fore.YELLOW + f"Se muestran 120 de {len(lines)} lineas para mantener la vista clara.")


def _run_compliance_audit(facts: DeviceFacts, reports_directory: Path) -> None:
    if not facts.running_config:
        print(Fore.YELLOW + "No hay configuracion disponible para la revision.")
        return
    findings = audit_running_config(facts.running_config)
    warnings = [item for item in findings if item.status is ComplianceStatus.WARNING]
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Revision de seguridad (solo lectura) ===")
    for item in findings:
        if item.status is ComplianceStatus.COMPLIANT:
            print(Fore.GREEN + f"OK: {item.title}")
        else:
            print(Fore.YELLOW + f"PENDIENTE: {item.title}")
            print(Fore.YELLOW + f"  {item.recommendation}")
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    try:
        path = export_compliance_json(findings, reports_directory / f"cumplimiento_{stamp}.json")
        print(Fore.BLUE + f"Reporte de revision: {path.name}")
    except OSError as exc:
        print(Fore.YELLOW + f"No se pudo guardar el reporte: {exc}")
    if warnings:
        print(Fore.YELLOW + f"Resultado: {len(warnings)} controles pendientes.")
    else:
        print(Fore.GREEN + "Resultado: controles revisados sin pendientes detectados.")


def _apply_observability_template(
    executor: CiscoExecutor,
    draft_store: DraftStore,
    reports_directory: Path,
) -> None:
    try:
        role = input("Sitio [sucursal/nucleo] (sucursal): ").strip() or "sucursal"
        ntp_server = input("Servidor NTP IPv4: ").strip()
        syslog_server = input("Servidor syslog IPv4: ").strip()
        plan = build_site_observability_plan(role, ntp_server, syslog_server)
        _execute_with_draft(executor, plan, draft_store, reports_directory)
    except ValidationError as exc:
        print(Fore.YELLOW + f"Plantilla cancelada: {exc}")


def _apply_snmpv3_template(
    executor: CiscoExecutor,
    draft_store: DraftStore,
    reports_directory: Path,
) -> None:
    """Solicita SNMPv3 sin mostrar ni conservar sus claves."""
    print(Fore.YELLOW + "SNMPv3 se agregara sin eliminar comunidades ni usuarios existentes.")
    try:
        group = input("Grupo SNMPv3: ").strip()
        username = input("Usuario SNMPv3: ").strip()
        auth_password = getpass.getpass("Clave de autenticacion SNMPv3: ")
        privacy_password = getpass.getpass("Clave de privacidad SNMPv3: ")
        plan = build_snmpv3_plan(group, username, auth_password, privacy_password)
        _execute_with_draft(executor, plan, draft_store, reports_directory)
    except ValidationError as exc:
        print(Fore.YELLOW + f"SNMPv3 cancelado: {exc}")


def _apply_aaa_local_template(
    executor: CiscoExecutor,
    facts: DeviceFacts,
    draft_store: DraftStore,
    reports_directory: Path,
) -> None:
    """Prepara AAA local solo cuando el operador confirma una via de recuperacion."""
    print(Fore.RED + Style.BRIGHT + "AAA puede bloquear el acceso remoto si se configura mal.")
    username = input("Usuario local existente para AAA: ").strip()
    console_ready = (
        input("Consola local conectada y probada. Escribe CONSOLA_LISTA para continuar: ").strip()
        == "CONSOLA_LISTA"
    )
    try:
        plan = build_aaa_local_plan(username, facts, console_ready)
        _execute_with_draft(executor, plan, draft_store, reports_directory)
    except ValidationError as exc:
        print(Fore.YELLOW + f"AAA cancelado: {exc}")


def _save_configuration_baseline(facts: DeviceFacts, paths: AppPaths) -> None:
    store = BaselineStore(paths.root / "referencia_configuracion.json")
    if store.exists() and not _confirm("Reemplazar la referencia local anterior"):
        return
    try:
        baseline = ConfigurationBaseline.from_config(facts.hostname, facts.running_config)
        store.save(baseline)
        print(Fore.GREEN + "Referencia segura guardada. No contiene secretos visibles.")
    except (OSError, ValueError) as exc:
        print(Fore.YELLOW + f"No se pudo guardar la referencia: {exc}")


def _show_configuration_drift(facts: DeviceFacts, paths: AppPaths) -> None:
    store = BaselineStore(paths.root / "referencia_configuracion.json")
    try:
        baseline = store.load()
        diff = compare_with_baseline(baseline, facts.running_config)
    except ValueError as exc:
        print(Fore.YELLOW + f"No se pudo comparar: {exc}")
        return
    if not diff:
        print(Fore.GREEN + "No hay cambios frente a la referencia guardada.")
        return
    lines = diff.splitlines()
    print(Fore.MAGENTA + Style.BRIGHT + f"\n=== Cambios desde {baseline.hostname} ===")
    for line in lines[:120]:
        print(line)
    if len(lines) > 120:
        print(Fore.YELLOW + f"Se muestran 120 de {len(lines)} líneas para mantener la vista clara.")


def _apply_basic_hardening(
    executor: CiscoExecutor,
    facts: DeviceFacts,
    draft_store: DraftStore,
    reports_directory: Path,
) -> None:
    try:
        plan = build_basic_hardening_plan(facts)
        _execute_with_draft(executor, plan, draft_store, reports_directory)
    except ValidationError as exc:
        print(Fore.YELLOW + f"Endurecimiento cancelado: {exc}")


def _device_session(
    connection: Any,
    device_kind: DeviceKind,
    paths: AppPaths,
    audit: AuditLogger,
    facts: DeviceFacts | None = None,
) -> None:
    executor = CiscoExecutor(connection, audit=audit, backup_directory=paths.backups)
    draft_store = DraftStore(paths.root / "drafts.json")
    facts = facts or discover_device(connection)
    audit.event("device_discovered", hostname=facts.hostname, model=facts.model, version=facts.version)
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + f"\n=== {facts.hostname} ===")
        print("  1) Ver estado e inventario")
        print("  2) Protocolos y servicios")
        print("  3) VLSM y configurar interfaces")
        print("  4) Consola libre")
        print("  5) Configuracion inicial segura")
        print("  6) Guardar configuracion (write memory)")
        print("  7) Comparar configuracion con un archivo")
        print("  8) Revision de seguridad (solo lectura)")
        print("  9) Plantilla NTP y syslog")
        print(" 10) SNMPv3 seguro (no elimina configuracion existente)")
        print(" 11) AAA local con recuperacion por consola")
        print(" 12) Guardar referencia segura de configuracion")
        print(" 13) Ver cambios desde la referencia")
        print(" 14) Endurecimiento basico seguro")
        print("  0) Desconectar")
        choice = input("> ").strip()
        if choice == "0":
            return
        if choice == "1":
            facts = discover_device(connection)
            _show_facts(facts)
        elif choice == "2":
            _service_menu(executor, facts, device_kind, draft_store, paths.reports)
            facts = discover_device(connection)
        elif choice == "3":
            try:
                _device_vlsm(executor, facts, draft_store, paths.reports)
            except (ValidationError, ValueError) as exc:
                print(Fore.YELLOW + f"VLSM cancelado: {exc}")
        elif choice == "4":
            _free_console(connection, audit)
        elif choice == "5":
            data = {
                "hostname": input("Hostname: ").strip(),
                "domain": input("Dominio: ").strip(),
                "username": input("Usuario administrador: ").strip(),
                "password": getpass.getpass("Password: "),
                "rsa_bits": input("RSA [2048/3072/4096]: ").strip(),
            }
            try:
                _execute_with_draft(executor, build_initial_setup_plan(data), draft_store, paths.reports)
            except ValidationError as exc:
                print(Fore.YELLOW + str(exc))
        elif choice == "6":
            if _confirm("Guardar running-config en startup-config"):
                output = str(connection.send_command_timing("write memory", read_timeout=30))
                print(output)
                audit.event("write_memory", output=output, errors=find_ios_errors(output))
        elif choice == "7":
            _compare_configuration_file(facts)
        elif choice == "8":
            _run_compliance_audit(facts, paths.reports)
        elif choice == "9":
            _apply_observability_template(executor, draft_store, paths.reports)
        elif choice == "10":
            _apply_snmpv3_template(executor, draft_store, paths.reports)
        elif choice == "11":
            _apply_aaa_local_template(executor, facts, draft_store, paths.reports)
        elif choice == "12":
            _save_configuration_baseline(facts, paths)
        elif choice == "13":
            _show_configuration_drift(facts, paths)
        elif choice == "14":
            _apply_basic_hardening(executor, facts, draft_store, paths.reports)
        else:
            print(Fore.YELLOW + "Opcion invalida.")


def _connect(
    paths: AppPaths,
    audit: AuditLogger,
    profile: ConnectionProfile | None = None,
    inventory: InventoryStore | None = None,
) -> None:
    try:
        if profile:
            kind = profile.device_kind
            mode = "1" if profile.transport == "ssh" else "2"
            if profile.transport == "ssh":
                username = profile.username or input("Usuario: ").strip()
                params = {
                    "device_type": "cisco_ios",
                    "host": profile.host,
                    "username": username,
                    "password": getpass.getpass("Password: "),
                    "secret": getpass.getpass("Enable secret (Enter si no aplica): "),
                }
            else:
                params = {
                    "device_type": "cisco_ios_serial",
                    "serial_settings": {"port": profile.serial_port, "baudrate": profile.baudrate},
                }
        else:
            print("  1) SSH")
            print("  2) Consola serial")
            mode = input("> ").strip()
            kind_text = input("Equipo [router/switch]: ").strip().lower()
            if kind_text not in {"router", "switch"}:
                print(Fore.YELLOW + "Tipo de equipo invalido.")
                return
            kind = DeviceKind(kind_text)
            if mode == "1":
                host = str(validate_ipv4(input("IPv4 del equipo: ").strip()))
                params = {
                    "device_type": "cisco_ios",
                    "host": host,
                    "username": input("Usuario: ").strip(),
                    "password": getpass.getpass("Password: "),
                    "secret": getpass.getpass("Enable secret (Enter si no aplica): "),
                }
            elif mode == "2":
                port = input("Puerto [COM3]: ").strip()
                baudrate = int(input("Baudrate [9600]: ").strip() or "9600")
                if baudrate <= 0:
                    raise ValueError("El baudrate debe ser positivo.")
                params = {
                    "device_type": "cisco_ios_serial",
                    "serial_settings": {"port": port, "baudrate": baudrate},
                }
            else:
                print(Fore.YELLOW + "Modo invalido.")
                return
    except (ValidationError, ValueError) as exc:
        print(Fore.YELLOW + f"Parametros de conexion invalidos: {exc}")
        audit.event("connection_failed", reason=f"parametros invalidos: {exc}")
        return
    try:
        audit.event("connection_attempt", mode=mode, target=params.get("host", params.get("serial_settings")))
        with ConnectHandler(**params) as connection:
            if params.get("secret") and not connection.check_enable_mode():
                connection.enable()
            facts = discover_device(connection)
            if profile and inventory:
                inventory.update_discovery(profile.id, facts)
            _device_session(connection, kind, paths, audit, facts)
    except NetmikoAuthenticationException:
        print(Fore.RED + "Autenticacion rechazada.")
        audit.event("connection_failed", reason="authentication")
    except NetmikoTimeoutException:
        print(Fore.RED + "Timeout de conexion.")
        audit.event("connection_failed", reason="timeout")
    except (OSError, ValueError) as exc:
        print(Fore.RED + f"No se pudo conectar: {redact_text(str(exc))}")
        audit.event("connection_failed", reason=str(exc))


def _show_profiles(profiles: list[ConnectionProfile]) -> None:
    if not profiles:
        print(Fore.YELLOW + "Aun no hay perfiles guardados.")
        return
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Inventario guardado ===")
    for index, profile in enumerate(profiles, 1):
        target = profile.host if profile.transport == "ssh" else profile.serial_port
        seen = profile.last_seen_at or "sin conexión registrada"
        print(
            f"  {index}) {profile.name} | {profile.device_kind.value} | "
            f"{profile.transport.upper()} {target} | visto: {seen}"
        )


def _select_profile(store: InventoryStore) -> ConnectionProfile | None:
    profiles = store.list_profiles()
    _show_profiles(profiles)
    if not profiles:
        return None
    try:
        selection = int(input("Perfil (0 para volver): ").strip())
    except ValueError:
        print(Fore.YELLOW + "Seleccion invalida.")
        return None
    if selection == 0:
        return None
    if not 1 <= selection <= len(profiles):
        print(Fore.YELLOW + "Seleccion invalida.")
        return None
    return profiles[selection - 1]


def _create_profile(store: InventoryStore) -> None:
    try:
        name = input("Nombre del perfil: ").strip()
        transport = input("Conexion [1 SSH / 2 serial]: ").strip()
        kind_text = input("Equipo [router/switch]: ").strip().lower()
        if kind_text not in {"router", "switch"}:
            raise ValueError("Tipo de equipo invalido.")
        kind = DeviceKind(kind_text)
        if transport == "1":
            host = str(validate_ipv4(input("IPv4 del equipo: ").strip()))
            username = input("Usuario habitual (opcional): ").strip()
            profile = ConnectionProfile.create_ssh(name, host, username, kind)
        elif transport == "2":
            port = input("Puerto [COM3]: ").strip()
            baudrate = int(input("Baudrate [9600]: ").strip() or "9600")
            profile = ConnectionProfile.create_serial(name, port, baudrate, kind)
        else:
            raise ValueError("Modo de conexion invalido.")
        groups = input("Grupos separados por coma (opcional): ").strip()
        if groups:
            profile = profile.with_groups(groups)
        store.add(profile)
        print(Fore.GREEN + "Perfil guardado. Las contraseñas nunca se almacenan.")
    except (ValidationError, ValueError) as exc:
        print(Fore.YELLOW + f"No se pudo guardar el perfil: {exc}")


def _show_drafts(drafts: list[PlanDraft]) -> None:
    if not drafts:
        print(Fore.YELLOW + "Aun no hay borradores guardados.")
        return
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Borradores seguros ===")
    for index, draft in enumerate(drafts, 1):
        print(f"  {index}) {draft.name} | {draft.service} | {draft.created_at}")


def _select_draft(store: DraftStore) -> PlanDraft | None:
    drafts = store.list_drafts()
    _show_drafts(drafts)
    if not drafts:
        return None
    try:
        selection = int(input("Borrador (0 para volver): ").strip())
    except ValueError:
        print(Fore.YELLOW + "Seleccion invalida.")
        return None
    if not 1 <= selection <= len(drafts):
        return None
    return drafts[selection - 1]


def _draft_menu(paths: AppPaths) -> None:
    store = DraftStore(paths.root / "drafts.json")
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n=== Borradores seguros ===")
        print("  1) Ver borradores")
        print("  2) Ver comandos de un borrador")
        print("  3) Eliminar un borrador")
        print("  0) Volver")
        choice = input("> ").strip()
        try:
            if choice == "0":
                return
            if choice == "1":
                _show_drafts(store.list_drafts())
            elif choice == "2":
                draft = _select_draft(store)
                if draft:
                    print(Fore.BLUE + f"\n=== {draft.name} ===")
                    for command in draft.commands:
                        print(f"  {command}")
            elif choice == "3":
                draft = _select_draft(store)
                if draft and store.remove(draft.id):
                    print(Fore.GREEN + "Borrador eliminado.")
            else:
                print(Fore.YELLOW + "Opcion invalida.")
        except ValueError as exc:
            print(Fore.YELLOW + f"Borradores no disponibles: {exc}")


def _inventory_menu(paths: AppPaths, audit: AuditLogger) -> None:
    store = InventoryStore(paths.root / "inventory.json")
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n=== Inventario y perfiles ===")
        print("  1) Ver equipos guardados")
        print("  2) Guardar nuevo perfil")
        print("  3) Conectar usando un perfil")
        print("  4) Eliminar un perfil")
        print("  5) Ver borradores seguros")
        print("  6) Ver equipos de un grupo")
        print("  7) Preparar lote gradual por grupo (sin ejecutar)")
        print("  0) Volver")
        choice = input("> ").strip()
        try:
            if choice == "0":
                return
            if choice == "1":
                _show_profiles(store.list_profiles())
            elif choice == "2":
                _create_profile(store)
            elif choice == "3":
                profile = _select_profile(store)
                if profile:
                    _connect(paths, audit, profile=profile, inventory=store)
            elif choice == "4":
                profile = _select_profile(store)
                if profile and store.remove(profile.id):
                    print(Fore.GREEN + "Perfil eliminado.")
            elif choice == "5":
                _draft_menu(paths)
            elif choice == "6":
                group = input("Grupo: ").strip()
                matches = store.profiles_in_group(group)
                if matches:
                    _show_profiles(matches)
                else:
                    print(Fore.YELLOW + "No hay equipos en ese grupo.")
            elif choice == "7":
                group = input("Grupo: ").strip()
                profiles = tuple(store.profiles_in_group(group))
                concurrent = int(input("Equipos maximos a la vez [1]: ").strip() or "1")
                initial = int(input("Equipos de prueba inicial [1]: ").strip() or "1")
                preview = BatchPreview(group, profiles, concurrent, initial)
                print(Fore.MAGENTA + Style.BRIGHT + "\n=== Lote preparado, sin ejecutar ===")
                print(f"Grupo: {preview.group} | equipos: {len(preview.profiles)}")
                print(f"Primer paso: {', '.join(item.name for item in preview.first_stage)}")
                if preview.remaining:
                    print(f"Despues: {', '.join(item.name for item in preview.remaining)}")
                print(Fore.YELLOW + "El lote se pausara ante un fallo cuando se habilite su ejecucion.")
            else:
                print(Fore.YELLOW + "Opcion invalida.")
        except ValueError as exc:
            print(Fore.YELLOW + f"Inventario no disponible: {exc}")


def _standalone_vlsm(paths: AppPaths) -> None:
    try:
        base = str(validate_ipv4_network(input("Introducir Red Base: ").strip()))
        if not _yes("¿Trabajar con subredes?"):
            _show_network_calculation(base)
            return
        reserved_text = input("Excluir IP separadas por coma (opcional): ").strip()
        reserved = tuple(item.strip() for item in reserved_text.split(",") if item.strip())
        count = int(input("Cantidad de subredes: ").strip())
        if count < 1:
            raise ValidationError("Indica al menos una subred.")
        requests: list[SubnetRequest] = []
        while len(requests) < count:
            name = input(f"Nombre de subred {len(requests) + 1}: ").strip()
            hosts = int(input("Hosts: ").strip())
            kind = input("Tipo [lan/point_to_point/loopback] (lan): ").strip() or "lan"
            candidate = SubnetRequest(name, hosts, kind=kind, gateway_policy=automatic_gateway_policy(kind))
            try:
                calculate_vlsm(base, [*requests, candidate], reserved=reserved)
            except ValidationError as exc:
                print(Fore.YELLOW + f"Corrige esta subred antes de continuar: {exc}")
                continue
            requests.append(candidate)
        plan = calculate_vlsm(base, requests, reserved=reserved)
        print(Fore.GREEN + Style.BRIGHT + f"Utilizacion: {plan.utilization_percent}%")
        for item in plan.allocations:
            print(f"{item.name}: {item.network} | {item.first_usable}-{item.last_usable} | GW {item.gateway}")
        if _yes("¿Exportar JSON y CSV?"):
            stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            print(export_plan_json(plan, paths.reports / f"vlsm_{stamp}.json"))
            print(export_plan_csv(plan, paths.reports / f"vlsm_{stamp}.csv"))
    except (ValidationError, ValueError) as exc:
        print(Fore.YELLOW + f"No se pudo calcular VLSM: {exc}")


def _show_network_calculation(base: str) -> None:
    network = validate_ipv4_network(base)
    if network.prefixlen == 32:
        first = last = network.network_address
        usable, gateway = 1, None
    elif network.prefixlen == 31:
        first, last = network.network_address, network.broadcast_address
        usable, gateway = 2, None
    else:
        first, last = network.network_address + 1, network.broadcast_address - 1
        usable, gateway = network.num_addresses - 2, first
    print(Fore.GREEN + Style.BRIGHT + "\n=== Calculo automatico de la red ===")
    print(f"Red: {network} | Mascara: {network.netmask}")
    print(f"Hosts disponibles: {usable} | Rango: {first}-{last}")
    print(f"Gateway automatico: {gateway or 'No aplica'} | Broadcast: {network.broadcast_address}")


def _scanner_menu(paths: AppPaths) -> None:
    print(Fore.RED + "Utiliza el escaner solo sobre redes que administras o tienes permiso para evaluar.")
    if not _confirm("Confirmar autorizacion sobre el objetivo", keyword="AUTORIZO"):
        return
    print("  1) Ping sweep IPv4")
    print("  2) Puertos TCP de una IPv4")
    choice = input("> ").strip()
    policy = ScanPolicy()
    try:
        if choice == "1":
            network = validate_ipv4_network(input("Red CIDR IPv4: ").strip())
            results = ping_sweep(
                network,
                policy=policy,
                resolve_dns=_yes("¿Resolver DNS inverso?"),
                resolve_mac=_yes("¿Consultar MAC en cache ARP?"),
            )
            for item in results:
                if item.alive:
                    print(Fore.GREEN + f"{item.ip} viva | {item.hostname or '-'} | {item.mac or '-'}")
        elif choice == "2":
            ip = str(validate_ipv4(input("IPv4 objetivo: ").strip()))
            results = scan_tcp_ports(ip, policy=policy)
            for item in results:
                color = Fore.GREEN if item.state is PortState.OPEN else Fore.LIGHTBLACK_EX
                print(color + f"{item.port}/{item.service}: {item.state.value} ({item.latency_ms} ms)")
        else:
            return
        if _yes("¿Exportar JSON y CSV?"):
            stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            print(export_scan_json(results, paths.reports / f"scan_{stamp}.json"))
            print(export_scan_csv(results, paths.reports / f"scan_{stamp}.csv"))
    except ValidationError as exc:
        print(Fore.YELLOW + str(exc))


def main() -> int:
    init(autoreset=True)
    paths = AppPaths.create(Path(__file__).resolve().parent.parent / "runtime")
    audit = AuditLogger(paths.logs)
    audit.event("application_started", version=__version__)
    try:
        while True:
            print(Fore.MAGENTA + Style.BRIGHT + f"\n=== SarevatApp {__version__} ===")
            print("  1) Conectar a equipo Cisco")
            print("  2) Planificar VLSM IPv4")
            print("  3) Escaner IPv4")
            print("  4) Inventario y perfiles")
            print("  0) Salir")
            choice = input("> ").strip()
            if choice == "0":
                return 0
            if choice == "1":
                _connect(paths, audit)
            elif choice == "2":
                _standalone_vlsm(paths)
            elif choice == "3":
                _scanner_menu(paths)
            elif choice == "4":
                _inventory_menu(paths, audit)
            else:
                print(Fore.YELLOW + "Opcion invalida.")
    except (KeyboardInterrupt, EOFError):
        print(Fore.BLUE + "\nAplicacion cerrada.")
        return 0
    except Exception as exc:
        audit.event("fatal_error", error=redact_text(str(exc)), type=type(exc).__name__)
        print(Fore.RED + f"Error fatal controlado: {redact_text(str(exc))}")
        return 1
    finally:
        audit.event("application_finished")
        audit.close()


if __name__ == "__main__":
    sys.exit(main())
