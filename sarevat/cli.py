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
from sarevat.cisco.discovery import discover_device
from sarevat.cisco.executor import CiscoExecutor
from sarevat.cisco.services import (
    SERVICE_CATALOG,
    build_initial_setup_plan,
    build_interface_ip_plan,
    build_service_plan,
    service_is_configured,
)
from sarevat.logging_utils import AuditLogger
from sarevat.models import CommandPlan, DeviceFacts, DeviceKind, ExecutionReport
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
from sarevat.vlsm import SubnetRequest, calculate_vlsm, export_plan_csv, export_plan_json


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


def _execute_interactive(executor: CiscoExecutor, plan: CommandPlan) -> None:
    _preview_plan(plan)
    dry_report = executor.execute(plan, dry_run=True)
    _print_report(dry_report)
    if not _yes("¿Aplicar realmente este plan?"):
        return
    report = executor.execute(
        plan,
        dry_run=False,
        confirm=_confirm,
        create_checkpoint=True,
        rollback_on_error=True,
    )
    _print_report(report)


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
                    _execute_interactive(executor, dependency_plan)
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
                    _execute_interactive(executor, plan)
                    facts = discover_device(executor.connection)
                continue
            plan = build_service_plan(service, _collect_service_data(service), facts, device_kind)
            _execute_interactive(executor, plan)
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


def _device_vlsm(executor: CiscoExecutor, facts: DeviceFacts) -> None:
    base = input(Fore.CYAN + "Red base CIDR: ").strip()
    requests: list[SubnetRequest] = []
    selected_interfaces: list[str] = []
    print("Indica interfaces y hosts. Deja la interfaz vacia para calcular.")
    while True:
        interface = input(Fore.CYAN + "Interfaz: ").strip()
        if not interface:
            break
        hosts = int(input("Hosts: ").strip())
        kind = input("Tipo [lan/point_to_point/loopback] (lan): ").strip() or "lan"
        selected_interfaces.append(interface)
        requests.append(SubnetRequest(interface, hosts, kind=kind))
    plan = calculate_vlsm(base, requests)
    for allocation in plan.allocations:
        interface_plan = build_interface_ip_plan(
            allocation.name,
            allocation.first_usable,
            allocation.netmask,
            facts,
        )
        _execute_interactive(executor, interface_plan)


def _device_session(connection: Any, device_kind: DeviceKind, paths: AppPaths, audit: AuditLogger) -> None:
    executor = CiscoExecutor(connection, audit=audit, backup_directory=paths.backups)
    facts = discover_device(connection)
    audit.event("device_discovered", hostname=facts.hostname, model=facts.model, version=facts.version)
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + f"\n=== {facts.hostname} ===")
        print("  1) Ver estado e inventario")
        print("  2) Protocolos y servicios")
        print("  3) VLSM y configurar interfaces")
        print("  4) Consola libre")
        print("  5) Configuracion inicial segura")
        print("  6) Guardar configuracion (write memory)")
        print("  0) Desconectar")
        choice = input("> ").strip()
        if choice == "0":
            return
        if choice == "1":
            facts = discover_device(connection)
            _show_facts(facts)
        elif choice == "2":
            _service_menu(executor, facts, device_kind)
            facts = discover_device(connection)
        elif choice == "3":
            try:
                _device_vlsm(executor, facts)
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
                _execute_interactive(executor, build_initial_setup_plan(data))
            except ValidationError as exc:
                print(Fore.YELLOW + str(exc))
        elif choice == "6":
            if _confirm("Guardar running-config en startup-config"):
                output = str(connection.send_command_timing("write memory", read_timeout=30))
                print(output)
                audit.event("write_memory", output=output, errors=find_ios_errors(output))
        else:
            print(Fore.YELLOW + "Opcion invalida.")


def _connect(paths: AppPaths, audit: AuditLogger) -> None:
    print("  1) SSH")
    print("  2) Consola serial")
    mode = input("> ").strip()
    kind_text = input("Equipo [router/switch]: ").strip().lower()
    if kind_text not in {"router", "switch"}:
        print(Fore.YELLOW + "Tipo de equipo invalido.")
        return
    kind = DeviceKind(kind_text)
    try:
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
            _device_session(connection, kind, paths, audit)
    except NetmikoAuthenticationException:
        print(Fore.RED + "Autenticacion rechazada.")
        audit.event("connection_failed", reason="authentication")
    except NetmikoTimeoutException:
        print(Fore.RED + "Timeout de conexion.")
        audit.event("connection_failed", reason="timeout")
    except (OSError, ValueError) as exc:
        print(Fore.RED + f"No se pudo conectar: {redact_text(str(exc))}")
        audit.event("connection_failed", reason=str(exc))


def _standalone_vlsm(paths: AppPaths) -> None:
    try:
        base = input("Red base CIDR: ").strip()
        reserved_text = input("Exclusiones CIDR separadas por coma (opcional): ").strip()
        requests: list[SubnetRequest] = []
        while True:
            name = input("Nombre de subred (vacio para calcular): ").strip()
            if not name:
                break
            hosts = int(input("Hosts: ").strip())
            kind = input("Tipo [lan/point_to_point/loopback] (lan): ").strip() or "lan"
            gateway = input("Gateway [first/last/none] (first): ").strip() or "first"
            requests.append(SubnetRequest(name, hosts, kind=kind, gateway_policy=gateway))
        reserved = tuple(item.strip() for item in reserved_text.split(",") if item.strip())
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
            print("  4) Salir")
            choice = input("> ").strip()
            if choice == "4":
                return 0
            if choice == "1":
                _connect(paths, audit)
            elif choice == "2":
                _standalone_vlsm(paths)
            elif choice == "3":
                _scanner_menu(paths)
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
