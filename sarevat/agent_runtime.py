"""Adaptador no interactivo del motor Sarevat para una interfaz web local.

El adaptador recibe trabajos estructurados, nunca comandos IOS arbitrarios. Las
credenciales se inyectan solo en memoria por el agente instalado en la red.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC
from pathlib import Path
from typing import Any

from netmiko import ConnectHandler

from sarevat.cisco.discovery import discover_device
from sarevat.cisco.executor import CiscoExecutor
from sarevat.cisco.services import (
    build_aaa_local_plan,
    build_basic_hardening_plan,
    build_initial_setup_plan,
    build_interface_ip_plan,
    build_service_plan,
    build_site_observability_plan,
    build_snmpv3_plan,
)
from sarevat.logging_utils import AuditLogger
from sarevat.models import DeviceKind
from sarevat.security import redact_text


class AgentJobError(ValueError):
    """Trabajo rechazado antes de abrir una conexión al equipo."""


def _connection_params(connection: dict[str, Any], credentials: dict[str, str]) -> dict[str, Any]:
    transport = connection.get("transport", "ssh")
    common = {
        "username": str(credentials.get("username", "")).strip(),
        "password": credentials.get("password", ""),
        "secret": credentials.get("secret", ""),
    }
    if transport == "ssh":
        host = str(connection.get("host", "")).strip()
        if not host or not common["username"] or not common["password"]:
            raise AgentJobError("El perfil SSH requiere host, usuario y password temporal.")
        return {"device_type": "cisco_ios", "host": host, **common}
    if transport == "serial":
        port = str(connection.get("port", "")).strip()
        try:
            baudrate = int(connection.get("baudrate", 9600))
        except (TypeError, ValueError) as exc:
            raise AgentJobError("El baudrate serial debe ser un entero positivo.") from exc
        if not port or baudrate <= 0:
            raise AgentJobError("El perfil serial requiere puerto y baudrate positivo.")
        return {
            "device_type": "cisco_ios_serial",
            "serial_settings": {"port": port, "baudrate": baudrate},
            **common,
        }
    raise AgentJobError("Transporte no permitido.")


def _facts_payload(facts: Any) -> dict[str, Any]:
    return {
        "hostname": facts.hostname,
        "model": facts.model,
        "version": facts.version,
        "serial": facts.serial,
        "interfaces": {name: asdict(item) for name, item in facts.interfaces.items()},
        "vlans": facts.vlans,
        "trunks": sorted(facts.trunks),
        "etherchannels": sorted(facts.etherchannels),
        "capabilities": sorted(facts.capabilities),
        "warnings": facts.warnings,
    }


def _report_payload(report: Any) -> dict[str, Any]:
    return {
        "plan": report.plan_name,
        "status": report.status.value,
        "dryRun": report.dry_run,
        "message": report.message,
        "checkpoint": report.checkpoint,
        "rolledBack": report.rolled_back,
        "startedAt": report.started_at.astimezone(UTC).isoformat(),
        "finishedAt": report.finished_at.astimezone(UTC).isoformat() if report.finished_at else None,
        "prechecks": report.precheck_output,
        "postchecks": report.postcheck_output,
        "results": [
            {
                "command": item.command,
                "success": item.success,
                "errors": list(item.errors),
                "output": item.output,
            }
            for item in report.results
        ],
    }


def _build_plan(service: str, data: dict[str, Any], facts: Any, device_kind: DeviceKind) -> Any:
    """Enruta únicamente formularios equivalentes a los de la GUI 7.0."""
    if service == "initial_setup":
        return build_initial_setup_plan(data)
    if service == "site_observability":
        return build_site_observability_plan(
            str(data.get("role", "sucursal")), str(data.get("ntp", "")), str(data.get("syslog", ""))
        )
    if service == "snmpv3":
        return build_snmpv3_plan(
            str(data.get("group", "")),
            str(data.get("username", "")),
            str(data.get("auth", "")),
            str(data.get("privacy", "")),
        )
    if service == "aaa_local":
        return build_aaa_local_plan(
            str(data.get("username", "")), facts, data.get("console") == "CONSOLA_LISTA"
        )
    if service == "basic_hardening":
        return build_basic_hardening_plan(facts)
    if service == "interface_ipv4":
        return build_interface_ip_plan(
            str(data.get("interface", "")),
            str(data.get("address", "")),
            str(data.get("netmask", "")),
            facts,
        )
    return build_service_plan(service, data, facts, device_kind)


def execute_agent_job(job: dict[str, Any], credentials: dict[str, str], runtime: Path) -> dict[str, Any]:
    """Ejecuta un trabajo permitido usando los validadores y executor 7.0.

    Tipos: ``discover``, ``ssh_test`` y ``service``. Un servicio siempre se
    construye desde ``SERVICE_CATALOG`` y primero debe pasar por dry-run.
    """
    kind = str(job.get("kind", ""))
    if kind not in {"discover", "ssh_test", "service"}:
        raise AgentJobError("Tipo de trabajo no permitido.")

    runtime = runtime.resolve()
    audit = AuditLogger(runtime / "logs")
    try:
        params = _connection_params(dict(job.get("connection", {})), credentials)
        with ConnectHandler(**params) as connection:
            if params.get("secret") and not connection.check_enable_mode():
                connection.enable()
            facts = discover_device(connection)
            if kind == "discover":
                return {"status": "succeeded", "facts": _facts_payload(facts)}
            if kind == "ssh_test":
                return {
                    "status": "succeeded",
                    "facts": _facts_payload(facts),
                    "message": "Autenticación y descubrimiento correctos.",
                }

            service = str(job.get("service", ""))
            data = job.get("data")
            if not isinstance(data, dict):
                raise AgentJobError("Los datos del servicio son inválidos.")
            try:
                device_kind = DeviceKind(str(job.get("deviceKind", "")))
            except ValueError as exc:
                raise AgentJobError("El tipo de equipo debe ser router o switch.") from exc
            plan = _build_plan(service, data, facts, device_kind)
            apply = bool(job.get("apply", False))
            if apply and not bool(job.get("confirmed", False)):
                raise AgentJobError("La aplicación requiere confirmación explícita.")
            if apply and plan.service == "aaa_local" and job.get("aaaConfirmation") != "AAA_APLICAR":
                raise AgentJobError("AAA requiere la confirmación exacta AAA_APLICAR.")
            executor = CiscoExecutor(connection, audit=audit, backup_directory=runtime / "backups")
            report = executor.execute(
                plan,
                dry_run=not apply,
                confirm=lambda _message: bool(job.get("confirmed", False)),
                rollback_on_error=True,
            )
            return {
                "status": "succeeded",
                "facts": _facts_payload(facts),
                "report": _report_payload(report),
            }
    except AgentJobError:
        raise
    except Exception as exc:
        audit.event("agent_job_failed", kind=kind, error=redact_text(str(exc)))
        return {"status": "failed", "message": redact_text(str(exc))}
    finally:
        audit.close()
