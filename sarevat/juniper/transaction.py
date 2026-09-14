"""Prechecks y contrato transaccional Junos sin ruta de configuracion remota."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

from sarevat.models import CommandPlan

_JUNOS_ERROR_RE = re.compile(
    r"(?im)^\s*(?:error:|syntax error|commit failed|configuration check-out failed|"
    r"unknown command|missing mandatory statement).*$"
)


class ConnectionLike(Protocol):
    def send_command(self, command: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class JunosPrecheckReport:
    """Resultado de comandos operativos de solo lectura previos a un candidato."""

    outputs: dict[str, str]
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


def find_junos_errors(output: str) -> tuple[str, ...]:
    """Extrae diagnosticos Junos relevantes sin confundir una salida normal con exito."""
    return tuple(match.group(0).strip() for match in _JUNOS_ERROR_RE.finditer(output))


def run_prechecks(connection: ConnectionLike, plan: CommandPlan) -> JunosPrecheckReport:
    """Ejecuta solamente los prechecks declarados por un candidato Junos."""
    if plan.metadata.get("platform") != "juniper_junos":
        raise ValueError("El precheck Junos requiere un candidato de plataforma juniper_junos.")
    if not plan.metadata.get("preview_only"):
        raise ValueError("La ejecución Junos permanece bloqueada hasta la certificación de laboratorio.")

    outputs: dict[str, str] = {}
    errors: list[str] = []
    for command in plan.prechecks:
        try:
            output = str(connection.send_command(command))
        except Exception as exc:  # Netmiko varía sus excepciones por transporte.
            errors.append(f"{command}: {type(exc).__name__}: {exc}")
            continue
        outputs[command] = output
        errors.extend(f"{command}: {error}" for error in find_junos_errors(output))
    return JunosPrecheckReport(outputs=outputs, errors=tuple(errors))


def transaction_preview(plan: CommandPlan, *, confirm_minutes: int = 5) -> tuple[str, ...]:
    """Describe el procedimiento Junos proyectado; no es un ejecutor de comandos."""
    if plan.metadata.get("platform") != "juniper_junos" or not plan.metadata.get("preview_only"):
        raise ValueError("Solo se pueden revisar candidatos Junos bloqueados para aplicación remota.")
    if not 1 <= confirm_minutes <= 10:
        raise ValueError("El tiempo de commit confirmed debe estar entre 1 y 10 minutos.")
    return (
        "configure private",
        "load merge terminal",
        *plan.commands,
        "<Ctrl-D para terminar la carga>",
        "show | compare",
        "commit check",
        f"commit confirmed {confirm_minutes}",
        "verificar conectividad e inicio de sesión SSH desde una segunda sesión",
        "commit",
        "Si la verificación falla: no confirmar; Junos revierte al vencer el temporizador.",
    )
