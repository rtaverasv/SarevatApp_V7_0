"""Prechecks y transaccion Junos con confirmacion recuperable de laboratorio."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from sarevat.logging_utils import AuditLogger
from sarevat.models import CommandPlan, CommandResult, ExecutionReport, ResultStatus
from sarevat.security import redact_command, redact_text

_JUNOS_ERROR_RE = re.compile(
    r"(?im)^\s*(?:error:|syntax error|commit failed|configuration check-out failed|"
    r"unknown command|missing mandatory statement).*$"
)

JUNOS_LAB_ACCEPTANCE = "JUNOS_LAB_APLICAR"


class ConnectionLike(Protocol):
    def send_command(self, command: str, **kwargs: Any) -> Any: ...


class ConfigConnectionLike(ConnectionLike, Protocol):
    def send_command_timing(self, command: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class JunosPrecheckReport:
    """Resultado de comandos operativos de solo lectura previos a un candidato."""

    outputs: dict[str, str]
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


def find_junos_errors(output: str) -> tuple[str, ...]:
    """Extrae diagnosticos Junos relevantes sin confundir salida normal con exito."""
    return tuple(match.group(0).strip() for match in _JUNOS_ERROR_RE.finditer(output))


def run_prechecks(connection: ConnectionLike, plan: CommandPlan) -> JunosPrecheckReport:
    """Ejecuta solamente los prechecks declarados por un candidato Junos."""
    if plan.metadata.get("platform") != "juniper_junos":
        raise ValueError("El precheck Junos requiere un candidato de plataforma juniper_junos.")
    if not (plan.metadata.get("preview_only") or plan.metadata.get("remote_apply_supported")):
        raise ValueError("El precheck Junos requiere un candidato certificado.")

    outputs: dict[str, str] = {}
    errors: list[str] = []
    for command in plan.prechecks:
        try:
            output = str(connection.send_command(command))
        except Exception as exc:  # Netmiko varia sus excepciones por transporte.
            errors.append(f"{command}: {type(exc).__name__}: {exc}")
            continue
        outputs[command] = output
        errors.extend(f"{command}: {error}" for error in find_junos_errors(output))
    return JunosPrecheckReport(outputs=outputs, errors=tuple(errors))


def transaction_preview(plan: CommandPlan, *, confirm_minutes: int = 5) -> tuple[str, ...]:
    """Describe el procedimiento Junos proyectado antes de ejecutarlo."""
    if plan.metadata.get("platform") != "juniper_junos" or not plan.metadata.get(
        "remote_apply_supported"
    ):
        raise ValueError("Solo se pueden revisar candidatos Junos certificados.")
    if not 1 <= confirm_minutes <= 10:
        raise ValueError("El tiempo de commit confirmed debe estar entre 1 y 10 minutos.")
    return (
        "configure private",
        "load set terminal",
        *plan.commands,
        "<Ctrl-D para terminar la carga>",
        "show | compare",
        "commit check",
        f"commit confirmed {confirm_minutes}",
        "verificar SSH e IP de gestion desde una segunda sesion",
        "commit",
        "Si la verificación falla: no confirmar; Junos revierte al vencer el temporizador.",
    )


class JunosExecutor:
    """Ejecutor Junos de laboratorio con ``commit confirmed`` y cierre explicito."""

    def __init__(self, connection: ConfigConnectionLike, *, audit: AuditLogger) -> None:
        self.connection = connection
        self.audit = audit

    @staticmethod
    def _check_output(output: str) -> None:
        if errors := find_junos_errors(output):
            raise RuntimeError("; ".join(errors))

    @staticmethod
    def _verify_postcheck(command: str, output: str, expected_tokens: tuple[str, ...]) -> None:
        normalized = output.casefold()
        if expected_tokens and not all(token.casefold() in normalized for token in expected_tokens):
            raise RuntimeError(f"Postcheck semantico no confirmado para: {command}")

    def _timing(self, command: str) -> str:
        output = str(self.connection.send_command_timing(command, read_timeout=45))
        self._check_output(output)
        return output

    def _apply_candidate(self, plan: CommandPlan, report: ExecutionReport, confirm_minutes: int) -> None:
        transcript = self._timing("configure private")
        transcript += self._timing("load set terminal")
        # Junos termina la carga interactiva con Ctrl-D; nunca se usa ``configure`` global.
        transcript += self._timing("\n".join(plan.commands) + "\n\x04")
        report.results.append(CommandResult("load set terminal", redact_text(transcript), True))
        compare = str(self.connection.send_command("show | compare"))
        self._check_output(compare)
        report.results.append(CommandResult("show | compare", redact_text(compare), True))
        checked = self._timing("commit check")
        report.results.append(CommandResult("commit check", redact_text(checked), True))
        confirmed = self._timing(f"commit confirmed {confirm_minutes}")
        report.results.append(
            CommandResult(f"commit confirmed {confirm_minutes}", redact_text(confirmed), True)
        )

    def execute(
        self,
        plan: CommandPlan,
        *,
        dry_run: bool = True,
        lab_acceptance: str | None = None,
        confirm: Callable[[str], bool] | None = None,
        verify_management: Callable[[], bool] | None = None,
        confirm_minutes: int = 5,
    ) -> ExecutionReport:
        """Aplica solo tras aceptacion y verificacion externa del nuevo acceso."""
        started = datetime.now(UTC)
        report = ExecutionReport(plan.name, ResultStatus.PLANNED, dry_run, started)
        self.audit.event(
            "junos_plan_started",
            name=plan.name,
            dry_run=dry_run,
            commands=[redact_command(command) for command in plan.commands],
        )
        candidate_started = False
        try:
            prechecks = run_prechecks(self.connection, plan)
            report.precheck_output = {
                command: redact_text(output) for command, output in prechecks.outputs.items()
            }
            if not prechecks.ok:
                report.status = ResultStatus.FAILED
                report.message = "Fallo de precheck Junos: " + "; ".join(
                    redact_text(error) for error in prechecks.errors
                )
                return report
            if dry_run:
                report.results.extend(
                    CommandResult(redact_command(command), "DRY-RUN", True) for command in plan.commands
                )
                report.message = "Candidato Junos y prechecks validados; no se enviaron comandos."
                return report
            if not plan.metadata.get("remote_apply_supported"):
                report.status = ResultStatus.SKIPPED
                report.message = "Aplicacion Junos no disponible para este candidato certificado."
                return report
            if not 1 <= confirm_minutes <= 10:
                raise ValueError("El tiempo de commit confirmed debe estar entre 1 y 10 minutos.")
            if lab_acceptance != JUNOS_LAB_ACCEPTANCE or confirm is None or not confirm(
                "Confirmas que este es un laboratorio autorizado con acceso de consola recuperable?"
            ):
                report.status = ResultStatus.SKIPPED
                report.message = "Aplicacion Junos cancelada: falta aceptacion explicita de laboratorio."
                return report
            self.audit.event("junos_apply_authorized", name=plan.name, confirm_minutes=confirm_minutes)
            candidate_started = True
            self._apply_candidate(plan, report, confirm_minutes)
            for command in plan.postchecks:
                output = str(self.connection.send_command(command))
                self._check_output(output)
                self._verify_postcheck(command, output, plan.postcheck_expectations.get(command, ()))
                report.postcheck_output[command] = redact_text(output)
            if verify_management is None or not verify_management():
                raise RuntimeError(
                    "No se confirmo una segunda sesion SSH; Junos revertira al vencer commit confirmed."
                )
            committed = self._timing("commit")
            report.results.append(CommandResult("commit", redact_text(committed), True))
            report.status = ResultStatus.APPLIED
            report.message = "Plan Junos aplicado, verificado por segunda sesion SSH y confirmado."
        except Exception as exc:
            report.status = ResultStatus.FAILED
            report.message = f"Aplicacion Junos detenida: {redact_text(str(exc))}"
            if not report.results:
                report.results.append(
                    CommandResult(
                        command="candidato Junos",
                        output="",
                        success=False,
                        errors=(redact_text(str(exc)),),
                    )
                )
            self.audit.event("junos_plan_failed", stage="apply", error=redact_text(str(exc)))
            if candidate_started:
                try:
                    cleanup = str(self.connection.send_command_timing("rollback 0", read_timeout=30))
                    report.results.append(CommandResult("rollback 0", redact_text(cleanup), True))
                    self.audit.event("junos_candidate_discarded", name=plan.name)
                except Exception as cleanup_error:
                    self.audit.event(
                        "junos_candidate_cleanup_failed", error=redact_text(str(cleanup_error))
                    )
        finally:
            report.finished_at = datetime.now(UTC)
            self.audit.event(
                "junos_plan_finished",
                name=plan.name,
                status=report.status,
                message=report.message,
            )
        return report
