"""Ejecucion fail-fast con dry-run, checkpoint, verificacion y rollback."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from netmiko.exceptions import ConfigInvalidException

from sarevat.logging_utils import AuditLogger
from sarevat.models import CommandPlan, CommandResult, ExecutionReport, ResultStatus
from sarevat.security import (
    IOS_ERROR_PATTERN,
    find_ios_errors,
    plan_dangerous_reasons,
    redact_command,
    redact_text,
)


class ConfigConnection(Protocol):
    def send_command(self, command: str, **kwargs: Any) -> str: ...

    def send_command_timing(self, command: str, **kwargs: Any) -> str: ...

    def send_config_set(self, config_commands: list[str] | tuple[str, ...], **kwargs: Any) -> str: ...


ConfirmCallback = Callable[[str], bool]


class CiscoExecutor:
    def __init__(
        self,
        connection: ConfigConnection,
        *,
        audit: AuditLogger,
        backup_directory: Path,
    ) -> None:
        self.connection = connection
        self.audit = audit
        self.backup_directory = backup_directory.resolve()

    def _run_show(self, command: str) -> str:
        output = str(self.connection.send_command(command))
        errors = find_ios_errors(output)
        if errors:
            raise RuntimeError("; ".join(errors))
        return output

    def _write_redacted_backup(self, running_config: str, plan_name: str) -> Path:
        self.backup_directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", plan_name)[:60]
        path = self.backup_directory / f"{safe_name}_{stamp}_redacted.cfg"
        path.write_text(redact_text(running_config), encoding="utf-8")
        with suppress(OSError):
            os.chmod(path, 0o600)
        return path

    def create_checkpoint(self, plan_name: str) -> str:
        digest = hashlib.sha256(f"{plan_name}{datetime.now(UTC).isoformat()}".encode()).hexdigest()[:10]
        filename = f"sarevat_{digest}.cfg"
        output = str(
            self.connection.send_command_timing(
                f"copy running-config flash:{filename}",
                read_timeout=30,
            )
        )
        if "destination filename" in output.lower():
            output += str(self.connection.send_command_timing("", read_timeout=30))
        errors = find_ios_errors(output)
        if errors or not any(token in output.lower() for token in ("copied", "bytes", "ok", "success")):
            raise RuntimeError("No se pudo confirmar el checkpoint: " + ("; ".join(errors) or output[-300:]))
        self.audit.event("checkpoint_created", filename=filename)
        return filename

    def rollback(self, checkpoint: str, confirm: ConfirmCallback) -> tuple[bool, str]:
        if not confirm(f"Rollback: reemplazar running-config desde flash:{checkpoint}"):
            return False, "Rollback no autorizado."
        output = str(
            self.connection.send_command_timing(
                f"configure replace flash:{checkpoint} force",
                read_timeout=90,
            )
        )
        errors = find_ios_errors(output)
        success = not errors and any(token in output.lower() for token in ("completed", "success", "rolled"))
        self.audit.event("rollback", checkpoint=checkpoint, success=success, output=redact_text(output))
        return success, output

    def execute(
        self,
        plan: CommandPlan,
        *,
        dry_run: bool = True,
        confirm: ConfirmCallback | None = None,
        create_checkpoint: bool = True,
        rollback_on_error: bool = True,
    ) -> ExecutionReport:
        started = datetime.now(UTC)
        report = ExecutionReport(plan.name, ResultStatus.PLANNED, dry_run, started)
        dangerous = plan_dangerous_reasons(plan.commands)
        self.audit.event(
            "plan_started",
            name=plan.name,
            service=plan.service,
            dry_run=dry_run,
            commands=[redact_command(item) for item in plan.commands],
            dangerous={redact_command(command): reasons for command, reasons in dangerous.items()},
        )

        try:
            for command in plan.prechecks:
                report.precheck_output[command] = redact_text(self._run_show(command))
        except Exception as exc:
            report.status = ResultStatus.FAILED
            report.message = f"Fallo de precheck: {exc}"
            report.finished_at = datetime.now(UTC)
            self.audit.event("plan_failed", stage="precheck", error=str(exc))
            return report

        if dry_run:
            report.results.extend(
                CommandResult(redact_command(command), "DRY-RUN", True) for command in plan.commands
            )
            report.message = "Plan validado; no se enviaron comandos."
            report.finished_at = datetime.now(UTC)
            self.audit.event("plan_dry_run_complete", name=plan.name)
            return report

        if confirm is None or not confirm(f"Aplicar {len(plan.commands)} comandos del plan '{plan.name}'"):
            report.status = ResultStatus.SKIPPED
            report.message = "Aplicacion cancelada por el usuario."
            report.finished_at = datetime.now(UTC)
            self.audit.event("plan_cancelled", name=plan.name)
            return report
        if dangerous and not confirm("El plan contiene comandos de alto impacto; confirmar nuevamente"):
            report.status = ResultStatus.SKIPPED
            report.message = "Comandos de alto impacto no autorizados."
            report.finished_at = datetime.now(UTC)
            self.audit.event("dangerous_plan_cancelled", name=plan.name)
            return report

        try:
            running_config = self._run_show("show running-config")
            report.backup_path = self._write_redacted_backup(running_config, plan.name)
            if create_checkpoint:
                report.checkpoint = self.create_checkpoint(plan.name)
            interactive_commands = set(plan.metadata.get("interactive_commands", ()))
            standard_commands = [command for command in plan.commands if command not in interactive_commands]
            output = ""
            if standard_commands:
                output = str(
                    self.connection.send_config_set(
                        standard_commands,
                        error_pattern=IOS_ERROR_PATTERN,
                        cmd_verify=True,
                        read_timeout=60,
                    )
                )
            for command in interactive_commands:
                interactive_output = str(self.connection.send_command_timing("configure terminal"))
                interactive_output += str(self.connection.send_command_timing(command, read_timeout=60))
                lowered = interactive_output.lower()
                if "how many bits" in lowered:
                    bits = command.rsplit(maxsplit=1)[-1]
                    interactive_output += str(self.connection.send_command_timing(bits, read_timeout=60))
                if "replace" in lowered or "[yes/no]" in lowered:
                    if not confirm or not confirm(f"{command} solicita reemplazar una clave existente"):
                        raise RuntimeError("Reemplazo de clave RSA no autorizado.")
                    interactive_output += str(self.connection.send_command_timing("yes", read_timeout=60))
                interactive_output += str(self.connection.send_command_timing("end"))
                output += "\n" + interactive_output
            errors = find_ios_errors(output)
            report.results.append(
                CommandResult(
                    command="\n".join(redact_command(item) for item in plan.commands),
                    output=redact_text(output),
                    success=not errors,
                    errors=errors,
                )
            )
            if errors:
                raise ConfigInvalidException("; ".join(errors))
            for command in plan.postchecks:
                report.postcheck_output[command] = redact_text(self._run_show(command))
            report.status = ResultStatus.APPLIED
            report.message = "Plan aplicado y postchecks completados."
        except Exception as exc:
            report.status = ResultStatus.FAILED
            report.message = f"Aplicacion detenida: {exc}"
            if not report.results:
                report.results.append(
                    CommandResult(
                        command="\n".join(redact_command(item) for item in plan.commands),
                        output="",
                        success=False,
                        errors=(redact_text(str(exc)),),
                    )
                )
            self.audit.event("plan_failed", stage="apply", error=redact_text(str(exc)))
            if rollback_on_error and report.checkpoint and confirm:
                rolled_back, rollback_output = self.rollback(report.checkpoint, confirm)
                report.rolled_back = rolled_back
                report.results.append(
                    CommandResult(
                        command=f"rollback flash:{report.checkpoint}",
                        output=redact_text(rollback_output),
                        success=rolled_back,
                        errors=() if rolled_back else ("No se pudo confirmar el rollback.",),
                    )
                )
                if rolled_back:
                    report.status = ResultStatus.ROLLED_BACK
                    report.message = "El plan fallo y el checkpoint fue restaurado."
        finally:
            report.finished_at = datetime.now(UTC)
            self.audit.event(
                "plan_finished",
                name=plan.name,
                status=report.status,
                rolled_back=report.rolled_back,
                message=report.message,
            )
        return report
