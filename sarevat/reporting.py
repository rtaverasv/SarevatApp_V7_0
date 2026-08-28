"""Exportación segura de resultados de ejecución."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from sarevat.models import ExecutionReport
from sarevat.security import redact_text


def _safe(value: object) -> str:
    return redact_text(str(value))


def execution_report_payload(report: ExecutionReport) -> dict[str, object]:
    """Convierte un resultado de ejecución en datos serializables y redactados."""
    return {
        "plan_name": _safe(report.plan_name),
        "status": report.status.value,
        "dry_run": report.dry_run,
        "started_at": report.started_at.isoformat(),
        "finished_at": report.finished_at.isoformat() if report.finished_at else None,
        "rolled_back": report.rolled_back,
        "message": _safe(report.message),
        "checkpoint": _safe(report.checkpoint) if report.checkpoint else None,
        "backup_path": str(report.backup_path) if report.backup_path else None,
        "results": [
            {
                "command": _safe(result.command),
                "success": result.success,
                "errors": [_safe(error) for error in result.errors],
                "output": _safe(result.output),
            }
            for result in report.results
        ],
        "prechecks": {command: _safe(output) for command, output in report.precheck_output.items()},
        "postchecks": {command: _safe(output) for command, output in report.postcheck_output.items()},
    }


def export_execution_report_json(report: ExecutionReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(execution_report_payload(report), indent=2, ensure_ascii=False) + "\n"
    path.write_text(content, encoding="utf-8")
    return path


def export_execution_report_csv(report: ExecutionReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        fields = ("plan", "status", "dry_run", "command", "success", "errors")
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in report.results:
            writer.writerow(
                {
                    "plan": _safe(report.plan_name),
                    "status": report.status.value,
                    "dry_run": report.dry_run,
                    "command": _safe(result.command),
                    "success": result.success,
                    "errors": "; ".join(_safe(error) for error in result.errors),
                }
            )
    return path
