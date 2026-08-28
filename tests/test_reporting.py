from __future__ import annotations

import json
from datetime import UTC, datetime

from sarevat.models import CommandResult, ExecutionReport, ResultStatus
from sarevat.reporting import (
    execution_report_payload,
    export_execution_report_csv,
    export_execution_report_json,
)


def _report() -> ExecutionReport:
    report = ExecutionReport("SNMP", ResultStatus.APPLIED, False, datetime.now(UTC), message="Aplicado")
    report.results.append(
        CommandResult(
            "snmp-server community PRIVATE RO",
            "community PRIVATE",
            True,
            ("% Error: community PRIVATE",),
        )
    )
    return report


def test_execution_report_payload_and_exports_redact_secrets(tmp_path) -> None:
    report = _report()
    payload = execution_report_payload(report)
    json_path = export_execution_report_json(report, tmp_path / "report.json")
    csv_path = export_execution_report_csv(report, tmp_path / "report.csv")
    rendered = (
        json.dumps(payload)
        + json_path.read_text(encoding="utf-8")
        + csv_path.read_text(encoding="utf-8")
    )
    assert "PRIVATE" not in rendered
    assert "********" in rendered
