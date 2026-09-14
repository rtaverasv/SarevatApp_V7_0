from __future__ import annotations

from pathlib import Path
from typing import Any

from sarevat.juniper.services import build_management_candidate
from sarevat.juniper.transaction import JunosExecutor
from sarevat.logging_utils import AuditLogger
from sarevat.models import DeviceFacts, InterfaceState, NetworkPlatform, ResultStatus


class ReadOnlyConnection:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def send_command(self, command: str, **_: Any) -> str:
        self.commands.append(command)
        return {
            "show configuration system host-name": "host-name Admin;",
            "show interfaces terse me0.0": "me0.0 up up inet 192.168.1.50/24",
        }[command]


def _plan():
    return build_management_candidate(
        {
            "hostname": "Admin",
            "interface": "me0.0",
            "address": "192.168.1.60",
            "netmask": "255.255.255.0",
        },
        DeviceFacts(
            platform=NetworkPlatform.JUNIPER_JUNOS,
            interfaces={"me0.0": InterfaceState("me0.0", "192.168.1.50", "up", "up")},
        ),
    )


def test_junos_executor_dry_run_collects_only_prechecks(tmp_path: Path) -> None:
    connection = ReadOnlyConnection()
    audit = AuditLogger(tmp_path / "logs")
    report = JunosExecutor(connection, audit=audit).execute(_plan())
    audit.close()

    assert report.status is ResultStatus.PLANNED
    assert connection.commands == ["show configuration system host-name", "show interfaces terse me0.0"]
    assert report.results and all(item.output == "DRY-RUN" for item in report.results)


def test_junos_executor_blocks_non_dry_run_without_configuration_api(tmp_path: Path) -> None:
    connection = ReadOnlyConnection()
    audit = AuditLogger(tmp_path / "logs")
    report = JunosExecutor(connection, audit=audit).execute(_plan(), dry_run=False)
    audit.close()

    assert report.status is ResultStatus.SKIPPED
    assert "bloqueada" in report.message
    assert connection.commands == ["show configuration system host-name", "show interfaces terse me0.0"]
