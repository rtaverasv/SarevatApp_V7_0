from __future__ import annotations

from pathlib import Path
from typing import Any

from sarevat.juniper.services import build_management_candidate
from sarevat.juniper.transaction import JUNOS_LAB_ACCEPTANCE, JunosExecutor
from sarevat.logging_utils import AuditLogger
from sarevat.models import DeviceFacts, InterfaceState, NetworkPlatform, ResultStatus


class FakeJunosConnection:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.timing_commands: list[str] = []
        self.changed = False

    def send_command(self, command: str, **_: Any) -> str:
        self.commands.append(command)
        if command == "show | compare":
            return "[edit system]\n+ host-name Admin;"
        if command == "show configuration system host-name":
            return "host-name Admin;"
        if command in {"show interfaces terse me0.0", "run show interfaces terse me0.0"}:
            return "me0.0 up up inet 192.168.1.60/24" if self.changed else "me0.0 up up inet 192.168.1.50/24"
        if command in {"commit check", "commit confirmed 5", "commit", "rollback 0"}:
            return "commit complete"
        raise AssertionError(command)

    def send_command_timing(self, command: str, **_: Any) -> str:
        self.timing_commands.append(command)
        if "\x04" in command:
            self.changed = True
        return "ok"


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
    connection = FakeJunosConnection()
    audit = AuditLogger(tmp_path / "logs")
    report = JunosExecutor(connection, audit=audit).execute(_plan())
    audit.close()

    assert report.status is ResultStatus.PLANNED
    assert connection.commands == ["show configuration system host-name", "show interfaces terse me0.0"]
    assert not connection.timing_commands
    assert report.results and all(item.output == "DRY-RUN" for item in report.results)


def test_junos_executor_requires_explicit_lab_acceptance(tmp_path: Path) -> None:
    connection = FakeJunosConnection()
    audit = AuditLogger(tmp_path / "logs")
    report = JunosExecutor(connection, audit=audit).execute(_plan(), dry_run=False)
    audit.close()

    assert report.status is ResultStatus.SKIPPED
    assert "aceptacion explicita" in report.message
    assert not connection.timing_commands


def test_junos_executor_commits_only_after_second_session_verification(tmp_path: Path) -> None:
    connection = FakeJunosConnection()
    audit = AuditLogger(tmp_path / "logs")
    report = JunosExecutor(connection, audit=audit).execute(
        _plan(),
        dry_run=False,
        lab_acceptance=JUNOS_LAB_ACCEPTANCE,
        confirm=lambda _: True,
        verify_management=lambda: True,
    )
    audit.close()

    assert report.status is ResultStatus.APPLIED
    assert connection.timing_commands[:2] == ["configure exclusive", "load set terminal"]
    assert "commit check" in connection.timing_commands
    assert "commit confirmed 5" in connection.timing_commands
    assert connection.timing_commands[-2:] == ["commit", ""]
    assert connection.commands == ["show configuration system host-name", "show interfaces terse me0.0"]


def test_junos_executor_leaves_confirmed_change_to_revert_when_reconnect_fails(tmp_path: Path) -> None:
    connection = FakeJunosConnection()
    audit = AuditLogger(tmp_path / "logs")
    report = JunosExecutor(connection, audit=audit).execute(
        _plan(),
        dry_run=False,
        lab_acceptance=JUNOS_LAB_ACCEPTANCE,
        confirm=lambda _: True,
        verify_management=lambda: False,
    )
    audit.close()

    assert report.status is ResultStatus.FAILED
    assert "revertira" in report.message
    assert "commit confirmed 5" in connection.timing_commands
    assert "commit" not in connection.timing_commands
    assert connection.timing_commands[-1] == "rollback 0"
