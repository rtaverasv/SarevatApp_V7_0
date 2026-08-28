from __future__ import annotations

from pathlib import Path

from sarevat.cisco.executor import CiscoExecutor
from sarevat.cisco.services import build_initial_setup_plan
from sarevat.logging_utils import AuditLogger
from sarevat.models import CommandPlan, ResultStatus


class FakeConnection:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.config_calls = 0
        self.last_config_commands: list[str] = []
        self.timing_commands: list[str] = []

    def send_command(self, command: str, **_: object) -> str:
        responses = {
            "show running-config": "hostname R1\nusername admin secret TOPSECRET\n",
            "show clock": "12:00:00 UTC",
            "show ip interface brief": "GigabitEthernet0/0 10.0.0.1 YES manual up up",
            "show ip ssh": "SSH Enabled - version 2.0",
            "show running-config | section line vty": "line vty 0 15\n login local\n transport input ssh",
        }
        return responses.get(command, "OK")

    def send_command_timing(self, command: str, **_: object) -> str:
        self.timing_commands.append(command)
        if command.startswith("copy running-config"):
            return "1234 bytes copied in 0.10 secs"
        if command.startswith("configure replace"):
            return "Configure replace completed successfully"
        return "OK"

    def send_config_set(self, commands: list[str], **_: object) -> str:
        self.config_calls += 1
        self.last_config_commands = commands
        if self.fail:
            return f"{commands[0]}\n% Invalid input detected at '^' marker."
        return "\n".join(commands) + "\nR1(config)#"


def _plan() -> CommandPlan:
    return CommandPlan(
        name="Prueba",
        service="test",
        commands=("interface GigabitEthernet0/0", "description PRUEBA", "exit"),
        prechecks=("show clock",),
        postchecks=("show ip interface brief",),
    )


def _executor(tmp_path: Path, connection: FakeConnection) -> tuple[CiscoExecutor, AuditLogger]:
    audit = AuditLogger(tmp_path / "logs")
    return CiscoExecutor(connection, audit=audit, backup_directory=tmp_path / "backups"), audit


def test_dry_run_never_sends_configuration(tmp_path: Path) -> None:
    connection = FakeConnection()
    executor, audit = _executor(tmp_path, connection)
    report = executor.execute(_plan(), dry_run=True)
    audit.close()
    assert report.status is ResultStatus.PLANNED
    assert connection.config_calls == 0
    assert report.precheck_output


def test_success_creates_checkpoint_backup_and_postchecks(tmp_path: Path) -> None:
    connection = FakeConnection()
    executor, audit = _executor(tmp_path, connection)
    report = executor.execute(_plan(), dry_run=False, confirm=lambda _: True)
    audit.close()
    assert report.status is ResultStatus.APPLIED
    assert report.checkpoint
    assert report.backup_path and report.backup_path.exists()
    assert "TOPSECRET" not in report.backup_path.read_text(encoding="utf-8")
    assert report.postcheck_output


def test_ios_error_stops_plan_and_rolls_back(tmp_path: Path) -> None:
    connection = FakeConnection(fail=True)
    executor, audit = _executor(tmp_path, connection)
    report = executor.execute(_plan(), dry_run=False, confirm=lambda _: True)
    audit.close()
    assert report.status is ResultStatus.ROLLED_BACK
    assert report.rolled_back
    assert any(command.startswith("configure replace") for command in connection.timing_commands)
    assert any(result.errors for result in report.results)


def test_audit_json_never_contains_plan_secrets(tmp_path: Path) -> None:
    connection = FakeConnection()
    executor, audit = _executor(tmp_path, connection)
    plan = CommandPlan(
        name="SNMP",
        service="snmp",
        commands=("snmp-server community SUPER_PRIVATE RO",),
    )
    executor.execute(plan, dry_run=True)
    audit_path = audit.path
    audit.close()
    content = audit_path.read_text(encoding="utf-8")
    assert "SUPER_PRIVATE" not in content
    assert "********" in content


def test_initial_setup_uses_timing_for_interactive_rsa(tmp_path: Path) -> None:
    connection = FakeConnection()
    executor, audit = _executor(tmp_path, connection)
    plan = build_initial_setup_plan(
        {
            "hostname": "R-LAB",
            "domain": "lab.local",
            "username": "admin",
            "password": "A_Strong_Test_Password",
            "rsa_bits": 2048,
        }
    )
    report = executor.execute(plan, dry_run=False, confirm=lambda _: True)
    audit.close()
    rsa_command = "crypto key generate rsa modulus 2048"
    assert report.status is ResultStatus.APPLIED
    assert rsa_command not in connection.last_config_commands
    assert rsa_command in connection.timing_commands
    assert "configure terminal" in connection.timing_commands
    assert "end" in connection.timing_commands
