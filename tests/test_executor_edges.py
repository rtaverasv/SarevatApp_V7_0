from __future__ import annotations

from pathlib import Path

import pytest

from sarevat.cisco.executor import CiscoExecutor
from sarevat.logging_utils import AuditLogger
from sarevat.models import CommandPlan, ResultStatus


class ScenarioConnection:
    def __init__(
        self,
        *,
        precheck_error: bool = False,
        checkpoint_prompt: bool = False,
        checkpoint_failure: bool = False,
        config_output: str = "description OK",
        config_exception: Exception | None = None,
        postcheck_error: bool = False,
        rsa_prompt: str = "RSA keys generated",
        rollback_output: str = "Configure replace completed successfully",
    ) -> None:
        self.precheck_error = precheck_error
        self.checkpoint_prompt = checkpoint_prompt
        self.checkpoint_failure = checkpoint_failure
        self.config_output = config_output
        self.config_exception = config_exception
        self.postcheck_error = postcheck_error
        self.rsa_prompt = rsa_prompt
        self.rollback_output = rollback_output
        self.timing: list[str] = []
        self.config_calls = 0

    def send_command(self, command: str, **_: object) -> str:
        if command == "show running-config":
            return "hostname R1\n"
        if command == "show clock" and self.precheck_error:
            return "% Invalid input detected at '^' marker."
        if command == "show ip interface brief" and self.postcheck_error:
            return "% Error: postcheck unavailable"
        return "OK"

    def send_command_timing(self, command: str, **_: object) -> str:
        self.timing.append(command)
        if command.startswith("copy running-config"):
            if self.checkpoint_failure:
                return "% Error copying file"
            if self.checkpoint_prompt:
                return "Destination filename [sarevat.cfg]?"
            return "100 bytes copied"
        if command == "":
            return "100 bytes copied"
        if command.startswith("configure replace"):
            return self.rollback_output
        if command.startswith("crypto key generate"):
            return self.rsa_prompt
        return "OK"

    def send_config_set(self, _: list[str], **__: object) -> str:
        self.config_calls += 1
        if self.config_exception:
            raise self.config_exception
        return self.config_output


def _executor(tmp_path: Path, connection: ScenarioConnection) -> tuple[CiscoExecutor, AuditLogger]:
    audit = AuditLogger(tmp_path / "logs")
    return CiscoExecutor(connection, audit=audit, backup_directory=tmp_path / "backups"), audit


def _plan(*, dangerous: bool = False, interactive: bool = False) -> CommandPlan:
    commands = ("reload",) if dangerous else ("interface GigabitEthernet0/0", "description TEST", "exit")
    metadata = {"interactive_commands": ("crypto key generate rsa modulus 2048",)} if interactive else {}
    if interactive:
        commands = ("hostname R1", "crypto key generate rsa modulus 2048")
    return CommandPlan(
        name="edge",
        service="test",
        commands=commands,
        prechecks=("show clock",),
        postchecks=("show ip interface brief",),
        metadata=metadata,
    )


def test_precheck_ios_error_stops_before_changes(tmp_path: Path) -> None:
    connection = ScenarioConnection(precheck_error=True)
    executor, audit = _executor(tmp_path, connection)
    report = executor.execute(_plan(), dry_run=True)
    audit.close()
    assert report.status is ResultStatus.FAILED
    assert connection.config_calls == 0
    assert "precheck" in report.message.lower()


def test_cancelled_apply_never_creates_checkpoint(tmp_path: Path) -> None:
    connection = ScenarioConnection()
    executor, audit = _executor(tmp_path, connection)
    report = executor.execute(_plan(), dry_run=False, confirm=lambda _: False)
    audit.close()
    assert report.status is ResultStatus.SKIPPED
    assert not connection.timing
    assert connection.config_calls == 0


def test_dangerous_plan_requires_second_confirmation(tmp_path: Path) -> None:
    connection = ScenarioConnection()
    executor, audit = _executor(tmp_path, connection)
    answers = iter((True, False))
    report = executor.execute(_plan(dangerous=True), dry_run=False, confirm=lambda _: next(answers))
    audit.close()
    assert report.status is ResultStatus.SKIPPED
    assert connection.config_calls == 0


def test_checkpoint_destination_prompt_is_answered(tmp_path: Path) -> None:
    connection = ScenarioConnection(checkpoint_prompt=True)
    executor, audit = _executor(tmp_path, connection)
    report = executor.execute(_plan(), dry_run=False, confirm=lambda _: True)
    audit.close()
    assert report.status is ResultStatus.APPLIED
    assert "" in connection.timing


def test_checkpoint_failure_blocks_configuration(tmp_path: Path) -> None:
    connection = ScenarioConnection(checkpoint_failure=True)
    executor, audit = _executor(tmp_path, connection)
    report = executor.execute(_plan(), dry_run=False, confirm=lambda _: True)
    audit.close()
    assert report.status is ResultStatus.FAILED
    assert connection.config_calls == 0
    assert report.results[0].errors


def test_failed_postcheck_triggers_rollback(tmp_path: Path) -> None:
    connection = ScenarioConnection(postcheck_error=True)
    executor, audit = _executor(tmp_path, connection)
    report = executor.execute(_plan(), dry_run=False, confirm=lambda _: True)
    audit.close()
    assert report.status is ResultStatus.ROLLED_BACK
    assert report.rolled_back


def test_rollback_can_be_declined(tmp_path: Path) -> None:
    connection = ScenarioConnection(config_output="% Invalid input detected at '^' marker.")
    executor, audit = _executor(tmp_path, connection)
    answers = iter((True, False))
    report = executor.execute(_plan(), dry_run=False, confirm=lambda _: next(answers))
    audit.close()
    assert report.status is ResultStatus.FAILED
    assert not report.rolled_back


def test_transport_exception_is_saved_as_command_error(tmp_path: Path) -> None:
    connection = ScenarioConnection(config_exception=RuntimeError("transport closed"))
    executor, audit = _executor(tmp_path, connection)
    report = executor.execute(_plan(), dry_run=False, confirm=lambda _: True)
    audit.close()
    assert report.status is ResultStatus.ROLLED_BACK
    assert "transport closed" in report.results[0].errors[0]


@pytest.mark.parametrize(
    ("prompt", "answers", "expected"),
    [
        ("How many bits in the modulus [512]:", (True,), ("2048",)),
        ("Replace existing keys? [yes/no]", (True, True), ("yes",)),
    ],
)
def test_interactive_rsa_prompts_are_handled(
    tmp_path: Path,
    prompt: str,
    answers: tuple[bool, ...],
    expected: tuple[str, ...],
) -> None:
    connection = ScenarioConnection(rsa_prompt=prompt)
    executor, audit = _executor(tmp_path, connection)
    confirmations = iter(answers)
    report = executor.execute(_plan(interactive=True), dry_run=False, confirm=lambda _: next(confirmations))
    audit.close()
    assert report.status is ResultStatus.APPLIED
    assert all(item in connection.timing for item in expected)


def test_rsa_replacement_can_be_rejected(tmp_path: Path) -> None:
    connection = ScenarioConnection(rsa_prompt="Replace existing keys? [yes/no]")
    executor, audit = _executor(tmp_path, connection)
    answers = iter((True, False, True))
    report = executor.execute(_plan(interactive=True), dry_run=False, confirm=lambda _: next(answers))
    audit.close()
    assert report.status is ResultStatus.ROLLED_BACK
    assert "yes" not in connection.timing
