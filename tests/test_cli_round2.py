from __future__ import annotations

import runpy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sarevat import cli
from sarevat.logging_utils import AuditLogger
from sarevat.models import (
    CommandPlan,
    CommandResult,
    DeviceFacts,
    DeviceKind,
    ExecutionReport,
    InterfaceState,
    ResultStatus,
)
from sarevat.scanner import HostResult, PortResult, PortState
from sarevat.validators import ValidationError


def _paths(tmp_path: Path) -> cli.AppPaths:
    return cli.AppPaths.create(tmp_path / "runtime")


def _facts(*, warnings: bool = False) -> DeviceFacts:
    return DeviceFacts(
        hostname="LAB",
        model="C8000V",
        version="17.12",
        serial="SIM1",
        interfaces={
            "GigabitEthernet0/0": InterfaceState("GigabitEthernet0/0", "10.0.0.1", "up", "up"),
            "GigabitEthernet0/1": InterfaceState("GigabitEthernet0/1", None, "down", "down"),
        },
        capabilities={"routing"},
        trunks={"GigabitEthernet0/2"},
        warnings=["show vlan: denied"] if warnings else [],
    )


def _report(status: ResultStatus, *, with_details: bool = False) -> ExecutionReport:
    report = ExecutionReport(
        "test", status, status is ResultStatus.PLANNED, datetime.now(UTC), message="mensaje"
    )
    if with_details:
        report.backup_path = Path("C:/tmp/backup.cfg")
        report.checkpoint = "sarevat_test.cfg"
        report.results.append(CommandResult("test", "", False, ("% Invalid input",)))
    return report


def test_confirm_yes_and_report_preview_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("builtins.input", lambda _: "CONFIRMAR")
    assert cli._confirm("riesgo")
    monkeypatch.setattr("builtins.input", lambda _: "no")
    assert not cli._yes("continuar")
    plan = CommandPlan("SNMP", "snmp", ("snmp-server community TOPSECRET RO",), warnings=("capacidad",))
    cli._preview_plan(plan)
    cli._print_report(_report(ResultStatus.FAILED, with_details=True))
    output = capsys.readouterr().out
    assert "TOPSECRET" not in output
    assert "Checkpoint" in output
    assert "Errores IOS" in output


def test_execute_interactive_cancel_and_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    class FakeExecutor:
        def execute(self, _plan: CommandPlan, **kwargs: Any) -> ExecutionReport:
            calls.append(kwargs)
            return _report(ResultStatus.PLANNED if kwargs.get("dry_run") else ResultStatus.APPLIED)

    plan = CommandPlan("test", "test", ("description test",))
    monkeypatch.setattr(cli, "_yes", lambda _: False)
    cli._execute_interactive(FakeExecutor(), plan)  # type: ignore[arg-type]
    assert len(calls) == 1
    monkeypatch.setattr(cli, "_yes", lambda _: True)
    cli._execute_interactive(FakeExecutor(), plan)  # type: ignore[arg-type]
    assert len(calls) == 3
    assert calls[-1]["rollback_on_error"]


def test_collect_service_data_and_show_facts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = iter(["192.0.2.20"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert cli._collect_service_data("ntp") == {"server": "192.0.2.20"}
    monkeypatch.setattr("getpass.getpass", lambda _: "COMMUNITY")
    assert cli._collect_service_data("snmp") == {"community": "COMMUNITY"}
    cli._show_facts(_facts(warnings=True))
    output = capsys.readouterr().out
    assert "LAB" in output and "Consultas no disponibles" in output


def test_service_menu_invalid_then_validation_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = iter(["invalid", "1", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(cli, "_collect_service_data", lambda _: {})
    monkeypatch.setattr(cli, "build_service_plan", lambda *_: (_ for _ in ()).throw(ValidationError("bad")))
    cli._service_menu(object(), _facts(), DeviceKind.ROUTER)  # type: ignore[arg-type]
    assert "Seleccion invalida" in capsys.readouterr().out


def test_free_console_normal_error_and_danger_cancel(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class Console:
        def find_prompt(self) -> str:
            return "R1#"

        def send_command_timing(self, command: str, **_: Any) -> str:
            return "% Invalid input detected" if command == "bad" else "OK"

    answers = iter(["", "reload", "bad", "salir"])
    confirmations = iter([False])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(cli, "_confirm", lambda *_args, **_kwargs: next(confirmations))
    audit = AuditLogger(tmp_path / "logs")
    cli._free_console(Console(), audit)
    audit.close()
    content = audit.path.read_text(encoding="utf-8")
    assert "free_command_cancelled" in content
    assert "free_command" in content


def test_device_vlsm_builds_interface_plans(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter(["192.0.2.0/24", "GigabitEthernet0/1", "10", "lan", ""])
    seen: list[CommandPlan] = []
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(cli, "_execute_interactive", lambda _executor, plan: seen.append(plan))
    cli._device_vlsm(object(), _facts())  # type: ignore[arg-type]
    assert len(seen) == 1
    assert seen[0].service == "interface_ipv4"


def test_standalone_vlsm_export_and_validation_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    answers = iter(["192.0.2.0/24", "", "LAN", "10", "lan", "first", "", "si"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    cli._standalone_vlsm(paths)
    assert list(paths.reports.glob("vlsm_*.json"))
    answers = iter(["bad", "", ""])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    cli._standalone_vlsm(paths)


def test_scanner_menu_ping_ports_and_validation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    monkeypatch.setattr(cli, "_confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        cli, "ping_sweep", lambda *_args, **_kwargs: [HostResult("192.0.2.1", True, "r1", "aa:bb")]
    )
    answers = iter(["1", "192.0.2.0/30", "si", "si", "si"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    cli._scanner_menu(paths)
    assert list(paths.reports.glob("scan_*.json"))

    monkeypatch.setattr(
        cli, "scan_tcp_ports", lambda *_args, **_kwargs: [PortResult("192.0.2.1", 22, "SSH", PortState.OPEN)]
    )
    answers = iter(["2", "192.0.2.1", "no"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    cli._scanner_menu(paths)

    answers = iter(["1", "not-a-network"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    cli._scanner_menu(paths)


def test_scanner_menu_declined_and_unknown_choice(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    monkeypatch.setattr(cli, "_confirm", lambda *_args, **_kwargs: False)
    cli._scanner_menu(paths)
    monkeypatch.setattr(cli, "_confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("builtins.input", lambda _: "9")
    cli._scanner_menu(paths)


def test_connect_invalid_and_error_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    audit = AuditLogger(paths.logs)
    answers = iter(["1", "invalid"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    cli._connect(paths, audit)
    answers = iter(["9", "router"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    cli._connect(paths, audit)

    answers = iter(["2", "switch", "COM99", "not-a-number"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    cli._connect(paths, audit)

    answers = iter(["1", "router", "192.0.2.1", "admin"])
    passwords = iter(["p", "s"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    monkeypatch.setattr(
        "sarevat.cli.ConnectHandler", lambda **_: (_ for _ in ()).throw(OSError("unreachable"))
    )
    cli._connect(paths, audit)
    audit.close()
    assert "connection_failed" in audit.path.read_text(encoding="utf-8")


def test_connect_enable_authentication_and_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    audit = AuditLogger(paths.logs)

    class EnableConnection:
        def __enter__(self) -> EnableConnection:
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def check_enable_mode(self) -> bool:
            return False

        def enable(self) -> None:
            self.enabled = True

    holder = EnableConnection()
    answers = iter(["1", "router", "192.0.2.1", "admin"])
    passwords = iter(["p", "enable"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    monkeypatch.setattr("sarevat.cli.ConnectHandler", lambda **_: holder)
    monkeypatch.setattr(cli, "_device_session", lambda *_: None)
    cli._connect(paths, audit)
    assert holder.enabled

    for exception in (cli.NetmikoAuthenticationException("bad"), cli.NetmikoTimeoutException("late")):
        answers = iter(["1", "router", "192.0.2.1", "admin"])
        passwords = iter(["p", "enable"])
        monkeypatch.setattr("builtins.input", lambda _, values=answers: next(values))
        monkeypatch.setattr("getpass.getpass", lambda _, values=passwords: next(values))
        monkeypatch.setattr(
            "sarevat.cli.ConnectHandler", lambda error=exception, **_: (_ for _ in ()).throw(error)
        )
        cli._connect(paths, audit)
    audit.close()


def test_service_menu_dependency_success_and_generic_error(monkeypatch: pytest.MonkeyPatch) -> None:
    facts = _facts()
    dependency_index = next(
        index
        for index, (service, _spec) in enumerate(
            [(key, spec) for key, spec in cli.SERVICE_CATALOG.items() if DeviceKind.SWITCH in spec.devices], 1
        )
        if service == "dai"
    )
    answers = iter([str(dependency_index), "0"])
    plans: list[str] = []
    discovered = iter(
        (
            DeviceFacts(running_config="ip dhcp snooping\n"),
            DeviceFacts(running_config="ip dhcp snooping\n"),
        )
    )
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(cli, "_collect_service_data", lambda service: {"service": service})
    monkeypatch.setattr(
        cli,
        "build_service_plan",
        lambda service, *_args: CommandPlan(service, service, ("description test",)),
    )
    monkeypatch.setattr(cli, "_execute_interactive", lambda _executor, plan: plans.append(plan.service))
    monkeypatch.setattr(cli, "discover_device", lambda _connection: next(discovered))
    cli._service_menu(type("Executor", (), {"connection": object()})(), facts, DeviceKind.SWITCH)
    assert plans == ["dhcp_snooping", "dai"]

    answers = iter(["1", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(
        cli, "build_service_plan", lambda *_: (_ for _ in ()).throw(RuntimeError("unexpected"))
    )
    cli._service_menu(object(), facts, DeviceKind.SWITCH)  # type: ignore[arg-type]


def test_service_menu_dependency_not_confirmed_and_regular_success(monkeypatch: pytest.MonkeyPatch) -> None:
    facts = _facts()
    dai_index = next(
        index
        for index, (service, _spec) in enumerate(
            [(key, spec) for key, spec in cli.SERVICE_CATALOG.items() if DeviceKind.SWITCH in spec.devices], 1
        )
        if service == "dai"
    )
    answers = iter([str(dai_index), "0"])
    plans: list[str] = []
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(cli, "_collect_service_data", lambda service: {"service": service})
    monkeypatch.setattr(
        cli,
        "build_service_plan",
        lambda service, *_args: CommandPlan(service, service, ("description test",)),
    )
    monkeypatch.setattr(cli, "_execute_interactive", lambda _executor, plan: plans.append(plan.service))
    monkeypatch.setattr(cli, "discover_device", lambda _connection: DeviceFacts())
    cli._service_menu(type("Executor", (), {"connection": object()})(), facts, DeviceKind.SWITCH)
    assert plans == ["dhcp_snooping"]

    ntp_index = next(
        index
        for index, (service, _spec) in enumerate(
            [(key, spec) for key, spec in cli.SERVICE_CATALOG.items() if DeviceKind.ROUTER in spec.devices], 1
        )
        if service == "ntp"
    )
    answers = iter([str(ntp_index), "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(cli, "discover_device", lambda _connection: facts)
    cli._service_menu(type("Executor", (), {"connection": object()})(), facts, DeviceKind.ROUTER)
    assert plans[-1] == "ntp"


def test_device_session_all_menu_actions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class Connection:
        def send_command_timing(self, command: str, **_: Any) -> str:
            return "OK"

    paths = _paths(tmp_path)
    audit = AuditLogger(paths.logs)
    answers = iter(["1", "2", "3", "4", "5", "R1", "lab.local", "admin", "2048", "6", "7", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _: "Password123")
    monkeypatch.setattr(cli, "discover_device", lambda _: _facts())
    monkeypatch.setattr(cli, "_show_facts", lambda _facts: None)
    monkeypatch.setattr(cli, "_service_menu", lambda *_: None)
    monkeypatch.setattr(cli, "_device_vlsm", lambda *_: None)
    monkeypatch.setattr(cli, "_free_console", lambda *_: None)
    monkeypatch.setattr(cli, "_execute_interactive", lambda *_: None)
    monkeypatch.setattr(cli, "_confirm", lambda *_args, **_kwargs: True)
    cli._device_session(Connection(), DeviceKind.ROUTER, paths, audit)
    audit.close()
    assert "write_memory" in audit.path.read_text(encoding="utf-8")


def test_device_session_handles_vlsm_and_initial_setup_validation_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Connection:
        def send_command_timing(self, _command: str, **_: Any) -> str:
            return "OK"

    paths = _paths(tmp_path)
    audit = AuditLogger(paths.logs)
    answers = iter(["3", "5", "R1", "lab.local", "admin", "2048", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _: "Password123")
    monkeypatch.setattr(cli, "discover_device", lambda _: _facts())
    monkeypatch.setattr(cli, "_device_vlsm", lambda *_: (_ for _ in ()).throw(ValidationError("bad VLSM")))
    monkeypatch.setattr(
        cli, "build_initial_setup_plan", lambda _data: (_ for _ in ()).throw(ValidationError("bad RSA"))
    )
    cli._device_session(Connection(), DeviceKind.ROUTER, paths, audit)
    audit.close()


def test_serial_connection_valid_parameters(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    audit = AuditLogger(paths.logs)
    captured: dict[str, Any] = {}

    class Connection:
        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *_: object) -> None:
            pass

    answers = iter(["2", "switch", "COM99", "9600"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(
        "sarevat.cli.ConnectHandler", lambda **kwargs: captured.update(kwargs) or Connection()
    )
    monkeypatch.setattr(cli, "_device_session", lambda *_: None)
    cli._connect(paths, audit)
    audit.close()
    assert captured["serial_settings"] == {"port": "COM99", "baudrate": 9600}


def test_serial_connection_rejects_nonpositive_baudrate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    paths = _paths(tmp_path)
    audit = AuditLogger(paths.logs)
    answers = iter(["2", "switch", "COM99", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    cli._connect(paths, audit)
    audit.close()


def test_main_dispatches_every_menu_option(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    called: list[str] = []

    def temporary_paths(_cls: type[cli.AppPaths], _root: Path) -> cli.AppPaths:
        root = tmp_path / "runtime_dispatch"
        logs, backups, reports = root / "logs", root / "backups", root / "reports"
        for path in (logs, backups, reports):
            path.mkdir(parents=True, exist_ok=True)
        return cli.AppPaths(root, logs, backups, reports)

    monkeypatch.setattr(cli.AppPaths, "create", classmethod(temporary_paths))
    monkeypatch.setattr(cli, "_connect", lambda *_: called.append("connect"))
    monkeypatch.setattr(cli, "_standalone_vlsm", lambda *_: called.append("vlsm"))
    monkeypatch.setattr(cli, "_scanner_menu", lambda *_: called.append("scanner"))
    answers = iter(["1", "2", "3", "4"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert cli.main() == 0
    assert called == ["connect", "vlsm", "scanner"]


def test_entrypoint_calls_sys_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "main", lambda: 0)
    with pytest.raises(SystemExit) as raised:
        runpy.run_path("SarevatApp_V7_0.py", run_name="__main__")
    assert raised.value.code == 0


def test_cli_module_entrypoint_calls_main(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _: "4")
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(Path(cli.__file__)), run_name="__main__")
    assert raised.value.code == 0


def test_main_invalid_exit_interrupt_and_fatal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def temporary_paths(_cls: type[cli.AppPaths], _root: Path) -> cli.AppPaths:
        root = tmp_path / "runtime"
        logs, backups, reports = root / "logs", root / "backups", root / "reports"
        for path in (logs, backups, reports):
            path.mkdir(parents=True, exist_ok=True)
        return cli.AppPaths(root, logs, backups, reports)

    monkeypatch.setattr(cli.AppPaths, "create", classmethod(temporary_paths))
    answers = iter(["9", "4"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert cli.main() == 0

    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert cli.main() == 0

    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(RuntimeError("fatal")))
    assert cli.main() == 1
