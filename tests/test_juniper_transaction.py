from __future__ import annotations

from typing import Any

import pytest

from sarevat.juniper.services import build_management_candidate
from sarevat.juniper.transaction import find_junos_errors, run_prechecks, transaction_preview
from sarevat.models import CommandPlan, DeviceFacts, InterfaceState, NetworkPlatform


def _plan() -> CommandPlan:
    return build_management_candidate(
        {
            "hostname": "EX2200-LAB",
            "interface": "vlan.0",
            "address": "192.0.2.50",
            "netmask": "255.255.255.0",
        },
        DeviceFacts(
            platform=NetworkPlatform.JUNIPER_JUNOS,
            interfaces={"vlan.0": InterfaceState("vlan.0")},
        ),
    )


def test_junos_error_parser_and_read_only_prechecks() -> None:
    class Connection:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def send_command(self, command: str, **_: Any) -> str:
            self.commands.append(command)
            if "interfaces" in command:
                return "error: configuration database locked"
            return "host-name EX2200-LAB;"

    connection = Connection()
    report = run_prechecks(connection, _plan())

    assert not report.ok
    assert connection.commands == ["show configuration system host-name", "show interfaces terse vlan.0"]
    assert "configuration database locked" in report.errors[0]
    assert find_junos_errors("syntax error, expecting <command>;") == (
        "syntax error, expecting <command>;",
    )


def test_junos_transaction_preview_includes_confirmed_commit_and_recovery() -> None:
    steps = transaction_preview(_plan())

    assert "commit check" in steps
    assert "commit confirmed 5" in steps
    assert steps[-1].startswith("Si la verificación falla")


def test_junos_prechecks_reject_non_junos_or_enabled_plan() -> None:
    with pytest.raises(ValueError, match="juniper_junos"):
        run_prechecks(
            object(),
            CommandPlan("Cisco", "test", ("show clock",), metadata={"platform": "cisco_ios"}),
        )
