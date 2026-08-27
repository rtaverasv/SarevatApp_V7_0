from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sarevat.cli import AppPaths, _connect
from sarevat.logging_utils import AuditLogger


class FakeCiscoConnection:
    def __enter__(self) -> FakeCiscoConnection:
        return self

    def __exit__(self, *_: object) -> None:
        pass

    def check_enable_mode(self) -> bool:
        return True

    def enable(self) -> None:
        raise AssertionError("No debe solicitar enable en este simulacro.")

    def send_command(self, command: str, **_: object) -> object:
        responses: dict[str, object] = {
            "show version": [
                {
                    "hostname": "LAB",
                    "hardware": "C8000V",
                    "version": "17.15",
                    "serial": "SIM123",
                }
            ],
            "show ip interface brief": [],
            "show vlan brief": [],
            "show interfaces trunk": [],
            "show etherchannel summary": "",
            "show running-config": "hostname LAB\n",
        }
        return responses[command]


def _run_connect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    answers: list[str],
    passwords: list[str],
) -> dict[str, Any]:
    captured: dict[str, Any] = {}
    answer_iterator = iter(answers)
    password_iterator = iter(passwords)
    monkeypatch.setattr("builtins.input", lambda _="": next(answer_iterator))
    monkeypatch.setattr("getpass.getpass", lambda _="": next(password_iterator))

    def fake_connect_handler(**params: Any) -> FakeCiscoConnection:
        captured.update(params)
        return FakeCiscoConnection()

    monkeypatch.setattr("sarevat.cli.ConnectHandler", fake_connect_handler)
    paths = AppPaths.create(tmp_path / "runtime")
    audit = AuditLogger(paths.logs)
    _connect(paths, audit)
    audit.close()
    return captured


def test_ssh_flow_uses_validated_ipv4_and_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured = _run_connect(
        monkeypatch,
        tmp_path,
        ["1", "router", "192.0.2.10", "admin", "0"],
        ["SSH_PASSWORD", "ENABLE_SECRET"],
    )
    assert captured["device_type"] == "cisco_ios"
    assert captured["host"] == "192.0.2.10"
    assert captured["username"] == "admin"
    assert captured["password"] == "SSH_PASSWORD"


def test_serial_flow_builds_netmiko_serial_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured = _run_connect(
        monkeypatch,
        tmp_path,
        ["2", "switch", "COM99", "9600", "0"],
        [],
    )
    assert captured["device_type"] == "cisco_ios_serial"
    assert captured["serial_settings"] == {"port": "COM99", "baudrate": 9600}
