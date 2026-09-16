from __future__ import annotations

import tkinter as tk
from types import SimpleNamespace

import pytest

from sarevat.gui import (
    SarevatGui,
    build_connection_params,
    build_vlsm_base_network,
    build_vlsm_requests,
    export_vlsm_outputs,
    format_junos_prechecks,
    inventory_overview,
    junos_lab_checkbox_acceptance,
    junos_physical_port_options,
    network_summary,
    profile_connection_target,
    widget_exists,
)
from sarevat.inventory import ConnectionProfile
from sarevat.juniper.transaction import JunosPrecheckReport
from sarevat.models import DeviceFacts, DeviceKind, InterfaceState, NetworkPlatform
from sarevat.validators import ValidationError
from sarevat.vlsm import SubnetRequest, automatic_gateway_policy, calculate_vlsm


def test_gui_ssh_connection_params_are_validated() -> None:
    params = build_connection_params("ssh", "192.0.2.10", "", "admin", "password", "enable")
    assert params["host"] == "192.0.2.10"
    assert params["password"] == "password"


def test_gui_serial_connection_can_omit_or_use_temporary_credentials() -> None:
    direct = build_connection_params("serial", "COM3", "9600")
    protected = build_connection_params("serial", "COM3", "9600", "admin", "console-password", "enable")
    assert direct == {
        "device_type": "cisco_ios_serial",
        "serial_settings": {"port": "COM3", "baudrate": 9600},
    }
    assert protected["password"] == "console-password"


def test_gui_connection_params_support_safe_ssh_detection_and_junos() -> None:
    automatic = build_connection_params(
        "ssh", "192.0.2.10", "", "admin", "password", platform=NetworkPlatform.UNKNOWN
    )
    junos = build_connection_params(
        "ssh", "192.0.2.10", "", "admin", "password", platform=NetworkPlatform.JUNIPER_JUNOS
    )
    assert automatic["device_type"] == "autodetect"
    assert junos["device_type"] == "juniper_junos"
    with pytest.raises(ValidationError, match="serial multi"):
        build_connection_params(
            "serial", "COM3", "9600", platform=NetworkPlatform.JUNIPER_JUNOS
        )


def test_junos_gui_session_has_guarded_executor(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    class Connection:
        def send_command(self, command: str, **_: object) -> str:
            return {
                "show version": "Hostname: EX2200\nModel: ex2200-24t\nJunos: 12.3R12.4",
                "show interfaces terse": "Interface Admin Link Proto Local\nge-0/0/0 up up",
                "show vlans": "Name Tag\ndefault 1",
            }[command]

        def disconnect(self) -> None:
            pass

    monkeypatch.setattr("sarevat.gui.ConnectHandler", lambda **_: Connection())
    params = build_connection_params(
        "ssh", "192.0.2.10", "", "netops", "temporary", platform=NetworkPlatform.JUNIPER_JUNOS
    )
    holder = SimpleNamespace(runtime=tmp_path)
    session = SarevatGui._open_session(holder, params, DeviceKind.SWITCH)
    try:
        assert session.platform is NetworkPlatform.JUNIPER_JUNOS
        assert session.executor is not None
        assert session.reconnect_params and session.reconnect_params["password"] == "temporary"
        assert session.facts.model == "ex2200-24t"
    finally:
        session.audit.close()


def test_gui_rejects_invalid_connection_values() -> None:
    with pytest.raises(ValidationError):
        build_connection_params("serial", "", "9600")
    with pytest.raises(ValidationError):
        build_connection_params("ssh", "not-an-ip", "", "admin", "password")


def test_gui_network_summary_uses_automatic_gateway() -> None:
    summary = network_summary("192.168.10.0/27")
    assert summary["Gateway automatico"] == "192.168.10.1"
    assert summary["Broadcast"] == "192.168.10.31"


def test_gui_vlsm_base_uses_the_separate_mask_selector() -> None:
    assert build_vlsm_base_network("10.0.0.0", "/24") == "10.0.0.0/24"
    with pytest.raises(ValidationError, match="mascara aparte"):
        build_vlsm_base_network("10.0.0.0/24", "/24")


def test_gui_vlsm_rows_report_a_missing_name_clearly() -> None:
    with pytest.raises(ValidationError, match="Subred 1: falta el nombre"):
        build_vlsm_requests([("", "10", "lan")])


def test_gui_connection_target_does_not_require_a_saved_profile() -> None:
    assert profile_connection_target(None) == ""
    ssh_profile = ConnectionProfile.create_ssh("R1", "192.0.2.10", "admin", DeviceKind.ROUTER)
    serial_profile = ConnectionProfile.create_serial("R2", "COM3", 9600, DeviceKind.SWITCH)
    assert (
        profile_connection_target(ssh_profile) == "192.0.2.10"
    )
    assert profile_connection_target(serial_profile) == "COM3"


def test_widget_exists_handles_a_destroyed_control_without_raising() -> None:
    class DestroyedWidget:
        def winfo_exists(self) -> bool:
            raise tk.TclError("invalid command name")

    assert not widget_exists(DestroyedWidget())


def test_inventory_overview_preserves_read_only_discovery_details() -> None:
    facts = DeviceFacts(
        interfaces={
            "ge-0/0/1": InterfaceState("ge-0/0/1", status="down", protocol="down"),
            "ge-0/0/0": InterfaceState("ge-0/0/0", "192.0.2.10", "up", "up"),
        },
        vlans={20: "voice", 10: "users"},
        capabilities={"interfaces", "vlans"},
        warnings=["Serial no disponible"],
    )

    assert inventory_overview(facts) == {
        "capabilities": ("interfaces", "vlans"),
        "interfaces": (
            ("ge-0/0/0", "192.0.2.10", "up", "up"),
            ("ge-0/0/1", "-", "down", "down"),
        ),
        "vlans": (("10", "users"), ("20", "voice")),
        "warnings": ("Serial no disponible",),
    }


def test_gui_formats_junos_prechecks_without_configuration_output() -> None:
    report = JunosPrecheckReport(
        outputs={"show interfaces terse me0.0": "me0.0 up up inet 192.168.1.50/24"},
        errors=(),
    )

    text = format_junos_prechecks(report)

    assert "SOLO LECTURA" in text
    assert "aprobado" in text
    assert "show interfaces terse me0.0" in text


def test_junos_lab_checkbox_requires_an_explicit_selection() -> None:
    assert junos_lab_checkbox_acceptance(False) is None
    assert junos_lab_checkbox_acceptance(True) == "JUNOS_LAB_APLICAR"


def test_junos_physical_port_options_accepts_unit_zero_inventory() -> None:
    facts = DeviceFacts(
        interfaces={
            "ge-0/0/0.0": InterfaceState("ge-0/0/0.0"),
            "ge-0/0/1.1": InterfaceState("ge-0/0/1.1"),
            "xe-0/1/0": InterfaceState("xe-0/1/0"),
            "me0.0": InterfaceState("me0.0"),
        }
    )

    assert junos_physical_port_options(facts) == ("ge-0/0/0.0", "xe-0/1/0")


def test_gui_exports_vlsm_results_as_local_json_and_csv(tmp_path) -> None:
    plan = calculate_vlsm(
        "192.0.2.0/24",
        [SubnetRequest("Usuarios", 30, gateway_policy=automatic_gateway_policy("lan"))],
    )

    json_path, csv_path = export_vlsm_outputs(plan, tmp_path, stamp="20260902_122212")

    assert json_path.name == "vlsm_20260902_122212.json"
    assert csv_path.name == "vlsm_20260902_122212.csv"
    assert json_path.is_file()
    assert csv_path.is_file()
