from __future__ import annotations

import pytest

from sarevat.gui import (
    build_connection_params,
    export_vlsm_outputs,
    network_summary,
    profile_connection_target,
)
from sarevat.inventory import ConnectionProfile
from sarevat.models import DeviceKind
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


def test_gui_rejects_invalid_connection_values() -> None:
    with pytest.raises(ValidationError):
        build_connection_params("serial", "", "9600")
    with pytest.raises(ValidationError):
        build_connection_params("ssh", "not-an-ip", "", "admin", "password")


def test_gui_network_summary_uses_automatic_gateway() -> None:
    summary = network_summary("192.168.10.0/27")
    assert summary["Gateway automatico"] == "192.168.10.1"
    assert summary["Broadcast"] == "192.168.10.31"


def test_gui_connection_target_does_not_require_a_saved_profile() -> None:
    assert profile_connection_target(None) == ""
    ssh_profile = ConnectionProfile.create_ssh("R1", "192.0.2.10", "admin", DeviceKind.ROUTER)
    serial_profile = ConnectionProfile.create_serial("R2", "COM3", 9600, DeviceKind.SWITCH)
    assert (
        profile_connection_target(ssh_profile) == "192.0.2.10"
    )
    assert profile_connection_target(serial_profile) == "COM3"


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
