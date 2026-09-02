import pytest

from sarevat.agent_runtime import AgentJobError, _build_plan, _connection_params
from sarevat.models import DeviceFacts, DeviceKind


def test_ssh_requires_temporary_credentials() -> None:
    with pytest.raises(AgentJobError):
        _connection_params({"transport": "ssh", "host": "10.0.0.1"}, {})


def test_serial_uses_positive_baudrate() -> None:
    params = _connection_params({"transport": "serial", "port": "COM3", "baudrate": 9600}, {})
    assert params["device_type"] == "cisco_ios_serial"
    assert params["serial_settings"] == {"port": "COM3", "baudrate": 9600}


def test_serial_rejects_invalid_baudrate() -> None:
    with pytest.raises(AgentJobError, match="entero"):
        _connection_params({"transport": "serial", "port": "COM3", "baudrate": "lento"}, {})


def test_unknown_transport_is_rejected() -> None:
    with pytest.raises(AgentJobError):
        _connection_params({"transport": "telnet"}, {})


def test_special_service_forms_use_original_plan_builders() -> None:
    facts = DeviceFacts(running_config="username rescue privilege 15 secret 9 hash")
    initial = _build_plan(
        "initial_setup",
        {
            "hostname": "r1",
            "domain": "example.test",
            "username": "admin",
            "password": "Secret123",
            "rsa_bits": 2048,
        },
        facts,
        DeviceKind.ROUTER,
    )
    aaa = _build_plan(
        "aaa_local",
        {"username": "rescue", "console": "CONSOLA_LISTA"},
        facts,
        DeviceKind.ROUTER,
    )
    assert initial.service == "initial_setup"
    assert aaa.service == "aaa_local"
