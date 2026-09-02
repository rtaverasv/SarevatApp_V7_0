import pytest

from sarevat.agent_runtime import AgentJobError, _connection_params


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
