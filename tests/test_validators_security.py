from __future__ import annotations

import pytest

from sarevat.security import dangerous_reasons, find_ios_errors, redact_text
from sarevat.validators import (
    ValidationError,
    parse_vlan_list,
    validate_asn,
    validate_hostname,
    validate_interface,
    validate_ipv4,
    validate_ipv4_network,
    validate_netmask,
    validate_vlan,
    validate_wildcard,
)


def test_ipv4_only_and_network_strict() -> None:
    assert str(validate_ipv4("192.0.2.1")) == "192.0.2.1"
    assert str(validate_ipv4_network("192.0.2.0/24")) == "192.0.2.0/24"
    with pytest.raises(ValidationError):
        validate_ipv4("2001:db8::1")
    with pytest.raises(ValidationError):
        validate_ipv4_network("192.0.2.1/24")


def test_cisco_identifiers() -> None:
    assert validate_hostname("SW-CORE-01") == "SW-CORE-01"
    assert validate_interface("GigabitEthernet0/1") == "GigabitEthernet0/1"
    with pytest.raises(ValidationError):
        validate_hostname("-invalido")
    with pytest.raises(ValidationError):
        validate_interface("Gi0/1; reload")
    with pytest.raises(ValidationError):
        validate_interface("NotAnInterface1")


def test_vlan_validation_and_ranges() -> None:
    assert validate_vlan(10) == 10
    assert parse_vlan_list("10,20-22") == (10, 20, 21, 22)
    with pytest.raises(ValidationError):
        validate_vlan(1002)
    with pytest.raises(ValidationError):
        parse_vlan_list("20-10")
    with pytest.raises(ValidationError):
        validate_vlan(4095)


def test_masks_wildcards_and_asn() -> None:
    assert str(validate_netmask("255.255.255.0")) == "255.255.255.0"
    assert str(validate_wildcard("0.0.0.255")) == "0.0.0.255"
    assert validate_asn(4_294_967_295) == 4_294_967_295
    with pytest.raises(ValidationError):
        validate_netmask("255.0.255.0")
    with pytest.raises(ValidationError):
        validate_wildcard("0.255.0.255")
    with pytest.raises(ValidationError):
        validate_asn(23_456)


@pytest.mark.parametrize(
    "command",
    [
        "reload",
        "do reload",
        "configure replace flash:old.cfg force",
        "copy tftp: running-config",
        "default interface Gi0/1",
        "clear ip ospf process",
        "no router ospf 1",
    ],
)
def test_dangerous_commands_are_detected(command: str) -> None:
    assert dangerous_reasons(command)


def test_no_shutdown_is_not_marked_dangerous() -> None:
    assert not dangerous_reasons("no shutdown")


def test_ios_errors_and_secret_redaction() -> None:
    output = "R1(config)# bad\n% Invalid input detected at '^' marker."
    assert find_ios_errors(output) == ("% Invalid input detected at '^' marker.",)
    text = "username admin privilege 15 secret SuperSecret\nsnmp-server community PUBLIC RO"
    redacted = redact_text(text)
    assert "SuperSecret" not in redacted
    assert "PUBLIC" not in redacted
    assert redacted.count("********") == 2
