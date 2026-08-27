from __future__ import annotations

import pytest

from sarevat.cisco.services import (
    build_initial_setup_plan,
    build_interface_ip_plan,
    build_service_plan,
    service_is_configured,
    validate_plan_conflicts,
)
from sarevat.models import DeviceFacts, DeviceKind, InterfaceState
from sarevat.validators import ValidationError


def _facts(*, active: bool = True, running_config: str = "") -> DeviceFacts:
    status = "up" if active else "down"
    protocol = "up" if active else "down"
    return DeviceFacts(
        interfaces={
            "GigabitEthernet0/0": InterfaceState("GigabitEthernet0/0", "10.0.0.1", status, protocol),
            "GigabitEthernet0/1": InterfaceState("GigabitEthernet0/1", None, "down", "down"),
            "GigabitEthernet0/2": InterfaceState("GigabitEthernet0/2", None, "down", "down"),
        },
        capabilities=set(),
        running_config=running_config,
    )


def test_unknown_service_wrong_device_missing_data_and_l3_requirement() -> None:
    facts = _facts(active=False)
    with pytest.raises(ValidationError):
        build_service_plan("missing", {}, facts, DeviceKind.ROUTER)
    with pytest.raises(ValidationError):
        build_service_plan("ospf", {}, facts, DeviceKind.SWITCH)
    with pytest.raises(ValidationError):
        build_service_plan("ntp", {}, facts, DeviceKind.ROUTER)
    with pytest.raises(ValidationError):
        build_service_plan(
            "ospf",
            {"process": 1, "network_address": "10.0.0.0", "wildcard": "0.0.0.255", "area": 0},
            facts,
            DeviceKind.ROUTER,
        )


def test_service_capability_warning_and_existing_config_idempotency() -> None:
    facts = _facts()
    plan = build_service_plan(
        "ospf",
        {"process": 1, "network_address": "10.0.0.0", "wildcard": "0.0.0.255", "area": 0},
        facts,
        DeviceKind.ROUTER,
    )
    assert plan.warnings
    existing = _facts(running_config="lldp run\n")
    assert service_is_configured("lldp", existing)
    with pytest.raises(ValidationError):
        build_service_plan("lldp", {}, existing, DeviceKind.ROUTER)


def test_trunk_dot1q_and_etherchannel_duplicate_member_rejected() -> None:
    facts = _facts()
    plan = build_service_plan(
        "trunk",
        {"interface": "GigabitEthernet0/1", "requires_dot1q": True},
        facts,
        DeviceKind.SWITCH,
    )
    assert "switchport trunk encapsulation dot1q" in plan.commands
    with pytest.raises(ValidationError):
        build_service_plan(
            "etherchannel",
            {"group": 1, "members": "GigabitEthernet0/1,GigabitEthernet0/1"},
            facts,
            DeviceKind.SWITCH,
        )


def test_span_dhcp_hsrp_and_initial_setup_validation() -> None:
    facts = _facts()
    with pytest.raises(ValidationError):
        build_service_plan(
            "span",
            {"source": "GigabitEthernet0/1", "destination": "GigabitEthernet0/1"},
            facts,
            DeviceKind.SWITCH,
        )
    with pytest.raises(ValidationError):
        build_service_plan(
            "dhcp",
            {
                "pool": "LAN",
                "network_address": "192.168.1.0",
                "netmask": "255.255.255.0",
                "gateway": "192.168.2.1",
            },
            facts,
            DeviceKind.ROUTER,
        )
    with pytest.raises(ValidationError):
        build_service_plan(
            "hsrp",
            {"interface": "GigabitEthernet0/0", "group": 1, "virtual_ip": "10.0.1.254", "priority": 110},
            facts,
            DeviceKind.ROUTER,
        )
    with pytest.raises(ValidationError):
        build_initial_setup_plan(
            {
                "hostname": "R1",
                "domain": "lab.local",
                "username": "admin",
                "password": "secret",
                "rsa_bits": 1024,
            }
        )


def test_interface_ip_plan_accepts_valid_values_and_rejects_unknown_interface() -> None:
    facts = _facts()
    plan = build_interface_ip_plan("GigabitEthernet0/1", "192.0.2.1", "255.255.255.0", facts)
    assert plan.interfaces == {"GigabitEthernet0/1"}
    with pytest.raises(ValidationError):
        build_interface_ip_plan("GigabitEthernet0/9", "192.0.2.1", "255.255.255.0", facts)


def test_integer_bgp_and_span_etherchannel_conflicts() -> None:
    facts = _facts()
    with pytest.raises(ValidationError):
        build_service_plan(
            "storm_control", {"interface": "GigabitEthernet0/1", "level": "bad"}, facts, DeviceKind.SWITCH
        )
    with pytest.raises(ValidationError):
        build_service_plan(
            "storm_control", {"interface": "GigabitEthernet0/1", "level": 101}, facts, DeviceKind.SWITCH
        )
    with pytest.raises(ValidationError):
        build_service_plan(
            "bgp", {"local_as": 65001, "neighbor": "192.0.2.2", "remote_as": 65001}, facts, DeviceKind.ROUTER
        )
    span = build_service_plan(
        "span",
        {"source": "GigabitEthernet0/1", "destination": "GigabitEthernet0/2"},
        facts,
        DeviceKind.SWITCH,
    )
    etherchannel = build_service_plan(
        "etherchannel",
        {"group": 1, "members": "GigabitEthernet0/1,GigabitEthernet0/2"},
        facts,
        DeviceKind.SWITCH,
    )
    assert validate_plan_conflicts([span, etherchannel], facts)
