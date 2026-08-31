from __future__ import annotations

from typing import ClassVar

import pytest

from sarevat.cisco.discovery import discover_device, parse_ip_interfaces
from sarevat.cisco.services import (
    SERVICE_CATALOG,
    build_aaa_local_plan,
    build_basic_hardening_plan,
    build_service_plan,
    build_snmpv3_plan,
    validate_plan_conflicts,
)
from sarevat.models import DeviceFacts, DeviceKind, InterfaceState
from sarevat.security import redact_command
from sarevat.validators import ValidationError


class DiscoveryConnection:
    responses: ClassVar[dict[str, object]] = {
        "show version": [
            {
                "hostname": "R1",
                "hardware": ["C8000V"],
                "version": "17.15.1",
                "serial": ["ABC123"],
            }
        ],
        "show ip interface brief": [
            {"interface": "GigabitEthernet0/0", "ip_address": "10.0.0.1", "status": "up", "proto": "up"},
            {
                "interface": "GigabitEthernet0/1",
                "ip_address": "unassigned",
                "status": "administratively down",
                "proto": "down",
            },
        ],
        "show vlan brief": "",
        "show interfaces trunk": "",
        "show etherchannel summary": "",
        "show running-config": "hostname R1\nip routing\n",
    }

    def send_command(self, command: str, **_: object) -> object:
        return self.responses[command]


def _facts() -> DeviceFacts:
    interfaces = {
        "GigabitEthernet0/0": InterfaceState("GigabitEthernet0/0", "10.0.0.1", "up", "up"),
        "GigabitEthernet0/1": InterfaceState("GigabitEthernet0/1", None, "down", "down"),
        "GigabitEthernet0/2": InterfaceState("GigabitEthernet0/2", None, "down", "down"),
        "GigabitEthernet0/3": InterfaceState("GigabitEthernet0/3", None, "down", "down"),
    }
    return DeviceFacts(
        hostname="LAB",
        interfaces=interfaces,
        capabilities={"routing", "switching", "vlan"},
        running_config="hostname LAB\n",
    )


def test_discovery_requires_up_up_for_active_l3() -> None:
    facts = discover_device(DiscoveryConnection())
    assert facts.hostname == "R1"
    assert facts.active_l3_interfaces == {"GigabitEthernet0/0"}
    assert "routing" in facts.capabilities
    down = parse_ip_interfaces(
        "Interface IP-Address OK? Method Status Protocol\n"
        "Gi0/0 10.0.0.1 YES manual administratively down down"
    )
    assert not down["Gi0/0"].l3_up


SERVICE_CASES = {
    "vlan_acceso": (DeviceKind.SWITCH, {"vlan": 10, "name": "VENTAS", "interface": "GigabitEthernet0/1"}),
    "trunk": (DeviceKind.SWITCH, {"interface": "GigabitEthernet0/1"}),
    "etherchannel": (DeviceKind.SWITCH, {"group": 1, "members": "GigabitEthernet0/1,GigabitEthernet0/2"}),
    "port_security": (DeviceKind.SWITCH, {"interface": "GigabitEthernet0/1", "maximum": 2}),
    "portfast": (DeviceKind.SWITCH, {"interface": "GigabitEthernet0/1"}),
    "dhcp_snooping": (DeviceKind.SWITCH, {"vlans": "10,20", "uplink": "GigabitEthernet0/1"}),
    "dai": (DeviceKind.SWITCH, {"vlans": "10,20"}),
    "ipsg": (DeviceKind.SWITCH, {"interface": "GigabitEthernet0/1"}),
    "span": (DeviceKind.SWITCH, {"source": "GigabitEthernet0/1", "destination": "GigabitEthernet0/2"}),
    "storm_control": (DeviceKind.SWITCH, {"interface": "GigabitEthernet0/1", "level": 10}),
    "ruta_estatica": (DeviceKind.ROUTER, {"network": "10.1.0.0/24", "next_hop": "10.0.0.2"}),
    "ospf": (
        DeviceKind.ROUTER,
        {"process": 1, "network_address": "10.0.0.0", "wildcard": "0.0.0.255", "area": 0},
    ),
    "bgp": (DeviceKind.ROUTER, {"local_as": 65001, "neighbor": "192.0.2.2", "remote_as": 65002}),
    "dhcp": (
        DeviceKind.ROUTER,
        {
            "pool": "LAN",
            "network_address": "192.168.10.0",
            "netmask": "255.255.255.0",
            "gateway": "192.168.10.1",
        },
    ),
    "dhcp_relay": (DeviceKind.ROUTER, {"interface": "GigabitEthernet0/0", "server": "192.0.2.10"}),
    "nat": (
        DeviceKind.ROUTER,
        {
            "inside": "GigabitEthernet0/0",
            "outside": "GigabitEthernet0/1",
            "acl": 1,
            "network_address": "10.0.0.0",
            "wildcard": "0.0.0.255",
        },
    ),
    "pbr": (
        DeviceKind.ROUTER,
        {
            "interface": "GigabitEthernet0/0",
            "acl": 1,
            "network_address": "10.0.0.0",
            "wildcard": "0.0.0.255",
            "next_hop": "10.0.0.2",
            "route_map": "PBR_WEB",
        },
    ),
    "hsrp": (
        DeviceKind.ROUTER,
        {
            "interface": "GigabitEthernet0/0",
            "group": 1,
            "virtual_ip": "10.0.0.254",
            "priority": 110,
            "prefix": 24,
        },
    ),
    "ntp": (DeviceKind.ROUTER, {"server": "192.0.2.20"}),
    "syslog": (DeviceKind.ROUTER, {"server": "192.0.2.30"}),
    "snmp": (DeviceKind.ROUTER, {"community": "TEST_RO"}),
    "lldp": (DeviceKind.ROUTER, {}),
    "password_encryption": (DeviceKind.ROUTER, {}),
}


@pytest.mark.parametrize("service", SERVICE_CASES)
def test_every_automatic_service_builds_a_valid_plan(service: str) -> None:
    kind, data = SERVICE_CASES[service]
    plan = build_service_plan(service, data, _facts(), kind)
    assert plan.service == service
    assert plan.commands
    assert plan.postchecks


def test_catalog_and_cases_stay_in_sync() -> None:
    assert set(SERVICE_CASES) == set(SERVICE_CATALOG)


def test_semantic_conflicts_and_invalid_nat() -> None:
    facts = _facts()
    trunk = build_service_plan("trunk", {"interface": "GigabitEthernet0/1"}, facts, DeviceKind.SWITCH)
    port_security = build_service_plan(
        "port_security",
        {"interface": "GigabitEthernet0/1", "maximum": 2},
        facts,
        DeviceKind.SWITCH,
    )
    assert validate_plan_conflicts([trunk, port_security], facts)
    with pytest.raises(ValidationError):
        build_service_plan(
            "nat",
            {
                "inside": "GigabitEthernet0/0",
                "outside": "GigabitEthernet0/0",
                "acl": 1,
                "network_address": "10.0.0.0",
                "wildcard": "0.0.0.255",
            },
            facts,
            DeviceKind.ROUTER,
        )


def test_observability_template_has_safe_commands_and_validates_ipv4() -> None:
    from sarevat.cisco.services import build_observability_template

    plan = build_observability_template("192.0.2.10", "192.0.2.20")
    assert plan.service == "observability_template"
    assert "ntp server 192.0.2.10" in plan.commands
    assert "logging host 192.0.2.20" in plan.commands
    with pytest.raises(ValidationError):
        build_observability_template("bad", "192.0.2.20")


def test_site_observability_plan_keeps_access_controls_untouched() -> None:
    from sarevat.cisco.services import build_site_observability_plan

    plan = build_site_observability_plan("nucleo", "192.0.2.10", "192.0.2.20")
    assert "service timestamps debug datetime msec" in plan.commands
    assert "AAA" in plan.warnings[0]
    with pytest.raises(ValidationError, match="sucursal o nucleo"):
        build_site_observability_plan("datacenter", "192.0.2.10", "192.0.2.20")


def test_snmpv3_plan_preserves_existing_monitoring_and_redacts_keys() -> None:
    plan = build_snmpv3_plan("MONITOR", "netops", "AuthSecret123", "PrivSecret123")
    assert plan.prechecks == ("show snmp user",)
    assert plan.warnings == ("No se eliminan comunidades ni usuarios SNMP existentes.",)
    preview = redact_command(plan.commands[1])
    assert "AuthSecret123" not in preview
    assert "PrivSecret123" not in preview


def test_aaa_local_requires_existing_user_and_console_recovery() -> None:
    facts = _facts()
    facts.running_config += "username rescue privilege 15 secret 9 hash\n"
    plan = build_aaa_local_plan("rescue", facts, True)
    assert plan.commands == ("aaa new-model", "aaa authentication login default local")
    assert plan.postcheck_expectations
    with pytest.raises(ValidationError, match="consola"):
        build_aaa_local_plan("rescue", facts, False)
    with pytest.raises(ValidationError, match="no existe"):
        build_aaa_local_plan("missing", facts, True)


def test_basic_hardening_only_adds_missing_low_risk_controls() -> None:
    facts = _facts()
    plan = build_basic_hardening_plan(facts)
    assert plan.commands == ("ip ssh version 2", "service password-encryption")
    assert "líneas VTY" in plan.warnings[0]
    facts.running_config += "ip ssh version 2\nservice password-encryption\n"
    with pytest.raises(ValidationError, match="ya están"):
        build_basic_hardening_plan(facts)
