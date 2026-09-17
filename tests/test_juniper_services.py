from __future__ import annotations

import pytest

from sarevat.juniper.services import (
    build_dns_candidate,
    build_existing_vlan_access_candidate,
    build_existing_vlan_trunk_candidate,
    build_management_candidate,
    build_ntp_candidate,
    build_snmpv3_candidate,
    build_ssh_hardening_candidate,
    build_syslog_candidate,
    build_vlan_access_candidate,
    preferred_management_interface,
)
from sarevat.models import DeviceFacts, InterfaceState, NetworkPlatform
from sarevat.validators import ValidationError


def _facts() -> DeviceFacts:
    return DeviceFacts(
        platform=NetworkPlatform.JUNIPER_JUNOS,
        interfaces={
            "ge-0/0/0": InterfaceState("ge-0/0/0"),
            "me0.0": InterfaceState("me0.0", "192.168.1.50"),
            "vlan.0": InterfaceState("vlan.0", "192.0.2.10"),
        },
    )


def test_junos_management_candidate_is_validated_and_preview_only() -> None:
    plan = build_management_candidate(
        {
            "hostname": "EX2200-LAB",
            "interface": "vlan.0",
            "address": "192.0.2.50",
            "netmask": "255.255.255.0",
        },
        _facts(),
    )

    assert plan.commands == (
        "set system host-name EX2200-LAB",
        "set interfaces vlan unit 0 family inet address 192.0.2.50/24",
    )


def test_junos_ssh_hardening_candidate_is_conservative() -> None:
    plan = build_ssh_hardening_candidate(
        {"connection_limit": "10", "rate_limit": "20"}, _facts(), "192.168.1.50"
    )
    assert plan.commands == (
        "set system services ssh protocol-version v2",
        "set system services ssh connection-limit 10",
        "set system services ssh rate-limit 20",
    )
    with pytest.raises(ValidationError, match="entre 1 y 250"):
        build_ssh_hardening_candidate(
            {"connection_limit": "0", "rate_limit": "20"}, _facts(), "192.168.1.50"
        )
    assert plan.metadata["preview_only"] is True
    assert "commit confirmed 5" in plan.metadata["manual_workflow"]


def test_junos_management_candidate_supports_and_prefers_me0() -> None:
    facts = _facts()
    plan = build_management_candidate(
        {
            "hostname": "Admin",
            "interface": "me0.0",
            "address": "192.168.1.60",
            "netmask": "255.255.255.0",
        },
        facts,
    )

    assert preferred_management_interface(facts) == "me0.0"
    assert plan.commands[-1] == "set interfaces me0 unit 0 family inet address 192.168.1.60/24"


def test_junos_management_candidate_rejects_an_interface_not_discovered() -> None:
    with pytest.raises(ValidationError, match="inventario descubierto"):
        build_management_candidate(
            {
                "hostname": "EX2200-LAB",
                "interface": "ge-0/0/47",
                "address": "192.0.2.50",
                "netmask": "255.255.255.0",
            },
            _facts(),
        )


def test_junos_ntp_candidate_verifies_the_server_from_a_second_session() -> None:
    plan = build_ntp_candidate({"server": "192.0.2.123"}, _facts(), "192.168.1.50")

    check = "show configuration system ntp | display set"
    assert plan.commands == ("set system ntp server 192.0.2.123",)
    assert plan.prechecks == (check, "show system uptime")
    assert plan.postchecks == (check,)
    assert plan.postcheck_expectations[check] == ("set system ntp server 192.0.2.123",)
    assert plan.metadata["management_address"] == "192.168.1.50"


def test_junos_ntp_candidate_rejects_an_invalid_server() -> None:
    with pytest.raises(ValidationError):
        build_ntp_candidate({"server": "no-es-ip"}, _facts(), "192.168.1.50")


def test_junos_syslog_candidate_adds_notice_collector_and_verifies_it() -> None:
    plan = build_syslog_candidate({"server": "192.0.2.200"}, _facts(), "192.168.1.50")

    check = "show configuration system syslog | display set"
    command = "set system syslog host 192.0.2.200 any notice"
    assert plan.commands == (command,)
    assert plan.prechecks == (check,)
    assert plan.postcheck_expectations[check] == (command,)


def test_junos_syslog_candidate_rejects_an_invalid_collector() -> None:
    with pytest.raises(ValidationError):
        build_syslog_candidate({"server": "collector.local"}, _facts(), "192.168.1.50")


def test_junos_dns_candidate_adds_one_or_two_distinct_servers() -> None:
    plan = build_dns_candidate(
        {"primary": "192.0.2.53", "secondary": "192.0.2.54"}, _facts(), "192.168.1.50"
    )

    assert plan.commands == (
        "set system name-server 192.0.2.53",
        "set system name-server 192.0.2.54",
    )
    assert plan.postcheck_expectations["show configuration system name-server | display set"] == plan.commands


def test_junos_dns_candidate_rejects_duplicate_or_invalid_servers() -> None:
    with pytest.raises(ValidationError, match="diferentes"):
        build_dns_candidate(
            {"primary": "192.0.2.53", "secondary": "192.0.2.53"}, _facts(), "192.168.1.50"
        )
    with pytest.raises(ValidationError):
        build_dns_candidate({"primary": "dns.local"}, _facts(), "192.168.1.50")


def test_junos_snmpv3_candidate_is_authpriv_and_requires_an_engine_id() -> None:
    plan = build_snmpv3_candidate(
        {
            "group": "MONITOR",
            "username": "netops",
            "auth_password": "AuthSecret8",
            "privacy_password": "PrivSecret8",
        },
        _facts(),
        "192.168.1.50",
    )

    engine_check = "show configuration snmp engine-id | display set"
    assert "set snmp view sarevat-ro oid .1 include" in plan.commands
    assert "security-level privacy read-view sarevat-ro" in "\n".join(plan.commands)
    assert plan.metadata["precheck_expectations"] == {engine_check: ("set snmp engine-id",)}
    assert "AuthSecret8" in "\n".join(plan.commands)


def test_junos_snmpv3_candidate_rejects_short_or_unsafe_secrets() -> None:
    data = {
        "group": "MONITOR",
        "username": "netops",
        "auth_password": "short",
        "privacy_password": "PrivSecret8",
    }
    with pytest.raises(ValidationError, match="entre 8"):
        build_snmpv3_candidate(data, _facts(), "192.168.1.50")


def test_junos_vlan_access_candidate_is_limited_to_new_vlan_and_physical_port() -> None:
    plan = build_vlan_access_candidate(
        {"vlan_name": "USERS", "vlan_id": "20", "interface": "ge-0/0/0"},
        _facts(),
        "192.0.2.10",
    )

    assert plan.commands == (
        "set vlans USERS vlan-id 20",
        "set interfaces ge-0/0/0 unit 0 family ethernet-switching port-mode access",
        "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members USERS",
    )
    assert plan.metadata["management_address"] == "192.0.2.10"
    port_check = "show configuration interfaces ge-0/0/0 | display set"
    assert plan.postchecks == ("show vlans", port_check)
    assert plan.postcheck_expectations["show vlans"] == ("USERS", "20")
    assert plan.postcheck_expectations[port_check] == ("vlan members USERS",)


def test_junos_vlan_access_candidate_rejects_existing_vlan_and_management_port() -> None:
    facts = _facts()
    facts.vlans[20] = "USERS"
    with pytest.raises(ValidationError, match="ya existe"):
        build_vlan_access_candidate(
            {"vlan_name": "USERS", "vlan_id": "20", "interface": "ge-0/0/0"}, facts, "192.0.2.10"
        )
    with pytest.raises(ValidationError, match="puerto fisico"):
        build_vlan_access_candidate(
            {"vlan_name": "VOICE", "vlan_id": "30", "interface": "me0.0"}, _facts(), "192.0.2.10"
        )


def test_junos_existing_vlan_access_candidate_reuses_discovered_vlan_only() -> None:
    facts = _facts()
    facts.vlans[20] = "USERS"
    plan = build_existing_vlan_access_candidate(
        {"vlan_name": "USERS", "interface": "ge-0/0/0"}, facts, "192.0.2.10"
    )

    assert plan.commands == (
        "set interfaces ge-0/0/0 unit 0 family ethernet-switching port-mode access",
        "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members USERS",
    )
    assert "set vlans" not in "\n".join(plan.commands)


def test_junos_existing_vlan_access_candidate_rejects_unknown_vlan() -> None:
    with pytest.raises(ValidationError, match="VLAN existente"):
        build_existing_vlan_access_candidate(
            {"vlan_name": "USERS", "interface": "ge-0/0/0"}, _facts(), "192.0.2.10"
        )


def test_junos_existing_vlan_trunk_candidate_adds_member_without_creating_vlan() -> None:
    facts = _facts()
    facts.vlans[20] = "USERS"
    plan = build_existing_vlan_trunk_candidate(
        {"vlan_name": "USERS", "interface": "ge-0/0/0"}, facts, "192.0.2.10"
    )

    assert plan.commands == (
        "set interfaces ge-0/0/0 unit 0 family ethernet-switching port-mode trunk",
        "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members USERS",
    )
    assert "set vlans" not in "\n".join(plan.commands)
    assert "show configuration interfaces ge-0/0/0 | display set" in plan.postchecks
