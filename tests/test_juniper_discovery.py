from __future__ import annotations

from typing import Any

from sarevat.juniper.discovery import (
    discover_device,
    parse_interfaces_terse,
    parse_vlan_interfaces,
    parse_vlans,
)
from sarevat.models import NetworkPlatform

VERSION = """Hostname: EX2200-LAB
Model: ex2200-24t-4g
Junos: 12.3R12.4
Serial Number: AB1234
"""
EX2200_VERSION = """Hostname: Admin
Model: ex2200-24p-4g
JUNOS Base OS boot [12.3R12.4]
JUNOS Base OS Software Suite [12.3R12.4]
"""
INTERFACES = """Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/1                up    down
me0.0                   up    up   inet     192.168.1.50/24
vlan.0                  up    up   inet     192.0.2.10/24
"""
MULTI_ADDRESS_INTERFACES = """Interface               Admin Link Proto    Local                 Remote
me0.0                   up    up   inet     192.168.1.50/24
me0.0                   up    up   inet     192.168.1.60/24
"""
VLANS = """Name                             Tag          Interfaces
USUARIOS                         10           ge-0/0/0.0
default-switch                   1            ge-0/0/1.0, ge-0/0/2.0
"""


class Connection:
    def send_command(self, command: str, **_: Any) -> str:
        return {
            "show version": VERSION,
            "show interfaces terse": INTERFACES,
            "show vlans": VLANS,
        }[command]


def test_junos_parsers_normalize_interfaces_and_vlans() -> None:
    interfaces = parse_interfaces_terse(INTERFACES)
    assert interfaces["ge-0/0/0"].l3_up is False
    assert interfaces["me0.0"].ip_address == "192.168.1.50"
    assert interfaces["vlan.0"].ip_address == "192.0.2.10"
    assert parse_vlans(VLANS) == {10: "USUARIOS", 1: "default-switch"}
    assert parse_vlan_interfaces(VLANS) == ("ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0")


def test_junos_parser_retains_all_ipv4_addresses_on_one_interface() -> None:
    interface = parse_interfaces_terse(MULTI_ADDRESS_INTERFACES)["me0.0"]

    assert interface.ip_address == "192.168.1.50"
    assert interface.ip_addresses == ("192.168.1.50", "192.168.1.60")


def test_junos_discovery_is_read_only_and_does_not_request_configuration() -> None:
    facts = discover_device(Connection())
    assert facts.platform is NetworkPlatform.JUNIPER_JUNOS
    assert facts.hostname == "EX2200-LAB"
    assert facts.model == "ex2200-24t-4g"
    assert facts.version == "12.3R12.4"
    assert "read_only_inventory" in facts.capabilities
    assert facts.running_config == ""
    assert facts.interfaces["ge-0/0/2.0"].status == "unknown"


def test_junos_parser_supports_ex2200_bracketed_version_output() -> None:
    class Ex2200Connection(Connection):
        def send_command(self, command: str, **_: Any) -> str:
            if command == "show version":
                return EX2200_VERSION
            return super().send_command(command)

    facts = discover_device(Ex2200Connection())
    assert facts.hostname == "Admin"
    assert facts.model == "ex2200-24p-4g"
    assert facts.version == "12.3R12.4"
