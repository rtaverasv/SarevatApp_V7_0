from __future__ import annotations

from typing import Any

from sarevat.juniper.discovery import (
    discover_device,
    parse_interfaces_terse,
    parse_vlans,
)
from sarevat.models import NetworkPlatform

VERSION = """Hostname: EX2200-LAB
Model: ex2200-24t-4g
Junos: 12.3R12.4
Serial Number: AB1234
"""
INTERFACES = """Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/1                up    down
vlan.0                  up    up   inet     192.0.2.10/24
"""
VLANS = """Name                             Tag          Interfaces
USUARIOS                         10           ge-0/0/0.0
default-switch                   1
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
    assert interfaces["vlan.0"].ip_address == "192.0.2.10"
    assert parse_vlans(VLANS) == {10: "USUARIOS", 1: "default-switch"}


def test_junos_discovery_is_read_only_and_does_not_request_configuration() -> None:
    facts = discover_device(Connection())
    assert facts.platform is NetworkPlatform.JUNIPER_JUNOS
    assert facts.hostname == "EX2200-LAB"
    assert facts.model == "ex2200-24t-4g"
    assert facts.version == "12.3R12.4"
    assert "read_only_inventory" in facts.capabilities
    assert facts.running_config == ""
