from __future__ import annotations

from typing import Any

from sarevat.cisco.discovery import (
    _parse_show_version,
    discover_device,
    parse_ip_interfaces,
    parse_trunks,
    parse_vlans,
)


def test_text_parsers_handle_raw_ios_outputs_and_malformed_rows() -> None:
    interfaces = parse_ip_interfaces(
        "Interface IP-Address OK? Method Status Protocol\n"
        "Gi0/0 192.0.2.1 YES manual up up\n"
        "esta linea no tiene suficientes columnas\n"
    )
    assert interfaces["Gi0/0"].l3_up
    assert parse_ip_interfaces("Gi0/0 incomplete") == {}
    assert parse_vlans("10 USERS active\n20 SERVERS active\ntexto") == {10: "USERS", 20: "SERVERS"}
    assert parse_trunks("Gi0/1 on 802.1q trunking 1\nGi0/2 auto 802.1q not-trunking 1") == {"Gi0/1"}


def test_structured_parsers_ignore_incomplete_rows() -> None:
    assert parse_ip_interfaces([{"interface": "", "ip_address": "192.0.2.1"}]) == {}
    assert parse_vlans([{"vlan": "n/a"}, {"vlan_id": "10", "vlan_name": "USERS"}]) == {10: "USERS"}
    assert parse_trunks([{"port": "Gi0/1", "status": "trunking"}, {"port": "Gi0/2", "status": "access"}]) == {
        "Gi0/1"
    }


def test_show_version_raw_and_structured_variants() -> None:
    raw = (
        "R1 uptime is 1 day\n"
        "Cisco IOS XE Software, Version 17.9.4\n"
        "cisco C9300-24T (X86) processor\n"
        "Processor board ID FOC123\n"
    )
    assert _parse_show_version(raw) == ("R1", "C9300-24T", "17.9.4", "FOC123")
    assert _parse_show_version([{"hostname": "SW1", "hardware": ["C9200"], "serial": []}]) == (
        "SW1",
        "C9200",
        "desconocida",
        "desconocido",
    )


class FailingConnection:
    def __init__(self, *, ios_xe: bool = False) -> None:
        self.ios_xe = ios_xe

    def send_command(self, command: str, **_: Any) -> Any:
        if command == "show version":
            return "Cisco IOS XE Software, Version 17.12\nCatalyst Switch" if self.ios_xe else ""
        if command == "show vlan brief":
            if self.ios_xe:
                return "10 USERS active"
            raise OSError("vlan unavailable")
        if command == "show running-config":
            if self.ios_xe:
                return "ip routing"
            raise RuntimeError("denied")
        raise TimeoutError(command)


def test_discovery_records_failures_without_crashing() -> None:
    facts = discover_device(FailingConnection())
    assert facts.hostname == "desconocido"
    assert len(facts.warnings) >= 5
    assert not facts.interfaces


def test_discovery_infers_ios_xe_and_switch_capabilities() -> None:
    facts = discover_device(FailingConnection(ios_xe=True))
    assert {
        "ios_xe",
        "netconf",
        "restconf",
        "switching",
        "vlan",
        "etherchannel",
        "routing",
    } <= facts.capabilities
