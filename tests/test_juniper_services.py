from __future__ import annotations

import pytest

from sarevat.juniper.services import build_management_candidate, preferred_management_interface
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
