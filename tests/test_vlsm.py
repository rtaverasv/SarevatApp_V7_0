from __future__ import annotations

import pytest

from sarevat.validators import ValidationError
from sarevat.vlsm import SubnetRequest, calculate_vlsm


def test_standard_vlsm_sorting_and_ranges() -> None:
    plan = calculate_vlsm(
        "192.168.10.0/24",
        [SubnetRequest("Ventas", 50), SubnetRequest("TI", 100), SubnetRequest("Voz", 10)],
    )
    assert [item.name for item in plan.allocations] == ["TI", "Ventas", "Voz"]
    assert [item.network for item in plan.allocations] == [
        "192.168.10.0/25",
        "192.168.10.128/26",
        "192.168.10.192/28",
    ]
    assert plan.allocations[-1].first_usable == "192.168.10.193"


def test_point_to_point_and_loopback_modes() -> None:
    plan = calculate_vlsm(
        "10.0.0.0/24",
        [
            SubnetRequest("Loopback0", 1, kind="loopback"),
            SubnetRequest("WAN", 2, kind="point_to_point"),
        ],
    )
    by_name = {item.name: item for item in plan.allocations}
    assert by_name["WAN"].network.endswith("/31")
    assert by_name["WAN"].usable_hosts == 2
    assert by_name["Loopback0"].network.endswith("/32")
    assert by_name["Loopback0"].usable_hosts == 1


def test_reserved_blocks_are_skipped() -> None:
    plan = calculate_vlsm(
        "172.16.0.0/24",
        [SubnetRequest("Usuarios", 50)],
        reserved=("172.16.0.0/26",),
    )
    assert plan.allocations[0].network == "172.16.0.64/26"


def test_overflow_and_external_exclusion_fail() -> None:
    with pytest.raises(ValidationError):
        calculate_vlsm(
            "192.168.1.0/24",
            [SubnetRequest("A", 200), SubnetRequest("B", 100)],
        )
    with pytest.raises(ValidationError):
        calculate_vlsm(
            "192.168.1.0/24",
            [SubnetRequest("A", 10)],
            reserved=("192.168.2.0/28",),
        )


def test_gateway_policy_and_utilization() -> None:
    plan = calculate_vlsm(
        "10.10.10.0/24",
        [SubnetRequest("LAN", 10, gateway_policy="last")],
    )
    item = plan.allocations[0]
    assert item.gateway == item.last_usable
    assert plan.utilization_percent == 6.25
