from __future__ import annotations

import ipaddress

import pytest

from sarevat.models import CommandPlan, ExecutionReport, ResultStatus
from sarevat.validators import (
    ValidationError,
    parse_vlan_list,
    validate_asn,
    validate_cisco_text,
    validate_hostname,
    validate_interface,
    validate_ipv4,
    validate_ipv4_network,
    validate_same_subnet,
    validate_vlan,
)
from sarevat.vlsm import (
    SubnetRequest,
    automatic_gateway_policy,
    calculate_vlsm,
    export_plan_csv,
    export_plan_json,
    required_prefix,
)


@pytest.mark.parametrize(
    "value",
    ["", "   ", "a;reload", "a\nb", "x" * 129],
)
def test_cisco_text_rejects_unsafe_values(value: str) -> None:
    with pytest.raises(ValidationError):
        validate_cisco_text(value, "campo")


def test_identifier_inventory_and_number_failures() -> None:
    with pytest.raises(ValidationError):
        validate_hostname("router con espacios")
    with pytest.raises(ValidationError):
        validate_interface("Gi0/2", ["Gi0/1"])
    with pytest.raises(ValidationError):
        validate_vlan("abc")
    with pytest.raises(ValidationError):
        parse_vlan_list("10 a 20")
    with pytest.raises(ValidationError):
        parse_vlan_list("10-a")
    with pytest.raises(ValidationError):
        validate_ipv4("999.1.1.1")
    with pytest.raises(ValidationError):
        validate_ipv4_network("10.0.0.1/24")
    with pytest.raises(ValidationError):
        validate_asn("abc")
    with pytest.raises(ValidationError):
        validate_same_subnet("192.0.2.1", ipaddress.ip_network("198.51.100.0/24"), "Gateway")


def test_vlsm_request_and_prefix_failure_paths() -> None:
    with pytest.raises(ValidationError):
        SubnetRequest("LAN", 0)
    with pytest.raises(ValidationError):
        SubnetRequest("LAN", 1, kind="unknown")
    with pytest.raises(ValidationError, match="loopback"):
        SubnetRequest("LO", 2, kind="loopback")
    with pytest.raises(ValidationError):
        SubnetRequest("LAN", 1, gateway_policy="middle")
    with pytest.raises(ValidationError):
        SubnetRequest("LAN", 1, prefix_override=33)
    with pytest.raises(ValidationError):
        required_prefix(SubnetRequest("LAN", 100, prefix_override=30))
    assert automatic_gateway_policy("lan") == "first"
    assert automatic_gateway_policy("loopback") == "none"


def test_vlsm_empty_overlap_and_small_base_failures() -> None:
    with pytest.raises(ValidationError):
        calculate_vlsm("10.0.0.0/24", [])
    with pytest.raises(ValidationError):
        calculate_vlsm(
            "10.0.0.0/24",
            [SubnetRequest("LAN", 10)],
            reserved=("10.0.0.0/28", "10.0.0.8/29"),
        )
    with pytest.raises(ValidationError):
        calculate_vlsm("10.0.0.0/24", [SubnetRequest("LAN", 10, prefix_override=16)])


def test_vlsm_summary_flags_and_exports(tmp_path: pytest.TempPathFactory) -> None:
    plan = calculate_vlsm(
        "192.0.2.0/24",
        [SubnetRequest("P2P", 2, kind="point_to_point"), SubnetRequest("LO", 1, kind="loopback")],
        allow_31=True,
        allow_32=True,
    )
    assert plan.summaries
    assert all("/" in item for item in plan.summaries)
    json_path = export_plan_json(plan, tmp_path / "plan.json")
    csv_path = export_plan_csv(plan, tmp_path / "plan.csv")
    assert '"base_network": "192.0.2.0/24"' in json_path.read_text(encoding="utf-8")
    assert "hosts_requested" in csv_path.read_text(encoding="utf-8-sig")


def test_models_reject_invalid_plan_and_report_status() -> None:
    with pytest.raises(ValueError):
        CommandPlan(name="", service="test", commands=("show clock",))
    with pytest.raises(ValueError):
        CommandPlan(name="test", service="test", commands=())
    report = ExecutionReport("test", ResultStatus.ROLLED_BACK, False, __import__("datetime").datetime.now())
    assert not report.success
