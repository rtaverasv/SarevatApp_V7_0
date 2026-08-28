from __future__ import annotations

import json

from sarevat.compliance import ComplianceStatus, audit_running_config, export_compliance_json


def test_compliance_audit_detects_present_and_missing_controls(tmp_path) -> None:
    config = """
ip ssh version 2
ntp server 192.0.2.10
logging host 192.0.2.20
snmp-server group MONITOR v3 priv
aaa new-model
service password-encryption
"""
    findings = audit_running_config(config)
    assert all(item.status is ComplianceStatus.COMPLIANT for item in findings)
    exported = export_compliance_json(findings, tmp_path / "compliance.json")
    payload = json.loads(exported.read_text(encoding="utf-8"))
    assert payload["scope"].startswith("Auditoría local")


def test_compliance_audit_warns_for_missing_controls() -> None:
    findings = audit_running_config("hostname R1")
    assert all(item.status is ComplianceStatus.WARNING for item in findings)
    assert any(item.key == "snmpv3" for item in findings)
