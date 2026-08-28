"""Auditoría de cumplimiento Cisco IPv4 sin modificar el equipo."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path


class ComplianceStatus(StrEnum):
    COMPLIANT = "compliant"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class ComplianceFinding:
    key: str
    title: str
    status: ComplianceStatus
    recommendation: str


_RULES: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    (
        "ssh_v2",
        "SSH versión 2",
        "Configura 'ip ssh version 2' antes de habilitar el acceso remoto.",
        ("ip ssh version 2",),
    ),
    (
        "ntp",
        "Sincronización horaria NTP",
        "Configura al menos un servidor NTP autorizado.",
        ("ntp server ",),
    ),
    (
        "syslog",
        "Registro remoto syslog",
        "Configura un servidor syslog para conservar eventos fuera del equipo.",
        ("logging host ",),
    ),
    (
        "snmpv3",
        "Monitoreo SNMPv3",
        "Configura un grupo SNMPv3; evita comunidades SNMPv2c en producción.",
        ("snmp-server group ", " v3"),
    ),
    (
        "aaa",
        "AAA habilitado",
        "Evalúa 'aaa new-model' con un método de recuperación probado.",
        ("aaa new-model",),
    ),
    (
        "password_encryption",
        "Cifrado básico de contraseñas",
        "Activa 'service password-encryption' como protección mínima local.",
        ("service password-encryption",),
    ),
)


def audit_running_config(running_config: str) -> list[ComplianceFinding]:
    """Evalúa indicadores simples, sin asumir que equivalen a una certificación."""
    normalized = running_config.casefold()
    findings: list[ComplianceFinding] = []
    for key, title, recommendation, markers in _RULES:
        passed = all(marker in normalized for marker in markers)
        findings.append(
            ComplianceFinding(
                key=key,
                title=title,
                status=ComplianceStatus.COMPLIANT if passed else ComplianceStatus.WARNING,
                recommendation=recommendation,
            )
        )
    return findings


def export_compliance_json(findings: list[ComplianceFinding], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": "Auditoría local de solo lectura; no certifica hardware Cisco.",
        "findings": [asdict(item) | {"status": item.status.value} for item in findings],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
