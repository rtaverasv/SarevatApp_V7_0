"""Modelos compartidos por el motor, descubrimiento y la CLI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class DeviceKind(StrEnum):
    ROUTER = "router"
    SWITCH = "switch"


class ResultStatus(StrEnum):
    PLANNED = "planned"
    APPLIED = "applied"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class InterfaceState:
    name: str
    ip_address: str | None = None
    status: str = "unknown"
    protocol: str = "unknown"
    mode: str | None = None
    vlan: str | None = None

    @property
    def l3_up(self) -> bool:
        return bool(
            self.ip_address
            and self.ip_address.lower() != "unassigned"
            and self.status.lower() == "up"
            and self.protocol.lower() == "up"
        )


@dataclass(slots=True)
class DeviceFacts:
    hostname: str = "desconocido"
    model: str = "desconocido"
    version: str = "desconocida"
    serial: str = "desconocido"
    interfaces: dict[str, InterfaceState] = field(default_factory=dict)
    vlans: dict[int, str] = field(default_factory=dict)
    trunks: set[str] = field(default_factory=set)
    etherchannels: set[str] = field(default_factory=set)
    capabilities: set[str] = field(default_factory=set)
    running_config: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def active_l3_interfaces(self) -> set[str]:
        return {name for name, item in self.interfaces.items() if item.l3_up}


@dataclass(frozen=True, slots=True)
class CommandPlan:
    name: str
    service: str
    commands: tuple[str, ...]
    interfaces: frozenset[str] = frozenset()
    prechecks: tuple[str, ...] = ()
    postchecks: tuple[str, ...] = ()
    postcheck_expectations: dict[str, tuple[str, ...]] = field(default_factory=dict, compare=False)
    warnings: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("El plan necesita un nombre.")
        if not self.commands:
            raise ValueError("El plan no contiene comandos.")
        unknown_checks = set(self.postcheck_expectations) - set(self.postchecks)
        if unknown_checks:
            raise ValueError("Cada expectativa debe corresponder a un postcheck declarado.")
        if any(not tokens for tokens in self.postcheck_expectations.values()):
            raise ValueError("Cada postcheck semántico necesita al menos una evidencia esperada.")


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: str
    output: str
    success: bool
    errors: tuple[str, ...] = ()


@dataclass(slots=True)
class ExecutionReport:
    plan_name: str
    status: ResultStatus
    dry_run: bool
    started_at: datetime
    finished_at: datetime | None = None
    results: list[CommandResult] = field(default_factory=list)
    precheck_output: dict[str, str] = field(default_factory=dict)
    postcheck_output: dict[str, str] = field(default_factory=dict)
    backup_path: Path | None = None
    checkpoint: str | None = None
    rolled_back: bool = False
    message: str = ""

    @property
    def success(self) -> bool:
        return self.status in {ResultStatus.PLANNED, ResultStatus.APPLIED}
