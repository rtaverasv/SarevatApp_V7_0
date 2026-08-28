"""Inventario local versionado y perfiles de conexión sin secretos."""

from __future__ import annotations

import ipaddress
import json
import os
import uuid
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from sarevat.models import DeviceFacts, DeviceKind

INVENTORY_SCHEMA_VERSION = 1
_TRANSPORTS = frozenset({"ssh", "serial"})


@dataclass(frozen=True, slots=True)
class ConnectionProfile:
    """Datos reutilizables de conexión; nunca incluye contraseñas ni secretos."""

    id: str
    name: str
    transport: str
    device_kind: DeviceKind
    host: str | None = None
    serial_port: str | None = None
    baudrate: int | None = None
    username: str | None = None
    model: str = "desconocido"
    version: str = "desconocida"
    serial: str = "desconocido"
    last_seen_at: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("El perfil necesita un nombre.")
        if self.transport not in _TRANSPORTS:
            raise ValueError("El transporte debe ser SSH o serial.")
        if self.transport == "ssh":
            if not self.host:
                raise ValueError("Un perfil SSH necesita una IPv4.")
            try:
                parsed = ipaddress.ip_address(self.host)
            except ValueError as exc:
                raise ValueError("La IPv4 del perfil no es válida.") from exc
            if parsed.version != 4:
                raise ValueError("El inventario de V7.0 solo admite IPv4.")
        if self.transport == "serial":
            if not self.serial_port:
                raise ValueError("Un perfil serial necesita un puerto.")
            if not self.baudrate or self.baudrate <= 0:
                raise ValueError("El baudrate debe ser positivo.")

    @classmethod
    def create_ssh(cls, name: str, host: str, username: str, device_kind: DeviceKind) -> ConnectionProfile:
        return cls(
            id=uuid.uuid4().hex,
            name=name.strip(),
            transport="ssh",
            device_kind=device_kind,
            host=str(ipaddress.IPv4Address(host)),
            username=username.strip() or None,
        )

    @classmethod
    def create_serial(
        cls, name: str, port: str, baudrate: int, device_kind: DeviceKind
    ) -> ConnectionProfile:
        return cls(
            id=uuid.uuid4().hex,
            name=name.strip(),
            transport="serial",
            device_kind=device_kind,
            serial_port=port.strip(),
            baudrate=baudrate,
        )

    def with_discovery(self, facts: DeviceFacts) -> ConnectionProfile:
        return replace(
            self,
            model=facts.model,
            version=facts.version,
            serial=facts.serial,
            last_seen_at=datetime.now(UTC).isoformat(),
        )

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["device_kind"] = self.device_kind.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ConnectionProfile:
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            transport=str(data["transport"]),
            device_kind=DeviceKind(str(data["device_kind"])),
            host=str(data["host"]) if data.get("host") else None,
            serial_port=str(data["serial_port"]) if data.get("serial_port") else None,
            baudrate=int(data["baudrate"]) if data.get("baudrate") else None,
            username=str(data["username"]) if data.get("username") else None,
            model=str(data.get("model") or "desconocido"),
            version=str(data.get("version") or "desconocida"),
            serial=str(data.get("serial") or "desconocido"),
            last_seen_at=str(data["last_seen_at"]) if data.get("last_seen_at") else None,
        )


class InventoryStore:
    """Persistencia JSON atómica del inventario, con esquema explícito."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def list_profiles(self) -> list[ConnectionProfile]:
        if not self.path.exists():
            return []
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("No se pudo leer el inventario local.") from exc
        if payload.get("schema_version") != INVENTORY_SCHEMA_VERSION:
            raise ValueError("La versión del inventario no es compatible.")
        profiles = [ConnectionProfile.from_dict(item) for item in payload.get("profiles", [])]
        return sorted(profiles, key=lambda profile: profile.name.casefold())

    def save_profiles(self, profiles: list[ConnectionProfile]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        ordered = sorted(profiles, key=lambda item: item.name.casefold())
        payload = {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "profiles": [profile.to_dict() for profile in ordered],
        }
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)

    def add(self, profile: ConnectionProfile) -> None:
        profiles = self.list_profiles()
        if any(item.name.casefold() == profile.name.casefold() for item in profiles):
            raise ValueError("Ya existe un perfil con ese nombre.")
        self.save_profiles([*profiles, profile])

    def remove(self, profile_id: str) -> bool:
        profiles = self.list_profiles()
        remaining = [item for item in profiles if item.id != profile_id]
        if len(remaining) == len(profiles):
            return False
        self.save_profiles(remaining)
        return True

    def update_discovery(self, profile_id: str, facts: DeviceFacts) -> ConnectionProfile | None:
        profiles = self.list_profiles()
        updated: ConnectionProfile | None = None
        saved: list[ConnectionProfile] = []
        for profile in profiles:
            if profile.id == profile_id:
                updated = profile.with_discovery(facts)
                saved.append(updated)
            else:
                saved.append(profile)
        if updated:
            self.save_profiles(saved)
        return updated
