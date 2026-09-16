"""Descubrimiento de solo lectura para Juniper Junos."""

from __future__ import annotations

import re
from typing import Any, Protocol

from sarevat.models import DeviceFacts, InterfaceState, NetworkPlatform


class ConnectionLike(Protocol):
    def send_command(self, command: str, **kwargs: Any) -> Any: ...


def _safe_command(connection: ConnectionLike, command: str, warnings: list[str]) -> str:
    try:
        return str(connection.send_command(command))
    except Exception as exc:  # Netmiko varía sus errores por transporte.
        warnings.append(f"{command}: {type(exc).__name__}: {exc}")
        return ""


def parse_interfaces_terse(output: str) -> dict[str, InterfaceState]:
    interfaces: dict[str, InterfaceState] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[0].lower() in {"interface", "name"}:
            continue
        name, admin, link = fields[:3]
        if not (
            re.match(r"^[A-Za-z][\w-]+-\d+/\d+/\d+(?:\.\d+)?$", name)
            or re.match(r"^(?:vlan|irb|lo0|me0)\.\d+$", name, re.I)
        ):
            continue
        ip_address = next(
            (item.split("/")[0] for item in fields[3:] if re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", item)),
            None,
        )
        previous = interfaces.get(name)
        addresses = list(previous.ip_addresses if previous and previous.ip_addresses else ())
        if previous and previous.ip_address and previous.ip_address not in addresses:
            addresses.append(previous.ip_address)
        if ip_address and ip_address not in addresses:
            addresses.append(ip_address)
        interfaces[name] = InterfaceState(
            name=name,
            ip_address=addresses[0] if addresses else None,
            status=admin,
            protocol=link,
            ip_addresses=tuple(addresses),
        )
    return interfaces


def parse_vlans(output: str) -> dict[int, str]:
    vlans: dict[int, str] = {}
    for line in output.splitlines():
        match = re.match(r"^\s*(\S+)\s+(\d+)\b", line)
        if match:
            vlans[int(match.group(2))] = match.group(1)
    return vlans


def parse_vlan_interfaces(output: str) -> tuple[str, ...]:
    """Extrae unidades Ethernet de ``show vlans``, incluso en lineas partidas."""
    found: dict[str, None] = {}
    for match in re.finditer(r"\b(?:ge|xe|et)-\d+/\d+/\d+\.0\b", output, re.IGNORECASE):
        found.setdefault(match.group(0), None)
    return tuple(found)


def _parse_version(output: str) -> tuple[str, str, str, str]:
    hostname = re.search(r"(?im)^Hostname:\s*(\S+)", output)
    model = re.search(r"(?im)^Model:\s*(\S+)", output)
    version = re.search(r"(?im)^Junos:\s*(\S+)", output)
    if not version:
        version = re.search(r"(?im)^JUNOS\s+.*?\[([^\]\s]+)\]", output)
    serial = re.search(r"(?im)^Serial Number:\s*(\S+)", output)
    return (
        hostname.group(1) if hostname else "desconocido",
        model.group(1) if model else "desconocido",
        version.group(1) if version else "desconocida",
        serial.group(1) if serial else "desconocido",
    )


def discover_device(connection: ConnectionLike) -> DeviceFacts:
    """Obtiene hechos Junos sin leer ni guardar la configuración completa."""
    warnings: list[str] = []
    version_output = _safe_command(connection, "show version", warnings)
    interfaces_output = _safe_command(connection, "show interfaces terse", warnings)
    vlans_output = _safe_command(connection, "show vlans", warnings)
    hostname, model, version, serial = _parse_version(version_output)
    interfaces = parse_interfaces_terse(interfaces_output)
    vlans = parse_vlans(vlans_output)
    # En algunas salidas EX2200, ``show interfaces terse`` omite puertos sin
    # direccion L3, pero ``show vlans`` aun los enumera como unidades access.
    for name in parse_vlan_interfaces(vlans_output):
        interfaces.setdefault(name, InterfaceState(name=name))
    capabilities = {"ssh", "ipv4", "junos", "read_only_inventory"}
    if "ex" in model.casefold() or vlans:
        capabilities.update({"switching", "vlan"})
    return DeviceFacts(
        platform=NetworkPlatform.JUNIPER_JUNOS,
        hostname=hostname,
        model=model,
        version=version,
        serial=serial,
        interfaces=interfaces,
        vlans=vlans,
        capabilities=capabilities,
        warnings=warnings,
    )
