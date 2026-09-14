"""Candidatos Junos validados; su aplicacion remota aun no esta certificada."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from sarevat.models import CommandPlan, DeviceFacts
from sarevat.validators import ValidationError, validate_hostname, validate_ipv4, validate_netmask

_INTERFACE_RE = re.compile(
    r"^(?P<base>(?:(?:ge|xe|et)-\d+/\d+/\d+)|(?:vlan|irb|lo0|me0))(?:\.(?P<unit>\d+))?$",
    re.IGNORECASE,
)


def preferred_management_interface(facts: DeviceFacts) -> str:
    """Prioriza la interfaz de gestión activa que descubrió el equipo."""
    items = tuple(facts.interfaces.items())
    for name, state in items:
        if name.casefold().startswith("me0.") and state.ip_address:
            return name
    for name, state in items:
        if state.ip_address:
            return name
    return next(iter(facts.interfaces), "")


def _junos_interface(value: str, facts: DeviceFacts) -> tuple[str, str, str]:
    name = value.strip()
    match = _INTERFACE_RE.fullmatch(name)
    if not match:
        raise ValidationError("Selecciona una interfaz Junos descubierta, como me0.0, ge-0/0/0 o vlan.0.")
    available = {item.casefold() for item in facts.interfaces}
    if name.casefold() not in available:
        raise ValidationError("La interfaz no aparece en el inventario descubierto del equipo.")
    base = match.group("base")
    unit = match.group("unit") or "0"
    return name, base, unit


def build_management_candidate(data: dict[str, Any], facts: DeviceFacts) -> CommandPlan:
    """Construye un candidato Junos de vista previa sin enviarlo a un equipo."""
    hostname = validate_hostname(str(data.get("hostname", "")))
    interface, base_interface, unit = _junos_interface(str(data.get("interface", "")), facts)
    address = validate_ipv4(str(data.get("address", "")))
    netmask = validate_netmask(str(data.get("netmask", "")))
    prefix = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    commands = (
        f"set system host-name {hostname}",
        f"set interfaces {base_interface} unit {unit} family inet address {address}/{prefix}",
    )
    return CommandPlan(
        name="Candidato de gestion Junos",
        service="junos_management_candidate",
        commands=commands,
        interfaces=frozenset({interface}),
        prechecks=("show configuration system host-name", f"show interfaces terse {interface}"),
        postchecks=("show configuration system host-name", f"show interfaces terse {interface}"),
        warnings=(
            "Vista previa solamente: SarevatApp no enviara este candidato al equipo Junos.",
            "En una futura prueba autorizada se usara configure private, commit check, "
            "commit confirmed y commit.",
            "No se incluye save ni una configuracion persistente fuera del commit controlado de Junos.",
        ),
        metadata={
            "platform": "juniper_junos",
            "preview_only": True,
            "manual_workflow": (
                "configure private",
                "load merge terminal",
                "show | compare",
                "commit check",
                "commit confirmed 5",
                "verificar SSH e IP de gestion",
                "commit",
            ),
        },
    )
