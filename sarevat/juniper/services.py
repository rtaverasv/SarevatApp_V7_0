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
_VLAN_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,62}$")


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
        postcheck_expectations={
            "show configuration system host-name": (hostname,),
            f"show interfaces terse {interface}": (str(address),),
        },
        warnings=(
            "Vista previa solamente: SarevatApp no enviara este candidato al equipo Junos.",
            "En una futura prueba autorizada se usara configure exclusive, commit check, "
            "commit confirmed y commit.",
            "No se incluye save ni una configuracion persistente fuera del commit controlado de Junos.",
        ),
        metadata={
            "platform": "juniper_junos",
            "preview_only": True,
            "remote_apply_supported": True,
            "management_address": str(address),
            "management_interface": interface,
            "manual_workflow": (
                "configure exclusive",
                "load set terminal",
                "show | compare",
                "commit check",
                "commit confirmed 5",
                "verificar SSH e IP de gestion",
                "commit",
            ),
        },
    )


def build_vlan_access_candidate(
    data: dict[str, Any], facts: DeviceFacts, management_address: str
) -> CommandPlan:
    """Prepara una VLAN nueva y un puerto access Junos sin modificar el equipo."""
    vlan_name = str(data.get("vlan_name", "")).strip()
    if not _VLAN_NAME_RE.fullmatch(vlan_name) or vlan_name.casefold() == "default":
        raise ValidationError("El nombre de VLAN debe iniciar con letra y usar solo letras, numeros, _ o -.")
    try:
        vlan_id = int(str(data.get("vlan_id", "")).strip())
    except ValueError as exc:
        raise ValidationError("El ID de VLAN debe ser un numero entre 2 y 4094.") from exc
    if not 2 <= vlan_id <= 4094:
        raise ValidationError("El ID de VLAN debe estar entre 2 y 4094.")
    if vlan_id in facts.vlans or any(
        name.casefold() == vlan_name.casefold() for name in facts.vlans.values()
    ):
        raise ValidationError(
            "La VLAN indicada ya existe en el inventario; este flujo solo crea VLAN nuevas."
        )
    interface, base_interface, unit = _junos_interface(str(data.get("interface", "")), facts)
    if unit != "0" or not re.fullmatch(r"(?:ge|xe|et)-\d+/\d+/\d+", base_interface, re.I):
        raise ValidationError(
            "Selecciona un puerto fisico Junos, por ejemplo ge-0/0/5, no una interfaz de gestion."
        )
    address = str(validate_ipv4(management_address))
    switching_check = f"show ethernet-switching interfaces {base_interface}"
    return CommandPlan(
        name="VLAN y puerto access Junos",
        service="junos_vlan_access",
        commands=(
            f"set vlans {vlan_name} vlan-id {vlan_id}",
            f"set interfaces {base_interface} unit 0 family ethernet-switching port-mode access",
            f"set interfaces {base_interface} unit 0 family ethernet-switching vlan members {vlan_name}",
        ),
        interfaces=frozenset({interface}),
        prechecks=("show vlans", f"show interfaces terse {interface}"),
        postchecks=("show vlans", switching_check),
        postcheck_expectations={
            "show vlans": (vlan_name, str(vlan_id)),
            switching_check: (base_interface, vlan_name),
        },
        warnings=(
            "Este candidato crea una VLAN nueva y cambia el puerto seleccionado a modo access.",
            "No selecciones un puerto de enlace, trunk, consola o gestion.",
            "La aplicacion requiere prechecks, commit confirmed y verificacion SSH independiente.",
        ),
        metadata={
            "platform": "juniper_junos",
            "preview_only": True,
            "remote_apply_supported": True,
            "management_address": address,
            "management_interface": preferred_management_interface(facts),
            "manual_workflow": (
                "configure exclusive",
                "load set terminal",
                "show | compare",
                "commit check",
                "commit confirmed 5",
                "verificar SSH e inventario desde una segunda sesion",
                "commit",
            ),
        },
    )
