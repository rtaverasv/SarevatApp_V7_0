"""Candidatos Junos validados; su aplicacion remota aun no esta certificada."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from sarevat.models import CommandPlan, DeviceFacts
from sarevat.validators import (
    ValidationError,
    validate_cisco_text,
    validate_hostname,
    validate_ipv4,
    validate_netmask,
)

_INTERFACE_RE = re.compile(
    r"^(?P<base>(?:(?:ge|xe|et)-\d+/\d+/\d+)|(?:vlan|irb|lo0|me0))(?:\.(?P<unit>\d+))?$",
    re.IGNORECASE,
)
_VLAN_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,62}$")
_SNMP_SECRET_RE = re.compile(r"^[A-Za-z0-9!@#$%^&*()_+=.,:/?-]{8,64}$")


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


def build_ntp_candidate(
    data: dict[str, Any], facts: DeviceFacts, management_address: str
) -> CommandPlan:
    """Prepara un servidor NTP Junos con la transaccion recuperable estandar."""
    server = str(validate_ipv4(str(data.get("server", ""))))
    address = str(validate_ipv4(management_address))
    config_check = "show configuration system ntp | display set"
    return CommandPlan(
        name="Servidor NTP Junos",
        service="junos_ntp",
        commands=(f"set system ntp server {server}",),
        prechecks=(config_check, "show system uptime"),
        postchecks=(config_check,),
        postcheck_expectations={config_check: (f"set system ntp server {server}",)},
        warnings=(
            "Este candidato agrega un servidor NTP; no reemplaza otros servidores NTP existentes.",
            "Confirma que el servidor NTP es alcanzable desde la red de gestion.",
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
                "verificar SSH y configuracion NTP desde una segunda sesion",
                "commit",
            ),
        },
    )


def build_syslog_candidate(
    data: dict[str, Any], facts: DeviceFacts, management_address: str
) -> CommandPlan:
    """Prepara un colector syslog remoto con nivel notice y verificacion externa."""
    server = str(validate_ipv4(str(data.get("server", ""))))
    address = str(validate_ipv4(management_address))
    config_check = "show configuration system syslog | display set"
    command = f"set system syslog host {server} any notice"
    return CommandPlan(
        name="Colector syslog Junos",
        service="junos_syslog",
        commands=(command,),
        prechecks=(config_check,),
        postchecks=(config_check,),
        postcheck_expectations={config_check: (command,)},
        warnings=(
            "Este candidato agrega un colector syslog remoto; no elimina colectores existentes.",
            "Se enviaran eventos de cualquier facility con severidad notice o superior.",
            "Confirma que el colector es alcanzable desde la red de gestion.",
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
                "verificar SSH y configuracion syslog desde una segunda sesion",
                "commit",
            ),
        },
    )


def build_dns_candidate(
    data: dict[str, Any], facts: DeviceFacts, management_address: str
) -> CommandPlan:
    """Prepara hasta dos resolvedores DNS Junos sin retirar los existentes."""
    primary = str(validate_ipv4(str(data.get("primary", ""))))
    secondary_raw = str(data.get("secondary", "")).strip()
    servers = (primary,) if not secondary_raw else (primary, str(validate_ipv4(secondary_raw)))
    if len(set(servers)) != len(servers):
        raise ValidationError("Los servidores DNS primario y secundario deben ser diferentes.")
    address = str(validate_ipv4(management_address))
    config_check = "show configuration system name-server | display set"
    commands = tuple(f"set system name-server {server}" for server in servers)
    return CommandPlan(
        name="Resolvedores DNS Junos",
        service="junos_dns",
        commands=commands,
        prechecks=(config_check,),
        postchecks=(config_check,),
        postcheck_expectations={config_check: commands},
        warnings=(
            "Este candidato agrega resolvedores DNS; no elimina resolvedores existentes.",
            "Junos usa como maximo los primeros tres servidores DNS configurados.",
            "Confirma que los servidores son alcanzables desde la red de gestion.",
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
                "verificar SSH y configuracion DNS desde una segunda sesion",
                "commit",
            ),
        },
    )


def _snmpv3_secret(value: str, field: str) -> str:
    secret = validate_cisco_text(value, field, max_length=64, allow_spaces=True)
    if not _SNMP_SECRET_RE.fullmatch(secret):
        raise ValidationError(
            f"{field} debe tener entre 8 y 64 caracteres sin espacios ni caracteres de control."
        )
    return secret


def build_snmpv3_candidate(
    data: dict[str, Any], facts: DeviceFacts, management_address: str
) -> CommandPlan:
    """Prepara SNMPv3 authPriv sin enviar ni conservar claves fuera de la sesion."""
    group = validate_cisco_text(str(data.get("group", "")), "Grupo SNMPv3", max_length=32, allow_spaces=False)
    username = validate_cisco_text(
        str(data.get("username", "")), "Usuario SNMPv3", max_length=32, allow_spaces=False
    )
    auth_password = _snmpv3_secret(str(data.get("auth_password", "")), "Clave de autenticacion")
    privacy_password = _snmpv3_secret(str(data.get("privacy_password", "")), "Clave de privacidad")
    address = str(validate_ipv4(management_address))
    engine_check = "show configuration snmp engine-id | display set"
    config_check = "show configuration snmp | display set"
    user_prefix = f"set snmp v3 usm local-engine user {username}"
    return CommandPlan(
        name="SNMPv3 Junos con autenticacion y privacidad",
        service="junos_snmpv3",
        commands=(
            "set snmp view sarevat-ro oid .1 include",
            f"set snmp v3 vacm security-to-group security-model usm security-name {username} group {group}",
            f"set snmp v3 vacm access group {group} default-context-prefix security-model usm "
            "security-level privacy read-view sarevat-ro",
            f"{user_prefix} authentication-sha authentication-password {auth_password}",
            f"{user_prefix} privacy-aes128 privacy-password {privacy_password}",
        ),
        prechecks=(engine_check, config_check),
        postchecks=(config_check,),
        postcheck_expectations={config_check: (user_prefix, "privacy-aes128")},
        warnings=(
            "SNMPv3 requiere un engine ID ya configurado; el precheck bloquea el cambio si falta.",
            "Las claves se ocultan en vista previa, auditoria, borradores y reportes; "
            "no se guardan en perfiles.",
            "El usuario obtiene solo la vista de lectura sarevat-ro y nivel de seguridad authPriv.",
        ),
        metadata={
            "platform": "juniper_junos",
            "preview_only": True,
            "remote_apply_supported": True,
            "management_address": address,
            "management_interface": preferred_management_interface(facts),
            "precheck_expectations": {engine_check: ("set snmp engine-id",)},
            "manual_workflow": (
                "configure exclusive",
                "load set terminal",
                "show | compare",
                "commit check",
                "commit confirmed 5",
                "verificar SSH y configuracion SNMPv3 desde una segunda sesion",
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
    port_config_check = f"show configuration interfaces {base_interface} | display set"
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
        # EX2200 muestra el nombre/ID en ``show vlans``; la configuracion
        # activa del puerto confirma de forma estable su miembro de VLAN.
        postchecks=("show vlans", port_config_check),
        postcheck_expectations={
            "show vlans": (vlan_name, str(vlan_id)),
            port_config_check: (f"vlan members {vlan_name}",),
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


def build_existing_vlan_access_candidate(
    data: dict[str, Any], facts: DeviceFacts, management_address: str
) -> CommandPlan:
    """Asigna una VLAN descubierta a un puerto access sin crear ni editar la VLAN."""
    vlan_name = str(data.get("vlan_name", "")).strip()
    matching_ids = [
        vlan_id for vlan_id, name in facts.vlans.items() if name.casefold() == vlan_name.casefold()
    ]
    if len(matching_ids) != 1:
        raise ValidationError("Selecciona una VLAN existente del inventario actual.")
    vlan_id = matching_ids[0]
    interface, base_interface, unit = _junos_interface(str(data.get("interface", "")), facts)
    if unit != "0" or not re.fullmatch(r"(?:ge|xe|et)-\d+/\d+/\d+", base_interface, re.I):
        raise ValidationError(
            "Selecciona un puerto fisico Junos, por ejemplo ge-0/0/5, no una interfaz de gestion."
        )
    address = str(validate_ipv4(management_address))
    port_config_check = f"show configuration interfaces {base_interface} | display set"
    return CommandPlan(
        name="Asignar VLAN existente a puerto access Junos",
        service="junos_existing_vlan_access",
        commands=(
            f"set interfaces {base_interface} unit 0 family ethernet-switching port-mode access",
            f"set interfaces {base_interface} unit 0 family ethernet-switching vlan members {vlan_name}",
        ),
        interfaces=frozenset({interface}),
        prechecks=("show vlans", f"show interfaces terse {interface}"),
        postchecks=("show vlans", port_config_check),
        postcheck_expectations={
            "show vlans": (vlan_name, str(vlan_id)),
            port_config_check: (f"vlan members {vlan_name}",),
        },
        warnings=(
            "Este candidato no crea, borra ni renombra VLANs existentes.",
            "El puerto seleccionado dejara de pertenecer a su VLAN access actual.",
            "No selecciones un puerto de enlace, trunk, consola o gestion.",
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


def build_existing_vlan_trunk_candidate(
    data: dict[str, Any], facts: DeviceFacts, management_address: str
) -> CommandPlan:
    """Añade una VLAN descubierta a un puerto trunk Junos con confirmación recuperable."""
    vlan_name = str(data.get("vlan_name", "")).strip()
    matching_ids = [
        vlan_id for vlan_id, name in facts.vlans.items() if name.casefold() == vlan_name.casefold()
    ]
    if len(matching_ids) != 1:
        raise ValidationError("Selecciona una VLAN existente del inventario actual.")
    vlan_id = matching_ids[0]
    interface, base_interface, unit = _junos_interface(str(data.get("interface", "")), facts)
    if unit != "0" or not re.fullmatch(r"(?:ge|xe|et)-\d+/\d+/\d+", base_interface, re.I):
        raise ValidationError(
            "Selecciona un puerto fisico Junos, por ejemplo ge-0/0/5, no una interfaz de gestion."
        )
    address = str(validate_ipv4(management_address))
    port_config_check = f"show configuration interfaces {base_interface} | display set"
    return CommandPlan(
        name="Agregar VLAN existente a puerto trunk Junos",
        service="junos_existing_vlan_trunk",
        commands=(
            f"set interfaces {base_interface} unit 0 family ethernet-switching port-mode trunk",
            f"set interfaces {base_interface} unit 0 family ethernet-switching vlan members {vlan_name}",
        ),
        interfaces=frozenset({interface}),
        prechecks=("show vlans", f"show interfaces terse {interface}", port_config_check),
        postchecks=("show vlans", port_config_check),
        postcheck_expectations={
            "show vlans": (vlan_name, str(vlan_id)),
            port_config_check: ("port-mode trunk", f"vlan members {vlan_name}"),
        },
        warnings=(
            "Este candidato agrega una VLAN permitida y establece el puerto en modo trunk.",
            "No lo uses para un equipo final; confirma que el cable conectado es un enlace entre equipos.",
            "Los miembros de VLAN existentes se conservan; revisa la vista previa antes de aplicar.",
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
