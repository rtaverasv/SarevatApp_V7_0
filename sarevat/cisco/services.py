"""Catalogo declarativo y generacion validada de planes Cisco."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from sarevat.models import CommandPlan, DeviceFacts, DeviceKind
from sarevat.validators import (
    ValidationError,
    parse_vlan_list,
    validate_asn,
    validate_cisco_text,
    validate_hostname,
    validate_interface,
    validate_ipv4,
    validate_ipv4_network,
    validate_netmask,
    validate_same_subnet,
    validate_vlan,
    validate_wildcard,
)


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    name: str
    devices: frozenset[DeviceKind]
    fields: tuple[tuple[str, str, str], ...]
    requires_l3: bool = False
    depends_on: tuple[str, ...] = ()
    required_capabilities: frozenset[str] = frozenset()


ROUTER = frozenset({DeviceKind.ROUTER})
SWITCH = frozenset({DeviceKind.SWITCH})
BOTH = frozenset({DeviceKind.ROUTER, DeviceKind.SWITCH})

SERVICE_CATALOG: dict[str, ServiceSpec] = {
    "vlan_acceso": ServiceSpec(
        "VLAN y puerto de acceso",
        SWITCH,
        (("vlan", "int", "ID de VLAN"), ("name", "token", "Nombre"), ("interface", "interface", "Puerto")),
    ),
    "trunk": ServiceSpec("Trunk 802.1Q", SWITCH, (("interface", "interface", "Interfaz trunk"),)),
    "etherchannel": ServiceSpec(
        "EtherChannel LACP",
        SWITCH,
        (("group", "int", "Port-Channel"), ("members", "interfaces", "Miembros separados por coma")),
    ),
    "port_security": ServiceSpec(
        "Port Security", SWITCH, (("interface", "interface", "Interfaz"), ("maximum", "int", "Maximo de MAC"))
    ),
    "portfast": ServiceSpec("PortFast y BPDU Guard", SWITCH, (("interface", "interface", "Interfaz final"),)),
    "dhcp_snooping": ServiceSpec(
        "DHCP Snooping", SWITCH, (("vlans", "vlans", "VLANs"), ("uplink", "interface", "Uplink confiable"))
    ),
    "dai": ServiceSpec(
        "Dynamic ARP Inspection", SWITCH, (("vlans", "vlans", "VLANs"),), depends_on=("dhcp_snooping",)
    ),
    "ipsg": ServiceSpec(
        "IP Source Guard",
        SWITCH,
        (("interface", "interface", "Puerto de acceso"),),
        depends_on=("dhcp_snooping",),
    ),
    "span": ServiceSpec(
        "SPAN", SWITCH, (("source", "interface", "Origen"), ("destination", "interface", "Destino"))
    ),
    "storm_control": ServiceSpec(
        "Storm Control", SWITCH, (("interface", "interface", "Interfaz"), ("level", "int", "Porcentaje"))
    ),
    "ruta_estatica": ServiceSpec(
        "Ruta estatica",
        ROUTER,
        (("network", "network", "Red destino"), ("next_hop", "ipv4", "Siguiente salto")),
    ),
    "ospf": ServiceSpec(
        "OSPF",
        ROUTER,
        (
            ("process", "int", "Proceso"),
            ("network_address", "ipv4", "Direccion"),
            ("wildcard", "wildcard", "Wildcard"),
            ("area", "int", "Area"),
        ),
        requires_l3=True,
        required_capabilities=frozenset({"routing"}),
    ),
    "bgp": ServiceSpec(
        "BGP",
        ROUTER,
        (
            ("local_as", "asn", "ASN local"),
            ("neighbor", "ipv4", "Vecino"),
            ("remote_as", "asn", "ASN remoto"),
        ),
        requires_l3=True,
        required_capabilities=frozenset({"routing"}),
    ),
    "dhcp": ServiceSpec(
        "Servidor DHCPv4",
        ROUTER,
        (
            ("pool", "token", "Pool"),
            ("network_address", "ipv4", "Red"),
            ("netmask", "netmask", "Mascara"),
            ("gateway", "ipv4", "Gateway"),
        ),
    ),
    "dhcp_relay": ServiceSpec(
        "DHCP Relay",
        ROUTER,
        (("interface", "interface", "Interfaz cliente"), ("server", "ipv4", "Servidor")),
        requires_l3=True,
    ),
    "nat": ServiceSpec(
        "NAT/PAT",
        ROUTER,
        (
            ("inside", "interface", "LAN"),
            ("outside", "interface", "WAN"),
            ("acl", "int", "ACL"),
            ("network_address", "ipv4", "Red interna"),
            ("wildcard", "wildcard", "Wildcard"),
        ),
    ),
    "pbr": ServiceSpec(
        "Policy-Based Routing",
        ROUTER,
        (
            ("interface", "interface", "Interfaz"),
            ("acl", "int", "ACL"),
            ("network_address", "ipv4", "Red origen"),
            ("wildcard", "wildcard", "Wildcard"),
            ("next_hop", "ipv4", "Siguiente salto"),
            ("route_map", "token", "Route-map"),
        ),
        requires_l3=True,
    ),
    "hsrp": ServiceSpec(
        "HSRP",
        ROUTER,
        (
            ("interface", "interface", "Interfaz L3"),
            ("group", "int", "Grupo"),
            ("virtual_ip", "ipv4", "IP virtual"),
            ("priority", "int", "Prioridad"),
        ),
        requires_l3=True,
    ),
    "ntp": ServiceSpec("NTP", BOTH, (("server", "ipv4", "Servidor"),)),
    "syslog": ServiceSpec("Syslog", BOTH, (("server", "ipv4", "Servidor"),)),
    "snmp": ServiceSpec("SNMPv2c RO", BOTH, (("community", "secret", "Comunidad"),)),
    "lldp": ServiceSpec("LLDP", BOTH, ()),
    "password_encryption": ServiceSpec("Cifrado basico de passwords", BOTH, ()),
}

_SERVICE_MARKERS: dict[str, tuple[str, ...]] = {
    "dhcp_snooping": ("ip dhcp snooping",),
    "dai": ("ip arp inspection vlan",),
    "lldp": ("lldp run",),
    "password_encryption": ("service password-encryption",),
}


def service_is_configured(service: str, facts: DeviceFacts) -> bool:
    config = facts.running_config.lower()
    markers = _SERVICE_MARKERS.get(service, ())
    return bool(markers) and all(marker in config for marker in markers)


def _value(data: dict[str, Any], key: str) -> Any:
    if key not in data:
        raise ValidationError(f"Falta el campo requerido: {key}.")
    return data[key]


def _integer(data: dict[str, Any], key: str, minimum: int, maximum: int) -> int:
    try:
        value = int(_value(data, key))
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{key} debe ser numerico.") from exc
    if not minimum <= value <= maximum:
        raise ValidationError(f"{key} debe estar entre {minimum} y {maximum}.")
    return value


def _interface(data: dict[str, Any], key: str, facts: DeviceFacts) -> str:
    inventory = facts.interfaces if facts.interfaces else None
    return validate_interface(str(_value(data, key)), inventory)


def _simple_plan(
    service: str,
    commands: list[str],
    interfaces: set[str],
    facts: DeviceFacts,
    *,
    warnings: list[str] | None = None,
    postchecks: tuple[str, ...] = (),
) -> CommandPlan:
    spec = SERVICE_CATALOG[service]
    plan_warnings = list(warnings or [])
    missing_capabilities = spec.required_capabilities - facts.capabilities
    if missing_capabilities:
        plan_warnings.append("Capacidades no confirmadas: " + ", ".join(sorted(missing_capabilities)))
    if spec.requires_l3 and not facts.active_l3_interfaces:
        raise ValidationError(f"{spec.name} requiere al menos una interfaz IPv4 up/up.")
    existing_lines = {line.strip().lower() for line in facts.running_config.splitlines()}
    meaningful = [command.lower() for command in commands if command.lower() not in {"exit", "end"}]
    if meaningful and all(command in existing_lines for command in meaningful):
        raise ValidationError(f"{spec.name} ya aparece configurado; no se generaron cambios duplicados.")
    return CommandPlan(
        name=spec.name,
        service=service,
        commands=tuple(commands),
        interfaces=frozenset(interfaces),
        prechecks=("show clock",),
        postchecks=postchecks,
        warnings=tuple(plan_warnings),
    )


def build_service_plan(
    service: str,
    data: dict[str, Any],
    facts: DeviceFacts,
    device_kind: DeviceKind,
) -> CommandPlan:
    if service not in SERVICE_CATALOG:
        raise ValidationError(f"Servicio no reconocido: {service}.")
    spec = SERVICE_CATALOG[service]
    if device_kind not in spec.devices:
        raise ValidationError(f"{spec.name} no corresponde a un {device_kind.value}.")
    commands: list[str] = []
    interfaces: set[str] = set()
    postchecks: tuple[str, ...] = ()

    if service == "vlan_acceso":
        vlan = validate_vlan(_value(data, "vlan"))
        name = validate_cisco_text(
            str(_value(data, "name")), "Nombre de VLAN", max_length=32, allow_spaces=False
        )
        interface = _interface(data, "interface", facts)
        interfaces.add(interface)
        commands = [
            f"vlan {vlan}",
            f"name {name}",
            "exit",
            f"interface {interface}",
            "switchport mode access",
            f"switchport access vlan {vlan}",
            "exit",
        ]
        postchecks = ("show vlan brief", f"show interfaces {interface} switchport")
    elif service == "trunk":
        interface = _interface(data, "interface", facts)
        interfaces.add(interface)
        commands = [f"interface {interface}"]
        if str(data.get("requires_dot1q", "false")).lower() in {"1", "true", "si", "yes"}:
            commands.append("switchport trunk encapsulation dot1q")
        commands.extend(["switchport mode trunk", "exit"])
        postchecks = ("show interfaces trunk",)
    elif service == "etherchannel":
        group = _integer(data, "group", 1, 255)
        raw_members = _value(data, "members")
        members = raw_members if isinstance(raw_members, (list, tuple)) else str(raw_members).split(",")
        normalized = [validate_interface(str(item).strip(), facts.interfaces or None) for item in members]
        if len(set(normalized)) < 2:
            raise ValidationError("EtherChannel necesita al menos dos interfaces distintas.")
        interfaces.update(normalized)
        for interface in normalized:
            commands.extend(
                [
                    f"interface {interface}",
                    "switchport mode trunk",
                    f"channel-group {group} mode active",
                    "exit",
                ]
            )
        commands.extend([f"interface Port-channel{group}", "switchport mode trunk", "exit"])
        postchecks = ("show etherchannel summary", "show interfaces trunk")
    elif service == "port_security":
        interface = _interface(data, "interface", facts)
        maximum = _integer(data, "maximum", 1, 128)
        interfaces.add(interface)
        commands = [
            f"interface {interface}",
            "switchport mode access",
            "switchport port-security",
            f"switchport port-security maximum {maximum}",
            "switchport port-security violation restrict",
            "exit",
        ]
        postchecks = (f"show port-security interface {interface}",)
    elif service == "portfast":
        interface = _interface(data, "interface", facts)
        interfaces.add(interface)
        commands = [
            f"interface {interface}",
            "spanning-tree portfast",
            "spanning-tree bpduguard enable",
            "exit",
        ]
        postchecks = (f"show spanning-tree interface {interface} detail",)
    elif service == "dhcp_snooping":
        vlans = parse_vlan_list(str(_value(data, "vlans")))
        uplink = _interface(data, "uplink", facts)
        interfaces.add(uplink)
        vlan_text = ",".join(map(str, vlans))
        commands = [
            "ip dhcp snooping",
            f"ip dhcp snooping vlan {vlan_text}",
            f"interface {uplink}",
            "ip dhcp snooping trust",
            "exit",
        ]
        postchecks = ("show ip dhcp snooping",)
    elif service == "dai":
        vlans = parse_vlan_list(str(_value(data, "vlans")))
        commands = [f"ip arp inspection vlan {','.join(map(str, vlans))}"]
        postchecks = ("show ip arp inspection",)
    elif service == "ipsg":
        interface = _interface(data, "interface", facts)
        interfaces.add(interface)
        commands = [f"interface {interface}", "ip verify source", "exit"]
        postchecks = (f"show ip verify source interface {interface}",)
    elif service == "span":
        source = _interface(data, "source", facts)
        destination = _interface(data, "destination", facts)
        if source.lower() == destination.lower():
            raise ValidationError("Origen y destino SPAN deben ser distintos.")
        interfaces.update({source, destination})
        commands = [
            f"monitor session 1 source interface {source}",
            f"monitor session 1 destination interface {destination}",
        ]
        postchecks = ("show monitor session 1",)
    elif service == "storm_control":
        interface = _interface(data, "interface", facts)
        level = _integer(data, "level", 1, 100)
        interfaces.add(interface)
        commands = [f"interface {interface}", f"storm-control broadcast level {level}.00", "exit"]
        postchecks = (f"show storm-control {interface}",)
    elif service == "ruta_estatica":
        network = validate_ipv4_network(str(_value(data, "network")))
        next_hop = validate_ipv4(str(_value(data, "next_hop")))
        commands = [f"ip route {network.network_address} {network.netmask} {next_hop}"]
        postchecks = (f"show ip route {network.network_address}",)
    elif service == "ospf":
        process = _integer(data, "process", 1, 65_535)
        address = validate_ipv4(str(_value(data, "network_address")))
        wildcard = validate_wildcard(str(_value(data, "wildcard")))
        area = _integer(data, "area", 0, 4_294_967_295)
        commands = [f"router ospf {process}", f"network {address} {wildcard} area {area}", "exit"]
        postchecks = ("show ip ospf neighbor", "show ip protocols")
    elif service == "bgp":
        local_as = validate_asn(_value(data, "local_as"))
        neighbor = validate_ipv4(str(_value(data, "neighbor")))
        remote_as = validate_asn(_value(data, "remote_as"))
        if local_as == remote_as:
            raise ValidationError("Para eBGP, ASN local y remoto deben ser distintos.")
        commands = [f"router bgp {local_as}", f"neighbor {neighbor} remote-as {remote_as}", "exit"]
        postchecks = ("show ip bgp summary",)
    elif service == "dhcp":
        pool = validate_cisco_text(str(_value(data, "pool")), "Pool DHCP", max_length=64, allow_spaces=False)
        address = validate_ipv4(str(_value(data, "network_address")))
        netmask = validate_netmask(str(_value(data, "netmask")))
        network = ipaddress.IPv4Network(f"{address}/{netmask}", strict=True)
        gateway = validate_same_subnet(str(_value(data, "gateway")), network, "El gateway")
        commands = [
            f"ip dhcp excluded-address {gateway}",
            f"ip dhcp pool {pool}",
            f"network {network.network_address} {network.netmask}",
            f"default-router {gateway}",
            "exit",
        ]
        postchecks = ("show ip dhcp pool", "show ip dhcp binding")
    elif service == "dhcp_relay":
        interface = _interface(data, "interface", facts)
        server = validate_ipv4(str(_value(data, "server")))
        interfaces.add(interface)
        commands = [f"interface {interface}", f"ip helper-address {server}", "exit"]
        postchecks = (f"show running-config interface {interface}",)
    elif service == "nat":
        inside = _interface(data, "inside", facts)
        outside = _interface(data, "outside", facts)
        if inside.lower() == outside.lower():
            raise ValidationError("Las interfaces NAT inside y outside deben ser distintas.")
        acl = _integer(data, "acl", 1, 99)
        address = validate_ipv4(str(_value(data, "network_address")))
        wildcard = validate_wildcard(str(_value(data, "wildcard")))
        interfaces.update({inside, outside})
        commands = [
            f"interface {inside}",
            "ip nat inside",
            "exit",
            f"interface {outside}",
            "ip nat outside",
            "exit",
            f"access-list {acl} permit {address} {wildcard}",
            f"ip nat inside source list {acl} interface {outside} overload",
        ]
        postchecks = ("show ip nat statistics", "show access-lists")
    elif service == "pbr":
        interface = _interface(data, "interface", facts)
        acl = _integer(data, "acl", 1, 99)
        address = validate_ipv4(str(_value(data, "network_address")))
        wildcard = validate_wildcard(str(_value(data, "wildcard")))
        next_hop = validate_ipv4(str(_value(data, "next_hop")))
        route_map = validate_cisco_text(
            str(_value(data, "route_map")), "Route-map", max_length=64, allow_spaces=False
        )
        interfaces.add(interface)
        commands = [
            f"access-list {acl} permit {address} {wildcard}",
            f"route-map {route_map} permit 10",
            f"match ip address {acl}",
            f"set ip next-hop {next_hop}",
            "exit",
            f"interface {interface}",
            f"ip policy route-map {route_map}",
            "exit",
        ]
        postchecks = ("show route-map", f"show ip policy interface {interface}")
    elif service == "hsrp":
        interface = _interface(data, "interface", facts)
        group = _integer(data, "group", 0, 255)
        virtual_ip = validate_ipv4(str(_value(data, "virtual_ip")))
        priority = _integer(data, "priority", 1, 255)
        state = facts.interfaces.get(interface)
        if state and state.ip_address:
            prefix = int(str(data.get("prefix", 24)))
            network = ipaddress.IPv4Network(f"{state.ip_address}/{prefix}", strict=False)
            validate_same_subnet(str(virtual_ip), network, "La IP virtual HSRP")
        interfaces.add(interface)
        commands = [
            f"interface {interface}",
            f"standby {group} ip {virtual_ip}",
            f"standby {group} priority {priority}",
            f"standby {group} preempt",
            "exit",
        ]
        postchecks = ("show standby brief",)
    elif service == "ntp":
        server = validate_ipv4(str(_value(data, "server")))
        commands = [f"ntp server {server}"]
        postchecks = ("show ntp associations",)
    elif service == "syslog":
        server = validate_ipv4(str(_value(data, "server")))
        commands = ["service timestamps log datetime msec", f"logging host {server}"]
        postchecks = ("show logging",)
    elif service == "snmp":
        community = validate_cisco_text(
            str(_value(data, "community")), "Comunidad SNMP", max_length=64, allow_spaces=False
        )
        commands = [f"snmp-server community {community} RO"]
        postchecks = ("show snmp community",)
    elif service == "lldp":
        commands = ["lldp run"]
        postchecks = ("show lldp", "show lldp neighbors")
    elif service == "password_encryption":
        commands = ["service password-encryption"]
        postchecks = ("show running-config | include service password-encryption",)

    return _simple_plan(service, commands, interfaces, facts, postchecks=postchecks)


def build_initial_setup_plan(data: dict[str, Any]) -> CommandPlan:
    hostname = validate_hostname(str(_value(data, "hostname")))
    domain = validate_cisco_text(str(_value(data, "domain")), "Dominio", max_length=253, allow_spaces=False)
    username = validate_cisco_text(
        str(_value(data, "username")), "Usuario", max_length=64, allow_spaces=False
    )
    password = validate_cisco_text(str(_value(data, "password")), "Password", max_length=128)
    rsa_bits = _integer(data, "rsa_bits", 1024, 4096)
    if rsa_bits not in {2048, 3072, 4096}:
        raise ValidationError("Utiliza RSA 2048, 3072 o 4096 bits.")
    commands = (
        f"hostname {hostname}",
        f"ip domain-name {domain}",
        f"username {username} privilege 15 secret {password}",
        "line vty 0 15",
        "login local",
        "transport input ssh",
        "exit",
        f"crypto key generate rsa modulus {rsa_bits}",
        "ip ssh version 2",
    )
    return CommandPlan(
        name="Configuracion inicial segura",
        service="initial_setup",
        commands=commands,
        prechecks=("show version", "show running-config | include hostname|username|ip ssh"),
        postchecks=("show ip ssh", "show running-config | section line vty"),
        metadata={"interactive_commands": (f"crypto key generate rsa modulus {rsa_bits}",)},
    )


def build_interface_ip_plan(interface: str, address: str, netmask: str, facts: DeviceFacts) -> CommandPlan:
    normalized = validate_interface(interface, facts.interfaces or None)
    ip_value = validate_ipv4(address)
    mask_value = validate_netmask(netmask)
    return CommandPlan(
        name=f"IPv4 en {normalized}",
        service="interface_ipv4",
        commands=(f"interface {normalized}", f"ip address {ip_value} {mask_value}", "no shutdown", "exit"),
        interfaces=frozenset({normalized}),
        prechecks=(f"show running-config interface {normalized}",),
        postchecks=(f"show ip interface {normalized}", "show ip interface brief"),
    )


def validate_plan_conflicts(plans: list[CommandPlan], facts: DeviceFacts) -> list[str]:
    conflicts: list[str] = []
    by_service: dict[str, set[str]] = {}
    for plan in plans:
        by_service.setdefault(plan.service, set()).update(plan.interfaces)
    trunks = set(facts.trunks) | by_service.get("trunk", set()) | by_service.get("etherchannel", set())
    for service in ("port_security", "portfast", "ipsg", "vlan_acceso"):
        overlap = trunks & by_service.get(service, set())
        if overlap:
            conflicts.append(f"{service} entra en conflicto con trunk en: {', '.join(sorted(overlap))}")
    span_destinations = by_service.get("span", set())
    if span_destinations & by_service.get("etherchannel", set()):
        conflicts.append("Una interfaz SPAN tambien fue seleccionada para EtherChannel.")
    return conflicts
