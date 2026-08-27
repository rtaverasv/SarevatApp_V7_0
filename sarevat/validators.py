"""Validadores estrictos para valores IPv4 y sintaxis Cisco."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable


class ValidationError(ValueError):
    """Una entrada no es segura o no tiene semantica valida."""


_HOSTNAME_RE = re.compile(r"^[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_INTERFACE_RE = re.compile(
    r"^(?:Gi|GigabitEthernet|Fa|FastEthernet|Te|TenGigabitEthernet|Eth|Ethernet|"
    r"Se|Serial|Lo|Loopback|Vl|Vlan|Po|Port-channel|Tu|Tunnel)\d+(?:/\d+){0,3}(?:\.\d+)?$",
    re.IGNORECASE,
)
_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
RESERVED_VLANS = frozenset({1002, 1003, 1004, 1005})


def validate_cisco_text(value: str, field: str, *, max_length: int = 128, allow_spaces: bool = True) -> str:
    value = value.strip()
    if not value:
        raise ValidationError(f"{field} no puede estar vacio.")
    if any(character in value for character in "\r\n;"):
        raise ValidationError(f"{field} contiene caracteres de control no permitidos.")
    if len(value) > max_length:
        raise ValidationError(f"{field} excede {max_length} caracteres.")
    if not allow_spaces and not _NAME_RE.fullmatch(value):
        raise ValidationError(f"{field} contiene caracteres no permitidos.")
    return value


def validate_hostname(value: str) -> str:
    value = validate_cisco_text(value, "El hostname", max_length=63, allow_spaces=False)
    if not _HOSTNAME_RE.fullmatch(value):
        raise ValidationError("El hostname no cumple el formato DNS/Cisco esperado.")
    return value


def validate_interface(value: str, inventory: Iterable[str] | None = None) -> str:
    value = validate_cisco_text(value, "La interfaz", max_length=64)
    if not _INTERFACE_RE.fullmatch(value):
        raise ValidationError(f"Interfaz no reconocida: {value}.")
    if inventory is not None:
        normalized = {item.lower(): item for item in inventory}
        if value.lower() not in normalized:
            raise ValidationError(f"La interfaz {value} no aparece en el inventario del equipo.")
        return normalized[value.lower()]
    return value


def validate_vlan(value: int | str, *, allow_reserved: bool = False) -> int:
    try:
        vlan = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("El ID de VLAN debe ser numerico.") from exc
    if not 1 <= vlan <= 4094:
        raise ValidationError("El ID de VLAN debe estar entre 1 y 4094.")
    if vlan in RESERVED_VLANS and not allow_reserved:
        raise ValidationError(f"La VLAN {vlan} esta reservada por Cisco.")
    return vlan


def parse_vlan_list(value: str) -> tuple[int, ...]:
    result: set[int] = set()
    value = validate_cisco_text(value, "La lista de VLAN")
    if any(character.isspace() for character in value):
        raise ValidationError("La lista de VLAN no puede contener espacios.")
    for part in value.split(","):
        if "-" in part:
            pieces = part.split("-", maxsplit=1)
            if len(pieces) != 2 or not all(piece.isdigit() for piece in pieces):
                raise ValidationError(f"Rango de VLAN invalido: {part}.")
            start, end = map(int, pieces)
            if start > end or end - start > 1024:
                raise ValidationError(f"Rango de VLAN invalido o excesivo: {part}.")
            result.update(validate_vlan(item) for item in range(start, end + 1))
        else:
            result.add(validate_vlan(part))
    return tuple(sorted(result))


def validate_ipv4(value: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValidationError(f"IPv4 invalida: {value}.") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValidationError("Solo se admite IPv4.")
    return address


def validate_ipv4_network(value: str, *, strict: bool = True) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value.strip(), strict=strict)
    except ValueError as exc:
        raise ValidationError(f"Red IPv4 invalida: {value}.") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValidationError("Solo se admite IPv4.")
    return network


def validate_netmask(value: str) -> ipaddress.IPv4Address:
    address = validate_ipv4(value)
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{address}")
    except ValueError as exc:
        raise ValidationError(f"Mascara no contigua: {value}.") from exc
    return address


def validate_wildcard(value: str) -> ipaddress.IPv4Address:
    wildcard = validate_ipv4(value)
    netmask = ipaddress.IPv4Address((~int(wildcard)) & 0xFFFFFFFF)
    validate_netmask(str(netmask))
    return wildcard


def validate_asn(value: int | str) -> int:
    try:
        asn = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("El ASN debe ser numerico.") from exc
    if not 1 <= asn <= 4_294_967_295 or asn == 23_456:
        raise ValidationError("ASN fuera del rango utilizable.")
    return asn


def validate_same_subnet(address: str, network: ipaddress.IPv4Network, field: str) -> ipaddress.IPv4Address:
    item = validate_ipv4(address)
    if item not in network:
        raise ValidationError(f"{field} no pertenece a {network}.")
    return item
