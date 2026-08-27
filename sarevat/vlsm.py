"""Planificador VLSM IPv4 con exclusiones, /31 y /32 opcionales."""

from __future__ import annotations

import csv
import ipaddress
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path

from sarevat.validators import ValidationError, validate_cisco_text, validate_ipv4_network


@dataclass(frozen=True, slots=True)
class SubnetRequest:
    name: str
    hosts: int
    kind: str = "lan"
    gateway_policy: str = "first"
    prefix_override: int | None = None

    def __post_init__(self) -> None:
        validate_cisco_text(self.name, "El nombre de subred", max_length=64)
        if self.hosts < 1:
            raise ValidationError("Cada subred necesita al menos una direccion utilizable.")
        if self.kind not in {"lan", "point_to_point", "loopback"}:
            raise ValidationError(f"Tipo de subred no soportado: {self.kind}.")
        if self.gateway_policy not in {"first", "last", "none"}:
            raise ValidationError("Politica de gateway no reconocida.")
        if self.prefix_override is not None and not 0 <= self.prefix_override <= 32:
            raise ValidationError("Prefijo manual fuera del rango IPv4.")


@dataclass(frozen=True, slots=True)
class VLSMAllocation:
    name: str
    kind: str
    hosts_requested: int
    network: str
    netmask: str
    first_usable: str
    last_usable: str
    broadcast: str
    usable_hosts: int
    gateway: str | None


@dataclass(frozen=True, slots=True)
class VLSMPlan:
    base_network: str
    allocations: tuple[VLSMAllocation, ...]
    reserved: tuple[str, ...]
    total_addresses: int
    allocated_addresses: int

    @property
    def utilization_percent(self) -> float:
        return round((self.allocated_addresses / self.total_addresses) * 100, 2)

    @property
    def summaries(self) -> tuple[str, ...]:
        networks = [ipaddress.ip_network(item.network) for item in self.allocations]
        return tuple(str(item) for item in ipaddress.collapse_addresses(networks))


def _usable_count(prefix: int, kind: str) -> int:
    addresses = 1 << (32 - prefix)
    if prefix == 32:
        return 1 if kind == "loopback" else 0
    if prefix == 31:
        return 2 if kind == "point_to_point" else 0
    return max(0, addresses - 2)


def required_prefix(request: SubnetRequest, *, allow_31: bool = True, allow_32: bool = True) -> int:
    if request.prefix_override is not None:
        prefix = request.prefix_override
    elif request.kind == "loopback" and request.hosts == 1 and allow_32:
        prefix = 32
    elif request.kind == "point_to_point" and request.hosts <= 2 and allow_31:
        prefix = 31
    else:
        host_bits = math.ceil(math.log2(request.hosts + 2))
        prefix = 32 - host_bits
    if _usable_count(prefix, request.kind) < request.hosts:
        raise ValidationError(
            f"El prefijo /{prefix} no ofrece {request.hosts} direcciones para {request.kind}."
        )
    return prefix


def _usable_bounds(
    network: ipaddress.IPv4Network, kind: str
) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    if network.prefixlen == 32 and kind == "loopback":
        return network.network_address, network.network_address
    if network.prefixlen == 31 and kind == "point_to_point":
        return network.network_address, network.broadcast_address
    return network.network_address + 1, network.broadcast_address - 1


def _find_available(
    base: ipaddress.IPv4Network,
    prefix: int,
    occupied: list[ipaddress.IPv4Network],
) -> ipaddress.IPv4Network:
    if prefix < base.prefixlen:
        raise ValidationError(f"Un bloque /{prefix} no cabe dentro de {base}.")
    for candidate in base.subnets(new_prefix=prefix):
        if not any(candidate.overlaps(item) for item in occupied):
            return candidate
    raise ValidationError(f"No queda espacio alineado para un bloque /{prefix} dentro de {base}.")


def calculate_vlsm(
    base_network: str | ipaddress.IPv4Network,
    requests: list[SubnetRequest],
    *,
    reserved: tuple[str | ipaddress.IPv4Network, ...] = (),
    allow_31: bool = True,
    allow_32: bool = True,
) -> VLSMPlan:
    base = validate_ipv4_network(base_network) if isinstance(base_network, str) else base_network
    if not requests:
        raise ValidationError("Debes indicar al menos una subred.")

    occupied: list[ipaddress.IPv4Network] = []
    reserved_networks: list[ipaddress.IPv4Network] = []
    for value in reserved:
        item = validate_ipv4_network(value) if isinstance(value, str) else value
        if not item.subnet_of(base):
            raise ValidationError(f"La exclusion {item} no pertenece a {base}.")
        if any(item.overlaps(existing) for existing in reserved_networks):
            raise ValidationError(f"La exclusion {item} se solapa con otra exclusion.")
        reserved_networks.append(item)
        occupied.append(item)

    prepared = [
        (request, required_prefix(request, allow_31=allow_31, allow_32=allow_32)) for request in requests
    ]
    prepared.sort(key=lambda pair: (pair[1], pair[0].name.lower()))

    allocations: list[VLSMAllocation] = []
    allocated_addresses = 0
    for request, prefix in prepared:
        network = _find_available(base, prefix, occupied)
        occupied.append(network)
        first, last = _usable_bounds(network, request.kind)
        gateway = None
        if request.gateway_policy == "first":
            gateway = str(first)
        elif request.gateway_policy == "last":
            gateway = str(last)
        allocations.append(
            VLSMAllocation(
                name=request.name,
                kind=request.kind,
                hosts_requested=request.hosts,
                network=str(network),
                netmask=str(network.netmask),
                first_usable=str(first),
                last_usable=str(last),
                broadcast=str(network.broadcast_address),
                usable_hosts=_usable_count(network.prefixlen, request.kind),
                gateway=gateway,
            )
        )
        allocated_addresses += network.num_addresses

    return VLSMPlan(
        base_network=str(base),
        allocations=tuple(allocations),
        reserved=tuple(str(item) for item in reserved_networks),
        total_addresses=base.num_addresses,
        allocated_addresses=allocated_addresses,
    )


def export_plan_json(plan: VLSMPlan, path: Path) -> Path:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(plan), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def export_plan_csv(plan: VLSMPlan, path: Path) -> Path:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(plan.allocations[0]).keys()))
        writer.writeheader()
        writer.writerows(asdict(item) for item in plan.allocations)
    return path
