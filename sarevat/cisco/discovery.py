"""Descubrimiento tolerante a variantes de salida Cisco."""

from __future__ import annotations

import re
from typing import Any, Protocol

from sarevat.models import DeviceFacts, InterfaceState


class ConnectionLike(Protocol):
    def send_command(self, command: str, **kwargs: Any) -> Any: ...


def _safe_command(
    connection: ConnectionLike, command: str, warnings: list[str], *, textfsm: bool = False
) -> Any:
    try:
        return connection.send_command(command, use_textfsm=textfsm)
    except (OSError, TimeoutError, ValueError) as exc:
        warnings.append(f"{command}: {exc}")
        return ""
    except Exception as exc:  # Netmiko expone distintas excepciones segun transporte/plataforma
        warnings.append(f"{command}: {type(exc).__name__}: {exc}")
        return ""


def parse_ip_interfaces(output: str | list[dict[str, Any]]) -> dict[str, InterfaceState]:
    interfaces: dict[str, InterfaceState] = {}
    if isinstance(output, list):
        for row in output:
            name = str(row.get("interface") or row.get("intf") or "").strip()
            if not name:
                continue
            ip_value = str(row.get("ip_address") or row.get("ipaddr") or "unassigned")
            interfaces[name] = InterfaceState(
                name=name,
                ip_address=None if ip_value.lower() == "unassigned" else ip_value,
                status=str(row.get("status") or "unknown"),
                protocol=str(row.get("proto") or row.get("protocol") or "unknown"),
            )
        return interfaces

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("interface"):
            continue
        fields = stripped.split()
        if len(fields) < 6:
            continue
        name, ip_value = fields[0], fields[1]
        interfaces[name] = InterfaceState(
            name=name,
            ip_address=None if ip_value.lower() == "unassigned" else ip_value,
            status=" ".join(fields[4:-1]),
            protocol=fields[-1],
        )
    return interfaces


def parse_vlans(output: str | list[dict[str, Any]]) -> dict[int, str]:
    vlans: dict[int, str] = {}
    if isinstance(output, list):
        for row in output:
            raw_id = row.get("vlan_id") or row.get("vlan")
            if str(raw_id).isdigit():
                vlans[int(raw_id)] = str(row.get("name") or row.get("vlan_name") or "")
        return vlans
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(\S+)", line)
        if match:
            vlans[int(match.group(1))] = match.group(2)
    return vlans


def parse_trunks(output: str | list[dict[str, Any]]) -> set[str]:
    trunks: set[str] = set()
    if isinstance(output, list):
        for row in output:
            name = row.get("interface") or row.get("port")
            status = str(row.get("status") or row.get("mode") or "").lower()
            if name and (not status or "trunk" in status):
                trunks.add(str(name))
        return trunks
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].lower() == "trunking":
            trunks.add(fields[0])
    return trunks


def _parse_show_version(output: str | list[dict[str, Any]]) -> tuple[str, str, str, str]:
    def scalar(value: Any, default: str) -> str:
        if isinstance(value, (list, tuple)):
            return str(value[0]) if value else default
        return str(value or default)

    if isinstance(output, list) and output:
        row = output[0]
        return (
            scalar(row.get("hostname"), "desconocido"),
            scalar(row.get("hardware") or row.get("platform"), "desconocido"),
            scalar(row.get("version"), "desconocida"),
            scalar(row.get("serial") or row.get("serial_number"), "desconocido"),
        )
    text = output if isinstance(output, str) else ""
    hostname_match = re.search(r"(?m)^(\S+) uptime is ", text)
    version_match = re.search(r"Cisco IOS(?: XE)? Software.*?Version\s+([^,\s]+)", text, re.I)
    model_match = re.search(r"(?m)^cisco\s+(\S+).*?processor", text, re.I)
    serial_match = re.search(r"Processor board ID\s+(\S+)", text, re.I)
    return (
        hostname_match.group(1) if hostname_match else "desconocido",
        model_match.group(1) if model_match else "desconocido",
        version_match.group(1) if version_match else "desconocida",
        serial_match.group(1) if serial_match else "desconocido",
    )


def discover_device(connection: ConnectionLike, *, include_running_config: bool = True) -> DeviceFacts:
    warnings: list[str] = []
    version_output = _safe_command(connection, "show version", warnings, textfsm=True)
    interface_output = _safe_command(connection, "show ip interface brief", warnings, textfsm=True)
    vlan_output = _safe_command(connection, "show vlan brief", warnings, textfsm=True)
    trunk_output = _safe_command(connection, "show interfaces trunk", warnings, textfsm=True)
    etherchannel_output = _safe_command(connection, "show etherchannel summary", warnings)
    running_config = (
        _safe_command(connection, "show running-config", warnings) if include_running_config else ""
    )
    hostname, model, version, serial = _parse_show_version(version_output)
    capabilities = {"ssh", "ipv4"}
    version_text = str(version_output).lower()
    config_text = str(running_config).lower()
    if "ios xe" in version_text or "ios-xe" in version_text:
        capabilities.update({"ios_xe", "netconf", "restconf"})
    if "switch" in version_text or "catalyst" in version_text or parse_vlans(vlan_output):
        capabilities.update({"switching", "vlan", "etherchannel"})
    if "router" in version_text or "ip routing" in config_text:
        capabilities.update({"routing", "ospf", "bgp", "nat"})
    etherchannels = set(re.findall(r"\bPo\d+\b", str(etherchannel_output), re.I))
    return DeviceFacts(
        hostname=hostname,
        model=model,
        version=version,
        serial=serial,
        interfaces=parse_ip_interfaces(interface_output),
        vlans=parse_vlans(vlan_output),
        trunks=parse_trunks(trunk_output),
        etherchannels=etherchannels,
        capabilities=capabilities,
        running_config=str(running_config),
        warnings=warnings,
    )
