"""Detección prudente y despacho de plataformas de red.

Este módulo no aplica configuraciones. La detección SSH de Netmiko emplea
solamente su sondeo de identificación y siempre cierra esa conexión antes de
abrir la sesión de trabajo con el adaptador seleccionado.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from netmiko.ssh_autodetect import SSHDetect

from sarevat.models import DeviceFacts, NetworkPlatform


class ConnectionLike(Protocol):
    def find_prompt(self, **kwargs: Any) -> str: ...


class PlatformAdapter(Protocol):
    platform: NetworkPlatform
    supports_configuration: bool

    def discover(self, connection: ConnectionLike) -> DeviceFacts: ...


@dataclass(frozen=True, slots=True)
class PlatformDetection:
    platform: NetworkPlatform
    netmiko_device_type: str | None
    confidence: int
    evidence: str

    @property
    def requires_confirmation(self) -> bool:
        return self.platform is NetworkPlatform.UNKNOWN or self.confidence < 90


_NETMIKO_PLATFORM_MAP = {
    "cisco_ios": NetworkPlatform.CISCO_IOS,
    "cisco_xe": NetworkPlatform.CISCO_IOS_XE,
    "juniper": NetworkPlatform.JUNIPER_JUNOS,
    "juniper_junos": NetworkPlatform.JUNIPER_JUNOS,
    "huawei": NetworkPlatform.HUAWEI_VRP,
    "huawei_vrp": NetworkPlatform.HUAWEI_VRP,
    "huawei_vrpv8": NetworkPlatform.HUAWEI_VRP,
}

_DEFAULT_DEVICE_TYPE = {
    NetworkPlatform.CISCO_IOS: "cisco_ios",
    NetworkPlatform.CISCO_IOS_XE: "cisco_ios",
    NetworkPlatform.JUNIPER_JUNOS: "juniper_junos",
    NetworkPlatform.HUAWEI_VRP: "huawei_vrp",
}


def detect_platform_text(*texts: str) -> PlatformDetection:
    """Clasifica texto de banner o versión sin enviar comandos al equipo."""
    value = "\n".join(texts).casefold()
    if "junos" in value or "juniper networks" in value:
        return PlatformDetection(NetworkPlatform.JUNIPER_JUNOS, "juniper_junos", 95, "banner Junos")
    if "huawei" in value or "vrp" in value:
        return PlatformDetection(NetworkPlatform.HUAWEI_VRP, "huawei_vrp", 95, "banner VRP")
    if "cisco ios xe" in value or "ios-xe" in value:
        return PlatformDetection(NetworkPlatform.CISCO_IOS_XE, "cisco_ios", 95, "banner Cisco IOS-XE")
    if "cisco ios" in value or "cisco systems" in value:
        return PlatformDetection(NetworkPlatform.CISCO_IOS, "cisco_ios", 95, "banner Cisco IOS")
    return PlatformDetection(NetworkPlatform.UNKNOWN, None, 0, "sin coincidencia de plataforma")


def detection_from_netmiko(
    device_type: str | None, matches: dict[str, int] | None = None
) -> PlatformDetection:
    """Convierte el resultado de Netmiko en una decisión explícita y auditable."""
    platform = _NETMIKO_PLATFORM_MAP.get(device_type or "", NetworkPlatform.UNKNOWN)
    confidence = int((matches or {}).get(device_type or "", 0))
    if platform is NetworkPlatform.UNKNOWN:
        return PlatformDetection(platform, None, confidence, "Netmiko no reconoció una plataforma compatible")
    return PlatformDetection(platform, device_type, confidence or 90, f"Netmiko detectó {device_type}")


def detect_ssh_platform(
    params: dict[str, Any], *, detector_factory: Callable[..., Any] = SSHDetect
) -> PlatformDetection:
    """Sondea SSH y devuelve una plataforma; no abre la sesión de trabajo."""
    detect_params = dict(params)
    detect_params["device_type"] = "autodetect"
    detector = detector_factory(**detect_params)
    detected_type = detector.autodetect()
    matches = getattr(detector, "potential_matches", {})
    return detection_from_netmiko(detected_type, matches if isinstance(matches, dict) else None)


def device_type_for(platform: NetworkPlatform, transport: str) -> str:
    """Devuelve el tipo Netmiko certificado para el transporte indicado."""
    if platform is NetworkPlatform.UNKNOWN:
        if transport == "ssh":
            return "autodetect"
        raise ValueError("La detección automática por consola serial aún no está certificada.")
    if transport == "serial" and platform.is_cisco:
        return "cisco_ios_serial"
    try:
        return _DEFAULT_DEVICE_TYPE[platform]
    except KeyError as exc:
        raise ValueError("La plataforma no tiene un controlador Netmiko certificado.") from exc


class CiscoAdapter:
    platform = NetworkPlatform.CISCO_IOS
    supports_configuration = True

    def discover(self, connection: ConnectionLike) -> DeviceFacts:
        from sarevat.cisco.discovery import discover_device

        facts = discover_device(connection)
        version = facts.version.casefold()
        facts.platform = NetworkPlatform.CISCO_IOS_XE if "xe" in version else NetworkPlatform.CISCO_IOS
        return facts


class JunosAdapter:
    platform = NetworkPlatform.JUNIPER_JUNOS
    supports_configuration = False

    def discover(self, connection: ConnectionLike) -> DeviceFacts:
        from sarevat.juniper.discovery import discover_device

        return discover_device(connection)


class ReadOnlyUnknownAdapter:
    """No envía comandos cuando la plataforma no tiene adaptador certificado."""

    supports_configuration = False

    def __init__(self, platform: NetworkPlatform) -> None:
        self.platform = platform

    def discover(self, connection: ConnectionLike) -> DeviceFacts:
        try:
            prompt = str(connection.find_prompt())
        except Exception as exc:  # La sesión puede carecer de prompt estable.
            return DeviceFacts(
                platform=self.platform, warnings=[f"No se obtuvo prompt: {type(exc).__name__}"]
            )
        return DeviceFacts(platform=self.platform, hostname=prompt.rstrip("#> ") or "desconocido")


def adapter_for(platform: NetworkPlatform) -> PlatformAdapter:
    if platform.is_cisco:
        return CiscoAdapter()
    if platform is NetworkPlatform.JUNIPER_JUNOS:
        return JunosAdapter()
    return ReadOnlyUnknownAdapter(platform)
