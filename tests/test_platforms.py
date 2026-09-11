from __future__ import annotations

import pytest

from sarevat.models import NetworkPlatform
from sarevat.platforms import (
    adapter_for,
    detect_platform_text,
    detect_ssh_platform,
    detection_from_netmiko,
    device_type_for,
)


@pytest.mark.parametrize(
    ("text", "platform", "device_type"),
    [
        ("Cisco IOS Software, Version 15.2", NetworkPlatform.CISCO_IOS, "cisco_ios"),
        ("Cisco IOS XE Software, Version 17.9", NetworkPlatform.CISCO_IOS_XE, "cisco_ios"),
        ("Junos: 12.3R12.4\nModel: ex2200-24t-4g", NetworkPlatform.JUNIPER_JUNOS, "juniper_junos"),
        ("Huawei Versatile Routing Platform Software", NetworkPlatform.HUAWEI_VRP, "huawei_vrp"),
    ],
)
def test_text_detection_recognizes_supported_platforms(
    text: str, platform: NetworkPlatform, device_type: str
) -> None:
    result = detect_platform_text(text)
    assert result.platform is platform
    assert result.netmiko_device_type == device_type
    assert not result.requires_confirmation


def test_unknown_text_requires_confirmation_and_never_gets_a_driver() -> None:
    result = detect_platform_text("generic switch")
    assert result.platform is NetworkPlatform.UNKNOWN
    assert result.requires_confirmation
    assert result.netmiko_device_type is None


def test_netmiko_detection_preserves_its_confidence() -> None:
    result = detection_from_netmiko("juniper_junos", {"juniper_junos": 99})
    assert result.platform is NetworkPlatform.JUNIPER_JUNOS
    assert result.confidence == 99


def test_ssh_autodetect_is_closed_before_work_session() -> None:
    captured: dict[str, object] = {}

    class Detector:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)
            self.potential_matches = {"juniper_junos": 99}

        def autodetect(self) -> str:
            return "juniper_junos"

    result = detect_ssh_platform(
        {"device_type": "cisco_ios", "host": "192.0.2.10"}, detector_factory=Detector
    )
    assert captured["device_type"] == "autodetect"
    assert result.platform is NetworkPlatform.JUNIPER_JUNOS


def test_platform_drivers_keep_cisco_serial_and_block_unknown_serial() -> None:
    assert device_type_for(NetworkPlatform.CISCO_IOS, "serial") == "cisco_ios_serial"
    assert device_type_for(NetworkPlatform.JUNIPER_JUNOS, "ssh") == "juniper_junos"
    with pytest.raises(ValueError, match="serial"):
        device_type_for(NetworkPlatform.UNKNOWN, "serial")


def test_non_cisco_adapter_is_read_only() -> None:
    assert not adapter_for(NetworkPlatform.JUNIPER_JUNOS).supports_configuration
    assert not adapter_for(NetworkPlatform.HUAWEI_VRP).supports_configuration
