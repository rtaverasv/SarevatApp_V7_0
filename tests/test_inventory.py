from __future__ import annotations

import json

import pytest

from sarevat.inventory import ConnectionProfile, InventoryStore
from sarevat.models import DeviceFacts, DeviceKind


def test_ssh_profile_roundtrip_and_discovery(tmp_path) -> None:
    store = InventoryStore(tmp_path / "inventory.json")
    profile = ConnectionProfile.create_ssh("Laboratorio", "192.0.2.10", "admin", DeviceKind.ROUTER)
    store.add(profile)
    saved = store.update_discovery(profile.id, DeviceFacts(model="C8000V", version="17.15", serial="SIM1"))
    reloaded = store.list_profiles()
    assert saved and saved.last_seen_at
    assert reloaded[0].host == "192.0.2.10"
    assert reloaded[0].model == "C8000V"
    assert "password" not in (tmp_path / "inventory.json").read_text(encoding="utf-8").lower()


def test_serial_profile_and_removal(tmp_path) -> None:
    store = InventoryStore(tmp_path / "inventory.json")
    profile = ConnectionProfile.create_serial("Consola", "COM9", 9600, DeviceKind.SWITCH)
    store.add(profile)
    assert store.remove(profile.id)
    assert not store.list_profiles()


def test_inventory_groups_are_normalized_and_filterable(tmp_path) -> None:
    store = InventoryStore(tmp_path / "inventory.json")
    profile = ConnectionProfile.create_ssh("R1", "192.0.2.1", "admin", DeviceKind.ROUTER)
    profile = ConnectionProfile.from_dict(profile.to_dict() | {"groups": "Core, laboratorio, Core"})
    store.add(profile)
    assert store.list_profiles()[0].groups == ("Core", "laboratorio")
    assert store.profiles_in_group("CORE") == [profile]
    with pytest.raises(ValueError, match="grupo"):
        store.profiles_in_group("")


def test_inventory_rejects_invalid_schema_and_duplicate_name(tmp_path) -> None:
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"schema_version": 99, "profiles": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="versión"):
        InventoryStore(path).list_profiles()

    store = InventoryStore(tmp_path / "fresh.json")
    first = ConnectionProfile.create_ssh("R1", "192.0.2.1", "admin", DeviceKind.ROUTER)
    store.add(first)
    with pytest.raises(ValueError, match="existe"):
        store.add(ConnectionProfile.create_ssh("r1", "192.0.2.2", "admin", DeviceKind.ROUTER))


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        (lambda: ConnectionProfile.create_ssh("R1", "not-an-ip", "admin", DeviceKind.ROUTER), "IPv4"),
        (lambda: ConnectionProfile.create_serial("S1", "", 9600, DeviceKind.SWITCH), "puerto"),
        (lambda: ConnectionProfile.create_serial("S1", "COM1", 0, DeviceKind.SWITCH), "baudrate"),
    ],
)
def test_profile_rejects_invalid_connection_data(factory, message) -> None:
    with pytest.raises(ValueError, match=message):
        factory()


def test_inventory_rejects_invalid_json_and_unknown_removal(tmp_path) -> None:
    path = tmp_path / "inventory.json"
    path.write_text("no es json", encoding="utf-8")
    with pytest.raises(ValueError, match="leer"):
        InventoryStore(path).list_profiles()
    store = InventoryStore(tmp_path / "empty.json")
    assert not store.remove("missing")
