from __future__ import annotations

from datetime import time

import pytest

from sarevat.batches import (
    BatchHistoryStore,
    BatchItemResult,
    BatchPreview,
    MaintenanceWindow,
    run_gradual_batch,
)
from sarevat.inventory import ConnectionProfile
from sarevat.models import DeviceKind


def test_batch_preview_stages_profiles_without_connecting() -> None:
    profiles = tuple(
        ConnectionProfile.create_ssh(f"R{index}", f"192.0.2.{index}", "admin", DeviceKind.ROUTER)
        for index in range(1, 4)
    )
    preview = BatchPreview("Core", profiles, 1, 1)
    assert [item.name for item in preview.first_stage] == ["R1"]
    assert [item.name for item in preview.remaining] == ["R2", "R3"]
    with pytest.raises(ValueError, match="concurrencia"):
        BatchPreview("Core", profiles, 4, 1)


def test_batch_pauses_after_failure_and_respects_window() -> None:
    profiles = tuple(
        ConnectionProfile.create_ssh(f"R{index}", f"192.0.2.{index}", "admin", DeviceKind.ROUTER)
        for index in range(1, 4)
    )
    preview = BatchPreview("Core", profiles, 1, 1)
    run = run_gradual_batch(
        preview,
        lambda profile: BatchItemResult(
            profile, profile.name != "R2", "ok" if profile.name != "R2" else "fallo"
        ),
    )
    assert run.paused and run.pending == ("R3",)
    blocked = run_gradual_batch(
        preview,
        lambda profile: BatchItemResult(profile, True, "ok"),
        window=MaintenanceWindow(time(22), time(2)),
        current_time=time(12),
    )
    assert blocked.paused and len(blocked.pending) == 3


def test_batch_history_can_filter_a_group(tmp_path) -> None:
    profile = ConnectionProfile.create_ssh("R1", "192.0.2.1", "admin", DeviceKind.ROUTER)
    store = BatchHistoryStore(tmp_path / "history.json")
    run = type("Run", (), {"paused": False, "results": (BatchItemResult(profile, True, "ok"),)})()
    store.add("Core", run)
    assert len(store.list("core")) == 1
