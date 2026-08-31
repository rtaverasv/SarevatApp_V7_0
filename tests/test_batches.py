from __future__ import annotations

import pytest

from sarevat.batches import BatchPreview
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
