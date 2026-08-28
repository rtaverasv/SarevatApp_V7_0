from __future__ import annotations

import json

import pytest

from sarevat.baselines import BaselineStore, ConfigurationBaseline, compare_with_baseline


def test_baseline_is_redacted_persisted_and_compared(tmp_path) -> None:
    baseline = ConfigurationBaseline.from_config(
        "R1", "hostname R1\nusername admin secret SuperSecret\n"
    )
    store = BaselineStore(tmp_path / "baseline.json")
    store.save(baseline)
    payload = json.loads(store.path.read_text(encoding="utf-8"))
    assert "SuperSecret" not in str(payload)
    loaded = store.load()
    assert not compare_with_baseline(loaded, "hostname R1\nusername admin secret OtherSecret\n")
    assert "+ntp server 192.0.2.10" in compare_with_baseline(
        loaded, "hostname R1\nusername admin secret OtherSecret\nntp server 192.0.2.10\n"
    )


def test_baseline_rejects_empty_or_invalid_data(tmp_path) -> None:
    with pytest.raises(ValueError, match="No hay configuración"):
        ConfigurationBaseline.from_config("R1", "")
    store = BaselineStore(tmp_path / "bad.json")
    store.path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="versión"):
        store.load()
