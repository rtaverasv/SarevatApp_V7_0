from __future__ import annotations

from sarevat.drafts import DraftStore, configuration_diff
from sarevat.models import CommandPlan


def test_draft_store_redacts_secrets_and_removes(tmp_path) -> None:
    store = DraftStore(tmp_path / "drafts.json")
    draft = store.add_plan(
        CommandPlan("SNMP", "snmp", ("snmp-server community PRIVATE_COMMUNITY RO",))
    )
    stored = (tmp_path / "drafts.json").read_text(encoding="utf-8")
    assert "PRIVATE_COMMUNITY" not in stored
    assert "********" in stored
    assert store.remove(draft.id)
    assert not store.list_drafts()


def test_configuration_diff_redacts_and_marks_changes() -> None:
    diff = configuration_diff("hostname R1\nenable secret OLD", "hostname R2\nenable secret NEW")
    assert "-hostname R1" in diff
    assert "+hostname R2" in diff
    assert "OLD" not in diff and "NEW" not in diff
    assert "********" in diff
