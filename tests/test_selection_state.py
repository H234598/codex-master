import pytest

from codex_master.selection import FairnessLedger
from codex_master.selection.state import ResourceState, ResourceStateError, ResourceStateStore, migrate_resource_state


def test_resource_state_uses_revision_cas_and_rejects_unknown_major_version() -> None:
    store = ResourceStateStore()
    assert store.read().revision == 0
    updated = store.compare_and_replace(expected_revision=0, state=ResourceState(1, FairnessLedger({})))
    assert updated.revision == 1
    with pytest.raises(ResourceStateError, match="stale_resource_revision"):
        store.compare_and_replace(expected_revision=0, state=ResourceState(1, FairnessLedger({})))
    with pytest.raises(ResourceStateError, match="unsupported_resource_schema"):
        migrate_resource_state({"schema_version": 99})
