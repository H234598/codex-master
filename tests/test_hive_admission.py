from datetime import datetime, timedelta, timezone

import pytest

from codex_master.admission import (
    AdmissionError,
    AdmissionPriority,
    AdmissionState,
    AdmissionStore,
    LeaseBinding,
    ResourceBinding,
    ScopeBinding,
    create_admission,
)


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def admission(name: str = "one", **changes: object):
    values: dict[str, object] = {
        "admission_id": f"adm-{name}", "request_id": f"req-{name}", "dispatch_id": f"dispatch-{name}",
        "workpackage_id": f"workpackage-{name}", "assignment_intent_id": f"intent-{name}",
        "repo_id": "codex-master", "principal_id": "specialist-one", "parent_principal_id": "lead-one",
        "grant_id": f"grant-{name}", "grant_digest": "sha256:grant", "work_item_version": 1,
        "scope": ScopeBinding("write", ("src",), "sha256:scope"),
        "resource": ResourceBinding("agent-one", "hmac:account", "standard", "gpt-primary", 1),
        "lease_context": LeaseBinding("claimed", "lease-one"),
        "priority": AdmissionPriority("DP1", "selection"), "now": NOW,
    }
    values.update(changes)
    return create_admission(**values)


def test_admission_binds_scope_resource_and_public_projection() -> None:
    record = admission()
    assert record.state is AdmissionState.PLANNED
    assert record.expires_at_utc == NOW + timedelta(seconds=30)
    public = record.public()
    assert public["scope"] == {"mode": "write", "path_count": 1}
    assert "account" not in str(public)
    assert "src" not in str(public)


def test_admission_store_enforces_revision_scope_and_paused_lifecycle() -> None:
    store = AdmissionStore()
    reserved = store.reserve(admission(), now=NOW)
    with pytest.raises(AdmissionError, match="stale_admission_revision"):
        store.begin_revalidation(reserved.admission_id, expected_revision=0, now=NOW)
    revalidating = store.begin_revalidation(reserved.admission_id, expected_revision=1, now=NOW)
    admitted = store.complete_revalidation(
        revalidating.admission_id, expected_revision=revalidating.revision, valid=True, now=NOW
    )
    executing = store.begin_execution(admitted.admission_id, expected_revision=admitted.revision, now=NOW)
    paused = store.transition(
        executing.admission_id, AdmissionState.PAUSED, expected_revision=executing.revision, now=NOW
    )
    assert paused.state is AdmissionState.PAUSED
    assert paused.active is True


def test_admission_scope_conflict_is_fail_closed() -> None:
    store = AdmissionStore(account_capacity=2, account_model_capacity=2)
    store.reserve(admission(), now=NOW)
    conflicting = admission("two", resource=ResourceBinding("agent-two", "hmac:account", "standard", "gpt-primary", 1))
    with pytest.raises(AdmissionError, match="scope_conflict"):
        store.reserve(conflicting, now=NOW)
