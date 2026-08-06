from datetime import datetime, timedelta, timezone

import pytest

from codex_master.admission import (
    DEFAULT_RESERVATION_TTL_SECONDS,
    MAX_RESERVATION_TTL_SECONDS,
    AdmissionError,
    AdmissionPriority,
    AdmissionState,
    AdmissionStore,
    FileAdmissionStore,
    LeaseBinding,
    ResourceBinding,
    ScopeBinding,
    create_admission,
)


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def admission(name: str = "one", **changes: object):
    values: dict[str, object] = {
        "admission_id": f"adm-{name}",
        "request_id": f"req-{name}",
        "dispatch_id": f"dsp-{name}",
        "workpackage_id": f"wp-{name}",
        "assignment_intent_id": f"intent-{name}",
        "repo_id": "codex-master",
        "principal_id": "specialist-1",
        "parent_principal_id": "teamlead-1",
        "grant_id": f"grant-{name}",
        "grant_digest": "sha256:grant-digest",
        "work_item_version": 4,
        "scope": ScopeBinding("write", ("src/codex_master/admission.py",), "sha256:scope-digest"),
        "resource": ResourceBinding("a1", "hmac:account-a", "standard", "gpt-primary", 5_000_000),
        "lease_context": LeaseBinding("claimed", "lease-private"),
        "priority": AdmissionPriority("DP1", "sp1a_budget"),
        "now": NOW,
    }
    values.update(changes)
    return create_admission(**values)


def test_create_binds_work_scope_resource_and_bounded_ttl() -> None:
    record = admission()

    assert record.state is AdmissionState.PLANNED
    assert record.revision == 0
    assert record.expires_at_utc == NOW + timedelta(seconds=DEFAULT_RESERVATION_TTL_SECONDS)
    public = record.public()
    assert public["resource"] == {
        "agent_id": "a1",
        "budget_key": "standard",
        "model_id": "gpt-primary",
        "expected_usage_micro": 5_000_000,
    }
    assert "account_key" not in str(public)
    assert "scope-digest" not in str(public)
    assert "admission.py" not in str(public)
    assert "principal_id" not in public


def test_ttl_is_capped_and_timestamps_must_be_aware() -> None:
    with pytest.raises(AdmissionError, match="invalid_reservation_ttl"):
        admission(ttl_seconds=MAX_RESERVATION_TTL_SECONDS + 1)
    with pytest.raises(AdmissionError, match="invalid_admission_time"):
        admission(now=datetime(2026, 8, 6, 12))


def test_store_reserves_atomically_and_rejects_stale_revision_and_conflicts() -> None:
    store = AdmissionStore()
    reserved = store.reserve(admission(), now=NOW)
    assert reserved.state is AdmissionState.RESERVED
    assert reserved.revision == 1

    with pytest.raises(AdmissionError, match="stale_admission_revision"):
        store.begin_revalidation(reserved.admission_id, expected_revision=0, now=NOW)

    conflicting = admission("two")
    with pytest.raises(AdmissionError, match="agent_conflict"):
        store.reserve(conflicting, now=NOW)
    with pytest.raises(AdmissionError, match="admission_not_found"):
        store.get(conflicting.admission_id)


def test_store_applies_scope_overlap_and_separate_capacity_gates() -> None:
    store = AdmissionStore(account_capacity=4, account_model_capacity=2)
    read = admission("read", scope=ScopeBinding("read", ("src",), "sha256:read"))
    read_reserved = store.reserve(read, now=NOW)
    other_read = admission(
        "other-read",
        resource=ResourceBinding("a2", "hmac:account-a", "standard", "gpt-primary", 1),
        scope=ScopeBinding("read", ("src/codex_master",), "sha256:other-read"),
    )
    assert store.reserve(other_read, now=NOW).state is AdmissionState.RESERVED

    write = admission(
        "write",
        resource=ResourceBinding("a3", "hmac:account-a", "standard", "gpt-primary", 1),
        scope=ScopeBinding("write", ("src/codex_master",), "sha256:write"),
    )
    with pytest.raises(AdmissionError, match="account_model_capacity_conflict"):
        store.reserve(write, now=NOW)

    different_model = admission(
        "different-model",
        resource=ResourceBinding("a4", "hmac:account-a", "standard", "gpt-secondary", 1),
        scope=ScopeBinding("write", ("src/codex_master",), "sha256:different-model"),
    )
    with pytest.raises(AdmissionError, match="scope_conflict"):
        store.reserve(different_model, now=NOW)
    assert read_reserved.state is AdmissionState.RESERVED

    account_limited = AdmissionStore(account_capacity=1)
    account_limited.reserve(admission("account-one"), now=NOW)
    with pytest.raises(AdmissionError, match="account_capacity_conflict"):
        account_limited.reserve(
            admission(
                "account-two",
                resource=ResourceBinding("a2", "hmac:account-a", "standard", "gpt-secondary", 1),
            ),
            now=NOW,
        )


def test_dispatch_priority_uses_the_plan_enum() -> None:
    with pytest.raises(AdmissionError, match="invalid_dispatch_priority"):
        AdmissionPriority("P1", "selection")


def test_file_store_persists_revisions_and_rejects_corrupt_or_symlink_state(tmp_path) -> None:
    state_path = tmp_path / "admissions.json"
    lock_path = tmp_path / "admission.lock"
    first = FileAdmissionStore(state_path, lock_path)
    reserved = first.reserve(admission(), now=NOW)
    second = FileAdmissionStore(state_path, lock_path)
    assert second.get(reserved.admission_id).state is AdmissionState.RESERVED
    assert second.get(reserved.admission_id).revision == 1
    assert second.public_snapshot()[0]["state"] == "reserved"

    state_path.write_text("{}", encoding="utf-8")
    with pytest.raises(AdmissionError, match="unsupported_admission_state_schema"):
        second.get(reserved.admission_id)

    state_path.unlink()
    symlink_target = tmp_path / "secret-state"
    symlink_target.write_text("{}", encoding="utf-8")
    state_path.symlink_to(symlink_target)
    with pytest.raises(AdmissionError, match="invalid_admission_state_file"):
        first.get(reserved.admission_id)


def test_file_store_persists_every_lifecycle_transition_across_instances(tmp_path) -> None:
    state_path = tmp_path / "admissions.json"
    lock_path = tmp_path / "admission.lock"
    first = FileAdmissionStore(state_path, lock_path)
    reserved = first.reserve(admission("lifecycle"), now=NOW)

    second = FileAdmissionStore(state_path, lock_path)
    revalidating = second.begin_revalidation(reserved.admission_id, expected_revision=reserved.revision, now=NOW)
    assert first.get(reserved.admission_id).state is AdmissionState.REVALIDATING

    admitted = second.complete_revalidation(
        reserved.admission_id,
        expected_revision=revalidating.revision,
        valid=True,
        now=NOW,
    )
    assert first.get(reserved.admission_id).state is AdmissionState.ADMITTED
    executing = first.begin_execution(
        reserved.admission_id,
        expected_revision=admitted.revision,
        now=NOW,
    )
    assert second.get(reserved.admission_id).state is AdmissionState.EXECUTING
    finalized = second.finalize(
        reserved.admission_id,
        expected_revision=executing.revision,
        now=NOW,
    )
    assert FileAdmissionStore(state_path, lock_path).get(reserved.admission_id) == finalized


def test_file_store_prunes_expired_records_across_instances(tmp_path) -> None:
    state_path = tmp_path / "admissions.json"
    lock_path = tmp_path / "admission.lock"
    first = FileAdmissionStore(state_path, lock_path)
    record = first.reserve(admission("expiring", ttl_seconds=1), now=NOW)
    second = FileAdmissionStore(state_path, lock_path)
    assert second.prune_expired(now=NOW + timedelta(seconds=1)) == (record.admission_id,)
    assert second.get(record.admission_id).state is AdmissionState.EXPIRED


def test_revalidation_execution_and_finalization_are_versioned_and_idempotent() -> None:
    store = AdmissionStore()
    reserved = store.reserve(admission(), now=NOW)
    revalidating = store.begin_revalidation(reserved.admission_id, expected_revision=1, now=NOW)
    admitted = store.complete_revalidation(
        reserved.admission_id, expected_revision=revalidating.revision, valid=True, now=NOW
    )
    executing = store.begin_execution(reserved.admission_id, expected_revision=admitted.revision, now=NOW)
    finalized = store.finalize(reserved.admission_id, expected_revision=executing.revision, now=NOW)
    assert finalized.state is AdmissionState.FINALIZED
    assert finalized.revision == 5
    assert store.finalize(reserved.admission_id, expected_revision=0, now=NOW) == finalized


def test_expiry_and_compensation_are_explicit_terminal_paths() -> None:
    store = AdmissionStore()
    record = admission(ttl_seconds=1)
    reserved = store.reserve(record, now=NOW)
    expired = store.expire(now=NOW + timedelta(seconds=1))
    assert expired == (reserved.advance(AdmissionState.EXPIRED, now=NOW + timedelta(seconds=1)),)
    compensated = store.compensate(reserved.admission_id, expected_revision=2, now=NOW + timedelta(seconds=1))
    assert compensated.state is AdmissionState.COMPENSATED

    denied_record = admission("denied", resource=ResourceBinding("a2", "hmac:account-b", "standard", "gpt-primary", 1))
    denied_reserved = store.reserve(denied_record, now=NOW)
    denied_revalidating = store.begin_revalidation(
        denied_reserved.admission_id, expected_revision=1, now=NOW
    )
    denied = store.complete_revalidation(
        denied_reserved.admission_id, expected_revision=denied_revalidating.revision, valid=False, now=NOW
    )
    assert denied.state is AdmissionState.DENIED
    assert store.compensate(denied.admission_id, expected_revision=3, now=NOW).state is AdmissionState.COMPENSATED


def test_execution_failure_requires_compensation_and_crash_recovery_can_finalize() -> None:
    store = AdmissionStore()
    reserved = store.reserve(admission(), now=NOW)
    revalidating = store.begin_revalidation(reserved.admission_id, expected_revision=1, now=NOW)
    admitted = store.complete_revalidation(
        reserved.admission_id, expected_revision=revalidating.revision, valid=True, now=NOW
    )
    failed = store.mark_execution_failed(admitted.admission_id, expected_revision=admitted.revision, now=NOW)
    compensating = store.begin_compensation(failed.admission_id, expected_revision=failed.revision, now=NOW)
    assert compensating.state is AdmissionState.COMPENSATING
    failed_final = store.finish_compensation(
        compensating.admission_id, expected_revision=compensating.revision, now=NOW
    )
    assert failed_final.state is AdmissionState.FAILED_FINAL

    recovered_store = AdmissionStore()
    recovered_reserved = recovered_store.reserve(admission("recovered"), now=NOW)
    recovered_revalidating = recovered_store.begin_revalidation(
        recovered_reserved.admission_id, expected_revision=1, now=NOW
    )
    recovered_admitted = recovered_store.complete_revalidation(
        recovered_reserved.admission_id, expected_revision=recovered_revalidating.revision, valid=True, now=NOW
    )
    recovered_executing = recovered_store.begin_execution(
        recovered_admitted.admission_id, expected_revision=recovered_admitted.revision, now=NOW
    )
    recovered = recovered_store.recover_after_crash(
        recovered_executing.admission_id, expected_revision=recovered_executing.revision, now=NOW
    )
    assert recovered_store.finalize(recovered.admission_id, expected_revision=recovered.revision, now=NOW).state is AdmissionState.FINALIZED


def test_paused_admission_holds_scope_until_revalidation_or_expiry() -> None:
    store = AdmissionStore()
    reserved = store.reserve(admission("paused"), now=NOW)
    revalidating = store.begin_revalidation(reserved.admission_id, expected_revision=reserved.revision, now=NOW)
    admitted = store.complete_revalidation(
        reserved.admission_id, expected_revision=revalidating.revision, valid=True, now=NOW
    )
    executing = store.begin_execution(admitted.admission_id, expected_revision=admitted.revision, now=NOW)
    paused = store.transition(executing.admission_id, AdmissionState.PAUSED, expected_revision=executing.revision, now=NOW)
    assert paused.active is True
    resumed = store.transition(paused.admission_id, AdmissionState.EXECUTING, expected_revision=paused.revision, now=NOW)
    assert resumed.state is AdmissionState.EXECUTING
    paused_again = store.transition(resumed.admission_id, AdmissionState.PAUSED, expected_revision=resumed.revision, now=NOW)
    assert store.expire(now=NOW + timedelta(seconds=DEFAULT_RESERVATION_TTL_SECONDS)) == (paused_again.advance(AdmissionState.EXPIRED, now=NOW + timedelta(seconds=DEFAULT_RESERVATION_TTL_SECONDS)),)
