from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import codex_master.admin_secret_ingress as ingress_module

from codex_master.admin_secret_ingress import (
    AdminSecretIngressError,
    AdminSecretIngressOwner,
    SecretResolveClaimV1,
    SecretUploadClaimV1,
)
from codex_master.admin_service import (
    MasterjetControlService,
    SecretIngressCapabilityV1,
    SecretIngressResolutionV1,
)
from codex_master.credential_vault import CredentialVault
from test_admin_service import command, principal, service_at


DIGEST = "sha256:" + "a" * 64


def _owner(root: Path, clock=lambda: 1_000.0) -> AdminSecretIngressOwner:
    vault = CredentialVault.for_test(root / "vault", key=b"k" * 32, clock=clock)
    return AdminSecretIngressOwner(
        root / "state",
        vault=vault,
        clock=clock,
    )


def _session(owner: AdminSecretIngressOwner):
    return owner.create_session(
        principal="operator-one",
        account_ref="google-one",
        credential_kind="google.oauth-client",
        expected_generation=4,
        idempotency_key="idem-create",
        plan_digest=DIGEST,
    )


def test_secret_ingress_claims_and_resolution_are_redacted() -> None:
    upload_claim = SecretUploadClaimV1("private-session", "a" * 64)
    resolve_claim = SecretResolveClaimV1("private-session", "b" * 64)
    resolution = SecretIngressResolutionV1(
        "private-session",
        bytearray(b"private-secret"),
        resolve_claim,
    )

    assert repr(upload_claim) == "SecretUploadClaimV1(<redacted>)"
    assert repr(resolve_claim) == "SecretResolveClaimV1(<redacted>)"
    assert repr(resolution) == "SecretIngressResolutionV1(<redacted>)"


def test_create_replay_returns_original_session_after_clock_advance_and_restart(
    tmp_path,
) -> None:
    now = [1_000.0]
    owner = _owner(tmp_path, clock=lambda: now[0])
    first = _session(owner)

    now[0] = 1_050.0
    replay = _session(_owner(tmp_path, clock=lambda: now[0]))

    assert replay == first
    assert replay.expires_at == 1_120.0
    assert replay.plan_digest == DIGEST
    assert replay.expected_generation == 4


def test_create_concurrent_replay_returns_one_persisted_session(tmp_path) -> None:
    owner = _owner(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        sessions = list(pool.map(lambda _index: _session(owner), range(8)))

    assert sessions == [sessions[0]] * 8


def test_create_prunes_expired_authorized_session_at_bound(
    tmp_path, monkeypatch
) -> None:
    now = [1_000.0]
    owner = _owner(tmp_path, clock=lambda: now[0])
    monkeypatch.setattr(ingress_module, "_MAX_SESSIONS", 1)
    _session(owner)
    now[0] = 1_121.0

    replacement = owner.create_session(
        principal="operator-one",
        account_ref="google-two",
        credential_kind="google.oauth-client",
        expected_generation=4,
        idempotency_key="idem-other",
        plan_digest=DIGEST,
    )

    assert replacement.account_ref == "google-two"


def test_concrete_owner_rejects_upload_without_reserved_exact_session(tmp_path) -> None:
    owner = _owner(tmp_path)
    with pytest.raises(AdminSecretIngressError, match="credential.upload_expired"):
        owner.put_secret(
            "missing",
            bytearray(b"secret"),
            principal="operator-one",
            upload_claim=None,
        )


def test_upload_claim_is_restart_verifiable_and_forgery_is_denied(tmp_path) -> None:
    owner = _owner(tmp_path)
    session = _session(owner)
    claim = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )

    restarted = _owner(tmp_path)
    replay = restarted.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    assert replay == claim
    with pytest.raises(AdminSecretIngressError, match="credential.upload_expired"):
        restarted.put_secret(
            session.id,
            bytearray(b"forged"),
            principal="operator-one",
            upload_claim=SecretUploadClaimV1(session.id, "0" * 64),
        )

    receipt = restarted.put_secret(
        session.id,
        bytearray(b"oauth-client-json"),
        principal="operator-one",
        upload_claim=replay,
    )
    restarted.commit_upload(replay, receipt)


def test_upload_reconciles_vault_success_when_store_reports_failure(
    tmp_path, monkeypatch
) -> None:
    owner = _owner(tmp_path)
    session = _session(owner)
    claim = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    real_store = CredentialVault.store_projection

    def write_then_fail(vault, *args, **kwargs):
        real_store(vault, *args, **kwargs)
        raise RuntimeError("fault after durable write")

    monkeypatch.setattr(CredentialVault, "store_projection", write_then_fail)
    receipt = owner.put_secret(
        session.id,
        bytearray(b"oauth-client-json"),
        principal="operator-one",
        upload_claim=claim,
    )
    owner.commit_upload(claim, receipt)

    assert receipt.generation == 5


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_upload_does_not_normalize_vault_process_signals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    owner = _owner(tmp_path)
    session = _session(owner)
    claim = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    monkeypatch.setattr(
        CredentialVault,
        "store_projection",
        lambda *_args, **_values: (_ for _ in ()).throw(signal_type("primary")),
    )

    with pytest.raises(signal_type, match="primary"):
        owner.put_secret(
            session.id,
            bytearray(b"oauth-client-json"),
            principal="operator-one",
            upload_claim=claim,
        )


def test_upload_commit_failure_is_reconciled_after_restart(
    tmp_path, monkeypatch
) -> None:
    owner = _owner(tmp_path)
    session = _session(owner)
    claim = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    receipt = owner.put_secret(
        session.id,
        bytearray(b"oauth-client-json"),
        principal="operator-one",
        upload_claim=claim,
    )
    real_write = owner._write_locked  # noqa: SLF001 - durable fault injection

    def fail_uploaded(document):
        record = document["sessions"][session.id]
        if record["state"] == "uploaded":
            raise AdminSecretIngressError("control.owner_unavailable")
        real_write(document)

    monkeypatch.setattr(owner, "_write_locked", fail_uploaded)
    with pytest.raises(AdminSecretIngressError, match="control.owner_unavailable"):
        owner.commit_upload(claim, receipt)

    restarted = _owner(tmp_path)
    replay = restarted.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    replay_receipt = restarted.put_secret(
        session.id,
        bytearray(b"same-request-retry"),
        principal="operator-one",
        upload_claim=replay,
    )
    restarted.commit_upload(replay, replay_receipt)
    assert replay_receipt == receipt


def test_upload_commit_write_then_error_returns_and_replays_real_receipt(
    tmp_path, monkeypatch
) -> None:
    """Break caught: post-replace error must not hide durable upload success."""

    owner = _owner(tmp_path)
    session = _session(owner)
    claim = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    receipt = owner.put_secret(
        session.id,
        bytearray(b"original-secret"),
        principal="operator-one",
        upload_claim=claim,
    )
    real_write = owner._write_locked  # noqa: SLF001 - post-replace fault injection

    def write_then_fail(document):
        real_write(document)
        if document["sessions"][session.id]["state"] == "uploaded":
            raise AdminSecretIngressError("control.owner_unavailable")

    monkeypatch.setattr(owner, "_write_locked", write_then_fail)
    owner.commit_upload(claim, receipt)

    restarted = _owner(tmp_path)
    replay_claim = restarted.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    replay_receipt = restarted.put_secret(
        session.id,
        bytearray(b"different-retry-body"),
        principal="operator-one",
        upload_claim=replay_claim,
    )
    restarted.commit_upload(replay_claim, replay_receipt)
    capability = restarted.continue_resolve(
        principal="operator-one",
        operation="google.oauth-client-import.apply",
        account_ref="google-one",
        transaction_id=None,
        plan_digest=DIGEST,
        expected_generation=4,
        idempotency_key="idem-apply",
    )
    resolution = restarted.resolve(
        restarted.reserve_resolve(capability.session_id, capability=capability)
    )

    assert replay_receipt == receipt
    assert resolution.upload == bytearray(b"original-secret")


def test_uploaded_session_reconstructs_exact_public_continuation_after_restart(
    tmp_path,
) -> None:
    """Break caught: transport restart must not require a RAM flow grant."""

    owner = _owner(tmp_path)
    session = _session(owner)
    upload = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    receipt = owner.put_secret(
        session.id,
        bytearray(b"oauth-client-json"),
        principal="operator-one",
        upload_claim=upload,
    )
    owner.commit_upload(upload, receipt)

    capability = _owner(tmp_path).continue_resolve(
        principal="operator-one",
        operation="google.oauth-client-import.apply",
        account_ref="google-one",
        transaction_id=None,
        plan_digest=DIGEST,
        expected_generation=4,
        idempotency_key="idem-apply",
    )

    assert capability.session_id == session.id
    assert capability.upload_idempotency_key == "idem-upload"
    assert capability.receipt_generation == 5
    assert capability.reconcile_only is False
    with pytest.raises(AdminSecretIngressError, match="credential.upload_expired"):
        _owner(tmp_path).continue_resolve(
            principal="operator-two",
            operation="google.oauth-client-import.apply",
            account_ref="google-one",
            transaction_id=None,
            plan_digest=DIGEST,
            expected_generation=4,
            idempotency_key="idem-apply",
        )


def test_apply_unknown_continuation_allows_only_exact_receipt_reconciliation(
    tmp_path, monkeypatch
) -> None:
    """Break caught: active unknown must query receipt without exposing secret."""

    owner = _owner(tmp_path)
    session = _session(owner)
    upload = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    receipt = owner.put_secret(
        session.id,
        bytearray(b"oauth-client-json"),
        principal="operator-one",
        upload_claim=upload,
    )
    owner.commit_upload(upload, receipt)
    values = {
        "principal": "operator-one",
        "operation": "google.oauth-client-import.apply",
        "account_ref": "google-one",
        "credential_kind": "google.oauth-client",
        "plan_digest": DIGEST,
        "expected_generation": 4,
        "create_idempotency_key": "idem-create",
        "upload_idempotency_key": "idem-upload",
        "idempotency_key": "idem-apply",
        "receipt_generation": receipt.generation,
    }
    resolution = owner.resolve(owner.reserve_resolve(session.id, **values))
    owner.mark_resolve_unknown(resolution)

    restarted = _owner(tmp_path)
    capability = restarted.continue_resolve(
        principal="operator-one",
        operation="google.oauth-client-import.apply",
        account_ref="google-one",
        transaction_id=None,
        plan_digest=DIGEST,
        expected_generation=4,
        idempotency_key="idem-apply",
    )
    assert capability.reconcile_only is True
    resolution = restarted.resolve(
        restarted.reserve_resolve(session.id, capability=capability)
    )
    assert resolution.reconcile_only is True
    assert resolution.upload == bytearray()

    variants = (
        {"principal": "operator-two"},
        {"expected_generation": 5},
        {"plan_digest": "sha256:" + "b" * 64},
        {"idempotency_key": "idem-forged"},
    )
    exact = {
        "principal": "operator-one",
        "operation": "google.oauth-client-import.apply",
        "account_ref": "google-one",
        "transaction_id": None,
        "plan_digest": DIGEST,
        "expected_generation": 4,
        "idempotency_key": "idem-apply",
    }
    for changes in variants:
        with pytest.raises(AdminSecretIngressError, match="credential.upload_expired"):
            restarted.continue_resolve(**(exact | changes))
    monkeypatch.setattr(
        CredentialVault,
        "projection_metadata",
        lambda _vault, _session_id: ("active", receipt.generation + 1),
    )
    with pytest.raises(AdminSecretIngressError, match="control.owner_unavailable"):
        restarted.continue_resolve(**exact)


def test_tombstones_do_not_consume_active_capacity_or_reopen_create_key(
    tmp_path, monkeypatch
) -> None:
    """Break caught: pruning must retain terminal and unknown authority."""

    now = [1_000.0]
    owner = _owner(tmp_path, clock=lambda: now[0])
    monkeypatch.setattr(ingress_module, "_MAX_SESSIONS", 1)
    session = _session(owner)
    owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    now[0] = 1_121.0
    replacement = owner.create_session(
        principal="operator-one",
        account_ref="google-two",
        credential_kind="google.oauth-client",
        expected_generation=4,
        idempotency_key="idem-other",
        plan_digest=DIGEST,
    )
    assert replacement.account_ref == "google-two"

    now[0] = 1_000.0
    unknown_root = tmp_path / "unknown"
    owner = _owner(unknown_root, clock=lambda: now[0])
    session = _session(owner)
    upload = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    receipt = owner.put_secret(
        session.id,
        bytearray(b"oauth-client-json"),
        principal="operator-one",
        upload_claim=upload,
    )
    owner.commit_upload(upload, receipt)
    resolution = owner.resolve(
        owner.reserve_resolve(
            session.id,
            principal="operator-one",
            operation="google.oauth-client-import.apply",
            account_ref="google-one",
            credential_kind="google.oauth-client",
            plan_digest=DIGEST,
            expected_generation=4,
            create_idempotency_key="idem-create",
            upload_idempotency_key="idem-upload",
            idempotency_key="idem-apply",
            receipt_generation=receipt.generation,
        )
    )
    owner.mark_resolve_unknown(resolution)
    with pytest.raises(AdminSecretIngressError, match="control.owner_unavailable"):
        owner.create_session(
            principal="operator-one",
            account_ref="google-two",
            credential_kind="google.oauth-client",
            expected_generation=4,
            idempotency_key="blocked-by-live-unknown",
            plan_digest=DIGEST,
        )
    now[0] = 1_121.0
    owner._vault.revoke_account(  # noqa: SLF001 - exact pruning evidence
        session.id, expected_generation=receipt.generation
    )
    restarted = _owner(unknown_root, clock=lambda: now[0])
    replacement = restarted.create_session(
        principal="operator-one",
        account_ref="google-two",
        credential_kind="google.oauth-client",
        expected_generation=4,
        idempotency_key="idem-reconciled",
        plan_digest=DIGEST,
    )
    assert replacement.account_ref == "google-two"
    capability = restarted.continue_resolve(
        principal="operator-one",
        operation="google.oauth-client-import.apply",
        account_ref="google-one",
        transaction_id=None,
        plan_digest=DIGEST,
        expected_generation=4,
        idempotency_key="idem-apply",
    )
    assert capability.reconcile_only is True

    restarted.commit_resolve(
        restarted.resolve(restarted.reserve_resolve(session.id, capability=capability))
    )
    replay = restarted.create_session(
        principal="operator-one",
        account_ref="google-one",
        credential_kind="google.oauth-client",
        expected_generation=4,
        idempotency_key="idem-create",
        plan_digest=DIGEST,
    )
    assert replay.state == "resolved"
    with pytest.raises(AdminSecretIngressError, match="credential.upload_expired"):
        restarted.reserve_upload(
            replay.id,
            principal="operator-one",
            expected_generation=4,
            idempotency_key="replacement-body",
        )


def test_owner_write_cap_matches_read_cap_without_replacing_readable_state(
    tmp_path, monkeypatch
) -> None:
    """Break caught: owner must not publish state its own reader rejects."""

    owner = _owner(tmp_path)
    first = _session(owner)
    state_path = tmp_path / "state" / "secret-ingress.json"
    readable = state_path.read_bytes()
    monkeypatch.setattr(ingress_module, "_MAX_STATE_BYTES", len(readable))

    with pytest.raises(AdminSecretIngressError, match="control.owner_unavailable"):
        owner.create_session(
            principal="operator-one",
            account_ref="google-two",
            credential_kind="google.oauth-client",
            expected_generation=4,
            idempotency_key="state-cap-overflow",
            plan_digest=DIGEST,
        )

    assert state_path.read_bytes() == readable
    assert (
        _owner(tmp_path).create_session(
            principal="operator-one",
            account_ref="google-one",
            credential_kind="google.oauth-client",
            expected_generation=4,
            idempotency_key="idem-create",
            plan_digest=DIGEST,
        )
        == first
    )


def test_expired_resolve_in_progress_tombstone_survives_revoked_vault(
    tmp_path, monkeypatch
) -> None:
    """Break caught: crash evidence must outlive TTL and capacity reclamation."""

    now = [1_000.0]
    owner = _owner(tmp_path, clock=lambda: now[0])
    monkeypatch.setattr(ingress_module, "_MAX_SESSIONS", 1)
    session = _session(owner)
    upload = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    receipt = owner.put_secret(
        session.id,
        bytearray(b"oauth-client-json"),
        principal="operator-one",
        upload_claim=upload,
    )
    owner.commit_upload(upload, receipt)
    resolution = owner.resolve(
        owner.reserve_resolve(
            session.id,
            principal="operator-one",
            operation="google.oauth-client-import.apply",
            account_ref="google-one",
            credential_kind="google.oauth-client",
            plan_digest=DIGEST,
            expected_generation=4,
            create_idempotency_key="idem-create",
            upload_idempotency_key="idem-upload",
            idempotency_key="idem-apply",
            receipt_generation=receipt.generation,
        )
    )
    resolution.upload[:] = b"\0" * len(resolution.upload)
    resolution.upload.clear()
    with pytest.raises(AdminSecretIngressError, match="control.owner_unavailable"):
        owner.create_session(
            principal="operator-one",
            account_ref="google-two",
            credential_kind="google.oauth-client",
            expected_generation=4,
            idempotency_key="blocked-while-active",
            plan_digest=DIGEST,
        )
    owner._vault.revoke_account(  # noqa: SLF001 - exact crash evidence
        session.id, expected_generation=receipt.generation
    )
    now[0] = 1_121.0
    restarted = _owner(tmp_path, clock=lambda: now[0])
    replacement = restarted.create_session(
        principal="operator-one",
        account_ref="google-two",
        credential_kind="google.oauth-client",
        expected_generation=4,
        idempotency_key="new-active-session",
        plan_digest=DIGEST,
    )
    capability = restarted.continue_resolve(
        principal="operator-one",
        operation="google.oauth-client-import.apply",
        account_ref="google-one",
        transaction_id=None,
        plan_digest=DIGEST,
        expected_generation=4,
        idempotency_key="idem-apply",
    )

    assert replacement.account_ref == "google-two"
    assert capability.reconcile_only is True


def test_concrete_owner_persists_exact_one_shot_capability_across_restart(
    tmp_path,
) -> None:
    owner = _owner(tmp_path)
    session = _session(owner)
    upload = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    receipt = owner.put_secret(
        session.id,
        bytearray(b"oauth-client-json"),
        principal="operator-one",
        upload_claim=upload,
    )
    owner.commit_upload(upload, receipt)

    restarted = _owner(tmp_path)
    capability = restarted.reserve_resolve(
        session.id,
        principal="operator-one",
        operation="google.oauth-client-import.apply",
        account_ref="google-one",
        credential_kind="google.oauth-client",
        plan_digest=DIGEST,
        expected_generation=4,
        create_idempotency_key="idem-create",
        upload_idempotency_key="idem-upload",
        idempotency_key="idem-apply",
        receipt_generation=receipt.generation,
    )
    resolution = restarted.resolve(capability)
    assert bytes(resolution.upload) == b"oauth-client-json"
    restarted.commit_resolve(resolution)
    with pytest.raises(AdminSecretIngressError, match="credential.upload_expired"):
        restarted.reserve_resolve(
            session.id,
            principal="operator-one",
            operation="google.oauth-client-import.apply",
            account_ref="google-one",
            credential_kind="google.oauth-client",
            plan_digest=DIGEST,
            expected_generation=4,
            create_idempotency_key="idem-create",
            upload_idempotency_key="idem-upload",
            idempotency_key="idem-replay",
            receipt_generation=receipt.generation,
        )


def test_concrete_owner_rolls_back_known_owner_failure_for_idempotent_retry(
    tmp_path,
) -> None:
    owner = _owner(tmp_path)
    session = _session(owner)
    upload = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    receipt = owner.put_secret(
        session.id,
        bytearray(b"oauth-client-json"),
        principal="operator-one",
        upload_claim=upload,
    )
    owner.commit_upload(upload, receipt)
    capability = owner.reserve_resolve(
        session.id,
        principal="operator-one",
        operation="google.oauth-client-import.apply",
        account_ref="google-one",
        credential_kind="google.oauth-client",
        plan_digest=DIGEST,
        expected_generation=4,
        create_idempotency_key="idem-create",
        upload_idempotency_key="idem-upload",
        idempotency_key="idem-apply",
        receipt_generation=receipt.generation,
    )
    resolution = owner.resolve(capability)
    owner.rollback_resolve(resolution)
    retry = owner.reserve_resolve(
        session.id,
        principal="operator-one",
        operation="google.oauth-client-import.apply",
        account_ref="google-one",
        credential_kind="google.oauth-client",
        plan_digest=DIGEST,
        expected_generation=4,
        create_idempotency_key="idem-create",
        upload_idempotency_key="idem-upload",
        idempotency_key="idem-apply",
        receipt_generation=receipt.generation,
    )
    assert retry.session_id == session.id


def test_resolve_commit_reconciles_revoked_vault_after_journal_failure(
    tmp_path, monkeypatch
) -> None:
    owner = _owner(tmp_path)
    session = _session(owner)
    upload = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    receipt = owner.put_secret(
        session.id,
        bytearray(b"oauth-client-json"),
        principal="operator-one",
        upload_claim=upload,
    )
    owner.commit_upload(upload, receipt)
    claim = owner.reserve_resolve(
        session.id,
        principal="operator-one",
        operation="google.oauth-client-import.apply",
        account_ref="google-one",
        credential_kind="google.oauth-client",
        plan_digest=DIGEST,
        expected_generation=4,
        create_idempotency_key="idem-create",
        upload_idempotency_key="idem-upload",
        idempotency_key="idem-apply",
        receipt_generation=receipt.generation,
    )
    resolution = owner.resolve(claim)
    real_write = owner._write_locked  # noqa: SLF001 - durable fault injection

    def fail_resolved(document):
        record = document["sessions"][session.id]
        if record["state"] == "resolved":
            raise AdminSecretIngressError("control.owner_unavailable")
        real_write(document)

    monkeypatch.setattr(owner, "_write_locked", fail_resolved)
    with pytest.raises(AdminSecretIngressError, match="control.owner_unavailable"):
        owner.commit_resolve(resolution)

    restarted = _owner(tmp_path)
    restarted.reconcile_resolve(claim)
    with pytest.raises(AdminSecretIngressError, match="credential.upload_expired"):
        restarted.reserve_resolve(
            session.id,
            principal="operator-one",
            operation="google.oauth-client-import.apply",
            account_ref="google-one",
            credential_kind="google.oauth-client",
            plan_digest=DIGEST,
            expected_generation=4,
            create_idempotency_key="idem-create",
            upload_idempotency_key="idem-upload",
            idempotency_key="idem-apply",
            receipt_generation=receipt.generation,
        )


def test_apply_unknown_rejects_direct_secret_retry_after_restart(tmp_path) -> None:
    owner = _owner(tmp_path)
    session = _session(owner)
    upload = owner.reserve_upload(
        session.id,
        principal="operator-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    receipt = owner.put_secret(
        session.id,
        bytearray(b"oauth-client-json"),
        principal="operator-one",
        upload_claim=upload,
    )
    owner.commit_upload(upload, receipt)
    values = {
        "principal": "operator-one",
        "operation": "google.oauth-client-import.apply",
        "account_ref": "google-one",
        "credential_kind": "google.oauth-client",
        "plan_digest": DIGEST,
        "expected_generation": 4,
        "create_idempotency_key": "idem-create",
        "upload_idempotency_key": "idem-upload",
        "idempotency_key": "idem-apply",
        "receipt_generation": receipt.generation,
    }
    claim = owner.reserve_resolve(session.id, **values)
    first = owner.resolve(claim)
    owner.mark_resolve_unknown(first)

    restarted = _owner(tmp_path)
    with pytest.raises(AdminSecretIngressError, match="credential.upload_expired"):
        restarted.reserve_resolve(session.id, **values)


def test_real_service_create_put_apply_uses_concrete_owner_one_shot(tmp_path) -> None:
    _service, owners = service_at()
    composed_ingress: list[object] = []

    def google_oauth_factory(ingress: object) -> object:
        composed_ingress.append(ingress)
        return owners.google_oauth

    service = MasterjetControlService.with_admin_secret_ingress(
        secret_ingress_state_root=tmp_path / "state",
        secret_ingress_vault=CredentialVault.for_test(
            tmp_path / "vault", key=b"k" * 32, clock=lambda: 1_000.0
        ),
        operation_store=owners.operation_store,
        openai_accounts=owners.openai_accounts,
        openai_credentials=owners.openai_credentials,
        google_manager=owners.google_manager,
        google_oauth_factory=google_oauth_factory,
        quota_collector=owners.quota_collector,
        google_provisioner=owners.google_provisioner,
        google_billing=owners.google_billing,
        host_registry=owners.hosts,
        clock=lambda: 1_000.0,
    )
    assert len(composed_ingress) == 1
    assert type(composed_ingress[0]) is AdminSecretIngressOwner
    who = principal("fleet.secrets.ingress", step_up=True)
    created = command(
        service,
        "secret.ingress.create",
        {
            "account_ref": "openai-one",
            "credential_kind": "openai.auth-json",
        },
        "fleet.secrets.ingress",
        digest=DIGEST,
        step_up=True,
    )
    claim = service.reserve_secret_upload(
        who,
        created["id"],
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    receipt = service.put_secret(
        who,
        created["id"],
        bytearray(b"openai-upload"),
        upload_claim=claim,
    )
    capability = SecretIngressCapabilityV1(
        created["id"],
        "operator-one",
        "openai-one",
        "openai.auth.apply",
        "openai.auth-json",
        None,
        DIGEST,
        4,
        "request-one",
        "idem-upload",
        "request-one",
        4,
        receipt["generation"],
        1_120.0,
    )

    applied = command(
        service,
        "openai.auth.apply",
        {"account_ref": "openai-one"},
        "fleet.secrets.ingress",
        digest=DIGEST,
        ingress_session=capability,
        step_up=True,
    )

    assert applied["account_ref"] == "openai-one"
    assert owners.openai_credentials.apply_calls == 1
    with pytest.raises(Exception, match="credential.upload_expired"):
        command(
            service,
            "openai.auth.apply",
            {"account_ref": "openai-one"},
            "fleet.secrets.ingress",
            digest=DIGEST,
            ingress_session=capability,
            step_up=True,
        )
