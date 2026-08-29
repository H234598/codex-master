from __future__ import annotations

from pathlib import Path

import pytest

from codex_master.admin_secret_ingress import (
    AdminSecretIngressError,
    AdminSecretIngressOwner,
)
from codex_master.admin_service import SecretIngressCapabilityV1
from codex_master.credential_vault import CredentialVault
from test_admin_service import command, principal, service_at


DIGEST = "sha256:" + "a" * 64


def _owner(root: Path, clock=lambda: 1_000.0) -> AdminSecretIngressOwner:
    vault = CredentialVault.for_test(root / "vault", key=b"k" * 32, clock=clock)
    return AdminSecretIngressOwner(
        root / "state",
        vault=vault,
        plan_resolver=lambda kind, _account, plan_id: (
            "google-client-plan" if kind == "google.oauth-client" else "plan:" + plan_id
        ),
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
        plan_id="plan-one",
    )


def test_concrete_owner_rejects_upload_without_reserved_exact_session(tmp_path) -> None:
    owner = _owner(tmp_path)
    with pytest.raises(AdminSecretIngressError, match="credential.upload_expired"):
        owner.put_secret(
            "missing",
            bytearray(b"secret"),
            principal="operator-one",
            upload_claim=None,
        )


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
        plan_id="plan-one",
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
            plan_id="plan-one",
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
        plan_id="plan-one",
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
        plan_id="plan-one",
        plan_digest=DIGEST,
        expected_generation=4,
        create_idempotency_key="idem-create",
        upload_idempotency_key="idem-upload",
        idempotency_key="idem-apply",
        receipt_generation=receipt.generation,
    )
    assert retry.session_id == session.id


def test_real_service_create_put_apply_uses_concrete_owner_one_shot(tmp_path) -> None:
    service, owners = service_at()
    service._secret_ingress = _owner(tmp_path)  # noqa: SLF001 - injected owner port
    who = principal("fleet.secrets.ingress", "fleet.google.oauth", step_up=True)
    created = command(
        service,
        "secret.ingress.create",
        {
            "account_ref": "google-one",
            "credential_kind": "google.oauth-client",
            "plan_id": "plan-one",
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
        bytearray(b"oauth-client-json"),
        upload_claim=claim,
    )
    capability = SecretIngressCapabilityV1(
        created["id"],
        "operator-one",
        "google-one",
        "google.oauth-client-import.apply",
        "google.oauth-client",
        "plan-one",
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
        "google.oauth-client-import.apply",
        {"account_ref": "google-one", "plan_id": "plan-one"},
        "fleet.google.oauth",
        digest=DIGEST,
        ingress_session=capability,
        step_up=True,
    )

    assert applied["account_ref"] == "google-one"
    assert owners.google_oauth.calls == ["client-apply"]
    with pytest.raises(Exception, match="credential.upload_expired"):
        command(
            service,
            "google.oauth-client-import.apply",
            {"account_ref": "google-one", "plan_id": "plan-one"},
            "fleet.google.oauth",
            digest=DIGEST,
            ingress_session=capability,
            step_up=True,
        )
