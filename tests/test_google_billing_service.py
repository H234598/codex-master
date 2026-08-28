from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import re
import threading

import pytest
import yaml

import codex_master.google_account_inventory_manager as manager_module
from codex_master.google_account_inventory import GoogleAccountInventoryLoader
from codex_master.google_account_inventory_manager import (
    GoogleAccountInventoryManager,
)
from codex_master.google_billing_service import (
    GoogleBillingBindingObservationV1,
    GoogleBillingBindResultV1,
    GoogleBillingError,
    GoogleBillingService,
)
from codex_master.google_cloud_api import GoogleCloudApiError


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class FakeBillingLease:
    def __init__(
        self,
        *,
        account_ref: str = "google-one",
        subject_id: str = "subject-one",
    ) -> None:
        self.account_ref = account_ref
        self.subject_id = subject_id
        self.bindings: dict[str, str] = {}
        self.calls: list[tuple[str, ...]] = []
        self.reads: list[tuple[str, ...]] = []
        self.fail_get: str | None = None
        self.fail_create: str | None = None
        self.get_error: Exception | None = None
        self.bind_error: Exception | None = None
        self.observation_override: object | None = None
        self.bind_result_override: object | None = None
        self.revision = 0
        self.lookup_hook: Callable[[], None] | None = None

    def get_project_billing_binding(
        self, project_id: str
    ) -> GoogleBillingBindingObservationV1:
        self.reads.append(("billing.resourceAssociations.get", project_id))
        if self.get_error is not None:
            raise self.get_error
        if self.fail_get is not None:
            raise GoogleCloudApiError(self.fail_get)
        if self.observation_override is not None:
            return self.observation_override  # type: ignore[return-value]
        observed = GoogleBillingBindingObservationV1(
            billing_account_id=self.bindings.get(project_id),
            precondition=f"etag-{self.revision}",
        )
        if self.lookup_hook is not None:
            self.lookup_hook()
        return observed

    def bind_project_if_unbound(
        self,
        project_id: str,
        billing_account_id: str,
        *,
        expected_precondition: str,
    ) -> GoogleBillingBindResultV1:
        self.calls.append(
            (
                "billing.resourceAssociations.create",
                project_id,
                billing_account_id,
                expected_precondition,
            )
        )
        if self.bind_error is not None:
            raise self.bind_error
        if self.fail_create is not None:
            raise GoogleCloudApiError(self.fail_create)
        if self.bind_result_override is not None:
            return self.bind_result_override  # type: ignore[return-value]
        current = self.bindings.get(project_id)
        if expected_precondition != f"etag-{self.revision}":
            return GoogleBillingBindResultV1(
                state="conflict", billing_account_id=current
            )
        if current is not None:
            return GoogleBillingBindResultV1(
                state="already_bound" if current == billing_account_id else "conflict",
                billing_account_id=current,
            )
        self.bindings[project_id] = billing_account_id
        self.revision += 1
        return GoogleBillingBindResultV1(
            state="created", billing_account_id=billing_account_id
        )

    def external_bind(self, project_id: str, billing_account_id: str) -> None:
        self.bindings[project_id] = billing_account_id
        self.revision += 1


class BlockingBillingLease(FakeBillingLease):
    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def bind_project_if_unbound(
        self,
        project_id: str,
        billing_account_id: str,
        *,
        expected_precondition: str,
    ) -> GoogleBillingBindResultV1:
        self.entered.set()
        assert self.release.wait(timeout=5)
        return super().bind_project_if_unbound(
            project_id,
            billing_account_id,
            expected_precondition=expected_precondition,
        )


class FakeCredentialAuthority:
    def __init__(self, lease: FakeBillingLease) -> None:
        self.lease = lease
        self.requests: list[tuple[str, str]] = []
        self.fail = False

    def lease_billing_effect(
        self, account_ref: str, subject_id: str
    ) -> FakeBillingLease:
        self.requests.append((account_ref, subject_id))
        if self.fail:
            raise RuntimeError("private-credential-source-marker")
        return self.lease


class ExplodingCredentialLease:
    @property
    def account_ref(self):
        raise RuntimeError("private-lease-attestation-marker")

    @property
    def subject_id(self):
        raise RuntimeError("private-lease-attestation-marker")


class ExplodingProviderCodeError(Exception):
    @property
    def code(self):
        raise RuntimeError("private-provider-code-marker")

    def __repr__(self) -> str:
        raise AssertionError("provider repr must not run")

    def __str__(self) -> str:
        raise AssertionError("provider str must not run")


def _inventory(
    tmp_path,
    *,
    project_id: str = "provider-project-one",
    billing_id: str = "provider-billing-one",
    second_billing: bool = True,
    variant: str = "base",
):
    accounts: list[dict[str, object]] = [
        {
            "ref": "google-one",
            "login_email": "one@example.test",
            "recovery_email": None,
            "label": f"One {variant}",
            "subject_id": "subject-one",
            "billing_accounts": [
                {
                    "ref": "billing-one",
                    "billing_account_id": billing_id,
                    "label": "Primary",
                },
                {
                    "ref": "billing-other",
                    "billing_account_id": "provider-billing-other",
                    "label": "Other",
                },
            ],
            "projects": [
                {
                    "ref": "the-hive-1",
                    "billing_account_ref": None,
                    "status": "active",
                    "project_id": project_id,
                    "project_number": "100001",
                    "key_id": None,
                    "key_uid": None,
                    "secret": "synthetic-secret-not-for-output",
                }
            ],
        }
    ]
    if second_billing:
        accounts.append(
            {
                "ref": "google-two",
                "login_email": "two@example.test",
                "recovery_email": None,
                "label": "Two",
                "subject_id": "subject-two",
                "billing_accounts": [
                    {
                        "ref": "billing-two",
                        "billing_account_id": "provider-billing-two",
                        "label": "Secondary",
                    }
                ],
                "projects": [],
            }
        )
    root = tmp_path / f"inventory-{project_id}-{billing_id}-{variant}"
    root.mkdir(mode=0o700)
    path = root / "api-token.yaml"
    path.write_text(
        yaml.safe_dump(
            {"schema_version": 1, "google_accounts": accounts},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return GoogleAccountInventoryLoader._for_test_path(path).load()


def _manager(document) -> GoogleAccountInventoryManager:
    manager = GoogleAccountInventoryManager._for_test_loader(
        lambda: document,
        monotonic_clock=lambda: 0.0,
        operator_timestamp_utc=lambda: "2026-08-28T12:00:00Z",
    )
    manager.reload()
    return manager


def _unloaded_manager(document) -> GoogleAccountInventoryManager:
    return GoogleAccountInventoryManager._for_test_loader(
        lambda: document,
        monotonic_clock=lambda: 0.0,
        operator_timestamp_utc=lambda: "2026-08-28T12:00:00Z",
    )


def _service(tmp_path, *, api=None, authority=None, clock=None):
    manager = _manager(_inventory(tmp_path))
    api = api or FakeBillingLease()
    authority = authority or FakeCredentialAuthority(api)
    clock = clock or Clock()
    return (
        GoogleBillingService(manager, authority, clock=clock),
        manager,
        api,
        clock,
    )


def _apply(service, plan, **overrides):
    arguments = {
        "account_ref": plan.account_ref,
        "project_ref": plan.project_ref,
        "billing_ref": plan.billing_ref,
        "expected_generation": plan.inventory_generation,
        "confirmed_digest": plan.digest,
        "idempotency_key": plan.idempotency_key,
    }
    arguments.update(overrides)
    return service.apply_billing_binding(plan.id, **arguments)


def _replace_snapshot(
    manager: GoogleAccountInventoryManager,
    document,
    *,
    preserve_fingerprint: bool,
) -> None:
    old = manager._snapshot_for_internal_use()
    snapshot = manager_module._build_snapshot(
        document,
        generation=old.generation,
        loaded_at_utc=old.loaded_at_utc,
        source_type=old.source_type,
    )
    if preserve_fingerprint:
        snapshot = replace(snapshot, content_fingerprint=old.content_fingerprint)
    assert manager._active is not None
    manager._active = replace(manager._active, document=document, snapshot=snapshot)


def test_plan_rejects_project_and_billing_from_different_accounts(tmp_path) -> None:
    service, _, api, _ = _service(tmp_path)

    with pytest.raises(GoogleBillingError, match="billing.account_mismatch"):
        service.plan_billing_binding(
            account_ref="google-one",
            project_ref="the-hive-1",
            billing_ref="billing-two",
            expected_generation=1,
            idempotency_key="cross-account",
        )

    assert api.reads == []
    assert api.calls == []

    retry = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="cross-account",
    )
    assert retry.billing_ref == "billing-one"


def test_plan_rejects_request_account_mismatch_before_any_effect_owner(
    tmp_path,
) -> None:
    lease = FakeBillingLease()
    authority = FakeCredentialAuthority(lease)
    service, _, _, _ = _service(tmp_path, api=lease, authority=authority)

    with pytest.raises(GoogleBillingError, match="billing.account_mismatch"):
        service.plan_billing_binding(
            account_ref="google-two",
            project_ref="the-hive-1",
            billing_ref="billing-one",
            expected_generation=1,
            idempotency_key="request-account-mismatch",
        )

    assert authority.requests == []
    assert lease.reads == []
    assert lease.calls == []


def test_apply_rejects_request_binding_mismatch_before_credential_or_provider(
    tmp_path,
) -> None:
    lease = FakeBillingLease()
    authority = FakeCredentialAuthority(lease)
    service, _, _, _ = _service(tmp_path, api=lease, authority=authority)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="apply-request-binding",
    )

    with pytest.raises(GoogleBillingError, match="billing.account_mismatch"):
        service.apply_billing_binding(
            plan.id,
            account_ref="google-two",
            project_ref="the-hive-1",
            billing_ref="billing-one",
            expected_generation=1,
            confirmed_digest=plan.digest,
            idempotency_key=plan.idempotency_key,
        )

    assert authority.requests == []
    assert lease.reads == []
    assert lease.calls == []


def test_plan_binds_private_snapshot_identity_but_public_view_is_redacted(
    tmp_path,
) -> None:
    service, manager, _, _ = _service(tmp_path)

    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="bind-one",
    )

    snapshot = manager._snapshot_for_internal_use()
    assert plan.account_ref == "google-one"
    assert plan.subject_id == "subject-one"
    assert plan.inventory_generation == 1
    assert plan.snapshot_fingerprint == snapshot.content_fingerprint
    assert plan.project_ref == "the-hive-1"
    assert plan.project_id == "provider-project-one"
    assert plan.billing_ref == "billing-one"
    assert plan.billing_account_id == "provider-billing-one"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", plan.digest)
    assert plan.idempotency_key == "bind-one"
    assert "provider-project-one" not in repr(plan)
    assert "provider-billing-one" not in repr(plan)
    assert "subject-one" not in repr(plan)
    assert (
        not {
            "subject_id",
            "project_id",
            "billing_account_id",
        }
        & plan.public_projection().keys()
    )


def test_plan_idempotency_reuses_same_plan_and_rejects_changed_payload(
    tmp_path,
) -> None:
    service, _, _, _ = _service(tmp_path)
    first = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="same-key",
    )
    second = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="same-key",
    )

    assert second == first
    with pytest.raises(GoogleBillingError, match="billing.idempotency_conflict"):
        service.plan_billing_binding(
            account_ref="google-one",
            project_ref="the-hive-1",
            billing_ref="billing-other",
            expected_generation=1,
            idempotency_key="same-key",
        )


def test_apply_exposes_only_project_binding_lookup_and_create(tmp_path) -> None:
    service, _, api, _ = _service(tmp_path)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="apply-one",
    )

    receipt = _apply(service, plan)

    assert receipt.state == "succeeded"
    assert api.calls == [
        (
            "billing.resourceAssociations.create",
            "provider-project-one",
            "provider-billing-one",
            "etag-0",
        )
    ]
    assert set(call[0] for call in api.reads + api.calls) == {
        "billing.resourceAssociations.get",
        "billing.resourceAssociations.create",
    }
    assert "provider-project-one" not in repr(receipt)
    assert "provider-billing-one" not in repr(receipt)


def test_effect_credential_lease_is_requested_and_attested_for_plan_identity(
    tmp_path,
) -> None:
    lease = FakeBillingLease()
    authority = FakeCredentialAuthority(lease)
    service, _, _, _ = _service(tmp_path, api=lease, authority=authority)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="credential-one",
    )

    _apply(service, plan)

    assert authority.requests == [("google-one", "subject-one")]
    assert len(lease.calls) == 1


def test_foreign_credential_lease_fails_before_provider_access(tmp_path) -> None:
    lease = FakeBillingLease(account_ref="google-two", subject_id="subject-two")
    authority = FakeCredentialAuthority(lease)
    service, _, _, _ = _service(tmp_path, api=lease, authority=authority)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="credential-foreign",
    )

    with pytest.raises(
        GoogleBillingError, match="billing.credential_identity_mismatch"
    ):
        _apply(service, plan)

    assert authority.requests == [("google-one", "subject-one")]
    assert lease.reads == []
    assert lease.calls == []


def test_credential_authority_failure_is_typed_and_redacted(tmp_path) -> None:
    lease = FakeBillingLease()
    authority = FakeCredentialAuthority(lease)
    authority.fail = True
    service, _, _, _ = _service(tmp_path, api=lease, authority=authority)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="credential-failure",
    )

    with pytest.raises(
        GoogleBillingError, match="billing.credential_unavailable"
    ) as raised:
        _apply(service, plan)

    assert "private-credential-source-marker" not in repr(raised.value)
    assert lease.reads == []
    assert lease.calls == []


def test_credential_attestation_failure_is_typed_and_redacted(tmp_path) -> None:
    lease = ExplodingCredentialLease()
    authority = FakeCredentialAuthority(lease)  # type: ignore[arg-type]
    service, _, _, _ = _service(tmp_path, authority=authority)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="credential-attestation-failure",
    )

    with pytest.raises(
        GoogleBillingError, match="billing.credential_unavailable"
    ) as raised:
        _apply(service, plan)

    assert "private-lease-attestation-marker" not in repr(raised.value)


def test_missing_digest_or_idempotency_never_reaches_credential_authority(
    tmp_path,
) -> None:
    lease = FakeBillingLease()
    authority = FakeCredentialAuthority(lease)
    service, _, _, _ = _service(tmp_path, api=lease, authority=authority)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="required-apply",
    )

    with pytest.raises(TypeError):
        service.apply_billing_binding(
            plan.id,
            account_ref=plan.account_ref,
            project_ref=plan.project_ref,
            billing_ref=plan.billing_ref,
            expected_generation=1,
            idempotency_key=plan.idempotency_key,
        )
    with pytest.raises(TypeError):
        service.apply_billing_binding(
            plan.id,
            account_ref=plan.account_ref,
            project_ref=plan.project_ref,
            billing_ref=plan.billing_ref,
            expected_generation=1,
            confirmed_digest=plan.digest,
        )

    assert authority.requests == []
    assert lease.reads == []
    assert lease.calls == []


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"confirmed_digest": "sha256:" + "0" * 64}, "billing.plan_digest_mismatch"),
        ({"idempotency_key": "other-key"}, "billing.idempotency_conflict"),
    ],
)
def test_apply_rejects_wrong_digest_or_idempotency_before_credential(
    tmp_path, overrides, code: str
) -> None:
    lease = FakeBillingLease()
    authority = FakeCredentialAuthority(lease)
    service, _, _, _ = _service(tmp_path, api=lease, authority=authority)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="exact-apply",
    )

    with pytest.raises(GoogleBillingError, match=code):
        _apply(service, plan, **overrides)

    assert authority.requests == []
    assert lease.reads == []
    assert lease.calls == []


@pytest.mark.parametrize("state", ["empty", "closed", "reload_blocked"])
def test_manager_state_errors_are_typed_at_plan_boundary(tmp_path, state: str) -> None:
    document = _inventory(tmp_path)
    manager = _unloaded_manager(document)
    if state != "empty":
        manager.reload()
    if state == "closed":
        manager.close()
    elif state == "reload_blocked":
        manager._block_after_reload_failure("private-manager-marker")
    lease = FakeBillingLease()
    authority = FakeCredentialAuthority(lease)
    service = GoogleBillingService(manager, authority, clock=Clock())

    with pytest.raises(GoogleBillingError, match="billing.inventory_unavailable"):
        service.plan_billing_binding(
            account_ref="google-one",
            project_ref="the-hive-1",
            billing_ref="billing-one",
            expected_generation=1,
            idempotency_key="manager-state",
        )

    assert lease.reads == []
    assert lease.calls == []


def test_reload_blocked_between_status_and_snapshot_cannot_publish_plan(
    tmp_path, monkeypatch
) -> None:
    service, manager, lease, _ = _service(tmp_path)
    original_snapshot = manager._snapshot_for_internal_use

    def snapshot_after_reload_block():
        manager._block_after_reload_failure("private-manager-race-marker")
        return original_snapshot()

    monkeypatch.setattr(
        manager, "_snapshot_for_internal_use", snapshot_after_reload_block
    )

    with pytest.raises(GoogleBillingError, match="billing.inventory_unavailable"):
        service.plan_billing_binding(
            account_ref="google-one",
            project_ref="the-hive-1",
            billing_ref="billing-one",
            expected_generation=1,
            idempotency_key="manager-race",
        )

    assert lease.reads == []
    assert lease.calls == []


def test_manager_failure_is_typed_at_apply_boundary(tmp_path) -> None:
    service, manager, lease, _ = _service(tmp_path)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="manager-apply",
    )
    manager.close()

    with pytest.raises(GoogleBillingError, match="billing.inventory_unavailable"):
        _apply(service, plan)

    assert lease.reads == []
    assert lease.calls == []


def test_apply_revalidates_generation_and_fingerprint_before_api(tmp_path) -> None:
    service, manager, api, _ = _service(tmp_path)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="stale-one",
    )
    _replace_snapshot(
        manager,
        _inventory(
            tmp_path,
            project_id="provider-project-one",
            billing_id="provider-billing-one",
            variant="changed",
        ),
        preserve_fingerprint=False,
    )

    with pytest.raises(GoogleBillingError, match="billing.plan_stale"):
        _apply(service, plan)

    assert api.reads == []
    assert api.calls == []
    retry = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="stale-one",
    )
    assert retry.id != plan.id


@pytest.mark.parametrize(
    ("project_id", "billing_id"),
    [
        ("provider-project-reused", "provider-billing-one"),
        ("provider-project-one", "provider-billing-reused"),
    ],
)
def test_apply_rejects_ref_reuse_and_provider_id_change_before_api(
    tmp_path, project_id: str, billing_id: str
) -> None:
    service, manager, api, _ = _service(tmp_path)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="reuse-one",
    )
    _replace_snapshot(
        manager,
        _inventory(tmp_path, project_id=project_id, billing_id=billing_id),
        preserve_fingerprint=True,
    )

    with pytest.raises(GoogleBillingError, match="billing.binding_changed"):
        _apply(service, plan)

    assert api.reads == []
    assert api.calls == []


def test_expired_plan_stops_before_api(tmp_path) -> None:
    clock = Clock()
    service, _, api, _ = _service(tmp_path, clock=clock)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="expired-one",
        ttl_seconds=5,
    )
    clock.advance(5)

    with pytest.raises(GoogleBillingError, match="billing.plan_expired"):
        _apply(service, plan)

    assert api.reads == []
    assert api.calls == []


def test_plan_expiring_during_lookup_stops_before_effect(tmp_path) -> None:
    clock = Clock()
    lease = FakeBillingLease()
    lease.lookup_hook = lambda: clock.advance(5)
    service, _, _, _ = _service(tmp_path, api=lease, clock=clock)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="expires-during-lookup",
        ttl_seconds=5,
    )

    with pytest.raises(GoogleBillingError, match="billing.plan_expired"):
        _apply(service, plan)

    assert len(lease.reads) == 1
    assert lease.calls == []


@pytest.mark.parametrize("idempotency_key", [None, "expired-retry"])
def test_expired_plan_does_not_poison_idempotency_key(
    tmp_path, idempotency_key: str | None
) -> None:
    clock = Clock()
    service, _, _, _ = _service(tmp_path, clock=clock)
    arguments = {
        "account_ref": "google-one",
        "project_ref": "the-hive-1",
        "billing_ref": "billing-one",
        "expected_generation": 1,
        "ttl_seconds": 5,
    }
    if idempotency_key is not None:
        arguments["idempotency_key"] = idempotency_key
    first = service.plan_billing_binding(**arguments)
    clock.advance(5)

    second = service.plan_billing_binding(**arguments)

    assert second.id != first.id
    assert second.idempotency_key == first.idempotency_key


def test_unexpired_plan_collection_is_bounded(tmp_path) -> None:
    service, _, _, _ = _service(tmp_path)
    for number in range(256):
        service.plan_billing_binding(
            account_ref="google-one",
            project_ref="the-hive-1",
            billing_ref="billing-one",
            expected_generation=1,
            idempotency_key=f"bounded-{number}",
        )

    with pytest.raises(GoogleBillingError, match="billing.plan_limit"):
        service.plan_billing_binding(
            account_ref="google-one",
            project_ref="the-hive-1",
            billing_ref="billing-one",
            expected_generation=1,
            idempotency_key="bounded-overflow",
        )


def test_existing_foreign_binding_is_never_replaced(tmp_path) -> None:
    api = FakeBillingLease()
    api.bindings["provider-project-one"] = "provider-billing-foreign"
    service, _, _, _ = _service(tmp_path, api=api)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="foreign-one",
    )

    with pytest.raises(GoogleBillingError, match="billing.foreign_binding"):
        _apply(service, plan)

    assert api.calls == []
    assert api.bindings == {"provider-project-one": "provider-billing-foreign"}


def test_provider_race_to_foreign_binding_is_cas_blocked(tmp_path) -> None:
    lease = FakeBillingLease()
    lease.lookup_hook = lambda: lease.external_bind(
        "provider-project-one", "provider-billing-foreign"
    )
    service, _, _, _ = _service(tmp_path, api=lease)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="provider-race",
    )

    with pytest.raises(GoogleBillingError, match="billing.foreign_binding"):
        _apply(service, plan)

    assert lease.calls == [
        (
            "billing.resourceAssociations.create",
            "provider-project-one",
            "provider-billing-one",
            "etag-0",
        )
    ]
    assert lease.bindings == {"provider-project-one": "provider-billing-foreign"}


def test_malformed_binding_lookup_is_redacted_before_mutation(tmp_path) -> None:
    api = FakeBillingLease()
    api.bindings["provider-project-one"] = 7  # type: ignore[assignment]
    service, _, _, _ = _service(tmp_path, api=api)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="malformed-one",
    )

    with pytest.raises(
        GoogleBillingError, match="billing.provider_response_invalid"
    ) as raised:
        _apply(service, plan)

    assert raised.value.partial is None
    assert api.calls == []


@pytest.mark.parametrize(
    "observation",
    [
        GoogleBillingBindingObservationV1(
            billing_account_id=chr(0xD800), precondition="etag-0"
        ),
        GoogleBillingBindingObservationV1(
            billing_account_id=None, precondition=chr(0xD800)
        ),
    ],
    ids=["billing-account-surrogate", "precondition-surrogate"],
)
def test_provider_observation_surrogate_is_typed_and_redacted(
    tmp_path, observation: GoogleBillingBindingObservationV1
) -> None:
    lease = FakeBillingLease()
    lease.observation_override = observation
    service, _, _, _ = _service(tmp_path, api=lease)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="observation-surrogate",
    )

    with pytest.raises(
        GoogleBillingError, match="billing.provider_response_invalid"
    ) as raised:
        _apply(service, plan)

    assert raised.value.partial is None
    assert lease.calls == []


def test_provider_bind_result_surrogate_is_typed_and_redacted(tmp_path) -> None:
    lease = FakeBillingLease()
    lease.bind_result_override = GoogleBillingBindResultV1(
        state="created", billing_account_id=chr(0xD800)
    )
    service, _, _, _ = _service(tmp_path, api=lease)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="bind-result-surrogate",
    )

    with pytest.raises(
        GoogleBillingError, match="billing.provider_response_invalid"
    ) as raised:
        _apply(service, plan)

    assert raised.value.partial is not None
    assert raised.value.partial.reason_code == "billing.provider_response_invalid"


@pytest.mark.parametrize("phase", ["lookup", "bind"])
def test_exploding_provider_code_property_is_typed_and_redacted(
    tmp_path, phase: str
) -> None:
    lease = FakeBillingLease()
    if phase == "lookup":
        lease.get_error = ExplodingProviderCodeError()
    else:
        lease.bind_error = ExplodingProviderCodeError()
    service, _, _, _ = _service(tmp_path, api=lease)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key=f"exploding-code-{phase}",
    )

    with pytest.raises(GoogleBillingError, match="billing.provider_failed") as raised:
        _apply(service, plan)

    assert "private-provider-code-marker" not in repr(raised.value)
    assert (raised.value.partial is not None) is (phase == "bind")


def test_repeated_and_concurrent_apply_create_one_association(tmp_path) -> None:
    api = BlockingBillingLease()
    service, _, _, _ = _service(tmp_path, api=api)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="concurrent-one",
    )
    receipts = []

    def apply() -> None:
        receipts.append(_apply(service, plan))

    first = threading.Thread(target=apply)
    second = threading.Thread(target=apply)
    first.start()
    assert api.entered.wait(timeout=5)
    second.start()
    api.release.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert len(receipts) == 2
    assert receipts[0] == receipts[1]
    assert len(api.calls) == 1
    assert _apply(service, plan) == receipts[0]
    assert len(api.calls) == 1


@pytest.mark.parametrize(
    ("provider_code", "public_code"),
    [
        ("google.api_auth_failed", "billing.provider_auth_failed"),
        ("google.api_unavailable", "billing.provider_unavailable"),
        ("google.api_response_invalid", "billing.provider_response_invalid"),
    ],
)
def test_provider_failures_are_structured_redacted_and_retryable(
    tmp_path, provider_code: str, public_code: str
) -> None:
    api = FakeBillingLease()
    api.fail_create = provider_code
    service, _, _, _ = _service(tmp_path, api=api)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="provider-one",
    )

    with pytest.raises(GoogleBillingError, match=public_code) as raised:
        _apply(service, plan)

    assert raised.value.code == public_code
    assert raised.value.partial is not None
    assert raised.value.partial.state == "partial"
    assert raised.value.partial.reason_code == public_code
    assert provider_code not in repr(raised.value.partial)
    assert "provider-project-one" not in repr(raised.value.partial)
    assert "provider-billing-one" not in repr(raised.value.partial)


def test_provider_lookup_failure_is_typed_without_partial_effect(tmp_path) -> None:
    lease = FakeBillingLease()
    lease.fail_get = "google.api_unavailable"
    service, _, _, _ = _service(tmp_path, api=lease)
    plan = service.plan_billing_binding(
        account_ref="google-one",
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="provider-lookup-failure",
    )

    with pytest.raises(
        GoogleBillingError, match="billing.provider_unavailable"
    ) as raised:
        _apply(service, plan)

    assert raised.value.partial is None
    assert lease.calls == []
