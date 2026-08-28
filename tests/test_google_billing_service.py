from __future__ import annotations

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


class FakeBillingApi:
    def __init__(self) -> None:
        self.bindings: dict[str, str] = {}
        self.calls: list[tuple[str, ...]] = []
        self.reads: list[tuple[str, ...]] = []
        self.fail_get: str | None = None
        self.fail_create: str | None = None

    def get_project_billing_binding(self, project_id: str) -> str | None:
        self.reads.append(("billing.resourceAssociations.get", project_id))
        if self.fail_get is not None:
            raise GoogleCloudApiError(self.fail_get)
        return self.bindings.get(project_id)

    def create_project_billing_binding(
        self, project_id: str, billing_account_id: str
    ) -> None:
        self.calls.append(
            (
                "billing.resourceAssociations.create",
                project_id,
                billing_account_id,
            )
        )
        if self.fail_create is not None:
            raise GoogleCloudApiError(self.fail_create)
        self.bindings[project_id] = billing_account_id


class BlockingBillingApi(FakeBillingApi):
    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def create_project_billing_binding(
        self, project_id: str, billing_account_id: str
    ) -> None:
        self.calls.append(
            (
                "billing.resourceAssociations.create",
                project_id,
                billing_account_id,
            )
        )
        self.entered.set()
        assert self.release.wait(timeout=5)
        self.bindings[project_id] = billing_account_id


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


def _service(tmp_path, *, api=None, clock=None):
    manager = _manager(_inventory(tmp_path))
    api = api or FakeBillingApi()
    clock = clock or Clock()
    return GoogleBillingService(manager, api, clock=clock), manager, api, clock


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
            project_ref="the-hive-1",
            billing_ref="billing-two",
            expected_generation=1,
            idempotency_key="cross-account",
        )

    assert api.reads == []
    assert api.calls == []


def test_plan_binds_private_snapshot_identity_but_public_view_is_redacted(
    tmp_path,
) -> None:
    service, manager, _, _ = _service(tmp_path)

    plan = service.plan_billing_binding(
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
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="same-key",
    )
    second = service.plan_billing_binding(
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="same-key",
    )

    assert second == first
    with pytest.raises(GoogleBillingError, match="billing.idempotency_conflict"):
        service.plan_billing_binding(
            project_ref="the-hive-1",
            billing_ref="billing-other",
            expected_generation=1,
            idempotency_key="same-key",
        )


def test_apply_exposes_only_project_binding_lookup_and_create(tmp_path) -> None:
    service, _, api, _ = _service(tmp_path)
    plan = service.plan_billing_binding(
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="apply-one",
    )

    receipt = service.apply_billing_binding(plan.id, expected_generation=1)

    assert receipt.state == "succeeded"
    assert api.calls == [
        (
            "billing.resourceAssociations.create",
            "provider-project-one",
            "provider-billing-one",
        )
    ]
    assert set(call[0] for call in api.reads + api.calls) == {
        "billing.resourceAssociations.get",
        "billing.resourceAssociations.create",
    }
    assert "provider-project-one" not in repr(receipt)
    assert "provider-billing-one" not in repr(receipt)


def test_apply_revalidates_generation_and_fingerprint_before_api(tmp_path) -> None:
    service, manager, api, _ = _service(tmp_path)
    plan = service.plan_billing_binding(
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
        service.apply_billing_binding(plan.id, expected_generation=1)

    assert api.reads == []
    assert api.calls == []


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
        service.apply_billing_binding(plan.id, expected_generation=1)

    assert api.reads == []
    assert api.calls == []


def test_expired_plan_stops_before_api(tmp_path) -> None:
    clock = Clock()
    service, _, api, _ = _service(tmp_path, clock=clock)
    plan = service.plan_billing_binding(
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="expired-one",
        ttl_seconds=5,
    )
    clock.advance(5)

    with pytest.raises(GoogleBillingError, match="billing.plan_expired"):
        service.apply_billing_binding(plan.id, expected_generation=1)

    assert api.reads == []
    assert api.calls == []


def test_existing_foreign_binding_is_never_replaced(tmp_path) -> None:
    api = FakeBillingApi()
    api.bindings["provider-project-one"] = "provider-billing-foreign"
    service, _, _, _ = _service(tmp_path, api=api)
    plan = service.plan_billing_binding(
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="foreign-one",
    )

    with pytest.raises(GoogleBillingError, match="billing.foreign_binding"):
        service.apply_billing_binding(plan.id, expected_generation=1)

    assert api.calls == []
    assert api.bindings == {"provider-project-one": "provider-billing-foreign"}


def test_malformed_binding_lookup_is_redacted_before_mutation(tmp_path) -> None:
    api = FakeBillingApi()
    api.bindings["provider-project-one"] = 7  # type: ignore[assignment]
    service, _, _, _ = _service(tmp_path, api=api)
    plan = service.plan_billing_binding(
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="malformed-one",
    )

    with pytest.raises(
        GoogleBillingError, match="billing.provider_response_invalid"
    ) as raised:
        service.apply_billing_binding(plan.id, expected_generation=1)

    assert raised.value.partial is None
    assert api.calls == []


def test_repeated_and_concurrent_apply_create_one_association(tmp_path) -> None:
    api = BlockingBillingApi()
    service, _, _, _ = _service(tmp_path, api=api)
    plan = service.plan_billing_binding(
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="concurrent-one",
    )
    receipts = []

    def apply() -> None:
        receipts.append(service.apply_billing_binding(plan.id, expected_generation=1))

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
    assert service.apply_billing_binding(plan.id, expected_generation=1) == receipts[0]
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
    api = FakeBillingApi()
    api.fail_create = provider_code
    service, _, _, _ = _service(tmp_path, api=api)
    plan = service.plan_billing_binding(
        project_ref="the-hive-1",
        billing_ref="billing-one",
        expected_generation=1,
        idempotency_key="provider-one",
    )

    with pytest.raises(GoogleBillingError, match=public_code) as raised:
        service.apply_billing_binding(plan.id, expected_generation=1)

    assert raised.value.code == public_code
    assert raised.value.partial is not None
    assert raised.value.partial.state == "partial"
    assert raised.value.partial.reason_code == public_code
    assert provider_code not in repr(raised.value.partial)
    assert "provider-project-one" not in repr(raised.value.partial)
    assert "provider-billing-one" not in repr(raised.value.partial)
