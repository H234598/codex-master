from __future__ import annotations

import copy
import re

import pytest

from codex_master.google_cloud_api import GoogleCloudApiError
from codex_master.google_cloud_provisioner import (
    GoogleCloudProvisionerError,
    GoogleQuotaEvidenceV1,
    ProvisionPartialReceipt,
    build_fill_to_quota_plan,
    execute_fill_to_quota_plan,
)


NOW = "2026-08-28T12:01:00Z"
INVENTORY_GENERATION = 7
INVENTORY_FINGERPRINT = "sha256:" + "a" * 64


def test_google_cloud_provisioner_error_repr_contains_only_code() -> None:
    error = GoogleCloudProvisionerError("provisioner.synthetic")

    assert repr(error) == "GoogleCloudProvisionerError('provisioner.synthetic')"


def _evidence(
    remaining: object,
    *,
    observed_at: object = "2026-08-28T12:00:00Z",
    source: object = "cloudresourcemanager",
    account_ref: object = "google-account-01",
    inventory_generation: object = INVENTORY_GENERATION,
    inventory_fingerprint: object = INVENTORY_FINGERPRINT,
) -> GoogleQuotaEvidenceV1:
    return GoogleQuotaEvidenceV1(
        remaining=remaining,
        observed_at=observed_at,
        source=source,
        account_ref=account_ref,
        inventory_generation=inventory_generation,
        inventory_fingerprint=inventory_fingerprint,
    )


def _execute(plan, *, api, store, now: str = NOW, binding=None):
    return execute_fill_to_quota_plan(
        plan,
        api=api,
        store=store,
        confirmed_fingerprint=plan.fingerprint,
        now=lambda: now,
        current_inventory=lambda: (
            binding or (INVENTORY_GENERATION, INVENTORY_FINGERPRINT)
        ),
    )


def _document() -> dict[str, object]:
    return {
        "schema_version": 2,
        "google_accounts": [
            {
                "ref": "google-account-01",
                "login_email": "one@example.test",
                "recovery_email": None,
                "subject_id": "subject-one",
                "billing_accounts": [],
                "projects": [
                    {
                        "ref": "the-hive-19",
                        "purpose": "oauth_control",
                        "project_name": "Quietglow Aurorabay",
                        "billing_account_ref": None,
                        "status": "active",
                        "project_id": "control-project-a1b2c3",
                        "project_number": "100019",
                        "key_id": None,
                        "key_uid": None,
                        "key_name": None,
                        "secret": None,
                    }
                ],
            },
            {
                "ref": "google-account-02",
                "login_email": "two@example.test",
                "recovery_email": None,
                "subject_id": "subject-two",
                "billing_accounts": [],
                "projects": [
                    {
                        "ref": "the-hive-40",
                        "purpose": "hive",
                        "project_name": "Brightbloom Meadowglen",
                        "billing_account_ref": None,
                        "status": "active",
                        "project_id": "bright-meadow-a1b2c3",
                        "project_number": "100040",
                        "key_id": "key-existing",
                        "key_uid": "uid-existing",
                        "key_name": "Brightbloom Meadowglen Key",
                        "secret": "private-existing-secret",
                    }
                ],
            },
        ],
    }


class MemoryStore:
    def __init__(self, document: dict[str, object]) -> None:
        self.document = copy.deepcopy(document)
        self.writes = 0

    def atomic_update(self, transform):
        candidate = copy.deepcopy(self.document)
        transform(candidate)
        self.document = candidate
        self.writes += 1

    def _read(self):
        return b"", copy.deepcopy(self.document)


class FakeApi:
    def __init__(
        self, *, subject: str = "subject-one", fail_create_at: int | None = None
    ) -> None:
        self.subject = subject
        self.fail_create_at = fail_create_at
        self.created: list[tuple[str, str]] = []
        self.enabled: list[str] = []
        self.keys: list[tuple[str, str]] = []
        self.existing_keys: dict[str, list[dict[str, object]]] = {}

    def subject_id(self):
        return self.subject

    def create_project(self, project_id, project_name):
        if self.fail_create_at == len(self.created):
            raise GoogleCloudApiError("google.api_quota_exhausted")
        self.created.append((project_id, project_name))
        return {
            "projectId": project_id,
            "name": f"projects/{200000 + len(self.created)}",
        }

    def enable_required_services(self, project_number):
        self.enabled.append(project_number)
        return {}

    def list_keys(self, project_number):
        return copy.deepcopy(self.existing_keys.get(project_number, []))

    def get_key_string(self, key_name):
        return "private-recovered-key"

    def create_restricted_key(self, project_number, display_name):
        self.keys.append((project_number, display_name))
        number = len(self.keys)
        return {
            "name": f"projects/{project_number}/locations/global/keys/key-{number}",
            "uid": f"uid-{number}",
            "keyString": f"private-key-{number}",
            "displayName": display_name,
        }


class PhaseFailApi(FakeApi):
    def __init__(self, phase: str, code: str = "google.api_quota_exhausted") -> None:
        super().__init__()
        self.phase = phase
        self.code = code

    def subject_id(self):
        if self.phase == "setup":
            raise GoogleCloudApiError(self.code)
        return super().subject_id()

    def create_project(self, project_id, project_name):
        if self.phase == "project_create":
            raise GoogleCloudApiError(self.code)
        return super().create_project(project_id, project_name)

    def enable_required_services(self, project_number):
        if self.phase == "services":
            raise GoogleCloudApiError(self.code)
        return super().enable_required_services(project_number)

    def list_keys(self, project_number):
        if self.phase == "api_key":
            raise GoogleCloudApiError(self.code)
        return super().list_keys(project_number)


def test_plan_uses_fresh_provider_quota_above_ten_and_global_refs() -> None:
    plan = build_fill_to_quota_plan(
        _document(),
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(13),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names={"Quietglow Aurorabay"},
        reserved_project_ids={"control-project-a1b2c3"},
    )

    assert len(plan.projects) == 13
    assert plan.projects[0].ref == "the-hive-41"
    assert plan.projects[-1].ref == "the-hive-53"
    assert all(not re.search(r"\d", item.project_name) for item in plan.projects)
    assert all(not re.search(r"\d", item.key_display_name) for item in plan.projects)
    assert all(
        "the-hive" not in item.key_display_name.casefold() for item in plan.projects
    )
    assert "private-existing-secret" not in repr(plan)


def test_zero_quota_plans_no_project() -> None:
    plan = build_fill_to_quota_plan(
        _document(),
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(0),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )
    assert plan.projects == ()


def test_execute_persists_after_each_external_stage_and_restricts_key() -> None:
    document = _document()
    plan = build_fill_to_quota_plan(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(1),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )
    store = MemoryStore(document)
    api = FakeApi()

    receipt = _execute(plan, api=api, store=store)

    assert receipt.completed == 1
    assert store.writes == 3
    added = store.document["google_accounts"][0]["projects"][-1]
    assert added["status"] == "active"
    assert added["secret"] == "private-key-1"
    assert added["project_name"] == plan.projects[0].project_name
    assert added["key_name"] == plan.projects[0].key_display_name
    assert api.keys[0][1] == plan.projects[0].key_display_name


def test_subject_or_plan_fingerprint_mismatch_stops_before_mutation() -> None:
    document = _document()
    plan = build_fill_to_quota_plan(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(1),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )
    for api, fingerprint in (
        (FakeApi(subject="wrong"), plan.fingerprint),
        (FakeApi(), "wrong"),
    ):
        store = MemoryStore(document)
        with pytest.raises(GoogleCloudProvisionerError):
            execute_fill_to_quota_plan(
                plan,
                api=api,
                store=store,
                confirmed_fingerprint=fingerprint,
                now=lambda: NOW,
                current_inventory=lambda: (
                    INVENTORY_GENERATION,
                    INVENTORY_FINGERPRINT,
                ),
            )
        assert api.created == []
        assert store.writes == 0


def test_first_create_failure_stops_remaining_batch_without_rollback() -> None:
    document = _document()
    plan = build_fill_to_quota_plan(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(3),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )
    store = MemoryStore(document)
    api = FakeApi(fail_create_at=1)

    with pytest.raises(
        GoogleCloudProvisionerError, match="quota.provider_exhausted"
    ) as caught:
        _execute(plan, api=api, store=store)

    assert len(api.created) == 1
    assert len(api.keys) == 1
    assert store.writes == 3
    assert caught.value.partial == ProvisionPartialReceipt(
        attempted=2,
        completed=1,
        planned=3,
        failed=1,
        not_attempted=1,
        reason_code="quota.provider_exhausted",
    )


@pytest.mark.parametrize(
    ("phase", "reason_code"),
    [
        ("services", "provisioner.services_retryable"),
        ("api_key", "provisioner.api_key_retryable"),
    ],
)
def test_non_create_429_keeps_phase_and_exact_partial_counts(
    phase: str, reason_code: str
) -> None:
    document = _document()
    plan = build_fill_to_quota_plan(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(3),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )

    with pytest.raises(GoogleCloudProvisionerError, match=reason_code) as caught:
        _execute(plan, api=PhaseFailApi(phase), store=MemoryStore(document))

    assert caught.value.partial == ProvisionPartialReceipt(
        attempted=1,
        completed=0,
        planned=3,
        failed=1,
        not_attempted=2,
        reason_code=reason_code,
    )


def test_setup_429_attempts_no_project_and_keeps_setup_phase() -> None:
    document = _document()
    plan = build_fill_to_quota_plan(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(3),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )

    with pytest.raises(
        GoogleCloudProvisionerError, match="provisioner.setup_retryable"
    ) as caught:
        _execute(plan, api=PhaseFailApi("setup"), store=MemoryStore(document))

    assert caught.value.partial == ProvisionPartialReceipt(
        attempted=0,
        completed=0,
        planned=3,
        failed=0,
        not_attempted=3,
        reason_code="provisioner.setup_retryable",
    )


@pytest.mark.parametrize(
    ("phase", "provider_code", "reason_code", "attempted", "failed"),
    [
        ("setup", "google.api_unavailable", "provisioner.setup_retryable", 0, 0),
        ("setup", "google.api_auth_failed", "provisioner.setup_failed", 0, 0),
        ("setup", "google.api_conflict", "provisioner.setup_conflict", 0, 0),
        (
            "setup",
            "google.api_response_invalid",
            "provisioner.setup_provider_contract",
            0,
            0,
        ),
        (
            "project_create",
            "google.api_unavailable",
            "provisioner.project_create_retryable",
            1,
            1,
        ),
        (
            "project_create",
            "google.api_auth_failed",
            "provisioner.project_create_failed",
            1,
            1,
        ),
        (
            "project_create",
            "google.api_conflict",
            "provisioner.project_create_conflict",
            1,
            1,
        ),
        (
            "project_create",
            "google.api_response_invalid",
            "provisioner.project_create_provider_contract",
            1,
            1,
        ),
        (
            "services",
            "google.api_unavailable",
            "provisioner.services_retryable",
            1,
            1,
        ),
        (
            "services",
            "google.api_auth_failed",
            "provisioner.services_failed",
            1,
            1,
        ),
        (
            "services",
            "google.api_conflict",
            "provisioner.services_conflict",
            1,
            1,
        ),
        (
            "services",
            "google.api_response_invalid",
            "provisioner.services_provider_contract",
            1,
            1,
        ),
        (
            "api_key",
            "google.api_unavailable",
            "provisioner.api_key_retryable",
            1,
            1,
        ),
        (
            "api_key",
            "google.api_auth_failed",
            "provisioner.api_key_failed",
            1,
            1,
        ),
        (
            "api_key",
            "google.api_conflict",
            "provisioner.api_key_conflict",
            1,
            1,
        ),
        (
            "api_key",
            "google.api_response_invalid",
            "provisioner.api_key_provider_contract",
            1,
            1,
        ),
    ],
)
def test_provider_errors_keep_phase_retry_semantics_and_exact_counts(
    phase: str,
    provider_code: str,
    reason_code: str,
    attempted: int,
    failed: int,
) -> None:
    document = _document()
    plan = build_fill_to_quota_plan(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(3),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )

    with pytest.raises(GoogleCloudProvisionerError, match=reason_code) as caught:
        _execute(
            plan,
            api=PhaseFailApi(phase, provider_code),
            store=MemoryStore(document),
        )

    assert caught.value.partial == ProvisionPartialReceipt(
        attempted=attempted,
        completed=0,
        planned=3,
        failed=failed,
        not_attempted=3 - attempted,
        reason_code=reason_code,
    )


@pytest.mark.parametrize("phase", ["project_create", "api_key"])
def test_malformed_provider_payload_is_permanent_contract_failure(phase: str) -> None:
    document = _document()
    plan = build_fill_to_quota_plan(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(1),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )

    class MalformedApi(FakeApi):
        def create_project(self, project_id, project_name):
            if phase == "project_create":
                return {"unexpected": "provider payload"}
            return super().create_project(project_id, project_name)

        def create_restricted_key(self, project_number, display_name):
            if phase == "api_key":
                return {"unexpected": "provider payload"}
            return super().create_restricted_key(project_number, display_name)

    reason_code = f"provisioner.{phase}_provider_contract"
    with pytest.raises(GoogleCloudProvisionerError, match=reason_code) as caught:
        _execute(plan, api=MalformedApi(), store=MemoryStore(document))

    assert caught.value.partial == ProvisionPartialReceipt(
        attempted=1,
        completed=0,
        planned=1,
        failed=1,
        not_attempted=0,
        reason_code=reason_code,
    )


def test_plan_resumes_partial_projects_before_using_current_quota() -> None:
    document = _document()
    document["google_accounts"][0]["projects"].append(
        {
            "ref": "the-hive-41",
            "purpose": "hive",
            "project_name": "Calmbright Robinfield",
            "billing_account_ref": None,
            "status": "services_enabled",
            "project_id": "calmbright-robinfield-a1b2c3",
            "project_number": "200041",
            "key_id": None,
            "key_uid": None,
            "key_name": "Calmbright Robinfield Key",
            "secret": None,
        }
    )

    plan = build_fill_to_quota_plan(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(2),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names={"Calmbright Robinfield"},
        reserved_project_ids={"calmbright-robinfield-a1b2c3"},
    )

    assert len(plan.projects) == 3
    assert plan.projects[0].ref == "the-hive-41"
    assert plan.projects[0].expected_project_number == "200041"
    assert plan.projects[1].expected_project_number is None
    assert plan.projects[1].ref == "the-hive-42"
    assert plan.projects[2].ref == "the-hive-43"


def test_execute_adopts_existing_key_when_resuming_services_enabled() -> None:
    document = _document()
    partial = {
        "ref": "the-hive-41",
        "purpose": "hive",
        "project_name": "Calmbright Robinfield",
        "billing_account_ref": None,
        "status": "services_enabled",
        "project_id": "calmbright-robinfield-a1b2c3",
        "project_number": "200041",
        "key_id": None,
        "key_uid": None,
        "key_name": "Calmbright Robinfield Key",
        "secret": None,
    }
    document["google_accounts"][0]["projects"].append(partial)
    plan = build_fill_to_quota_plan(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(0),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names={partial["project_name"]},
        reserved_project_ids={partial["project_id"]},
    )
    store = MemoryStore(document)
    api = FakeApi()
    api.existing_keys["200041"] = [
        {
            "name": "projects/200041/locations/global/keys/key-existing",
            "uid": "uid-existing",
            "displayName": "Calmbright Robinfield Key",
            "restrictions": {
                "apiTargets": [{"service": "generativelanguage.googleapis.com"}]
            },
        }
    ]

    receipt = _execute(plan, api=api, store=store)

    assert receipt == type(receipt)(completed=1, planned=1)
    assert api.created == []
    assert api.enabled == []
    assert api.keys == []
    project = store.document["google_accounts"][0]["projects"][-1]
    assert project["status"] == "active"
    assert project["key_id"] == "key-existing"
    assert project["secret"] == "private-recovered-key"


@pytest.mark.parametrize("remaining", [-1, 10_001, True, 1.0, None])
def test_invalid_provider_quota_never_builds_plan(remaining: object) -> None:
    with pytest.raises(GoogleCloudProvisionerError, match="quota.evidence_invalid"):
        build_fill_to_quota_plan(
            _document(),
            account_ref="google-account-01",
            expected_subject_id="subject-one",
            quota_evidence=_evidence(remaining),
            inventory_generation=INVENTORY_GENERATION,
            inventory_fingerprint=INVENTORY_FINGERPRINT,
            now=NOW,
            visible_project_names=set(),
            reserved_project_ids=set(),
        )


@pytest.mark.parametrize(
    ("observed_at", "code"),
    [
        ("2026-08-28T11:55:59Z", "quota.evidence_stale"),
        ("2026-08-28T12:01:31Z", "quota.evidence_future"),
        ("2026-08-28T12:00:00", "quota.evidence_invalid"),
        ("2026-08-28T14:00:00+02:00", "quota.evidence_invalid"),
    ],
)
def test_stale_future_or_non_utc_quota_never_builds_plan(
    observed_at: object, code: str
) -> None:
    with pytest.raises(GoogleCloudProvisionerError, match=code):
        build_fill_to_quota_plan(
            _document(),
            account_ref="google-account-01",
            expected_subject_id="subject-one",
            quota_evidence=_evidence(1, observed_at=observed_at),
            inventory_generation=INVENTORY_GENERATION,
            inventory_fingerprint=INVENTORY_FINGERPRINT,
            now=NOW,
            visible_project_names=set(),
            reserved_project_ids=set(),
        )


@pytest.mark.parametrize(
    ("evidence", "generation", "code"),
    [
        (
            _evidence(1, account_ref="google-account-02"),
            7,
            "quota.evidence_account_mismatch",
        ),
        (_evidence(1, inventory_generation=8), 7, "quota.evidence_generation_mismatch"),
        (_evidence(1, source="operator"), 7, "quota.evidence_source_invalid"),
    ],
)
def test_wrong_quota_binding_never_builds_plan(
    evidence: GoogleQuotaEvidenceV1, generation: int, code: str
) -> None:
    with pytest.raises(GoogleCloudProvisionerError, match=code):
        build_fill_to_quota_plan(
            _document(),
            account_ref="google-account-01",
            expected_subject_id="subject-one",
            quota_evidence=evidence,
            inventory_generation=generation,
            inventory_fingerprint=evidence.inventory_fingerprint,
            now=NOW,
            visible_project_names=set(),
            reserved_project_ids=set(),
        )


def test_plan_fingerprint_canonically_binds_complete_quota_evidence() -> None:
    plan = build_fill_to_quota_plan(
        _document(),
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(0),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )
    changed_observation = build_fill_to_quota_plan(
        _document(),
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(0, observed_at="2026-08-28T12:00:01Z"),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )
    changed_generation = build_fill_to_quota_plan(
        _document(),
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(0, inventory_generation=8),
        inventory_generation=8,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )

    assert plan.fingerprint == (
        "sha256:5a40f365bea49c548f820d1039bb007c675dc7c939738cf78fab589d68b69239"
    )
    assert changed_observation.fingerprint != plan.fingerprint
    assert changed_generation.fingerprint != plan.fingerprint


def test_same_inventory_and_quota_evidence_rebuild_same_plan() -> None:
    arguments = {
        "account_ref": "google-account-01",
        "expected_subject_id": "subject-one",
        "quota_evidence": _evidence(2),
        "inventory_generation": INVENTORY_GENERATION,
        "inventory_fingerprint": INVENTORY_FINGERPRINT,
        "now": NOW,
        "visible_project_names": {"Quietglow Aurorabay"},
        "reserved_project_ids": {"control-project-a1b2c3"},
    }

    first = build_fill_to_quota_plan(_document(), **arguments)
    second = build_fill_to_quota_plan(_document(), **arguments)

    assert second == first


def test_restart_same_generation_changed_inventory_fingerprint_rejects_old_evidence() -> (
    None
):
    with pytest.raises(
        GoogleCloudProvisionerError, match="quota.evidence_inventory_mismatch"
    ):
        build_fill_to_quota_plan(
            _document(),
            account_ref="google-account-01",
            expected_subject_id="subject-one",
            quota_evidence=_evidence(1),
            inventory_generation=INVENTORY_GENERATION,
            inventory_fingerprint="sha256:" + "b" * 64,
            now=NOW,
            visible_project_names=set(),
            reserved_project_ids=set(),
        )


def test_resume_project_number_is_bound_to_plan_and_fingerprint() -> None:
    original = _document()
    partial = {
        "ref": "the-hive-41",
        "purpose": "hive",
        "project_name": "Calmbright Robinfield",
        "billing_account_ref": None,
        "status": "services_enabled",
        "project_id": "calmbright-robinfield-a1b2c3",
        "project_number": "200041",
        "key_id": None,
        "key_uid": None,
        "key_name": "Calmbright Robinfield Key",
        "secret": None,
    }
    original["google_accounts"][0]["projects"].append(partial)
    plan = build_fill_to_quota_plan(
        original,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(0),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names={"Calmbright Robinfield"},
        reserved_project_ids={"calmbright-robinfield-a1b2c3"},
    )
    changed = copy.deepcopy(original)
    changed["google_accounts"][0]["projects"][-1]["project_number"] = "999999"
    changed_plan = build_fill_to_quota_plan(
        changed,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(0),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names={"Calmbright Robinfield"},
        reserved_project_ids={"calmbright-robinfield-a1b2c3"},
    )
    api = FakeApi()

    with pytest.raises(
        GoogleCloudProvisionerError, match="provisioner.inventory_conflict"
    ):
        _execute(plan, api=api, store=MemoryStore(changed))

    assert changed_plan.fingerprint != plan.fingerprint
    assert api.enabled == []
    assert api.keys == []


@pytest.mark.parametrize(
    ("now", "binding", "code"),
    [
        (
            "2026-08-28T12:05:01Z",
            (INVENTORY_GENERATION, INVENTORY_FINGERPRINT),
            "quota.evidence_stale",
        ),
        (
            NOW,
            (INVENTORY_GENERATION, "sha256:" + "b" * 64),
            "quota.evidence_inventory_mismatch",
        ),
        (
            NOW,
            (INVENTORY_GENERATION + 1, INVENTORY_FINGERPRINT),
            "quota.evidence_generation_mismatch",
        ),
        (NOW, (True, INVENTORY_FINGERPRINT), "quota.evidence_invalid"),
    ],
)
def test_apply_revalidates_fresh_current_inventory_before_first_mutation(
    now: str, binding: tuple[int, str], code: str
) -> None:
    document = _document()
    plan = build_fill_to_quota_plan(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(1),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )
    store = MemoryStore(document)
    api = FakeApi()

    with pytest.raises(GoogleCloudProvisionerError, match=code):
        _execute(plan, api=api, store=store, now=now, binding=binding)

    assert api.created == []
    assert api.enabled == []
    assert api.keys == []
    assert store.writes == 0


def test_ref_race_after_cloud_create_fails_before_followup_mutation() -> None:
    document = _document()
    plan = build_fill_to_quota_plan(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        quota_evidence=_evidence(1),
        inventory_generation=INVENTORY_GENERATION,
        inventory_fingerprint=INVENTORY_FINGERPRINT,
        now=NOW,
        visible_project_names=set(),
        reserved_project_ids=set(),
    )

    class RacingStore(MemoryStore):
        def atomic_update(self, transform):
            if self.writes == 0:
                self.document["google_accounts"][0]["projects"].append(
                    {
                        "ref": plan.projects[0].ref,
                        "purpose": "hive",
                        "project_name": "Foreign Meadow",
                        "status": "provisioning",
                        "project_id": "foreign-meadow-a1b2c3",
                        "project_number": "999999",
                        "key_name": "Foreign Meadow Key",
                    }
                )
            super().atomic_update(transform)

    store = RacingStore(document)
    api = FakeApi()

    with pytest.raises(
        GoogleCloudProvisionerError, match="provisioner.inventory_conflict"
    ):
        _execute(plan, api=api, store=store)

    assert len(api.created) == 1
    assert api.enabled == []
    assert api.keys == []
