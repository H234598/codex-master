"""Quota-driven, resumable Google Cloud project provisioning."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import re
from typing import Callable, Collection, Protocol, cast

from .google_cloud_api import GoogleCloudApiError
from .google_project_naming import (
    generate_pretty_project_identity,
    next_hive_ref,
    pretty_key_display_name,
)


class GoogleCloudProvisionerError(Exception):
    __slots__ = ("code", "partial")

    def __init__(
        self, code: str, *, partial: ProvisionPartialReceipt | None = None
    ) -> None:
        self.code = code
        self.partial = partial
        super().__init__(code)

    def __repr__(self) -> str:
        return f"GoogleCloudProvisionerError({self.code!r})"


@dataclass(frozen=True, slots=True)
class PlannedHiveProject:
    ref: str
    project_name: str
    project_id: str
    expected_project_number: str | None
    key_display_name: str


@dataclass(frozen=True, slots=True)
class GoogleQuotaEvidenceV1:
    remaining: int
    observed_at: str
    source: str
    account_ref: str
    inventory_generation: int
    inventory_fingerprint: str


@dataclass(frozen=True, slots=True)
class FillToQuotaPlan:
    account_ref: str
    expected_subject_id: str
    quota_remaining: int
    quota_evidence: GoogleQuotaEvidenceV1
    inventory_generation: int
    inventory_fingerprint: str
    projects: tuple[PlannedHiveProject, ...]
    fingerprint: str


@dataclass(frozen=True, slots=True)
class ProvisionReceipt:
    completed: int
    planned: int


@dataclass(frozen=True, slots=True)
class ProvisionPartialReceipt:
    attempted: int
    completed: int
    planned: int
    failed: int
    not_attempted: int
    reason_code: str


class _Api(Protocol):
    def subject_id(self) -> str: ...
    def create_project(
        self, project_id: str, project_name: str
    ) -> dict[str, object]: ...
    def enable_required_services(self, project_number: str) -> dict[str, object]: ...
    def list_keys(self, project_number: str) -> list[dict[str, object]]: ...
    def get_key_string(self, key_name: str) -> str: ...
    def create_restricted_key(
        self, project_number: str, display_name: str
    ) -> dict[str, object]: ...


class _Store(Protocol):
    def _read(self) -> tuple[bytes, dict[str, object]]: ...
    def atomic_update(self, transform) -> object: ...


_QUOTA_SOURCES = frozenset({"cloudresourcemanager"})
_MAX_QUOTA_REMAINING = 10_000
_MAX_QUOTA_AGE = timedelta(minutes=5)
_MAX_QUOTA_FUTURE_SKEW = timedelta(seconds=30)
_UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)


def _utc_timestamp(value: object) -> datetime:
    if type(value) is not str or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise GoogleCloudProvisionerError("quota.evidence_invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise GoogleCloudProvisionerError("quota.evidence_invalid") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise GoogleCloudProvisionerError("quota.evidence_invalid")
    return parsed


def _validate_quota_evidence(
    evidence: object,
    *,
    account_ref: str,
    inventory_generation: int,
    inventory_fingerprint: str,
    now: object,
) -> GoogleQuotaEvidenceV1:
    if (
        type(evidence) is not GoogleQuotaEvidenceV1
        or type(evidence.remaining) is not int
        or not 0 <= evidence.remaining <= _MAX_QUOTA_REMAINING
        or type(evidence.account_ref) is not str
        or not evidence.account_ref
        or len(evidence.account_ref.encode("utf-8")) > 256
        or type(evidence.inventory_generation) is not int
        or not 1 <= evidence.inventory_generation <= 2**63 - 1
        or type(inventory_generation) is not int
        or not 1 <= inventory_generation <= 2**63 - 1
        or type(evidence.inventory_fingerprint) is not str
        or _FINGERPRINT.fullmatch(evidence.inventory_fingerprint) is None
        or type(inventory_fingerprint) is not str
        or _FINGERPRINT.fullmatch(inventory_fingerprint) is None
    ):
        raise GoogleCloudProvisionerError("quota.evidence_invalid")
    if type(evidence.source) is not str or evidence.source not in _QUOTA_SOURCES:
        raise GoogleCloudProvisionerError("quota.evidence_source_invalid")
    observed_at = _utc_timestamp(evidence.observed_at)
    now_utc = _utc_timestamp(now)
    if evidence.account_ref != account_ref:
        raise GoogleCloudProvisionerError("quota.evidence_account_mismatch")
    if evidence.inventory_generation != inventory_generation:
        raise GoogleCloudProvisionerError("quota.evidence_generation_mismatch")
    if evidence.inventory_fingerprint != inventory_fingerprint:
        raise GoogleCloudProvisionerError("quota.evidence_inventory_mismatch")
    if observed_at > now_utc + _MAX_QUOTA_FUTURE_SKEW:
        raise GoogleCloudProvisionerError("quota.evidence_future")
    if now_utc - observed_at > _MAX_QUOTA_AGE:
        raise GoogleCloudProvisionerError("quota.evidence_stale")
    return evidence


def _account(document: dict[str, object], account_ref: str) -> dict[str, object]:
    accounts = document.get("google_accounts")
    if type(accounts) is not list:
        raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
    matches = [
        item
        for item in accounts
        if type(item) is dict and item.get("ref") == account_ref
    ]
    if len(matches) != 1:
        raise GoogleCloudProvisionerError("provisioner.account_invalid")
    return matches[0]


def _hive_ref_number(project: dict[str, object]) -> int:
    ref = project.get("ref")
    if type(ref) is not str or re.fullmatch(r"the-hive-[1-9][0-9]*", ref) is None:
        raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
    return int(ref.rsplit("-", 1)[-1])


def build_fill_to_quota_plan(
    document: dict[str, object],
    *,
    account_ref: str,
    expected_subject_id: str,
    quota_evidence: GoogleQuotaEvidenceV1,
    inventory_generation: int,
    inventory_fingerprint: str,
    now: str,
    visible_project_names: Collection[str],
    reserved_project_ids: Collection[str],
) -> FillToQuotaPlan:
    if (
        type(account_ref) is not str
        or not account_ref
        or type(expected_subject_id) is not str
        or not expected_subject_id
        or type(inventory_generation) is not int
        or not 1 <= inventory_generation <= 2**63 - 1
        or type(inventory_fingerprint) is not str
        or _FINGERPRINT.fullmatch(inventory_fingerprint) is None
    ):
        raise GoogleCloudProvisionerError("provisioner.plan_invalid")
    evidence = _validate_quota_evidence(
        quota_evidence,
        account_ref=account_ref,
        inventory_generation=inventory_generation,
        inventory_fingerprint=inventory_fingerprint,
        now=now,
    )
    account = _account(document, account_ref)
    if account.get("subject_id") != expected_subject_id:
        raise GoogleCloudProvisionerError("provisioner.subject_mismatch")
    accounts = document.get("google_accounts")
    if type(accounts) is not list:
        raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
    raw_refs = [
        project.get("ref")
        for item in accounts
        if type(item) is dict
        for project in item.get("projects", [])
        if type(project) is dict
    ]
    if any(type(ref) is not str for ref in raw_refs):
        raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
    refs = cast(list[str], raw_refs)
    names = set(visible_project_names)
    project_ids = set(reserved_project_ids)
    projects = account.get("projects")
    if type(projects) is not list:
        raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
    partials = [
        project
        for project in projects
        if type(project) is dict
        and project.get("purpose") == "hive"
        and project.get("status") in {"provisioning", "services_enabled"}
    ]
    planned: list[PlannedHiveProject] = []
    for project in sorted(partials, key=_hive_ref_number):
        ref = project.get("ref")
        project_name = project.get("project_name")
        project_id = project.get("project_id")
        project_number = project.get("project_number")
        key_name = project.get("key_name")
        if (
            type(ref) is not str
            or not re.fullmatch(r"the-hive-[1-9][0-9]*", ref)
            or type(project_name) is not str
            or not project_name
            or type(project_id) is not str
            or not project_id
            or type(project_number) is not str
            or not project_number
            or type(key_name) is not str
            or not key_name
        ):
            raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
        planned.append(
            PlannedHiveProject(
                ref=ref,
                project_name=project_name,
                project_id=project_id,
                expected_project_number=project_number,
                key_display_name=key_name,
            )
        )
        names.add(project_name)
        project_ids.add(project_id)
    naming_seed = sha256(
        json.dumps(
            {
                "account_ref": account_ref,
                "expected_subject_id": expected_subject_id,
                "quota_evidence": {
                    "remaining": evidence.remaining,
                    "observed_at": evidence.observed_at,
                    "source": evidence.source,
                    "account_ref": evidence.account_ref,
                    "inventory_generation": evidence.inventory_generation,
                    "inventory_fingerprint": evidence.inventory_fingerprint,
                },
                "refs": sorted(refs),
                "visible_project_names": sorted(names),
                "reserved_project_ids": sorted(project_ids),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).digest()
    for _ in range(evidence.remaining):
        ref = next_hive_ref(refs)
        identity = generate_pretty_project_identity(
            visible_names=names,
            reserved_project_ids=project_ids,
            entropy=sha256(naming_seed + ref.encode("ascii")).digest(),
        )
        item = PlannedHiveProject(
            ref=ref,
            project_name=identity.project_name,
            project_id=identity.project_id,
            expected_project_number=None,
            key_display_name=pretty_key_display_name(identity.project_name),
        )
        planned.append(item)
        refs.append(ref)
        names.add(identity.project_name)
        project_ids.add(identity.project_id)
    payload = {
        "account_ref": account_ref,
        "expected_subject_id": expected_subject_id,
        "quota_evidence": {
            "remaining": evidence.remaining,
            "observed_at": evidence.observed_at,
            "source": evidence.source,
            "account_ref": evidence.account_ref,
            "inventory_generation": evidence.inventory_generation,
            "inventory_fingerprint": evidence.inventory_fingerprint,
        },
        "projects": [
            {
                "ref": item.ref,
                "project_name": item.project_name,
                "project_id": item.project_id,
                "expected_project_number": item.expected_project_number,
                "key_display_name": item.key_display_name,
            }
            for item in planned
        ],
    }
    fingerprint = (
        "sha256:"
        + sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    )
    return FillToQuotaPlan(
        account_ref=account_ref,
        expected_subject_id=expected_subject_id,
        quota_remaining=evidence.remaining,
        quota_evidence=evidence,
        inventory_generation=inventory_generation,
        inventory_fingerprint=inventory_fingerprint,
        projects=tuple(planned),
        fingerprint=fingerprint,
    )


def _project_number(response: dict[str, object]) -> str:
    number = response.get("projectNumber")
    if type(number) is str and number:
        return number
    name = response.get("name")
    if type(name) is str and name.startswith("projects/") and name[9:].isdigit():
        return name[9:]
    raise GoogleCloudProvisionerError("provisioner.google_response_invalid")


def _find_project(document: dict[str, object], account_ref: str, ref: str):
    account = _account(document, account_ref)
    projects = account.get("projects")
    if type(projects) is not list:
        raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
    matches = [
        item for item in projects if type(item) is dict and item.get("ref") == ref
    ]
    if len(matches) > 1:
        raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
    return matches[0] if matches else None


def _validate_account_subject(
    document: dict[str, object], plan: FillToQuotaPlan
) -> None:
    if (
        _account(document, plan.account_ref).get("subject_id")
        != plan.expected_subject_id
    ):
        raise GoogleCloudProvisionerError("provisioner.subject_mismatch")


def _validate_project_identity(
    project: dict[str, object], item: PlannedHiveProject, project_number: str
) -> None:
    if (
        project.get("project_name") != item.project_name
        or project.get("project_id") != item.project_id
        or project.get("project_number") != project_number
        or project.get("key_name") != item.key_display_name
        or project.get("purpose") != "hive"
    ):
        raise GoogleCloudProvisionerError("provisioner.inventory_conflict")


def _persist_created(
    store: _Store,
    plan: FillToQuotaPlan,
    item: PlannedHiveProject,
    project_number: str,
) -> None:
    def update(document: dict[str, object]) -> None:
        _validate_account_subject(document, plan)
        if item.expected_project_number is not None:
            raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
        account = _account(document, plan.account_ref)
        projects = account.get("projects")
        if type(projects) is not list:
            raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
        existing = _find_project(document, plan.account_ref, item.ref)
        if existing is not None:
            raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
        projects.append(
            {
                "ref": item.ref,
                "purpose": "hive",
                "project_name": item.project_name,
                "billing_account_ref": None,
                "status": "provisioning",
                "project_id": item.project_id,
                "project_number": project_number,
                "key_id": None,
                "key_uid": None,
                "key_name": item.key_display_name,
                "secret": None,
            }
        )

    store.atomic_update(update)


def _partial_failure(
    code: str, *, attempted: int, completed: int, planned: int
) -> GoogleCloudProvisionerError:
    return GoogleCloudProvisionerError(
        code,
        partial=ProvisionPartialReceipt(
            attempted=attempted,
            completed=completed,
            planned=planned,
            failed=int(attempted > completed),
            not_attempted=max(planned - attempted, 0),
            reason_code=code,
        ),
    )


def _persist_services(
    store: _Store,
    plan: FillToQuotaPlan,
    item: PlannedHiveProject,
    project_number: str,
) -> None:
    def update(document: dict[str, object]) -> None:
        _validate_account_subject(document, plan)
        project = _find_project(document, plan.account_ref, item.ref)
        if project is None:
            raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
        _validate_project_identity(project, item, project_number)
        if project.get("status") == "services_enabled":
            return
        if project.get("status") != "provisioning":
            raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
        project["status"] = "services_enabled"

    store.atomic_update(update)


def _persist_key(
    store: _Store,
    plan: FillToQuotaPlan,
    item: PlannedHiveProject,
    project_number: str,
    key: dict[str, object],
) -> None:
    name = key.get("name")
    uid = key.get("uid")
    secret = key.get("keyString")
    if (
        type(name) is not str
        or "/keys/" not in name
        or type(uid) is not str
        or not uid
        or type(secret) is not str
        or not secret
    ):
        raise GoogleCloudProvisionerError("provisioner.google_response_invalid")
    key_id = name.rsplit("/", 1)[-1]

    def update(document: dict[str, object]) -> None:
        _validate_account_subject(document, plan)
        project = _find_project(document, plan.account_ref, item.ref)
        if project is None:
            raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
        _validate_project_identity(project, item, project_number)
        if project.get("status") == "active":
            if (
                project.get("key_id") == key_id
                and project.get("key_uid") == uid
                and project.get("secret") == secret
            ):
                return
            raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
        if project.get("status") != "services_enabled":
            raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
        project.update(
            {"status": "active", "key_id": key_id, "key_uid": uid, "secret": secret}
        )

    store.atomic_update(update)


def execute_fill_to_quota_plan(
    plan: FillToQuotaPlan,
    *,
    api: _Api,
    store: _Store,
    confirmed_fingerprint: str,
    now: Callable[[], str],
    current_inventory: Callable[[], tuple[int, str]],
) -> ProvisionReceipt:
    if type(plan) is not FillToQuotaPlan or confirmed_fingerprint != plan.fingerprint:
        raise GoogleCloudProvisionerError("provisioner.confirmation_invalid")
    completed = 0
    attempted = 0
    planned = len(plan.projects)
    try:
        subject_id = api.subject_id()
    except GoogleCloudApiError:
        raise _partial_failure(
            "provisioner.setup_retryable",
            attempted=attempted,
            completed=completed,
            planned=planned,
        ) from None
    if subject_id != plan.expected_subject_id:
        raise GoogleCloudProvisionerError("provisioner.subject_mismatch")
    try:
        try:
            current_generation, current_fingerprint = current_inventory()
            current_now = now()
        except Exception:
            raise GoogleCloudProvisionerError(
                "provisioner.inventory_conflict"
            ) from None
        _validate_quota_evidence(
            plan.quota_evidence,
            account_ref=plan.account_ref,
            inventory_generation=current_generation,
            inventory_fingerprint=current_fingerprint,
            now=current_now,
        )
        for item in plan.projects:
            attempted += 1
            document = store._read()[1]
            _validate_account_subject(document, plan)
            project = _find_project(document, plan.account_ref, item.ref)
            if project is None:
                if item.expected_project_number is not None:
                    raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
                try:
                    response = api.create_project(item.project_id, item.project_name)
                except GoogleCloudApiError as error:
                    code = (
                        "quota.provider_exhausted"
                        if error.code == "google.api_quota_exhausted"
                        else "provisioner.project_create_failed"
                    )
                    raise _partial_failure(
                        code,
                        attempted=attempted,
                        completed=completed,
                        planned=planned,
                    ) from None
                number = _project_number(response)
                _persist_created(store, plan, item, number)
                status = "provisioning"
            else:
                expected_number = item.expected_project_number
                if expected_number is None:
                    raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
                _validate_project_identity(project, item, expected_number)
                number = expected_number
                if project.get("status") not in {
                    "provisioning",
                    "services_enabled",
                    "active",
                }:
                    raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
                status = project["status"]
            if status == "active":
                completed += 1
                continue
            if status == "provisioning":
                try:
                    api.enable_required_services(number)
                except GoogleCloudApiError:
                    raise _partial_failure(
                        "provisioner.services_retryable",
                        attempted=attempted,
                        completed=completed,
                        planned=planned,
                    ) from None
                _persist_services(store, plan, item, number)
            try:
                matches = [
                    key
                    for key in api.list_keys(number)
                    if key.get("displayName") == item.key_display_name
                    and key.get("restrictions")
                    == {
                        "apiTargets": [{"service": "generativelanguage.googleapis.com"}]
                    }
                ]
                if len(matches) > 1:
                    raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
                if matches:
                    key = matches[0]
                    key["keyString"] = api.get_key_string(str(key.get("name", "")))
                else:
                    key = api.create_restricted_key(number, item.key_display_name)
            except GoogleCloudApiError:
                raise _partial_failure(
                    "provisioner.api_key_retryable",
                    attempted=attempted,
                    completed=completed,
                    planned=planned,
                ) from None
            _persist_key(store, plan, item, number, key)
            completed += 1
        return ProvisionReceipt(completed=completed, planned=planned)
    except GoogleCloudProvisionerError:
        raise
