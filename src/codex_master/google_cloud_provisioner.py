"""Quota-driven, resumable Google Cloud project provisioning."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Collection, Protocol

from .google_cloud_api import GoogleCloudApiError
from .google_project_naming import (
    generate_pretty_project_identity,
    next_hive_ref,
    pretty_key_display_name,
)


class GoogleCloudProvisionerError(Exception):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"GoogleCloudProvisionerError({self.code!r})"


@dataclass(frozen=True, slots=True)
class PlannedHiveProject:
    ref: str
    project_name: str
    project_id: str
    key_display_name: str


@dataclass(frozen=True, slots=True)
class FillToQuotaPlan:
    account_ref: str
    expected_subject_id: str
    quota_remaining: int
    projects: tuple[PlannedHiveProject, ...]
    fingerprint: str


@dataclass(frozen=True, slots=True)
class ProvisionReceipt:
    completed: int
    planned: int


class _Api(Protocol):
    def subject_id(self) -> str: ...
    def create_project(self, project_id: str, project_name: str) -> dict[str, object]: ...
    def enable_required_services(self, project_number: str) -> dict[str, object]: ...
    def list_keys(self, project_number: str) -> list[dict[str, object]]: ...
    def get_key_string(self, key_name: str) -> str: ...
    def create_restricted_key(
        self, project_number: str, display_name: str
    ) -> dict[str, object]: ...


class _Store(Protocol):
    def _read(self) -> tuple[bytes, dict[str, object]]: ...
    def atomic_update(self, transform) -> object: ...


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
    quota_remaining: int,
    visible_project_names: Collection[str],
    reserved_project_ids: Collection[str],
) -> FillToQuotaPlan:
    if (
        type(account_ref) is not str
        or not account_ref
        or type(expected_subject_id) is not str
        or not expected_subject_id
        or type(quota_remaining) is not int
        or not 0 <= quota_remaining <= 10_000
    ):
        raise GoogleCloudProvisionerError("provisioner.plan_invalid")
    account = _account(document, account_ref)
    if account.get("subject_id") != expected_subject_id:
        raise GoogleCloudProvisionerError("provisioner.subject_mismatch")
    accounts = document.get("google_accounts", [])
    refs = [
        project.get("ref")
        for item in accounts
        if type(item) is dict
        for project in item.get("projects", [])
        if type(project) is dict
    ]
    if any(type(ref) is not str for ref in refs):
        raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
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
                key_display_name=key_name,
            )
        )
        names.add(project_name)
        project_ids.add(project_id)
    for _ in range(quota_remaining):
        ref = next_hive_ref(refs)
        identity = generate_pretty_project_identity(
            visible_names=names, reserved_project_ids=project_ids
        )
        item = PlannedHiveProject(
            ref=ref,
            project_name=identity.project_name,
            project_id=identity.project_id,
            key_display_name=pretty_key_display_name(identity.project_name),
        )
        planned.append(item)
        refs.append(ref)
        names.add(identity.project_name)
        project_ids.add(identity.project_id)
    payload = {
        "account_ref": account_ref,
        "expected_subject_id": expected_subject_id,
        "quota_remaining": quota_remaining,
        "projects": [
            {
                "ref": item.ref,
                "project_name": item.project_name,
                "project_id": item.project_id,
                "key_display_name": item.key_display_name,
            }
            for item in planned
        ],
    }
    fingerprint = "sha256:" + sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return FillToQuotaPlan(
        account_ref=account_ref,
        expected_subject_id=expected_subject_id,
        quota_remaining=quota_remaining,
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
    matches = [item for item in projects if type(item) is dict and item.get("ref") == ref]
    if len(matches) > 1:
        raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
    return matches[0] if matches else None


def _persist_created(
    store: _Store,
    plan: FillToQuotaPlan,
    item: PlannedHiveProject,
    project_number: str,
) -> None:
    def update(document: dict[str, object]) -> None:
        account = _account(document, plan.account_ref)
        projects = account.get("projects")
        if type(projects) is not list:
            raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
        if any(type(value) is dict and value.get("ref") == item.ref for value in projects):
            return
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


def _persist_services(store: _Store, plan: FillToQuotaPlan, item: PlannedHiveProject) -> None:
    def update(document: dict[str, object]) -> None:
        project = _find_project(document, plan.account_ref, item.ref)
        if project is None:
            raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
        project["status"] = "services_enabled"

    store.atomic_update(update)


def _persist_key(
    store: _Store,
    plan: FillToQuotaPlan,
    item: PlannedHiveProject,
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
        project = _find_project(document, plan.account_ref, item.ref)
        if project is None:
            raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
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
) -> ProvisionReceipt:
    if type(plan) is not FillToQuotaPlan or confirmed_fingerprint != plan.fingerprint:
        raise GoogleCloudProvisionerError("provisioner.confirmation_invalid")
    try:
        if api.subject_id() != plan.expected_subject_id:
            raise GoogleCloudProvisionerError("provisioner.subject_mismatch")
        completed = 0
        for item in plan.projects:
            document = store._read()[1]
            project = _find_project(document, plan.account_ref, item.ref)
            if project is None:
                response = api.create_project(item.project_id, item.project_name)
                number = _project_number(response)
                _persist_created(store, plan, item, number)
                status = "provisioning"
            else:
                if (
                    project.get("project_name") != item.project_name
                    or project.get("project_id") != item.project_id
                    or project.get("key_name") != item.key_display_name
                    or project.get("purpose") != "hive"
                    or project.get("status")
                    not in {"provisioning", "services_enabled", "active"}
                ):
                    raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
                number = project.get("project_number")
                if type(number) is not str or not number:
                    raise GoogleCloudProvisionerError("provisioner.inventory_invalid")
                status = project["status"]
            if status == "active":
                completed += 1
                continue
            if status == "provisioning":
                api.enable_required_services(number)
                _persist_services(store, plan, item)
            matches = [
                key
                for key in api.list_keys(number)
                if key.get("displayName") == item.key_display_name
                and key.get("restrictions")
                == {
                    "apiTargets": [
                        {"service": "generativelanguage.googleapis.com"}
                    ]
                }
            ]
            if len(matches) > 1:
                raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
            if matches:
                key = matches[0]
                key["keyString"] = api.get_key_string(str(key.get("name", "")))
            else:
                key = api.create_restricted_key(number, item.key_display_name)
            _persist_key(store, plan, item, key)
            completed += 1
        return ProvisionReceipt(completed=completed, planned=len(plan.projects))
    except GoogleCloudProvisionerError:
        raise
    except GoogleCloudApiError:
        raise GoogleCloudProvisionerError("provisioner.google_failed") from None
