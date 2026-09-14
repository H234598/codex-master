"""Evidence-based reconciliation and safe display-name migration."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Collection, Protocol

from .google_cloud_api import GoogleCloudApiError
from .google_project_naming import (
    generate_pretty_project_identity,
    next_hive_ref,
    pretty_key_display_name,
)


class GoogleCloudInventoryError(Exception):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"GoogleCloudInventoryError({self.code!r})"


@dataclass(frozen=True, slots=True)
class RenameInventoryReceipt:
    projects_renamed: int
    keys_renamed: int


class _Api(Protocol):
    def subject_id(self) -> str: ...
    def search_projects(self) -> list[dict[str, object]]: ...
    def lookup_key(self, key_string: str) -> dict[str, object]: ...
    def update_project_name(self, resource_name: str, project_name: str) -> dict[str, object]: ...
    def update_key_display_name(self, key_name: str, display_name: str) -> dict[str, object]: ...


class _Store(Protocol):
    def atomic_update(self, transform) -> object: ...


def _account(document: dict[str, object], account_ref: str) -> dict[str, object]:
    accounts = document.get("google_accounts")
    if type(accounts) is not list:
        raise GoogleCloudInventoryError("inventory.document_invalid")
    found = [
        item
        for item in accounts
        if type(item) is dict and item.get("ref") == account_ref
    ]
    if len(found) != 1:
        raise GoogleCloudInventoryError("inventory.account_invalid")
    return found[0]


def _project_number(resource_name: object) -> str:
    if type(resource_name) is not str:
        raise GoogleCloudInventoryError("inventory.google_response_invalid")
    match = re.fullmatch(r"projects/([0-9]+)", resource_name)
    if match is None:
        raise GoogleCloudInventoryError("inventory.google_response_invalid")
    return match.group(1)


def _lookup_number(parent: object) -> str:
    if type(parent) is not str:
        raise GoogleCloudInventoryError("inventory.google_response_invalid")
    match = re.fullmatch(r"projects/([0-9]+)/locations/global", parent)
    if match is None:
        raise GoogleCloudInventoryError("inventory.google_response_invalid")
    return match.group(1)


def _all_refs(document: dict[str, object]) -> list[str]:
    accounts = document.get("google_accounts")
    if type(accounts) is not list:
        raise GoogleCloudInventoryError("inventory.document_invalid")
    refs: list[str] = []
    for account in accounts:
        if type(account) is not dict or type(account.get("projects")) is not list:
            raise GoogleCloudInventoryError("inventory.document_invalid")
        for project in account["projects"]:
            if type(project) is not dict or type(project.get("ref")) is not str:
                raise GoogleCloudInventoryError("inventory.document_invalid")
            refs.append(project["ref"])
    return refs


def rename_and_reconcile_existing_projects(
    document: dict[str, object],
    *,
    account_ref: str,
    expected_subject_id: str,
    api: _Api,
    store: _Store,
    control_project_ids: Collection[str],
) -> RenameInventoryReceipt:
    account = _account(document, account_ref)
    if account.get("subject_id") != expected_subject_id:
        raise GoogleCloudInventoryError("inventory.subject_mismatch")
    try:
        if api.subject_id() != expected_subject_id:
            raise GoogleCloudInventoryError("inventory.subject_mismatch")
        cloud_projects = api.search_projects()
        projects = account.get("projects")
        if type(projects) is not list:
            raise GoogleCloudInventoryError("inventory.document_invalid")

        by_number: dict[str, dict[str, object]] = {}
        key_resource_by_ref: dict[str, str] = {}
        for project in projects:
            if type(project) is not dict:
                raise GoogleCloudInventoryError("inventory.document_invalid")
            number = project.get("project_number")
            if type(number) is str and number:
                by_number[number] = project
            secret = project.get("secret")
            if type(secret) is str and secret:
                lookup = api.lookup_key(secret)
                lookup_number = _lookup_number(lookup.get("parent"))
                key_name = lookup.get("name")
                if type(key_name) is not str or not key_name:
                    raise GoogleCloudInventoryError("inventory.google_response_invalid")
                existing = by_number.get(lookup_number)
                if existing is not None and existing is not project:
                    raise GoogleCloudInventoryError("inventory.mapping_conflict")
                by_number[lookup_number] = project
                key_resource_by_ref[str(project["ref"])] = key_name

        refs = _all_refs(document)
        visible_names = {
            value
            for item in cloud_projects
            if type(item) is dict
            for value in (item.get("displayName"),)
            if type(value) is str
        }
        visible_names.update(
            value
            for project in projects
            if type(project) is dict
            for value in (project.get("project_name"),)
            if type(value) is str and value
        )
        reserved_ids = {
            value
            for item in cloud_projects
            if type(item) is dict
            for value in (item.get("projectId"),)
            if type(value) is str
        }
        projects_renamed = 0
        keys_renamed = 0
        for cloud in sorted(cloud_projects, key=lambda item: str(item.get("name"))):
            if cloud.get("state") != "ACTIVE":
                continue
            resource_name = cloud.get("name")
            number = _project_number(resource_name)
            project_id = cloud.get("projectId")
            if type(project_id) is not str or not project_id:
                raise GoogleCloudInventoryError("inventory.google_response_invalid")
            local = by_number.get(number)
            if local is None:
                ref = next_hive_ref(refs)
                refs.append(ref)
                purpose = (
                    "oauth_control"
                    if project_id in control_project_ids
                    or str(cloud.get("displayName", "")).casefold() in {"mji", "mj-cp"}
                    else "external"
                )
            else:
                ref = str(local["ref"])
                purpose = str(local.get("purpose", "hive"))
                if project_id in control_project_ids:
                    purpose = "oauth_control"
            persisted_project_name = (
                local.get("project_name") if local is not None else None
            )
            if type(persisted_project_name) is str and persisted_project_name:
                project_name = persisted_project_name
            else:
                identity = generate_pretty_project_identity(
                    visible_names=visible_names, reserved_project_ids=reserved_ids
                )
                project_name = identity.project_name
                visible_names.add(project_name)
                api.update_project_name(str(resource_name), project_name)

                def persist_project(candidate: dict[str, object]) -> None:
                    target_account = _account(candidate, account_ref)
                    target_projects = target_account.get("projects")
                    if type(target_projects) is not list:
                        raise GoogleCloudInventoryError("inventory.document_invalid")
                    matches = [
                        item
                        for item in target_projects
                        if type(item) is dict and item.get("ref") == ref
                    ]
                    if matches:
                        target = matches[0]
                        target.update(
                            {
                                "purpose": purpose,
                                "project_name": project_name,
                                "project_id": project_id,
                                "project_number": number,
                            }
                        )
                    else:
                        target_projects.append(
                            {
                                "ref": ref,
                                "purpose": purpose,
                                "project_name": project_name,
                                "billing_account_ref": None,
                                "status": "active",
                                "project_id": project_id,
                                "project_number": number,
                                "key_id": None,
                                "key_uid": None,
                                "key_name": None,
                                "secret": None,
                            }
                        )

                store.atomic_update(persist_project)
                projects_renamed += 1

            key_resource = key_resource_by_ref.get(ref)
            key_display_name = pretty_key_display_name(project_name)
            persisted_key_name = local.get("key_name") if local is not None else None
            if key_resource is not None and persisted_key_name != key_display_name:
                api.update_key_display_name(key_resource, key_display_name)

                def persist_key(candidate: dict[str, object]) -> None:
                    target = _account(candidate, account_ref)
                    target_projects = target.get("projects")
                    if type(target_projects) is not list:
                        raise GoogleCloudInventoryError("inventory.document_invalid")
                    matches = [
                        item
                        for item in target_projects
                        if type(item) is dict and item.get("ref") == ref
                    ]
                    if len(matches) != 1:
                        raise GoogleCloudInventoryError("inventory.mapping_conflict")
                    matches[0]["key_id"] = key_resource.rsplit("/", 1)[-1]
                    matches[0]["key_name"] = key_display_name

                store.atomic_update(persist_key)
                keys_renamed += 1
        return RenameInventoryReceipt(projects_renamed, keys_renamed)
    except GoogleCloudInventoryError:
        raise
    except GoogleCloudApiError:
        raise GoogleCloudInventoryError("inventory.google_failed") from None
