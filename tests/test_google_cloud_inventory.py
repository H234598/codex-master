from __future__ import annotations

import copy
import re

import pytest

from codex_master.google_cloud_inventory import (
    GoogleCloudInventoryError,
    rename_and_reconcile_existing_projects,
)


class MemoryStore:
    def __init__(self, document):
        self.document = copy.deepcopy(document)
        self.writes = 0

    def atomic_update(self, transform):
        candidate = copy.deepcopy(self.document)
        transform(candidate)
        self.document = candidate
        self.writes += 1


class FakeApi:
    def __init__(self, subject="subject-one"):
        self.subject = subject
        self.project_patches = []
        self.key_patches = []
        self.lookups = []

    def subject_id(self):
        return self.subject

    def search_projects(self):
        return [
            {
                "name": "projects/100",
                "projectId": "old-hive-project",
                "displayName": "Hive 11",
                "state": "ACTIVE",
            },
            {
                "name": "projects/200",
                "projectId": "mji-control-project",
                "displayName": "MJI",
                "state": "ACTIVE",
            },
            {
                "name": "projects/300",
                "projectId": "other-project",
                "displayName": "Other 3",
                "state": "ACTIVE",
            },
        ]

    def lookup_key(self, secret):
        self.lookups.append(secret)
        return {
            "parent": "projects/100/locations/global",
            "name": "projects/100/locations/global/keys/key-one",
        }

    def update_project_name(self, resource_name, project_name):
        self.project_patches.append((resource_name, project_name))
        return {"name": resource_name, "displayName": project_name}

    def update_key_display_name(self, key_name, display_name):
        self.key_patches.append((key_name, display_name))
        return {"name": key_name, "displayName": display_name}


def _document():
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
                        "ref": "the-hive-11",
                        "purpose": "hive",
                        "project_name": None,
                        "billing_account_ref": None,
                        "status": "active",
                        "project_id": None,
                        "project_number": None,
                        "key_id": None,
                        "key_uid": None,
                        "key_name": None,
                        "secret": "private-key-one",
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
                        "ref": "the-hive-19",
                        "purpose": "hive",
                        "project_name": None,
                        "billing_account_ref": None,
                        "status": "blocked",
                        "project_id": None,
                        "project_number": None,
                        "key_id": None,
                        "key_uid": None,
                        "key_name": None,
                        "secret": None,
                    }
                ],
            },
        ],
    }


def test_lookup_proves_hive_mapping_then_renames_every_active_project_and_key() -> None:
    document = _document()
    store = MemoryStore(document)
    api = FakeApi()

    receipt = rename_and_reconcile_existing_projects(
        document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        api=api,
        store=store,
        control_project_ids={"mji-control-project"},
    )

    assert receipt.projects_renamed == 3
    assert receipt.keys_renamed == 1
    assert api.lookups == ["private-key-one"]
    assert len(api.project_patches) == 3
    assert len(api.key_patches) == 1
    account = store.document["google_accounts"][0]
    by_id = {item["project_id"]: item for item in account["projects"]}
    assert by_id["old-hive-project"]["ref"] == "the-hive-11"
    assert by_id["old-hive-project"]["project_number"] == "100"
    assert by_id["old-hive-project"]["purpose"] == "hive"
    assert by_id["mji-control-project"]["purpose"] == "oauth_control"
    assert by_id["other-project"]["purpose"] == "external"
    assert {by_id["mji-control-project"]["ref"], by_id["other-project"]["ref"]} == {
        "the-hive-20",
        "the-hive-21",
    }
    assert all(not re.search(r"\d", item["project_name"]) for item in by_id.values())
    assert not re.search(r"\d", by_id["old-hive-project"]["key_name"])
    assert store.writes == 4


def test_subject_mismatch_stops_before_secret_lookup_or_patch() -> None:
    document = _document()
    store = MemoryStore(document)
    api = FakeApi(subject="wrong")

    with pytest.raises(GoogleCloudInventoryError, match="inventory.subject_mismatch"):
        rename_and_reconcile_existing_projects(
            document,
            account_ref="google-account-01",
            expected_subject_id="subject-one",
            api=api,
            store=store,
            control_project_ids=set(),
        )

    assert api.lookups == []
    assert api.project_patches == []
    assert store.writes == 0
    assert "private-key-one" not in repr(api)


def test_completed_rename_is_idempotent_even_when_project_search_is_stale() -> None:
    first_store = MemoryStore(_document())
    rename_and_reconcile_existing_projects(
        first_store.document,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        api=FakeApi(),
        store=first_store,
        control_project_ids={"mji-control-project"},
    )
    completed = copy.deepcopy(first_store.document)
    second_store = MemoryStore(completed)
    stale_api = FakeApi()

    receipt = rename_and_reconcile_existing_projects(
        completed,
        account_ref="google-account-01",
        expected_subject_id="subject-one",
        api=stale_api,
        store=second_store,
        control_project_ids={"mji-control-project"},
    )

    assert receipt.projects_renamed == 0
    assert receipt.keys_renamed == 0
    assert stale_api.project_patches == []
    assert stale_api.key_patches == []
    assert second_store.writes == 0
