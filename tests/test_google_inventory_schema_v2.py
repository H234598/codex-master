from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from codex_master.google_account_inventory import (
    GoogleAccountInventoryError,
    GoogleAccountInventoryLoader,
)


def _write(root: Path, document: object) -> Path:
    root.mkdir(mode=0o700)
    path = root / "inventory.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)
    return path


def _account(projects: list[dict[str, object]]) -> dict[str, object]:
    return {
        "ref": "google-account-01",
        "login_email": "account@example.test",
        "recovery_email": None,
        "label": None,
        "subject_id": "123456789",
        "auth": {
            "access_token": "private-access-token",
            "refresh_token": "private-refresh-token",
            "cookies": [{"name": "SID", "value": "private-cookie"}],
        },
        "billing_accounts": [],
        "projects": projects,
    }


def _project(slot: int) -> dict[str, object]:
    return {
        "ref": f"the-hive-{slot}",
        "purpose": "hive",
        "project_name": f"Quiet Aurora {chr(64 + slot)}",
        "billing_account_ref": None,
        "status": "active",
        "project_id": f"quiet-aurora-{slot:06d}",
        "project_number": str(100_000 + slot),
        "key_id": f"key-{slot}",
        "key_uid": f"uid-{slot}",
        "key_name": f"Quiet Aurora {chr(64 + slot)} Key",
        "secret": f"secret-{slot}",
    }


def _load(path: Path):
    return GoogleAccountInventoryLoader._for_test_path(path).load()


def test_v2_loads_more_than_ten_projects_and_keeps_auth_private(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "private",
        {"schema_version": 2, "google_accounts": [_account([_project(i) for i in range(1, 26)])]},
    )

    document = _load(path)

    assert document.schema_version == 2
    assert len(document.accounts[0].projects) == 25
    project_25 = document.by_hive_slot[25]
    assert project_25.project_name == "Quiet Aurora Y"
    assert project_25.purpose == "hive"
    rendered = repr(document) + repr(document.public_projection())
    assert "private-access-token" not in rendered
    assert "private-refresh-token" not in rendered
    assert "private-cookie" not in rendered


@pytest.mark.parametrize(
    "change",
    [
        lambda project: project.pop("project_name"),
        lambda project: project.__setitem__("project_name", "bad/name"),
        lambda project: project.__setitem__("project_name", "abc"),
        lambda project: project.pop("purpose"),
        lambda project: project.__setitem__("purpose", "billing_control"),
    ],
)
def test_v2_requires_valid_project_name_and_closed_purpose(
    tmp_path: Path, change
) -> None:
    project = _project(1)
    change(project)
    path = _write(
        tmp_path / "private",
        {"schema_version": 2, "google_accounts": [_account([project])]},
    )

    with pytest.raises(
        GoogleAccountInventoryError, match="credential.inventory_schema_invalid"
    ):
        _load(path)


def test_v2_requires_name_only_when_google_project_exists(tmp_path: Path) -> None:
    blocked = _project(1)
    blocked.update(
        {
            "status": "blocked",
            "project_name": None,
            "project_id": None,
            "project_number": None,
            "key_id": None,
            "key_uid": None,
            "secret": None,
        }
    )
    path = _write(
        tmp_path / "private",
        {"schema_version": 2, "google_accounts": [_account([blocked])]},
    )

    document = _load(path)

    assert document.accounts[0].projects[0].project_name is None


def test_v1_remains_loadable_during_explicit_migration(tmp_path: Path) -> None:
    legacy = _project(1)
    legacy.pop("project_name")
    legacy.pop("purpose")
    legacy.pop("key_name")
    account = _account([legacy])
    account.pop("auth")
    path = _write(
        tmp_path / "private", {"schema_version": 1, "google_accounts": [account]}
    )

    document = _load(path)

    project = document.accounts[0].projects[0]
    assert project.project_name is None
    assert project.purpose == "hive"


def test_active_oauth_control_project_requires_no_gemini_key(tmp_path: Path) -> None:
    control = _project(1)
    control.update(
        {
            "purpose": "oauth_control",
            "key_id": None,
            "key_uid": None,
            "key_name": None,
            "secret": None,
        }
    )
    path = _write(
        tmp_path / "private",
        {"schema_version": 2, "google_accounts": [_account([control])]},
    )

    document = _load(path)

    assert document.accounts[0].projects[0].purpose == "oauth_control"
    assert document.accounts[0].projects[0].key_id is None
