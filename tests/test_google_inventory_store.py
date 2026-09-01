from __future__ import annotations

import multiprocessing
from pathlib import Path
import stat

import pytest
import yaml

from codex_master import google_account_inventory
from codex_master.google_account_inventory import GoogleAccountInventoryLoader
from codex_master.google_inventory_store import (
    GoogleInventoryStore,
    GoogleInventoryStoreError,
)


SECRET = "AIza-private-project-secret"


def test_public_store_uses_only_canonical_inventory_path() -> None:
    store = GoogleInventoryStore()
    assert store._path == google_account_inventory.DEFAULT_GOOGLE_ACCOUNT_INVENTORY_PATH


def _legacy_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "google_accounts": [
            {
                "ref": "google-account-01",
                "login_email": "account@example.test",
                "recovery_email": None,
                "subject_id": "123456",
                "billing_accounts": [],
                "projects": [
                    {
                        "ref": "the-hive-1",
                        "billing_account_ref": None,
                        "status": "active",
                        "project_id": None,
                        "project_number": None,
                        "key_id": None,
                        "key_uid": None,
                        "secret": SECRET,
                    }
                ],
            }
        ],
    }


def _store(tmp_path: Path) -> tuple[GoogleInventoryStore, Path]:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "api-token.yaml"
    path.write_text(
        yaml.safe_dump(_legacy_document(), sort_keys=False), encoding="utf-8"
    )
    path.chmod(0o600)
    return GoogleInventoryStore._for_test_path(path), path


def _blocking_update(path: str, entered, release) -> None:
    store = GoogleInventoryStore._for_test_path(Path(path))

    def update(document: dict[str, object]) -> None:
        entered.set()
        if not release.wait(5):
            raise RuntimeError("test release timeout")
        document["google_accounts"][0]["login_email"] = "first@example.test"

    store.atomic_update(update)


def _observed_update(path: str, started, entered) -> None:
    store = GoogleInventoryStore._for_test_path(Path(path))
    started.set()

    def update(document: dict[str, object]) -> None:
        entered.set()
        document["google_accounts"][0]["recovery_email"] = "second@example.test"

    store.atomic_update(update)


def test_migrate_v2_preserves_secret_and_adds_project_fields(tmp_path: Path) -> None:
    store, path = _store(tmp_path)

    receipt = store.migrate_to_v2()

    private = yaml.safe_load(path.read_text(encoding="utf-8"))
    project = private["google_accounts"][0]["projects"][0]
    assert private["schema_version"] == 2
    assert project["project_name"] is None
    assert project["purpose"] == "hive"
    assert project["key_name"] is None
    assert project["secret"] == SECRET
    assert receipt.schema_version == 2
    assert SECRET not in repr(receipt)
    GoogleAccountInventoryLoader._for_test_path(path).load()


def test_atomic_update_writes_0600_backup_and_replacement(tmp_path: Path) -> None:
    store, path = _store(tmp_path)
    original = path.read_bytes()

    store.migrate_to_v2()

    backups = list(path.parent.glob("api-token.yaml.backup-*"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == original
    assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(path.parent.glob(".api-token.yaml.tmp-*"))


def test_atomic_update_serializes_independent_processes_before_read(
    tmp_path: Path,
) -> None:
    _, path = _store(tmp_path)
    context = multiprocessing.get_context("fork")
    first_entered = context.Event()
    release_first = context.Event()
    second_started = context.Event()
    second_entered = context.Event()
    first = context.Process(
        target=_blocking_update,
        args=(str(path), first_entered, release_first),
    )
    second = context.Process(
        target=_observed_update,
        args=(str(path), second_started, second_entered),
    )

    first.start()
    assert first_entered.wait(5)
    second.start()
    assert second_started.wait(5)
    serialized = not second_entered.wait(0.25)
    release_first.set()
    first.join(5)
    second.join(5)

    assert serialized
    assert first.exitcode == 0
    assert second.exitcode == 0
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    account = document["google_accounts"][0]
    assert account["login_email"] == "first@example.test"
    assert account["recovery_email"] == "second@example.test"


def test_failed_transform_leaves_original_byte_equal_and_secret_free(
    tmp_path: Path,
) -> None:
    store, path = _store(tmp_path)
    original = path.read_bytes()

    def fail(document: dict[str, object]) -> None:
        document["marker"] = SECRET
        raise RuntimeError(SECRET)

    with pytest.raises(GoogleInventoryStoreError) as raised:
        store.atomic_update(fail)

    assert path.read_bytes() == original
    assert SECRET not in str(raised.value)
    assert SECRET not in repr(raised.value)
    assert not list(path.parent.glob("api-token.yaml.backup-*"))


@pytest.mark.parametrize("mode", [0o644, 0o400])
def test_store_rejects_nonprivate_file_mode(tmp_path: Path, mode: int) -> None:
    store, path = _store(tmp_path)
    path.chmod(mode)

    with pytest.raises(GoogleInventoryStoreError, match="inventory.store_permissions"):
        store.migrate_to_v2()


def test_store_rejects_symlink_without_touching_target(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    target = private / "target.yaml"
    target.write_text(yaml.safe_dump(_legacy_document()), encoding="utf-8")
    target.chmod(0o600)
    link = private / "api-token.yaml"
    link.symlink_to(target.name)
    store = GoogleInventoryStore._for_test_path(link)
    original = target.read_bytes()

    with pytest.raises(GoogleInventoryStoreError, match="inventory.store_permissions"):
        store.migrate_to_v2()

    assert target.read_bytes() == original


def test_redacted_summary_contains_counts_not_credentials(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)

    summary = store.redacted_summary()

    assert summary == {"schema_version": 1, "account_count": 1, "project_count": 1}
    assert SECRET not in repr(summary)


def test_store_accepts_owner_0755_parent_but_rejects_group_write(
    tmp_path: Path,
) -> None:
    store, path = _store(tmp_path)
    path.parent.chmod(0o755)
    assert store.redacted_summary()["account_count"] == 1

    path.parent.chmod(0o775)
    with pytest.raises(GoogleInventoryStoreError, match="inventory.store_permissions"):
        store.redacted_summary()
