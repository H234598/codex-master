from __future__ import annotations

from dataclasses import replace
import multiprocessing
from pathlib import Path
import pickle

import pytest
import yaml

from the_hive import google_account_inventory as inventory
from the_hive import google_inventory_store as store_module
from the_hive.google_account_inventory_manager import GoogleAccountInventoryManager


def _store(tmp_path, *, generation=7):
    path = tmp_path / "synthetic-inventory.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 3,
                "authority_generation": generation,
                "google_accounts": [
                    {
                        "ref": "synthetic-account-01",
                        "login_email": "synthetic@example.test",
                        "billing_accounts": [],
                        "projects": [],
                    }
                ],
            },
            sort_keys=False,
        )
    )
    path.chmod(0o600)
    return store_module.GoogleInventoryStore._for_test_path(path), path


def _fingerprint(document):
    return inventory._document_from_bytes(
        yaml.safe_dump(document).encode()
    ).content_fingerprint


def test_transaction_rehydrates_fresh_source_and_reattests_once_under_lock(
    tmp_path, monkeypatch
):
    store, path = _store(tmp_path)
    calls = []
    original = GoogleAccountInventoryManager._from_authority_bytes.__func__

    def rehydrate(cls, raw):
        calls.append(raw)
        return original(cls, raw)

    monkeypatch.setattr(
        GoogleAccountInventoryManager, "_from_authority_bytes", classmethod(rehydrate)
    )
    with store_module._authority_transaction(store) as transaction:
        assert transaction.manager.inventory_generation() == 7
        assert transaction.binding.authority_generation == 7
        assert calls == [path.read_bytes()]
        transaction.attest()
        transaction.attest()
        assert len(calls) == 2
        assert transaction.manager.inventory_generation() == 7
    assert len(calls) == 2
    assert not list(tmp_path.glob("*.backup-*"))
    with pytest.raises(
        store_module.GoogleInventoryStoreError, match="transaction_closed"
    ):
        transaction.attest()


def test_commit_owns_one_increment_and_result_manager_uses_exact_written_bytes(
    tmp_path,
):
    store, path = _store(tmp_path)
    original = path.read_bytes()
    with store_module._authority_transaction(store) as transaction:
        candidate = transaction.document
        candidate["google_accounts"][0]["subject_id"] = "synthetic-subject"
        fingerprint = _fingerprint(candidate)
        receipt = transaction.commit(
            candidate,
            expected=transaction.binding,
            expected_content_fingerprint=fingerprint,
        )
        assert receipt.authority_generation == 8
        assert transaction.manager.inventory_generation() == 8
        assert (
            transaction.manager._snapshot_for_internal_use().content_fingerprint
            == fingerprint
        )
    assert yaml.safe_load(path.read_bytes())["authority_generation"] == 8
    assert list(tmp_path.glob("*.backup-*"))[0].read_bytes() == original
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "failure", ["stale", "generation", "schema", "result", "external"]
)
def test_commit_rejects_stale_binding_invalid_result_or_source_before_write(
    tmp_path, failure
):
    store, path = _store(tmp_path)
    with pytest.raises(store_module.GoogleInventoryStoreError):
        with store_module._authority_transaction(store) as transaction:
            candidate = transaction.document
            expected = transaction.binding
            fingerprint = _fingerprint(candidate)
            if failure == "stale":
                expected = replace(expected, authority_generation=6)
            elif failure == "generation":
                candidate["authority_generation"] = 100
            elif failure == "schema":
                candidate["extra"] = "synthetic-private-marker"
            elif failure == "result":
                fingerprint = "sha256:" + "0" * 64
            elif failure == "external":
                path.write_bytes(path.read_bytes() + b"\n")
            original = path.read_bytes()
            transaction.commit(
                candidate, expected=expected, expected_content_fingerprint=fingerprint
            )
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.backup-*"))


def test_no_commit_attestation_rejects_changed_bytes_with_same_content(tmp_path):
    store, path = _store(tmp_path)
    with pytest.raises(store_module.GoogleInventoryStoreError, match="source_conflict"):
        with store_module._authority_transaction(store):
            path.write_bytes(path.read_bytes() + b"\n")


def test_failed_transaction_revokes_its_source_manager(tmp_path):
    store, path = _store(tmp_path)
    with pytest.raises(store_module.GoogleInventoryStoreError, match="source_conflict"):
        with store_module._authority_transaction(store) as transaction:
            path.write_bytes(path.read_bytes() + b"\n")
    assert not transaction.manager.status().new_work_allowed


def test_parent_replacement_cannot_move_write_outside_locked_directory(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    store, path = _store(private)
    original = path.read_bytes()
    with pytest.raises(store_module.GoogleInventoryStoreError, match="source_conflict"):
        with store_module._authority_transaction(store) as transaction:
            private.rename(tmp_path / "moved")
            private.mkdir(mode=0o700)
            path.write_bytes(original)
            path.chmod(0o600)
            transaction.commit(
                transaction.document,
                expected=transaction.binding,
                expected_content_fingerprint=transaction.binding.content_fingerprint,
            )
    assert path.read_bytes() == original
    assert (tmp_path / "moved" / path.name).read_bytes() == original
    assert not list((tmp_path / "moved").glob("*.backup-*"))


def test_generation_exhaustion_rejects_commit_without_mutation(tmp_path):
    store, path = _store(tmp_path, generation=2**63 - 1)
    original = path.read_bytes()
    with pytest.raises(
        store_module.GoogleInventoryStoreError, match="generation_exhausted"
    ):
        store.atomic_update(lambda document: None)
    assert path.read_bytes() == original


def test_attestation_rejects_replaced_parent_even_with_identical_bytes(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    store, path = _store(private)
    original = path.read_bytes()
    with pytest.raises(store_module.GoogleInventoryStoreError, match="source_conflict"):
        with store_module._authority_transaction(store):
            private.rename(tmp_path / "moved")
            private.mkdir(mode=0o700)
            path.write_bytes(original)
            path.chmod(0o600)


def test_authority_capabilities_hide_private_data_and_reject_pickle(tmp_path):
    store, _ = _store(tmp_path)
    with store_module._authority_transaction(store) as transaction:
        for value in (transaction, transaction.binding):
            assert "synthetic" not in repr(value)
            with pytest.raises(TypeError, match="not serializable"):
                pickle.dumps(value)


def test_atomic_update_rejects_legacy_and_increments_schema3_durably(tmp_path):
    store, path = _store(tmp_path)
    store.atomic_update(lambda document: None)
    assert yaml.safe_load(path.read_bytes())["authority_generation"] == 8
    path.write_text("schema_version: 2\ngoogle_accounts: []\n")
    with pytest.raises(store_module.GoogleInventoryStoreError, match="schema_invalid"):
        store.atomic_update(
            lambda document: document.update(schema_version=3, authority_generation=1)
        )
    with pytest.raises(
        store_module.GoogleInventoryStoreError, match="migration_unavailable"
    ):
        store.migrate_to_v2()


def test_atomic_write_failure_preserves_original(tmp_path, monkeypatch):
    store, path = _store(tmp_path)
    original = path.read_bytes()
    monkeypatch.setattr(
        store_module.os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )
    with pytest.raises(store_module.GoogleInventoryStoreError, match="write_failed"):
        store.atomic_update(lambda document: None)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".*.tmp-*"))


def test_result_readback_failure_is_not_reported_as_success(tmp_path, monkeypatch):
    store, path = _store(tmp_path)
    original_replace = store_module.os.replace

    def replace_then_change(*args, **kwargs):
        original_replace(*args, **kwargs)
        path.write_bytes(path.read_bytes() + b"\n")

    monkeypatch.setattr(store_module.os, "replace", replace_then_change)
    with pytest.raises(store_module.GoogleInventoryStoreError, match="result_conflict"):
        store.atomic_update(lambda document: None)


def _hold_transaction(path, entered, release):
    store = store_module.GoogleInventoryStore._for_test_path(Path(path))
    with store_module._authority_transaction(store):
        entered.set()
        assert release.wait(5)


def _enter_transaction(path, started, entered):
    store = store_module.GoogleInventoryStore._for_test_path(Path(path))
    started.set()
    with store_module._authority_transaction(store):
        entered.set()


def test_process_lock_covers_fresh_read_through_final_attestation(tmp_path):
    _, path = _store(tmp_path)
    context = multiprocessing.get_context("fork")
    entered, release, started, second_entered = (context.Event() for _ in range(4))
    first = context.Process(
        target=_hold_transaction, args=(str(path), entered, release)
    )
    second = context.Process(
        target=_enter_transaction, args=(str(path), started, second_entered)
    )
    try:
        first.start()
        assert entered.wait(5)
        second.start()
        assert started.wait(5)
        assert not second_entered.wait(0.2)
    finally:
        release.set()
        first.join(5)
        if second.pid is not None:
            second.join(5)
    assert first.exitcode == second.exitcode == 0
