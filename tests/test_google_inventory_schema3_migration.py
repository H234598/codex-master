from __future__ import annotations

from dataclasses import replace
import pickle

import pytest
import yaml

from the_hive import google_inventory_store as store_module
from the_hive.google_account_inventory import GoogleAccountInventoryLoader


def _legacy(tmp_path):
    path = tmp_path / "synthetic-inventory.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 2,
                "google_accounts": [
                    {
                        "ref": "synthetic-account-01",
                        "login_email": "synthetic@example.test",
                        "billing_accounts": [],
                        "projects": [],
                        "auth": {"refresh_token": "synthetic-private-marker"},
                    }
                ],
            },
            sort_keys=False,
        )
    )
    path.chmod(0o600)
    port, queen = store_module._schema3_migration_for_test(path)
    return path, port, queen


def test_queen_plan_digest_migration_validates_and_atomically_initializes_generation(
    tmp_path,
):
    path, port, queen = _legacy(tmp_path)
    original = path.read_bytes()
    plan = port.plan(queen=queen, plan_id="synthetic-schema-migration")
    assert path.read_bytes() == original
    receipt = port.apply(queen=queen, plan=plan, plan_digest=plan.plan_digest)
    document = GoogleAccountInventoryLoader._for_test_path(path).load()
    assert document.schema_version == receipt.schema_version == 3
    assert document.authority_generation == receipt.authority_generation == 1
    assert list(tmp_path.glob("*.backup-*"))[0].read_bytes() == original
    assert (
        yaml.safe_load(path.read_bytes())["google_accounts"][0]["auth"]["refresh_token"]
        == "synthetic-private-marker"
    )
    for value in (port, queen, plan):
        assert "synthetic-private-marker" not in repr(value)
        with pytest.raises(TypeError, match="not serializable"):
            pickle.dumps(value)


@pytest.mark.parametrize("failure", ["queen", "digest", "plan", "stale", "replay"])
def test_migration_denies_unbound_or_stale_effect_before_mutation(tmp_path, failure):
    path, port, queen = _legacy(tmp_path)
    plan = port.plan(queen=queen, plan_id="synthetic-migration")
    digest = plan.plan_digest
    if failure == "queen":
        queen = object()
    elif failure == "digest":
        digest = "sha256:" + "0" * 64
    elif failure == "plan":
        plan = replace(plan, plan_id="another-migration")
    elif failure == "stale":
        path.write_bytes(path.read_bytes() + b"\n")
    elif failure == "replay":
        port.apply(queen=queen, plan=plan, plan_digest=digest)
    original = path.read_bytes()
    backup_count = len(list(tmp_path.glob("*.backup-*")))
    with pytest.raises(store_module.GoogleInventoryStoreError):
        port.apply(queen=queen, plan=plan, plan_digest=digest)
    assert path.read_bytes() == original
    assert len(list(tmp_path.glob("*.backup-*"))) == backup_count


@pytest.mark.parametrize(
    "invalid", ["schema", "unknown", "duplicate", "auth", "project", "generation"]
)
def test_migration_fully_validates_legacy_source_before_plan(tmp_path, invalid):
    path, port, queen = _legacy(tmp_path)
    source = yaml.safe_load(path.read_bytes())
    account = source["google_accounts"][0]
    if invalid == "schema":
        source["schema_version"] = 1
    elif invalid == "unknown":
        account["unexpected"] = "synthetic-private-marker"
    elif invalid == "duplicate":
        source["google_accounts"].append(account.copy())
    elif invalid == "auth":
        account["auth"] = {"refresh_token": []}
    elif invalid == "project":
        account["projects"] = [{"ref": "the-hive-1"}]
    elif invalid == "generation":
        source["authority_generation"] = 1
    path.write_text(yaml.safe_dump(source))
    original = path.read_bytes()
    with pytest.raises(store_module.GoogleInventoryStoreError, match="schema_invalid"):
        port.plan(queen=queen, plan_id="synthetic-migration")
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.backup-*"))


def test_migration_effect_has_only_synthetic_test_factory(tmp_path):
    with pytest.raises(
        store_module.GoogleInventoryStoreError, match="migration_unavailable"
    ):
        store_module._schema3_migration_for_test(tmp_path / "api-token.yaml")


def test_migration_failed_replace_keeps_schema2_unchanged(tmp_path, monkeypatch):
    path, port, queen = _legacy(tmp_path)
    plan = port.plan(queen=queen, plan_id="synthetic-migration")
    original = path.read_bytes()
    monkeypatch.setattr(
        store_module.os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )
    with pytest.raises(store_module.GoogleInventoryStoreError, match="write_failed"):
        port.apply(queen=queen, plan=plan, plan_digest=plan.plan_digest)
    assert path.read_bytes() == original
