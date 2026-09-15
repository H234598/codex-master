from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pickle

import pytest

import the_hive.google_inventory_desktop_client_registry as registry_module
import the_hive.google_inventory_token_vault as vault_module


def _record(
    account_ref: str = "synthetic-account-a",
    client_id: str = "000000000000-syntheticclient.apps.googleusercontent.com",
) -> dict[str, object]:
    value = {
        "account_ref": account_ref,
        "client_id": client_id,
        "client_type": "installed",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_kind": "ipv4_loopback_ephemeral_callback",
    }
    value["fingerprint"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
    )
    return value


def _document(records: list[dict[str, object]] | None = None) -> bytes:
    return json.dumps(
        {
            "format_version": 1,
            "record_kind": "inventory_desktop_client_registry_v1",
            "registry_generation": 1,
            "records": [_record()] if records is None else records,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def test_registry_parser_roundtrips_public_immutable_metadata() -> None:
    registry = registry_module.InventoryDesktopClientRegistryV1.parse(_document())
    record = registry.for_account("synthetic-account-a")
    assert registry.registry_generation == 1
    assert registry.fingerprint == "sha256:" + hashlib.sha256(_document()).hexdigest()
    assert record.fingerprint == _record()["fingerprint"]
    assert record.client_id == _record()["client_id"]
    assert registry.canonical_bytes() == _document()
    with pytest.raises((AttributeError, TypeError)):
        record.client_id = "changed"  # type: ignore[misc]
    with pytest.raises(registry_module.InventoryDesktopClientRegistryError):
        registry.for_account("missing-account")


@pytest.mark.parametrize(
    "change",
    [
        {"client_secret": "synthetic-rejected-secret"},
        {"auth_uri": "https://untrusted.example.test/auth"},
        {"token_uri": "https://untrusted.example.test/token"},
        {"redirect_kind": "device"},
        {"fingerprint": "sha256:" + "0" * 64},
        {"client_id": "unrelated-client"},
        {"client_type": "web"},
    ],
)
def test_registry_parser_rejects_unknown_secret_fields_and_changed_bindings(
    change,
) -> None:
    record = _record()
    record.update(change)
    with pytest.raises(registry_module.InventoryDesktopClientRegistryError):
        registry_module.InventoryDesktopClientRegistryV1.parse(_document([record]))


@pytest.mark.parametrize(
    "raw",
    [
        b'{"format_version":1,"format_version":1}',
        _document([_record(), _record()]),
        _document().replace(b'"registry_generation":1', b'"registry_generation":true'),
        _document().replace(b'"registry_generation":1', b'"registry_generation":0'),
        b"{}" * (32 * 1024),
    ],
)
def test_registry_parser_rejects_duplicate_and_invalid_documents(raw: bytes) -> None:
    with pytest.raises(registry_module.InventoryDesktopClientRegistryError):
        registry_module.InventoryDesktopClientRegistryV1.parse(raw)


@pytest.fixture
def registry_store(tmp_path: Path):
    state = tmp_path / "synthetic-state"
    state.mkdir(mode=0o700)
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    code, identity = vault_module._validated_directory_identity(
        fd,
        expected_owner=os.geteuid(),
        exact_mode=0o700,
        reject_group_world_write=False,
    )
    assert code is None
    capability = vault_module._DirectoryCapability(
        [
            vault_module._DirectoryNode(
                fd,
                None,
                identity,
                expected_owner=os.geteuid(),
                exact_mode=0o700,
                reject_group_world_write=False,
            )
        ]
    )
    components = vault_module._for_test_the_hive_inventory_vault_production_components(
        capability
    )
    vault_module._close_directory_capability(capability)
    components._preflight_for_inventory_authorize()
    try:
        store = registry_module._InventoryDesktopClientRegistryStoreV1(
            components._layout
        )
        yield (
            store,
            state / "the-hive-mcp/google-oauth" / registry_module._REGISTRY_NAME,
        )
    finally:
        components.clear()


def test_registry_store_uses_fixed_owner_layout_and_atomic_generation(
    registry_store,
) -> None:
    store, path = registry_store
    assert store.load() is None
    registry = registry_module.InventoryDesktopClientRegistryV1.parse(_document())
    store._replace(registry, expected_generation=0)
    assert path.read_bytes() == _document()
    assert path.stat().st_mode & 0o777 == 0o600
    assert store.load() == registry
    assert "synthetic-state" not in repr(store)
    with pytest.raises(TypeError):
        pickle.dumps(store)
    with pytest.raises(registry_module.InventoryDesktopClientRegistryError):
        store._replace(registry, expected_generation=0)
    assert path.read_bytes() == _document()


@pytest.mark.parametrize(
    "kind", ["symlink", "hardlink", "mode", "owner", "directory_symlink"]
)
def test_registry_store_rejects_unsafe_file_or_directory(
    registry_store, monkeypatch, kind
) -> None:
    store, path = registry_store
    store._replace(
        registry_module.InventoryDesktopClientRegistryV1.parse(_document()),
        expected_generation=0,
    )
    if kind == "symlink":
        target = path.with_suffix(".synthetic")
        path.rename(target)
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(path, path.with_suffix(".synthetic"))
    elif kind == "mode":
        path.chmod(0o644)
    elif kind == "owner":
        monkeypatch.setattr(vault_module.os, "geteuid", lambda: 123456)
    else:
        target = path.parent.with_name("synthetic-moved-oauth")
        path.parent.rename(target)
        path.parent.symlink_to(target)
    with pytest.raises(registry_module.InventoryDesktopClientRegistryError):
        store.load()


def test_registry_failed_atomic_replace_preserves_previous_document(
    registry_store, monkeypatch
) -> None:
    store, path = registry_store
    store._replace(
        registry_module.InventoryDesktopClientRegistryV1.parse(_document()),
        expected_generation=0,
    )
    updated = registry_module.InventoryDesktopClientRegistryV1.parse(
        _document().replace(b'"registry_generation":1', b'"registry_generation":2')
    )

    def fail_replace(*args, **kwargs):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(vault_module.os, "replace", fail_replace)
    with pytest.raises(registry_module.InventoryDesktopClientRegistryError):
        store._replace(updated, expected_generation=1)
    assert path.read_bytes() == _document()
    assert not list(path.parent.glob("*.tmp"))


def test_provision_effect_is_test_minted_plan_bound_one_shot_and_nonserializable(
    registry_store,
) -> None:
    store, path = registry_store
    registry = registry_module.InventoryDesktopClientRegistryV1.parse(_document())
    effect = registry_module._for_test_inventory_desktop_client_provision_effect(
        store=store,
        registry=registry,
        plan_id="synthetic-plan-a",
        account_ref="synthetic-account-a",
        expected_generation=0,
    )
    assert not path.exists()
    assert "synthetic" not in repr(effect)
    with pytest.raises(TypeError):
        pickle.dumps(effect)
    effect._apply_preconfirmed_for_queen(
        plan_id="synthetic-plan-a",
        plan_digest=effect.plan_digest,
        account_ref="synthetic-account-a",
        expected_generation=0,
    )
    assert store.load() == registry
    with pytest.raises(registry_module.InventoryDesktopClientRegistryError):
        effect._apply_preconfirmed_for_queen(
            plan_id="synthetic-plan-a",
            plan_digest=effect.plan_digest,
            account_ref="synthetic-account-a",
            expected_generation=0,
        )


@pytest.mark.parametrize(
    "change",
    [
        {"plan_id": "synthetic-other-plan"},
        {"plan_digest": "sha256:" + "0" * 64},
        {"account_ref": "synthetic-other-account"},
        {"expected_generation": 1},
    ],
)
def test_provision_effect_rejects_changed_approval_before_write(
    registry_store, change
) -> None:
    store, path = registry_store
    effect = registry_module._for_test_inventory_desktop_client_provision_effect(
        store=store,
        registry=registry_module.InventoryDesktopClientRegistryV1.parse(_document()),
        plan_id="synthetic-plan-a",
        account_ref="synthetic-account-a",
        expected_generation=0,
    )
    approval = dict(
        plan_id="synthetic-plan-a",
        plan_digest=effect.plan_digest,
        account_ref="synthetic-account-a",
        expected_generation=0,
    )
    approval.update(change)
    with pytest.raises(registry_module.InventoryDesktopClientRegistryError):
        effect._apply_preconfirmed_for_queen(**approval)
    assert not path.exists()
