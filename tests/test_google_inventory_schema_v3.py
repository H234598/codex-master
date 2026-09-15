from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from the_hive import google_account_inventory as inventory
from the_hive.google_account_inventory_manager import GoogleAccountInventoryManager


def _raw(*, version: object = 3, generation: object = 1) -> bytes:
    return yaml.safe_dump(
        {
            "schema_version": version,
            "authority_generation": generation,
            "google_accounts": [],
        },
        sort_keys=False,
    ).encode()


def _load(tmp_path: Path, raw: bytes):
    path = tmp_path / "inventory.yaml"
    path.write_bytes(raw)
    path.chmod(0o600)
    return inventory.GoogleAccountInventoryLoader._for_test_path(path).load()


@pytest.mark.parametrize("generation", [1, 2, 42, 2**63 - 1])
def test_schema3_requires_durable_bounded_integer_generation(tmp_path, generation):
    document = _load(tmp_path, _raw(generation=generation))
    assert document.schema_version == 3
    assert document.authority_generation == generation
    assert document.public_projection()["authority_generation"] == generation


@pytest.mark.parametrize("generation", [None, True, False, 0, -1, 2**63, "1", 1.0])
def test_schema3_rejects_invalid_generation(tmp_path, generation):
    with pytest.raises(inventory.GoogleAccountInventoryError, match="schema_invalid"):
        _load(tmp_path, _raw(generation=generation))


@pytest.mark.parametrize("literal", ["01", "+1", "0x1", "1_0", "1:00", "9" * 10000])
def test_generation_rejects_noncanonical_integer_literals(tmp_path, literal):
    with pytest.raises(inventory.GoogleAccountInventoryError, match="schema_invalid"):
        _load(
            tmp_path,
            _raw().replace(
                b"authority_generation: 1", f"authority_generation: {literal}".encode()
            ),
        )


@pytest.mark.parametrize("version", [1, 2, "3", 3.0, True, 4])
def test_runtime_rejects_every_non_schema3_source(tmp_path, version):
    raw = yaml.safe_dump({"schema_version": version, "google_accounts": []}).encode()
    with pytest.raises(inventory.GoogleAccountInventoryError, match="schema_invalid"):
        _load(tmp_path, raw)


def test_schema3_requires_generation_and_rejects_unknown_or_duplicate_fields(tmp_path):
    for raw in (
        b"schema_version: 3\ngoogle_accounts: []\n",
        _raw() + b"unknown: null\n",
        _raw() + b"authority_generation: 2\n",
    ):
        with pytest.raises(
            inventory.GoogleAccountInventoryError, match="schema_invalid"
        ):
            _load(tmp_path, raw)


def test_private_byte_parser_preserves_generation_without_another_source(tmp_path):
    document = inventory._document_from_bytes(_raw(generation=41))
    assert document.authority_generation == 41
    assert (
        document.content_fingerprint
        == _load(tmp_path, _raw(generation=42)).content_fingerprint
    )


def test_manager_rehydrates_exact_bytes_at_durable_generation(monkeypatch):
    monkeypatch.setattr(
        inventory.GoogleAccountInventoryLoader,
        "load",
        lambda _: pytest.fail("rehydration must not read another source"),
    )
    manager = GoogleAccountInventoryManager._from_authority_bytes(_raw(generation=41))
    assert manager.inventory_generation() == 41
    assert manager.reload(expected_generation=41).generation == 41
    assert (
        GoogleAccountInventoryManager._from_authority_bytes(
            _raw(generation=41)
        ).inventory_generation()
        == 41
    )


def test_manager_reload_uses_stored_generation_and_rejects_rollback():
    sources = iter(
        (
            _raw(generation=41),
            _raw(generation=41),
            _raw(generation=42),
            _raw(generation=40),
        )
    )
    manager = GoogleAccountInventoryManager._for_test_loader(
        lambda: inventory._document_from_bytes(next(sources)),
        monotonic_clock=lambda: 0.0,
        operator_timestamp_utc=lambda: "2026-09-15T00:00:00Z",
    )
    assert manager.reload().generation == 41
    assert manager.reload().generation == 41
    assert manager.reload().generation == 42
    with pytest.raises(inventory.GoogleAccountInventoryError, match="reload_failed"):
        manager.reload()
    assert not manager.status().new_work_allowed


def test_manager_can_reload_maximum_durable_generation_without_increment():
    manager = GoogleAccountInventoryManager._from_authority_bytes(
        _raw(generation=2**63 - 1)
    )
    assert manager.reload().generation == 2**63 - 1
