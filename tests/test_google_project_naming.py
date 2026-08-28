from __future__ import annotations

import re

import pytest

from codex_master.google_project_naming import (
    _ADJECTIVES,
    _NOUNS,
    GoogleProjectNamingError,
    generate_pretty_project_identity,
    next_hive_ref,
    pretty_key_display_name,
)


def test_generated_names_and_ids_obey_google_rules_and_avoid_internal_identity() -> None:
    seen_names: set[str] = set()
    seen_ids: set[str] = set()

    for _ in range(1_000):
        identity = generate_pretty_project_identity(
            visible_names=seen_names, reserved_project_ids=seen_ids
        )
        assert re.fullmatch(r"[A-Za-z][A-Za-z' !-]{2,28}[A-Za-z]", identity.project_name)
        assert re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", identity.project_id)
        assert "the-hive" not in identity.project_name.casefold()
        assert "the-hive" not in identity.project_id
        assert identity.project_name not in seen_names
        assert identity.project_id not in seen_ids
        seen_names.add(identity.project_name)
        seen_ids.add(identity.project_id)

    assert len(_ADJECTIVES) == 400
    assert len(_NOUNS) == 400


def test_generator_retries_visible_name_and_project_id_collisions(monkeypatch) -> None:
    choices = iter(("Quietglow", "Aurorabay", "Brightbloom", "Meadowglen"))
    suffixes = iter(("a1b2c3", "d4e5f6"))
    monkeypatch.setattr("codex_master.google_project_naming.secrets.choice", lambda _: next(choices))
    monkeypatch.setattr("codex_master.google_project_naming.secrets.token_hex", lambda _: next(suffixes))

    identity = generate_pretty_project_identity(
        visible_names={"Quietglow Aurorabay"},
        reserved_project_ids={"brightbloom-meadowglen-a1b2c3"},
    )

    assert identity.project_name == "Brightbloom Meadowglen"
    assert identity.project_id == "brightbloom-meadowglen-d4e5f6"


def test_key_display_name_has_no_number_or_hive_ref() -> None:
    assert pretty_key_display_name("Quietglow Aurorabay") == "Quietglow Aurorabay Key"
    with pytest.raises(GoogleProjectNamingError):
        pretty_key_display_name("Hive 17")


def test_next_hive_ref_is_global_monotone_and_never_fills_gaps() -> None:
    assert next_hive_ref(["the-hive-2", "the-hive-19", "the-hive-4"]) == "the-hive-20"
    assert next_hive_ref([]) == "the-hive-1"


@pytest.mark.parametrize("ref", ["hive-1", "the-hive-0", "the-hive-x", "the-hive-01"])
def test_next_hive_ref_rejects_noncanonical_existing_refs(ref: str) -> None:
    with pytest.raises(GoogleProjectNamingError, match="project.naming_ref_invalid"):
        next_hive_ref([ref])
