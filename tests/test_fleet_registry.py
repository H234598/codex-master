from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from codex_master.fleet_registry import (
    AuthKind, FleetAccount, FleetSeries, FleetValidationError, LimitState,
    Provider, RunnerKind, SecretState, build_inventory, fleet_document,
    mark_account_limit, normalize_fleet_document, plan_account_delete,
    plan_account_disable, plan_account_upsert, plan_series_apply,
    plan_series_delete, plan_series_disable, public_fleet_snapshot,
)


def gemini_document() -> dict[str, object]:
    return {
        "schema_version": 1, "generation": 4,
        "accounts": [{"account_id": f"gemini-project-{n}", "label": f"Gemini {n}",
                      "provider": "gemini_api", "auth_kind": "api_key", "enabled": True,
                      "limit_state": "ready"} for n in range(1, 4)],
        "series": [{"prefix": prefix, "display_name": f"Gemini {prefix.upper()}", "count": 100,
                    "runner": "gemini_cli", "provider": "gemini_api",
                    "model": "gemini-3-flash-preview", "account_id": f"gemini-project-{n}",
                    "enabled": True} for n, prefix in enumerate(("d", "e", "f"), 1)],
    }


def valid_document() -> dict[str, object]:
    document = gemini_document()
    document["accounts"] = [document["accounts"][0]]
    document["series"] = [document["series"][0]]
    return document


def test_normalizes_three_independent_gemini_series() -> None:
    snapshot = normalize_fleet_document(gemini_document())
    assert snapshot.generation == 4
    assert [series.prefix for series in snapshot.series] == ["d", "e", "f"]
    assert len({series.account_id for series in snapshot.series}) == 3


def test_normalization_sorts_entries_and_applies_safe_defaults() -> None:
    document = valid_document()
    document["accounts"] = [
        {"account_id": "zeta", "label": "Zeta", "provider": "gemini_api",
         "auth_kind": "api_key", "enabled": True},
        document["accounts"][0],
    ]
    document["series"] = [
        {"prefix": "z", "display_name": "Z series", "count": 1, "runner": "gemini_cli",
         "provider": "gemini_api", "model": "gemini-3-flash-preview", "account_id": "zeta",
         "enabled": True},
        document["series"][0],
    ]
    snapshot = normalize_fleet_document(document)
    assert [item.account_id for item in snapshot.accounts] == ["gemini-project-1", "zeta"]
    assert [item.prefix for item in snapshot.series] == ["d", "z"]
    assert snapshot.accounts[0].secret_state is SecretState.MISSING
    assert snapshot.accounts[1].limit_state is LimitState.UNKNOWN


def test_normalization_rejects_not_required_secret_state_for_api_account() -> None:
    document = valid_document()
    document["accounts"][0]["secret_state"] = "not_required"

    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)

    assert caught.value.code == "invalid_account"


@pytest.mark.parametrize(("change", "code"), [
    (lambda document: document["series"].append(deepcopy(document["series"][0])), "invalid_series"),
    (lambda document: document["series"][0].update(prefix="aa"), "invalid_series"),
    (lambda document: document["series"][0].update(count=0), "invalid_series"),
    (lambda document: document["series"][0].update(count=101), "invalid_series"),
    (lambda document: document["series"][0].update(runner="codex_cli"), "invalid_series"),
    (lambda document: document["series"][0].update(account_id=None), "invalid_series"),
    (lambda document: document["accounts"][0].update(provider="openai_api"), "invalid_series"),
    (lambda document: document["accounts"][0].update(label="bad\nlabel"), "invalid_account"),
    (lambda document: document["series"][0].update(model="x" * 201), "invalid_series"),
    (lambda document: document["accounts"][0].update(reset_at_utc="2026-08-03T12:00:00"), "invalid_account"),
])
def test_normalization_rejects_invalid_contract_values(change: object, code: str) -> None:
    document = valid_document()
    change(document)  # type: ignore[operator]
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == code


@pytest.mark.parametrize("field", ["secret", "token", "home", "email", "backend_account_id"])
@pytest.mark.parametrize("location", ["accounts", "series"])
def test_normalization_rejects_private_or_unknown_fields(field: str, location: str) -> None:
    document = valid_document()
    document[location][0][field] = "ignored"
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == ("invalid_account" if location == "accounts" else "invalid_series")


def test_normalization_rejects_duplicate_accounts_and_total_agent_limit() -> None:
    duplicate = valid_document()
    duplicate["accounts"].append(deepcopy(duplicate["accounts"][0]))
    excess = gemini_document()
    excess["series"] = [
        {"prefix": chr(ord("a") + i), "display_name": f"Series {i}",
         "count": 100 if i < 10 else 1, "runner": "gemini_cli", "provider": "gemini_api",
         "model": "gemini-3-flash-preview", "account_id": "gemini-project-1", "enabled": True}
        for i in range(11)
    ]
    for document, code in ((duplicate, "invalid_account"), (excess, "invalid_document")):
        with pytest.raises(FleetValidationError) as caught:
            normalize_fleet_document(document)
        assert caught.value.code == code


def test_normalization_rejects_more_than_twenty_six_series() -> None:
    document = valid_document()
    document["series"] = [
        {"prefix": chr(ord("a") + (index % 26)), "display_name": f"Series {index}", "count": 1,
         "runner": "gemini_cli", "provider": "gemini_api", "model": "gemini-3-flash-preview",
         "account_id": "gemini-project-1", "enabled": True}
        for index in range(27)
    ]

    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)

    assert caught.value.code == "invalid_document"


def test_normalization_enforces_local_provider_without_account() -> None:
    document = valid_document()
    document["accounts"] = []
    document["series"][0].update(provider="ollama_local", runner="codex_cli", account_id=None)
    assert normalize_fleet_document(document).series[0].account_id is None
    document["accounts"] = [{"account_id": "local", "label": "Local", "provider": "ollama_local",
                              "auth_kind": "none", "enabled": True}]
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == "invalid_account"


def test_fleet_document_round_trips_immutable_snapshot() -> None:
    snapshot = normalize_fleet_document(valid_document())
    assert normalize_fleet_document(fleet_document(snapshot)) == snapshot
    with pytest.raises(FrozenInstanceError):
        snapshot.generation = 5  # type: ignore[misc]


def test_inventory_derives_exact_agent_ids(tmp_path: Path) -> None:
    inventory = build_inventory(normalize_fleet_document(gemini_document()), tmp_path / "agents")
    assert inventory.agent_ids[0] == "d1"
    assert inventory.agent_ids[99] == "d100"
    assert inventory.agent_ids[100] == "e1"
    assert inventory.agent_ids[-1] == "f100"
    assert inventory.by_series["d-series"][-1] == "d100"
    assert inventory.agents["d1"].home == tmp_path / "agents" / "d1"
    assert inventory.agents["d1"].session == "codex_agent_d1_mcp"
    assert inventory.positions["f100"] == 299
    assert isinstance(inventory.agents, Mapping)
    with pytest.raises(TypeError):
        inventory.agents["x1"] = inventory.agents["d1"]  # type: ignore[index]


def test_inventory_keeps_disabled_entries_manageable(tmp_path: Path) -> None:
    document = valid_document()
    document["accounts"][0]["enabled"] = False
    document["series"][0]["enabled"] = False
    assert build_inventory(normalize_fleet_document(document), tmp_path).agents["d1"].enabled is False


def test_public_snapshot_uses_only_whitelisted_metadata() -> None:
    public = public_fleet_snapshot(normalize_fleet_document(valid_document()))
    allowed = {"generation", "account_count", "series_count", "agent_count", "accounts", "series",
               "label", "provider", "auth_kind", "secret_state", "limit_state", "enabled", "prefix",
               "display_name", "count", "runner", "model"}
    def visit(value: object) -> None:
        if isinstance(value, dict):
            assert set(value).issubset(allowed)
            for child in value.values(): visit(child)
        elif isinstance(value, list):
            for child in value: visit(child)
    visit(public)
    assert public["agent_count"] == 100
    assert public["accounts"][0]["secret_state"] == "missing"


def account() -> FleetAccount:
    return FleetAccount("gemini-project-1", "Changed account", Provider.GEMINI_API,
                        AuthKind.API_KEY, SecretState.CONFIGURED, LimitState.READY, True,
                        None, None, None)


def series(count: int = 3) -> FleetSeries:
    return FleetSeries("d", "Changed series", count, RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
                       "gemini-3-flash-preview", "gemini-project-1", True)


def test_account_planners_are_pure_and_use_generation_compare_and_swap() -> None:
    snapshot = normalize_fleet_document(valid_document())
    changed = plan_account_upsert(snapshot, account(), expected_generation=4)
    disabled = plan_account_disable(changed, "gemini-project-1", expected_generation=5)
    limited = mark_account_limit(disabled, "gemini-project-1", reset_at_utc="2026-08-03T12:00:00Z",
                                 reason="rate_limited", expected_generation=6)
    assert snapshot.generation == 4
    assert changed.generation == 5 and changed.accounts[0].label == "Changed account"
    assert disabled.accounts[0].enabled is False
    assert limited.generation == 7 and limited.accounts[0].limit_state is LimitState.LIMITED
    with pytest.raises(FleetValidationError) as caught:
        plan_account_upsert(snapshot, account(), expected_generation=5)
    assert caught.value.code == "generation_conflict"


def test_delete_and_shrink_require_safe_preconditions() -> None:
    document = valid_document()
    document["series"][0]["count"] = 3
    snapshot = normalize_fleet_document(document)
    with pytest.raises(FleetValidationError) as caught:
        plan_account_delete(snapshot, "gemini-project-1", expected_generation=4)
    assert caught.value.code == "account_in_use"
    with pytest.raises(FleetValidationError) as caught:
        plan_series_apply(snapshot, series(1), expected_generation=4)
    assert caught.value.code == "remove_confirmation_required"
    changed = plan_series_apply(snapshot, series(1), expected_generation=4,
                                confirmed_remove_ids=("d2", "d3"))
    assert changed.generation == 5 and changed.series[0].count == 1
    with pytest.raises(FleetValidationError) as caught:
        plan_series_delete(snapshot, "d", expected_generation=4)
    assert caught.value.code == "series_must_be_disabled"
    disabled = plan_series_disable(snapshot, "d", expected_generation=4)
    no_series = plan_series_delete(disabled, "d", expected_generation=5)
    assert plan_account_delete(no_series, "gemini-project-1", expected_generation=6).accounts == ()
