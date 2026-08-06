from __future__ import annotations

import pytest

from codex_master.control_center import (
    AGENT_ID_RE,
    FLEET_CATEGORY,
    SERIES_FILTER_RE,
    FleetControlCenter,
    FleetControlCenterError,
)


def _payloads() -> tuple[dict[str, object], dict[str, object]]:
    return (
        {"generation": 4, "accounts": [{
            "account_id": "project-1", "label": "Project", "provider": "gemini_api",
            "auth_kind": "api_key", "secret_state": "missing", "limit_state": "unknown",
            "enabled": True,
        }]},
        {"generation": 4, "series": [{
            "prefix": "d", "display_name": "D", "count": 1, "runner": "gemini_cli",
            "provider": "gemini_api", "model": "gemini-3-flash-preview",
            "account_id": "project-1", "enabled": True,
        }]},
    )


def test_filters_accept_only_bounded_dynamic_ids() -> None:
    assert SERIES_FILTER_RE.fullmatch("d")
    assert not SERIES_FILTER_RE.fullmatch("dd")
    assert AGENT_ID_RE.fullmatch("d100")
    assert not AGENT_ID_RE.fullmatch("d101")
    assert FLEET_CATEGORY == "Serien & Accounts"


def test_secret_is_cleared_after_dispatch_even_on_failure() -> None:
    seen: list[dict[str, object]] = []

    def dispatch(_tool: str, args: dict[str, object]):
        seen.append(args)
        raise RuntimeError("transport failed")

    center = FleetControlCenter(dispatch)
    with pytest.raises(RuntimeError, match="transport failed"):
        center.set_account_secret(account_id="project-1", secret="synthetic", expected_generation=4)
    assert seen[0]["secret"] == ""
    assert "synthetic" not in repr(center.view)


def test_dry_run_generation_is_required_for_apply() -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def dispatch(tool: str, args: dict[str, object]):
        calls.append((tool, args))
        return {"generation": 4, "next_generation": 5}

    center = FleetControlCenter(dispatch)
    center.refresh(*_payloads())
    with pytest.raises(FleetControlCenterError, match="stale"):
        center.apply_series(
            prefix="d", count=1, runner="gemini_cli", provider="gemini_api",
            model="gemini-3-flash-preview", account_id="project-1", enabled=True,
            expected_generation=4,
        )
    center.plan_series(
        prefix="d", count=1, runner="gemini_cli", provider="gemini_api",
        model="gemini-3-flash-preview", account_id="project-1", enabled=True,
        expected_generation=4,
    )
    center.apply_series(
        prefix="d", count=1, runner="gemini_cli", provider="gemini_api",
        model="gemini-3-flash-preview", account_id="project-1", enabled=True,
        expected_generation=5,
    )
    assert [tool for tool, _args in calls] == ["fleet_series_plan", "fleet_series_apply"]


def test_control_center_completes_gpt_account_bound_series_flow() -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def dispatch(tool: str, args: dict[str, object]):
        calls.append((tool, dict(args)))
        return {"generation": 4, "next_generation": 5}

    center = FleetControlCenter(dispatch)
    center.refresh(
        {"generation": 4, "accounts": []},
        {"generation": 4, "series": []},
    )
    center.upsert_account(
        account_id="chatgpt-project", label="ChatGPT Project",
        provider="openai_chatgpt", auth_kind="chatgpt_session", enabled=True,
        expected_generation=4,
    )
    center.plan_series(
        prefix="g", count=2, runner="codex_cli", provider="openai_chatgpt",
        model="gpt-5.3-spark", account_id="chatgpt-project", enabled=True,
        expected_generation=4,
    )
    center.apply_series(
        prefix="g", count=2, runner="codex_cli", provider="openai_chatgpt",
        model="gpt-5.3-spark", account_id="chatgpt-project", enabled=True,
        expected_generation=5,
    )

    assert [tool for tool, _args in calls] == [
        "fleet_account_upsert", "fleet_series_plan", "fleet_series_apply",
    ]
    assert calls[0][1]["auth_kind"] == "chatgpt_session"
    assert calls[2][1]["account_id"] == "chatgpt-project"
