from __future__ import annotations

import pytest

from codex_master.fleet_control import (
    FleetControlError,
    account_secret_args,
    account_upsert_args,
    ollama_instance_plan_args,
    parse_ollama_page,
    parse_fleet_page,
    series_apply_args,
    series_plan_args,
)


def _accounts() -> dict[str, object]:
    return {
        "generation": 4,
        "accounts": [{
            "account_id": "gemini-project-1", "label": "Project 1",
            "provider": "gemini_api", "auth_kind": "api_key",
            "secret_state": "configured", "limit_state": "ready", "enabled": True,
            "secret": "must not be copied", "home": "/home/private",
        }],
    }


def _series(count: int = 26) -> dict[str, object]:
    return {
        "generation": 4,
        "series": [{
            "prefix": chr(ord("a") + index), "display_name": f"Series {index}",
            "count": 1, "runner": "gemini_cli", "provider": "gemini_api",
            "model": "gemini-3-flash-preview", "account_id": "gemini-project-1",
            "enabled": True, "runner_path": "/home/private/gemini",
        } for index in range(count)],
    }


def test_page_state_is_bounded_and_whitelisted() -> None:
    state = parse_fleet_page(_accounts(), _series())

    assert len(state.accounts) <= 64
    assert len(state.series) <= 26
    assert "secret" not in repr(state)
    assert "/home/" not in repr(state)


def test_account_secret_state_is_compatibility_view_of_auth_status() -> None:
    account = parse_fleet_page(_accounts(), _series()).accounts[0]
    assert account.secret_state == account.auth_status == "configured"


def test_page_parser_rejects_generation_mismatch_without_private_payload() -> None:
    series = _series()
    series["generation"] = 5
    state = parse_fleet_page(_accounts(), series)
    assert state.error_code == "generation_conflict"
    assert state.accounts == ()
    assert state.series == ()


@pytest.mark.parametrize(("provider", "auth_kind"), [
    ("gemini_api", "api_key"),
    ("openai_api", "api_key"),
    ("openai_chatgpt", "chatgpt_session"),
    ("huggingface_inference", "api_key"),
])
def test_account_builder_enforces_provider_auth_contract(provider: str, auth_kind: str) -> None:
    result = account_upsert_args(
        account_id="project-1", label="Project", provider=provider,
        auth_kind=auth_kind, enabled=True, expected_generation=4,
    )
    assert result["provider"] == provider
    assert result["expected_generation"] == 4


def test_account_builder_rejects_ollama_account_and_mismatched_auth() -> None:
    with pytest.raises(FleetControlError):
        account_upsert_args(
            account_id="local", label="Local", provider="ollama_local",
            auth_kind="none", enabled=True, expected_generation=1,
        )
    with pytest.raises(FleetControlError):
        account_upsert_args(
            account_id="project", label="Project", provider="gemini_api",
            auth_kind="chatgpt_session", enabled=True, expected_generation=1,
        )


def test_secret_builder_is_bounded_but_keeps_secret_only_for_immediate_dispatch() -> None:
    synthetic_secret = "syn" + "thetic"
    args = account_secret_args(account_id="project-1", secret=synthetic_secret, expected_generation=4)
    assert args == {"account_id": "project-1", "secret": "synthetic", "expected_generation": 4}


def test_series_builder_enforces_provider_runner_account_contract() -> None:
    args = series_plan_args(
        prefix="d", count=100, runner="gemini_cli", provider="gemini_api",
        model="gemini-3-flash-preview", account_id="project-1", enabled=True,
        expected_generation=4, confirmed_remove_ids=[],
    )
    assert args["prefix"] == "d"
    assert args["count"] == 100
    with pytest.raises(FleetControlError):
        series_apply_args(
            prefix="d", count=1, runner="codex_cli", provider="gemini_api",
            model="model", account_id=None, enabled=True,
            expected_generation=4, confirmed_remove_ids=[],
        )


def _ollama_models_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "model_count": 1,
        "models": [
            {
                "ref": "llama-small",
                "provider_model_id": "provider/llama-small",
                "installed": True,
                "hive_enabled": True,
                "simple_only": True,
                "capabilities": ["chat", "tools"],
                "evidence_at_utc": "2026-08-30T12:00:00Z",
            }
        ],
    }


def _ollama_instances_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "generation": 7,
        "instance_count": 1,
        "instances": [
            {
                "ref": "quiet-runner",
                "label": "Quiet Runner",
                "host_ref": "control-host",
                "selected_model_refs": ["llama-small"],
                "allowed_cpus": "4-7",
                "cpu_quota_percent": 350,
                "cpu_weight": 40,
                "lifecycle_state": "running",
                "readiness_state": "ready",
                "path_state": "configured_private",
            }
        ],
    }


def test_ollama_page_keeps_models_and_instances_separate() -> None:
    state = parse_ollama_page(
        _ollama_models_payload(), _ollama_instances_payload()
    )

    assert state.models[0].model_ref == "llama-small"
    assert state.models[0].capabilities == ("chat", "tools")
    assert state.instances[0].selected_model_refs == ("llama-small",)
    assert "/usr/bin" not in repr(state)


def test_ollama_page_discards_unknown_rows_with_bounded_error_counts() -> None:
    models = _ollama_models_payload()
    instances = _ollama_instances_payload()
    models["models"] = [*models["models"], {"ref": "/private/model"}]  # type: ignore[index]
    instances["instances"] = [*instances["instances"], {"ref": "broken"}]  # type: ignore[index]

    state = parse_ollama_page(models, instances)

    assert len(state.models) == 1
    assert len(state.instances) == 1
    assert state.rejected_model_count == 1
    assert state.rejected_instance_count == 1


def test_ollama_instance_args_preserve_exact_cpu_profile() -> None:
    args = ollama_instance_plan_args(
        ref="quiet-runner",
        label="Quiet Runner",
        host_ref="control-host",
        ollama_executable="/usr/bin/ollama",
        models_directory="/srv/ollama/models",
        selected_model_refs=("llama-small", "qwen-small"),
        allowed_cpus="4-7",
        cpu_quota_percent=350,
        cpu_weight=40,
        expected_generation=7,
        idempotency_key="request-one",
    )

    assert args["selected_model_refs"] == ["llama-small", "qwen-small"]
    assert args["allowed_cpus"] == "4-7"
    assert args["cpu_quota_percent"] == 350
    assert args["cpu_weight"] == 40
