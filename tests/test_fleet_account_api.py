from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_master import server
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetSeries,
    FleetSnapshot,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
)
from codex_master.fleet_recovery import RecoveryPhase
from codex_master.fleet_runners import ProbeResult, ProviderModelsResult


def test_account_and_series_api_is_generation_bound_and_secret_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")

    created = server.fleet_account_upsert(
        account_id="gemini-project-1",
        label="Gemini one",
        provider="gemini_api",
        auth_kind="api_key",
        enabled=True,
        expected_generation=1,
    )
    assert created["generation"] == 2
    assert created["account"]["secret_state"] == "missing"

    configured = server.fleet_account_set_secret(
        account_id="gemini-project-1",
        secret="local-only-secret",
        expected_generation=2,
    )
    assert configured == {
        "configured": True,
        "generation": 3,
        "secret": "not_returned",
        "raw_output": "not_returned",
    }
    secret_path = tmp_path / "state" / "fleet" / "secrets" / "gemini-project-1.secret"
    assert secret_path.read_text() == "local-only-secret"
    assert "local-only-secret" not in json.dumps(server.fleet_account_list())

    service = server.current_fleet_service()
    current = service.load()
    series = FleetSeries(
        "d", "Gemini D", 2, RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "gemini-3-flash-preview", "gemini-project-1", True,
    )
    service.commit_snapshot(
        FleetSnapshot(1, current.generation + 1, current.accounts, (series,)),
        expected_generation=current.generation,
    )
    listed = server.fleet_series_list()
    assert listed["generation"] == 4
    assert listed["series"] == [{
        "prefix": "d",
        "display_name": "Gemini D",
        "count": 2,
        "runner": "gemini_cli",
        "provider": "gemini_api",
        "model": "gemini-3-flash-preview",
        "account_id": "gemini-project-1",
        "enabled": True,
    }]

    disabled = server.fleet_account_disable(
        account_id="gemini-project-1",
        expected_generation=4,
    )
    assert disabled["generation"] == 5
    assert disabled["account"]["enabled"] is False

    with pytest.raises(server.AgentError, match="generation_conflict"):
        server.fleet_account_disable(account_id="gemini-project-1", expected_generation=4)


def test_account_upsert_rejects_provider_change_for_bound_series(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    account = FleetAccount(
        "shared", "Shared", Provider.GEMINI_API, AuthKind.API_KEY,
        SecretState.CONFIGURED, LimitState.READY, True,
        None, "2026-08-03T12:00:00Z", None,
    )
    series = FleetSeries(
        "d", "D", 1, RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "model", "shared", True,
    )
    server.current_fleet_service().commit_snapshot(
        FleetSnapshot(1, 2, (account,), (series,)), expected_generation=1,
    )

    with pytest.raises(server.AgentError, match="account_in_use"):
        server.fleet_account_upsert(
            account_id="shared",
            label="Changed",
            provider="openai_api",
            auth_kind="api_key",
            enabled=True,
            expected_generation=2,
        )


def test_account_api_readers_survive_blocking_recovery_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / "state"
    pool_root = tmp_path / "pool"
    monkeypatch.setattr(server, "STATE_ROOT", state_root)
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", pool_root)
    journal = replace(
        server.FleetRecoveryJournal(
            schema_version=1,
            journal_id="a" * 32,
            operation=server.RecoveryOperation.SERIES_APPLY,
            pool_root_digest=hashlib.sha256(
                server._pool_root_digest_text(pool_root).encode("utf-8")
            ).hexdigest(),
            expected_generation=1,
            planned_generation=2,
            authoritative_generation=None,
            phase=RecoveryPhase.DEGRADED,
            entries=(),
            blocking_error_codes=("fleet_recovery_incomplete",),
        )
    )
    server._fleet_store_recovery_journal(journal)

    assert server.fleet_account_list()["account_count"] == 0
    with pytest.raises(server.FleetRecoveryBlockedError):
        server.fleet_account_upsert(
            account_id="blocked",
            label="Blocked",
            provider="gemini_api",
            auth_kind="api_key",
            enabled=True,
            expected_generation=1,
        )


def test_account_tool_catalog_has_no_secret_default_or_private_fields() -> None:
    by_name = {tool["name"]: tool for tool in server.TOOLS}
    assert {
        "fleet_account_list",
        "fleet_account_upsert",
        "fleet_account_set_secret",
        "fleet_account_probe",
        "fleet_account_disable",
        "fleet_account_delete",
        "fleet_series_list",
        "fleet_series_plan",
        "fleet_series_apply",
        "fleet_series_disable",
        "fleet_series_delete",
        "fleet_provider_models",
    } <= set(by_name)
    secret_schema = by_name["fleet_account_set_secret"]["inputSchema"]
    assert "secret" in secret_schema["properties"]
    assert "default" not in secret_schema["properties"]["secret"]
    assert secret_schema["additionalProperties"] is False
    provider_schema = by_name["fleet_provider_models"]["inputSchema"]
    assert provider_schema["properties"]["provider"]["enum"] == [
        "ollama_local", "huggingface_inference",
    ]


def test_fleet_cli_namespace_exposes_read_only_account_listing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    assert server.main_cli(["fleet", "account", "list"]) == 0
    assert json.loads(capsys.readouterr().out)["account_count"] == 0


def test_provider_models_is_bounded_and_keeps_hf_secret_private(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    captured: dict[str, object] = {}

    def fake_probe(provider: Provider, *, secret: str | None = None) -> ProviderModelsResult:
        captured["provider"] = provider
        captured["secret"] = secret
        return ProviderModelsResult(
            provider,
            True,
            ({"id": "good/model", "agentic": True},),
            None,
        )

    monkeypatch.setattr(server, "probe_provider_models", fake_probe)
    ollama = server.fleet_provider_models(provider="ollama_local")
    assert ollama["model_count"] == 1
    assert captured == {"provider": Provider.OLLAMA_LOCAL, "secret": None}

    server.fleet_account_upsert(
        account_id="hf-main",
        label="HF main",
        provider="huggingface_inference",
        auth_kind="api_key",
        enabled=True,
        expected_generation=1,
    )
    server.fleet_account_set_secret(
        account_id="hf-main",
        secret="hf-private-token",
        expected_generation=2,
    )
    huggingface = server.fleet_provider_models(
        provider="huggingface_inference",
        account_id="hf-main",
    )
    assert huggingface["models"] == [{"id": "good/model", "agentic": True}]
    assert captured == {"provider": Provider.HUGGINGFACE_INFERENCE, "secret": "hf-private-token"}
    assert "hf-private-token" not in json.dumps(huggingface)


def test_provider_models_requires_configured_hf_account_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    with pytest.raises(server.AgentError, match="secret_missing"):
        server.fleet_provider_models(provider="huggingface_inference")


def test_account_probe_persists_only_redacted_readiness_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    server.fleet_account_upsert(
        account_id="hf-probe",
        label="HF probe",
        provider="huggingface_inference",
        auth_kind="api_key",
        enabled=True,
        expected_generation=1,
    )
    server.fleet_account_set_secret(
        account_id="hf-probe",
        secret="probe-token",
        expected_generation=2,
    )
    monkeypatch.setattr(
        server,
        "probe_provider_models",
        lambda provider, *, secret=None: ProviderModelsResult(
            provider,
            True,
            ({"id": "good/model", "agentic": True},),
            None,
        ),
    )
    result = server.fleet_account_probe(account_id="hf-probe", expected_generation=3)
    assert result == {
        "probed": True,
        "generation": 4,
        "ready": True,
        "reason": "ready",
        "model": "good/model",
        "raw_output": "not_returned",
    }
    assert server.fleet_account_list()["accounts"][0]["limit_state"] == "ready"
    assert "probe-token" not in json.dumps(server.fleet_account_list())


def test_gemini_account_probe_reports_missing_secret_without_invalidating_account(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    server.fleet_account_upsert(
        account_id="gemini-missing",
        label="Gemini missing",
        provider="gemini_api",
        auth_kind="api_key",
        enabled=True,
        expected_generation=1,
    )

    result = server.fleet_account_probe(account_id="gemini-missing", expected_generation=2)

    assert result == {
        "probed": True,
        "generation": 3,
        "ready": False,
        "reason": "secret_missing",
        "raw_output": "not_returned",
    }
    account = server.fleet_account_list()["accounts"][0]
    assert account["secret_state"] == "missing"  # type: ignore[index]
    assert account["limit_state"] == "unknown"  # type: ignore[index]


def test_gemini_account_probe_returns_verified_model_without_secret_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    server.fleet_account_upsert(
        account_id="gemini-ready",
        label="Gemini ready",
        provider="gemini_api",
        auth_kind="api_key",
        enabled=True,
        expected_generation=1,
    )
    server.fleet_account_set_secret(
        account_id="gemini-ready",
        secret="gemini-private-token",
        expected_generation=2,
    )
    monkeypatch.setattr(server.shutil, "which", lambda _name: "/usr/local/bin/gemini")
    monkeypatch.setattr(server, "trusted_gemini_executable", lambda path: path)
    captured: dict[str, object] = {}

    def fake_probe(secret: str, executable: Path, **_kwargs: object) -> ProbeResult:
        captured["secret"] = secret
        captured["executable"] = executable
        return ProbeResult(
            Provider.GEMINI_API,
            True,
            "gemini-3-flash-preview",
            True,
            None,
        )

    monkeypatch.setattr(server, "probe_gemini_cli", fake_probe)
    result = server.fleet_account_probe(account_id="gemini-ready", expected_generation=3)

    assert result == {
        "probed": True,
        "generation": 4,
        "ready": True,
        "reason": "ready",
        "model": "gemini-3-flash-preview",
        "raw_output": "not_returned",
    }
    assert captured["secret"] == "gemini-private-token"
    assert "gemini-private-token" not in json.dumps(result)


def test_account_delete_requires_disabled_unbound_account_and_removes_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    server.fleet_account_upsert(
        account_id="delete-me",
        label="Delete me",
        provider="gemini_api",
        auth_kind="api_key",
        enabled=True,
        expected_generation=1,
    )
    server.fleet_account_set_secret(
        account_id="delete-me",
        secret="delete-private",
        expected_generation=2,
    )
    with pytest.raises(server.AgentError, match="account_must_be_disabled"):
        server.fleet_account_delete(account_id="delete-me", expected_generation=3)
    server.fleet_account_disable(account_id="delete-me", expected_generation=3)
    deleted = server.fleet_account_delete(account_id="delete-me", expected_generation=4)
    assert deleted == {
        "mutation_performed": True,
        "deleted": True,
        "generation": 5,
        "cleanup_pending": False,
        "raw_output": "not_returned",
    }
    assert not (tmp_path / "state" / "fleet" / "secrets" / "delete-me.secret").exists()
    assert server.fleet_account_list()["accounts"] == []


def test_account_provider_change_removes_old_secret_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    server.fleet_account_upsert(
        account_id="switch-me",
        label="Switch me",
        provider="gemini_api",
        auth_kind="api_key",
        enabled=True,
        expected_generation=1,
    )
    server.fleet_account_set_secret(
        account_id="switch-me",
        secret="old-provider-secret",
        expected_generation=2,
    )
    switched = server.fleet_account_upsert(
        account_id="switch-me",
        label="Switched",
        provider="openai_api",
        auth_kind="api_key",
        enabled=True,
        expected_generation=3,
    )
    assert switched["cleanup_pending"] is False
    assert switched["account"]["secret_state"] == "missing"
    assert not (tmp_path / "state" / "fleet" / "secrets" / "switch-me.secret").exists()


def test_account_provider_change_cleanup_is_retryable_after_sidecar_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    server.fleet_account_upsert(
        account_id="retry-me",
        label="Retry me",
        provider="gemini_api",
        auth_kind="api_key",
        enabled=True,
        expected_generation=1,
    )
    server.fleet_account_set_secret(
        account_id="retry-me",
        secret="old-provider-secret",
        expected_generation=2,
    )
    real_remove = server.FleetService.remove_secret_sidecar
    calls = 0

    def fail_once(service: object, *args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise server.FleetSecretError("secret_write_failed")
        return real_remove(service, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(server.FleetService, "remove_secret_sidecar", fail_once)
    first = server.fleet_account_upsert(
        account_id="retry-me",
        label="Retry me",
        provider="openai_api",
        auth_kind="api_key",
        enabled=True,
        expected_generation=3,
    )
    assert first["cleanup_pending"] is True
    assert (tmp_path / "state" / "fleet" / "secrets" / "retry-me.secret").exists()

    second = server.fleet_account_upsert(
        account_id="retry-me",
        label="Retry me",
        provider="openai_api",
        auth_kind="api_key",
        enabled=True,
        expected_generation=4,
    )
    assert second["cleanup_pending"] is False
    assert not (tmp_path / "state" / "fleet" / "secrets" / "retry-me.secret").exists()


def test_fleet_mutation_dispatch_requires_expected_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")

    with pytest.raises(server.AgentError, match="expected_generation is required"):
        server.call_tool(
            "fleet_account_upsert",
            {
                "account_id": "missing-generation",
                "label": "Missing generation",
                "provider": "gemini_api",
                "auth_kind": "api_key",
                "enabled": True,
            },
        )


def test_selector_policy_falls_back_to_one_published_fleet_series(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    series = FleetSeries(
        "d", "D", 2, RunnerKind.CODEX_CLI, Provider.OLLAMA_LOCAL,
        "local-model", None, True,
    )
    inventory = server.build_inventory(FleetSnapshot(1, 1, (), (series,)), tmp_path / "pool")
    monkeypatch.setattr(server, "published_agent_inventory", lambda: (inventory, True))
    monkeypatch.setattr(server, "current_agent_inventory", lambda: inventory)
    monkeypatch.setattr(server, "SELECTOR_POLICY_FILE", tmp_path / "selector-policy.json")
    assert server.selector_policy_series() == ("d",)
    assert server.agent_ids("both") == ["d1", "d2"]
