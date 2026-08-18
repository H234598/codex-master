from __future__ import annotations

import hashlib
import hmac
import json
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from codex_master import server
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetAccountV2,
    FleetSeries,
    FleetSeriesMember,
    FleetSeriesV2,
    FleetSnapshot,
    FleetSnapshotV2,
    FleetValidationError,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
)
from codex_master.fleet_recovery import RecoveryPhase
from codex_master.fleet_runners import ProbeDiagnosticCode, ProbeResult, ProviderError, ProviderModelsResult


GEMINI_PROJECT_CREDENTIAL = "local-only-secret"
HF_MAIN_CREDENTIAL = "hf-private-token"
HF_PROBE_CREDENTIAL = "probe-token"
GEMINI_READY_CREDENTIAL = "gemini-private-token"
DELETE_CREDENTIAL = "delete-private"
OLD_PROVIDER_CREDENTIAL = "old-provider-secret"
FIXED_BINDING_SALT = bytes(range(32))


def v2_gemini_snapshot(*, generation: int = 2, enabled: bool = False) -> FleetSnapshotV2:
    accounts = tuple(
        FleetAccountV2(
            account_id,
            label,
            Provider.GEMINI_API,
            AuthKind.API_KEY,
            SecretState.MISSING,
            LimitState.READY,
            enabled,
            None,
            None,
            None,
        )
        for account_id, label in (
            ("gemini-project-1", "Gemini one"),
            ("gemini-project-2", "Gemini two"),
        )
    )
    members = (
        FleetSeriesMember("00000000-0000-4000-8000-000000000001", 1, "gemini-project-1", enabled),
        FleetSeriesMember("00000000-0000-4000-8000-000000000002", 2, "gemini-project-2", enabled),
    )
    return FleetSnapshotV2(
        2,
        generation,
        accounts,
        (
            FleetSeriesV2(
                "g",
                "Gemini G",
                RunnerKind.GEMINI_CLI,
                Provider.GEMINI_API,
                "gemini-3-flash-preview",
                enabled,
                "generic",
                "standard",
                members,
            ),
        ),
    )


def v2_account(snapshot: FleetSnapshotV2, account_id: str) -> FleetAccountV2:
    matches = [item for item in snapshot.accounts if item.account_id == account_id]
    assert len(matches) == 1
    return matches[0]


def test_v2_gemini_secret_binding_is_stable_private_and_rotation_sensitive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    service = server.current_fleet_service()
    service.commit_snapshot(v2_gemini_snapshot(), expected_generation=1)

    service.set_secret("gemini-project-1", "same-key", expected_generation=2)
    first = v2_account(service.load(), "gemini-project-1").credential_binding_id
    service.set_secret("gemini-project-2", "same-key", expected_generation=3)
    second = v2_account(service.load(), "gemini-project-2").credential_binding_id

    assert first == second
    assert first is not None and first.startswith("hmac-sha256:")
    salt_path = service._paths.secrets / ".credential-binding-salt"
    assert salt_path.stat().st_size == 32
    assert stat.S_IMODE(salt_path.stat().st_mode) == 0o600
    service.set_secret("gemini-project-1", "rotated-key", expected_generation=4)
    assert v2_account(service.load(), "gemini-project-1").credential_binding_id != first
    public = json.dumps(service.public_snapshot())
    assert first not in public
    assert "credential_binding_id" not in public


def test_v2_configured_gemini_without_binding_is_denied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    service = server.current_fleet_service()
    snapshot = v2_gemini_snapshot(enabled=True)
    configured = replace(
        snapshot,
        accounts=tuple(replace(account, secret_state=SecretState.CONFIGURED) for account in snapshot.accounts),
    )
    service.commit_snapshot(configured, expected_generation=1)

    decision = service.account_gate("g1")
    assert decision.reason == "credential_binding_unknown"
    assert decision.allowed is False


def test_second_active_v2_gemini_same_credential_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    service = server.current_fleet_service()
    service.commit_snapshot(v2_gemini_snapshot(enabled=True), expected_generation=1)
    service.set_secret("gemini-project-1", "same-key", expected_generation=2)

    with pytest.raises(FleetValidationError, match="duplicate_credential_binding"):
        service.set_secret("gemini-project-2", "same-key", expected_generation=3)
    assert not (service._paths.secrets / "gemini-project-2.secret").exists()
    after = service.load()
    assert after.generation == 3
    assert v2_account(after, "gemini-project-2").credential_binding_id is None


def test_existing_binding_salt_wrong_mode_fails_closed_after_sidecar_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    service = server.current_fleet_service()
    service.commit_snapshot(v2_gemini_snapshot(enabled=True), expected_generation=1)
    service.set_secret("gemini-project-1", "first-key", expected_generation=2)
    service.set_secret("gemini-project-2", "second-key", expected_generation=3)
    before = service.load()
    second_before = v2_account(before, "gemini-project-2")
    salt_path = service._paths.secrets / ".credential-binding-salt"
    salt = salt_path.read_bytes()
    salt_path.chmod(0o644)

    with pytest.raises(server.FleetSecretError, match="credential_binding_unavailable"):
        service.set_secret("gemini-project-2", "rotated-key", expected_generation=4)

    assert salt_path.read_bytes() == salt
    assert stat.S_IMODE(salt_path.stat().st_mode) == 0o644
    assert (service._paths.secrets / "gemini-project-2.secret").read_text() == "second-key"
    after = service.load()
    assert after.generation == before.generation
    assert v2_account(after, "gemini-project-2").credential_binding_id == (
        second_before.credential_binding_id
    )


def test_existing_binding_missing_salt_fails_closed_without_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    service = server.current_fleet_service()
    service.commit_snapshot(v2_gemini_snapshot(enabled=True), expected_generation=1)
    service.set_secret("gemini-project-1", "first-key", expected_generation=2)
    before = service.load()
    salt_path = service._paths.secrets / ".credential-binding-salt"
    salt_path.unlink()

    with pytest.raises(server.FleetSecretError, match="credential_binding_unavailable"):
        service.set_secret("gemini-project-2", "second-key", expected_generation=3)

    assert not salt_path.exists()
    assert not (service._paths.secrets / "gemini-project-2.secret").exists()
    after = service.load()
    assert after.generation == before.generation
    assert v2_account(after, "gemini-project-1").credential_binding_id == (
        v2_account(before, "gemini-project-1").credential_binding_id
    )


@pytest.mark.parametrize("invalid_salt", [b"", b"invalid-salt"])
def test_existing_binding_invalid_salt_fails_closed(
    invalid_salt: bytes,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    service = server.current_fleet_service()
    service.commit_snapshot(v2_gemini_snapshot(enabled=True), expected_generation=1)
    service.set_secret("gemini-project-1", "first-key", expected_generation=2)
    before = service.load()
    salt_path = service._paths.secrets / ".credential-binding-salt"
    salt_path.write_bytes(invalid_salt)
    salt_path.chmod(0o600)

    with pytest.raises(server.FleetSecretError, match="credential_binding_unavailable"):
        service.set_secret("gemini-project-2", "second-key", expected_generation=3)

    assert salt_path.read_bytes() == invalid_salt
    assert not (service._paths.secrets / "gemini-project-2.secret").exists()
    assert service.load().generation == before.generation


def test_duplicate_binding_restores_target_sidecar_and_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    service = server.current_fleet_service()
    service.commit_snapshot(v2_gemini_snapshot(enabled=True), expected_generation=1)
    service.set_secret("gemini-project-1", "same-key", expected_generation=2)
    service.set_secret("gemini-project-2", "old-second-key", expected_generation=3)
    before = service.load()
    second_before = v2_account(before, "gemini-project-2")

    with pytest.raises(FleetValidationError, match="duplicate_credential_binding"):
        service.set_secret("gemini-project-2", "same-key", expected_generation=4)

    assert (service._paths.secrets / "gemini-project-2.secret").read_text() == "old-second-key"
    after = service.load()
    assert after.generation == before.generation
    assert v2_account(after, "gemini-project-2").credential_binding_id == (
        second_before.credential_binding_id
    )


def test_binding_hmac_fixed_vector_uses_private_domain_and_salt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    service = server.current_fleet_service()
    salt_path = service._paths.secrets / ".credential-binding-salt"
    salt_path.parent.mkdir(parents=True, exist_ok=True)
    salt_path.write_bytes(FIXED_BINDING_SALT)
    salt_path.chmod(0o600)
    service.commit_snapshot(v2_gemini_snapshot(), expected_generation=1)

    service.set_secret("gemini-project-1", "fixed-secret", expected_generation=2)
    expected = "hmac-sha256:" + hmac.new(
        FIXED_BINDING_SALT,
        b"codex-master:gemini-credential-binding:v1\0fixed-secret",
        hashlib.sha256,
    ).hexdigest()
    assert v2_account(service.load(), "gemini-project-1").credential_binding_id == expected


def test_public_v2_account_api_redacts_binding_salt_and_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    service = server.current_fleet_service()
    service.commit_snapshot(v2_gemini_snapshot(), expected_generation=1)
    service.set_secret("gemini-project-1", "publicly-secret", expected_generation=2)

    payload = json.dumps(server.fleet_account_list())
    assert "credential_binding_id" not in payload
    assert "publicly-secret" not in payload
    assert ".credential-binding-salt" not in payload


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
        secret=GEMINI_PROJECT_CREDENTIAL,
        expected_generation=2,
    )
    assert configured == {
        "configured": True,
        "generation": 3,
        "secret": "not_returned",
        "raw_output": "not_returned",
    }
    secret_path = tmp_path / "state" / "fleet" / "secrets" / "gemini-project-1.secret"
    assert secret_path.read_text() == GEMINI_PROJECT_CREDENTIAL
    assert GEMINI_PROJECT_CREDENTIAL not in json.dumps(server.fleet_account_list())

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
        secret=HF_MAIN_CREDENTIAL,
        expected_generation=2,
    )
    huggingface = server.fleet_provider_models(
        provider="huggingface_inference",
        account_id="hf-main",
    )
    assert huggingface["models"] == [{"id": "good/model", "agentic": True}]
    assert captured == {"provider": Provider.HUGGINGFACE_INFERENCE, "secret": HF_MAIN_CREDENTIAL}
    assert HF_MAIN_CREDENTIAL not in json.dumps(huggingface)


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
        secret=HF_PROBE_CREDENTIAL,
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
    assert HF_PROBE_CREDENTIAL not in json.dumps(server.fleet_account_list())


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
        secret=GEMINI_READY_CREDENTIAL,
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
    assert captured["secret"] == GEMINI_READY_CREDENTIAL
    assert GEMINI_READY_CREDENTIAL not in json.dumps(result)


@pytest.mark.parametrize((
    "error_kind",
    "error_retryable",
    "diagnostic_code",
    "expected_observed",
    "expected_process",
    "expected_observed_process",
    "expected_ready",
    "expected_reason",
    "expected_event_status",
    "model_name",
), [
    (
        "provider_unavailable",
        False,
        "gemini_probe_process_timeout",
        "gemini_probe_process_timeout",
        "gemini_probe_timeout_output_unclassified",
        "gemini_probe_timeout_output_unclassified",
        False,
        "provider_unavailable",
        "failed",
        None,
    ),
    (
        "runner_failed",
        False,
        "gemini_probe_runner_failure",
        "gemini_probe_runner_failure",
        "gemini_probe_process_group_unreaped",
        "gemini_probe_process_group_unreaped",
        False,
        "provider_unavailable",
        "failed",
        None,
    ),
    (
        "provider_unavailable",
        False,
        "mystery_probe_code",
        None,
        "not_a_phase",
        None,
        False,
        "provider_unavailable",
        "failed",
        None,
    ),
    (
        "provider_unavailable",
        False,
        None,
        None,
        "gemini_probe_normal_exit",
        "gemini_probe_normal_exit",
        True,
        "ready",
        "completed",
        "gemini-2.5-flash",
    ),
])
def test_gemini_account_probe_persists_probe_diagnostic_code_for_provider_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_kind: str,
    error_retryable: bool,
    diagnostic_code: str,
    expected_observed: ProbeDiagnosticCode | None,
    expected_process: str,
    expected_observed_process: str | None,
    expected_ready: bool,
    expected_reason: str,
    expected_event_status: str,
    model_name: str | None,
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
        secret=GEMINI_READY_CREDENTIAL,
        expected_generation=2,
    )
    monkeypatch.setattr(server.shutil, "which", lambda _name: "/usr/local/bin/gemini")
    monkeypatch.setattr(server, "trusted_gemini_executable", lambda path: path)

    def fake_probe(secret: str, executable: Path, **_kwargs: object) -> ProbeResult:
        if not expected_ready:
            return ProbeResult(
                Provider.GEMINI_API,
                False,
                None,
                False,
                ProviderError(
                    error_kind,
                    error_retryable,
                    None,
                    None,
                    diagnostic_code=diagnostic_code,
                ),
                process_phase=expected_process,
            )

        return ProbeResult(
            Provider.GEMINI_API,
            True,
            model_name,
            True,
            None,
            process_phase=expected_process,
        )

    monkeypatch.setattr(server, "probe_gemini_cli", fake_probe)
    result = server.fleet_account_probe(account_id="gemini-ready", expected_generation=3)

    assert result["probed"] is True
    assert result["ready"] is expected_ready
    assert result["reason"] == expected_reason
    if expected_observed is None:
        assert "diagnostic_code" not in result
        assert result.get("process_phase") == expected_observed_process
        if model_name is not None:
            assert result.get("model") == model_name
    else:
        if model_name is not None:
            assert result.get("model") == model_name
        assert result["diagnostic_code"] == expected_observed
        assert result.get("process_phase") == expected_observed_process
    events = (server.STATE_ROOT / "fleet" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert events, "missing account_probe event"
    event = json.loads(events[-1])
    assert isinstance(event, dict)
    assert event["event_type"] == "account_probe"
    assert event["status"] == expected_event_status
    assert event.get("reason") == expected_reason
    if expected_observed is None:
        assert "diagnostic_code" not in event
    else:
        assert event.get("diagnostic_code") == expected_observed
    if expected_observed_process is None:
        assert "process_phase" not in event
    else:
        assert event.get("process_phase") == expected_observed_process
    assert GEMINI_READY_CREDENTIAL not in json.dumps(result)


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
        secret=DELETE_CREDENTIAL,
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
        secret=OLD_PROVIDER_CREDENTIAL,
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
        secret=OLD_PROVIDER_CREDENTIAL,
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
