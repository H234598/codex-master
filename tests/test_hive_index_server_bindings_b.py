from __future__ import annotations

import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_master import server
from codex_master.admission import (
    AdmissionPriority,
    AdmissionRecord,
    AdmissionState,
    LeaseBinding,
    ResourceBinding,
    ScopeBinding,
)
from codex_master.admission_runtime import RuntimeGateDecision
from codex_master.fleet_registry import AgentDescriptor, InventorySnapshot, Provider, RunnerKind


NOW = datetime(2026, 8, 30, 12, tzinfo=timezone.utc)


def make_admission(
    *,
    agent_id: str = "a1",
    account_key: str = "native-a",
    model_id: str = "gpt-test",
    scope_digest: str = "sha256:scope",
    lease_state: str = "unclaimed",
    state: AdmissionState = AdmissionState.REVALIDATING,
    revision: int = 1,
) -> AdmissionRecord:
    return AdmissionRecord(
        schema_version=1,
        admission_id="admission-one",
        request_id="request-one",
        dispatch_id="dispatch-one",
        workpackage_id="workpackage-one",
        assignment_intent_id="intent-one",
        repo_id="codex-master",
        principal_id="principal-one",
        parent_principal_id="parent-one",
        grant_id="grant-one",
        grant_digest="sha256:grant",
        work_item_version=1,
        scope=ScopeBinding("write", ("tests/test_hive_index_server_bindings_b.py",), scope_digest),
        resource=ResourceBinding(agent_id, account_key, "budget-one", model_id, 1),
        lease_context=LeaseBinding(lease_state),
        priority=AdmissionPriority("DP1", "selected"),
        state=state,
        created_at_utc=NOW,
        expires_at_utc=NOW + timedelta(seconds=30),
        revision=revision,
    )


def make_descriptor(
    *,
    agent_id: str = "a1",
    runner: RunnerKind = RunnerKind.CODEX_CLI,
    provider: Provider = Provider.OPENAI_CHATGPT,
    model: str = "gpt-test",
    account_id: str | None = "native-a",
    enabled: bool = True,
    home: Path = Path("/tmp/a1"),
) -> AgentDescriptor:
    return AgentDescriptor(
        agent_id=agent_id,
        series_prefix=agent_id[0],
        ordinal=1,
        label=agent_id,
        runner=runner,
        provider=provider,
        model=model,
        account_id=account_id,
        home=home,
        session=f"codex-{agent_id}",
        enabled=enabled,
        runner_path=home / "codex",
    )


def make_inventory(descriptor: AgentDescriptor) -> InventorySnapshot:
    return InventorySnapshot(
        agent_ids=(descriptor.agent_id,),
        agents={descriptor.agent_id: descriptor},
        by_series={f"{descriptor.series_prefix}-series": (descriptor.agent_id,)},
        positions={descriptor.agent_id: 1},
        series_prefixes=(descriptor.series_prefix,),
    )


def patch_descriptor(monkeypatch: pytest.MonkeyPatch, descriptor: AgentDescriptor) -> None:
    monkeypatch.setattr(server, "current_agent_inventory", lambda: make_inventory(descriptor))


def assert_decision(decision: RuntimeGateDecision, allowed: bool, reason: str) -> None:
    assert decision.public() == {"allowed": allowed, "reason_code": reason}


def test_runtime_descriptor_resolves_inventory_descriptor(monkeypatch: pytest.MonkeyPatch) -> None:
    descriptor = make_descriptor()
    patch_descriptor(monkeypatch, descriptor)

    selected = server._server_runtime_descriptor(make_admission())

    assert selected == (make_inventory(descriptor), descriptor)
    assert server._server_runtime_descriptor(SimpleNamespace()) is None


def test_runtime_resource_gates_validate_account_model_usage_and_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = make_descriptor()
    patch_descriptor(monkeypatch, descriptor)
    monkeypatch.setattr(
        server,
        "_readonly_fleet_service",
        lambda: SimpleNamespace(
            load=lambda: "snapshot",
            account_gate=lambda agent, **kwargs: SimpleNamespace(
                allowed=agent == "a1", reason="account_ready"
            ),
        ),
    )
    monkeypatch.setattr(server, "ensure_agent_not_blocked_by_codex_usage", lambda agent: {"blocked": False})
    monkeypatch.setattr(
        server,
        "agent_lease_status",
        lambda agent, initialize_state=False: {"state": "unclaimed", "held_by_this_server": False},
    )

    admission = make_admission()
    assert [
        server._server_runtime_account_gate(admission).public(),
        server._server_runtime_model_gate(admission).public(),
        server._server_runtime_usage_gate(admission).public(),
        server._server_runtime_lease_gate(admission).public(),
    ] == [
        {"allowed": True, "reason_code": "account_ready"},
        {"allowed": True, "reason_code": "model_verified"},
        {"allowed": True, "reason_code": "usage_verified"},
        {"allowed": True, "reason_code": "lease_verified"},
    ]

    assert_decision(
        server._server_runtime_account_gate(make_admission(account_key="other")),
        False,
        "account_binding_mismatch",
    )
    assert_decision(
        server._server_runtime_model_gate(make_admission(model_id="other")),
        False,
        "model_binding_mismatch",
    )
    monkeypatch.setattr(server, "ensure_agent_not_blocked_by_codex_usage", lambda agent: {"blocked": True})
    assert_decision(server._server_runtime_usage_gate(admission), False, "usage_gate_denied")
    monkeypatch.setattr(
        server,
        "agent_lease_status",
        lambda agent, initialize_state=False: {"state": "held", "held_by_this_server": False},
    )
    assert_decision(server._server_runtime_lease_gate(admission), False, "lease_conflict")


def test_runtime_process_auth_and_config_gates_cover_codex_and_gemini(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codex = make_descriptor()
    patch_descriptor(monkeypatch, codex)
    monkeypatch.setattr(server, "agent_home_process_summary", lambda agent: {"process_count": 1})
    monkeypatch.setattr(server, "tmux_alive", lambda session: True)
    monkeypatch.setattr(server, "pane_pid", lambda session: 123)
    monkeypatch.setattr(server, "agent_identity_guard", lambda running, summary, **kwargs: {"ok": True})
    monkeypatch.setattr(server, "agent_auth_status", lambda agent: {"authenticated": True})
    monkeypatch.setattr(server, "agent_config", lambda agent: {"runner": Path("/tmp/codex")})
    monkeypatch.setattr(server, "is_regular_executable_no_symlink", lambda path: True)

    admission = make_admission()
    assert [
        server._server_runtime_process_gate(admission).public(),
        server._server_runtime_auth_gate(admission).public(),
        server._server_runtime_config_gate(admission).public(),
    ] == [
        {"allowed": True, "reason_code": "process_verified"},
        {"allowed": True, "reason_code": "auth_verified"},
        {"allowed": True, "reason_code": "config_verified"},
    ]

    gemini = make_descriptor(
        agent_id="g1",
        runner=RunnerKind.GEMINI_CLI,
        provider=Provider.GEMINI_API,
        account_id="gemini-one",
    )
    patch_descriptor(monkeypatch, gemini)
    monkeypatch.setattr(server, "headless_job_status", lambda agent: {"status": "identity_unverified"})
    monkeypatch.setattr(server, "_headless_executable", lambda descriptor: Path("/tmp/gemini"))
    gemini_admission = make_admission(agent_id="g1", account_key="gemini-one")
    assert_decision(
        server._server_runtime_process_gate(gemini_admission),
        False,
        "process_identity_unknown",
    )
    assert_decision(server._server_runtime_auth_gate(gemini_admission), True, "provider_auth_verified")
    assert_decision(server._server_runtime_config_gate(gemini_admission), True, "config_verified")


def test_hive_repository_and_scope_gates_bind_registry_decisions() -> None:
    admission = make_admission(scope_digest="sha256:expected")
    repository = SimpleNamespace(
        validate=lambda repo_id: SimpleNamespace(allowed=repo_id == "codex-master", reason_code="repository_verified"),
        scope_digest=lambda repo_id, mode, paths: "sha256:expected",
    )

    assert_decision(server._server_hive_repository_gate(repository, admission), True, "repository_verified")
    assert_decision(server._server_hive_scope_gate(repository, admission), True, "scope_verified")

    mismatch = replace(admission, scope=replace(admission.scope, canonical_digest="sha256:other"))
    assert_decision(server._server_hive_scope_gate(repository, mismatch), False, "scope_digest_mismatch")


def test_build_server_admission_runtime_binds_repository_scope_and_denies_missing_hive_gates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "AuthorityEngine", object)
    monkeypatch.setattr(server, "RepositoryRegistry", object)
    authority = SimpleNamespace(
        get_grant=lambda grant_id: SimpleNamespace(binding_digest=lambda: "sha256:grant"),
        validate_grant=lambda grant_id, **kwargs: SimpleNamespace(
            allowed=kwargs["capability"] == "hive.specialist.assign",
            reason_code="authority_verified",
        ),
    )
    repository = SimpleNamespace(
        validate=lambda repo_id: SimpleNamespace(allowed=True, reason_code="repository_verified"),
        scope_digest=lambda repo_id, mode, paths: "sha256:scope",
    )
    runtime = server.build_server_admission_runtime(
        authority_engine=authority,
        repository_registry=repository,
        now=lambda: NOW,
    )

    assert runtime._gates["authority"].__name__ == "bound_authority_gate"
    assert runtime._gates["repository"].__name__ == "bound_repository_gate"
    assert runtime._gates["scope"].__name__ == "bound_scope_gate"
    assert_decision(runtime._gates["authority"](make_admission()), True, "authority_verified")
    assert_decision(runtime._gates["repository"](make_admission()), True, "repository_verified")
    assert_decision(runtime._gates["scope"](make_admission()), True, "scope_verified")

    missing = server.build_server_admission_runtime(now=lambda: NOW)
    assert missing.revalidate(make_admission()) is False
    assert missing.last_failure() == {"allowed": False, "reason_code": "missing_authority_gate"}


def test_commit_ready_and_integration_status_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run_command(command, **kwargs):
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(server, "repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(server, "run_command", fake_run_command)
    monkeypatch.setattr(server, "git_excerpt", lambda command: "git output")
    monkeypatch.setattr(server, "list_assignments", lambda agent, limit: {"agent": agent, "limit": limit})

    ready = server.commit_ready_check(run_tests=False)
    assert ready["ok"] is True
    assert [check["name"] for check in ready["checks"]] == ["diff_check", "compileall"]
    assert calls[0] == ("git", "diff", "--check")
    assert calls[1][:4] == (sys.executable, "-m", "compileall", "-q")

    status = server.integration_status()
    assert status["repo"] == server.PATH_NOT_RETURNED
    assert status["status"] == "git output"
    assert status["assignments"] == {"agent": "all", "limit": 10}


def test_current_store_default_pool_aliases_and_assignment_helpers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_dir = tmp_path / "private"
    monkeypatch.setattr(server, "ADMISSION_STATE_FILE", state_dir / "admissions.json")
    monkeypatch.setattr(server, "ADMISSION_LOCK_FILE", state_dir / "admissions.lock")
    store = server.current_admission_store()
    assert store._state_path == state_dir / "admissions.json"
    assert store._lock_path == state_dir / "admissions.lock"

    pool = server.default_agent_pool_spec()
    assert pool["schema_version"] == server.POOL_SCHEMA_VERSION
    assert pool["series"][0] == {"prefix": "a", "count": 100, "template": "a1", "authenticated": ["a1"]}
    assert pool["auth"]["policy"] == "preserve_existing_only"

    monkeypatch.setattr(server, "fleet_sync_skill_projections", lambda: {"synced_count": 2})
    assert server.fleet_sync_gemini_skills() == {"synced_count": 2}

    monkeypatch.setattr(server, "list_assignments", lambda agent, limit: {"records": [{"agent": agent}]})
    assert server.last_assignment_status("a1")["status"] == "found"
    monkeypatch.setattr(server, "list_assignments", lambda agent, limit: {"records": []})
    assert server.last_assignment_status("a1")["record"] is None


def test_series_running_limits_principals_and_main(monkeypatch: pytest.MonkeyPatch) -> None:
    inventory = InventorySnapshot(
        agent_ids=("a1", "a2"),
        agents={},
        by_series={"a-series": ("a1", "a2")},
        positions={},
        series_prefixes=("a",),
    )
    assert server.series_agent_ids("a-series", snapshot=inventory) == ("a1", "a2")
    with pytest.raises(server.AgentError, match="unknown Agentinnen series selector"):
        server.series_agent_ids("x-series", snapshot=inventory)

    monkeypatch.setattr(server, "canonical_agent_id", lambda agent, snapshot=None: agent)
    monkeypatch.setattr(server, "agent_config", lambda agent: {"session": f"session-{agent}"})
    monkeypatch.setattr(server, "tmux_alive", lambda session: True)
    server.require_running_agent("a1")
    monkeypatch.setattr(server, "tmux_alive", lambda session: False)
    with pytest.raises(server.AgentError, match="agent a1 is not running"):
        server.require_running_agent("a1")

    monkeypatch.setattr(server, "read_hive_principals", lambda: {"digest-one": {"class": "koenigin"}})
    assert server.read_teamleader_principals() == {"digest-one"}
    monkeypatch.setattr(server, "assert_install_context_allows_master_registration", lambda: None)
    monkeypatch.setattr(server, "active_codex_home_path", lambda: Path("/tmp/home"))
    monkeypatch.setattr(server, "teamleader_principal_digest", lambda path: "digest-one")
    monkeypatch.setattr(server, "_read_hive_principals_strict", lambda missing_ok: {"digest-one": {"class": "koenigin"}})
    written: list[dict[str, object]] = []
    monkeypatch.setattr(server, "_write_hive_principals", lambda principals: written.append(dict(principals)))
    assert server.revoke_current_teamleader()["changed"] is True
    assert written == [{}]

    monkeypatch.setattr(server.sys, "argv", ["codex-master", "doctor"])
    monkeypatch.setattr(server, "main_cli", lambda argv: 7)
    assert server.main() == 7
    monkeypatch.setattr(server.sys, "argv", ["codex-master"])
    monkeypatch.setattr(server, "serve_mcp", lambda: 9)
    assert server.main() == 9


def test_normalize_wait_infer_limit_model_and_pool_expand_text() -> None:
    assert server.normalize_wait_seconds(0) == 0
    assert server.normalize_wait_seconds(server.MAX_WAIT_SECONDS) == server.MAX_WAIT_SECONDS
    with pytest.raises(server.AgentError, match="wait_seconds"):
        server.normalize_wait_seconds(True)

    assert server.infer_limit_model("rate limit reached on spark", {}, None) == server.WRITE_AGENT_MODEL
    assert (
        server.infer_limit_model(
            "rate limit reached",
            {"model": "session-model"},
            {"model": "assignment-model"},
        )
        == "assignment-model"
    )

    assert server.pool_expand_text("${MISSING_CODEX_TEST_VALUE:-fallback}/bin") == "fallback/bin"


def test_trusted_executables_and_skill_sync_are_wrapped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    exe = tmp_path / "codex"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    exe.chmod(0o700)
    monkeypatch.setattr(server, "directory_chain_is_real_no_symlink", lambda path: True)
    monkeypatch.setattr(server, "executable_directory_chain_is_trusted", lambda path: True)
    assert server.trusted_runner_executable(exe) == exe
    assert server.trusted_gemini_executable(exe) == exe

    with pytest.raises(server.AgentError, match="fleet_executable_invalid"):
        server.trusted_runner_executable(Path("relative"))

    descriptor = make_descriptor(agent_id="g1", runner=RunnerKind.GEMINI_CLI, provider=Provider.GEMINI_API)
    calls: list[tuple[Path, object]] = []
    monkeypatch.setattr(server, "canonical_agent_id", lambda agent: agent)
    monkeypatch.setattr(server, "_headless_descriptor", lambda agent: descriptor)
    monkeypatch.setattr(server, "_headless_executable", lambda descriptor: exe)
    monkeypatch.setattr(server, "pool_root_lock", lambda root: nullcontext())
    monkeypatch.setattr(server, "pool_root_operation", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(server, "path_present_no_follow", lambda path: True)
    monkeypatch.setattr(server, "_fleet_artifacts", lambda descriptor, executable: {"gemini": b"runner"})
    monkeypatch.setattr(server, "_fleet_write_home", lambda home, artifacts: calls.append((home, artifacts)) or False)
    assert server.sync_gemini_skill_home("g1") is True
    assert calls == [(descriptor.home, {"gemini": b"runner"})]


def test_fleet_materialize_native_registry_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "require_fleet_recovery_ready", lambda operation: None)
    monkeypatch.setattr(server, "fleet_mutation_lock", lambda paths: nullcontext())
    monkeypatch.setattr(server, "pool_root_lock", lambda root: nullcontext())
    monkeypatch.setattr(server, "pool_root_operation", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(server, "path_present_no_follow", lambda path: True)
    monkeypatch.setattr(server, "replace_private_text", lambda *args, **kwargs: None)
    monkeypatch.setattr(server.shutil, "which", lambda name: "/tmp/codex")
    monkeypatch.setattr(server, "trusted_runner_executable", lambda path: path)
    monkeypatch.setattr(server, "_fleet_artifacts", lambda descriptor, executable: {"codex": b"runner"})
    monkeypatch.setattr(server, "_fleet_write_home", lambda *args, **kwargs: False)
    monkeypatch.setattr(server, "publish_agent_inventory", lambda inventory: None)
    monkeypatch.setattr(server, "AGENTS", {"a1": {"home": Path("/tmp/a1")}, "b1": {"home": Path("/tmp/b1")}, "c1": {"home": Path("/tmp/c1")}})

    class FakeService:
        def __init__(self) -> None:
            self.snapshot = SimpleNamespace(generation=0, accounts=(), series=())

        def load(self):
            return self.snapshot

        def commit_snapshot(self, planned, *, expected_generation):
            self.snapshot = SimpleNamespace(generation=self.snapshot.generation + 1, accounts=(), series=())
            return self.snapshot

    monkeypatch.setattr(server, "current_fleet_service", FakeService)
    monkeypatch.setattr(server, "plan_account_upsert", lambda current, account, expected_generation: ("account", account))
    monkeypatch.setattr(server, "plan_series_apply", lambda current, candidate, **kwargs: ("series", candidate))
    monkeypatch.setattr(
        server,
        "build_inventory",
        lambda current, root: InventorySnapshot(
            agent_ids=(),
            agents={},
            by_series={"a-series": (), "b-series": (), "c-series": ()},
            positions={},
            series_prefixes=("a", "b", "c"),
        ),
    )

    result = server.fleet_materialize_native_registry()
    assert result["materialized_series"] == ["a", "b", "c"]
    assert result["agent_count"] == 11
    assert result["legacy_runtime_source"] == "removed_for_a_b_c"


class nullcontext:
    def __enter__(self):
        return Path("/tmp/pool")

    def __exit__(self, exc_type, exc, tb):
        return False
