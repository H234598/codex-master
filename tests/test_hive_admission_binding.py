from datetime import datetime, timedelta, timezone
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from the_hive.admission import (
    AdmissionPriority,
    AdmissionState,
    LeaseBinding,
)
from the_hive.dynamic_pool import (
    DynamicPoolInventoryEntryV1,
    DynamicPoolInventoryV1,
)
from the_hive.hive.admission import HiveAdmissionError, create_assignment_admission
from the_hive.hive.authority import AuthorityContext, AuthorityEngine
from the_hive.hive.dispatch import (
    AssignmentIntent,
    WorkPackage,
    plan_queen_assignment_from_selection,
)
from the_hive.hive.principals import Principal, PrincipalRegistry
from the_hive.hive.repositories import RepositoryBinding, RepositoryRegistry
from the_hive.hive.state import HiveStateStore
from the_hive.hive.types import DispatchPriority, TaskComplexity
from the_hive.selection import SelectionBand, SelectionResult
from the_hive import server
from the_hive.server import _server_hive_authority_gate
from the_hive.usage_snapshot import PoolAuthorityV2, UsageEvidenceV2


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64
REQUEST_DIGEST = "sha256:" + "b" * 64


def _pool_authority_evidence(*, provider: str = "openai") -> UsageEvidenceV2:
    return UsageEvidenceV2(
        accounts=(),
        status="complete",
        captured_at=NOW,
        generated_at=NOW,
        pool_authorities=(
            PoolAuthorityV2(
                account_id="account-one",
                pool_id="dynamic-pool",
                provider=provider,
                allowed_lifecycles=("persistent",),
                allowed_model_families=("gpt-primary",),
                hive_available=True,
                persistent_leadership_eligible=True,
                long_running_leadership_eligible=True,
                reasoning_minimum="low",
                reasoning_maximum="high",
            ),
        ),
    )


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "remote.origin.url", "https://github.com/example/repo.git"],
        check=True,
    )
    return root


def _principal(
    principal_id: str,
    class_id: str,
    parent: str | None,
    repo_id: str | None,
    scope_kind: str,
) -> Principal:
    return Principal(
        principal_id,
        class_id,
        parent,
        "profile",
        scope_kind,
        repo_id,
        "active",
        DIGEST,
        1,
    )


def _authority(tmp_path: Path) -> tuple[AuthorityEngine, RepositoryRegistry]:
    state = HiveStateStore(tmp_path / "state")
    principals = PrincipalRegistry(state)
    principals.create(_principal("godbee-main", "gottbiene", None, None, "global"))
    principals.create(_principal("queen-codex-master", "koenigin", "godbee-main", "codex-master", "repository"))
    principals.create(_principal("teamlead-one", "teamleiterin", "queen-codex-master", "codex-master", "repository"))
    principals.create(_principal("specialist-one", "spezialistin", "teamlead-one", "codex-master", "repository"))
    repositories = RepositoryRegistry(
        [RepositoryBinding("codex-master", "https://github.com/example/repo.git", _repo(tmp_path), "main", DIGEST)]
    )
    authority = AuthorityEngine(
        AuthorityContext(
            principals,
            repositories,
            {"profile": frozenset({"hive.specialist.assign"})},
        ),
        state=state,
        now=lambda: NOW,
    )
    return authority, repositories


def _workpackage() -> WorkPackage:
    return WorkPackage(
        "workpackage-one",
        "dispatch-one",
        "teamlead-one",
        "Implement bounded task",
        ("src",),
        ("src/task.py",),
        ("tests pass",),
        ("pytest",),
        "teamlead_commit",
        (),
        {"complexity": "complex"},
        state="admission_planned",
        version=7,
    )


def _intent() -> AssignmentIntent:
    return AssignmentIntent(
        "intent-one",
        "request-one",
        "dispatch-one",
        "workpackage-one",
        "codex-master",
        "teamlead-one",
        "grant-one",
        "spezialistin",
        DispatchPriority.DP1,
        TaskComplexity.COMPLEX,
        {"primary_only": True},
        {"mode": "write", "path_count": 1},
        "standard",
        ("decision-one",),
        "sha256:context",
    )


def _plan(*, mode: str = "enforced"):
    return plan_queen_assignment_from_selection(
        queen_id="queen-codex-master",
        dispatch_id="dispatch-one",
        workpackage={
            "workpackage_id": "workpackage-one",
            "repo_id": "codex-master",
            "teamlead_principal_id": "teamlead-one",
            "specialist_principal_id": "specialist-one",
            "writer_class_id": "spezialistin",
            "agent_id": "agent-one",
            "account_key": "hmac:account",
            "model_id": "gpt-primary",
            "model_role": "primary",
            "task_complexity": "complex",
            "scope": ("src",),
            "write_paths": ("src/task.py",),
            "mode": mode,
            "pilot_enabled": True,
            "account_confirmed": True,
            "authority_verified": True,
            "repository_verified": True,
            "scope_verified": True,
            "lease_available": True,
            "selection_band": "none",
        },
        selection=SelectionResult("agent-one", "gpt-primary", SelectionBand.SP3, 0),
        dynamic_inventory=DynamicPoolInventoryV1(
            {
                "agent-one": DynamicPoolInventoryEntryV1(
                    account_id="account-one",
                    pool_id="dynamic-pool",
                    authority_provider="openai",
                    runtime_provider="openai_chatgpt",
                ),
            }
        ),
    )


def _grant(authority: AuthorityEngine):
    return authority.issue_grant(
        grant_id="grant-one",
        issuer_principal_id="teamlead-one",
        subject_principal_id="specialist-one",
        repo_id="codex-master",
        dispatch_id="dispatch-one",
        capabilities=("hive.specialist.assign",),
        scope=("src",),
        write_paths=("src/task.py",),
        max_delegation_depth=1,
        issued_at_utc=NOW,
        expires_at_utc=NOW + timedelta(hours=1),
        nonce="nonce-one",
        request_digest=REQUEST_DIGEST,
    )


def test_assignment_binding_materializes_only_a_planned_record(tmp_path: Path) -> None:
    authority, repositories = _authority(tmp_path)
    grant = _grant(authority)
    workpackage = _workpackage()
    plan = _plan()
    record = create_assignment_admission(
        plan=plan,
        workpackage=workpackage,
        intent=_intent(),
        grant=grant,
        authority=authority,
        repositories=repositories,
        admission_id="admission-one",
        lease_context=LeaseBinding("claimed", "lease-one"),
        budget_key="standard",
        expected_usage_micro=1,
        priority=AdmissionPriority("DP1", "selection"),
        now=NOW,
    )

    assert record.state is AdmissionState.PLANNED
    assert record.work_item_version == workpackage.version
    assert record.grant_digest == grant.binding_digest()
    assert record.scope.paths == ("src/task.py",)
    assert record.scope.canonical_digest == repositories.scope_digest(
        "codex-master", "write", ("src/task.py",)
    )
    assert record.resource.account_pool_binding is plan.account_pool_binding
    assert authority.get_grant("grant-one").status == "active"
    assert "hmac:account" not in str(record.public())

    assert _server_hive_authority_gate(authority, record, "hive.specialist.assign").public() == {
        "allowed": True,
        "reason_code": "grant_verified",
    }
    tampered = replace(record, grant_digest="sha256:" + "f" * 64)
    assert _server_hive_authority_gate(authority, tampered, "hive.specialist.assign").public() == {
        "allowed": False,
        "reason_code": "grant_digest_mismatch",
    }


def test_server_hive_assignment_bridge_binds_plan_before_selection_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority, repositories = _authority(tmp_path)
    grant = _grant(authority)
    captured: dict[str, object] = {}
    pool_authority_reader = _pool_authority_evidence

    class FakeSelectionService:
        def execute_with_retry(self, plan_factory, operation):
            captured["operation"] = operation
            record = plan_factory()
            captured["record"] = record
            return {"status": "planned", "admission_id": record.admission_id}

    def fake_factory(**kwargs):
        captured.update(kwargs)
        return FakeSelectionService()

    monkeypatch.setattr(server, "build_server_selection_service", fake_factory)
    result = server.execute_server_hive_assignment(
        plan=_plan(),
        workpackage=_workpackage(),
        intent=_intent(),
        grant=grant,
        authority_engine=authority,
        repository_registry=repositories,
        admission_id="bridge-admission",
        lease_context=LeaseBinding("claimed", "lease-one"),
        budget_key="standard",
        expected_usage_micro=1,
        priority=AdmissionPriority("DP1", "selection"),
        operations={"hive_assignment_callback": lambda *_args: {"status": "executed"}},
        operation="hive_assignment_callback",
        pool_authority_reader=pool_authority_reader,
        now=lambda: NOW,
    )

    record = captured["record"]
    assert result == {"status": "planned", "admission_id": "bridge-admission"}
    assert captured["operation"] == "hive_assignment_callback"
    assert record.state is AdmissionState.PLANNED
    assert record.grant_digest == grant.binding_digest()
    assert callable(captured["execute"])
    assert captured["pool_authority_reader"] is pool_authority_reader


def test_server_hive_assignment_bridge_requires_explicit_pool_authority_reader(
    tmp_path: Path,
) -> None:
    authority, repositories = _authority(tmp_path)
    grant = _grant(authority)

    with pytest.raises(TypeError, match="pool_authority_reader"):
        server.execute_server_hive_assignment(
            plan=_plan(),
            workpackage=_workpackage(),
            intent=_intent(),
            grant=grant,
            authority_engine=authority,
            repository_registry=repositories,
            admission_id="bridge-reader-required",
            lease_context=LeaseBinding("claimed", "lease-one"),
            budget_key="standard",
            expected_usage_micro=1,
            priority=AdmissionPriority("DP1", "selection"),
            operations={"hive_assignment_callback": lambda *_args: {"status": "executed"}},
            now=lambda: NOW,
        )

    with pytest.raises(server.AgentError, match="invalid_pool_authority_reader"):
        server.execute_server_hive_assignment(
            plan=_plan(),
            workpackage=_workpackage(),
            intent=_intent(),
            grant=grant,
            authority_engine=authority,
            repository_registry=repositories,
            admission_id="bridge-reader-invalid",
            lease_context=LeaseBinding("claimed", "lease-one"),
            budget_key="standard",
            expected_usage_micro=1,
            priority=AdmissionPriority("DP1", "selection"),
            operations={"hive_assignment_callback": lambda *_args: {"status": "executed"}},
            pool_authority_reader=None,  # type: ignore[arg-type]
            now=lambda: NOW,
        )


def test_server_hive_assignment_bridge_blocks_a_missing_dynamic_pool_binding() -> None:
    with pytest.raises(server.AgentError, match="dynamic_pool_binding_missing"):
        server.execute_server_hive_assignment(
            plan=replace(_plan(), account_pool_binding=None),
            workpackage=_workpackage(),
            intent=_intent(),
            grant=object(),  # type: ignore[arg-type]
            authority_engine=object(),  # type: ignore[arg-type]
            repository_registry=object(),  # type: ignore[arg-type]
            admission_id="bridge-missing-binding",
            lease_context=LeaseBinding("claimed", "lease-one"),
            budget_key="standard",
            expected_usage_micro=1,
            priority=AdmissionPriority("DP1", "selection"),
            operations={},
            pool_authority_reader=_pool_authority_evidence,
            now=lambda: NOW,
        )


def test_server_hive_assignment_execution_bridge_delegates_scope_digest_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The private adapter reads the repository-owned digest without hashing."""

    authority, repositories = _authority(tmp_path)
    grant = _grant(authority)
    bridge = server._build_server_hive_assignment_execution_bridge(
        workpackage=_workpackage(),
        intent=_intent(),
        grant=grant,
        authority_engine=authority,
        repository_registry=repositories,
        admission_id="bridge-scope-digest",
        lease_context=LeaseBinding("claimed", "lease-one"),
        budget_key="standard",
        expected_usage_micro=1,
        priority=AdmissionPriority("DP1", "selection"),
        now=lambda: NOW,
    )
    expected = repositories.scope_digest("codex-master", "write", ("src/task.py",))
    calls: list[tuple[str, str, tuple[str, ...]]] = []

    def counted_scope_digest(
        repo_id: str, mode: str, paths: tuple[str, ...]
    ) -> str:
        calls.append((repo_id, mode, paths))
        return expected

    monkeypatch.setattr(repositories, "scope_digest", counted_scope_digest)

    assert bridge.scope_digest("codex-master", "write", ("src/task.py",)) == expected
    assert calls == [("codex-master", "write", ("src/task.py",))]


def test_server_hive_assignment_execution_bridge_reads_its_bound_admission_id(
    tmp_path: Path,
) -> None:
    """The dispatcher can persist the bridge's already validated base ID."""

    authority, repositories = _authority(tmp_path)
    bridge = server._build_server_hive_assignment_execution_bridge(
        workpackage=_workpackage(),
        intent=_intent(),
        grant=_grant(authority),
        authority_engine=authority,
        repository_registry=repositories,
        admission_id="bridge-bound-admission-id",
        lease_context=LeaseBinding("claimed", "lease-one"),
        budget_key="standard",
        expected_usage_micro=1,
        priority=AdmissionPriority("DP1", "selection"),
        now=lambda: NOW,
    )

    assert bridge.base_admission_id() == "bridge-bound-admission-id"


def test_source_only_dispatcher_composition_uses_the_real_admission_and_lease_path(
    tmp_path: Path,
) -> None:
    """A sandboxed process reaches the private port only through real gates.

    The child has an isolated HOME, state root, and pool root before importing
    ``server``.  Its temporary runner is validated but never executed; the
    only effect double is the dispatcher-owned PoolExecutionPort.
    """

    sandbox = tmp_path / "composition-sandbox"
    sandbox.mkdir(mode=0o700)
    repository = _repo(sandbox)
    (repository / "task.py").write_text("# source-only fixture\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "task.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "-c",
            "user.name=source-only",
            "-c",
            "user.email=source-only@example.invalid",
            "commit",
            "-q",
            "-m",
            "source-only fixture",
        ],
        check=True,
    )
    home = sandbox / "home"
    state_root = sandbox / "state"
    pool_root = sandbox / "pool"
    for directory in (home, state_root, pool_root):
        directory.mkdir(mode=0o700)

    child = textwrap.dedent(
        """
        from __future__ import annotations

        from datetime import datetime, timedelta, timezone
        import json
        import os
        from pathlib import Path

        from the_hive import server
        from the_hive.admission import AdmissionPriority, LeaseBinding
        from the_hive.admission_runtime import AdmissionRuntimeError
        from the_hive.dynamic_pool import DynamicPoolInventoryEntryV1, DynamicPoolInventoryV1
        from the_hive.fleet_registry import (
            AuthKind, FleetAccount, FleetSeries, FleetSnapshot, LimitState,
            Provider, RunnerKind, SecretState,
        )
        from the_hive.hive.authority import AuthorityContext, AuthorityEngine
        from the_hive.hive.control_plane_store import HiveControlPlaneStore
        from the_hive.hive.dispatch import AssignmentIntent, WorkPackage
        from the_hive.hive.principals import Principal, PrincipalRegistry
        from the_hive.hive.repositories import RepositoryBinding, RepositoryRegistry
        from the_hive.hive.state import HiveStateStore
        from the_hive.hive.types import DispatchPriority, TaskComplexity
        from the_hive.hive.work_dispatcher import HiveWorkDispatcher
        from the_hive.selection import SelectionBand, SelectionResult
        from the_hive.selection_service import SelectionDeniedError
        from the_hive.usage_snapshot import PoolAuthorityV2, UsageEvidenceV2


        root = Path(os.environ["D166_COMPOSITION_ROOT"])
        repository_root = Path(os.environ["D166_COMPOSITION_REPOSITORY"])
        moment = datetime.now(timezone.utc)
        digest = "sha256:" + "a" * 64
        request_digest = "sha256:" + "b" * 64

        # This is a temporary, local Fleet registry.  It never performs a
        # provider probe; the Gemini runner avoids home-auth and usage calls.
        fleet = FleetSnapshot(
            1,
            2,
            (
                FleetAccount(
                    "account-one", "source-only", Provider.GEMINI_API,
                    AuthKind.API_KEY, SecretState.CONFIGURED, LimitState.READY,
                    True, None, moment.isoformat(), None,
                ),
            ),
            (
                FleetSeries(
                    "g", "source-only", 1, RunnerKind.GEMINI_CLI,
                    Provider.GEMINI_API, "gemini-test", "account-one", True,
                ),
            ),
        )
        server.current_fleet_service().commit_snapshot(fleet, expected_generation=1)
        inventory = server.build_inventory(fleet, server.AGENT_POOL_ROOT)
        runner = server.AGENT_POOL_ROOT / "g1" / "gemini"
        runner.parent.mkdir(mode=0o700)
        runner.write_text("#!/bin/sh\\nexit 0\\n", encoding="utf-8")
        runner.chmod(0o700)

        # The real capacity guard reads this fresh v2 record and its shared
        # lock.  The runner above is not called by this test.
        probe_root = Path.home() / ".local" / "state" / "codex-master-mcp"
        probe_root.mkdir(parents=True, mode=0o700)
        probe_record = {
            "schema_version": 2,
            "checked_at": moment.isoformat(),
            "checks": {"runtime_layout": True, "hive_runtime": True, "hive_doctor": True},
            "commands": {"runtime_status": True, "hive_status": True, "hive_doctor": True},
        }
        probe_file = probe_root / "hive-hourly-health.json"
        probe_file.write_text(json.dumps(probe_record), encoding="utf-8")
        probe_file.chmod(0o600)
        probe_lock = probe_root / ".hive-hourly-probe.lock"
        probe_lock.touch(mode=0o600)
        probe_lock.chmod(0o600)

        hive_state = HiveStateStore(root / "hive")
        principals = PrincipalRegistry(hive_state)
        for principal in (
            Principal("godbee-main", "gottbiene", None, "profile", "global", None, "active", digest, 1),
            Principal("queen-codex-master", "koenigin", "godbee-main", "profile", "repository", "codex-master", "active", digest, 1),
            Principal("teamlead-one", "teamleiterin", "queen-codex-master", "profile", "repository", "codex-master", "active", digest, 1),
            Principal("specialist-one", "spezialistin", "teamlead-one", "profile", "repository", "codex-master", "active", digest, 1),
        ):
            principals.create(principal)
        repositories = RepositoryRegistry(
            (RepositoryBinding("codex-master", "https://github.com/example/repo.git", repository_root, "main", digest),)
        )
        authority = AuthorityEngine(
            AuthorityContext(principals, repositories, {"profile": frozenset({"hive.specialist.assign"})}),
            state=hive_state,
            now=lambda: moment,
        )
        control = HiveControlPlaneStore(HiveStateStore(root / "control"))
        control.initialize_task9(now=moment)

        class TestOnlyPoolExecutionPort:
            def __init__(self) -> None:
                self.calls = 0
                self.admission_ids: list[str] = []

            def execute(self, admission, _fresh_lease):
                self.calls += 1
                self.admission_ids.append(admission.admission_id)
                return {"status": "test_only_port"}

        port = TestOnlyPoolExecutionPort()
        dispatcher = HiveWorkDispatcher(control, execution_port=port)

        def evidence(provider: str) -> UsageEvidenceV2:
            return UsageEvidenceV2(
                accounts=(), status="complete", captured_at=moment, generated_at=moment,
                pool_authorities=(
                    PoolAuthorityV2(
                        account_id="account-one", pool_id="dynamic-pool", provider=provider,
                        allowed_lifecycles=("persistent",),
                        allowed_model_families=("gemini-test",), hive_available=True,
                        persistent_leadership_eligible=True,
                        long_running_leadership_eligible=True,
                        reasoning_minimum="low", reasoning_maximum="high",
                    ),
                ),
            )

        def run_case(name: str, providers: tuple[str, str]) -> tuple[int, int, str, str, tuple[str, ...]]:
            dispatch_id = f"dispatch-{name}"
            workpackage = WorkPackage(
                f"workpackage-{name}", dispatch_id, "teamlead-one", "source-only composition",
                ("src",), ("src/task.py",), ("port gated",), ("pytest",),
                "teamlead_commit", (), {"complexity": "complex"},
                state="admission_planned", version=1,
            )
            intent = AssignmentIntent(
                f"intent-{name}", f"request-{name}", dispatch_id, workpackage.workpackage_id,
                "codex-master", "teamlead-one", f"grant-{name}", "spezialistin",
                DispatchPriority.DP1, TaskComplexity.COMPLEX, {"primary_only": True},
                {"mode": "write", "path_count": 1}, "standard", ("decision-one",), digest,
            )
            grant = authority.issue_grant(
                grant_id=f"grant-{name}", issuer_principal_id="teamlead-one",
                subject_principal_id="specialist-one", repo_id="codex-master",
                dispatch_id=dispatch_id, capabilities=("hive.specialist.assign",),
                scope=("src",), write_paths=("src/task.py",), max_delegation_depth=1,
                issued_at_utc=moment, expires_at_utc=moment + timedelta(minutes=5),
                nonce=f"nonce-{name}", request_digest=request_digest,
            )
            selection = SelectionResult("g1", "gemini-test", SelectionBand.SP3, 0)
            dynamic_inventory = DynamicPoolInventoryV1(
                {"g1": DynamicPoolInventoryEntryV1("account-one", "dynamic-pool", "gemini", "gemini_api")}
            )
            bridge = server._build_server_hive_assignment_execution_bridge(
                workpackage=workpackage, intent=intent, grant=grant,
                authority_engine=authority, repository_registry=repositories,
                admission_id=f"admission-{name}", lease_context=LeaseBinding("unclaimed"),
                budget_key="standard", expected_usage_micro=1,
                priority=AdmissionPriority("DP1", "selection"),
                state_path=root / f"admission-{name}.json",
                lock_path=root / f"admission-{name}.lock",
                now=lambda: moment, sleeper=lambda _delay: None,
            )
            reads: list[UsageEvidenceV2] = []
            values = iter(providers)

            def reader() -> UsageEvidenceV2:
                value = evidence(next(values))
                reads.append(value)
                return value

            planner_input = {
                "workpackage_id": workpackage.workpackage_id, "repo_id": "codex-master",
                "teamlead_principal_id": "teamlead-one", "specialist_principal_id": "specialist-one",
                "writer_class_id": "spezialistin", "agent_id": "g1", "account_key": "account-one",
                "model_id": "gemini-test", "model_role": "primary", "task_complexity": "complex",
                "scope": ("src",), "write_paths": ("src/task.py",), "mode": "enforced",
                "pilot_enabled": True, "account_confirmed": True, "authority_verified": True,
                "repository_verified": True, "scope_verified": True, "lease_available": True,
                "selection_band": "none",
            }
            calls_before = port.calls
            callback_ids_before = len(port.admission_ids)
            try:
                result = dispatcher.dispatch(
                    queen_id="queen-codex-master", workpackage=workpackage, intent=intent,
                    grant=grant, selection=selection, dynamic_inventory=dynamic_inventory,
                    planner_input=planner_input, execution_bridge=bridge,
                    pool_authority_reader=reader, now=moment,
                )
            except (AdmissionRuntimeError, SelectionDeniedError):
                result = {"status": "denied"}
            status = result.get("status")
            if status is None:
                nested = result.get("result")
                status = nested.get("status") if isinstance(nested, dict) else None
            if status is None:
                raise AssertionError(repr(result))
            aggregate = dispatcher.rehydrate(dispatch_id)
            return (
                len(reads), port.calls - calls_before, status,
                aggregate.base_admission_id,
                tuple(port.admission_ids[callback_ids_before:]),
            )

        with server.temporary_agent_inventory(inventory):
            success_reads, success_calls, success_status, success_base_id, success_callback_ids = run_case("success", ("gemini", "gemini"))
            drift_reads, drift_calls, drift_status, drift_base_id, drift_callback_ids = run_case("drift", ("gemini", "other-provider"))

        assert (success_reads, success_calls, success_status) == (2, 1, "test_only_port")
        assert (success_base_id, success_callback_ids) == ("admission-success", ("admission-success",))
        assert (drift_reads, drift_calls, drift_status) == (2, 0, "denied")
        assert (drift_base_id, drift_callback_ids) == ("admission-drift", ())
        print(json.dumps({"ok": True}, sort_keys=True))
        """
    )
    environment = dict(os.environ)
    environment.update(
        {
            "HOME": str(home),
            "CODEX_MASTER_MCP_STATE": str(state_root),
            "CODEX_AGENT_POOL_ROOT": str(pool_root),
            "D166_COMPOSITION_ROOT": str(sandbox),
            "D166_COMPOSITION_REPOSITORY": str(repository),
            "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
        }
    )
    environment.pop("CODEX_AGENT_MCP_STATE", None)
    completed = subprocess.run(
        [sys.executable, "-c", child],
        cwd=Path(__file__).parents[1],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"ok": True}


def test_assignment_binding_rejects_shadow_and_mismatched_workpackage(tmp_path: Path) -> None:
    authority, repositories = _authority(tmp_path)
    grant = _grant(authority)
    with pytest.raises(HiveAdmissionError, match="assignment_shadow_only"):
        create_assignment_admission(
            plan=_plan(mode="shadow"), workpackage=_workpackage(), intent=_intent(), grant=grant,
            authority=authority, repositories=repositories, admission_id="admission-shadow",
            lease_context=LeaseBinding("claimed"), budget_key="standard", expected_usage_micro=1,
            priority=AdmissionPriority("DP1", "selection"), now=NOW,
        )

    mismatched = WorkPackage(
        "workpackage-other", "dispatch-one", "teamlead-one", "Implement bounded task", ("src",),
        ("src/task.py",), ("tests pass",), ("pytest",), "teamlead_commit", (), {},
        state="admission_planned", version=7,
    )
    with pytest.raises(HiveAdmissionError, match="workpackage_binding_mismatch"):
        create_assignment_admission(
            plan=_plan(), workpackage=mismatched, intent=_intent(), grant=grant,
            authority=authority, repositories=repositories, admission_id="admission-mismatch",
            lease_context=LeaseBinding("claimed"), budget_key="standard", expected_usage_micro=1,
            priority=AdmissionPriority("DP1", "selection"), now=NOW,
        )


def test_assignment_binding_rejects_changed_grant_and_scope(tmp_path: Path) -> None:
    authority, repositories = _authority(tmp_path)
    grant = _grant(authority)
    with pytest.raises(HiveAdmissionError, match="grant_binding_mismatch"):
        create_assignment_admission(
            plan=_plan(), workpackage=_workpackage(), intent=_intent(),
            grant=grant.__class__(
                grant.schema_version, grant.grant_id, grant.issuer_principal_id, "other-specialist",
                grant.repo_id, grant.dispatch_id, grant.capabilities, grant.scope, grant.write_paths,
                grant.max_delegation_depth, grant.issued_at_utc, grant.expires_at_utc,
                grant.nonce_digest, grant.request_digest, grant.status, grant.version,
            ),
            authority=authority, repositories=repositories, admission_id="admission-bad-grant",
            lease_context=LeaseBinding("claimed"), budget_key="standard", expected_usage_micro=1,
            priority=AdmissionPriority("DP1", "selection"), now=NOW,
        )

    authority.revoke_grant("grant-one", expected_version=grant.version)
    with pytest.raises(HiveAdmissionError, match="grant_state_changed|grant_inactive"):
        create_assignment_admission(
            plan=_plan(), workpackage=_workpackage(), intent=_intent(), grant=grant,
            authority=authority, repositories=repositories, admission_id="admission-revoked",
            lease_context=LeaseBinding("claimed"), budget_key="standard", expected_usage_micro=1,
            priority=AdmissionPriority("DP1", "selection"), now=NOW,
        )
