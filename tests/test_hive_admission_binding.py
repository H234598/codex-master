from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path
import subprocess

import pytest

from codex_master.admission import AdmissionPriority, AdmissionState, LeaseBinding
from codex_master.hive.admission import HiveAdmissionError, create_assignment_admission
from codex_master.hive.authority import AuthorityContext, AuthorityEngine
from codex_master.hive.dispatch import AssignmentIntent, WorkPackage, plan_queen_assignment
from codex_master.hive.principals import Principal, PrincipalRegistry
from codex_master.hive.repositories import RepositoryBinding, RepositoryRegistry
from codex_master.hive.state import HiveStateStore
from codex_master.hive.types import DispatchPriority, TaskComplexity
from codex_master import server
from codex_master.server import _server_hive_authority_gate


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64
REQUEST_DIGEST = "sha256:" + "b" * 64


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
    return plan_queen_assignment(
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
    record = create_assignment_admission(
        plan=_plan(),
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
    assert record.scope.canonical_digest == repositories.scope_digest("codex-master", "write", ("src/task.py",))
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
        now=lambda: NOW,
    )

    record = captured["record"]
    assert result == {"status": "planned", "admission_id": "bridge-admission"}
    assert captured["operation"] == "hive_assignment_callback"
    assert record.state is AdmissionState.PLANNED
    assert record.grant_digest == grant.binding_digest()
    assert callable(captured["execute"])


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
