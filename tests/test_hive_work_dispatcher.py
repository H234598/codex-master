"""Direct source-only coverage for the one dynamic-pool product dispatcher."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections.abc import Callable, Mapping

import pytest

from the_hive.admission import (
    AdmissionState,
    AdmissionStore,
    AdmissionPriority,
    AdmissionRecord,
    LeaseBinding,
    ResourceBinding,
    ScopeBinding,
    create_admission,
)
from the_hive.dynamic_pool import (
    AccountPoolBindingV1,
    DynamicPoolInventoryEntryV1,
    DynamicPoolInventoryV1,
)
from the_hive.hive.authority import DelegationGrant
from the_hive.hive.admission import create_assignment_admission
from the_hive.hive.control_plane_store import HiveControlPlaneStore
from the_hive.hive.dispatch import (
    AssignmentIntent,
    WorkPackage,
    plan_queen_assignment_from_selection,
)
from the_hive.hive.authority import AuthorityContext, AuthorityEngine
from the_hive.hive.principals import Principal, PrincipalRegistry
from the_hive.hive.repositories import RepositoryBinding, RepositoryRegistry
from the_hive.hive.state import HiveStateStore
from the_hive.hive.types import DispatchPriority, TaskComplexity
from the_hive.hive import work_dispatcher as dispatcher_module
from the_hive.hive.work_dispatcher import HiveWorkDispatcher
from the_hive.selection import SelectionBand, SelectionResult


NOW = datetime(2026, 9, 15, 12, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64
REQUEST_DIGEST = "sha256:" + "b" * 64


def _workpackage(*, dispatch_id: str = "dispatch-one") -> WorkPackage:
    return WorkPackage(
        "workpackage-one",
        dispatch_id,
        "teamlead-one",
        "Persist one complete product unit",
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


def _intent(*, dispatch_id: str = "dispatch-one") -> AssignmentIntent:
    return AssignmentIntent(
        "intent-one",
        "request-one",
        dispatch_id,
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


def _grant(*, dispatch_id: str = "dispatch-one") -> DelegationGrant:
    return DelegationGrant(
        1,
        "grant-one",
        "teamlead-one",
        "specialist-one",
        "codex-master",
        dispatch_id,
        ("hive.specialist.assign",),
        ("src",),
        ("src/task.py",),
        1,
        NOW,
        NOW + timedelta(hours=1),
        DIGEST,
        REQUEST_DIGEST,
        "active",
        3,
    )


def _selection() -> SelectionResult:
    return SelectionResult("agent-one", "gpt-primary", SelectionBand.SP3, 0)


def _inventory() -> DynamicPoolInventoryV1:
    return DynamicPoolInventoryV1(
        {
            "agent-one": DynamicPoolInventoryEntryV1(
                account_id="account-one",
                pool_id="dynamic-pool",
                authority_provider="openai",
                runtime_provider="openai_chatgpt",
            ),
        }
    )


def _real_assignment_authority(tmp_path: Path) -> tuple[AuthorityEngine, RepositoryRegistry]:
    repository_root = tmp_path / "repository"
    repository_root.mkdir()
    authority_state = HiveStateStore(tmp_path / "authority-state")
    principals = PrincipalRegistry(authority_state)
    for principal in (
        Principal("godbee-main", "gottbiene", None, "profile", "global", None, "active", DIGEST, 1),
        Principal(
            "queen-codex-master",
            "koenigin",
            "godbee-main",
            "profile",
            "repository",
            "codex-master",
            "active",
            DIGEST,
            1,
        ),
        Principal(
            "teamlead-one",
            "teamleiterin",
            "queen-codex-master",
            "profile",
            "repository",
            "codex-master",
            "active",
            DIGEST,
            1,
        ),
        Principal(
            "specialist-one",
            "spezialistin",
            "teamlead-one",
            "profile",
            "repository",
            "codex-master",
            "active",
            DIGEST,
            1,
        ),
    ):
        principals.create(principal)
    repositories = RepositoryRegistry(
        [
            RepositoryBinding(
                "codex-master",
                "https://github.com/example/repo.git",
                repository_root,
                "main",
                DIGEST,
            )
        ]
    )
    return (
        AuthorityEngine(
            AuthorityContext(
                principals,
                repositories,
                {"profile": frozenset({"hive.specialist.assign"})},
            ),
            state=authority_state,
            now=lambda: NOW,
        ),
        repositories,
    )


def _real_assignment_grant(authority: AuthorityEngine) -> DelegationGrant:
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


def _executing_assignment_admission(
    tmp_path: Path,
) -> tuple[DelegationGrant, AdmissionRecord, RepositoryRegistry]:
    authority, repositories = _real_assignment_authority(tmp_path)
    grant = _real_assignment_grant(authority)
    plan = plan_queen_assignment_from_selection(
        queen_id="queen-codex-master",
        dispatch_id="dispatch-one",
        workpackage=_planner_input(),
        selection=_selection(),
        dynamic_inventory=_inventory(),
    )
    now = datetime.now(timezone.utc)
    planned = create_assignment_admission(
        plan=plan,
        workpackage=_workpackage(),
        intent=_intent(),
        grant=grant,
        authority=authority,
        repositories=repositories,
        admission_id="admission-real",
        lease_context=LeaseBinding("claimed", "lease-one"),
        budget_key="standard",
        expected_usage_micro=1,
        priority=AdmissionPriority("DP1", "selection"),
        now=now,
    )
    store = AdmissionStore()
    reserved = store.reserve(planned, now=now)
    revalidating = store.begin_revalidation(
        reserved.admission_id, expected_revision=reserved.revision, now=now
    )
    admitted = store.complete_revalidation(
        revalidating.admission_id,
        expected_revision=revalidating.revision,
        valid=True,
        now=now,
    )
    return (
        grant,
        store.begin_execution(
            admitted.admission_id, expected_revision=admitted.revision, now=now
        ),
        repositories,
    )


def _planner_input() -> dict[str, object]:
    return {
        "workpackage_id": "workpackage-one",
        "repo_id": "codex-master",
        "teamlead_principal_id": "teamlead-one",
        "specialist_principal_id": "specialist-one",
        "writer_class_id": "spezialistin",
        "agent_id": "agent-one",
        "account_key": "account-key",
        "model_id": "gpt-primary",
        "model_role": "primary",
        "task_complexity": "complex",
        "scope": ("src",),
        "write_paths": ("src/task.py",),
        "mode": "enforced",
        "pilot_enabled": True,
        "account_confirmed": True,
        "authority_verified": True,
        "repository_verified": True,
        "scope_verified": True,
        "lease_available": True,
        "selection_band": "none",
    }


def _admission() -> AdmissionRecord:
    now = datetime.now(timezone.utc)
    planned = create_admission(
        admission_id="admission-one",
        request_id="request-one",
        dispatch_id="dispatch-one",
        workpackage_id="workpackage-one",
        assignment_intent_id="intent-one",
        repo_id="codex-master",
        principal_id="specialist-one",
        parent_principal_id="teamlead-one",
        grant_id="grant-one",
        grant_digest=_grant().binding_digest(),
        work_item_version=7,
        scope=ScopeBinding("write", ("src/task.py",), DIGEST),
        resource=ResourceBinding(
            "agent-one",
            "account-key",
            "standard",
            "gpt-primary",
            1,
            AccountPoolBindingV1("account-one", "dynamic-pool", "openai", "openai_chatgpt"),
        ),
        lease_context=LeaseBinding("claimed", "lease-one"),
        priority=AdmissionPriority("DP1", "selection"),
        now=now,
    )
    store = AdmissionStore()
    reserved = store.reserve(planned, now=now)
    revalidating = store.begin_revalidation(
        reserved.admission_id, expected_revision=reserved.revision, now=now
    )
    admitted = store.complete_revalidation(
        revalidating.admission_id,
        expected_revision=revalidating.revision,
        valid=True,
        now=now,
    )
    return store.begin_execution(
        admitted.admission_id, expected_revision=admitted.revision, now=now
    )


def _without_admission_id(record: AdmissionRecord) -> AdmissionRecord:
    """Model a damaged typed record that bypassed its constructor boundary."""

    object.__setattr__(record, "admission_id", "")
    return record


class RecordingPoolExecutionPort:
    def __init__(self) -> None:
        self.calls: list[tuple[AdmissionRecord, dict[str, object]]] = []

    def execute(
        self, admission: AdmissionRecord, fresh_lease: Mapping[str, object]
    ) -> dict[str, object]:
        self.calls.append((admission, fresh_lease))
        return {"status": "test_double_executed"}


class RecordingServerBridge:
    def __init__(self, admission: AdmissionRecord) -> None:
        self.admission = admission
        self.calls = 0
        self.plans: list[object] = []
        self.readers: list[object] = []
        self.scope_digest_requests: list[tuple[str, str, tuple[str, ...]]] = []

    def scope_digest(self, repo_id: str, mode: str, paths: tuple[str, ...]) -> str:
        self.scope_digest_requests.append((repo_id, mode, paths))
        return DIGEST

    def base_admission_id(self) -> str:
        """Expose the same base ID the server uses for its retry records."""

        return "admission-one"

    def execute(
        self,
        *,
        plan: object,
        pool_authority_reader: object,
        hive_assignment_callback: object,
    ) -> dict[str, object]:
        self.calls += 1
        self.plans.append(plan)
        self.readers.append(pool_authority_reader)
        assert callable(pool_authority_reader)
        assert callable(hive_assignment_callback)
        return hive_assignment_callback(
            self.admission,
            {"state": "held", "held_by_this_server": True, "lease_id": "lease-one"},
        )


def test_dispatcher_persists_rehydrates_full_unit_binds_once_and_calls_one_bound_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "state"))
    control.initialize_task9(now=NOW)
    port = RecordingPoolExecutionPort()
    bridge = RecordingServerBridge(_admission())
    dispatcher = HiveWorkDispatcher(control, execution_port=port)
    calls = 0
    original = dispatcher_module.plan_queen_assignment_from_selection

    def reader() -> object:
        return object()

    def counted_planner(**kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(**kwargs)

    monkeypatch.setattr(dispatcher_module, "plan_queen_assignment_from_selection", counted_planner)

    result = dispatcher.dispatch(
        queen_id="queen-codex-master",
        workpackage=_workpackage(),
        intent=_intent(),
        grant=_grant(),
        selection=_selection(),
        dynamic_inventory=_inventory(),
        planner_input=_planner_input(),
        execution_bridge=bridge,
        pool_authority_reader=reader,
        now=NOW,
    )

    assert result == {"status": "test_double_executed"}
    assert calls == 1
    assert bridge.calls == 1
    assert bridge.readers == [reader]
    assert bridge.scope_digest_requests == [
        ("codex-master", "write", ("src/task.py",))
    ]
    assert len(port.calls) == 1
    aggregate = dispatcher.rehydrate("dispatch-one")
    assert aggregate.generation == 3
    assert aggregate.state == "bridge_returned"
    assert aggregate.digest.startswith("sha256:")
    assert aggregate.workpackage == _workpackage()
    assert aggregate.intent == _intent()
    assert aggregate.grant == _grant()
    assert aggregate.selection == _selection()
    assert aggregate.dynamic_inventory == _inventory()
    assert aggregate.scope_digest == DIGEST
    assert aggregate.base_admission_id == "admission-one"
    assert tuple(step.state for step in aggregate.transitions) == (
        "persisted",
        "bound",
        "bridge_returned",
    )
    assert HiveWorkDispatcher(control, execution_port=port).rehydrate("dispatch-one") == aggregate
    assert len(control.load_task9()["pool_dispatches"]) == 1


def test_dispatcher_callback_rejects_an_id_only_foreign_executing_admission_after_restart(
    tmp_path: Path,
) -> None:
    """A matching aggregate cannot be replayed through another admission ID."""

    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "state"))
    control.initialize_task9(now=NOW)
    port = RecordingPoolExecutionPort()
    bridge = RecordingServerBridge(replace(_admission(), admission_id="admission-foreign"))

    result = HiveWorkDispatcher(control, execution_port=port).dispatch(
        queen_id="queen-codex-master",
        workpackage=_workpackage(),
        intent=_intent(),
        grant=_grant(),
        selection=_selection(),
        dynamic_inventory=_inventory(),
        planner_input=_planner_input(),
        execution_bridge=bridge,
        pool_authority_reader=lambda: object(),
        now=NOW,
    )

    aggregate = HiveWorkDispatcher(control, execution_port=port).rehydrate("dispatch-one")
    assert aggregate.base_admission_id == "admission-one"
    assert result == {"allowed": False, "reason_code": "pool_execution_unavailable"}
    assert port.calls == []


def test_dispatcher_callback_accepts_the_canonical_server_retry_admission_id(
    tmp_path: Path,
) -> None:
    """The second server attempt remains bound to its persisted base admission ID."""

    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "state"))
    control.initialize_task9(now=NOW)
    port = RecordingPoolExecutionPort()
    bridge = RecordingServerBridge(replace(_admission(), admission_id="admission-one-attempt-2"))

    result = HiveWorkDispatcher(control, execution_port=port).dispatch(
        queen_id="queen-codex-master",
        workpackage=_workpackage(),
        intent=_intent(),
        grant=_grant(),
        selection=_selection(),
        dynamic_inventory=_inventory(),
        planner_input=_planner_input(),
        execution_bridge=bridge,
        pool_authority_reader=lambda: object(),
        now=NOW,
    )

    assert result == {"status": "test_double_executed"}
    assert [record.admission_id for record, _lease in port.calls] == ["admission-one-attempt-2"]


@pytest.mark.parametrize(
    ("base_admission_id", "admission_id", "expected"),
    (
        ("admission-one", "admission-one", True),
        ("admission-one", "admission-one-attempt-2", True),
        ("admission-one", "admission-one-attempt-3", True),
        ("admission-one", "admission-one-attempt-1", False),
        ("admission-one", "admission-one-attempt-4", False),
        ("admission-one", "admission-foreign", False),
        (
            "a" * 128,
            f"{'a' * (128 - len('-attempt-2'))}-attempt-2",
            True,
        ),
    ),
)
def test_dispatcher_accepts_only_the_existing_server_retry_admission_id_form(
    base_admission_id: str, admission_id: str, expected: bool
) -> None:
    assert (
        dispatcher_module._admission_id_matches_base(admission_id, base_admission_id)
        is expected
    )


def test_dispatcher_requires_a_bridge_base_admission_id_before_persisting(
    tmp_path: Path,
) -> None:
    """No aggregate exists when an injected bridge lacks the ID reader contract."""

    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "state"))
    control.initialize_task9(now=NOW)

    class MissingBaseIdBridge:
        def scope_digest(self, _repo_id: str, _mode: str, _paths: tuple[str, ...]) -> str:
            return DIGEST

        def execute(self, **_kwargs: object) -> Mapping[str, object]:
            raise AssertionError("bridge must not execute")

    with pytest.raises(dispatcher_module.HiveWorkDispatcherError, match="invalid_hive_execution_bridge"):
        HiveWorkDispatcher(control, execution_port=RecordingPoolExecutionPort()).dispatch(
            queen_id="queen-codex-master",
            workpackage=_workpackage(),
            intent=_intent(),
            grant=_grant(),
            selection=_selection(),
            dynamic_inventory=_inventory(),
            planner_input=_planner_input(),
            execution_bridge=MissingBaseIdBridge(),
            pool_authority_reader=lambda: object(),
            now=NOW,
        )

    assert control.load_task9()["pool_dispatches"] == []


def test_dispatcher_rehydrate_rejects_a_persisted_base_admission_id_substitution(
    tmp_path: Path,
) -> None:
    """The base ID participates in the persisted aggregate and transition digests."""

    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "state"))
    control.initialize_task9(now=NOW)
    port = RecordingPoolExecutionPort()
    dispatcher = HiveWorkDispatcher(control, execution_port=port)
    dispatcher.dispatch(
        queen_id="queen-codex-master",
        workpackage=_workpackage(),
        intent=_intent(),
        grant=_grant(),
        selection=_selection(),
        dynamic_inventory=_inventory(),
        planner_input=_planner_input(),
        execution_bridge=RecordingServerBridge(_admission()),
        pool_authority_reader=lambda: object(),
        now=NOW,
    )
    tampered = control.load_task9()
    tampered_records = list(tampered["pool_dispatches"])
    tampered_records[0] = {**tampered_records[0], "base_admission_id": "admission-foreign"}
    tampered["pool_dispatches"] = tampered_records
    control.replace_task9(tampered, expected_revision=tampered["revision"], now=NOW)

    with pytest.raises(dispatcher_module.HiveWorkDispatcherError, match="hive_work_digest_mismatch"):
        dispatcher.rehydrate("dispatch-one")


def test_dispatcher_callback_accepts_real_assignment_admission_and_rejects_digest_tampering(
    tmp_path: Path,
) -> None:
    """The final port accepts the genuine admission's two authoritative digests."""

    grant, admission, repositories = _executing_assignment_admission(tmp_path)
    assert admission.grant_digest == grant.binding_digest()
    assert admission.grant_digest != grant.nonce_digest
    assert admission.scope.canonical_digest != grant.nonce_digest

    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "control-state"))
    control.initialize_task9(now=NOW)
    port = RecordingPoolExecutionPort()
    dispatcher = HiveWorkDispatcher(control, execution_port=port)
    fresh_lease = {"state": "held", "held_by_this_server": True, "lease_id": "lease-one"}

    class GenuineAdmissionBridge:
        def scope_digest(self, repo_id: str, mode: str, paths: tuple[str, ...]) -> str:
            return repositories.scope_digest(repo_id, mode, paths)

        def base_admission_id(self) -> str:
            return admission.admission_id

        def execute(
            self, *, hive_assignment_callback: object, **_kwargs: object
        ) -> Mapping[str, object]:
            assert callable(hive_assignment_callback)
            result = hive_assignment_callback(admission, fresh_lease)
            assert hive_assignment_callback(
                replace(admission, grant_digest=grant.nonce_digest), fresh_lease
            ) == {"allowed": False, "reason_code": "pool_execution_unavailable"}
            assert hive_assignment_callback(
                replace(
                    admission,
                    scope=replace(
                        admission.scope,
                        canonical_digest=grant.nonce_digest,
                    ),
                ),
                fresh_lease,
            ) == {"allowed": False, "reason_code": "pool_execution_unavailable"}
            return result

    result = dispatcher.dispatch(
        queen_id="queen-codex-master",
        workpackage=_workpackage(),
        intent=_intent(),
        grant=grant,
        selection=_selection(),
        dynamic_inventory=_inventory(),
        planner_input=_planner_input(),
        execution_bridge=GenuineAdmissionBridge(),
        pool_authority_reader=lambda: object(),
        now=NOW,
    )

    assert result == {"status": "test_double_executed"}
    assert len(port.calls) == 1


def test_dispatcher_without_product_port_is_unavailable_and_never_calls_a_port(tmp_path: Path) -> None:
    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "state"))
    control.initialize_task9(now=NOW)
    dispatcher = HiveWorkDispatcher(control)

    assert dispatcher._hive_assignment_callback(
        _admission(),
        {"state": "held", "held_by_this_server": True, "lease_id": "lease-one"},
    ) == {
        "allowed": False,
        "reason_code": "pool_execution_unavailable",
    }


def test_dispatcher_callback_rejects_unbound_and_foreign_admissions_without_a_port_call(
    tmp_path: Path,
) -> None:
    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "state"))
    control.initialize_task9(now=NOW)
    port = RecordingPoolExecutionPort()
    dispatcher = HiveWorkDispatcher(control, execution_port=port)
    dispatcher.persist(
        workpackage=_workpackage(),
        intent=_intent(),
        grant=_grant(),
        selection=_selection(),
        dynamic_inventory=_inventory(),
        scope_digest=DIGEST,
        base_admission_id="admission-one",
        now=NOW,
    )

    assert dispatcher._hive_assignment_callback(
        _admission(),
        {"state": "held", "held_by_this_server": True, "lease_id": "lease-one"},
    ) == {
        "allowed": False,
        "reason_code": "pool_execution_unavailable",
    }
    assert port.calls == []

    foreign = replace(
        _admission(), dispatch_id="dispatch-two", assignment_intent_id="intent-foreign"
    )
    bridge = RecordingServerBridge(foreign)
    result = dispatcher.dispatch(
        queen_id="queen-codex-master",
        workpackage=_workpackage(dispatch_id="dispatch-two"),
        intent=_intent(dispatch_id="dispatch-two"),
        grant=_grant(dispatch_id="dispatch-two"),
        selection=_selection(),
        dynamic_inventory=_inventory(),
        planner_input={**_planner_input(), "workpackage_id": "workpackage-one"},
        execution_bridge=bridge,
        pool_authority_reader=lambda: object(),
        now=NOW + timedelta(minutes=1),
    )

    assert result == {"allowed": False, "reason_code": "pool_execution_unavailable"}
    assert port.calls == []


@pytest.mark.parametrize(
    "tamper",
    (
        lambda record: replace(record, request_id="request-foreign"),
        lambda record: replace(record, workpackage_id="workpackage-foreign"),
        lambda record: replace(record, assignment_intent_id="intent-foreign"),
        lambda record: replace(record, repo_id="repo-foreign"),
        lambda record: replace(record, principal_id="specialist-foreign"),
        lambda record: replace(record, parent_principal_id="teamlead-foreign"),
        lambda record: replace(record, grant_id="grant-foreign"),
        lambda record: replace(record, grant_digest=REQUEST_DIGEST),
        lambda record: replace(record, work_item_version=8),
        lambda record: replace(record, scope=ScopeBinding("write", ("src/other.py",), DIGEST)),
        lambda record: replace(record, resource=replace(record.resource, agent_id="agent-two")),
        lambda record: replace(record, resource=replace(record.resource, model_id="gpt-secondary")),
        lambda record: replace(
            record,
            resource=replace(
                record.resource,
                account_pool_binding=AccountPoolBindingV1(
                    "account-two", "dynamic-pool", "openai", "openai_chatgpt"
                ),
            ),
        ),
    ),
)
def test_dispatcher_callback_requires_every_bound_admission_identity(
    tmp_path: Path, tamper: Callable[[AdmissionRecord], AdmissionRecord]
) -> None:
    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "state"))
    control.initialize_task9(now=NOW)
    port = RecordingPoolExecutionPort()
    dispatcher = HiveWorkDispatcher(control, execution_port=port)

    class TamperingBridge:
        def scope_digest(self, _repo_id: str, _mode: str, _paths: tuple[str, ...]) -> str:
            return DIGEST

        def base_admission_id(self) -> str:
            return "admission-one"

        def execute(
            self, *, hive_assignment_callback: object, **_kwargs: object
        ) -> Mapping[str, object]:
            assert callable(hive_assignment_callback)
            return hive_assignment_callback(
                tamper(_admission()),
                {"state": "held", "held_by_this_server": True, "lease_id": "lease-one"},
            )

    result = dispatcher.dispatch(
        queen_id="queen-codex-master",
        workpackage=_workpackage(),
        intent=_intent(),
        grant=_grant(),
        selection=_selection(),
        dynamic_inventory=_inventory(),
        planner_input=_planner_input(),
        execution_bridge=TamperingBridge(),
        pool_authority_reader=lambda: object(),
        now=NOW,
    )

    assert result == {"allowed": False, "reason_code": "pool_execution_unavailable"}
    assert port.calls == []


@pytest.mark.parametrize(
    "tamper",
    (
        lambda record: replace(record, state=AdmissionState.PLANNED),
        lambda record: replace(record, state=AdmissionState.ADMITTED),
        lambda record: replace(record, state=AdmissionState.FINALIZED),
        _without_admission_id,
        lambda record: replace(record, revision=3),
        lambda record: replace(
            record,
            created_at_utc=record.created_at_utc - timedelta(minutes=2),
            expires_at_utc=record.created_at_utc - timedelta(minutes=1),
        ),
    ),
)
def test_dispatcher_callback_requires_a_current_executing_admission(
    tmp_path: Path, tamper: Callable[[AdmissionRecord], AdmissionRecord]
) -> None:
    """Only a current, lifecycle-valid execution record can reach the port."""

    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "state"))
    control.initialize_task9(now=NOW)
    port = RecordingPoolExecutionPort()
    dispatcher = HiveWorkDispatcher(control, execution_port=port)

    class TamperingBridge:
        def scope_digest(self, _repo_id: str, _mode: str, _paths: tuple[str, ...]) -> str:
            return DIGEST

        def base_admission_id(self) -> str:
            return "admission-one"

        def execute(
            self, *, hive_assignment_callback: object, **_kwargs: object
        ) -> Mapping[str, object]:
            assert callable(hive_assignment_callback)
            return hive_assignment_callback(
                tamper(_admission()),
                {"state": "held", "held_by_this_server": True, "lease_id": "lease-one"},
            )

    result = dispatcher.dispatch(
        queen_id="queen-codex-master",
        workpackage=_workpackage(),
        intent=_intent(),
        grant=_grant(),
        selection=_selection(),
        dynamic_inventory=_inventory(),
        planner_input=_planner_input(),
        execution_bridge=TamperingBridge(),
        pool_authority_reader=lambda: object(),
        now=NOW,
    )

    assert result == {"allowed": False, "reason_code": "pool_execution_unavailable"}
    assert port.calls == []


def test_dispatcher_callback_rejects_a_mismatched_fresh_lease(tmp_path: Path) -> None:
    """The callback independently keeps the executing record's exact lease."""

    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "state"))
    control.initialize_task9(now=NOW)
    port = RecordingPoolExecutionPort()
    dispatcher = HiveWorkDispatcher(control, execution_port=port)

    class LeaseDriftBridge:
        def scope_digest(self, _repo_id: str, _mode: str, _paths: tuple[str, ...]) -> str:
            return DIGEST

        def base_admission_id(self) -> str:
            return "admission-one"

        def execute(
            self, *, hive_assignment_callback: object, **_kwargs: object
        ) -> Mapping[str, object]:
            assert callable(hive_assignment_callback)
            return hive_assignment_callback(
                _admission(),
                {"state": "held", "held_by_this_server": True, "lease_id": "lease-foreign"},
            )

    result = dispatcher.dispatch(
        queen_id="queen-codex-master",
        workpackage=_workpackage(),
        intent=_intent(),
        grant=_grant(),
        selection=_selection(),
        dynamic_inventory=_inventory(),
        planner_input=_planner_input(),
        execution_bridge=LeaseDriftBridge(),
        pool_authority_reader=lambda: object(),
        now=NOW,
    )

    assert result == {"allowed": False, "reason_code": "pool_execution_unavailable"}
    assert port.calls == []


def test_dispatcher_persists_exact_d69_binding_before_bridge_and_rehydrates_after_bridge_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = HiveControlPlaneStore(HiveStateStore(tmp_path / "state"))
    control.initialize_task9(now=NOW)
    port = RecordingPoolExecutionPort()
    dispatcher = HiveWorkDispatcher(control, execution_port=port)
    calls = 0
    original = dispatcher_module.plan_queen_assignment_from_selection

    class FailingBridge:
        def scope_digest(self, _repo_id: str, _mode: str, _paths: tuple[str, ...]) -> str:
            return DIGEST

        def base_admission_id(self) -> str:
            return "admission-one"

        def execute(self, **_kwargs: object) -> dict[str, object]:
            raise RuntimeError("bridge unavailable")

    def counted_planner(**kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(**kwargs)

    monkeypatch.setattr(dispatcher_module, "plan_queen_assignment_from_selection", counted_planner)

    with pytest.raises(RuntimeError, match="bridge unavailable"):
        dispatcher.dispatch(
            queen_id="queen-codex-master",
            workpackage=_workpackage(),
            intent=_intent(),
            grant=_grant(),
            selection=_selection(),
            dynamic_inventory=_inventory(),
            planner_input=_planner_input(),
            execution_bridge=FailingBridge(),
            pool_authority_reader=lambda: object(),
            now=NOW,
        )

    aggregate = HiveWorkDispatcher(control, execution_port=port).rehydrate("dispatch-one")
    assert calls == 1
    assert aggregate.state == "bound"
    assert aggregate.bound_account_pool_binding == AccountPoolBindingV1(
        "account-one", "dynamic-pool", "openai", "openai_chatgpt"
    )
    assert aggregate.bound_dynamic_pool_digest.startswith("sha256:")
    assert port.calls == []
    with pytest.raises(dispatcher_module.HiveWorkDispatcherError, match="duplicate_hive_work_dispatch"):
        dispatcher.dispatch(
            queen_id="queen-codex-master",
            workpackage=_workpackage(),
            intent=_intent(),
            grant=_grant(),
            selection=_selection(),
            dynamic_inventory=_inventory(),
            planner_input=_planner_input(),
            execution_bridge=FailingBridge(),
            pool_authority_reader=lambda: object(),
            now=NOW + timedelta(minutes=1),
        )
    assert calls == 1
