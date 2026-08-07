from datetime import datetime, timezone

import pytest

from codex_master.admission import (
    AdmissionState,
    AdmissionStore,
    AdmissionPriority,
    LeaseBinding,
    ResourceBinding,
    ScopeBinding,
    create_admission,
)
from codex_master.selection import ModelRole, SelectionCandidate, SelectionPolicy, TaskKind
from codex_master.selection import AdmissionMode, AdmissionPolicy
from codex_master.selection_service import (
    RetryableSelectionError,
    SelectionDeniedError,
    SelectionRequest,
    SelectionService,
    SelectionServiceError,
)


NOW = datetime.now(timezone.utc)


def candidate(agent: str = "a1") -> SelectionCandidate:
    return SelectionCandidate(
        agent_id=agent,
        account_key=f"account-{agent}",
        model_id="gpt-primary",
        task_kind=TaskKind.SIMPLE,
        model_role=ModelRole.PRIMARY,
    )


def plan(name: str = "one"):
    return create_admission(
        admission_id=f"adm-{name}",
        request_id=f"req-{name}",
        dispatch_id=f"dsp-{name}",
        workpackage_id=f"wp-{name}",
        assignment_intent_id=f"intent-{name}",
        repo_id="codex-master",
        principal_id="specialist-1",
        parent_principal_id="teamlead-1",
        grant_id=f"grant-{name}",
        grant_digest="sha256:grant",
        work_item_version=1,
        scope=ScopeBinding("write", ("src",), "sha256:scope"),
        resource=ResourceBinding(f"agent-{name}", f"account-{name}", "standard", "gpt-primary", 1),
        lease_context=LeaseBinding("available"),
        priority=AdmissionPriority("DP1", "selection"),
        now=NOW,
    )


class Runtime:
    def __init__(self, *, revalidations=None, failures=0, completed=False):
        self.revalidations = list(revalidations or [True, True, True])
        self.failures = failures
        self.completed = completed
        self.events = []

    def revalidate(self, admission):
        self.events.append(("revalidate", admission.admission_id))
        return self.revalidations.pop(0)

    def execute(self, admission, operation):
        self.events.append(("execute", admission.admission_id, operation))
        if self.failures:
            self.failures -= 1
            raise RetryableSelectionError("transient runtime race")
        return {"status": "ok"}

    def execution_completed(self, admission):
        return self.completed


def test_preview_uses_the_same_non_mutating_selection_core() -> None:
    service = SelectionService(AdmissionStore(), Runtime())
    preview = service.preview(SelectionRequest((candidate(),), SelectionPolicy(sp3=True), NOW))
    assert preview.selected is not None
    assert preview.selected.agent_id == "a1"


def test_admission_preview_shares_planner_without_touching_store() -> None:
    store = AdmissionStore()
    service = SelectionService(store)
    preview = service.admission_preview(
        SelectionRequest((candidate(),), SelectionPolicy(sp3=True), NOW),
        AdmissionPolicy(mode=AdmissionMode.SHADOW),
    )
    assert preview.planned is True
    assert preview.executable is False
    assert store.records_snapshot() == ()


def test_execution_revalidates_before_runtime_and_retries_with_fixed_backoff() -> None:
    runtime = Runtime(failures=2)
    sleeps = []
    service = SelectionService(AdmissionStore(), runtime, sleeper=sleeps.append)
    names = iter(("one", "two", "three"))
    result = service.execute_with_retry(lambda: plan(next(names)), "assign")

    assert result["attempt"] == 3
    assert sleeps == [0.05, 0.1]
    assert [event[0] for event in runtime.events] == [
        "revalidate", "execute", "revalidate", "execute", "revalidate", "execute"
    ]
    assert result["admission"]["state"] == AdmissionState.FINALIZED.value


def test_denial_never_executes_and_failure_compensates() -> None:
    runtime = Runtime(revalidations=[False])
    service = SelectionService(AdmissionStore(), runtime)

    with pytest.raises(SelectionDeniedError):
        service.execute_with_retry(lambda: plan(), "assign")
    assert [event[0] for event in runtime.events] == ["revalidate"]

    runtime = Runtime(failures=10)
    store = AdmissionStore()
    service = SelectionService(store, runtime, sleeper=lambda _: None)
    with pytest.raises(SelectionServiceError):
        service.execute_with_retry(lambda: plan("failure"), "assign")


def test_reconcile_recovers_completed_execution_without_second_runtime_call() -> None:
    store = AdmissionStore()
    reserved = store.reserve(plan("recover"), now=NOW)
    revalidating = store.begin_revalidation(reserved.admission_id, expected_revision=1, now=NOW)
    admitted = store.complete_revalidation(
        reserved.admission_id, expected_revision=revalidating.revision, valid=True, now=NOW
    )
    executing = store.begin_execution(admitted.admission_id, expected_revision=admitted.revision, now=NOW)
    runtime = Runtime(completed=True)
    service = SelectionService(store, runtime)

    result = service.reconcile_incomplete()
    assert result == {"recovered": 1, "compensated": 0, "unresolved": 0, "raw_output": "not_returned"}
    assert store.get(executing.admission_id).state is AdmissionState.FINALIZED
