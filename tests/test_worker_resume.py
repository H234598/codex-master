import ast
import dataclasses
import importlib
import pickle
from pathlib import Path
from threading import Barrier, Lock, Thread

import pytest

from codex_master.spark_retry import ResumeCapsuleV1


MODULE_PATH = Path(__file__).resolve().parents[1] / "src/codex_master/worker_resume.py"


def _resume_module():
    return importlib.import_module("codex_master.worker_resume")


def _spawn_module():
    return importlib.import_module("codex_master.worker_spawn_ledger")


def _digest(value: str) -> str:
    return "sha256:" + (value * 64)


def _backend(spawn):
    class _SharedFakeBackend(spawn.SpawnLedgerStatePort):
        def __init__(self) -> None:
            self._lock = Lock()
            self._state = spawn.SpawnLedgerStateV2.empty()

        def read(self):
            with self._lock:
                return self._state

        def compare_and_swap(self, expected_revision, replacement) -> bool:
            with self._lock:
                if self._state.state_revision != expected_revision:
                    return False
                self._state = replacement
                return True

    return _SharedFakeBackend()


def _teamlead(spawn):
    return spawn.VerifiedPrincipalV2(
        principal_id="teamlead-2",
        role=spawn.PrincipalRole.TEAMLEADER,
        authority_digest=_digest("f"),
    )


def _requester(spawn):
    return spawn.VerifiedPrincipalV2(
        principal_id="worker-11",
        role=spawn.PrincipalRole.NON_LEADERSHIP,
        authority_digest=_digest("b"),
    )


def _ledger(spawn, backend=None):
    return spawn.WorkerSpawnLedger(
        state_port=backend or _backend(spawn),
        delegable_nonleadership_class_ids=frozenset({"worker.research"}),
    )


def _publish(spawn, ledger, *, request_id: str = "request-7"):
    return ledger.publish_requested(
        request_id=request_id,
        requester=_requester(spawn),
        work_package_id="work-package-8",
        topic_digest=_digest("c"),
        target_class_id="worker.research",
        authorized_teamlead=_teamlead(spawn),
        resolution_decision_digest=_digest("a"),
        resolution_generation=spawn.Generation(4),
        policy_digest=_digest("d"),
        policy_generation=spawn.Generation(9),
        lifecycle=spawn.WorkerLifecycle.PERSISTENT,
        resume_requirement=True,
        fence_epoch=spawn.FenceEpoch(6),
    )


def _append(spawn, ledger, ticket, phase, *, lease_evidence=None):
    return ledger.append_phase(
        ticket,
        phase,
        expected_revision=ticket.ledger_revision,
        expected_fence_epoch=ticket.fence_epoch,
        teamlead=_teamlead(spawn),
        lease_evidence=lease_evidence,
    )


def _capsule(resume, ticket, *, digest: str = "2", generation: int = 2):
    return resume.create_resume_capsule(
        capsule_digest=_digest(digest),
        capsule_generation=resume.CapsuleGeneration(generation),
        bee_digest=_digest("a"),
        session_digest=_digest("b"),
        topic_digest=ticket.topic_digest,
        policy_digest=ticket.policy_digest,
        account_binding_digest=ticket.account_binding_digest,
    )


def _checkpointed(*, backend=None):
    resume = _resume_module()
    spawn = _spawn_module()
    backend = backend or _backend(spawn)
    ledger = _ledger(spawn, backend)
    ticket = _publish(spawn, ledger)
    ticket = ledger.claim(
        ticket.request_id,
        teamlead=_teamlead(spawn),
        expected_revision=ticket.ledger_revision,
    )
    ticket = _append(spawn, ledger, ticket, spawn.SpawnPhase.OFFER_VALIDATED)
    lease = spawn.LeaseReservationEvidenceV2(
        lease_binding_digest=_digest("1"),
        account_binding_digest=_digest("e"),
    )
    ticket = _append(
        spawn,
        ledger,
        ticket,
        spawn.SpawnPhase.LEASE_RESERVED,
        lease_evidence=lease,
    )
    for phase in (
        spawn.SpawnPhase.PROJECTED,
        spawn.SpawnPhase.HOME_COMMITTED,
        spawn.SpawnPhase.REGISTRY_RESERVED,
        spawn.SpawnPhase.START_GRANTED,
        spawn.SpawnPhase.RUNNING,
        spawn.SpawnPhase.DRAINING,
    ):
        ticket = _append(spawn, ledger, ticket, phase)
    capsule = _capsule(resume, ticket)
    ticket = ledger.bind_resume_capsule(
        ticket,
        capsule,
        expected_revision=ticket.ledger_revision,
        expected_fence_epoch=ticket.fence_epoch,
        teamlead=_teamlead(spawn),
    )
    ticket = _append(spawn, ledger, ticket, spawn.SpawnPhase.CHECKPOINTED)
    return resume, spawn, backend, ledger, ticket, capsule, lease


def _begin(resume, spawn, ledger, ticket, capsule, *, request_id: str):
    return resume.begin_resume_request(
        ledger,
        source_ticket=ticket,
        capsule=capsule,
        new_request_id=request_id,
        new_fence_epoch=spawn.FenceEpoch(ticket.fence_epoch.value + 1),
        expected_revision=ticket.ledger_revision,
        expected_capsule_generation=capsule.capsule_generation,
        teamlead=_teamlead(spawn),
    )


def test_persistent_or_resumable_worker_requires_topic_resume_capsule() -> None:
    resume = _resume_module()
    capsule = resume.create_resume_capsule(
        capsule_digest=_digest("2"),
        capsule_generation=resume.CapsuleGeneration(2),
        bee_digest=_digest("a"),
        session_digest=_digest("b"),
        topic_digest=_digest("c"),
        policy_digest=_digest("d"),
        account_binding_digest=_digest("e"),
    )

    with pytest.raises(resume.ResumeDenied):
        resume.require_terminal_capsule(
            lifecycle=resume.WorkerLifecycle.PERSISTENT,
            resumable=False,
            capsule=None,
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
        )
    assert (
        resume.require_terminal_capsule(
            lifecycle=resume.WorkerLifecycle.PERSISTENT,
            resumable=False,
            capsule=capsule,
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
        )
        is capsule
    )


def test_binding_lifecycle_requires_capsule_even_when_not_marked_resumable() -> None:
    resume = _resume_module()

    with pytest.raises(resume.ResumeDenied):
        resume.require_terminal_capsule(
            lifecycle=resume.WorkerLifecycle.BINDING,
            resumable=False,
            capsule=None,
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
        )


def test_ephemeral_and_invocation_worker_can_finish_without_capsule() -> None:
    resume = _resume_module()

    for lifecycle in (
        resume.WorkerLifecycle.EPHEMERAL,
        resume.WorkerLifecycle.INVOCATION,
    ):
        assert (
            resume.require_terminal_capsule(
                lifecycle=lifecycle,
                resumable=False,
                capsule=None,
                topic_digest=_digest("c"),
                policy_digest=_digest("d"),
                account_binding_digest=_digest("e"),
            )
            is None
        )


def test_capsule_binds_every_terminal_digest_and_rejects_drift() -> None:
    resume = _resume_module()
    _, _, _, _, ticket, capsule, _ = _checkpointed()

    for key in ("topic_digest", "policy_digest", "account_binding_digest"):
        expected = {
            "topic_digest": ticket.topic_digest,
            "policy_digest": ticket.policy_digest,
            "account_binding_digest": ticket.account_binding_digest,
        }
        expected[key] = _digest("f")
        with pytest.raises(resume.ResumeDenied):
            resume.require_terminal_capsule(
                lifecycle=resume.WorkerLifecycle.PERSISTENT,
                resumable=True,
                capsule=capsule,
                **expected,
            )


def test_capsule_rejects_malformed_digest_and_prohibited_secret_fields() -> None:
    resume = _resume_module()

    with pytest.raises(resume.ResumeDenied):
        resume.create_resume_capsule(
            capsule_digest=_digest("2"),
            capsule_generation=resume.CapsuleGeneration(2),
            bee_digest="bee-plain-id",
            session_digest=_digest("b"),
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
        )
    with pytest.raises(resume.ResumeDenied):
        resume.CapsuleGeneration(True)
    with pytest.raises(TypeError):
        resume.create_resume_capsule(
            capsule_digest=_digest("2"),
            capsule_generation=resume.CapsuleGeneration(2),
            bee_digest=_digest("a"),
            session_digest=_digest("b"),
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
            profile_id="profile-private",
        )


def test_spark_resume_capsule_v1_is_not_silently_reused() -> None:
    resume = _resume_module()
    v1_capsule = ResumeCapsuleV1(
        bee_id="bee-1",
        session_id="session-1",
        spark_requirement="explicit_spark",
        model="gpt-5.3",
        provider="provider",
        effort="low",
        account_binding=_digest("e"),
    )

    with pytest.raises(resume.ResumeDenied):
        resume.require_terminal_capsule(
            lifecycle=resume.WorkerLifecycle.PERSISTENT,
            resumable=True,
            capsule=v1_capsule,
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
        )


def test_resume_starts_new_requested_transaction_and_requires_new_lease() -> None:
    resume, spawn, _, ledger, ticket, capsule, _ = _checkpointed()
    request = _begin(
        resume, spawn, ledger, ticket, capsule, request_id="request-after-resume"
    )
    new_ticket = ledger.read(request.request_id)

    assert request.phase is resume.ResumeRequestPhase.REQUESTED
    assert request.requested_revision == 1
    assert request.requires_new_lease is True
    assert request.allows_in_place_credential_rotation is False
    assert new_ticket.phase is spawn.SpawnPhase.REQUESTED
    assert new_ticket.ledger_revision == spawn.LedgerRevision(1)
    assert new_ticket.lease_binding_digest is None
    assert new_ticket.account_binding_digest is None


def test_resume_request_is_bound_to_capsule_digests() -> None:
    resume, spawn, _, ledger, ticket, capsule, _ = _checkpointed()
    request = _begin(resume, spawn, ledger, ticket, capsule, request_id="request-next")
    new_ticket = ledger.read(request.request_id)

    assert request.capsule_digest == capsule.capsule_digest
    assert request.capsule_generation == capsule.capsule_generation
    assert request.bee_digest == capsule.bee_digest
    assert request.session_digest == capsule.session_digest
    assert request.topic_digest == capsule.topic_digest
    assert request.policy_digest == capsule.policy_digest
    assert request.account_binding_digest == capsule.account_binding_digest
    assert new_ticket.source_resume_capsule_digest == capsule.capsule_digest
    assert new_ticket.source_resume_capsule_generation == capsule.capsule_generation
    assert new_ticket.topic_resume_binding == capsule.topic_digest
    assert new_ticket.source_resume_policy_digest == capsule.policy_digest
    assert (
        new_ticket.source_resume_account_binding_digest
        == capsule.account_binding_digest
    )
    assert new_ticket.account_binding_digest is None
    assert new_ticket.resume_capsule_digest is None
    with pytest.raises(spawn.SpawnDenied):
        dataclasses.replace(new_ticket, source_resume_account_binding_digest=None)


def test_resume_capsule_redacts_account_profile_and_paths() -> None:
    _, _, _, _, _, capsule, _ = _checkpointed()

    assert repr(capsule) == "<WorkerResumeCapsuleV2 redacted>"
    assert str(capsule) == repr(capsule)
    for prohibited in ("account", "profile", "/home", "credential", "prompt"):
        assert prohibited not in repr(capsule).lower()
    assert not {
        "account_id",
        "profile_id",
        "home_path",
        "credential",
        "prompt",
    } & set(capsule.__dataclass_fields__)


def test_resume_types_are_frozen_slotted_and_not_serializable() -> None:
    resume, spawn, _, ledger, ticket, capsule, _ = _checkpointed()
    request = _begin(resume, spawn, ledger, ticket, capsule, request_id="request-next")

    for value in (capsule, request):
        assert dataclasses.is_dataclass(value)
        assert hasattr(type(value), "__slots__")
        with pytest.raises(TypeError):
            pickle.dumps(value)
    with pytest.raises(dataclasses.FrozenInstanceError):
        capsule.topic_digest = _digest("f")


def test_resume_module_is_local_and_does_not_import_spark_or_runtime_boundaries() -> (
    None
):
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imports = {
        name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for name in ([node.module] if isinstance(node, ast.ImportFrom) else [])
        + [alias.name for alias in node.names]
        if name is not None
    }
    forbidden = {
        "spark_retry",
        "server",
        "runtime_account_allocator",
        "fleet_registry",
        "fleet_home",
        "broker",
        "mcp",
        "provider",
    }

    assert not {
        name
        for name in imports
        if any(fragment in name.lower() for fragment in forbidden)
    }


def test_h3_same_capsule_cannot_create_two_resume_requests() -> None:
    resume, spawn, _, ledger, ticket, capsule, _ = _checkpointed()
    first = _begin(resume, spawn, ledger, ticket, capsule, request_id="resume-first")

    assert first.phase is resume.ResumeRequestPhase.REQUESTED
    with pytest.raises(resume.ResumeDenied):
        _begin(resume, spawn, ledger, ticket, capsule, request_id="resume-replay")


def test_h3_parallel_capsule_claim_across_ledgers_has_one_winner() -> None:
    resume, spawn, backend, ledger, ticket, capsule, _ = _checkpointed()
    ledgers = [ledger, _ledger(spawn, backend)]
    gate = Barrier(3)
    outcomes: list[str] = []

    def resume_once(index: int) -> None:
        gate.wait()
        try:
            _begin(
                resume,
                spawn,
                ledgers[index],
                ticket,
                capsule,
                request_id=f"resume-race-{index}",
            )
        except resume.ResumeDenied:
            outcomes.append("denied")
        else:
            outcomes.append("requested")

    workers = [Thread(target=resume_once, args=(index,)) for index in range(2)]
    for worker in workers:
        worker.start()
    gate.wait()
    for worker in workers:
        worker.join()

    assert outcomes.count("requested") == 1
    assert outcomes.count("denied") == 1


def test_resume_rejects_capsule_generation_fence_and_phase_drift() -> None:
    resume, spawn, _, ledger, ticket, capsule, _ = _checkpointed()

    with pytest.raises(resume.ResumeDenied):
        resume.begin_resume_request(
            ledger,
            source_ticket=ticket,
            capsule=capsule,
            new_request_id="resume-bool-generation",
            new_fence_epoch=spawn.FenceEpoch(ticket.fence_epoch.value + 1),
            expected_revision=ticket.ledger_revision,
            expected_capsule_generation=True,
            teamlead=_teamlead(spawn),
        )
    with pytest.raises(resume.ResumeDenied):
        resume.begin_resume_request(
            ledger,
            source_ticket=ticket,
            capsule=capsule,
            new_request_id="resume-bool-fence",
            new_fence_epoch=True,
            expected_revision=ticket.ledger_revision,
            expected_capsule_generation=capsule.capsule_generation,
            teamlead=_teamlead(spawn),
        )

    stopped = _append(spawn, ledger, ticket, spawn.SpawnPhase.STOPPED)
    with pytest.raises(resume.ResumeDenied):
        _begin(resume, spawn, ledger, stopped, capsule, request_id="resume-stopped")


def test_resume_cannot_reuse_old_lease_binding() -> None:
    resume, spawn, _, ledger, ticket, capsule, old_lease = _checkpointed()
    request = _begin(
        resume, spawn, ledger, ticket, capsule, request_id="resume-new-lease"
    )
    new_ticket = ledger.read(request.request_id)
    new_ticket = ledger.claim(
        new_ticket.request_id,
        teamlead=_teamlead(spawn),
        expected_revision=new_ticket.ledger_revision,
    )
    new_ticket = _append(spawn, ledger, new_ticket, spawn.SpawnPhase.OFFER_VALIDATED)

    with pytest.raises(spawn.SpawnDenied):
        _append(
            spawn,
            ledger,
            new_ticket,
            spawn.SpawnPhase.LEASE_RESERVED,
            lease_evidence=old_lease,
        )

    new_lease = spawn.LeaseReservationEvidenceV2(
        lease_binding_digest=_digest("3"),
        account_binding_digest=_digest("e"),
    )
    reserved = _append(
        spawn,
        ledger,
        new_ticket,
        spawn.SpawnPhase.LEASE_RESERVED,
        lease_evidence=new_lease,
    )
    assert reserved.lease_binding_digest == new_lease.lease_binding_digest
