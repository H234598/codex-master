from __future__ import annotations

import dataclasses
from hashlib import sha256

import pytest

from codex_master.fleet_home_broker import OfflineBrokerPlan
from codex_master.fleet_home_broker_consumer import BrokerIntentResumeContext
from codex_master.fleet_home_broker_dispatch import BrokerDispatchCommand
from codex_master.fleet_home_broker_execution import RootBrokerExecutionComposition
from codex_master.fleet_home_broker_identity import (
    BrokerIdentity,
    ImportClosure,
    ImportClosureEntry,
)
from codex_master.fleet_home_broker_intent import (
    BrokerIntentOperation,
    BrokerIntentV1,
    canonical_intent_payload,
)
from codex_master.fleet_home_broker_linux import FdStat, PidfdIdentity
from codex_master.fleet_home_broker_protocol import (
    BindingExpectation,
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRegistryState,
    BrokerResultCode,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    ChpbTransactionOperation,
    PolicyBinding,
    PrincipalBinding,
    ReplaceHomeRequest,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
)
from codex_master.fleet_home_broker_wal import append_status, decode_wal_record


PEER_PID = 1234
AGENT = "bee_1"
MANIFEST = 3
UNIT = 9
INVOCATION = "1" * 32
PROJECTION = "a" * 64
STORE = "3" * 32
TRANSACTION = "2" * 32
REQUEST_ID = "4" * 32
CONTROL_GROUP = "/user.slice/broker.scope"


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _closure() -> ImportClosure:
    return ImportClosure(
        (ImportClosureEntry("codex_master/fleet_home_broker.py", _digest("broker")),)
    )


def _principal(**changes: object) -> PrincipalBinding:
    values: dict[str, object] = {
        "agent_id": AGENT,
        "manifest_generation": MANIFEST,
        "unit_generation": UNIT,
        "cgroup_dev": 0,
        "cgroup_ino": 1,
        "invocation_id": INVOCATION,
        "mcs_pair": "c0,c1",
        "fencing_epoch": 4,
    }
    values.update(changes)
    return PrincipalBinding(**values)


def _plan(**changes: object) -> OfflineBrokerPlan:
    principal = _principal()
    closure = _closure()
    values: dict[str, object] = {
        "identity": BrokerIdentity(
            AGENT,
            MANIFEST,
            "c0,c1",
            "slot-1",
            7,
            PROJECTION,
            closure.digest(),
            4,
        ),
        "import_closure": closure,
        "expected_principal": principal,
        "operation": ChpbTransactionOperation.REPLACE,
        "store_uuid": STORE,
        "population_total": 1,
    }
    values.update(changes)
    return OfflineBrokerPlan(**values)


def _intent(
    plan: OfflineBrokerPlan, transaction_id: str = TRANSACTION
) -> BrokerIntentV1:
    unsigned = BrokerIntentV1(
        schema_version=1,
        intent_generation=7,
        operation=BrokerIntentOperation.REPLACE,
        transaction_id=transaction_id,
        request_id=REQUEST_ID,
        agent_id=plan.identity.agent_id,
        manifest_generation=plan.identity.manifest_generation,
        unit_generation=plan.expected_principal.unit_generation,
        policy_generation=plan.identity.policy_generation,
        fencing_epoch=plan.identity.fencing_epoch,
        store_uuid=plan.store_uuid,
        slot_id=plan.identity.slot_snapshot,
        mcs_pair=plan.identity.mcs_pair,
        projection_digest=plan.identity.projection_digest,
        joint_release_id="release-0.11.0",
        server_digest="b" * 64,
        broker_manifest_digest="c" * 64,
        credential_binding_ref="cred-bind-01",
        credential_generation=2,
        created_at_unix_ms=1_700_000_000_000,
        expires_at_unix_ms=1_700_000_030_000,
        nonce="d" * 32,
        digest="0" * 64,
    )
    return dataclasses.replace(
        unsigned, digest=sha256(canonical_intent_payload(unsigned)).hexdigest()
    )


def _initial() -> BrokerObservation:
    return BrokerObservation(
        BrokerObjectState.REPLACEMENT_ORIGINAL,
        BrokerRegistryState.NOT_APPLICABLE,
        0,
    )


class FakeLinux:
    def __init__(self, principal: PrincipalBinding) -> None:
        self.principal = principal
        self.identity = PidfdIdentity(PEER_PID, 7)

    def pidfd_open(self, pid: int, flags: int) -> int:
        return 11

    def pidfd_reuse_check(self, *args: object) -> PidfdIdentity:
        return self.identity

    def open_pinned_proc_pid(self, *args: object) -> int:
        return 12

    def open_proc_cgroup(self, *args: object) -> int:
        return 13

    def fstat(self, fd: int) -> FdStat:
        if fd == 13:
            return FdStat(0, 1, 0o40755, 0, 0)
        return FdStat(0, 1, 0o40700, 0, 0)

    def read_proc_control_group(self, *args: object) -> str:
        return CONTROL_GROUP

    def read_pid1_unit_name(self, *args: object) -> str:
        return "broker.scope"

    def read_pid1_unit_generation(self, *args: object) -> int:
        return self.principal.unit_generation

    def read_pid1_invocation_id(self, *args: object) -> str:
        return self.principal.invocation_id

    def read_pid1_control_group(self, *args: object) -> str:
        return CONTROL_GROUP

    def read_peer_mcs_pair(self, *args: object) -> str:
        return self.principal.mcs_pair

    def close(self, fd: int) -> None:
        return None


class FakeWal:
    def __init__(self) -> None:
        self.records: list[bytes] = []
        self.fail_before_append: int | None = None
        self.fail_after_fsync: int | None = None
        self.fail_after_parent_fsync: int | None = None
        self.append_count = 0
        self.fsync_count = 0
        self.parent_fsync_count = 0
        self.error_text: str | None = None

    def read_all(self) -> tuple[bytes, ...]:
        return tuple(self.records)

    def append(self, record: bytes) -> None:
        self.append_count += 1
        if self.append_count == self.fail_before_append:
            self.fail_before_append = None
            raise RuntimeError(self.error_text or "redacted-cutpoint")
        self.records.append(record)

    def fsync_wal(self) -> None:
        self.fsync_count += 1
        if self.fsync_count == self.fail_after_fsync:
            self.fail_after_fsync = None
            raise RuntimeError(self.error_text or "redacted-cutpoint")

    def fsync_parent(self) -> None:
        self.parent_fsync_count += 1
        if self.parent_fsync_count == self.fail_after_parent_fsync:
            self.fail_after_parent_fsync = None
            raise RuntimeError(self.error_text or "redacted-cutpoint")


class FakeReplaceOperations:
    def __init__(self, plan: OfflineBrokerPlan) -> None:
        self.plan = plan
        self.object_state = BrokerObjectState.REPLACEMENT_ORIGINAL
        self.registry_state = BrokerRegistryState.NOT_APPLICABLE
        self.prepare_needs_checkpoint = False
        self.switch_needs_checkpoint = False
        self.effects: list[str] = []
        self.generated_ids: list[str] = []
        self.closed: list[int] = []
        self.old_quarantined = False
        self.restore_attempts = 0
        self.delete_attempts = 0
        self.fail_effect: str | None = None
        self.switch_race = False
        self.unknown_post_switch = False
        self.initial_override: BrokerObservation | None = None
        self.error_text: str | None = None

    def new_transaction_id(self) -> str:
        self.generated_ids.append("f" * 32)
        return "f" * 32

    def observe(self, plan: OfflineBrokerPlan) -> BrokerObservation:
        assert plan is self.plan
        if not self.effects and self.initial_override is not None:
            return self.initial_override
        if self.unknown_post_switch and self.old_quarantined:
            return BrokerObservation(
                BrokerObjectState.DRIFT, BrokerRegistryState.FOREIGN, 0
            )
        if self.prepare_needs_checkpoint:
            self.prepare_needs_checkpoint = False
            return BrokerObservation(
                BrokerObjectState.REPLACEMENT_ORIGINAL,
                BrokerRegistryState.NOT_APPLICABLE,
                0,
            )
        if self.switch_needs_checkpoint:
            self.switch_needs_checkpoint = False
            return BrokerObservation(
                BrokerObjectState.REPLACEMENT_SWITCHED,
                BrokerRegistryState.NOT_APPLICABLE,
                0,
            )
        return BrokerObservation(self.object_state, self.registry_state, 0)

    def _effect(self, name: str) -> None:
        self.effects.append(name)
        if self.fail_effect == name:
            self.fail_effect = None
            raise RuntimeError(self.error_text or "redacted-effect-error")

    def create_staging(self, plan: OfflineBrokerPlan) -> None:
        raise AssertionError("replace must not provision")

    def populate_next(self, plan: OfflineBrokerPlan) -> None:
        raise AssertionError("replace must not populate")

    def publish_home(self, plan: OfflineBrokerPlan) -> None:
        raise AssertionError("replace must not publish")

    def prepare_replacement(self, plan: OfflineBrokerPlan) -> None:
        self._effect("prepare_replacement")
        self.object_state = BrokerObjectState.REPLACEMENT_PREPARED

    def switch_replacement(
        self, plan: OfflineBrokerPlan, binding: TransactionBinding
    ) -> None:
        self._effect("switch_replacement")
        self.object_state = BrokerObjectState.REPLACEMENT_SWITCHED
        self.registry_state = BrokerRegistryState.OLD
        self.old_quarantined = True
        self.switch_needs_checkpoint = True
        if self.switch_race:
            raise RuntimeError(self.error_text or "redacted-switch-race")

    def cas_registry(
        self, plan: OfflineBrokerPlan, binding: TransactionBinding
    ) -> None:
        self._effect("cas_registry")
        self.registry_state = BrokerRegistryState.CURRENT

    def close(self, fd: int) -> None:
        self.closed.append(fd)


def _composition(
    plan: OfflineBrokerPlan, operations: FakeReplaceOperations, wal: FakeWal
) -> RootBrokerExecutionComposition:
    return RootBrokerExecutionComposition(
        operations, FakeLinux(plan.expected_principal), wal, peer_pid=PEER_PID
    )


def _context(intent: BrokerIntentV1) -> BrokerIntentResumeContext:
    return BrokerIntentResumeContext(intent.transaction_id, _initial())


def test_replace_intent_runs_one_bound_atomic_quarantine_transaction() -> None:
    plan = _plan()
    operations = FakeReplaceOperations(plan)
    wal = FakeWal()

    response = _composition(plan, operations, wal).execute_intent(_intent(plan), plan)

    assert response.reply.result is BrokerResultCode.COMMITTED
    assert response.reply.transaction is not None
    assert response.reply.transaction.binding.transaction_id == TRANSACTION
    assert operations.generated_ids == []
    assert operations.effects == [
        "prepare_replacement",
        "switch_replacement",
        "cas_registry",
    ]
    assert operations.old_quarantined
    assert [decode_wal_record(record).status.checkpoint for record in wal.records] == [
        BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
        BrokerCheckpoint.REPLACEMENT_PREPARED,
        BrokerCheckpoint.SWITCH_INTENT,
        BrokerCheckpoint.SWITCHED,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        BrokerCheckpoint.FINALIZE_INTENT,
        BrokerCheckpoint.COMMITTED,
    ]


def test_direct_replace_dispatch_command_returns_bound_terminal_reply() -> None:
    plan = _plan()
    intent = _intent(plan)
    request = ReplaceHomeRequest(
        CHPB_PROTOCOL,
        ChpbMessageKind.REPLACE_HOME,
        intent.request_id,
        intent.transaction_id,
        BindingExpectation(AGENT, MANIFEST, UNIT, 7, PROJECTION, 4),
        TransactionBinding(
            plan.operation,
            intent.transaction_id,
            plan.store_uuid,
            plan.expected_principal,
            PolicyBinding(7, PROJECTION),
        ),
    )

    response = _composition(plan, FakeReplaceOperations(plan), FakeWal()).execute(
        BrokerDispatchCommand(plan.expected_principal, request, "b" * 64, plan)
    )

    assert response.reply.result is BrokerResultCode.COMMITTED
    assert response.reply.transaction is not None
    assert response.reply.transaction.binding == request.binding


def test_first_replace_wal_failure_uses_replace_initial_observation_and_same_tx() -> (
    None
):
    plan = _plan()
    intent = _intent(plan)
    operations = FakeReplaceOperations(plan)
    wal = FakeWal()
    wal.fail_before_append = 1

    first = _composition(plan, operations, wal).execute_intent(intent, plan)
    fresh = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert first.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert first.reply.transaction is not None
    assert first.reply.transaction.observation == _initial()
    assert fresh.reply.result is BrokerResultCode.COMMITTED
    assert fresh.reply.transaction is not None
    assert fresh.reply.transaction.binding.transaction_id == intent.transaction_id
    assert operations.generated_ids == []


@pytest.mark.parametrize(
    "failure_field",
    ("fail_before_append", "fail_after_fsync", "fail_after_parent_fsync"),
)
@pytest.mark.parametrize("ordinal", range(1, 8))
def test_every_replace_wal_cutpoint_resumes_same_transaction_or_blocks(
    failure_field: str, ordinal: int
) -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeReplaceOperations(plan)
    wal = FakeWal()
    setattr(wal, failure_field, ordinal)

    first = _composition(plan, operations, wal).execute_intent(intent, plan)
    fresh = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert first.reply.result in {
        BrokerResultCode.COMMITTED,
        BrokerResultCode.BLOCKED_DRIFT,
    }
    assert fresh.reply.result in {
        BrokerResultCode.COMMITTED,
        BrokerResultCode.BLOCKED_DRIFT,
    }
    assert operations.generated_ids == []
    assert operations.effects.count("prepare_replacement") <= 1
    assert operations.effects.count("switch_replacement") <= 1
    assert operations.effects.count("cas_registry") <= 1
    if failure_field == "fail_after_parent_fsync":
        assert wal.parent_fsync_count >= ordinal
    assert first.reply.transaction is not None
    assert fresh.reply.transaction is not None
    assert first.reply.transaction.binding.transaction_id == intent.transaction_id
    assert fresh.reply.transaction.binding.transaction_id == intent.transaction_id


def test_replace_cas_failure_and_failed_blocked_record_never_retries_cas() -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeReplaceOperations(plan)
    operations.fail_effect = "cas_registry"
    wal = FakeWal()
    wal.fail_before_append = 6

    first = _composition(plan, operations, wal).execute_intent(intent, plan)
    second = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert first.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert second.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects.count("cas_registry") == 1
    assert second.reply.transaction is not None
    assert second.reply.transaction.binding.transaction_id == intent.transaction_id


def test_replace_current_registry_evidence_resumes_finalization_without_cas() -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeReplaceOperations(plan)
    operations.object_state = BrokerObjectState.REPLACEMENT_SWITCHED
    operations.registry_state = BrokerRegistryState.CURRENT
    operations.old_quarantined = True
    wal = FakeWal()
    binding = TransactionBinding(
        plan.operation,
        intent.transaction_id,
        plan.store_uuid,
        plan.expected_principal,
        PolicyBinding(7, PROJECTION),
    )
    statuses = (
        TransactionStatus(
            binding,
            b2a_phase_for_checkpoint(BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT),
            BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
            _initial(),
            1,
            None,
        ),
        TransactionStatus(
            binding,
            b2a_phase_for_checkpoint(BrokerCheckpoint.REPLACEMENT_PREPARED),
            BrokerCheckpoint.REPLACEMENT_PREPARED,
            BrokerObservation(
                BrokerObjectState.REPLACEMENT_PREPARED,
                BrokerRegistryState.NOT_APPLICABLE,
                0,
            ),
            1,
            None,
        ),
        TransactionStatus(
            binding,
            b2a_phase_for_checkpoint(BrokerCheckpoint.SWITCH_INTENT),
            BrokerCheckpoint.SWITCH_INTENT,
            BrokerObservation(
                BrokerObjectState.REPLACEMENT_PREPARED,
                BrokerRegistryState.NOT_APPLICABLE,
                0,
            ),
            1,
            None,
        ),
        TransactionStatus(
            binding,
            b2a_phase_for_checkpoint(BrokerCheckpoint.SWITCHED),
            BrokerCheckpoint.SWITCHED,
            BrokerObservation(
                BrokerObjectState.REPLACEMENT_SWITCHED,
                BrokerRegistryState.NOT_APPLICABLE,
                0,
            ),
            1,
            None,
        ),
        TransactionStatus(
            binding,
            b2a_phase_for_checkpoint(BrokerCheckpoint.REGISTRY_CAS_INTENT),
            BrokerCheckpoint.REGISTRY_CAS_INTENT,
            BrokerObservation(
                BrokerObjectState.REPLACEMENT_SWITCHED,
                BrokerRegistryState.OLD,
                0,
            ),
            1,
            None,
        ),
    )
    for status in statuses:
        append_status(wal, status)

    response = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert response.reply.result is BrokerResultCode.COMMITTED
    assert operations.effects.count("cas_registry") == 0


def test_switch_race_keeps_old_object_quarantined_without_restore_or_delete() -> None:
    plan = _plan()
    operations = FakeReplaceOperations(plan)
    operations.switch_race = True
    response = _composition(plan, operations, FakeWal()).execute_intent(
        _intent(plan), plan
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects.count("switch_replacement") == 1
    assert operations.old_quarantined
    assert operations.restore_attempts == 0
    assert operations.delete_attempts == 0


def test_unknown_post_switch_is_blocked_with_quarantine_retained() -> None:
    plan = _plan()
    operations = FakeReplaceOperations(plan)
    operations.unknown_post_switch = True
    response = _composition(plan, operations, FakeWal()).execute_intent(
        _intent(plan), plan
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.old_quarantined
    assert operations.restore_attempts == 0
    assert operations.delete_attempts == 0
    assert operations.effects.count("cas_registry") == 0


@pytest.mark.parametrize(
    "plan_change",
    (
        lambda plan: dataclasses.replace(
            plan,
            expected_principal=dataclasses.replace(
                plan.expected_principal, fencing_epoch=5
            ),
        ),
        lambda plan: dataclasses.replace(
            plan,
            expected_principal=dataclasses.replace(
                plan.expected_principal, mcs_pair="c1,c2"
            ),
        ),
    ),
)
def test_replace_fence_or_mcs_plan_drift_blocks_before_effect(plan_change) -> None:
    plan = _plan()
    operations = FakeReplaceOperations(plan)
    response = _composition(plan, operations, FakeWal()).execute_intent(
        _intent(plan), plan_change(plan)
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects == []


@pytest.mark.parametrize(
    "intent_change",
    (
        lambda intent: dataclasses.replace(intent, fencing_epoch=5),
        lambda intent: dataclasses.replace(intent, mcs_pair="c1,c2"),
    ),
)
def test_replace_fence_or_mcs_intent_drift_blocks_before_effect(intent_change) -> None:
    plan = _plan()
    operations = FakeReplaceOperations(plan)
    response = _composition(plan, operations, FakeWal()).execute_intent(
        intent_change(_intent(plan)), plan
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects == []


def test_replace_foreign_initial_object_fails_closed_before_effect() -> None:
    plan = _plan()
    foreign = FakeReplaceOperations(plan)
    foreign.initial_override = BrokerObservation(
        BrokerObjectState.DRIFT, BrokerRegistryState.FOREIGN, 0
    )
    response = _composition(plan, foreign, FakeWal()).execute_intent(
        _intent(plan), plan
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert foreign.effects == []


def test_replace_rollback_boundary_fails_closed_without_cleanup_effect() -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeReplaceOperations(plan)
    wal = FakeWal()
    binding = TransactionBinding(
        plan.operation,
        intent.transaction_id,
        plan.store_uuid,
        plan.expected_principal,
        PolicyBinding(7, PROJECTION),
    )
    statuses = (
        TransactionStatus(
            binding,
            b2a_phase_for_checkpoint(BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT),
            BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
            _initial(),
            1,
            None,
        ),
        TransactionStatus(
            binding,
            b2a_phase_for_checkpoint(BrokerCheckpoint.REPLACEMENT_PREPARED),
            BrokerCheckpoint.REPLACEMENT_PREPARED,
            BrokerObservation(
                BrokerObjectState.REPLACEMENT_PREPARED,
                BrokerRegistryState.NOT_APPLICABLE,
                0,
            ),
            1,
            None,
        ),
        TransactionStatus(
            binding,
            b2a_phase_for_checkpoint(BrokerCheckpoint.SWITCH_INTENT),
            BrokerCheckpoint.SWITCH_INTENT,
            BrokerObservation(
                BrokerObjectState.REPLACEMENT_PREPARED,
                BrokerRegistryState.NOT_APPLICABLE,
                0,
            ),
            1,
            None,
        ),
        TransactionStatus(
            binding,
            b2a_phase_for_checkpoint(BrokerCheckpoint.ROLLBACK_INTENT),
            BrokerCheckpoint.ROLLBACK_INTENT,
            BrokerObservation(
                BrokerObjectState.ROLLBACK_READY,
                BrokerRegistryState.NOT_APPLICABLE,
                0,
            ),
            1,
            None,
        ),
    )
    for status in statuses:
        append_status(wal, status)
    operations.object_state = BrokerObjectState.ROLLBACK_READY

    response = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects == []
    assert operations.restore_attempts == 0
    assert operations.delete_attempts == 0


def test_replace_resume_rejects_provision_initial_context() -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeReplaceOperations(plan)

    response = _composition(plan, operations, FakeWal()).resume_intent(
        intent,
        plan,
        BrokerIntentResumeContext(
            intent.transaction_id,
            BrokerObservation(
                BrokerObjectState.ABSENT,
                BrokerRegistryState.NOT_APPLICABLE,
                0,
            ),
        ),
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects == []


def test_replace_failures_redact_injected_values_and_close_per_valid_call() -> None:
    plan = _plan()
    operations = FakeReplaceOperations(plan)
    operations.fail_effect = "prepare_replacement"
    operations.error_text = "/root/private/credential=manifest-secret"
    composition = _composition(plan, operations, FakeWal())

    response = composition.execute_intent(_intent(plan), plan)
    for fd in (4, 4, -1, True):
        composition.close(fd)

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert "/root/private" not in repr(response)
    assert "manifest-secret" not in str(response.reply)
    assert operations.closed == [4, 4]
