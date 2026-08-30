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
    BrokerRecoveryAction,
    BrokerRegistryState,
    BrokerResultCode,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    ChpbTransactionOperation,
    DeprovisionHomeRequest,
    PolicyBinding,
    PrincipalBinding,
    TransactionBinding,
)
from codex_master.fleet_home_broker_wal import decode_wal_record


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
            AGENT, MANIFEST, "c0,c1", "slot-1", 7, PROJECTION, closure.digest(), 4
        ),
        "import_closure": closure,
        "expected_principal": principal,
        "operation": ChpbTransactionOperation.DEPROVISION,
        "store_uuid": STORE,
        "population_total": 1,
    }
    values.update(changes)
    return OfflineBrokerPlan(**values)


def _intent(plan: OfflineBrokerPlan) -> BrokerIntentV1:
    unsigned = BrokerIntentV1(
        schema_version=1,
        intent_generation=7,
        operation=BrokerIntentOperation.DEPROVISION,
        transaction_id=TRANSACTION,
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
        BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 0
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
        return FdStat(0, 1, 0o40755 if fd == 13 else 0o40700, 0, 0)

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
            raise RuntimeError(self.error_text or "cutpoint")
        self.records.append(record)

    def fsync_wal(self) -> None:
        self.fsync_count += 1
        if self.fsync_count == self.fail_after_fsync:
            self.fail_after_fsync = None
            raise RuntimeError(self.error_text or "cutpoint")

    def fsync_parent(self) -> None:
        self.parent_fsync_count += 1
        if self.parent_fsync_count == self.fail_after_parent_fsync:
            self.fail_after_parent_fsync = None
            raise RuntimeError(self.error_text or "cutpoint")


class FakeDeprovisionOperations:
    def __init__(self, plan: OfflineBrokerPlan) -> None:
        self.plan = plan
        self.object_state = BrokerObjectState.FINAL_COMPLETE
        self.registry_state = BrokerRegistryState.CURRENT
        self.effects: list[str] = []
        self.generated_ids: list[str] = []
        self.closed: list[int] = []
        self.gate_error: str | None = None
        self.gate_fail_on_call: int | None = None
        self.gate_calls = 0
        self.fail_effect: str | None = None
        self.error_text: str | None = None
        self.initial_override: BrokerObservation | None = None

    def new_transaction_id(self) -> str:
        self.generated_ids.append("f" * 32)
        return "f" * 32

    def observe(self, plan: OfflineBrokerPlan) -> BrokerObservation:
        assert plan is self.plan
        if not self.effects and self.initial_override is not None:
            return self.initial_override
        return BrokerObservation(self.object_state, self.registry_state, 0)

    def create_staging(self, plan: OfflineBrokerPlan) -> None:
        raise AssertionError("deprovision must not provision")

    def populate_next(self, plan: OfflineBrokerPlan) -> None:
        raise AssertionError("deprovision must not populate")

    def publish_home(self, plan: OfflineBrokerPlan) -> None:
        raise AssertionError("deprovision must not publish")

    def prepare_replacement(self, plan: OfflineBrokerPlan) -> None:
        raise AssertionError("deprovision must not replace")

    def switch_replacement(
        self, plan: OfflineBrokerPlan, binding: TransactionBinding
    ) -> None:
        raise AssertionError("deprovision must not replace")

    def attest_deprovision_effect(
        self,
        plan: OfflineBrokerPlan,
        binding: TransactionBinding,
        action: BrokerRecoveryAction,
    ) -> None:
        self.effects.append("attest")
        self.gate_calls += 1
        if self.gate_error is not None and (
            self.gate_fail_on_call is None or self.gate_fail_on_call == self.gate_calls
        ):
            raise RuntimeError(self.error_text or self.gate_error)

    def cas_registry(
        self, plan: OfflineBrokerPlan, binding: TransactionBinding
    ) -> None:
        self.effects.append("cas_registry")
        if self.fail_effect == "cas_registry":
            self.fail_effect = None
            raise RuntimeError(self.error_text or "cas-error")
        self.registry_state = BrokerRegistryState.NOT_APPLICABLE

    def deprovision_home(
        self, plan: OfflineBrokerPlan, binding: TransactionBinding
    ) -> None:
        self.effects.append("deprovision_home")
        if self.fail_effect == "deprovision_home":
            self.fail_effect = None
            raise RuntimeError(self.error_text or "remove-error")
        self.object_state = BrokerObjectState.ABSENT

    def close(self, fd: int) -> None:
        self.closed.append(fd)


def _composition(
    plan: OfflineBrokerPlan, operations: FakeDeprovisionOperations, wal: FakeWal
) -> RootBrokerExecutionComposition:
    return RootBrokerExecutionComposition(
        operations, FakeLinux(plan.expected_principal), wal, peer_pid=PEER_PID
    )


def _context(intent: BrokerIntentV1) -> BrokerIntentResumeContext:
    return BrokerIntentResumeContext(intent.transaction_id, _initial())


def test_deprovision_runs_bound_cas_finalize_cleanup_transaction() -> None:
    plan = _plan()
    operations = FakeDeprovisionOperations(plan)
    wal = FakeWal()

    response = _composition(plan, operations, wal).execute_intent(_intent(plan), plan)

    assert response.reply.result is BrokerResultCode.COMMITTED
    assert response.reply.transaction is not None
    assert response.reply.transaction.binding.transaction_id == TRANSACTION
    assert operations.generated_ids == []
    assert operations.effects == [
        "attest",
        "cas_registry",
        "attest",
        "deprovision_home",
    ]
    assert [decode_wal_record(record).status.checkpoint for record in wal.records] == [
        BrokerCheckpoint.DEPROVISION_INTENT,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        BrokerCheckpoint.FINALIZE_INTENT,
        BrokerCheckpoint.DEPROVISIONED,
    ]


def test_deprovision_gate_receives_the_effect_action_for_each_fresh_attestation() -> (
    None
):
    class ActionAwareOperations(FakeDeprovisionOperations):
        def __init__(self, plan: OfflineBrokerPlan) -> None:
            super().__init__(plan)
            self.gate_actions: list[BrokerRecoveryAction] = []

        def attest_deprovision_effect(
            self,
            plan: OfflineBrokerPlan,
            binding: TransactionBinding,
            action: BrokerRecoveryAction,
        ) -> None:
            self.effects.append("attest")
            self.gate_actions.append(action)

    plan = _plan()
    operations = ActionAwareOperations(plan)

    response = _composition(plan, operations, FakeWal()).execute_intent(
        _intent(plan), plan
    )

    assert response.reply.result is BrokerResultCode.COMMITTED
    assert operations.gate_actions == [
        BrokerRecoveryAction.CAS_REGISTRY,
        BrokerRecoveryAction.DEPROVISION_HOME,
    ]


def test_direct_deprovision_dispatch_returns_bound_terminal_reply() -> None:
    plan = _plan()
    intent = _intent(plan)
    request = DeprovisionHomeRequest(
        CHPB_PROTOCOL,
        ChpbMessageKind.DEPROVISION_HOME,
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

    response = _composition(plan, FakeDeprovisionOperations(plan), FakeWal()).execute(
        BrokerDispatchCommand(plan.expected_principal, request, "b" * 64, plan)
    )

    assert response.reply.result is BrokerResultCode.COMMITTED
    assert response.reply.transaction is not None
    assert response.reply.transaction.binding == request.binding


def test_absent_deprovision_is_bound_idempotent_without_effects() -> None:
    plan = _plan()
    operations = FakeDeprovisionOperations(plan)
    operations.initial_override = BrokerObservation(
        BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE, 0
    )

    response = _composition(plan, operations, FakeWal()).execute_intent(
        _intent(plan), plan
    )

    assert response.reply.result is BrokerResultCode.COMMITTED
    assert response.reply.transaction is not None
    assert response.reply.transaction.checkpoint is BrokerCheckpoint.DEPROVISIONED
    assert operations.effects == []


@pytest.mark.parametrize(
    "failure_field",
    ("fail_before_append", "fail_after_fsync", "fail_after_parent_fsync"),
)
@pytest.mark.parametrize("ordinal", range(1, 5))
def test_deprovision_wal_cutpoints_never_duplicate_effects(
    failure_field: str, ordinal: int
) -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeDeprovisionOperations(plan)
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
    assert operations.effects.count("cas_registry") <= 1
    assert operations.effects.count("deprovision_home") <= 1
    assert first.reply.transaction is not None
    assert fresh.reply.transaction is not None
    assert first.reply.transaction.binding.transaction_id == TRANSACTION
    assert fresh.reply.transaction.binding.transaction_id == TRANSACTION


def test_deprovision_cas_ambiguity_blocks_fresh_resume_without_retry() -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeDeprovisionOperations(plan)
    operations.fail_effect = "cas_registry"
    wal = FakeWal()
    wal.fail_before_append = 3

    first = _composition(plan, operations, wal).execute_intent(intent, plan)
    fresh = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert first.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert fresh.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects.count("cas_registry") == 1
    assert operations.effects.count("deprovision_home") == 0


def test_deprovision_cleanup_intent_ambiguity_blocks_without_second_delete() -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeDeprovisionOperations(plan)
    wal = FakeWal()
    wal.fail_after_fsync = 3

    first = _composition(plan, operations, wal).execute_intent(intent, plan)
    fresh = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert first.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert fresh.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects.count("cas_registry") == 1
    assert operations.effects.count("deprovision_home") == 0


def test_deprovision_cleanup_failure_after_durable_finalize_never_retries_delete() -> (
    None
):
    plan = _plan()
    intent = _intent(plan)
    operations = FakeDeprovisionOperations(plan)
    operations.fail_effect = "deprovision_home"
    wal = FakeWal()

    first = _composition(plan, operations, wal).execute_intent(intent, plan)
    fresh = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert first.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert fresh.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert [decode_wal_record(record).status.checkpoint for record in wal.records][
        :3
    ] == [
        BrokerCheckpoint.DEPROVISION_INTENT,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        BrokerCheckpoint.FINALIZE_INTENT,
    ]
    assert operations.effects.count("cas_registry") == 1
    assert operations.effects.count("deprovision_home") == 1
    assert operations.object_state is BrokerObjectState.FINAL_COMPLETE


@pytest.mark.parametrize(
    "gate",
    ("active-process", "open-lease", "inode-mismatch", "registry-drift", "stale-fence"),
)
def test_deprovision_gate_blocks_cleanup_before_removal(gate: str) -> None:
    plan = _plan()
    operations = FakeDeprovisionOperations(plan)
    operations.gate_error = gate

    response = _composition(plan, operations, FakeWal()).execute_intent(
        _intent(plan), plan
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects == ["attest"]
    assert operations.object_state is BrokerObjectState.FINAL_COMPLETE


def test_deprovision_second_fresh_gate_blocks_cleanup_after_one_cas() -> None:
    plan = _plan()
    operations = FakeDeprovisionOperations(plan)
    operations.gate_error = "active-process"
    operations.gate_fail_on_call = 2

    response = _composition(plan, operations, FakeWal()).execute_intent(
        _intent(plan), plan
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects == ["attest", "cas_registry", "attest"]
    assert operations.object_state is BrokerObjectState.FINAL_COMPLETE


@pytest.mark.parametrize(
    "observation",
    (
        BrokerObservation(
            BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.FOREIGN, 0
        ),
        BrokerObservation(BrokerObjectState.DRIFT, BrokerRegistryState.FOREIGN, 0),
    ),
)
def test_deprovision_foreign_initial_observation_blocks_before_effect(
    observation: BrokerObservation,
) -> None:
    plan = _plan()
    operations = FakeDeprovisionOperations(plan)
    operations.initial_override = observation

    response = _composition(plan, operations, FakeWal()).execute_intent(
        _intent(plan), plan
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects == []


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
def test_deprovision_fence_or_mcs_plan_drift_blocks_before_effect(plan_change) -> None:
    plan = _plan()
    operations = FakeDeprovisionOperations(plan)

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
def test_deprovision_fence_or_mcs_intent_drift_blocks_before_effect(
    intent_change,
) -> None:
    plan = _plan()
    operations = FakeDeprovisionOperations(plan)

    response = _composition(plan, operations, FakeWal()).execute_intent(
        intent_change(_intent(plan)), plan
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects == []


def test_deprovision_redacts_effect_failure_and_closes_each_valid_call() -> None:
    plan = _plan()
    operations = FakeDeprovisionOperations(plan)
    operations.gate_error = "gate"
    operations.error_text = "/root/private/credential=manifest-secret"
    composition = _composition(plan, operations, FakeWal())

    response = composition.execute_intent(_intent(plan), plan)
    for fd in (4, 4, -1, True):
        composition.close(fd)

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert "/root/private" not in repr(response)
    assert "manifest-secret" not in str(response.reply)
    assert operations.closed == [4, 4]
