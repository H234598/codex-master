from __future__ import annotations

import dataclasses
from hashlib import sha256

import pytest

from codex_master.fleet_home_broker import OfflineBrokerPlan
from codex_master.fleet_home_broker_consumer import BrokerIntentResumeContext
from codex_master.fleet_home_broker_dispatch import (
    BrokerDispatchCommand,
    dispatch_request,
)
from codex_master.fleet_home_broker_execution import (
    RootBrokerExecutionComposition,
    RootBrokerProvisionOperations,
)
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
    ProvisionHomeRequest,
    TransactionBinding,
)
from codex_master.fleet_home_broker_wal import decode_wal_record
from codex_master.fleet_home_broker_transport import BrokerPeer


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


def _principal() -> PrincipalBinding:
    return PrincipalBinding(AGENT, MANIFEST, UNIT, 0, 1, INVOCATION, "c0,c1", 4)


def _plan(*, population_total: int = 2) -> OfflineBrokerPlan:
    closure = _closure()
    identity = BrokerIdentity(
        AGENT,
        MANIFEST,
        "c0,c1",
        "slot-1",
        7,
        PROJECTION,
        closure.digest(),
        4,
    )
    return OfflineBrokerPlan(
        identity,
        closure,
        _principal(),
        ChpbTransactionOperation.PROVISION,
        STORE,
        population_total,
    )


def _intent(
    plan: OfflineBrokerPlan, transaction_id: str = TRANSACTION
) -> BrokerIntentV1:
    unsigned = BrokerIntentV1(
        schema_version=1,
        intent_generation=7,
        operation=BrokerIntentOperation.PROVISION,
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
        BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE, 0
    )


class FakeLinux:
    def __init__(self, principal: PrincipalBinding, events: list[str]) -> None:
        self.principal = principal
        self.identity = PidfdIdentity(PEER_PID, 7)
        self.events = events

    def pidfd_open(self, pid: int, flags: int) -> int:
        self.events.append("linux:pidfd_open")
        return 11

    def pidfd_reuse_check(self, *args: object) -> PidfdIdentity:
        self.events.append("linux:pidfd_reuse_check")
        return self.identity

    def open_pinned_proc_pid(self, *args: object) -> int:
        self.events.append("linux:open_pinned_proc_pid")
        return 12

    def open_proc_cgroup(self, *args: object) -> int:
        self.events.append("linux:open_proc_cgroup")
        return 13

    def fstat(self, fd: int) -> FdStat:
        self.events.append("linux:fstat")
        if fd == 13:
            return FdStat(0, 1, 0o40755, 0, 0)
        return FdStat(0, 1, 0o40700, 0, 0)

    def read_proc_control_group(self, *args: object) -> str:
        self.events.append("linux:read_proc_control_group")
        return CONTROL_GROUP

    def read_pid1_unit_name(self, *args: object) -> str:
        self.events.append("linux:read_pid1_unit_name")
        return "broker.scope"

    def read_pid1_unit_generation(self, *args: object) -> int:
        self.events.append("linux:read_pid1_unit_generation")
        return self.principal.unit_generation

    def read_pid1_invocation_id(self, *args: object) -> str:
        self.events.append("linux:read_pid1_invocation_id")
        return self.principal.invocation_id

    def read_pid1_control_group(self, *args: object) -> str:
        self.events.append("linux:read_pid1_control_group")
        return CONTROL_GROUP

    def read_peer_mcs_pair(self, *args: object) -> str:
        self.events.append("linux:read_peer_mcs_pair")
        return self.principal.mcs_pair

    def close(self, fd: int) -> None:
        self.events.append("linux:close")
        return None


class FakeWal:
    def __init__(
        self, records: list[bytes] | None = None, events: list[str] | None = None
    ) -> None:
        self.records = records if records is not None else []
        self.fail_before_append: int | None = None
        self.fail_after_fsync: int | None = None
        self.append_count = 0
        self.fsync_count = 0
        self.error_text: str | None = None
        self.events = events if events is not None else []

    def read_all(self) -> tuple[bytes, ...]:
        self.events.append("wal:read")
        return tuple(self.records)

    def append(self, record: bytes) -> None:
        self.events.append("wal:append")
        self.append_count += 1
        if self.append_count == self.fail_before_append:
            self.fail_before_append = None
            raise RuntimeError(self.error_text or "redacted-cutpoint")
        self.records.append(record)

    def fsync_wal(self) -> None:
        self.events.append("wal:fsync")
        self.fsync_count += 1
        if self.fsync_count == self.fail_after_fsync:
            self.fail_after_fsync = None
            raise RuntimeError(self.error_text or "redacted-cutpoint")

    def fsync_parent(self) -> None:
        self.events.append("wal:parent_fsync")
        return None


class FakeProvisionOperations:
    def __init__(self, plan: OfflineBrokerPlan) -> None:
        self.plan = plan
        self.object_state = BrokerObjectState.ABSENT
        self.registry_state = BrokerRegistryState.NOT_APPLICABLE
        self.population_index = 0
        self.events: list[str] = []
        self.publish_needs_checkpoint = False
        self.transaction_ids: list[str] = []
        self.effects: list[str] = []
        self.population_effects: list[int] = []
        self.fail_effect: str | None = None
        self.error_text: str | None = None
        self.fail_observe = False
        self.fail_close: set[int] = set()
        self.closed: list[int] = []

    def new_transaction_id(self) -> str:
        self.transaction_ids.append("f" * 32)
        return "f" * 32

    def observe(self, plan: OfflineBrokerPlan) -> BrokerObservation:
        assert plan is self.plan
        self.events.append("operations:observe")
        if self.fail_observe:
            raise RuntimeError(self.error_text or "redacted-observation-failure")
        if self.publish_needs_checkpoint:
            self.publish_needs_checkpoint = False
            return BrokerObservation(
                BrokerObjectState.FINAL_COMPLETE,
                BrokerRegistryState.NOT_APPLICABLE,
                self.population_index,
            )
        return BrokerObservation(
            self.object_state, self.registry_state, self.population_index
        )

    def _effect(self, name: str) -> None:
        self.effects.append(name)
        if self.fail_effect == name:
            self.fail_effect = None
            raise RuntimeError(self.error_text or "redacted-effect-failure")

    def create_staging(self, plan: OfflineBrokerPlan) -> None:
        self._effect("create_staging")
        self.object_state = BrokerObjectState.STAGING_EMPTY

    def populate_next(self, plan: OfflineBrokerPlan) -> None:
        self._effect("populate_next")
        self.population_index += 1
        self.population_effects.append(self.population_index)
        self.object_state = (
            BrokerObjectState.STAGING_COMPLETE
            if self.population_index == plan.population_total
            else BrokerObjectState.STAGING_PREFIX
        )

    def publish_home(self, plan: OfflineBrokerPlan) -> None:
        self._effect("publish_home")
        self.object_state = BrokerObjectState.FINAL_COMPLETE
        self.registry_state = BrokerRegistryState.OLD
        self.publish_needs_checkpoint = True

    def cas_registry(
        self, plan: OfflineBrokerPlan, binding: TransactionBinding
    ) -> None:
        self._effect("cas_registry")
        self.registry_state = BrokerRegistryState.CURRENT

    def close(self, fd: int) -> None:
        self.closed.append(fd)
        if fd in self.fail_close:
            raise RuntimeError("redacted-close-failure")


def _composition(
    plan: OfflineBrokerPlan, operations: FakeProvisionOperations, wal: FakeWal
) -> RootBrokerExecutionComposition:
    return RootBrokerExecutionComposition(
        operations,
        FakeLinux(plan.expected_principal, operations.events),
        wal,
        peer_pid=PEER_PID,
    )


def _context(intent: BrokerIntentV1) -> BrokerIntentResumeContext:
    return BrokerIntentResumeContext(intent.transaction_id, _initial())


def _last_checkpoint(wal: FakeWal) -> BrokerCheckpoint:
    return decode_wal_record(wal.records[-1]).status.checkpoint


def test_root_broker_execution_composition_module_exists() -> None:
    assert RootBrokerExecutionComposition is not None
    assert all(
        hasattr(RootBrokerProvisionOperations, name)
        for name in (
            "new_transaction_id",
            "observe",
            "create_staging",
            "populate_next",
            "publish_home",
            "cas_registry",
            "close",
        )
    )


def test_execute_intent_commits_one_canonical_bound_provision() -> None:
    plan = _plan()
    operations = FakeProvisionOperations(plan)
    wal = FakeWal()
    response = _composition(plan, operations, wal).execute_intent(_intent(plan), plan)

    assert response.fds == ()
    assert response.reply.result is BrokerResultCode.COMMITTED
    assert response.reply.request_id == REQUEST_ID
    assert response.reply.transaction is not None
    assert response.reply.transaction.binding.transaction_id == TRANSACTION
    assert response.reply.transaction.checkpoint is BrokerCheckpoint.COMMITTED
    assert operations.transaction_ids == []
    assert operations.effects == [
        "create_staging",
        "populate_next",
        "populate_next",
        "publish_home",
        "cas_registry",
    ]
    assert [decode_wal_record(record).status.checkpoint for record in wal.records] == [
        BrokerCheckpoint.CREATE_INTENT,
        BrokerCheckpoint.STAGING_PINNED,
        BrokerCheckpoint.POPULATE_PENDING,
        BrokerCheckpoint.PUBLISH_INTENT,
        BrokerCheckpoint.PUBLISHED,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        BrokerCheckpoint.FINALIZE_INTENT,
        BrokerCheckpoint.COMMITTED,
    ]


def test_execute_dispatch_command_preserves_canonical_request_binding() -> None:
    plan = _plan()
    intent = _intent(plan)
    request = ProvisionHomeRequest(
        CHPB_PROTOCOL,
        ChpbMessageKind.PROVISION_HOME,
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
    command = BrokerDispatchCommand(plan.expected_principal, request, "b" * 64, plan)

    response = _composition(plan, FakeProvisionOperations(plan), FakeWal()).execute(
        command
    )

    assert response.reply.result is BrokerResultCode.COMMITTED
    assert response.reply.transaction is not None
    assert response.reply.transaction.binding == request.binding


def test_execute_replaces_an_invalid_direct_request_id_with_safe_typed_failure() -> (
    None
):
    plan = _plan()
    request = ProvisionHomeRequest(
        CHPB_PROTOCOL,
        ChpbMessageKind.PROVISION_HOME,
        "G" * 32,
        TRANSACTION,
        BindingExpectation(AGENT, MANIFEST, UNIT, 7, PROJECTION, 4),
        TransactionBinding(
            plan.operation,
            TRANSACTION,
            plan.store_uuid,
            plan.expected_principal,
            PolicyBinding(7, PROJECTION),
        ),
    )

    response = _composition(plan, FakeProvisionOperations(plan), FakeWal()).execute(
        BrokerDispatchCommand(plan.expected_principal, request, "b" * 64, plan)
    )

    assert response.reply.result is BrokerResultCode.INTERNAL_ERROR
    assert response.reply.request_id == "0" * 32
    assert response.reply.transaction is None


def test_dispatch_binds_only_to_the_root_execution_composition() -> None:
    plan = _plan()
    intent = _intent(plan)
    request = ProvisionHomeRequest(
        CHPB_PROTOCOL,
        ChpbMessageKind.PROVISION_HOME,
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

    class Resolver:
        def resolve_principal(self, peer: BrokerPeer) -> PrincipalBinding:
            assert peer == BrokerPeer(41)
            return plan.expected_principal

        def resolve_mutation_plan(
            self, principal: PrincipalBinding, received: ProvisionHomeRequest
        ) -> OfflineBrokerPlan:
            assert principal == plan.expected_principal
            assert received == request
            return plan

    response = dispatch_request(
        BrokerPeer(41),
        request,
        Resolver(),
        _composition(plan, FakeProvisionOperations(plan), FakeWal()),
    )

    assert response.reply.result is BrokerResultCode.COMMITTED
    assert response.reply.transaction is not None
    assert response.reply.transaction.binding == request.binding


@pytest.mark.parametrize("failure_field", ("fail_before_append", "fail_after_fsync"))
@pytest.mark.parametrize("ordinal", range(1, 9))
def test_every_wal_pre_or_post_fsync_cutpoint_resumes_same_transaction_or_blocks(
    failure_field: str, ordinal: int
) -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeProvisionOperations(plan)
    wal = FakeWal()
    setattr(wal, failure_field, ordinal)
    first = _composition(plan, operations, wal).execute_intent(intent, plan)
    fresh = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert first.reply.result in {
        BrokerResultCode.BLOCKED_DRIFT,
        BrokerResultCode.COMMITTED,
    }
    assert fresh.reply.result in {
        BrokerResultCode.BLOCKED_DRIFT,
        BrokerResultCode.COMMITTED,
    }
    assert operations.transaction_ids == []
    assert operations.effects.count("create_staging") <= 1
    assert len(operations.population_effects) <= plan.population_total
    assert len(operations.population_effects) == len(set(operations.population_effects))
    assert operations.effects.count("publish_home") <= 1
    assert operations.effects.count("cas_registry") <= 1
    if fresh.reply.transaction is not None:
        assert fresh.reply.transaction.binding.transaction_id == TRANSACTION


@pytest.mark.parametrize(
    "mutate",
    (
        lambda operations: setattr(operations, "object_state", BrokerObjectState.DRIFT),
        lambda operations: setattr(
            operations, "registry_state", BrokerRegistryState.FOREIGN
        ),
    ),
)
def test_resume_drift_is_typed_blocked_and_never_replays_effect(mutate) -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeProvisionOperations(plan)
    wal = FakeWal()
    wal.fail_before_append = 2
    _composition(plan, operations, wal).execute_intent(intent, plan)
    mutate(operations)

    response = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert response.reply.transaction is not None
    assert response.reply.transaction.terminal_result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects == ["create_staging"]


def test_registry_cas_conflict_is_single_attempt_and_never_claims_commit() -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeProvisionOperations(plan)
    operations.fail_effect = "cas_registry"
    wal = FakeWal()

    response = _composition(plan, operations, wal).execute_intent(intent, plan)

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects.count("cas_registry") == 1
    assert _last_checkpoint(wal) is not BrokerCheckpoint.COMMITTED


@pytest.mark.parametrize(
    "context",
    (
        lambda intent: BrokerIntentResumeContext("f" * 32, _initial()),
        lambda intent: BrokerIntentResumeContext(
            intent.transaction_id,
            BrokerObservation(
                BrokerObjectState.STAGING_EMPTY, BrokerRegistryState.NOT_APPLICABLE, 0
            ),
        ),
        lambda intent: BrokerIntentResumeContext(
            intent.transaction_id, BrokerObservation("absent", "not_applicable", 0)
        ),
        lambda intent: None,
    ),
)
def test_resume_requires_exact_transaction_and_initial_observation(context) -> None:
    plan = _plan()
    intent = _intent(plan)
    response = _composition(
        plan, FakeProvisionOperations(plan), FakeWal()
    ).resume_intent(intent, plan, context(intent))

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT


def test_empty_wal_recovery_restarts_the_same_attested_intent_transaction() -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeProvisionOperations(plan)
    wal = FakeWal()

    response = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert response.reply.result is BrokerResultCode.COMMITTED
    assert response.reply.transaction is not None
    assert response.reply.transaction.binding.transaction_id == intent.transaction_id
    assert (
        decode_wal_record(wal.records[0]).status.binding.transaction_id
        == intent.transaction_id
    )
    assert operations.transaction_ids == []


def test_empty_wal_recovery_first_observes_only_after_linux_identity_attestation() -> (
    None
):
    plan = _plan()
    intent = _intent(plan)
    operations = FakeProvisionOperations(plan)
    wal = FakeWal(events=operations.events)

    response = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert response.reply.result is BrokerResultCode.COMMITTED
    empty_wal_read = [
        index for index, event in enumerate(operations.events) if event == "wal:read"
    ][1]
    assert operations.events[empty_wal_read + 1] == "linux:pidfd_open"
    assert response.reply.transaction is not None
    assert response.reply.transaction.binding.transaction_id == intent.transaction_id


def test_post_fsync_population_ambiguity_terminalizes_from_latest_wal_status() -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeProvisionOperations(plan)
    wal = FakeWal()
    wal.fail_after_fsync = 3

    first = _composition(plan, operations, wal).execute_intent(intent, plan)
    effects_before = tuple(operations.effects)
    fresh = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert first.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert fresh.reply.result is BrokerResultCode.BLOCKED_DRIFT
    terminal = decode_wal_record(wal.records[-1]).status
    assert terminal.checkpoint is BrokerCheckpoint.BLOCKED_DRIFT
    assert terminal.observation.population_index == 1
    assert tuple(operations.effects) == effects_before


def test_nonempty_or_invalid_wal_never_uses_the_empty_wal_resume_rule() -> None:
    plan = _plan()
    intent = _intent(plan)
    operations = FakeProvisionOperations(plan)
    wal = FakeWal([b"truncated-wal"])

    response = _composition(plan, operations, wal).resume_intent(
        intent, plan, _context(intent)
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert operations.effects == []
    assert operations.transaction_ids == []


def test_wal_transaction_binding_drift_blocks_without_a_second_effect() -> None:
    plan = _plan()
    operations = FakeProvisionOperations(plan)
    wal = FakeWal()
    original = _intent(plan)
    assert _composition(plan, operations, wal).execute_intent(
        original, plan
    ).reply.result is (BrokerResultCode.COMMITTED)
    effects_before = tuple(operations.effects)
    mismatched = _intent(plan, "8" * 32)

    response = _composition(plan, operations, wal).resume_intent(
        mismatched, plan, _context(mismatched)
    )

    assert response.reply.result is BrokerResultCode.BLOCKED_DRIFT
    assert tuple(operations.effects) == effects_before


def test_close_handles_reused_fd_numbers_per_call_and_masks_close_errors() -> None:
    plan = _plan()
    operations = FakeProvisionOperations(plan)
    operations.fail_close.add(4)
    composition = _composition(plan, operations, FakeWal())

    for fd in (4, 4, -1, True, 5):
        composition.close(fd)

    assert operations.closed == [4, 4, 5]


@pytest.mark.parametrize("failure", ("observe", "effect", "wal"))
def test_failure_replies_are_typed_and_redact_injected_secret_or_path(
    failure: str,
) -> None:
    plan = _plan()
    intent = _intent(plan)
    secret = "/root/private/token=do-not-disclose"
    operations = FakeProvisionOperations(plan)
    wal = FakeWal()
    if failure == "observe":
        operations.fail_observe = True
        operations.error_text = secret
    elif failure == "effect":
        operations.fail_effect = "create_staging"
        operations.error_text = secret
    else:
        wal.fail_before_append = 1
        wal.error_text = secret

    response = _composition(plan, operations, wal).execute_intent(intent, plan)

    assert response.reply.result in {
        BrokerResultCode.BLOCKED_DRIFT,
        BrokerResultCode.INTERNAL_ERROR,
    }
    assert secret not in repr(response)
    assert secret not in str(response.reply)
