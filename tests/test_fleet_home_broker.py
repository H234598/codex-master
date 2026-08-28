import ast
import dataclasses
from dataclasses import FrozenInstanceError
from hashlib import sha256
import inspect
from pathlib import Path

import pytest

from codex_master.fleet_home_broker import (
    OfflineBrokerError,
    OfflineBrokerOperations,
    OfflineBrokerPlan,
    OfflineBrokerStep,
    begin_offline_transaction,
    recover_offline_transaction,
)
from codex_master.fleet_home_broker_identity import (
    BrokerIdentity,
    ImportClosure,
    ImportClosureEntry,
)
from codex_master.fleet_home_broker_linux import FdStat, PidfdIdentity
from codex_master.fleet_home_broker_protocol import (
    B2aRecoveryPhase,
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRecoveryAction,
    BrokerRegistryState,
    ChpbTransactionOperation,
    PolicyBinding,
    PrincipalBinding,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
    decide_broker_recovery,
)
from codex_master.fleet_home_broker_wal import (
    append_status,
)


ROOT = Path(__file__).parents[1]
PEER_PID = 1234
AGENT = "bee_1"
MANIFEST = 3
UNIT_GENERATION = 9
INVOCATION = "1" * 32
PROJECTION = "a" * 64
STORE = "3" * 32
TRANSACTION = "2" * 32
GENESIS = "0" * 64
CONTROL_GROUP = "/user.slice/broker.scope"


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _closure() -> ImportClosure:
    return ImportClosure(
        (ImportClosureEntry("codex_master/fleet_home_broker.py", _digest("broker")),)
    )


def _identity(**changes) -> BrokerIdentity:
    closure = _closure()
    values = {
        "agent_id": AGENT,
        "manifest_generation": MANIFEST,
        "mcs_pair": "c0,c1",
        "slot_snapshot": "slot-1",
        "policy_generation": 7,
        "projection_digest": PROJECTION,
        "executable_fingerprint": closure.digest(),
        "fencing_epoch": 4,
    }
    values.update(changes)
    return BrokerIdentity(**values)


def _principal(**changes) -> PrincipalBinding:
    values = {
        "agent_id": AGENT,
        "manifest_generation": MANIFEST,
        "unit_generation": UNIT_GENERATION,
        "cgroup_dev": 0,
        "cgroup_ino": 1,
        "invocation_id": INVOCATION,
        "mcs_pair": "c0,c1",
        "fencing_epoch": 4,
    }
    values.update(changes)
    return PrincipalBinding(**values)


def _plan(**changes) -> OfflineBrokerPlan:
    values = {
        "identity": _identity(),
        "import_closure": _closure(),
        "expected_principal": _principal(),
        "operation": ChpbTransactionOperation.PROVISION,
        "store_uuid": STORE,
        "population_total": 1,
    }
    values.update(changes)
    return OfflineBrokerPlan(**values)


def _observation(
    object_state=BrokerObjectState.ABSENT,
    registry_state=BrokerRegistryState.NOT_APPLICABLE,
    population_index=0,
):
    return BrokerObservation(object_state, registry_state, population_index)


class FakeLinuxOperations:
    def __init__(self, *, expected=None, events=None, operation_errors=None):
        self.expected = expected or _principal()
        self.events = events if events is not None else []
        self.operation_errors = dict(operation_errors or {})
        self.pid_identity = PidfdIdentity(PEER_PID, 7)

    def _raise_if_configured(self, name):
        error = self.operation_errors.get(name)
        if error is not None:
            raise error

    def pidfd_open(self, pid, flags):
        self.events.append(("pidfd_open", pid, flags))
        self._raise_if_configured("pidfd_open")
        return 11

    def pidfd_reuse_check(self, pidfd, pid, proc_fd, cgroup_fd, identity):
        self.events.append(("pidfd_reuse_check", pidfd, pid, proc_fd, cgroup_fd))
        self._raise_if_configured("pidfd_reuse_check")
        return self.pid_identity

    def open_pinned_proc_pid(self, pidfd, pid, identity):
        self.events.append(("open_pinned_proc_pid", pidfd, pid))
        self._raise_if_configured("open_pinned_proc_pid")
        return 12

    def open_proc_cgroup(self, pidfd, proc_fd, identity):
        self.events.append(("open_proc_cgroup", pidfd, proc_fd))
        self._raise_if_configured("open_proc_cgroup")
        return 13

    def fstat(self, fd):
        self.events.append(("fstat", fd))
        self._raise_if_configured("fstat")
        return FdStat(
            self.expected.cgroup_dev,
            self.expected.cgroup_ino,
            0o40755,
            1000,
            1000,
        )

    def read_proc_control_group(
        self, pidfd, proc_fd, cgroup_fd, cgroup_dev, cgroup_ino
    ):
        self.events.append(("read_proc_control_group", pidfd, proc_fd, cgroup_fd))
        self._raise_if_configured("read_proc_control_group")
        return CONTROL_GROUP

    def read_pid1_unit_name(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.events.append(("read_pid1_unit_name", pidfd, cgroup_fd))
        self._raise_if_configured("read_pid1_unit_name")
        return "broker.scope"

    def read_pid1_unit_generation(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.events.append(("read_pid1_unit_generation", pidfd, cgroup_fd))
        self._raise_if_configured("read_pid1_unit_generation")
        return self.expected.unit_generation

    def read_pid1_invocation_id(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.events.append(("read_pid1_invocation_id", pidfd, cgroup_fd))
        self._raise_if_configured("read_pid1_invocation_id")
        return self.expected.invocation_id

    def read_pid1_control_group(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.events.append(("read_pid1_control_group", pidfd, cgroup_fd))
        self._raise_if_configured("read_pid1_control_group")
        return CONTROL_GROUP

    def read_peer_mcs_pair(self, pidfd, proc_fd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.events.append(("read_peer_mcs_pair", pidfd, proc_fd, cgroup_fd))
        self._raise_if_configured("read_peer_mcs_pair")
        return self.expected.mcs_pair

    def close(self, fd):
        self.events.append(("close", fd))


class FakeBrokerOperations:
    def __init__(self, observation, transaction_id=TRANSACTION, events=None):
        self.observation = observation
        self.transaction_id = transaction_id
        self.events = events if events is not None else []
        self.observed_plans = []

    def new_transaction_id(self):
        self.events.append("new_transaction_id")
        return self.transaction_id

    def observe(self, plan):
        self.events.append("observe")
        self.observed_plans.append(plan)
        return self.observation


class FakeWalOperations:
    def __init__(self, records=(), events=None):
        self.records = list(records)
        self.events = events if events is not None else []

    def read_all(self):
        self.events.append("read")
        return tuple(self.records)

    def append(self, record):
        self.events.append("append")
        self.records.append(record)

    def fsync_wal(self):
        self.events.append("fsync_wal")

    def fsync_parent(self):
        self.events.append("fsync_parent")


def _operations(plan, observation, *, wal=None, events=None):
    broker_events = events if events is not None else []
    return (
        FakeBrokerOperations(observation, events=broker_events),
        FakeLinuxOperations(expected=plan.expected_principal),
        wal or FakeWalOperations(),
    )


def _shared_operations(
    plan,
    observation,
    eventlog,
    *,
    wal_records=(),
    linux_errors=None,
):
    return (
        FakeBrokerOperations(observation, events=eventlog),
        FakeLinuxOperations(
            expected=plan.expected_principal,
            events=eventlog,
            operation_errors=linux_errors,
        ),
        FakeWalOperations(wal_records, events=eventlog),
    )


def _wal_events(eventlog):
    return [
        event
        for event in eventlog
        if event in {"read", "append", "fsync_wal", "fsync_parent"}
    ]


def _last_close(eventlog):
    return max(index for index, event in enumerate(eventlog) if event[0] == "close")


def _begin(plan, observation=None, *, wal=None, events=None):
    if observation is None:
        observation = _initial_observation(plan.operation)
    operations, linux, wal = _operations(plan, observation, wal=wal, events=events)
    result = begin_offline_transaction(plan, PEER_PID, operations, linux, wal)
    return result, operations, linux, wal


def _initial_observation(operation):
    return {
        ChpbTransactionOperation.PROVISION: _observation(),
        ChpbTransactionOperation.REPLACE: _observation(
            BrokerObjectState.REPLACEMENT_ORIGINAL
        ),
        ChpbTransactionOperation.DEPROVISION: _observation(
            BrokerObjectState.FINAL_COMPLETE
        ),
    }[operation]


def _binding(plan, transaction_id=TRANSACTION):
    return TransactionBinding(
        plan.operation,
        transaction_id,
        plan.store_uuid,
        plan.expected_principal,
        PolicyBinding(plan.identity.policy_generation, plan.identity.projection_digest),
    )


def _status(
    plan, checkpoint, observation, *, transaction_id=TRANSACTION, terminal=None
):
    if terminal is None:
        terminal = {
            BrokerCheckpoint.COMMITTED: "committed",
            BrokerCheckpoint.DEPROVISIONED: "committed",
            BrokerCheckpoint.ROLLED_BACK: "rolled_back",
            BrokerCheckpoint.BLOCKED_DRIFT: "blocked_drift",
        }.get(checkpoint)
        if terminal is not None:
            from codex_master.fleet_home_broker_protocol import BrokerResultCode

            terminal = BrokerResultCode(terminal)
    return TransactionStatus(
        _binding(plan, transaction_id),
        b2a_phase_for_checkpoint(checkpoint),
        checkpoint,
        observation,
        plan.population_total,
        terminal,
    )


def _wal_for_statuses(statuses):
    wal = FakeWalOperations()
    for value in statuses:
        append_status(wal, value)
    wal.events.clear()
    return wal


def test_public_types_are_frozen_slotted_and_api_has_no_client_transaction_id():
    for value in (_plan(), OfflineBrokerStep(None, _blocked_decision_for_test())):
        klass = type(value)
        assert dataclasses.is_dataclass(value)
        assert klass.__dataclass_params__.frozen
        assert hasattr(klass, "__slots__")
        assert not hasattr(value, "__dict__")
    with pytest.raises(FrozenInstanceError):
        _plan().store_uuid = "4" * 32

    assert tuple(
        inspect.signature(OfflineBrokerOperations.new_transaction_id).parameters
    ) == ("self",)
    assert tuple(inspect.signature(OfflineBrokerOperations.observe).parameters) == (
        "self",
        "plan",
    )
    assert "transaction_id" not in inspect.signature(OfflineBrokerPlan).parameters
    assert "client" not in inspect.signature(begin_offline_transaction).parameters


def _blocked_decision_for_test():
    from codex_master.fleet_home_broker_protocol import (
        BrokerResultCode,
        RecoveryDecision,
    )

    return RecoveryDecision(
        BrokerRecoveryAction.RETURN_BLOCKED,
        B2aRecoveryPhase.BLOCKED,
        BrokerCheckpoint.BLOCKED_DRIFT,
        BrokerResultCode.BLOCKED_DRIFT,
    )


@pytest.mark.parametrize(
    ("change",),
    [
        (lambda: {"identity": _identity(executable_fingerprint="f" * 64)},),
        (lambda: {"expected_principal": _principal(agent_id="bee_2")},),
        (lambda: {"expected_principal": _principal(manifest_generation=4)},),
        (lambda: {"expected_principal": _principal(mcs_pair="c1,c2")},),
        (lambda: {"expected_principal": _principal(fencing_epoch=5)},),
        (lambda: {"store_uuid": "not-a-store"},),
        (lambda: {"population_total": 0},),
        (lambda: {"population_total": 257},),
    ],
)
def test_plan_validation_rejects_static_drift_before_any_call(change):
    plan = _plan(**change())
    operations, linux, wal = _operations(plan, _initial_observation(plan.operation))

    with pytest.raises(OfflineBrokerError):
        begin_offline_transaction(plan, PEER_PID, operations, linux, wal)

    assert operations.events == []
    assert wal.events == []
    assert linux.events == []


@pytest.mark.parametrize(
    ("operation", "object_state", "checkpoint", "phase", "action"),
    [
        (
            ChpbTransactionOperation.PROVISION,
            BrokerObjectState.ABSENT,
            BrokerCheckpoint.CREATE_INTENT,
            B2aRecoveryPhase.ABSENT_CREATE_PENDING,
            BrokerRecoveryAction.CREATE_STAGING,
        ),
        (
            ChpbTransactionOperation.REPLACE,
            BrokerObjectState.REPLACEMENT_ORIGINAL,
            BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
            B2aRecoveryPhase.PREPARE_PENDING,
            BrokerRecoveryAction.PREPARE_REPLACEMENT,
        ),
        (
            ChpbTransactionOperation.DEPROVISION,
            BrokerObjectState.FINAL_COMPLETE,
            BrokerCheckpoint.DEPROVISION_INTENT,
            B2aRecoveryPhase.DEPROVISION_PENDING,
            BrokerRecoveryAction.DEPROVISION_HOME,
        ),
    ],
)
def test_begin_uses_broker_id_initial_mapping_and_proposal(
    operation, object_state, checkpoint, phase, action
):
    plan = _plan(operation=operation)
    result, operations, _, wal = _begin(plan, _observation(object_state))

    assert result.status is not None
    assert result.status.binding.transaction_id == TRANSACTION
    assert result.status.binding.operation is operation
    assert result.status.binding.store_uuid == STORE
    assert result.status.binding.policy == PolicyBinding(7, PROJECTION)
    assert result.status.checkpoint is checkpoint
    assert result.status.b2a_phase is phase
    assert result.status.observation == _observation(object_state)
    assert result.decision.action is action
    assert result.decision.next_checkpoint is None
    assert operations.events == ["new_transaction_id", "observe"]
    assert wal.events == ["read", "append", "fsync_wal", "fsync_parent"]


def test_begin_rejects_wrong_initial_observation_without_wal_write():
    plan = _plan()
    result, operations, _, wal = _begin(
        plan, _observation(BrokerObjectState.STAGING_EMPTY)
    )

    assert result.status is None
    assert result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED
    assert result.decision.next_checkpoint is BrokerCheckpoint.BLOCKED_DRIFT
    assert operations.events == ["new_transaction_id", "observe"]
    assert wal.events == []


def test_recovery_reads_only_and_redacts_blocked_decision_status():
    plan = _plan()
    started, _, _, wal = _begin(plan)
    wal.events.clear()
    events = []
    operations, linux, _ = _operations(plan, _observation(), wal=wal, events=events)

    result = recover_offline_transaction(plan, PEER_PID, operations, linux, wal)

    assert result.status == started.status
    assert result.decision.action is BrokerRecoveryAction.CREATE_STAGING
    assert events == ["observe"]
    assert wal.events == ["read"]
    assert "new_transaction_id" not in events
    assert "append" not in events
    assert "fsync_wal" not in events
    assert "fsync_parent" not in events


@pytest.mark.parametrize("records", [(), (b"corrupt",)])
def test_recovery_blocks_empty_or_corrupt_wal_without_status_leak(records):
    plan = _plan()
    wal = FakeWalOperations(records)
    operations, linux, _ = _operations(plan, _observation(), wal=wal)
    result = recover_offline_transaction(plan, PEER_PID, operations, linux, wal)

    assert result.status is None
    assert result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED
    assert result.decision.next_checkpoint is BrokerCheckpoint.BLOCKED_DRIFT


def test_recovery_blocks_foreign_wal_and_binding_drift_without_status_leak():
    foreign_plan = _plan(store_uuid="4" * 32)
    foreign, _, _, foreign_wal = _begin(foreign_plan)
    assert foreign.status is not None
    foreign_wal.events.clear()
    operations, linux, _ = _operations(_plan(), _observation(), wal=foreign_wal)

    foreign_result = recover_offline_transaction(
        _plan(), PEER_PID, operations, linux, foreign_wal
    )
    assert foreign_result.status is None
    assert foreign_result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED

    started, _, _, drift_wal = _begin(_plan())
    drift_wal.events.clear()
    drift_operations, drift_linux, _ = _operations(
        _plan(), _observation(population_index=2), wal=drift_wal
    )
    drift_result = recover_offline_transaction(
        _plan(), PEER_PID, drift_operations, drift_linux, drift_wal
    )
    assert started.status is not None
    assert drift_result.status is None
    assert drift_result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED


def test_recovery_blocks_forked_wal_without_status_leak():
    plan = _plan()
    started, _, _, wal = _begin(plan)
    assert started.status is not None
    wal.records.append(wal.records[0])
    wal.events.clear()
    operations, linux, _ = _operations(plan, _observation(), wal=wal)

    result = recover_offline_transaction(plan, PEER_PID, operations, linux, wal)

    assert result.status is None
    assert result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED
    assert wal.events == ["read"]


def test_registry_cas_and_provision_replace_terminal_states_are_blocked():
    plan = _plan()
    statuses = [
        _status(
            plan,
            BrokerCheckpoint.CREATE_INTENT,
            _observation(),
        ),
        _status(
            plan,
            BrokerCheckpoint.STAGING_PINNED,
            _observation(BrokerObjectState.STAGING_EMPTY),
        ),
        _status(
            plan,
            BrokerCheckpoint.POPULATE_PENDING,
            _observation(BrokerObjectState.STAGING_PREFIX),
        ),
        _status(
            plan,
            BrokerCheckpoint.PUBLISH_INTENT,
            _observation(BrokerObjectState.STAGING_COMPLETE, population_index=1),
        ),
        _status(
            plan,
            BrokerCheckpoint.PUBLISHED,
            _observation(BrokerObjectState.FINAL_COMPLETE, population_index=1),
        ),
        _status(
            plan,
            BrokerCheckpoint.REGISTRY_CAS_INTENT,
            _observation(
                BrokerObjectState.FINAL_COMPLETE,
                BrokerRegistryState.OLD,
                1,
            ),
        ),
    ]
    wal = _wal_for_statuses(statuses)
    operations, linux, _ = _operations(
        plan,
        _observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.OLD, 1),
        wal=wal,
    )

    result = recover_offline_transaction(plan, PEER_PID, operations, linux, wal)

    assert result.status is None
    assert result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED


@pytest.mark.parametrize(
    "checkpoint", [BrokerCheckpoint.FINALIZE_INTENT, BrokerCheckpoint.COMMITTED]
)
def test_provision_finalize_and_committed_are_blocked(checkpoint):
    plan = _plan()
    statuses = [
        _status(plan, BrokerCheckpoint.CREATE_INTENT, _observation()),
        _status(
            plan,
            BrokerCheckpoint.STAGING_PINNED,
            _observation(BrokerObjectState.STAGING_EMPTY),
        ),
        _status(
            plan,
            BrokerCheckpoint.POPULATE_PENDING,
            _observation(BrokerObjectState.STAGING_PREFIX),
        ),
        _status(
            plan,
            BrokerCheckpoint.PUBLISH_INTENT,
            _observation(BrokerObjectState.STAGING_COMPLETE, population_index=1),
        ),
        _status(
            plan,
            BrokerCheckpoint.PUBLISHED,
            _observation(BrokerObjectState.FINAL_COMPLETE, population_index=1),
        ),
        _status(
            plan,
            BrokerCheckpoint.REGISTRY_CAS_INTENT,
            _observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.OLD, 1),
        ),
        _status(
            plan,
            BrokerCheckpoint.FINALIZE_INTENT,
            _observation(
                BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1
            ),
        ),
    ]
    if checkpoint is BrokerCheckpoint.COMMITTED:
        statuses.append(
            _status(
                plan,
                checkpoint,
                _observation(
                    BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1
                ),
                terminal=None,
            )
        )
    wal = _wal_for_statuses(statuses)
    observation = statuses[-1].observation
    operations, linux, _ = _operations(plan, observation, wal=wal)

    result = recover_offline_transaction(plan, PEER_PID, operations, linux, wal)

    assert result.status is None
    assert result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED


def test_deprovisioned_terminal_fact_is_allowed_read_only():
    plan = _plan(operation=ChpbTransactionOperation.DEPROVISION)
    statuses = [
        _status(
            plan,
            BrokerCheckpoint.DEPROVISION_INTENT,
            _observation(BrokerObjectState.FINAL_COMPLETE),
        ),
        _status(
            plan,
            BrokerCheckpoint.DEPROVISIONED,
            _observation(BrokerObjectState.ABSENT),
        ),
    ]
    wal = _wal_for_statuses(statuses)
    operations, linux, _ = _operations(plan, _observation(), wal=wal)

    result = recover_offline_transaction(plan, PEER_PID, operations, linux, wal)

    assert result.status == statuses[-1]
    assert result.decision.action is BrokerRecoveryAction.RETURN_COMMITTED
    assert wal.events == ["read"]


@pytest.mark.parametrize(
    ("label", "foreign_plan"),
    [
        (
            "policy_generation",
            lambda: _plan(identity=_identity(policy_generation=8)),
        ),
        (
            "policy_digest",
            lambda: _plan(identity=_identity(projection_digest="b" * 64)),
        ),
        (
            "fence",
            lambda: _plan(
                identity=_identity(fencing_epoch=5),
                expected_principal=_principal(fencing_epoch=5),
            ),
        ),
        (
            "unit_generation",
            lambda: _plan(expected_principal=_principal(unit_generation=10)),
        ),
        (
            "cgroup_dev",
            lambda: _plan(expected_principal=_principal(cgroup_dev=2)),
        ),
        (
            "cgroup_ino",
            lambda: _plan(expected_principal=_principal(cgroup_ino=2)),
        ),
        (
            "invocation_id",
            lambda: _plan(expected_principal=_principal(invocation_id="4" * 32)),
        ),
        (
            "mcs",
            lambda: _plan(
                identity=_identity(mcs_pair="c1,c2"),
                expected_principal=_principal(mcs_pair="c1,c2"),
            ),
        ),
        (
            "operation",
            lambda: _plan(operation=ChpbTransactionOperation.REPLACE),
        ),
        (
            "population_total",
            lambda: _plan(population_total=2),
        ),
    ],
)
def test_recovery_binding_matrix_redacts_valid_foreign_wal(label, foreign_plan):
    target = _plan()
    foreign_result, _, _, foreign_wal = _begin(foreign_plan())
    assert foreign_result.status is not None, label

    eventlog = []
    operations, linux, wal = _shared_operations(
        target,
        _observation(),
        eventlog,
        wal_records=foreign_wal.records,
    )
    result = recover_offline_transaction(target, PEER_PID, operations, linux, wal)

    assert result.status is None, label
    assert result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED
    assert result.decision.next_checkpoint is BrokerCheckpoint.BLOCKED_DRIFT
    assert _wal_events(eventlog) == ["read"]
    assert "append" not in eventlog
    assert "fsync_wal" not in eventlog
    assert "fsync_parent" not in eventlog


def test_begin_eventlog_closes_all_linux_fds_before_observe_and_wal():
    plan = _plan()
    eventlog = []
    operations, linux, wal = _shared_operations(plan, _observation(), eventlog)

    result = begin_offline_transaction(plan, PEER_PID, operations, linux, wal)

    assert result.status is not None
    assert eventlog[0] == "new_transaction_id"
    assert {
        event for event in eventlog if isinstance(event, tuple) and event[0] == "close"
    } == {
        ("close", 13),
        ("close", 12),
        ("close", 11),
    }
    close_index = _last_close(eventlog)
    observe_index = eventlog.index("observe")
    first_wal_index = min(
        index
        for index, event in enumerate(eventlog)
        if event in {"read", "append", "fsync_wal", "fsync_parent"}
    )
    assert close_index < observe_index < first_wal_index
    assert _wal_events(eventlog) == ["read", "append", "fsync_wal", "fsync_parent"]


def test_recover_eventlog_closes_all_linux_fds_before_observe_and_read():
    plan = _plan()
    started, _, _, source_wal = _begin(plan)
    assert started.status is not None
    eventlog = []
    operations, linux, wal = _shared_operations(
        plan,
        _observation(),
        eventlog,
        wal_records=source_wal.records,
    )

    result = recover_offline_transaction(plan, PEER_PID, operations, linux, wal)

    assert result.status == started.status
    close_index = _last_close(eventlog)
    observe_index = eventlog.index("observe")
    read_index = eventlog.index("read")
    assert close_index < observe_index < read_index
    assert "new_transaction_id" not in eventlog
    assert _wal_events(eventlog) == ["read"]


@pytest.mark.parametrize("failure", ["pidfd_open", "read_peer_mcs_pair"])
def test_begin_linux_failure_stops_before_observe_or_wal(failure):
    plan = _plan()
    eventlog = []
    operations, linux, wal = _shared_operations(
        plan,
        _observation(),
        eventlog,
        linux_errors={failure: RuntimeError(failure)},
    )

    result = begin_offline_transaction(plan, PEER_PID, operations, linux, wal)

    assert result.status is None
    assert result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED
    assert "observe" not in eventlog
    assert _wal_events(eventlog) == []


@pytest.mark.parametrize("failure", ["pidfd_open", "read_peer_mcs_pair"])
def test_recover_linux_failure_stops_before_observe_or_wal(failure):
    plan = _plan()
    started, _, _, source_wal = _begin(plan)
    assert started.status is not None
    eventlog = []
    operations, linux, wal = _shared_operations(
        plan,
        _observation(),
        eventlog,
        wal_records=source_wal.records,
        linux_errors={failure: RuntimeError(failure)},
    )

    result = recover_offline_transaction(plan, PEER_PID, operations, linux, wal)

    assert result.status is None
    assert result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED
    assert "observe" not in eventlog
    assert _wal_events(eventlog) == []


def _published_recovery_case():
    plan = _plan()
    statuses = [
        _status(plan, BrokerCheckpoint.CREATE_INTENT, _observation()),
        _status(
            plan,
            BrokerCheckpoint.STAGING_PINNED,
            _observation(BrokerObjectState.STAGING_EMPTY),
        ),
        _status(
            plan,
            BrokerCheckpoint.POPULATE_PENDING,
            _observation(BrokerObjectState.STAGING_PREFIX),
        ),
        _status(
            plan,
            BrokerCheckpoint.PUBLISH_INTENT,
            _observation(BrokerObjectState.STAGING_COMPLETE, population_index=1),
        ),
        _status(
            plan,
            BrokerCheckpoint.PUBLISHED,
            _observation(BrokerObjectState.FINAL_COMPLETE, population_index=1),
        ),
    ]
    return (
        plan,
        statuses,
        _observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.OLD, 1),
    )


def _switched_recovery_case():
    plan = _plan(operation=ChpbTransactionOperation.REPLACE)
    statuses = [
        _status(
            plan,
            BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
            _observation(BrokerObjectState.REPLACEMENT_ORIGINAL),
        ),
        _status(
            plan,
            BrokerCheckpoint.REPLACEMENT_PREPARED,
            _observation(BrokerObjectState.REPLACEMENT_PREPARED),
        ),
        _status(
            plan,
            BrokerCheckpoint.SWITCH_INTENT,
            _observation(BrokerObjectState.REPLACEMENT_PREPARED),
        ),
        _status(
            plan,
            BrokerCheckpoint.SWITCHED,
            _observation(BrokerObjectState.REPLACEMENT_SWITCHED),
        ),
    ]
    return (
        plan,
        statuses,
        _observation(
            BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.OLD, 0
        ),
    )


@pytest.mark.parametrize("case", [_published_recovery_case, _switched_recovery_case])
def test_registry_cas_next_checkpoint_gate_blocks_before_status_leak_or_write(case):
    plan, statuses, observation = case()
    proposal = decide_broker_recovery(statuses[-1], observation)
    assert proposal.action is BrokerRecoveryAction.PERSIST_CHECKPOINT
    assert proposal.next_checkpoint is BrokerCheckpoint.REGISTRY_CAS_INTENT

    wal = _wal_for_statuses(statuses)
    eventlog = []
    operations, linux, recovery_wal = _shared_operations(
        plan,
        observation,
        eventlog,
        wal_records=wal.records,
    )
    result = recover_offline_transaction(
        plan, PEER_PID, operations, linux, recovery_wal
    )

    assert result.status is None
    assert result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED
    assert result.decision.next_checkpoint is BrokerCheckpoint.BLOCKED_DRIFT
    assert _wal_events(eventlog) == ["read"]
    assert "append" not in eventlog
    assert "fsync_wal" not in eventlog
    assert "fsync_parent" not in eventlog


def test_new_module_imports_only_offline_contract_boundaries():
    source = (ROOT / "src/codex_master/fleet_home_broker.py").read_text()
    tree = ast.parse(source)
    imported = {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    imported.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    forbidden = {
        "os",
        "socket",
        "subprocess",
        "server",
        "fleet_home_broker_emulator",
    }
    assert not imported & forbidden
    assert {
        "fleet_home_broker_identity",
        "fleet_home_broker_linux",
        "fleet_home_broker_protocol",
        "fleet_home_broker_wal",
    } <= imported
