import dataclasses

import pytest

from codex_master.fleet_home_broker_emulator import (
    BrokerEmulatorState,
    EmulatorTransaction,
    handle_emulator_message,
    make_emulator_state,
    open_emulator_transaction,
    persist_emulator_checkpoint,
    recover_emulator_transaction,
)
from codex_master.fleet_home_broker_protocol import (
    CANONICAL_AGENT_HOME,
    CHPB_PROTOCOL,
    AttestHomeRequest,
    B2aRecoveryPhase,
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRecoveryAction,
    BrokerRegistryState,
    BrokerResultCode,
    ChpbMessageKind,
    ChpbTransactionOperation,
    ChpbValidationError,
    DirectoryIdentity,
    HomeAttestation,
    PolicyBinding,
    PrincipalBinding,
    QueryTransactionRequest,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
    decide_broker_recovery,
    encode_chpb_message,
)


AGENT = "bee_1"
A = "a" * 64
INVOCATION = "1" * 32
REQUEST_ID = INVOCATION
T = "2" * 32
U = "3" * 32


def principal(**changes):
    values = {"agent_id": AGENT, "manifest_generation": 3, "unit_generation": 9, "cgroup_dev": 0, "cgroup_ino": 1, "invocation_id": INVOCATION, "mcs_pair": "c0,c1", "fencing_epoch": 4}
    values.update(changes)
    return PrincipalBinding(**values)


def operation_for_checkpoint(checkpoint):
    if checkpoint in {
        BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
        BrokerCheckpoint.REPLACEMENT_PREPARED,
        BrokerCheckpoint.SWITCH_INTENT,
        BrokerCheckpoint.SWITCHED,
    }:
        return ChpbTransactionOperation.REPLACE
    if checkpoint in {BrokerCheckpoint.DEPROVISION_INTENT, BrokerCheckpoint.DEPROVISIONED}:
        return ChpbTransactionOperation.DEPROVISION
    return ChpbTransactionOperation.PROVISION


def bind(p=None, checkpoint=BrokerCheckpoint.CREATE_INTENT):
    return TransactionBinding(operation_for_checkpoint(checkpoint), T, U, p or principal(), PolicyBinding(7, A))


def obs(state=BrokerObjectState.ABSENT, registry=BrokerRegistryState.NOT_APPLICABLE, index=0):
    return BrokerObservation(state, registry, index)


def stat(checkpoint=BrokerCheckpoint.CREATE_INTENT, observation=None, total=1, p=None, terminal=None):
    observation = observation or obs()
    return TransactionStatus(bind(p, checkpoint), b2a_phase_for_checkpoint(checkpoint), checkpoint, observation, total, terminal)


def attest(status_value):
    return HomeAttestation(status_value.binding, CANONICAL_AGENT_HOME, DirectoryIdentity(0, 1, 0o40700), A, "c0,c1")


def request(transaction_id=T, request_id=REQUEST_ID, expected_agent=AGENT):
    from codex_master.fleet_home_broker_protocol import BindingExpectation
    return AttestHomeRequest(CHPB_PROTOCOL, ChpbMessageKind.ATTEST_HOME, request_id, transaction_id, BindingExpectation(expected_agent, 3, 9, 7, A, 4))


def opened(state=None, status_value=None, now_ns=1):
    state = state or make_emulator_state(now_ns=0)
    status_value = status_value or stat()
    return open_emulator_transaction(state, status_value, attest(status_value), now_ns=now_ns)


def test_make_emulator_state_is_empty_immutable_and_uses_injected_now_ns():
    state = make_emulator_state(now_ns=9)
    assert state == BrokerEmulatorState((), (), 9)
    with pytest.raises(dataclasses.FrozenInstanceError):
        state.last_now_ns = 10


def test_open_transaction_sorts_and_replays_identical_input_as_noop():
    first = opened()
    second = opened(first, stat(), 2)
    assert second == first
    other = stat(p=principal(agent_id="bee_2"))
    with pytest.raises(ChpbValidationError):
        open_emulator_transaction(first, other, attest(other), now_ns=2)


def test_open_transaction_rejects_conflicting_id_and_capacity_overflow():
    state = opened()
    with pytest.raises(ChpbValidationError):
        open_emulator_transaction(state, stat(checkpoint=BrokerCheckpoint.STAGING_PINNED), attest(stat(checkpoint=BrokerCheckpoint.STAGING_PINNED)), now_ns=2)
    full = make_emulator_state(now_ns=0)
    for n in range(32):
        txid = f"{n + 10:032x}"
        p = principal()
        s = TransactionStatus(TransactionBinding(ChpbTransactionOperation.PROVISION, txid, U, p, PolicyBinding(7, A)), B2aRecoveryPhase.ABSENT_CREATE_PENDING, BrokerCheckpoint.CREATE_INTENT, obs(), 1, None)
        full = open_emulator_transaction(full, s, HomeAttestation(s.binding, CANONICAL_AGENT_HOME, DirectoryIdentity(0, 1, 0o40700), A, "c0,c1"), now_ns=n)
    with pytest.raises(ChpbValidationError):
        open_emulator_transaction(full, stat(), attest(stat()), now_ns=33)


def test_persist_checkpoint_enforces_binding_transition_and_monotonic_now_ns():
    state = opened()
    current = state.transactions[0].status
    decision = decide_broker_recovery(current, obs(BrokerObjectState.STAGING_EMPTY))
    state = persist_emulator_checkpoint(state, T, current.binding, decision, obs(BrokerObjectState.STAGING_EMPTY), now_ns=2)
    assert state.transactions[0].status.checkpoint is BrokerCheckpoint.STAGING_PINNED
    with pytest.raises(ChpbValidationError):
        persist_emulator_checkpoint(state, T, current.binding, decision, obs(BrokerObjectState.STAGING_EMPTY), now_ns=1)


def test_recover_each_crash_matrix_row_is_deterministic():
    state = opened()
    step = recover_emulator_transaction(state, T, principal(), obs(BrokerObjectState.STAGING_EMPTY), now_ns=2)
    assert step.action is BrokerRecoveryAction.PERSIST_CHECKPOINT
    assert step.state.transactions[0].status.checkpoint is BrokerCheckpoint.STAGING_PINNED


@pytest.mark.parametrize("object_state", [BrokerObjectState.STAGING_AND_FINAL, BrokerObjectState.DRIFT])
def test_recover_publish_conflicts_blocks_without_persisting_and_replays_deterministically(object_state):
    initial = stat(BrokerCheckpoint.PUBLISH_INTENT, obs(BrokerObjectState.STAGING_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1), 1)
    state = opened(status_value=initial)
    conflicting = obs(object_state, BrokerRegistryState.NOT_APPLICABLE, 1)
    first = recover_emulator_transaction(state, T, principal(), conflicting, now_ns=2)
    second = recover_emulator_transaction(first.state, T, principal(), conflicting, now_ns=3)
    assert first.action is BrokerRecoveryAction.RETURN_BLOCKED
    assert second.action is BrokerRecoveryAction.RETURN_BLOCKED
    assert first.state.transactions == state.transactions
    assert second.state.transactions == state.transactions
    assert first.state.transactions[0].status == initial
    assert second.state.transactions[0].status == initial


@pytest.mark.parametrize(
    "checkpoint,current,registry,index,total,action,target,status_terminal",
    [
        (BrokerCheckpoint.CREATE_INTENT, BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE, 0, 1, BrokerRecoveryAction.CREATE_STAGING, None, None),
        (BrokerCheckpoint.CREATE_INTENT, BrokerObjectState.STAGING_EMPTY, BrokerRegistryState.NOT_APPLICABLE, 0, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.STAGING_PINNED, None),
        (BrokerCheckpoint.STAGING_PINNED, BrokerObjectState.STAGING_EMPTY, BrokerRegistryState.NOT_APPLICABLE, 0, 1, BrokerRecoveryAction.POPULATE_NEXT, None, None),
        (BrokerCheckpoint.STAGING_PINNED, BrokerObjectState.STAGING_PREFIX, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.POPULATE_PENDING, None),
        (BrokerCheckpoint.POPULATE_PENDING, BrokerObjectState.STAGING_PREFIX, BrokerRegistryState.NOT_APPLICABLE, 0, 2, BrokerRecoveryAction.POPULATE_NEXT, None, None),
        (BrokerCheckpoint.POPULATE_PENDING, BrokerObjectState.STAGING_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.PUBLISH_INTENT, None),
        (BrokerCheckpoint.PUBLISH_INTENT, BrokerObjectState.STAGING_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.PUBLISH_HOME, None, None),
        (BrokerCheckpoint.PUBLISH_INTENT, BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.PUBLISHED, None),
        (BrokerCheckpoint.PUBLISHED, BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.OLD, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.REGISTRY_CAS_INTENT, None),
        (BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT, BrokerObjectState.REPLACEMENT_ORIGINAL, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.PREPARE_REPLACEMENT, None, None),
        (BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT, BrokerObjectState.REPLACEMENT_PREPARED, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.REPLACEMENT_PREPARED, None),
        (BrokerCheckpoint.REPLACEMENT_PREPARED, BrokerObjectState.REPLACEMENT_PREPARED, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.SWITCH_INTENT, None),
        (BrokerCheckpoint.SWITCH_INTENT, BrokerObjectState.REPLACEMENT_PREPARED, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.SWITCH_REPLACEMENT, None, None),
        (BrokerCheckpoint.SWITCH_INTENT, BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.SWITCHED, None),
        (BrokerCheckpoint.SWITCHED, BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.OLD, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.REGISTRY_CAS_INTENT, None),
        (BrokerCheckpoint.REGISTRY_CAS_INTENT, BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.OLD, 1, 1, BrokerRecoveryAction.CAS_REGISTRY, None, None),
        (BrokerCheckpoint.REGISTRY_CAS_INTENT, BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.CURRENT, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.FINALIZE_INTENT, None),
        (BrokerCheckpoint.REGISTRY_CAS_INTENT, BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.FOREIGN, 1, 1, BrokerRecoveryAction.RETURN_BLOCKED, None, None),
        (BrokerCheckpoint.FINALIZE_INTENT, BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.CURRENT, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.COMMITTED, None),
        (BrokerCheckpoint.ROLLBACK_INTENT, BrokerObjectState.ROLLBACK_READY, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.ROLLBACK, None, None),
        (BrokerCheckpoint.ROLLBACK_INTENT, BrokerObjectState.ROLLED_BACK, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.ROLLED_BACK, None),
        (BrokerCheckpoint.DEPROVISION_INTENT, BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.REGISTRY_CAS_INTENT, None),
        (BrokerCheckpoint.DEPROVISION_INTENT, BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.DEPROVISIONED, None),
        (BrokerCheckpoint.COMMITTED, BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1, 1, BrokerRecoveryAction.RETURN_COMMITTED, BrokerCheckpoint.COMMITTED, BrokerResultCode.COMMITTED),
        (BrokerCheckpoint.ROLLED_BACK, BrokerObjectState.ROLLED_BACK, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.RETURN_ROLLED_BACK, BrokerCheckpoint.ROLLED_BACK, BrokerResultCode.ROLLED_BACK),
        (BrokerCheckpoint.DEPROVISIONED, BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE, 1, 1, BrokerRecoveryAction.RETURN_COMMITTED, BrokerCheckpoint.DEPROVISIONED, BrokerResultCode.COMMITTED),
        (BrokerCheckpoint.BLOCKED_DRIFT, BrokerObjectState.DRIFT, BrokerRegistryState.FOREIGN, 1, 1, BrokerRecoveryAction.RETURN_BLOCKED, BrokerCheckpoint.BLOCKED_DRIFT, BrokerResultCode.BLOCKED_DRIFT),
    ],
)
def test_recover_complete_crash_matrix(checkpoint, current, registry, index, total, action, target, status_terminal):
    status_value = stat(checkpoint, obs(current, registry, index), total, terminal=status_terminal)
    if status_terminal is None:
        state = opened(status_value=status_value)
    else:
        state = BrokerEmulatorState((EmulatorTransaction(status_value, attest(status_value), 0, 0),), (), 0)
    step = recover_emulator_transaction(state, T, principal(), obs(current, registry, index), now_ns=2)
    assert step.action is action
    assert step.reply is None
    if target is not None:
        assert step.state.transactions[0].status.checkpoint is target
        expected_terminal = {
            BrokerCheckpoint.COMMITTED: BrokerResultCode.COMMITTED,
            BrokerCheckpoint.DEPROVISIONED: BrokerResultCode.COMMITTED,
            BrokerCheckpoint.ROLLED_BACK: BrokerResultCode.ROLLED_BACK,
            BrokerCheckpoint.BLOCKED_DRIFT: BrokerResultCode.BLOCKED_DRIFT,
        }.get(target)
        assert step.state.transactions[0].status.terminal_result is expected_terminal


def test_deprovision_emulator_persists_cas_then_finalize_before_cleanup_action():
    initial = stat(
        BrokerCheckpoint.DEPROVISION_INTENT,
        obs(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1),
        1,
    )
    initial_state = opened(status_value=initial)

    cas_intent = recover_emulator_transaction(
        initial_state,
        T,
        principal(),
        obs(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1),
        now_ns=2,
    )
    assert cas_intent.action is BrokerRecoveryAction.PERSIST_CHECKPOINT
    assert cas_intent.state.transactions[0].status.checkpoint is BrokerCheckpoint.REGISTRY_CAS_INTENT

    finalize_intent = recover_emulator_transaction(
        cas_intent.state,
        T,
        principal(),
        obs(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1),
        now_ns=3,
    )
    assert finalize_intent.action is BrokerRecoveryAction.PERSIST_CHECKPOINT
    assert finalize_intent.state.transactions[0].status.checkpoint is BrokerCheckpoint.FINALIZE_INTENT

    cleanup = recover_emulator_transaction(
        finalize_intent.state,
        T,
        principal(),
        obs(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1),
        now_ns=4,
    )
    assert cleanup.action is BrokerRecoveryAction.DEPROVISION_HOME
    assert cleanup.state.transactions == finalize_intent.state.transactions


def _committed_state():
    status_value = stat(BrokerCheckpoint.FINALIZE_INTENT, obs(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1), 1)
    state = opened(status_value=status_value)
    decision = decide_broker_recovery(status_value, status_value.observation)
    state = persist_emulator_checkpoint(state, T, status_value.binding, decision, status_value.observation, now_ns=2)
    return state, state.transactions[0].status


def test_same_request_same_principal_returns_byte_identical_cached_reply():
    state, _ = _committed_state()
    first = handle_emulator_message(state, principal(), request(), now_ns=2)
    second = handle_emulator_message(first.state, principal(), request(), now_ns=3)
    assert encode_chpb_message(first.reply) == encode_chpb_message(second.reply)
    assert second.state == first.state


def test_same_request_id_different_payload_returns_stale_generation_before_reuse():
    state, _ = _committed_state()
    first = handle_emulator_message(state, principal(), request(), now_ns=2)
    from codex_master.fleet_home_broker_protocol import BindingExpectation
    changed = dataclasses.replace(request(), expected=BindingExpectation(AGENT, 3, 9, 8, A, 4))
    second = handle_emulator_message(first.state, principal(), changed, now_ns=3)
    assert second.reply.result is BrokerResultCode.STALE_GENERATION


def test_same_cache_key_changed_request_kind_returns_request_id_reuse_without_payload():
    state, _ = _committed_state()
    original = request()
    first = handle_emulator_message(state, principal(), original, now_ns=2)
    changed_kind = QueryTransactionRequest(CHPB_PROTOCOL, ChpbMessageKind.QUERY_TRANSACTION, original.request_id, original.transaction_id, original.expected)
    second = handle_emulator_message(first.state, principal(), changed_kind, now_ns=3)
    assert first.reply.result is BrokerResultCode.OK
    assert second.reply.result is BrokerResultCode.REQUEST_ID_REUSE
    assert second.reply.transaction is None
    assert second.reply.attestation is None
    assert second.state == first.state


@pytest.mark.parametrize("changes", [{"mcs_pair": "c0,c2"}, {"cgroup_dev": 1}, {"cgroup_ino": 2}])
def test_foreign_mcs_or_cgroup_replay_is_rejected_before_cache_lookup(changes):
    state, _ = _committed_state()
    first = handle_emulator_message(state, principal(), request(), now_ns=2)
    replay = handle_emulator_message(first.state, principal(**changes), request(), now_ns=3)
    assert replay.reply.result is BrokerResultCode.WRONG_PRINCIPAL
    assert replay.reply.transaction is None
    assert replay.reply.attestation is None
    assert replay.state == first.state


@pytest.mark.parametrize("expected_changes", [{"policy_generation": 8}, {"projection_digest": "b" * 64}])
def test_policy_generation_and_projection_are_stale_before_request_id_reuse(expected_changes):
    state, _ = _committed_state()
    first = handle_emulator_message(state, principal(), request(), now_ns=2)
    from codex_master.fleet_home_broker_protocol import BindingExpectation
    changed = dataclasses.replace(request(), expected=BindingExpectation(AGENT, 3, 9, expected_changes.get("policy_generation", 7), expected_changes.get("projection_digest", A), 4))
    replay = handle_emulator_message(first.state, principal(), changed, now_ns=3)
    assert replay.reply.result is BrokerResultCode.STALE_GENERATION


def test_wrong_principal_fenced_and_stale_generation_precede_lookup():
    state, _ = _committed_state()
    assert handle_emulator_message(state, principal(agent_id="bee_2"), request(), now_ns=2).reply.result is BrokerResultCode.WRONG_PRINCIPAL
    assert handle_emulator_message(state, principal(fencing_epoch=5), request(), now_ns=2).reply.result is BrokerResultCode.FENCED
    assert handle_emulator_message(state, principal(manifest_generation=8), request(), now_ns=2).reply.result is BrokerResultCode.STALE_GENERATION
    assert handle_emulator_message(state, principal(unit_generation=10), request(), now_ns=2).reply.result is BrokerResultCode.STALE_GENERATION


def test_attest_home_for_committed_bound_transaction_returns_stored_attestation():
    state, status_value = _committed_state()
    step = handle_emulator_message(state, principal(), request(), now_ns=2)
    assert step.reply.result is BrokerResultCode.OK
    assert step.reply.transaction == status_value
    assert step.reply.attestation == state.transactions[0].attestation
    assert step.reply.request_id == REQUEST_ID
    assert len(step.state.response_cache) == 1


def test_attest_home_for_deprovisioned_transaction_returns_terminal_fact_without_attestation():
    initial = stat(
        BrokerCheckpoint.DEPROVISION_INTENT,
        obs(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1),
        1,
    )
    state = opened(status_value=initial)
    recovered = recover_emulator_transaction(
        state,
        T,
        principal(),
        obs(BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE, 1),
        now_ns=2,
    )
    terminal = recovered.state.transactions[0].status
    assert recovered.action is BrokerRecoveryAction.PERSIST_CHECKPOINT
    assert terminal.checkpoint is BrokerCheckpoint.DEPROVISIONED
    assert terminal.terminal_result is BrokerResultCode.COMMITTED

    step = handle_emulator_message(recovered.state, principal(), request(), now_ns=3)

    assert step.reply.result is BrokerResultCode.COMMITTED
    assert step.reply.transaction == terminal
    assert step.reply.attestation is None
    assert encode_chpb_message(step.reply)


def test_terminal_reconnect_with_new_request_id_returns_same_terminal_fact():
    state, status_value = _committed_state()
    step = handle_emulator_message(state, principal(), request(request_id="5" * 32), now_ns=2)
    assert step.reply.result is BrokerResultCode.OK
    assert step.reply.transaction == status_value


def test_cache_full_rejects_new_entry_but_preserves_existing_replay():
    state, _ = _committed_state()
    for n in range(32):
        rid = f"{n + 10:032x}"
        state = handle_emulator_message(state, principal(), request(request_id=rid), now_ns=n + 2).state
    full = handle_emulator_message(state, principal(), request(request_id="f" * 32), now_ns=40)
    assert full.reply.result is BrokerResultCode.CACHE_FULL
    assert len(full.state.response_cache) == 32
    replay = handle_emulator_message(full.state, principal(), request(request_id="0000000000000000000000000000000a"), now_ns=41)
    assert replay.reply.result is BrokerResultCode.OK


def test_equal_inputs_produce_equal_sorted_state_and_reply():
    state, _ = _committed_state()
    a = handle_emulator_message(state, principal(), request(), now_ns=2)
    b = handle_emulator_message(state, principal(), request(), now_ns=2)
    assert a == b
    assert tuple(tx.status.binding.transaction_id for tx in a.state.transactions) == tuple(sorted(tx.status.binding.transaction_id for tx in a.state.transactions))


def test_pb_s1_modules_have_no_forbidden_imports_or_nondeterministic_calls():
    import pathlib
    for name in ("fleet_home_broker_protocol.py", "fleet_home_broker_emulator.py"):
        source = pathlib.Path("src/codex_master", name).read_text()
        assert "fleet_home_recovery" not in source
        for forbidden in ("datetime.now", "time.time", "time.monotonic", "uuid.", "random.", "server", "sqlite", "systemd", "selinux"):
            assert forbidden not in source.lower()
