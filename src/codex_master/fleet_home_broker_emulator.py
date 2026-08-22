"""Deterministic, in-memory CHPB/2 transaction emulator."""

from dataclasses import dataclass
import hashlib

from .fleet_home_broker_protocol import (
    MAX_CHPB_EMULATOR_TRANSACTIONS,
    MAX_CHPB_GENERATION,
    MAX_CHPB_RESPONSE_CACHE,
    AttestHomeRequest,
    BrokerCheckpoint,
    BrokerRecoveryAction,
    BrokerReply,
    BrokerRequest,
    BrokerResultCode,
    ChpbMessageKind,
    CHPB_PROTOCOL,
    ChpbValidationCode,
    ChpbValidationError,
    HomeAttestation,
    PrincipalBinding,
    RecoveryDecision,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
    decide_broker_recovery,
    encode_chpb_message,
    is_checkpoint_transition_allowed,
    validate_chpb_message,
    validate_principal_binding,
    validate_transaction_binding,
    validate_transaction_status,
    _validate_attestation,
    _validate_observation,
)


@dataclass(frozen=True, slots=True)
class CachedReply:
    cache_key: str
    request_digest: str
    reply: BrokerReply


@dataclass(frozen=True, slots=True)
class EmulatorTransaction:
    status: TransactionStatus
    attestation: HomeAttestation
    created_ns: int
    updated_ns: int


@dataclass(frozen=True, slots=True)
class BrokerEmulatorState:
    transactions: tuple[EmulatorTransaction, ...]
    response_cache: tuple[CachedReply, ...]
    last_now_ns: int


@dataclass(frozen=True, slots=True)
class EmulatorStep:
    state: BrokerEmulatorState
    action: BrokerRecoveryAction | None
    reply: BrokerReply | None


def _fail(code: ChpbValidationCode):
    raise ChpbValidationError(code)


def _now(value: object, previous: int) -> int:
    if type(value) is not int:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if value < 0 or value > MAX_CHPB_GENERATION:
        _fail(ChpbValidationCode.INVALID_FIELD)
    if value < previous:
        _fail(ChpbValidationCode.INVALID_TRANSITION)
    return value


def _state(value: object) -> BrokerEmulatorState:
    if type(value) is not BrokerEmulatorState:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if type(value.transactions) is not tuple or type(value.response_cache) is not tuple:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if len(value.transactions) > MAX_CHPB_EMULATOR_TRANSACTIONS or len(value.response_cache) > MAX_CHPB_RESPONSE_CACHE:
        _fail(ChpbValidationCode.INVALID_FIELD)
    if type(value.last_now_ns) is not int or not 0 <= value.last_now_ns <= MAX_CHPB_GENERATION:
        _fail(ChpbValidationCode.INVALID_FIELD)
    previous = ""
    for transaction in value.transactions:
        if type(transaction) is not EmulatorTransaction:
            _fail(ChpbValidationCode.INVALID_TYPE)
        validate_transaction_status(transaction.status)
        _validate_attestation(transaction.attestation)
        if transaction.attestation.binding != transaction.status.binding:
            _fail(ChpbValidationCode.INVALID_BINDING)
        if type(transaction.created_ns) is not int or type(transaction.updated_ns) is not int or transaction.created_ns < 0 or transaction.updated_ns < transaction.created_ns or transaction.updated_ns > value.last_now_ns:
            _fail(ChpbValidationCode.INVALID_FIELD)
        key = transaction.status.binding.transaction_id
        if key <= previous:
            _fail(ChpbValidationCode.INVALID_FIELD)
        previous = key
    previous = ""
    for cached in value.response_cache:
        if type(cached) is not CachedReply:
            _fail(ChpbValidationCode.INVALID_TYPE)
        if type(cached.cache_key) is not str or type(cached.request_digest) is not str:
            _fail(ChpbValidationCode.INVALID_TYPE)
        if len(cached.cache_key) != 64 or len(cached.request_digest) != 64:
            _fail(ChpbValidationCode.INVALID_FIELD)
        if any(character not in "0123456789abcdef" for character in cached.cache_key + cached.request_digest):
            _fail(ChpbValidationCode.INVALID_FIELD)
        validate_chpb_message(cached.reply)
        if cached.cache_key <= previous:
            _fail(ChpbValidationCode.INVALID_FIELD)
        previous = cached.cache_key
    return value


def _replace_transaction(state: BrokerEmulatorState, transaction: EmulatorTransaction, now_ns: int) -> BrokerEmulatorState:
    values = [item if item.status.binding.transaction_id != transaction.status.binding.transaction_id else transaction for item in state.transactions]
    values.sort(key=lambda item: item.status.binding.transaction_id)
    return BrokerEmulatorState(tuple(values), state.response_cache, now_ns)


def make_emulator_state(*, now_ns: int) -> BrokerEmulatorState:
    _now(now_ns, 0)
    return BrokerEmulatorState((), (), now_ns)


def open_emulator_transaction(state: BrokerEmulatorState, status: TransactionStatus, attestation: HomeAttestation, *, now_ns: int) -> BrokerEmulatorState:
    state = _state(state)
    now_ns = _now(now_ns, state.last_now_ns)
    validate_transaction_status(status)
    _validate_attestation(attestation)
    if attestation.binding != status.binding:
        _fail(ChpbValidationCode.INVALID_BINDING)
    if status.terminal_result is not None:
        _fail(ChpbValidationCode.INVALID_TRANSITION)
    transaction_id = status.binding.transaction_id
    existing = next((item for item in state.transactions if item.status.binding.transaction_id == transaction_id), None)
    if existing is not None:
        if existing.status == status and existing.attestation == attestation:
            return state
        _fail(ChpbValidationCode.INVALID_BINDING)
    if len(state.transactions) >= MAX_CHPB_EMULATOR_TRANSACTIONS:
        _fail(ChpbValidationCode.INVALID_FIELD)
    transaction = EmulatorTransaction(status, attestation, now_ns, now_ns)
    values = (*state.transactions, transaction)
    values = tuple(sorted(values, key=lambda item: item.status.binding.transaction_id))
    return BrokerEmulatorState(values, state.response_cache, now_ns)


def persist_emulator_checkpoint(state: BrokerEmulatorState, transaction_id: str, expected: TransactionBinding, decision: RecoveryDecision, observation, *, now_ns: int) -> BrokerEmulatorState:
    state = _state(state)
    now_ns = _now(now_ns, state.last_now_ns)
    validate_transaction_binding(expected)
    _validate_observation(observation)
    transaction = next((item for item in state.transactions if item.status.binding.transaction_id == transaction_id), None)
    if transaction is None:
        _fail(ChpbValidationCode.INVALID_BINDING)
    if transaction.status.binding != expected:
        _fail(ChpbValidationCode.INVALID_BINDING)
    if type(decision) is not RecoveryDecision or decision.action is not BrokerRecoveryAction.PERSIST_CHECKPOINT or decision.next_checkpoint is None:
        _fail(ChpbValidationCode.INVALID_TRANSITION)
    actual = decide_broker_recovery(transaction.status, observation)
    if actual != decision or not is_checkpoint_transition_allowed(transaction.status.checkpoint, decision.next_checkpoint):
        _fail(ChpbValidationCode.INVALID_TRANSITION)
    terminal = {
        BrokerCheckpoint.COMMITTED: BrokerResultCode.COMMITTED,
        BrokerCheckpoint.ROLLED_BACK: BrokerResultCode.ROLLED_BACK,
        BrokerCheckpoint.BLOCKED_DRIFT: BrokerResultCode.BLOCKED_DRIFT,
    }.get(decision.next_checkpoint)
    status = TransactionStatus(transaction.status.binding, b2a_phase_for_checkpoint(decision.next_checkpoint), decision.next_checkpoint, observation, transaction.status.population_total, terminal)
    return _replace_transaction(state, EmulatorTransaction(status, transaction.attestation, transaction.created_ns, now_ns), now_ns)


def recover_emulator_transaction(state: BrokerEmulatorState, transaction_id: str, peer: PrincipalBinding, observation, *, now_ns: int) -> EmulatorStep:
    state = _state(state)
    validate_principal_binding(peer)
    now_ns = _now(now_ns, state.last_now_ns)
    transaction = next((item for item in state.transactions if item.status.binding.transaction_id == transaction_id), None)
    if transaction is None:
        _fail(ChpbValidationCode.INVALID_BINDING)
    if transaction.status.binding.principal != peer:
        _fail(ChpbValidationCode.INVALID_BINDING)
    decision = decide_broker_recovery(transaction.status, observation)
    if decision.action is BrokerRecoveryAction.PERSIST_CHECKPOINT:
        state = persist_emulator_checkpoint(state, transaction_id, transaction.status.binding, decision, observation, now_ns=now_ns)
    elif now_ns != state.last_now_ns:
        state = BrokerEmulatorState(state.transactions, state.response_cache, now_ns)
    return EmulatorStep(state, decision.action, None)


def _cache_key(peer: PrincipalBinding, transaction_id: str, request_id: str) -> str:
    value = repr((peer.agent_id, peer.manifest_generation, peer.unit_generation, peer.invocation_id, peer.fencing_epoch, transaction_id, request_id)).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _request_digest(message: BrokerRequest) -> str:
    return hashlib.sha256(encode_chpb_message(message)).hexdigest()


def _reply(request_id: str, result: BrokerResultCode, transaction: TransactionStatus | None = None, attestation: HomeAttestation | None = None) -> BrokerReply:
    return BrokerReply(CHPB_PROTOCOL, ChpbMessageKind.REPLY, request_id, result, transaction, attestation)


def _cached(state: BrokerEmulatorState, cache_key: str, digest: str) -> CachedReply | None:
    return next((item for item in state.response_cache if item.cache_key == cache_key), None)


def _store_reply(state: BrokerEmulatorState, cache_key: str, digest: str, reply: BrokerReply, now_ns: int) -> BrokerEmulatorState:
    if len(state.response_cache) >= MAX_CHPB_RESPONSE_CACHE:
        return state
    values = (*state.response_cache, CachedReply(cache_key, digest, reply))
    values = tuple(sorted(values, key=lambda item: item.cache_key))
    return BrokerEmulatorState(state.transactions, values, now_ns)


def handle_emulator_message(state: BrokerEmulatorState, peer: PrincipalBinding, message: BrokerRequest, *, now_ns: int) -> EmulatorStep:
    state = _state(state)
    validate_principal_binding(peer)
    validate_chpb_message(message)
    now_ns = _now(now_ns, state.last_now_ns)
    request_id = message.request_id
    cache_key = _cache_key(peer, message.transaction_id, request_id)
    digest = _request_digest(message)
    transaction = next((item for item in state.transactions if item.status.binding.transaction_id == message.transaction_id), None)
    if message.expected.agent_id != peer.agent_id:
        return EmulatorStep(state, None, _reply(request_id, BrokerResultCode.WRONG_PRINCIPAL))
    if transaction is not None:
        binding = transaction.status.binding
        transaction_peer = binding.principal
        if (transaction_peer.agent_id != peer.agent_id or transaction_peer.mcs_pair != peer.mcs_pair or transaction_peer.cgroup_dev != peer.cgroup_dev or transaction_peer.cgroup_ino != peer.cgroup_ino or transaction_peer.invocation_id != peer.invocation_id):
            return EmulatorStep(state, None, _reply(request_id, BrokerResultCode.WRONG_PRINCIPAL))
        if transaction_peer.fencing_epoch != peer.fencing_epoch or message.expected.fencing_epoch != peer.fencing_epoch:
            return EmulatorStep(state, None, _reply(request_id, BrokerResultCode.FENCED))
        if (transaction_peer.manifest_generation != peer.manifest_generation or transaction_peer.unit_generation != peer.unit_generation or message.expected.manifest_generation != peer.manifest_generation or message.expected.unit_generation != peer.unit_generation):
            return EmulatorStep(state, None, _reply(request_id, BrokerResultCode.STALE_GENERATION))
        if message.expected.policy_generation != binding.policy.policy_generation or message.expected.projection_digest != binding.policy.projection_digest:
            return EmulatorStep(state, None, _reply(request_id, BrokerResultCode.STALE_GENERATION))
    else:
        if message.expected.fencing_epoch != peer.fencing_epoch:
            return EmulatorStep(state, None, _reply(request_id, BrokerResultCode.FENCED))
        if message.expected.manifest_generation != peer.manifest_generation or message.expected.unit_generation != peer.unit_generation:
            return EmulatorStep(state, None, _reply(request_id, BrokerResultCode.STALE_GENERATION))
    cached = _cached(state, cache_key, digest)
    if cached is not None:
        if cached.request_digest == digest:
            return EmulatorStep(state, None, cached.reply)
        return EmulatorStep(state, None, _reply(request_id, BrokerResultCode.REQUEST_ID_REUSE))
    if transaction is None:
        reply = _reply(request_id, BrokerResultCode.TRANSACTION_NOT_FOUND)
        if len(state.response_cache) >= MAX_CHPB_RESPONSE_CACHE:
            return EmulatorStep(BrokerEmulatorState(state.transactions, state.response_cache, now_ns), None, _reply(request_id, BrokerResultCode.CACHE_FULL))
        return EmulatorStep(_store_reply(state, cache_key, digest, reply, now_ns), None, reply)
    status = transaction.status
    if status.terminal_result is None:
        reply = _reply(request_id, BrokerResultCode.PENDING, status)
    elif isinstance(message, AttestHomeRequest) and status.terminal_result is BrokerResultCode.COMMITTED:
        reply = _reply(request_id, BrokerResultCode.OK, status, transaction.attestation)
    else:
        reply = _reply(request_id, status.terminal_result, status)
    if len(state.response_cache) >= MAX_CHPB_RESPONSE_CACHE:
        return EmulatorStep(BrokerEmulatorState(state.transactions, state.response_cache, now_ns), None, _reply(request_id, BrokerResultCode.CACHE_FULL))
    return EmulatorStep(_store_reply(state, cache_key, digest, reply, now_ns), None, reply)
