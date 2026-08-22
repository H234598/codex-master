"""Pure CHPB/2 contract types and deterministic recovery rules."""

from dataclasses import dataclass
from enum import Enum
import json
import re


CHPB_PROTOCOL = "CHPB/2"
CHPB_SCHEMA_VERSION = 2
MAX_CHPB_MESSAGE_BYTES = 64 * 1024
MAX_CHPB_AGENT_ID_BYTES = 128
MAX_CHPB_CANONICAL_PATH_BYTES = 64
MAX_CHPB_EMULATOR_TRANSACTIONS = 32
MAX_CHPB_RESPONSE_CACHE = 32
MAX_CHPB_POPULATION_ENTRIES = 256
MAX_CHPB_NESTING_DEPTH = 5
MAX_CHPB_OBJECT_FIELDS = 16
MAX_CHPB_GENERATION = 2**63 - 1
MAX_CHPB_DEVICE = 2**63 - 1
MAX_CHPB_INODE = 2**63 - 1
MAX_CHPB_MCS_CATEGORY = 1023
CANONICAL_AGENT_HOME = "/run/codex-master-agent/home"


class ChpbValidationCode(str, Enum):
    INVALID_TYPE = "invalid_type"
    INVALID_FIELD = "invalid_field"
    UNKNOWN_FIELD = "unknown_field"
    DUPLICATE_KEY = "duplicate_key"
    INVALID_UTF8 = "invalid_utf8"
    MESSAGE_TOO_LARGE = "message_too_large"
    NON_CANONICAL = "non_canonical"
    UNSUPPORTED_PROTOCOL = "unsupported_protocol"
    INVALID_BINDING = "invalid_binding"
    INVALID_TRANSITION = "invalid_transition"


class ChpbMessageKind(str, Enum):
    ATTEST_HOME = "attest_home"
    QUERY_TRANSACTION = "query_transaction"
    GET_TERMINAL_RESULT = "get_terminal_result"
    REPLY = "reply"


class BrokerResultCode(str, Enum):
    OK = "ok"
    PENDING = "pending"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    BLOCKED_DRIFT = "blocked_drift"
    INVALID_MESSAGE = "invalid_message"
    WRONG_PRINCIPAL = "wrong_principal"
    STALE_PEER = "stale_peer"
    STALE_GENERATION = "stale_generation"
    FENCED = "fenced"
    REQUEST_ID_REUSE = "request_id_reuse"
    TRANSACTION_ID_REUSE = "transaction_id_reuse"
    TRANSACTION_NOT_FOUND = "transaction_not_found"
    ATTESTATION_MISMATCH = "attestation_mismatch"
    CACHE_FULL = "cache_full"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    INTERNAL_ERROR = "internal_error"


class B2aRecoveryPhase(str, Enum):
    ABSENT_CREATE_PENDING = "absent_create_pending"
    ABSENT_PIN_PENDING = "absent_pin_pending"
    ABSENT_POPULATE_PENDING = "absent_populate_pending"
    ABSENT_PUBLISH_PENDING = "absent_publish_pending"
    ABSENT_PUBLISHED = "absent_published"
    PREPARE_PENDING = "prepare_pending"
    PREPARED = "prepared"
    SWITCH_PENDING = "switch_pending"
    SWITCHED = "switched"
    CAS_PENDING = "cas_pending"
    COMMIT_PENDING = "commit_pending"
    ROLLBACK_PENDING = "rollback_pending"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    BLOCKED = "blocked"


class BrokerCheckpoint(str, Enum):
    CREATE_INTENT = "create_intent"
    STAGING_PINNED = "staging_pinned"
    POPULATE_PENDING = "populate_pending"
    PUBLISH_INTENT = "publish_intent"
    PUBLISHED = "published"
    REPLACEMENT_PREPARE_INTENT = "replacement_prepare_intent"
    REPLACEMENT_PREPARED = "replacement_prepared"
    SWITCH_INTENT = "switch_intent"
    SWITCHED = "switched"
    REGISTRY_CAS_INTENT = "registry_cas_intent"
    FINALIZE_INTENT = "finalize_intent"
    ROLLBACK_INTENT = "rollback_intent"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    BLOCKED_DRIFT = "blocked_drift"


class BrokerObjectState(str, Enum):
    ABSENT = "absent"
    STAGING_EMPTY = "staging_empty"
    STAGING_PREFIX = "staging_prefix"
    STAGING_COMPLETE = "staging_complete"
    FINAL_COMPLETE = "final_complete"
    STAGING_AND_FINAL = "staging_and_final"
    REPLACEMENT_ORIGINAL = "replacement_original"
    REPLACEMENT_PREPARED = "replacement_prepared"
    REPLACEMENT_SWITCHED = "replacement_switched"
    ROLLBACK_READY = "rollback_ready"
    ROLLED_BACK = "rolled_back"
    DRIFT = "drift"


class BrokerRegistryState(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    OLD = "old"
    CURRENT = "current"
    FOREIGN = "foreign"


class BrokerRecoveryAction(str, Enum):
    CREATE_STAGING = "create_staging"
    POPULATE_NEXT = "populate_next"
    PUBLISH_HOME = "publish_home"
    PREPARE_REPLACEMENT = "prepare_replacement"
    SWITCH_REPLACEMENT = "switch_replacement"
    CAS_REGISTRY = "cas_registry"
    ROLLBACK = "rollback"
    PERSIST_CHECKPOINT = "persist_checkpoint"
    RETURN_COMMITTED = "return_committed"
    RETURN_ROLLED_BACK = "return_rolled_back"
    RETURN_BLOCKED = "return_blocked"


class ChpbValidationError(ValueError):
    """Stable, machine-readable validation failure."""

    __slots__ = ("code",)
    code: ChpbValidationCode

    def __init__(self, code: ChpbValidationCode):
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class PrincipalBinding:
    agent_id: str
    manifest_generation: int
    unit_generation: int
    cgroup_dev: int
    cgroup_ino: int
    invocation_id: str
    mcs_pair: str
    fencing_epoch: int


@dataclass(frozen=True, slots=True)
class PolicyBinding:
    policy_generation: int
    projection_digest: str


@dataclass(frozen=True, slots=True)
class TransactionBinding:
    transaction_id: str
    store_uuid: str
    principal: PrincipalBinding
    policy: PolicyBinding


@dataclass(frozen=True, slots=True)
class BindingExpectation:
    agent_id: str
    manifest_generation: int
    unit_generation: int
    policy_generation: int
    projection_digest: str
    fencing_epoch: int


@dataclass(frozen=True, slots=True)
class DirectoryIdentity:
    dev: int
    ino: int
    mode: int


@dataclass(frozen=True, slots=True)
class BrokerObservation:
    object_state: BrokerObjectState
    registry_state: BrokerRegistryState
    population_index: int


@dataclass(frozen=True, slots=True)
class TransactionStatus:
    binding: TransactionBinding
    b2a_phase: B2aRecoveryPhase
    checkpoint: BrokerCheckpoint
    observation: BrokerObservation
    population_total: int
    terminal_result: BrokerResultCode | None


@dataclass(frozen=True, slots=True)
class HomeAttestation:
    binding: TransactionBinding
    canonical_path: str
    directory: DirectoryIdentity
    manifest_digest: str
    mcs_pair: str


@dataclass(frozen=True, slots=True)
class AttestHomeRequest:
    protocol: str
    kind: ChpbMessageKind
    request_id: str
    transaction_id: str
    expected: BindingExpectation


@dataclass(frozen=True, slots=True)
class QueryTransactionRequest:
    protocol: str
    kind: ChpbMessageKind
    request_id: str
    transaction_id: str
    expected: BindingExpectation


@dataclass(frozen=True, slots=True)
class GetTerminalResultRequest:
    protocol: str
    kind: ChpbMessageKind
    request_id: str
    transaction_id: str
    expected: BindingExpectation


@dataclass(frozen=True, slots=True)
class BrokerReply:
    protocol: str
    kind: ChpbMessageKind
    request_id: str
    result: BrokerResultCode
    transaction: TransactionStatus | None
    attestation: HomeAttestation | None


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    action: BrokerRecoveryAction
    next_b2a_phase: B2aRecoveryPhase | None
    next_checkpoint: BrokerCheckpoint | None
    result: BrokerResultCode


BrokerRequest = AttestHomeRequest | QueryTransactionRequest | GetTerminalResultRequest
ChpbMessage = BrokerRequest | BrokerReply


_HEX32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_AGENT = re.compile(r"[a-z][a-z0-9_-]{0,127}\Z", re.ASCII)
_MCS = re.compile(r"c(0|[1-9][0-9]{0,3}),c(0|[1-9][0-9]{0,3})\Z", re.ASCII)


def _fail(code: ChpbValidationCode):
    raise ChpbValidationError(code)


def _string(value: object, pattern: re.Pattern[str], max_bytes: int | None = None) -> str:
    if type(value) is not str:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if max_bytes is not None and len(value.encode("utf-8")) > max_bytes:
        _fail(ChpbValidationCode.INVALID_FIELD)
    if pattern.fullmatch(value) is None:
        _fail(ChpbValidationCode.INVALID_FIELD)
    return value


def _integer(value: object, low: int, high: int) -> int:
    if type(value) is not int:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if value < low or value > high:
        _fail(ChpbValidationCode.INVALID_FIELD)
    return value


def _enum(value: object, klass: type[Enum]):
    if type(value) is not klass:
        _fail(ChpbValidationCode.INVALID_TYPE)
    return value


def _digest(value: object, size: int) -> str:
    return _string(value, _HEX32 if size == 32 else _HEX64)


def _mcs(value: object) -> str:
    text = _string(value, _MCS)
    left, right = (int(part[1:]) for part in text.split(","))
    if not 0 <= left < right <= MAX_CHPB_MCS_CATEGORY:
        _fail(ChpbValidationCode.INVALID_FIELD)
    return text


def _validate_directory(value: object) -> DirectoryIdentity:
    if type(value) is not DirectoryIdentity:
        _fail(ChpbValidationCode.INVALID_TYPE)
    _integer(value.dev, 0, MAX_CHPB_DEVICE)
    _integer(value.ino, 1, MAX_CHPB_INODE)
    _integer(value.mode, 0o40700, 0o40700)
    return value


def validate_principal_binding(value: object) -> PrincipalBinding:
    if type(value) is not PrincipalBinding:
        _fail(ChpbValidationCode.INVALID_TYPE)
    _string(value.agent_id, _AGENT, MAX_CHPB_AGENT_ID_BYTES)
    _integer(value.manifest_generation, 1, MAX_CHPB_GENERATION)
    _integer(value.unit_generation, 1, MAX_CHPB_GENERATION)
    _integer(value.cgroup_dev, 0, MAX_CHPB_DEVICE)
    _integer(value.cgroup_ino, 1, MAX_CHPB_INODE)
    _digest(value.invocation_id, 32)
    _mcs(value.mcs_pair)
    _integer(value.fencing_epoch, 0, MAX_CHPB_GENERATION)
    return value


def _validate_policy(value: object) -> PolicyBinding:
    if type(value) is not PolicyBinding:
        _fail(ChpbValidationCode.INVALID_TYPE)
    _integer(value.policy_generation, 1, MAX_CHPB_GENERATION)
    _digest(value.projection_digest, 64)
    return value


def validate_transaction_binding(value: object) -> TransactionBinding:
    if type(value) is not TransactionBinding:
        _fail(ChpbValidationCode.INVALID_TYPE)
    _digest(value.transaction_id, 32)
    _digest(value.store_uuid, 32)
    validate_principal_binding(value.principal)
    _validate_policy(value.policy)
    return value


def _validate_expectation(value: object) -> BindingExpectation:
    if type(value) is not BindingExpectation:
        _fail(ChpbValidationCode.INVALID_TYPE)
    _string(value.agent_id, _AGENT, MAX_CHPB_AGENT_ID_BYTES)
    _integer(value.manifest_generation, 1, MAX_CHPB_GENERATION)
    _integer(value.unit_generation, 1, MAX_CHPB_GENERATION)
    _integer(value.policy_generation, 1, MAX_CHPB_GENERATION)
    _digest(value.projection_digest, 64)
    _integer(value.fencing_epoch, 0, MAX_CHPB_GENERATION)
    return value


def _validate_observation(value: object) -> BrokerObservation:
    if type(value) is not BrokerObservation:
        _fail(ChpbValidationCode.INVALID_TYPE)
    _enum(value.object_state, BrokerObjectState)
    _enum(value.registry_state, BrokerRegistryState)
    _integer(value.population_index, 0, MAX_CHPB_POPULATION_ENTRIES)
    return value


def validate_transaction_status(value: object) -> TransactionStatus:
    if type(value) is not TransactionStatus:
        _fail(ChpbValidationCode.INVALID_TYPE)
    validate_transaction_binding(value.binding)
    _enum(value.b2a_phase, B2aRecoveryPhase)
    _enum(value.checkpoint, BrokerCheckpoint)
    if b2a_phase_for_checkpoint(value.checkpoint) is not value.b2a_phase:
        _fail(ChpbValidationCode.INVALID_TRANSITION)
    _validate_observation(value.observation)
    _integer(value.population_total, 1, MAX_CHPB_POPULATION_ENTRIES)
    if value.observation.population_index > value.population_total:
        _fail(ChpbValidationCode.INVALID_FIELD)
    terminal = {
        BrokerCheckpoint.COMMITTED: BrokerResultCode.COMMITTED,
        BrokerCheckpoint.ROLLED_BACK: BrokerResultCode.ROLLED_BACK,
        BrokerCheckpoint.BLOCKED_DRIFT: BrokerResultCode.BLOCKED_DRIFT,
    }.get(value.checkpoint)
    if terminal is None:
        if value.terminal_result is not None:
            _fail(ChpbValidationCode.INVALID_TRANSITION)
    elif value.terminal_result is not terminal:
        _fail(ChpbValidationCode.INVALID_TRANSITION)
    return value


def _validate_attestation(value: object) -> HomeAttestation:
    if type(value) is not HomeAttestation:
        _fail(ChpbValidationCode.INVALID_TYPE)
    validate_transaction_binding(value.binding)
    if value.canonical_path != CANONICAL_AGENT_HOME:
        _fail(ChpbValidationCode.INVALID_FIELD)
    if type(value.canonical_path) is not str or len(value.canonical_path.encode("utf-8")) != len(CANONICAL_AGENT_HOME.encode("utf-8")):
        _fail(ChpbValidationCode.INVALID_FIELD)
    _validate_directory(value.directory)
    _digest(value.manifest_digest, 64)
    _mcs(value.mcs_pair)
    if value.mcs_pair != value.binding.principal.mcs_pair:
        _fail(ChpbValidationCode.INVALID_BINDING)
    return value


def _validate_request(value: BrokerRequest, klass: type, kind: ChpbMessageKind) -> BrokerRequest:
    if type(value) is not klass:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if type(value.protocol) is not str:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if value.protocol != CHPB_PROTOCOL:
        _fail(ChpbValidationCode.UNSUPPORTED_PROTOCOL)
    _enum(value.kind, ChpbMessageKind)
    if value.kind is not kind:
        _fail(ChpbValidationCode.INVALID_FIELD)
    _digest(value.request_id, 32)
    _digest(value.transaction_id, 32)
    _validate_expectation(value.expected)
    return value


def validate_chpb_message(value: object) -> ChpbMessage:
    if type(value) is AttestHomeRequest:
        return _validate_request(value, AttestHomeRequest, ChpbMessageKind.ATTEST_HOME)
    if type(value) is QueryTransactionRequest:
        return _validate_request(value, QueryTransactionRequest, ChpbMessageKind.QUERY_TRANSACTION)
    if type(value) is GetTerminalResultRequest:
        return _validate_request(value, GetTerminalResultRequest, ChpbMessageKind.GET_TERMINAL_RESULT)
    if type(value) is not BrokerReply:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if value.protocol != CHPB_PROTOCOL:
        _fail(ChpbValidationCode.UNSUPPORTED_PROTOCOL)
    if type(value.kind) is not ChpbMessageKind or value.kind is not ChpbMessageKind.REPLY:
        _fail(ChpbValidationCode.INVALID_FIELD)
    _digest(value.request_id, 32)
    _enum(value.result, BrokerResultCode)
    if value.transaction is not None:
        validate_transaction_status(value.transaction)
    if value.attestation is not None:
        _validate_attestation(value.attestation)
    if value.result is BrokerResultCode.OK:
        if value.transaction is None or value.attestation is None or value.transaction.checkpoint is not BrokerCheckpoint.COMMITTED:
            _fail(ChpbValidationCode.INVALID_FIELD)
        if value.attestation.binding != value.transaction.binding:
            _fail(ChpbValidationCode.INVALID_BINDING)
    elif value.result is BrokerResultCode.PENDING:
        if value.transaction is None or value.attestation is not None or value.transaction.terminal_result is not None:
            _fail(ChpbValidationCode.INVALID_FIELD)
    elif value.result in (BrokerResultCode.COMMITTED, BrokerResultCode.ROLLED_BACK, BrokerResultCode.BLOCKED_DRIFT):
        if value.transaction is None or value.transaction.terminal_result is not value.result or value.attestation is not None:
            _fail(ChpbValidationCode.INVALID_FIELD)
    elif value.transaction is not None or value.attestation is not None:
        _fail(ChpbValidationCode.INVALID_FIELD)
    return value


def _principal_doc(value: PrincipalBinding) -> dict[str, object]:
    return {"agent_id": value.agent_id, "cgroup_dev": value.cgroup_dev, "cgroup_ino": value.cgroup_ino, "fencing_epoch": value.fencing_epoch, "invocation_id": value.invocation_id, "manifest_generation": value.manifest_generation, "mcs_pair": value.mcs_pair, "unit_generation": value.unit_generation}


def _policy_doc(value: PolicyBinding) -> dict[str, object]:
    return {"policy_generation": value.policy_generation, "projection_digest": value.projection_digest}


def _binding_doc(value: TransactionBinding) -> dict[str, object]:
    return {"policy": _policy_doc(value.policy), "principal": _principal_doc(value.principal), "store_uuid": value.store_uuid, "transaction_id": value.transaction_id}


def _expectation_doc(value: BindingExpectation) -> dict[str, object]:
    return {"agent_id": value.agent_id, "fencing_epoch": value.fencing_epoch, "manifest_generation": value.manifest_generation, "policy_generation": value.policy_generation, "projection_digest": value.projection_digest, "unit_generation": value.unit_generation}


def _directory_doc(value: DirectoryIdentity) -> dict[str, object]:
    return {"dev": value.dev, "ino": value.ino, "mode": value.mode}


def _observation_doc(value: BrokerObservation) -> dict[str, object]:
    return {"object_state": value.object_state.value, "population_index": value.population_index, "registry_state": value.registry_state.value}


def _status_doc(value: TransactionStatus) -> dict[str, object]:
    return {"binding": _binding_doc(value.binding), "b2a_phase": value.b2a_phase.value, "checkpoint": value.checkpoint.value, "observation": _observation_doc(value.observation), "population_total": value.population_total, "terminal_result": value.terminal_result.value if value.terminal_result is not None else None}


def _attestation_doc(value: HomeAttestation) -> dict[str, object]:
    return {"binding": _binding_doc(value.binding), "canonical_path": value.canonical_path, "directory": _directory_doc(value.directory), "manifest_digest": value.manifest_digest, "mcs_pair": value.mcs_pair}


def _message_doc(value: ChpbMessage) -> dict[str, object]:
    if type(value) in (AttestHomeRequest, QueryTransactionRequest, GetTerminalResultRequest):
        return {"expected": _expectation_doc(value.expected), "kind": value.kind.value, "protocol": value.protocol, "request_id": value.request_id, "transaction_id": value.transaction_id}
    return {"attestation": _attestation_doc(value.attestation) if value.attestation is not None else None, "kind": value.kind.value, "protocol": value.protocol, "request_id": value.request_id, "result": value.result.value, "transaction": _status_doc(value.transaction) if value.transaction is not None else None}


def encode_chpb_message(message: ChpbMessage) -> bytes:
    validate_chpb_message(message)
    raw = (json.dumps(_message_doc(message), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    if len(raw) > MAX_CHPB_MESSAGE_BYTES:
        _fail(ChpbValidationCode.MESSAGE_TOO_LARGE)
    return raw


class _DecodeFailure(Exception):
    def __init__(self, code: ChpbValidationCode):
        self.code = code


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DecodeFailure(ChpbValidationCode.DUPLICATE_KEY)
        result[key] = value
    return result


def _constant(_value):
    raise _DecodeFailure(ChpbValidationCode.INVALID_FIELD)


def _shape(value: object, depth: int = 0) -> None:
    if type(value) is dict:
        if depth >= MAX_CHPB_NESTING_DEPTH:
            _fail(ChpbValidationCode.INVALID_FIELD)
        if len(value) > MAX_CHPB_OBJECT_FIELDS:
            _fail(ChpbValidationCode.INVALID_FIELD)
        for key, child in value.items():
            if type(key) is not str:
                _fail(ChpbValidationCode.INVALID_TYPE)
            _shape(child, depth + 1)
    elif type(value) is list or type(value) is float:
        _fail(ChpbValidationCode.INVALID_TYPE)
    elif type(value) not in (str, int, bool) and value is not None:
        _fail(ChpbValidationCode.INVALID_TYPE)


def _keys(document: object, expected: set[str]) -> dict[str, object]:
    if type(document) is not dict:
        _fail(ChpbValidationCode.INVALID_TYPE)
    actual = set(document)
    if actual != expected:
        _fail(ChpbValidationCode.UNKNOWN_FIELD if not actual <= expected else ChpbValidationCode.INVALID_FIELD)
    return document


def _as_enum(value: object, klass: type[Enum]):
    if type(value) is not str:
        _fail(ChpbValidationCode.INVALID_TYPE)
    try:
        return klass(value)
    except ValueError:
        _fail(ChpbValidationCode.INVALID_FIELD)


def _principal_from(document: object) -> PrincipalBinding:
    doc = _keys(document, {"agent_id", "cgroup_dev", "cgroup_ino", "fencing_epoch", "invocation_id", "manifest_generation", "mcs_pair", "unit_generation"})
    return PrincipalBinding(doc["agent_id"], doc["manifest_generation"], doc["unit_generation"], doc["cgroup_dev"], doc["cgroup_ino"], doc["invocation_id"], doc["mcs_pair"], doc["fencing_epoch"])


def _binding_from(document: object) -> TransactionBinding:
    doc = _keys(document, {"policy", "principal", "store_uuid", "transaction_id"})
    return TransactionBinding(doc["transaction_id"], doc["store_uuid"], _principal_from(doc["principal"]), _policy_from(doc["policy"]))


def _policy_from(document: object) -> PolicyBinding:
    doc = _keys(document, {"policy_generation", "projection_digest"})
    return PolicyBinding(doc["policy_generation"], doc["projection_digest"])


def _expectation_from(document: object) -> BindingExpectation:
    doc = _keys(document, {"agent_id", "fencing_epoch", "manifest_generation", "policy_generation", "projection_digest", "unit_generation"})
    return BindingExpectation(doc["agent_id"], doc["manifest_generation"], doc["unit_generation"], doc["policy_generation"], doc["projection_digest"], doc["fencing_epoch"])


def _directory_from(document: object) -> DirectoryIdentity:
    doc = _keys(document, {"dev", "ino", "mode"})
    return DirectoryIdentity(doc["dev"], doc["ino"], doc["mode"])


def _observation_from(document: object) -> BrokerObservation:
    doc = _keys(document, {"object_state", "population_index", "registry_state"})
    return BrokerObservation(_as_enum(doc["object_state"], BrokerObjectState), _as_enum(doc["registry_state"], BrokerRegistryState), doc["population_index"])


def _status_from(document: object) -> TransactionStatus:
    doc = _keys(document, {"b2a_phase", "binding", "checkpoint", "observation", "population_total", "terminal_result"})
    terminal = None if doc["terminal_result"] is None else _as_enum(doc["terminal_result"], BrokerResultCode)
    return TransactionStatus(_binding_from(doc["binding"]), _as_enum(doc["b2a_phase"], B2aRecoveryPhase), _as_enum(doc["checkpoint"], BrokerCheckpoint), _observation_from(doc["observation"]), doc["population_total"], terminal)


def _attestation_from(document: object) -> HomeAttestation:
    doc = _keys(document, {"binding", "canonical_path", "directory", "manifest_digest", "mcs_pair"})
    return HomeAttestation(_binding_from(doc["binding"]), doc["canonical_path"], _directory_from(doc["directory"]), doc["manifest_digest"], doc["mcs_pair"])


def _message_from(document: object) -> ChpbMessage:
    if type(document) is not dict:
        _fail(ChpbValidationCode.INVALID_TYPE)
    kind = _as_enum(document.get("kind"), ChpbMessageKind)
    if kind is ChpbMessageKind.REPLY:
        doc = _keys(document, {"attestation", "kind", "protocol", "request_id", "result", "transaction"})
        transaction = None if doc["transaction"] is None else _status_from(doc["transaction"])
        attestation = None if doc["attestation"] is None else _attestation_from(doc["attestation"])
        return BrokerReply(doc["protocol"], kind, doc["request_id"], _as_enum(doc["result"], BrokerResultCode), transaction, attestation)
    doc = _keys(document, {"expected", "kind", "protocol", "request_id", "transaction_id"})
    klass = {ChpbMessageKind.ATTEST_HOME: AttestHomeRequest, ChpbMessageKind.QUERY_TRANSACTION: QueryTransactionRequest, ChpbMessageKind.GET_TERMINAL_RESULT: GetTerminalResultRequest}.get(kind)
    if klass is None:
        _fail(ChpbValidationCode.INVALID_FIELD)
    return klass(doc["protocol"], kind, doc["request_id"], doc["transaction_id"], _expectation_from(doc["expected"]))


def decode_chpb_message(raw: bytes) -> ChpbMessage:
    if type(raw) is not bytes:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if not 1 <= len(raw) <= MAX_CHPB_MESSAGE_BYTES:
        _fail(ChpbValidationCode.MESSAGE_TOO_LARGE if len(raw) > MAX_CHPB_MESSAGE_BYTES else ChpbValidationCode.INVALID_FIELD)
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _fail(ChpbValidationCode.INVALID_UTF8)
    if text.startswith("\ufeff"):
        _fail(ChpbValidationCode.INVALID_UTF8)
    try:
        document = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except _DecodeFailure as error:
        _fail(error.code)
    except (json.JSONDecodeError, UnicodeError):
        _fail(ChpbValidationCode.INVALID_FIELD)
    _shape(document)
    message = _message_from(document)
    validate_chpb_message(message)
    if encode_chpb_message(message) != raw:
        _fail(ChpbValidationCode.NON_CANONICAL)
    return message


_PHASE_TO_CHECKPOINT = {
    B2aRecoveryPhase.ABSENT_CREATE_PENDING: BrokerCheckpoint.CREATE_INTENT,
    B2aRecoveryPhase.ABSENT_PIN_PENDING: BrokerCheckpoint.STAGING_PINNED,
    B2aRecoveryPhase.ABSENT_POPULATE_PENDING: BrokerCheckpoint.POPULATE_PENDING,
    B2aRecoveryPhase.ABSENT_PUBLISH_PENDING: BrokerCheckpoint.PUBLISH_INTENT,
    B2aRecoveryPhase.ABSENT_PUBLISHED: BrokerCheckpoint.PUBLISHED,
    B2aRecoveryPhase.PREPARE_PENDING: BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
    B2aRecoveryPhase.PREPARED: BrokerCheckpoint.REPLACEMENT_PREPARED,
    B2aRecoveryPhase.SWITCH_PENDING: BrokerCheckpoint.SWITCH_INTENT,
    B2aRecoveryPhase.SWITCHED: BrokerCheckpoint.SWITCHED,
    B2aRecoveryPhase.CAS_PENDING: BrokerCheckpoint.REGISTRY_CAS_INTENT,
    B2aRecoveryPhase.COMMIT_PENDING: BrokerCheckpoint.FINALIZE_INTENT,
    B2aRecoveryPhase.ROLLBACK_PENDING: BrokerCheckpoint.ROLLBACK_INTENT,
    B2aRecoveryPhase.COMMITTED: BrokerCheckpoint.COMMITTED,
    B2aRecoveryPhase.ROLLED_BACK: BrokerCheckpoint.ROLLED_BACK,
    B2aRecoveryPhase.BLOCKED: BrokerCheckpoint.BLOCKED_DRIFT,
}
_CHECKPOINT_TO_PHASE = {value: key for key, value in _PHASE_TO_CHECKPOINT.items()}


def checkpoint_for_b2a_phase(phase: B2aRecoveryPhase) -> BrokerCheckpoint:
    _enum(phase, B2aRecoveryPhase)
    return _PHASE_TO_CHECKPOINT[phase]


def b2a_phase_for_checkpoint(checkpoint: BrokerCheckpoint) -> B2aRecoveryPhase:
    _enum(checkpoint, BrokerCheckpoint)
    return _CHECKPOINT_TO_PHASE[checkpoint]


_TRANSITIONS = {
    BrokerCheckpoint.CREATE_INTENT: {BrokerCheckpoint.STAGING_PINNED, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.STAGING_PINNED: {BrokerCheckpoint.POPULATE_PENDING, BrokerCheckpoint.ROLLBACK_INTENT, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.POPULATE_PENDING: {BrokerCheckpoint.POPULATE_PENDING, BrokerCheckpoint.PUBLISH_INTENT, BrokerCheckpoint.ROLLBACK_INTENT, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.PUBLISH_INTENT: {BrokerCheckpoint.PUBLISHED, BrokerCheckpoint.ROLLBACK_INTENT, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.PUBLISHED: {BrokerCheckpoint.REGISTRY_CAS_INTENT, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT: {BrokerCheckpoint.REPLACEMENT_PREPARED, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.REPLACEMENT_PREPARED: {BrokerCheckpoint.SWITCH_INTENT, BrokerCheckpoint.ROLLBACK_INTENT, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.SWITCH_INTENT: {BrokerCheckpoint.SWITCHED, BrokerCheckpoint.ROLLBACK_INTENT, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.SWITCHED: {BrokerCheckpoint.REGISTRY_CAS_INTENT, BrokerCheckpoint.ROLLBACK_INTENT, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.REGISTRY_CAS_INTENT: {BrokerCheckpoint.FINALIZE_INTENT, BrokerCheckpoint.ROLLBACK_INTENT, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.FINALIZE_INTENT: {BrokerCheckpoint.COMMITTED, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.ROLLBACK_INTENT: {BrokerCheckpoint.ROLLED_BACK, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.COMMITTED: {BrokerCheckpoint.COMMITTED},
    BrokerCheckpoint.ROLLED_BACK: {BrokerCheckpoint.ROLLED_BACK},
    BrokerCheckpoint.BLOCKED_DRIFT: {BrokerCheckpoint.BLOCKED_DRIFT},
}


def is_checkpoint_transition_allowed(current: BrokerCheckpoint, target: BrokerCheckpoint) -> bool:
    _enum(current, BrokerCheckpoint)
    _enum(target, BrokerCheckpoint)
    return target in _TRANSITIONS[current]


def _decision(action, checkpoint, result=BrokerResultCode.PENDING):
    phase = b2a_phase_for_checkpoint(checkpoint) if checkpoint is not None else None
    return RecoveryDecision(action, phase, checkpoint, result)


def _blocked_decision():
    return _decision(BrokerRecoveryAction.RETURN_BLOCKED, BrokerCheckpoint.BLOCKED_DRIFT, BrokerResultCode.BLOCKED_DRIFT)


def decide_broker_recovery(status: TransactionStatus, observation: BrokerObservation) -> RecoveryDecision:
    try:
        validate_transaction_status(status)
        _validate_observation(observation)
    except ChpbValidationError:
        return _blocked_decision()
    checkpoint = status.checkpoint
    if checkpoint is BrokerCheckpoint.BLOCKED_DRIFT:
        return _blocked_decision()
    old_index = status.observation.population_index
    index = observation.population_index
    if index < old_index or index > old_index + 1:
        return _blocked_decision()
    total = status.population_total
    obj = observation.object_state
    reg = observation.registry_state
    na = BrokerRegistryState.NOT_APPLICABLE
    if checkpoint is BrokerCheckpoint.CREATE_INTENT:
        if obj is BrokerObjectState.ABSENT and reg is na:
            return _decision(BrokerRecoveryAction.CREATE_STAGING, None)
        if obj is BrokerObjectState.STAGING_EMPTY and reg is na:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.STAGING_PINNED)
    elif checkpoint is BrokerCheckpoint.STAGING_PINNED:
        if obj is BrokerObjectState.STAGING_EMPTY and reg is na:
            return _decision(BrokerRecoveryAction.POPULATE_NEXT, None)
        if obj is BrokerObjectState.STAGING_PREFIX and reg is na:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.POPULATE_PENDING)
    elif checkpoint is BrokerCheckpoint.POPULATE_PENDING:
        if obj is BrokerObjectState.STAGING_PREFIX and reg is na and index < total:
            return _decision(BrokerRecoveryAction.POPULATE_NEXT, None)
        if obj is BrokerObjectState.STAGING_COMPLETE and reg is na and index == total:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.PUBLISH_INTENT)
    elif checkpoint is BrokerCheckpoint.PUBLISH_INTENT:
        if obj is BrokerObjectState.STAGING_COMPLETE and reg is na:
            return _decision(BrokerRecoveryAction.PUBLISH_HOME, None)
        if obj is BrokerObjectState.FINAL_COMPLETE and reg is na:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.PUBLISHED)
    elif checkpoint is BrokerCheckpoint.PUBLISHED:
        if obj is BrokerObjectState.FINAL_COMPLETE and reg is BrokerRegistryState.OLD:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.REGISTRY_CAS_INTENT)
    elif checkpoint is BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT:
        if obj is BrokerObjectState.REPLACEMENT_ORIGINAL and reg is na:
            return _decision(BrokerRecoveryAction.PREPARE_REPLACEMENT, None)
        if obj is BrokerObjectState.REPLACEMENT_PREPARED and reg is na:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.REPLACEMENT_PREPARED)
    elif checkpoint is BrokerCheckpoint.REPLACEMENT_PREPARED:
        if obj is BrokerObjectState.REPLACEMENT_PREPARED and reg is na:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.SWITCH_INTENT)
    elif checkpoint is BrokerCheckpoint.SWITCH_INTENT:
        if obj is BrokerObjectState.REPLACEMENT_PREPARED and reg is na:
            return _decision(BrokerRecoveryAction.SWITCH_REPLACEMENT, None)
        if obj is BrokerObjectState.REPLACEMENT_SWITCHED and reg is na:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.SWITCHED)
    elif checkpoint is BrokerCheckpoint.SWITCHED:
        if obj is BrokerObjectState.REPLACEMENT_SWITCHED and reg is BrokerRegistryState.OLD:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.REGISTRY_CAS_INTENT)
    elif checkpoint is BrokerCheckpoint.REGISTRY_CAS_INTENT:
        if obj in (BrokerObjectState.FINAL_COMPLETE, BrokerObjectState.REPLACEMENT_SWITCHED) and reg is BrokerRegistryState.OLD:
            return _decision(BrokerRecoveryAction.CAS_REGISTRY, None)
        if obj in (BrokerObjectState.FINAL_COMPLETE, BrokerObjectState.REPLACEMENT_SWITCHED) and reg is BrokerRegistryState.CURRENT:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.FINALIZE_INTENT)
    elif checkpoint is BrokerCheckpoint.FINALIZE_INTENT:
        if obj in (BrokerObjectState.FINAL_COMPLETE, BrokerObjectState.REPLACEMENT_SWITCHED) and reg is BrokerRegistryState.CURRENT:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.COMMITTED, BrokerResultCode.COMMITTED)
    elif checkpoint is BrokerCheckpoint.ROLLBACK_INTENT:
        if obj is BrokerObjectState.ROLLBACK_READY and reg is na:
            return _decision(BrokerRecoveryAction.ROLLBACK, None)
        if obj is BrokerObjectState.ROLLED_BACK and reg is na:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.ROLLED_BACK, BrokerResultCode.ROLLED_BACK)
    elif checkpoint is BrokerCheckpoint.COMMITTED:
        if observation == status.observation and obj in (BrokerObjectState.FINAL_COMPLETE, BrokerObjectState.REPLACEMENT_SWITCHED) and reg is BrokerRegistryState.CURRENT:
            return _decision(BrokerRecoveryAction.RETURN_COMMITTED, BrokerCheckpoint.COMMITTED, BrokerResultCode.COMMITTED)
    elif checkpoint is BrokerCheckpoint.ROLLED_BACK:
        if observation == status.observation and obj is BrokerObjectState.ROLLED_BACK and reg is na:
            return _decision(BrokerRecoveryAction.RETURN_ROLLED_BACK, BrokerCheckpoint.ROLLED_BACK, BrokerResultCode.ROLLED_BACK)
    return _blocked_decision()
