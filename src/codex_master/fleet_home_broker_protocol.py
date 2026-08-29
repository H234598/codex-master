"""Pure CHPB/2 contract types and deterministic recovery rules."""

from dataclasses import dataclass
from enum import Enum
import json
import re

from codex_master.fleet_control_release_v2 import (
    ControlReleaseSpecV2,
    decode_control_release_v2,
    encode_control_release_v2,
)
from codex_master.fleet_home_broker_identity import BrokerIdentity


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
    PROVISION_HOME = "provision_home"
    REPLACE_HOME = "replace_home"
    DEPROVISION_HOME = "deprovision_home"
    REPLY = "reply"
    AGENT_START_CLAIM = "agent_start_claim"
    AGENT_START_ENVELOPE = "agent_start_envelope"


class ChpbTransactionOperation(str, Enum):
    PROVISION = "provision"
    REPLACE = "replace"
    DEPROVISION = "deprovision"


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
    DEPROVISION_PENDING = "deprovision_pending"
    DEPROVISIONED = "deprovisioned"
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
    DEPROVISION_INTENT = "deprovision_intent"
    DEPROVISIONED = "deprovisioned"
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
    DEPROVISION_HOME = "deprovision_home"
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
    operation: ChpbTransactionOperation
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
class ProvisionHomeRequest:
    protocol: str
    kind: ChpbMessageKind
    request_id: str
    transaction_id: str
    expected: BindingExpectation
    binding: TransactionBinding


@dataclass(frozen=True, slots=True)
class ReplaceHomeRequest:
    protocol: str
    kind: ChpbMessageKind
    request_id: str
    transaction_id: str
    expected: BindingExpectation
    binding: TransactionBinding


@dataclass(frozen=True, slots=True)
class DeprovisionHomeRequest:
    protocol: str
    kind: ChpbMessageKind
    request_id: str
    transaction_id: str
    expected: BindingExpectation
    binding: TransactionBinding


@dataclass(frozen=True, slots=True)
class BrokerReply:
    protocol: str
    kind: ChpbMessageKind
    request_id: str
    result: BrokerResultCode
    transaction: TransactionStatus | None
    attestation: HomeAttestation | None


@dataclass(frozen=True, slots=True)
class AgentStartClaim:
    protocol: str
    kind: ChpbMessageKind
    request_id: str


@dataclass(frozen=True, slots=True)
class AgentStartExecutablePin:
    path: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class AgentStartEnvironmentProjection:
    values: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class AgentStartEnvelope:
    protocol: str
    kind: ChpbMessageKind
    request_id: str
    release: ControlReleaseSpecV2
    release_payload_version: str
    snapshot_generation: int
    principal: PrincipalBinding
    expected: BindingExpectation
    unit_name: str
    identity: BrokerIdentity
    executable: AgentStartExecutablePin
    environment: AgentStartEnvironmentProjection
    attestation: HomeAttestation


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    action: BrokerRecoveryAction
    next_b2a_phase: B2aRecoveryPhase | None
    next_checkpoint: BrokerCheckpoint | None
    result: BrokerResultCode


BrokerRequest = AttestHomeRequest | QueryTransactionRequest | GetTerminalResultRequest | ProvisionHomeRequest | ReplaceHomeRequest | DeprovisionHomeRequest
ChpbMessage = BrokerRequest | BrokerReply | AgentStartClaim | AgentStartEnvelope


_HEX32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_AGENT = re.compile(r"[a-z][a-z0-9_-]{0,127}\Z", re.ASCII)
_MCS = re.compile(r"c(0|[1-9][0-9]{0,3}),c(0|[1-9][0-9]{0,3})\Z", re.ASCII)
_MCS_INSTANCE = re.compile(r"c[0-9]{1,4}\\x2cc[0-9]{1,4}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)

_AGENT_START_ENVIRONMENT = (
    ("CODEX_HOME", CANONICAL_AGENT_HOME),
    ("GEMINI_CLI_HOME", CANONICAL_AGENT_HOME),
    ("HOME", CANONICAL_AGENT_HOME),
)


def agent_unit_name_for_mcs(mcs_pair: object) -> str:
    """Return the only unit spelling permitted for one validated MCS pair."""

    mcs = _mcs(mcs_pair)
    low, high = (int(part[1:]) for part in mcs.split(","))
    instance = f"c{low}\\x2cc{high}"
    if _MCS_INSTANCE.fullmatch(instance) is None:
        _fail(ChpbValidationCode.INVALID_BINDING)
    return f"codex-master-agent@{instance}.service"


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
    _enum(value.operation, ChpbTransactionOperation)
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
    allowed_checkpoints = {
        ChpbTransactionOperation.PROVISION: {
            BrokerCheckpoint.CREATE_INTENT,
            BrokerCheckpoint.STAGING_PINNED,
            BrokerCheckpoint.POPULATE_PENDING,
            BrokerCheckpoint.PUBLISH_INTENT,
            BrokerCheckpoint.PUBLISHED,
            BrokerCheckpoint.REGISTRY_CAS_INTENT,
            BrokerCheckpoint.FINALIZE_INTENT,
            BrokerCheckpoint.ROLLBACK_INTENT,
            BrokerCheckpoint.COMMITTED,
            BrokerCheckpoint.ROLLED_BACK,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        ChpbTransactionOperation.REPLACE: {
            BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
            BrokerCheckpoint.REPLACEMENT_PREPARED,
            BrokerCheckpoint.SWITCH_INTENT,
            BrokerCheckpoint.SWITCHED,
            BrokerCheckpoint.REGISTRY_CAS_INTENT,
            BrokerCheckpoint.FINALIZE_INTENT,
            BrokerCheckpoint.ROLLBACK_INTENT,
            BrokerCheckpoint.COMMITTED,
            BrokerCheckpoint.ROLLED_BACK,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        ChpbTransactionOperation.DEPROVISION: {
            BrokerCheckpoint.DEPROVISION_INTENT,
            BrokerCheckpoint.DEPROVISIONED,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
    }[value.binding.operation]
    if value.checkpoint not in allowed_checkpoints:
        _fail(ChpbValidationCode.INVALID_BINDING)
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
        BrokerCheckpoint.DEPROVISIONED: BrokerResultCode.COMMITTED,
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


def _validate_identity(value: object) -> BrokerIdentity:
    if type(value) is not BrokerIdentity:
        _fail(ChpbValidationCode.INVALID_TYPE)
    try:
        BrokerIdentity(
            value.agent_id,
            value.manifest_generation,
            value.mcs_pair,
            value.slot_snapshot,
            value.policy_generation,
            value.projection_digest,
            value.executable_fingerprint,
            value.fencing_epoch,
        )
    except Exception:
        _fail(ChpbValidationCode.INVALID_BINDING)
    return value


def _validate_executable_pin(value: object) -> AgentStartExecutablePin:
    if type(value) is not AgentStartExecutablePin:
        _fail(ChpbValidationCode.INVALID_TYPE)
    path = value.path
    if (
        type(path) is not str
        or not path.startswith("/")
        or path != path.strip()
        or "//" in path
        or path.endswith("/")
        or "\x00" in path
        or "\\" in path
    ):
        _fail(ChpbValidationCode.INVALID_FIELD)
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]):
        _fail(ChpbValidationCode.INVALID_FIELD)
    if tuple(parts[-3:-1]) == ("self", "fd"):
        _fail(ChpbValidationCode.INVALID_FIELD)
    _digest(value.fingerprint, 64)
    return value


def _validate_environment_projection(
    value: object,
) -> AgentStartEnvironmentProjection:
    if type(value) is not AgentStartEnvironmentProjection:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if type(value.values) is not tuple or value.values != _AGENT_START_ENVIRONMENT:
        _fail(ChpbValidationCode.INVALID_FIELD)
    for pair in value.values:
        if (
            type(pair) is not tuple
            or len(pair) != 2
            or type(pair[0]) is not str
            or type(pair[1]) is not str
        ):
            _fail(ChpbValidationCode.INVALID_TYPE)
    return value


def _validate_agent_start_claim(value: object) -> AgentStartClaim:
    if type(value) is not AgentStartClaim:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if type(value.protocol) is not str:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if value.protocol != CHPB_PROTOCOL:
        _fail(ChpbValidationCode.UNSUPPORTED_PROTOCOL)
    if type(value.kind) is not ChpbMessageKind:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if value.kind is not ChpbMessageKind.AGENT_START_CLAIM:
        _fail(ChpbValidationCode.INVALID_FIELD)
    _digest(value.request_id, 32)
    return value


def _validate_agent_start_envelope(value: object) -> AgentStartEnvelope:
    if type(value) is not AgentStartEnvelope:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if type(value.protocol) is not str:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if value.protocol != CHPB_PROTOCOL:
        _fail(ChpbValidationCode.UNSUPPORTED_PROTOCOL)
    if type(value.kind) is not ChpbMessageKind:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if value.kind is not ChpbMessageKind.AGENT_START_ENVELOPE:
        _fail(ChpbValidationCode.INVALID_FIELD)
    _digest(value.request_id, 32)
    if type(value.release_payload_version) is not str:
        _fail(ChpbValidationCode.INVALID_TYPE)
    if type(value.release) is not ControlReleaseSpecV2:
        _fail(ChpbValidationCode.INVALID_TYPE)
    try:
        release = ControlReleaseSpecV2(
            value.release.schema_version,
            value.release.payload_version,
            value.release.payloads,
            value.release.broker_protocol,
            value.release.system_bus_interface,
            value.release.system_bus_method,
            value.release.agent_unit_template,
            value.release.launcher_path,
        )
        release_bytes = encode_control_release_v2(release)
        decoded_release = decode_control_release_v2(
            release_bytes, value.release_payload_version
        )
    except Exception:
        _fail(ChpbValidationCode.INVALID_BINDING)
    if release != value.release or decoded_release != value.release:
        _fail(ChpbValidationCode.INVALID_BINDING)
    _integer(value.snapshot_generation, 1, MAX_CHPB_GENERATION)
    validate_principal_binding(value.principal)
    _validate_expectation(value.expected)
    if (
        value.principal.agent_id != value.expected.agent_id
        or value.principal.manifest_generation != value.expected.manifest_generation
        or value.principal.unit_generation != value.expected.unit_generation
        or value.principal.fencing_epoch != value.expected.fencing_epoch
    ):
        _fail(ChpbValidationCode.INVALID_BINDING)
    _validate_identity(value.identity)
    if (
        value.identity.agent_id != value.principal.agent_id
        or value.identity.manifest_generation != value.principal.manifest_generation
        or value.identity.mcs_pair != value.principal.mcs_pair
        or value.identity.policy_generation != value.expected.policy_generation
        or value.identity.projection_digest != value.expected.projection_digest
        or value.identity.fencing_epoch != value.principal.fencing_epoch
    ):
        _fail(ChpbValidationCode.INVALID_BINDING)
    if value.unit_name != agent_unit_name_for_mcs(value.principal.mcs_pair):
        _fail(ChpbValidationCode.INVALID_BINDING)
    _validate_executable_pin(value.executable)
    if (
        value.executable.path != value.release.launcher_path
        or value.executable.fingerprint != value.identity.executable_fingerprint
    ):
        _fail(ChpbValidationCode.INVALID_BINDING)
    _validate_environment_projection(value.environment)
    _validate_attestation(value.attestation)
    attestation = value.attestation
    if (
        attestation.binding.principal != value.principal
        or attestation.binding.policy.policy_generation
        != value.expected.policy_generation
        or attestation.binding.policy.projection_digest
        != value.expected.projection_digest
        or attestation.mcs_pair != value.principal.mcs_pair
    ):
        _fail(ChpbValidationCode.INVALID_BINDING)
    return value


def _validate_request(
    value: BrokerRequest,
    klass: type,
    kind: ChpbMessageKind,
    *,
    has_binding: bool = False,
) -> BrokerRequest:
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
    if has_binding:
        validate_transaction_binding(value.binding)
        if kind is ChpbMessageKind.PROVISION_HOME and value.binding.operation is not ChpbTransactionOperation.PROVISION:
            _fail(ChpbValidationCode.INVALID_BINDING)
        if kind is ChpbMessageKind.REPLACE_HOME and value.binding.operation is not ChpbTransactionOperation.REPLACE:
            _fail(ChpbValidationCode.INVALID_BINDING)
        if kind is ChpbMessageKind.DEPROVISION_HOME and value.binding.operation is not ChpbTransactionOperation.DEPROVISION:
            _fail(ChpbValidationCode.INVALID_BINDING)
        if value.binding.transaction_id != value.transaction_id:
            _fail(ChpbValidationCode.INVALID_BINDING)
        if (
            value.binding.principal.agent_id != value.expected.agent_id
            or value.binding.principal.manifest_generation != value.expected.manifest_generation
            or value.binding.principal.unit_generation != value.expected.unit_generation
            or value.binding.principal.fencing_epoch != value.expected.fencing_epoch
            or value.binding.policy.policy_generation != value.expected.policy_generation
            or value.binding.policy.projection_digest != value.expected.projection_digest
        ):
            _fail(ChpbValidationCode.INVALID_BINDING)
    return value


def validate_chpb_message(value: object) -> ChpbMessage:
    if type(value) is AttestHomeRequest:
        return _validate_request(value, AttestHomeRequest, ChpbMessageKind.ATTEST_HOME)
    if type(value) is QueryTransactionRequest:
        return _validate_request(value, QueryTransactionRequest, ChpbMessageKind.QUERY_TRANSACTION)
    if type(value) is GetTerminalResultRequest:
        return _validate_request(value, GetTerminalResultRequest, ChpbMessageKind.GET_TERMINAL_RESULT)
    if type(value) is ProvisionHomeRequest:
        return _validate_request(value, ProvisionHomeRequest, ChpbMessageKind.PROVISION_HOME, has_binding=True)
    if type(value) is ReplaceHomeRequest:
        return _validate_request(value, ReplaceHomeRequest, ChpbMessageKind.REPLACE_HOME, has_binding=True)
    if type(value) is DeprovisionHomeRequest:
        return _validate_request(value, DeprovisionHomeRequest, ChpbMessageKind.DEPROVISION_HOME, has_binding=True)
    if type(value) is AgentStartClaim:
        return _validate_agent_start_claim(value)
    if type(value) is AgentStartEnvelope:
        return _validate_agent_start_envelope(value)
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
    return {"operation": value.operation.value, "policy": _policy_doc(value.policy), "principal": _principal_doc(value.principal), "store_uuid": value.store_uuid, "transaction_id": value.transaction_id}


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


def _identity_doc(value: BrokerIdentity) -> dict[str, object]:
    return {
        "agent_id": value.agent_id,
        "fencing_epoch": value.fencing_epoch,
        "executable_fingerprint": value.executable_fingerprint,
        "manifest_generation": value.manifest_generation,
        "mcs_pair": value.mcs_pair,
        "policy_generation": value.policy_generation,
        "projection_digest": value.projection_digest,
        "slot_snapshot": value.slot_snapshot,
    }


def _executable_doc(value: AgentStartExecutablePin) -> dict[str, object]:
    return {"fingerprint": value.fingerprint, "path": value.path}


def _environment_doc(
    value: AgentStartEnvironmentProjection,
) -> dict[str, object]:
    return {
        "codex_home": value.values[0][1],
        "gemini_cli_home": value.values[1][1],
        "home": value.values[2][1],
    }


def _message_doc(value: ChpbMessage) -> dict[str, object]:
    if type(value) is AgentStartClaim:
        return {
            "kind": value.kind.value,
            "protocol": value.protocol,
            "request_id": value.request_id,
        }
    if type(value) is AgentStartEnvelope:
        return {
            "attestation": _attestation_doc(value.attestation),
            "environment": _environment_doc(value.environment),
            "executable": _executable_doc(value.executable),
            "expected": _expectation_doc(value.expected),
            "identity": _identity_doc(value.identity),
            "kind": value.kind.value,
            "principal": _principal_doc(value.principal),
            "protocol": value.protocol,
            "release": encode_control_release_v2(value.release).decode("utf-8"),
            "release_payload_version": value.release_payload_version,
            "request_id": value.request_id,
            "snapshot_generation": value.snapshot_generation,
            "unit_name": value.unit_name,
        }
    if type(value) in (
        AttestHomeRequest,
        QueryTransactionRequest,
        GetTerminalResultRequest,
    ):
        return {"expected": _expectation_doc(value.expected), "kind": value.kind.value, "protocol": value.protocol, "request_id": value.request_id, "transaction_id": value.transaction_id}
    if type(value) in (
        ProvisionHomeRequest,
        ReplaceHomeRequest,
        DeprovisionHomeRequest,
    ):
        return {"binding": _binding_doc(value.binding), "expected": _expectation_doc(value.expected), "kind": value.kind.value, "protocol": value.protocol, "request_id": value.request_id, "transaction_id": value.transaction_id}
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
    doc = _keys(document, {"operation", "policy", "principal", "store_uuid", "transaction_id"})
    return TransactionBinding(
        _as_enum(doc["operation"], ChpbTransactionOperation),
        doc["transaction_id"],
        doc["store_uuid"],
        _principal_from(doc["principal"]),
        _policy_from(doc["policy"]),
    )


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


def _identity_from(document: object) -> BrokerIdentity:
    doc = _keys(
        document,
        {
            "agent_id",
            "executable_fingerprint",
            "fencing_epoch",
            "manifest_generation",
            "mcs_pair",
            "policy_generation",
            "projection_digest",
            "slot_snapshot",
        },
    )
    try:
        return BrokerIdentity(
            doc["agent_id"],
            doc["manifest_generation"],
            doc["mcs_pair"],
            doc["slot_snapshot"],
            doc["policy_generation"],
            doc["projection_digest"],
            doc["executable_fingerprint"],
            doc["fencing_epoch"],
        )
    except Exception as exc:
        raise ChpbValidationError(ChpbValidationCode.INVALID_BINDING) from exc


def _executable_from(document: object) -> AgentStartExecutablePin:
    doc = _keys(document, {"fingerprint", "path"})
    return AgentStartExecutablePin(doc["path"], doc["fingerprint"])


def _environment_from(document: object) -> AgentStartEnvironmentProjection:
    doc = _keys(document, {"codex_home", "gemini_cli_home", "home"})
    return AgentStartEnvironmentProjection(
        (
            ("CODEX_HOME", doc["codex_home"]),
            ("GEMINI_CLI_HOME", doc["gemini_cli_home"]),
            ("HOME", doc["home"]),
        )
    )


def _message_from(document: object) -> ChpbMessage:
    if type(document) is not dict:
        _fail(ChpbValidationCode.INVALID_TYPE)
    kind = _as_enum(document.get("kind"), ChpbMessageKind)
    if kind is ChpbMessageKind.REPLY:
        doc = _keys(document, {"attestation", "kind", "protocol", "request_id", "result", "transaction"})
        transaction = None if doc["transaction"] is None else _status_from(doc["transaction"])
        attestation = None if doc["attestation"] is None else _attestation_from(doc["attestation"])
        return BrokerReply(doc["protocol"], kind, doc["request_id"], _as_enum(doc["result"], BrokerResultCode), transaction, attestation)
    if kind is ChpbMessageKind.AGENT_START_CLAIM:
        doc = _keys(document, {"kind", "protocol", "request_id"})
        return AgentStartClaim(doc["protocol"], kind, doc["request_id"])
    if kind is ChpbMessageKind.AGENT_START_ENVELOPE:
        doc = _keys(
            document,
            {
                "attestation",
                "environment",
                "executable",
                "expected",
                "identity",
                "kind",
                "principal",
                "protocol",
                "release",
                "release_payload_version",
                "request_id",
                "snapshot_generation",
                "unit_name",
            },
        )
        if type(doc["release"]) is not str:
            _fail(ChpbValidationCode.INVALID_TYPE)
        try:
            release = decode_control_release_v2(
                doc["release"].encode("utf-8"), doc["release_payload_version"]
            )
        except Exception as exc:
            raise ChpbValidationError(ChpbValidationCode.INVALID_BINDING) from exc
        return AgentStartEnvelope(
            doc["protocol"],
            kind,
            doc["request_id"],
            release,
            doc["release_payload_version"],
            doc["snapshot_generation"],
            _principal_from(doc["principal"]),
            _expectation_from(doc["expected"]),
            doc["unit_name"],
            _identity_from(doc["identity"]),
            _executable_from(doc["executable"]),
            _environment_from(doc["environment"]),
            _attestation_from(doc["attestation"]),
        )
    klass = {
        ChpbMessageKind.ATTEST_HOME: AttestHomeRequest,
        ChpbMessageKind.QUERY_TRANSACTION: QueryTransactionRequest,
        ChpbMessageKind.GET_TERMINAL_RESULT: GetTerminalResultRequest,
        ChpbMessageKind.PROVISION_HOME: ProvisionHomeRequest,
        ChpbMessageKind.REPLACE_HOME: ReplaceHomeRequest,
        ChpbMessageKind.DEPROVISION_HOME: DeprovisionHomeRequest,
    }.get(kind)
    if klass is None:
        _fail(ChpbValidationCode.INVALID_FIELD)
    if kind is ChpbMessageKind.ATTEST_HOME:
        doc = _keys(document, {"expected", "kind", "protocol", "request_id", "transaction_id"})
        return klass(doc["protocol"], kind, doc["request_id"], doc["transaction_id"], _expectation_from(doc["expected"]))
    if kind is ChpbMessageKind.QUERY_TRANSACTION:
        doc = _keys(document, {"expected", "kind", "protocol", "request_id", "transaction_id"})
        return klass(doc["protocol"], kind, doc["request_id"], doc["transaction_id"], _expectation_from(doc["expected"]))
    if kind is ChpbMessageKind.GET_TERMINAL_RESULT:
        doc = _keys(document, {"expected", "kind", "protocol", "request_id", "transaction_id"})
        return klass(doc["protocol"], kind, doc["request_id"], doc["transaction_id"], _expectation_from(doc["expected"]))
    doc = _keys(document, {"binding", "expected", "kind", "protocol", "request_id", "transaction_id"})
    return klass(
        doc["protocol"],
        kind,
        doc["request_id"],
        doc["transaction_id"],
        _expectation_from(doc["expected"]),
        _binding_from(doc["binding"]),
    )


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
    B2aRecoveryPhase.DEPROVISION_PENDING: BrokerCheckpoint.DEPROVISION_INTENT,
    B2aRecoveryPhase.DEPROVISIONED: BrokerCheckpoint.DEPROVISIONED,
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
    BrokerCheckpoint.DEPROVISION_INTENT: {BrokerCheckpoint.DEPROVISIONED, BrokerCheckpoint.BLOCKED_DRIFT},
    BrokerCheckpoint.DEPROVISIONED: {BrokerCheckpoint.DEPROVISIONED},
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
    elif checkpoint is BrokerCheckpoint.DEPROVISION_INTENT:
        if obj is BrokerObjectState.FINAL_COMPLETE and reg is na:
            return _decision(BrokerRecoveryAction.DEPROVISION_HOME, None)
        if obj is BrokerObjectState.ABSENT and reg is na:
            return _decision(BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.DEPROVISIONED, BrokerResultCode.COMMITTED)
    elif checkpoint is BrokerCheckpoint.COMMITTED:
        if observation == status.observation and obj in (BrokerObjectState.FINAL_COMPLETE, BrokerObjectState.REPLACEMENT_SWITCHED) and reg is BrokerRegistryState.CURRENT:
            return _decision(BrokerRecoveryAction.RETURN_COMMITTED, BrokerCheckpoint.COMMITTED, BrokerResultCode.COMMITTED)
    elif checkpoint is BrokerCheckpoint.ROLLED_BACK:
        if observation == status.observation and obj is BrokerObjectState.ROLLED_BACK and reg is na:
            return _decision(BrokerRecoveryAction.RETURN_ROLLED_BACK, BrokerCheckpoint.ROLLED_BACK, BrokerResultCode.ROLLED_BACK)
    elif checkpoint is BrokerCheckpoint.DEPROVISIONED:
        if observation == status.observation and obj is BrokerObjectState.ABSENT and reg is na:
            return _decision(BrokerRecoveryAction.RETURN_COMMITTED, BrokerCheckpoint.DEPROVISIONED, BrokerResultCode.COMMITTED)
    return _blocked_decision()
