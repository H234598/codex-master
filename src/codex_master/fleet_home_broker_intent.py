"""Immutable root-broker intent contract and strict canonical codec."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re

from codex_master.fleet_home_broker_protocol import (
    ChpbTransactionOperation,
    PolicyBinding,
    PrincipalBinding,
)
from codex_master.fleet_home_broker_runtime import BrokerReleaseSpec


MAX_BROKER_INTENT_BYTES = 16 * 1024
MAX_BROKER_INTENT_TEXT_BYTES = 256
MAX_BROKER_INTENT_GENERATION = (1 << 63) - 1
MAX_BROKER_INTENT_TIMESTAMP = (1 << 63) - 1


class BrokerIntentCode(str, Enum):
    """Stable, value-free failure categories for the intent boundary."""

    INVALID_TYPE = "invalid_type"
    INVALID_FIELD = "invalid_field"
    UNKNOWN_FIELD = "unknown_field"
    MISSING_FIELD = "missing_field"
    DUPLICATE_KEY = "duplicate_key"
    INVALID_UTF8 = "invalid_utf8"
    INTENT_TOO_LARGE = "intent_too_large"
    NON_CANONICAL = "non_canonical"
    DIGEST_MISMATCH = "digest_mismatch"
    EXPIRED = "expired"
    INVERTED_TIMESTAMPS = "inverted_timestamps"
    FORBIDDEN_VALUE = "forbidden_value"
    QUEUE_FULL = "queue_full"


class BrokerIntentError(ValueError):
    """Stable public error carrying only a :class:`BrokerIntentCode`."""

    __slots__ = ("code",)
    code: BrokerIntentCode

    def __init__(self, code: BrokerIntentCode):
        self.code = code
        super().__init__(code.value)


class BrokerIntentOperation(str, Enum):
    PROVISION = "provision"
    REPLACE = "replace"
    DEPROVISION = "deprovision"


_INTENT_FIELDS = (
    "schema_version",
    "intent_generation",
    "operation",
    "transaction_id",
    "request_id",
    "agent_id",
    "manifest_generation",
    "unit_generation",
    "policy_generation",
    "fencing_epoch",
    "store_uuid",
    "slot_id",
    "mcs_pair",
    "projection_digest",
    "joint_release_id",
    "server_digest",
    "broker_manifest_digest",
    "credential_binding_ref",
    "credential_generation",
    "created_at_unix_ms",
    "expires_at_unix_ms",
    "nonce",
    "digest",
)
_INTENT_FIELD_SET = frozenset(_INTENT_FIELDS)
_INTENT_PAYLOAD_FIELDS = _INTENT_FIELDS[:-1]
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@+\-]{0,255}\Z", re.ASCII)
_MCS_PAIR = re.compile(r"c(0|[1-9][0-9]{0,3}),c(0|[1-9][0-9]{0,3})\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_FORBIDDEN_MARKERS = (
    "secret",
    "token",
    "password",
    "private",
    "pickle",
    "reducer",
    "callable",
    "module",
)
_CHPB_OPERATION_VALUES = frozenset(item.value for item in ChpbTransactionOperation)

# These imports are part of the A0 dependency closure.  The scalar manifest
# deliberately does not serialize any of these objects; later slices consume
# this same closure when reconstructing authoritative bindings.
_A0_CONTRACT_TYPES = (
    ChpbTransactionOperation,
    PrincipalBinding,
    PolicyBinding,
    BrokerReleaseSpec,
)


@dataclass(frozen=True, slots=True)
class BrokerIntentV1:
    schema_version: int
    intent_generation: int
    operation: BrokerIntentOperation
    transaction_id: str
    request_id: str
    agent_id: str
    manifest_generation: int
    unit_generation: int
    policy_generation: int
    fencing_epoch: int
    store_uuid: str
    slot_id: str
    mcs_pair: str
    projection_digest: str
    joint_release_id: str
    server_digest: str
    broker_manifest_digest: str
    credential_binding_ref: str
    credential_generation: int
    created_at_unix_ms: int
    expires_at_unix_ms: int
    nonce: str
    digest: str

    def __post_init__(self) -> None:
        _validate_intent(self)


def _fail(code: BrokerIntentCode) -> None:
    raise BrokerIntentError(code)


def _integer(value: object, low: int, high: int) -> int:
    if type(value) is not int:
        _fail(BrokerIntentCode.INVALID_TYPE)
    if not low <= value <= high:
        _fail(BrokerIntentCode.INVALID_FIELD)
    return value


def _identifier(value: object) -> str:
    if type(value) is not str:
        _fail(BrokerIntentCode.INVALID_TYPE)
    if (
        not value
        or value != value.strip()
        or any(character.isspace() for character in value)
    ):
        _fail(BrokerIntentCode.INVALID_FIELD)
    if (
        "/" in value
        or "\\" in value
        or (len(value) > 1 and value[1] == ":" and value[0].isalpha())
    ):
        _fail(BrokerIntentCode.FORBIDDEN_VALUE)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        _fail(BrokerIntentCode.INVALID_FIELD)
    if len(encoded) > MAX_BROKER_INTENT_TEXT_BYTES:
        _fail(BrokerIntentCode.INVALID_FIELD)
    if _IDENTIFIER.fullmatch(value) is None:
        _fail(BrokerIntentCode.INVALID_FIELD)
    lowered = value.casefold()
    if any(marker in lowered for marker in _FORBIDDEN_MARKERS):
        _fail(BrokerIntentCode.FORBIDDEN_VALUE)
    return value


def _digest(value: object) -> str:
    if type(value) is not str:
        _fail(BrokerIntentCode.INVALID_TYPE)
    if _SHA256.fullmatch(value) is None:
        _fail(BrokerIntentCode.INVALID_FIELD)
    return value


def _mcs_pair(value: object) -> str:
    if type(value) is not str:
        _fail(BrokerIntentCode.INVALID_TYPE)
    if _MCS_PAIR.fullmatch(value) is None:
        _fail(BrokerIntentCode.INVALID_FIELD)
    low, high = (int(part[1:]) for part in value.split(","))
    if not 0 <= low < high <= 1023:
        _fail(BrokerIntentCode.INVALID_FIELD)
    return value


def _validate_intent(intent: object) -> BrokerIntentV1:
    if type(intent) is not BrokerIntentV1:
        _fail(BrokerIntentCode.INVALID_TYPE)
    _integer(intent.schema_version, 1, 1)
    _integer(intent.intent_generation, 1, MAX_BROKER_INTENT_GENERATION)
    if type(intent.operation) is not BrokerIntentOperation:
        _fail(BrokerIntentCode.INVALID_TYPE)
    if intent.operation.value not in _CHPB_OPERATION_VALUES:
        _fail(BrokerIntentCode.INVALID_FIELD)
    _identifier(intent.transaction_id)
    _identifier(intent.request_id)
    _identifier(intent.agent_id)
    _integer(intent.manifest_generation, 1, MAX_BROKER_INTENT_GENERATION)
    _integer(intent.unit_generation, 1, MAX_BROKER_INTENT_GENERATION)
    _integer(intent.policy_generation, 1, MAX_BROKER_INTENT_GENERATION)
    _integer(intent.fencing_epoch, 0, MAX_BROKER_INTENT_GENERATION)
    _identifier(intent.store_uuid)
    _identifier(intent.slot_id)
    _mcs_pair(intent.mcs_pair)
    _digest(intent.projection_digest)
    _identifier(intent.joint_release_id)
    _digest(intent.server_digest)
    _digest(intent.broker_manifest_digest)
    _identifier(intent.credential_binding_ref)
    _integer(intent.credential_generation, 1, MAX_BROKER_INTENT_GENERATION)
    _integer(intent.created_at_unix_ms, 0, MAX_BROKER_INTENT_TIMESTAMP)
    _integer(intent.expires_at_unix_ms, 0, MAX_BROKER_INTENT_TIMESTAMP)
    if intent.expires_at_unix_ms <= intent.created_at_unix_ms:
        _fail(BrokerIntentCode.INVERTED_TIMESTAMPS)
    _identifier(intent.nonce)
    _digest(intent.digest)
    return intent


def _intent_document(
    intent: BrokerIntentV1, *, include_digest: bool
) -> dict[str, object]:
    document: dict[str, object] = {}
    for field in _INTENT_PAYLOAD_FIELDS:
        value = getattr(intent, field)
        document[field] = value.value if type(value) is BrokerIntentOperation else value
    if include_digest:
        document["digest"] = intent.digest
    return document


def _json_bytes(document: dict[str, object], *, trailing_newline: bool) -> bytes:
    try:
        encoded = json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError):
        _fail(BrokerIntentCode.INVALID_FIELD)
    return encoded + (b"\n" if trailing_newline else b"")


def canonical_intent_payload(intent: BrokerIntentV1) -> bytes:
    """Return the canonical digest preimage, excluding ``digest`` itself."""

    try:
        _validate_intent(intent)
        encoded = _json_bytes(
            _intent_document(intent, include_digest=False), trailing_newline=False
        )
    except BrokerIntentError:
        raise
    except Exception:
        _fail(BrokerIntentCode.INVALID_TYPE)
    if len(encoded) > MAX_BROKER_INTENT_BYTES:
        _fail(BrokerIntentCode.INTENT_TOO_LARGE)
    return encoded


def encode_broker_intent(intent: BrokerIntentV1) -> bytes:
    """Encode an intent only when its lowercase SHA-256 digest is correct."""

    try:
        _validate_intent(intent)
        preimage = canonical_intent_payload(intent)
        expected_digest = hashlib.sha256(preimage).hexdigest()
        if intent.digest != expected_digest:
            _fail(BrokerIntentCode.DIGEST_MISMATCH)
        encoded = _json_bytes(
            _intent_document(intent, include_digest=True), trailing_newline=True
        )
    except BrokerIntentError:
        raise
    except Exception:
        _fail(BrokerIntentCode.INVALID_TYPE)
    if len(encoded) > MAX_BROKER_INTENT_BYTES:
        _fail(BrokerIntentCode.INTENT_TOO_LARGE)
    return encoded


class _DecodeFailure(Exception):
    __slots__ = ("code",)

    def __init__(self, code: BrokerIntentCode):
        self.code = code


def _object_pairs(pairs: list[tuple[object, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str:
            raise _DecodeFailure(BrokerIntentCode.INVALID_TYPE)
        if key in document:
            raise _DecodeFailure(BrokerIntentCode.DUPLICATE_KEY)
        document[key] = value
    return document


def _reject_constant(_value: str) -> None:
    raise _DecodeFailure(BrokerIntentCode.INVALID_FIELD)


def _decode_document(payload: bytes) -> dict[str, object]:
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _fail(BrokerIntentCode.INVALID_UTF8)
    if text.startswith("\ufeff"):
        _fail(BrokerIntentCode.INVALID_UTF8)
    try:
        document = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except _DecodeFailure as error:
        _fail(error.code)
    except (
        json.JSONDecodeError,
        UnicodeError,
        OverflowError,
        RecursionError,
        ValueError,
    ):
        _fail(BrokerIntentCode.INVALID_FIELD)
    if type(document) is not dict:
        _fail(BrokerIntentCode.INVALID_TYPE)
    actual = set(document)
    if not actual <= _INTENT_FIELD_SET:
        _fail(BrokerIntentCode.UNKNOWN_FIELD)
    if actual != _INTENT_FIELD_SET:
        _fail(BrokerIntentCode.MISSING_FIELD)
    return document


def _enum(value: object) -> BrokerIntentOperation:
    if type(value) is not str:
        _fail(BrokerIntentCode.INVALID_TYPE)
    try:
        return BrokerIntentOperation(value)
    except ValueError:
        _fail(BrokerIntentCode.INVALID_FIELD)


def _intent_from_document(document: dict[str, object]) -> BrokerIntentV1:
    try:
        return BrokerIntentV1(
            document["schema_version"],
            document["intent_generation"],
            _enum(document["operation"]),
            document["transaction_id"],
            document["request_id"],
            document["agent_id"],
            document["manifest_generation"],
            document["unit_generation"],
            document["policy_generation"],
            document["fencing_epoch"],
            document["store_uuid"],
            document["slot_id"],
            document["mcs_pair"],
            document["projection_digest"],
            document["joint_release_id"],
            document["server_digest"],
            document["broker_manifest_digest"],
            document["credential_binding_ref"],
            document["credential_generation"],
            document["created_at_unix_ms"],
            document["expires_at_unix_ms"],
            document["nonce"],
            document["digest"],
        )
    except BrokerIntentError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        _fail(BrokerIntentCode.INVALID_TYPE)


def decode_broker_intent(payload: bytes, *, now_unix_ms: int) -> BrokerIntentV1:
    """Decode exactly one canonical, live, digest-bound intent."""

    if type(payload) is not bytes:
        _fail(BrokerIntentCode.INVALID_TYPE)
    if not payload:
        _fail(BrokerIntentCode.INVALID_FIELD)
    if len(payload) > MAX_BROKER_INTENT_BYTES:
        _fail(BrokerIntentCode.INTENT_TOO_LARGE)
    _integer(now_unix_ms, 0, MAX_BROKER_INTENT_TIMESTAMP)
    document = _decode_document(payload)
    intent = _intent_from_document(document)
    expected_digest = hashlib.sha256(canonical_intent_payload(intent)).hexdigest()
    if intent.digest != expected_digest:
        _fail(BrokerIntentCode.DIGEST_MISMATCH)
    if now_unix_ms >= intent.expires_at_unix_ms:
        _fail(BrokerIntentCode.EXPIRED)
    try:
        canonical = encode_broker_intent(intent)
    except BrokerIntentError as error:
        raise error
    if canonical != payload:
        _fail(BrokerIntentCode.NON_CANONICAL)
    return intent


__all__ = [
    "MAX_BROKER_INTENT_BYTES",
    "MAX_BROKER_INTENT_GENERATION",
    "MAX_BROKER_INTENT_TEXT_BYTES",
    "MAX_BROKER_INTENT_TIMESTAMP",
    "BrokerIntentCode",
    "BrokerIntentError",
    "BrokerIntentOperation",
    "BrokerIntentV1",
    "canonical_intent_payload",
    "decode_broker_intent",
    "encode_broker_intent",
]
