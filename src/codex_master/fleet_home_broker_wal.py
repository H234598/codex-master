"""Strict, injected CHPB/2 broker status WAL."""

from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol

from .fleet_home_broker_protocol import (
    B2aRecoveryPhase,
    BrokerCheckpoint,
    BrokerObservation,
    BrokerRecoveryAction,
    BrokerReply,
    BrokerResultCode,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    RecoveryDecision,
    TransactionStatus,
    decode_chpb_message,
    decide_broker_recovery,
    encode_chpb_message,
    is_checkpoint_transition_allowed,
)


_MAGIC = b"CHPB/2-WAL-Magic"
_DIGEST_BYTES = 64
_GENESIS = "0" * _DIGEST_BYTES
_MAX_SEQUENCE = 2**64 - 1
_MIN_RECORD_BYTES = len(_MAGIC) + 8 + _DIGEST_BYTES + 4 + _DIGEST_BYTES
_INITIAL_CHECKPOINTS = {
    BrokerCheckpoint.CREATE_INTENT,
    BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
    BrokerCheckpoint.DEPROVISION_INTENT,
}


class WalValidationError(ValueError):
    """Raised when a WAL record or status payload is not strict CHPB/2."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class WalRecord:
    sequence: int
    previous_digest: str
    digest: str
    status: TransactionStatus


@dataclass(frozen=True, slots=True)
class WalRecovery:
    status: TransactionStatus | None
    decision: RecoveryDecision


class WalOperations(Protocol):
    def read_all(self) -> tuple[bytes, ...]:
        ...

    def append(self, record: bytes) -> None:
        ...

    def fsync_wal(self) -> None:
        ...

    def fsync_parent(self) -> None:
        ...


def _invalid(message: str) -> None:
    raise WalValidationError(message)


def _digest_text(value: object, field: str) -> str:
    if type(value) is not str or len(value) != _DIGEST_BYTES or any(character not in "0123456789abcdef" for character in value):
        _invalid(f"{field} is not a lowercase SHA-256 digest")
    return value


def _validate_record_fields(record: WalRecord) -> None:
    if type(record) is not WalRecord:
        _invalid("record type is invalid")
    if type(record.sequence) is not int or not 1 <= record.sequence <= _MAX_SEQUENCE:
        _invalid("record sequence is outside strict bounds")
    _digest_text(record.previous_digest, "previous digest")
    _digest_text(record.digest, "digest")
    if record.sequence == 1 and record.previous_digest != _GENESIS:
        _invalid("record one does not use genesis digest")
    if record.sequence > 1 and record.previous_digest == _GENESIS:
        _invalid("non-genesis record uses genesis digest")


def encode_status_payload(status: TransactionStatus) -> bytes:
    if type(status) is not TransactionStatus:
        _invalid("status type is invalid")
    try:
        result = status.terminal_result if status.terminal_result is not None else BrokerResultCode.PENDING
        message = BrokerReply(CHPB_PROTOCOL, ChpbMessageKind.REPLY, status.binding.transaction_id, result, status, None)
        return encode_chpb_message(message)
    except Exception as exc:
        raise WalValidationError("status payload is invalid") from exc


def decode_status_payload(raw: bytes) -> TransactionStatus:
    if type(raw) is not bytes:
        _invalid("status payload type is invalid")
    try:
        message = decode_chpb_message(raw)
    except Exception as exc:
        raise WalValidationError("status payload is invalid") from exc
    if type(message) is not BrokerReply or message.protocol != CHPB_PROTOCOL or message.kind is not ChpbMessageKind.REPLY:
        _invalid("status payload is not a CHPB/2 reply")
    if message.attestation is not None or message.transaction is None:
        _invalid("status payload has an attestation or no transaction")
    status = message.transaction
    if message.request_id != status.binding.transaction_id:
        _invalid("status payload request binding is invalid")
    expected_result = status.terminal_result if status.terminal_result is not None else BrokerResultCode.PENDING
    if message.result is not expected_result:
        _invalid("status payload result is invalid")
    if encode_status_payload(status) != raw:
        _invalid("status payload is not canonical")
    return status


def _preimage(sequence: int, previous_digest: str, payload: bytes) -> bytes:
    if type(payload) is not bytes:
        _invalid("record payload type is invalid")
    return _MAGIC + sequence.to_bytes(8, "big") + previous_digest.encode("ascii") + len(payload).to_bytes(4, "big") + payload


def _record_from_status(sequence: int, previous_digest: str, status: TransactionStatus, payload: bytes) -> WalRecord:
    preimage = _preimage(sequence, previous_digest, payload)
    return WalRecord(sequence, previous_digest, sha256(preimage).hexdigest(), status)


def encode_wal_record(record: WalRecord) -> bytes:
    _validate_record_fields(record)
    payload = encode_status_payload(record.status)
    preimage = _preimage(record.sequence, record.previous_digest, payload)
    digest = sha256(preimage).hexdigest()
    if record.digest != digest:
        _invalid("record digest does not match preimage")
    return preimage + digest.encode("ascii")


def decode_wal_record(raw: bytes) -> WalRecord:
    if type(raw) is not bytes or len(raw) < _MIN_RECORD_BYTES:
        _invalid("record framing is truncated")
    if raw[: len(_MAGIC)] != _MAGIC:
        _invalid("record magic is invalid")
    sequence_start = len(_MAGIC)
    sequence = int.from_bytes(raw[sequence_start : sequence_start + 8], "big")
    previous_start = sequence_start + 8
    previous_digest = raw[previous_start : previous_start + _DIGEST_BYTES]
    length_start = previous_start + _DIGEST_BYTES
    payload_length = int.from_bytes(raw[length_start : length_start + 4], "big")
    payload_start = length_start + 4
    expected_length = payload_start + payload_length + _DIGEST_BYTES
    if len(raw) != expected_length:
        _invalid("record length is not exact")
    digest_raw = raw[-_DIGEST_BYTES:]
    try:
        previous_text = previous_digest.decode("ascii")
        digest_text = digest_raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WalValidationError("record digest encoding is invalid") from exc
    _digest_text(previous_text, "previous digest")
    _digest_text(digest_text, "digest")
    if sha256(raw[:-_DIGEST_BYTES]).hexdigest() != digest_text:
        _invalid("record digest does not match preimage")
    status = decode_status_payload(raw[payload_start : payload_start + payload_length])
    record = WalRecord(sequence, previous_text, digest_text, status)
    _validate_record_fields(record)
    return record


def _validate_initial(status: TransactionStatus) -> None:
    if status.checkpoint not in _INITIAL_CHECKPOINTS:
        _invalid("record one is not an initial mutation checkpoint")


def _validate_following(previous: TransactionStatus, current: TransactionStatus) -> None:
    if previous.binding != current.binding or previous.population_total != current.population_total:
        _invalid("WAL status binding or population total changed")
    if not is_checkpoint_transition_allowed(previous.checkpoint, current.checkpoint):
        _invalid("WAL checkpoint transition is not allowed")
    old_index = previous.observation.population_index
    new_index = current.observation.population_index
    if new_index < old_index or new_index > old_index + 1:
        _invalid("WAL population index is not monotonic")


def _validated_chain(raw_records: tuple[bytes, ...]) -> tuple[WalRecord, ...]:
    if type(raw_records) is not tuple:
        _invalid("WAL read result is not a tuple")
    records = []
    expected_sequence = 1
    expected_previous = _GENESIS
    for raw in raw_records:
        record = decode_wal_record(raw)
        if record.sequence != expected_sequence or record.previous_digest != expected_previous:
            _invalid("WAL sequence or hash chain is broken")
        if not records:
            _validate_initial(record.status)
        else:
            _validate_following(records[-1].status, record.status)
        records.append(record)
        expected_sequence += 1
        expected_previous = record.digest
    return tuple(records)


def append_status(operations: WalOperations, status: TransactionStatus) -> WalRecord:
    payload = encode_status_payload(status)
    records = _validated_chain(operations.read_all())
    if records:
        previous = records[-1]
        if previous.sequence == _MAX_SEQUENCE:
            _invalid("WAL sequence cannot advance")
        _validate_following(previous.status, status)
        record = _record_from_status(previous.sequence + 1, previous.digest, status, payload)
    else:
        _validate_initial(status)
        record = _record_from_status(1, _GENESIS, status, payload)
    wire = encode_wal_record(record)
    operations.append(wire)
    operations.fsync_wal()
    operations.fsync_parent()
    return record


def _blocked_decision() -> RecoveryDecision:
    return RecoveryDecision(
        BrokerRecoveryAction.RETURN_BLOCKED,
        B2aRecoveryPhase.BLOCKED,
        BrokerCheckpoint.BLOCKED_DRIFT,
        BrokerResultCode.BLOCKED_DRIFT,
    )


def recover_status(operations: WalOperations, observation: BrokerObservation) -> WalRecovery:
    try:
        records = _validated_chain(operations.read_all())
    except Exception:
        return WalRecovery(None, _blocked_decision())
    if not records:
        return WalRecovery(None, _blocked_decision())
    try:
        decision = decide_broker_recovery(records[-1].status, observation)
    except Exception:
        return WalRecovery(None, _blocked_decision())
    return WalRecovery(records[-1].status, decision)


__all__ = [
    "WalOperations",
    "WalRecord",
    "WalRecovery",
    "WalValidationError",
    "append_status",
    "decode_status_payload",
    "decode_wal_record",
    "encode_status_payload",
    "encode_wal_record",
    "recover_status",
]
