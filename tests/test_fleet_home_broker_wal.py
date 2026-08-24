import ast
import dataclasses
from hashlib import sha256
import inspect

import pytest

from codex_master.fleet_home_broker_protocol import (
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRecoveryAction,
    BrokerRegistryState,
    BrokerReply,
    BrokerResultCode,
    ChpbMessageKind,
    ChpbTransactionOperation,
    CHPB_PROTOCOL,
    PolicyBinding,
    PrincipalBinding,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
    decide_broker_recovery,
    encode_chpb_message,
)
from codex_master.fleet_home_broker_wal import (
    WalOperations,
    WalRecord,
    WalRecovery,
    WalValidationError,
    append_status,
    decode_status_payload,
    decode_wal_record,
    encode_status_payload,
    encode_wal_record,
    recover_status,
)


AGENT = "bee_1"
PROJECTION = "a" * 64
INVOCATION = "1" * 32
TRANSACTION = "2" * 32
STORE = "3" * 32
MAGIC = b"CHPB/2-WAL-Magic"
GENESIS = "0" * 64


class FakeWalOperations:
    def __init__(self, records=(), fail_at=None):
        self.records = list(records)
        self.fail_at = fail_at
        self.events = []

    def read_all(self):
        self.events.append("read")
        return tuple(self.records)

    def append(self, record):
        self.events.append("append")
        if self.fail_at == "append":
            raise RuntimeError("append cutpoint")
        self.records.append(record)

    def fsync_wal(self):
        self.events.append("fsync_wal")
        if self.fail_at == "fsync_wal":
            raise RuntimeError("wal fsync cutpoint")

    def fsync_parent(self):
        self.events.append("fsync_parent")
        if self.fail_at == "fsync_parent":
            raise RuntimeError("parent fsync cutpoint")


def principal(**changes):
    values = {
        "agent_id": AGENT,
        "manifest_generation": 3,
        "unit_generation": 9,
        "cgroup_dev": 0,
        "cgroup_ino": 1,
        "invocation_id": INVOCATION,
        "mcs_pair": "c0,c1",
        "fencing_epoch": 4,
    }
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


def binding(checkpoint=BrokerCheckpoint.CREATE_INTENT, **changes):
    values = {
        "operation": operation_for_checkpoint(checkpoint),
        "transaction_id": TRANSACTION,
        "store_uuid": STORE,
        "principal": principal(),
        "policy": PolicyBinding(7, PROJECTION),
    }
    values.update(changes)
    return TransactionBinding(**values)


def observation(state=BrokerObjectState.ABSENT, registry=BrokerRegistryState.NOT_APPLICABLE, index=0):
    return BrokerObservation(state, registry, index)


def status(checkpoint=BrokerCheckpoint.CREATE_INTENT, *, obs=None, total=1, bind=None, terminal=None):
    if obs is None:
        obs = observation()
    if bind is None:
        bind = binding(checkpoint)
    if terminal is None:
        terminal = {
            BrokerCheckpoint.COMMITTED: BrokerResultCode.COMMITTED,
            BrokerCheckpoint.DEPROVISIONED: BrokerResultCode.COMMITTED,
            BrokerCheckpoint.ROLLED_BACK: BrokerResultCode.ROLLED_BACK,
            BrokerCheckpoint.BLOCKED_DRIFT: BrokerResultCode.BLOCKED_DRIFT,
        }.get(checkpoint)
    return TransactionStatus(bind, b2a_phase_for_checkpoint(checkpoint), checkpoint, obs, total, terminal)


def wire_with_fields(sequence, previous_digest, payload):
    preimage = (
        MAGIC
        + sequence.to_bytes(8, "big")
        + previous_digest.encode("ascii")
        + len(payload).to_bytes(4, "big")
        + payload
    )
    return preimage + sha256(preimage).hexdigest().encode("ascii")


def first_wire(value=None):
    fake = FakeWalOperations()
    record = append_status(fake, value or status())
    return record, fake.records[0]


def test_wal_module_exports_immutable_slotted_contract_types():
    for klass in (WalRecord, WalRecovery):
        assert dataclasses.is_dataclass(klass)
        assert klass.__dataclass_params__.frozen
        assert hasattr(klass, "__slots__")
    assert all(hasattr(WalOperations, name) for name in ("read_all", "append", "fsync_wal", "fsync_parent"))


def test_status_payload_matches_chpb2_golden_and_roundtrips():
    value = status()
    raw = encode_status_payload(value)
    assert raw == b'{"attestation":null,"kind":"reply","protocol":"CHPB/2","request_id":"22222222222222222222222222222222","result":"pending","transaction":{"b2a_phase":"absent_create_pending","binding":{"operation":"provision","policy":{"policy_generation":7,"projection_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"principal":{"agent_id":"bee_1","cgroup_dev":0,"cgroup_ino":1,"fencing_epoch":4,"invocation_id":"11111111111111111111111111111111","manifest_generation":3,"mcs_pair":"c0,c1","unit_generation":9},"store_uuid":"33333333333333333333333333333333","transaction_id":"22222222222222222222222222222222"},"checkpoint":"create_intent","observation":{"object_state":"absent","population_index":0,"registry_state":"not_applicable"},"population_total":1,"terminal_result":null}}\n'
    assert decode_status_payload(raw) == value
    assert encode_status_payload(decode_status_payload(raw)) == raw


def test_terminal_status_payload_uses_terminal_result_and_no_attestation():
    value = status(
        BrokerCheckpoint.COMMITTED,
        obs=observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1),
    )
    raw = encode_status_payload(value)
    assert b'"result":"committed"' in raw
    assert b'"attestation":null' in raw
    assert decode_status_payload(raw) == value


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{}\n",
        b'{"kind":"attest_home"}\n',
        encode_chpb_message(
            BrokerReply(CHPB_PROTOCOL, ChpbMessageKind.REPLY, TRANSACTION, BrokerResultCode.PENDING, status(), None)
        ).replace(b'"request_id":"22222222222222222222222222222222"', b'"request_id":"11111111111111111111111111111111"'),
        encode_chpb_message(
            BrokerReply(CHPB_PROTOCOL, ChpbMessageKind.REPLY, TRANSACTION, BrokerResultCode.PENDING, status(), None)
        ).replace(b'"result":"pending"', b'"result":"ok"'),
    ],
)
def test_status_payload_rejects_non_reply_noncanonical_and_wrong_binding_forms(raw):
    with pytest.raises(WalValidationError):
        decode_status_payload(raw)


def test_framing_digest_length_and_roundtrip_are_byte_exact():
    record, raw = first_wire()
    payload = encode_status_payload(status())
    expected = wire_with_fields(1, GENESIS, payload)
    assert raw == expected
    assert record == WalRecord(1, GENESIS, sha256(expected[:-64]).hexdigest(), status())
    assert encode_wal_record(record) == raw
    assert decode_wal_record(raw) == record


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: b"X" + raw[1:],
        lambda raw: raw[:-1],
        lambda raw: raw + b"trailing",
        lambda raw: raw[:len(MAGIC) + 8 + 64] + (999999).to_bytes(4, "big") + raw[len(MAGIC) + 8 + 68:],
        lambda raw: raw[:-64] + raw[-64:].upper(),
        lambda raw: raw[:-64] + (b"f" * 64),
    ],
)
def test_framing_rejects_magic_truncation_trailing_length_and_digest_tamper(mutate):
    _, raw = first_wire()
    with pytest.raises(WalValidationError):
        decode_wal_record(mutate(raw))


def test_sequence_and_genesis_are_strictly_framed():
    _, raw = first_wire()
    payload = encode_status_payload(status())
    for candidate in (
        wire_with_fields(0, GENESIS, payload),
        wire_with_fields(1, "f" * 64, payload),
        wire_with_fields(2, GENESIS, payload),
    ):
        with pytest.raises(WalValidationError):
            decode_wal_record(candidate)


@pytest.mark.parametrize(
    "checkpoint",
    [
        BrokerCheckpoint.STAGING_PINNED,
        BrokerCheckpoint.POPULATE_PENDING,
        BrokerCheckpoint.PUBLISH_INTENT,
        BrokerCheckpoint.COMMITTED,
        BrokerCheckpoint.REPLACEMENT_PREPARED,
        BrokerCheckpoint.DEPROVISIONED,
    ],
)
def test_record_one_accepts_only_initial_mutation_checkpoints(checkpoint):
    fake = FakeWalOperations()
    with pytest.raises(WalValidationError):
        append_status(fake, status(checkpoint))
    assert fake.events == ["read"]


@pytest.mark.parametrize(
    "checkpoint",
    [
        BrokerCheckpoint.CREATE_INTENT,
        BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
        BrokerCheckpoint.DEPROVISION_INTENT,
    ],
)
def test_record_one_accepts_each_operation_initial_mutation_checkpoint(checkpoint):
    fake = FakeWalOperations()
    assert append_status(fake, status(checkpoint)).sequence == 1
    assert len(fake.records) == 1


def test_following_record_requires_allowed_transition_same_binding_total_and_monotonic_population():
    fake = FakeWalOperations()
    first = append_status(fake, status())
    second_status = status(BrokerCheckpoint.STAGING_PINNED)
    second = append_status(fake, second_status)
    assert second.sequence == 2
    assert second.previous_digest == first.digest

    for invalid in (
        status(BrokerCheckpoint.POPULATE_PENDING),
        status(BrokerCheckpoint.STAGING_PINNED, total=2),
        status(BrokerCheckpoint.STAGING_PINNED, bind=binding(BrokerCheckpoint.STAGING_PINNED, principal=principal(agent_id="bee_2"))),
        status(BrokerCheckpoint.STAGING_PINNED, bind=binding(BrokerCheckpoint.STAGING_PINNED, policy=PolicyBinding(8, PROJECTION))),
        status(BrokerCheckpoint.STAGING_PINNED, bind=binding(BrokerCheckpoint.STAGING_PINNED, principal=principal(fencing_epoch=5))),
        status(BrokerCheckpoint.STAGING_PINNED, obs=observation(index=2), total=3),
    ):
        candidate = FakeWalOperations()
        append_status(candidate, status())
        with pytest.raises(WalValidationError):
            append_status(candidate, invalid)

    indexed = FakeWalOperations()
    append_status(indexed, status(obs=observation(index=1), total=2))
    with pytest.raises(WalValidationError):
        append_status(indexed, status(BrokerCheckpoint.STAGING_PINNED, obs=observation(index=0), total=2))


def test_existing_sequence_gap_hash_fork_and_tampered_chain_are_rejected_before_append():
    first, raw = first_wire()
    payload = encode_status_payload(status(BrokerCheckpoint.STAGING_PINNED))
    gap = wire_with_fields(3, first.digest, payload)
    fork = wire_with_fields(2, "f" * 64, payload)
    tampered = raw[:-64] + b"f" * 64
    for records in ((gap,), (raw, gap), (raw, fork), (tampered,)):
        fake = FakeWalOperations(records)
        with pytest.raises(WalValidationError):
            append_status(fake, status(BrokerCheckpoint.STAGING_PINNED))
        assert fake.events == ["read"]


@pytest.mark.parametrize("fail_at", [None, "append", "fsync_wal", "fsync_parent"])
def test_append_order_and_each_cutpoint_is_strict(fail_at):
    fake = FakeWalOperations(fail_at=fail_at)
    if fail_at is None:
        result = append_status(fake, status())
        assert result.sequence == 1
        assert fake.events == ["read", "append", "fsync_wal", "fsync_parent"]
    else:
        with pytest.raises(RuntimeError, match="cutpoint"):
            append_status(fake, status())
        expected = ["read", "append"]
        if fail_at != "append":
            expected.extend(["fsync_wal"])
        if fail_at == "fsync_parent":
            expected.append("fsync_parent")
        assert fake.events == expected


def test_recovery_is_read_only_and_returns_exact_existing_decision():
    fake = FakeWalOperations()
    value = status()
    append_status(fake, value)
    fake.events.clear()
    observed = observation(BrokerObjectState.STAGING_EMPTY)
    result = recover_status(fake, observed)
    assert result == WalRecovery(value, decide_broker_recovery(value, observed))
    assert result.decision.action is BrokerRecoveryAction.PERSIST_CHECKPOINT
    assert fake.events == ["read"]


def test_recovery_uses_last_status_and_blocks_invalid_observation_without_repair():
    fake = FakeWalOperations()
    first = append_status(fake, status())
    append_status(fake, status(BrokerCheckpoint.STAGING_PINNED))
    fake.events.clear()
    observed = observation(BrokerObjectState.DRIFT, BrokerRegistryState.FOREIGN, 0)
    result = recover_status(fake, observed)
    expected = decide_broker_recovery(status(BrokerCheckpoint.STAGING_PINNED), observed)
    assert result.status == status(BrokerCheckpoint.STAGING_PINNED)
    assert result.decision == expected
    assert result.decision.result is BrokerResultCode.BLOCKED_DRIFT
    assert first.digest != result.status.binding.transaction_id
    assert fake.events == ["read"]


def test_recovery_empty_corrupt_foreign_and_forked_wal_has_no_status_and_blocks():
    _, raw = first_wire()
    payload = encode_status_payload(status(BrokerCheckpoint.STAGING_PINNED))
    candidates = (
        (),
        (b"foreign",),
        (raw[:-1],),
        (raw, wire_with_fields(2, "f" * 64, payload)),
    )
    for records in candidates:
        fake = FakeWalOperations(records)
        result = recover_status(fake, observation(BrokerObjectState.STAGING_EMPTY))
        assert result.status is None
        assert result.decision.action is BrokerRecoveryAction.RETURN_BLOCKED
        assert result.decision.next_checkpoint is BrokerCheckpoint.BLOCKED_DRIFT
        assert result.decision.result is BrokerResultCode.BLOCKED_DRIFT
        assert fake.events == ["read"]


def test_recovery_calls_existing_decision_only_after_full_chain_validation(monkeypatch):
    fake = FakeWalOperations()
    value = status()
    append_status(fake, value)
    calls = []
    expected = decide_broker_recovery(value, observation(BrokerObjectState.STAGING_EMPTY))

    def decide(last_status, observed):
        calls.append((last_status, observed))
        return expected

    import codex_master.fleet_home_broker_wal as wal

    monkeypatch.setattr(wal, "decide_broker_recovery", decide)
    observed = observation(BrokerObjectState.STAGING_EMPTY)
    assert recover_status(fake, observed).decision == expected
    assert calls == [(value, observed)]

    fake.records[0] = fake.records[0][:-1]
    calls.clear()
    assert recover_status(fake, observed).status is None
    assert calls == []


def test_wal_import_scope_has_no_legacy_or_runtime_boundaries():
    import codex_master.fleet_home_broker_wal as wal

    tree = ast.parse(inspect.getsource(wal))
    modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    assert set(modules) <= {
        "dataclasses",
        "hashlib",
        "typing",
        "fleet_home_broker_protocol",
    }
    forbidden = {"v1", "compat", "server", "linux", "os", "socket", "lifecycle"}
    assert not any(any(word in module.lower() for word in forbidden) for module in modules)
