import dataclasses
import json

import pytest

from codex_master.fleet_home_broker_protocol import (
    CANONICAL_AGENT_HOME,
    CHPB_PROTOCOL,
    MAX_CHPB_GENERATION,
    MAX_CHPB_MCS_CATEGORY,
    MAX_CHPB_MESSAGE_BYTES,
    MAX_CHPB_OBJECT_FIELDS,
    AttestHomeRequest,
    B2aRecoveryPhase,
    BindingExpectation,
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRecoveryAction,
    BrokerRegistryState,
    BrokerReply,
    BrokerResultCode,
    ChpbMessageKind,
    ChpbValidationCode,
    ChpbValidationError,
    DirectoryIdentity,
    GetTerminalResultRequest,
    HomeAttestation,
    PolicyBinding,
    PrincipalBinding,
    QueryTransactionRequest,
    RecoveryDecision,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
    checkpoint_for_b2a_phase,
    decide_broker_recovery,
    decode_chpb_message,
    encode_chpb_message,
    is_checkpoint_transition_allowed,
    validate_chpb_message,
    validate_principal_binding,
    validate_transaction_binding,
    validate_transaction_status,
)


AGENT = "bee_1"
A = "a" * 64
INVOCATION = "1" * 32
REQUEST_ID = INVOCATION
T = "2" * 32
U = "3" * 32
V = "4" * 32


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


def policy(**changes):
    values = {"policy_generation": 7, "projection_digest": A}
    values.update(changes)
    return PolicyBinding(**values)


def binding(**changes):
    values = {
        "transaction_id": T,
        "store_uuid": U,
        "principal": principal(),
        "policy": policy(),
    }
    values.update(changes)
    return TransactionBinding(**values)


def expected(**changes):
    values = {
        "agent_id": AGENT,
        "manifest_generation": 3,
        "unit_generation": 9,
        "policy_generation": 7,
        "projection_digest": A,
        "fencing_epoch": 4,
    }
    values.update(changes)
    return BindingExpectation(**values)


def observation(state=BrokerObjectState.ABSENT, registry=BrokerRegistryState.NOT_APPLICABLE, index=0):
    return BrokerObservation(state, registry, index)


def status(checkpoint=BrokerCheckpoint.CREATE_INTENT, obs=None, total=1):
    if obs is None:
        obs = observation()
    return TransactionStatus(
        binding(), b2a_phase_for_checkpoint(checkpoint), checkpoint, obs, total, None
    )


def attestation(bind=None):
    bind = bind or binding()
    return HomeAttestation(bind, CANONICAL_AGENT_HOME, DirectoryIdentity(0, 1, 0o40700), A, "c0,c1")


def request(kind=ChpbMessageKind.ATTEST_HOME, request_id=REQUEST_ID, transaction_id=T):
    klass = {
        ChpbMessageKind.ATTEST_HOME: AttestHomeRequest,
        ChpbMessageKind.QUERY_TRANSACTION: QueryTransactionRequest,
        ChpbMessageKind.GET_TERMINAL_RESULT: GetTerminalResultRequest,
    }[kind]
    return klass(CHPB_PROTOCOL, kind, request_id, transaction_id, expected())


def test_public_contract_types_are_frozen_and_slotted():
    for klass in (
        PrincipalBinding,
        PolicyBinding,
        TransactionBinding,
        BindingExpectation,
        DirectoryIdentity,
        BrokerObservation,
        TransactionStatus,
        HomeAttestation,
        AttestHomeRequest,
        QueryTransactionRequest,
        GetTerminalResultRequest,
        BrokerReply,
        RecoveryDecision,
    ):
        assert dataclasses.is_dataclass(klass)
        assert klass.__dataclass_params__.frozen
        assert hasattr(klass, "__slots__")


def test_validate_principal_binding_accepts_exact_boundaries():
    assert validate_principal_binding(principal(manifest_generation=1, unit_generation=1, fencing_epoch=0)) == principal(manifest_generation=1, unit_generation=1, fencing_epoch=0)
    assert validate_principal_binding(principal(manifest_generation=MAX_CHPB_GENERATION, unit_generation=MAX_CHPB_GENERATION, fencing_epoch=MAX_CHPB_GENERATION))


@pytest.mark.parametrize(
    "field,value",
    [
        ("manifest_generation", True),
        ("unit_generation", False),
        ("fencing_epoch", True),
        ("cgroup_dev", -1),
        ("cgroup_ino", 0),
        ("manifest_generation", 0),
        ("unit_generation", MAX_CHPB_GENERATION + 1),
        ("fencing_epoch", MAX_CHPB_GENERATION + 1),
        ("agent_id", "Bee_1"),
        ("invocation_id", "z" * 32),
        ("mcs_pair", "c2,c1"),
    ],
)
def test_validate_principal_binding_rejects_bool_as_int_and_each_out_of_range_field(field, value):
    with pytest.raises(ChpbValidationError):
        validate_principal_binding(principal(**{field: value}))


def test_validate_transaction_binding_binds_store_principal_policy_and_epoch():
    value = validate_transaction_binding(binding())
    assert value.store_uuid == U
    assert value.principal.fencing_epoch == 4
    assert validate_transaction_binding(binding(principal=principal(agent_id="other"))).principal.agent_id == "other"


@pytest.mark.parametrize("checkpoint", list(BrokerCheckpoint))
def test_validate_transaction_status_requires_exact_phase_checkpoint_terminal_combination(checkpoint):
    terminal = {
        BrokerCheckpoint.COMMITTED: BrokerResultCode.COMMITTED,
        BrokerCheckpoint.ROLLED_BACK: BrokerResultCode.ROLLED_BACK,
        BrokerCheckpoint.BLOCKED_DRIFT: BrokerResultCode.BLOCKED_DRIFT,
    }.get(checkpoint)
    value = TransactionStatus(binding(), b2a_phase_for_checkpoint(checkpoint), checkpoint, observation(), 1, terminal)
    assert validate_transaction_status(value) == value
    if terminal is None:
        with pytest.raises(ChpbValidationError):
            validate_transaction_status(dataclasses.replace(value, terminal_result=BrokerResultCode.COMMITTED))


def test_all_string_and_mcs_boundaries_are_exact():
    assert validate_principal_binding(principal(agent_id="a"))
    assert validate_principal_binding(principal(agent_id="a" + "b" * 127))
    assert validate_principal_binding(principal(mcs_pair=f"c0,c{MAX_CHPB_MCS_CATEGORY}"))
    for pair in ("c0,c0", "c01,c2", "c0,c1024", "c-1,c2", "c0,c2,x"):
        with pytest.raises(ChpbValidationError):
            validate_principal_binding(principal(mcs_pair=pair))


def test_wire_contract_contains_no_list_field():
    raw = encode_chpb_message(request())
    assert b"[" not in raw
    with pytest.raises(ChpbValidationError):
        decode_chpb_message(raw.replace(b'"expected":{', b'"x":[],"expected":{'))


def test_encode_each_message_variant_matches_golden_chpb2_bytes():
    for kind in ChpbMessageKind:
        if kind is not ChpbMessageKind.REPLY:
            raw = encode_chpb_message(request(kind))
            assert raw.endswith(b"\n")
            assert raw == json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def test_decode_each_golden_message_roundtrips_byte_exactly():
    for kind in (ChpbMessageKind.ATTEST_HOME, ChpbMessageKind.QUERY_TRANSACTION, ChpbMessageKind.GET_TERMINAL_RESULT):
        raw = encode_chpb_message(request(kind))
        assert encode_chpb_message(decode_chpb_message(raw)) == raw


def test_reply_golden_bytes_and_roundtrips_cover_all_reply_variants():
    pending = status(BrokerCheckpoint.CREATE_INTENT)
    committed = dataclasses.replace(status(BrokerCheckpoint.COMMITTED, observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1), 1), terminal_result=BrokerResultCode.COMMITTED)
    rolled_back = dataclasses.replace(status(BrokerCheckpoint.ROLLED_BACK, observation(BrokerObjectState.ROLLED_BACK, BrokerRegistryState.NOT_APPLICABLE, 1), 1), terminal_result=BrokerResultCode.ROLLED_BACK)
    blocked = dataclasses.replace(status(BrokerCheckpoint.BLOCKED_DRIFT, observation(BrokerObjectState.DRIFT, BrokerRegistryState.FOREIGN, 1), 1), terminal_result=BrokerResultCode.BLOCKED_DRIFT)
    replies = (
        BrokerReply(CHPB_PROTOCOL, ChpbMessageKind.REPLY, REQUEST_ID, BrokerResultCode.INVALID_MESSAGE, None, None),
        BrokerReply(CHPB_PROTOCOL, ChpbMessageKind.REPLY, REQUEST_ID, BrokerResultCode.PENDING, pending, None),
        BrokerReply(CHPB_PROTOCOL, ChpbMessageKind.REPLY, REQUEST_ID, BrokerResultCode.COMMITTED, committed, None),
        BrokerReply(CHPB_PROTOCOL, ChpbMessageKind.REPLY, REQUEST_ID, BrokerResultCode.ROLLED_BACK, rolled_back, None),
        BrokerReply(CHPB_PROTOCOL, ChpbMessageKind.REPLY, REQUEST_ID, BrokerResultCode.BLOCKED_DRIFT, blocked, None),
        BrokerReply(CHPB_PROTOCOL, ChpbMessageKind.REPLY, REQUEST_ID, BrokerResultCode.OK, committed, attestation()),
    )
    golden_error = b'{"attestation":null,"kind":"reply","protocol":"CHPB/2","request_id":"11111111111111111111111111111111","result":"invalid_message","transaction":null}\n'
    assert encode_chpb_message(replies[0]) == golden_error
    for reply in replies:
        raw = encode_chpb_message(reply)
        assert decode_chpb_message(raw) == reply
        assert encode_chpb_message(decode_chpb_message(raw)) == raw


def test_decode_rejects_unknown_missing_and_duplicate_fields():
    raw = encode_chpb_message(request())
    with pytest.raises(ChpbValidationError):
        decode_chpb_message(raw.replace(b'"kind":', b'"extra":1,"kind":'))
    with pytest.raises(ChpbValidationError):
        decode_chpb_message(raw.replace(b',"transaction_id"', b''))
    with pytest.raises(ChpbValidationError):
        decode_chpb_message(raw.replace(b'"kind":', b'"kind":"attest_home","kind":'))


def test_decode_rejects_bom_invalid_utf8_float_nan_array_and_bool_integer():
    for raw in (b"\xef\xbb\xbf{}\n", b"\xff\n", b'{"expected":{},"kind":"attest_home","protocol":"CHPB/2","request_id":true,"transaction_id":"' + T.encode() + b'"}\n', b'{"x":1.0}\n', b'{"x":NaN}\n', b'[]\n'):
        with pytest.raises(ChpbValidationError):
            decode_chpb_message(raw)


def test_decode_rejects_wrong_key_order_whitespace_crlf_and_newline_variants():
    raw = encode_chpb_message(request())
    doc = json.loads(raw)
    wrong = json.dumps(dict(reversed(tuple(doc.items()))), separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    assert wrong != raw
    for candidate in (wrong, raw.replace(b"\n", b"\r\n"), raw[:-1], raw + b"\n", raw.replace(b",", b", ")):
        with pytest.raises(ChpbValidationError):
            decode_chpb_message(candidate)


def test_decode_enforces_64k_depth_field_and_string_limits():
    with pytest.raises(ChpbValidationError):
        decode_chpb_message(b"{" + b'"x":{' * 6 + b"null" + b"}" * 6 + b"}\n")
    raw = encode_chpb_message(request()).replace(AGENT.encode(), b"a" * 129)
    with pytest.raises(ChpbValidationError):
        decode_chpb_message(raw)


def test_decode_enforces_real_64k_and_16_field_boundaries():
    valid = encode_chpb_message(request())
    at_limit = valid + b" " * (MAX_CHPB_MESSAGE_BYTES - len(valid))
    with pytest.raises(ChpbValidationError) as at_limit_error:
        decode_chpb_message(at_limit)
    assert at_limit_error.value.code is ChpbValidationCode.NON_CANONICAL
    over_limit = valid + b" " * (MAX_CHPB_MESSAGE_BYTES + 1 - len(valid))
    with pytest.raises(ChpbValidationError) as over_limit_error:
        decode_chpb_message(over_limit)
    assert over_limit_error.value.code is ChpbValidationCode.MESSAGE_TOO_LARGE
    document = json.loads(valid)
    for index in range(MAX_CHPB_OBJECT_FIELDS - len(document)):
        document[f"extra_{index}"] = 0
    sixteen = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    with pytest.raises(ChpbValidationError) as sixteen_error:
        decode_chpb_message(sixteen)
    assert sixteen_error.value.code is ChpbValidationCode.UNKNOWN_FIELD
    document["extra_over"] = 0
    seventeen = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    with pytest.raises(ChpbValidationError) as seventeen_error:
        decode_chpb_message(seventeen)
    assert seventeen_error.value.code is ChpbValidationCode.INVALID_FIELD


def test_validate_chpb_message_enforces_reply_payload_combinations():
    assert validate_chpb_message(request())
    reply = BrokerReply(CHPB_PROTOCOL, ChpbMessageKind.REPLY, REQUEST_ID, BrokerResultCode.PENDING, status(), None)
    assert validate_chpb_message(reply)
    with pytest.raises(ChpbValidationError):
        validate_chpb_message(dataclasses.replace(reply, kind=ChpbMessageKind.ATTEST_HOME))
    with pytest.raises(ChpbValidationError):
        validate_chpb_message(dataclasses.replace(reply, result=BrokerResultCode.INVALID_MESSAGE, transaction=status()))


def test_b2a_mapping_is_total_bijective_and_exact_for_all_15_phases():
    assert len(B2aRecoveryPhase) == 15
    assert len(BrokerCheckpoint) == 15
    assert {checkpoint_for_b2a_phase(p) for p in B2aRecoveryPhase} == set(BrokerCheckpoint)


def test_b2a_mapping_matches_literal_brief_table_for_all_15_pairs():
    expected = {
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
    assert len(expected) == 15
    for phase, checkpoint in expected.items():
        assert checkpoint_for_b2a_phase(phase) is checkpoint
        assert b2a_phase_for_checkpoint(checkpoint) is phase


def test_b2a_mapping_functions_are_exact_inverses():
    for phase in B2aRecoveryPhase:
        assert b2a_phase_for_checkpoint(checkpoint_for_b2a_phase(phase)) is phase
    for checkpoint in BrokerCheckpoint:
        assert checkpoint_for_b2a_phase(b2a_phase_for_checkpoint(checkpoint)) is checkpoint


def test_checkpoint_transition_table_accepts_only_documented_edges():
    allowed = {
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
    for source in BrokerCheckpoint:
        for target in BrokerCheckpoint:
            assert is_checkpoint_transition_allowed(source, target) is (target in allowed[source])


def _decision(status_value, obs):
    return decide_broker_recovery(status_value, obs)


@pytest.mark.parametrize(
    "checkpoint,obj,reg,index,action,next_checkpoint,result",
    [
        (BrokerCheckpoint.CREATE_INTENT, BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE, 0, BrokerRecoveryAction.CREATE_STAGING, None, BrokerResultCode.PENDING),
        (BrokerCheckpoint.CREATE_INTENT, BrokerObjectState.STAGING_EMPTY, BrokerRegistryState.NOT_APPLICABLE, 0, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.STAGING_PINNED, BrokerResultCode.PENDING),
        (BrokerCheckpoint.STAGING_PINNED, BrokerObjectState.STAGING_EMPTY, BrokerRegistryState.NOT_APPLICABLE, 0, BrokerRecoveryAction.POPULATE_NEXT, None, BrokerResultCode.PENDING),
        (BrokerCheckpoint.STAGING_PINNED, BrokerObjectState.STAGING_PREFIX, BrokerRegistryState.NOT_APPLICABLE, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.POPULATE_PENDING, BrokerResultCode.PENDING),
        (BrokerCheckpoint.POPULATE_PENDING, BrokerObjectState.STAGING_PREFIX, BrokerRegistryState.NOT_APPLICABLE, 0, BrokerRecoveryAction.POPULATE_NEXT, None, BrokerResultCode.PENDING),
        (BrokerCheckpoint.POPULATE_PENDING, BrokerObjectState.STAGING_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.PUBLISH_INTENT, BrokerResultCode.PENDING),
        (BrokerCheckpoint.PUBLISH_INTENT, BrokerObjectState.STAGING_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1, BrokerRecoveryAction.PUBLISH_HOME, None, BrokerResultCode.PENDING),
        (BrokerCheckpoint.PUBLISH_INTENT, BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.PUBLISHED, BrokerResultCode.PENDING),
        (BrokerCheckpoint.PUBLISHED, BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.OLD, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.REGISTRY_CAS_INTENT, BrokerResultCode.PENDING),
        (BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT, BrokerObjectState.REPLACEMENT_ORIGINAL, BrokerRegistryState.NOT_APPLICABLE, 1, BrokerRecoveryAction.PREPARE_REPLACEMENT, None, BrokerResultCode.PENDING),
        (BrokerCheckpoint.REPLACEMENT_PREPARED, BrokerObjectState.REPLACEMENT_PREPARED, BrokerRegistryState.NOT_APPLICABLE, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.SWITCH_INTENT, BrokerResultCode.PENDING),
        (BrokerCheckpoint.SWITCH_INTENT, BrokerObjectState.REPLACEMENT_PREPARED, BrokerRegistryState.NOT_APPLICABLE, 1, BrokerRecoveryAction.SWITCH_REPLACEMENT, None, BrokerResultCode.PENDING),
        (BrokerCheckpoint.SWITCHED, BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.OLD, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.REGISTRY_CAS_INTENT, BrokerResultCode.PENDING),
        (BrokerCheckpoint.REGISTRY_CAS_INTENT, BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.OLD, 1, BrokerRecoveryAction.CAS_REGISTRY, None, BrokerResultCode.PENDING),
        (BrokerCheckpoint.REGISTRY_CAS_INTENT, BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.FINALIZE_INTENT, BrokerResultCode.PENDING),
        (BrokerCheckpoint.FINALIZE_INTENT, BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.COMMITTED, BrokerResultCode.COMMITTED),
        (BrokerCheckpoint.ROLLBACK_INTENT, BrokerObjectState.ROLLBACK_READY, BrokerRegistryState.NOT_APPLICABLE, 1, BrokerRecoveryAction.ROLLBACK, None, BrokerResultCode.PENDING),
        (BrokerCheckpoint.ROLLBACK_INTENT, BrokerObjectState.ROLLED_BACK, BrokerRegistryState.NOT_APPLICABLE, 1, BrokerRecoveryAction.PERSIST_CHECKPOINT, BrokerCheckpoint.ROLLED_BACK, BrokerResultCode.ROLLED_BACK),
    ],
)
def test_recovery_decision_covers_every_documented_crash_row(checkpoint, obj, reg, index, action, next_checkpoint, result):
    total = max(1, index)
    old = status(checkpoint, observation(), total)
    decision = _decision(old, observation(obj, reg, index))
    assert decision.action is action
    assert decision.next_checkpoint is next_checkpoint
    assert decision.result is result


def test_recovery_default_is_blocked_drift():
    decision = decide_broker_recovery(status(), observation(BrokerObjectState.DRIFT, BrokerRegistryState.FOREIGN, 0))
    assert decision == RecoveryDecision(BrokerRecoveryAction.RETURN_BLOCKED, B2aRecoveryPhase.BLOCKED, BrokerCheckpoint.BLOCKED_DRIFT, BrokerResultCode.BLOCKED_DRIFT)


def test_publish_intent_with_only_final_persists_published():
    d = decide_broker_recovery(status(BrokerCheckpoint.PUBLISH_INTENT), observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1))
    assert d.next_checkpoint is BrokerCheckpoint.PUBLISHED


def test_publish_intent_with_staging_and_final_blocks():
    d = decide_broker_recovery(status(BrokerCheckpoint.PUBLISH_INTENT), observation(BrokerObjectState.STAGING_AND_FINAL, BrokerRegistryState.NOT_APPLICABLE, 1))
    assert d.action is BrokerRecoveryAction.RETURN_BLOCKED


def test_registry_foreign_generation_blocks():
    d = decide_broker_recovery(status(BrokerCheckpoint.REGISTRY_CAS_INTENT), observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.FOREIGN, 1))
    assert d.action is BrokerRecoveryAction.RETURN_BLOCKED


def test_population_index_is_monotonic_and_complete_before_publish():
    current = status(BrokerCheckpoint.POPULATE_PENDING, observation(BrokerObjectState.STAGING_PREFIX, BrokerRegistryState.NOT_APPLICABLE, 2), 3)
    assert decide_broker_recovery(current, observation(BrokerObjectState.STAGING_PREFIX, BrokerRegistryState.NOT_APPLICABLE, 3)).action is BrokerRecoveryAction.RETURN_BLOCKED
    assert decide_broker_recovery(current, observation(BrokerObjectState.STAGING_PREFIX, BrokerRegistryState.NOT_APPLICABLE, 0)).action is BrokerRecoveryAction.RETURN_BLOCKED
    assert decide_broker_recovery(current, observation(BrokerObjectState.STAGING_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 3)).next_checkpoint is BrokerCheckpoint.PUBLISH_INTENT


def test_terminal_recovery_is_idempotent_only_for_exact_observation():
    committed = dataclasses.replace(status(BrokerCheckpoint.COMMITTED, observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1), 1), terminal_result=BrokerResultCode.COMMITTED)
    assert decide_broker_recovery(committed, committed.observation).action is BrokerRecoveryAction.RETURN_COMMITTED
    assert decide_broker_recovery(committed, observation(BrokerObjectState.DRIFT, BrokerRegistryState.CURRENT, 1)).action is BrokerRecoveryAction.RETURN_BLOCKED
