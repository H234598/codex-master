import ast
from dataclasses import fields, replace
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import get_type_hints

import pytest

from codex_master.fleet_home_broker_linux import FdStat
from codex_master.fleet_home_broker_protocol import (
    AgentStartClaim,
    AgentStartEnvironmentProjection,
    AgentStartEnvelope,
    AgentStartExecutablePin,
    AttestHomeRequest,
    B2aRecoveryPhase,
    BindingExpectation,
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRegistryState,
    BrokerReply,
    BrokerResultCode,
    BrokerRequest,
    CANONICAL_AGENT_HOME,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    ChpbTransactionOperation,
    DeprovisionHomeRequest,
    DirectoryIdentity,
    GetTerminalResultRequest,
    HomeAttestation,
    PolicyBinding,
    PrincipalBinding,
    ProvisionHomeRequest,
    QueryTransactionRequest,
    ReplaceHomeRequest,
    TransactionBinding,
    TransactionStatus,
    encode_chpb_message,
)
from codex_master.fleet_control_release_v2 import (
    ControlReleaseSpecV2,
    ReleasePayloadDigestV2,
)
from codex_master.fleet_home_broker_identity import BrokerIdentity


client = importlib.import_module("codex_master.fleet_home_broker_client")

REQUEST_ID = "a" * 32
TRANSACTION_ID = "b" * 32
OTHER_ID = "c" * 32
PRINCIPAL = PrincipalBinding("agent_one", 7, 9, 17, 29, "d" * 32, "c1,c2", 11)
EXPECTED = BindingExpectation("agent_one", 7, 9, 13, "e" * 64, 11)
POLICY = PolicyBinding(13, "e" * 64)
BINDING = TransactionBinding(
    ChpbTransactionOperation.PROVISION,
    TRANSACTION_ID,
    "f" * 32,
    PRINCIPAL,
    POLICY,
)
OBSERVATION = BrokerObservation(
    object_state=BrokerObjectState.FINAL_COMPLETE,
    registry_state=BrokerRegistryState.CURRENT,
    population_index=0,
)
TRANSACTION = TransactionStatus(
    BINDING,
    B2aRecoveryPhase.COMMITTED,
    BrokerCheckpoint.COMMITTED,
    OBSERVATION,
    1,
    BrokerResultCode.COMMITTED,
)
DIRECTORY = DirectoryIdentity(17, 31, 0o40700)
ATTESTATION = HomeAttestation(
    BINDING, CANONICAL_AGENT_HOME, DIRECTORY, "1" * 64, "c1,c2"
)
REPLY = BrokerReply(
    CHPB_PROTOCOL,
    ChpbMessageKind.REPLY,
    REQUEST_ID,
    BrokerResultCode.OK,
    TRANSACTION,
    ATTESTATION,
)
REQUEST = AttestHomeRequest(
    CHPB_PROTOCOL,
    ChpbMessageKind.ATTEST_HOME,
    REQUEST_ID,
    TRANSACTION_ID,
    EXPECTED,
)
EXPECTED_STAT = FdStat(DIRECTORY.dev, DIRECTORY.ino, DIRECTORY.mode, 0, 0)

REPLACE_BINDING = replace(BINDING, operation=ChpbTransactionOperation.REPLACE)
DEPROVISION_BINDING = replace(BINDING, operation=ChpbTransactionOperation.DEPROVISION)
REPLACE_TRANSACTION = replace(TRANSACTION, binding=REPLACE_BINDING)
DEPROVISION_TRANSACTION = replace(
    TRANSACTION,
    binding=DEPROVISION_BINDING,
    b2a_phase=B2aRecoveryPhase.DEPROVISIONED,
    checkpoint=BrokerCheckpoint.DEPROVISIONED,
)
QUERY_REQUEST = QueryTransactionRequest(
    CHPB_PROTOCOL,
    ChpbMessageKind.QUERY_TRANSACTION,
    REQUEST_ID,
    TRANSACTION_ID,
    EXPECTED,
)
TERMINAL_REQUEST = GetTerminalResultRequest(
    CHPB_PROTOCOL,
    ChpbMessageKind.GET_TERMINAL_RESULT,
    REQUEST_ID,
    TRANSACTION_ID,
    EXPECTED,
)
PROVISION_REQUEST = ProvisionHomeRequest(
    CHPB_PROTOCOL,
    ChpbMessageKind.PROVISION_HOME,
    REQUEST_ID,
    TRANSACTION_ID,
    EXPECTED,
    BINDING,
)
REPLACE_REQUEST = ReplaceHomeRequest(
    CHPB_PROTOCOL,
    ChpbMessageKind.REPLACE_HOME,
    REQUEST_ID,
    TRANSACTION_ID,
    EXPECTED,
    REPLACE_BINDING,
)
DEPROVISION_REQUEST = DeprovisionHomeRequest(
    CHPB_PROTOCOL,
    ChpbMessageKind.DEPROVISION_HOME,
    REQUEST_ID,
    TRANSACTION_ID,
    EXPECTED,
    DEPROVISION_BINDING,
)


class FakeOperations:
    def __init__(
        self,
        frame,
        *,
        stat=EXPECTED_STAT,
        receive_error=None,
        fstat_error=None,
        close_error=None,
    ):
        self.frame = frame
        self.stat = stat
        self.receive_error = receive_error
        self.fstat_error = fstat_error
        self.close_error = close_error
        self.received = []
        self.fstat_calls = []
        self.closed = []

    def receive_frame(self, request):
        self.received.append(request)
        if self.receive_error is not None:
            raise self.receive_error
        return self.frame

    def fstat(self, fd):
        self.fstat_calls.append(fd)
        if self.fstat_error is not None:
            raise self.fstat_error
        return self.stat

    def close(self, fd):
        self.closed.append(fd)
        if self.close_error is not None:
            raise self.close_error


class FakeAgentStartOperations:
    def __init__(self, frame, *, stat=EXPECTED_STAT, fstat_error=None, close_error=None):
        self.frame = frame
        self.stat = stat
        self.fstat_error = fstat_error
        self.close_error = close_error
        self.received = []
        self.fstat_calls = []
        self.closed = []

    def receive_frame(self, claim):
        self.received.append(claim)
        return self.frame

    def fstat(self, fd):
        self.fstat_calls.append(fd)
        if self.fstat_error is not None:
            raise self.fstat_error
        return self.stat

    def close(self, fd):
        self.closed.append(fd)
        if self.close_error is not None:
            raise self.close_error


def frame(reply=REPLY, fds=(0,)):
    return client.ScmFrame(encode_chpb_message(reply), tuple(fds))


def run(frame_, *, request=REQUEST, expected_principal=PRINCIPAL, stat=EXPECTED_STAT):
    operations = FakeOperations(frame_, stat=stat)
    result = client.receive_attested_home(request, expected_principal, operations)
    return result, operations


def assert_rejected(frame_, *, request=REQUEST, expected_principal=PRINCIPAL):
    operations = FakeOperations(frame_)
    with pytest.raises(client.BrokerClientError):
        client.receive_attested_home(request, expected_principal, operations)
    return operations


def payload_document(reply=REPLY):
    return json.loads(encode_chpb_message(reply))


def payload_from_document(document):
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def reply_for(*, binding=BINDING, attestation=ATTESTATION, result=BrokerResultCode.OK):
    transaction = replace(TRANSACTION, binding=binding)
    if attestation is ATTESTATION:
        attestation = replace(ATTESTATION, binding=binding)
    return BrokerReply(
        CHPB_PROTOCOL,
        ChpbMessageKind.REPLY,
        REQUEST_ID,
        result,
        transaction,
        attestation,
    )


def transaction_reply(request, transaction=TRANSACTION, result=None):
    return BrokerReply(
        CHPB_PROTOCOL,
        ChpbMessageKind.REPLY,
        request.request_id,
        transaction.terminal_result if result is None else result,
        transaction,
        None,
    )


def agent_start_claim():
    return AgentStartClaim(CHPB_PROTOCOL, ChpbMessageKind.AGENT_START_CLAIM, REQUEST_ID)


def agent_start_release():
    return ControlReleaseSpecV2(
        2,
        "0.10.5",
        (
            ReleasePayloadDigestV2("python_runtime", "a" * 64),
            ReleasePayloadDigestV2("root_helpers", "b" * 64),
            ReleasePayloadDigestV2("selinux_policy", "c" * 64),
            ReleasePayloadDigestV2("systemd_units", "d" * 64),
        ),
        CHPB_PROTOCOL,
        "org.codex_master.HomeBrokerControl2",
        "StartDynamicTeamlead",
        "codex-master-agent@.service",
        "/usr/libexec/codex-master-agent-launcher",
    )


def agent_start_envelope():
    identity = BrokerIdentity(
        PRINCIPAL.agent_id,
        PRINCIPAL.manifest_generation,
        PRINCIPAL.mcs_pair,
        "slot-1",
        EXPECTED.policy_generation,
        EXPECTED.projection_digest,
        "f" * 64,
        PRINCIPAL.fencing_epoch,
    )
    return AgentStartEnvelope(
        CHPB_PROTOCOL,
        ChpbMessageKind.AGENT_START_ENVELOPE,
        REQUEST_ID,
        agent_start_release(),
        "0.10.5",
        13,
        PRINCIPAL,
        EXPECTED,
        "codex-master-agent@c1\\x2cc2.service",
        identity,
        AgentStartExecutablePin("/usr/libexec/codex-master-agent-launcher", "f" * 64),
        AgentStartEnvironmentProjection(
            (
                ("CODEX_HOME", CANONICAL_AGENT_HOME),
                ("GEMINI_CLI_HOME", CANONICAL_AGENT_HOME),
                ("HOME", CANONICAL_AGENT_HOME),
            )
        ),
        ATTESTATION,
    )


def agent_start_frame(envelope=None, fds=(61,), **changes):
    return client.AgentStartFrame(
        encode_chpb_message(envelope or agent_start_envelope()),
        tuple(fds),
        **changes,
    )


def transaction_frame(reply, fds=()):
    return client.ScmFrame(encode_chpb_message(reply), fds)


def run_transaction(frame_, *, request=QUERY_REQUEST, expected_principal=PRINCIPAL):
    operations = FakeOperations(frame_)
    result = client.receive_transaction_reply(request, expected_principal, operations)
    return result, operations


def assert_transaction_rejected(
    frame_, *, request=QUERY_REQUEST, expected_principal=PRINCIPAL, operations=None
):
    operations = FakeOperations(frame_) if operations is None else operations
    with pytest.raises(client.BrokerClientError):
        client.receive_transaction_reply(request, expected_principal, operations)
    return operations


def test_public_api_types_are_frozen_and_slotted():
    for type_ in (client.ScmFrame, client.AttestedHome):
        assert getattr(type_, "__dataclass_params__").frozen
        assert getattr(type_, "__slots__")
    assert tuple(field.name for field in fields(client.ScmFrame)) == ("payload", "fds")
    assert tuple(field.name for field in fields(client.AttestedHome)) == (
        "fd",
        "reply",
        "attestation",
    )


def test_public_error_and_operations_protocol_are_minimal():
    assert issubclass(client.BrokerClientError, ValueError)
    assert {"receive_frame", "fstat", "close"} <= set(
        client.BrokerClientOperations.__dict__
    )
    assert get_type_hints(client.BrokerClientOperations.receive_frame)["request"] == (
        BrokerRequest
    )


@pytest.mark.parametrize(
    ("request_", "transaction"),
    (
        (QUERY_REQUEST, TRANSACTION),
        (TERMINAL_REQUEST, TRANSACTION),
        (PROVISION_REQUEST, TRANSACTION),
        (REPLACE_REQUEST, REPLACE_TRANSACTION),
        (DEPROVISION_REQUEST, DEPROVISION_TRANSACTION),
    ),
)
def test_receive_transaction_reply_accepts_all_transaction_request_types(
    request_, transaction
):
    reply = transaction_reply(request_, transaction)

    result, operations = run_transaction(transaction_frame(reply), request=request_)

    assert result == reply
    assert operations.received == [request_]
    assert operations.fstat_calls == []
    assert operations.closed == []


def test_receive_transaction_reply_rejects_attestation_request_before_receive():
    operations = FakeOperations(transaction_frame(transaction_reply(QUERY_REQUEST)))

    with pytest.raises(client.BrokerClientError):
        client.receive_transaction_reply(REQUEST, PRINCIPAL, operations)

    assert operations.received == []
    assert operations.closed == []


@pytest.mark.parametrize(
    ("request_", "expected_principal"),
    (
        (replace(QUERY_REQUEST, kind=ChpbMessageKind.REPLY), PRINCIPAL),
        (QUERY_REQUEST, replace(PRINCIPAL, cgroup_ino=0)),
    ),
)
def test_transaction_request_and_principal_are_validated_before_receive(
    request_, expected_principal
):
    operations = FakeOperations(transaction_frame(transaction_reply(QUERY_REQUEST)))

    with pytest.raises(client.BrokerClientError):
        client.receive_transaction_reply(request_, expected_principal, operations)

    assert operations.received == []
    assert operations.closed == []


@pytest.mark.parametrize(
    ("received_frame", "closed"),
    (
        (
            SimpleNamespace(
                payload=encode_chpb_message(transaction_reply(QUERY_REQUEST)),
                fds=(0, 2),
            ),
            [0, 2],
        ),
        (client.ScmFrame("not-bytes", ()), []),
        (
            client.ScmFrame(encode_chpb_message(transaction_reply(QUERY_REQUEST)), []),
            [],
        ),
        (
            client.ScmFrame(
                encode_chpb_message(transaction_reply(QUERY_REQUEST)), (0,)
            ),
            [0],
        ),
    ),
)
def test_transaction_frame_requires_exact_bytes_payload_and_empty_tuple_fds(
    received_frame, closed
):
    operations = assert_transaction_rejected(received_frame)

    assert operations.closed == closed
    assert operations.fstat_calls == []


def test_transaction_frame_cleanup_deduplicates_real_nonnegative_fds_and_masks_close_errors():
    received_frame = client.ScmFrame(
        encode_chpb_message(transaction_reply(QUERY_REQUEST)),
        (0, 0, -1, True, "fd", 3),
    )
    operations = FakeOperations(
        received_frame, close_error=RuntimeError("close failed")
    )

    with pytest.raises(client.BrokerClientError):
        client.receive_transaction_reply(QUERY_REQUEST, PRINCIPAL, operations)

    assert operations.closed == [0, 3]
    assert operations.fstat_calls == []


def test_transaction_receive_failure_does_not_close_unreceived_fds():
    operations = FakeOperations(
        transaction_frame(transaction_reply(QUERY_REQUEST)),
        receive_error=OSError("not received"),
    )

    with pytest.raises(client.BrokerClientError):
        client.receive_transaction_reply(QUERY_REQUEST, PRINCIPAL, operations)

    assert operations.received == [QUERY_REQUEST]
    assert operations.closed == []
    assert operations.fstat_calls == []


def test_transaction_payload_must_decode_to_exact_canonical_broker_reply():
    raw_request = encode_chpb_message(QUERY_REQUEST)
    operations = assert_transaction_rejected(client.ScmFrame(raw_request, ()))

    assert operations.closed == []


def test_transaction_reply_request_id_must_match():
    reply = replace(transaction_reply(QUERY_REQUEST), request_id=OTHER_ID)
    operations = assert_transaction_rejected(transaction_frame(reply))

    assert operations.closed == []


def test_transaction_reply_rejects_ok_and_attestation():
    operations = assert_transaction_rejected(
        client.ScmFrame(encode_chpb_message(REPLY), ())
    )

    assert operations.closed == []


def test_transaction_reply_rejects_attestation_even_on_error(monkeypatch):
    invalid_reply = BrokerReply(
        CHPB_PROTOCOL,
        ChpbMessageKind.REPLY,
        REQUEST_ID,
        BrokerResultCode.INVALID_MESSAGE,
        None,
        ATTESTATION,
    )
    monkeypatch.setattr(client, "decode_chpb_message", lambda _payload: invalid_reply)
    operations = assert_transaction_rejected(client.ScmFrame(b"ignored", ()))

    assert operations.closed == []


@pytest.mark.parametrize(
    "request_", (QUERY_REQUEST, TERMINAL_REQUEST, PROVISION_REQUEST)
)
def test_canonical_error_without_transaction_is_passed_through(request_):
    reply = BrokerReply(
        CHPB_PROTOCOL,
        ChpbMessageKind.REPLY,
        request_.request_id,
        BrokerResultCode.INVALID_MESSAGE,
        None,
        None,
    )

    result, operations = run_transaction(transaction_frame(reply), request=request_)

    assert result == reply
    assert operations.closed == []
    assert operations.fstat_calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("transaction_id", OTHER_ID),
        ("agent_id", "other_agent"),
        ("manifest_generation", 8),
        ("unit_generation", 10),
        ("cgroup_dev", 18),
        ("cgroup_ino", 30),
        ("invocation_id", "2" * 32),
        ("mcs_pair", "c2,c3"),
        ("fencing_epoch", 12),
        ("policy_generation", 14),
        ("projection_digest", "2" * 64),
    ),
)
def test_transaction_reply_binds_transaction_id_full_principal_and_policy(field, value):
    binding = BINDING
    if field == "transaction_id":
        binding = replace(binding, transaction_id=value)
    elif field in {
        "agent_id",
        "manifest_generation",
        "unit_generation",
        "cgroup_dev",
        "cgroup_ino",
        "invocation_id",
        "mcs_pair",
        "fencing_epoch",
    }:
        binding = replace(binding, principal=replace(PRINCIPAL, **{field: value}))
    else:
        binding = replace(binding, policy=replace(POLICY, **{field: value}))
    reply = transaction_reply(QUERY_REQUEST, replace(TRANSACTION, binding=binding))

    operations = assert_transaction_rejected(transaction_frame(reply))

    assert operations.closed == []


def test_query_reply_does_not_require_unknown_mutation_operation_or_store_uuid():
    binding = replace(
        BINDING,
        operation=ChpbTransactionOperation.REPLACE,
        store_uuid=OTHER_ID,
    )
    reply = transaction_reply(QUERY_REQUEST, replace(TRANSACTION, binding=binding))

    result, operations = run_transaction(transaction_frame(reply))

    assert result == reply
    assert operations.closed == []


@pytest.mark.parametrize(
    ("request_", "transaction", "binding"),
    (
        (
            PROVISION_REQUEST,
            TRANSACTION,
            replace(BINDING, operation=ChpbTransactionOperation.REPLACE),
        ),
        (
            REPLACE_REQUEST,
            REPLACE_TRANSACTION,
            replace(REPLACE_BINDING, operation=ChpbTransactionOperation.PROVISION),
        ),
        (
            DEPROVISION_REQUEST,
            DEPROVISION_TRANSACTION,
            replace(DEPROVISION_BINDING, store_uuid=OTHER_ID),
        ),
    ),
)
def test_mutation_reply_requires_full_request_binding(request_, transaction, binding):
    reply = transaction_reply(request_, replace(transaction, binding=binding))

    operations = assert_transaction_rejected(transaction_frame(reply), request=request_)

    assert operations.closed == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("agent_id", "other_agent"),
        ("manifest_generation", 8),
        ("unit_generation", 10),
        ("fencing_epoch", 12),
    ),
)
def test_pre_receive_expectation_drift_rejects_without_receive(field, value):
    request = replace(REQUEST, expected=replace(EXPECTED, **{field: value}))
    operations = FakeOperations(frame())

    with pytest.raises(client.BrokerClientError):
        client.receive_attested_home(request, PRINCIPAL, operations)

    assert operations.received == []
    assert operations.fstat_calls == []
    assert operations.closed == []


def test_pre_receive_validates_request_kind_and_principal_before_receive():
    wrong_kind = replace(REQUEST, kind=ChpbMessageKind.REPLY)
    invalid_principal = replace(PRINCIPAL, cgroup_ino=0)

    for request, expected_principal in (
        (wrong_kind, PRINCIPAL),
        (REQUEST, invalid_principal),
    ):
        operations = FakeOperations(frame())
        with pytest.raises(client.BrokerClientError):
            client.receive_attested_home(request, expected_principal, operations)
        assert operations.received == []


def test_receive_uses_exactly_one_frame_and_one_fstat():
    result, operations = run(frame(fds=(0,)))

    assert operations.received == [REQUEST]
    assert operations.fstat_calls == [0]
    assert result == client.AttestedHome(0, REPLY, ATTESTATION)
    assert operations.closed == []


@pytest.mark.parametrize("fds", ((), (10, 11)))
def test_zero_or_multiple_received_fds_close_all_and_fail(fds):
    operations = assert_rejected(frame(fds=fds))

    assert operations.closed == list(fds)
    assert operations.fstat_calls == []


def test_attested_error_closes_each_unique_real_nonnegative_fd_once():
    operations = assert_rejected(frame(fds=(0, 0, -1, True, 2)))

    assert operations.closed == [0, 2]


def test_receive_failure_does_not_close_unreceived_fds():
    operations = FakeOperations(frame(), receive_error=OSError("not received"))

    with pytest.raises(client.BrokerClientError):
        client.receive_attested_home(REQUEST, PRINCIPAL, operations)

    assert operations.received == [REQUEST]
    assert operations.closed == []


def test_noncanonical_payload_is_rejected_and_fd_is_closed():
    raw = encode_chpb_message(REPLY)
    operations = assert_rejected(client.ScmFrame(raw[:-1] + b" \n", (4,)))

    assert operations.closed == [4]
    assert operations.fstat_calls == []


def test_payload_must_decode_to_exact_broker_reply():
    raw_request = encode_chpb_message(
        QueryTransactionRequest(
            CHPB_PROTOCOL,
            ChpbMessageKind.QUERY_TRANSACTION,
            REQUEST_ID,
            TRANSACTION_ID,
            EXPECTED,
        )
    )
    operations = assert_rejected(client.ScmFrame(raw_request, (5,)))

    assert operations.closed == [5]


def test_wrong_reply_request_id_is_rejected():
    reply = replace(REPLY, request_id=OTHER_ID)
    operations = assert_rejected(frame(reply, (6,)))

    assert operations.closed == [6]


def test_wrong_reply_result_is_rejected():
    reply = reply_for(result=BrokerResultCode.COMMITTED, attestation=None)
    operations = assert_rejected(frame(reply, (7,)))

    assert operations.closed == [7]


def test_success_requires_reply_transaction_and_closes_fd(monkeypatch):
    reply = replace(REPLY, transaction=None)
    monkeypatch.setattr(client, "decode_chpb_message", lambda _payload: reply)
    operations = assert_rejected(client.ScmFrame(b"ignored", (17,)))

    assert operations.closed == [17]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("transaction_id", OTHER_ID),
        ("principal", replace(PRINCIPAL, agent_id="other_agent")),
        ("principal", replace(PRINCIPAL, manifest_generation=8)),
        ("principal", replace(PRINCIPAL, unit_generation=10)),
        ("principal", replace(PRINCIPAL, fencing_epoch=12)),
        ("policy", replace(POLICY, policy_generation=14)),
        ("policy", replace(POLICY, projection_digest="2" * 64)),
    ),
)
def test_reply_transaction_binding_must_match_attestation(field, value, monkeypatch):
    binding = BINDING
    if field == "transaction_id":
        binding = replace(binding, transaction_id=value)
    elif field == "principal":
        binding = replace(binding, principal=value)
    else:
        binding = replace(binding, policy=value)
    reply = replace(REPLY, transaction=replace(TRANSACTION, binding=binding))
    monkeypatch.setattr(client, "decode_chpb_message", lambda _payload: reply)
    operations = assert_rejected(client.ScmFrame(b"ignored", (18,)))

    assert operations.closed == [18]


def test_invalid_frame_list_fds_is_rejected_and_fd_is_closed():
    operations = assert_rejected(client.ScmFrame(encode_chpb_message(REPLY), [14]))

    assert operations.closed == [14]


def test_missing_attestation_is_rejected():
    document = payload_document()
    document["attestation"] = None
    operations = assert_rejected(client.ScmFrame(payload_from_document(document), (8,)))

    assert operations.closed == [8]


def test_missing_attestation_path_is_rejected():
    document = payload_document()
    document["attestation"].pop("canonical_path")
    operations = assert_rejected(client.ScmFrame(payload_from_document(document), (9,)))

    assert operations.closed == [9]


def test_noncanonical_attestation_path_is_rejected():
    document = payload_document()
    document["attestation"]["canonical_path"] = "/run/other-home"
    operations = assert_rejected(
        client.ScmFrame(payload_from_document(document), (15,))
    )

    assert operations.closed == [15]


def test_attestation_mcs_drift_is_rejected():
    document = payload_document()
    document["attestation"]["mcs_pair"] = "c2,c3"
    operations = assert_rejected(
        client.ScmFrame(payload_from_document(document), (16,))
    )

    assert operations.closed == [16]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("transaction_id", OTHER_ID),
        ("principal", replace(PRINCIPAL, agent_id="other_agent")),
        ("principal", replace(PRINCIPAL, manifest_generation=8)),
        ("principal", replace(PRINCIPAL, unit_generation=10)),
        ("principal", replace(PRINCIPAL, cgroup_dev=18)),
        ("principal", replace(PRINCIPAL, cgroup_ino=30)),
        ("principal", replace(PRINCIPAL, invocation_id="2" * 32)),
        ("principal", replace(PRINCIPAL, mcs_pair="c2,c3")),
        ("principal", replace(PRINCIPAL, fencing_epoch=12)),
        ("policy", replace(POLICY, policy_generation=14)),
        ("policy", replace(POLICY, projection_digest="2" * 64)),
    ),
)
def test_every_returned_binding_drift_is_rejected(field, value):
    binding = BINDING
    attestation_mcs = ATTESTATION.mcs_pair
    if field == "transaction_id":
        binding = replace(binding, transaction_id=value)
    elif field == "principal":
        binding = replace(binding, principal=value)
        attestation_mcs = value.mcs_pair
    else:
        binding = replace(binding, policy=value)
    attestation = replace(ATTESTATION, binding=binding, mcs_pair=attestation_mcs)
    operations = assert_rejected(
        frame(reply_for(binding=binding, attestation=attestation), (10,))
    )

    assert operations.closed == [10]


def test_request_policy_expectation_is_bound_after_receive():
    request = replace(REQUEST, expected=replace(EXPECTED, policy_generation=14))
    operations = assert_rejected(frame(fds=(11,)), request=request)

    assert operations.closed == [11]


@pytest.mark.parametrize(
    ("field", "value"),
    (("dev", 18), ("ino", 32), ("mode", 0o40701)),
)
def test_fd_stat_dev_ino_mode_must_match_attested_directory(field, value):
    stat = replace(EXPECTED_STAT, **{field: value})
    operations = FakeOperations(frame(fds=(12,)), stat=stat)

    with pytest.raises(client.BrokerClientError):
        client.receive_attested_home(REQUEST, PRINCIPAL, operations)

    assert operations.fstat_calls == [12]
    assert operations.closed == [12]


def test_fstat_failure_closes_received_fd():
    operations = FakeOperations(frame(fds=(13,)), fstat_error=OSError("stat failed"))

    with pytest.raises(client.BrokerClientError):
        client.receive_attested_home(REQUEST, PRINCIPAL, operations)

    assert operations.closed == [13]


def test_success_returns_attested_home_and_leaves_exact_fd_open():
    result, operations = run(frame(fds=(14,)))

    assert result.fd == 14
    assert result.reply == REPLY
    assert result.attestation == ATTESTATION
    assert operations.closed == []


def test_client_source_has_no_forbidden_transport_or_integration_surface():
    source_path = Path(client.__file__)
    source = source_path.read_text()
    tree = ast.parse(source)
    forbidden_text = (
        "socket",
        "recvmsg",
        "sendmsg",
        "proc",
        "server",
        "launcher",
        "v1",
        "compat",
        "fallback",
    )
    lowered = source.lower()
    for token in forbidden_text:
        assert token not in lowered

    forbidden_modules = {"socket", "server", "launcher"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(
                alias.name.split(".")[0] not in forbidden_modules
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            assert (
                node.module is None
                or node.module.split(".")[0] not in forbidden_modules
            )


def test_agent_start_client_returns_one_attested_fd_without_closing_success():
    claim = agent_start_claim()
    envelope = agent_start_envelope()
    operations = FakeAgentStartOperations(agent_start_frame(envelope))

    result = client.receive_attested_agent_start(claim, envelope, operations)

    assert type(result) is client.AttestedAgentStart
    assert result.fd == 61
    assert result.envelope == envelope
    assert operations.received == [claim]
    assert operations.fstat_calls == [61]
    assert operations.closed == []


def test_agent_start_client_rejects_injected_frame_drift_and_closes_each_fd_once():
    claim = agent_start_claim()
    envelope = agent_start_envelope()
    cases = (
        (client.ScmFrame(b"", (61,)), (61,)),
        (agent_start_frame(envelope, fds=(61, 61)), (61,)),
        (agent_start_frame(envelope, fds=(61, -1, True, 62)), (61, 62)),
        (agent_start_frame(envelope, message_truncated=True), (61,)),
        (agent_start_frame(envelope, control_truncated=True), (61,)),
        (agent_start_frame(envelope, scm_rights_count=2), (61,)),
        (agent_start_frame(envelope, fds=()), ()),
    )
    for frame_, expected_closed in cases:
        operations = FakeAgentStartOperations(frame_)
        with pytest.raises(client.BrokerClientError):
            client.receive_attested_agent_start(claim, envelope, operations)
        assert operations.closed == list(expected_closed)
        assert operations.received == [claim]


@pytest.mark.parametrize(
    "changes",
    (
        {"request_id": OTHER_ID},
        {"snapshot_generation": 14},
        {"identity": replace(agent_start_envelope().identity, slot_snapshot="slot-2")},
    ),
)
def test_agent_start_client_rejects_envelope_binding_drift(changes):
    operations = FakeAgentStartOperations(agent_start_frame())
    expected = replace(agent_start_envelope(), **changes)

    with pytest.raises(client.BrokerClientError):
        client.receive_attested_agent_start(
            agent_start_claim(), expected, operations
        )

    assert operations.closed == [61]
    assert operations.fstat_calls == []


def test_agent_start_client_rejects_fd_stat_drift_and_close_errors_are_fail_closed():
    operations = FakeAgentStartOperations(
        agent_start_frame(),
        stat=FdStat(DIRECTORY.dev + 1, DIRECTORY.ino, DIRECTORY.mode, 0, 0),
        close_error=OSError("close failed"),
    )

    with pytest.raises(client.BrokerClientError):
        client.receive_attested_agent_start(
            agent_start_claim(), agent_start_envelope(), operations
        )

    assert operations.fstat_calls == [61]
    assert operations.closed == [61]
