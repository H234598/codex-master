import ast
from dataclasses import fields, replace
import importlib
import json
from pathlib import Path

import pytest

from codex_master.fleet_home_broker_linux import FdStat
from codex_master.fleet_home_broker_protocol import (
    AttestHomeRequest,
    B2aRecoveryPhase,
    BindingExpectation,
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRegistryState,
    BrokerReply,
    BrokerResultCode,
    CANONICAL_AGENT_HOME,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    ChpbTransactionOperation,
    DirectoryIdentity,
    HomeAttestation,
    PolicyBinding,
    PrincipalBinding,
    QueryTransactionRequest,
    TransactionBinding,
    TransactionStatus,
    encode_chpb_message,
)


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


class FakeOperations:
    def __init__(
        self, frame, *, stat=EXPECTED_STAT, receive_error=None, fstat_error=None
    ):
        self.frame = frame
        self.stat = stat
        self.receive_error = receive_error
        self.fstat_error = fstat_error
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
