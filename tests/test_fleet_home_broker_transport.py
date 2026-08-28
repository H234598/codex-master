from __future__ import annotations

import ast
import dataclasses
import inspect
import re

import pytest

import codex_master.fleet_home_broker_transport as transport
from codex_master.fleet_home_broker_client import ScmFrame
from codex_master.fleet_home_broker_protocol import (
    AttestHomeRequest,
    BindingExpectation,
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRegistryState,
    BrokerReply,
    BrokerRequest,
    BrokerResultCode,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    ChpbTransactionOperation,
    DirectoryIdentity,
    HomeAttestation,
    PolicyBinding,
    PrincipalBinding,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
    encode_chpb_message,
)


REQUEST_ID = "1" * 32
TRANSACTION_ID = "2" * 32
STORE_UUID = "3" * 32
PROJECTION_DIGEST = "a" * 64


class FakeOperations:
    def __init__(
        self, received, *, receive_error=None, send_error=None, close_error=False
    ):
        self.received = received
        self.receive_error = receive_error
        self.send_error = send_error
        self.close_error = close_error
        self.sent = []
        self.closed = []
        self.events = []

    def receive_frame(self):
        if self.receive_error is not None:
            raise self.receive_error
        return self.received

    def send_frame(self, frame):
        self.events.append(("send", frame))
        self.sent.append(frame)
        if self.send_error is not None:
            raise self.send_error

    def close(self, fd):
        self.events.append(("close", fd))
        self.closed.append(fd)
        if self.close_error:
            raise RuntimeError("close failed")


class FakeHandler:
    def __init__(self, response=None, *, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def handle(self, peer, request):
        self.calls.append((peer, request))
        if self.error is not None:
            raise self.error
        return self.response


def _request(request_id=REQUEST_ID):
    expected = BindingExpectation("bee_1", 3, 9, 7, PROJECTION_DIGEST, 4)
    return AttestHomeRequest(
        CHPB_PROTOCOL,
        ChpbMessageKind.ATTEST_HOME,
        request_id,
        TRANSACTION_ID,
        expected,
    )


def _binding():
    principal = PrincipalBinding("bee_1", 3, 9, 0, 1, REQUEST_ID, "c0,c1", 4)
    policy = PolicyBinding(7, PROJECTION_DIGEST)
    return TransactionBinding(
        ChpbTransactionOperation.PROVISION,
        TRANSACTION_ID,
        STORE_UUID,
        principal,
        policy,
    )


def _pending_status():
    binding = _binding()
    observation = BrokerObservation(
        BrokerObjectState.ABSENT,
        BrokerRegistryState.NOT_APPLICABLE,
        0,
    )
    return TransactionStatus(
        binding,
        b2a_phase_for_checkpoint(BrokerCheckpoint.CREATE_INTENT),
        BrokerCheckpoint.CREATE_INTENT,
        observation,
        1,
        None,
    )


def _pending_reply(request_id=REQUEST_ID):
    return BrokerReply(
        CHPB_PROTOCOL,
        ChpbMessageKind.REPLY,
        request_id,
        BrokerResultCode.PENDING,
        _pending_status(),
        None,
    )


def _ok_reply(request_id=REQUEST_ID):
    binding = _binding()
    status = dataclasses.replace(
        _pending_status(),
        binding=binding,
        b2a_phase=b2a_phase_for_checkpoint(BrokerCheckpoint.COMMITTED),
        checkpoint=BrokerCheckpoint.COMMITTED,
        observation=BrokerObservation(
            BrokerObjectState.FINAL_COMPLETE,
            BrokerRegistryState.CURRENT,
            1,
        ),
        terminal_result=BrokerResultCode.COMMITTED,
    )
    attestation = HomeAttestation(
        binding,
        "/run/codex-master-agent/home",
        DirectoryIdentity(0, 1, 0o40700),
        PROJECTION_DIGEST,
        "c0,c1",
    )
    return BrokerReply(
        CHPB_PROTOCOL,
        ChpbMessageKind.REPLY,
        request_id,
        BrokerResultCode.OK,
        status,
        attestation,
    )


def _operations(payload, fds=()):
    return FakeOperations((transport.BrokerPeer(41), ScmFrame(payload, fds)))


def test_public_api_exports_exact_frozen_slotted_fields_and_protocol_methods():
    assert transport.__all__ == (
        "BrokerTransportError",
        "MAX_TRANSPORT_RESPONSE_FDS",
        "MAX_OPERATION_REQUEST_BYTES",
        "MAX_OPERATION_RESPONSE_BYTES",
        "OPERATION_TIMEOUT_SECONDS",
        "BrokerPeer",
        "BrokerTransportResponse",
        "BrokerOllamaInstancePayload",
        "BrokerOperationRequest",
        "BrokerOperationResponse",
        "BrokerTransportOperations",
        "BrokerRequestHandler",
        "BrokerOperationClient",
        "exchange_typed_operation",
        "serve_once",
    )
    assert issubclass(transport.BrokerTransportError, ValueError)
    assert transport.MAX_TRANSPORT_RESPONSE_FDS == 1
    for klass, fields in (
        (transport.BrokerPeer, ("pid",)),
        (transport.BrokerTransportResponse, ("reply", "fds")),
        (
            transport.BrokerOllamaInstancePayload,
            (
                "host_ref",
                "instance_ref",
                "selected_model_refs",
                "allowed_cpus",
                "cpu_quota_percent",
                "cpu_weight",
                "model_generation",
                "runtime_generation",
                "fence",
                "plan_digest",
                "idempotency_key",
            ),
        ),
        (
            transport.BrokerOperationRequest,
            (
                "schema_version",
                "operation_type",
                "action",
                "host_ref",
                "lease_id",
                "request_id",
                "payload",
            ),
        ),
        (
            transport.BrokerOperationResponse,
            (
                "schema_version",
                "operation_type",
                "action",
                "host_ref",
                "request_id",
                "status_code",
                "redirected",
                "payload",
            ),
        ),
    ):
        assert dataclasses.is_dataclass(klass)
        assert klass.__dataclass_params__.frozen
        assert hasattr(klass, "__slots__")
        assert tuple(field.name for field in dataclasses.fields(klass)) == fields
    assert getattr(transport.BrokerTransportOperations, "_is_protocol", False)
    assert getattr(transport.BrokerRequestHandler, "_is_protocol", False)
    assert getattr(transport.BrokerOperationClient, "_is_protocol", False)
    assert tuple(
        inspect.signature(transport.BrokerTransportOperations.receive_frame).parameters
    ) == ("self",)
    assert tuple(
        inspect.signature(transport.BrokerTransportOperations.send_frame).parameters
    ) == (
        "self",
        "frame",
    )
    assert tuple(
        inspect.signature(transport.BrokerTransportOperations.close).parameters
    ) == (
        "self",
        "fd",
    )
    assert tuple(
        inspect.signature(transport.BrokerRequestHandler.handle).parameters
    ) == (
        "self",
        "peer",
        "request",
    )
    assert tuple(
        inspect.signature(transport.BrokerOperationClient.exchange).parameters
    ) == ("self", "request", "timeout_seconds", "max_response_bytes")


class FakeOperationClient:
    def __init__(self, response=None, *, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def exchange(self, request, *, timeout_seconds, max_response_bytes):
        self.calls.append((request, timeout_seconds, max_response_bytes))
        if self.error is not None:
            raise self.error
        return self.response


def _operation_payload():
    return transport.BrokerOllamaInstancePayload(
        "worker-west",
        "ollama-west",
        ("llama-small",),
        "2-3",
        200,
        50,
        8,
        13,
        3,
        "d" * 64,
        "e" * 64,
    )


def _operation_request(payload=None):
    return transport.BrokerOperationRequest(
        1,
        "ollama.instance",
        "plan",
        "worker-west",
        "lease-" + "a" * 32,
        "b" * 32,
        payload or _operation_payload(),
    )


def _operation_response(payload=b"{}", **changes):
    values = {
        "schema_version": 1,
        "operation_type": "ollama.instance",
        "action": "plan",
        "host_ref": "worker-west",
        "request_id": "b" * 32,
        "status_code": 200,
        "redirected": False,
        "payload": payload,
    }
    values.update(changes)
    return transport.BrokerOperationResponse(**values)


def test_typed_operation_exchange_accepts_only_bound_bounded_response():
    request = _operation_request()
    response = _operation_response(b'{"status":"planned"}')
    client = FakeOperationClient(response)

    assert transport.exchange_typed_operation(client, request) is response
    assert client.calls == [
        (
            request,
            transport.OPERATION_TIMEOUT_SECONDS,
            transport.MAX_OPERATION_RESPONSE_BYTES,
        )
    ]
    assert "lease-" not in repr(request)


def test_typed_operation_request_rejects_raw_or_free_operation_payload():
    with pytest.raises(
        transport.BrokerTransportError, match="^provider.operation_not_allowed$"
    ):
        _operation_request(b'{"argv":["/private/worker/ollama","serve"]}')


@pytest.mark.parametrize(
    "response",
    (
        object(),
        _operation_response(redirected=True),
        _operation_response(host_ref="worker-east"),
        _operation_response(request_id="c" * 32),
        _operation_response(status_code=302),
        _operation_response(payload=b"x" * (64 * 1024 + 1)),
    ),
)
def test_typed_operation_exchange_rejects_malformed_oversize_or_redirected_response(
    response,
):
    client = FakeOperationClient(response)

    with pytest.raises(
        transport.BrokerTransportError, match="^resource.host_response_invalid$"
    ):
        transport.exchange_typed_operation(client, _operation_request())


def test_typed_operation_exchange_redacts_client_exception():
    client = FakeOperationClient(error=RuntimeError("/secret/worker/path"))

    with pytest.raises(
        transport.BrokerTransportError, match="^resource.host_unreachable$"
    ) as raised:
        transport.exchange_typed_operation(client, _operation_request())

    assert "/secret" not in repr(raised.value)


def test_broker_peer_accepts_only_positive_real_int_pid():
    assert transport.BrokerPeer(1).pid == 1
    assert transport.BrokerPeer(2**63).pid == 2**63

    class IntChild(int):
        pass

    for pid in (0, -1, True, 1.0, "1", IntChild(1)):
        with pytest.raises(
            transport.BrokerTransportError, match="^invalid broker peer$"
        ):
            transport.BrokerPeer(pid)


def test_attest_home_ok_forwards_arguments_canonical_reply_one_fd_and_closes_after_send():
    request = _request()
    reply = _ok_reply()
    operations = _operations(encode_chpb_message(request))
    handler = FakeHandler(transport.BrokerTransportResponse(reply, (73,)))

    result = transport.serve_once(operations, handler)

    assert result is reply
    assert handler.calls == [(transport.BrokerPeer(41), request)]
    assert operations.sent == [ScmFrame(encode_chpb_message(reply), (73,))]
    assert operations.events == [("send", operations.sent[0]), ("close", 73)]
    assert operations.closed == [73]


def test_non_ok_reply_sends_without_fds_and_closes_none():
    reply = _pending_reply()
    operations = _operations(encode_chpb_message(_request()))
    handler = FakeHandler(transport.BrokerTransportResponse(reply, ()))

    assert transport.serve_once(operations, handler) is reply
    assert operations.sent == [ScmFrame(encode_chpb_message(reply), ())]
    assert operations.closed == []


def test_incoming_one_or_more_fds_are_rejected_and_all_are_closed_without_handler_or_send():
    for fds in ((11,), (12, 13)):
        operations = _operations(encode_chpb_message(_request()), fds)
        handler = FakeHandler(_pending_reply())

        with pytest.raises(
            transport.BrokerTransportError, match="^invalid broker request frame$"
        ):
            transport.serve_once(operations, handler)
        assert operations.closed == list(fds)
        assert handler.calls == []
        assert operations.sent == []


def test_malformed_noncanonical_and_reply_payloads_are_rejected_as_requests():
    payloads = (
        b"not-json",
        encode_chpb_message(_request()).replace(b"\n", b" \n"),
        encode_chpb_message(_pending_reply()),
    )
    for payload in payloads:
        operations = _operations(payload)
        handler = FakeHandler(_pending_reply())

        with pytest.raises(
            transport.BrokerTransportError, match="^invalid broker request frame$"
        ):
            transport.serve_once(operations, handler)
        assert handler.calls == []
        assert operations.sent == []
        assert operations.closed == []

    for frame, expected_closed in (
        (ScmFrame("not-bytes", ()), []),
        (ScmFrame(encode_chpb_message(_request()), [26]), [26]),
    ):
        operations = FakeOperations((transport.BrokerPeer(41), frame))
        handler = FakeHandler(_pending_reply())

        with pytest.raises(
            transport.BrokerTransportError, match="^invalid broker request frame$"
        ):
            transport.serve_once(operations, handler)
        assert handler.calls == []
        assert operations.sent == []
        assert operations.closed == expected_closed


def test_receive_exception_and_wrong_shape_are_normalized():
    cases = (
        FakeOperations(None, receive_error=RuntimeError("receive failed")),
        FakeOperations((transport.BrokerPeer(41),)),
    )
    for operations in cases:
        handler = FakeHandler(_pending_reply())

        with pytest.raises(
            transport.BrokerTransportError, match="^broker frame receive failed$"
        ):
            transport.serve_once(operations, handler)
        assert handler.calls == []
        assert operations.sent == []


def test_handler_exception_is_normalized_without_send():
    operations = _operations(encode_chpb_message(_request()))
    handler = FakeHandler(error=RuntimeError("handler failed"))

    with pytest.raises(
        transport.BrokerTransportError, match="^broker request handling failed$"
    ):
        transport.serve_once(operations, handler)
    assert len(handler.calls) == 1
    assert operations.sent == []
    assert operations.closed == []


def test_wrong_response_wrong_reply_invalid_reply_and_request_id_are_rejected():
    responses = (
        object(),
        transport.BrokerTransportResponse(object(), ()),
        transport.BrokerTransportResponse(
            BrokerReply(
                CHPB_PROTOCOL,
                ChpbMessageKind.REPLY,
                REQUEST_ID,
                BrokerResultCode.PENDING,
                None,
                None,
            ),
            (),
        ),
        transport.BrokerTransportResponse(_pending_reply("4" * 32), ()),
    )
    for response in responses:
        operations = _operations(encode_chpb_message(_request()))
        handler = FakeHandler(response)

        with pytest.raises(
            transport.BrokerTransportError, match="^invalid broker response$"
        ):
            transport.serve_once(operations, handler)
        assert operations.sent == []


def test_response_fd_matrix_enforces_result_cardinality_and_closes_valid_fds():
    cases = (
        (_ok_reply(), (), []),
        (_ok_reply(), (21, 22), [21, 22]),
        (_ok_reply(), (23, True, -1, "bad"), [23]),
        (_ok_reply(), (27, 27), [27]),
        (_pending_reply(), (24,), [24]),
    )
    for reply, fds, expected_closed in cases:
        operations = _operations(encode_chpb_message(_request()))
        handler = FakeHandler(transport.BrokerTransportResponse(reply, fds))

        with pytest.raises(
            transport.BrokerTransportError, match="^invalid broker response$"
        ):
            transport.serve_once(operations, handler)
        assert operations.closed == expected_closed
        assert operations.sent == []


def test_send_exception_is_normalized_and_close_error_does_not_mask_it():
    operations = FakeOperations(
        (transport.BrokerPeer(41), ScmFrame(encode_chpb_message(_request()), ())),
        send_error=RuntimeError("send failed"),
        close_error=True,
    )
    handler = FakeHandler(transport.BrokerTransportResponse(_ok_reply(), (25,)))

    with pytest.raises(
        transport.BrokerTransportError, match="^broker frame send failed$"
    ):
        transport.serve_once(operations, handler)
    assert operations.sent == [ScmFrame(encode_chpb_message(_ok_reply()), (25,))]
    assert operations.closed == [25]
    assert operations.events[-1] == ("close", 25)


def test_source_uses_only_allowed_imports_and_contains_no_forbidden_transport_tokens():
    source = inspect.getsource(transport)
    tree = ast.parse(source)
    imports = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.extend((alias.name, (alias.asname,)) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(
                (
                    node.module,
                    tuple(alias.name for alias in node.names),
                )
            )
    assert imports == [
        ("__future__", ("annotations",)),
        ("dataclasses", ("dataclass", "field")),
        ("typing", ("Protocol", "cast")),
        ("codex_master.fleet_home_broker_client", ("ScmFrame",)),
        (
            "codex_master.fleet_home_broker_protocol",
            (
                "BrokerReply",
                "BrokerRequest",
                "BrokerResultCode",
                "decode_chpb_message",
                "encode_chpb_message",
                "validate_chpb_message",
            ),
        ),
    ]
    assert transport.ScmFrame.__module__ == "codex_master.fleet_home_broker_client"
    assert transport.BrokerRequest is BrokerRequest
    for name in (
        "BrokerReply",
        "BrokerResultCode",
        "decode_chpb_message",
        "encode_chpb_message",
        "validate_chpb_message",
    ):
        assert (
            getattr(transport, name).__module__
            == "codex_master.fleet_home_broker_protocol"
        )
    forbidden = (
        "socket",
        "recvmsg",
        "sendmsg",
        "os",
        "pathlib",
        "subprocess",
        "server",
        "emulator",
        "fallback",
        "compat",
    )
    source_lower = source.lower()
    assert all(
        re.search(rf"(?<![a-z0-9_]){re.escape(token)}(?![a-z0-9_])", source_lower)
        is None
        for token in forbidden
    )
