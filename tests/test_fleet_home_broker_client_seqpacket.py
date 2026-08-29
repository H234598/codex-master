import copy
import pickle

import pytest

from codex_master.fleet_home_broker_client import BrokerClientError, ScmFrame
from codex_master.fleet_home_broker_linux import FdStat
from codex_master.fleet_home_broker_protocol import (
    BindingExpectation,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    QueryTransactionRequest,
    encode_chpb_message,
)
from codex_master.fleet_home_broker_client_seqpacket import (
    SeqpacketBrokerClientOperations,
)


REQUEST = QueryTransactionRequest(
    CHPB_PROTOCOL,
    ChpbMessageKind.QUERY_TRANSACTION,
    "a" * 32,
    "b" * 32,
    BindingExpectation("agent_one", 7, 9, 13, "c" * 64, 11),
)
STAT = FdStat(17, 31, 0o40700, 0, 0)
CONTEXT_IDENTITY = object()
RELEASE_IDENTITY = object()


class EqualIdentityMarker:
    def __eq__(self, other: object) -> bool:
        return isinstance(other, EqualIdentityMarker)

    __hash__ = None


class FakeExchangeOperations:
    def __init__(
        self,
        response: object,
        *,
        exchange_error: Exception | None = None,
        fstat_error: Exception | None = None,
        close_error: Exception | None = None,
    ) -> None:
        self.response = response
        self.exchange_error = exchange_error
        self.fstat_error = fstat_error
        self.close_error = close_error
        self.exchanges = []
        self.fstat_calls = []
        self.closed = []

    def exchange(self, request: ScmFrame) -> ScmFrame:
        self.exchanges.append(request)
        if self.exchange_error is not None:
            raise self.exchange_error
        return self.response

    def fstat(self, fd: int) -> FdStat:
        self.fstat_calls.append(fd)
        if self.fstat_error is not None:
            raise self.fstat_error
        return STAT

    def close(self, fd: int) -> None:
        self.closed.append(fd)
        if self.close_error is not None:
            raise self.close_error


def response_frame(*, payload: bytes | None = None, fds: object = ()) -> ScmFrame:
    return ScmFrame(encode_chpb_message(REQUEST) if payload is None else payload, fds)


def adapter(operations: FakeExchangeOperations) -> SeqpacketBrokerClientOperations:
    return SeqpacketBrokerClientOperations(
        operations,
        a3_context_identity=CONTEXT_IDENTITY,
        release_identity=RELEASE_IDENTITY,
    )


def test_receive_frame_exchanges_one_canonical_request_and_preserves_response_fd_ownership():
    response = response_frame(fds=(37,))
    operations = FakeExchangeOperations(response)
    client = adapter(operations)

    received = client.receive_frame(REQUEST)

    assert received is response
    assert operations.exchanges == [ScmFrame(encode_chpb_message(REQUEST), ())]
    assert operations.fstat_calls == []
    assert operations.closed == []


def test_constructor_rejects_incomplete_exchange_capability():
    class IncompleteOperations:
        def exchange(self, request: ScmFrame) -> ScmFrame:
            raise AssertionError("must not exchange")

        def close(self, fd: int) -> None:
            raise AssertionError("must not close")

    with pytest.raises(BrokerClientError, match="incomplete"):
        SeqpacketBrokerClientOperations(
            IncompleteOperations(),
            a3_context_identity=CONTEXT_IDENTITY,
            release_identity=RELEASE_IDENTITY,
        )


def test_constructor_rejects_missing_identity_arguments():
    with pytest.raises(TypeError):
        SeqpacketBrokerClientOperations(FakeExchangeOperations(response_frame()))


@pytest.mark.parametrize(
    "kwargs",
    (
        {"a3_context_identity": None, "release_identity": RELEASE_IDENTITY},
        {"a3_context_identity": CONTEXT_IDENTITY, "release_identity": None},
    ),
)
def test_constructor_rejects_none_identity_arguments(kwargs):
    with pytest.raises(BrokerClientError, match="identity"):
        SeqpacketBrokerClientOperations(FakeExchangeOperations(response_frame()), **kwargs)


def test_identity_properties_preserve_equal_but_distinct_references():
    operations = FakeExchangeOperations(response_frame())
    context_identity = EqualIdentityMarker()
    release_identity = EqualIdentityMarker()
    client = SeqpacketBrokerClientOperations(
        operations,
        a3_context_identity=context_identity,
        release_identity=release_identity,
    )

    assert context_identity == release_identity
    assert context_identity is not release_identity
    assert client.a3_context_identity is context_identity
    assert client.release_identity is release_identity
    with pytest.raises(AttributeError):
        client.a3_context_identity = object()


@pytest.mark.parametrize("transfer", (copy.copy, copy.deepcopy, pickle.dumps))
def test_adapter_rejects_copy_and_pickle(transfer):
    with pytest.raises(BrokerClientError, match="non-transferable"):
        transfer(adapter(FakeExchangeOperations(response_frame())))


def test_receive_frame_rejects_unencodable_request_before_exchange():
    operations = FakeExchangeOperations(response_frame())
    client = adapter(operations)

    with pytest.raises(BrokerClientError, match="request encoding"):
        client.receive_frame(object())

    assert operations.exchanges == []
    assert operations.closed == []


def test_receive_frame_wraps_exchange_failure_without_fd_cleanup():
    failure = RuntimeError("exchange failed")
    operations = FakeExchangeOperations(response_frame(), exchange_error=failure)
    client = adapter(operations)

    with pytest.raises(BrokerClientError, match="frame exchange") as caught:
        client.receive_frame(REQUEST)

    assert caught.value.__cause__ is failure
    assert operations.exchanges == [ScmFrame(encode_chpb_message(REQUEST), ())]
    assert operations.closed == []


def test_receive_frame_rejects_non_frame_response_without_closing_response_fds():
    operations = FakeExchangeOperations(object())
    client = adapter(operations)

    with pytest.raises(BrokerClientError, match="wrong type"):
        client.receive_frame(REQUEST)

    assert operations.closed == []


@pytest.mark.parametrize(
    "response",
    (
        response_frame(payload=b"not CHPB/2", fds=(41,)),
        response_frame(fds=[41]),
    ),
)
def test_receive_frame_rejects_malformed_response_frame_without_closing_fds(response):
    operations = FakeExchangeOperations(response)
    client = adapter(operations)

    with pytest.raises(BrokerClientError):
        client.receive_frame(REQUEST)

    assert operations.closed == []


@pytest.mark.parametrize("fds", ((41, 41), (-1,), (True,)))
def test_receive_frame_rejects_duplicate_or_noncanonical_response_fds(fds):
    operations = FakeExchangeOperations(response_frame(fds=fds))
    client = adapter(operations)

    with pytest.raises(BrokerClientError, match="response fd"):
        client.receive_frame(REQUEST)

    assert operations.closed == []


def test_fstat_delegates_result():
    operations = FakeExchangeOperations(response_frame())
    client = adapter(operations)

    assert client.fstat(43) is STAT
    assert operations.fstat_calls == [43]


def test_fstat_delegation_error_is_not_swallowed():
    failure = RuntimeError("fstat failed")
    operations = FakeExchangeOperations(response_frame(), fstat_error=failure)
    client = adapter(operations)

    with pytest.raises(RuntimeError) as caught:
        client.fstat(43)

    assert caught.value is failure
    assert operations.fstat_calls == [43]


def test_close_delegates_and_preserves_error():
    failure = RuntimeError("close failed")
    operations = FakeExchangeOperations(response_frame(), close_error=failure)
    client = adapter(operations)

    with pytest.raises(RuntimeError) as caught:
        client.close(47)

    assert caught.value is failure
    assert operations.closed == [47]
