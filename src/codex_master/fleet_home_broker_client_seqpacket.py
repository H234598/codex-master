"""Injected CHPB/2 client exchange adapter."""

from typing import Protocol

from codex_master.fleet_home_broker_client import (
    BrokerClientError,
    BrokerClientOperations,
    ScmFrame,
)
from codex_master.fleet_home_broker_linux import FdStat
from codex_master.fleet_home_broker_protocol import (
    BrokerRequest,
    decode_chpb_message,
    encode_chpb_message,
)


class BrokerClientExchangeOperations(Protocol):
    def exchange(self, request: ScmFrame) -> ScmFrame: ...

    def fstat(self, fd: int) -> FdStat: ...

    def close(self, fd: int) -> None: ...


class SeqpacketBrokerClientOperations(BrokerClientOperations):
    __slots__ = ("_operations", "_a3_context_identity", "_release_identity")

    def __init__(
        self,
        operations: BrokerClientExchangeOperations,
        *,
        a3_context_identity: object,
        release_identity: object,
    ) -> None:
        if a3_context_identity is None or release_identity is None:
            raise BrokerClientError("identity bindings are required")
        for name in ("exchange", "fstat", "close"):
            try:
                operation = getattr(operations, name)
            except Exception as exc:
                raise BrokerClientError("exchange operations are incomplete") from exc
            if not callable(operation):
                raise BrokerClientError("exchange operations are incomplete")
        self._operations = operations
        self._a3_context_identity = a3_context_identity
        self._release_identity = release_identity

    @property
    def a3_context_identity(self) -> object:
        return self._a3_context_identity

    @property
    def release_identity(self) -> object:
        return self._release_identity

    def __copy__(self) -> "SeqpacketBrokerClientOperations":
        raise BrokerClientError("exchange adapter is non-transferable")

    def __deepcopy__(self, memo: object) -> "SeqpacketBrokerClientOperations":
        del memo
        raise BrokerClientError("exchange adapter is non-transferable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise BrokerClientError("exchange adapter is non-transferable")

    def receive_frame(self, request: BrokerRequest) -> ScmFrame:
        try:
            outbound = ScmFrame(encode_chpb_message(request), ())
        except Exception as exc:
            raise BrokerClientError("request encoding failed") from exc
        try:
            response = self._operations.exchange(outbound)
        except Exception as exc:
            raise BrokerClientError("frame exchange failed") from exc
        if type(response) is not ScmFrame:
            raise BrokerClientError("received frame has wrong type")
        if type(response.payload) is not bytes or type(response.fds) is not tuple:
            raise BrokerClientError("received frame is invalid")
        if any(type(fd) is not int or fd < 0 for fd in response.fds):
            raise BrokerClientError("received response fd is invalid")
        if len(set(response.fds)) != len(response.fds):
            raise BrokerClientError("received response fd is duplicated")
        try:
            decode_chpb_message(response.payload)
        except Exception as exc:
            raise BrokerClientError("received response payload is invalid") from exc
        return response

    def fstat(self, fd: int) -> FdStat:
        return self._operations.fstat(fd)

    def close(self, fd: int) -> None:
        self._operations.close(fd)


__all__ = ["BrokerClientExchangeOperations", "SeqpacketBrokerClientOperations"]
