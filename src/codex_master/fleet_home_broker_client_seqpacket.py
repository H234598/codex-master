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
    __slots__ = ("_operations",)

    def __init__(self, operations: BrokerClientExchangeOperations) -> None:
        for name in ("exchange", "fstat", "close"):
            try:
                operation = getattr(operations, name)
            except Exception as exc:
                raise BrokerClientError("exchange operations are incomplete") from exc
            if not callable(operation):
                raise BrokerClientError("exchange operations are incomplete")
        self._operations = operations

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
