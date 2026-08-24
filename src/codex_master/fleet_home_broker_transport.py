from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from codex_master.fleet_home_broker_client import ScmFrame
from codex_master.fleet_home_broker_protocol import (
    BrokerReply,
    BrokerRequest,
    BrokerResultCode,
    decode_chpb_message,
    encode_chpb_message,
    validate_chpb_message,
)


class BrokerTransportError(ValueError):
    """Broker transport contract error."""


MAX_TRANSPORT_RESPONSE_FDS = 1


@dataclass(frozen=True, slots=True)
class BrokerPeer:
    pid: int

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid <= 0:
            raise BrokerTransportError("invalid broker peer") from None


@dataclass(frozen=True, slots=True)
class BrokerTransportResponse:
    reply: BrokerReply
    fds: tuple[int, ...]


class BrokerTransportOperations(Protocol):
    def receive_frame(self) -> tuple[BrokerPeer, ScmFrame]: ...

    def send_frame(self, frame: ScmFrame) -> None: ...

    def close(self, fd: int) -> None: ...


class BrokerRequestHandler(Protocol):
    def handle(
        self, peer: BrokerPeer, request: BrokerRequest
    ) -> BrokerTransportResponse: ...


def serve_once(
    operations: BrokerTransportOperations,
    handler: BrokerRequestHandler,
) -> BrokerReply:
    try:
        received = operations.receive_frame()
    except Exception:
        raise BrokerTransportError("broker frame receive failed") from None

    input_fds = _frame_fds(received)
    try:
        if type(received) is not tuple or len(received) != 2:
            raise BrokerTransportError("broker frame receive failed")
        peer, frame = received
        if type(peer) is not BrokerPeer or type(frame) is not ScmFrame:
            raise BrokerTransportError("broker frame receive failed")
        if type(frame.payload) is not bytes or type(frame.fds) is not tuple:
            raise BrokerTransportError("invalid broker request frame")
        if frame.fds:
            raise BrokerTransportError("invalid broker request frame")
        try:
            request = decode_chpb_message(frame.payload)
            validate_chpb_message(request)
        except Exception:
            raise BrokerTransportError("invalid broker request frame") from None
        if type(request) is BrokerReply:
            raise BrokerTransportError("invalid broker request frame")
    finally:
        _close_fds(operations, input_fds)

    try:
        response = handler.handle(peer, request)
    except Exception:
        raise BrokerTransportError("broker request handling failed") from None

    outgoing_fds = _frame_fds(response)
    try:
        if type(response) is not BrokerTransportResponse:
            raise BrokerTransportError("invalid broker response")
        if type(response.reply) is not BrokerReply or type(response.fds) is not tuple:
            raise BrokerTransportError("invalid broker response")
        if any(type(fd) is not int or fd < 0 for fd in response.fds):
            raise BrokerTransportError("invalid broker response")
        if len(set(response.fds)) != len(response.fds):
            raise BrokerTransportError("invalid broker response")
        reply = response.reply
        try:
            validate_chpb_message(reply)
        except Exception:
            raise BrokerTransportError("invalid broker response") from None
        if reply.request_id != request.request_id:
            raise BrokerTransportError("invalid broker response")
        if reply.result is BrokerResultCode.OK:
            if len(response.fds) != MAX_TRANSPORT_RESPONSE_FDS:
                raise BrokerTransportError("invalid broker response")
        elif response.fds:
            raise BrokerTransportError("invalid broker response")
        try:
            frame = ScmFrame(encode_chpb_message(reply), response.fds)
        except Exception:
            raise BrokerTransportError("invalid broker response") from None
        try:
            operations.send_frame(frame)
        except Exception:
            raise BrokerTransportError("broker frame send failed") from None
        return reply
    finally:
        _close_fds(operations, outgoing_fds)


def _frame_fds(value: object) -> tuple[int, ...]:
    if type(value) in (tuple, list) and len(value) >= 2:
        value = value[1]
    try:
        fds = getattr(value, "fds", ())
    except Exception:
        return ()
    if type(fds) not in (tuple, list):
        return ()
    result = []
    for fd in fds:
        if type(fd) is int and fd >= 0 and fd not in result:
            result.append(fd)
    return tuple(result)


def _close_fds(operations: BrokerTransportOperations, fds: tuple[int, ...]) -> None:
    for fd in fds:
        try:
            operations.close(fd)
        except Exception:
            pass


__all__ = (
    "BrokerTransportError",
    "MAX_TRANSPORT_RESPONSE_FDS",
    "BrokerPeer",
    "BrokerTransportResponse",
    "BrokerTransportOperations",
    "BrokerRequestHandler",
    "serve_once",
)
