from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, cast

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
MAX_OPERATION_REQUEST_BYTES = 16 * 1024
MAX_OPERATION_RESPONSE_BYTES = 64 * 1024
OPERATION_TIMEOUT_SECONDS = 5.0
_OPERATION_TYPE = "ollama.instance"
_OPERATION_ACTIONS = ("plan", "apply", "probe", "stop")


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


@dataclass(frozen=True, slots=True)
class BrokerOllamaInstancePayload:
    host_ref: str
    instance_ref: str
    selected_model_refs: tuple[str, ...]
    allowed_cpus: str
    cpu_quota_percent: int
    cpu_weight: int
    model_generation: int
    runtime_generation: int
    fence: int
    plan_digest: str
    idempotency_key: str

    def __post_init__(self) -> None:
        if (
            not _safe_token(self.host_ref, maximum=128)
            or not _safe_token(self.instance_ref, maximum=128)
            or type(self.selected_model_refs) is not tuple
            or not 1 <= len(self.selected_model_refs) <= 64
            or any(
                not _safe_token(model_ref, maximum=128)
                for model_ref in self.selected_model_refs
            )
            or len(set(self.selected_model_refs)) != len(self.selected_model_refs)
            or type(self.allowed_cpus) is not str
            or not 1 <= len(self.allowed_cpus) <= 256
            or any(character not in "0123456789,-" for character in self.allowed_cpus)
            or type(self.cpu_quota_percent) is not int
            or not 1 <= self.cpu_quota_percent <= 10000
            or type(self.cpu_weight) is not int
            or not 1 <= self.cpu_weight <= 10000
            or type(self.model_generation) is not int
            or self.model_generation < 0
            or type(self.runtime_generation) is not int
            or self.runtime_generation < 0
            or type(self.fence) is not int
            or self.fence < 0
            or not _hex_token(self.plan_digest, length=64)
            or not _hex_token(self.idempotency_key, length=64)
        ):
            raise BrokerTransportError("provider.operation_not_allowed") from None


@dataclass(frozen=True, slots=True)
class BrokerOperationRequest:
    schema_version: int
    operation_type: str
    action: str
    host_ref: str
    lease_id: str = field(repr=False)
    request_id: str
    payload: BrokerOllamaInstancePayload

    def __post_init__(self) -> None:
        if (
            self.schema_version != 1
            or self.operation_type != _OPERATION_TYPE
            or self.action not in _OPERATION_ACTIONS
            or not _safe_token(self.host_ref, maximum=128)
            or not _safe_token(self.lease_id, maximum=128)
            or not _hex_token(self.request_id, length=32)
            or type(self.payload) is not BrokerOllamaInstancePayload
        ):
            raise BrokerTransportError("provider.operation_not_allowed") from None
        self.payload.__post_init__()
        if self.payload.host_ref != self.host_ref:
            raise BrokerTransportError("provider.operation_not_allowed") from None


@dataclass(frozen=True, slots=True)
class BrokerOperationResponse:
    schema_version: int
    operation_type: str
    action: str
    host_ref: str
    request_id: str
    status_code: int
    redirected: bool
    payload: bytes


class BrokerTransportOperations(Protocol):
    def receive_frame(self) -> tuple[BrokerPeer, ScmFrame]: ...

    def send_frame(self, frame: ScmFrame) -> None: ...

    def close(self, fd: int) -> None: ...


class BrokerRequestHandler(Protocol):
    def handle(
        self, peer: BrokerPeer, request: BrokerRequest
    ) -> BrokerTransportResponse: ...


class BrokerOperationClient(Protocol):
    def exchange(
        self,
        request: BrokerOperationRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> BrokerOperationResponse: ...


def exchange_typed_operation(
    client: BrokerOperationClient,
    request: BrokerOperationRequest,
) -> BrokerOperationResponse:
    if type(request) is not BrokerOperationRequest:
        raise BrokerTransportError("provider.operation_not_allowed") from None
    request.__post_init__()
    try:
        response = client.exchange(
            request,
            timeout_seconds=OPERATION_TIMEOUT_SECONDS,
            max_response_bytes=MAX_OPERATION_RESPONSE_BYTES,
        )
    except Exception:
        raise BrokerTransportError("resource.host_unreachable") from None
    if (
        type(response) is not BrokerOperationResponse
        or response.schema_version != request.schema_version
        or response.operation_type != request.operation_type
        or response.action != request.action
        or response.host_ref != request.host_ref
        or response.request_id != request.request_id
        or response.status_code != 200
        or response.redirected is not False
        or type(response.payload) is not bytes
        or not response.payload
        or len(response.payload) > MAX_OPERATION_RESPONSE_BYTES
    ):
        raise BrokerTransportError("resource.host_response_invalid") from None
    return response


def _safe_token(value: object, *, maximum: int) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and all(character.isascii() and (character.isalnum() or character in "._-") for character in value)
    )


def _hex_token(value: object, *, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


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
    if type(value) in (tuple, list):
        sequence = cast(tuple[object, ...] | list[object], value)
        if len(sequence) >= 2:
            value = sequence[1]
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
