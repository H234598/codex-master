"""Read-only CHPB/2 home-attestation client boundary."""

from dataclasses import dataclass
from typing import Protocol

from codex_master.fleet_home_broker_linux import FdStat
from codex_master.fleet_home_broker_protocol import (
    AttestHomeRequest,
    BrokerReply,
    BrokerResultCode,
    CANONICAL_AGENT_HOME,
    ChpbMessageKind,
    HomeAttestation,
    PrincipalBinding,
    TransactionStatus,
    decode_chpb_message,
    validate_chpb_message,
    validate_principal_binding,
)


class BrokerClientError(ValueError):
    """Raised when a broker response is not bound to the request."""


@dataclass(frozen=True, slots=True)
class ScmFrame:
    payload: bytes
    fds: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class AttestedHome:
    fd: int
    reply: BrokerReply
    attestation: HomeAttestation


class BrokerClientOperations(Protocol):
    def receive_frame(self, request: AttestHomeRequest) -> ScmFrame: ...

    def fstat(self, fd: int) -> FdStat: ...

    def close(self, fd: int) -> None: ...


def _close_all(operations: BrokerClientOperations, fds: tuple[int, ...]) -> None:
    for fd in fds:
        try:
            operations.close(fd)
        except Exception:
            pass


def _validate_before_receive(
    request: AttestHomeRequest,
    expected_principal: PrincipalBinding,
) -> None:
    try:
        validate_chpb_message(request)
        validate_principal_binding(expected_principal)
    except Exception as exc:
        raise BrokerClientError("invalid request binding") from exc

    if (
        type(request) is not AttestHomeRequest
        or request.kind is not ChpbMessageKind.ATTEST_HOME
    ):
        raise BrokerClientError("request is not attest_home")

    expected = request.expected
    if (
        expected.agent_id != expected_principal.agent_id
        or expected.manifest_generation != expected_principal.manifest_generation
        or expected.unit_generation != expected_principal.unit_generation
        or expected.fencing_epoch != expected_principal.fencing_epoch
    ):
        raise BrokerClientError("request principal expectation drifted")


def _validate_reply(
    request: AttestHomeRequest,
    expected_principal: PrincipalBinding,
    reply: object,
) -> HomeAttestation:
    if type(reply) is not BrokerReply:
        raise BrokerClientError("broker reply has wrong type")
    if reply.kind is not ChpbMessageKind.REPLY:
        raise BrokerClientError("broker reply has wrong kind")
    if reply.request_id != request.request_id:
        raise BrokerClientError("broker reply has wrong request id")
    if reply.result is not BrokerResultCode.OK:
        raise BrokerClientError("broker reply is not successful")
    if type(reply.attestation) is not HomeAttestation:
        raise BrokerClientError("broker reply has no attestation")
    if type(reply.transaction) is not TransactionStatus:
        raise BrokerClientError("broker reply has no transaction")

    attestation = reply.attestation
    if reply.transaction.binding != attestation.binding:
        raise BrokerClientError("transaction and attestation bindings differ")
    if attestation.canonical_path != CANONICAL_AGENT_HOME:
        raise BrokerClientError("home path is not canonical")
    if attestation.binding.transaction_id != request.transaction_id:
        raise BrokerClientError("transaction binding drifted")
    if attestation.binding.principal != expected_principal:
        raise BrokerClientError("principal binding drifted")
    if (
        attestation.binding.policy.policy_generation
        != request.expected.policy_generation
        or attestation.binding.policy.projection_digest
        != request.expected.projection_digest
    ):
        raise BrokerClientError("policy binding drifted")
    if attestation.mcs_pair != expected_principal.mcs_pair:
        raise BrokerClientError("MCS binding drifted")
    return attestation


def receive_attested_home(
    request: AttestHomeRequest,
    expected_principal: PrincipalBinding,
    operations: BrokerClientOperations,
) -> AttestedHome:
    _validate_before_receive(request, expected_principal)

    try:
        frame = operations.receive_frame(request)
    except Exception as exc:
        raise BrokerClientError("frame receive failed") from exc

    received_fds = getattr(frame, "fds", ())
    cleanup_fds = tuple(received_fds) if type(received_fds) in (tuple, list) else ()
    try:
        if type(frame) is not ScmFrame:
            raise BrokerClientError("received frame has wrong type")
        if type(frame.payload) is not bytes or type(frame.fds) is not tuple:
            raise BrokerClientError("received frame is invalid")
        if any(type(fd) is not int or fd < 0 for fd in frame.fds):
            raise BrokerClientError("received fd is invalid")
        if len(frame.fds) != 1:
            raise BrokerClientError("received frame does not contain exactly one fd")

        reply = decode_chpb_message(frame.payload)
        attestation = _validate_reply(request, expected_principal, reply)
        observed = operations.fstat(frame.fds[0])
        if type(observed) is not FdStat:
            raise BrokerClientError("fd stat has wrong type")
        if (
            observed.dev != attestation.directory.dev
            or observed.ino != attestation.directory.ino
            or observed.mode != attestation.directory.mode
        ):
            raise BrokerClientError("fd stat drifted")
        return AttestedHome(frame.fds[0], reply, attestation)
    except Exception as exc:
        _close_all(operations, cleanup_fds)
        if isinstance(exc, BrokerClientError):
            raise
        raise BrokerClientError("invalid broker frame") from exc


__all__ = [
    "AttestedHome",
    "BrokerClientError",
    "BrokerClientOperations",
    "ScmFrame",
    "receive_attested_home",
]
