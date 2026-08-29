"""Read-only CHPB/2 home-attestation client boundary."""

from dataclasses import dataclass
from typing import Protocol

from codex_master.fleet_home_broker_linux import FdStat, _validate_fd_stat
from codex_master.fleet_home_broker_protocol import (
    AgentStartClaim,
    AgentStartEnvelope,
    AttestHomeRequest,
    BrokerReply,
    BrokerResultCode,
    BrokerRequest,
    CANONICAL_AGENT_HOME,
    ChpbMessageKind,
    DeprovisionHomeRequest,
    GetTerminalResultRequest,
    HomeAttestation,
    PolicyBinding,
    PrincipalBinding,
    ProvisionHomeRequest,
    QueryTransactionRequest,
    ReplaceHomeRequest,
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
class AgentStartCmsg:
    level: int
    cmsg_type: int
    fds: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class AgentStartFrame:
    payload: bytes
    cmsgs: tuple[AgentStartCmsg, ...]
    message_truncated: bool
    control_truncated: bool


@dataclass(frozen=True, slots=True)
class AttestedHome:
    fd: int
    reply: BrokerReply
    attestation: HomeAttestation


@dataclass(frozen=True, slots=True)
class AttestedAgentStart:
    fd: int
    envelope: AgentStartEnvelope


class BrokerClientOperations(Protocol):
    def receive_frame(self, request: BrokerRequest) -> ScmFrame: ...

    def fstat(self, fd: int) -> FdStat: ...

    def close(self, fd: int) -> None: ...


class AgentStartClientOperations(Protocol):
    def receive_frame(self, claim: AgentStartClaim) -> AgentStartFrame: ...

    def fstat(self, fd: int) -> FdStat: ...

    def close(self, fd: int) -> None: ...


def _frame_fds(value: object) -> tuple[int, ...]:
    try:
        fds = getattr(value, "fds")
    except Exception:
        return ()
    if type(fds) not in (tuple, list):
        return ()
    result = []
    for fd in fds:
        if type(fd) is int and fd >= 0 and fd not in result:
            result.append(fd)
    return tuple(result)


def _agent_start_cmsg_fds(value: object) -> tuple[int, ...]:
    try:
        cmsgs = getattr(value, "cmsgs")
    except Exception:
        return ()
    if type(cmsgs) not in (tuple, list):
        return ()
    result = []
    for cmsg in cmsgs:
        try:
            fds = getattr(cmsg, "fds")
        except Exception:
            continue
        if type(fds) not in (tuple, list):
            continue
        for fd in fds:
            if type(fd) is int and fd >= 0 and fd not in result:
                result.append(fd)
    return tuple(result)


def _close_all(operations: BrokerClientOperations, fds: object) -> None:
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


_TRANSACTION_REQUEST_TYPES = (
    QueryTransactionRequest,
    GetTerminalResultRequest,
    ProvisionHomeRequest,
    ReplaceHomeRequest,
    DeprovisionHomeRequest,
)


def _validate_transaction_request(
    request: object, expected_principal: PrincipalBinding
) -> None:
    if type(request) not in _TRANSACTION_REQUEST_TYPES:
        raise BrokerClientError("request is not transactional")
    try:
        validate_chpb_message(request)
        validate_principal_binding(expected_principal)
    except Exception as exc:
        raise BrokerClientError("invalid request binding") from exc

    expected = request.expected
    if (
        expected.agent_id != expected_principal.agent_id
        or expected.manifest_generation != expected_principal.manifest_generation
        or expected.unit_generation != expected_principal.unit_generation
        or expected.fencing_epoch != expected_principal.fencing_epoch
    ):
        raise BrokerClientError("request principal expectation drifted")


def _validate_transaction_reply(
    request: QueryTransactionRequest
    | GetTerminalResultRequest
    | ProvisionHomeRequest
    | ReplaceHomeRequest
    | DeprovisionHomeRequest,
    expected_principal: PrincipalBinding,
    reply: object,
) -> BrokerReply:
    if type(reply) is not BrokerReply:
        raise BrokerClientError("broker reply has wrong type")
    try:
        validate_chpb_message(reply)
    except Exception as exc:
        raise BrokerClientError("broker reply is not canonical") from exc
    if reply.request_id != request.request_id:
        raise BrokerClientError("broker reply has wrong request id")
    if reply.result is BrokerResultCode.OK:
        raise BrokerClientError("transaction reply is successful")
    if reply.attestation is not None:
        raise BrokerClientError("transaction reply has attestation")

    transaction = reply.transaction
    if transaction is None:
        return reply

    binding = transaction.binding
    expected_policy = PolicyBinding(
        request.expected.policy_generation,
        request.expected.projection_digest,
    )
    if binding.transaction_id != request.transaction_id:
        raise BrokerClientError("transaction binding drifted")
    if binding.principal != expected_principal:
        raise BrokerClientError("principal binding drifted")
    if binding.policy != expected_policy:
        raise BrokerClientError("policy binding drifted")
    if (
        type(request)
        in (
            ProvisionHomeRequest,
            ReplaceHomeRequest,
            DeprovisionHomeRequest,
        )
        and binding != request.binding
    ):
        raise BrokerClientError("request binding drifted")
    return reply


def receive_transaction_reply(
    request: QueryTransactionRequest
    | GetTerminalResultRequest
    | ProvisionHomeRequest
    | ReplaceHomeRequest
    | DeprovisionHomeRequest,
    expected_principal: PrincipalBinding,
    operations: BrokerClientOperations,
) -> BrokerReply:
    _validate_transaction_request(request, expected_principal)

    try:
        frame = operations.receive_frame(request)
    except Exception as exc:
        raise BrokerClientError("frame receive failed") from exc

    cleanup_fds = _frame_fds(frame)
    try:
        if type(frame) is not ScmFrame:
            raise BrokerClientError("received frame has wrong type")
        if type(frame.payload) is not bytes or type(frame.fds) is not tuple:
            raise BrokerClientError("received frame is invalid")
        if frame.fds != ():
            raise BrokerClientError("transaction reply contains fds")

        reply = decode_chpb_message(frame.payload)
        return _validate_transaction_reply(request, expected_principal, reply)
    except Exception as exc:
        _close_all(operations, cleanup_fds)
        if isinstance(exc, BrokerClientError):
            raise
        raise BrokerClientError("invalid broker frame") from exc


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

    cleanup_fds = _frame_fds(frame)
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


def receive_attested_agent_start(
    claim: AgentStartClaim,
    expected: AgentStartEnvelope,
    operations: AgentStartClientOperations,
) -> AttestedAgentStart:
    try:
        if type(claim) is not AgentStartClaim:
            raise BrokerClientError("agent start claim has wrong type")
        if type(expected) is not AgentStartEnvelope:
            raise BrokerClientError("agent start envelope has wrong type")
        validate_chpb_message(claim)
        validate_chpb_message(expected)
    except Exception as exc:
        if isinstance(exc, BrokerClientError):
            raise
        raise BrokerClientError("agent start binding is invalid") from exc

    try:
        frame = operations.receive_frame(claim)
    except Exception as exc:
        raise BrokerClientError("agent start frame receive failed") from exc

    cleanup_fds = _agent_start_cmsg_fds(frame)
    try:
        if type(frame) is not AgentStartFrame:
            raise BrokerClientError("agent start frame has wrong type")
        if type(frame.payload) is not bytes or type(frame.cmsgs) is not tuple:
            raise BrokerClientError("agent start frame is invalid")
        if (
            type(frame.message_truncated) is not bool
            or type(frame.control_truncated) is not bool
            or frame.message_truncated
            or frame.control_truncated
        ):
            raise BrokerClientError("agent start frame is truncated")
        if len(frame.cmsgs) != 1:
            raise BrokerClientError("agent start frame ancillary count is invalid")
        cmsg = frame.cmsgs[0]
        if (
            type(cmsg) is not AgentStartCmsg
            or type(cmsg.level) is not int
            or cmsg.level != 1
            or type(cmsg.cmsg_type) is not int
            or cmsg.cmsg_type != 1
            or type(cmsg.fds) is not tuple
        ):
            raise BrokerClientError("agent start ancillary descriptor is invalid")
        if len(cmsg.fds) != 1 or type(cmsg.fds[0]) is not int or cmsg.fds[0] < 0:
            raise BrokerClientError("agent start frame does not contain one fd")
        if len(cleanup_fds) != 1:
            raise BrokerClientError("agent start frame fd identity is invalid")
        fd = cmsg.fds[0]

        envelope = decode_chpb_message(frame.payload)
        if type(envelope) is not AgentStartEnvelope:
            raise BrokerClientError("agent start frame has wrong payload")
        if envelope != expected or envelope.request_id != claim.request_id:
            raise BrokerClientError("agent start envelope binding drifted")

        observed = _validate_fd_stat(operations.fstat(fd))
        if (
            observed.uid != 0
            or observed.gid != 0
            or observed.dev != envelope.attestation.directory.dev
            or observed.ino != envelope.attestation.directory.ino
            or observed.mode != envelope.attestation.directory.mode
        ):
            raise BrokerClientError("agent start fd stat drifted")
        return AttestedAgentStart(fd, envelope)
    except Exception as exc:
        _close_all(operations, cleanup_fds)
        if isinstance(exc, BrokerClientError):
            raise
        raise BrokerClientError("invalid agent start frame") from exc


__all__ = [
    "AgentStartClientOperations",
    "AgentStartCmsg",
    "AgentStartFrame",
    "AttestedAgentStart",
    "AttestedHome",
    "BrokerClientError",
    "BrokerClientOperations",
    "ScmFrame",
    "receive_attested_agent_start",
    "receive_attested_home",
    "receive_transaction_reply",
]
