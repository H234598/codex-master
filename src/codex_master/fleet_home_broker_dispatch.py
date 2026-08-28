from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Protocol

from codex_master.fleet_home_broker import OfflineBrokerPlan
from codex_master.fleet_home_broker_protocol import (
    AttestHomeRequest,
    BrokerReply,
    BrokerRequest,
    BrokerResultCode,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    DeprovisionHomeRequest,
    GetTerminalResultRequest,
    PolicyBinding,
    PrincipalBinding,
    ProvisionHomeRequest,
    QueryTransactionRequest,
    ReplaceHomeRequest,
    TransactionBinding,
    encode_chpb_message,
    validate_chpb_message,
    validate_principal_binding,
    validate_transaction_binding,
)
from codex_master.fleet_home_broker_transport import BrokerPeer, BrokerTransportResponse


class BrokerDispatchError(ValueError):
    """Broker dispatch contract error."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class BrokerDispatchCommand:
    principal: PrincipalBinding
    request: BrokerRequest
    request_digest: str
    plan: OfflineBrokerPlan | None


class BrokerDispatchResolver(Protocol):
    def resolve_principal(self, peer: BrokerPeer) -> PrincipalBinding: ...

    def resolve_mutation_plan(
        self,
        principal: PrincipalBinding,
        request: ProvisionHomeRequest | ReplaceHomeRequest | DeprovisionHomeRequest,
    ) -> OfflineBrokerPlan: ...


class BrokerDispatchOperations(Protocol):
    def execute(self, command: BrokerDispatchCommand) -> BrokerTransportResponse: ...

    def close(self, fd: int) -> None: ...


def _reply(request_id: str, result: BrokerResultCode) -> BrokerTransportResponse:
    return BrokerTransportResponse(
        BrokerReply(
            CHPB_PROTOCOL, ChpbMessageKind.REPLY, request_id, result, None, None
        ),
        (),
    )


def _request_type(value: object) -> bool:
    return type(value) in (
        AttestHomeRequest,
        QueryTransactionRequest,
        GetTerminalResultRequest,
        ProvisionHomeRequest,
        ReplaceHomeRequest,
        DeprovisionHomeRequest,
    )


def _peer_drift(
    principal: PrincipalBinding, request: BrokerRequest
) -> BrokerResultCode | None:
    expected = request.expected
    if expected.agent_id != principal.agent_id:
        return BrokerResultCode.WRONG_PRINCIPAL
    if expected.fencing_epoch != principal.fencing_epoch:
        return BrokerResultCode.FENCED
    if (
        expected.manifest_generation != principal.manifest_generation
        or expected.unit_generation != principal.unit_generation
    ):
        return BrokerResultCode.STALE_GENERATION
    return None


def _principal_drift(
    expected: PrincipalBinding, actual: PrincipalBinding
) -> BrokerResultCode | None:
    if (
        expected.agent_id != actual.agent_id
        or expected.cgroup_dev != actual.cgroup_dev
        or expected.cgroup_ino != actual.cgroup_ino
        or expected.invocation_id != actual.invocation_id
        or expected.mcs_pair != actual.mcs_pair
    ):
        return BrokerResultCode.WRONG_PRINCIPAL
    if expected.fencing_epoch != actual.fencing_epoch:
        return BrokerResultCode.FENCED
    if (
        expected.manifest_generation != actual.manifest_generation
        or expected.unit_generation != actual.unit_generation
    ):
        return BrokerResultCode.STALE_GENERATION
    return None


def _binding_drift(
    expected: TransactionBinding, actual: TransactionBinding
) -> BrokerResultCode | None:
    principal_drift = _principal_drift(expected.principal, actual.principal)
    if principal_drift is not None:
        return principal_drift
    if expected.policy != actual.policy:
        return BrokerResultCode.STALE_GENERATION
    if (
        expected.operation != actual.operation
        or expected.store_uuid != actual.store_uuid
        or expected.transaction_id != actual.transaction_id
    ):
        return BrokerResultCode.TRANSACTION_ID_REUSE
    return None


def _plan_binding(
    plan: OfflineBrokerPlan,
    request: ProvisionHomeRequest | ReplaceHomeRequest | DeprovisionHomeRequest,
) -> TransactionBinding:
    if type(plan) is not OfflineBrokerPlan:
        raise ValueError
    validate_principal_binding(plan.expected_principal)
    policy = PolicyBinding(
        plan.identity.policy_generation, plan.identity.projection_digest
    )
    binding = TransactionBinding(
        plan.operation,
        request.transaction_id,
        plan.store_uuid,
        plan.expected_principal,
        policy,
    )
    validate_transaction_binding(binding)
    return binding


def _response_fds(value: object) -> tuple[int, ...]:
    try:
        fds = value.fds
    except Exception:
        return ()
    if type(fds) not in (tuple, list):
        return ()
    result = []
    for fd in fds:
        if type(fd) is int and fd >= 0 and fd not in result:
            result.append(fd)
    return tuple(result)


def _close_response_fds(operations: BrokerDispatchOperations, response: object) -> None:
    for fd in _response_fds(response):
        try:
            operations.close(fd)
        except Exception:
            pass


def _validate_response(
    response: object, request: BrokerRequest, principal: PrincipalBinding
) -> BrokerTransportResponse:
    if type(response) is not BrokerTransportResponse:
        raise ValueError
    if type(response.fds) is not tuple:
        raise ValueError
    seen = []
    for fd in response.fds:
        if type(fd) is not int or fd < 0 or fd in seen:
            raise ValueError
        seen.append(fd)
    reply = response.reply
    validate_chpb_message(reply)
    if reply.request_id != request.request_id:
        raise ValueError
    if reply.result is BrokerResultCode.OK:
        if type(request) is not AttestHomeRequest or len(response.fds) != 1:
            raise ValueError
    elif len(response.fds) != 0:
        raise ValueError
    if reply.transaction is not None:
        expected_policy = PolicyBinding(
            request.expected.policy_generation,
            request.expected.projection_digest,
        )
        binding = reply.transaction.binding
        if (
            binding.transaction_id != request.transaction_id
            or binding.principal != principal
            or binding.policy != expected_policy
        ):
            raise ValueError
    return response


def dispatch_request(
    peer: BrokerPeer,
    request: BrokerRequest,
    resolver: BrokerDispatchResolver,
    operations: BrokerDispatchOperations,
) -> BrokerTransportResponse:
    if type(peer) is not BrokerPeer or not _request_type(request):
        raise BrokerDispatchError("invalid broker dispatch request") from None
    try:
        validate_chpb_message(request)
    except Exception:
        raise BrokerDispatchError("invalid broker dispatch request") from None

    try:
        principal = resolver.resolve_principal(peer)
        if type(principal) is not PrincipalBinding:
            raise ValueError
        validate_principal_binding(principal)
    except Exception:
        raise BrokerDispatchError("broker principal resolution failed") from None

    drift = _peer_drift(principal, request)
    if drift is not None:
        return _reply(request.request_id, drift)

    plan = None
    if type(request) in (
        ProvisionHomeRequest,
        ReplaceHomeRequest,
        DeprovisionHomeRequest,
    ):
        try:
            plan = resolver.resolve_mutation_plan(principal, request)
            plan_binding = _plan_binding(plan, request)
        except Exception:
            raise BrokerDispatchError("broker plan resolution failed") from None
        drift = _principal_drift(principal, plan.expected_principal)
        if drift is not None:
            return _reply(request.request_id, drift)
        expected_policy = PolicyBinding(
            request.expected.policy_generation,
            request.expected.projection_digest,
        )
        if plan_binding.policy != expected_policy:
            return _reply(request.request_id, BrokerResultCode.STALE_GENERATION)
        drift = _binding_drift(plan_binding, request.binding)
        if drift is not None:
            return _reply(request.request_id, drift)

    digest = hashlib.sha256(encode_chpb_message(request)).hexdigest()
    command = BrokerDispatchCommand(principal, request, digest, plan)
    try:
        response = operations.execute(command)
    except Exception:
        raise BrokerDispatchError("broker dispatch execution failed") from None
    try:
        return _validate_response(response, request, principal)
    except Exception:
        _close_response_fds(operations, response)
        raise BrokerDispatchError("invalid broker dispatch response") from None


__all__ = (
    "BrokerDispatchCommand",
    "BrokerDispatchError",
    "BrokerDispatchOperations",
    "BrokerDispatchResolver",
    "dispatch_request",
)
