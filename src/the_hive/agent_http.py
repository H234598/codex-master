"""Bounded application boundary for the private host-agent API."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from collections.abc import Callable
from typing import Final, Protocol, cast

from .admin_hosts import AgentPrincipalV1, HostRegistryError
from .admin_operations import AdminOperationError
from .agent_contracts import (
    AgentContractError,
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentPollV1,
    AgentReceiptV1,
    parse_agent_poll,
    parse_agent_receipt,
    serialize_agent_lease,
)
from .agent_operations import (
    AgentAttemptExhaustionV1,
    AgentOperationDeadlineExpiryV1,
    AgentOperationError,
    AgentPrincipalV1 as OperationPrincipalV1,
)
from .fleet_service import FleetConflictError


MAX_AGENT_BODY_BYTES: Final[int] = 64 * 1024
MAX_AGENT_HEADER_BYTES: Final[int] = 16 * 1024
_RECEIPT_ROUTE = re.compile(
    r"/agent/v1/operations/([A-Za-z0-9._:-]{1,128})/receipts\Z", re.ASCII
)
_HEADERS = (("Content-Type", "application/json"), ("Cache-Control", "no-store"))


class _Store(Protocol):
    def poll(
        self,
        principal: OperationPrincipalV1,
        poll: object,
        *,
        attempt_exhaustion_owner: Callable[[AgentAttemptExhaustionV1], bool]
        | None = None,
        operation_deadline_owner: Callable[[AgentOperationDeadlineExpiryV1], bool]
        | None = None,
        lifecycle_ack_owner: Callable[
            [AgentAttemptExhaustionV1 | AgentOperationDeadlineExpiryV1], None
        ]
        | None = None,
    ) -> object: ...
    def complete(self, principal: OperationPrincipalV1, receipt: object) -> object: ...


@dataclass(frozen=True, slots=True)
class AgentHttpResponse:
    status: int
    body: bytes
    headers: tuple[tuple[str, str], ...] = _HEADERS


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _json_body(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _response(status: int, value: object) -> AgentHttpResponse:
    return AgentHttpResponse(status, _json_body(value))


def _problem(status: int, code: str) -> AgentHttpResponse:
    return _response(status, {"error": code})


class AgentHttpApplication:
    """Dispatch exactly the two agent routes to the existing operation store."""

    def __init__(self, store: _Store, completion_owner: object | None = None) -> None:
        if not hasattr(store, "poll") or not hasattr(store, "complete"):
            raise TypeError("agent.store_invalid")
        self._store = store
        self._completion_owner = completion_owner

    def handle(
        self,
        principal: AgentPrincipalV1,
        method: str,
        target: str,
        body: bytes,
    ) -> AgentHttpResponse:
        if type(principal) is not AgentPrincipalV1:
            return _problem(403, "agent.identity_invalid")
        if type(method) is not str or type(target) is not str or type(body) is not bytes:
            return _problem(400, "agent.request_invalid")
        if len(body) > MAX_AGENT_BODY_BYTES:
            return _problem(413, "agent.request_too_large")

        receipt_match = _RECEIPT_ROUTE.fullmatch(target)
        known_path = target == "/agent/v1/polls" or receipt_match is not None
        if not known_path:
            return _problem(404, "agent.route_not_found")
        if method != "POST":
            return _problem(405, "agent.method_not_allowed")
        try:
            value = json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
            if target == "/agent/v1/polls":
                parsed_poll = parse_agent_poll(value)
                owner = self._completion_owner
                exhaustion_owner = getattr(
                    owner,
                    "reconcile_attempt_exhaustion",
                    None,
                )
                deadline_owner = getattr(
                    owner,
                    "reconcile_operation_deadline",
                    None,
                )
                lifecycle_ack_owner = getattr(
                    owner,
                    "acknowledge_agent_lifecycle",
                    None,
                )
                if callable(deadline_owner):
                    result = self._store.poll(
                        _operation_principal(principal),
                        _authoritative_poll(principal, parsed_poll),
                        attempt_exhaustion_owner=(
                            exhaustion_owner if callable(exhaustion_owner) else None
                        ),
                        operation_deadline_owner=deadline_owner,
                        lifecycle_ack_owner=(
                            lifecycle_ack_owner
                            if callable(lifecycle_ack_owner)
                            else None
                        ),
                    )
                elif callable(exhaustion_owner):
                    result = self._store.poll(
                        _operation_principal(principal),
                        _authoritative_poll(principal, parsed_poll),
                        attempt_exhaustion_owner=exhaustion_owner,
                        lifecycle_ack_owner=(
                            lifecycle_ack_owner
                            if callable(lifecycle_ack_owner)
                            else None
                        ),
                    )
                else:
                    result = self._store.poll(
                        _operation_principal(principal),
                        _authoritative_poll(principal, parsed_poll),
                    )
                return _response(200, self._poll_result(result))
            receipt = parse_agent_receipt(value)
            if receipt.operation_id != cast(re.Match[str], receipt_match).group(1):
                raise AgentContractError
            _validate_binding_epoch(principal, receipt)
            owner = self._completion_owner
            if callable(getattr(owner, "complete", None)):
                owner.complete(principal, receipt)
            else:
                self._store.complete(_operation_principal(principal), receipt)
            return _response(
                200,
                {"schema_version": 1, "operation_id": receipt.operation_id, "accepted": True},
            )
        except AgentOperationError as error:
            if error.code in {
                "host.poll_already_active",
                "host.registry_generation_stale",
                "host.lease_epoch_stale",
                "host.lease_stale",
                "host.identity_mismatch",
                "host.receipt_conflict",
            }:
                return _problem(409, error.code)
            if error.code == "host.operation_store_unavailable":
                return _problem(503, "agent.temporarily_unavailable")
            return _problem(400, "agent.request_invalid")
        except (AdminOperationError, HostRegistryError):
            return _problem(503, "agent.temporarily_unavailable")
        except FleetConflictError as error:
            if error.code in {
                "host.identity_mismatch",
                "host.registry_generation_stale",
                "host.lease_epoch_stale",
                "host.lease_stale",
                "host.receipt_conflict",
            }:
                return _problem(409, error.code)
            return _problem(400, "agent.request_invalid")
        except (AgentContractError, UnicodeError, ValueError, TypeError, RecursionError):
            return _problem(400, "agent.request_invalid")

    @staticmethod
    def _poll_result(value: object) -> dict[str, object]:
        if type(value) is AgentLeaseV1:
            return serialize_agent_lease(value)
        if type(value) is AgentNoWorkV1:
            no_work = cast(AgentNoWorkV1, value)
            return {
                "schema_version": 1,
                "registry_generation": no_work.registry_generation,
                "lease_epoch": no_work.lease_epoch,
                "max_wait_seconds": no_work.max_wait_seconds,
            }
        raise AgentOperationError("host.operation_store_unavailable")


def _operation_principal(principal: AgentPrincipalV1) -> OperationPrincipalV1:
    return OperationPrincipalV1(
        principal.host_ref,
        principal.registry_generation,
    )


def _authoritative_poll(
    principal: AgentPrincipalV1, poll: AgentPollV1
) -> AgentPollV1:
    if poll.lease_epoch != principal.lease_epoch:
        raise AgentOperationError("host.lease_epoch_stale")
    if poll.registry_generation > principal.registry_generation:
        raise AgentOperationError("host.registry_generation_stale")
    return AgentPollV1(
        principal.registry_generation,
        poll.lease_epoch,
        poll.capabilities_digest,
        poll.max_wait_seconds,
    )


def _validate_binding_epoch(
    principal: AgentPrincipalV1, receipt: AgentReceiptV1
) -> None:
    if receipt.lease_epoch != principal.lease_epoch:
        raise AgentOperationError("host.lease_epoch_stale")


__all__ = [
    "AgentHttpApplication",
    "AgentHttpResponse",
    "MAX_AGENT_BODY_BYTES",
    "MAX_AGENT_HEADER_BYTES",
]
