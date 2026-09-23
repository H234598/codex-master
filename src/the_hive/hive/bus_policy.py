"""Pure BUS-S2/A topic-queen delegation validation.

This module owns no delegation state.  Its collection input is the complete
currently active delegation set supplied by a caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from the_hive.hive.authority import (
    MAX_GRANT_PATHS,
    MAX_GRANT_TTL_SECONDS,
    AuthorityEngine,
)
from the_hive.hive.bus_types import (
    HiveBusContractError,
    _digest as _validate_s0_digest,
    validate_topic_partition,
)
from the_hive.hive.capabilities import QUEEN_CLASSES
from the_hive.hive.principals import PrincipalError
from the_hive.hive.repositories import RepositoryError
from the_hive.hive.types import (
    HiveValidationError,
    validate_identifier,
    validate_utc_datetime,
)


def _reject(code: str) -> None:
    raise HiveBusContractError(code)


def _identifier(value: object, *, field: str) -> str:
    try:
        return validate_identifier(value, field=field)
    except HiveValidationError:
        _reject("BUS_E_SCHEMA")
    raise AssertionError("unreachable")


def _utc(value: object, *, field: str) -> datetime:
    try:
        normalized = validate_utc_datetime(value, field=field)
    except (HiveValidationError, TypeError, ValueError):
        _reject("BUS_E_SCHEMA")
    if value.utcoffset() != timedelta(0):
        _reject("BUS_E_SCHEMA")
    return normalized


@dataclass(frozen=True, slots=True)
class QueenTopicDelegationV1:
    """One effect-free, repo-local delegation from a topic queen to an integration queen."""

    schema_version: int
    repo_id: str
    topic_id: str
    plan_digest: str
    exclusive_paths: tuple[str, ...]
    topic_queen_principal_id: str
    integration_queen_principal_id: str
    authority_generation: str
    issued_at_utc: datetime
    expires_at_utc: datetime

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _reject("BUS_E_SCHEMA")
        object.__setattr__(self, "repo_id", _identifier(self.repo_id, field="repo"))
        topic_id = validate_topic_partition(self.topic_id)
        topic_parts = topic_id.split("/")
        if (
            len(topic_parts) != 4
            or topic_parts[0] != "repo"
            or topic_parts[1] != self.repo_id
            or topic_parts[2] != "topic"
        ):
            _reject("BUS_E_REPO_SCOPE")
        object.__setattr__(self, "topic_id", topic_id)
        if (
            type(self.exclusive_paths) is not tuple
            or not self.exclusive_paths
            or len(self.exclusive_paths) > MAX_GRANT_PATHS
            or any(type(path) is not str for path in self.exclusive_paths)
            or self.exclusive_paths != tuple(sorted(self.exclusive_paths))
            or len(self.exclusive_paths) != len(set(self.exclusive_paths))
        ):
            _reject("BUS_E_SCHEMA")
        object.__setattr__(self, "plan_digest", _validate_s0_digest(self.plan_digest))
        object.__setattr__(
            self,
            "topic_queen_principal_id",
            _identifier(self.topic_queen_principal_id, field="topic_queen_principal"),
        )
        object.__setattr__(
            self,
            "integration_queen_principal_id",
            _identifier(
                self.integration_queen_principal_id, field="integration_queen_principal"
            ),
        )
        object.__setattr__(
            self,
            "authority_generation",
            _validate_s0_digest(self.authority_generation),
        )
        issued = _utc(self.issued_at_utc, field="issued")
        expires = _utc(self.expires_at_utc, field="expires")
        ttl_seconds = (expires - issued).total_seconds()
        if not 1 <= ttl_seconds <= MAX_GRANT_TTL_SECONDS:
            _reject("BUS_E_SCHEMA")
        object.__setattr__(self, "issued_at_utc", issued)
        object.__setattr__(self, "expires_at_utc", expires)


def _validated_resolved_paths(
    delegation: object, *, authority: object
) -> tuple[object, ...]:
    if (
        type(delegation) is not QueenTopicDelegationV1
        or type(authority) is not AuthorityEngine
    ):
        _reject("BUS_E_SCHEMA")
    try:
        authority.context.repositories.get(delegation.repo_id)
        resolved_paths = tuple(
            authority.context.repositories.resolve_path(delegation.repo_id, path)
            for path in delegation.exclusive_paths
        )
    except RepositoryError:
        _reject("BUS_E_REPO_SCOPE")
    for index, current_path in enumerate(resolved_paths):
        if any(
            current_path.is_relative_to(previous_path)
            or previous_path.is_relative_to(current_path)
            for previous_path in resolved_paths[:index]
        ):
            _reject("BUS_E_ACL_DENIED")
    for principal_id in (
        delegation.topic_queen_principal_id,
        delegation.integration_queen_principal_id,
    ):
        try:
            principal = authority.context.principals.get(principal_id)
        except PrincipalError:
            _reject("BUS_E_ACL_DENIED")
        if (
            principal.state != "active"
            or principal.class_id not in QUEEN_CLASSES
            or principal.repo_id != delegation.repo_id
        ):
            _reject("BUS_E_ACL_DENIED")
    if delegation.topic_queen_principal_id == delegation.integration_queen_principal_id:
        _reject("BUS_E_ACL_DENIED")
    return resolved_paths


def validate_queen_topic_delegation_v1(
    delegation: object, *, authority: object
) -> QueenTopicDelegationV1:
    """Validate one value against the existing authority and repository registries."""

    _validated_resolved_paths(delegation, authority=authority)
    return delegation


def validate_active_queen_topic_delegations(
    delegations: object, *, authority: object
) -> tuple[QueenTopicDelegationV1, ...]:
    """Fail closed unless the supplied active set is topic- and path-disjoint."""

    if type(delegations) is not tuple:
        _reject("BUS_E_SCHEMA")
    resolved_paths = tuple(
        _validated_resolved_paths(delegation, authority=authority)
        for delegation in delegations
    )
    seen_topics: set[tuple[str, str]] = set()
    seen_generations: set[tuple[str, str, str]] = set()
    seen_paths: list[object] = []
    for delegation, current_paths in zip(delegations, resolved_paths, strict=True):
        topic_key = (delegation.repo_id, delegation.topic_id)
        generation_key = (*topic_key, delegation.authority_generation)
        if topic_key in seen_topics or generation_key in seen_generations:
            _reject("BUS_E_ACL_DENIED")
        for current_path in current_paths:
            if any(
                current_path.is_relative_to(previous_path)
                or previous_path.is_relative_to(current_path)
                for previous_path in seen_paths
            ):
                _reject("BUS_E_ACL_DENIED")
        seen_topics.add(topic_key)
        seen_generations.add(generation_key)
        seen_paths.extend(current_paths)
    return delegations


__all__ = [
    "QueenTopicDelegationV1",
    "validate_active_queen_topic_delegations",
    "validate_queen_topic_delegation_v1",
]
