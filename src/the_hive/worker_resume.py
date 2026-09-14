"""Local V2 worker resume values and nominal ledger transaction port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
import re
from typing import Final


_DIGEST_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")


class ResumeDenied(ValueError):
    """Raised when resume or terminal evidence fails closed."""


class _RedactedNonSerializable:
    __slots__ = ()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("worker resume internals are not serializable")


class WorkerLifecycle(str, Enum):
    EPHEMERAL = "ephemeral"
    INVOCATION = "invocation"
    BINDING = "binding"
    PERSISTENT = "persistent"


class ResumeRequestPhase(str, Enum):
    REQUESTED = "REQUESTED"


def _require_digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ResumeDenied(f"invalid {field}")
    return value


def _require_request_id(value: object) -> str:
    if type(value) is not str or not value:
        raise ResumeDenied("invalid new request id")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class CapsuleGeneration(_RedactedNonSerializable):
    value: int

    def __post_init__(self) -> None:
        if type(self.value) is not int or self.value < 1:
            raise ResumeDenied("invalid capsule generation")


@dataclass(frozen=True, slots=True, repr=False)
class WorkerResumeCapsuleV2(_RedactedNonSerializable):
    schema_version: int
    capsule_digest: str
    capsule_generation: CapsuleGeneration
    bee_digest: str
    session_digest: str
    topic_digest: str
    policy_digest: str
    account_binding_digest: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 2:
            raise ResumeDenied("unsupported capsule schema")
        if type(self.capsule_generation) is not CapsuleGeneration:
            raise ResumeDenied("invalid capsule generation")
        _require_digest(self.capsule_digest, "capsule_digest")
        _require_digest(self.bee_digest, "bee_digest")
        _require_digest(self.session_digest, "session_digest")
        _require_digest(self.topic_digest, "topic_digest")
        _require_digest(self.policy_digest, "policy_digest")
        _require_digest(self.account_binding_digest, "account_binding_digest")


@dataclass(frozen=True, slots=True, repr=False)
class WorkerResumeRequestV2(_RedactedNonSerializable):
    request_id: str
    capsule_digest: str
    capsule_generation: CapsuleGeneration
    bee_digest: str
    session_digest: str
    topic_digest: str
    policy_digest: str
    account_binding_digest: str
    phase: ResumeRequestPhase
    requested_revision: int
    requires_new_lease: bool
    allows_in_place_credential_rotation: bool

    def __post_init__(self) -> None:
        _require_request_id(self.request_id)
        if type(self.capsule_generation) is not CapsuleGeneration:
            raise ResumeDenied("invalid capsule generation")
        _require_digest(self.capsule_digest, "capsule_digest")
        _require_digest(self.bee_digest, "bee_digest")
        _require_digest(self.session_digest, "session_digest")
        _require_digest(self.topic_digest, "topic_digest")
        _require_digest(self.policy_digest, "policy_digest")
        _require_digest(self.account_binding_digest, "account_binding_digest")
        if type(self.phase) is not ResumeRequestPhase:
            raise ResumeDenied("invalid resume request phase")
        if type(self.requested_revision) is not int or self.requested_revision != 1:
            raise ResumeDenied("resume must start at revision one")
        if self.requires_new_lease is not True:
            raise ResumeDenied("resume must require a new lease")
        if self.allows_in_place_credential_rotation is not False:
            raise ResumeDenied("in-place credential rotation forbidden")


class ResumeTransactionPort(ABC):
    """Nominal port for one atomic capsule consume plus new request."""

    @abstractmethod
    def claim_resume_capsule(
        self,
        source_ticket: object,
        capsule: WorkerResumeCapsuleV2,
        *,
        new_request_id: object,
        new_fence_epoch: object,
        expected_revision: object,
        expected_capsule_generation: object,
        teamlead: object,
    ) -> WorkerResumeRequestV2:
        raise NotImplementedError


def create_resume_capsule(
    *,
    capsule_digest: object,
    capsule_generation: object,
    bee_digest: object,
    session_digest: object,
    topic_digest: object,
    policy_digest: object,
    account_binding_digest: object,
) -> WorkerResumeCapsuleV2:
    """Create strict V2 evidence containing only immutable digest bindings."""

    if type(capsule_generation) is not CapsuleGeneration:
        raise ResumeDenied("invalid capsule generation")
    return WorkerResumeCapsuleV2(
        schema_version=2,
        capsule_digest=_require_digest(capsule_digest, "capsule_digest"),
        capsule_generation=capsule_generation,
        bee_digest=_require_digest(bee_digest, "bee_digest"),
        session_digest=_require_digest(session_digest, "session_digest"),
        topic_digest=_require_digest(topic_digest, "topic_digest"),
        policy_digest=_require_digest(policy_digest, "policy_digest"),
        account_binding_digest=_require_digest(
            account_binding_digest, "account_binding_digest"
        ),
    )


def require_terminal_capsule(
    *,
    lifecycle: object,
    resumable: object,
    capsule: object | None,
    topic_digest: object,
    policy_digest: object,
    account_binding_digest: object,
) -> WorkerResumeCapsuleV2 | None:
    """Validate capsule evidence before terminal cleanup or revoke."""

    if type(lifecycle) is not WorkerLifecycle:
        raise ResumeDenied("invalid lifecycle")
    if type(resumable) is not bool:
        raise ResumeDenied("invalid resumable flag")
    topic_digest = _require_digest(topic_digest, "topic_digest")
    policy_digest = _require_digest(policy_digest, "policy_digest")
    account_binding_digest = _require_digest(
        account_binding_digest, "account_binding_digest"
    )
    capsule_required = resumable or lifecycle in {
        WorkerLifecycle.BINDING,
        WorkerLifecycle.PERSISTENT,
    }
    if capsule is None:
        if capsule_required:
            raise ResumeDenied("terminal capsule required")
        return None
    if type(capsule) is not WorkerResumeCapsuleV2:
        raise ResumeDenied("worker resume capsule v2 required")
    if (
        capsule.topic_digest != topic_digest
        or capsule.policy_digest != policy_digest
        or capsule.account_binding_digest != account_binding_digest
    ):
        raise ResumeDenied("terminal capsule binding drift")
    return capsule


def begin_resume_request(
    ledger: object,
    *,
    source_ticket: object,
    capsule: object,
    new_request_id: object,
    new_fence_epoch: object,
    expected_revision: object,
    expected_capsule_generation: object,
    teamlead: object,
) -> WorkerResumeRequestV2:
    """Delegate one resume to the nominal atomic ledger port."""

    if not isinstance(ledger, ResumeTransactionPort):
        raise ResumeDenied("resume transaction port required")
    if type(capsule) is not WorkerResumeCapsuleV2:
        raise ResumeDenied("worker resume capsule v2 required")
    if type(expected_capsule_generation) is not CapsuleGeneration:
        raise ResumeDenied("invalid expected capsule generation")
    _require_request_id(new_request_id)
    try:
        result = ledger.claim_resume_capsule(
            source_ticket,
            capsule,
            new_request_id=new_request_id,
            new_fence_epoch=new_fence_epoch,
            expected_revision=expected_revision,
            expected_capsule_generation=expected_capsule_generation,
            teamlead=teamlead,
        )
    except (TypeError, ValueError) as exc:
        raise ResumeDenied("resume transaction denied") from exc
    if type(result) is not WorkerResumeRequestV2:
        raise ResumeDenied("invalid resume transaction result")
    return result


__all__ = [
    "CapsuleGeneration",
    "ResumeDenied",
    "ResumeRequestPhase",
    "ResumeTransactionPort",
    "WorkerLifecycle",
    "WorkerResumeCapsuleV2",
    "WorkerResumeRequestV2",
    "begin_resume_request",
    "create_resume_capsule",
    "require_terminal_capsule",
]
