"""Local V2 worker resume capsule rules with no runtime or provider access."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final


_DIGEST_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_LIFECYCLES: Final = frozenset({"ephemeral", "invocation", "binding", "persistent"})
_CAPSULE_REQUIRED_LIFECYCLES: Final = frozenset({"binding", "persistent"})


class ResumeDenied(ValueError):
    """Raised when a terminal or resume operation lacks its immutable binding."""


class _RedactedNonSerializable:
    __slots__ = ()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("worker resume internals are not serializable")


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ResumeDenied(f"invalid {field}")
    return value


def _require_non_negative_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ResumeDenied(f"invalid {field}")
    return value


def _require_request_id(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ResumeDenied("invalid new request id")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class WorkerResumeCapsuleV2(_RedactedNonSerializable):
    schema_version: int
    capsule_revision: int
    bee_digest: str
    session_digest: str
    topic_digest: str
    policy_digest: str
    account_binding_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != 2:
            raise ResumeDenied("unsupported capsule schema")
        _require_non_negative_int(self.capsule_revision, "capsule_revision")
        _require_digest(self.bee_digest, "bee_digest")
        _require_digest(self.session_digest, "session_digest")
        _require_digest(self.topic_digest, "topic_digest")
        _require_digest(self.policy_digest, "policy_digest")
        _require_digest(self.account_binding_digest, "account_binding_digest")


@dataclass(frozen=True, slots=True, repr=False)
class WorkerResumeRequestV2(_RedactedNonSerializable):
    request_id: str
    bee_digest: str
    session_digest: str
    topic_digest: str
    policy_digest: str
    account_binding_digest: str
    phase: str
    requires_new_lease: bool
    allows_in_place_credential_rotation: bool

    def __post_init__(self) -> None:
        _require_request_id(self.request_id)
        _require_digest(self.bee_digest, "bee_digest")
        _require_digest(self.session_digest, "session_digest")
        _require_digest(self.topic_digest, "topic_digest")
        _require_digest(self.policy_digest, "policy_digest")
        _require_digest(self.account_binding_digest, "account_binding_digest")
        if self.phase != "REQUESTED" or self.requires_new_lease is not True:
            raise ResumeDenied("resume must begin with a new lease request")
        if self.allows_in_place_credential_rotation is not False:
            raise ResumeDenied("in-place credential rotation forbidden")


def create_resume_capsule(
    *,
    bee_digest: object,
    session_digest: object,
    topic_digest: object,
    policy_digest: object,
    account_binding_digest: object,
    capsule_revision: object,
) -> WorkerResumeCapsuleV2:
    """Create a strict V2 capsule containing only immutable digest bindings."""

    return WorkerResumeCapsuleV2(
        schema_version=2,
        capsule_revision=_require_non_negative_int(
            capsule_revision, "capsule_revision"
        ),
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
    """Require V2 capsule before terminal revoke or home teardown when applicable."""

    if not isinstance(lifecycle, str) or lifecycle not in _LIFECYCLES:
        raise ResumeDenied("invalid lifecycle")
    if not isinstance(resumable, bool):
        raise ResumeDenied("invalid resumable flag")
    topic_digest = _require_digest(topic_digest, "topic_digest")
    policy_digest = _require_digest(policy_digest, "policy_digest")
    account_binding_digest = _require_digest(
        account_binding_digest, "account_binding_digest"
    )
    if capsule is None:
        if resumable or lifecycle in _CAPSULE_REQUIRED_LIFECYCLES:
            raise ResumeDenied("terminal capsule required")
        return None
    if not isinstance(capsule, WorkerResumeCapsuleV2):
        raise ResumeDenied("worker resume capsule v2 required")
    if (
        capsule.topic_digest != topic_digest
        or capsule.policy_digest != policy_digest
        or capsule.account_binding_digest != account_binding_digest
    ):
        raise ResumeDenied("terminal capsule binding drift")
    return capsule


def begin_resume_request(
    capsule: object, *, new_request_id: object
) -> WorkerResumeRequestV2:
    """Bind a resume to a fresh ``REQUESTED`` transaction and new lease."""

    if not isinstance(capsule, WorkerResumeCapsuleV2):
        raise ResumeDenied("worker resume capsule v2 required")
    return WorkerResumeRequestV2(
        request_id=_require_request_id(new_request_id),
        bee_digest=capsule.bee_digest,
        session_digest=capsule.session_digest,
        topic_digest=capsule.topic_digest,
        policy_digest=capsule.policy_digest,
        account_binding_digest=capsule.account_binding_digest,
        phase="REQUESTED",
        requires_new_lease=True,
        allows_in_place_credential_rotation=False,
    )


__all__ = [
    "ResumeDenied",
    "WorkerResumeCapsuleV2",
    "WorkerResumeRequestV2",
    "begin_resume_request",
    "create_resume_capsule",
    "require_terminal_capsule",
]
