"""Attested test evidence identities and conservative reuse decisions."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RESULTS = frozenset({"passed", "failed", "blocked", "cancelled"})
_COOLDOWN_MAX_SECONDS = {
    "deterministic": 30 * 60,
    "integration": 10 * 60,
    "environmental": 0,
    "external": 0,
    "mandatory": 0,
}
_RESULT_REASONS = {
    "failed": "test.run_failed",
    "blocked": "test.run_blocked",
    "cancelled": "test.evidence_unavailable",
}


class TestEvidenceError(ValueError):
    """Typed, bounded receipt validation failure."""


def _validate_digest(value: str) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise TestEvidenceError("test.evidence_corrupt")


def _validate_text(value: str, *, maximum: int = 2048) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(char) < 32 for char in value):
        raise TestEvidenceError("test.evidence_corrupt")


@dataclass(frozen=True, slots=True)
class EvidenceContextV1:
    repository_id: str
    index_digest: str
    function_ids: tuple[str, ...]
    test_id: str
    source_digest_set_digest: str
    test_digest: str
    assertion_digest: str
    dependency_digest_set_digest: str
    executor_fingerprint: str
    boot_id_digest: str
    runner_version_digest: str
    environment_digest: str

    def __post_init__(self) -> None:
        _validate_text(self.repository_id, maximum=128)
        _validate_text(self.test_id)
        if not self.function_ids or tuple(sorted(set(self.function_ids))) != self.function_ids:
            raise TestEvidenceError("test.evidence_corrupt")
        for function_id in self.function_ids:
            _validate_text(function_id)
        for value in (
            self.index_digest,
            self.source_digest_set_digest,
            self.test_digest,
            self.assertion_digest,
            self.dependency_digest_set_digest,
            self.executor_fingerprint,
            self.boot_id_digest,
            self.runner_version_digest,
            self.environment_digest,
        ):
            _validate_digest(value)


@dataclass(frozen=True, slots=True)
class EvidenceReceiptV1:
    repository_id: str
    index_digest: str
    function_ids: tuple[str, ...]
    test_id: str
    source_digest_set_digest: str
    test_digest: str
    assertion_digest: str
    dependency_digest_set_digest: str
    executor_fingerprint: str
    boot_id_digest: str
    runner_version_digest: str
    environment_digest: str
    attempt_id: str
    started_at: str
    finished_at: str
    started_monotonic_ns: int
    finished_monotonic_ns: int
    result: str
    reason_code: str
    duration_ms: int
    cooldown_class: str
    expires_monotonic_ns: int

    @classmethod
    def from_mapping(cls, value: object) -> EvidenceReceiptV1:
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise TestEvidenceError("test.evidence_corrupt")
        converted = dict(value)
        function_ids = converted.get("function_ids")
        if not isinstance(function_ids, (list, tuple)):
            raise TestEvidenceError("test.evidence_corrupt")
        converted["function_ids"] = tuple(function_ids)
        try:
            return cls(**converted)
        except TypeError:
            raise TestEvidenceError("test.evidence_corrupt") from None

    def __post_init__(self) -> None:
        EvidenceContextV1(
            self.repository_id,
            self.index_digest,
            self.function_ids,
            self.test_id,
            self.source_digest_set_digest,
            self.test_digest,
            self.assertion_digest,
            self.dependency_digest_set_digest,
            self.executor_fingerprint,
            self.boot_id_digest,
            self.runner_version_digest,
            self.environment_digest,
        )
        for value in (self.attempt_id, self.started_at, self.finished_at, self.reason_code):
            _validate_text(value, maximum=128)
        for value in (
            self.started_monotonic_ns,
            self.finished_monotonic_ns,
            self.duration_ms,
            self.expires_monotonic_ns,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise TestEvidenceError("test.evidence_corrupt")
        if self.finished_monotonic_ns < self.started_monotonic_ns:
            raise TestEvidenceError("test.evidence_corrupt")
        if self.result not in _RESULTS or self.cooldown_class not in _COOLDOWN_MAX_SECONDS:
            raise TestEvidenceError("test.evidence_corrupt")
        maximum_expiry = self.finished_monotonic_ns + _COOLDOWN_MAX_SECONDS[self.cooldown_class] * 1_000_000_000
        if self.expires_monotonic_ns > maximum_expiry:
            raise TestEvidenceError("test.evidence_corrupt")

    @property
    def evidence_id(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()

    def public(self) -> dict[str, object]:
        value = asdict(self)
        value["function_ids"] = list(self.function_ids)
        return value

    def canonical_bytes(self) -> bytes:
        return (
            json.dumps(self.public(), ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class EvidenceReuseDecision:
    action: str
    reason_code: str
    evidence_id: str | None
    remaining_cooldown_seconds: int


def evaluate_evidence_reuse(
    receipt: EvidenceReceiptV1 | None,
    context: EvidenceContextV1,
    *,
    now_monotonic_ns: int,
    mandatory_gate: bool = False,
    higher_risk_context: bool = False,
    revoked: bool = False,
    ambiguous: bool = False,
    superseded: bool = False,
) -> EvidenceReuseDecision:
    """Return reuse only for fresh Passed evidence with every identity equal."""
    if isinstance(now_monotonic_ns, bool) or not isinstance(now_monotonic_ns, int) or now_monotonic_ns < 0:
        raise TestEvidenceError("test.evidence_corrupt")
    if mandatory_gate:
        return EvidenceReuseDecision("run", "test.gate_required", None, 0)
    if receipt is None:
        return EvidenceReuseDecision("run", "test.evidence_unavailable", None, 0)
    if receipt.result != "passed":
        return EvidenceReuseDecision("run", _RESULT_REASONS[receipt.result], None, 0)
    if receipt.cooldown_class not in {"deterministic", "integration"}:
        return EvidenceReuseDecision("run", "test.cooldown_expired", None, 0)
    if receipt.executor_fingerprint != context.executor_fingerprint:
        return EvidenceReuseDecision("run", "test.executor_mismatch", None, 0)
    if receipt.boot_id_digest != context.boot_id_digest:
        return EvidenceReuseDecision("run", "test.boot_mismatch", None, 0)
    identity_fields = (
        "repository_id",
        "index_digest",
        "function_ids",
        "test_id",
        "source_digest_set_digest",
        "test_digest",
        "assertion_digest",
        "dependency_digest_set_digest",
        "runner_version_digest",
        "environment_digest",
    )
    if any(getattr(receipt, field) != getattr(context, field) for field in identity_fields):
        return EvidenceReuseDecision("run", "test.evidence_stale", None, 0)
    if higher_risk_context or revoked or ambiguous or superseded:
        return EvidenceReuseDecision("run", "test.evidence_stale", None, 0)
    if now_monotonic_ns >= receipt.expires_monotonic_ns:
        return EvidenceReuseDecision("run", "test.cooldown_expired", None, 0)
    remaining = (receipt.expires_monotonic_ns - now_monotonic_ns) // 1_000_000_000
    return EvidenceReuseDecision("reuse", "test.evidence_reused", receipt.evidence_id, remaining)


__all__ = [
    "EvidenceContextV1",
    "EvidenceReceiptV1",
    "EvidenceReuseDecision",
    "TestEvidenceError",
    "evaluate_evidence_reuse",
]
