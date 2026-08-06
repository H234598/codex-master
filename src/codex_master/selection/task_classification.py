"""Conservative task classification for model eligibility."""

from __future__ import annotations

from dataclasses import dataclass

from codex_master.hive.types import TaskComplexity


class TaskClassificationError(ValueError):
    """Raised for invalid classification evidence."""


@dataclass(frozen=True, slots=True)
class TaskClassificationRequest:
    objective: str
    scope_kind: str
    changed_files: tuple[str, ...] = ()
    security_sensitive: bool = False
    migration: bool = False
    cross_repository: bool = False
    requires_subagents: bool = False
    ci_or_release: bool = False
    complexity_override: TaskComplexity | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.objective, str) or not 1 <= len(self.objective) <= 8192:
            raise TaskClassificationError("invalid_task_objective")
        if self.scope_kind not in {"read", "write", "unknown"}:
            raise TaskClassificationError("invalid_task_scope")
        if not isinstance(self.changed_files, tuple) or len(self.changed_files) > 256:
            raise TaskClassificationError("invalid_changed_files")
        if any(not isinstance(value, str) or not 1 <= len(value) <= 512 for value in self.changed_files):
            raise TaskClassificationError("invalid_changed_files")
        for value in (self.security_sensitive, self.migration, self.cross_repository, self.requires_subagents, self.ci_or_release):
            if not isinstance(value, bool):
                raise TaskClassificationError("invalid_task_evidence")
        if self.complexity_override is not None and not isinstance(self.complexity_override, TaskComplexity):
            raise TaskClassificationError("invalid_complexity_override")


@dataclass(frozen=True, slots=True)
class TaskProfile:
    complexity: TaskComplexity
    reason_codes: tuple[str, ...]
    expected_usage_micro: int | None
    required_capabilities: tuple[str, ...]
    allow_secondary_model: bool


class TaskClassifier:
    def classify(self, request: TaskClassificationRequest) -> TaskProfile:
        if not isinstance(request, TaskClassificationRequest):
            raise TaskClassificationError("invalid_task_request")
        reasons: list[str] = []
        complex_evidence = (
            (request.security_sensitive, "security_sensitive"),
            (request.migration, "migration"),
            (request.cross_repository, "cross_repository"),
            (request.requires_subagents, "subagents_required"),
            (request.ci_or_release, "ci_or_release"),
        )
        for enabled, reason in complex_evidence:
            if enabled:
                reasons.append(reason)
        if request.scope_kind == "unknown":
            reasons.append("scope_unknown")
        if len(request.changed_files) > 8:
            reasons.append("wide_change")
        if request.complexity_override is TaskComplexity.COMPLEX:
            reasons.append("complexity_override")
        complexity = TaskComplexity.COMPLEX if reasons else TaskComplexity.UNKNOWN
        if complexity is TaskComplexity.UNKNOWN and request.scope_kind == "read" and len(request.changed_files) == 0:
            complexity = TaskComplexity.SIMPLE
            reasons.append("positive_read_only_evidence")
        if request.complexity_override is TaskComplexity.SIMPLE and complexity is not TaskComplexity.SIMPLE:
            reasons.append("simple_override_rejected")
        allow_secondary = complexity is TaskComplexity.SIMPLE
        capabilities = ("simple_task_eligible",) if allow_secondary else ("complex_task_eligible",)
        return TaskProfile(complexity, tuple(reasons), 1000 if allow_secondary else None, capabilities, allow_secondary)


__all__ = ["TaskClassificationError", "TaskClassificationRequest", "TaskClassifier", "TaskProfile"]
