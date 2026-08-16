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
    concurrency: bool = False
    data_change: bool = False
    architecture: bool = False
    task_phase: str = "unknown"
    fully_specified: bool = False
    reversible: bool = False
    low_risk: bool = False
    root_cause_known: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.objective, str) or not 1 <= len(self.objective) <= 8192:
            raise TaskClassificationError("invalid_task_objective")
        if not isinstance(self.scope_kind, str) or self.scope_kind not in {"read", "write", "unknown"}:
            raise TaskClassificationError("invalid_task_scope")
        if not isinstance(self.changed_files, tuple) or len(self.changed_files) > 256:
            raise TaskClassificationError("invalid_changed_files")
        if any(not isinstance(value, str) or not 1 <= len(value) <= 512 for value in self.changed_files):
            raise TaskClassificationError("invalid_changed_files")
        for value in (
            self.security_sensitive,
            self.migration,
            self.cross_repository,
            self.requires_subagents,
            self.ci_or_release,
            self.concurrency,
            self.data_change,
            self.architecture,
            self.fully_specified,
            self.reversible,
            self.low_risk,
            self.root_cause_known,
        ):
            if not isinstance(value, bool):
                raise TaskClassificationError("invalid_task_evidence")
        if not isinstance(self.task_phase, str) or self.task_phase not in {"atomic_fix", "diagnosis", "unknown"}:
            raise TaskClassificationError("invalid_task_phase")
        if self.complexity_override is not None and not isinstance(self.complexity_override, TaskComplexity):
            raise TaskClassificationError("invalid_complexity_override")


@dataclass(frozen=True, slots=True)
class TaskProfile:
    complexity: TaskComplexity
    reason_codes: tuple[str, ...]
    expected_usage_micro: int | None
    required_capabilities: tuple[str, ...]
    spark_eligible: bool


class TaskClassifier:
    def classify(self, request: TaskClassificationRequest) -> TaskProfile:
        if not isinstance(request, TaskClassificationRequest):
            raise TaskClassificationError("invalid_task_request")
        reasons: list[str] = []
        hard_evidence = (
            (request.security_sensitive, "security_sensitive"),
            (request.concurrency, "concurrency"),
            (request.migration, "migration"),
            (request.data_change, "data_change"),
            (request.cross_repository, "cross_repository"),
            (request.architecture, "architecture"),
            (request.ci_or_release, "ci_or_release"),
            (request.requires_subagents, "subagents_required"),
        )
        hard_reasons = [reason for enabled, reason in hard_evidence if enabled]
        if len(request.changed_files) > 8:
            hard_reasons.append("wide_change")

        complexity: TaskComplexity
        if hard_reasons:
            complexity = TaskComplexity.COMPLEX
            reasons.extend(hard_reasons)
        elif request.complexity_override is TaskComplexity.COMPLEX:
            complexity = TaskComplexity.COMPLEX
            reasons.append("complexity_override")
        elif request.complexity_override is TaskComplexity.MEDIUM:
            complexity = TaskComplexity.MEDIUM
            reasons.append("medium_complexity_override")
        elif request.scope_kind == "read" and not request.changed_files:
            complexity = TaskComplexity.SIMPLE
            reasons.append("positive_read_only_evidence")
        elif request.scope_kind == "write" and self._is_positive_atomic_write(request):
            complexity = TaskComplexity.SIMPLE
            reasons.append("positive_atomic_low_risk_write_evidence")
        else:
            complexity = TaskComplexity.UNKNOWN
            if request.scope_kind == "unknown":
                reasons.append("scope_unknown")
            if request.scope_kind == "read" and request.changed_files:
                reasons.append("read_scope_with_changed_files")
            if request.scope_kind == "write":
                if not request.changed_files:
                    reasons.append("write_paths_missing")
                if request.task_phase == "diagnosis":
                    reasons.append("task_phase_diagnosis")
                elif request.task_phase == "unknown":
                    reasons.append("task_phase_unknown")
                if not request.root_cause_known:
                    reasons.append("root_cause_unknown")
                if not request.fully_specified:
                    reasons.append("task_not_fully_specified")
                if not request.reversible:
                    reasons.append("not_reversible")
                if not request.low_risk:
                    reasons.append("risk_not_low")
            elif request.task_phase == "diagnosis":
                reasons.append("task_phase_diagnosis")
            elif request.task_phase == "unknown":
                reasons.append("task_phase_unknown")

        if request.complexity_override is TaskComplexity.SIMPLE and complexity is not TaskComplexity.SIMPLE:
            reasons.append("simple_override_rejected")

        spark_eligible = complexity is TaskComplexity.SIMPLE and self._is_positive_atomic_write(request)
        if request.scope_kind == "read":
            capabilities = ("read",)
        elif spark_eligible:
            capabilities = ("write",)
        else:
            capabilities = ("write", "complex_task_eligible")
        return TaskProfile(
            complexity,
            tuple(dict.fromkeys(reasons)),
            1000 if spark_eligible else None,
            capabilities,
            spark_eligible,
        )

    @staticmethod
    def _is_positive_atomic_write(request: TaskClassificationRequest) -> bool:
        return (
            request.scope_kind == "write"
            and 1 <= len(request.changed_files) <= 8
            and request.task_phase == "atomic_fix"
            and request.fully_specified
            and request.reversible
            and request.low_risk
            and request.root_cause_known
            and request.complexity_override not in {TaskComplexity.MEDIUM, TaskComplexity.COMPLEX}
            and not any(
                (
                    request.security_sensitive,
                    request.concurrency,
                    request.migration,
                    request.data_change,
                    request.cross_repository,
                    request.architecture,
                    request.ci_or_release,
                    request.requires_subagents,
                )
            )
        )


__all__ = ["TaskClassificationError", "TaskClassificationRequest", "TaskClassifier", "TaskProfile"]
