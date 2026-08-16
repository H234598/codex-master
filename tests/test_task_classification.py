import pytest

from codex_master.hive.types import TaskComplexity
from codex_master.selection.task_classification import (
    TaskClassificationError,
    TaskClassificationRequest,
    TaskClassifier,
)


def atomic_fix_request(**overrides: object) -> TaskClassificationRequest:
    values: dict[str, object] = {
        "objective": "Rename one local symbol and run its focused test.",
        "scope_kind": "write",
        "changed_files": ("src/example.py",),
        "task_phase": "atomic_fix",
        "fully_specified": True,
        "reversible": True,
        "low_risk": True,
        "root_cause_known": True,
    }
    values.update(overrides)
    return TaskClassificationRequest(**values)


def test_only_positive_read_only_evidence_is_not_spark_eligible() -> None:
    profile = TaskClassifier().classify(TaskClassificationRequest("read status", "read"))
    assert profile.complexity is TaskComplexity.SIMPLE
    assert profile.spark_eligible is False
    assert profile.required_capabilities == ("read",)
    assert profile.expected_usage_micro is None


def test_hard_boundary_and_simple_downgrade_remain_conservative() -> None:
    profile = TaskClassifier().classify(
        TaskClassificationRequest(
            "change auth",
            "write",
            security_sensitive=True,
            complexity_override=TaskComplexity.SIMPLE,
        )
    )
    assert profile.complexity is TaskComplexity.COMPLEX
    assert profile.spark_eligible is False
    assert profile.required_capabilities == ("write", "complex_task_eligible")
    assert "simple_override_rejected" in profile.reason_codes


def test_confirmed_atomic_low_risk_write_is_simple_and_spark_eligible() -> None:
    profile = TaskClassifier().classify(atomic_fix_request())

    assert profile.complexity is TaskComplexity.SIMPLE
    assert profile.spark_eligible is True
    assert profile.required_capabilities == ("write",)
    assert profile.reason_codes == ("positive_atomic_low_risk_write_evidence",)
    assert profile.expected_usage_micro == 1000


def test_explicit_medium_remains_luna_only() -> None:
    profile = TaskClassifier().classify(
        atomic_fix_request(complexity_override=TaskComplexity.MEDIUM)
    )

    assert profile.complexity is TaskComplexity.MEDIUM
    assert profile.spark_eligible is False
    assert profile.required_capabilities == ("write", "complex_task_eligible")
    assert "medium_complexity_override" in profile.reason_codes


def test_simple_hint_without_positive_evidence_is_not_spark_eligible() -> None:
    profile = TaskClassifier().classify(
        TaskClassificationRequest(
            "Fix it.", "write", changed_files=("src/example.py",), complexity_override=TaskComplexity.SIMPLE
        )
    )

    assert profile.complexity is TaskComplexity.UNKNOWN
    assert profile.spark_eligible is False
    assert "simple_override_rejected" in profile.reason_codes


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("task_phase", "task_phase_unknown"),
        ("fully_specified", "task_not_fully_specified"),
        ("reversible", "not_reversible"),
        ("low_risk", "risk_not_low"),
        ("root_cause_known", "root_cause_unknown"),
    ],
)
def test_missing_positive_write_evidence_stays_unknown(field: str, reason: str) -> None:
    profile = TaskClassifier().classify(atomic_fix_request(**{field: False if field != "task_phase" else "unknown"}))

    assert profile.complexity is TaskComplexity.UNKNOWN
    assert profile.spark_eligible is False
    assert reason in profile.reason_codes


def test_diagnosis_is_never_spark_eligible() -> None:
    profile = TaskClassifier().classify(atomic_fix_request(task_phase="diagnosis"))

    assert profile.complexity is TaskComplexity.UNKNOWN
    assert profile.spark_eligible is False
    assert profile.reason_codes == ("task_phase_diagnosis",)


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("security_sensitive", "security_sensitive"),
        ("concurrency", "concurrency"),
        ("migration", "migration"),
        ("data_change", "data_change"),
        ("cross_repository", "cross_repository"),
        ("architecture", "architecture"),
        ("ci_or_release", "ci_or_release"),
        ("requires_subagents", "subagents_required"),
    ],
)
def test_hard_luna_boundaries_are_complex(field: str, reason: str) -> None:
    profile = TaskClassifier().classify(atomic_fix_request(**{field: True}))

    assert profile.complexity is TaskComplexity.COMPLEX
    assert profile.spark_eligible is False
    assert reason in profile.reason_codes


def test_more_than_eight_write_paths_is_complex() -> None:
    profile = TaskClassifier().classify(
        atomic_fix_request(changed_files=tuple(f"src/{index}.py" for index in range(9)))
    )

    assert profile.complexity is TaskComplexity.COMPLEX
    assert profile.spark_eligible is False
    assert "wide_change" in profile.reason_codes
    assert profile.reason_codes.count("wide_change") == 1


def test_write_without_paths_is_unknown() -> None:
    profile = TaskClassifier().classify(atomic_fix_request(changed_files=()))

    assert profile.complexity is TaskComplexity.UNKNOWN
    assert profile.spark_eligible is False
    assert "write_paths_missing" in profile.reason_codes


def test_read_request_with_changed_files_explains_unknown_classification() -> None:
    profile = TaskClassifier().classify(
        TaskClassificationRequest(
            "Inspect changed file.",
            "read",
            changed_files=("src/example.py",),
            task_phase="atomic_fix",
        )
    )

    assert profile.complexity is TaskComplexity.UNKNOWN
    assert profile.reason_codes == ("read_scope_with_changed_files",)


@pytest.mark.parametrize("field", ["fully_specified", "reversible", "low_risk", "root_cause_known"])
def test_evidence_requires_real_booleans(field: str) -> None:
    with pytest.raises(TaskClassificationError, match="invalid_task_evidence"):
        atomic_fix_request(**{field: 1})
