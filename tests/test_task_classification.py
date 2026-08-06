from codex_master.hive.types import TaskComplexity
from codex_master.selection.task_classification import TaskClassificationRequest, TaskClassifier


def test_only_positive_read_only_evidence_allows_secondary_model() -> None:
    profile = TaskClassifier().classify(TaskClassificationRequest("read status", "read"))
    assert profile.complexity is TaskComplexity.SIMPLE
    assert profile.allow_secondary_model is True


def test_unknown_security_migration_and_simple_downgrade_remain_conservative() -> None:
    profile = TaskClassifier().classify(TaskClassificationRequest("change auth", "write", security_sensitive=True, complexity_override=TaskComplexity.SIMPLE))
    assert profile.complexity is TaskComplexity.COMPLEX
    assert profile.allow_secondary_model is False
    assert "simple_override_rejected" in profile.reason_codes
