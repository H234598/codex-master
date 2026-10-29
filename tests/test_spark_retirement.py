"""Focused active-route regression coverage for the retired Spark model."""

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from the_hive import server
from the_hive.agent_resolver import build_selection_offer, policies_from_catalogs
from the_hive.fleet_registry import Provider, RunnerKind
from the_hive.hive.config import load_agent_class_catalog
from the_hive.selection.model_policy import ModelDefinition, ModelPolicyRegistry
from the_hive.selection.task_classification import (
    TaskClassificationRequest,
    TaskClassifier,
)


ROOT = Path(__file__).resolve().parents[1]
SPARK = "gpt-5.3-codex-spark"


def test_old_policy_and_usage_availability_cannot_offer_spark() -> None:
    registry = ModelPolicyRegistry(
        (
            ModelDefinition(
                "gpt-6-luna",
                ("luna",),
                "primary",
                "openai",
                ("read", "write", "complex_task_eligible"),
                "luna",
                family="luna",
                rank=20,
            ),
            ModelDefinition(
                SPARK,
                ("spark",),
                "secondary_simple",
                "openai",
                ("write", "simple_task_eligible"),
                "spark",
                family="spark",
                rank=10,
            ),
        )
    )
    classes, models = policies_from_catalogs(
        load_agent_class_catalog(ROOT / "codex-agent-classes.json"), registry
    )
    offer = build_selection_offer(
        classes=(item for item in classes if item.class_id == "arbeitsbiene"),
        models=models,
        available_models={"gpt-6-luna", SPARK},
    )
    assert registry.get_exact(SPARK) is None
    assert registry.resolve_alias("spark") is None
    assert all(item["family"] != "spark" for item in registry.public())
    assert offer.models == ("gpt-6-luna",)


def test_explicit_retired_model_is_denied_before_start_or_resume_effects() -> None:
    profile = TaskClassifier().classify(TaskClassificationRequest("inspect", "read"))
    with pytest.raises(server.AgentError, match="retired_model_unavailable"):
        server.resolve_runtime_agent_selection(
            agent="a1",
            role="arbeitsbiene",
            routing=None,
            task_profile=profile,
            requested_model=SPARK,
        )
    with pytest.raises(server.AgentError, match="retired_model_unavailable"):
        server.agent_base_args(SPARK, "low")
    with pytest.raises(server.AgentError, match="retired_model_unavailable"):
        server.start_agent("a1", model=SPARK)
    with pytest.raises(server.AgentError, match="retired_model_unavailable"):
        server._start_agent_unlocked("a1", model=SPARK)
    with pytest.raises(server.AgentError, match="retired_model_unavailable"):
        server.ensure_assignment_session_model(
            "a1", model=SPARK, reasoning_effort="low", lease={}
        )


def test_native_resume_denies_managed_session_bound_to_retired_spark() -> None:
    registry = {
        "agents": [
            {
                "session_id": "thr_parent",
                "agent_id": "agent_1",
                "activity_state": "completed",
            }
        ],
        "sessions": [{"session_id": "thr_parent", "managed_session": "managed-a1"}],
    }
    inventory = SimpleNamespace(
        agents={"a1": SimpleNamespace(session="managed-a1", model=SPARK)}
    )
    with (
        patch.object(server, "spawn_admission_lock", return_value=nullcontext()),
        patch.object(server, "native_agent_registry_lock", return_value=nullcontext()),
        patch.object(
            server, "_read_native_agent_registry", return_value=(registry, "ready")
        ),
        patch.object(server, "current_agent_inventory", return_value=inventory),
        patch.object(server, "_write_native_agent_registry") as write,
    ):
        result = server.activate_native_agent_resume(
            {
                "hook_event_name": "PreToolUse",
                "session_id": "thr_parent",
                "tool_name": "send_input",
                "tool_input": {"target": "agent_1"},
            },
            now=1_002.0,
        )
    assert result["error_code"] == "retired_model_unavailable"
    write.assert_not_called()


def test_old_descriptor_is_denied_before_invocability_and_at_runtime_gate() -> None:
    descriptor = SimpleNamespace(
        account_id="account",
        runner=RunnerKind.CODEX_CLI,
        provider=Provider.OPENAI_CHATGPT,
        model=SPARK,
        enabled=True,
    )
    admission = server._model_runner_admission("a1", SPARK, descriptor=descriptor)
    assert admission.allowed is False
    assert admission.missing_factor == "model_removed_or_disabled"
    binding = SimpleNamespace(resource=SimpleNamespace(model_id=SPARK))
    with patch.object(
        server, "_server_runtime_descriptor", return_value=(None, descriptor)
    ):
        assert server._server_runtime_model_gate(binding).allowed is False


def test_old_usage_routing_spark_decision_is_rejected() -> None:
    with pytest.raises(
        server.AgentError, match="codex-usage routing decision is invalid"
    ):
        server.validate_codex_usage_routing_decision(
            {
                "schema_version": 1,
                "account": "a",
                "role": "arbeitsbiene",
                "decision": "spark",
                "model": SPARK,
            },
            agent="a1",
            role="arbeitsbiene",
        )


def test_simple_write_remains_gpt6_eligible_without_spark_retry() -> None:
    profile = TaskClassifier().classify(
        TaskClassificationRequest(
            "small fix",
            "write",
            changed_files=("a.py",),
            task_phase="atomic_fix",
            fully_specified=True,
            reversible=True,
            low_risk=True,
            root_cause_known=True,
        )
    )
    assert profile.spark_eligible is False
    assert profile.required_capabilities == ("write", "complex_task_eligible")
    from the_hive.spark_retry import is_capacity_retry_code

    assert is_capacity_retry_code("at_capacity") is False
