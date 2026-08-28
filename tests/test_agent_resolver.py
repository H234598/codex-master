from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from codex_master.hive.types import TaskComplexity
from codex_master.agent_resolver import (
    AgentClassPolicy,
    ModelPolicy,
    ResolutionRequest,
    build_selection_offer,
    policies_from_catalogs,
    resolve_agent_selection,
    validate_canonical_agent_tuple,
)
from codex_master.hive.config import load_agent_class_catalog
from codex_master.selection.model_policy import load_model_policy
from codex_master.server import (
    AgentError,
    _main_cli_impl,
    agent_base_args,
    agent_selection_options,
    public_resolution_decision,
    resolver_class_for_agent,
    resolve_runtime_agent_selection,
    validate_codex_usage_routing_decision,
)
from codex_master.selection.task_classification import TaskClassificationRequest, TaskClassifier
import pytest


MODELS = (
    ModelPolicy(
        "gpt-5.3-codex-spark", "spark", 10, ("low", "medium", "high"),
        ("write", "simple_task_eligible"),
    ),
    ModelPolicy(
        "gpt-5.6-luna", "luna", 20, ("low", "medium", "high", "xhigh"),
        ("read", "write", "complex_task_eligible"),
    ),
    ModelPolicy(
        "gpt-5.6-terra", "terra", 30, ("high", "xhigh"),
        ("read", "write", "complex_task_eligible"),
    ),
    ModelPolicy(
        "gpt-5.6-sol", "sol", 40, ("xhigh", "max"),
        ("read", "write", "complex_task_eligible"),
    ),
)

CLASSES = (
    AgentClassPolicy(
        "arbeitsbiene",
        default_lifecycle="ephemeral",
        allowed_lifecycles=("ephemeral", "binding", "persistent"),
        allowed_families=("spark", "luna", "terra", "sol"),
        min_reasoning="low",
        max_reasoning="xhigh",
        supported_scopes=("read", "write"),
    ),
    AgentClassPolicy(
        "goettin", "persistent", ("persistent",), ("sol",), "max", "max", ("read", "write")
    ),
    AgentClassPolicy(
        "gottbiene", "persistent", ("persistent",), ("sol",), "max", "max", ("read", "write")
    ),
    AgentClassPolicy(
        "koenigin", "persistent", ("persistent",), ("sol",), "xhigh", "xhigh", ("read", "write")
    ),
    AgentClassPolicy(
        "teamleiterin", "persistent", ("persistent",), ("terra",), "xhigh", "xhigh", ("read", "write"),
        ("gpt-5.6-terra",),
    ),
)

WORKER_CLASSES = (
    AgentClassPolicy(
        "spezialistin",
        default_lifecycle="binding",
        allowed_lifecycles=("binding",),
        allowed_families=("spark", "luna", "terra", "sol"),
        min_reasoning="high",
        max_reasoning="xhigh",
        supported_scopes=("read", "write"),
    ),
    AgentClassPolicy(
        "arbeitsbiene",
        default_lifecycle="ephemeral",
        allowed_lifecycles=("ephemeral", "binding", "persistent"),
        allowed_families=("spark", "luna", "terra", "sol"),
        min_reasoning="low",
        max_reasoning="xhigh",
        supported_scopes=("read",),
    ),
)


def resolve(**overrides):
    values = {
        "scope_kind": "read",
        "complexity": "simple",
        "requested_class": "arbeitsbiene",
    }
    values.update(overrides)
    if values["scope_kind"] == "write" and values["complexity"] == "simple":
        values.setdefault("required_capabilities", ("write",))
        values.setdefault("spark_eligible", True)
    return resolve_agent_selection(
        ResolutionRequest(**values),
        classes=CLASSES,
        models=MODELS,
        available_models={model.model_id for model in MODELS},
    )


def runtime_profile(*, complexity_override: TaskComplexity | None = None, scope_kind: str = "write"):
    return TaskClassifier().classify(
        TaskClassificationRequest(
            "Rename one local symbol and run its focused test.",
            scope_kind,
            changed_files=("src/example.py",) if scope_kind == "write" else (),
            task_phase="atomic_fix" if scope_kind == "write" else "unknown",
            fully_specified=scope_kind == "write",
            reversible=scope_kind == "write",
            low_risk=scope_kind == "write",
            root_cause_known=scope_kind == "write",
            complexity_override=complexity_override,
        )
    )


def test_invocation_is_accepted_but_ephemeral_is_returned() -> None:
    decision = resolve(requested_lifecycle="invocation")

    assert decision.lifecycle == "ephemeral"
    assert "lifecycle_alias_normalized" in decision.reason_codes


def test_simple_write_without_model_defaults_to_spark_low() -> None:
    decision = resolve(scope_kind="write", complexity="simple")

    assert (decision.model, decision.reasoning) == ("gpt-5.3-codex-spark", "low")


def test_explicit_spark_for_medium_write_falls_back_to_luna_with_capability_reason() -> None:
    decision = resolve(
        scope_kind="write",
        complexity="medium",
        requested_model="gpt-5.3-codex-spark",
        required_capabilities=("write", "complex_task_eligible"),
        spark_eligible=False,
    )

    assert (decision.model, decision.reasoning, decision.fallback) == (
        "gpt-5.6-luna", "medium", True
    )
    assert decision.requested_model == "gpt-5.3-codex-spark"
    assert "requested_model_capability_mismatch" in decision.reason_codes


def test_explicit_luna_for_simple_write_remains_a_compatible_upgrade() -> None:
    decision = resolve(
        scope_kind="write",
        complexity="simple",
        requested_model="gpt-5.6-luna",
        required_capabilities=("write",),
        spark_eligible=True,
    )

    assert (decision.model, decision.fallback) == ("gpt-5.6-luna", False)


def test_spark_without_simple_task_capability_defaults_to_luna() -> None:
    models = (
        ModelPolicy("gpt-5.3-codex-spark", "spark", 10, ("low",), ("write",)),
        MODELS[1],
    )
    decision = resolve_agent_selection(
        ResolutionRequest(
            "write",
            "simple",
            requested_class="arbeitsbiene",
            required_capabilities=("write",),
            spark_eligible=True,
        ),
        classes=CLASSES,
        models=models,
        available_models={item.model_id for item in models},
    )

    assert decision.model == "gpt-5.6-luna"
    assert decision.fallback is True
    assert "spark_model_capability_mismatch" in decision.reason_codes
    assert "default_model_unavailable" in decision.reason_codes


def test_unknown_explicit_model_for_simple_write_falls_back_to_luna() -> None:
    decision = resolve(
        scope_kind="write",
        complexity="simple",
        requested_lifecycle="ephemeral",
        requested_model="gpt-5.4-mini",
        requested_reasoning="low",
    )

    assert (decision.model, decision.reasoning) == ("gpt-5.6-luna", "low")
    assert decision.requested_model == "gpt-5.4-mini"
    assert decision.fallback is True
    assert decision.reason_codes == ("requested_model_unknown",)


def test_unavailable_explicit_model_for_simple_write_falls_back_to_luna() -> None:
    decision = resolve_agent_selection(
        ResolutionRequest(
            scope_kind="write",
            complexity="simple",
            requested_class="arbeitsbiene",
            requested_lifecycle="ephemeral",
            requested_model="gpt-5.6-terra",
            requested_reasoning="high",
        ),
        classes=CLASSES,
        models=MODELS,
        available_models={"gpt-5.3-codex-spark", "gpt-5.6-luna"},
    )

    assert (decision.model, decision.reasoning) == ("gpt-5.6-luna", "high")
    assert decision.requested_model == "gpt-5.6-terra"
    assert decision.fallback is True
    assert decision.reason_codes == ("requested_model_unavailable",)


def test_non_simple_write_without_model_uses_luna() -> None:
    for complexity in ("medium", "complex", "unknown"):
        decision = resolve(scope_kind="write", complexity=complexity)
        assert (decision.model, decision.reasoning) == ("gpt-5.6-luna", "medium")


def test_read_only_ephemeral_defaults_to_luna_medium() -> None:
    decision = resolve(scope_kind="read", requested_lifecycle="ephemeral")

    assert (decision.model, decision.reasoning) == ("gpt-5.6-luna", "medium")


def test_binding_defaults_to_luna_high() -> None:
    decision = resolve(requested_lifecycle="binding")

    assert (decision.model, decision.reasoning) == ("gpt-5.6-luna", "high")


def test_persistent_worker_defaults_to_luna_xhigh() -> None:
    decision = resolve(requested_lifecycle="persistent")

    assert (decision.model, decision.reasoning) == ("gpt-5.6-luna", "xhigh")


@pytest.mark.parametrize("requested_reasoning", ["low", "medium", "high"])
def test_persistent_worker_enforces_xhigh_minimum(requested_reasoning: str) -> None:
    decision = resolve(
        requested_lifecycle="persistent",
        requested_reasoning=requested_reasoning,
    )

    assert (decision.model, decision.reasoning) == ("gpt-5.6-luna", "xhigh")


def test_sol_root_fixture_defaults_to_exact_profiles_green_at_baseline() -> None:
    expected = {
        "goettin": "max",
        "gottbiene": "max",
        "koenigin": "xhigh",
    }
    for class_id, reasoning in expected.items():
        decision = resolve(requested_class=class_id)
        assert (decision.lifecycle, decision.model, decision.reasoning) == (
            "persistent",
            "gpt-5.6-sol",
            reasoning,
        )
        assert decision.fallback is False


def test_goettin_fixture_defaults_to_sol_family_max_green_at_baseline() -> None:
    decision = resolve(requested_class="goettin")

    assert (decision.class_id, decision.lifecycle, decision.model, decision.reasoning) == (
        "goettin", "persistent", "gpt-5.6-sol", "max"
    )
    assert decision.fallback is False


@pytest.mark.parametrize(
    ("class_id", "reasoning"),
    (("goettin", "max"), ("gottbiene", "max"), ("koenigin", "xhigh")),
)
def test_sol_root_fixture_accepts_second_sol_family_member_green_at_baseline(
    class_id: str, reasoning: str,
) -> None:
    alternate_sol = ModelPolicy(
        "gpt-5.6-sol-alt", "sol", 41, ("xhigh", "max"),
        ("read", "write", "complex_task_eligible"),
    )
    decision = resolve_agent_selection(
        ResolutionRequest(
            "read", "simple", requested_class=class_id,
            requested_model=alternate_sol.model_id, requested_reasoning=reasoning,
        ),
        classes=CLASSES,
        models=MODELS + (alternate_sol,),
        available_models={item.model_id for item in MODELS} | {alternate_sol.model_id},
    )

    assert (decision.class_id, decision.lifecycle, decision.model, decision.reasoning) == (
        class_id, "persistent", "gpt-5.6-sol-alt", reasoning,
    )
    assert decision.fallback is False


@pytest.mark.parametrize(
    ("class_id", "lifecycle", "model", "reasoning"),
    (
        ("goettin", "ephemeral", None, None),
        ("goettin", None, "gpt-5.6-luna", None),
        ("goettin", None, None, "xhigh"),
        ("gottbiene", "ephemeral", None, None),
        ("gottbiene", None, "gpt-5.6-luna", None),
        ("gottbiene", None, None, "xhigh"),
        ("koenigin", "ephemeral", None, None),
        ("koenigin", None, "gpt-5.6-luna", None),
        ("koenigin", None, None, "max"),
    ),
)
def test_sol_root_fixture_rejects_noncanonical_explicit_profile_red_then_green(
    class_id: str,
    lifecycle: str | None,
    model: str | None,
    reasoning: str | None,
) -> None:
    with pytest.raises(ValueError, match=r"^leadership_explicit_tuple_required$"):
        resolve(
            requested_class=class_id,
            requested_lifecycle=lifecycle,
            requested_model=model,
            requested_reasoning=reasoning,
        )


def test_teamleiterin_defaults_to_the_exact_terra_xhigh_tuple() -> None:
    decision = resolve(requested_class="teamleiterin")
    assert (decision.class_id, decision.lifecycle, decision.model, decision.reasoning) == (
        "teamleiterin", "persistent", "gpt-5.6-terra", "xhigh",
    )


@pytest.mark.parametrize("model", ["gpt-5.3-codex-spark", "gpt-5.6-luna", "gpt-5.6-sol"])
def test_teamleiterin_rejects_other_model_families_from_explicit_tuple(model: str) -> None:
    with pytest.raises(ValueError, match=r"^leadership_explicit_tuple_required$"):
        resolve(requested_class="teamleiterin", requested_model=model, requested_reasoning="xhigh")


@pytest.mark.parametrize("reasoning", ["low", "medium", "high", "max"])
def test_teamleiterin_rejects_every_non_xhigh_explicit_effort(reasoning: str) -> None:
    with pytest.raises(ValueError, match=r"^leadership_explicit_tuple_required$"):
        resolve(requested_class="teamleiterin", requested_model="gpt-5.6-terra", requested_reasoning=reasoning)


@pytest.mark.parametrize("lifecycle", ["ephemeral", "binding", "invocation"])
def test_teamleiterin_rejects_every_non_persistent_explicit_lifecycle(lifecycle: str) -> None:
    with pytest.raises(ValueError, match=r"^leadership_explicit_tuple_required$"):
        resolve(requested_class="teamleiterin", requested_lifecycle=lifecycle)


def test_teamleiterin_refuses_missing_required_terra_without_fallback() -> None:
    with pytest.raises(ValueError, match="required_model_unavailable:gpt-5.6-terra"):
        resolve_agent_selection(
            ResolutionRequest("write", "simple", requested_class="teamleiterin"),
            classes=CLASSES,
            models=MODELS,
            available_models={"gpt-5.6-luna", "gpt-5.6-sol"},
        )


def test_teamleiterin_never_selects_a_second_terra_family_model() -> None:
    second_terra = ModelPolicy("gpt-5.6-terra-next", "terra", 31, ("high", "xhigh"))
    decision = resolve_agent_selection(
        ResolutionRequest("write", "simple", requested_class="teamleiterin"),
        classes=CLASSES,
        models=MODELS + (second_terra,),
        available_models={item.model_id for item in MODELS} | {second_terra.model_id},
    )
    assert (decision.model, decision.reasoning) == ("gpt-5.6-terra", "xhigh")


def test_teamleiterin_refuses_required_terra_without_xhigh() -> None:
    terra_without_xhigh = ModelPolicy("gpt-5.6-terra", "terra", 30, ("high",))
    with pytest.raises(ValueError, match="required_model_effort_unavailable:gpt-5.6-terra:xhigh"):
        resolve_agent_selection(
            ResolutionRequest("write", "simple", requested_class="teamleiterin"),
            classes=CLASSES,
            models=tuple(item for item in MODELS if item.model_id != "gpt-5.6-terra") + (terra_without_xhigh,),
            available_models={item.model_id for item in MODELS},
        )


def test_root_catalog_goettin_defaults_to_persistent_sol_max_red_then_green() -> None:
    root = Path(__file__).resolve().parents[1]
    classes, models = policies_from_catalogs(
        load_agent_class_catalog(root / "codex-agent-classes.json"),
        load_model_policy(root / "codex-model-policy.json"),
    )
    decision = resolve_agent_selection(
        ResolutionRequest("read", "simple", requested_class="goettin"),
        classes=classes,
        models=models,
        available_models={item.model_id for item in models},
    )

    assert (decision.class_id, decision.lifecycle, decision.model, decision.reasoning) == (
        "goettin", "persistent", "gpt-5.6-sol", "max"
    )
    assert decision.fallback is False


def test_root_catalog_goettin_accepts_explicit_second_sol_with_max_red_then_green() -> None:
    root = Path(__file__).resolve().parents[1]
    classes, models = policies_from_catalogs(
        load_agent_class_catalog(root / "codex-agent-classes.json"),
        load_model_policy(root / "codex-model-policy.json"),
    )
    alternate_sol = ModelPolicy(
        "gpt-5.6-sol-alt", "sol", 41, ("xhigh", "max"),
        ("read", "write", "complex_task_eligible"),
    )
    decision = resolve_agent_selection(
        ResolutionRequest(
            "read", "simple", requested_class="goettin",
            requested_model="gpt-5.6-sol-alt", requested_reasoning="max",
        ),
        classes=classes,
        models=tuple(models) + (alternate_sol,),
        available_models={item.model_id for item in models} | {alternate_sol.model_id},
    )

    assert (decision.lifecycle, decision.model, decision.reasoning) == (
        "persistent", "gpt-5.6-sol-alt", "max"
    )
    assert decision.fallback is False


def test_goettin_is_never_auto_selected_from_a_goddess_only_pool() -> None:
    goddess_only = tuple(item for item in CLASSES if item.class_id == "goettin")

    with pytest.raises(ValueError, match=r"^no_compatible_class$"):
        resolve_agent_selection(
            ResolutionRequest("read", "simple"),
            classes=goddess_only,
            models=MODELS,
            available_models={model.model_id for model in MODELS},
        )


@pytest.mark.parametrize(
    ("class_id", "model_id", "reasoning"),
    (
        ("goettin", "gpt-5.6-sol", "max"),
        ("goettin", "gpt-5.6-sol-alt", "max"),
        ("gottbiene", "gpt-5.6-sol", "max"),
        ("gottbiene", "gpt-5.6-sol-alt", "max"),
        ("koenigin", "gpt-5.6-sol", "xhigh"),
        ("koenigin", "gpt-5.6-sol-alt", "xhigh"),
        ("teamleiterin", "gpt-5.6-terra", "xhigh"),
    ),
)
def test_validate_canonical_agent_tuple_accepts_governance_matrix_red_then_green(
    class_id: str, model_id: str, reasoning: str,
) -> None:
    alternate_sol = ModelPolicy(
        "gpt-5.6-sol-alt", "sol", 41, ("xhigh", "max"),
        ("read", "write", "complex_task_eligible"),
    )
    classes = {item.class_id: item for item in CLASSES + WORKER_CLASSES}
    models = {item.model_id: item for item in MODELS + (alternate_sol,)}

    validate_canonical_agent_tuple(classes[class_id], models[model_id], "persistent", reasoning)


@pytest.mark.parametrize(
    ("class_id", "model_id", "lifecycle", "reasoning"),
    (
        ("goettin", "gpt-5.6-sol", "persistent", "xhigh"),
        ("goettin", "gpt-5.6-luna", "persistent", "max"),
        ("gottbiene", "gpt-5.6-sol", "persistent", "xhigh"),
        ("gottbiene", "gpt-5.6-luna", "persistent", "max"),
        ("koenigin", "gpt-5.6-sol", "persistent", "max"),
        ("koenigin", "gpt-5.6-luna", "persistent", "xhigh"),
        ("teamleiterin", "gpt-5.6-sol", "persistent", "xhigh"),
        ("arbeitsbiene", "gpt-5.6-sol", "ephemeral", "max"),
        ("spezialistin", "gpt-5.6-sol", "binding", "max"),
    ),
)
def test_validate_canonical_agent_tuple_rejects_noncanonical_governance_matrix_red_then_green(
    class_id: str, model_id: str, lifecycle: str, reasoning: str,
) -> None:
    classes = {item.class_id: item for item in CLASSES + WORKER_CLASSES}
    models = {item.model_id: item for item in MODELS}

    with pytest.raises(ValueError, match=r"^invalid_canonical_agent_tuple$"):
        validate_canonical_agent_tuple(classes[class_id], models[model_id], lifecycle, reasoning)


def test_ultra_is_never_selected() -> None:
    with pytest.raises(ValueError, match=r"^invalid_requested_reasoning$"):
        resolve(requested_reasoning="ultra")


def test_valid_explicit_upgrade_is_preserved() -> None:
    decision = resolve(requested_model="gpt-5.6-terra", requested_reasoning="high")

    assert (decision.model, decision.reasoning) == ("gpt-5.6-terra", "high")
    assert decision.fallback is False


def test_unavailable_explicit_model_falls_back_with_reason() -> None:
    decision = resolve_agent_selection(
        ResolutionRequest(
            scope_kind="read",
            complexity="simple",
            requested_class="arbeitsbiene",
            requested_model="gpt-5.6-terra",
            requested_reasoning="high",
        ),
        classes=CLASSES,
        models=MODELS,
        available_models={"gpt-5.6-luna"},
    )

    assert (decision.model, decision.reasoning) == ("gpt-5.6-luna", "high")
    assert decision.fallback is True
    assert "requested_model_unavailable" in decision.reason_codes
    assert public_resolution_decision(decision) == {
        "schema_version": 1,
        "class": "arbeitsbiene",
        "lifecycle": "ephemeral",
        "model": "gpt-5.6-luna",
        "reasoning": "high",
        "requested": {
            "class": "arbeitsbiene",
            "lifecycle": None,
            "model": "gpt-5.6-terra",
            "reasoning": "high",
        },
        "fallback": True,
        "reason_codes": ["lifecycle_defaulted", "requested_model_unavailable"],
        "raw_output": "not_returned",
    }


def test_missing_class_selects_compatible_worker() -> None:
    decision = resolve(requested_class=None, scope_kind="write")

    assert decision.class_id == "arbeitsbiene"
    assert "class_auto_selected" in decision.reason_codes


@pytest.mark.parametrize("classes", [CLASSES, tuple(reversed(CLASSES))])
def test_missing_class_never_auto_selects_a_leadership_class(
    classes: tuple[AgentClassPolicy, ...],
) -> None:
    decision = resolve_agent_selection(
        ResolutionRequest("read", "simple"),
        classes=classes,
        models=MODELS,
        available_models={model.model_id for model in MODELS},
    )

    assert decision.class_id == "arbeitsbiene"


def test_missing_class_selects_specialist_when_worker_cannot_write() -> None:
    selections = {
        resolve_agent_selection(
            ResolutionRequest("write", "simple"),
            classes=classes,
            models=MODELS,
            available_models={model.model_id for model in MODELS},
        ).class_id
        for classes in (WORKER_CLASSES, tuple(reversed(WORKER_CLASSES)))
    }

    assert selections == {"spezialistin"}


@pytest.mark.parametrize(
    ("complexity", "expected_class"),
    [("simple", "arbeitsbiene"), ("medium", "spezialistin"), ("complex", "spezialistin")],
)
def test_missing_class_matches_worker_authority_to_task_complexity(
    complexity: str,
    expected_class: str,
) -> None:
    read_capable_workers = tuple(
        AgentClassPolicy(
            item.class_id,
            item.default_lifecycle,
            item.allowed_lifecycles,
            item.allowed_families,
            item.min_reasoning,
            item.max_reasoning,
            ("read",),
        )
        for item in WORKER_CLASSES
    )

    selections = {
        resolve_agent_selection(
            ResolutionRequest("read", complexity),
            classes=classes,
            models=MODELS,
            available_models={model.model_id for model in MODELS},
        ).class_id
        for classes in (read_capable_workers, tuple(reversed(read_capable_workers)))
    }

    assert selections == {expected_class}


def test_explicit_compatible_class_keeps_precedence_over_auto_selection() -> None:
    decision = resolve_agent_selection(
        ResolutionRequest("read", "simple", requested_class="spezialistin"),
        classes=tuple(reversed(WORKER_CLASSES)),
        models=MODELS,
        available_models={model.model_id for model in MODELS},
    )

    assert decision.class_id == "spezialistin"
    assert "class_auto_selected" not in decision.reason_codes


def test_missing_class_fails_when_only_leadership_classes_are_compatible() -> None:
    leadership_classes = tuple(item for item in CLASSES if item.class_id != "arbeitsbiene")

    with pytest.raises(ValueError, match="no_compatible_class"):
        resolve_agent_selection(
            ResolutionRequest("read", "simple"),
            classes=leadership_classes,
            models=MODELS,
            available_models={model.model_id for model in MODELS},
        )


def test_offer_contains_only_valid_combinations_and_public_lifecycle_names() -> None:
    alternate_sol = ModelPolicy(
        "gpt-5.6-sol-alt", "sol", 41, ("xhigh", "max"),
        ("read", "write", "complex_task_eligible"),
    )
    offer = build_selection_offer(
        classes=CLASSES,
        models=MODELS + (alternate_sol,),
        available_models={model.model_id for model in MODELS} | {alternate_sol.model_id},
    )

    assert set(offer.lifecycles) == {"ephemeral", "binding", "persistent"}
    assert "invocation" not in offer.lifecycles
    assert offer.classes == ("arbeitsbiene", "goettin", "gottbiene", "koenigin", "teamleiterin")
    for class_id, reasoning in (("goettin", "max"), ("gottbiene", "max"), ("koenigin", "xhigh")):
        options = [item for item in offer.options if item.class_id == class_id]
        assert [(item.lifecycle, item.model, item.reasoning) for item in options] == [
            ("persistent", "gpt-5.6-sol", reasoning),
            ("persistent", "gpt-5.6-sol-alt", reasoning),
        ]
        assert all(item.model.startswith("gpt-5.6-sol") for item in options)
    assert all(item.reasoning != "ultra" for item in offer.options)
    assert not any(
        item.class_id == "arbeitsbiene" and item.lifecycle == "persistent" and item.model == "gpt-5.3-codex-spark"
        for item in offer.options
    )


def test_persistent_offer_options_round_trip_through_resolver_invariants() -> None:
    offer = build_selection_offer(classes=CLASSES, models=MODELS, available_models={model.model_id for model in MODELS})
    persistent_options = [item for item in offer.options if item.lifecycle == "persistent"]

    assert persistent_options
    assert all(item.reasoning in {"xhigh", "max"} for item in persistent_options)
    for option in persistent_options:
        decision = resolve_agent_selection(
            ResolutionRequest(
                "read",
                "simple",
                requested_class=option.class_id,
                requested_lifecycle=option.lifecycle,
                requested_model=option.model,
                requested_reasoning=option.reasoning,
            ),
            classes=CLASSES,
            models=MODELS,
            available_models={model.model_id for model in MODELS},
        )
        assert (decision.class_id, decision.lifecycle, decision.model, decision.reasoning) == (
            option.class_id,
            option.lifecycle,
            option.model,
            option.reasoning,
        )


def test_offer_and_resolver_reject_persistent_class_without_xhigh_capacity() -> None:
    incompatible_class = AgentClassPolicy(
        "legacy-worker",
        default_lifecycle="persistent",
        allowed_lifecycles=("persistent",),
        allowed_families=("luna",),
        min_reasoning="high",
        max_reasoning="high",
        supported_scopes=("read",),
    )
    offer = build_selection_offer(
        classes=(incompatible_class,),
        models=MODELS,
        available_models={model.model_id for model in MODELS},
    )

    assert offer.options == ()
    with pytest.raises(ValueError, match="no_compatible_reasoning_level"):
        resolve_agent_selection(
            ResolutionRequest("read", "simple", requested_class="legacy-worker"),
            classes=(incompatible_class,),
            models=MODELS,
            available_models={model.model_id for model in MODELS},
        )


def test_offer_generation_changes_with_availability() -> None:
    complete = build_selection_offer(classes=CLASSES, models=MODELS, available_models={model.model_id for model in MODELS})
    without_spark = build_selection_offer(
        classes=CLASSES,
        models=MODELS,
        available_models={model.model_id for model in MODELS if model.family != "spark"},
    )

    assert complete.generation != without_spark.generation
    assert "gpt-5.3-codex-spark" in complete.models
    assert "gpt-5.3-codex-spark" not in without_spark.models


def test_checked_in_catalogs_drive_resolver_without_hardcoded_model_ids() -> None:
    root = Path(__file__).resolve().parents[1]
    classes, models = policies_from_catalogs(
        load_agent_class_catalog(root / "codex-agent-classes.json"),
        load_model_policy(root / "codex-model-policy.json"),
    )
    decision = resolve_agent_selection(
        ResolutionRequest("read", "simple", requested_class="spezialistin"),
        classes=classes,
        models=models,
        available_models={item.model_id for item in models},
    )

    assert (decision.lifecycle, decision.model, decision.reasoning) == ("binding", "gpt-5.6-luna", "high")


def test_agent_base_args_accepts_catalog_models_and_enforces_max_exception() -> None:
    terra = agent_base_args("gpt-5.6-terra", "high")
    assert terra[:2] == ["--model", "gpt-5.6-terra"]
    assert 'model_reasoning_effort="high"' in terra
    for class_id, reasoning in (("goettin", "max"), ("gottbiene", "max"), ("koenigin", "xhigh")):
        assert agent_base_args("gpt-5.6-sol", reasoning, agent_class=class_id)[:2] == ["--model", "gpt-5.6-sol"]
    with pytest.raises(AgentError, match=r"^unsupported routed agent tuple$"):
        agent_base_args("gpt-5.6-sol", "max")


@pytest.mark.parametrize(
    ("model", "reasoning", "agent_class"),
    (
        ("gpt-5.6-sol", "xhigh", "goettin"),
        ("gpt-5.6-sol", "xhigh", "gottbiene"),
        ("gpt-5.6-sol", "max", "koenigin"),
        ("gpt-5.6-luna", "max", "goettin"),
        ("gpt-5.6-terra", "max", "gottbiene"),
        ("gpt-5.3-codex-spark", "xhigh", "koenigin"),
        ("gpt-5.6-terra", "high", "teamleiterin"),
        ("gpt-5.6-sol", "max", "arbeitsbiene"),
        ("gpt-5.6-sol", "ultra", "gottbiene"),
    ),
)
def test_agent_base_args_rejects_noncanonical_root_and_worker_tuples(
    model: str, reasoning: str, agent_class: str,
) -> None:
    with pytest.raises(AgentError, match=r"^unsupported routed agent tuple$"):
        agent_base_args(model, reasoning, agent_class=agent_class)


@pytest.mark.parametrize(
    ("class_id", "reasoning"),
    (("goettin", "max"), ("gottbiene", "max"), ("koenigin", "xhigh")),
)
def test_agent_base_args_accepts_second_sol_family_member_red_then_green(
    monkeypatch: pytest.MonkeyPatch, class_id: str, reasoning: str,
) -> None:
    root = Path(__file__).resolve().parents[1]
    base_registry = load_model_policy(root / "codex-model-policy.json")
    alternate_definition = SimpleNamespace(
        model_id="gpt-5.6-sol-alt", enabled=True, spawn_behavior="manual",
        family="sol", reasoning_levels=("xhigh", "max"),
    )
    alternate_public = {
        "model_id": "gpt-5.6-sol-alt", "family": "sol", "rank": 41,
        "reasoning_levels": ["xhigh", "max"],
        "capabilities": ["read", "write", "complex_task_eligible"],
        "enabled": True, "spawn_behavior": "manual",
    }
    registry = SimpleNamespace(
        get_exact=lambda model_id: (
            alternate_definition if model_id == alternate_definition.model_id
            else base_registry.get_exact(model_id)
        ),
        public=lambda: base_registry.public() + (alternate_public,),
    )
    monkeypatch.setattr("codex_master.server.load_model_policy", lambda _path: registry)

    assert agent_base_args(alternate_definition.model_id, reasoning, agent_class=class_id)[:2] == [
        "--model", alternate_definition.model_id,
    ]


def test_assign_write_cli_rejects_ultra_before_dispatch(capsys: pytest.CaptureFixture[str]) -> None:
    argv = [
        "assign-write", "a1", "--task", "P0 parser-only negative",
        "--reasoning-effort", "ultra",
    ]
    with patch("codex_master.server.call_validated_tool") as call_validated_tool:
        with pytest.raises(SystemExit) as raised:
            _main_cli_impl(argv)
    assert raised.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
    call_validated_tool.assert_not_called()


def test_legacy_codex_usage_main_model_is_normalized_to_luna_with_reason() -> None:
    decision = validate_codex_usage_routing_decision(
        {
            "schema_version": 1,
            "account": "Birthe_Privat",
            "backend_account_id": "backend-birthe",
            "role": "arbeitsbiene",
            "decision": "main",
            "model": "gpt-5.4-mini",
            "reason": "spark_unavailable_or_exhausted",
            "usage_state": "known",
            "paid_overage_allowed": False,
            "policy_source": "global",
        },
        agent="q1",
        role="arbeitsbiene",
    )

    assert decision["model"] == "gpt-5.6-luna"
    assert decision["model_fallback"] == {
        "requested": "gpt-5.4-mini",
        "selected": "gpt-5.6-luna",
        "reason": "legacy_main_model_replaced",
    }


def test_runtime_resolver_uses_task_complexity_after_codex_usage_account_gate() -> None:
    simple = resolve_runtime_agent_selection(
        role="arbeitsbiene",
        routing={"decision": "spark", "model": "gpt-5.3-codex-spark"},
        task_profile=runtime_profile(),
    )
    complex_job = resolve_runtime_agent_selection(
        role="arbeitsbiene",
        routing={"decision": "spark", "model": "gpt-5.3-codex-spark"},
        task_profile=runtime_profile(complexity_override=TaskComplexity.COMPLEX),
    )
    no_spark = resolve_runtime_agent_selection(
        role="arbeitsbiene",
        routing={"decision": "main", "model": "gpt-5.6-luna"},
        task_profile=runtime_profile(),
    )

    assert (simple.class_id, simple.model, simple.reasoning) == (
        "arbeitsbiene",
        "gpt-5.3-codex-spark",
        "low",
    )
    assert (complex_job.class_id, complex_job.model, complex_job.reasoning) == (
        "spezialistin",
        "gpt-5.6-luna",
        "high",
    )
    assert (no_spark.class_id, no_spark.model, no_spark.reasoning) == (
        "arbeitsbiene",
        "gpt-5.6-luna",
        "medium",
    )
    assert "default_model_unavailable" in no_spark.reason_codes
    assert no_spark.fallback is True


def test_selection_options_keeps_q_target_bound_to_requester_authority() -> None:
    inventory = SimpleNamespace(
        agents={"q1": SimpleNamespace(series_prefix="q", skill_profile="teamleiterin")},
        agent_ids=("q1",),
    )
    with patch("codex_master.server.canonical_agent_id", return_value="q1"), patch(
        "codex_master.server.current_agent_inventory", return_value=inventory
    ), patch(
        "codex_master.server.ensure_agent_not_blocked_by_codex_usage",
        return_value={"blocked": False},
    ):
        offer = agent_selection_options("q1", requester_class="teamleiterin")
        unchanged = agent_selection_options(
            "q1",
            requester_class="teamleiterin",
            known_generation=offer["generation"],
        )

    assert "teamleiterin" not in offer["classes"]
    assert offer["options"]
    assert all(option["class"] != "teamleiterin" for option in offer["options"])
    assert offer["options_changed"] is True
    assert unchanged["options_changed"] is False


def test_selection_options_hides_teamlead_for_worker_authority() -> None:
    inventory = SimpleNamespace(
        agents={"q1": SimpleNamespace(series_prefix="q", skill_profile="teamleiterin")},
        agent_ids=("q1",),
    )
    with patch("codex_master.server.canonical_agent_id", return_value="q1"), patch(
        "codex_master.server.current_agent_inventory", return_value=inventory
    ), patch(
        "codex_master.server.ensure_agent_not_blocked_by_codex_usage",
        return_value={"blocked": False},
    ):
        offer = agent_selection_options("q1", requester_class="arbeitsbiene")
    assert "teamleiterin" not in offer["classes"]


def test_skill_profile_cannot_bind_worker_targets_to_leadership() -> None:
    inventory = type(
        "Inventory",
        (),
        {
            "agents": {
                "a1": type(
                    "Descriptor",
                    (),
                    {"series_prefix": "a", "skill_profile": "teamleiterin"},
                )(),
                "c1": type(
                    "Descriptor",
                    (),
                    {"series_prefix": "c", "skill_profile": "teamleiterin"},
                )(),
            }
        },
    )()
    with patch("codex_master.server.current_agent_inventory", return_value=inventory):
        assert resolver_class_for_agent("a1", None) is None
        assert resolver_class_for_agent("c1", "arbeitsbiene") == "arbeitsbiene"


def test_q_target_does_not_bind_leadership_from_series_metadata() -> None:
    inventory = type(
        "Inventory",
        (),
        {
            "agents": {
                "q1": type(
                    "Descriptor",
                    (),
                    {"series_prefix": "q", "skill_profile": "teamleiterin"},
                )(),
            }
        },
    )()
    with patch("codex_master.server.current_agent_inventory", return_value=inventory):
        assert resolver_class_for_agent(
            "q1",
            "arbeitsbiene",
            authority_class="teamleiterin",
        ) == "arbeitsbiene"
        assert resolver_class_for_agent("q1", "arbeitsbiene") == "arbeitsbiene"


def test_unbound_leadership_request_remains_filtered_by_principal_authority() -> None:
    decision = resolve_runtime_agent_selection(
        role="exploriererin",
        routing={"decision": "main", "model": "gpt-5.6-sol"},
        task_profile=runtime_profile(complexity_override=TaskComplexity.COMPLEX, scope_kind="read"),
        requested_class="teamleiterin",
        authority_class="teamleiterin",
    )
    assert decision.class_id != "teamleiterin"
    assert decision.model != "gpt-5.6-sol"
    assert decision.fallback is True
    assert "requested_class_unavailable" in decision.reason_codes


def test_runtime_missing_class_auto_selects_specialist_for_complex_teamlead_work() -> None:
    decision = resolve_runtime_agent_selection(
        role="arbeitsbiene",
        routing={"decision": "main", "model": "gpt-5.6-luna"},
        task_profile=runtime_profile(complexity_override=TaskComplexity.COMPLEX),
        requested_class=None,
        authority_class="teamleiterin",
    )

    assert decision.class_id == "spezialistin"
    assert "class_auto_selected" in decision.reason_codes


def test_bound_teamlead_selection_keeps_persistent_terra_xhigh_defaults() -> None:
    decision = resolve_runtime_agent_selection(
        role="arbeitsbiene",
        routing={"decision": "main", "model": "gpt-5.6-sol"},
        task_profile=runtime_profile(),
        requested_class="teamleiterin",
        authority_class=None,
    )
    assert (decision.class_id, decision.lifecycle, decision.model, decision.reasoning) == (
        "teamleiterin",
        "persistent",
        "gpt-5.6-terra",
        "xhigh",
    )
