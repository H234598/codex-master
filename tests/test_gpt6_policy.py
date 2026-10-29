"""Bounded regression for the checked-in GPT-6 model and class catalogs."""

from pathlib import Path

from the_hive.agent_resolver import (
    ResolutionRequest,
    policies_from_catalogs,
    resolve_agent_selection,
)
from the_hive.hive.config import load_agent_class_catalog
from the_hive.selection.model_policy import load_model_policy
from the_hive.server import (
    DEFAULT_AGENT_MODEL,
    limit_model_pool,
    model_from_status_text,
)


ROOT = Path(__file__).resolve().parents[1]


def _catalogs():
    return policies_from_catalogs(
        load_agent_class_catalog(ROOT / "codex-agent-classes.json"),
        load_model_policy(ROOT / "codex-model-policy.json"),
    )


def test_checked_in_catalog_has_no_spark_offer_or_gpt5_fallback():
    classes, models = _catalogs()
    ids = {model.model_id for model in models}
    assert {"gpt-6-luna", "gpt-6-sol", "gpt-6.1-sol", "gpt-6-astra"} <= ids
    assert all(not model_id.startswith("gpt-5") for model_id in ids)
    assert all(model.family != "spark" for model in models)
    assert all("spark" not in policy.allowed_families for policy in classes)
    assert {policy.class_id for policy in classes} >= {"teamleiterin", "arbeitsbiene"}


def test_teamlead_requires_available_gpt6_sol_at_xhigh():
    classes, models = _catalogs()
    request = ResolutionRequest("write", "complex", requested_class="teamleiterin")
    decision = resolve_agent_selection(
        request,
        classes=classes,
        models=models,
        available_models={model.model_id for model in models},
    )
    assert (decision.model, decision.reasoning) == ("gpt-6-sol", "xhigh")


def test_gpt6_limit_status_preserves_model_and_uses_main_pool():
    for model_id in ("gpt-6-luna", "gpt-6-sol", "gpt-6.1-sol", "gpt-6-astra"):
        assert limit_model_pool(model_id) == "default_agent_model"
        assert (
            model_from_status_text(f"Session model: {model_id}. Weekly limit reached")
            == model_id
        )
    assert limit_model_pool("gpt-5.3-codex-spark") == "spark_write_model"
    assert model_from_status_text("Session model: gpt-5.4-mini") == DEFAULT_AGENT_MODEL
    assert model_from_status_text("No known model") is None
