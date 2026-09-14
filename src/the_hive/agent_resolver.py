"""Pure class, lifecycle, model, and reasoning policy resolution."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from collections.abc import Mapping
from typing import Any, Iterable


REASONING_RANK = {"low": 10, "medium": 20, "high": 30, "xhigh": 40, "max": 50}
LIFECYCLE_ALIASES = {"invocation": "ephemeral"}
LEADERSHIP_CLASS_IDS = frozenset({"goettin", "gottbiene", "koenigin", "teamleiterin"})
LIFECYCLE_RANK = {"ephemeral": 10, "binding": 20, "persistent": 30}
_MAX_RESOLUTION_TEXT_LENGTH = 256
_MAX_REASON_CODES = 64
_MAX_SELECTION_OPTIONS = 4096


@dataclass(frozen=True, slots=True)
class ModelPolicy:
    model_id: str
    family: str
    rank: int
    reasoning_levels: tuple[str, ...]
    capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.model_id or not self.family or self.rank < 0:
            raise ValueError("invalid_model_policy")
        if not self.reasoning_levels or any(level not in REASONING_RANK for level in self.reasoning_levels):
            raise ValueError("invalid_model_reasoning_levels")
        if (
            not isinstance(self.capabilities, tuple)
            or len(self.capabilities) > 64
            or any(not isinstance(capability, str) or not capability for capability in self.capabilities)
            or len(set(self.capabilities)) != len(self.capabilities)
        ):
            raise ValueError("invalid_model_capabilities")


@dataclass(frozen=True, slots=True)
class AgentClassPolicy:
    class_id: str
    default_lifecycle: str
    allowed_lifecycles: tuple[str, ...]
    allowed_families: tuple[str, ...]
    min_reasoning: str
    max_reasoning: str
    supported_scopes: tuple[str, ...]
    allowed_model_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not self.class_id
            or self.default_lifecycle not in self.allowed_lifecycles
            or self.min_reasoning not in REASONING_RANK
            or self.max_reasoning not in REASONING_RANK
            or REASONING_RANK[self.min_reasoning] > REASONING_RANK[self.max_reasoning]
            or not isinstance(self.allowed_model_ids, tuple)
            or any(not isinstance(model_id, str) or not model_id for model_id in self.allowed_model_ids)
            or len(set(self.allowed_model_ids)) != len(self.allowed_model_ids)
        ):
            raise ValueError("invalid_agent_class_policy")


@dataclass(frozen=True, slots=True)
class ResolutionRequest:
    scope_kind: str
    complexity: str
    requested_class: str | None = None
    requested_lifecycle: str | None = None
    requested_model: str | None = None
    requested_reasoning: str | None = None
    required_capabilities: tuple[str, ...] = ()
    spark_eligible: bool = False

    def __post_init__(self) -> None:
        if self.scope_kind not in {"read", "write", "unknown"}:
            raise ValueError("invalid_scope_kind")
        if self.complexity not in {"simple", "medium", "complex", "unknown"}:
            raise ValueError("invalid_complexity")
        if (
            not isinstance(self.required_capabilities, tuple)
            or len(self.required_capabilities) > 64
            or any(not isinstance(capability, str) or not capability for capability in self.required_capabilities)
            or len(set(self.required_capabilities)) != len(self.required_capabilities)
        ):
            raise ValueError("invalid_required_capabilities")
        if not isinstance(self.spark_eligible, bool):
            raise ValueError("invalid_spark_eligible")
        if self.requested_reasoning == "ultra":
            raise ValueError("invalid_requested_reasoning")


@dataclass(frozen=True, slots=True)
class ResolutionDecision:
    class_id: str
    lifecycle: str
    model: str
    reasoning: str
    reason_codes: tuple[str, ...]
    fallback: bool
    requested_class: str | None
    requested_lifecycle: str | None
    requested_model: str | None
    requested_reasoning: str | None


@dataclass(frozen=True, slots=True)
class SelectionOption:
    class_id: str
    lifecycle: str
    model: str
    reasoning: str


@dataclass(frozen=True, slots=True)
class SelectionOffer:
    generation: str
    classes: tuple[str, ...]
    lifecycles: tuple[str, ...]
    models: tuple[str, ...]
    reasoning_levels: tuple[str, ...]
    options: tuple[SelectionOption, ...]


def canonical_worker_lifecycle(lifecycle: object) -> str:
    """Return the central canonical lifecycle name used by worker boundaries."""

    if type(lifecycle) is not str:
        raise ValueError("invalid_worker_lifecycle")
    canonical = LIFECYCLE_ALIASES.get(lifecycle, lifecycle)
    if canonical not in LIFECYCLE_RANK:
        raise ValueError("invalid_worker_lifecycle")
    return canonical


def canonical_resolution_decision_digest(decision: object) -> str:
    """Return one stable digest for every field of a central resolution decision."""

    if type(decision) is not ResolutionDecision:
        raise ValueError("invalid_resolution_decision")
    required_text = {
        "class_id": decision.class_id,
        "lifecycle": decision.lifecycle,
        "model": decision.model,
        "reasoning": decision.reasoning,
    }
    if any(
        type(value) is not str or not value or len(value) > _MAX_RESOLUTION_TEXT_LENGTH
        for value in required_text.values()
    ):
        raise ValueError("invalid_resolution_decision")
    if canonical_worker_lifecycle(decision.lifecycle) != decision.lifecycle:
        raise ValueError("invalid_resolution_decision")
    if decision.reasoning not in REASONING_RANK:
        raise ValueError("invalid_resolution_decision")
    if (
        type(decision.reason_codes) is not tuple
        or len(decision.reason_codes) > _MAX_REASON_CODES
        or any(
            type(code) is not str
            or not code
            or len(code) > _MAX_RESOLUTION_TEXT_LENGTH
            for code in decision.reason_codes
        )
        or len(set(decision.reason_codes)) != len(decision.reason_codes)
        or type(decision.fallback) is not bool
    ):
        raise ValueError("invalid_resolution_decision")
    requested_values = (
        decision.requested_class,
        decision.requested_lifecycle,
        decision.requested_model,
        decision.requested_reasoning,
    )
    if any(
        value is not None
        and (
            type(value) is not str
            or not value
            or len(value) > _MAX_RESOLUTION_TEXT_LENGTH
        )
        for value in requested_values
    ):
        raise ValueError("invalid_resolution_decision")
    encoded = json.dumps(
        {
            "class_id": decision.class_id,
            "lifecycle": decision.lifecycle,
            "model": decision.model,
            "reasoning": decision.reasoning,
            "reason_codes": list(decision.reason_codes),
            "fallback": decision.fallback,
            "requested_class": decision.requested_class,
            "requested_lifecycle": decision.requested_lifecycle,
            "requested_model": decision.requested_model,
            "requested_reasoning": decision.requested_reasoning,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_resolution_decision_offer(decision: object, offer: object) -> None:
    """Require one central decision to be present in one canonical central offer."""

    canonical_resolution_decision_digest(decision)
    if type(offer) is not SelectionOffer:
        raise ValueError("invalid_selection_offer")
    if (
        type(offer.generation) is not str
        or len(offer.generation) != 71
        or not offer.generation.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in offer.generation[7:])
    ):
        raise ValueError("invalid_selection_offer")
    public_values = (
        offer.classes,
        offer.lifecycles,
        offer.models,
        offer.reasoning_levels,
    )
    if any(
        type(values) is not tuple
        or len(values) > _MAX_SELECTION_OPTIONS
        or any(
            type(value) is not str
            or not value
            or len(value) > _MAX_RESOLUTION_TEXT_LENGTH
            for value in values
        )
        or len(set(values)) != len(values)
        for values in public_values
    ):
        raise ValueError("invalid_selection_offer")
    if type(offer.options) is not tuple or len(offer.options) > _MAX_SELECTION_OPTIONS:
        raise ValueError("invalid_selection_offer")
    option_values: list[tuple[str, str, str, str]] = []
    for option in offer.options:
        if type(option) is not SelectionOption:
            raise ValueError("invalid_selection_offer")
        values = (option.class_id, option.lifecycle, option.model, option.reasoning)
        if any(
            type(value) is not str
            or not value
            or len(value) > _MAX_RESOLUTION_TEXT_LENGTH
            for value in values
        ):
            raise ValueError("invalid_selection_offer")
        if canonical_worker_lifecycle(option.lifecycle) != option.lifecycle:
            raise ValueError("invalid_selection_offer")
        if option.reasoning not in REASONING_RANK:
            raise ValueError("invalid_selection_offer")
        option_values.append(values)
    if len(set(option_values)) != len(option_values):
        raise ValueError("invalid_selection_offer")
    if offer.lifecycles and any(
        canonical_worker_lifecycle(lifecycle) != lifecycle for lifecycle in offer.lifecycles
    ):
        raise ValueError("invalid_selection_offer")
    expected_public_values = (
        tuple(dict.fromkeys(value[0] for value in option_values)),
        tuple(dict.fromkeys(value[1] for value in option_values)),
        tuple(dict.fromkeys(value[2] for value in option_values)),
        tuple(dict.fromkeys(value[3] for value in option_values)),
    )
    if public_values != expected_public_values:
        raise ValueError("invalid_selection_offer")
    encoded = json.dumps(option_values, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if offer.generation != "sha256:" + hashlib.sha256(encoded).hexdigest():
        raise ValueError("invalid_selection_offer")
    if (
        decision.class_id,
        decision.lifecycle,
        decision.model,
        decision.reasoning,
    ) not in option_values:
        raise ValueError("resolution_decision_not_offered")


def _select_class(request: ResolutionRequest, classes: tuple[AgentClassPolicy, ...], reasons: list[str]) -> AgentClassPolicy:
    by_id = {item.class_id: item for item in classes}
    if request.requested_class in by_id:
        return by_id[request.requested_class]
    if request.requested_class is not None:
        reasons.append("requested_class_unavailable")
    candidates = tuple(
        item
        for item in classes
        if item.class_id not in LEADERSHIP_CLASS_IDS
        and (request.scope_kind in item.supported_scopes or request.scope_kind == "unknown")
    )
    if not candidates:
        raise ValueError("no_compatible_class")

    preferred_class = "spezialistin" if request.complexity in {"medium", "complex"} else "arbeitsbiene"
    selected = min(
        candidates,
        key=lambda item: (
            item.class_id != preferred_class,
            LIFECYCLE_RANK.get(item.default_lifecycle, 100),
            REASONING_RANK[item.min_reasoning],
            REASONING_RANK[item.max_reasoning],
            item.class_id,
        ),
    )
    reasons.append("class_auto_selected")
    return selected


def _default_model_family(request: ResolutionRequest, lifecycle: str) -> str:
    if lifecycle == "persistent" or lifecycle == "binding":
        return "luna"
    if request.scope_kind == "write" and request.complexity == "simple" and request.spark_eligible:
        return "spark"
    return "luna"


def _default_reasoning(model: ModelPolicy, lifecycle: str) -> str:
    if model.family == "spark":
        return "low"
    if lifecycle == "persistent":
        return "xhigh"
    if lifecycle == "binding":
        return "high"
    return "medium"


def _model_allowed_for_class(model: ModelPolicy, class_policy: AgentClassPolicy) -> bool:
    return (
        model.family in class_policy.allowed_families
        and (not class_policy.allowed_model_ids or model.model_id in class_policy.allowed_model_ids)
    )


def _model_supports_task(model: ModelPolicy, request: ResolutionRequest) -> bool:
    if not set(request.required_capabilities).issubset(model.capabilities):
        return False
    return (
        model.family != "spark"
        or (
            request.spark_eligible
            and request.scope_kind == "write"
            and {"write", "simple_task_eligible"}.issubset(model.capabilities)
        )
    )


def _clamp_reasoning(
    requested: str,
    *,
    model: ModelPolicy,
    class_policy: AgentClassPolicy,
    lifecycle: str,
    reasons: list[str],
) -> str:
    allowed = _allowed_reasoning_levels(model, class_policy, lifecycle)
    if not allowed:
        raise ValueError("no_compatible_reasoning_level")
    if requested not in REASONING_RANK:
        reasons.append("requested_reasoning_unsupported")
        requested = _default_reasoning(model, lifecycle)
    target_rank = REASONING_RANK[requested]
    selected = min(allowed, key=lambda level: (abs(REASONING_RANK[level] - target_rank), REASONING_RANK[level]))
    if selected != requested:
        reasons.append("requested_reasoning_outside_limits")
    return selected


def _allowed_reasoning_levels(
    model: ModelPolicy,
    class_policy: AgentClassPolicy,
    lifecycle: str,
) -> tuple[str, ...]:
    minimum_rank = REASONING_RANK[class_policy.min_reasoning]
    if lifecycle == "persistent":
        minimum_rank = max(minimum_rank, REASONING_RANK["xhigh"])
    maximum_rank = REASONING_RANK[class_policy.max_reasoning]
    return tuple(
        level
        for level in model.reasoning_levels
        if minimum_rank <= REASONING_RANK[level] <= maximum_rank
    )


def validate_canonical_agent_tuple(
    class_policy: AgentClassPolicy,
    model: ModelPolicy,
    lifecycle: str,
    reasoning: str,
) -> None:
    if (
        lifecycle not in class_policy.allowed_lifecycles
        or not _model_allowed_for_class(model, class_policy)
        or reasoning not in _allowed_reasoning_levels(model, class_policy, lifecycle)
    ):
        raise ValueError("invalid_canonical_agent_tuple")


def resolve_agent_selection(
    request: ResolutionRequest,
    *,
    classes: Iterable[AgentClassPolicy],
    models: Iterable[ModelPolicy],
    available_models: set[str] | frozenset[str],
) -> ResolutionDecision:
    """Resolve one valid selection. Callers must not reapply defaults."""

    class_values = tuple(classes)
    model_values = tuple(models)
    reasons: list[str] = []
    class_policy = _select_class(request, class_values, reasons)

    requested_lifecycle = request.requested_lifecycle
    lifecycle = LIFECYCLE_ALIASES.get(requested_lifecycle, requested_lifecycle)
    if lifecycle != requested_lifecycle and requested_lifecycle is not None:
        reasons.append("lifecycle_alias_normalized")
    is_explicit_leadership = (
        request.requested_class == class_policy.class_id
        and class_policy.class_id in LEADERSHIP_CLASS_IDS
    )
    if is_explicit_leadership and (
        len(class_policy.allowed_lifecycles) != 1
        or class_policy.default_lifecycle != "persistent"
        or lifecycle not in {None, class_policy.default_lifecycle}
    ):
        raise ValueError("leadership_explicit_tuple_required")
    if lifecycle is None:
        lifecycle = class_policy.default_lifecycle
        reasons.append("lifecycle_defaulted")
    elif lifecycle not in class_policy.allowed_lifecycles:
        lifecycle = class_policy.default_lifecycle
        reasons.append("requested_lifecycle_outside_class")

    by_id = {item.model_id: item for item in model_values}
    requested_model = by_id.get(request.requested_model or "")
    if is_explicit_leadership and request.requested_model is not None and (
        requested_model is None
        or not _model_allowed_for_class(requested_model, class_policy)
        or requested_model.model_id not in available_models
        or not _model_supports_task(requested_model, request)
    ):
        raise ValueError("leadership_explicit_tuple_required")
    if request.requested_model is not None and requested_model is None:
        reasons.append("requested_model_unknown")
    if (
        not is_explicit_leadership
        and requested_model is not None
        and not _model_allowed_for_class(requested_model, class_policy)
    ):
        reasons.append("requested_model_outside_class")
        requested_model = None
    if (
        not is_explicit_leadership
        and requested_model is not None
        and requested_model.model_id not in available_models
    ):
        reasons.append("requested_model_unavailable")
        requested_model = None
    if (
        not is_explicit_leadership
        and requested_model is not None
        and not _model_supports_task(requested_model, request)
    ):
        reasons.append("requested_model_capability_mismatch")
        requested_model = None

    explicit_model_rejected = request.requested_model is not None and requested_model is None
    minimum_family = "luna" if explicit_model_rejected else _default_model_family(request, lifecycle)
    family_rank = {item.family: item.rank for item in model_values}
    if len(class_policy.allowed_families) == 1:
        minimum_family = class_policy.allowed_families[0]
    minimum_rank = family_rank.get(minimum_family, 0)
    if class_policy.allowed_model_ids:
        allowed_ranks = [item.rank for item in model_values if item.model_id in class_policy.allowed_model_ids]
        minimum_rank = min(allowed_ranks, default=0)
    candidates = sorted(
        (
            item
            for item in model_values
            if _model_allowed_for_class(item, class_policy)
            and item.model_id in available_models
            and item.rank >= minimum_rank
            and _model_supports_task(item, request)
        ),
        key=lambda item: item.rank,
    )
    if (
        request.requested_model is None
        and minimum_family == "spark"
        and any(
            item.family == "spark"
            and item.model_id in available_models
            and _model_allowed_for_class(item, class_policy)
            and not _model_supports_task(item, request)
            for item in model_values
        )
    ):
        reasons.append("spark_model_capability_mismatch")
    if requested_model is not None and requested_model.rank >= minimum_rank:
        model = requested_model
    else:
        if requested_model is not None:
            reasons.append("requested_model_below_task_minimum")
        if not candidates:
            if class_policy.allowed_model_ids:
                raise ValueError("required_model_unavailable:" + ",".join(class_policy.allowed_model_ids))
            raise ValueError("no_compatible_model")
        model = candidates[0]
        if request.requested_model is None:
            reasons.append("model_defaulted")
            if model.family != minimum_family:
                reasons.append("default_model_unavailable")

    requested_reasoning = request.requested_reasoning
    if is_explicit_leadership and requested_reasoning is not None:
        try:
            validate_canonical_agent_tuple(class_policy, model, lifecycle, requested_reasoning)
        except ValueError as exc:
            raise ValueError("leadership_explicit_tuple_required") from exc
    if class_policy.min_reasoning == class_policy.max_reasoning:
        if class_policy.min_reasoning not in _allowed_reasoning_levels(model, class_policy, lifecycle):
            if class_policy.allowed_model_ids:
                raise ValueError(
                    f"required_model_effort_unavailable:{model.model_id}:{class_policy.min_reasoning}"
                )
            raise ValueError("no_compatible_reasoning_level")
        reasoning = class_policy.min_reasoning
        if requested_reasoning is not None and requested_reasoning != reasoning:
            reasons.append("requested_reasoning_outside_limits")
    else:
        if requested_reasoning is None:
            requested_reasoning = _default_reasoning(model, lifecycle)
            reasons.append("reasoning_defaulted")
        reasoning = _clamp_reasoning(
            requested_reasoning,
            model=model,
            class_policy=class_policy,
            lifecycle=lifecycle,
            reasons=reasons,
        )

    validate_canonical_agent_tuple(class_policy, model, lifecycle, reasoning)

    fallback_codes = {
        "requested_class_unavailable",
        "requested_lifecycle_outside_class",
        "requested_model_unknown",
        "requested_model_outside_class",
        "requested_model_unavailable",
        "requested_model_capability_mismatch",
        "requested_model_below_task_minimum",
        "requested_reasoning_unsupported",
        "requested_reasoning_outside_limits",
        "default_model_unavailable",
        "spark_model_capability_mismatch",
    }
    return ResolutionDecision(
        class_id=class_policy.class_id,
        lifecycle=lifecycle,
        model=model.model_id,
        reasoning=reasoning,
        reason_codes=tuple(dict.fromkeys(reasons)),
        fallback=bool(fallback_codes.intersection(reasons)),
        requested_class=request.requested_class,
        requested_lifecycle=request.requested_lifecycle,
        requested_model=request.requested_model,
        requested_reasoning=request.requested_reasoning,
    )


def build_selection_offer(
    *,
    classes: Iterable[AgentClassPolicy],
    models: Iterable[ModelPolicy],
    available_models: set[str] | frozenset[str],
) -> SelectionOffer:
    """Return only valid public class/lifecycle/model/reasoning tuples."""

    options: list[SelectionOption] = []
    for class_policy in sorted(classes, key=lambda item: item.class_id):
        compatible_models = [
            model
            for model in sorted(models, key=lambda item: item.rank)
            if model.model_id in available_models and _model_allowed_for_class(model, class_policy)
        ]
        if class_policy.allowed_model_ids and not compatible_models:
            raise ValueError("required_model_unavailable:" + ",".join(class_policy.allowed_model_ids))
        for lifecycle in class_policy.allowed_lifecycles:
            for model in compatible_models:
                allowed_reasoning = _allowed_reasoning_levels(model, class_policy, lifecycle)
                if class_policy.min_reasoning == class_policy.max_reasoning and not allowed_reasoning:
                    if class_policy.allowed_model_ids:
                        raise ValueError(
                            f"required_model_effort_unavailable:{model.model_id}:{class_policy.min_reasoning}"
                        )
                    continue
                for reasoning in allowed_reasoning:
                    validate_canonical_agent_tuple(class_policy, model, lifecycle, reasoning)
                    options.append(SelectionOption(class_policy.class_id, lifecycle, model.model_id, reasoning))
    encoded = json.dumps(
        [(item.class_id, item.lifecycle, item.model, item.reasoning) for item in options],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return SelectionOffer(
        generation="sha256:" + hashlib.sha256(encoded).hexdigest(),
        classes=tuple(dict.fromkeys(item.class_id for item in options)),
        lifecycles=tuple(dict.fromkeys(item.lifecycle for item in options)),
        models=tuple(dict.fromkeys(item.model for item in options)),
        reasoning_levels=tuple(dict.fromkeys(item.reasoning for item in options)),
        options=tuple(options),
    )


def policies_from_catalogs(
    class_catalog: Mapping[str, Any],
    model_registry: Any,
) -> tuple[tuple[AgentClassPolicy, ...], tuple[ModelPolicy, ...]]:
    """Adapt strict Hive/model registries to the pure resolver contract."""

    classes = tuple(
        AgentClassPolicy(
            class_id=profile.class_id,
            default_lifecycle=profile.public_lifecycle,
            allowed_lifecycles=profile.allowed_lifecycles,
            allowed_families=profile.allowed_model_families,
            min_reasoning=profile.min_reasoning,
            max_reasoning=profile.max_reasoning,
            supported_scopes=("read",) if profile.write_mode == "none" else ("read", "write"),
            allowed_model_ids=profile.allowed_model_ids,
        )
        for profile in class_catalog.values()
    )
    models = tuple(
        ModelPolicy(
            model_id=item["model_id"],
            family=item["family"],
            rank=item["rank"],
            reasoning_levels=tuple(item["reasoning_levels"]),
            capabilities=tuple(item.get("capabilities", ())),
        )
        for item in model_registry.public()
        if item["enabled"] and item["spawn_behavior"] == "manual"
    )
    return classes, models


__all__ = [
    "AgentClassPolicy",
    "ModelPolicy",
    "ResolutionDecision",
    "ResolutionRequest",
    "SelectionOffer",
    "SelectionOption",
    "build_selection_offer",
    "policies_from_catalogs",
    "resolve_agent_selection",
]
