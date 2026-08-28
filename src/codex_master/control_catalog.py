from __future__ import annotations

import math

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any


MAX_CATALOG_TOOLS = 128
MAX_FIELDS_PER_TOOL = 64
MAX_ENUM_ITEMS = 64
MAX_DESCRIPTOR_NAME_CHARS = 128
MAX_DESCRIPTOR_TEXT_CHARS = 2_000
MAX_SUPPORTED_STRING_CHARS = 16_384
MAX_SUPPORTED_ARRAY_ITEMS = 1_000


class CatalogError(ValueError):
    pass


class SchemaError(CatalogError):
    pass


class Risk(str, Enum):
    UNCLASSIFIED = "unclassified"
    READ_ONLY = "read_only"
    MUTATING = "mutating"
    BROAD = "broad"
    DESTRUCTIVE = "destructive"


class FieldKind(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    STRING_ARRAY = "string_array"


@dataclass(frozen=True, slots=True)
class FieldDescriptor:
    name: str
    kind: FieldKind
    required: bool
    description: str = ""
    has_default: bool = False
    default: str | int | float | bool | tuple[str, ...] | None = None
    enum: tuple[str | int, ...] = ()
    minimum: int | float | None = None
    maximum: int | float | None = None
    max_length: int | None = None
    min_items: int | None = None
    max_items: int | None = None
    item_max_length: int | None = None


@dataclass(frozen=True, slots=True)
class ToolDescriptor:
    name: str
    description: str
    risk: Risk
    fields: tuple[FieldDescriptor, ...]
    enabled: bool
    disabled_reason: str | None = None


_READ_ONLY_TOOLS = {
    "agent_spawn_offers",
    "agent_status",
    "agent_lease_status",
    "agent_wait",
    "agent_safe_tail",
    "agent_skills",
    "agent_skill_match",
    "agent_capabilities",
    "agent_scope_check",
    "agent_routing_decision",
    "agent_selection_options",
    "agent_assignments",
    "agent_last_assignment_status",
    "agent_assignment_report",
    "agent_selector_preview",
    "worktree_status",
    "integration_status",
    "master_app_bridge_status",
    "master_plugin_status",
    "master_namespace_status",
    "master_release_status",
    "master_watchdog_status",
    "master_timeout_policy",
    "master_applet_status",
    "agent_pool_validate",
    "agent_pool_status",
    "agent_doctor",
    "fleet_account_list",
    "fleet_gemini_bootstrap_plan",
    "fleet_series_list",
    "fleet_provider_models",
    "fleet_series_plan",
    "hive_status",
    "godbee_status",
    "queen_list",
    "queen_status",
    "hive_dispatch_status",
    "hive_queue_status",
    "hive_decisions",
    "hive_authority_check",
    "hive_plan_dispatch",
    "hive_admission_status",
    "agent_selection_preview",
    "agent_selection_status",
    "fleet_overview",
    "fleet_status_compact",
    "goddess_report_status",
    "goddess_report_list",
    "usage_fast_mode_status",
    "emergency_queen_status",
}
_MUTATING_TOOLS = {
    "agent_claim",
    "agent_release",
    "agent_send",
    "agent_interrupt",
    "agent_assign",
    "agent_assign_readonly",
    "agent_assign_live_data",
    "agent_assign_write",
    "agent_report_request",
    "agent_selector_policy",
    "worktree_create_for_agent",
    "commit_ready_check",
    "fleet_account_upsert",
    "fleet_account_set_secret",
    "fleet_account_disable",
    "fleet_account_probe",
    "fleet_account_delete",
    "fleet_series_apply",
    "fleet_series_disable",
    "fleet_series_delete",
    "goddess_report_run",
    "emergency_queen_plan_completed",
    "emergency_queen_child_started",
    "emergency_queen_child_completed",
}
_BROAD_TOOLS = {
    "agent_start",
    "agent_stop",
    "fleet_watchdog",
    "usage_watchdog",
    "agent_pool_install",
    "agent_pool_copy_auth",
    "usage_fast_mode",
    "usage_fast_mode_reconcile",
}
_DESTRUCTIVE_TOOLS = {"agent_pool_destroy_pool"}

RISK_BY_TOOL = MappingProxyType(
    {
        **{name: Risk.READ_ONLY for name in _READ_ONLY_TOOLS},
        **{name: Risk.MUTATING for name in _MUTATING_TOOLS},
        **{name: Risk.BROAD for name in _BROAD_TOOLS},
        **{name: Risk.DESTRUCTIVE for name in _DESTRUCTIVE_TOOLS},
    }
)

_ROOT_KEYWORDS = frozenset({"type", "required", "properties", "additionalProperties"})
_STRING_KEYWORDS = frozenset({"type", "description", "default", "enum", "maxLength"})
_INTEGER_KEYWORDS = frozenset({"type", "description", "default", "enum", "minimum", "maximum"})
_BOOLEAN_KEYWORDS = frozenset({"type", "description", "default"})
_ARRAY_KEYWORDS = frozenset({"type", "description", "default", "items", "minItems", "maxItems"})
_ARRAY_ITEM_KEYWORDS = frozenset({"type", "maxLength"})

_DANGEROUS_TRUE_ARGUMENTS = frozenset(
    {
        "force",
        "remove_root",
        "allow_unauthenticated",
        "allow_broad_selector",
        "allow_missing_skill",
        "allow_subagents",
        "manage_unclaimed",
        "overwrite",
        "overwrite_auth",
    }
)
_DANGEROUS_FALSE_ARGUMENTS = frozenset({"require_lease"})


def _bounded_display_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value[:MAX_DESCRIPTOR_TEXT_CHARS]


def _schema_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise SchemaError(f"{label} keys must be strings")
    return value


def _reject_unknown_keywords(schema: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(schema) - allowed)
    if unknown:
        raise SchemaError(f"{label} uses unsupported keyword")


def _optional_non_negative_int(schema: Mapping[str, Any], key: str, label: str) -> int | None:
    if key not in schema:
        return None
    value = schema[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SchemaError(f"{label} {key} must be a non-negative integer")
    return value


def _optional_int(schema: Mapping[str, Any], key: str, label: str) -> int | None:
    if key not in schema:
        return None
    value = schema[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise SchemaError(f"{label} {key} must be an integer")
    return value


def _field_description(schema: Mapping[str, Any], label: str) -> str:
    value = schema.get("description", "")
    if not isinstance(value, str):
        raise SchemaError(f"{label} description must be a string")
    return _bounded_display_text(value)


def _enum_values(
    schema: Mapping[str, Any],
    label: str,
    expected_type: type[str] | type[int],
) -> tuple[str | int, ...]:
    if "enum" not in schema:
        return ()
    values = schema["enum"]
    if not isinstance(values, list) or not values or len(values) > MAX_ENUM_ITEMS:
        raise SchemaError(f"{label} enum must be a bounded non-empty array")
    normalized: list[str | int] = []
    for value in values:
        if expected_type is int:
            valid = isinstance(value, int) and not isinstance(value, bool)
        else:
            valid = isinstance(value, str) and len(value) <= MAX_DESCRIPTOR_TEXT_CHARS
        if not valid:
            raise SchemaError(f"{label} enum has an invalid value")
        if value in normalized:
            raise SchemaError(f"{label} enum must not contain duplicates")
        normalized.append(value)
    return tuple(normalized)


def _normalize_value(
    field: FieldDescriptor,
    value: Any,
    *,
    error_type: type[CatalogError] = CatalogError,
) -> str | int | float | bool | tuple[str, ...]:
    label = field.name
    if field.kind is FieldKind.STRING:
        if not isinstance(value, str):
            raise error_type(f"{label} must be a string")
        if field.enum and value not in field.enum:
            raise error_type(f"{label} must be one of the supported values")
        if field.max_length is not None and len(value) > field.max_length:
            raise error_type(f"{label} must not exceed {field.max_length} characters")
        return value
    if field.kind is FieldKind.INTEGER:
        if isinstance(value, bool) or not isinstance(value, int):
            raise error_type(f"{label} must be an integer")
        if field.enum and value not in field.enum:
            raise error_type(f"{label} must be one of the supported values")
        if field.minimum is not None and value < field.minimum:
            raise error_type(f"{label} must be >= {field.minimum}")
        if field.maximum is not None and value > field.maximum:
            raise error_type(f"{label} must be <= {field.maximum}")
        return value
    if field.kind is FieldKind.NUMBER:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise error_type(f"{label} must be a number")
        if field.minimum is not None and value < field.minimum:
            raise error_type(f"{label} must be >= {field.minimum}")
        if field.maximum is not None and value > field.maximum:
            raise error_type(f"{label} must be <= {field.maximum}")
        return value
    if field.kind is FieldKind.BOOLEAN:
        if not isinstance(value, bool):
            raise error_type(f"{label} must be a boolean")
        return value
    if not isinstance(value, (list, tuple)):
        raise error_type(f"{label} must be an array")
    if field.min_items is not None and len(value) < field.min_items:
        raise error_type(f"{label} must contain at least {field.min_items} item(s)")
    if field.max_items is not None and len(value) > field.max_items:
        raise error_type(f"{label} must contain at most {field.max_items} item(s)")
    normalized_items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise error_type(f"{label}[{index}] must be a string")
        if field.item_max_length is not None and len(item) > field.item_max_length:
            raise error_type(
                f"{label}[{index}] must not exceed {field.item_max_length} characters"
            )
        normalized_items.append(item)
    return tuple(normalized_items)


def _with_default(field: FieldDescriptor, schema: Mapping[str, Any]) -> FieldDescriptor:
    if "default" not in schema:
        return field
    try:
        value = _normalize_value(field, schema["default"], error_type=SchemaError)
    except SchemaError as exc:
        raise SchemaError(f"{field.name} has an invalid default") from exc
    return FieldDescriptor(
        name=field.name,
        kind=field.kind,
        required=field.required,
        description=field.description,
        has_default=True,
        default=value,
        enum=field.enum,
        minimum=field.minimum,
        maximum=field.maximum,
        max_length=field.max_length,
        min_items=field.min_items,
        max_items=field.max_items,
        item_max_length=field.item_max_length,
    )


def _compile_field(name: str, raw_schema: Any, required: bool) -> FieldDescriptor:
    if not name or len(name) > MAX_DESCRIPTOR_NAME_CHARS:
        raise SchemaError("field name is invalid or too long")
    schema = _schema_mapping(raw_schema, f"field {name}")
    value_type = schema.get("type")
    label = f"field {name}"
    description = _field_description(schema, label)

    if value_type == "string":
        _reject_unknown_keywords(schema, _STRING_KEYWORDS, label)
        max_length = _optional_non_negative_int(schema, "maxLength", label)
        if max_length is not None and max_length > MAX_SUPPORTED_STRING_CHARS:
            raise SchemaError(f"{label} maxLength exceeds supported bound")
        enum = _enum_values(schema, label, str)
        if max_length is None and not enum:
            raise SchemaError(f"{label} string input is unbounded")
        field = FieldDescriptor(
            name=name,
            kind=FieldKind.STRING,
            required=required,
            description=description,
            enum=enum,
            max_length=max_length,
        )
    elif value_type == "integer":
        _reject_unknown_keywords(schema, _INTEGER_KEYWORDS, label)
        minimum = _optional_int(schema, "minimum", label)
        maximum = _optional_int(schema, "maximum", label)
        if minimum is not None and maximum is not None and minimum > maximum:
            raise SchemaError(f"{label} minimum must not exceed maximum")
        field = FieldDescriptor(
            name=name,
            kind=FieldKind.INTEGER,
            required=required,
            description=description,
            enum=_enum_values(schema, label, int),
            minimum=minimum,
            maximum=maximum,
        )
    elif value_type == "number":
        _reject_unknown_keywords(schema, frozenset({"type", "description", "default", "minimum", "maximum"}), label)
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        for bound_name, bound in (("minimum", minimum), ("maximum", maximum)):
            if bound is not None and (
                isinstance(bound, bool)
                or not isinstance(bound, (int, float))
                or not math.isfinite(bound)
            ):
                raise SchemaError(f"{label} {bound_name} must be a finite number")
        if minimum is not None and maximum is not None and minimum > maximum:
            raise SchemaError(f"{label} minimum must not exceed maximum")
        field = FieldDescriptor(
            name=name,
            kind=FieldKind.NUMBER,
            required=required,
            description=description,
            minimum=minimum,
            maximum=maximum,
        )
    elif value_type == "boolean":
        _reject_unknown_keywords(schema, _BOOLEAN_KEYWORDS, label)
        field = FieldDescriptor(
            name=name,
            kind=FieldKind.BOOLEAN,
            required=required,
            description=description,
        )
    elif value_type == "array":
        _reject_unknown_keywords(schema, _ARRAY_KEYWORDS, label)
        items = _schema_mapping(schema.get("items"), f"{label} items")
        _reject_unknown_keywords(items, _ARRAY_ITEM_KEYWORDS, f"{label} items")
        if items.get("type") != "string":
            raise SchemaError(f"{label} only supports string-array items")
        item_max_length = _optional_non_negative_int(items, "maxLength", f"{label} items")
        if item_max_length is None or item_max_length > MAX_SUPPORTED_STRING_CHARS:
            raise SchemaError(f"{label} item maxLength is missing or unsupported")
        min_items = _optional_non_negative_int(schema, "minItems", label)
        max_items = _optional_non_negative_int(schema, "maxItems", label)
        if max_items is None or max_items > MAX_SUPPORTED_ARRAY_ITEMS:
            raise SchemaError(f"{label} maxItems is missing or unsupported")
        if min_items is not None and min_items > max_items:
            raise SchemaError(f"{label} minItems must not exceed maxItems")
        field = FieldDescriptor(
            name=name,
            kind=FieldKind.STRING_ARRAY,
            required=required,
            description=description,
            min_items=min_items,
            max_items=max_items,
            item_max_length=item_max_length,
        )
    else:
        raise SchemaError(f"{label} uses unsupported type")
    return _with_default(field, schema)


def compile_input_schema(raw_schema: Any) -> tuple[FieldDescriptor, ...]:
    schema = _schema_mapping(raw_schema, "input schema")
    _reject_unknown_keywords(schema, _ROOT_KEYWORDS, "input schema")
    if schema.get("type") != "object":
        raise SchemaError("input schema type must be object")
    if schema.get("additionalProperties") is not False:
        raise SchemaError("input schema must set additionalProperties to false")

    properties = _schema_mapping(schema.get("properties"), "input schema properties")
    if len(properties) > MAX_FIELDS_PER_TOOL:
        raise SchemaError("input schema has too many fields")
    raw_required = schema.get("required", [])
    if not isinstance(raw_required, list) or any(not isinstance(value, str) for value in raw_required):
        raise SchemaError("input schema required must be an array of field names")
    if len(raw_required) != len(set(raw_required)):
        raise SchemaError("input schema required must not contain duplicates")
    required = set(raw_required)
    if not required.issubset(properties):
        raise SchemaError("input schema required references an unknown field")

    fields = tuple(
        _compile_field(name, field_schema, name in required)
        for name, field_schema in properties.items()
    )
    return fields


def compile_catalog(raw_tools: Iterable[Any]) -> tuple[ToolDescriptor, ...]:
    tools: list[Any] = []
    for tool in raw_tools:
        if len(tools) >= MAX_CATALOG_TOOLS:
            raise CatalogError("too many tools in catalog")
        tools.append(tool)

    exact_names = [tool.get("name") if isinstance(tool, Mapping) else None for tool in tools]
    counts = Counter(name for name in exact_names if isinstance(name, str))
    descriptors: list[ToolDescriptor] = []
    for index, raw_tool in enumerate(tools):
        if not isinstance(raw_tool, Mapping):
            descriptors.append(
                ToolDescriptor(
                    name=f"<invalid-tool-{index + 1}>",
                    description="",
                    risk=Risk.UNCLASSIFIED,
                    fields=(),
                    enabled=False,
                    disabled_reason="invalid tool descriptor",
                )
            )
            continue
        exact_name = raw_tool.get("name")
        valid_name = (
            isinstance(exact_name, str)
            and bool(exact_name)
            and len(exact_name) <= MAX_DESCRIPTOR_NAME_CHARS
        )
        name = exact_name if valid_name else _bounded_display_text(exact_name) or f"<invalid-tool-{index + 1}>"
        description = _bounded_display_text(raw_tool.get("description"))
        risk = RISK_BY_TOOL.get(exact_name, Risk.UNCLASSIFIED) if valid_name else Risk.UNCLASSIFIED
        fields: tuple[FieldDescriptor, ...] = ()
        schema_error: SchemaError | None = None
        try:
            fields = compile_input_schema(raw_tool.get("inputSchema"))
        except SchemaError as exc:
            schema_error = exc

        disabled_reason = None
        if valid_name and counts[exact_name] > 1:
            disabled_reason = "duplicate tool name"
        elif risk is Risk.UNCLASSIFIED:
            disabled_reason = "unclassified tool"
        elif schema_error is not None:
            disabled_reason = f"unsupported schema: {schema_error}"
        descriptors.append(
            ToolDescriptor(
                name=name,
                description=description,
                risk=risk,
                fields=fields if schema_error is None else (),
                enabled=disabled_reason is None,
                disabled_reason=disabled_reason,
            )
        )
    return tuple(descriptors)


def effective_risk(tool: ToolDescriptor, arguments: Mapping[str, Any]) -> Risk:
    if tool.risk is Risk.UNCLASSIFIED:
        return Risk.UNCLASSIFIED
    if any(arguments.get(name) is True for name in _DANGEROUS_TRUE_ARGUMENTS):
        return Risk.DESTRUCTIVE
    if any(arguments.get(name) is False for name in _DANGEROUS_FALSE_ARGUMENTS if name in arguments):
        return Risk.DESTRUCTIVE
    return tool.risk


def serialize_arguments(tool: ToolDescriptor, values: Mapping[str, Any]) -> dict[str, Any]:
    if not tool.enabled:
        raise CatalogError("tool is disabled")
    if not isinstance(values, Mapping):
        raise CatalogError("arguments must be an object")
    fields = {field.name: field for field in tool.fields}
    unknown = sorted(set(values) - set(fields))
    if unknown:
        raise CatalogError("unknown argument")
    missing = [field.name for field in tool.fields if field.required and field.name not in values]
    if missing:
        raise CatalogError("missing required argument")

    serialized: dict[str, Any] = {}
    for field in tool.fields:
        if field.name not in values:
            continue
        normalized = _normalize_value(field, values[field.name])
        serialized[field.name] = list(normalized) if field.kind is FieldKind.STRING_ARRAY else normalized
    return serialized
