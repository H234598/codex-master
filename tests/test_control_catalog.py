from __future__ import annotations

import dataclasses
import unittest

from codex_master.control_catalog import (
    MAX_CATALOG_TOOLS,
    MAX_DESCRIPTOR_TEXT_CHARS,
    CatalogError,
    FieldKind,
    Risk,
    RISK_BY_TOOL,
    SchemaError,
    compile_catalog,
    compile_input_schema,
    effective_risk,
    serialize_arguments,
)
from codex_master.server import TOOLS


EXPECTED_RISKS = {
    "agent_spawn_offers": Risk.READ_ONLY,
    "agent_start": Risk.BROAD,
    "agent_status": Risk.READ_ONLY,
    "agent_lease_status": Risk.READ_ONLY,
    "agent_claim": Risk.MUTATING,
    "agent_release": Risk.MUTATING,
    "agent_wait": Risk.READ_ONLY,
    "fleet_watchdog": Risk.BROAD,
    "usage_watchdog": Risk.BROAD,
    "agent_send": Risk.MUTATING,
    "agent_interrupt": Risk.MUTATING,
    "agent_stop": Risk.BROAD,
    "agent_safe_tail": Risk.READ_ONLY,
    "agent_skills": Risk.READ_ONLY,
    "agent_skill_match": Risk.READ_ONLY,
    "agent_capabilities": Risk.READ_ONLY,
    "agent_scope_check": Risk.READ_ONLY,
    "agent_routing_decision": Risk.READ_ONLY,
    "agent_selection_options": Risk.READ_ONLY,
    "agent_assign": Risk.MUTATING,
    "agent_assign_readonly": Risk.MUTATING,
    "agent_assign_live_data": Risk.MUTATING,
    "agent_assign_write": Risk.MUTATING,
    "agent_assignments": Risk.READ_ONLY,
    "agent_last_assignment_status": Risk.READ_ONLY,
    "agent_report_request": Risk.MUTATING,
    "agent_assignment_report": Risk.READ_ONLY,
    "agent_selector_policy": Risk.MUTATING,
    "agent_selector_preview": Risk.READ_ONLY,
    "worktree_create_for_agent": Risk.MUTATING,
    "worktree_status": Risk.READ_ONLY,
    "integration_status": Risk.READ_ONLY,
    "commit_ready_check": Risk.MUTATING,
    "master_app_bridge_status": Risk.READ_ONLY,
    "master_plugin_status": Risk.READ_ONLY,
    "master_namespace_status": Risk.READ_ONLY,
    "master_release_status": Risk.READ_ONLY,
    "master_watchdog_status": Risk.READ_ONLY,
    "master_timeout_policy": Risk.READ_ONLY,
    "master_applet_status": Risk.READ_ONLY,
    "agent_pool_validate": Risk.READ_ONLY,
    "agent_pool_install": Risk.BROAD,
    "agent_pool_status": Risk.READ_ONLY,
    "agent_pool_copy_auth": Risk.BROAD,
    "agent_pool_destroy_pool": Risk.DESTRUCTIVE,
    "agent_doctor": Risk.READ_ONLY,
    "fleet_account_list": Risk.READ_ONLY,
    "fleet_gemini_bootstrap_plan": Risk.READ_ONLY,
    "fleet_series_list": Risk.READ_ONLY,
    "fleet_account_upsert": Risk.MUTATING,
    "fleet_account_set_secret": Risk.MUTATING,
    "fleet_account_disable": Risk.MUTATING,
    "fleet_account_probe": Risk.MUTATING,
    "fleet_account_delete": Risk.MUTATING,
    "fleet_provider_models": Risk.READ_ONLY,
    "fleet_series_plan": Risk.READ_ONLY,
    "fleet_series_apply": Risk.MUTATING,
    "fleet_series_disable": Risk.MUTATING,
    "fleet_series_delete": Risk.MUTATING,
    "hive_status": Risk.READ_ONLY,
    "godbee_status": Risk.READ_ONLY,
    "queen_list": Risk.READ_ONLY,
    "queen_status": Risk.READ_ONLY,
    "hive_dispatch_status": Risk.READ_ONLY,
    "hive_queue_status": Risk.READ_ONLY,
    "hive_decisions": Risk.READ_ONLY,
    "hive_authority_check": Risk.READ_ONLY,
    "hive_plan_dispatch": Risk.READ_ONLY,
    "hive_admission_status": Risk.READ_ONLY,
    "agent_selection_preview": Risk.READ_ONLY,
    "agent_selection_status": Risk.READ_ONLY,
    "fleet_overview": Risk.READ_ONLY,
    "fleet_status_compact": Risk.READ_ONLY,
    "goddess_report_status": Risk.READ_ONLY,
    "goddess_report_run": Risk.MUTATING,
    "goddess_report_list": Risk.READ_ONLY,
    "usage_fast_mode": Risk.BROAD,
    "usage_fast_mode_reconcile": Risk.BROAD,
    "usage_fast_mode_status": Risk.READ_ONLY,
    "emergency_queen_status": Risk.READ_ONLY,
    "emergency_queen_plan_completed": Risk.MUTATING,
    "emergency_queen_child_started": Risk.MUTATING,
    "emergency_queen_child_completed": Risk.MUTATING,
}


def tool_fixture(
    name: str = "agent_status",
    *,
    schema: dict | None = None,
    description: str = "status",
) -> dict:
    return {
        "name": name,
        "description": description,
        "inputSchema": schema
        or {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    }


class ControlCatalogTest(unittest.TestCase):
    def test_risk_registry_exactly_covers_current_tools(self) -> None:
        published_names = {tool["name"] for tool in TOOLS}

        self.assertEqual(len(EXPECTED_RISKS), len(published_names))
        self.assertEqual(dict(RISK_BY_TOOL), EXPECTED_RISKS)
        self.assertEqual(published_names, set(EXPECTED_RISKS))

    def test_current_server_catalog_compiles_with_immutable_bounded_descriptors(self) -> None:
        catalog = compile_catalog(TOOLS)

        self.assertEqual(len(catalog), len(TOOLS))
        self.assertTrue(all(tool.enabled for tool in catalog))
        self.assertTrue(all(isinstance(tool.fields, tuple) for tool in catalog))
        status = next(tool for tool in catalog if tool.name == "agent_status")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            status.enabled = False

        scope_check = next(tool for tool in catalog if tool.name == "agent_scope_check")
        scope = next(field for field in scope_check.fields if field.name == "scope")
        self.assertIsInstance(scope.default, tuple)

    def test_descriptor_display_text_and_catalog_size_are_bounded(self) -> None:
        catalog = compile_catalog(
            [tool_fixture(description="x" * (MAX_DESCRIPTOR_TEXT_CHARS + 100))]
        )
        self.assertEqual(len(catalog[0].description), MAX_DESCRIPTOR_TEXT_CHARS)

        oversized = [tool_fixture(f"unknown_{index}") for index in range(MAX_CATALOG_TOOLS + 1)]
        with self.assertRaisesRegex(CatalogError, "too many tools"):
            compile_catalog(oversized)

    def test_unknown_and_duplicate_tools_remain_visible_but_disabled(self) -> None:
        known = tool_fixture()
        catalog = compile_catalog([known, tool_fixture("future_tool"), known])

        self.assertEqual([tool.name for tool in catalog], ["agent_status", "future_tool", "agent_status"])
        self.assertFalse(catalog[0].enabled)
        self.assertIn("duplicate", catalog[0].disabled_reason)
        self.assertFalse(catalog[1].enabled)
        self.assertEqual(catalog[1].risk, Risk.UNCLASSIFIED)
        self.assertIn("unclassified", catalog[1].disabled_reason)
        self.assertFalse(catalog[2].enabled)

    def test_schema_compiler_supports_only_current_field_shapes(self) -> None:
        schema = {
            "type": "object",
            "required": ["text", "count", "enabled", "paths"],
            "properties": {
                "text": {"type": "string", "maxLength": 12, "description": "text"},
                "mode": {"type": "string", "enum": ["one", "two"], "default": "one"},
                "count": {"type": "integer", "minimum": 1, "maximum": 9},
                "level": {"type": "integer", "enum": [1, 2], "default": 1},
                "enabled": {"type": "boolean", "default": False},
                "paths": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 3,
                    "items": {"type": "string", "maxLength": 20},
                },
            },
            "additionalProperties": False,
        }

        compiled = compile_input_schema(schema)

        self.assertEqual(
            [field.kind for field in compiled],
            [
                FieldKind.STRING,
                FieldKind.STRING,
                FieldKind.INTEGER,
                FieldKind.INTEGER,
                FieldKind.BOOLEAN,
                FieldKind.STRING_ARRAY,
            ],
        )
        self.assertEqual([field.required for field in compiled], [True, False, True, False, True, True])
        self.assertEqual(compiled[1].enum, ("one", "two"))

    def test_schema_compiler_rejects_unknown_or_nested_schema_forms(self) -> None:
        invalid_schemas = {
            "open root": {
                "type": "object",
                "properties": {},
                "additionalProperties": True,
            },
            "root ref": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
                "$ref": "#/$defs/input",
            },
            "root oneOf": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
                "oneOf": [],
            },
            "root anyOf": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
                "anyOf": [],
            },
            "unknown field keyword": {
                "type": "object",
                "properties": {"text": {"type": "string", "pattern": ".*"}},
                "additionalProperties": False,
            },
            "unsupported number keyword": {
                "type": "object",
                "properties": {"ratio": {"type": "number", "multipleOf": 0.5}},
                "additionalProperties": False,
            },
            "nested object": {
                "type": "object",
                "properties": {"nested": {"type": "object"}},
                "additionalProperties": False,
            },
            "non-string array": {
                "type": "object",
                "properties": {"values": {"type": "array", "items": {"type": "integer"}}},
                "additionalProperties": False,
            },
        }

        for label, schema in invalid_schemas.items():
            with self.subTest(label=label), self.assertRaises(SchemaError):
                compile_input_schema(schema)

    def test_invalid_known_schema_is_visible_disabled_without_raw_fallback(self) -> None:
        catalog = compile_catalog(
            [
                tool_fixture(
                    schema={
                        "type": "object",
                        "properties": {"payload": {"type": "object"}},
                        "additionalProperties": False,
                    }
                )
            ]
        )

        descriptor = catalog[0]
        self.assertFalse(descriptor.enabled)
        self.assertEqual(descriptor.fields, ())
        self.assertIn("unsupported schema", descriptor.disabled_reason)
        with self.assertRaisesRegex(CatalogError, "disabled"):
            serialize_arguments(descriptor, {"payload": "{}"})

    def test_effective_risk_escalates_dangerous_overrides_to_destructive(self) -> None:
        catalog = {tool.name: tool for tool in compile_catalog(TOOLS)}
        cases = [
            ("agent_claim", {"force": True}),
            ("agent_release", {"force": True}),
            ("agent_start", {"allow_unauthenticated": True}),
            ("agent_start", {"allow_broad_selector": True}),
            ("fleet_watchdog", {"manage_unclaimed": True}),
            ("fleet_watchdog", {"require_lease": False}),
            ("agent_assign", {"allow_missing_skill": True}),
            ("agent_assign", {"allow_subagents": True}),
            ("agent_pool_install", {"overwrite_auth": True}),
            ("agent_pool_copy_auth", {"overwrite": True}),
            ("agent_pool_destroy_pool", {"remove_root": True}),
        ]

        for name, arguments in cases:
            with self.subTest(name=name, arguments=arguments):
                self.assertEqual(effective_risk(catalog[name], arguments), Risk.DESTRUCTIVE)

        self.assertEqual(effective_risk(catalog["agent_claim"], {"force": False}), Risk.MUTATING)
        self.assertEqual(effective_risk(catalog["agent_pool_install"], {"yes": True}), Risk.BROAD)

    def test_argument_serialization_is_strict_and_does_not_inject_defaults(self) -> None:
        schema = {
            "type": "object",
            "required": ["agent", "count", "paths"],
            "properties": {
                "agent": {"type": "string", "maxLength": 4},
                "count": {"type": "integer", "minimum": 1, "maximum": 3},
                "paths": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 2,
                    "items": {"type": "string", "maxLength": 5},
                },
                "enabled": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        }
        descriptor = compile_catalog([tool_fixture(schema=schema)])[0]

        result = serialize_arguments(descriptor, {"agent": "a1", "count": 2, "paths": ("src",)})

        self.assertEqual(result, {"agent": "a1", "count": 2, "paths": ["src"]})
        self.assertNotIn("enabled", result)

    def test_argument_serialization_rejects_missing_unknown_and_invalid_values(self) -> None:
        schema = {
            "type": "object",
            "required": ["agent"],
            "properties": {
                "agent": {"type": "string", "maxLength": 2, "enum": ["a1", "b1"]},
                "note": {"type": "string", "maxLength": 2},
                "count": {"type": "integer", "minimum": 1, "maximum": 2},
                "enabled": {"type": "boolean"},
                "paths": {
                    "type": "array",
                    "maxItems": 1,
                    "items": {"type": "string", "maxLength": 3},
                },
            },
            "additionalProperties": False,
        }
        descriptor = compile_catalog([tool_fixture(schema=schema)])[0]
        invalid = [
            ({}, "missing required"),
            ({"agent": "a1", "extra": True}, "unknown argument"),
            ({"agent": "c1"}, "one of"),
            ({"agent": "a1", "note": "long"}, "characters"),
            ({"agent": "a1", "count": True}, "integer"),
            ({"agent": "a1", "count": 3}, "<= 2"),
            ({"agent": "a1", "enabled": "false"}, "boolean"),
            ({"agent": "a1", "paths": "src"}, "array"),
            ({"agent": "a1", "paths": ["long"]}, "characters"),
            ({"agent": "a1", "paths": ["src", "tst"]}, "at most"),
        ]

        for arguments, message in invalid:
            with self.subTest(arguments=arguments), self.assertRaisesRegex(CatalogError, message):
                serialize_arguments(descriptor, arguments)


if __name__ == "__main__":
    unittest.main()
