import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "src/codex_master/server.py"
CATALOG_PATH = ROOT / "src/codex_master/control_catalog.py"
START_PATH = ROOT / "src/codex_master/dynamic_teamlead_start.py"


def _module(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _assignment(module: ast.Module, name: str) -> ast.AST:
    for statement in module.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else (statement.target,)
            )
            if any(
                isinstance(target, ast.Name) and target.id == name for target in targets
            ):
                return statement.value
    raise AssertionError(f"missing assignment: {name}")


def _function(module: ast.Module, name: str) -> ast.FunctionDef:
    for node in ast.walk(module):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"missing function: {name}")


def _call_lines(function: ast.FunctionDef, name: str) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == name:
            lines.append(node.lineno)
    return lines


def _string_constants(node: ast.AST) -> set[str]:
    return {
        value.value
        for value in ast.walk(node)
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    }


def _tool_by_name(module: ast.Module, name: str) -> ast.Dict:
    tools = _assignment(module, "TOOLS")
    assert isinstance(tools, ast.List)
    for tool in tools.elts:
        if not isinstance(tool, ast.Dict):
            continue
        values = {
            key.value: value
            for key, value in zip(tool.keys, tool.values, strict=True)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        tool_name = values.get("name")
        if isinstance(tool_name, ast.Constant) and tool_name.value == name:
            return tool
    raise AssertionError(f"missing tool: {name}")


def _dict_values(node: ast.Dict) -> dict[str, ast.AST]:
    return {
        key.value: value
        for key, value in zip(node.keys, node.values, strict=True)
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }


def test_dynamic_teamlead_start_static_tool_contract_and_catalog_risk() -> None:
    server = _module(SERVER_PATH)
    catalog = _module(CATALOG_PATH)

    tool = _tool_by_name(server, "dynamic_teamlead_start")
    tool_values = _dict_values(tool)
    schema = tool_values.get("inputSchema")
    assert isinstance(schema, ast.Dict)
    assert ast.literal_eval(schema) == {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }

    teamleader_expression = _assignment(server, "TEAMLEADER_TOOL_NAMES")
    assert (
        isinstance(teamleader_expression, ast.Call)
        and isinstance(teamleader_expression.func, ast.Name)
        and teamleader_expression.func.id == "frozenset"
        and len(teamleader_expression.args) == 1
    )
    teamleader_tools = ast.literal_eval(teamleader_expression.args[0])
    assert "agent_start" in teamleader_tools
    assert "dynamic_teamlead_start" not in teamleader_tools

    visibility = _function(server, "allowed_tool_names_for_principal_class")
    visibility_constants = _string_constants(visibility)
    assert {"koenigin", "teamleiterin"} <= visibility_constants
    assert "TOOLS" in {
        node.id for node in ast.walk(visibility) if isinstance(node, ast.Name)
    }
    assert "TEAMLEADER_TOOL_NAMES" in {
        node.id for node in ast.walk(visibility) if isinstance(node, ast.Name)
    }

    mutating_tools = ast.literal_eval(_assignment(catalog, "_MUTATING_TOOLS"))
    broad_tools = ast.literal_eval(_assignment(catalog, "_BROAD_TOOLS"))
    assert "dynamic_teamlead_start" in mutating_tools
    assert "dynamic_teamlead_start" not in broad_tools

    call_tool = _function(server, "call_tool")
    dynamic_returns = [
        node.value
        for node in ast.walk(call_tool)
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "dynamic_teamlead_start"
    ]
    assert len(dynamic_returns) == 1
    assert dynamic_returns[0].args == []
    assert dynamic_returns[0].keywords == []


def test_legacy_teamlead_exclusions_remain_before_start_side_effects() -> None:
    server = _module(SERVER_PATH)

    reject = _function(server, "_reject_legacy_teamlead_start_target")
    assert "dynamic_teamlead_legacy_target_forbidden" in _string_constants(reject)

    for name in (
        "start_agent",
        "_start_agent_unlocked",
        "_start_agent_with_lease_unlocked",
    ):
        assert _call_lines(
            _function(server, name), "_reject_legacy_teamlead_start_target"
        )

    legacy_start = _function(server, "_start_agent_with_lease_unlocked")
    reject_line = min(_call_lines(legacy_start, "_reject_legacy_teamlead_start_target"))
    for side_effect in (
        "require_authenticated_agent_for_mutation",
        "codex_usage_routing_decision",
        "resolve_runtime_agent_selection",
        "claim_agent",
        "start_agent",
    ):
        lines = _call_lines(legacy_start, side_effect)
        assert lines and reject_line < min(lines)

    legacy_home_start = _function(server, "_start_agent_unlocked")
    home_guard = min(
        _call_lines(legacy_home_start, "_reject_legacy_teamlead_start_target")
    )
    home_mutation = _call_lines(
        legacy_home_start, "_materialize_managed_codex_runtime_class"
    )
    assert home_mutation and home_guard < min(home_mutation)

    options = _function(server, "agent_selection_options")
    assert _call_lines(options, "delegable_nonleadership_class_ids")
    delegated = _function(server, "delegable_nonleadership_class_ids")
    assert "LEADERSHIP_CLASS_IDS" in {
        node.id for node in ast.walk(delegated) if isinstance(node, ast.Name)
    }


def test_isolated_port_is_one_way_a3_flow_without_legacy_paths() -> None:
    start = _module(START_PATH)
    codex_imports = {
        node.module
        for node in start.body
        if isinstance(node, ast.ImportFrom)
        and node.module
        and node.module.startswith("codex_master.")
    }
    assert codex_imports == {
        "codex_master.dynamic_teamlead_coordinator",
        "codex_master.fleet_home_broker_client",
        "codex_master.fleet_runners",
    }

    flow = _function(start, "dynamic_teamlead_start")
    coordinate_lines = _call_lines(flow, "coordinate_dynamic_teamlead")
    prepare_lines = _call_lines(flow, "prepare_dynamic_teamlead_runner")
    executor_lines = _call_lines(flow, "executor")
    assert len(coordinate_lines) == len(prepare_lines) == len(executor_lines) == 1
    assert coordinate_lines[0] < prepare_lines[0] < executor_lines[0]

    forbidden_calls = {
        "start_agent",
        "start_agent_with_lease",
        "_start_agent_with_lease_unlocked",
        "_start_agent_unlocked",
        "_materialize_managed_codex_runtime_class",
        "_fleet_create_home",
        "_fleet_write_home",
        "_fleet_managed_home_state",
        "write_meta",
        "replace_private_text",
        "replace_private_bytes",
        "agent_ids",
        "canonical_agent_id",
        "agent_config",
        "resolve_runtime_agent_selection",
        "resolve_agent_selection",
        "codex_usage_routing_decision",
        "commit_snapshot",
        "receive_frame",
    }
    present_calls = {
        node.func.id
        for node in ast.walk(flow)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not present_calls & forbidden_calls
    assert "fallback" not in _string_constants(flow)
