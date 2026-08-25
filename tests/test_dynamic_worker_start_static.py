import ast
import dataclasses
import importlib.util
import pickle
import sys
from pathlib import Path

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "src/codex_master/dynamic_worker_start.py"
)


def _start_module():
    assert MODULE_PATH.is_file(), "dynamic_worker_start module is missing"
    spec = importlib.util.spec_from_file_location(
        "dynamic_worker_start_under_test", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _module_tree() -> ast.Module:
    assert MODULE_PATH.is_file(), "dynamic_worker_start module is missing"
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))


def _called_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id.lower())
        elif isinstance(node.func, ast.Attribute):
            names.add(node.func.attr.lower())
    return names


def _imported_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.lower() for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names.add(node.module.lower())
    return names


def test_static_port_has_no_legacy_start_resolver_or_home_calls() -> None:
    tree = _module_tree()
    forbidden_fragments = {
        "resolver",
        "home",
        "meta",
        "cli",
        "commit_snapshot",
        "brokerframe",
        "broker_frame",
        "legacy",
        "fallback",
        "dualwrite",
        "dual_write",
    }
    names = _called_names(tree) | _imported_names(tree)

    assert "agent_start" not in names
    assert not {name for name in names if name.startswith("_start_agent")}
    assert not {
        name
        for name in names
        if any(fragment in name for fragment in forbidden_fragments)
    }


def test_public_return_has_only_sparse_contract_fields() -> None:
    tree = _module_tree()
    public_keys = {
        key.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        for key in node.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }

    assert public_keys <= {"status", "reason"}
    assert public_keys == {"status", "reason"}


def test_private_port_and_result_types_are_redacted_and_not_serializable() -> None:
    module = _start_module()
    b5_port = module._DynamicWorkerStartB5Port(
        coordinate=lambda: "launch-secret",
        prepare=lambda launch: launch,
    )
    a3_port = module._DynamicWorkerStartA3Port(execute=lambda _runner: None)
    result = module._DynamicWorkerStartResult(
        status="started",
        reason="dynamic_worker_started",
    )

    for value in (b5_port, a3_port, result):
        value_type = type(value)
        assert value_type.__name__.startswith("_")
        assert dataclasses.is_dataclass(value)
        assert value_type.__dataclass_params__.frozen
        assert "__dict__" not in value_type.__slots__
        assert "secret" not in repr(value)
        assert str(value) == repr(value)
        with pytest.raises(TypeError, match="not serializable"):
            pickle.dumps(value)

    assert result.to_public() == {
        "status": "started",
        "reason": "dynamic_worker_started",
    }
