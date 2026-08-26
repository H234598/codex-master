import ast
import copy
import dataclasses
import hashlib
import importlib.util
import json
import pickle
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/codex_master/dynamic_worker_start.py"
FUNCTION_TEST_PATH = ROOT / "tests/test_dynamic_worker_start.py"
PARENT_FUNCTION_AST_SHA256_V1 = {
    "dynamic_worker_start._RedactedNonSerializable.__repr__": (
        "65b005994386624bdb41781623937f1288e728c23620b5046a46a2a026062f06"
    ),
    "dynamic_worker_start._RedactedNonSerializable.__reduce_ex__": (
        "80decd7b7307e771d639d4449ca51f23cb798e39a61d5e667734e336ead042b8"
    ),
    "dynamic_worker_start._DynamicWorkerStartResult.to_public": (
        "33b46e687c171cfaa0200fcf8743b44db1bcf32b29e9a8c037fb9cea321201f2"
    ),
    "dynamic_worker_start.dynamic_worker_start": (
        "89640f473eff329a9271c1be009de898baab11960b5178f7fe720230ce987ab1"
    ),
}


def _start_module():
    assert MODULE_PATH.is_file(), "dynamic_worker_start module is missing"
    spec = importlib.util.spec_from_file_location(
        "dynamic_worker_start_static_under_test", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _module_tree() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))


def _function_dumps(tree: ast.Module) -> dict[str, str]:
    found: dict[str, str] = {}
    stack: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            name = ".".join(("dynamic_worker_start", *stack, node.name))
            dump = ast.dump(node, include_attributes=False)
            found[name] = hashlib.sha256(dump.encode()).hexdigest()
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

    Visitor().visit(tree)
    return found


def _callable_port_fields(tree: ast.Module) -> set[str]:
    found: set[str] = set()
    port_classes = {
        "_DynamicWorkerStartB5Port",
        "_DynamicWorkerStartA3Port",
    }
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name not in port_classes:
            continue
        for statement in node.body:
            if not isinstance(statement, ast.AnnAssign):
                continue
            if not isinstance(statement.target, ast.Name):
                continue
            if not any(
                isinstance(item, ast.Name) and item.id == "Callable"
                for item in ast.walk(statement.annotation)
            ):
                continue
            found.add(
                ".".join(
                    (
                        "dynamic_worker_start",
                        node.name,
                        statement.target.id,
                    )
                )
            )
    return found


def _literal_function_matrix() -> dict[str, str]:
    tree = ast.parse(FUNCTION_TEST_PATH.read_text(encoding="utf-8"))
    assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "FUNCTION_TEST_MATRIX_V1"
    ]
    assert len(assignments) == 1
    value = ast.literal_eval(assignments[0].value)
    assert type(value) is dict
    return value


def _test_function_names() -> list[str]:
    tree = ast.parse(FUNCTION_TEST_PATH.read_text(encoding="utf-8"))
    return [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ]


def test_positive_import_and_a3_call_gate_is_exact() -> None:
    tree = _module_tree()
    project_imports = [
        node
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.startswith("codex_master")
    ]

    assert len(project_imports) == 1
    project_import = project_imports[0]
    assert project_import.module == "codex_master.dynamic_worker_coordinator"
    assert [(alias.name, alias.asname) for alias in project_import.names] == [
        ("DynamicWorkerPreStartPortV1", None),
        ("PreStartReceiptV1", None),
    ]
    assert not [node for node in tree.body if isinstance(node, ast.Import)]

    forbidden_reflection = {
        "getattr",
        "setattr",
        "vars",
        "__getattribute__",
        "import_module",
    }
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not forbidden_reflection & (called_names | called_attributes)

    port_calls = [
        (node.func.value.id, node.func.attr)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"b5_port", "a3_port"}
    ]
    assert set(port_calls) <= {
        ("b5_port", "prepare"),
        ("b5_port", "record_start_granted"),
        ("b5_port", "record_running"),
        ("b5_port", "compensate_not_started"),
        ("b5_port", "quarantine_unknown_or_started"),
        ("a3_port", "execute"),
    }
    assert port_calls.count(("a3_port", "execute")) == 1
    assert ("b5_port", "coordinate") not in port_calls

    forbidden_fragments = {
        "agent_start",
        "allocator",
        "broker",
        "commit_snapshot",
        "dynamic_teamlead",
        "fallback",
        "fleet_registry",
        "fleet_service",
        "home",
        "legacy",
        "resolver",
        "server",
        "worker_resolution_carrier",
        "worker_spawn_ledger",
    }
    imported_modules = {
        node.module.lower()
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert not {
        module
        for module in imported_modules
        if module != "codex_master.dynamic_worker_coordinator"
        and any(fragment in module for fragment in forbidden_fragments)
    }


def test_function_matrix_matches_parent_ast_diff_and_callable_ports_exactly() -> None:
    parent = PARENT_FUNCTION_AST_SHA256_V1
    candidate_tree = _module_tree()
    candidate = _function_dumps(candidate_tree)
    changed = {
        name
        for name in set(parent) | set(candidate)
        if parent.get(name) != candidate.get(name)
    }
    inventory = changed | _callable_port_fields(candidate_tree)
    matrix = _literal_function_matrix()

    assert inventory == set(matrix)
    assert len(matrix.values()) == len(set(matrix.values()))
    test_names = _test_function_names()
    for node_id in matrix.values():
        path, separator, function_name = node_id.partition("::")
        assert path == "tests/test_dynamic_worker_start.py"
        assert separator == "::"
        assert test_names.count(function_name) == 1


def test_public_and_private_values_are_sparse_redacted_and_not_serializable() -> None:
    module = _start_module()
    receipt = module.PreStartReceiptV1(object(), object())
    pre_start_port = module.DynamicWorkerPreStartPortV1(
        ledger=object(),
        state_port=object(),
        allocator=object(),
        allocation_port=object(),
        projection_port=object(),
        home_port=object(),
        registry_port=object(),
        teamlead=object(),
        principal_id="dw-" + "5" * 32,
    )
    secret = "start-secret"
    b5_port = module._DynamicWorkerStartB5Port(
        pre_start_port=pre_start_port,
        receipt=receipt,
        prepare=lambda _receipt: secret,
        record_start_granted=lambda _receipt: True,
        record_running=lambda _receipt: True,
        compensate_not_started=lambda _receipt, _primary: None,
        quarantine_unknown_or_started=lambda _receipt, _primary: None,
    )
    a3_port = module._DynamicWorkerStartA3Port(
        receipt=receipt,
        execute=lambda _receipt: None,
    )
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
        assert secret not in repr(value)
        assert str(value) == repr(value)
        with pytest.raises(TypeError, match="not serializable"):
            pickle.dumps(value)
        with pytest.raises(TypeError):
            copy.copy(value)
        with pytest.raises(TypeError):
            json.dumps(value)

    for value in (b5_port, a3_port):
        with pytest.raises(TypeError, match="not serializable"):
            dataclasses.asdict(value)

    assert result.to_public() == {
        "status": "started",
        "reason": "dynamic_worker_started",
    }
    assert set(result.to_public()) == {"status", "reason"}
