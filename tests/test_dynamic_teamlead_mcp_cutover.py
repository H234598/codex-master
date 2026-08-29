import importlib.util
from pathlib import Path
from unittest.mock import patch

import codex_master.server as server_module
from codex_master.masterjet_runtime import MasterjetRuntime


MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "src/codex_master/dynamic_teamlead_start.py"
)


def _start_module():
    assert MODULE_PATH.is_file(), "dynamic_teamlead_start module is missing"
    spec = importlib.util.spec_from_file_location(
        "dynamic_teamlead_start_under_test", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_a3_port_returns_unavailable_before_coordination(monkeypatch) -> None:
    module = _start_module()

    def coordinate(*_args: object) -> object:
        raise AssertionError("coordination must not run without A3")

    monkeypatch.setattr(module, "coordinate_dynamic_teamlead", coordinate)

    assert module.dynamic_teamlead_start() == {
        "schema_version": 1,
        "status": "unavailable",
        "reason": "dynamic_teamlead_runtime_unavailable",
        "raw_output": "not_returned",
    }


def test_a3_port_coordinates_prepares_then_executes_once(monkeypatch) -> None:
    module = _start_module()
    events: list[tuple[str, object]] = []
    launch = object()
    runner = object()

    def coordinate(
        request: object, registry_operations: object, broker_operations: object
    ) -> object:
        events.append(("coordinate", (request, registry_operations, broker_operations)))
        return launch

    def prepare(value: object) -> object:
        events.append(("prepare", value))
        return runner

    class A3Port:
        request = object()
        registry_operations = object()
        broker_operations = object()

        def execute_dynamic_teamlead_runner(self, value: object) -> None:
            events.append(("execute", value))

    monkeypatch.setattr(module, "coordinate_dynamic_teamlead", coordinate)
    monkeypatch.setattr(module, "prepare_dynamic_teamlead_runner", prepare)

    assert module.dynamic_teamlead_start(A3Port()) == {
        "schema_version": 1,
        "status": "started",
        "raw_output": "not_returned",
    }
    assert events == [
        (
            "coordinate",
            (A3Port.request, A3Port.registry_operations, A3Port.broker_operations),
        ),
        ("prepare", launch),
        ("execute", runner),
    ]


def test_call_tool_dispatches_dynamic_teamlead_through_injected_runtime() -> None:
    class Control:
        calls = 0

        def start_dynamic_teamlead(self) -> dict[str, int | str]:
            self.calls += 1
            return {
                "schema_version": 1,
                "status": "started",
                "raw_output": "not_returned",
            }

    control = Control()
    with patch.object(
        server_module,
        "dynamic_teamlead_start",
        side_effect=AssertionError("explicit runtime must use wrapper"),
        create=True,
    ):
        result = server_module.call_tool(
            "dynamic_teamlead_start",
            {},
            runtime=MasterjetRuntime(control),
        )

    assert result == {
        "schema_version": 1,
        "status": "started",
        "raw_output": "not_returned",
    }
    assert control.calls == 1


def test_call_tool_dynamic_teamlead_absent_or_invalid_runtime_is_unavailable() -> None:
    class InvalidRuntime:
        calls = 0

        def start_dynamic_teamlead(self) -> dict[str, int | str]:
            self.calls += 1
            raise AssertionError("invalid runtime must not be called")

    expected = {
        "schema_version": 1,
        "status": "unavailable",
        "reason": "dynamic_teamlead_runtime_unavailable",
        "raw_output": "not_returned",
    }
    invalid = InvalidRuntime()

    with patch.object(
        server_module,
        "dynamic_teamlead_start",
        side_effect=AssertionError("unavailable path must not call old consumer"),
        create=True,
    ):
        absent = server_module.call_tool("dynamic_teamlead_start", {})
        rejected = server_module.call_tool(
            "dynamic_teamlead_start", {}, runtime=invalid
        )

    assert absent == expected
    assert rejected == expected
    assert absent is not rejected
    assert invalid.calls == 0


def test_call_tool_ignores_runtime_for_other_tools() -> None:
    class Control:
        calls = 0

        def start_dynamic_teamlead(self) -> dict[str, int | str]:
            self.calls += 1
            raise AssertionError("non-dynamic tool must ignore runtime")

    control = Control()
    with patch.object(
        server_module,
        "agent_spawn_offers",
        return_value={"status": "ok"},
    ):
        result = server_module.call_tool(
            "agent_spawn_offers",
            {},
            runtime=MasterjetRuntime(control),
        )

    assert result == {"status": "ok"}
    assert control.calls == 0


def test_call_tool_dynamic_teamlead_runtime_exception_stays_sparse() -> None:
    class Control:
        def start_dynamic_teamlead(self) -> dict[str, int | str]:
            raise RuntimeError("private control detail")

    result = server_module.call_tool(
        "dynamic_teamlead_start",
        {},
        runtime=MasterjetRuntime(Control()),
    )

    assert result == {
        "schema_version": 1,
        "status": "unavailable",
        "reason": "dynamic_teamlead_runtime_unavailable",
        "raw_output": "not_returned",
    }
    assert "private control detail" not in str(result)
