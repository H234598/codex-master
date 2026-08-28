import importlib.util
from pathlib import Path


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
