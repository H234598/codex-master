import importlib.util
import sys
from pathlib import Path


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


def test_missing_b5_or_a3_port_returns_sparse_unavailable_before_coordination() -> None:
    module = _start_module()
    events: list[str] = []
    b5_port = module._DynamicWorkerStartB5Port(
        coordinate=lambda: events.append("coordinate"),
        prepare=lambda launch: launch,
    )
    a3_port = module._DynamicWorkerStartA3Port(execute=events.append)

    assert module.dynamic_worker_start(None, a3_port) == {
        "status": "unavailable",
        "reason": "dynamic_worker_runtime_unavailable",
    }
    assert module.dynamic_worker_start(b5_port, None) == {
        "status": "unavailable",
        "reason": "dynamic_worker_runtime_unavailable",
    }
    assert events == []


def test_b5_port_coordinates_prepares_then_a3_executes_once() -> None:
    module = _start_module()
    events: list[tuple[str, object]] = []
    launch = object()
    runner = object()

    def coordinate() -> object:
        events.append(("coordinate", launch))
        return launch

    def prepare(value: object) -> object:
        events.append(("prepare", value))
        return runner

    def execute(value: object) -> None:
        events.append(("execute", value))

    b5_port = module._DynamicWorkerStartB5Port(
        coordinate=coordinate,
        prepare=prepare,
    )
    a3_port = module._DynamicWorkerStartA3Port(execute=execute)

    assert module.dynamic_worker_start(b5_port, a3_port) == {
        "status": "started",
        "reason": "dynamic_worker_started",
    }
    assert events == [
        ("coordinate", launch),
        ("prepare", launch),
        ("execute", runner),
    ]
