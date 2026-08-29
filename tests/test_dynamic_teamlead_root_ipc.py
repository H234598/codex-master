from __future__ import annotations

import ast
import copy
import dataclasses
import inspect
import pickle
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from codex_master.dynamic_teamlead_root_ipc import (
    RootControlExchangeOperations,
    SystemBusDynamicTeamleadStartControl,
)


STARTED = {
    "schema_version": 2,
    "status": "started",
    "reason_code": "none",
}
RUNTIME_UNAVAILABLE = {
    "schema_version": 2,
    "status": "unavailable",
    "reason_code": "dynamic_teamlead_runtime_unavailable",
}
INVALID = {
    "schema_version": 2,
    "status": "unavailable",
    "reason_code": "dynamic_teamlead_root_control_invalid",
}


class RecordingExchange:
    def __init__(self, responses: list[object]):
        self.responses = list(responses)
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def call_start_dynamic_teamlead(self, *args: object, **kwargs: object) -> object:
        self.calls.append((args, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class TupleSubclass(tuple):
    pass


@pytest.mark.parametrize(
    ("response", "expected"),
    (
        ((2, "started", "none"), STARTED),
        (
            (2, "unavailable", "dynamic_teamlead_runtime_unavailable"),
            RUNTIME_UNAVAILABLE,
        ),
    ),
)
def test_control_decodes_valid_root_reply_with_zero_arguments(
    response: tuple[object, ...], expected: dict[str, int | str]
) -> None:
    exchange = RecordingExchange([response, response])
    control = SystemBusDynamicTeamleadStartControl(exchange)

    first = control.start_dynamic_teamlead()
    second = control.start_dynamic_teamlead()

    assert type(first) is dict
    assert type(second) is dict
    assert first == expected
    assert second == expected
    assert first is not second
    assert first is not expected
    assert second is not expected
    assert exchange.calls == [((), {}), ((), {})]


def test_control_remains_reusable_after_exchange_error() -> None:
    exchange = RecordingExchange(
        [RuntimeError("private exchange detail"), (2, "started", "none")]
    )
    control = SystemBusDynamicTeamleadStartControl(exchange)

    first = control.start_dynamic_teamlead()
    second = control.start_dynamic_teamlead()

    assert first == INVALID
    assert second == STARTED
    assert first is not second
    assert exchange.calls == [((), {}), ((), {})]


@pytest.mark.parametrize(
    "response",
    (
        [2, "started", "none"],
        TupleSubclass((2, "started", "none")),
        (),
        (2, "started"),
        (2, "started", "none", "secret extra"),
        (True, "started", "none"),
        (1, "started", "none"),
        (3, "started", "none"),
        ("2", "started", "none"),
        (2, True, "none"),
        (2, "started", None),
        (2, "unknown", "none"),
        (2, "started", "unknown"),
        (2, "started", "dynamic_teamlead_runtime_unavailable"),
        (2, "unavailable", "none"),
    ),
)
def test_control_rejects_every_noncanonical_reply_without_detail(
    response: object,
) -> None:
    exchange = RecordingExchange([response, response])
    control = SystemBusDynamicTeamleadStartControl(exchange)

    first = control.start_dynamic_teamlead()
    second = control.start_dynamic_teamlead()

    assert first == INVALID
    assert second == INVALID
    assert first is not second
    assert "secret extra" not in repr(first)
    assert exchange.calls == [((), {}), ((), {})]


class NonCallableExchange:
    call_start_dynamic_teamlead = None


class MissingExchange:
    pass


class RaisingAttributeExchange:
    @property
    def call_start_dynamic_teamlead(self) -> object:
        raise RuntimeError("private attribute detail")


@pytest.mark.parametrize(
    "exchange_factory",
    (
        lambda: RecordingExchange([RuntimeError("private exception detail")]),
        NonCallableExchange,
        MissingExchange,
        RaisingAttributeExchange,
    ),
)
def test_control_redacts_exchange_failure_and_noncallable_operation(
    exchange_factory,
) -> None:
    exchange = exchange_factory()
    control = SystemBusDynamicTeamleadStartControl(exchange)

    result = control.start_dynamic_teamlead()

    assert result == INVALID
    assert "private" not in repr(result)
    assert "private" not in str(result)


@pytest.mark.parametrize(
    "clone",
    (
        copy.copy,
        copy.deepcopy,
        lambda value: pickle.loads(pickle.dumps(value)),
        dataclasses.replace,
    ),
)
def test_control_cannot_be_copied_serialized_or_replaced(clone) -> None:
    control = SystemBusDynamicTeamleadStartControl(RecordingExchange([]))

    with pytest.raises(Exception):
        clone(control)


def test_control_rejects_regular_mutation_and_subclassing() -> None:
    control = SystemBusDynamicTeamleadStartControl(RecordingExchange([]))

    with pytest.raises(FrozenInstanceError):
        control._exchange = RecordingExchange([])  # type: ignore[misc]

    with pytest.raises(TypeError):

        class ChildControl(SystemBusDynamicTeamleadStartControl):
            pass


def test_control_has_only_start_method_and_constant_redacted_identity() -> None:
    first = SystemBusDynamicTeamleadStartControl(RecordingExchange([]))
    second = SystemBusDynamicTeamleadStartControl(RecordingExchange([]))

    assert not hasattr(first, "__dict__")
    assert not hasattr(first, "exchange")
    assert {
        name for name in dir(first) if not name.startswith("_")
    } == {"start_dynamic_teamlead"}
    assert repr(first) == repr(second)
    assert str(first) == repr(first)
    assert "RecordingExchange" not in repr(first)


def test_exchange_protocol_exposes_only_zero_argument_operation() -> None:
    assert tuple(
        name
        for name in RootControlExchangeOperations.__dict__
        if not name.startswith("_")
    ) == ("call_start_dynamic_teamlead",)
    assert list(
        inspect.signature(
            RootControlExchangeOperations.call_start_dynamic_teamlead
        ).parameters
    ) == ["self"]


def test_root_control_module_has_no_transport_or_root_service_imports_or_calls() -> None:
    path = Path(__file__).resolve().parents[1] / (
        "src/codex_master/dynamic_teamlead_root_ipc.py"
    )
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden = {
        "dbus",
        "gi",
        "socket",
        "subprocess",
        "os",
        "pathlib",
        "server",
        "fleet_root_system_bus",
        "rootservice",
        "launcher",
        "ContextVar",
        "cache",
        "singleton",
        "factory",
        "callback",
    }

    imported_names = []
    called_names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported_names.append(node.module or "")
            imported_names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called_names.append(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called_names.append(node.func.attr)

    assert not forbidden.intersection(imported_names)
    assert not forbidden.intersection(called_names)
