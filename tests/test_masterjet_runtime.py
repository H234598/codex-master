from __future__ import annotations

from dataclasses import FrozenInstanceError, fields

import pytest

from codex_master.masterjet_runtime import MasterjetRuntime


UNAVAILABLE = {
    "schema_version": 1,
    "status": "unavailable",
    "reason": "dynamic_teamlead_runtime_unavailable",
    "raw_output": "not_returned",
}
STARTED = {
    "schema_version": 1,
    "status": "started",
    "raw_output": "not_returned",
}


class RecordingControl:
    def __init__(self, result: object = STARTED, error: BaseException | None = None):
        self.result = result
        self.error = error
        self.calls = 0

    def start_dynamic_teamlead(self) -> object:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


def test_none_control_returns_exact_unavailable_without_call() -> None:
    runtime = MasterjetRuntime(None)

    assert runtime.start_dynamic_teamlead() == UNAVAILABLE


def test_valid_control_returns_started_and_is_called_once() -> None:
    control = RecordingControl()
    runtime = MasterjetRuntime(control)

    assert runtime.start_dynamic_teamlead() == STARTED
    assert control.calls == 1


def test_runtime_returns_fresh_canonical_result_not_control_owned_dict() -> None:
    producer_result = {
        "schema_version": 1,
        "status": "started",
        "raw_output": "not_returned",
    }
    control = RecordingControl(result=producer_result)
    runtime = MasterjetRuntime(control)

    first = runtime.start_dynamic_teamlead()
    second = runtime.start_dynamic_teamlead()

    assert first == STARTED
    assert second == STARTED
    assert first is not second
    assert first is not producer_result
    assert second is not producer_result
    producer_result["raw_output"] = "private detail"
    assert first == STARTED
    assert second == STARTED
    assert control.calls == 2


@pytest.mark.parametrize(
    "control",
    (
        object(),
        type("NonCallableControl", (), {"start_dynamic_teamlead": None})(),
        RecordingControl(error=RuntimeError("private detail")),
    ),
)
def test_invalid_control_returns_exact_unavailable(control: object) -> None:
    assert MasterjetRuntime(control).start_dynamic_teamlead() == UNAVAILABLE


@pytest.mark.parametrize(
    "result",
    (
        {},
        {"schema_version": 1, "status": "started"},
        {
            "schema_version": 1,
            "status": "started",
            "raw_output": "not_returned",
            "extra": "x",
        },
        {"schema_version": 1, "status": "unavailable", "raw_output": "not_returned"},
        {"schema_version": True, "status": "started", "raw_output": "not_returned"},
        {"schema_version": 1, "status": True, "raw_output": "not_returned"},
        {"schema_version": 1, "status": "started", "raw_output": None},
        {"schema_version": 1, "status": "started", "raw_output": "returned"},
        {"schema_version": 2, "status": "started", "raw_output": "not_returned"},
        {"schema_version": 1, "status": "failed", "raw_output": "not_returned"},
        {
            "schema_version": 1,
            "status": "unavailable",
            "reason": "wrong",
            "raw_output": "not_returned",
        },
    ),
)
def test_malformed_control_result_returns_exact_unavailable(result: object) -> None:
    control = RecordingControl(result=result)

    assert MasterjetRuntime(control).start_dynamic_teamlead() == UNAVAILABLE
    assert control.calls == 1


def test_runtime_instances_hold_independent_controls_and_only_one_slot() -> None:
    first_control = RecordingControl(result=STARTED)
    second_control = RecordingControl(result=UNAVAILABLE)
    first = MasterjetRuntime(first_control)
    second = MasterjetRuntime(second_control)

    assert [field.name for field in fields(MasterjetRuntime)] == [
        "dynamic_teamlead_control"
    ]
    assert not hasattr(first, "__dict__")
    assert not hasattr(first, "port")
    assert not hasattr(first, "composition")
    assert not hasattr(first, "permit")
    assert first.start_dynamic_teamlead() == STARTED
    assert second.start_dynamic_teamlead() == UNAVAILABLE
    assert first_control.calls == 1
    assert second_control.calls == 1
    with pytest.raises(FrozenInstanceError):
        first.dynamic_teamlead_control = None  # type: ignore[misc]
