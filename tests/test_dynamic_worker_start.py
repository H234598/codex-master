import importlib.util
import sys
from pathlib import Path
from queue import Queue
from threading import Barrier, Event, Thread

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "src/codex_master/dynamic_worker_start.py"
)

FUNCTION_TEST_MATRIX_V1: dict[str, str] = {
    "dynamic_worker_start.dynamic_worker_start": (
        "tests/test_dynamic_worker_start.py::"
        "test_dynamic_worker_start_orders_receipt_prepare_start_granted_a3_running"
    ),
    "dynamic_worker_start._DynamicWorkerStartB5Port.prepare": (
        "tests/test_dynamic_worker_start.py::"
        "test_b5_port_prepare_runs_only_after_bound_prestart_receipt"
    ),
    "dynamic_worker_start._DynamicWorkerStartB5Port.record_start_granted": (
        "tests/test_dynamic_worker_start.py::"
        "test_b5_port_start_granted_waits_for_all_preconditions_and_is_single_use"
    ),
    "dynamic_worker_start._DynamicWorkerStartA3Port.execute": (
        "tests/test_dynamic_worker_start.py::"
        "test_a3_port_executes_once_only_after_persisted_start_granted"
    ),
    "dynamic_worker_start._DynamicWorkerStartB5Port.record_running": (
        "tests/test_dynamic_worker_start.py::"
        "test_b5_port_running_requires_one_completed_a3_call"
    ),
    "dynamic_worker_start._DynamicWorkerStartB5Port.compensate_not_started": (
        "tests/test_dynamic_worker_start.py::"
        "test_b5_port_compensates_once_only_for_proven_never_started_outcome"
    ),
    ("dynamic_worker_start._DynamicWorkerStartB5Port.quarantine_unknown_or_started"): (
        "tests/test_dynamic_worker_start.py::"
        "test_b5_port_quarantines_unknown_without_release_cleanup_or_retry"
    ),
}


class _CrashAfterEffect(BaseException):
    pass


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


class _StartHarness:
    def __init__(self, module) -> None:
        self.module = module
        self.events: list[tuple[str, object]] = []
        self.prepare_result: object = True
        self.prepare_error: Exception | None = None
        self.grant_result: object = True
        self.grant_error: BaseException | None = None
        self.grant_persists_before_error = False
        self.a3_error: BaseException | None = None
        self.running_result: object = True
        self.running_error: BaseException | None = None
        self.running_persists_before_error = False
        self.compensation_error: Exception | None = None
        self.quarantine_error: Exception | None = None
        self.grant_persisted = False
        self.running_persisted = False
        self.prepare_calls = 0
        self.start_granted_calls = 0
        self.a3_calls = 0
        self.running_calls = 0
        self.compensation_calls = 0
        self.quarantine_calls = 0
        self.compensation_primary: list[Exception] = []
        self.quarantine_primary: list[Exception] = []
        self.receipt = module.PreStartReceiptV1(object(), object())
        self.pre_start_port = module.DynamicWorkerPreStartPortV1(
            ledger=object(),
            state_port=object(),
            allocator=object(),
            allocation_port=object(),
            projection_port=object(),
            home_port=object(),
            registry_port=object(),
            teamlead=object(),
            principal_id="dw-" + "4" * 32,
        )
        self.b5_port = self.make_b5_port(self.receipt)
        self.a3_port = module._DynamicWorkerStartA3Port(
            receipt=self.receipt,
            execute=self.execute,
        )

    def make_b5_port(self, receipt: object):
        return self.module._DynamicWorkerStartB5Port(
            pre_start_port=self.pre_start_port,
            receipt=receipt,
            prepare=self.prepare,
            record_start_granted=self.record_start_granted,
            record_running=self.record_running,
            compensate_not_started=self.compensate_not_started,
            quarantine_unknown_or_started=self.quarantine_unknown_or_started,
        )

    def prepare(self, receipt: object) -> object:
        self.prepare_calls += 1
        self.events.append(("prepare", receipt))
        if self.prepare_error is not None:
            raise self.prepare_error
        return self.prepare_result

    def record_start_granted(self, receipt: object) -> object:
        self.start_granted_calls += 1
        self.events.append(("start_granted", receipt))
        if self.grant_persists_before_error:
            self.grant_persisted = True
        if self.grant_error is not None:
            raise self.grant_error
        if self.grant_result is True:
            self.grant_persisted = True
        return self.grant_result

    def execute(self, receipt: object) -> None:
        self.a3_calls += 1
        self.events.append(("a3", receipt))
        if self.a3_error is not None:
            raise self.a3_error

    def record_running(self, receipt: object) -> object:
        self.running_calls += 1
        self.events.append(("running", receipt))
        if self.running_persists_before_error:
            self.running_persisted = True
        if self.running_error is not None:
            raise self.running_error
        if self.running_result is True:
            self.running_persisted = True
        return self.running_result

    def compensate_not_started(self, receipt: object, primary: Exception) -> None:
        self.compensation_calls += 1
        self.compensation_primary.append(primary)
        self.events.append(("compensate", receipt))
        if self.compensation_error is not None:
            raise self.compensation_error

    def quarantine_unknown_or_started(
        self, receipt: object, primary: Exception
    ) -> None:
        self.quarantine_calls += 1
        self.quarantine_primary.append(primary)
        self.events.append(("quarantine", receipt))
        if self.quarantine_error is not None:
            raise self.quarantine_error

    def start(self) -> dict[str, str]:
        return self.module.dynamic_worker_start(self.b5_port, self.a3_port)


def test_missing_b5_or_a3_port_returns_sparse_denial_without_side_effects() -> None:
    module = _start_module()
    harness = _StartHarness(module)

    expected = {
        "status": "denied",
        "reason": "dynamic_worker_start_port_denied",
    }
    assert module.dynamic_worker_start(None, harness.a3_port) == expected
    assert module.dynamic_worker_start(harness.b5_port, None) == expected
    assert harness.events == []


def test_dynamic_worker_start_orders_receipt_prepare_start_granted_a3_running() -> None:
    harness = _StartHarness(_start_module())

    assert harness.start() == {
        "status": "started",
        "reason": "dynamic_worker_started",
    }
    assert harness.events == [
        ("prepare", harness.receipt),
        ("start_granted", harness.receipt),
        ("a3", harness.receipt),
        ("running", harness.receipt),
    ]
    assert (
        harness.start_granted_calls,
        harness.a3_calls,
        harness.running_calls,
        harness.compensation_calls,
        harness.quarantine_calls,
    ) == (1, 1, 1, 0, 0)


def test_b5_port_prepare_runs_only_after_bound_prestart_receipt() -> None:
    harness = _StartHarness(_start_module())
    invalid_port = harness.make_b5_port(object())

    assert harness.module.dynamic_worker_start(invalid_port, harness.a3_port) == {
        "status": "denied",
        "reason": "dynamic_worker_start_port_denied",
    }
    cross_receipt = harness.module.PreStartReceiptV1(object(), object())
    cross_port = harness.make_b5_port(cross_receipt)
    assert harness.module.dynamic_worker_start(cross_port, harness.a3_port) == {
        "status": "denied",
        "reason": "dynamic_worker_start_port_denied",
    }
    assert harness.prepare_calls == 0

    primary = RuntimeError("prepare denied")
    harness.prepare_error = primary
    assert harness.start() == {
        "status": "not_started",
        "reason": "dynamic_worker_prepare_failed",
    }
    assert harness.compensation_primary == [primary]
    assert (harness.start_granted_calls, harness.a3_calls) == (0, 0)


def test_b5_port_start_granted_waits_for_all_preconditions_and_is_single_use() -> None:
    denied = _StartHarness(_start_module())
    denied.prepare_result = False
    assert denied.start()["status"] == "not_started"
    assert (denied.start_granted_calls, denied.a3_calls, denied.compensation_calls) == (
        0,
        0,
        1,
    )

    success = _StartHarness(_start_module())
    assert success.start()["status"] == "started"
    assert success.start()["status"] == "quarantined"
    assert (success.start_granted_calls, success.a3_calls) == (1, 1)


def test_a3_port_executes_once_only_after_persisted_start_granted() -> None:
    denied = _StartHarness(_start_module())
    denied.grant_result = False
    assert denied.start()["status"] == "not_started"
    assert (denied.start_granted_calls, denied.a3_calls) == (1, 0)

    success = _StartHarness(_start_module())
    assert success.start()["status"] == "started"
    assert success.start()["status"] == "quarantined"
    assert (success.grant_persisted, success.a3_calls) == (True, 1)


def test_b5_port_running_requires_one_completed_a3_call() -> None:
    failed_a3 = _StartHarness(_start_module())
    failed_a3.a3_error = TimeoutError("A3 outcome unknown")
    assert failed_a3.start()["status"] == "quarantined"
    assert failed_a3.running_calls == 0

    success = _StartHarness(_start_module())
    assert success.start()["status"] == "started"
    assert (success.a3_calls, success.running_calls, success.running_persisted) == (
        1,
        1,
        True,
    )


def test_b5_port_compensates_once_only_for_proven_never_started_outcome() -> None:
    prepare_denied = _StartHarness(_start_module())
    prepare_denied.prepare_error = RuntimeError("prepare failed")
    assert prepare_denied.start()["status"] == "not_started"
    assert (prepare_denied.compensation_calls, prepare_denied.a3_calls) == (1, 0)

    grant_denied = _StartHarness(_start_module())
    grant_denied.grant_result = False
    assert grant_denied.start()["status"] == "not_started"
    assert (grant_denied.compensation_calls, grant_denied.a3_calls) == (1, 0)

    unknown = _StartHarness(_start_module())
    unknown.grant_error = TimeoutError("grant outcome unknown")
    assert unknown.start()["status"] == "quarantined"
    assert (unknown.compensation_calls, unknown.quarantine_calls) == (0, 1)


def test_b5_port_quarantines_unknown_without_release_cleanup_or_retry() -> None:
    harness = _StartHarness(_start_module())
    harness.grant_error = TimeoutError("grant outcome unknown")

    assert harness.start()["status"] == "quarantined"
    assert harness.start()["status"] == "quarantined"
    assert (
        harness.start_granted_calls,
        harness.compensation_calls,
        harness.quarantine_calls,
        harness.a3_calls,
    ) == (1, 0, 1, 0)
    assert not {
        "cleanup",
        "delete",
        "release",
        "revoke",
        "compare_and_swap",
    } & {name for name, _value in harness.events}


def test_start_granted_is_invisible_until_receipt_prepare_intent_home_and_registry_are_committed() -> (
    None
):
    invalid = _StartHarness(_start_module())
    invalid_port = invalid.make_b5_port(object())
    assert (
        invalid.module.dynamic_worker_start(invalid_port, invalid.a3_port)["status"]
        == "denied"
    )
    assert (invalid.start_granted_calls, invalid.a3_calls) == (0, 0)

    for missing in ("intent", "home", "registry"):
        uncertain = _StartHarness(_start_module())
        uncertain.prepare_result = {"missing": missing}
        assert uncertain.start()["status"] == "quarantined"
        assert (
            uncertain.start_granted_calls,
            uncertain.a3_calls,
            uncertain.compensation_calls,
            uncertain.quarantine_calls,
        ) == (0, 0, 0, 1)


def test_known_start_granted_cas_no_write_compensates_once_without_a3() -> None:
    harness = _StartHarness(_start_module())
    harness.grant_result = False

    assert harness.start() == {
        "status": "not_started",
        "reason": "dynamic_worker_start_grant_denied",
    }
    assert (
        harness.start_granted_calls,
        harness.compensation_calls,
        harness.quarantine_calls,
        harness.a3_calls,
    ) == (1, 1, 0, 0)


def test_start_granted_cas_timeout_or_exception_quarantines_without_compensation_or_retry() -> (
    None
):
    for primary in (
        TimeoutError("grant timeout"),
        RuntimeError("grant exception"),
    ):
        harness = _StartHarness(_start_module())
        harness.grant_error = primary
        assert harness.start()["status"] == "quarantined"
        assert harness.start()["status"] == "quarantined"
        assert harness.quarantine_primary == [primary]
        assert (
            harness.start_granted_calls,
            harness.compensation_calls,
            harness.quarantine_calls,
            harness.a3_calls,
        ) == (1, 0, 1, 0)


def test_crash_after_persisted_start_granted_before_a3_quarantines_and_never_regrants() -> (
    None
):
    harness = _StartHarness(_start_module())
    primary = _CrashAfterEffect("crash after persisted START_GRANTED")
    harness.grant_persists_before_error = True
    harness.grant_error = primary

    with pytest.raises(_CrashAfterEffect, match="persisted START_GRANTED"):
        harness.start()
    assert harness.grant_persisted
    assert harness.start()["status"] == "quarantined"
    assert (
        harness.start_granted_calls,
        harness.a3_calls,
        harness.compensation_calls,
        harness.quarantine_calls,
    ) == (1, 0, 0, 0)


def test_a3_timeout_exception_or_crash_before_running_quarantines_without_retry() -> (
    None
):
    for primary in (TimeoutError("A3 timeout"), RuntimeError("A3 exception")):
        harness = _StartHarness(_start_module())
        harness.a3_error = primary
        assert harness.start()["status"] == "quarantined"
        assert harness.start()["status"] == "quarantined"
        assert harness.quarantine_primary == [primary]
        assert (
            harness.start_granted_calls,
            harness.a3_calls,
            harness.running_calls,
            harness.compensation_calls,
            harness.quarantine_calls,
        ) == (1, 1, 0, 0, 1)

    crashed = _StartHarness(_start_module())
    crashed.a3_error = _CrashAfterEffect("A3 process crash")
    with pytest.raises(_CrashAfterEffect, match="A3 process crash"):
        crashed.start()
    assert crashed.start()["status"] == "quarantined"
    assert (
        crashed.start_granted_calls,
        crashed.a3_calls,
        crashed.running_calls,
        crashed.compensation_calls,
        crashed.quarantine_calls,
    ) == (1, 1, 0, 0, 0)


def test_running_journal_unknown_after_a3_return_quarantines_and_never_replays_start() -> (
    None
):
    harness = _StartHarness(_start_module())
    primary = RuntimeError("RUNNING journal outcome unknown")
    harness.running_persists_before_error = True
    harness.running_error = primary

    assert harness.start()["status"] == "quarantined"
    assert harness.running_persisted
    assert harness.start()["status"] == "quarantined"
    assert (
        harness.start_granted_calls,
        harness.a3_calls,
        harness.running_calls,
        harness.compensation_calls,
        harness.quarantine_calls,
    ) == (1, 1, 1, 0, 1)


def test_compensation_callback_failure_preserves_primary_error_and_does_not_retry() -> (
    None
):
    harness = _StartHarness(_start_module())
    primary = RuntimeError("prepare primary")
    harness.prepare_error = primary
    harness.compensation_error = RuntimeError("secondary compensation failure")

    result = harness.start()

    assert result == {
        "status": "not_started",
        "reason": "dynamic_worker_prepare_failed",
    }
    assert harness.compensation_primary == [primary]
    assert (harness.compensation_calls, harness.a3_calls) == (1, 0)
    assert "secondary" not in repr(result)


def test_replay_or_duplicate_never_regrants_or_reexecutes_a3() -> None:
    harness = _StartHarness(_start_module())

    assert harness.start()["status"] == "started"
    assert harness.start() == {
        "status": "quarantined",
        "reason": "dynamic_worker_start_replay_denied",
    }
    assert (
        harness.prepare_calls,
        harness.start_granted_calls,
        harness.a3_calls,
        harness.running_calls,
    ) == (1, 1, 1, 1)


def test_parallel_duplicate_claims_start_exactly_once() -> None:
    harness = _StartHarness(_start_module())
    receipt_line = next(
        line_number
        for line_number, line in enumerate(
            MODULE_PATH.read_text(encoding="utf-8").splitlines(),
            start=1,
        )
        if line.strip() == "receipt = b5_port.receipt"
    )
    start_barrier = Barrier(3)
    release_receipt_line = Event()
    signals: Queue[tuple[str, int, object]] = Queue()

    def invoke(index: int) -> None:
        paused = False

        def trace(frame, event: str, _argument):
            nonlocal paused
            if (
                not paused
                and frame.f_code is harness.module.dynamic_worker_start.__code__
                and event == "line"
                and frame.f_lineno == receipt_line
            ):
                paused = True
                signals.put(("receipt", index, None))
                if not release_receipt_line.wait(timeout=2):
                    raise TimeoutError("parallel receipt-line release timed out")
            return trace

        sys.settrace(trace)
        try:
            start_barrier.wait(timeout=2)
            signals.put(("result", index, harness.start()))
        except BaseException as error:
            signals.put(("error", index, error))
        finally:
            sys.settrace(None)

    threads = [Thread(target=invoke, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    start_barrier.wait(timeout=2)
    observed = []
    try:
        observed.append(signals.get(timeout=2))
        observed.append(signals.get(timeout=2))
    finally:
        release_receipt_line.set()
    for thread in threads:
        thread.join(timeout=2)
        assert not thread.is_alive()
    while not signals.empty():
        observed.append(signals.get_nowait())

    assert not [signal for signal in observed if signal[0] == "error"]
    results = [signal[2] for signal in observed if signal[0] == "result"]
    assert sorted(results, key=lambda result: result["status"]) == [
        {
            "status": "quarantined",
            "reason": "dynamic_worker_start_replay_denied",
        },
        {
            "status": "started",
            "reason": "dynamic_worker_started",
        },
    ]
    assert (
        harness.prepare_calls,
        harness.start_granted_calls,
        harness.a3_calls,
        harness.running_calls,
        harness.compensation_calls,
        harness.quarantine_calls,
    ) == (1, 1, 1, 1, 0, 0)
