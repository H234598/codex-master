from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from threading import Lock

from codex_master.dynamic_worker_coordinator import (
    DynamicWorkerPreStartPortV1,
    PreStartReceiptV1,
)


class _RedactedNonSerializable:
    __slots__ = ()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("dynamic worker start internals are not serializable")


@dataclass(frozen=True, slots=True, repr=False)
class _DynamicWorkerStartB5Port(_RedactedNonSerializable):
    pre_start_port: DynamicWorkerPreStartPortV1
    receipt: PreStartReceiptV1
    prepare: Callable[[PreStartReceiptV1], object]
    record_start_granted: Callable[[PreStartReceiptV1], object]
    record_running: Callable[[PreStartReceiptV1], object]
    compensate_not_started: Callable[[PreStartReceiptV1, Exception], object]
    quarantine_unknown_or_started: Callable[[PreStartReceiptV1, Exception], object]
    _state: set[str] = field(
        default_factory=set,
        init=False,
        repr=False,
        compare=False,
    )
    _seal: _RedactedNonSerializable = field(
        default_factory=_RedactedNonSerializable,
        init=False,
        repr=False,
        compare=False,
    )
    _claim_lock: Lock = field(
        default_factory=Lock,
        init=False,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True, slots=True, repr=False)
class _DynamicWorkerStartA3Port(_RedactedNonSerializable):
    receipt: PreStartReceiptV1
    execute: Callable[[PreStartReceiptV1], None]
    _seal: _RedactedNonSerializable = field(
        default_factory=_RedactedNonSerializable,
        init=False,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True, slots=True, repr=False)
class _DynamicWorkerStartResult(_RedactedNonSerializable):
    status: str
    reason: str

    def to_public(self) -> dict[str, str]:
        return {"status": self.status, "reason": self.reason}


def dynamic_worker_start(
    b5_port: object,
    a3_port: object,
) -> dict[str, str]:
    if not (
        type(b5_port) is _DynamicWorkerStartB5Port
        and type(a3_port) is _DynamicWorkerStartA3Port
        and type(b5_port.pre_start_port) is DynamicWorkerPreStartPortV1
        and type(b5_port.receipt) is PreStartReceiptV1
        and a3_port.receipt is b5_port.receipt
        and callable(b5_port.prepare)
        and callable(b5_port.record_start_granted)
        and callable(b5_port.record_running)
        and callable(b5_port.compensate_not_started)
        and callable(b5_port.quarantine_unknown_or_started)
        and callable(a3_port.execute)
        and type(b5_port._state) is set
    ):
        return _DynamicWorkerStartResult(
            status="denied",
            reason="dynamic_worker_start_port_denied",
        ).to_public()

    if not b5_port._claim_lock.acquire(blocking=False):
        return _DynamicWorkerStartResult(
            status="quarantined",
            reason="dynamic_worker_start_replay_denied",
        ).to_public()
    try:
        if b5_port._state:
            return _DynamicWorkerStartResult(
                status="quarantined",
                reason="dynamic_worker_start_replay_denied",
            ).to_public()
        b5_port._state.add("entered")
    finally:
        b5_port._claim_lock.release()

    receipt = b5_port.receipt
    b5_port._state.add("prepare_attempted")
    try:
        prepared = b5_port.prepare(receipt)
    except Exception as primary:
        b5_port._state.add("compensation_attempted")
        try:
            b5_port.compensate_not_started(receipt, primary)
        except Exception:
            b5_port._state.add("compensation_failed")
        b5_port._state.add("finished")
        return _DynamicWorkerStartResult(
            status="not_started",
            reason="dynamic_worker_prepare_failed",
        ).to_public()

    if prepared is False:
        primary = RuntimeError("dynamic worker prepare denied")
        b5_port._state.add("compensation_attempted")
        try:
            b5_port.compensate_not_started(receipt, primary)
        except Exception:
            b5_port._state.add("compensation_failed")
        b5_port._state.add("finished")
        return _DynamicWorkerStartResult(
            status="not_started",
            reason="dynamic_worker_prepare_denied",
        ).to_public()
    if prepared is not True:
        primary = RuntimeError("dynamic worker prepare outcome unknown")
        b5_port._state.add("quarantine_attempted")
        try:
            b5_port.quarantine_unknown_or_started(receipt, primary)
        except Exception:
            b5_port._state.add("quarantine_failed")
        b5_port._state.add("quarantined")
        return _DynamicWorkerStartResult(
            status="quarantined",
            reason="dynamic_worker_prepare_outcome_unknown",
        ).to_public()

    b5_port._state.add("prepared")
    b5_port._state.add("start_granted_attempted")
    try:
        start_granted = b5_port.record_start_granted(receipt)
    except Exception as primary:
        b5_port._state.add("quarantine_attempted")
        try:
            b5_port.quarantine_unknown_or_started(receipt, primary)
        except Exception:
            b5_port._state.add("quarantine_failed")
        b5_port._state.add("quarantined")
        return _DynamicWorkerStartResult(
            status="quarantined",
            reason="dynamic_worker_start_grant_outcome_unknown",
        ).to_public()

    if start_granted is False:
        primary = RuntimeError("dynamic worker start grant denied")
        b5_port._state.add("compensation_attempted")
        try:
            b5_port.compensate_not_started(receipt, primary)
        except Exception:
            b5_port._state.add("compensation_failed")
        b5_port._state.add("finished")
        return _DynamicWorkerStartResult(
            status="not_started",
            reason="dynamic_worker_start_grant_denied",
        ).to_public()
    if start_granted is not True:
        primary = RuntimeError("dynamic worker start grant outcome unknown")
        b5_port._state.add("quarantine_attempted")
        try:
            b5_port.quarantine_unknown_or_started(receipt, primary)
        except Exception:
            b5_port._state.add("quarantine_failed")
        b5_port._state.add("quarantined")
        return _DynamicWorkerStartResult(
            status="quarantined",
            reason="dynamic_worker_start_grant_outcome_unknown",
        ).to_public()

    b5_port._state.add("start_granted")
    b5_port._state.add("a3_entered")
    try:
        a3_port.execute(receipt)
    except Exception as primary:
        b5_port._state.add("quarantine_attempted")
        try:
            b5_port.quarantine_unknown_or_started(receipt, primary)
        except Exception:
            b5_port._state.add("quarantine_failed")
        b5_port._state.add("quarantined")
        return _DynamicWorkerStartResult(
            status="quarantined",
            reason="dynamic_worker_a3_outcome_unknown",
        ).to_public()

    b5_port._state.add("a3_returned")
    b5_port._state.add("running_attempted")
    try:
        running = b5_port.record_running(receipt)
    except Exception as primary:
        b5_port._state.add("quarantine_attempted")
        try:
            b5_port.quarantine_unknown_or_started(receipt, primary)
        except Exception:
            b5_port._state.add("quarantine_failed")
        b5_port._state.add("quarantined")
        return _DynamicWorkerStartResult(
            status="quarantined",
            reason="dynamic_worker_running_outcome_unknown",
        ).to_public()
    if running is not True:
        primary = RuntimeError("dynamic worker running outcome unknown")
        b5_port._state.add("quarantine_attempted")
        try:
            b5_port.quarantine_unknown_or_started(receipt, primary)
        except Exception:
            b5_port._state.add("quarantine_failed")
        b5_port._state.add("quarantined")
        return _DynamicWorkerStartResult(
            status="quarantined",
            reason="dynamic_worker_running_outcome_unknown",
        ).to_public()

    b5_port._state.add("running")
    return _DynamicWorkerStartResult(
        status="started",
        reason="dynamic_worker_started",
    ).to_public()


__all__ = ["dynamic_worker_start"]
