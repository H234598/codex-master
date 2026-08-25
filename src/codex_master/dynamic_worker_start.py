from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


class _RedactedNonSerializable:
    __slots__ = ()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("dynamic worker start internals are not serializable")


@dataclass(frozen=True, slots=True, repr=False)
class _DynamicWorkerStartB5Port(_RedactedNonSerializable):
    coordinate: Callable[[], object]
    prepare: Callable[[object], object]


@dataclass(frozen=True, slots=True, repr=False)
class _DynamicWorkerStartA3Port(_RedactedNonSerializable):
    execute: Callable[[object], None]


@dataclass(frozen=True, slots=True, repr=False)
class _DynamicWorkerStartResult(_RedactedNonSerializable):
    status: str
    reason: str

    def to_public(self) -> dict[str, str]:
        return {"status": self.status, "reason": self.reason}


def dynamic_worker_start(
    b5_port: object | None = None,
    a3_port: object | None = None,
) -> dict[str, str]:
    if not (
        isinstance(b5_port, _DynamicWorkerStartB5Port)
        and isinstance(a3_port, _DynamicWorkerStartA3Port)
        and callable(b5_port.coordinate)
        and callable(b5_port.prepare)
        and callable(a3_port.execute)
    ):
        return _DynamicWorkerStartResult(
            status="unavailable",
            reason="dynamic_worker_runtime_unavailable",
        ).to_public()

    launch = b5_port.coordinate()
    runner = b5_port.prepare(launch)
    a3_port.execute(runner)
    return _DynamicWorkerStartResult(
        status="started",
        reason="dynamic_worker_started",
    ).to_public()


__all__ = ["dynamic_worker_start"]
