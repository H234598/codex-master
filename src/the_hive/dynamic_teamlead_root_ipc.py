from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


class RootControlExchangeOperations(Protocol):
    def call_start_dynamic_teamlead(self) -> tuple[object, ...]: ...


def _invalid_result() -> dict[str, int | str]:
    return {
        "schema_version": 2,
        "status": "unavailable",
        "reason_code": "dynamic_teamlead_root_control_invalid",
    }


def _decode_reply(result: object) -> dict[str, int | str]:
    if type(result) is not tuple or len(result) != 3:
        return _invalid_result()

    schema_version, status, reason_code = result
    if (
        type(schema_version) is not int
        or type(status) is not str
        or type(reason_code) is not str
    ):
        return _invalid_result()

    if (schema_version, status, reason_code) == (2, "started", "none"):
        return {
            "schema_version": 2,
            "status": "started",
            "reason_code": "none",
        }
    if (
        schema_version,
        status,
        reason_code,
    ) == (2, "unavailable", "dynamic_teamlead_runtime_unavailable"):
        return {
            "schema_version": 2,
            "status": "unavailable",
            "reason_code": "dynamic_teamlead_runtime_unavailable",
        }
    return _invalid_result()


@dataclass(frozen=True, slots=True, init=False, eq=False, repr=False)
class SystemBusDynamicTeamleadStartControl:
    _exchange: RootControlExchangeOperations = field(
        init=False, repr=False, compare=False
    )

    def __init__(self, exchange: RootControlExchangeOperations) -> None:
        object.__setattr__(self, "_exchange", exchange)

    def start_dynamic_teamlead(self) -> dict[str, int | str]:
        try:
            operation = getattr(self._exchange, "call_start_dynamic_teamlead")
            if not callable(operation):
                return _invalid_result()
            return _decode_reply(operation())
        except BaseException:
            return _invalid_result()

    def __copy__(self) -> object:
        raise TypeError("control cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> object:
        raise TypeError("control cannot be deep-copied")

    def __reduce__(self) -> object:
        raise TypeError("control cannot be serialized")

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("control cannot be serialized")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("control cannot be subclassed")

    def __repr__(self) -> str:
        return "SystemBusDynamicTeamleadStartControl(<redacted>)"

    def __str__(self) -> str:
        return "SystemBusDynamicTeamleadStartControl(<redacted>)"


__all__ = (
    "RootControlExchangeOperations",
    "SystemBusDynamicTeamleadStartControl",
)
