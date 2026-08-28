from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


def _unavailable() -> dict[str, int | str]:
    return {
        "schema_version": 1,
        "status": "unavailable",
        "reason": "dynamic_teamlead_runtime_unavailable",
        "raw_output": "not_returned",
    }


def _sparse_result(value: object) -> dict[str, int | str]:
    if type(value) is not dict:
        return _unavailable()
    if any(type(key) is not str for key in value):
        return _unavailable()
    if type(value.get("schema_version")) is not int:
        return _unavailable()
    if (
        value["schema_version"] != 1
        or type(value.get("status")) is not str
        or type(value.get("raw_output")) is not str
    ):
        return _unavailable()
    if value["status"] == "started":
        if set(value) != {"schema_version", "status", "raw_output"}:
            return _unavailable()
    elif value["status"] == "unavailable":
        if set(value) != {
            "schema_version",
            "status",
            "reason",
            "raw_output",
        }:
            return _unavailable()
        if (
            type(value.get("reason")) is not str
            or value.get("reason") != "dynamic_teamlead_runtime_unavailable"
        ):
            return _unavailable()
    else:
        return _unavailable()
    if value.get("raw_output") != "not_returned":
        return _unavailable()
    if value["status"] == "started":
        return {
            "schema_version": 1,
            "status": "started",
            "raw_output": "not_returned",
        }
    return _unavailable()


class DynamicTeamleadStartControl(Protocol):
    def start_dynamic_teamlead(self) -> dict[str, int | str]: ...


@dataclass(frozen=True, slots=True)
class MasterjetRuntime:
    dynamic_teamlead_control: DynamicTeamleadStartControl | None

    def start_dynamic_teamlead(self) -> dict[str, int | str]:
        if self.dynamic_teamlead_control is None:
            return _unavailable()
        try:
            start = getattr(self.dynamic_teamlead_control, "start_dynamic_teamlead")
            if not callable(start):
                return _unavailable()
            return _sparse_result(start())
        except BaseException:
            return _unavailable()


__all__ = ("DynamicTeamleadStartControl", "MasterjetRuntime")
