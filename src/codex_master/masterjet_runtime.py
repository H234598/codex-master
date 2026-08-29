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
    schema_version = value.get("schema_version")
    if (type(schema_version) is int and schema_version == 2) or (
        not (type(schema_version) is int and schema_version == 1)
        and "reason_code" in value
    ):
        if any(type(key) is not str for key in value):
            return _v2_invalid()
        if set(value) != {"schema_version", "status", "reason_code"}:
            return _v2_invalid()
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 2
            or type(value["status"]) is not str
            or type(value["reason_code"]) is not str
        ):
            return _v2_invalid()
        if (value["status"], value["reason_code"]) == ("started", "none"):
            return {
                "schema_version": 2,
                "status": "started",
                "reason_code": "none",
            }
        if (value["status"], value["reason_code"]) == (
            "unavailable",
            "dynamic_teamlead_runtime_unavailable",
        ):
            return {
                "schema_version": 2,
                "status": "unavailable",
                "reason_code": "dynamic_teamlead_runtime_unavailable",
            }
        return _v2_invalid()
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


def _v2_invalid() -> dict[str, int | str]:
    return {
        "schema_version": 2,
        "status": "unavailable",
        "reason_code": "dynamic_teamlead_root_control_invalid",
    }


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
