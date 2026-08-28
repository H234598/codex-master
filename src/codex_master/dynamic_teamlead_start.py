from __future__ import annotations

from typing import Protocol

from codex_master.dynamic_teamlead_coordinator import (
    DynamicTeamleadCoordinatorRequest,
    DynamicTeamleadRegistryOperations,
    coordinate_dynamic_teamlead,
)
from codex_master.fleet_home_broker_client import BrokerClientOperations
from codex_master.fleet_runners import (
    DynamicTeamleadRunnerPlan,
    prepare_dynamic_teamlead_runner,
)


class DynamicTeamleadStartA3Port(Protocol):
    request: DynamicTeamleadCoordinatorRequest
    registry_operations: DynamicTeamleadRegistryOperations
    broker_operations: BrokerClientOperations

    def execute_dynamic_teamlead_runner(
        self, plan: DynamicTeamleadRunnerPlan
    ) -> None: ...


def dynamic_teamlead_start(
    a3_port: DynamicTeamleadStartA3Port | None = None,
) -> dict[str, int | str]:
    if a3_port is None:
        return {
            "schema_version": 1,
            "status": "unavailable",
            "reason": "dynamic_teamlead_runtime_unavailable",
            "raw_output": "not_returned",
        }
    try:
        request = a3_port.request
        registry_operations = a3_port.registry_operations
        broker_operations = a3_port.broker_operations
        executor = a3_port.execute_dynamic_teamlead_runner
    except AttributeError:
        return {
            "schema_version": 1,
            "status": "unavailable",
            "reason": "dynamic_teamlead_runtime_unavailable",
            "raw_output": "not_returned",
        }
    if not callable(executor):
        return {
            "schema_version": 1,
            "status": "unavailable",
            "reason": "dynamic_teamlead_runtime_unavailable",
            "raw_output": "not_returned",
        }
    launch = coordinate_dynamic_teamlead(
        request, registry_operations, broker_operations
    )
    runner = prepare_dynamic_teamlead_runner(launch)
    executor(runner)
    return {"schema_version": 1, "status": "started", "raw_output": "not_returned"}


__all__ = ["DynamicTeamleadStartA3Port", "dynamic_teamlead_start"]
