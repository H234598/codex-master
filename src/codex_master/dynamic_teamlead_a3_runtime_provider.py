from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from codex_master.dynamic_teamlead import prepare_dynamic_teamlead
from codex_master.dynamic_teamlead_a3_registry import FleetV2RegistryOperations
from codex_master.dynamic_teamlead_coordinator import (
    DynamicTeamleadCoordinatorRequest,
    DynamicTeamleadRegistryOperations,
    _check_static_request,
)
from codex_master.dynamic_teamlead_start import DynamicTeamleadStartA3Port
from codex_master.fleet_home_broker_client import BrokerClientOperations
from codex_master.fleet_home_broker_client_seqpacket import (
    SeqpacketBrokerClientOperations,
)
from codex_master.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    TrustedPrincipalGrantContext,
)
from codex_master.fleet_registry import FleetRuntimePrincipalV2, FleetSnapshotV2
from codex_master.fleet_runners import DynamicTeamleadRunnerPlan


_INVALID_CONTEXT = "invalid_dynamic_teamlead_a3_runtime_context"
_NONTRANSFERABLE_CONTEXT = "dynamic_teamlead_a3_runtime_context_nontransferable"
_INVALID_PORT = "invalid_dynamic_teamlead_a3_runtime_port"
_NONTRANSFERABLE_PORT = "dynamic_teamlead_a3_runtime_port_nontransferable"


class DynamicTeamleadA3RuntimeProviderError(ValueError):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class OneShotDynamicTeamleadRunnerExecutor(Protocol):
    def execute_dynamic_teamlead_runner(
        self, plan: DynamicTeamleadRunnerPlan
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class DynamicTeamleadA3RuntimeContext:
    context: TrustedPrincipalGrantContext
    request: DynamicTeamleadCoordinatorRequest
    release: BrokerReleaseSpec

    def __copy__(self) -> DynamicTeamleadA3RuntimeContext:
        raise DynamicTeamleadA3RuntimeProviderError(_NONTRANSFERABLE_CONTEXT)

    def __deepcopy__(self, memo: object) -> DynamicTeamleadA3RuntimeContext:
        del memo
        raise DynamicTeamleadA3RuntimeProviderError(_NONTRANSFERABLE_CONTEXT)

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise DynamicTeamleadA3RuntimeProviderError(_NONTRANSFERABLE_CONTEXT)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RootOwnedDynamicTeamleadStartPort(DynamicTeamleadStartA3Port):
    request: DynamicTeamleadCoordinatorRequest
    registry_operations: DynamicTeamleadRegistryOperations
    broker_operations: BrokerClientOperations
    _executor: OneShotDynamicTeamleadRunnerExecutor = field(
        repr=False, compare=False
    )

    def __init__(self) -> None:
        raise TypeError("root_owned_dynamic_teamlead_start_port_factory_required")

    def execute_dynamic_teamlead_runner(
        self, plan: DynamicTeamleadRunnerPlan
    ) -> None:
        self._executor.execute_dynamic_teamlead_runner(plan)

    def __copy__(self) -> RootOwnedDynamicTeamleadStartPort:
        raise DynamicTeamleadA3RuntimeProviderError(_NONTRANSFERABLE_PORT)

    def __deepcopy__(self, memo: object) -> RootOwnedDynamicTeamleadStartPort:
        del memo
        raise DynamicTeamleadA3RuntimeProviderError(_NONTRANSFERABLE_PORT)

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise DynamicTeamleadA3RuntimeProviderError(_NONTRANSFERABLE_PORT)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__


def validate_dynamic_teamlead_a3_runtime_context(
    value: DynamicTeamleadA3RuntimeContext,
) -> DynamicTeamleadA3RuntimeContext:
    if type(value) is not DynamicTeamleadA3RuntimeContext:
        raise DynamicTeamleadA3RuntimeProviderError(_INVALID_CONTEXT)
    if (
        type(value.context) is not TrustedPrincipalGrantContext
        or type(value.request) is not DynamicTeamleadCoordinatorRequest
        or type(value.release) is not BrokerReleaseSpec
        or type(value.context.snapshot) is not FleetSnapshotV2
        or value.context.snapshot.schema_version != 2
    ):
        raise DynamicTeamleadA3RuntimeProviderError(_INVALID_CONTEXT)
    release = value.release
    if (
        type(release.joint_release_version) is not int
        or release.joint_release_version != 1
        or release.release_id != "0.11.0"
        or release.chpb_abi != "CHPB/2"
        or release.socket_unit != "codex-master-home-broker.socket"
        or release.service_unit != "codex-master-home-broker.service"
        or release.system_bus_name != "org.codex_master.HomeBrokerControl"
        or release.system_bus_path != "/org/codex_master/HomeBrokerControl"
        or release.system_bus_interface != "org.codex_master.HomeBrokerControl1"
        or release.broker_domain != "codex_master_home_broker_t"
        or release.gateway_domain != "codex_master_control_t"
        or release.socket_type != "codex_master_home_broker_runtime_t"
        or release.agent_domain != "codex_master_agent_t"
        or type(release.policy_abi) is not str
        or not release.policy_abi
        or type(release.provider_abi) is not str
        or not release.provider_abi
        or any(
            type(digest) is not str
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in (
                release.server_digest,
                release.broker_manifest_digest,
                release.unit_digest,
                release.selinux_digest,
            )
        )
    ):
        raise DynamicTeamleadA3RuntimeProviderError(_INVALID_CONTEXT)
    context = value.context
    request = value.request
    try:
        _check_static_request(request)
    except Exception:
        raise DynamicTeamleadA3RuntimeProviderError(_INVALID_CONTEXT) from None
    if (
        type(context.snapshot) is not type(request.snapshot)
        or type(context.selection) is not type(request.selection)
        or type(context.profile_binding) is not type(request.profile_binding)
        or type(context.expected_principal) is not type(request.expected_principal)
        or type(context.identity) is not type(request.identity)
    ):
        raise DynamicTeamleadA3RuntimeProviderError(_INVALID_CONTEXT)
    if (
        context.snapshot != request.snapshot
        or context.selection != request.selection
        or context.profile_binding != request.profile_binding
        or context.expected_principal != request.expected_principal
        or context.identity != request.identity
    ):
        raise DynamicTeamleadA3RuntimeProviderError(_INVALID_CONTEXT)
    try:
        plan = prepare_dynamic_teamlead(
            context.snapshot,
            context.selection,
            context.profile_binding,
        )
    except Exception:
        raise DynamicTeamleadA3RuntimeProviderError(_INVALID_CONTEXT) from None
    if (
        type(request.runtime_principal) is not FleetRuntimePrincipalV2
        or request.runtime_principal != plan.principal
    ):
        raise DynamicTeamleadA3RuntimeProviderError(_INVALID_CONTEXT)
    return value


def build_root_owned_dynamic_teamlead_start_port(
    context: DynamicTeamleadA3RuntimeContext,
    registry_operations: FleetV2RegistryOperations,
    broker_operations: SeqpacketBrokerClientOperations,
    executor: OneShotDynamicTeamleadRunnerExecutor,
) -> RootOwnedDynamicTeamleadStartPort:
    validated = validate_dynamic_teamlead_a3_runtime_context(context)
    if (
        type(registry_operations) is not FleetV2RegistryOperations
        or type(broker_operations) is not SeqpacketBrokerClientOperations
        or registry_operations._snapshot != validated.request.snapshot
        or not callable(
            getattr(executor, "execute_dynamic_teamlead_runner", None)
        )
    ):
        raise DynamicTeamleadA3RuntimeProviderError(_INVALID_PORT)
    port = object.__new__(RootOwnedDynamicTeamleadStartPort)
    object.__setattr__(port, "request", validated.request)
    object.__setattr__(port, "registry_operations", registry_operations)
    object.__setattr__(port, "broker_operations", broker_operations)
    object.__setattr__(port, "_executor", executor)
    return port


__all__ = (
    "DynamicTeamleadA3RuntimeContext",
    "DynamicTeamleadA3RuntimeProviderError",
    "OneShotDynamicTeamleadRunnerExecutor",
    "RootOwnedDynamicTeamleadStartPort",
    "build_root_owned_dynamic_teamlead_start_port",
    "validate_dynamic_teamlead_a3_runtime_context",
)
