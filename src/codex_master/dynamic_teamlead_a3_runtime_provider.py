from __future__ import annotations

from dataclasses import dataclass, field

from codex_master.dynamic_teamlead import prepare_dynamic_teamlead
from codex_master.dynamic_teamlead_a3_registry import FleetV2RegistryOperations
from codex_master.dynamic_teamlead_coordinator import (
    DynamicTeamleadCoordinatorRequest,
    DynamicTeamleadRegistryOperations,
    _check_static_request,
)
from codex_master.dynamic_teamlead_a3_runner import (
    RootDynamicTeamleadRunnerBindingEvidence,
    RootDynamicTeamleadStartComposition,
)
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
_INVALID_COMPOSITION = "invalid_root_owned_dynamic_teamlead_start_composition"
_NONTRANSFERABLE_PORT = "root_owned_dynamic_teamlead_start_port_nontransferable"


class DynamicTeamleadA3RuntimeProviderError(ValueError):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


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
        context.snapshot is not request.snapshot
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


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RootOwnedDynamicTeamleadStartPort:
    request: DynamicTeamleadCoordinatorRequest
    registry_operations: DynamicTeamleadRegistryOperations
    broker_operations: BrokerClientOperations
    _executor: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("root_owned_dynamic_teamlead_start_port_factory_required")

    def __copy__(self) -> RootOwnedDynamicTeamleadStartPort:
        raise DynamicTeamleadA3RuntimeProviderError(_NONTRANSFERABLE_PORT)

    def __deepcopy__(self, memo: object) -> RootOwnedDynamicTeamleadStartPort:
        del memo
        raise DynamicTeamleadA3RuntimeProviderError(_NONTRANSFERABLE_PORT)

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise DynamicTeamleadA3RuntimeProviderError(_NONTRANSFERABLE_PORT)

    def __repr__(self) -> str:
        return "<RootOwnedDynamicTeamleadStartPort redacted>"

    __str__ = __repr__

    def execute_dynamic_teamlead_runner(
        self, plan: DynamicTeamleadRunnerPlan
    ) -> None:
        self._executor.execute_dynamic_teamlead_runner(plan)


def _reject_composition() -> None:
    raise DynamicTeamleadA3RuntimeProviderError(_INVALID_COMPOSITION)


def build_root_owned_dynamic_teamlead_start_port(
    composition: RootDynamicTeamleadStartComposition,
) -> RootOwnedDynamicTeamleadStartPort:
    if type(composition) is not RootDynamicTeamleadStartComposition:
        _reject_composition()
    try:
        request = composition.request
        registry_operations = composition.registry_operations
        broker_operations = composition.broker_operations
        executor = composition.executor
        evidence = composition.evidence
        context = composition.context_identity
        snapshot_identity = composition.snapshot_identity
        release_identity = composition.release_identity
        validate_dynamic_teamlead_a3_runtime_context(context)
        if (
            type(request) is not DynamicTeamleadCoordinatorRequest
            or type(registry_operations) is not FleetV2RegistryOperations
            or type(broker_operations) is not SeqpacketBrokerClientOperations
            or type(evidence) is not RootDynamicTeamleadRunnerBindingEvidence
            or not callable(executor.execute_dynamic_teamlead_runner)
            or executor.binding_evidence is not evidence
            or context.request is not request
            or context.context.snapshot is not snapshot_identity
            or context.release is not release_identity
            or registry_operations._snapshot is not request.snapshot
            or broker_operations.a3_context_identity is not context
            or broker_operations.release_identity is not release_identity
            or evidence.executor_identity is not executor
            or evidence.context_identity is not context.context
            or evidence.snapshot_identity is not snapshot_identity
            or evidence.release_identity is not release_identity
        ):
            _reject_composition()
    except DynamicTeamleadA3RuntimeProviderError:
        raise
    except Exception:
        _reject_composition()

    port = object.__new__(RootOwnedDynamicTeamleadStartPort)
    object.__setattr__(port, "request", request)
    object.__setattr__(port, "registry_operations", registry_operations)
    object.__setattr__(port, "broker_operations", broker_operations)
    object.__setattr__(port, "_executor", executor)
    return port


__all__ = (
    "DynamicTeamleadA3RuntimeContext",
    "DynamicTeamleadA3RuntimeProviderError",
    "RootOwnedDynamicTeamleadStartPort",
    "build_root_owned_dynamic_teamlead_start_port",
    "validate_dynamic_teamlead_a3_runtime_context",
)
