from __future__ import annotations

from dataclasses import dataclass

from codex_master.dynamic_teamlead import prepare_dynamic_teamlead
from codex_master.dynamic_teamlead_coordinator import (
    DynamicTeamleadCoordinatorRequest,
    _check_static_request,
)
from codex_master.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    TrustedPrincipalGrantContext,
)
from codex_master.fleet_registry import FleetRuntimePrincipalV2, FleetSnapshotV2


_INVALID_CONTEXT = "invalid_dynamic_teamlead_a3_runtime_context"
_NONTRANSFERABLE_CONTEXT = "dynamic_teamlead_a3_runtime_context_nontransferable"


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
    if (
        context.snapshot != request.snapshot
        or context.selection != request.selection
        or context.profile_binding != request.profile_binding
        or context.expected_principal != request.expected_principal
        or context.identity != request.identity
    ):
        raise DynamicTeamleadA3RuntimeProviderError(_INVALID_CONTEXT)
    try:
        _check_static_request(request)
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


__all__ = (
    "DynamicTeamleadA3RuntimeContext",
    "DynamicTeamleadA3RuntimeProviderError",
    "validate_dynamic_teamlead_a3_runtime_context",
)
