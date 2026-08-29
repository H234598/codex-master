"""Root-owned, read-only systemd runner for Dynamic-Teamlead Control2."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from threading import Lock
from typing import Literal, Protocol

from codex_master.dynamic_teamlead_a3_runner import RootDynamicTeamleadRunnerPermit
from codex_master.fleet_control_release_v2 import ControlReleaseSpecV2
from codex_master.fleet_home_broker_client import AttestedHome
from codex_master.fleet_home_broker_protocol import (
    AttestHomeRequest,
    BindingExpectation,
    BrokerCheckpoint,
    BrokerReply,
    BrokerResultCode,
    ChpbMessageKind,
    HomeAttestation,
    PrincipalBinding,
    validate_chpb_message,
    validate_principal_binding,
)
from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_registry import FleetRuntimePrincipalV2
from codex_master.fleet_runners import DynamicTeamleadRunnerPlan


_MCS = re.compile(r"c(0|[1-9][0-9]{0,3}),c(0|[1-9][0-9]{0,3})\Z", re.ASCII)
_MCS_INSTANCE = re.compile(r"c[0-9]{1,4}\\x2cc[0-9]{1,4}\Z", re.ASCII)


class SystemdManagerOperations(Protocol):
    def start_unit(self, unit: str, mode: Literal["fail"]) -> None: ...

    def unit_is_active(self, unit: str) -> bool: ...


class _DynamicTeamleadSystemdRunnerError(ValueError):
    __slots__ = ()


def _invalid() -> None:
    raise _DynamicTeamleadSystemdRunnerError(
        "dynamic_teamlead_systemd_runner_invalid"
    ) from None


def _validate_release(release: object) -> None:
    if type(release) is not ControlReleaseSpecV2:
        _invalid()
    try:
        ControlReleaseSpecV2(
            release.schema_version,
            release.payload_version,
            release.payloads,
            release.broker_protocol,
            release.system_bus_interface,
            release.system_bus_method,
            release.agent_unit_template,
            release.launcher_path,
        )
    except Exception:
        _invalid()


def _validate_expectation(expectation: object) -> None:
    if type(expectation) is not BindingExpectation:
        _invalid()
    try:
        validate_chpb_message(
            AttestHomeRequest(
                "CHPB/2",
                ChpbMessageKind.ATTEST_HOME,
                "0" * 32,
                "0" * 32,
                expectation,
            )
        )
    except Exception:
        _invalid()


def _unit_for_mcs(mcs_pair: object) -> str:
    if type(mcs_pair) is not str:
        _invalid()
    match = _MCS.fullmatch(mcs_pair)
    if match is None:
        _invalid()
    low = int(match.group(1))
    high = int(match.group(2))
    if not 0 <= low < high <= 1023:
        _invalid()
    instance = f"c{low}\\x2cc{high}"
    if _MCS_INSTANCE.fullmatch(instance) is None:
        _invalid()
    return f"codex-master-agent@{instance}.service"


def _validate_plan(plan: object) -> str:
    if type(plan) is not DynamicTeamleadRunnerPlan:
        _invalid()
    runtime = plan.runtime_principal
    expected = plan.expected_principal
    expectation = plan.expectation
    identity = plan.identity
    home = plan.home
    if type(runtime) is not FleetRuntimePrincipalV2:
        _invalid()
    if type(expected) is not PrincipalBinding:
        _invalid()
    if type(identity) is not BrokerIdentity:
        _invalid()
    if type(home) is not AttestedHome:
        _invalid()
    if type(home.reply) is not BrokerReply or type(home.attestation) is not HomeAttestation:
        _invalid()
    if type(home.fd) is not int or home.fd < 0:
        _invalid()
    try:
        validate_principal_binding(expected)
        _validate_expectation(expectation)
        BrokerIdentity(
            identity.agent_id,
            identity.manifest_generation,
            identity.mcs_pair,
            identity.slot_snapshot,
            identity.policy_generation,
            identity.projection_digest,
            identity.executable_fingerprint,
            identity.fencing_epoch,
        )
        validate_chpb_message(home.reply)
    except Exception:
        _invalid()

    attestation = home.attestation
    binding = attestation.binding
    attested_principal = binding.principal
    attested_policy = binding.policy
    transaction = home.reply.transaction
    if (
        runtime.class_id != "teamleiterin"
        or runtime.lifecycle != "persistent"
        or runtime.enabled is not True
        or runtime.principal_id != expected.agent_id
        or expected.agent_id != expectation.agent_id
        or expected.agent_id != identity.agent_id
        or expected.agent_id != attested_principal.agent_id
        or expected.manifest_generation != expectation.manifest_generation
        or expected.manifest_generation != identity.manifest_generation
        or expected.manifest_generation != attested_principal.manifest_generation
        or expected.unit_generation != expectation.unit_generation
        or expected.unit_generation != attested_principal.unit_generation
        or expected.fencing_epoch != expectation.fencing_epoch
        or expected.fencing_epoch != identity.fencing_epoch
        or expected.fencing_epoch != attested_principal.fencing_epoch
        or expectation.policy_generation != identity.policy_generation
        or expectation.policy_generation != attested_policy.policy_generation
        or expectation.projection_digest != identity.projection_digest
        or expectation.projection_digest != attested_policy.projection_digest
        or expected.mcs_pair != identity.mcs_pair
        or expected.mcs_pair != attested_principal.mcs_pair
        or expected.mcs_pair != attestation.mcs_pair
        or attestation != home.reply.attestation
        or transaction is None
        or transaction.binding != binding
        or home.reply.result is not BrokerResultCode.OK
        or transaction.checkpoint is not BrokerCheckpoint.COMMITTED
    ):
        _invalid()
    return _unit_for_mcs(expected.mcs_pair)


@dataclass(frozen=True, slots=True, repr=False)
class RootSystemdDynamicTeamleadRunnerOperations:
    release: ControlReleaseSpecV2
    systemd: SystemdManagerOperations
    _lock: Lock = field(init=False, repr=False, compare=False)
    _terminal: bool = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_lock", Lock())
        object.__setattr__(self, "_terminal", False)

    def __repr__(self) -> str:
        return "<RootSystemdDynamicTeamleadRunnerOperations redacted>"

    __str__ = __repr__

    def execute(
        self,
        plan: DynamicTeamleadRunnerPlan,
        *,
        permit: RootDynamicTeamleadRunnerPermit,
    ) -> None:
        with self._lock:
            if self._terminal:
                _invalid()
            object.__setattr__(self, "_terminal", True)

        if type(permit) is not RootDynamicTeamleadRunnerPermit:
            _invalid()
        _validate_release(self.release)
        unit = _validate_plan(plan)
        try:
            start_result = self.systemd.start_unit(unit, "fail")
        except Exception:
            _invalid()
        if start_result is not None:
            _invalid()
        try:
            active = self.systemd.unit_is_active(unit)
        except Exception:
            _invalid()
        if type(active) is not bool or active is not True:
            _invalid()


__all__ = (
    "SystemdManagerOperations",
    "RootSystemdDynamicTeamleadRunnerOperations",
)
