"""Fail-closed contract for one pool-only Teamleiterin runtime.

This module owns no registry, resolver, credential bytes, filesystem home, or
broker transport.  It validates the already-resolved selection and requires a
committed CHPB/2 attestation before a caller may publish runtime inventory.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

from .fleet_home_broker_protocol import (
    BindingExpectation,
    BrokerCheckpoint,
    BrokerReply,
    BrokerResultCode,
    HomeAttestation,
    validate_chpb_message,
)
from .fleet_registry import (
    AuthKind,
    FleetAccountV2,
    FleetRuntimePrincipalV2,
    FleetSnapshotV2,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
)


_AGENT_ID = re.compile(r"tl-[0-9a-f]{32}\Z", re.ASCII)
_PROFILE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
_BINDING = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z", re.ASCII)


class DynamicTeamleadCode(str, Enum):
    REGISTRY_V2_REQUIRED = "registry_v2_required"
    STALE_REGISTRY = "stale_registry"
    LEGACY_TARGET_FORBIDDEN = "legacy_target_forbidden"
    ACCOUNT_NOT_FOUND = "account_not_found"
    ACCOUNT_INELIGIBLE = "account_ineligible"
    PROFILE_BINDING_INVALID = "profile_binding_invalid"
    RUNTIME_PRINCIPAL_INVALID = "runtime_principal_invalid"
    PROFILE_IDENTITY_MISMATCH = "profile_identity_mismatch"
    INVALID_CLASS_SELECTION = "invalid_class_selection"
    HOME_BROKER_UNAVAILABLE = "home_broker_unavailable"
    HOME_BROKER_REJECTED = "home_broker_rejected"
    HOME_ATTESTATION_INVALID = "home_attestation_invalid"


class DynamicTeamleadError(ValueError):
    __slots__ = ("code",)

    def __init__(self, code: DynamicTeamleadCode):
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class DynamicTeamleadRequest:
    agent_id: str
    account_id: str
    registry_generation: int
    model: str
    reasoning: str


@dataclass(frozen=True, slots=True)
class ProfileBinding:
    """Opaque registered credential binding plus canonical Codex-Usage id."""

    profile_id: str
    credential_binding_id: str


@dataclass(frozen=True, slots=True)
class DynamicTeamleadPlan:
    request: DynamicTeamleadRequest
    profile_binding: ProfileBinding
    principal: FleetRuntimePrincipalV2
    class_id: str = "teamleiterin"
    lifecycle: str = "persistent"


def _fail(code: DynamicTeamleadCode) -> None:
    raise DynamicTeamleadError(code)


def _valid_binding(value: object) -> str:
    if type(value) is not str or _BINDING.fullmatch(value) is None:
        _fail(DynamicTeamleadCode.PROFILE_BINDING_INVALID)
    return value


def _valid_profile_id(value: object) -> str:
    if type(value) is not str or _PROFILE_ID.fullmatch(value) is None:
        _fail(DynamicTeamleadCode.PROFILE_BINDING_INVALID)
    return value


def _valid_request(value: object) -> DynamicTeamleadRequest:
    if type(value) is not DynamicTeamleadRequest:
        _fail(DynamicTeamleadCode.INVALID_CLASS_SELECTION)
    if type(value.agent_id) is not str or _AGENT_ID.fullmatch(value.agent_id) is None:
        _fail(DynamicTeamleadCode.LEGACY_TARGET_FORBIDDEN)
    if type(value.account_id) is not str or not value.account_id:
        _fail(DynamicTeamleadCode.ACCOUNT_NOT_FOUND)
    if type(value.registry_generation) is not int or value.registry_generation < 1:
        _fail(DynamicTeamleadCode.STALE_REGISTRY)
    return value


def _valid_profile_binding(value: object) -> ProfileBinding:
    if type(value) is not ProfileBinding:
        _fail(DynamicTeamleadCode.PROFILE_BINDING_INVALID)
    _valid_profile_id(value.profile_id)
    _valid_binding(value.credential_binding_id)
    return value


def _account(snapshot: FleetSnapshotV2, account_id: str) -> FleetAccountV2:
    account = next((item for item in snapshot.accounts if item.account_id == account_id), None)
    if type(account) is not FleetAccountV2:
        _fail(DynamicTeamleadCode.ACCOUNT_NOT_FOUND)
    return account


def _eligible_account(account: FleetAccountV2) -> FleetAccountV2:
    if (
        account.provider is not Provider.OPENAI_CHATGPT
        or account.auth_kind is not AuthKind.CHATGPT_SESSION
        or account.secret_state is not SecretState.CONFIGURED
        or account.limit_state is not LimitState.READY
        or account.enabled is not True
    ):
        _fail(DynamicTeamleadCode.ACCOUNT_INELIGIBLE)
    return account


def _runtime_principal(snapshot: FleetSnapshotV2, agent_id: str) -> FleetRuntimePrincipalV2:
    principals = snapshot.runtime_principals
    matches = tuple(
        item
        for item in principals
        if getattr(item, "principal_id", object()) == agent_id
    )
    if len(matches) != 1 or type(matches[0]) is not FleetRuntimePrincipalV2:
        _fail(DynamicTeamleadCode.RUNTIME_PRINCIPAL_INVALID)
    return matches[0]


def prepare_dynamic_teamlead(
    snapshot: object,
    request: object,
    profile_binding: object,
) -> DynamicTeamleadPlan:
    """Validate already-resolved dynamic Teamleiterin inputs without I/O.

    Account choice belongs to existing resolver/routing. This function only
    verifies its result; it cannot fall back to a series, another account, or
    another model.
    """

    if type(snapshot) is not FleetSnapshotV2 or snapshot.schema_version != 2:
        _fail(DynamicTeamleadCode.REGISTRY_V2_REQUIRED)
    selected = _valid_request(request)
    binding = _valid_profile_binding(profile_binding)
    if snapshot.generation != selected.registry_generation:
        _fail(DynamicTeamleadCode.STALE_REGISTRY)
    principal = _runtime_principal(snapshot, selected.agent_id)
    account = _account(snapshot, selected.account_id)
    _valid_binding(account.credential_binding_id)
    if (
        principal.principal_id != selected.agent_id
        or principal.account_id != selected.account_id
        or principal.account_id != account.account_id
        or account.account_id != selected.account_id
        or principal.profile_id != binding.profile_id
        or principal.credential_binding_id != binding.credential_binding_id
        or principal.credential_binding_id != account.credential_binding_id
        or account.credential_binding_id != binding.credential_binding_id
    ):
        _fail(DynamicTeamleadCode.PROFILE_IDENTITY_MISMATCH)
    if (
        selected.model != "gpt-5.6-terra"
        or selected.reasoning != "xhigh"
        or principal.class_id != "teamleiterin"
        or principal.lifecycle != "persistent"
        or principal.provider is not Provider.OPENAI_CHATGPT
        or principal.runner is not RunnerKind.CODEX_CLI
        or principal.model != "gpt-5.6-terra"
        or principal.reasoning != "xhigh"
    ):
        _fail(DynamicTeamleadCode.INVALID_CLASS_SELECTION)
    if principal.enabled is not True:
        _fail(DynamicTeamleadCode.RUNTIME_PRINCIPAL_INVALID)
    _eligible_account(account)
    return DynamicTeamleadPlan(selected, binding, principal)


def require_committed_home_attestation(
    reply: object,
    expected: object,
) -> HomeAttestation:
    """Accept only a CHPB/2 committed, exactly bound home attestation."""

    if reply is None:
        _fail(DynamicTeamleadCode.HOME_BROKER_UNAVAILABLE)
    if type(reply) is not BrokerReply or type(expected) is not BindingExpectation:
        _fail(DynamicTeamleadCode.HOME_ATTESTATION_INVALID)
    try:
        validate_chpb_message(reply)
    except ValueError:
        _fail(DynamicTeamleadCode.HOME_ATTESTATION_INVALID)
    if reply.result is BrokerResultCode.UNSUPPORTED_PLATFORM:
        _fail(DynamicTeamleadCode.HOME_BROKER_UNAVAILABLE)
    if reply.result is not BrokerResultCode.OK:
        _fail(DynamicTeamleadCode.HOME_BROKER_REJECTED)
    transaction = reply.transaction
    attestation = reply.attestation
    if (
        transaction is None
        or attestation is None
        or transaction.checkpoint is not BrokerCheckpoint.COMMITTED
        or transaction.binding.principal.agent_id != expected.agent_id
        or transaction.binding.principal.manifest_generation != expected.manifest_generation
        or transaction.binding.principal.unit_generation != expected.unit_generation
        or transaction.binding.principal.fencing_epoch != expected.fencing_epoch
        or transaction.binding.policy.policy_generation != expected.policy_generation
        or transaction.binding.policy.projection_digest != expected.projection_digest
        or attestation.binding != transaction.binding
    ):
        _fail(DynamicTeamleadCode.HOME_ATTESTATION_INVALID)
    return attestation
