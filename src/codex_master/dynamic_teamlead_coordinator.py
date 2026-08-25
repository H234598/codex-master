from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol

from codex_master.dynamic_teamlead import (
    DynamicTeamleadCode,
    DynamicTeamleadError,
    DynamicTeamleadPlan,
    DynamicTeamleadRequest,
    ProfileBinding,
    prepare_dynamic_teamlead,
    require_committed_home_attestation,
)
from codex_master.fleet_home_broker_client import (
    AttestedHome,
    BrokerClientOperations,
    receive_attested_home,
    receive_transaction_reply,
)
from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_home_broker_protocol import (
    AttestHomeRequest,
    BindingExpectation,
    BrokerCheckpoint,
    BrokerReply,
    BrokerResultCode,
    ChpbTransactionOperation,
    GetTerminalResultRequest,
    HomeAttestation,
    PolicyBinding,
    PrincipalBinding,
    ProvisionHomeRequest,
    ReplaceHomeRequest,
    TransactionBinding,
    TransactionStatus,
    validate_chpb_message,
    validate_principal_binding,
    validate_transaction_binding,
)
from codex_master.fleet_registry import (
    FleetRuntimePrincipalV2,
    FleetSnapshotV2,
    plan_runtime_principal_upsert,
)


MAX_DYNAMIC_TEAMLEAD_TERMINAL_POLLS = 3


class DynamicTeamleadCoordinatorCode(str, Enum):
    INVALID_REQUEST = "invalid_request"
    RUNTIME_PRINCIPAL_CONFLICT = "runtime_principal_conflict"
    BROKER_TRANSACTION_FAILED = "broker_transaction_failed"
    BROKER_TERMINAL_PENDING = "broker_terminal_pending"
    BROKER_TERMINAL_REJECTED = "broker_terminal_rejected"
    HOME_BINDING_DRIFT = "home_binding_drift"
    REGISTRY_CAS_FAILED = "registry_cas_failed"


class DynamicTeamleadCoordinatorError(ValueError):
    __slots__ = ("code",)

    def __init__(self, code: DynamicTeamleadCoordinatorCode):
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class DynamicTeamleadCoordinatorRequest:
    snapshot: FleetSnapshotV2
    selection: DynamicTeamleadRequest
    profile_binding: ProfileBinding
    runtime_principal: FleetRuntimePrincipalV2
    expected_principal: PrincipalBinding
    identity: BrokerIdentity
    mutation: ProvisionHomeRequest | ReplaceHomeRequest
    terminal_requests: tuple[GetTerminalResultRequest, ...]
    attestation: AttestHomeRequest


@dataclass(frozen=True, slots=True)
class DynamicTeamleadLaunchPlan:
    teamlead: DynamicTeamleadPlan
    snapshot: FleetSnapshotV2
    expected_principal: PrincipalBinding
    expectation: BindingExpectation
    identity: BrokerIdentity
    home: AttestedHome


class DynamicTeamleadRegistryOperations(Protocol):
    def commit_snapshot(
        self, snapshot: FleetSnapshotV2, *, expected_generation: int
    ) -> FleetSnapshotV2: ...


def _fail(code: DynamicTeamleadCoordinatorCode) -> None:
    raise DynamicTeamleadCoordinatorError(code)


def _close_home(operations: BrokerClientOperations, home: object) -> None:
    try:
        fd = home.fd
    except Exception:
        return
    if type(fd) is not int or fd < 0:
        return
    try:
        operations.close(fd)
    except Exception:
        pass


def _check_identity(request: DynamicTeamleadCoordinatorRequest) -> None:
    if type(request.identity) is not BrokerIdentity:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    try:
        BrokerIdentity(
            request.identity.agent_id,
            request.identity.manifest_generation,
            request.identity.mcs_pair,
            request.identity.slot_snapshot,
            request.identity.policy_generation,
            request.identity.projection_digest,
            request.identity.executable_fingerprint,
            request.identity.fencing_epoch,
        )
        validate_principal_binding(request.expected_principal)
    except Exception:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if (
        request.identity.agent_id != request.expected_principal.agent_id
        or request.identity.manifest_generation
        != request.expected_principal.manifest_generation
        or request.identity.mcs_pair != request.expected_principal.mcs_pair
        or request.identity.fencing_epoch != request.expected_principal.fencing_epoch
    ):
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)


def _check_requests(request: DynamicTeamleadCoordinatorRequest) -> None:
    mutation = request.mutation
    terminals = request.terminal_requests
    attest = request.attestation
    if type(terminals) is not tuple:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if not 0 <= len(terminals) <= MAX_DYNAMIC_TEAMLEAD_TERMINAL_POLLS:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if type(mutation) not in (ProvisionHomeRequest, ReplaceHomeRequest):
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if type(attest) is not AttestHomeRequest:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if any(type(item) is not GetTerminalResultRequest for item in terminals):
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    try:
        validate_chpb_message(mutation)
        for terminal in terminals:
            validate_chpb_message(terminal)
        validate_chpb_message(attest)
        validate_transaction_binding(mutation.binding)
    except Exception:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)

    messages = (mutation, *terminals, attest)
    request_ids = tuple(item.request_id for item in messages)
    transaction_ids = tuple(item.transaction_id for item in messages)
    expectations = tuple(item.expected for item in messages)
    if len(request_ids) != len(set(request_ids)):
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if len(set(transaction_ids)) != 1 or len(set(expectations)) != 1:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if mutation.binding.principal != request.expected_principal:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    expected_policy = PolicyBinding(
        request.identity.policy_generation,
        request.identity.projection_digest,
    )
    if (
        mutation.binding.operation
        not in (
            ChpbTransactionOperation.PROVISION,
            ChpbTransactionOperation.REPLACE,
        )
        or mutation.binding.policy != expected_policy
        or mutation.expected.policy_generation != expected_policy.policy_generation
        or mutation.expected.projection_digest != expected_policy.projection_digest
        or mutation.expected.agent_id != request.expected_principal.agent_id
        or mutation.expected.manifest_generation
        != request.expected_principal.manifest_generation
        or mutation.expected.unit_generation
        != request.expected_principal.unit_generation
        or mutation.expected.fencing_epoch != request.expected_principal.fencing_epoch
    ):
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if mutation.binding.operation is not (
        ChpbTransactionOperation.PROVISION
        if type(mutation) is ProvisionHomeRequest
        else ChpbTransactionOperation.REPLACE
    ):
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)


def _check_static_request(request: DynamicTeamleadCoordinatorRequest) -> None:
    if type(request.snapshot) is not FleetSnapshotV2:
        try:
            prepare_dynamic_teamlead(
                request.snapshot, request.selection, request.profile_binding
            )
        except DynamicTeamleadError as exc:
            if exc.code is DynamicTeamleadCode.REGISTRY_V2_REQUIRED:
                raise
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if (
        type(request.snapshot.schema_version) is not int
        or request.snapshot.schema_version != 2
    ):
        try:
            prepare_dynamic_teamlead(
                request.snapshot, request.selection, request.profile_binding
            )
        except DynamicTeamleadError as exc:
            if exc.code is DynamicTeamleadCode.REGISTRY_V2_REQUIRED:
                raise
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if type(request.selection) is not DynamicTeamleadRequest:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if type(request.profile_binding) is not ProfileBinding:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if (
        type(request.snapshot.generation) is not int
        or request.snapshot.generation < 1
        or type(request.selection.registry_generation) is not int
        or request.selection.registry_generation != request.snapshot.generation
    ):
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if type(request.runtime_principal) is not FleetRuntimePrincipalV2:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if type(request.expected_principal) is not PrincipalBinding:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if request.selection.agent_id != request.runtime_principal.principal_id:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if request.selection.agent_id != request.expected_principal.agent_id:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    _check_identity(request)
    _check_requests(request)


def _prepare(
    request: DynamicTeamleadCoordinatorRequest,
) -> tuple[DynamicTeamleadPlan, FleetSnapshotV2, bool]:
    matches = tuple(
        item
        for item in request.snapshot.runtime_principals
        if getattr(item, "principal_id", object())
        == request.runtime_principal.principal_id
    )
    if len(matches) > 1:
        _fail(DynamicTeamleadCoordinatorCode.RUNTIME_PRINCIPAL_CONFLICT)
    if matches and matches[0] != request.runtime_principal:
        _fail(DynamicTeamleadCoordinatorCode.RUNTIME_PRINCIPAL_CONFLICT)
    if matches:
        try:
            prepared = prepare_dynamic_teamlead(
                request.snapshot, request.selection, request.profile_binding
            )
        except DynamicTeamleadError as exc:
            if exc.code is DynamicTeamleadCode.REGISTRY_V2_REQUIRED:
                raise
            _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
        return prepared, request.snapshot, False
    try:
        planned = plan_runtime_principal_upsert(
            request.snapshot,
            request.runtime_principal,
            expected_generation=request.snapshot.generation,
        )
    except Exception:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if (
        type(planned) is not FleetSnapshotV2
        or planned.schema_version != 2
        or planned.generation != request.snapshot.generation + 1
    ):
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    effective_selection = replace(
        request.selection, registry_generation=planned.generation
    )
    try:
        prepared = prepare_dynamic_teamlead(
            planned, effective_selection, request.profile_binding
        )
    except DynamicTeamleadError as exc:
        if exc.code is DynamicTeamleadCode.REGISTRY_V2_REQUIRED:
            raise
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    return prepared, planned, True


def _transaction_status(
    reply: object,
    binding: TransactionBinding,
) -> TransactionStatus:
    if (
        type(reply) is not BrokerReply
        or type(reply.transaction) is not TransactionStatus
    ):
        _fail(DynamicTeamleadCoordinatorCode.BROKER_TRANSACTION_FAILED)
    try:
        validate_chpb_message(reply)
    except Exception:
        _fail(DynamicTeamleadCoordinatorCode.BROKER_TRANSACTION_FAILED)
    if reply.transaction.binding != binding:
        _fail(DynamicTeamleadCoordinatorCode.BROKER_TRANSACTION_FAILED)
    return reply.transaction


def _receive_transaction(
    broker_operations: BrokerClientOperations,
    request: ProvisionHomeRequest | ReplaceHomeRequest | GetTerminalResultRequest,
    expected_principal: PrincipalBinding,
    binding: TransactionBinding,
) -> BrokerReply:
    try:
        reply = receive_transaction_reply(
            request, expected_principal, broker_operations
        )
    except Exception:
        _fail(DynamicTeamleadCoordinatorCode.BROKER_TRANSACTION_FAILED)
    _transaction_status(reply, binding)
    return reply


def _is_pending(reply: BrokerReply, binding: TransactionBinding) -> bool:
    status = _transaction_status(reply, binding)
    return reply.result is BrokerResultCode.PENDING and status.terminal_result is None


def _is_committed(reply: BrokerReply, binding: TransactionBinding) -> bool:
    status = _transaction_status(reply, binding)
    return (
        reply.result is BrokerResultCode.COMMITTED
        and status.checkpoint is BrokerCheckpoint.COMMITTED
        and status.terminal_result is BrokerResultCode.COMMITTED
    )


def _wait_for_commit(
    request: DynamicTeamleadCoordinatorRequest,
    broker_operations: BrokerClientOperations,
) -> None:
    mutation = request.mutation
    binding = mutation.binding
    first = _receive_transaction(
        broker_operations,
        mutation,
        request.expected_principal,
        binding,
    )
    if _is_committed(first, binding):
        return
    if not _is_pending(first, binding):
        _fail(DynamicTeamleadCoordinatorCode.BROKER_TRANSACTION_FAILED)
    for terminal in request.terminal_requests:
        reply = _receive_transaction(
            broker_operations,
            terminal,
            request.expected_principal,
            binding,
        )
        if _is_committed(reply, binding):
            return
        if _is_pending(reply, binding):
            continue
        if reply.result is not BrokerResultCode.PENDING:
            _fail(DynamicTeamleadCoordinatorCode.BROKER_TERMINAL_REJECTED)
        _fail(DynamicTeamleadCoordinatorCode.BROKER_TRANSACTION_FAILED)
    _fail(DynamicTeamleadCoordinatorCode.BROKER_TERMINAL_PENDING)


def _receive_home(
    request: DynamicTeamleadCoordinatorRequest,
    broker_operations: BrokerClientOperations,
) -> AttestedHome:
    home = None
    binding = request.mutation.binding
    try:
        home = receive_attested_home(
            request.attestation,
            request.expected_principal,
            broker_operations,
        )
        if type(home) is not AttestedHome:
            _fail(DynamicTeamleadCoordinatorCode.HOME_BINDING_DRIFT)
        committed_attestation = require_committed_home_attestation(
            home.reply, request.attestation.expected
        )
        if (
            type(home.fd) is not int
            or home.fd < 0
            or type(home.reply) is not BrokerReply
            or type(home.reply.transaction) is not TransactionStatus
            or type(home.attestation) is not HomeAttestation
            or type(home.reply.attestation) is not HomeAttestation
            or committed_attestation != home.attestation
            or home.reply.transaction.binding != binding
            or home.attestation.binding != binding
            or home.reply.attestation != home.attestation
        ):
            _fail(DynamicTeamleadCoordinatorCode.HOME_BINDING_DRIFT)
        return home
    except DynamicTeamleadCoordinatorError:
        if home is not None:
            _close_home(broker_operations, home)
        raise
    except Exception:
        if home is not None:
            _close_home(broker_operations, home)
        _fail(DynamicTeamleadCoordinatorCode.HOME_BINDING_DRIFT)


def _commit_registry(
    request: DynamicTeamleadCoordinatorRequest,
    broker_operations: BrokerClientOperations,
    registry_operations: DynamicTeamleadRegistryOperations,
    home: AttestedHome,
    planned: FleetSnapshotV2,
) -> FleetSnapshotV2:
    try:
        stored = registry_operations.commit_snapshot(
            planned,
            expected_generation=request.snapshot.generation,
        )
        if type(stored) is not FleetSnapshotV2 or stored.schema_version != 2:
            _fail(DynamicTeamleadCoordinatorCode.REGISTRY_CAS_FAILED)
        if stored.generation != planned.generation or stored != planned:
            _fail(DynamicTeamleadCoordinatorCode.REGISTRY_CAS_FAILED)
        matches = tuple(
            item
            for item in stored.runtime_principals
            if getattr(item, "principal_id", object())
            == request.runtime_principal.principal_id
        )
        if len(matches) != 1 or matches[0] != request.runtime_principal:
            _fail(DynamicTeamleadCoordinatorCode.REGISTRY_CAS_FAILED)
        return stored
    except DynamicTeamleadCoordinatorError:
        _close_home(broker_operations, home)
        raise
    except Exception:
        _close_home(broker_operations, home)
        _fail(DynamicTeamleadCoordinatorCode.REGISTRY_CAS_FAILED)


def coordinate_dynamic_teamlead(
    request: DynamicTeamleadCoordinatorRequest,
    registry_operations: DynamicTeamleadRegistryOperations,
    broker_operations: BrokerClientOperations,
) -> DynamicTeamleadLaunchPlan:
    if type(request) is not DynamicTeamleadCoordinatorRequest:
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    _check_static_request(request)
    if any(
        not callable(getattr(broker_operations, name, None))
        for name in ("receive_frame", "fstat", "close")
    ):
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    if not callable(getattr(registry_operations, "commit_snapshot", None)):
        _fail(DynamicTeamleadCoordinatorCode.INVALID_REQUEST)
    prepared, planned, is_new = _prepare(request)
    _wait_for_commit(request, broker_operations)
    home = _receive_home(request, broker_operations)
    final_snapshot = planned
    if is_new:
        final_snapshot = _commit_registry(
            request,
            broker_operations,
            registry_operations,
            home,
            planned,
        )
    return DynamicTeamleadLaunchPlan(
        teamlead=prepared,
        snapshot=final_snapshot,
        expected_principal=request.expected_principal,
        expectation=request.mutation.expected,
        identity=request.identity,
        home=home,
    )


__all__ = [
    "DynamicTeamleadCoordinatorCode",
    "DynamicTeamleadCoordinatorError",
    "DynamicTeamleadCoordinatorRequest",
    "DynamicTeamleadLaunchPlan",
    "DynamicTeamleadRegistryOperations",
    "MAX_DYNAMIC_TEAMLEAD_TERMINAL_POLLS",
    "coordinate_dynamic_teamlead",
]
