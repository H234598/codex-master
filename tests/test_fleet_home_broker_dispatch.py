from __future__ import annotations

import ast
import dataclasses
from dataclasses import FrozenInstanceError
import hashlib
import inspect

import pytest

try:
    import codex_master.fleet_home_broker_dispatch as dispatch
except ModuleNotFoundError:
    dispatch = None
from codex_master.fleet_home_broker import OfflineBrokerPlan
from codex_master.fleet_home_broker_identity import (
    BrokerIdentity,
    ImportClosure,
    ImportClosureEntry,
)
from codex_master.fleet_home_broker_protocol import (
    AttestHomeRequest,
    BindingExpectation,
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRegistryState,
    BrokerReply,
    BrokerResultCode,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    ChpbTransactionOperation,
    DeprovisionHomeRequest,
    DirectoryIdentity,
    GetTerminalResultRequest,
    HomeAttestation,
    PolicyBinding,
    PrincipalBinding,
    ProvisionHomeRequest,
    QueryTransactionRequest,
    ReplaceHomeRequest,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
    encode_chpb_message,
)
from codex_master.fleet_home_broker_transport import BrokerPeer, BrokerTransportResponse


AGENT = "bee_1"
OTHER_AGENT = "bee_2"
MANIFEST = 3
UNIT = 9
INVOCATION = "1" * 32
OTHER_INVOCATION = "2" * 32
PROJECTION = "a" * 64
OTHER_PROJECTION = "b" * 64
STORE = "3" * 32
OTHER_STORE = "4" * 32
TRANSACTION = "5" * 32
OTHER_TRANSACTION = "6" * 32
REQUEST_ID = "7" * 32
OTHER_REQUEST_ID = "8" * 32
MCS = "c0,c1"
OTHER_MCS = "c0,c2"
PEER = BrokerPeer(41)
PRINCIPAL = PrincipalBinding(AGENT, MANIFEST, UNIT, 17, 29, INVOCATION, MCS, 4)
EXPECTED = BindingExpectation(AGENT, MANIFEST, UNIT, 7, PROJECTION, 4)
POLICY = PolicyBinding(7, PROJECTION)


def _closure() -> ImportClosure:
    return ImportClosure((ImportClosureEntry("codex_master/probe.py", "d" * 64),))


def _principal(**changes: object) -> PrincipalBinding:
    values = {
        "agent_id": AGENT,
        "manifest_generation": MANIFEST,
        "unit_generation": UNIT,
        "cgroup_dev": 17,
        "cgroup_ino": 29,
        "invocation_id": INVOCATION,
        "mcs_pair": MCS,
        "fencing_epoch": 4,
    }
    values.update(changes)
    return PrincipalBinding(**values)


def _policy(**changes: object) -> PolicyBinding:
    values = {"policy_generation": 7, "projection_digest": PROJECTION}
    values.update(changes)
    return PolicyBinding(**values)


def _plan(
    *,
    principal: PrincipalBinding = PRINCIPAL,
    operation: ChpbTransactionOperation = ChpbTransactionOperation.PROVISION,
    store_uuid: str = STORE,
    policy: PolicyBinding = POLICY,
) -> OfflineBrokerPlan:
    closure = _closure()
    identity = BrokerIdentity(
        principal.agent_id,
        principal.manifest_generation,
        principal.mcs_pair,
        "slot-1",
        policy.policy_generation,
        policy.projection_digest,
        closure.digest(),
        principal.fencing_epoch,
    )
    return OfflineBrokerPlan(
        identity,
        closure,
        principal,
        operation,
        store_uuid,
        1,
    )


def _binding(
    *,
    operation: ChpbTransactionOperation = ChpbTransactionOperation.PROVISION,
    transaction_id: str = TRANSACTION,
    store_uuid: str = STORE,
    principal: PrincipalBinding = PRINCIPAL,
    policy: PolicyBinding = POLICY,
) -> TransactionBinding:
    return TransactionBinding(operation, transaction_id, store_uuid, principal, policy)


def _mutation_request(
    operation: ChpbTransactionOperation = ChpbTransactionOperation.PROVISION,
    *,
    request_id: str = REQUEST_ID,
    transaction_id: str = TRANSACTION,
    binding: TransactionBinding | None = None,
):
    values = {
        ChpbTransactionOperation.PROVISION: (
            ProvisionHomeRequest,
            ChpbMessageKind.PROVISION_HOME,
        ),
        ChpbTransactionOperation.REPLACE: (
            ReplaceHomeRequest,
            ChpbMessageKind.REPLACE_HOME,
        ),
        ChpbTransactionOperation.DEPROVISION: (
            DeprovisionHomeRequest,
            ChpbMessageKind.DEPROVISION_HOME,
        ),
    }
    klass, kind = values[operation]
    return klass(
        CHPB_PROTOCOL,
        kind,
        request_id,
        transaction_id,
        EXPECTED,
        binding or _binding(operation=operation, transaction_id=transaction_id),
    )


def _read_request(kind: ChpbMessageKind, *, request_id: str = REQUEST_ID):
    klass = {
        ChpbMessageKind.ATTEST_HOME: AttestHomeRequest,
        ChpbMessageKind.QUERY_TRANSACTION: QueryTransactionRequest,
        ChpbMessageKind.GET_TERMINAL_RESULT: GetTerminalResultRequest,
    }[kind]
    return klass(CHPB_PROTOCOL, kind, request_id, TRANSACTION, EXPECTED)


def _status(
    binding: TransactionBinding,
    checkpoint: BrokerCheckpoint | None = None,
    terminal_result: BrokerResultCode | None = None,
) -> TransactionStatus:
    if checkpoint is None:
        checkpoint = {
            ChpbTransactionOperation.PROVISION: BrokerCheckpoint.CREATE_INTENT,
            ChpbTransactionOperation.REPLACE: BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
            ChpbTransactionOperation.DEPROVISION: BrokerCheckpoint.DEPROVISION_INTENT,
        }[binding.operation]
    if terminal_result is not None:
        checkpoint = {
            BrokerResultCode.COMMITTED: (
                BrokerCheckpoint.DEPROVISIONED
                if binding.operation is ChpbTransactionOperation.DEPROVISION
                else BrokerCheckpoint.COMMITTED
            ),
            BrokerResultCode.ROLLED_BACK: BrokerCheckpoint.ROLLED_BACK,
            BrokerResultCode.BLOCKED_DRIFT: BrokerCheckpoint.BLOCKED_DRIFT,
        }[terminal_result]
    observation = {
        BrokerCheckpoint.COMMITTED: BrokerObservation(
            BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1
        ),
        BrokerCheckpoint.DEPROVISIONED: BrokerObservation(
            BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE, 1
        ),
        BrokerCheckpoint.ROLLED_BACK: BrokerObservation(
            BrokerObjectState.ROLLED_BACK, BrokerRegistryState.NOT_APPLICABLE, 1
        ),
        BrokerCheckpoint.BLOCKED_DRIFT: BrokerObservation(
            BrokerObjectState.DRIFT, BrokerRegistryState.FOREIGN, 1
        ),
    }.get(
        checkpoint,
        BrokerObservation(
            BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE, 0
        ),
    )
    return TransactionStatus(
        binding,
        b2a_phase_for_checkpoint(checkpoint),
        checkpoint,
        observation,
        1,
        terminal_result,
    )


def _response(
    request,
    result: BrokerResultCode = BrokerResultCode.PENDING,
    *,
    binding: TransactionBinding | None = None,
    fds: tuple[int, ...] = (),
) -> BrokerTransportResponse:
    if result in {
        BrokerResultCode.PENDING,
        BrokerResultCode.COMMITTED,
        BrokerResultCode.ROLLED_BACK,
        BrokerResultCode.BLOCKED_DRIFT,
    }:
        status = _status(
            binding or getattr(request, "binding", _binding()),
            terminal_result=None if result is BrokerResultCode.PENDING else result,
        )
        attestation = None
        if result is BrokerResultCode.OK:
            attestation = HomeAttestation(
                status.binding,
                "/run/codex-master-agent/home",
                DirectoryIdentity(0, 1, 0o40700),
                status.binding.policy.projection_digest,
                status.binding.principal.mcs_pair,
            )
        reply = BrokerReply(
            CHPB_PROTOCOL,
            ChpbMessageKind.REPLY,
            request.request_id,
            result,
            status,
            attestation,
        )
    elif result is BrokerResultCode.OK:
        status = _status(
            binding or getattr(request, "binding", _binding()),
            terminal_result=BrokerResultCode.COMMITTED,
        )
        reply = BrokerReply(
            CHPB_PROTOCOL,
            ChpbMessageKind.REPLY,
            request.request_id,
            result,
            status,
            HomeAttestation(
                status.binding,
                "/run/codex-master-agent/home",
                DirectoryIdentity(0, 1, 0o40700),
                status.binding.policy.projection_digest,
                status.binding.principal.mcs_pair,
            ),
        )
    else:
        reply = BrokerReply(
            CHPB_PROTOCOL,
            ChpbMessageKind.REPLY,
            request.request_id,
            result,
            None,
            None,
        )
    return BrokerTransportResponse(reply, fds)


class FakeResolver:
    def __init__(
        self, principal=PRINCIPAL, plan=None, *, principal_error=None, plan_error=None
    ):
        self.principal = principal
        self.plan = plan
        self.principal_error = principal_error
        self.plan_error = plan_error
        self.principal_calls = []
        self.plan_calls = []

    def resolve_principal(self, peer):
        self.principal_calls.append(peer)
        if self.principal_error is not None:
            raise self.principal_error
        return self.principal

    def resolve_mutation_plan(self, principal, request):
        self.plan_calls.append((principal, request))
        if self.plan_error is not None:
            raise self.plan_error
        return self.plan


class FakeOperations:
    def __init__(self, responses=(), *, execute_error=None, close_error=False):
        self.responses = list(responses)
        self.execute_error = execute_error
        self.close_error = close_error
        self.execute_calls = []
        self.closed = []

    def execute(self, command):
        self.execute_calls.append(command)
        if self.execute_error is not None:
            raise self.execute_error
        return self.responses.pop(0)

    def close(self, fd):
        self.closed.append(fd)
        if self.close_error:
            raise RuntimeError("close failed")


def test_public_api_exports_exact_frozen_slotted_command_and_protocol_methods():
    assert dispatch.__all__ == (
        "BrokerDispatchCommand",
        "BrokerDispatchError",
        "BrokerDispatchOperations",
        "BrokerDispatchResolver",
        "dispatch_request",
    )
    assert issubclass(dispatch.BrokerDispatchError, ValueError)
    assert dataclasses.is_dataclass(dispatch.BrokerDispatchCommand)
    assert dispatch.BrokerDispatchCommand.__dataclass_params__.frozen
    assert hasattr(dispatch.BrokerDispatchCommand, "__slots__")
    assert tuple(
        field.name for field in dataclasses.fields(dispatch.BrokerDispatchCommand)
    ) == (
        "principal",
        "request",
        "request_digest",
        "plan",
    )
    with pytest.raises(FrozenInstanceError):
        dispatch.BrokerDispatchCommand(
            PRINCIPAL, _read_request(ChpbMessageKind.ATTEST_HOME), "a" * 64, None
        ).principal = PRINCIPAL
    assert getattr(dispatch.BrokerDispatchOperations, "_is_protocol", False)
    assert getattr(dispatch.BrokerDispatchResolver, "_is_protocol", False)
    assert tuple(
        inspect.signature(dispatch.BrokerDispatchOperations.execute).parameters
    ) == (
        "self",
        "command",
    )
    assert tuple(
        inspect.signature(dispatch.BrokerDispatchOperations.close).parameters
    ) == (
        "self",
        "fd",
    )
    assert tuple(
        inspect.signature(dispatch.BrokerDispatchResolver.resolve_principal).parameters
    ) == (
        "self",
        "peer",
    )
    assert tuple(
        inspect.signature(
            dispatch.BrokerDispatchResolver.resolve_mutation_plan
        ).parameters
    ) == (
        "self",
        "principal",
        "request",
    )


def test_invalid_peer_or_request_is_rejected_before_resolution_or_execution():
    resolver = FakeResolver(plan=_plan())
    operations = FakeOperations()
    with pytest.raises(
        dispatch.BrokerDispatchError, match="^invalid broker dispatch request$"
    ):
        dispatch.dispatch_request(
            object(), _read_request(ChpbMessageKind.ATTEST_HOME), resolver, operations
        )
    with pytest.raises(
        dispatch.BrokerDispatchError, match="^invalid broker dispatch request$"
    ):
        dispatch.dispatch_request(PEER, object(), resolver, operations)
    assert resolver.principal_calls == []
    assert operations.execute_calls == []


def test_principal_mismatch_precedence_returns_code_without_plan_or_execute():
    cases = (
        (
            _principal(agent_id=OTHER_AGENT, fencing_epoch=8, manifest_generation=8),
            BrokerResultCode.WRONG_PRINCIPAL,
        ),
        (
            _principal(fencing_epoch=8, manifest_generation=8, unit_generation=10),
            BrokerResultCode.FENCED,
        ),
        (
            _principal(manifest_generation=8, unit_generation=10),
            BrokerResultCode.STALE_GENERATION,
        ),
    )
    request = _read_request(ChpbMessageKind.QUERY_TRANSACTION)
    for principal, result in cases:
        resolver = FakeResolver(principal=principal, plan=_plan())
        operations = FakeOperations()
        response = dispatch.dispatch_request(PEER, request, resolver, operations)
        assert response == BrokerTransportResponse(
            BrokerReply(
                CHPB_PROTOCOL, ChpbMessageKind.REPLY, REQUEST_ID, result, None, None
            ),
            (),
        )
        assert resolver.plan_calls == []
        assert operations.execute_calls == []


def test_provision_maps_plan_and_request_digest_into_command():
    request = _mutation_request()
    plan = _plan()
    expected = _response(request)
    resolver = FakeResolver(plan=plan)
    operations = FakeOperations((expected,))
    result = dispatch.dispatch_request(PEER, request, resolver, operations)
    assert result is expected
    assert resolver.plan_calls == [(PRINCIPAL, request)]
    command = operations.execute_calls == [
        dispatch.BrokerDispatchCommand(
            PRINCIPAL,
            request,
            hashlib.sha256(encode_chpb_message(request)).hexdigest(),
            plan,
        )
    ]
    assert command


def test_replace_maps_exact_mutation_plan():
    request = _mutation_request(ChpbTransactionOperation.REPLACE)
    plan = _plan(operation=ChpbTransactionOperation.REPLACE)
    expected = _response(request)
    resolver = FakeResolver(plan=plan)
    operations = FakeOperations((expected,))
    assert dispatch.dispatch_request(PEER, request, resolver, operations) is expected
    assert resolver.plan_calls == [(PRINCIPAL, request)]
    assert operations.execute_calls[0].plan is plan
    assert (
        operations.execute_calls[0].request_digest
        == hashlib.sha256(encode_chpb_message(request)).hexdigest()
    )


def test_deprovision_maps_exact_mutation_plan():
    request = _mutation_request(ChpbTransactionOperation.DEPROVISION)
    plan = _plan(operation=ChpbTransactionOperation.DEPROVISION)
    expected = _response(request)
    resolver = FakeResolver(plan=plan)
    operations = FakeOperations((expected,))
    assert dispatch.dispatch_request(PEER, request, resolver, operations) is expected
    assert resolver.plan_calls == [(PRINCIPAL, request)]
    assert operations.execute_calls[0].principal == PRINCIPAL
    assert operations.execute_calls[0].plan is plan


def test_read_requests_skip_plan_resolution_and_send_none_plan():
    for kind in (
        ChpbMessageKind.QUERY_TRANSACTION,
        ChpbMessageKind.GET_TERMINAL_RESULT,
        ChpbMessageKind.ATTEST_HOME,
    ):
        request = _read_request(kind)
        expected = _response(request)
        resolver = FakeResolver(plan=_plan())
        operations = FakeOperations((expected,))
        assert (
            dispatch.dispatch_request(PEER, request, resolver, operations) is expected
        )
        assert resolver.plan_calls == []
        assert operations.execute_calls[0].plan is None


def test_plan_binding_matrix_returns_drift_codes_without_execute():
    cases = (
        (
            _plan(principal=_principal(agent_id=OTHER_AGENT)),
            BrokerResultCode.WRONG_PRINCIPAL,
        ),
        (_plan(principal=_principal(cgroup_dev=18)), BrokerResultCode.WRONG_PRINCIPAL),
        (_plan(principal=_principal(cgroup_ino=30)), BrokerResultCode.WRONG_PRINCIPAL),
        (
            _plan(principal=_principal(invocation_id=OTHER_INVOCATION)),
            BrokerResultCode.WRONG_PRINCIPAL,
        ),
        (
            _plan(principal=_principal(mcs_pair=OTHER_MCS)),
            BrokerResultCode.WRONG_PRINCIPAL,
        ),
        (_plan(principal=_principal(fencing_epoch=5)), BrokerResultCode.FENCED),
        (
            _plan(principal=_principal(manifest_generation=4)),
            BrokerResultCode.STALE_GENERATION,
        ),
        (
            _plan(principal=_principal(unit_generation=10)),
            BrokerResultCode.STALE_GENERATION,
        ),
        (_plan(policy=_policy(policy_generation=8)), BrokerResultCode.STALE_GENERATION),
        (
            _plan(operation=ChpbTransactionOperation.REPLACE),
            BrokerResultCode.TRANSACTION_ID_REUSE,
        ),
        (_plan(store_uuid=OTHER_STORE), BrokerResultCode.TRANSACTION_ID_REUSE),
    )
    request = _mutation_request()
    for plan, result in cases:
        resolver = FakeResolver(plan=plan)
        operations = FakeOperations()
        response = dispatch.dispatch_request(PEER, request, resolver, operations)
        assert response.reply.result is result
        assert response.reply.request_id == REQUEST_ID
        assert response.fds == ()
        assert operations.execute_calls == []


def test_identical_request_and_digest_are_passed_through_for_each_execution():
    request = _mutation_request()
    plan = _plan()
    first = _response(request)
    second = _response(request)
    resolver = FakeResolver(plan=plan)
    operations = FakeOperations((first, second))
    assert dispatch.dispatch_request(PEER, request, resolver, operations) is first
    assert dispatch.dispatch_request(PEER, request, resolver, operations) is second
    assert (
        operations.execute_calls[0].request_digest
        == operations.execute_calls[1].request_digest
    )
    assert (
        operations.execute_calls[0].request_digest
        == hashlib.sha256(encode_chpb_message(request)).hexdigest()
    )


def test_reuse_and_cache_result_codes_are_valid_passthrough_replies():
    request = _read_request(ChpbMessageKind.QUERY_TRANSACTION)
    responses = tuple(
        _response(request, result)
        for result in (
            BrokerResultCode.REQUEST_ID_REUSE,
            BrokerResultCode.TRANSACTION_ID_REUSE,
            BrokerResultCode.CACHE_FULL,
        )
    )
    resolver = FakeResolver(plan=_plan())
    operations = FakeOperations(responses)
    for expected in responses:
        assert (
            dispatch.dispatch_request(PEER, request, resolver, operations) is expected
        )
    assert len(operations.execute_calls) == 3


def test_query_and_terminal_requests_accept_pending_and_terminal_reply_matrix():
    results = (
        BrokerResultCode.PENDING,
        BrokerResultCode.COMMITTED,
        BrokerResultCode.ROLLED_BACK,
        BrokerResultCode.BLOCKED_DRIFT,
        BrokerResultCode.TRANSACTION_NOT_FOUND,
    )
    for kind in (
        ChpbMessageKind.QUERY_TRANSACTION,
        ChpbMessageKind.GET_TERMINAL_RESULT,
    ):
        for result in results:
            request = _read_request(kind)
            expected = _response(request, result)
            resolver = FakeResolver(plan=_plan())
            operations = FakeOperations((expected,))
            assert (
                dispatch.dispatch_request(PEER, request, resolver, operations)
                is expected
            )


def test_attest_accepts_only_ok_with_exact_attestation_and_other_ok_is_rejected():
    attest = _read_request(ChpbMessageKind.ATTEST_HOME)
    ok = _response(attest, BrokerResultCode.OK, fds=(71,))
    resolver = FakeResolver(plan=_plan())
    operations = FakeOperations((ok,))
    assert dispatch.dispatch_request(PEER, attest, resolver, operations) is ok
    query = _read_request(ChpbMessageKind.QUERY_TRANSACTION)
    bad_ok = _response(query, BrokerResultCode.OK, fds=(72,))
    operations = FakeOperations((bad_ok,))
    with pytest.raises(
        dispatch.BrokerDispatchError, match="^invalid broker dispatch response$"
    ):
        dispatch.dispatch_request(PEER, query, resolver, operations)
    assert operations.closed == [72]

    invalid_fd_cases = (
        (_response(attest, BrokerResultCode.OK, fds=()), []),
        (_response(attest, BrokerResultCode.OK, fds=(73, 74)), [73, 74]),
        (_response(attest, BrokerResultCode.OK, fds=(75, 75)), [75]),
        (_response(attest, BrokerResultCode.PENDING, fds=(76,)), [76]),
    )
    for response, closed in invalid_fd_cases:
        operations = FakeOperations((response,))
        with pytest.raises(
            dispatch.BrokerDispatchError, match="^invalid broker dispatch response$"
        ):
            dispatch.dispatch_request(PEER, attest, resolver, operations)
        assert operations.closed == closed


def test_transaction_policy_and_principal_reply_drift_is_rejected():
    request = _read_request(ChpbMessageKind.QUERY_TRANSACTION)
    drifted = (
        _binding(transaction_id=OTHER_TRANSACTION),
        _binding(policy=_policy(projection_digest=OTHER_PROJECTION)),
        _binding(principal=_principal(cgroup_dev=18)),
    )
    for binding in drifted:
        response = _response(request, binding=binding, fds=(73,))
        resolver = FakeResolver(plan=_plan())
        operations = FakeOperations((response,))
        with pytest.raises(
            dispatch.BrokerDispatchError, match="^invalid broker dispatch response$"
        ):
            dispatch.dispatch_request(PEER, request, resolver, operations)
        assert operations.closed == [73]


def test_resolution_and_execution_exceptions_are_sparse_and_cause_free():
    request = _read_request(ChpbMessageKind.QUERY_TRANSACTION)
    resolver = FakeResolver(principal_error=RuntimeError("principal detail"))
    with pytest.raises(
        dispatch.BrokerDispatchError, match="^broker principal resolution failed$"
    ) as principal_error:
        dispatch.dispatch_request(PEER, request, resolver, FakeOperations())
    assert principal_error.value.__cause__ is None
    resolver = FakeResolver(plan=_plan(), plan_error=RuntimeError("plan detail"))
    with pytest.raises(
        dispatch.BrokerDispatchError, match="^broker plan resolution failed$"
    ) as plan_error:
        dispatch.dispatch_request(PEER, _mutation_request(), resolver, FakeOperations())
    assert plan_error.value.__cause__ is None
    resolver = FakeResolver(plan=_plan())
    with pytest.raises(
        dispatch.BrokerDispatchError, match="^broker dispatch execution failed$"
    ) as execution_error:
        dispatch.dispatch_request(
            PEER,
            request,
            resolver,
            FakeOperations(execute_error=RuntimeError("execute detail")),
        )
    assert execution_error.value.__cause__ is None


def test_invalid_response_closes_unique_valid_fds_and_masks_close_failures():
    request = _read_request(ChpbMessageKind.QUERY_TRANSACTION)
    invalid = BrokerTransportResponse(
        BrokerReply(
            CHPB_PROTOCOL,
            ChpbMessageKind.REPLY,
            REQUEST_ID,
            BrokerResultCode.PENDING,
            None,
            None,
        ),
        (74, 74, -1, True, "bad", 75),
    )
    resolver = FakeResolver(plan=_plan())
    operations = FakeOperations((invalid,), close_error=True)
    with pytest.raises(
        dispatch.BrokerDispatchError, match="^invalid broker dispatch response$"
    ) as error:
        dispatch.dispatch_request(PEER, request, resolver, operations)
    assert error.value.__cause__ is None
    assert operations.closed == [74, 75]


@pytest.mark.parametrize(
    ("fds", "closed"),
    (
        ([83, 83, True, -1, "bad", 84], [83, 84]),
        ({86, 85, True, -1}, [85, 86]),
        (frozenset((88, 87, True, -1)), [87, 88]),
        ({"bad": 89}, []),
        ("not-an-fd-container", []),
    ),
)
def test_invalid_response_fd_cleanup_accepts_only_explicit_safe_containers(fds, closed):
    request = _read_request(ChpbMessageKind.QUERY_TRANSACTION)
    invalid = BrokerTransportResponse(
        BrokerReply(
            CHPB_PROTOCOL,
            ChpbMessageKind.REPLY,
            REQUEST_ID,
            BrokerResultCode.PENDING,
            None,
            None,
        ),
        fds,
    )
    operations = FakeOperations((invalid,), close_error=True)
    with pytest.raises(
        dispatch.BrokerDispatchError, match="^invalid broker dispatch response$"
    ):
        dispatch.dispatch_request(PEER, request, FakeResolver(plan=_plan()), operations)
    assert operations.closed == closed


def test_imports_and_tokens_have_no_host_runtime_or_transaction_bootstrap_surface():
    source = inspect.getsource(dispatch)
    tree = ast.parse(source)
    imports = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.extend((alias.name, None) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append((node.module, tuple(alias.name for alias in node.names)))
    assert imports == [
        ("__future__", ("annotations",)),
        ("dataclasses", ("dataclass",)),
        ("hashlib", None),
        ("typing", ("Protocol",)),
        ("codex_master.fleet_home_broker", ("OfflineBrokerPlan",)),
        (
            "codex_master.fleet_home_broker_protocol",
            (
                "AttestHomeRequest",
                "BrokerReply",
                "BrokerRequest",
                "BrokerResultCode",
                "CHPB_PROTOCOL",
                "ChpbMessageKind",
                "DeprovisionHomeRequest",
                "GetTerminalResultRequest",
                "PolicyBinding",
                "PrincipalBinding",
                "ProvisionHomeRequest",
                "QueryTransactionRequest",
                "ReplaceHomeRequest",
                "TransactionBinding",
                "encode_chpb_message",
                "validate_chpb_message",
                "validate_principal_binding",
                "validate_transaction_binding",
            ),
        ),
        (
            "codex_master.fleet_home_broker_transport",
            ("BrokerPeer", "BrokerTransportResponse"),
        ),
    ]
    forbidden = {
        "socket",
        "subprocess",
        "os",
        "pathlib",
        "begin_offline_transaction",
        "PidfdIdentity",
    }
    assert forbidden.isdisjoint(
        token.id for token in ast.walk(tree) if isinstance(token, ast.Name)
    )
