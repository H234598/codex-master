from __future__ import annotations

import os
import json
import importlib
import threading
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType

import pytest

from codex_master.agent_resolver import (
    AgentClassPolicy,
    ModelPolicy,
    ResolutionRequest,
    build_selection_offer,
    canonical_resolution_decision_digest,
    resolve_agent_selection,
)
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetAccountV2,
    FleetDynamicWorkerPrincipalV2,
    FleetSeries,
    FleetSeriesMember,
    FleetSeriesV2,
    FleetSnapshot,
    FleetSnapshotV2,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
    fleet_document,
    normalize_fleet_document,
    DynamicWorkerRegistryPlannerV2,
)
from codex_master.fleet_runners import (
    ProviderError,
    ProviderErrorQuotaObservation,
    ProbeResult,
)
from codex_master.fleet_service import FleetRateLimitError
from codex_master.worker_resolution_carrier import (
    WorkerRegistryReservationIssuerV2,
    WorkerResolutionEvidenceV2,
    build_worker_resolution_carrier,
)
from codex_master.worker_resume import WorkerLifecycle
from codex_master.worker_spawn_ledger import (
    FenceEpoch,
    Generation,
    LeaseBindingConsumerInputV1,
    LedgerRevision,
    SpawnPhase,
    WorkerSpawnTicketV2,
)


def test_fleet_paths_keep_registry_and_secrets_separate(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetPaths

    paths = FleetPaths.from_state_root(tmp_path)

    assert paths.registry == tmp_path / "fleet" / "registry.json"
    assert paths.secrets == tmp_path / "fleet" / "secrets"
    assert paths.limits == tmp_path / "fleet" / "limits.json"
    assert paths.rate_limits == tmp_path / "fleet" / "rate-limits.json"
    assert paths.lock == tmp_path / "fleet" / "registry.lock"
    assert paths.recovery == tmp_path / "fleet" / "recovery.json"
    assert paths.mutation_lock == tmp_path / "fleet" / "mutation.lock"


def _account(
    account_id: str = "shared",
    *,
    enabled: bool = True,
    secret_state: SecretState = SecretState.MISSING,
    limit_state: LimitState = LimitState.UNKNOWN,
) -> FleetAccount:
    return FleetAccount(
        account_id,
        "Shared account",
        Provider.GEMINI_API,
        AuthKind.API_KEY,
        secret_state,
        limit_state,
        enabled,
        None,
        None,
        None,
    )


def _series(
    prefix: str = "d",
    *,
    account_id: str | None = "shared",
    enabled: bool = True,
    model: str = "model",
) -> FleetSeries:
    provider = Provider.OLLAMA_LOCAL if account_id is None else Provider.GEMINI_API
    runner = RunnerKind.CODEX_CLI if account_id is None else RunnerKind.GEMINI_CLI
    return FleetSeries(
        prefix, f"Series {prefix}", 1, runner, provider, model, account_id, enabled
    )


def _service(tmp_path: Path, snapshot: FleetSnapshot | None = None):
    from codex_master.fleet_service import FleetPaths, FleetService
    from codex_master.server import build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path)
    private_io = replace(
        build_fleet_private_io(paths),
        utc_now=lambda: datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
    )
    service = FleetService(paths, private_io, pool_root=tmp_path / "pool")
    if snapshot is not None:
        service.commit_snapshot(snapshot, expected_generation=1)
    return service, paths


def _r3_service(tmp_path: Path, snapshot: FleetSnapshotV2):
    from codex_master.fleet_service import FleetPaths, FleetPrivateIO, FleetService

    paths = FleetPaths.from_state_root(tmp_path)

    def read_text(path: Path, _maximum: int, _error: str) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None

    def replace_text(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def read_bytes(path: Path, _maximum: int, _error: str) -> bytes | None:
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    def replace_bytes(path: Path, value: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        path.chmod(mode)

    io = FleetPrivateIO(
        ensure_dir=lambda path: path.mkdir(parents=True, exist_ok=True),
        read_text=read_text,
        replace_text=replace_text,
        read_bytes=read_bytes,
        replace_bytes=replace_bytes,
        lock=lambda: nullcontext(),
        utc_now=lambda: datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
    )
    service = FleetService(paths, io, pool_root=tmp_path / "pool")
    service.commit_snapshot(snapshot, expected_generation=1)
    return service, paths


def _configured_snapshot(*, generation: int = 2) -> FleetSnapshot:
    return FleetSnapshot(
        1, generation, (_account(secret_state=SecretState.CONFIGURED),), (_series(),)
    )


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _empty_worker_snapshot() -> FleetSnapshotV2:
    document = json.loads(
        (Path(__file__).parent / "fixtures" / "fleet-registry-v2.json").read_text(
            encoding="utf-8"
        )
    )
    document["runtime_principals"] = []
    snapshot = normalize_fleet_document(document)
    assert isinstance(snapshot, FleetSnapshotV2)
    return replace(snapshot, generation=2)


def _worker_registry_reservation():
    classes = (
        AgentClassPolicy(
            "arbeitsbiene",
            "ephemeral",
            ("ephemeral", "binding", "persistent"),
            ("luna",),
            "low",
            "xhigh",
            ("read", "write"),
        ),
    )
    model = "gpt-5.6-luna"
    models = (
        ModelPolicy(
            model, "luna", 20, ("low", "medium", "high", "xhigh"), ("read", "write")
        ),
    )
    request = ResolutionRequest(
        "read",
        "simple",
        requested_class="arbeitsbiene",
        requested_lifecycle="invocation",
    )
    decision = resolve_agent_selection(
        request, classes=classes, models=models, available_models={model}
    )
    offer = build_selection_offer(
        classes=classes, models=models, available_models={model}
    )
    ticket = WorkerSpawnTicketV2(
        ticket_id="ticket:worker-7",
        request_id="worker-7",
        requester_principal_id="worker-11",
        requester_authority_digest=_digest("a"),
        work_package_id="work-package-8",
        topic_digest=_digest("b"),
        target_class_id=decision.class_id,
        authorized_teamlead_id="teamlead-2",
        authorized_teamlead_authority_digest=_digest("c"),
        resolution_decision_digest=canonical_resolution_decision_digest(decision),
        resolution_generation=Generation(4),
        policy_digest=_digest("d"),
        policy_generation=Generation(9),
        lifecycle=WorkerLifecycle.INVOCATION,
        resume_requirement=False,
        fence_epoch=FenceEpoch(6),
        ledger_revision=LedgerRevision(1),
        phase=SpawnPhase.REQUESTED,
    )
    evidence = WorkerResolutionEvidenceV2(
        decision=decision,
        offer=offer,
        offer_generation=offer.generation,
        capability_binding_digest=_digest("e"),
        resolution_generation=ticket.resolution_generation,
        policy_digest=ticket.policy_digest,
        policy_generation=ticket.policy_generation,
        ticket_fence_epoch=ticket.fence_epoch,
    )
    carrier = build_worker_resolution_carrier(ticket, evidence)
    allocator_module = importlib.import_module("codex_master.runtime_account_allocator")

    class _Adapter:
        adapter_id = "adapter-service"

        def reserve_capability_atomically(self, _capability, capacity_evidence):
            return allocator_module.AccountReservation(
                reservation_id="reservation-service",
                account_binding_digest=_digest("a"),
                profile_binding_digest=_digest("b"),
                provider_adapter_id=self.adapter_id,
                capacity_evidence=capacity_evidence,
                lease_revision=1,
                evidence_revision=capacity_evidence.evidence_revision,
                fencing_token=capacity_evidence.fencing_token,
                fence_epoch=capacity_evidence.fence_epoch,
                expires_at_utc=capacity_evidence.expires_at_utc,
            )

        def release_reservation(self, _reservation):
            return True

    allocator = allocator_module.RuntimeAccountAllocator(_Adapter())
    p0_ticket = allocator_module.ValidatedAllocationTicket(
        ticket_id=ticket.ticket_id,
        resolution_decision=carrier.decision,
        selection_offer=carrier.offer,
        resolver_offer_generation=carrier.resolver_offer_generation,
        policy_generation=ticket.policy_generation.value,
        policy_digest=ticket.policy_digest,
        capability_binding_digest=carrier.capability_binding_digest,
        ledger_revision=ticket.ledger_revision.value,
        phase="OFFER_VALIDATED",
        fencing_token="fence-service",
        fence_epoch=ticket.fence_epoch.value,
    )
    now = datetime.now(UTC)
    evidence = allocator_module.CapacityEvidence(
        ticket_id=p0_ticket.ticket_id,
        resolver_offer_generation=p0_ticket.resolver_offer_generation,
        policy_generation=p0_ticket.policy_generation,
        capability_binding_digest=p0_ticket.capability_binding_digest,
        ledger_revision=p0_ticket.ledger_revision,
        fencing_token=p0_ticket.fencing_token,
        fence_epoch=p0_ticket.fence_epoch,
        provider_adapter_id="adapter-service",
        capacity_units=2,
        quota_units=2,
        cost_units=2,
        resource_units=2,
        evidence_revision=1,
        observed_at_utc=now - timedelta(seconds=1),
        expires_at_utc=now + timedelta(minutes=5),
    )
    lease = allocator.allocate(p0_ticket, evidence)
    receipt = allocator.issue_lease_binding_receipt(lease, p0_ticket, evidence)
    verification = allocator.verify_lease_binding_receipt(
        receipt,
        expected_lease=lease,
        expected_ticket=p0_ticket,
        expected_capacity_evidence=evidence,
    )
    reference = allocator.lease_binding_reference_for(verification)
    allocator.close_lease_binding_verification(verification)
    binding = LeaseBindingConsumerInputV1(
        receipt=receipt,
        lease=lease,
        allocation_ticket=p0_ticket,
        capacity_evidence=evidence,
    )
    current_ticket = replace(
        ticket,
        phase=SpawnPhase.LEASE_RESERVED,
        ledger_revision=LedgerRevision(2),
        lease_binding_reference=reference,
        account_binding_digest=str(lease.account_binding_digest),
    )
    reservation = WorkerRegistryReservationIssuerV2(allocator).issue(
        resolution=carrier,
        current_ticket=current_ticket,
        principal_id="dw-" + "7" * 32,
        lease_binding=binding,
    )
    return allocator, reservation


def test_registry_snapshot_reads_registry_only_without_clock_or_limits(
    tmp_path: Path,
) -> None:
    from codex_master.fleet_service import FleetPaths, FleetPrivateIO, FleetService

    expected = _configured_snapshot(generation=7)
    paths = FleetPaths.from_state_root(tmp_path)
    calls: list[str] = []

    def read_text(path: Path, _maximum: int, _error: str) -> str:
        calls.append("registry")
        assert path == paths.registry
        return json.dumps(fleet_document(expected))

    io = FleetPrivateIO(
        ensure_dir=lambda _path: None,
        read_text=read_text,
        replace_text=lambda *_args: (_ for _ in ()).throw(AssertionError("write")),
        read_bytes=lambda *_args: (_ for _ in ()).throw(AssertionError("sidecar")),
        replace_bytes=lambda *_args: (_ for _ in ()).throw(AssertionError("write")),
        remove_file=lambda *_args: (_ for _ in ()).throw(AssertionError("write")),
        lock=lambda: (_ for _ in ()).throw(AssertionError("lock")),
        utc_now=lambda: (_ for _ in ()).throw(AssertionError("clock")),
    )
    service = FleetService(paths, io, pool_root=tmp_path / "pool", read_only=True)

    assert service.registry_snapshot() == expected
    assert calls == ["registry"]


def test_registry_snapshot_v2_never_calls_clock_sidecar_lock_or_write_callbacks(
    tmp_path: Path,
) -> None:
    expected = FleetSnapshotV2(
        2,
        7,
        (
            FleetAccountV2(
                "g-account",
                "G account",
                Provider.GEMINI_API,
                AuthKind.API_KEY,
                SecretState.CONFIGURED,
                LimitState.READY,
                True,
                None,
                None,
                None,
                None,
                "hmac-sha256:" + "a" * 64,
            ),
        ),
        (
            FleetSeriesV2(
                "g",
                "G series",
                RunnerKind.GEMINI_CLI,
                Provider.GEMINI_API,
                "gemini-test",
                True,
                "generic",
                "standard",
                (
                    FleetSeriesMember(
                        "11111111-1111-4111-8111-111111111111",
                        1,
                        "g-account",
                        True,
                    ),
                ),
            ),
        ),
        (),
    )
    from codex_master.fleet_service import FleetPaths, FleetPrivateIO, FleetService

    paths = FleetPaths.from_state_root(tmp_path)
    callback_calls = {"registry": 0, "ensure": 0}

    def ensure_dir(_path: Path) -> None:
        callback_calls["ensure"] += 1

    def read_text(path: Path, _maximum: int, _error: str) -> str:
        callback_calls["registry"] += 1
        assert path == paths.registry
        return json.dumps(fleet_document(expected))

    io = FleetPrivateIO(
        ensure_dir=ensure_dir,
        read_text=read_text,
        replace_text=lambda *_args: (_ for _ in ()).throw(AssertionError("write")),
        read_bytes=lambda *_args: (_ for _ in ()).throw(AssertionError("sidecar")),
        replace_bytes=lambda *_args: (_ for _ in ()).throw(AssertionError("write")),
        remove_file=lambda *_args: (_ for _ in ()).throw(AssertionError("write")),
        lock=lambda: (_ for _ in ()).throw(AssertionError("lock")),
        utc_now=lambda: (_ for _ in ()).throw(AssertionError("clock")),
    )
    service = FleetService(paths, io, pool_root=tmp_path / "pool", read_only=True)

    assert service.registry_snapshot() == expected
    assert callback_calls == {"registry": 1, "ensure": 2}


def _synthetic_g_binding_state(tmp_path: Path):
    service, paths = _service(tmp_path, _configured_snapshot())
    salt_path = paths.secrets / ".credential-binding-salt"
    salt_path.write_bytes(bytes(range(32)))
    salt_path.chmod(0o600)
    secret_path = paths.secrets / "shared.secret"
    secret_path.write_bytes(b"synthetic-secret")
    secret_path.chmod(0o600)
    return service, paths


def test_g_binding_evidence_never_creates_salt_or_mutates_registry(
    tmp_path: Path,
) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, paths = _service(tmp_path, _configured_snapshot())
    callback_called: list[bool] = []
    with pytest.raises(FleetSecretError, match="credential_binding_unknown"):
        service._with_g_migration_binding_evidence(
            ("shared",),
            expected_generation=2,
            callback=lambda _snapshot, _bindings: callback_called.append(True),
        )
    assert callback_called == []
    assert not (paths.secrets / ".credential-binding-salt").exists()
    assert service.load().generation == 2


def test_g_binding_evidence_returns_immutable_redacted_hmac_mapping(
    tmp_path: Path,
) -> None:
    service, paths = _synthetic_g_binding_state(tmp_path)
    seen: list[tuple[FleetSnapshot, MappingProxyType]] = []

    def callback(
        snapshot: FleetSnapshot, bindings: MappingProxyType
    ) -> dict[str, object]:
        seen.append((snapshot, bindings))
        with pytest.raises(TypeError):
            bindings["other"] = "not-allowed"  # type: ignore[index]
        return {"generation": snapshot.generation, "binding": bindings["shared"]}

    result = service._with_g_migration_binding_evidence(
        ("shared",), expected_generation=2, callback=callback
    )

    assert result["generation"] == 2
    assert isinstance(result["binding"], str)
    assert result["binding"].startswith("hmac-sha256:")
    assert len(seen) == 1
    assert seen[0][0].generation == 2
    assert type(seen[0][1]) is MappingProxyType
    rendered = repr(result)
    assert "synthetic-secret" not in rendered
    assert bytes(range(32)).hex() not in rendered
    assert paths.registry.exists()


@pytest.mark.parametrize("salt_kind", ["mode", "symlink"])
def test_g_binding_evidence_rejects_unsafe_salt_without_mutation(
    tmp_path: Path, salt_kind: str
) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, paths = _synthetic_g_binding_state(tmp_path)
    salt_path = paths.secrets / ".credential-binding-salt"
    original = bytes(range(32))
    if salt_kind == "mode":
        salt_path.chmod(0o644)
    else:
        target = tmp_path / "salt-target"
        target.write_bytes(original)
        target.chmod(0o600)
        salt_path.unlink()
        salt_path.symlink_to(target)
    callback_called: list[bool] = []

    with pytest.raises(FleetSecretError, match="credential_binding_unknown"):
        service._with_g_migration_binding_evidence(
            ("shared",),
            expected_generation=2,
            callback=lambda _snapshot, _bindings: callback_called.append(True),
        )
    assert callback_called == []
    assert service.load().generation == 2
    if salt_kind == "mode":
        assert salt_path.read_bytes() == original
        assert salt_path.stat().st_mode & 0o777 == 0o644
    else:
        assert salt_path.is_symlink()


@pytest.mark.parametrize(
    "account_ids, expected_generation",
    [("shared", 2), (("missing",), 2), (("shared",), 1)],
)
def test_g_binding_evidence_rejects_invalid_account_or_generation(
    tmp_path: Path, account_ids: object, expected_generation: int
) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, _paths = _service(tmp_path, _configured_snapshot())
    callback_called: list[bool] = []
    with pytest.raises(FleetSecretError, match="credential_binding_unknown"):
        service._with_g_migration_binding_evidence(
            account_ids,
            expected_generation=expected_generation,
            callback=lambda _snapshot, _bindings: callback_called.append(True),
        )
    assert callback_called == []
    assert service.load().generation == 2


@pytest.mark.parametrize("sidecar_kind", ["missing", "unreadable", "rotated"])
def test_g_binding_evidence_rejects_sidecar_drift_without_callback(
    tmp_path: Path, sidecar_kind: str
) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, paths = _synthetic_g_binding_state(tmp_path)
    secret_path = paths.secrets / "shared.secret"
    if sidecar_kind == "missing":
        secret_path.unlink()
    else:
        real_io = service._io

        def read_bytes(path: Path, limit: int, error: str) -> bytes | None:
            if path == secret_path and sidecar_kind == "unreadable":
                raise OSError("synthetic-sidecar-error")
            value = real_io.read_bytes(path, limit, error)
            if path == secret_path and sidecar_kind == "rotated":
                path.write_bytes(b"rotated-sidecar")
                path.chmod(0o600)
            return value

        service = type(service)(
            paths,
            replace(real_io, read_bytes=read_bytes),
            pool_root=tmp_path / "pool",
        )
    callback_called: list[bool] = []
    with pytest.raises(FleetSecretError, match="credential_binding_unknown"):
        service._with_g_migration_binding_evidence(
            ("shared",),
            expected_generation=2,
            callback=lambda _snapshot, _bindings: callback_called.append(True),
        )
    assert callback_called == []
    assert service.load().generation == 2


def test_missing_registry_loads_initial_private_layout(tmp_path: Path) -> None:
    service, paths = _service(tmp_path)
    assert service.load() == FleetSnapshot(1, 1, (), ())
    assert os.stat(paths.root).st_mode & 0o777 == 0o700
    assert os.stat(paths.secrets).st_mode & 0o777 == 0o700


def test_set_secret_writes_only_private_file_and_public_status(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))
    result = service.set_secret("shared", "tiny-secret", expected_generation=2)
    assert result == {"configured": True, "generation": 3}
    assert os.stat(paths.secrets / "shared.secret").st_mode & 0o777 == 0o600
    assert os.stat(paths.registry).st_mode & 0o777 == 0o600
    assert service.load().accounts[0].secret_state is SecretState.CONFIGURED
    assert "tiny-secret" not in repr(service.public_snapshot())


@pytest.mark.parametrize("secret", ["", "x" * (16 * 1024 + 1)])
def test_set_secret_rejects_invalid_size(tmp_path: Path, secret: str) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))
    with pytest.raises(FleetSecretError) as raised:
        service.set_secret("shared", secret, expected_generation=2)
    assert str(raised.value) == "invalid_secret"
    assert not (paths.secrets / "shared.secret").exists()


def test_set_secret_rejects_value_above_16_kib(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))

    with pytest.raises(FleetSecretError) as raised:
        service.set_secret("shared", "x" * (16 * 1024 + 1), expected_generation=2)

    assert str(raised.value) == "invalid_secret"
    assert not (paths.secrets / "shared.secret").exists()


def test_set_secret_accepts_exactly_16_kib(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))

    service.set_secret("shared", "x" * (16 * 1024), expected_generation=2)

    assert (paths.secrets / "shared.secret").stat().st_size == 16 * 1024


def test_generation_conflict_does_not_overwrite_secret(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetConflictError

    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))
    service.set_secret("shared", "first", expected_generation=2)
    with pytest.raises(FleetConflictError):
        service.set_secret("shared", "second", expected_generation=2)
    assert (paths.secrets / "shared.secret").read_text() == "first"


def test_account_id_cannot_escape_secret_directory(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))
    with pytest.raises(FleetSecretError):
        service.set_secret("../outside", "tiny", expected_generation=2)
    assert not (paths.secrets.parent / "outside.secret").exists()
    assert not (tmp_path / "outside.secret").exists()


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_set_secret_rejects_link_targets(tmp_path: Path, link_kind: str) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))
    service.load()
    target = tmp_path / "target"
    target.write_text("untouched")
    secret_path = paths.secrets / "shared.secret"
    if link_kind == "symlink":
        secret_path.symlink_to(target)
    else:
        os.link(target, secret_path)
    with pytest.raises(FleetSecretError):
        service.set_secret("shared", "replacement", expected_generation=2)
    assert target.read_text() == "untouched"


def test_commit_rejects_stale_generation(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetConflictError

    service, _ = _service(tmp_path)
    current = service.load()
    next_snapshot = FleetSnapshot(1, 2, (_account(),), ())
    service.commit_snapshot(next_snapshot, expected_generation=current.generation)

    with pytest.raises(FleetConflictError):
        service.commit_snapshot(next_snapshot, expected_generation=current.generation)


def test_fleet_service_persists_reloads_worker_evidence_and_redacts_public_snapshot(
    tmp_path: Path,
) -> None:
    service, paths = _r3_service(tmp_path, _empty_worker_snapshot())
    current = service.registry_snapshot()
    allocator, reservation = _worker_registry_reservation()
    planner = DynamicWorkerRegistryPlannerV2(allocator)
    with planner.plan_dynamic_worker_principal_reserve(
        current, reservation, expected_generation=current.generation
    ) as candidate:
        committed = service.commit_snapshot(
            candidate, expected_generation=current.generation
        )
    reloaded = type(service)(paths, service._io, pool_root=tmp_path / "pool")
    loaded = reloaded.registry_snapshot()

    assert loaded == committed
    assert loaded.generation == 3
    principal = next(
        item
        for item in loaded.runtime_principals
        if isinstance(item, FleetDynamicWorkerPrincipalV2)
    )
    assert principal.resolution_evidence == WorkerResolutionEvidenceV2(
        decision=reservation.resolution.decision,
        offer=reservation.resolution.offer,
        offer_generation=reservation.resolution.resolver_offer_generation,
        capability_binding_digest=reservation.resolution.capability_binding_digest,
        resolution_generation=reservation.resolution.ticket_resolution_generation,
        policy_digest=reservation.resolution.ticket_policy_digest,
        policy_generation=reservation.resolution.ticket_policy_generation,
        ticket_fence_epoch=reservation.resolution.ticket_fence_epoch,
    )
    private = json.loads(paths.registry.read_text(encoding="utf-8"))
    private_worker = next(
        item
        for item in private["runtime_principals"]
        if item["principal_id"] == reservation.principal_id
    )
    assert set(private_worker["resolution_evidence"]) == {
        "decision",
        "offer",
        "offer_generation",
        "capability_binding_digest",
        "resolution_generation",
        "policy_digest",
        "policy_generation",
        "ticket_fence_epoch",
    }

    public = json.dumps(reloaded.public_snapshot(), sort_keys=True)
    for marker in (
        "principal_id",
        "ticket_id",
        "lease_binding_digest",
        "policy_digest",
        "capability_binding_digest",
        "credential_binding_id",
        "resolution_evidence",
        reservation.principal_id,
        reservation.resolution.ticket_id,
        reservation.resolution.ticket_policy_digest,
        reservation.resolution.capability_binding_digest,
        str(paths.root),
    ):
        assert marker not in public

    with planner.plan_dynamic_worker_principal_release(
        loaded, reservation, expected_generation=loaded.generation
    ) as release_candidate:
        released = reloaded.commit_snapshot(
            release_candidate, expected_generation=loaded.generation
        )
    assert released.runtime_principals == ()
    assert allocator._active_lease_binding_verifications == {}


def test_fleet_service_stale_worker_commit_is_strict_no_write(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetConflictError

    service, paths = _r3_service(tmp_path, _empty_worker_snapshot())
    current = service.registry_snapshot()
    allocator, reservation = _worker_registry_reservation()
    planner = DynamicWorkerRegistryPlannerV2(allocator)
    with planner.plan_dynamic_worker_principal_reserve(
        current, reservation, expected_generation=current.generation
    ) as candidate:
        service.commit_snapshot(candidate, expected_generation=current.generation)
    before = paths.registry.read_bytes()

    with pytest.raises(FleetConflictError, match="generation_conflict"):
        service.commit_snapshot(candidate, expected_generation=current.generation)

    assert paths.registry.read_bytes() == before
    assert service.registry_snapshot() == candidate


def test_registry_operation_holds_guard_through_actual_fleet_service_cas(
    tmp_path: Path,
) -> None:
    service, paths = _r3_service(tmp_path, _empty_worker_snapshot())
    allocator, reservation = _worker_registry_reservation()
    planner = DynamicWorkerRegistryPlannerV2(allocator)
    active_during_write: list[bool] = []
    real_io = service._io

    def replace_text(path: Path, text: str) -> None:
        if path == paths.registry:
            active_during_write.append(
                bool(allocator._active_lease_binding_verifications)
            )
        real_io.replace_text(path, text)

    service._io = replace(real_io, replace_text=replace_text)
    current = service.registry_snapshot()
    with planner.plan_dynamic_worker_principal_reserve(
        current, reservation, expected_generation=current.generation
    ) as candidate:
        committed = service.commit_snapshot(
            candidate, expected_generation=current.generation
        )

    assert committed.generation == current.generation + 1
    assert active_during_write == [True]
    assert allocator._active_lease_binding_verifications == {}


def test_registry_operation_stale_fleet_service_cas_has_no_write_or_retry(
    tmp_path: Path,
) -> None:
    from codex_master.fleet_service import FleetConflictError

    service, paths = _r3_service(tmp_path, _empty_worker_snapshot())
    allocator, reservation = _worker_registry_reservation()
    planner = DynamicWorkerRegistryPlannerV2(allocator)
    current = service.registry_snapshot()
    operation = planner.plan_dynamic_worker_principal_reserve(
        current, reservation, expected_generation=current.generation
    )
    external = replace(current, generation=current.generation + 1)
    service.commit_snapshot(external, expected_generation=current.generation)
    before = paths.registry.read_bytes()
    active_during_read: list[bool] = []
    real_io = service._io

    def read_text(path: Path, maximum: int, error: str) -> str | None:
        if path == paths.registry:
            active_during_read.append(
                bool(allocator._active_lease_binding_verifications)
            )
        return real_io.read_text(path, maximum, error)

    service._io = replace(real_io, read_text=read_text)
    with pytest.raises(FleetConflictError, match="generation_conflict"):
        with operation as candidate:
            service.commit_snapshot(candidate, expected_generation=current.generation)

    assert paths.registry.read_bytes() == before
    assert active_during_read == [True]
    assert allocator._active_lease_binding_verifications == {}


def test_process_loss_denies_foreign_releaser_without_registry_mutation(
    tmp_path: Path,
) -> None:
    from codex_master.fleet_registry import FleetValidationError

    service, paths = _r3_service(tmp_path, _empty_worker_snapshot())
    allocator, reservation = _worker_registry_reservation()
    planner = DynamicWorkerRegistryPlannerV2(allocator)
    current = service.registry_snapshot()
    with planner.plan_dynamic_worker_principal_reserve(
        current, reservation, expected_generation=current.generation
    ) as candidate:
        service.commit_snapshot(candidate, expected_generation=current.generation)
    before = paths.registry.read_bytes()
    loaded = service.registry_snapshot()

    foreign_allocator, foreign_reservation = _worker_registry_reservation()
    foreign_planner = DynamicWorkerRegistryPlannerV2(foreign_allocator)
    with pytest.raises(FleetValidationError, match="worker_reservation_mismatch"):
        with foreign_planner.plan_dynamic_worker_principal_release(
            loaded,
            foreign_reservation,
            expected_generation=loaded.generation,
        ):
            pass

    assert paths.registry.read_bytes() == before
    assert foreign_allocator._active_lease_binding_verifications == {}


def test_mark_limited_overlays_shared_account_gate(tmp_path: Path) -> None:
    snapshot = FleetSnapshot(
        1,
        2,
        (_account(secret_state=SecretState.CONFIGURED),),
        (_series("d"), _series("e"), _series("f", account_id=None)),
    )
    service, _ = _service(tmp_path, snapshot)
    service.mark_limited(
        "shared", reset_at_utc="2026-08-04T00:00:00Z", reason="provider_429"
    )
    assert service.account_gate("d1").reason == "limit_active"
    assert service.account_gate("e1").reason == "limit_active"
    assert service.account_gate("f1").reason == "ready"


def test_known_reset_time_expires_to_unknown_without_probe(tmp_path: Path) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())
    service.mark_limited(
        "shared", reset_at_utc="2026-08-03T11:00:00Z", reason="provider_429"
    )
    assert service.account_gate("d1").reason == "limit_unknown"


def test_invalid_limit_sidecar_is_quarantined_and_fail_closed(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())
    paths.limits.write_text("{invalid", encoding="utf-8")

    assert service.account_gate("d1").reason == "limit_unknown"
    marker = paths.recovery.with_name("limits.recovery.json")
    assert marker.exists()
    assert "invalid_fleet_limits" in marker.read_text(encoding="utf-8")


def test_gemini_rate_reservation_blocks_bursts_across_service_instances(
    tmp_path: Path,
) -> None:
    from codex_master.fleet_service import FleetRateLimitError

    service, paths = _service(tmp_path, _configured_snapshot())
    reservation = service.reserve_gemini_request("shared")
    assert reservation.account_id == "shared"
    assert paths.rate_limits.exists()

    with pytest.raises(FleetRateLimitError) as raised:
        type(service)(
            paths, service._io, pool_root=tmp_path / "pool"
        ).reserve_gemini_request("shared")

    assert raised.value.reason == "gemini_local_rate_limit"
    assert raised.value.retry_after_seconds >= 60
    assert reservation.reservation_id in paths.rate_limits.read_text(encoding="utf-8")


def test_tier1_quota_profile_keeps_provider_quotas_dashboard_driven(
    tmp_path: Path,
) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())

    tier1 = service.gemini_quota_profile("the-hive-1")
    tier1_lite = service.gemini_quota_profile(
        "the-hive-1", model="gemini-3.1-flash-lite"
    )
    tier1_flash = service.gemini_quota_profile("the-hive-1", model="gemini-3-flash")
    unknown = service.gemini_quota_profile("the-hive-11")

    assert tier1["billing_tier"] == "tier1"
    assert (
        service.project_limit_identity("the-hive-1")["billing_group"]
        == "the-hive-account-1"
    )
    assert tier1["rpm_limit"] is None
    assert tier1_lite["rpm_limit"] == 4000
    assert tier1_lite["tpm_limit"] == 4_000_000
    assert tier1_lite["rpd_limit"] == 150_000
    assert tier1_flash["rpm_limit"] == 1000
    assert tier1_flash["tpm_limit"] == 2_000_000
    assert tier1_flash["rpd_limit"] == 10_000
    assert type(service).gemini_quota_limits("tier0", "gemini-3.1-flash-lite") == {
        "rpm": 15,
        "tpm": 250_000,
        "rpd": 500,
    }
    assert tier1["spend_rate_limit_usd_per_10_minutes"] == 10.0
    assert tier1["billing_cap_usd_per_month"] == 250.0
    assert tier1["local_request_interval_seconds"] == 4
    tier0 = service.gemini_quota_profile("the-hive-4", model="gemini-3-flash")
    assert tier0["billing_tier"] == "tier0"
    assert tier0["rpm_limit"] == 5
    assert tier0["tpm_limit"] == 250_000
    assert tier0["rpd_limit"] == 20
    assert tier0["spend_rate_limit_usd_per_10_minutes"] is None
    assert service.gemini_quota_profile("the-hive-3")["billing_tier"] == "tier0"
    assert service.gemini_quota_profile("the-hive-3")["limits_by_model"] == {}
    assert unknown["billing_tier"] == "unknown"
    assert unknown["local_request_interval_seconds"] == 60


def test_gemini_billing_group_profile_and_registry_override(tmp_path: Path) -> None:
    registry_account = replace(
        _account("the-hive-1", secret_state=SecretState.CONFIGURED),
        billing_group="registry-billing-account",
    )
    snapshot = FleetSnapshot(
        1, 2, (registry_account,), (_series(account_id="the-hive-1"),)
    )
    service, _ = _service(tmp_path, snapshot)

    assert (
        service.gemini_quota_profile("the-hive-1")["billing_group"]
        == "the-hive-account-1"
    )
    assert (
        service.project_limit_identity("the-hive-1")["billing_group"]
        == "registry-billing-account"
    )


def test_gemini_usage_status_reports_observations_without_fake_quota_percentages(
    tmp_path: Path,
) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())
    service.record_gemini_usage(
        "the-hive-1",
        model="gemini-3.1-flash-lite",
        input_tokens=120,
        output_tokens=30,
    )

    status = service.gemini_usage_status("the-hive-1")
    stored = service._load_usage().get("the-hive-1", [])

    assert status["rpm_observed"] == 1
    assert status["tpm_observed"] == 120
    assert status["rpd_observed"] == 1
    assert status["quota_evaluation"]["state"] == "within_limits"
    assert status["quota_evaluation"]["limits"] == {
        "rpm": 4000,
        "tpm": 4_000_000,
        "rpd": 150_000,
    }
    assert status["quota_evaluation"]["utilization_percent"] == {
        "rpm": 0.03,
        "tpm": 0.0,
        "rpd": 0.0,
    }
    assert status["quota_evaluation"]["quota_observation"] is None
    assert stored
    assert stored[0].get("quota_scope") is None
    assert stored[0].get("quota_retry_after_seconds") is None
    assert status["spend_evaluation"]["state"] == "billing_export_required"


def test_model_scoped_usage_observation_blocks_model_only_and_not_account_limits(
    tmp_path: Path,
) -> None:
    account = replace(
        _account(
            "the-hive-1",
            secret_state=SecretState.CONFIGURED,
            limit_state=LimitState.READY,
        ),
        last_probe_at_utc="2026-08-03T12:00:00Z",
    )
    service, _ = _service(
        tmp_path,
        FleetSnapshot(
            1,
            2,
            (account,),
            (_series("d", account_id="the-hive-1", model="gemini-3.1-flash-lite"),),
        ),
    )
    service.record_gemini_usage(
        "the-hive-1",
        model="gemini-3.1-flash-lite",
        status="failed",
        gate_action="defer_until",
        gate_code="gemini_model_limited",
        next_reset_at_utc="2026-08-03T12:10:00Z",
        quota_observation=ProviderErrorQuotaObservation(
            scope="model",
            retry_after_seconds=120,
        ),
    )

    decision = service.gemini_headless_gate("d1")

    assert decision.action == "defer_until"
    assert decision.diagnostic_code == "gemini_model_limited"
    assert decision.defer_until == "2026-08-03T12:02:00Z"
    assert service.account_gate("d1").reason == "ready"
    assert service._load_limits() == {}
    events = service._load_usage().get("the-hive-1", [])
    assert events and events[-1]["quota_scope"] == "model"
    assert events[-1]["quota_retry_after_seconds"] == 120
    assert events[-1]["gate_code"] == "gemini_model_limited"

    service._io = replace(
        service._io, utc_now=lambda: datetime(2026, 8, 3, 12, 5, tzinfo=timezone.utc)
    )
    decision = service.gemini_headless_gate("d1")
    assert decision.action == "allow"
    assert decision.diagnostic_code == "gemini_ready"


def test_gemini_rate_status_exposes_quota_profile_before_first_request(
    tmp_path: Path,
) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())

    status = service.gemini_rate_status("the-hive-1")

    assert status["allowed"] is True
    assert status["billing_tier"] == "tier1"
    assert status["local_request_interval_seconds"] == 4


def test_gemini_rate_reservation_applies_exponential_429_cooldown(
    tmp_path: Path,
) -> None:
    from codex_master.fleet_service import FleetRateLimitError

    service, paths = _service(tmp_path, _configured_snapshot())
    reservation = service.reserve_gemini_request("shared")
    service.release_gemini_request(reservation, outcome="rate_limited")

    with pytest.raises(FleetRateLimitError) as raised:
        service.reserve_gemini_request("shared")

    assert raised.value.retry_after_seconds >= 15 * 60
    assert '"in_flight": null' in paths.rate_limits.read_text(encoding="utf-8")


def test_model_scoped_rate_requests_block_only_matching_model(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())

    a = service.reserve_gemini_request("shared", model="gemini-3-flash")
    reserved = json.loads(paths.rate_limits.read_text(encoding="utf-8"))["accounts"][
        "shared"
    ]
    assert reserved["in_flight"]["reservation_id"] == a.reservation_id
    assert (
        reserved["models"]["gemini-3-flash"]["in_flight"]["reservation_id"]
        == a.reservation_id
    )
    service.release_gemini_request(
        a,
        outcome="rate_limited",
        reset_at_utc="2026-08-03T12:10:00Z",
    )

    status_a = service.gemini_rate_status("shared", model="gemini-3-flash")
    assert status_a["allowed"] is False
    assert (
        service.gemini_rate_status("shared", model="gemini-3.1-flash-lite")["allowed"]
        is True
    )

    service.reserve_gemini_request("shared", model="gemini-3.1-flash-lite")
    with pytest.raises(FleetRateLimitError):
        service.reserve_gemini_request("shared", model="gemini-3-flash")

    rate_limits = json.loads(paths.rate_limits.read_text(encoding="utf-8"))
    account_entry = rate_limits["accounts"]["shared"]
    assert account_entry["cooldown_until_utc"] is None
    assert "models" in account_entry
    assert "gemini-3-flash" in account_entry["models"]


def test_25_flash_lite_rate_state_is_model_bound_with_unknown_dashboard_limits(
    tmp_path: Path,
) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())
    model = "gemini-2.5-flash-lite"

    profile = service.gemini_quota_profile("the-hive-1", model=model)
    assert profile["quota_model"] == model
    assert profile["provider_quota_source"] == "ai_studio_dashboard"
    assert profile["rpm_limit"] is None
    assert profile["tpm_limit"] is None
    assert profile["rpd_limit"] is None

    error = ProviderError(
        "account_limited",
        True,
        429,
        "2026-08-03T12:10:00Z",
        quota_observation=ProviderErrorQuotaObservation("model", 120),
    )
    result = service.probe_account(
        "shared",
        lambda account: ProbeResult(account.provider, False, model, False, error),
        model=model,
        expected_generation=2,
    )

    assert result["model"] == model
    rate_limits = json.loads(paths.rate_limits.read_text(encoding="utf-8"))["accounts"][
        "shared"
    ]
    assert rate_limits["cooldown_until_utc"] is None
    assert rate_limits["consecutive_429"] == 0
    assert rate_limits["models"][model]["in_flight"] is None
    assert rate_limits["models"][model]["cooldown_until_utc"] is None
    usage_event = service._load_usage()["shared"][-1]
    assert usage_event["model"] == model
    assert usage_event["quota_scope"] == "model"
    assert service.gemini_rate_status("shared", model=model)["quota_model"] == model


def test_future_catalog_model_stays_model_bound_with_unknown_quota(
    tmp_path: Path,
) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())
    model = "gemini-9.9-future-preview"

    reservation = service.reserve_gemini_request("shared", model=model)
    status = service.gemini_rate_status("shared", model=model)
    assert reservation.model == model
    assert status["quota_model"] == model
    assert status["rpm_limit"] is None
    assert status["tpm_limit"] is None
    assert status["rpd_limit"] is None

    service.release_gemini_request(reservation, outcome="provider_error")
    rate_state = json.loads(paths.rate_limits.read_text(encoding="utf-8"))["accounts"][
        "shared"
    ]
    assert rate_state["in_flight"] is None
    assert rate_state["models"][model]["in_flight"] is None


def test_model_scoped_gemini_rate_limits_migrate_v1_to_v2(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())
    paths.rate_limits.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "accounts": {
                    "shared": {
                        "next_allowed_at_utc": "2026-08-03T11:00:00Z",
                        "cooldown_until_utc": None,
                        "in_flight": None,
                        "consecutive_429": 2,
                    }
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    service.reserve_gemini_request("shared", model="gemini-3-flash")

    written = json.loads(paths.rate_limits.read_text(encoding="utf-8"))
    assert written["schema_version"] == 2
    assert "models" in written["accounts"]["shared"]
    assert "gemini-3-flash" in written["accounts"]["shared"]["models"]


def test_invalid_gemini_rate_state_fails_closed(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())
    paths.rate_limits.write_text("{invalid", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid_gemini_rate_limits"):
        service.reserve_gemini_request("shared")

    marker = paths.recovery.with_name("rate-limits.recovery.json")
    assert marker.exists()


def test_v2_rate_limits_reject_unknown_fields_and_invalid_models(
    tmp_path: Path,
) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())
    service.reserve_gemini_request("shared", model="gemini-3-flash")
    valid_text = paths.rate_limits.read_text(encoding="utf-8")

    raw = json.loads(valid_text)
    raw["accounts"]["shared"]["unexpected"] = None
    paths.rate_limits.write_text(json.dumps(raw) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid_gemini_rate_limits"):
        service._load_rate_limits()

    raw = json.loads(valid_text)
    model_state = raw["accounts"]["shared"]["models"].pop("gemini-3-flash")
    raw["accounts"]["shared"]["models"]["gemini-3-flash:preview"] = model_state
    paths.rate_limits.write_text(json.dumps(raw) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid_gemini_rate_limits"):
        service._load_rate_limits()

    paths.rate_limits.write_text(valid_text, encoding="utf-8")
    entries = service._load_rate_limits()
    entries["shared"]["models"]["invalid-model"] = entries["shared"]["models"].pop(
        "gemini-3-flash"
    )
    with pytest.raises(ValueError, match="invalid_gemini_rate_limits"):
        service._write_rate_limits(entries)
    assert paths.rate_limits.read_text(encoding="utf-8") == valid_text


@pytest.mark.parametrize(
    ("account", "want"),
    [
        (
            _account(enabled=False, secret_state=SecretState.CONFIGURED),
            "account_disabled",
        ),
        (_account(), "secret_missing"),
        (_account(secret_state=SecretState.INVALID), "auth_invalid"),
        (
            _account(
                secret_state=SecretState.CONFIGURED, limit_state=LimitState.UNKNOWN
            ),
            "limit_unknown",
        ),
        (
            replace(
                _account(
                    secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY
                ),
                limit_reason="provider_unavailable",
            ),
            "provider_unavailable",
        ),
        (
            replace(
                _account(
                    secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY
                ),
                limit_reason="model_unavailable",
            ),
            "model_unavailable",
        ),
        (
            replace(
                _account(
                    secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY
                ),
                last_probe_at_utc="2026-08-03T11:44:59Z",
            ),
            "probe_stale",
        ),
        (
            replace(
                _account(
                    secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY
                ),
                last_probe_at_utc="2026-08-03T11:45:00Z",
            ),
            "ready",
        ),
    ],
)
def test_account_gate_uses_fixed_priority_codes(
    tmp_path: Path, account: FleetAccount, want: str
) -> None:
    service, _ = _service(tmp_path, FleetSnapshot(1, 2, (account,), (_series(),)))
    decision = service.account_gate("d1")
    assert decision.allowed is (want == "ready")
    assert decision.reason == want
    assert decision.account_id == "shared"
    assert decision.generation == 2


def test_series_gate_allows_accountless_ollama_and_rejects_disabled(
    tmp_path: Path,
) -> None:
    service, _ = _service(tmp_path)
    ollama = service.series_gate(_series(account_id=None))
    disabled = service.series_gate(_series(account_id=None, enabled=False))
    assert ollama == type(ollama)(True, "ready", None, 1)
    assert disabled == type(disabled)(False, "series_disabled", None, 1)


def test_probe_runs_without_registry_lock_and_sets_ready(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())
    real_io = service._io
    held = False
    held_during_probe: list[bool] = []

    @contextmanager
    def observed_lock():
        nonlocal held
        assert held is False
        held = True
        try:
            with real_io.lock():
                yield
        finally:
            held = False

    observed = type(service)(
        paths, replace(real_io, lock=observed_lock), pool_root=tmp_path / "pool"
    )

    def probe(account: FleetAccount) -> ProbeResult:
        held_during_probe.append(held)
        return ProbeResult(account.provider, True, "model", True, None)

    result = observed.probe_account("shared", probe, expected_generation=2)
    assert held_during_probe == [False]
    assert result == {
        "probed": True,
        "generation": 3,
        "ready": True,
        "reason": "ready",
        "model": "model",
    }
    assert observed.account_gate("d1").reason == "ready"


def test_probe_rejects_generation_change_while_external_call_runs(
    tmp_path: Path,
) -> None:
    from codex_master.fleet_service import FleetConflictError

    service, _ = _service(tmp_path, _configured_snapshot())

    def probe(account: FleetAccount) -> ProbeResult:
        service.mark_limited(
            account.account_id, reset_at_utc=None, reason="provider_429"
        )
        return ProbeResult(account.provider, True, "model", True, None)

    with pytest.raises(FleetConflictError):
        service.probe_account("shared", probe, expected_generation=2)

    assert service.account_gate("d1").reason == "limit_active"


@pytest.mark.parametrize(
    ("kind", "want", "secret_state", "retryable", "status_code"),
    [
        ("account_limited", "limit_active", SecretState.CONFIGURED, True, 429),
        ("auth_invalid", "auth_invalid", SecretState.INVALID, True, 429),
        ("secret_missing", "secret_missing", SecretState.MISSING, True, 429),
        (
            "provider_unavailable",
            "provider_unavailable",
            SecretState.CONFIGURED,
            True,
            429,
        ),
        ("model_unavailable", "model_unavailable", SecretState.CONFIGURED, True, 429),
        ("runner_failed", "runner_failed", SecretState.CONFIGURED, False, None),
    ],
)
def test_probe_errors_become_fixed_gate_reasons(
    tmp_path: Path,
    kind: str,
    want: str,
    secret_state: SecretState,
    retryable: bool,
    status_code: int | None,
) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())
    diagnostic_code = (
        "gemini_probe_generate_content_http_4xx_contract_rejected"
        if kind == "runner_failed"
        else None
    )
    error = ProviderError(  # type: ignore[arg-type]
        kind,
        retryable,
        status_code,
        None,
        diagnostic_code=diagnostic_code,
    )
    result = service.probe_account(
        "shared",
        lambda account: ProbeResult(
            account.provider,
            False,
            "model",
            False,
            error,
            endpoint_role="generate_content" if kind == "runner_failed" else None,
            http_class="4xx" if kind == "runner_failed" else None,
        ),
        expected_generation=2,
    )
    assert result["reason"] == want
    assert service.load().accounts[0].secret_state is secret_state
    assert service.account_gate("d1").reason == want
    if kind == "runner_failed":
        assert (
            result["diagnostic_code"]
            == "gemini_probe_generate_content_http_4xx_contract_rejected"
        )
        assert result["endpoint_role"] == "generate_content"
        assert result["http_class"] == "4xx"
        gate = service.gemini_headless_gate("d1")
        assert gate.diagnostic_code == "gemini_runner_failed"
        assert gate.retryable is False
        assert gate.action == "reject"
        service.record_gemini_event(
            event_type="account_probe",
            agent_id="probe",
            account_id="shared",
            assignment_id=None,
            status="failed",
            reason=want,
            gate_action=gate.action,
            gate_code=gate.diagnostic_code,
            diagnostic_code=result["diagnostic_code"],
            endpoint_role=result["endpoint_role"],
            http_class=result["http_class"],
        )
        event = service.gemini_event_status(limit=1)[0]
        assert event["reason"] == "runner_failed"
        assert event["gate_code"] == "gemini_runner_failed"
        assert event["gate_action"] == "reject"
        assert (
            event["diagnostic_code"]
            == "gemini_probe_generate_content_http_4xx_contract_rejected"
        )
        assert event["endpoint_role"] == "generate_content"
        assert event["http_class"] == "4xx"


@pytest.mark.parametrize(
    ("quota_scope", "retry_after_seconds"),
    [
        ("model", None),
        ("account", 120),
        ("unknown", 120),
    ],
)
def test_probe_model_scope_without_retry_or_accountwide_scopes_fail_closed(
    tmp_path: Path,
    quota_scope: str,
    retry_after_seconds: int | None,
) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())
    error = ProviderError(
        "account_limited",
        True,
        429,
        "2026-08-03T12:03:00Z",
        quota_observation=ProviderErrorQuotaObservation(
            scope=quota_scope,
            retry_after_seconds=retry_after_seconds,
        ),
    )

    result = service.probe_account(
        "shared",
        lambda account: ProbeResult(
            account.provider, False, "gemini-3.1-flash", False, error
        ),
        expected_generation=2,
    )

    assert result["reason"] == "limit_active"
    assert service.account_gate("d1").reason == "limit_active"
    events = service._load_usage().get("shared", [])
    assert events
    assert events[-1]["quota_scope"] == quota_scope
    assert events[-1]["quota_retry_after_seconds"] == retry_after_seconds
    assert events[-1]["gate_code"] == "gemini_account_limited"
    assert (
        service._load_limits().get("shared", {}).get("reset_at_utc")
        == "2026-08-03T12:03:00Z"
    )


def test_record_gemini_event_unknown_diagnostic_code_is_omitted(tmp_path: Path) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())

    for malformed_http_class in ({"class": "4xx"}, ["4xx"]):
        probe_status = service._probe_status(
            service.load(),
            ready=False,
            reason="runner_failed",
            http_class=malformed_http_class,  # type: ignore[arg-type]
        )
        assert "http_class" not in probe_status

        result = service.record_gemini_event(
            event_type="account_probe",
            agent_id="probe",
            account_id="shared",
            assignment_id=None,
            status="failed",
            reason="provider_unavailable",
            diagnostic_code="unknown_code",
            endpoint_role="unknown_endpoint",
            http_class=malformed_http_class,  # type: ignore[arg-type]
        )

        assert result["recorded"] is True
        events = service.gemini_event_status(limit=1)
        assert len(events) == 1
        assert "diagnostic_code" not in events[0]
        assert "endpoint_role" not in events[0]
        assert "http_class" not in events[0]


def test_detail_poor_429_binds_account_limit_to_existing_rate_cooldown(
    tmp_path: Path, monkeypatch
) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())
    reservation = service.reserve_gemini_request("shared")
    monkeypatch.setattr(
        service, "reserve_gemini_request", lambda _account_id, **_kwargs: reservation
    )

    assert (
        service.gemini_rate_status("shared").get("defer_until")
        == "2026-08-03T14:01:00Z"
    )

    result = service.probe_account(
        "shared",
        lambda account: ProbeResult(
            account.provider,
            False,
            "gemini-3.1-flash",
            False,
            ProviderError("account_limited", True, 429, None),
        ),
        expected_generation=2,
    )

    assert result["reason"] == "limit_active"
    assert service.account_gate("d1").reason == "limit_active"
    assert service._load_limits()["shared"] == {
        "reset_at_utc": "2026-08-03T12:15:00Z",
        "reason": "provider_429",
    }
    assert (
        service.gemini_rate_status("shared").get("defer_until")
        == "2026-08-03T12:15:00Z"
    )

    service._io = replace(
        service._io, utc_now=lambda: datetime(2026, 8, 3, 12, 16, tzinfo=timezone.utc)
    )
    assert service.account_gate("d1").reason == "limit_unknown"


@pytest.mark.parametrize(
    ("inject_invalid_local_deadline", "raise_status"),
    [
        (False, False),
        (True, False),
        (False, True),
    ],
)
def test_detail_poor_429_without_valid_rate_deadline_remains_unbounded_limited(
    tmp_path: Path,
    monkeypatch,
    inject_invalid_local_deadline: bool,
    raise_status: bool,
) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())
    if raise_status:

        def _raise_status(_account_id: str) -> dict[str, object]:
            raise RuntimeError("status-unavailable")
    elif inject_invalid_local_deadline:
        status = {
            "defer_until": "not-a-time",
            "allowed": False,
            "reason": "gemini_local_rate_limit",
        }
    else:
        status = {}
    if raise_status:
        monkeypatch.setattr(service, "gemini_rate_status", _raise_status)
    else:
        monkeypatch.setattr(
            service,
            "gemini_rate_status",
            lambda _account_id: status,
        )

    result = service.probe_account(
        "shared",
        lambda account: ProbeResult(
            account.provider,
            False,
            "gemini-3.1-flash",
            False,
            ProviderError("account_limited", True, 429, None),
        ),
        expected_generation=2,
    )

    assert result["reason"] == "limit_active"
    assert service._load_limits()["shared"]["reset_at_utc"] is None
    service._io = replace(
        service._io, utc_now=lambda: datetime(2026, 8, 3, 13, 0, tzinfo=timezone.utc)
    )
    assert service.account_gate("d1").reason == "limit_active"


def test_legacy_usage_events_missing_quota_fields_normalize_to_none(
    tmp_path: Path,
) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())
    paths.usage.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "accounts": {
                    "shared": [
                        {
                            "at_utc": "2026-08-03T12:00:00Z",
                            "model": "gemini-3.1-flash",
                            "input_tokens": 1,
                            "output_tokens": 0,
                            "tool_call_count": 0,
                            "status": "failed",
                        }
                    ],
                },
            },
        )
        + "\n",
        encoding="utf-8",
    )

    status = service.gemini_usage_status("shared")
    loaded = service._load_usage()
    assert status["quota_evaluation"]["quota_observation"] is None
    assert loaded["shared"][-1]["quota_scope"] is None
    assert loaded["shared"][-1]["quota_retry_after_seconds"] is None


def test_probe_model_scope_limit_records_model_lock_not_account_limit(
    tmp_path: Path,
) -> None:
    account = _account(
        "shared", secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY
    )
    service, _ = _service(
        tmp_path,
        FleetSnapshot(
            1,
            2,
            (account,),
            (_series("d", account_id="shared", model="gemini-3-flash"),),
        ),
    )

    error = ProviderError(
        "account_limited",
        True,
        429,
        "2026-08-03T12:03:00Z",
        quota_observation=ProviderErrorQuotaObservation(
            scope="model", retry_after_seconds=120
        ),
    )

    result = service.probe_account(
        "shared",
        lambda account: ProbeResult(
            account.provider, False, "gemini-3-flash", False, error
        ),
        expected_generation=2,
    )
    assert result["reason"] == "ready"
    assert service.account_gate("d1").reason == "ready"
    assert service._load_limits() == {}

    decision = service.gemini_headless_gate("d1")
    assert decision.diagnostic_code == "gemini_model_limited"
    assert decision.action == "defer_until"
    assert decision.defer_until == "2026-08-03T12:02:00Z"

    rate_limits = service._load_rate_limits()
    assert rate_limits.get("shared", {}).get("cooldown_until_utc") is None

    service._io = replace(
        service._io, utc_now=lambda: datetime(2026, 8, 3, 12, 2, tzinfo=timezone.utc)
    )
    decision = service.gemini_headless_gate("d1")
    assert decision.action == "allow"


def test_model_scope_limit_survives_followup_model_usage_without_quota_fields(
    tmp_path: Path,
) -> None:
    account = _account(
        "shared", secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY
    )
    service, _ = _service(
        tmp_path,
        FleetSnapshot(
            1,
            2,
            (account,),
            (_series("d", account_id="shared", model="gemini-3-flash"),),
        ),
    )

    service.record_gemini_usage(
        "shared",
        model="gemini-3-flash",
        status="failed",
        gate_action="defer_until",
        gate_code="gemini_model_limited",
        next_reset_at_utc="2026-08-03T12:04:00Z",
        quota_observation=ProviderErrorQuotaObservation(
            scope="model",
            retry_after_seconds=120,
        ),
    )
    service.record_gemini_usage(
        "shared",
        model="gemini-3-flash",
        status="completed",
    )
    result = service.probe_account(
        "shared",
        lambda account: ProbeResult(
            account.provider, True, "gemini-3-flash", False, None
        ),
        expected_generation=2,
    )
    assert result["reason"] == "ready"

    status = service.gemini_usage_status("shared", model="gemini-3-flash")
    observation = status["quota_evaluation"]["quota_observation"]
    assert isinstance(observation, dict)
    assert observation["scope"] == "model"
    assert observation["retry_after_seconds"] == 120

    rate_limits = service._load_rate_limits()
    assert rate_limits.get("shared", {}).get("cooldown_until_utc") is None

    decision = service.gemini_headless_gate("d1")
    assert decision.action == "defer_until"
    assert decision.diagnostic_code == "gemini_model_limited"


def test_probe_exception_is_redacted_from_public_result(tmp_path: Path) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())

    def failing_probe(account: FleetAccount) -> ProbeResult:
        raise RuntimeError("SYNTHETIC-KEY /private/path backend-value")

    result = service.probe_account("shared", failing_probe, expected_generation=2)
    rendered = repr((result, service.public_snapshot()))
    assert result["reason"] == "provider_unavailable"
    assert "SYNTHETIC-KEY" not in rendered
    assert "/private/path" not in rendered
    assert "backend-value" not in rendered


def test_private_io_distinguishes_missing_from_unsafe_files(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetPaths
    from codex_master.server import AgentError, build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path)
    io = build_fleet_private_io(paths)
    io.ensure_dir(paths.root)
    io.ensure_dir(paths.secrets)
    assert io.read_text(paths.registry, 1024, "registry_error") is None
    assert io.read_bytes(paths.secrets / "missing.secret", 1024, "secret_error") is None
    target = tmp_path / "target"
    target.write_text("data")
    paths.registry.symlink_to(target)
    with pytest.raises(AgentError, match="registry_error"):
        io.read_text(paths.registry, 1024, "registry_error")


@pytest.mark.parametrize("kind", ["text", "bytes"])
@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_private_io_rejects_symlink_and_hardlink_writes(
    tmp_path: Path, kind: str, link_kind: str
) -> None:
    from codex_master.fleet_service import FleetPaths
    from codex_master.server import AgentError, build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path)
    io = build_fleet_private_io(paths)
    io.ensure_dir(paths.root)
    target = tmp_path / "target"
    target.write_text("untouched")
    target_path = paths.registry
    if link_kind == "symlink":
        target_path.symlink_to(target)
    else:
        os.link(target, target_path)
    with pytest.raises(AgentError):
        if kind == "text":
            io.replace_text(target_path, "changed")
        else:
            io.replace_bytes(target_path, b"changed", 0o600)
    assert target.read_text() == "untouched"


def test_private_lock_is_reentrant_and_redacts_paths(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetPaths
    from codex_master.server import build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path / "private-state")
    io = build_fleet_private_io(paths)
    with io.lock():
        with io.lock():
            assert os.stat(paths.lock).st_mode & 0o777 == 0o600
    assert all(
        str(path) not in repr(paths)
        for path in (
            paths.root,
            paths.registry,
            paths.secrets,
            paths.limits,
            paths.lock,
        )
    )


def test_private_lock_serializes_cross_thread_registry_access(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetPaths
    from codex_master.server import build_fleet_private_io

    io = build_fleet_private_io(FleetPaths.from_state_root(tmp_path / "private-state"))
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def first() -> None:
        with io.lock():
            first_entered.set()
            release_first.wait(2)

    def second() -> None:
        first_entered.wait(1)
        with io.lock():
            second_entered.set()

    first_thread = threading.Thread(target=first)
    second_thread = threading.Thread(target=second)
    first_thread.start()
    assert first_entered.wait(1)
    second_thread.start()
    assert not second_entered.wait(0.05)
    release_first.set()
    first_thread.join(2)
    second_thread.join(2)
    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert second_entered.is_set()
