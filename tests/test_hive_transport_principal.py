from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_master.hive import transport_principal
from codex_master.hive.authority import AuthorityContext, AuthorityEngine
from codex_master.hive.principals import ExecutionBinding, Principal, PrincipalRegistry
from codex_master.hive.repositories import RepositoryBinding, RepositoryRegistry
from codex_master.hive.transport_principal import (
    AttestedPrincipalV1,
    TransportPrincipalAdapter,
    TransportPrincipalError,
    VerifiedTransportClaims,
)


NOW = datetime(2026, 8, 16, 12, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64
TRANSPORT_DIGEST = "sha256:" + "b" * 64
RESOURCE_SCOPE = (".codex-master/resource-status",)
CAPABILITIES = (
    "hive.resource.trend.read",
    "hive.resource.absolute.read",
)


def test_transport_identifier_redacts_validation_details() -> None:
    assert transport_principal._identifier("principal-one", "principal") == "principal-one"
    with pytest.raises(TransportPrincipalError, match="resource_access_denied"):
        transport_principal._identifier("bad principal", "principal")


class FakeVerifier:
    def __init__(self, claims: object) -> None:
        self.claims = claims
        self.calls: list[tuple[object, datetime]] = []

    def verify(self, evidence: object, *, now: datetime) -> object:
        self.calls.append((evidence, now))
        return self.claims


class RejectingVerifier:
    def __init__(self, marker: str) -> None:
        self.marker = marker

    def verify(self, evidence: object, *, now: datetime) -> object:
        raise TransportPrincipalError(self.marker)


class ExplodingVerifier:
    def verify(self, evidence: object, *, now: datetime) -> object:
        raise RuntimeError("internal verifier failure")


class ExplodingClock:
    def __call__(self) -> datetime:
        raise RuntimeError("internal clock failure")


class CountingClock:
    def __init__(self, now: datetime = NOW) -> None:
        self.now = now
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return self.now


def _principal(principal_id: str, class_id: str, parent_id: str | None, repo_id: str | None) -> Principal:
    return Principal(
        principal_id,
        class_id,
        parent_id,
        "resource-reader",
        "global" if repo_id is None else "repository",
        repo_id,
        "active",
        DIGEST,
        1,
    )


def _registry(class_id: str) -> PrincipalRegistry:
    registry = PrincipalRegistry()
    registry.create(_principal("godbee-main", "gottbiene", None, None))
    if class_id == "teamleiterin":
        registry.create(_principal("queen-repo", "koenigin", "godbee-main", "repo-one"))
        registry.create(_principal("resource-reader", class_id, "queen-repo", "repo-one"))
    else:
        registry.create(_principal("resource-reader", class_id, "godbee-main", "repo-one"))
    registry.bind_execution(
        ExecutionBinding(
            "binding-one",
            "resource-reader",
            "repo-one",
            "dispatch-one",
            "agent-one",
            "private-account",
            "model-one",
            "lease-one",
            "admission-one",
            "active",
            "2026-08-16T12:00:45Z",
        )
    )
    return registry


def _authority(tmp_path: Path, registry: PrincipalRegistry, capabilities: frozenset[str]) -> AuthorityEngine:
    root = tmp_path / "repo"
    root.mkdir()
    repositories = RepositoryRegistry(
        (RepositoryBinding("repo-one", "https://example.invalid/repo.git", root, "main", DIGEST),)
    )
    return AuthorityEngine(
        AuthorityContext(registry, repositories, {"resource-reader": capabilities})
    )


def _claims(
    *,
    class_id: str = "teamleiterin",
    issued_at_utc: datetime = NOW,
    expires_at_utc: datetime = NOW + timedelta(seconds=30),
    principal_id: str = "resource-reader",
    repo_id: str = "repo-one",
    principal_version: int = 1,
    config_digest: str = DIGEST,
    execution_binding_id: str = "binding-one",
) -> VerifiedTransportClaims:
    return VerifiedTransportClaims(
        principal_id=principal_id,
        class_id=class_id,
        repo_id=repo_id,
        principal_version=principal_version,
        config_digest=config_digest,
        execution_binding_id=execution_binding_id,
        transport_digest=TRANSPORT_DIGEST,
        issued_at_utc=issued_at_utc,
        expires_at_utc=expires_at_utc,
    )


def _adapter(
    tmp_path: Path,
    *,
    class_id: str = "teamleiterin",
    claims: object | None = None,
    capabilities: frozenset[str] = frozenset(CAPABILITIES),
    clock: CountingClock | None = None,
) -> tuple[TransportPrincipalAdapter, PrincipalRegistry, FakeVerifier, CountingClock]:
    registry = _registry(class_id)
    verifier = FakeVerifier(claims if claims is not None else _claims(class_id=class_id))
    used_clock = clock or CountingClock()
    return (
        TransportPrincipalAdapter(
            registry,
            _authority(tmp_path, registry, capabilities),
            verifier,
            now=used_clock,
        ),
        registry,
        verifier,
        used_clock,
    )


@pytest.mark.parametrize("class_id", ("teamleiterin", "koenigin", "queen"))
@pytest.mark.parametrize("capability", CAPABILITIES)
def test_attests_only_exact_allowed_principal_classes_and_fixed_resource_capabilities(
    tmp_path: Path, class_id: str, capability: str
) -> None:
    adapter, _, verifier, clock = _adapter(tmp_path, class_id=class_id)
    evidence = object()

    attested = adapter.attest(evidence, capability=capability)

    assert attested == AttestedPrincipalV1(
        attestation_schema_version=1,
        principal_id="resource-reader",
        class_id=class_id,
        repo_id="repo-one",
        scope=RESOURCE_SCOPE,
        principal_version=1,
        config_digest=DIGEST,
        execution_binding_id="binding-one",
        attested_transport_digest=TRANSPORT_DIGEST,
        expires_at_utc=NOW + timedelta(seconds=30),
    )
    assert verifier.calls == [(evidence, NOW)]
    assert clock.calls == 1
    assert not hasattr(attested, "__dict__")
    with pytest.raises(FrozenInstanceError):
        attested.class_id = "worker"  # type: ignore[misc]


@pytest.mark.parametrize(
    "class_id",
    ("teamleader-v1", "teamleader", "teamlead", "worker", "arbeitsbiene", "specialist", "spezialistin"),
)
def test_denies_legacy_alias_and_worker_class_claims(tmp_path: Path, class_id: str) -> None:
    adapter, _, _, _ = _adapter(tmp_path, claims=_claims(class_id=class_id))

    _denies(adapter, object(), capability=CAPABILITIES[0])


@pytest.mark.parametrize(
    "claims",
    (
        {"principal_id": "resource-reader"},
        _claims(principal_id="other-principal"),
        _claims(repo_id="other-repo"),
        _claims(principal_version=2),
        _claims(config_digest="sha256:" + "c" * 64),
        _claims(execution_binding_id="binding-other"),
        _claims(issued_at_utc=NOW - timedelta(seconds=30), expires_at_utc=NOW),
    ),
)
def test_denies_unverified_or_nonmatching_transport_claims(tmp_path: Path, claims: object) -> None:
    adapter, _, _, _ = _adapter(tmp_path, claims=claims)

    _denies(adapter, object(), capability=CAPABILITIES[0])


def test_denies_claims_issued_after_injected_clock(tmp_path: Path) -> None:
    adapter, _, _, _ = _adapter(
        tmp_path,
        claims=_claims(
            issued_at_utc=NOW + timedelta(seconds=1),
            expires_at_utc=NOW + timedelta(seconds=31),
        ),
    )

    _denies(adapter, object(), capability=CAPABILITIES[0])


def test_revalidates_binding_after_live_revocation(tmp_path: Path) -> None:
    adapter, registry, _, _ = _adapter(tmp_path)
    evidence = object()

    assert adapter.attest(evidence, capability=CAPABILITIES[0]).execution_binding_id == "binding-one"
    registry.release_execution("binding-one")

    _denies(adapter, evidence, capability=CAPABILITIES[0])


@pytest.mark.parametrize(
    "capabilities, capability",
    (
        (frozenset(), CAPABILITIES[0]),
        (frozenset(CAPABILITIES), "hive.resource.other.read"),
    ),
)
def test_denies_missing_or_caller_supplied_capability(
    tmp_path: Path, capabilities: frozenset[str], capability: str
) -> None:
    adapter, _, _, _ = _adapter(tmp_path, capabilities=capabilities)

    _denies(adapter, object(), capability=capability)


def test_constructor_denies_authority_with_different_principal_registry(tmp_path: Path) -> None:
    principals = _registry("teamleiterin")
    authority_principals = _registry("teamleiterin")

    with pytest.raises(TransportPrincipalError, match="resource_access_denied") as caught:
        TransportPrincipalAdapter(
            principals,
            _authority(tmp_path, authority_principals, frozenset(CAPABILITIES)),
            FakeVerifier(_claims()),
            now=CountingClock(),
        )

    assert caught.value.__cause__ is None


def test_denies_verifier_failure_without_leaking_transport_markers(tmp_path: Path) -> None:
    registry = _registry("teamleiterin")
    marker = "secret-home-/home/forbidden-session-123-pid-999-account-private"
    adapter = TransportPrincipalAdapter(
        registry,
        _authority(tmp_path, registry, frozenset(CAPABILITIES)),
        RejectingVerifier(marker),
        now=CountingClock(),
    )
    recursive_evidence: list[object] = []
    recursive_evidence.append(recursive_evidence)

    with pytest.raises(TransportPrincipalError) as caught:
        adapter.attest(recursive_evidence, capability=CAPABILITIES[0])

    assert str(caught.value) == "resource_access_denied"
    assert repr(caught.value) == "TransportPrincipalError('resource_access_denied')"
    assert caught.value.__cause__ is None
    assert marker not in str(caught.value)
    assert marker not in repr(caught.value)


def test_propagates_unexpected_verifier_failure(tmp_path: Path) -> None:
    registry = _registry("teamleiterin")
    adapter = TransportPrincipalAdapter(
        registry,
        _authority(tmp_path, registry, frozenset(CAPABILITIES)),
        ExplodingVerifier(),
        now=CountingClock(),
    )

    with pytest.raises(RuntimeError, match="internal verifier failure"):
        adapter.attest(object(), capability=CAPABILITIES[0])


def test_propagates_unexpected_clock_failure(tmp_path: Path) -> None:
    registry = _registry("teamleiterin")
    adapter = TransportPrincipalAdapter(
        registry,
        _authority(tmp_path, registry, frozenset(CAPABILITIES)),
        FakeVerifier(_claims()),
        now=ExplodingClock(),
    )

    with pytest.raises(RuntimeError, match="internal clock failure"):
        adapter.attest(object(), capability=CAPABILITIES[0])


def test_denies_invalid_clock_time(tmp_path: Path) -> None:
    adapter, _, _, _ = _adapter(tmp_path, clock=CountingClock(NOW.replace(tzinfo=None)))

    _denies(adapter, object(), capability=CAPABILITIES[0])


@pytest.mark.parametrize(
    "kwargs",
    (
        {"attestation_schema_version": 2},
        {"class_id": "teamlead"},
        {"scope": ("src",)},
        {"attested_transport_digest": "not-a-digest"},
    ),
)
def test_attested_principal_rejects_invalid_public_shape(kwargs: dict[str, object]) -> None:
    valid = AttestedPrincipalV1(
        attestation_schema_version=1,
        principal_id="resource-reader",
        class_id="teamleiterin",
        repo_id="repo-one",
        scope=RESOURCE_SCOPE,
        principal_version=1,
        config_digest=DIGEST,
        execution_binding_id="binding-one",
        attested_transport_digest=TRANSPORT_DIGEST,
        expires_at_utc=NOW + timedelta(seconds=30),
    )

    with pytest.raises(TransportPrincipalError, match="resource_access_denied"):
        replace(valid, **kwargs)


@pytest.mark.parametrize(
    "kwargs",
    (
        {"issued_at_utc": NOW + timedelta(seconds=30)},
        {"expires_at_utc": NOW + timedelta(seconds=61)},
        {"issued_at_utc": datetime(2026, 8, 16, 12)},
    ),
)
def test_verified_transport_claims_reject_invalid_time_bounds(kwargs: dict[str, object]) -> None:
    with pytest.raises(TransportPrincipalError, match="resource_access_denied"):
        replace(_claims(), **kwargs)


def _denies(adapter: TransportPrincipalAdapter, evidence: object, *, capability: str) -> None:
    with pytest.raises(TransportPrincipalError, match="resource_access_denied") as caught:
        adapter.attest(evidence, capability=capability)
    assert caught.value.__cause__ is None
