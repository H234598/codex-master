"""Offline runtime boundary for one kernel-attested broker start grant.

Grant issuance is internal to trusted root-broker process code. Request, MCP,
and broker payloads carry only public dataclass fields and cannot carry issuer
state.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Protocol

from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_home_broker_linux import (
    LinuxOperations,
    PeerSnapshot,
    attest_peer_principal,
)
from codex_master.fleet_home_broker_protocol import (
    MAX_CHPB_DEVICE,
    MAX_CHPB_GENERATION,
    MAX_CHPB_INODE,
    PrincipalBinding,
    validate_principal_binding,
)
from codex_master.fleet_home_broker_transport import BrokerPeer


class RuntimeBoundaryError(ValueError):
    """Raised when an offline runtime boundary cannot be attested safely."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class KernelPeerEvidence:
    pid: int
    uid: int
    gid: int
    start_time: int
    cgroup_dev: int
    cgroup_ino: int
    unit_generation: int
    invocation_id: str
    mcs_pair: str


@dataclass(frozen=True, slots=True)
class CredentialProjection:
    profile_id: str
    binding_id: str
    generation: int
    provider: str
    fds: tuple[int, ...]


class _StartGrantCarrier:
    __slots__ = ("_grant_state",)

    def __copy__(self):
        return self

    def __deepcopy__(self, _memo):
        return self

    def __reduce_ex__(self, _protocol):
        raise TypeError("start grant is not serializable")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class StartGrant(_StartGrantCarrier):
    peer: BrokerPeer
    evidence: KernelPeerEvidence
    principal: PrincipalBinding
    identity: BrokerIdentity
    profile_id: str
    binding_id: str
    generation: int
    provider: str
    projection: CredentialProjection


class RuntimePeerOperations(Protocol):
    def is_root_system_bus_gateway(self) -> bool: ...

    def read_kernel_peer_evidence(self, peer: BrokerPeer) -> KernelPeerEvidence: ...

    def close(self, fd: int) -> None: ...


class RuntimePrincipalResolver(Protocol):
    def resolve_principal(self, evidence: KernelPeerEvidence) -> PrincipalBinding: ...


class CredentialProjectionProvider(Protocol):
    def project(
        self,
        profile_id: str,
        binding_id: str,
        generation: int,
        provider: str,
    ) -> CredentialProjection: ...


_MAX_ID = 2**32 - 1
_MAX_TEXT = 256


class _StartGrantState:
    __slots__ = ("_binding", "_claimed", "_lock", "__weakref__")

    def __init__(self, binding: tuple[object, ...]):
        self._binding = binding
        self._claimed = False
        self._lock = Lock()

    def matches(self, binding: tuple[object, ...]) -> bool:
        return self._binding == binding

    def claim(self) -> bool:
        with self._lock:
            if self._claimed:
                return False
            self._claimed = True
            return True

    def projection(self) -> object:
        return self._binding[-1]


def _fail(message: str) -> None:
    raise RuntimeBoundaryError(message) from None


def _text(value: object, field: str) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "\x00" in value
        or any(ord(char) < 32 for char in value)
        or len(value) > _MAX_TEXT
    ):
        _fail(f"{field} is invalid")


def _generation(value: object, field: str) -> None:
    if type(value) is not int or not 1 <= value <= MAX_CHPB_GENERATION:
        _fail(f"{field} is invalid")


def _validate_runtime_binding(
    profile_id: object,
    binding_id: object,
    generation: object,
    provider: object,
    identity: object,
) -> None:
    try:
        _text(profile_id, "profile id")
        _text(binding_id, "binding id")
        _generation(generation, "generation")
        _text(provider, "provider")
    except RuntimeBoundaryError:
        _fail("runtime binding is invalid")
    if type(identity) is not BrokerIdentity:
        _fail("broker identity is invalid")
    if generation != identity.policy_generation:
        _fail("generation is not bound to broker identity")


def _validate_peer(peer: object) -> BrokerPeer:
    if type(peer) is not BrokerPeer:
        _fail("broker peer is invalid")
    return peer


def _validate_evidence(value: object, peer: BrokerPeer) -> KernelPeerEvidence:
    if type(value) is not KernelPeerEvidence:
        _fail("kernel peer evidence is invalid")
    if (
        type(value.pid) is not int
        or value.pid <= 0
        or value.pid != peer.pid
        or type(value.uid) is not int
        or not 0 <= value.uid <= _MAX_ID
        or type(value.gid) is not int
        or not 0 <= value.gid <= _MAX_ID
        or type(value.start_time) is not int
        or not 1 <= value.start_time <= MAX_CHPB_GENERATION
        or type(value.cgroup_dev) is not int
        or not 0 <= value.cgroup_dev <= MAX_CHPB_DEVICE
        or type(value.cgroup_ino) is not int
        or not 1 <= value.cgroup_ino <= MAX_CHPB_INODE
        or type(value.unit_generation) is not int
        or not 1 <= value.unit_generation <= MAX_CHPB_GENERATION
    ):
        _fail("kernel peer evidence is invalid")
    _text(value.invocation_id, "invocation id")
    _text(value.mcs_pair, "MCS pair")
    return value


def _snapshot(value: KernelPeerEvidence) -> PeerSnapshot:
    return PeerSnapshot(
        value.pid,
        value.cgroup_dev,
        value.cgroup_ino,
        value.invocation_id,
        value.unit_generation,
        value.mcs_pair,
    )


def _validate_principal(
    value: object, evidence: KernelPeerEvidence, identity: BrokerIdentity
) -> PrincipalBinding:
    if type(value) is not PrincipalBinding:
        _fail("principal resolution failed")
    try:
        validate_principal_binding(value)
    except Exception:
        _fail("principal resolution failed")
    if (
        value.unit_generation != evidence.unit_generation
        or value.cgroup_dev != evidence.cgroup_dev
        or value.cgroup_ino != evidence.cgroup_ino
        or value.invocation_id != evidence.invocation_id
        or value.mcs_pair != evidence.mcs_pair
        or value.agent_id != identity.agent_id
        or value.manifest_generation != identity.manifest_generation
        or value.mcs_pair != identity.mcs_pair
        or value.fencing_epoch != identity.fencing_epoch
    ):
        _fail("principal resolution failed")
    return value


def _projection_fds(value: object) -> tuple[int, ...]:
    try:
        fds = value.fds
    except Exception:
        return ()
    if type(fds) not in (tuple, list):
        return ()
    result = []
    for fd in fds:
        if type(fd) is int and fd >= 0 and fd not in result:
            result.append(fd)
    return tuple(result)


def _close_projection(operations: RuntimePeerOperations, value: object) -> None:
    for fd in _projection_fds(value):
        try:
            operations.close(fd)
        except Exception:
            pass


def _start_grant_binding(grant: StartGrant) -> tuple[object, ...]:
    return (
        grant.peer,
        grant.evidence,
        grant.principal,
        grant.identity,
        grant.profile_id,
        grant.binding_id,
        grant.generation,
        grant.provider,
        grant.projection,
    )


def _start_grant_state(grant: StartGrant) -> _StartGrantState:
    try:
        state = grant._grant_state
    except AttributeError:
        _fail("start grant is invalid")
    if type(state) is not _StartGrantState:
        _fail("start grant is invalid")
    return state


def _issue_start_grant(binding: tuple[object, ...]) -> StartGrant:
    """Issue only inside trusted root-broker attestation code."""

    grant = StartGrant(*binding)
    object.__setattr__(grant, "_grant_state", _StartGrantState(binding))
    return grant


def _validate_projection(
    value: object,
    profile_id: object,
    binding_id: object,
    generation: object,
    provider: object,
) -> CredentialProjection:
    if type(value) is not CredentialProjection or type(value.fds) is not tuple:
        _fail("credential projection is invalid")
    if (
        value.profile_id != profile_id
        or value.binding_id != binding_id
        or value.generation != generation
        or value.provider != provider
    ):
        _fail("credential projection binding drifted")
    try:
        _text(value.profile_id, "projection profile id")
        _text(value.binding_id, "projection binding id")
        _generation(value.generation, "projection generation")
        _text(value.provider, "projection provider")
    except RuntimeBoundaryError:
        _fail("credential projection is invalid")
    if not value.fds or any(type(fd) is not int or fd < 0 for fd in value.fds):
        _fail("credential projection is invalid")
    if len(set(value.fds)) != len(value.fds):
        _fail("credential projection is invalid")
    return value


def _read_evidence(
    operations: RuntimePeerOperations, peer: BrokerPeer
) -> KernelPeerEvidence:
    try:
        value = operations.read_kernel_peer_evidence(peer)
    except Exception:
        _fail("kernel peer evidence unavailable")
    return _validate_evidence(value, peer)


def _read_rechecked_evidence(
    operations: RuntimePeerOperations, peer: BrokerPeer
) -> KernelPeerEvidence:
    try:
        return _read_evidence(operations, peer)
    except RuntimeBoundaryError:
        _fail("peer evidence drifted")


def attest_kernel_peer(
    peer: BrokerPeer,
    identity: BrokerIdentity,
    profile_id: str,
    binding_id: str,
    generation: int,
    provider: str,
    peer_operations: RuntimePeerOperations,
    linux_operations: LinuxOperations,
    principal_resolver: RuntimePrincipalResolver,
    projection_provider: CredentialProjectionProvider,
) -> StartGrant:
    """Return one bound start grant after root-gateway kernel attestation."""

    peer = _validate_peer(peer)
    if not callable(getattr(peer_operations, "is_root_system_bus_gateway", None)):
        _fail("root system bus gateway required")
    try:
        root_gateway = peer_operations.is_root_system_bus_gateway()
    except Exception:
        _fail("root system bus gateway required")
    if root_gateway is not True:
        _fail("root system bus gateway required")
    _validate_runtime_binding(profile_id, binding_id, generation, provider, identity)
    if not callable(getattr(principal_resolver, "resolve_principal", None)):
        _fail("principal resolution failed")
    if not callable(getattr(projection_provider, "project", None)):
        _fail("credential projection failed")

    first_evidence = _read_evidence(peer_operations, peer)
    try:
        principal = principal_resolver.resolve_principal(first_evidence)
    except Exception:
        _fail("principal resolution failed")
    principal = _validate_principal(principal, first_evidence, identity)

    try:
        observed_snapshot = attest_peer_principal(linux_operations, peer.pid, principal)
    except Exception:
        _fail("kernel peer attestation failed")
    if observed_snapshot != _snapshot(first_evidence):
        _fail("peer evidence drifted")

    second_evidence = _read_rechecked_evidence(peer_operations, peer)
    if second_evidence != first_evidence:
        _fail("peer evidence drifted")

    try:
        projection = projection_provider.project(
            profile_id, binding_id, generation, provider
        )
    except Exception:
        _fail("credential projection failed")
    try:
        projection = _validate_projection(
            projection, profile_id, binding_id, generation, provider
        )
        third_evidence = _read_rechecked_evidence(peer_operations, peer)
        if third_evidence != first_evidence:
            _fail("peer evidence drifted")
        binding = (
            peer,
            first_evidence,
            principal,
            identity,
            profile_id,
            binding_id,
            generation,
            provider,
            projection,
        )
        return _issue_start_grant(binding)
    except RuntimeBoundaryError:
        _close_projection(peer_operations, projection)
        raise
    except Exception:
        _close_projection(peer_operations, projection)
        _fail("runtime grant construction failed")


class OneShotGrantConsumer:
    __slots__ = ("_grant", "_operations")

    def __init__(self, grant: StartGrant, operations: RuntimePeerOperations):
        if type(grant) is not StartGrant:
            _fail("start grant is invalid")
        if not callable(getattr(operations, "close", None)):
            _fail("runtime peer operations are incomplete")
        _start_grant_state(grant)
        self._grant = grant
        self._operations = operations

    def consume(
        self,
        peer: BrokerPeer,
        evidence: KernelPeerEvidence,
        principal: PrincipalBinding,
        identity: BrokerIdentity,
    ) -> CredentialProjection:
        state = _start_grant_state(self._grant)
        if not state.claim():
            _fail("start grant already consumed")
        try:
            grant = self._grant
            if (
                type(peer) is not BrokerPeer
                or type(evidence) is not KernelPeerEvidence
                or type(principal) is not PrincipalBinding
                or type(identity) is not BrokerIdentity
                or peer != grant.peer
                or evidence != grant.evidence
                or principal != grant.principal
                or identity != grant.identity
            ):
                _fail("start grant binding drifted")
            _validate_evidence(grant.evidence, grant.peer)
            _validate_principal(grant.principal, grant.evidence, grant.identity)
            _validate_runtime_binding(
                grant.profile_id,
                grant.binding_id,
                grant.generation,
                grant.provider,
                grant.identity,
            )
            try:
                _validate_projection(
                    grant.projection,
                    grant.profile_id,
                    grant.binding_id,
                    grant.generation,
                    grant.provider,
                )
            except Exception:
                _fail("start grant projection is invalid")
            if not state.matches(_start_grant_binding(grant)):
                _fail("start grant binding drifted")
            return state.projection()
        except RuntimeBoundaryError:
            _close_projection(self._operations, state.projection())
            raise
        except Exception:
            _close_projection(self._operations, state.projection())
            _fail("start grant binding drifted")


__all__ = (
    "CredentialProjection",
    "CredentialProjectionProvider",
    "KernelPeerEvidence",
    "OneShotGrantConsumer",
    "RuntimeBoundaryError",
    "RuntimePeerOperations",
    "RuntimePrincipalResolver",
    "StartGrant",
    "attest_kernel_peer",
)
