"""Offline root-host coordination for fleet runtime quiescence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
from threading import Lock

from codex_master.fleet_registry import (
    FleetSnapshot,
    FleetSnapshotV2,
    fleet_document,
    normalize_fleet_document,
)
from codex_master.fleet_registry_v2_migration import RegistryV2QuiescenceEvidence


class FleetRootRuntimeHostError(ValueError):
    """Sparse root-host coordination failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RootHostParticipant(Enum):
    SYSTEM_BUS_ADMISSION = "system_bus_admission"
    FLEET_REGISTRY = "fleet_registry"
    ACCOUNT_ALLOCATOR = "account_allocator"
    BROKER_WAL = "broker_wal"
    RUNNER_UNITS = "runner_units"
    RECOVERY = "recovery"


class _ActivityKind(Enum):
    PRINCIPAL_OR_AGENT = 0
    LEASE_OR_RESERVATION = 1
    REGISTRY_OR_BROKER_TRANSACTION = 2
    RECOVERY = 3


@dataclass(frozen=True, slots=True)
class RootHostParticipantBinding:
    participant: RootHostParticipant
    generation: int


class _NonTransferable:
    __slots__ = ()

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("root_host_capability_factory_required")

    def __copy__(self):
        raise TypeError("root_host_capability_not_cloneable")

    def __deepcopy__(self, _memo):
        raise TypeError("root_host_capability_not_cloneable")

    def __reduce_ex__(self, _protocol):
        raise TypeError("root_host_capability_not_serializable")

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RootRuntimeActivityOwnership(_NonTransferable):
    host_generation: int
    begin_epoch: int


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RootAdmissionStopOwnership(_NonTransferable):
    host_generation: int
    stop_epoch: int


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RootQuiescenceWindow(_NonTransferable):
    host_generation: int
    window_epoch: int
    source_generation: int
    source_digest: str


@dataclass(frozen=True, slots=True)
class FleetRootRuntimeHostState:
    host_generation: int
    participant_generation: int
    runtime_broker_epoch: int
    reconciled: bool
    admission_stopped: bool
    active_principals_or_agents: int
    active_leases_or_reservations: int
    pending_registry_or_broker_transactions: int
    pending_recoveries: int


_PARTICIPANTS = frozenset(RootHostParticipant)
_MAXIMUM = 2**63 - 1


@dataclass(slots=True)
class _ActivityRecord:
    ownership: RootRuntimeActivityOwnership
    host_generation: int
    begin_epoch: int
    category: _ActivityKind
    index: int


@dataclass(slots=True)
class _AdmissionRecord:
    ownership: RootAdmissionStopOwnership
    host_generation: int
    stop_epoch: int


@dataclass(slots=True)
class _WindowRecord:
    window: RootQuiescenceWindow
    admission: RootAdmissionStopOwnership
    host_generation: int
    window_epoch: int
    source: FleetSnapshot | FleetSnapshotV2
    source_generation: int
    source_digest: str
    source_payload: bytes
    invalidated: bool = False


def _issue_activity_ownership(
    host_generation: int, begin_epoch: int
) -> RootRuntimeActivityOwnership:
    ownership = object.__new__(RootRuntimeActivityOwnership)
    object.__setattr__(ownership, "host_generation", host_generation)
    object.__setattr__(ownership, "begin_epoch", begin_epoch)
    return ownership


def _issue_admission_ownership(
    host_generation: int, stop_epoch: int
) -> RootAdmissionStopOwnership:
    ownership = object.__new__(RootAdmissionStopOwnership)
    object.__setattr__(ownership, "host_generation", host_generation)
    object.__setattr__(ownership, "stop_epoch", stop_epoch)
    return ownership


def _issue_window(
    host_generation: int,
    window_epoch: int,
    source_generation: int,
    source_digest: str,
) -> RootQuiescenceWindow:
    window = object.__new__(RootQuiescenceWindow)
    object.__setattr__(window, "host_generation", host_generation)
    object.__setattr__(window, "window_epoch", window_epoch)
    object.__setattr__(window, "source_generation", source_generation)
    object.__setattr__(window, "source_digest", source_digest)
    return window


def _canonical_source(
    source: object,
) -> tuple[FleetSnapshot | FleetSnapshotV2, int, str, bytes]:
    try:
        if type(source) not in (FleetSnapshot, FleetSnapshotV2):
            raise ValueError
        document = fleet_document(source)
        normalized = normalize_fleet_document(document)
        if type(normalized) is not type(source) or normalized != source:
            raise ValueError
        if type(source.generation) is not int or not 1 <= source.generation <= _MAXIMUM:
            raise ValueError
        payload = json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        digest = "sha256:" + sha256(payload).hexdigest()
        return source, source.generation, digest, payload
    except Exception:
        raise FleetRootRuntimeHostError("registry_source_invalid") from None


class FleetRootRuntimeHost:
    """One in-process serialization boundary for root runtime state."""

    __slots__ = (
        "_lock",
        "_host_generation",
        "_participant_generation",
        "_epoch",
        "_reconciled",
        "_admission_stopped",
        "_bindings",
        "_counts",
        "_activities",
        "_admission_record",
        "_window_record",
    )

    def __init__(self) -> None:
        self._lock = Lock()
        self._host_generation = 0
        self._participant_generation = 0
        self._epoch = 0
        self._reconciled = False
        self._admission_stopped = False
        self._bindings: tuple[RootHostParticipantBinding, ...] = ()
        self._counts = [0, 0, 0, 0]
        self._activities: dict[int, _ActivityRecord] = {}
        self._admission_record: _AdmissionRecord | None = None
        self._window_record: _WindowRecord | None = None

    def _advance_epoch_locked(self) -> int:
        if self._epoch == _MAXIMUM:
            raise FleetRootRuntimeHostError("epoch_overflow")
        self._epoch += 1
        return self._epoch

    def snapshot(self) -> FleetRootRuntimeHostState:
        with self._lock:
            return FleetRootRuntimeHostState(
                self._host_generation,
                self._participant_generation,
                self._epoch,
                self._reconciled,
                self._admission_stopped,
                *self._counts,
            )

    def reconcile(self, bindings: object) -> int:
        if type(bindings) is not tuple:
            raise FleetRootRuntimeHostError("participant_contract_invalid")
        copied: dict[RootHostParticipant, RootHostParticipantBinding] = {}
        try:
            for item in bindings:
                if (
                    type(item) is not RootHostParticipantBinding
                    or type(item.participant) is not RootHostParticipant
                    or type(item.generation) is not int
                    or not 1 <= item.generation <= _MAXIMUM
                    or item.participant in copied
                ):
                    raise ValueError
                copied[item.participant] = RootHostParticipantBinding(
                    item.participant, item.generation
                )
        except Exception:
            raise FleetRootRuntimeHostError("participant_contract_invalid")
        if set(copied) != _PARTICIPANTS:
            raise FleetRootRuntimeHostError("participant_contract_invalid")
        canonical = tuple(copied[participant] for participant in RootHostParticipant)
        generations = {item.generation for item in canonical}
        if len(generations) != 1:
            raise FleetRootRuntimeHostError("participant_contract_invalid")
        with self._lock:
            generation = next(iter(generations))
            if self._reconciled:
                raise FleetRootRuntimeHostError("participant_contract_invalid")
            if generation <= self._participant_generation:
                raise FleetRootRuntimeHostError("participant_generation_stale")
            if any(self._counts):
                raise FleetRootRuntimeHostError("activity_present")
            if self._host_generation == _MAXIMUM or self._epoch == _MAXIMUM:
                raise FleetRootRuntimeHostError("epoch_overflow")
            self._host_generation += 1
            self._advance_epoch_locked()
            self._participant_generation = generation
            self._bindings = canonical
            self._reconciled = True
            self._admission_stopped = False
            return self._host_generation

    def mark_participant_lost(self, binding: object) -> None:
        with self._lock:
            if not self._reconciled:
                raise FleetRootRuntimeHostError("host_unreconciled")
            if (
                type(binding) is not RootHostParticipantBinding
                or type(binding.participant) is not RootHostParticipant
                or type(binding.generation) is not int
            ):
                raise FleetRootRuntimeHostError("participant_contract_invalid")
            current = next(
                (
                    item
                    for item in self._bindings
                    if item.participant is binding.participant
                ),
                None,
            )
            if current is None or current.generation != binding.generation:
                raise FleetRootRuntimeHostError("participant_contract_invalid")
            self._advance_epoch_locked()
            self._reconciled = False
            self._admission_stopped = False
            self._bindings = ()
            self._admission_record = None
            self._window_record = None

    def _begin(self, category: _ActivityKind) -> RootRuntimeActivityOwnership:
        if type(category) is not _ActivityKind:
            raise FleetRootRuntimeHostError("ownership_invalid")
        index = category.value
        with self._lock:
            if not self._reconciled:
                raise FleetRootRuntimeHostError("host_unreconciled")
            if index == 0 and self._admission_stopped:
                raise FleetRootRuntimeHostError("admission_stopped")
            if self._counts[index] == _MAXIMUM or self._epoch == _MAXIMUM:
                raise FleetRootRuntimeHostError("epoch_overflow")
            begin_epoch = self._epoch + 1
            ownership = _issue_activity_ownership(self._host_generation, begin_epoch)
            record = _ActivityRecord(
                ownership,
                self._host_generation,
                begin_epoch,
                category,
                index,
            )
            self._activities[id(ownership)] = record
            if self._window_record is not None:
                self._window_record.invalidated = True
            self._epoch = begin_epoch
            self._counts[index] += 1
            return ownership

    def _end(self, ownership: object, category: _ActivityKind) -> int:
        if type(category) is not _ActivityKind:
            raise FleetRootRuntimeHostError("ownership_invalid")
        index = category.value
        with self._lock:
            record = (
                self._activities.get(id(ownership))
                if type(ownership) is RootRuntimeActivityOwnership
                else None
            )
            if (
                record is None
                or record.ownership is not ownership
                or record.category != category
                or record.index != index
            ):
                raise FleetRootRuntimeHostError("ownership_invalid")
            if (
                ownership.host_generation != record.host_generation
                or record.host_generation != self._host_generation
            ):
                raise FleetRootRuntimeHostError("host_generation_stale")
            if ownership.begin_epoch != record.begin_epoch:
                raise FleetRootRuntimeHostError("ownership_invalid")
            if self._counts[index] <= 0:
                raise FleetRootRuntimeHostError("ownership_invalid")
            terminal_epoch = self._advance_epoch_locked()
            self._counts[index] -= 1
            del self._activities[id(ownership)]
            return terminal_epoch

    def begin_principal_or_agent(self) -> RootRuntimeActivityOwnership:
        return self._begin(_ActivityKind.PRINCIPAL_OR_AGENT)

    def end_principal_or_agent(self, ownership: RootRuntimeActivityOwnership) -> int:
        return self._end(ownership, _ActivityKind.PRINCIPAL_OR_AGENT)

    def begin_lease_or_reservation(self) -> RootRuntimeActivityOwnership:
        return self._begin(_ActivityKind.LEASE_OR_RESERVATION)

    def end_lease_or_reservation(self, ownership: RootRuntimeActivityOwnership) -> int:
        return self._end(ownership, _ActivityKind.LEASE_OR_RESERVATION)

    def begin_registry_or_broker_transaction(self) -> RootRuntimeActivityOwnership:
        return self._begin(_ActivityKind.REGISTRY_OR_BROKER_TRANSACTION)

    def end_registry_or_broker_transaction(
        self, ownership: RootRuntimeActivityOwnership
    ) -> int:
        return self._end(ownership, _ActivityKind.REGISTRY_OR_BROKER_TRANSACTION)

    def begin_recovery(self) -> RootRuntimeActivityOwnership:
        return self._begin(_ActivityKind.RECOVERY)

    def end_recovery(self, ownership: RootRuntimeActivityOwnership) -> int:
        return self._end(ownership, _ActivityKind.RECOVERY)

    def stop_admission(self) -> RootAdmissionStopOwnership:
        with self._lock:
            if not self._reconciled:
                raise FleetRootRuntimeHostError("host_unreconciled")
            if self._admission_stopped or self._admission_record is not None:
                raise FleetRootRuntimeHostError("admission_stopped")
            if self._epoch == _MAXIMUM:
                raise FleetRootRuntimeHostError("epoch_overflow")
            stop_epoch = self._epoch + 1
            ownership = _issue_admission_ownership(self._host_generation, stop_epoch)
            record = _AdmissionRecord(ownership, self._host_generation, stop_epoch)
            self._epoch = stop_epoch
            self._admission_stopped = True
            self._admission_record = record
            return ownership

    def _admission_matches_locked(self, admission: object) -> bool:
        record = self._admission_record
        return (
            type(admission) is RootAdmissionStopOwnership
            and record is not None
            and record.ownership is admission
            and record.host_generation == self._host_generation
            and admission.host_generation == self._host_generation
            and admission.stop_epoch == record.stop_epoch
        )

    def open_quiescence_window(
        self, admission: object, source: object
    ) -> RootQuiescenceWindow:
        with self._lock:
            if not self._reconciled:
                raise FleetRootRuntimeHostError("host_unreconciled")
            if not self._admission_stopped:
                raise FleetRootRuntimeHostError("admission_open")
            if not self._admission_matches_locked(admission):
                raise FleetRootRuntimeHostError("ownership_invalid")
            if self._window_record is not None:
                raise FleetRootRuntimeHostError("quiescence_window_stale")
            if any(self._counts):
                raise FleetRootRuntimeHostError("activity_present")
            canonical, source_generation, source_digest, payload = _canonical_source(
                source
            )
            if self._epoch == _MAXIMUM:
                raise FleetRootRuntimeHostError("epoch_overflow")
            window_epoch = self._epoch + 1
            window = _issue_window(
                self._host_generation,
                window_epoch,
                source_generation,
                source_digest,
            )
            self._window_record = _WindowRecord(
                window,
                admission,
                self._host_generation,
                window_epoch,
                canonical,
                source_generation,
                source_digest,
                payload,
            )
            self._epoch = window_epoch
            return window

    def _window_record_locked(self, window: object) -> _WindowRecord:
        record = self._window_record
        if (
            type(window) is not RootQuiescenceWindow
            or record is None
            or record.window is not window
        ):
            raise FleetRootRuntimeHostError("quiescence_window_stale")
        if (
            window.host_generation != record.host_generation
            or record.host_generation != self._host_generation
        ):
            raise FleetRootRuntimeHostError("host_generation_stale")
        if window.window_epoch != record.window_epoch:
            raise FleetRootRuntimeHostError("quiescence_epoch_drift")
        if (
            window.source_generation != record.source_generation
            or window.source_digest != record.source_digest
        ):
            raise FleetRootRuntimeHostError("registry_source_invalid")
        return record

    def probe_quiescence(self, window: object) -> RegistryV2QuiescenceEvidence:
        with self._lock:
            if not self._reconciled:
                raise FleetRootRuntimeHostError("host_unreconciled")
            record = self._window_record_locked(window)
            if not self._admission_stopped or not self._admission_matches_locked(
                record.admission
            ):
                raise FleetRootRuntimeHostError("admission_open")
            if record.invalidated or self._epoch != window.window_epoch:
                raise FleetRootRuntimeHostError("quiescence_epoch_drift")
            if any(self._counts):
                raise FleetRootRuntimeHostError("activity_present")
            source, generation, digest, payload = _canonical_source(record.source)
            if (
                source is not record.source
                or generation != record.source_generation
                or digest != record.source_digest
                or payload != record.source_payload
            ):
                raise FleetRootRuntimeHostError("registry_source_invalid")
            return RegistryV2QuiescenceEvidence(
                record.source_generation,
                record.source_digest,
                self._epoch,
                True,
                *self._counts,
            )

    def close_quiescence_window(self, window: object) -> int:
        with self._lock:
            record = self._window_record_locked(window)
            if record.invalidated or self._epoch != window.window_epoch:
                raise FleetRootRuntimeHostError("quiescence_epoch_drift")
            terminal_epoch = self._advance_epoch_locked()
            self._window_record = None
            return terminal_epoch

    def abort_quiescence_window(self, window: object) -> int:
        with self._lock:
            self._window_record_locked(window)
            terminal_epoch = self._advance_epoch_locked()
            self._window_record = None
            return terminal_epoch

    def reopen_admission(self, admission: object) -> int:
        with self._lock:
            if not self._admission_matches_locked(admission):
                raise FleetRootRuntimeHostError("ownership_invalid")
            if self._window_record is not None:
                raise FleetRootRuntimeHostError("quiescence_window_stale")
            if any(self._counts):
                raise FleetRootRuntimeHostError("activity_present")
            reopen_epoch = self._advance_epoch_locked()
            self._admission_stopped = False
            self._admission_record = None
            return reopen_epoch


__all__ = (
    "FleetRootRuntimeHost",
    "FleetRootRuntimeHostError",
    "FleetRootRuntimeHostState",
    "RootAdmissionStopOwnership",
    "RootHostParticipant",
    "RootHostParticipantBinding",
    "RootQuiescenceWindow",
    "RootRuntimeActivityOwnership",
)
