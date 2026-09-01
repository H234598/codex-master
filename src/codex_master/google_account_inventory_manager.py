"""GA-I1 runtime snapshot and secret-lease manager."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import math
import threading
import time
from types import MappingProxyType
from typing import Callable, Mapping
import weakref

from . import google_account_inventory as _inventory
from .admin_contracts import public_admin_ref, public_admin_text
from .google_account_inventory import GoogleAccountInventoryDocumentV1
from .google_account_inventory import GoogleAccountInventoryError
from .google_account_inventory import GoogleAccountInventoryLoader
from .google_account_inventory import GoogleAccountV1
from .google_account_inventory import GoogleBillingAccountV1
from .google_account_inventory import GoogleProjectV1
from .google_account_inventory import _FrozenIndex


class InventorySourceTypeV1(str, Enum):
    CANONICAL_YAML = "canonical_yaml"
    TEST = "test"


class InventoryManagerStateV1(str, Enum):
    EMPTY = "empty"
    READY = "ready"
    RELOAD_BLOCKED = "reload_blocked"
    CLOSED = "closed"


class _SecretLeasePurposeV1(str, Enum):
    PROVIDER_REQUEST = "provider_request"
    PROVIDER_PROBE = "provider_probe"


class _SecretLeaseStateV1(str, Enum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"


DEFAULT_SECRET_LEASE_TTL_SECONDS = 30.0
MAX_SECRET_LEASE_TTL_SECONDS = 60.0
MAX_OUTSTANDING_SECRET_LEASES = 128
MAX_INVENTORY_GENERATION = 2**63 - 1


class _SecretLeaseV1:
    __slots__ = (
        "_manager_token",
        "_document",
        "_generation",
        "_account_ref",
        "_project_ref",
        "_key_id",
        "_purpose",
        "_expires_at_monotonic",
        "_terminal_state",
        "__weakref__",
    )

    def __init__(
        self,
        *,
        manager_token: object,
        document: GoogleAccountInventoryDocumentV1,
        generation: int,
        account_ref: str,
        project_ref: str,
        key_id: str,
        purpose: _SecretLeasePurposeV1,
        expires_at_monotonic: float,
    ) -> None:
        self._manager_token = manager_token
        self._document = document
        self._generation = generation
        self._account_ref = account_ref
        self._project_ref = project_ref
        self._key_id = key_id
        self._purpose = purpose
        self._expires_at_monotonic = expires_at_monotonic
        self._terminal_state = _SecretLeaseStateV1.ISSUED

    def __repr__(self) -> str:
        return "_SecretLeaseV1()"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("_SecretLeaseV1 is not serializable")


class _IssuedLeaseRecordV1:
    __slots__ = ("secret", "expires_at_monotonic")

    def __init__(self, *, secret: str, expires_at_monotonic: float) -> None:
        self.secret = secret
        self.expires_at_monotonic = expires_at_monotonic

    def __repr__(self) -> str:
        return "_IssuedLeaseRecordV1()"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("_IssuedLeaseRecordV1 is not serializable")


class _ReloadFailureV1:
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code

    def __repr__(self) -> str:
        return "_ReloadFailureV1()"

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("_ReloadFailureV1 is not serializable")


@dataclass(frozen=True)
class _DocumentOwnershipRecordV1:
    document_ref: weakref.ReferenceType[GoogleAccountInventoryDocumentV1]
    owner_token: object
    identity_token: object


_DOCUMENT_OWNERS: dict[int, _DocumentOwnershipRecordV1] = {}
_DOCUMENT_OWNERSHIP_LOCK = threading.Lock()


def _remove_ownership_if_current(
    document_id: int,
    reference: weakref.ReferenceType[GoogleAccountInventoryDocumentV1],
    identity_token: object,
) -> None:
    with _DOCUMENT_OWNERSHIP_LOCK:
        current = _DOCUMENT_OWNERS.get(document_id)
        if (
            current is not None
            and current.document_ref is reference
            and current.identity_token is identity_token
        ):
            _DOCUMENT_OWNERS.pop(document_id, None)


def _claim_document_ownership(
    document: GoogleAccountInventoryDocumentV1, owner_token: object
) -> None:
    document_id = id(document)
    with _DOCUMENT_OWNERSHIP_LOCK:
        current = _DOCUMENT_OWNERS.get(document_id)
        if current is not None:
            current_document = current.document_ref()
            if current_document is document:
                code = (
                    "credential.inventory_document_consumed"
                    if current.owner_token is owner_token
                    else "credential.inventory_document_foreign"
                )
                raise GoogleAccountInventoryError(code)
            _DOCUMENT_OWNERS.pop(document_id, None)

        identity_token = object()

        def discard(
            reference: weakref.ReferenceType[GoogleAccountInventoryDocumentV1],
        ) -> None:
            _remove_ownership_if_current(document_id, reference, identity_token)

        reference = weakref.ref(document, discard)
        _DOCUMENT_OWNERS[document_id] = _DocumentOwnershipRecordV1(
            document_ref=reference,
            owner_token=owner_token,
            identity_token=identity_token,
        )


def _valid_ttl(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        seconds = float(value)
    except (OverflowError, ValueError):
        return False
    return math.isfinite(seconds) and 0.0 < seconds <= MAX_SECRET_LEASE_TTL_SECONDS


def _valid_generation(value: object) -> bool:
    return type(value) is int and 1 <= value <= MAX_INVENTORY_GENERATION


def _valid_nonempty_string(value: object) -> bool:
    return type(value) is str and bool(value)


def _valid_operator_timestamp(value: object) -> bool:
    if type(value) is not str or len(value) != 20:
        return False
    if (
        value[4] != "-"
        or value[7] != "-"
        or value[10] != "T"
        or value[13] != ":"
        or value[16] != ":"
        or value[19] != "Z"
    ):
        return False
    if not all(
        value[index].isdigit()
        for index in (0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18)
    ):
        return False
    try:
        parsed = time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return False
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", parsed) == value


@dataclass(frozen=True, repr=False)
class _GoogleAccountInventorySnapshotV1:
    generation: int
    loaded_at_utc: str
    source_type: InventorySourceTypeV1
    content_fingerprint: str
    accounts: tuple[GoogleAccountV1, ...] = field(repr=False)
    by_account_ref: _FrozenIndex[GoogleAccountV1] = field(
        repr=False, compare=False, hash=False
    )
    by_subject_id: _FrozenIndex[GoogleAccountV1] = field(
        repr=False, compare=False, hash=False
    )
    by_billing_ref: _FrozenIndex[GoogleBillingAccountV1] = field(
        repr=False, compare=False, hash=False
    )
    by_billing_account_id: _FrozenIndex[GoogleBillingAccountV1] = field(
        repr=False, compare=False, hash=False
    )
    by_project_ref: _FrozenIndex[GoogleProjectV1] = field(
        repr=False, compare=False, hash=False
    )
    by_project_id: _FrozenIndex[GoogleProjectV1] = field(
        repr=False, compare=False, hash=False
    )
    by_key_id: _FrozenIndex[GoogleProjectV1] = field(
        repr=False, compare=False, hash=False
    )
    by_key_uid: _FrozenIndex[GoogleProjectV1] = field(
        repr=False, compare=False, hash=False
    )
    by_hive_slot: _FrozenIndex[GoogleProjectV1] = field(
        repr=False, compare=False, hash=False
    )

    def public_projection(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "generation": self.generation,
                "loaded_at_utc": self.loaded_at_utc,
                "source_type": self.source_type.value,
                "content_fingerprint": self.content_fingerprint,
                "account_count": len(self.accounts),
                "billing_account_count": sum(
                    len(account.billing_accounts) for account in self.accounts
                ),
                "project_count": sum(
                    len(account.projects) for account in self.accounts
                ),
                "active_project_count": sum(
                    1
                    for account in self.accounts
                    for project in account.projects
                    if project.status == "active"
                ),
            }
        )

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("_GoogleAccountInventorySnapshotV1 is not serializable")


@dataclass(frozen=True)
class GoogleAccountInventoryStatusV1:
    state: InventoryManagerStateV1
    generation: int | None
    loaded_at_utc: str | None
    source_type: InventorySourceTypeV1 | None
    content_fingerprint: str | None
    new_work_allowed: bool
    reload_error_code: str | None
    account_count: int
    billing_account_count: int
    project_count: int
    active_project_count: int

    def public_projection(self) -> Mapping[str, int | str | bool | None]:
        return {
            "state": self.state.value,
            "new_work_allowed": self.new_work_allowed,
            "generation": self.generation,
            "loaded_at_utc": self.loaded_at_utc,
            "source_type": (
                self.source_type.value if self.source_type is not None else None
            ),
            "content_fingerprint": self.content_fingerprint,
            "account_count": self.account_count,
            "billing_account_count": self.billing_account_count,
            "project_count": self.project_count,
            "active_project_count": self.active_project_count,
        }


@dataclass(frozen=True, repr=False)
class _ActiveStateV1:
    document: GoogleAccountInventoryDocumentV1 | None = field(repr=False)
    source: object | None = field(repr=False)
    snapshot: _GoogleAccountInventorySnapshotV1


def _build_snapshot(
    document: GoogleAccountInventoryDocumentV1,
    *,
    generation: int,
    loaded_at_utc: str,
    source_type: InventorySourceTypeV1,
) -> _GoogleAccountInventorySnapshotV1:
    return _GoogleAccountInventorySnapshotV1(
        generation=generation,
        loaded_at_utc=loaded_at_utc,
        source_type=source_type,
        content_fingerprint=document.content_fingerprint,
        accounts=document.accounts,
        by_account_ref=_FrozenIndex(
            {account.ref: account for account in document.accounts}
        ),
        by_subject_id=_FrozenIndex(
            {
                account.subject_id: account
                for account in document.accounts
                if account.subject_id is not None
            }
        ),
        by_billing_ref=_FrozenIndex(
            {
                billing.ref: billing
                for account in document.accounts
                for billing in account.billing_accounts
            }
        ),
        by_billing_account_id=_FrozenIndex(
            {
                billing.billing_account_id: billing
                for account in document.accounts
                for billing in account.billing_accounts
                if billing.billing_account_id is not None
            }
        ),
        by_project_ref=_FrozenIndex(
            {
                project.ref: project
                for account in document.accounts
                for project in account.projects
            }
        ),
        by_project_id=_FrozenIndex(
            {
                project.project_id: project
                for account in document.accounts
                for project in account.projects
                if project.project_id is not None
            }
        ),
        by_key_id=_FrozenIndex(
            {
                project.key_id: project
                for account in document.accounts
                for project in account.projects
                if project.key_id is not None
            }
        ),
        by_key_uid=_FrozenIndex(
            {
                project.key_uid: project
                for account in document.accounts
                for project in account.projects
                if project.key_uid is not None
            }
        ),
        by_hive_slot=_FrozenIndex(
            {
                project.hive_slot: project
                for account in document.accounts
                for project in account.projects
            }
        ),
    )


class GoogleAccountInventoryManager:
    def __init__(self) -> None:
        self._initialize(
            GoogleAccountInventoryLoader().load,
            monotonic_clock=time.monotonic,
            operator_timestamp_utc=lambda: time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            ),
            source_type=InventorySourceTypeV1.CANONICAL_YAML,
        )

    @classmethod
    def from_systemd_state_directory(cls) -> GoogleAccountInventoryManager:
        manager = cls.__new__(cls)
        manager._initialize(
            GoogleAccountInventoryLoader.from_systemd_state_directory().load,
            monotonic_clock=time.monotonic,
            operator_timestamp_utc=lambda: time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            ),
            source_type=InventorySourceTypeV1.CANONICAL_YAML,
        )
        return manager

    @classmethod
    def _for_test_loader(
        cls,
        document_loader: Callable[[], GoogleAccountInventoryDocumentV1],
        *,
        monotonic_clock: Callable[[], object],
        operator_timestamp_utc: Callable[[], object],
    ) -> GoogleAccountInventoryManager:
        manager = cls.__new__(cls)
        manager._initialize(
            document_loader,
            monotonic_clock=monotonic_clock,
            operator_timestamp_utc=operator_timestamp_utc,
            source_type=InventorySourceTypeV1.TEST,
        )
        return manager

    def _initialize(
        self,
        document_loader: Callable[[], GoogleAccountInventoryDocumentV1],
        *,
        monotonic_clock: Callable[[], object],
        operator_timestamp_utc: Callable[[], object],
        source_type: InventorySourceTypeV1,
    ) -> None:
        self._lock = threading.RLock()
        self._document_loader = document_loader
        self._monotonic_clock = monotonic_clock
        self._operator_timestamp_utc = operator_timestamp_utc
        self._source_type = source_type
        self._state = InventoryManagerStateV1.EMPTY
        self._generation = 0
        self._last_monotonic: float | None = None
        self._active: _ActiveStateV1 | None = None
        self._reload_error_code: str | None = None
        self._owner_token = object()
        self._manager_token = object()
        self._lease_records: weakref.WeakKeyDictionary[
            _SecretLeaseV1, _IssuedLeaseRecordV1
        ] = weakref.WeakKeyDictionary()

    def _block_after_reload_failure(self, code: str) -> None:
        self._reload_error_code = code
        if self._active is not None:
            self._active = _ActiveStateV1(
                document=None,
                source=None,
                snapshot=self._active.snapshot,
            )
            self._state = InventoryManagerStateV1.RELOAD_BLOCKED

    def _prepare_and_publish_reload_locked(
        self,
    ) -> _ReloadFailureV1 | GoogleAccountInventoryStatusV1:
        document: GoogleAccountInventoryDocumentV1 | None = None
        source: object | None = None
        try:
            document = self._document_loader()
            _claim_document_ownership(document, self._owner_token)
            source = _inventory._consume_document_secret_source(document)
            loaded_at_utc = self._operator_timestamp_utc()
            if not _valid_operator_timestamp(loaded_at_utc):
                raise GoogleAccountInventoryError(
                    "credential.inventory_timestamp_invalid"
                )
            snapshot = _build_snapshot(
                document,
                generation=self._generation + 1,
                loaded_at_utc=loaded_at_utc,
                source_type=self._source_type,
            )
            status = self._status_for_snapshot(
                snapshot,
                state=InventoryManagerStateV1.READY,
                reload_error_code=None,
            )
            self._active = _ActiveStateV1(
                document=document,
                source=source,
                snapshot=snapshot,
            )
            self._generation = snapshot.generation
            self._state = InventoryManagerStateV1.READY
            self._reload_error_code = None
            document = None
            source = None
            return status
        except GoogleAccountInventoryError as error:
            code = error.code
            document = None
            source = None
            if code in {
                "credential.inventory_document_consumed",
                "credential.inventory_document_foreign",
                "credential.inventory_timestamp_invalid",
            }:
                return _ReloadFailureV1(code)
            return _ReloadFailureV1("credential.inventory_reload_failed")
        except Exception:
            document = None
            source = None
            return _ReloadFailureV1("credential.inventory_reload_failed")

    def reload(
        self, *, expected_generation: int | None = None
    ) -> GoogleAccountInventoryStatusV1:
        with self._lock:
            if self._state is InventoryManagerStateV1.CLOSED:
                raise GoogleAccountInventoryError("credential.inventory_manager_closed")
            if expected_generation is not None and (
                type(expected_generation) is not int
                or not 0 <= expected_generation <= MAX_INVENTORY_GENERATION
                or expected_generation != self._generation
            ):
                raise GoogleAccountInventoryError("credential.generation_conflict")
            if self._generation >= MAX_INVENTORY_GENERATION:
                self._block_after_reload_failure(
                    "credential.inventory_generation_exhausted"
                )
                raise GoogleAccountInventoryError(
                    "credential.inventory_generation_exhausted"
                )
            result = self._prepare_and_publish_reload_locked()
            if isinstance(result, _ReloadFailureV1):
                code = result.code
                self._block_after_reload_failure(code)
                if code in {
                    "credential.inventory_document_consumed",
                    "credential.inventory_document_foreign",
                    "credential.inventory_timestamp_invalid",
                }:
                    raise GoogleAccountInventoryError(code) from None
                raise GoogleAccountInventoryError(
                    "credential.inventory_reload_failed"
                ) from None
            return result

    def _snapshot_for_internal_use(self) -> _GoogleAccountInventorySnapshotV1:
        with self._lock:
            if self._state is InventoryManagerStateV1.CLOSED:
                raise GoogleAccountInventoryError("credential.inventory_manager_closed")
            if self._active is None:
                raise GoogleAccountInventoryError(
                    "credential.inventory_snapshot_unavailable"
                )
            return self._active.snapshot

    @staticmethod
    def _account_admin_projection(
        account: GoogleAccountV1, generation: int
    ) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "ref": public_admin_ref(account.ref),
                "label": (
                    None if account.label is None else public_admin_text(account.label)
                ),
                "subject_bound": account.subject_id is not None,
                "inventory_generation": generation,
                "project_count": len(account.projects),
                "billing_count": len(account.billing_accounts),
                "billing_refs": tuple(
                    public_admin_ref(item.ref) for item in account.billing_accounts
                ),
            }
        )

    @staticmethod
    def _project_admin_projection(
        project: GoogleProjectV1, generation: int
    ) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "ref": public_admin_ref(project.ref),
                "project_name": (
                    None
                    if project.project_name is None
                    else public_admin_text(project.project_name)
                ),
                "key_name": (
                    None
                    if project.key_name is None
                    else public_admin_text(project.key_name)
                ),
                "purpose": public_admin_text(project.purpose),
                "billing_ref": (
                    None
                    if project.billing_account_ref is None
                    else public_admin_ref(project.billing_account_ref)
                ),
                "status": public_admin_text(project.status),
                "inventory_generation": generation,
            }
        )

    def list_accounts(self) -> tuple[Mapping[str, object], ...]:
        snapshot = self._snapshot_for_internal_use()
        return tuple(
            self._account_admin_projection(account, snapshot.generation)
            for account in snapshot.accounts
        )

    def get_account(self, account_ref: str) -> Mapping[str, object]:
        if not _valid_nonempty_string(account_ref):
            raise GoogleAccountInventoryError("credential.account_not_found")
        snapshot = self._snapshot_for_internal_use()
        try:
            account = snapshot.by_account_ref[account_ref]
        except KeyError:
            raise GoogleAccountInventoryError("credential.account_not_found") from None
        return self._account_admin_projection(account, snapshot.generation)

    def list_projects(self, account_ref: str) -> tuple[Mapping[str, object], ...]:
        if not _valid_nonempty_string(account_ref):
            raise GoogleAccountInventoryError("credential.account_not_found")
        snapshot = self._snapshot_for_internal_use()
        try:
            account = snapshot.by_account_ref[account_ref]
        except KeyError:
            raise GoogleAccountInventoryError("credential.account_not_found") from None
        return tuple(
            self._project_admin_projection(project, snapshot.generation)
            for project in account.projects
        )

    def inventory_generation(self) -> int:
        return self._snapshot_for_internal_use().generation

    def _read_monotonic(self) -> float:
        try:
            value = self._monotonic_clock()
            if type(value) not in (int, float):
                raise ValueError
            seconds = float(value)
            if not math.isfinite(seconds):
                raise ValueError
            if self._last_monotonic is not None and seconds < self._last_monotonic:
                raise ValueError
        except Exception:
            raise GoogleAccountInventoryError(
                "credential.inventory_clock_invalid"
            ) from None
        self._last_monotonic = seconds
        return seconds

    def _issue_secret_lease(
        self,
        *,
        expected_generation: int,
        account_ref: str,
        project_ref: str,
        key_id: str,
        purpose: _SecretLeasePurposeV1,
        ttl_seconds: float = DEFAULT_SECRET_LEASE_TTL_SECONDS,
    ) -> _SecretLeaseV1:
        with self._lock:
            if self._state is InventoryManagerStateV1.CLOSED:
                raise GoogleAccountInventoryError("credential.inventory_manager_closed")
            if self._active is None:
                raise GoogleAccountInventoryError(
                    "credential.inventory_snapshot_unavailable"
                )
            if self._state is InventoryManagerStateV1.RELOAD_BLOCKED:
                raise GoogleAccountInventoryError("credential.inventory_reload_failed")
            if not _valid_generation(expected_generation):
                raise GoogleAccountInventoryError("credential.generation_conflict")
            if not _valid_nonempty_string(account_ref):
                raise GoogleAccountInventoryError("credential.account_not_found")
            if not _valid_nonempty_string(project_ref):
                raise GoogleAccountInventoryError("credential.project_not_found")
            if not _valid_nonempty_string(key_id):
                raise GoogleAccountInventoryError("credential.key_not_found")
            if type(purpose) is not _SecretLeasePurposeV1:
                raise GoogleAccountInventoryError("credential.secret_lease_invalid")
            snapshot = self._active.snapshot
            if expected_generation != snapshot.generation:
                raise GoogleAccountInventoryError("credential.generation_conflict")
            try:
                account = snapshot.by_account_ref[account_ref]
            except KeyError:
                raise GoogleAccountInventoryError(
                    "credential.account_not_found"
                ) from None
            try:
                project = snapshot.by_project_ref[project_ref]
            except KeyError:
                raise GoogleAccountInventoryError(
                    "credential.project_not_found"
                ) from None
            if project not in account.projects:
                raise GoogleAccountInventoryError("credential.project_not_found")
            if project.status != "active":
                raise GoogleAccountInventoryError("credential.project_blocked")
            if (
                type(project.key_id) is not str
                or not project.key_id
                or type(key_id) is not str
                or not key_id
                or project.key_id != key_id
            ):
                raise GoogleAccountInventoryError("credential.key_not_found")
            if not _valid_ttl(ttl_seconds):
                raise GoogleAccountInventoryError("credential.secret_lease_invalid")

            now = self._read_monotonic()
            self._sweep_expired_leases(now)
            if len(self._lease_records) >= MAX_OUTSTANDING_SECRET_LEASES:
                raise GoogleAccountInventoryError(
                    "credential.secret_lease_capacity_exhausted"
                )
            if self._active.source is None or self._active.document is None:
                raise GoogleAccountInventoryError("credential.secret_lease_invalid")
            try:
                secret = self._active.source._secret_for_project(project_ref)
            except Exception:
                raise GoogleAccountInventoryError(
                    "credential.secret_lease_invalid"
                ) from None
            deadline = now + float(ttl_seconds)
            lease = _SecretLeaseV1(
                manager_token=self._manager_token,
                document=self._active.document,
                generation=snapshot.generation,
                account_ref=account_ref,
                project_ref=project_ref,
                key_id=key_id,
                purpose=purpose,
                expires_at_monotonic=deadline,
            )
            self._lease_records[lease] = _IssuedLeaseRecordV1(
                secret=secret,
                expires_at_monotonic=deadline,
            )
            return lease

    def _sweep_expired_leases(self, now: float) -> None:
        for lease, record in tuple(self._lease_records.items()):
            if now >= record.expires_at_monotonic:
                record.secret = None  # type: ignore[assignment]
                lease._terminal_state = _SecretLeaseStateV1.EXPIRED
                del self._lease_records[lease]

    def _consume_secret_lease(
        self,
        lease: _SecretLeaseV1,
        *,
        expected_generation: int,
        account_ref: str,
        project_ref: str,
        key_id: str,
        purpose: _SecretLeasePurposeV1,
    ) -> str:
        with self._lock:
            if type(lease) is not _SecretLeaseV1:
                raise GoogleAccountInventoryError("credential.secret_lease_invalid")
            if lease._manager_token is not self._manager_token:
                raise GoogleAccountInventoryError(
                    "credential.secret_lease_manager_mismatch"
                )
            if lease._terminal_state is _SecretLeaseStateV1.EXPIRED:
                raise GoogleAccountInventoryError("credential.secret_lease_expired")
            if lease._terminal_state is _SecretLeaseStateV1.REVOKED:
                raise GoogleAccountInventoryError("credential.secret_lease_revoked")
            if lease._terminal_state is _SecretLeaseStateV1.CONSUMED:
                raise GoogleAccountInventoryError("credential.secret_lease_invalid")
            record = self._lease_records.get(lease)
            if record is None:
                raise GoogleAccountInventoryError("credential.secret_lease_invalid")
            if not _valid_generation(expected_generation):
                raise GoogleAccountInventoryError(
                    "credential.secret_lease_generation_mismatch"
                )
            if (
                not _valid_nonempty_string(account_ref)
                or not _valid_nonempty_string(project_ref)
                or not _valid_nonempty_string(key_id)
                or type(purpose) is not _SecretLeasePurposeV1
            ):
                raise GoogleAccountInventoryError(
                    "credential.secret_lease_binding_mismatch"
                )
            if lease._generation != expected_generation:
                raise GoogleAccountInventoryError(
                    "credential.secret_lease_generation_mismatch"
                )
            if (
                lease._account_ref != account_ref
                or lease._project_ref != project_ref
                or lease._key_id != key_id
                or lease._purpose is not purpose
            ):
                raise GoogleAccountInventoryError(
                    "credential.secret_lease_binding_mismatch"
                )
            now = self._read_monotonic()
            if now >= record.expires_at_monotonic:
                record.secret = None  # type: ignore[assignment]
                lease._terminal_state = _SecretLeaseStateV1.EXPIRED
                del self._lease_records[lease]
                raise GoogleAccountInventoryError("credential.secret_lease_expired")
            secret = record.secret
            record.secret = None  # type: ignore[assignment]
            lease._terminal_state = _SecretLeaseStateV1.CONSUMED
            del self._lease_records[lease]
            if secret is None:
                raise GoogleAccountInventoryError("credential.secret_lease_invalid")
            return secret

    @staticmethod
    def _status_for_snapshot(
        snapshot: _GoogleAccountInventorySnapshotV1,
        *,
        state: InventoryManagerStateV1,
        reload_error_code: str | None,
    ) -> GoogleAccountInventoryStatusV1:
        projection = snapshot.public_projection()
        return GoogleAccountInventoryStatusV1(
            state=state,
            generation=snapshot.generation,
            loaded_at_utc=snapshot.loaded_at_utc,
            source_type=snapshot.source_type,
            content_fingerprint=snapshot.content_fingerprint,
            new_work_allowed=state is InventoryManagerStateV1.READY,
            reload_error_code=reload_error_code,
            account_count=projection["account_count"],
            billing_account_count=projection["billing_account_count"],
            project_count=projection["project_count"],
            active_project_count=projection["active_project_count"],
        )

    def _status_locked(self) -> GoogleAccountInventoryStatusV1:
        snapshot = self._active.snapshot if self._active is not None else None
        if snapshot is None:
            return GoogleAccountInventoryStatusV1(
                state=self._state,
                generation=None,
                loaded_at_utc=None,
                source_type=None,
                content_fingerprint=None,
                new_work_allowed=self._state is InventoryManagerStateV1.READY,
                reload_error_code=self._reload_error_code,
                account_count=0,
                billing_account_count=0,
                project_count=0,
                active_project_count=0,
            )
        return self._status_for_snapshot(
            snapshot,
            state=self._state,
            reload_error_code=self._reload_error_code,
        )

    def status(self) -> GoogleAccountInventoryStatusV1:
        with self._lock:
            return self._status_locked()

    def close(self) -> None:
        with self._lock:
            if self._active is not None:
                self._active = _ActiveStateV1(
                    document=None,
                    source=None,
                    snapshot=self._active.snapshot,
                )
            for lease, record in tuple(self._lease_records.items()):
                record.secret = None  # type: ignore[assignment]
                lease._terminal_state = _SecretLeaseStateV1.REVOKED
                del self._lease_records[lease]
            self._state = InventoryManagerStateV1.CLOSED

    def __repr__(self) -> str:
        return "GoogleAccountInventoryManager()"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("GoogleAccountInventoryManager is not serializable")
