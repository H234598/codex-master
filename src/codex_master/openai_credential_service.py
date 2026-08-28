"""Account-bound OpenAI auth synchronization and short-lived materialization."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import threading
import time
from typing import Final, cast
import weakref

from .codex_usage_credential_authority import (
    CredentialAuthorityError,
    MAX_AUTH_BYTES,
    validate_openai_auth_json,
)
from .credential_vault import (
    CredentialCleanupTarget,
    CredentialLease,
    CredentialVault,
    CredentialVaultError,
)
from .hive.state import HiveStateError, HiveStateStore


MAX_AUTH_SYNC_PLAN_SECONDS: Final[int] = 5 * 60
_MAX_GENERATION: Final[int] = 2**63 - 1
_ACCOUNT_REF: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII
)
_BACKEND_ACCOUNT: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z", re.ASCII
)
_FINAL_NAME: Final[str] = "auth.json"
_CLAIM_XATTR: Final[str] = "user.codex_master_claim"
_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "control.plan_stale",
        "control.idempotency_conflict",
        "control.operation_ambiguous",
        "control.request_invalid",
        "credential.generation_conflict",
        "credential.source_unavailable",
        "credential.upload_expired",
        "oauth.identity_mismatch",
    }
)
_IDEMPOTENCY_KEY: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII
)
_RECEIPT_DOCUMENT: Final[PurePosixPath] = PurePosixPath("openai-auth-sync.json")
_IDENTITY_DOCUMENT: Final[PurePosixPath] = PurePosixPath("openai-identities.json")
_MAX_RECEIPT_BYTES: Final[int] = 2 * 1024 * 1024
_MAX_RECEIPTS: Final[int] = 4096


class OpenAICredentialError(ValueError):
    """Stable, code-only OpenAI credential-service failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            raise TypeError("invalid OpenAI credential error code")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, weakref_slot=True, repr=False)
class AuthSyncPlanV1:
    account_ref: str
    expected_generation: int
    expires_at: float
    nonce: str
    idempotency_key: str
    plan_digest: str
    _issuer: object

    def __repr__(self) -> str:
        return "AuthSyncPlanV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AuthSyncReceiptV1:
    account_ref: str
    generation: int
    plan_digest: str
    state: str = "succeeded"

    def __repr__(self) -> str:
        return "AuthSyncReceiptV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class OpenAIAccountIdentity:
    enabled: bool
    backend_account_id: str
    generation: int

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise OpenAICredentialError("control.request_invalid")
        _backend_account(self.backend_account_id)
        _generation(self.generation)

    def __repr__(self) -> str:
        return "OpenAIAccountIdentity(<redacted>)"


class OpenAIIdentitySource:
    """Durable authoritative account identities exposed under Hive CAS."""

    __slots__ = ("_state",)

    def __init__(
        self,
        state_root: Path,
        *,
        initial_identities: Mapping[str, OpenAIAccountIdentity] | None = None,
    ) -> None:
        if (
            not isinstance(state_root, Path)
            or not state_root.is_absolute()
            or (
                initial_identities is not None
                and (
                    not isinstance(initial_identities, Mapping)
                    or not 1 <= len(initial_identities) <= 4096
                )
            )
        ):
            raise OpenAICredentialError("control.request_invalid")
        try:
            self._state = HiveStateStore(state_root)
            with self._state.locked():
                existing = self._read_locked()
                if initial_identities is not None:
                    supplied = {
                        _account_ref(account_ref): identity
                        for account_ref, identity in initial_identities.items()
                    }
                    if any(
                        not isinstance(identity, OpenAIAccountIdentity)
                        for identity in supplied.values()
                    ):
                        raise OpenAICredentialError("control.request_invalid")
                    if existing and existing != supplied:
                        raise OpenAICredentialError("credential.generation_conflict")
                    if not existing:
                        self._write_locked(supplied)
        except OpenAICredentialError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError):
            raise OpenAICredentialError("credential.source_unavailable") from None

    @contextmanager
    def guard(self, account_ref: str) -> Iterator[OpenAIAccountIdentity]:
        account_ref = _account_ref(account_ref)
        try:
            with self._state.locked():
                identity = self._read_locked().get(account_ref)
                if identity is None:
                    raise OpenAICredentialError("control.request_invalid")
                yield identity
        except OpenAICredentialError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError):
            raise OpenAICredentialError("credential.source_unavailable") from None

    def set_identity(self, account_ref: str, identity: OpenAIAccountIdentity) -> None:
        account_ref = _account_ref(account_ref)
        if not isinstance(identity, OpenAIAccountIdentity):
            raise OpenAICredentialError("control.request_invalid")
        try:
            with self._state.locked():
                identities = self._read_locked()
                current = identities.get(account_ref)
                if current is not None and (
                    identity.generation < current.generation
                    or (
                        identity.generation == current.generation
                        and identity != current
                    )
                ):
                    raise OpenAICredentialError("credential.generation_conflict")
                if current == identity:
                    return
                identities[account_ref] = identity
                self._write_locked(identities)
        except OpenAICredentialError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError):
            raise OpenAICredentialError("credential.source_unavailable") from None

    def _read_locked(self) -> dict[str, OpenAIAccountIdentity]:
        try:
            raw = self._state.read_private_bytes(
                _IDENTITY_DOCUMENT, max_bytes=_MAX_RECEIPT_BYTES
            )
        except HiveStateError as exc:
            if exc.args == ("state_not_found",):
                return {}
            raise
        try:
            document = json.loads(
                raw.decode("ascii"), object_pairs_hook=_receipt_json_object
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise OpenAICredentialError("credential.source_unavailable") from None
        if (
            not isinstance(document, Mapping)
            or set(document) != {"schema_version", "identities"}
            or document.get("schema_version") != 1
            or type(document.get("identities")) is not list
            or len(document["identities"]) > 4096
        ):
            raise OpenAICredentialError("credential.source_unavailable")
        identities: dict[str, OpenAIAccountIdentity] = {}
        for value in document["identities"]:
            if not isinstance(value, Mapping) or set(value) != {
                "account_ref",
                "backend_account_id",
                "enabled",
                "generation",
            }:
                raise OpenAICredentialError("credential.source_unavailable")
            try:
                account_ref = _account_ref(value["account_ref"])
                identity = OpenAIAccountIdentity(
                    enabled=value["enabled"],
                    backend_account_id=value["backend_account_id"],
                    generation=value["generation"],
                )
            except (OpenAICredentialError, TypeError):
                raise OpenAICredentialError("credential.source_unavailable") from None
            if account_ref in identities:
                raise OpenAICredentialError("credential.source_unavailable")
            identities[account_ref] = identity
        if raw != _identity_document(identities):
            raise OpenAICredentialError("credential.source_unavailable")
        return identities

    def _write_locked(self, identities: Mapping[str, OpenAIAccountIdentity]) -> None:
        try:
            self._state.replace_private_bytes(
                _IDENTITY_DOCUMENT, _identity_document(identities)
            )
        except (HiveStateError, OSError, TypeError, ValueError, RecursionError):
            raise OpenAICredentialError("credential.source_unavailable") from None


class OpenAIAuthReceiptStore:
    """Durable shared intent/receipt CAS for auth-sync idempotency."""

    __slots__ = ("_state",)

    def __init__(self, state_root: Path) -> None:
        if not isinstance(state_root, Path) or not state_root.is_absolute():
            raise OpenAICredentialError("credential.source_unavailable")
        try:
            self._state = HiveStateStore(state_root)
        except (HiveStateError, OSError, ValueError):
            raise OpenAICredentialError("credential.source_unavailable") from None

    def plan(self, candidate: Mapping[str, object]) -> dict[str, object]:
        with self._locked_records() as records:
            key = candidate["idempotency_key"]
            for record in records:
                if record["idempotency_key"] != key:
                    continue
                if (
                    record["account_ref"] != candidate["account_ref"]
                    or record["expected_generation"] != candidate["expected_generation"]
                ):
                    raise OpenAICredentialError("control.idempotency_conflict")
                return dict(record)
            if len(records) >= _MAX_RECEIPTS:
                raise OpenAICredentialError("credential.source_unavailable")
            record = dict(candidate)
            record["state"] = "planned"
            records.append(record)
            self._write_locked(records)
            return dict(record)

    def begin(self, plan: AuthSyncPlanV1) -> str:
        with self._locked_records() as records:
            record = self._matching_record(records, plan)
            state = record["state"]
            if state == "succeeded":
                return "succeeded"
            if state == "running":
                raise OpenAICredentialError("control.operation_ambiguous")
            if state == "expired":
                raise OpenAICredentialError("control.plan_stale")
            record["state"] = "running"
            self._write_locked(records)
            return "running"

    def status(self, plan: AuthSyncPlanV1) -> str:
        with self._locked_records() as records:
            return str(self._matching_record(records, plan)["state"])

    def succeed(self, plan: AuthSyncPlanV1) -> None:
        with self._locked_records() as records:
            record = self._matching_record(records, plan)
            if record["state"] != "running":
                raise OpenAICredentialError("control.operation_ambiguous")
            record["state"] = "succeeded"
            self._write_locked(records)

    def expire(self, plan: AuthSyncPlanV1) -> None:
        with self._locked_records() as records:
            record = self._matching_record(records, plan)
            if record["state"] != "running":
                raise OpenAICredentialError("control.operation_ambiguous")
            record["state"] = "expired"
            self._write_locked(records)

    @contextmanager
    def _locked_records(self) -> Iterator[list[dict[str, object]]]:
        try:
            with self._state.locked():
                yield self._read_locked()
        except OpenAICredentialError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError):
            raise OpenAICredentialError("credential.source_unavailable") from None

    def _read_locked(self) -> list[dict[str, object]]:
        try:
            raw = self._state.read_private_bytes(
                _RECEIPT_DOCUMENT, max_bytes=_MAX_RECEIPT_BYTES
            )
        except HiveStateError as exc:
            if exc.args == ("state_not_found",):
                return []
            raise
        try:
            document = json.loads(
                raw.decode("ascii"), object_pairs_hook=_receipt_json_object
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise OpenAICredentialError("credential.source_unavailable") from None
        if (
            not isinstance(document, Mapping)
            or set(document) != {"schema_version", "records"}
            or document.get("schema_version") != 1
            or type(document.get("records")) is not list
            or len(document["records"]) > _MAX_RECEIPTS
        ):
            raise OpenAICredentialError("credential.source_unavailable")
        records = [self._validated_record(value) for value in document["records"]]
        keys = [record["idempotency_key"] for record in records]
        if len(set(keys)) != len(keys):
            raise OpenAICredentialError("credential.source_unavailable")
        if raw != _receipt_document(records):
            raise OpenAICredentialError("credential.source_unavailable")
        return records

    def _write_locked(self, records: list[dict[str, object]]) -> None:
        try:
            raw = _receipt_document(records)
            if len(raw) > _MAX_RECEIPT_BYTES:
                raise OpenAICredentialError("credential.source_unavailable")
            self._state.replace_private_bytes(_RECEIPT_DOCUMENT, raw)
        except OpenAICredentialError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError, RecursionError):
            raise OpenAICredentialError("credential.source_unavailable") from None

    @staticmethod
    def _validated_record(value: object) -> dict[str, object]:
        fields = {
            "account_ref",
            "expected_generation",
            "expires_at",
            "idempotency_key",
            "nonce",
            "plan_digest",
            "state",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise OpenAICredentialError("credential.source_unavailable")
        record = dict(value)
        try:
            _account_ref(record["account_ref"])
            _generation(record["expected_generation"])
            _idempotency_key(record["idempotency_key"])
            expires = record["expires_at"]
            if (
                isinstance(expires, bool)
                or not isinstance(expires, (int, float))
                or not math.isfinite(expires)
                or type(record["nonce"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", record["nonce"], re.ASCII) is None
                or type(record["plan_digest"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", record["plan_digest"], re.ASCII)
                is None
                or record["state"] not in {"planned", "running", "succeeded", "expired"}
            ):
                raise OpenAICredentialError("credential.source_unavailable")
            digest = _plan_digest(
                str(record["account_ref"]),
                int(record["expected_generation"]),
                float(expires),
                str(record["nonce"]),
                str(record["idempotency_key"]),
            )
        except OpenAICredentialError:
            raise OpenAICredentialError("credential.source_unavailable") from None
        if not hmac.compare_digest(digest, str(record["plan_digest"])):
            raise OpenAICredentialError("credential.source_unavailable")
        record["expires_at"] = float(expires)
        return record

    @staticmethod
    def _matching_record(
        records: list[dict[str, object]], plan: AuthSyncPlanV1
    ) -> dict[str, object]:
        for record in records:
            if record["idempotency_key"] != plan.idempotency_key:
                continue
            if any(
                record[field] != getattr(plan, field)
                for field in (
                    "account_ref",
                    "expected_generation",
                    "expires_at",
                    "nonce",
                    "plan_digest",
                )
            ):
                raise OpenAICredentialError("control.idempotency_conflict")
            return record
        raise OpenAICredentialError("control.plan_stale")


class AuthorizedAuthIngress:
    """Capability-bound one-shot container for authorized raw auth bytes."""

    __slots__ = (
        "_account_ref",
        "_authority",
        "_closed",
        "_consumed",
        "_generation",
        "_lock",
        "_nonce",
        "_payload",
        "_plan_digest",
        "_plan_issuer",
        "_process_id",
    )

    _account_ref: str
    _authority: object
    _closed: bool
    _consumed: bool
    _generation: int
    _lock: threading.Lock
    _nonce: str
    _payload: bytearray
    _plan_digest: str
    _plan_issuer: object
    _process_id: int

    def __init__(self) -> None:
        raise TypeError("AuthorizedAuthIngress requires authorized issuance")

    @classmethod
    def issue(
        cls,
        authority: object,
        plan: object,
        payload: bytes,
    ) -> AuthorizedAuthIngress:
        if (
            authority is None
            or not isinstance(plan, AuthSyncPlanV1)
            or type(payload) is not bytes
            or not 1 <= len(payload) <= MAX_AUTH_BYTES
        ):
            raise OpenAICredentialError("control.request_invalid")
        ingress = cls.__new__(cls)
        ingress._authority = authority
        ingress._plan_issuer = plan._issuer
        ingress._account_ref = plan.account_ref
        ingress._generation = plan.expected_generation
        ingress._nonce = plan.nonce
        ingress._plan_digest = plan.plan_digest
        ingress._payload = bytearray(payload)
        ingress._consumed = False
        ingress._closed = False
        ingress._process_id = os.getpid()
        ingress._lock = threading.Lock()
        return ingress

    def _consume(
        self,
        authority: object,
        plan: AuthSyncPlanV1,
        process_id: int,
    ) -> bytearray:
        if (
            self._authority is not authority
            or self._plan_issuer is not plan._issuer
            or self._process_id != process_id
            or self._process_id != os.getpid()
            or self._account_ref != plan.account_ref
            or self._generation != plan.expected_generation
            or not hmac.compare_digest(self._nonce, plan.nonce)
            or not hmac.compare_digest(self._plan_digest, plan.plan_digest)
        ):
            raise OpenAICredentialError("credential.upload_expired")
        with self._lock:
            if self._consumed or self._closed:
                raise OpenAICredentialError("credential.upload_expired")
            self._consumed = True
            payload = self._payload
            self._payload = bytearray(len(payload))
            return payload

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def close(self) -> None:
        lock = getattr(self, "_lock", None)
        if lock is None:
            return
        with lock:
            _zero(self._payload)
            self._closed = True

    def __enter__(self) -> AuthorizedAuthIngress:
        if self.closed:
            raise OpenAICredentialError("credential.upload_expired")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def __repr__(self) -> str:
        return "AuthorizedAuthIngress(<redacted>)"


class _MaterializedAuth:
    __slots__ = (
        "_account_ref",
        "_descriptor",
        "_file_metadata",
        "_finalize_lock",
        "_invalidated",
        "_lease",
        "_lock",
        "_published",
        "_runtime_fd",
        "_runtime_metadata",
        "_temporary_name",
    )

    def __init__(
        self,
        account_ref: str,
        runtime_fd: int,
        runtime_metadata: tuple[int, ...],
        temporary_name: str,
    ) -> None:
        self._account_ref = account_ref
        self._runtime_fd: int | None = runtime_fd
        self._runtime_metadata = runtime_metadata
        self._temporary_name = temporary_name
        self._descriptor: int | None = None
        self._file_metadata: tuple[int, ...] | None = None
        self._published = False
        self._invalidated = False
        self._lease: CredentialLease | None = None
        self._lock = threading.RLock()
        self._finalize_lock = threading.Lock()

    @property
    def published(self) -> bool:
        with self._lock:
            return self._published

    @property
    def invalidated(self) -> bool:
        with self._lock:
            return self._invalidated

    def prepare(self) -> tuple[int, ...]:
        with self._lock:
            if self._descriptor is not None:
                raise OpenAICredentialError("credential.source_unavailable")
            if self._runtime_fd is None:
                raise OpenAICredentialError("credential.source_unavailable")
            descriptor, metadata = _prepare_auth(
                self._runtime_fd, self._runtime_metadata, self._temporary_name
            )
            self._descriptor = descriptor
            return metadata

    def bind_lease(self, lease: CredentialLease) -> None:
        with self._lock:
            if self._lease is not None:
                raise OpenAICredentialError("credential.source_unavailable")
            self._lease = lease

    def publish(
        self,
        payload: bytearray,
        record_file: Callable[[tuple[int, ...]], None],
    ) -> tuple[int, tuple[int, ...]]:
        with self._lock:
            if self._invalidated:
                raise OpenAICredentialError("credential.source_unavailable")
            if self._descriptor is None:
                raise OpenAICredentialError("credential.source_unavailable")
            if self._runtime_fd is None:
                raise OpenAICredentialError("credential.source_unavailable")
            metadata = _publish_auth(
                self._runtime_fd,
                self._runtime_metadata,
                self._temporary_name,
                self._descriptor,
                payload,
                record_file,
            )
            self._file_metadata = metadata
            self._published = True
            return self._descriptor, metadata

    def invalidate(self) -> None:
        with self._lock:
            self._invalidated = True
            self._remove_locked()

    def close(self) -> None:
        with self._lock:
            self._invalidated = True
            self._remove_locked()

    def _remove_locked(self) -> None:
        if not self._published:
            return
        if self._descriptor is None or self._file_metadata is None:
            raise OpenAICredentialError("credential.source_unavailable")
        if self._runtime_fd is None:
            raise OpenAICredentialError("credential.source_unavailable")
        try:
            _remove_auth(
                self._runtime_fd,
                self._runtime_metadata,
                self._temporary_name,
                self._descriptor,
                self._file_metadata,
            )
        except OpenAICredentialError:
            if _auth_name_absent(self._runtime_fd):
                self._published = False
                return
            raise
        else:
            self._published = False

    def lease(self) -> CredentialLease | None:
        with self._lock:
            return self._lease

    def take_resources(self) -> tuple[int | None, int | None]:
        with self._lock:
            descriptor = self._descriptor
            runtime_fd = self._runtime_fd
            self._descriptor = None
            self._runtime_fd = None
            self._lease = None
            return descriptor, runtime_fd


class OpenAICredentialService:
    """Synchronize authorized auth uploads and materialize one vault lease."""

    __slots__ = (
        "_clock",
        "_closed",
        "_identity_source",
        "_ingress_authority",
        "_janitor_started",
        "_janitor_stop",
        "_janitor_thread",
        "_lock",
        "_materializations",
        "_materializing_accounts",
        "_nonce_factory",
        "_plan_issuer",
        "_plan_refs",
        "_process_id",
        "_receipts",
        "_receipt_cache",
        "_vault",
        "__weakref__",
    )

    def __init__(
        self,
        vault: CredentialVault,
        identity_source: OpenAIIdentitySource,
        receipt_store: OpenAIAuthReceiptStore,
        *,
        ingress_authority: object,
        clock: Callable[[], float] | None = None,
        nonce_factory: Callable[[], bytes] | None = None,
    ) -> None:
        if (
            not isinstance(vault, CredentialVault)
            or not isinstance(identity_source, OpenAIIdentitySource)
            or not isinstance(receipt_store, OpenAIAuthReceiptStore)
            or ingress_authority is None
            or (clock is not None and not callable(clock))
            or (nonce_factory is not None and not callable(nonce_factory))
        ):
            raise OpenAICredentialError("control.request_invalid")
        self._vault = vault
        self._identity_source = identity_source
        self._receipts = receipt_store
        self._receipt_cache: dict[str, AuthSyncReceiptV1] = {}
        self._ingress_authority = ingress_authority
        self._clock = clock or time.time
        self._nonce_factory = nonce_factory or (lambda: os.urandom(32))
        self._plan_issuer = object()
        self._plan_refs: dict[int, weakref.ReferenceType[AuthSyncPlanV1]] = {}
        self._materializations: set[_MaterializedAuth] = set()
        self._materializing_accounts: set[str] = set()
        self._janitor_stop = threading.Event()
        self._janitor_started = False
        self._janitor_thread: threading.Thread | None = None
        self._closed = False
        self._lock = threading.RLock()
        self._process_id = os.getpid()
        try:
            self._vault.recover_materializations()
        except CredentialVaultError:
            raise OpenAICredentialError("credential.source_unavailable") from None

    def __repr__(self) -> str:
        return "OpenAICredentialService(<redacted>)"

    def plan_auth_sync(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
        ttl_seconds: int = MAX_AUTH_SYNC_PLAN_SECONDS,
    ) -> AuthSyncPlanV1:
        self._ensure_current_process()
        account_ref = _account_ref(account_ref)
        expected_generation = _generation(expected_generation)
        idempotency_key = _idempotency_key(idempotency_key)
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or not 1 <= ttl_seconds <= MAX_AUTH_SYNC_PLAN_SECONDS
        ):
            raise OpenAICredentialError("control.request_invalid")
        with self._identity_source.guard(account_ref) as identity:
            if not identity.enabled or identity.generation != expected_generation:
                raise OpenAICredentialError("control.request_invalid")
            now = self._now()
            nonce = self._new_nonce()
            expires_at = now + ttl_seconds
            plan_digest = _plan_digest(
                account_ref,
                expected_generation,
                expires_at,
                nonce,
                idempotency_key,
            )
            record = self._receipts.plan(
                {
                    "account_ref": account_ref,
                    "expected_generation": expected_generation,
                    "expires_at": expires_at,
                    "idempotency_key": idempotency_key,
                    "nonce": nonce,
                    "plan_digest": plan_digest,
                }
            )
        plan = AuthSyncPlanV1(
            str(record["account_ref"]),
            cast(int, record["expected_generation"]),
            cast(float, record["expires_at"]),
            str(record["nonce"]),
            str(record["idempotency_key"]),
            str(record["plan_digest"]),
            self._plan_issuer,
        )
        self._register_plan(plan)
        return plan

    def apply_auth_sync(
        self,
        plan: AuthSyncPlanV1,
        upload: AuthorizedAuthIngress,
    ) -> AuthSyncReceiptV1:
        self._ensure_current_process()
        raw = bytearray()
        if not isinstance(upload, AuthorizedAuthIngress):
            raise OpenAICredentialError("credential.upload_expired")
        try:
            with self._lock:
                plan = self._validated_plan(plan)
                status = self._receipts.status(plan)
                if status == "succeeded":
                    return self._receipt(plan)
                if status == "running":
                    raise OpenAICredentialError("control.operation_ambiguous")
                if status == "expired":
                    raise OpenAICredentialError("control.plan_stale")
                if self._now() >= plan.expires_at:
                    raise OpenAICredentialError("control.plan_stale")
                raw = upload._consume(self._ingress_authority, plan, self._process_id)
                with self._identity_source.guard(plan.account_ref) as initial_identity:
                    if (
                        not initial_identity.enabled
                        or initial_identity.generation != plan.expected_generation
                    ):
                        raise OpenAICredentialError("control.plan_stale")
                    expected_backend_account = initial_identity.backend_account_id
                try:
                    canonical = validate_openai_auth_json(
                        raw,
                        expected_account_id=expected_backend_account,
                    )
                except CredentialAuthorityError as exc:
                    if exc.code == "credential_identity_mismatch":
                        raise OpenAICredentialError("oauth.identity_mismatch") from None
                    raise OpenAICredentialError(
                        "credential.source_unavailable"
                    ) from None
                with self._identity_source.guard(plan.account_ref) as current_identity:
                    if (
                        not current_identity.enabled
                        or current_identity.generation != plan.expected_generation
                        or current_identity != initial_identity
                        or self._now() >= plan.expires_at
                    ):
                        raise OpenAICredentialError("control.plan_stale")
                    begin_state = self._receipts.begin(plan)
                    if begin_state == "succeeded":
                        return self._receipt(plan)
                    if self._now() >= plan.expires_at:
                        self._receipts.expire(plan)
                        raise OpenAICredentialError("control.plan_stale")
                    try:
                        self._vault.store_projection(
                            plan.account_ref,
                            plan.expected_generation,
                            canonical,
                        )
                    except CredentialVaultError as exc:
                        if exc.code == "credential.generation_conflict":
                            raise OpenAICredentialError(
                                "credential.generation_conflict"
                            ) from None
                        raise OpenAICredentialError(
                            "credential.source_unavailable"
                        ) from None
                    self._receipts.succeed(plan)
                return self._receipt(plan)
        finally:
            _zero(raw)
            upload.close()

    @contextmanager
    def materialize_auth_lease(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        runtime_dir_fd: int,
    ) -> Iterator[PurePosixPath]:
        self._ensure_current_process()
        account_ref = _account_ref(account_ref)
        expected_generation = _generation(expected_generation)
        runtime_fd, runtime_metadata, runtime_path = _duplicate_runtime_dir(
            runtime_dir_fd
        )
        temporary_name = _materialization_temporary_name()
        entry = _MaterializedAuth(
            account_ref, runtime_fd, runtime_metadata, temporary_name
        )
        payload = bytearray()
        owner_pid = self._process_id
        registered = False
        active: CredentialLease | None = None
        try:
            with entry._finalize_lock:  # noqa: SLF001 - setup/finalize boundary
                with self._lock:
                    if self._closed:
                        raise OpenAICredentialError("credential.source_unavailable")
                    if account_ref in self._materializing_accounts:
                        raise OpenAICredentialError("credential.source_unavailable")
                    self._materializing_accounts.add(account_ref)
                    self._materializations.add(entry)
                    registered = True
                    self._ensure_janitor_locked()
                with self._identity_source.guard(account_ref) as identity:
                    if (
                        not identity.enabled
                        or identity.generation != expected_generation
                    ):
                        raise OpenAICredentialError("control.request_invalid")
                    active, plaintext = self._vault.begin_materialization(
                        account_ref,
                        expected_generation=expected_generation,
                        ttl_seconds=MAX_AUTH_SYNC_PLAN_SECONDS,
                        invalidator=entry.invalidate,
                        cleanup_target=CredentialCleanupTarget(
                            runtime_path, runtime_metadata, temporary_name
                        ),
                        prepare=entry.prepare,
                    )
                    entry.bind_lease(active)
            try:
                payload = bytearray(plaintext)
                self._vault.publish_active(
                    active,
                    lambda record_file: entry.publish(payload, record_file),
                )
                yield PurePosixPath(_FINAL_NAME)
            except CredentialVaultError as exc:
                if exc.code == "credential.generation_conflict":
                    raise OpenAICredentialError(
                        "credential.generation_conflict"
                    ) from None
                raise OpenAICredentialError("credential.source_unavailable") from None
        finally:
            _zero(payload)
            cleanup_error: OpenAICredentialError | None = None
            active_error = sys.exc_info()[0] is not None
            if os.getpid() == owner_pid:
                attempts = 2 if active_error else 1
                for _attempt in range(attempts):
                    try:
                        entry.close()
                    except OpenAICredentialError:
                        if not active_error and _attempt + 1 == attempts:
                            cleanup_error = OpenAICredentialError(
                                "credential.source_unavailable"
                            )
                    if not entry.published:
                        break
            if not entry.published:
                try:
                    self._finalize_entry(entry, registered=registered)
                except OpenAICredentialError:
                    if not active_error:
                        cleanup_error = OpenAICredentialError(
                            "credential.source_unavailable"
                        )
            if cleanup_error is not None:
                raise cleanup_error

    def reap_materializations(self) -> None:
        self._ensure_current_process()
        try:
            self._vault.reconcile_active_leases()
        except CredentialVaultError:
            pass
        with self._lock:
            entries = tuple(self._materializations)
        for entry in entries:
            if not entry.invalidated:
                continue
            if entry.published:
                try:
                    entry.close()
                except OpenAICredentialError:
                    continue
            if not entry.published:
                self._finalize_entry(entry, registered=True)

    def close(self) -> None:
        """Stop janitor and deterministically close or durably orphan all claims."""

        self._ensure_current_process()
        with self._lock:
            self._closed = True
            self._janitor_stop.set()
            thread = self._janitor_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join()
        with self._lock:
            entries = tuple(self._materializations)
        failed = False
        for entry in entries:
            cleanup_failed = False
            try:
                entry.close()
            except OpenAICredentialError:
                failed = True
                cleanup_failed = True
            if cleanup_failed:
                try:
                    self._mark_entry_orphaned(entry)
                except OpenAICredentialError:
                    failed = True
                continue
            if not entry.published:
                try:
                    self._finalize_entry(entry, registered=True)
                except OpenAICredentialError:
                    failed = True
        if failed:
            raise OpenAICredentialError("credential.source_unavailable")

    def __enter__(self) -> OpenAICredentialService:
        self._ensure_current_process()
        return self

    def __exit__(self, _exc_type: object, primary: object, _traceback: object) -> None:
        try:
            self.close()
        except OpenAICredentialError:
            if primary is None:
                raise

    def _finalize_entry(self, entry: _MaterializedAuth, *, registered: bool) -> None:
        with entry._finalize_lock:  # noqa: SLF001 - service owns entry lifecycle
            lease = entry.lease()
            try:
                if lease is not None:
                    self._vault.complete_materialization(lease)
                    self._vault.release_materialization(lease)
            except CredentialVaultError:
                raise OpenAICredentialError("credential.source_unavailable") from None
            descriptor, runtime_fd = entry.take_resources()
            with self._lock:
                if registered:
                    self._materializing_accounts.discard(entry._account_ref)  # noqa: SLF001
                    self._materializations.discard(entry)
            _close(descriptor)
            _close(runtime_fd)

    def _mark_entry_orphaned(self, entry: _MaterializedAuth) -> None:
        with entry._finalize_lock:  # noqa: SLF001 - service owns entry lifecycle
            lease = entry.lease()
            try:
                if lease is not None:
                    self._vault.abandon_materialization(lease)
            except CredentialVaultError:
                raise OpenAICredentialError("credential.source_unavailable") from None

    def _ensure_janitor_locked(self) -> None:
        if self._janitor_started:
            return
        self._janitor_started = True
        thread = threading.Thread(
            target=_materialization_janitor,
            args=(weakref.ref(self), self._janitor_stop),
            name="openai-auth-materialization-janitor",
            daemon=True,
        )
        self._janitor_thread = thread
        try:
            thread.start()
        except Exception:
            self._janitor_started = False
            self._janitor_thread = None
            raise OpenAICredentialError("credential.source_unavailable") from None

    def _validated_plan(self, plan: object) -> AuthSyncPlanV1:
        reference = (
            self._plan_refs.get(id(plan)) if isinstance(plan, AuthSyncPlanV1) else None
        )
        if (
            not isinstance(plan, AuthSyncPlanV1)
            or plan._issuer is not self._plan_issuer
            or reference is None
            or reference() is not plan
            or _plan_digest(
                plan.account_ref,
                plan.expected_generation,
                plan.expires_at,
                plan.nonce,
                plan.idempotency_key,
            )
            != plan.plan_digest
        ):
            raise OpenAICredentialError("control.plan_stale")
        return plan

    def _registered_account(self, value: object) -> str:
        account_ref = _account_ref(value)
        with self._identity_source.guard(account_ref) as identity:
            if not identity.enabled:
                raise OpenAICredentialError("control.request_invalid")
        return account_ref

    def _register_plan(self, plan: AuthSyncPlanV1) -> None:
        plan_id = id(plan)
        service_ref = weakref.ref(self)

        def forgotten(reference: weakref.ReferenceType[AuthSyncPlanV1]) -> None:
            service = service_ref()
            if service is None:
                return
            with service._lock:
                if service._plan_refs.get(plan_id) is reference:
                    service._plan_refs.pop(plan_id, None)

        with self._lock:
            self._plan_refs[plan_id] = weakref.ref(plan, forgotten)

    def _receipt(self, plan: AuthSyncPlanV1) -> AuthSyncReceiptV1:
        receipt = self._receipt_cache.get(plan.plan_digest)
        if receipt is None:
            receipt = AuthSyncReceiptV1(
                plan.account_ref, plan.expected_generation, plan.plan_digest
            )
            self._receipt_cache[plan.plan_digest] = receipt
        return receipt

    def _new_nonce(self) -> str:
        try:
            value = self._nonce_factory()
        except Exception:
            raise OpenAICredentialError("credential.source_unavailable") from None
        if type(value) is not bytes or len(value) != 32:
            raise OpenAICredentialError("credential.source_unavailable")
        return value.hex()

    def _now(self) -> float:
        try:
            value = self._clock()
        except Exception:
            raise OpenAICredentialError("credential.source_unavailable") from None
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise OpenAICredentialError("credential.source_unavailable")
        return float(value)

    def _ensure_current_process(self) -> None:
        if self._process_id != os.getpid():
            raise OpenAICredentialError("credential.source_unavailable")


def _account_ref(value: object) -> str:
    if type(value) is not str or _ACCOUNT_REF.fullmatch(value) is None:
        raise OpenAICredentialError("control.request_invalid")
    return value


def _receipt_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OpenAICredentialError("credential.source_unavailable")
        result[key] = value
    return result


def _receipt_document(records: list[dict[str, object]]) -> bytes:
    try:
        return (
            json.dumps(
                {"schema_version": 1, "records": records},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise OpenAICredentialError("credential.source_unavailable") from None


def _identity_document(
    identities: Mapping[str, OpenAIAccountIdentity],
) -> bytes:
    try:
        records = [
            {
                "account_ref": account_ref,
                "backend_account_id": identity.backend_account_id,
                "enabled": identity.enabled,
                "generation": identity.generation,
            }
            for account_ref, identity in sorted(identities.items())
        ]
        return (
            json.dumps(
                {"schema_version": 1, "identities": records},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise OpenAICredentialError("credential.source_unavailable") from None


def _backend_account(value: object) -> str:
    if type(value) is not str or _BACKEND_ACCOUNT.fullmatch(value) is None:
        raise OpenAICredentialError("control.request_invalid")
    return value


def _generation(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _MAX_GENERATION
    ):
        raise OpenAICredentialError("control.request_invalid")
    return value


def _idempotency_key(value: object) -> str:
    if type(value) is not str or _IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise OpenAICredentialError("control.request_invalid")
    return value


def _plan_digest(
    account_ref: str,
    generation: int,
    expires_at: float,
    nonce: str,
    idempotency_key: str,
) -> str:
    if (
        _ACCOUNT_REF.fullmatch(account_ref) is None
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= _MAX_GENERATION
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or not math.isfinite(expires_at)
        or type(nonce) is not str
        or re.fullmatch(r"[0-9a-f]{64}", nonce, re.ASCII) is None
        or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
    ):
        raise OpenAICredentialError("control.plan_stale")
    document = json.dumps(
        {
            "account_ref": account_ref,
            "expected_generation": generation,
            "expires_at": float(expires_at).hex(),
            "idempotency_key": idempotency_key,
            "nonce": nonce,
            "schema_version": 1,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(b"codex-master/openai-auth-sync/v1\0" + document).hexdigest()


def _directory_metadata(value: os.stat_result) -> tuple[int, ...]:
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_IMODE(value.st_mode) != 0o700
        or value.st_uid != os.geteuid()
        or value.st_gid != os.getegid()
        or value.st_nlink < 1
    ):
        raise OpenAICredentialError("credential.source_unavailable")
    return _raw_directory_metadata(value)


def _raw_directory_metadata(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
    )


def _file_metadata(
    value: os.stat_result, expected_size: int, *, expected_links: int = 1
) -> tuple[int, ...]:
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_uid != os.geteuid()
        or value.st_gid != os.getegid()
        or value.st_nlink != expected_links
        or value.st_size != expected_size
    ):
        raise OpenAICredentialError("credential.source_unavailable")
    return _raw_file_metadata(value)


def _raw_file_metadata(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _duplicate_runtime_dir(value: object) -> tuple[int, tuple[int, ...], str]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise OpenAICredentialError("credential.source_unavailable")
    duplicate: int | None = None
    try:
        before = _directory_metadata(os.fstat(value))
        duplicate = os.dup(value)
        os.set_inheritable(duplicate, False)
        copied = _directory_metadata(os.fstat(duplicate))
        after = _directory_metadata(os.fstat(value))
        if before != copied or copied != after:
            raise OpenAICredentialError("credential.source_unavailable")
        runtime_path = os.readlink(f"/proc/self/fd/{duplicate}")
        if (
            not runtime_path.startswith("/")
            or runtime_path.endswith(" (deleted)")
            or "\x00" in runtime_path
            or len(runtime_path.encode("utf-8", errors="replace")) > 4096
        ):
            raise OpenAICredentialError("credential.source_unavailable")
        path_fd = os.open(
            runtime_path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            if _directory_metadata(os.fstat(path_fd)) != copied:
                raise OpenAICredentialError("credential.source_unavailable")
        finally:
            _close(path_fd)
        return duplicate, copied, runtime_path
    except OpenAICredentialError:
        _close(duplicate)
        raise
    except Exception:
        _close(duplicate)
        raise OpenAICredentialError("credential.source_unavailable") from None


def _materialization_temporary_name() -> str:
    try:
        random_part = os.urandom(32).hex()
    except Exception:
        raise OpenAICredentialError("credential.source_unavailable") from None
    if re.fullmatch(r"[0-9a-f]{64}", random_part, re.ASCII) is None:
        raise OpenAICredentialError("credential.source_unavailable")
    return f".{_FINAL_NAME}.{random_part}.tmp"


def _temporary_claim_token(temporary_name: str) -> bytes:
    match = re.fullmatch(r"\.auth\.json\.([0-9a-f]{64})\.tmp", temporary_name)
    if match is None:
        raise OpenAICredentialError("credential.source_unavailable")
    return match.group(1).encode("ascii")


def _reattest_directory(fd: int, expected: tuple[int, ...]) -> None:
    try:
        observed = _directory_metadata(os.fstat(fd))
    except OpenAICredentialError:
        raise
    except Exception:
        raise OpenAICredentialError("credential.source_unavailable") from None
    if observed != expected:
        raise OpenAICredentialError("credential.source_unavailable")


def _prepare_auth(
    runtime_fd: int,
    runtime_metadata: tuple[int, ...],
    temporary_name: str,
) -> tuple[int, tuple[int, ...]]:
    descriptor: int | None = None
    succeeded = False
    try:
        _reattest_directory(runtime_fd, runtime_metadata)
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=runtime_fd,
        )
        os.fchmod(descriptor, 0o600)
        claim_token = _temporary_claim_token(temporary_name)
        os.setxattr(descriptor, _CLAIM_XATTR, claim_token, flags=os.XATTR_CREATE)
        if not hmac.compare_digest(os.getxattr(descriptor, _CLAIM_XATTR), claim_token):
            raise OpenAICredentialError("credential.source_unavailable")
        os.fsync(descriptor)
        os.fsync(runtime_fd)
        metadata = _file_metadata(os.fstat(descriptor), 0)
        _reattest_directory(runtime_fd, runtime_metadata)
        succeeded = True
        return descriptor, metadata
    except OpenAICredentialError:
        raise
    except Exception:
        raise OpenAICredentialError("credential.source_unavailable") from None
    finally:
        if not succeeded:
            _close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=runtime_fd)
                os.fsync(runtime_fd)
            except OSError:
                pass


def _publish_auth(
    runtime_fd: int,
    runtime_metadata: tuple[int, ...],
    temporary_name: str,
    descriptor: int,
    payload: bytearray,
    record_file: Callable[[tuple[int, ...]], None],
) -> tuple[int, ...]:
    try:
        _reattest_directory(runtime_fd, runtime_metadata)
        _file_metadata(os.fstat(descriptor), 0)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
        before = _file_metadata(os.fstat(descriptor), len(payload))
        record_file(before)
        _reattest_directory(runtime_fd, runtime_metadata)
        os.link(
            temporary_name,
            _FINAL_NAME,
            src_dir_fd=runtime_fd,
            dst_dir_fd=runtime_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=runtime_fd)
        os.fsync(runtime_fd)
        _reattest_directory(runtime_fd, runtime_metadata)
        named = _file_metadata(
            os.stat(_FINAL_NAME, dir_fd=runtime_fd, follow_symlinks=False),
            len(payload),
        )
        opened = _file_metadata(os.fstat(descriptor), len(payload))
        if before[:2] != named[:2] or named != opened:
            raise OpenAICredentialError("credential.source_unavailable")
        return opened
    except OpenAICredentialError:
        raise
    except Exception:
        raise OpenAICredentialError("credential.source_unavailable") from None


def _remove_auth(
    runtime_fd: int,
    runtime_metadata: tuple[int, ...],
    temporary_name: str,
    descriptor: int,
    expected_metadata: tuple[int, ...],
) -> None:
    try:
        directory_before = _raw_directory_metadata(os.fstat(runtime_fd))
        if directory_before[:2] != runtime_metadata[:2]:
            raise OpenAICredentialError("credential.source_unavailable")
        directory_drifted = directory_before != runtime_metadata
        opened = _raw_file_metadata(os.fstat(descriptor))
        if not hmac.compare_digest(
            os.getxattr(descriptor, _CLAIM_XATTR),
            _temporary_claim_token(temporary_name),
        ):
            raise OpenAICredentialError("credential.source_unavailable")
        named_info = os.stat(
            _FINAL_NAME,
            dir_fd=runtime_fd,
            follow_symlinks=False,
        )
        named = _raw_file_metadata(named_info)
        if opened[:2] != named[:2]:
            raise OpenAICredentialError("credential.source_unavailable")
        drifted = opened != expected_metadata or named != expected_metadata
        os.unlink(_FINAL_NAME, dir_fd=runtime_fd)
        os.fsync(runtime_fd)
        directory_after = _raw_directory_metadata(os.fstat(runtime_fd))
        if directory_after[:2] != runtime_metadata[:2]:
            raise OpenAICredentialError("credential.source_unavailable")
        if drifted or directory_drifted or directory_after != runtime_metadata:
            raise OpenAICredentialError("credential.source_unavailable")
    except OpenAICredentialError:
        raise
    except Exception:
        raise OpenAICredentialError("credential.source_unavailable") from None


def _auth_name_absent(runtime_fd: int) -> bool:
    try:
        os.stat(_FINAL_NAME, dir_fd=runtime_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _materialization_janitor(
    service_ref: weakref.ReferenceType[OpenAICredentialService],
    stop: threading.Event,
) -> None:
    while not stop.wait(0.1):
        service = service_ref()
        if service is None:
            return
        try:
            service.reap_materializations()
        except BaseException:
            pass
        finally:
            del service


def _zero(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _close(value: int | None) -> None:
    if value is None:
        return
    try:
        os.close(value)
    except OSError:
        pass


__all__ = (
    "AuthorizedAuthIngress",
    "AuthSyncPlanV1",
    "AuthSyncReceiptV1",
    "MAX_AUTH_SYNC_PLAN_SECONDS",
    "OpenAIAccountIdentity",
    "OpenAIAuthReceiptStore",
    "OpenAICredentialError",
    "OpenAICredentialService",
    "OpenAIIdentitySource",
)
