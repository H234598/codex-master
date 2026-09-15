"""Closed read-only inventory control authority.

This module is the only non-admin public entrypoint for the read-only Google
inventory flow.  Its adapters, operation state and plans are deliberately
private; public callers can neither select OAuth policy nor substitute a
provider, token or storage port.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from types import MappingProxyType
from typing import Final

import yaml

from . import google_account_inventory as _inventory
from . import google_inventory_readonly_scan as _scan
from . import google_inventory_store as _inventory_store
from . import google_inventory_token_vault as _token_vault
from . import google_oauth_session as _oauth_session
from .google_inventory_token_vault import (
    _authorization_binding_fingerprint as _vault_authorization_binding_fingerprint,
)


_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "oauth.interactive_authorization_required",
        "inventory.readonly_control_request_invalid",
        "inventory.readonly_control_unavailable",
        "inventory.readonly_control_plan_invalid",
        "inventory.readonly_control_plan_expired",
        "inventory.readonly_control_plan_consumed",
        "inventory.readonly_control_plan_stale",
        "inventory.readonly_control_apply_failed",
        "inventory.readonly_control_reload_failed",
        "inventory.readonly_control_recovery_failed",
    }
)
_BINDING_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "account_ref",
        "subject_id",
        "inventory_generation",
        "content_fingerprint",
        "oauth_client_fingerprint",
        "scope_fingerprint",
        "plan_id",
        "plan_digest",
        "resulting_content_fingerprint",
        "created_at",
        "expires_at",
    }
)
_PROJECTION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "status",
        "account_count",
        "project_count",
        "billing_account_count",
        "service_count",
        "key_count",
        "changes",
    }
)
_FINGERPRINT_PREFIX: Final[str] = "sha256:"
_MAX_GENERATION: Final[int] = 2**63 - 1
_MAX_REFERENCE_BYTES: Final[int] = 192
_MAX_SUBJECT_BYTES: Final[int] = 1024
_MAX_PLAN_ID_BYTES: Final[int] = 192
_MAX_PLAN_REGISTRY_ENTRIES: Final[int] = 128
_MAX_RECEIPTS: Final[int] = 128
_JOURNAL_FILENAME: Final[str] = ".google-inventory-readonly-operation-v1.json"
_AUTHORIZATION_JOURNAL_FILENAME: Final[str] = (
    ".google-inventory-readonly-authorize-v1.json"
)
_JOURNAL_MAX_BYTES: Final[int] = 1024 * 1024
_PUBLIC_CHANGE_KINDS: Final[frozenset[str]] = frozenset({"canonical_account"})
_INVENTORY_READONLY_PROFILE_ID: Final[str] = "inventory_readonly"


class GoogleInventoryReadonlyControlError(Exception):
    """Code-only failure at the closed inventory-control boundary."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            raise TypeError("invalid inventory control error code")
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"GoogleInventoryReadonlyControlError({self.code!r})"

    def __str__(self) -> str:
        return self.code


def _fail(code: str) -> None:
    raise GoogleInventoryReadonlyControlError(code) from None


def _is_nonempty_text(value: object, maximum_bytes: int) -> bool:
    if type(value) is not str or not value or "\x00" in value:
        return False
    try:
        return len(value.encode("utf-8")) <= maximum_bytes
    except UnicodeError:
        return False


def _is_fingerprint(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 71
        and value.startswith(_FINGERPRINT_PREFIX)
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _is_timestamp(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        parsed = float(value)
    except (OverflowError, ValueError):
        return False
    return math.isfinite(parsed) and 0.0 <= parsed <= float(_MAX_GENERATION)


@dataclass(frozen=True, slots=True, repr=False)
class _InventoryDocumentState:
    content_fingerprint: str
    subjects_by_account_ref: Mapping[str, str | None] = field(repr=False)

    def __repr__(self) -> str:
        return "_InventoryDocumentState(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("_InventoryDocumentState is not serializable")


@dataclass(frozen=True, slots=True, repr=False)
class _PlanBinding:
    account_ref: str = field(repr=False)
    subject_id: str = field(repr=False)
    inventory_generation: int
    content_fingerprint: str
    oauth_client_fingerprint: str
    scope_fingerprint: str
    plan_id: str = field(repr=False)
    plan_digest: str
    resulting_content_fingerprint: str
    created_at: float
    expires_at: float

    def __repr__(self) -> str:
        return "_PlanBinding(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("_PlanBinding is not serializable")


@dataclass(frozen=True, slots=True, repr=False)
class _PlanRegistryEntry:
    plan: object = field(repr=False)
    binding: _PlanBinding = field(repr=False)
    consumed: bool

    def __repr__(self) -> str:
        return "_PlanRegistryEntry(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("_PlanRegistryEntry is not serializable")


class _PlanRegistry:
    __slots__ = ("_entries",)

    def __init__(self) -> None:
        self._entries: dict[str, _PlanRegistryEntry] = {}

    def register(self, plan: object, binding: _PlanBinding) -> str:
        if len(self._entries) >= _MAX_PLAN_REGISTRY_ENTRIES:
            _fail("inventory.readonly_control_unavailable")
        for _ in range(8):
            reference = "plan-" + secrets.token_urlsafe(32)
            if reference not in self._entries:
                self._entries[reference] = _PlanRegistryEntry(
                    plan=plan, binding=binding, consumed=False
                )
                return reference
        _fail("inventory.readonly_control_unavailable")

    def resolve(self, reference: object) -> tuple[str, _PlanRegistryEntry]:
        if not _is_nonempty_text(reference, _MAX_REFERENCE_BYTES):
            _fail("inventory.readonly_control_request_invalid")
        assert type(reference) is str
        try:
            return reference, self._entries[reference]
        except KeyError:
            _fail("inventory.readonly_control_plan_invalid")

    def known(self, reference: str) -> _PlanRegistryEntry | None:
        return self._entries.get(reference)

    def restore(
        self, reference: str, plan: object, binding: _PlanBinding, *, consumed: bool
    ) -> None:
        if (
            not _is_nonempty_text(reference, _MAX_REFERENCE_BYTES)
            or reference in self._entries
        ):
            _fail("inventory.readonly_control_unavailable")
        self._entries[reference] = _PlanRegistryEntry(
            plan=plan, binding=binding, consumed=consumed
        )

    def consume(self, reference: str, entry: _PlanRegistryEntry) -> _PlanRegistryEntry:
        if entry.consumed:
            return entry
        consumed = _PlanRegistryEntry(
            plan=entry.plan, binding=entry.binding, consumed=True
        )
        self._entries[reference] = consumed
        return consumed


@dataclass(frozen=True, slots=True, repr=False)
class _CommittedOperation:
    plan_reference: str = field(repr=False)
    plan_id: str = field(repr=False)
    plan_digest: str
    account_fingerprint: str
    subject_fingerprint: str
    source_generation: int
    source_fingerprint: str
    oauth_client_fingerprint: str
    scope_fingerprint: str
    resulting_fingerprint: str

    def __repr__(self) -> str:
        return "_CommittedOperation(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("_CommittedOperation is not serializable")


@dataclass(frozen=True, slots=True, repr=False)
class _PendingAuthorization:
    """Secret-free recovery binding for one private authorization effect."""

    operation_digest: str
    binding_fingerprint: str
    account_fingerprint: str
    subject_fingerprint: str
    oauth_client_fingerprint: str
    scope_fingerprint: str
    source_generation: int
    inventory_generation: int
    source_fingerprint: str
    resulting_fingerprint: str

    def __repr__(self) -> str:
        return "_PendingAuthorization(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("_PendingAuthorization is not serializable")


@dataclass(frozen=True, slots=True, repr=False)
class _SealedPlanRecord:
    reference: str = field(repr=False)
    plan_digest: str
    payload: bytes = field(repr=False)

    def __repr__(self) -> str:
        return "_SealedPlanRecord(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("_SealedPlanRecord is not serializable")


class _JournalFailure(Exception):
    __slots__ = ()


class _OperationJournal:
    """Single-operation, secret-free durable journal owned by this authority."""

    __slots__ = ("_directory", "_prepared", "_receipt", "_sealed_plan")

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._prepared: _CommittedOperation | None = None
        self._receipt: _CommittedOperation | None = None
        self._sealed_plan: _SealedPlanRecord | None = None
        self._load()

    def __repr__(self) -> str:
        return "_OperationJournal(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("_OperationJournal is not serializable")

    def prepared(self) -> _CommittedOperation | None:
        return self._prepared

    def sealed_plan(self) -> _SealedPlanRecord | None:
        return self._sealed_plan

    def store_plan(self, record: _SealedPlanRecord) -> None:
        if self._prepared is not None:
            raise _JournalFailure
        self._write("plan", None, record)
        self._sealed_plan = record
        self._receipt = None

    def prepare(self, operation: _CommittedOperation) -> None:
        if self._prepared is not None:
            raise _JournalFailure
        if (
            self._sealed_plan is None
            or self._sealed_plan.reference != operation.plan_reference
        ):
            raise _JournalFailure
        if self._receipt is not None:
            self._receipt = None
        self._write("prepared", operation, self._sealed_plan)
        self._prepared = operation

    def discard_prepared(self, operation: _CommittedOperation) -> None:
        if self._prepared != operation:
            raise _JournalFailure
        if self._sealed_plan is None:
            raise _JournalFailure
        self._write("plan", None, self._sealed_plan)
        self._prepared = None

    def mark_reloaded(self, operation: _CommittedOperation) -> None:
        if self._prepared != operation:
            raise _JournalFailure
        if self._sealed_plan is None:
            raise _JournalFailure
        self._write("receipt", operation, self._sealed_plan)
        self._receipt = operation
        self._prepared = None

    def receipt_for(self, reference: str, binding: _PlanBinding) -> bool:
        operation = self._receipt
        return (
            operation is not None
            and operation.plan_reference == reference
            and operation.plan_id == binding.plan_id
            and operation.plan_digest == binding.plan_digest
            and operation.account_fingerprint
            == _account_fingerprint(binding.account_ref)
            and operation.subject_fingerprint
            == _subject_fingerprint(binding.subject_id)
            and operation.source_generation == binding.inventory_generation
            and operation.source_fingerprint == binding.content_fingerprint
            and operation.oauth_client_fingerprint == binding.oauth_client_fingerprint
            and operation.scope_fingerprint == binding.scope_fingerprint
            and operation.resulting_fingerprint == binding.resulting_content_fingerprint
        )

    def receipt_for_reference(self, reference: str) -> bool:
        return self._receipt is not None and self._receipt.plan_reference == reference

    def _load(self) -> None:
        directory_fd = self._open_directory()
        descriptor: int | None = None
        try:
            try:
                item = os.stat(
                    _JOURNAL_FILENAME, dir_fd=directory_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                return
            if (
                not stat.S_ISREG(item.st_mode)
                or item.st_uid != os.geteuid()
                or stat.S_IMODE(item.st_mode) != 0o600
                or item.st_nlink != 1
            ):
                raise _JournalFailure
            descriptor = os.open(
                _JOURNAL_FILENAME,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (item.st_dev, item.st_ino):
                raise _JournalFailure
            payload = b""
            while len(payload) <= _JOURNAL_MAX_BYTES:
                block = os.read(descriptor, 4096)
                if not block:
                    break
                payload += block
            if len(payload) > _JOURNAL_MAX_BYTES:
                raise _JournalFailure
            current = os.stat(
                _JOURNAL_FILENAME, dir_fd=directory_fd, follow_symlinks=False
            )
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise _JournalFailure
            state, operation, sealed_plan = self._decode(payload)
            self._sealed_plan = sealed_plan
            if state == "prepared":
                assert operation is not None
                self._prepared = operation
            elif state == "receipt":
                assert operation is not None
                self._receipt = operation
        except _JournalFailure:
            raise
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            raise _JournalFailure from None
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                os.close(directory_fd)
            except OSError:
                pass

    def _write(
        self,
        state: str,
        operation: _CommittedOperation | None,
        sealed_plan: _SealedPlanRecord,
    ) -> None:
        payload = json.dumps(
            {
                "operation": (
                    None if operation is None else self._encode_operation(operation)
                ),
                "sealed_plan": self._encode_sealed_plan(sealed_plan),
                "state": state,
                "version": 2,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if len(payload) > _JOURNAL_MAX_BYTES:
            raise _JournalFailure
        directory_fd = self._open_directory()
        temporary_fd: int | None = None
        temporary_name: str | None = None
        replaced = False
        try:
            for _ in range(8):
                candidate = f".{_JOURNAL_FILENAME}.{secrets.token_hex(16)}.tmp"
                try:
                    temporary_fd = os.open(
                        candidate,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_CLOEXEC
                        | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=directory_fd,
                    )
                except FileExistsError:
                    continue
                temporary_name = candidate
                break
            if temporary_fd is None or temporary_name is None:
                raise _JournalFailure
            self._write_all(temporary_fd, payload)
            os.fchmod(temporary_fd, 0o600)
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None
            os.replace(
                temporary_name,
                _JOURNAL_FILENAME,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            replaced = True
            os.fsync(directory_fd)
        except _JournalFailure:
            raise
        except OSError:
            raise _JournalFailure from None
        finally:
            if temporary_fd is not None:
                try:
                    os.close(temporary_fd)
                except OSError:
                    pass
            if not replaced and temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except OSError:
                    pass
            try:
                os.close(directory_fd)
            except OSError:
                pass

    def _clear(self) -> None:
        directory_fd = self._open_directory()
        try:
            os.unlink(_JOURNAL_FILENAME, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except OSError:
            raise _JournalFailure from None
        finally:
            try:
                os.close(directory_fd)
            except OSError:
                pass

    def _open_directory(self) -> int:
        path = self._directory
        try:
            if not path.is_absolute():
                raise _JournalFailure
            item = os.lstat(path)
            if (
                not stat.S_ISDIR(item.st_mode)
                or item.st_uid != os.geteuid()
                or bool(stat.S_IMODE(item.st_mode) & 0o022)
            ):
                raise _JournalFailure
            descriptor = os.open(
                path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            opened = os.fstat(descriptor)
            current = os.lstat(path)
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                os.close(descriptor)
                raise _JournalFailure
            return descriptor
        except _JournalFailure:
            raise
        except OSError:
            raise _JournalFailure from None

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise _JournalFailure
            view = view[written:]

    @staticmethod
    def _encode_operation(operation: _CommittedOperation) -> dict[str, object]:
        return {
            "account_fingerprint": operation.account_fingerprint,
            "oauth_client_fingerprint": operation.oauth_client_fingerprint,
            "plan_digest": operation.plan_digest,
            "plan_id": operation.plan_id,
            "plan_reference": operation.plan_reference,
            "resulting_fingerprint": operation.resulting_fingerprint,
            "scope_fingerprint": operation.scope_fingerprint,
            "source_fingerprint": operation.source_fingerprint,
            "source_generation": operation.source_generation,
            "subject_fingerprint": operation.subject_fingerprint,
        }

    @staticmethod
    def _decode(
        payload: bytes,
    ) -> tuple[str, _CommittedOperation | None, _SealedPlanRecord]:
        try:
            parsed = json.loads(payload.decode("ascii"))
        except (UnicodeError, json.JSONDecodeError):
            raise _JournalFailure from None
        if (
            type(parsed) is not dict
            or set(parsed) != {"operation", "sealed_plan", "state", "version"}
            or parsed.get("version") != 2
            or parsed.get("state") not in {"plan", "prepared", "receipt"}
            or type(parsed.get("sealed_plan")) is not dict
        ):
            raise _JournalFailure
        state = parsed["state"]
        assert type(state) is str
        operation_raw = parsed["operation"]
        if (state == "plan" and operation_raw is not None) or (
            state != "plan" and type(operation_raw) is not dict
        ):
            raise _JournalFailure
        sealed_plan = _OperationJournal._decode_sealed_plan(parsed["sealed_plan"])
        if state == "plan":
            return state, None, sealed_plan
        raw = operation_raw
        assert type(raw) is dict
        fields = {
            "account_fingerprint",
            "oauth_client_fingerprint",
            "plan_digest",
            "plan_id",
            "plan_reference",
            "resulting_fingerprint",
            "scope_fingerprint",
            "source_fingerprint",
            "source_generation",
            "subject_fingerprint",
        }
        if set(raw) != fields:
            raise _JournalFailure
        generation = raw["source_generation"]
        if not (
            _is_nonempty_text(raw["plan_reference"], _MAX_REFERENCE_BYTES)
            and _is_nonempty_text(raw["plan_id"], _MAX_PLAN_ID_BYTES)
            and type(generation) is int
            and 1 <= generation <= _MAX_GENERATION
            and all(
                _is_fingerprint(raw[field])
                for field in fields - {"plan_reference", "plan_id", "source_generation"}
            )
        ):
            raise _JournalFailure
        operation = _CommittedOperation(
            plan_reference=raw["plan_reference"],
            plan_id=raw["plan_id"],
            plan_digest=raw["plan_digest"],
            account_fingerprint=raw["account_fingerprint"],
            subject_fingerprint=raw["subject_fingerprint"],
            source_generation=generation,
            source_fingerprint=raw["source_fingerprint"],
            oauth_client_fingerprint=raw["oauth_client_fingerprint"],
            scope_fingerprint=raw["scope_fingerprint"],
            resulting_fingerprint=raw["resulting_fingerprint"],
        )
        if operation.plan_reference != sealed_plan.reference:
            raise _JournalFailure
        return (
            state,
            operation,
            sealed_plan,
        )

    @staticmethod
    def _encode_sealed_plan(record: _SealedPlanRecord) -> dict[str, str]:
        return {
            "payload": base64.b64encode(record.payload).decode("ascii"),
            "plan_digest": record.plan_digest,
            "reference": record.reference,
        }

    @staticmethod
    def _decode_sealed_plan(value: object) -> _SealedPlanRecord:
        if type(value) is not dict or set(value) != {
            "payload",
            "plan_digest",
            "reference",
        }:
            raise _JournalFailure
        reference = value["reference"]
        encoded = value["payload"]
        plan_digest = value["plan_digest"]
        if not (
            _is_nonempty_text(reference, _MAX_REFERENCE_BYTES)
            and type(encoded) is str
            and encoded
            and _is_fingerprint(plan_digest)
        ):
            raise _JournalFailure
        try:
            payload = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (UnicodeError, ValueError):
            raise _JournalFailure from None
        if not payload or len(payload) > _JOURNAL_MAX_BYTES:
            raise _JournalFailure
        assert type(reference) is str
        assert type(plan_digest) is str
        return _SealedPlanRecord(
            reference=reference, plan_digest=plan_digest, payload=payload
        )


class _AuthorizationJournal:
    """Durable, secret-free private recovery state for authorization only."""

    __slots__ = ("_directory", "_pending", "_receipt")

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._pending: _PendingAuthorization | None = None
        self._receipt: _PendingAuthorization | None = None
        self._load()

    def __repr__(self) -> str:
        return "_AuthorizationJournal(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("_AuthorizationJournal is not serializable")

    def record(self) -> _PendingAuthorization | None:
        return self._pending if self._pending is not None else self._receipt

    def prepare(self, record: _PendingAuthorization) -> None:
        if self.record() is not None:
            raise _JournalFailure
        self._write("pending", record)
        self._pending = record

    def discard(self, record: _PendingAuthorization) -> None:
        if self._pending != record:
            raise _JournalFailure
        self._clear()
        self._pending = None

    def mark_receipt(self, record: _PendingAuthorization) -> None:
        if self.record() != record:
            raise _JournalFailure
        self._write("receipt", record)
        self._pending = None
        self._receipt = record

    def _load(self) -> None:
        directory_fd = self._open_directory()
        descriptor: int | None = None
        try:
            try:
                item = os.stat(
                    _AUTHORIZATION_JOURNAL_FILENAME,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return
            if (
                not stat.S_ISREG(item.st_mode)
                or item.st_uid != os.geteuid()
                or stat.S_IMODE(item.st_mode) != 0o600
                or item.st_nlink != 1
            ):
                raise _JournalFailure
            descriptor = os.open(
                _AUTHORIZATION_JOURNAL_FILENAME,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (item.st_dev, item.st_ino):
                raise _JournalFailure
            payload = b""
            while len(payload) <= _JOURNAL_MAX_BYTES:
                block = os.read(descriptor, 4096)
                if not block:
                    break
                payload += block
            if len(payload) > _JOURNAL_MAX_BYTES:
                raise _JournalFailure
            current = os.stat(
                _AUTHORIZATION_JOURNAL_FILENAME,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise _JournalFailure
            state, record = self._decode(payload)
            if state == "pending":
                self._pending = record
            else:
                self._receipt = record
        except _JournalFailure:
            raise
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            raise _JournalFailure from None
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                os.close(directory_fd)
            except OSError:
                pass

    def _write(self, state: str, record: _PendingAuthorization) -> None:
        payload = json.dumps(
            {
                "record": self._encode(record),
                "state": state,
                "version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if len(payload) > _JOURNAL_MAX_BYTES:
            raise _JournalFailure
        directory_fd = self._open_directory()
        temporary_fd: int | None = None
        temporary_name: str | None = None
        replaced = False
        try:
            for _ in range(8):
                candidate = (
                    f".{_AUTHORIZATION_JOURNAL_FILENAME}.{secrets.token_hex(16)}.tmp"
                )
                try:
                    temporary_fd = os.open(
                        candidate,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_CLOEXEC
                        | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=directory_fd,
                    )
                except FileExistsError:
                    continue
                temporary_name = candidate
                break
            if temporary_fd is None or temporary_name is None:
                raise _JournalFailure
            _OperationJournal._write_all(temporary_fd, payload)
            os.fchmod(temporary_fd, 0o600)
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None
            os.replace(
                temporary_name,
                _AUTHORIZATION_JOURNAL_FILENAME,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            replaced = True
            os.fsync(directory_fd)
        except _JournalFailure:
            raise
        except OSError:
            raise _JournalFailure from None
        finally:
            if temporary_fd is not None:
                try:
                    os.close(temporary_fd)
                except OSError:
                    pass
            if not replaced and temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except OSError:
                    pass
            try:
                os.close(directory_fd)
            except OSError:
                pass

    def _clear(self) -> None:
        directory_fd = self._open_directory()
        try:
            os.unlink(_AUTHORIZATION_JOURNAL_FILENAME, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except OSError:
            raise _JournalFailure from None
        finally:
            try:
                os.close(directory_fd)
            except OSError:
                pass

    def _open_directory(self) -> int:
        return _OperationJournal._open_directory(self)  # type: ignore[arg-type]

    @staticmethod
    def _encode(record: _PendingAuthorization) -> dict[str, object]:
        return {
            "account_fingerprint": record.account_fingerprint,
            "binding_fingerprint": record.binding_fingerprint,
            "inventory_generation": record.inventory_generation,
            "oauth_client_fingerprint": record.oauth_client_fingerprint,
            "operation_digest": record.operation_digest,
            "scope_fingerprint": record.scope_fingerprint,
            "source_generation": record.source_generation,
            "source_fingerprint": record.source_fingerprint,
            "resulting_fingerprint": record.resulting_fingerprint,
            "subject_fingerprint": record.subject_fingerprint,
        }

    @staticmethod
    def _decode(payload: bytes) -> tuple[str, _PendingAuthorization]:
        try:
            parsed = json.loads(payload.decode("ascii"))
        except (UnicodeError, json.JSONDecodeError):
            raise _JournalFailure from None
        if (
            type(parsed) is not dict
            or set(parsed) != {"record", "state", "version"}
            or parsed.get("version") != 1
            or parsed.get("state") not in {"pending", "receipt"}
            or type(parsed.get("record")) is not dict
        ):
            raise _JournalFailure
        raw = parsed["record"]
        assert type(raw) is dict
        fields = {
            "account_fingerprint",
            "binding_fingerprint",
            "inventory_generation",
            "oauth_client_fingerprint",
            "operation_digest",
            "scope_fingerprint",
            "source_generation",
            "subject_fingerprint",
            "source_fingerprint",
            "resulting_fingerprint",
        }
        if set(raw) != fields:
            raise _JournalFailure
        source_generation = raw["source_generation"]
        inventory_generation = raw["inventory_generation"]
        if not (
            type(source_generation) is int
            and 1 <= source_generation <= _MAX_GENERATION
            and type(inventory_generation) is int
            and source_generation <= inventory_generation <= source_generation + 1
            and all(
                _is_fingerprint(raw[field])
                for field in fields - {"source_generation", "inventory_generation"}
            )
        ):
            raise _JournalFailure
        state = parsed["state"]
        assert type(state) is str
        return (
            state,
            _PendingAuthorization(
                operation_digest=raw["operation_digest"],
                binding_fingerprint=raw["binding_fingerprint"],
                account_fingerprint=raw["account_fingerprint"],
                subject_fingerprint=raw["subject_fingerprint"],
                oauth_client_fingerprint=raw["oauth_client_fingerprint"],
                scope_fingerprint=raw["scope_fingerprint"],
                source_generation=source_generation,
                inventory_generation=inventory_generation,
                source_fingerprint=raw["source_fingerprint"],
                resulting_fingerprint=raw["resulting_fingerprint"],
            ),
        )


class _StoreCompareAbort(Exception):
    __slots__ = ()

    def __repr__(self) -> str:
        return "_StoreCompareAbort()"


class _UnavailableAuthorizationPort:
    __slots__ = ()

    def authorize(self) -> object:
        _fail("inventory.readonly_control_unavailable")


class _UnavailableAuthorizationTokenPort:
    __slots__ = ()

    def store_authorization_refresh_token(self, **kwargs: object) -> object:
        del kwargs
        _fail("inventory.readonly_control_unavailable")


class _UnavailableScanPort:
    __slots__ = ()

    def scan_plan(self) -> object:
        _fail("inventory.readonly_control_unavailable")


def _production_document_state(document: dict[str, object]) -> _InventoryDocumentState:
    try:
        parsed = _inventory._document_from_bytes(
            yaml.safe_dump(document, sort_keys=False).encode("utf-8")
        )
        subjects = {account.ref: account.subject_id for account in parsed.accounts}
    except Exception:
        _fail("inventory.readonly_control_apply_failed")
    return _InventoryDocumentState(
        content_fingerprint=parsed.content_fingerprint,
        subjects_by_account_ref=MappingProxyType(subjects),
    )


def _production_plan_rehydrator(payload: bytes) -> object:
    from . import google_inventory_readonly_scan as scan

    return scan._rehydrate_sealed_plan_for_authority(payload)


class GoogleInventoryReadonlyControlService:
    """The single public, non-admin authority for read-only inventory control."""

    __slots__ = (
        "_authorization_journal",
        "_authorization_port",
        "_authorization_token_port",
        "_document_state_reader",
        "_journal",
        "_manager",
        "_operation_lock",
        "_plan_registry",
        "_plan_rehydrator",
        "_scan_component",
        "_scan_owner",
        "_scan_port",
        "_store",
        "_transaction",
        "_vault_components",
        "_subject_binding_verified",
        "_clock",
    )

    def __init__(self) -> None:
        """Compose the sole fixed production authority without caller input."""

        components: object | None = None
        try:
            store = _inventory_store.GoogleInventoryStore.from_systemd_state_directory()
            components = (
                _token_vault._new_the_hive_inventory_vault_production_components()
            )
            journal_directory = getattr(
                components, "_journal_directory_for_authority"
            )()
            if not isinstance(journal_directory, Path):
                _fail("inventory.readonly_control_unavailable")
            self._initialize(
                store=store,
                manager=None,
                authorization_port=_UnavailableAuthorizationPort(),
                authorization_token_port=_UnavailableAuthorizationTokenPort(),
                scan_port=None,
                scan_component=None,
                scan_owner=None,
                document_state_reader=_production_document_state,
                journal_directory=journal_directory,
                plan_rehydrator=_production_plan_rehydrator,
                clock=time.time,
            )
            self._vault_components = components
        except GoogleInventoryReadonlyControlError:
            self._clear_components_after_failed_construction(components)
            raise
        except (KeyboardInterrupt, SystemExit):
            self._clear_components_after_failed_construction(components)
            raise
        except Exception:
            self._clear_components_after_failed_construction(components)
            _fail("inventory.readonly_control_unavailable")

    @classmethod
    def _for_test_components(
        cls,
        *,
        store: object,
        manager: object,
        document_state_reader: Callable[[dict[str, object]], _InventoryDocumentState],
        authorization_port: object | None = None,
        authorization_token_port: object | None = None,
        scan_port: object | None = None,
        scan_component: object | None = None,
        scan_owner: object | None = None,
        journal_directory: Path,
        plan_rehydrator: Callable[[bytes], object] = _production_plan_rehydrator,
        clock: Callable[[], object],
    ) -> GoogleInventoryReadonlyControlService:
        service = cls.__new__(cls)
        service._initialize(
            store=store,
            manager=manager,
            authorization_port=(
                _UnavailableAuthorizationPort()
                if authorization_port is None
                else authorization_port
            ),
            authorization_token_port=(
                _UnavailableAuthorizationTokenPort()
                if authorization_token_port is None
                else authorization_token_port
            ),
            scan_port=_UnavailableScanPort() if scan_port is None else scan_port,
            scan_component=scan_component,
            scan_owner=scan_owner,
            document_state_reader=document_state_reader,
            journal_directory=journal_directory,
            plan_rehydrator=plan_rehydrator,
            clock=clock,
        )
        return service

    def _initialize(
        self,
        *,
        store: object,
        manager: object,
        authorization_port: object,
        authorization_token_port: object,
        scan_port: object | None,
        scan_component: object | None,
        scan_owner: object | None,
        document_state_reader: Callable[[dict[str, object]], _InventoryDocumentState],
        journal_directory: Path,
        plan_rehydrator: Callable[[bytes], object],
        clock: Callable[[], object],
    ) -> None:
        if not (
            callable(document_state_reader)
            and callable(plan_rehydrator)
            and callable(clock)
        ):
            _fail("inventory.readonly_control_unavailable")
        self._store = store
        self._manager = manager
        self._transaction = None
        self._vault_components = None
        self._authorization_port = authorization_port
        self._authorization_token_port = authorization_token_port
        self._scan_port = scan_port
        self._scan_component = scan_component
        self._scan_owner = scan_owner
        self._document_state_reader = document_state_reader
        self._plan_rehydrator = plan_rehydrator
        self._clock = clock
        self._operation_lock = threading.RLock()
        self._plan_registry = _PlanRegistry()
        self._subject_binding_verified = False
        try:
            self._journal = _OperationJournal(journal_directory)
            self._authorization_journal = _AuthorizationJournal(journal_directory)
        except _JournalFailure:
            _fail("inventory.readonly_control_unavailable")
        try:
            self._restore_sealed_plan_locked()
        except GoogleInventoryReadonlyControlError:
            _fail("inventory.readonly_control_unavailable")

    @staticmethod
    def _clear_components_after_failed_construction(components: object | None) -> None:
        if components is None:
            return
        try:
            clear = getattr(components, "clear")
            if callable(clear):
                clear()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "GoogleInventoryReadonlyControlService(<redacted>)"

    @contextmanager
    def _authority_transaction_locked(self) -> Iterator[object]:
        """Own fresh source, result reload and final byte attestation together."""

        if self._transaction is not None:
            _fail("inventory.readonly_control_unavailable")
        self._subject_binding_verified = False
        try:
            with _inventory_store._authority_transaction(self._store) as transaction:
                self._transaction = transaction
                self._manager = transaction.manager
                self._bind_production_ports_locked()
                yield transaction
                transaction.attest()
                self._manager = transaction.manager
        except GoogleInventoryReadonlyControlError:
            self._subject_binding_verified = False
            raise
        except BaseException as error:
            self._subject_binding_verified = False
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            _fail("inventory.readonly_control_unavailable")
        finally:
            self._transaction = None
            self._manager = None
            if self._vault_components is not None:
                self._authorization_port = _UnavailableAuthorizationPort()
                self._authorization_token_port = _UnavailableAuthorizationTokenPort()

    def _bind_production_ports_locked(self) -> None:
        """Bind private OAuth/Vault owners to this transaction's exact Manager."""

        components = self._vault_components
        if components is None:
            return
        transaction = self._transaction
        if transaction is None:
            _fail("inventory.readonly_control_unavailable")
        manager = transaction.manager
        self._authorization_token_port = (
            _token_vault._new_inventory_readonly_authorization_token_port(
                getattr(components, "_vault"), manager
            )
        )
        self._authorization_port = (
            _oauth_session._new_the_hive_inventory_readonly_authorization_port(
                vault_components=components, manager=manager
            )
        )

    def authorize(self) -> Mapping[str, str]:
        """Run only the constructor-owned inventory authorization adapter."""

        with self._operation_lock, self._authority_transaction_locked():
            if self._recover_authorization_receipt_locked():
                self._subject_binding_verified = True
                return MappingProxyType({"status": "authorized"})
            try:
                authorize = getattr(self._authorization_port, "authorize")
                if not callable(authorize):
                    _fail("inventory.readonly_control_unavailable")
                effect = authorize()
            except GoogleInventoryReadonlyControlError:
                raise
            except _oauth_session.GoogleOAuthSessionError as error:
                if error.code == "oauth.interactive_authorization_required":
                    _fail("oauth.interactive_authorization_required")
                _fail("inventory.readonly_control_unavailable")
            except Exception:
                _fail("inventory.readonly_control_unavailable")
            self._consume_authorization_effect_locked(effect)
            self._subject_binding_verified = True
            return MappingProxyType({"status": "authorized"})

    def _recover_authorization_receipt_locked(self) -> bool:
        """Recover only a durable record with its exact opaque vault receipt."""

        record = self._authorization_journal.record()
        if record is None:
            return False
        recovery_state = self._recover_authorization_state_locked(record)
        if recovery_state == "uncommitted":
            try:
                self._authorization_journal.discard(record)
            except _JournalFailure:
                _fail("inventory.readonly_control_recovery_failed")
            return False
        if recovery_state != "attested":
            _fail("inventory.readonly_control_recovery_failed")
        try:
            lookup = getattr(
                self._authorization_token_port,
                "lookup_authorization_refresh_receipt",
            )
            if not callable(lookup):
                _fail("inventory.readonly_control_unavailable")
            receipt = lookup(
                operation_digest=record.operation_digest,
                binding_fingerprint=record.binding_fingerprint,
            )
        except GoogleInventoryReadonlyControlError:
            raise
        except Exception:
            _fail("inventory.readonly_control_unavailable")
        if receipt is None:
            if self._authorization_journal._receipt is not None:
                _fail("inventory.readonly_control_recovery_failed")
            try:
                self._authorization_journal.discard(record)
            except _JournalFailure:
                _fail("inventory.readonly_control_recovery_failed")
            return False
        if not self._authorization_receipt_matches(record, receipt):
            _fail("inventory.readonly_control_recovery_failed")
        try:
            self._authorization_journal.mark_receipt(record)
        except _JournalFailure:
            _fail("inventory.readonly_control_recovery_failed")
        return True

    def _recover_authorization_state_locked(self, record: _PendingAuthorization) -> str:
        """Classify a pending authorization without retaining any identity bytes."""

        try:
            state = self._current_document_state()
            snapshot = self._snapshot()
            state_matches = [
                subject
                for account_ref, subject in state.subjects_by_account_ref.items()
                if _account_fingerprint(account_ref) == record.account_fingerprint
            ]
            if len(state_matches) != 1:
                return "invalid"
            document_subject = state_matches[0]
            snapshot_matches = [
                account
                for account in snapshot.accounts
                if _account_fingerprint(account.ref) == record.account_fingerprint
            ]
            if len(snapshot_matches) != 1 or not _is_fingerprint(
                getattr(snapshot, "content_fingerprint")
            ):
                return "invalid"
            snapshot_subject = getattr(snapshot_matches[0], "subject_id")
            if (
                record.inventory_generation == record.source_generation + 1
                and document_subject is None
                and getattr(snapshot, "generation") == record.source_generation
                and state.content_fingerprint
                == getattr(snapshot, "content_fingerprint")
                and state.content_fingerprint == record.source_fingerprint
                and snapshot_subject is None
            ):
                return "uncommitted"
            if _subject_fingerprint(document_subject) != record.subject_fingerprint:
                return "invalid"
            return (
                "attested"
                if self._authorization_record_matches_current(record, state, snapshot)
                else "invalid"
            )
        except GoogleInventoryReadonlyControlError:
            return "invalid"
        except Exception:
            return "invalid"

    def _consume_authorization_effect_locked(self, effect: object) -> None:
        refresh_token: bytearray | None = None
        try:
            consume = getattr(effect, "_consume_for_authority")
            if not callable(consume):
                _fail("inventory.readonly_control_unavailable")
            values = consume()
            if type(values) is not tuple or len(values) != 6:
                _fail("inventory.readonly_control_unavailable")
            (
                account_ref,
                subject_id,
                source_generation,
                oauth_client_fingerprint,
                scope_fingerprint,
                refresh_token,
            ) = values
            if not (
                _is_nonempty_text(account_ref, _MAX_REFERENCE_BYTES)
                and _is_nonempty_text(subject_id, _MAX_SUBJECT_BYTES)
                and type(source_generation) is int
                and 1 <= source_generation <= _MAX_GENERATION
                and _is_fingerprint(oauth_client_fingerprint)
                and _is_fingerprint(scope_fingerprint)
                and type(refresh_token) is bytearray
                and refresh_token
            ):
                _fail("inventory.readonly_control_unavailable")
            assert type(account_ref) is str
            assert type(subject_id) is str
            assert type(source_generation) is int
            assert type(oauth_client_fingerprint) is str
            assert type(scope_fingerprint) is str
            source_snapshot, source_account = self._require_authorization_source(
                account_ref, subject_id, source_generation
            )
            current = self._current_document_state()
            requires_subject_cas = self._require_authorization_document_source(
                current,
                source_snapshot,
                account_ref,
                subject_id,
                source_generation,
            )
            inventory_generation = (
                source_generation + 1 if requires_subject_cas else source_generation
            )
            if inventory_generation > _MAX_GENERATION:
                _fail("inventory.readonly_control_unavailable")
            login_email = getattr(source_account, "login_email", None)
            binding_fingerprint = _authorization_binding_fingerprint(
                account_ref=account_ref,
                subject_id=subject_id,
                login_email=login_email,
                oauth_client_fingerprint=oauth_client_fingerprint,
                scope_fingerprint=scope_fingerprint,
                inventory_generation=inventory_generation,
            )
            operation_digest = _authorization_operation_digest(
                account_ref,
                subject_id,
                source_generation,
                oauth_client_fingerprint,
                scope_fingerprint,
            )
            candidate, _ = self._current_document_for_authority()
            for account in candidate["google_accounts"]:
                if account["ref"] == account_ref:
                    account["subject_id"] = subject_id
            resulting_fingerprint = self._document_state_reader(
                candidate
            ).content_fingerprint
            pending = _PendingAuthorization(
                operation_digest=operation_digest,
                binding_fingerprint=binding_fingerprint,
                account_fingerprint=_account_fingerprint(account_ref),
                subject_fingerprint=_subject_fingerprint(subject_id),
                oauth_client_fingerprint=oauth_client_fingerprint,
                scope_fingerprint=scope_fingerprint,
                source_generation=source_generation,
                inventory_generation=inventory_generation,
                source_fingerprint=current.content_fingerprint,
                resulting_fingerprint=resulting_fingerprint,
            )
            try:
                self._authorization_journal.prepare(pending)
            except _JournalFailure:
                _fail("inventory.readonly_control_unavailable")
            if requires_subject_cas:
                self._subject_cas_locked(
                    account_ref,
                    subject_id,
                    source_snapshot,
                )
                self._reload_authorization_binding_locked(
                    account_ref,
                    subject_id,
                    source_generation,
                    inventory_generation,
                )
            else:
                self._reattest_authorization_binding_locked(
                    account_ref,
                    subject_id,
                    source_generation,
                )
            self._bind_production_ports_locked()
            store = getattr(
                self._authorization_token_port, "store_authorization_refresh_token"
            )
            if not callable(store):
                _fail("inventory.readonly_control_unavailable")
            receipt = store(
                operation_digest=operation_digest,
                account_ref=account_ref,
                subject_id=subject_id,
                oauth_client_fingerprint=oauth_client_fingerprint,
                inventory_generation=inventory_generation,
                expected_vault_generation=None,
                refresh_token=refresh_token,
            )
            refresh_token = None
            if not self._authorization_receipt_matches(pending, receipt):
                _fail("inventory.readonly_control_unavailable")
            try:
                self._authorization_journal.mark_receipt(pending)
            except _JournalFailure:
                _fail("inventory.readonly_control_unavailable")
        except GoogleInventoryReadonlyControlError:
            raise
        except Exception:
            _fail("inventory.readonly_control_unavailable")
        finally:
            if refresh_token is not None:
                refresh_token[:] = b"\x00" * len(refresh_token)

    def _require_authorization_source(
        self, account_ref: str, subject_id: str, generation: int
    ) -> tuple[object, object]:
        snapshot = self._snapshot()
        try:
            if getattr(snapshot, "generation") != generation or not _is_fingerprint(
                getattr(snapshot, "content_fingerprint")
            ):
                _fail("inventory.readonly_control_unavailable")
            matches = [
                account for account in snapshot.accounts if account.ref == account_ref
            ]
            if len(matches) != 1 or matches[0].subject_id not in {None, subject_id}:
                _fail("inventory.readonly_control_unavailable")
            return snapshot, matches[0]
        except GoogleInventoryReadonlyControlError:
            raise
        except Exception:
            _fail("inventory.readonly_control_unavailable")

    def _require_authorization_document_source(
        self,
        state: _InventoryDocumentState,
        snapshot: object,
        account_ref: str,
        subject_id: str,
        generation: int,
    ) -> bool:
        if (
            getattr(snapshot, "generation", None) != generation
            or state.content_fingerprint
            != getattr(snapshot, "content_fingerprint", None)
            or account_ref not in state.subjects_by_account_ref
        ):
            _fail("inventory.readonly_control_unavailable")
        existing_subject = state.subjects_by_account_ref[account_ref]
        if existing_subject not in {None, subject_id}:
            _fail("inventory.readonly_control_unavailable")
        return existing_subject is None

    def _subject_cas_locked(
        self,
        account_ref: str,
        subject_id: str,
        source_snapshot: object,
    ) -> None:
        try:
            source_generation = getattr(source_snapshot, "generation")
            source_fingerprint = getattr(source_snapshot, "content_fingerprint")
            source_accounts = getattr(source_snapshot, "accounts")
            source_matches = [
                account for account in source_accounts if account.ref == account_ref
            ]
            if not (
                type(source_generation) is int
                and 1 <= source_generation <= _MAX_GENERATION
                and _is_fingerprint(source_fingerprint)
                and len(source_matches) == 1
                and source_matches[0].subject_id is None
            ):
                _fail("inventory.readonly_control_unavailable")
            assert type(source_fingerprint) is str
        except GoogleInventoryReadonlyControlError:
            raise
        except Exception:
            _fail("inventory.readonly_control_unavailable")

        try:
            transaction = self._transaction
            if transaction is None:
                _fail("inventory.readonly_control_unavailable")
            document = transaction.document
            state = self._document_state_reader(document)
            fresh_snapshot = self._snapshot()
            fresh_matches = [
                account
                for account in fresh_snapshot.accounts
                if account.ref == account_ref
            ]
            if not (
                state.content_fingerprint == source_fingerprint
                and getattr(fresh_snapshot, "generation") == source_generation
                and getattr(fresh_snapshot, "content_fingerprint") == source_fingerprint
                and len(fresh_matches) == 1
                and fresh_matches[0].subject_id is None
            ):
                _fail("inventory.readonly_control_unavailable")
            accounts = document.get("google_accounts")
            if type(accounts) is not list:
                _fail("inventory.readonly_control_unavailable")
            matches = [
                account
                for account in accounts
                if type(account) is dict and account.get("ref") == account_ref
            ]
            if len(matches) != 1 or matches[0].get("subject_id") is not None:
                _fail("inventory.readonly_control_unavailable")
            matches[0]["subject_id"] = subject_id
            transaction.commit(
                document,
                expected=transaction.binding,
                expected_content_fingerprint=self._document_state_reader(
                    document
                ).content_fingerprint,
            )
        except GoogleInventoryReadonlyControlError:
            raise
        except Exception:
            _fail("inventory.readonly_control_unavailable")

    def _reattest_authorization_binding_locked(
        self,
        account_ref: str,
        subject_id: str,
        generation: int,
    ) -> None:
        if self._transaction is None:
            _fail("inventory.readonly_control_unavailable")
        self._transaction.attest()
        reloaded = self._snapshot()
        fingerprint = getattr(reloaded, "content_fingerprint", None)
        if not (
            _is_fingerprint(fingerprint)
            and self._snapshot_matches(
                reloaded,
                account_fingerprint=_account_fingerprint(account_ref),
                subject_fingerprint=_subject_fingerprint(subject_id),
                generation=generation,
                fingerprint=fingerprint,
            )
            and self._current_document_state().content_fingerprint == fingerprint
        ):
            _fail("inventory.readonly_control_unavailable")

    def _reload_authorization_binding_locked(
        self,
        account_ref: str,
        subject_id: str,
        generation: int,
        inventory_generation: int,
    ) -> None:
        try:
            if self._transaction is None:
                _fail("inventory.readonly_control_unavailable")
            if inventory_generation != generation + 1:
                _fail("inventory.readonly_control_unavailable")
            self._transaction.attest()
        except GoogleInventoryReadonlyControlError:
            raise
        except Exception:
            _fail("inventory.readonly_control_unavailable")
        reloaded = self._snapshot()
        fingerprint = getattr(reloaded, "content_fingerprint", None)
        if not (
            _is_fingerprint(fingerprint)
            and self._snapshot_matches(
                reloaded,
                account_fingerprint=_account_fingerprint(account_ref),
                subject_fingerprint=_subject_fingerprint(subject_id),
                generation=inventory_generation,
                fingerprint=fingerprint,
            )
            and self._current_document_state().content_fingerprint == fingerprint
        ):
            _fail("inventory.readonly_control_unavailable")

    def _authorization_record_matches_current(
        self,
        record: _PendingAuthorization,
        state: _InventoryDocumentState | None = None,
        snapshot: object | None = None,
    ) -> bool:
        try:
            if state is None:
                state = self._current_document_state()
            state_matches = [
                subject
                for account_ref, subject in state.subjects_by_account_ref.items()
                if _account_fingerprint(account_ref) == record.account_fingerprint
            ]
            if snapshot is None:
                snapshot = self._snapshot()
            snapshot_matches = [
                account
                for account in snapshot.accounts
                if _account_fingerprint(account.ref) == record.account_fingerprint
            ]
            return (
                len(state_matches) == 1
                and _subject_fingerprint(state_matches[0]) == record.subject_fingerprint
                and len(snapshot_matches) == 1
                and _subject_fingerprint(snapshot_matches[0].subject_id)
                == record.subject_fingerprint
                and getattr(snapshot, "generation") == record.inventory_generation
                and _is_fingerprint(getattr(snapshot, "content_fingerprint"))
                and state.content_fingerprint
                == getattr(snapshot, "content_fingerprint")
                and state.content_fingerprint == record.resulting_fingerprint
            )
        except GoogleInventoryReadonlyControlError:
            return False
        except Exception:
            return False

    @staticmethod
    def _authorization_receipt_matches(
        record: _PendingAuthorization, receipt: object
    ) -> bool:
        try:
            return (
                getattr(receipt, "_binding_fingerprint") == record.binding_fingerprint
                and type(getattr(receipt, "_vault_generation")) is int
                and 1 <= getattr(receipt, "_vault_generation") <= _MAX_GENERATION
            )
        except Exception:
            return False

    def subject_status(self) -> Mapping[str, str]:
        """Return only whether this authority has a verified private binding."""

        with self._operation_lock, self._authority_transaction_locked():
            if self._authorization_journal._receipt is not None:
                self._fresh_scan_authorization_binding_locked()
            return MappingProxyType(
                {
                    "status": (
                        "bound" if self._subject_binding_verified else "unavailable"
                    )
                }
            )

    def scan_plan(self) -> Mapping[str, object]:
        """Create one private scan plan through the fixed read-only adapter."""

        with self._operation_lock, self._authority_transaction_locked():
            try:
                (
                    canonical_document,
                    account_ref,
                    subject_id,
                    inventory_generation,
                    content_fingerprint,
                    oauth_client_fingerprint,
                    scope_fingerprint,
                ) = self._fresh_scan_authorization_binding_locked()
                scan_component = self._scan_component
                scan_owner = self._scan_owner
                if self._vault_components is not None:
                    broker = _token_vault._new_inventory_readonly_scan_broker(
                        getattr(self._vault_components, "_vault"),
                        self._transaction.manager,
                    )
                    discovery = _scan._FixedGoogleInventoryReadonlyDiscoveryV1(broker)
                    scan_component, scan_owner = (
                        _scan._create_scan_component_for_control(
                            broker=broker, discovery=discovery
                        )
                    )
                if scan_component is not None and scan_owner is not None:
                    new_binding = getattr(
                        scan_component, "_new_verified_binding_for_control"
                    )
                    scan_for_control = getattr(scan_component, "_scan_for_control")
                    if not callable(new_binding) or not callable(scan_for_control):
                        _fail("inventory.readonly_control_unavailable")
                    record = self._authorization_journal._receipt
                    if record is None:
                        _fail("inventory.readonly_control_unavailable")
                    verified_binding = new_binding(
                        scan_owner,
                        account_ref=account_ref,
                        subject_id=subject_id,
                        inventory_generation=inventory_generation,
                        content_fingerprint=content_fingerprint,
                        oauth_client_fingerprint=oauth_client_fingerprint,
                        scope_fingerprint=scope_fingerprint,
                        receipt_operation_digest=record.operation_digest,
                        receipt_binding_fingerprint=record.binding_fingerprint,
                    )
                    result = scan_for_control(
                        scan_owner, verified_binding, canonical_document
                    )
                else:
                    scan = getattr(self._scan_port, "scan_plan")
                    if not callable(scan):
                        _fail("inventory.readonly_control_unavailable")
                    result = scan()
                plan = getattr(result, "_plan")
                projection = getattr(result, "_public_projection")
                binding = self._binding_for_plan(plan)
                public_projection = self._public_projection(projection)
            except GoogleInventoryReadonlyControlError:
                raise
            except Exception:
                _fail("inventory.readonly_control_unavailable")
            reference = self._plan_registry.register(plan, binding)
            self._persist_sealed_plan_locked(reference, plan)
            return MappingProxyType({**public_projection, "plan_reference": reference})

    def _fresh_scan_authorization_binding_locked(
        self,
    ) -> tuple[dict[str, object], str, str, int, str, str, str]:
        """Reattest one durable authorize receipt to current local identity state."""

        record = self._authorization_journal._receipt
        if record is None or self._authorization_journal._pending is not None:
            _fail("inventory.readonly_control_unavailable")
        try:
            lookup = getattr(
                self._authorization_token_port,
                "lookup_authorization_refresh_receipt",
            )
            if not callable(lookup):
                _fail("inventory.readonly_control_unavailable")
            receipt = lookup(
                operation_digest=record.operation_digest,
                binding_fingerprint=record.binding_fingerprint,
            )
            if not self._authorization_receipt_matches(record, receipt):
                _fail("inventory.readonly_control_unavailable")
            canonical_document, state = self._current_document_for_authority()
            snapshot = self._snapshot()
            snapshot_fingerprint = getattr(snapshot, "content_fingerprint", None)
            snapshot_generation = getattr(snapshot, "generation", None)
            if not (
                type(snapshot_generation) is int
                and snapshot_generation == record.inventory_generation
                and _is_fingerprint(snapshot_fingerprint)
                and state.content_fingerprint == snapshot_fingerprint
                and state.content_fingerprint == record.resulting_fingerprint
            ):
                _fail("inventory.readonly_control_unavailable")
            account_matches = [
                account
                for account in snapshot.accounts
                if _account_fingerprint(getattr(account, "ref", None))
                == record.account_fingerprint
                and _subject_fingerprint(getattr(account, "subject_id", None))
                == record.subject_fingerprint
            ]
            document_matches = [
                (account_ref, subject_id)
                for account_ref, subject_id in state.subjects_by_account_ref.items()
                if _account_fingerprint(account_ref) == record.account_fingerprint
                and _subject_fingerprint(subject_id) == record.subject_fingerprint
            ]
            if len(account_matches) != 1 or len(document_matches) != 1:
                _fail("inventory.readonly_control_unavailable")
            account_ref, subject_id = document_matches[0]
            snapshot_account = account_matches[0]
            if not (
                _is_nonempty_text(account_ref, _MAX_REFERENCE_BYTES)
                and _is_nonempty_text(subject_id, _MAX_SUBJECT_BYTES)
                and getattr(snapshot_account, "ref", None) == account_ref
                and getattr(snapshot_account, "subject_id", None) == subject_id
            ):
                _fail("inventory.readonly_control_unavailable")
            self._subject_binding_verified = True
            return (
                canonical_document,
                account_ref,
                subject_id,
                snapshot_generation,
                snapshot_fingerprint,
                record.oauth_client_fingerprint,
                record.scope_fingerprint,
            )
        except GoogleInventoryReadonlyControlError:
            raise
        except Exception:
            _fail("inventory.readonly_control_unavailable")

    def _register_scan_plan_for_internal_use(self, plan: object) -> str:
        """Private scan-adapter handoff into the authority-owned registry."""

        with self._operation_lock:
            reference = self._plan_registry.register(plan, self._binding_for_plan(plan))
            self._persist_sealed_plan_locked(reference, plan)
            return reference

    def _persist_sealed_plan_locked(self, reference: str, plan: object) -> None:
        try:
            exporter = getattr(plan, "_export_sealed_for_authority")
            if not callable(exporter):
                _fail("inventory.readonly_control_plan_invalid")
            payload = exporter()
            if (
                type(payload) is not bytes
                or not payload
                or len(payload) > _JOURNAL_MAX_BYTES
            ):
                _fail("inventory.readonly_control_plan_invalid")
            binding = self._binding_for_plan(plan, require_verified_digest=True)
            self._journal.store_plan(
                _SealedPlanRecord(
                    reference=reference,
                    plan_digest=binding.plan_digest,
                    payload=payload,
                )
            )
        except GoogleInventoryReadonlyControlError:
            raise
        except _JournalFailure:
            _fail("inventory.readonly_control_unavailable")
        except Exception:
            _fail("inventory.readonly_control_plan_invalid")

    def _restore_sealed_plan_locked(self) -> None:
        record = self._journal.sealed_plan()
        if record is None:
            return
        try:
            plan = self._plan_rehydrator(record.payload)
            binding = self._binding_for_plan(plan, require_verified_digest=True)
            if binding.plan_digest != record.plan_digest:
                _fail("inventory.readonly_control_plan_invalid")
            self._plan_registry.restore(
                record.reference,
                plan,
                binding,
                consumed=self._journal.prepared() is not None
                or self._journal.receipt_for_reference(record.reference),
            )
        except GoogleInventoryReadonlyControlError:
            raise
        except Exception:
            _fail("inventory.readonly_control_plan_invalid")

    def apply(self, plan_reference: object) -> Mapping[str, str]:
        """Apply one bound local inventory plan without provider access."""

        with self._operation_lock, self._authority_transaction_locked():
            if not _is_nonempty_text(plan_reference, _MAX_REFERENCE_BYTES):
                _fail("inventory.readonly_control_request_invalid")
            assert type(plan_reference) is str
            pending = self._journal.prepared()
            if pending is not None:
                self._recover_prepared_locked(pending)
            reference, entry = self._plan_registry.resolve(plan_reference)
            if self._journal.receipt_for(reference, entry.binding):
                self._require_registered_plan_current(
                    entry, "inventory.readonly_control_recovery_failed"
                )
                binding = entry.binding
                if not self._snapshot_matches(
                    self._snapshot(),
                    account_fingerprint=_account_fingerprint(binding.account_ref),
                    subject_fingerprint=_subject_fingerprint(binding.subject_id),
                    generation=binding.inventory_generation + 1,
                    fingerprint=binding.resulting_content_fingerprint,
                ):
                    _fail("inventory.readonly_control_recovery_failed")
                self._subject_binding_verified = True
                return MappingProxyType({"status": "applied"})
            if entry.consumed:
                _fail("inventory.readonly_control_plan_consumed")
            entry = self._plan_registry.consume(reference, entry)
            return self._apply_new_locked(reference, entry)

    def _apply_new_locked(
        self, reference: str, entry: _PlanRegistryEntry
    ) -> Mapping[str, str]:
        binding = entry.binding
        self._require_registered_plan_current(
            entry, "inventory.readonly_control_plan_invalid"
        )
        self._require_unexpired(binding)
        self._require_snapshot_source(binding)
        self._require_document_source(self._current_document_state(), binding)
        operation = _CommittedOperation(
            plan_reference=reference,
            plan_id=binding.plan_id,
            plan_digest=binding.plan_digest,
            account_fingerprint=_account_fingerprint(binding.account_ref),
            subject_fingerprint=_subject_fingerprint(binding.subject_id),
            source_generation=binding.inventory_generation,
            source_fingerprint=binding.content_fingerprint,
            oauth_client_fingerprint=binding.oauth_client_fingerprint,
            scope_fingerprint=binding.scope_fingerprint,
            resulting_fingerprint=binding.resulting_content_fingerprint,
        )
        try:
            self._journal.prepare(operation)
        except _JournalFailure:
            _fail("inventory.readonly_control_unavailable")
        try:
            transaction = self._transaction
            if transaction is None:
                _fail("inventory.readonly_control_unavailable")
            document = transaction.document
            self._require_document_source(
                self._document_state_reader(document), binding
            )
            transform = getattr(entry.plan, "_transform_for_authority")
            if not callable(transform):
                _fail("inventory.readonly_control_plan_invalid")
            transform(document)
            result = self._document_state_reader(document)
            if result.content_fingerprint != binding.resulting_content_fingerprint:
                _fail("inventory.readonly_control_plan_invalid")
            self._require_document_subject(result, binding)
            transaction.commit(
                document,
                expected=transaction.binding,
                expected_content_fingerprint=binding.resulting_content_fingerprint,
            )
        except GoogleInventoryReadonlyControlError:
            raise
        except Exception:
            _fail("inventory.readonly_control_apply_failed")

        self._recover_prepared_locked(operation)
        return MappingProxyType({"status": "applied"})

    def _recover_prepared_locked(self, operation: _CommittedOperation) -> None:
        entry = self._plan_registry.known(operation.plan_reference)
        if entry is not None:
            if not entry.consumed:
                _fail("inventory.readonly_control_recovery_failed")
            self._require_registered_plan_current(
                entry, "inventory.readonly_control_recovery_failed"
            )
            if not self._operation_matches_binding(operation, entry.binding):
                _fail("inventory.readonly_control_recovery_failed")
        state = self._current_document_state()
        if not self._state_matches_operation(state, operation):
            _fail("inventory.readonly_control_recovery_failed")
        snapshot = self._snapshot()
        if (
            self._snapshot_matches(
                snapshot,
                account_fingerprint=operation.account_fingerprint,
                subject_fingerprint=operation.subject_fingerprint,
                generation=operation.source_generation,
                fingerprint=operation.source_fingerprint,
            )
            and state.content_fingerprint == operation.source_fingerprint
        ):
            try:
                self._journal.discard_prepared(operation)
            except _JournalFailure:
                _fail("inventory.readonly_control_recovery_failed")
            return
        if state.content_fingerprint != operation.resulting_fingerprint:
            _fail("inventory.readonly_control_recovery_failed")
        if self._snapshot_matches(
            snapshot,
            account_fingerprint=operation.account_fingerprint,
            subject_fingerprint=operation.subject_fingerprint,
            generation=operation.source_generation + 1,
            fingerprint=operation.resulting_fingerprint,
        ):
            self._mark_reloaded(operation)
            return
        _fail("inventory.readonly_control_recovery_failed")

    def _mark_reloaded(self, operation: _CommittedOperation) -> None:
        try:
            self._journal.mark_reloaded(operation)
        except _JournalFailure:
            _fail("inventory.readonly_control_recovery_failed")
        self._subject_binding_verified = True

    def _current_document_state(self) -> _InventoryDocumentState:
        return self._current_document_for_authority()[1]

    def _current_document_for_authority(
        self,
    ) -> tuple[dict[str, object], _InventoryDocumentState]:
        try:
            if self._transaction is None:
                _fail("inventory.readonly_control_unavailable")
            reader = getattr(self._store, "_read")
            if not callable(reader):
                _fail("inventory.readonly_control_recovery_failed")
            result = reader()
            if (
                type(result) is not tuple
                or len(result) != 2
                or type(result[1]) is not dict
            ):
                _fail("inventory.readonly_control_recovery_failed")
            return result[1], self._document_state_reader(result[1])
        except GoogleInventoryReadonlyControlError:
            raise
        except Exception:
            _fail("inventory.readonly_control_recovery_failed")

    @staticmethod
    def _state_matches_operation(
        state: _InventoryDocumentState, operation: _CommittedOperation
    ) -> bool:
        try:
            matches = [
                subject
                for account_ref, subject in state.subjects_by_account_ref.items()
                if _account_fingerprint(account_ref) == operation.account_fingerprint
            ]
            return (
                len(matches) == 1
                and _subject_fingerprint(matches[0]) == operation.subject_fingerprint
            )
        except Exception:
            return False

    @staticmethod
    def _operation_matches_binding(
        operation: _CommittedOperation, binding: _PlanBinding
    ) -> bool:
        return (
            operation.plan_id == binding.plan_id
            and operation.plan_digest == binding.plan_digest
            and operation.account_fingerprint
            == _account_fingerprint(binding.account_ref)
            and operation.subject_fingerprint
            == _subject_fingerprint(binding.subject_id)
            and operation.source_generation == binding.inventory_generation
            and operation.source_fingerprint == binding.content_fingerprint
            and operation.oauth_client_fingerprint == binding.oauth_client_fingerprint
            and operation.scope_fingerprint == binding.scope_fingerprint
            and operation.resulting_fingerprint == binding.resulting_content_fingerprint
        )

    def _require_registered_plan_current(
        self, entry: _PlanRegistryEntry, code: str
    ) -> None:
        """Require the still-private immutable plan to match its registry digest."""

        try:
            current = self._binding_for_plan(entry.plan, require_verified_digest=True)
        except GoogleInventoryReadonlyControlError:
            _fail(code)
        if current != entry.binding:
            _fail(code)

    def _binding_for_plan(
        self, plan: object, *, require_verified_digest: bool = False
    ) -> _PlanBinding:
        try:
            reader = getattr(
                plan,
                (
                    "_verify_for_authority"
                    if require_verified_digest
                    else "_binding_for_authority"
                ),
            )
            value = reader()
        except Exception:
            _fail("inventory.readonly_control_plan_invalid")
        if not isinstance(value, Mapping) or set(value) != _BINDING_FIELDS:
            _fail("inventory.readonly_control_plan_invalid")
        account_ref = value["account_ref"]
        subject_id = value["subject_id"]
        generation = value["inventory_generation"]
        plan_id = value["plan_id"]
        if not (
            _is_nonempty_text(account_ref, _MAX_REFERENCE_BYTES)
            and _is_nonempty_text(subject_id, _MAX_SUBJECT_BYTES)
            and type(generation) is int
            and 1 <= generation <= _MAX_GENERATION
            and _is_nonempty_text(plan_id, _MAX_PLAN_ID_BYTES)
            and all(
                _is_fingerprint(value[field])
                for field in (
                    "content_fingerprint",
                    "oauth_client_fingerprint",
                    "scope_fingerprint",
                    "plan_digest",
                    "resulting_content_fingerprint",
                )
            )
            and _is_timestamp(value["created_at"])
            and _is_timestamp(value["expires_at"])
            and float(value["created_at"]) <= float(value["expires_at"])
        ):
            _fail("inventory.readonly_control_plan_invalid")
        assert type(account_ref) is str
        assert type(subject_id) is str
        assert type(generation) is int
        assert type(plan_id) is str
        return _PlanBinding(
            account_ref=account_ref,
            subject_id=subject_id,
            inventory_generation=generation,
            content_fingerprint=value["content_fingerprint"],
            oauth_client_fingerprint=value["oauth_client_fingerprint"],
            scope_fingerprint=value["scope_fingerprint"],
            plan_id=plan_id,
            plan_digest=value["plan_digest"],
            resulting_content_fingerprint=value["resulting_content_fingerprint"],
            created_at=float(value["created_at"]),
            expires_at=float(value["expires_at"]),
        )

    def _require_unexpired(self, binding: _PlanBinding) -> None:
        try:
            now = float(self._clock())
        except (OverflowError, TypeError, ValueError):
            _fail("inventory.readonly_control_unavailable")
        if not math.isfinite(now):
            _fail("inventory.readonly_control_unavailable")
        if now > binding.expires_at:
            _fail("inventory.readonly_control_plan_expired")

    def _snapshot(self) -> object:
        try:
            if self._transaction is None:
                _fail("inventory.readonly_control_unavailable")
            reader = getattr(self._transaction.manager, "_snapshot_for_internal_use")
            if not callable(reader):
                _fail("inventory.readonly_control_unavailable")
            return reader()
        except GoogleInventoryReadonlyControlError:
            raise
        except Exception:
            _fail("inventory.readonly_control_unavailable")

    def _require_snapshot_source(self, binding: _PlanBinding) -> None:
        if not self._snapshot_matches(
            self._snapshot(),
            account_fingerprint=_account_fingerprint(binding.account_ref),
            subject_fingerprint=_subject_fingerprint(binding.subject_id),
            generation=binding.inventory_generation,
            fingerprint=binding.content_fingerprint,
        ):
            _fail("inventory.readonly_control_plan_stale")

    @staticmethod
    def _snapshot_matches(
        snapshot: object,
        *,
        account_fingerprint: str,
        subject_fingerprint: str,
        generation: int,
        fingerprint: str,
    ) -> bool:
        try:
            if (
                getattr(snapshot, "generation") != generation
                or getattr(snapshot, "content_fingerprint") != fingerprint
            ):
                return False
            accounts = getattr(snapshot, "accounts")
            matches = [
                account
                for account in accounts
                if _account_fingerprint(account.ref) == account_fingerprint
            ]
            return (
                len(matches) == 1
                and _subject_fingerprint(matches[0].subject_id) == subject_fingerprint
            )
        except Exception:
            return False

    @staticmethod
    def _require_document_source(
        state: _InventoryDocumentState, binding: _PlanBinding
    ) -> None:
        if state.content_fingerprint != binding.content_fingerprint:
            _fail("inventory.readonly_control_plan_stale")
        GoogleInventoryReadonlyControlService._require_document_subject(state, binding)

    @staticmethod
    def _require_document_subject(
        state: _InventoryDocumentState, binding: _PlanBinding
    ) -> None:
        try:
            subject = state.subjects_by_account_ref[binding.account_ref]
        except (KeyError, TypeError):
            _fail("inventory.readonly_control_plan_stale")
        if type(subject) is not str or subject != binding.subject_id:
            _fail("inventory.readonly_control_plan_stale")

    @staticmethod
    def _public_projection(value: object) -> dict[str, object]:
        if not isinstance(value, Mapping) or set(value) != _PROJECTION_FIELDS:
            _fail("inventory.readonly_control_unavailable")
        if value.get("status") != "planned":
            _fail("inventory.readonly_control_unavailable")
        result: dict[str, object] = {"status": "planned"}
        for projection_field in (
            "account_count",
            "project_count",
            "billing_account_count",
            "service_count",
            "key_count",
        ):
            count = value.get(projection_field)
            if type(count) is not int or count < 0:
                _fail("inventory.readonly_control_unavailable")
            result[projection_field] = count
        changes = value.get("changes")
        if not isinstance(changes, Mapping) or len(changes) > 32:
            _fail("inventory.readonly_control_unavailable")
        safe_changes: dict[str, int] = {}
        for kind, count in changes.items():
            if kind not in _PUBLIC_CHANGE_KINDS or type(count) is not int or count < 0:
                _fail("inventory.readonly_control_unavailable")
            assert type(kind) is str
            safe_changes[kind] = count
        result["changes"] = MappingProxyType(safe_changes)
        return result


def _subject_fingerprint(subject: object) -> str:
    if type(subject) is not str:
        return "sha256:" + "0" * 64
    return "sha256:" + sha256(subject.encode("utf-8")).hexdigest()


def _account_fingerprint(account_ref: object) -> str:
    if type(account_ref) is not str:
        return "sha256:" + "0" * 64
    return "sha256:" + sha256(account_ref.encode("utf-8")).hexdigest()


def _authorization_binding_fingerprint(
    *,
    account_ref: object,
    subject_id: object,
    login_email: object,
    oauth_client_fingerprint: object,
    scope_fingerprint: object,
    inventory_generation: object,
) -> str:
    """Reuse GA-I2b's exact, irreversible authorization-binding calculation."""

    if not (
        _is_nonempty_text(account_ref, _MAX_REFERENCE_BYTES)
        and _is_nonempty_text(subject_id, _MAX_SUBJECT_BYTES)
        and _is_nonempty_text(login_email, _MAX_SUBJECT_BYTES)
        and _is_fingerprint(oauth_client_fingerprint)
        and _is_fingerprint(scope_fingerprint)
        and type(inventory_generation) is int
        and 1 <= inventory_generation <= _MAX_GENERATION
    ):
        _fail("inventory.readonly_control_unavailable")
    assert type(account_ref) is str
    assert type(subject_id) is str
    assert type(login_email) is str
    assert type(oauth_client_fingerprint) is str
    assert type(scope_fingerprint) is str
    assert type(inventory_generation) is int
    try:
        return _vault_authorization_binding_fingerprint(
            account_ref=account_ref,
            subject_fingerprint=_subject_fingerprint(subject_id),
            login_fingerprint="sha256:"
            + sha256(login_email.encode("utf-8")).hexdigest(),
            oauth_client_fingerprint=oauth_client_fingerprint,
            profile_id=_INVENTORY_READONLY_PROFILE_ID,
            scope_fingerprint=scope_fingerprint,
            inventory_generation=inventory_generation,
        )
    except Exception:
        _fail("inventory.readonly_control_unavailable")


def _authorization_operation_digest(
    account_ref: str,
    subject_id: str,
    generation: int,
    oauth_client_fingerprint: str,
    scope_fingerprint: str,
) -> str:
    return (
        "sha256:"
        + sha256(
            (
                "the-hive.google.inventory.authorize\0"
                + _account_fingerprint(account_ref)
                + "\0"
                + _subject_fingerprint(subject_id)
                + "\0"
                + str(generation)
                + "\0"
                + oauth_client_fingerprint
                + "\0"
                + scope_fingerprint
            ).encode("utf-8")
        ).hexdigest()
    )
