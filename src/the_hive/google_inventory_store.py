"""Atomic private YAML updates for Google account inventory."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import copy
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import time
from typing import Callable, Iterator

import yaml

from . import google_account_inventory as _inventory
from .google_account_inventory_manager import GoogleAccountInventoryManager


class GoogleInventoryStoreError(Exception):
    """Code-only private store failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"GoogleInventoryStoreError({self.code!r})"


@dataclass(frozen=True, slots=True)
class GoogleInventoryStoreReceipt:
    schema_version: int
    authority_generation: int
    account_count: int
    project_count: int
    backup_created: bool


def _raise(code: str) -> None:
    raise GoogleInventoryStoreError(code) from None


def _normalize(value: object) -> object:
    if isinstance(value, _inventory._YamlIntegerLiteral):
        return int(value.value)
    if type(value) is dict:
        return {key: _normalize(item) for key, item in value.items()}
    if type(value) is list:
        return [_normalize(item) for item in value]
    return value


class GoogleInventoryStore:
    __slots__ = ("_path",)

    def __init__(self) -> None:
        self._path = _inventory.DEFAULT_GOOGLE_ACCOUNT_INVENTORY_PATH

    @classmethod
    def from_systemd_state_directory(cls) -> GoogleInventoryStore:
        store = cls.__new__(cls)
        try:
            store._path = _inventory.systemd_google_account_inventory_path()
        except _inventory.GoogleAccountInventoryError:
            _raise("inventory.store_unavailable")
        return store

    @classmethod
    def _for_test_path(cls, path: Path) -> GoogleInventoryStore:
        store = cls.__new__(cls)
        store._path = path
        return store

    def _read(self) -> tuple[bytes, dict[str, object]]:
        raw = _read_source_bytes(self)
        try:
            _inventory._document_from_bytes(raw)
            parsed = _inventory._load_strict_yaml(raw.decode("utf-8"))
            normalized = _normalize(parsed)
            if type(normalized) is not dict:
                _raise("inventory.store_schema_invalid")
            return raw, normalized
        except GoogleInventoryStoreError:
            raise
        except Exception:
            _raise("inventory.store_schema_invalid")

    def redacted_summary(self) -> dict[str, int]:
        _, document = self._read()
        accounts = document.get("google_accounts")
        if type(accounts) is not list:
            _raise("inventory.store_schema_invalid")
        return {
            "schema_version": int(document.get("schema_version", 0)),
            "account_count": len(accounts),
            "project_count": sum(
                len(account.get("projects", []))
                for account in accounts
                if type(account) is dict
            ),
        }

    def migrate_to_v2(self) -> GoogleInventoryStoreReceipt:
        _raise("inventory.store_migration_unavailable")

    def atomic_update(
        self, transform: Callable[[dict[str, object]], None]
    ) -> GoogleInventoryStoreReceipt:
        with _authority_transaction(self) as transaction:
            candidate = transaction.document
            try:
                transform(candidate)
                validated = _inventory._document_from_bytes(
                    yaml.safe_dump(candidate, sort_keys=False).encode("utf-8")
                )
            except Exception:
                _raise("inventory.store_transform_failed")
            return transaction.commit(
                candidate,
                expected=transaction.binding,
                expected_content_fingerprint=validated.content_fingerprint,
            )

    def _replace_locked(self, original: bytes, payload: bytes, parent_fd: int) -> None:
        path = self._path
        backup_fd: int | None = None
        temporary_fd: int | None = None
        temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{time.time_ns()}"
        backup = path.parent / f"{path.name}.backup-{time.time_ns()}"
        replaced = False
        try:
            _assert_locked_parent(self, parent_fd)
            if _read_source_bytes(self) != original:
                _raise("inventory.store_source_conflict")
            backup_fd = os.open(
                backup.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            self._write_all(backup_fd, original)
            os.fsync(backup_fd)
            os.close(backup_fd)
            backup_fd = None
            temporary_fd = os.open(
                temporary.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            self._write_all(temporary_fd, payload)
            os.fchmod(temporary_fd, 0o600)
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None
            _assert_locked_parent(self, parent_fd)
            if _read_source_bytes(self) != original:
                _raise("inventory.store_source_conflict")
            os.replace(
                temporary.name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd
            )
            replaced = True
            os.fsync(parent_fd)
        except OSError:
            _raise(
                "inventory.store_durability_failed"
                if replaced
                else "inventory.store_write_failed"
            )
        finally:
            for descriptor in (temporary_fd, backup_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            if not replaced:
                try:
                    os.unlink(temporary.name, dir_fd=parent_fd)
                except OSError:
                    pass

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]


def _read_source_bytes(store: GoogleInventoryStore) -> bytes:
    try:
        return _inventory._read_private_inventory_bytes(store._path)
    except _inventory.GoogleAccountInventoryError as error:
        if error.code == "credential.inventory_permissions":
            _raise("inventory.store_permissions")
        _raise("inventory.store_unavailable")


def _assert_locked_parent(store: GoogleInventoryStore, descriptor: int) -> None:
    opened = os.fstat(descriptor)
    current = os.lstat(store._path.parent)
    if not _inventory._safe_private_parent(current) or (
        opened.st_dev,
        opened.st_ino,
    ) != (current.st_dev, current.st_ino):
        _raise("inventory.store_source_conflict")


@contextmanager
def _locked_inventory_parent(store: GoogleInventoryStore) -> Iterator[int]:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            store._path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        opened = os.fstat(descriptor)
        current = os.lstat(store._path.parent)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or bool(stat.S_IMODE(opened.st_mode) & 0o022)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            _raise("inventory.store_permissions")
        yield descriptor
    except OSError:
        _raise("inventory.store_unavailable")
    finally:
        if descriptor is not None:
            os.close(descriptor)


class _PrivateStoreValue:
    __slots__ = ()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("private inventory authority is not serializable")


@dataclass(frozen=True, slots=True, repr=False)
class _InventoryAuthorityBinding(_PrivateStoreValue):
    authority_generation: int
    source_digest: str
    content_fingerprint: str


class _InventoryAuthorityTransaction(_PrivateStoreValue):
    __slots__ = (
        "_store",
        "_parent_fd",
        "_source",
        "_loaded",
        "_expected_result",
        "_finished",
        "_closed",
        "binding",
        "manager",
    )

    def __init__(self, store: GoogleInventoryStore, parent_fd: int) -> None:
        self._store = store
        self._parent_fd = parent_fd
        self._source, self._loaded = store._read()
        self.manager = GoogleAccountInventoryManager._from_authority_bytes(self._source)
        snapshot = self.manager._snapshot_for_internal_use()
        self.binding = _InventoryAuthorityBinding(
            snapshot.generation,
            "sha256:" + sha256(self._source).hexdigest(),
            snapshot.content_fingerprint,
        )
        self._expected_result = self._source
        self._finished = False
        self._closed = False

    @property
    def document(self) -> dict[str, object]:
        if self._closed:
            _raise("inventory.store_transaction_closed")
        return copy.deepcopy(self._loaded)

    def attest(self) -> None:
        if self._closed:
            _raise("inventory.store_transaction_closed")
        _assert_locked_parent(self._store, self._parent_fd)
        raw, _ = self._store._read()
        if raw != self._expected_result:
            _raise(
                "inventory.store_source_conflict"
                if self._expected_result == self._source
                else "inventory.store_result_conflict"
            )
        if self._finished:
            return
        manager = GoogleAccountInventoryManager._from_authority_bytes(raw)
        self.manager.close()
        self.manager = manager
        self._finished = True

    def commit(
        self,
        candidate: dict[str, object],
        *,
        expected: _InventoryAuthorityBinding,
        expected_content_fingerprint: str,
    ) -> GoogleInventoryStoreReceipt:
        if self._closed or self._finished:
            _raise("inventory.store_transaction_closed")
        if type(expected) is not _InventoryAuthorityBinding or expected != self.binding:
            _raise("inventory.store_source_conflict")
        if (
            type(candidate) is not dict
            or type(candidate.get("authority_generation")) is not int
            or candidate["authority_generation"] != self.binding.authority_generation
        ):
            _raise("inventory.store_generation_conflict")
        if self.binding.authority_generation >= _inventory.MAX_AUTHORITY_GENERATION:
            _raise("inventory.store_generation_exhausted")
        try:
            result = copy.deepcopy(candidate)
            result["authority_generation"] = self.binding.authority_generation + 1
            payload = yaml.safe_dump(result, sort_keys=False).encode("utf-8")
            validated = _inventory._document_from_bytes(payload)
        except Exception:
            _raise("inventory.store_schema_invalid")
        if (
            type(expected_content_fingerprint) is not str
            or validated.content_fingerprint != expected_content_fingerprint
        ):
            _raise("inventory.store_result_conflict")
        self._store._replace_locked(self._source, payload, self._parent_fd)
        self._expected_result = payload
        self.attest()
        summary = validated.public_projection()
        return GoogleInventoryStoreReceipt(
            schema_version=3,
            authority_generation=validated.authority_generation,
            account_count=int(summary["account_count"]),
            project_count=int(summary["project_count"]),
            backup_created=True,
        )


@contextmanager
def _authority_transaction(
    store: GoogleInventoryStore,
) -> Iterator[_InventoryAuthorityTransaction]:
    """ControlService-only source/CAS boundary, covering final reattestation."""

    if type(store) is not GoogleInventoryStore:
        _raise("inventory.store_unavailable")
    with _locked_inventory_parent(store) as parent_fd:
        transaction = _InventoryAuthorityTransaction(store, parent_fd)
        try:
            yield transaction
            transaction.attest()
        except BaseException:
            transaction.manager.close()
            raise
        finally:
            transaction._closed = True


class _Schema3MigrationQueen(_PrivateStoreValue):
    """Identity capability with no runtime issuer."""

    __slots__ = ()


@dataclass(frozen=True, slots=True, repr=False)
class _Schema3MigrationPlan(_PrivateStoreValue):
    plan_id: str
    source_digest: str
    result_digest: str
    plan_digest: str


def _schema3_migration_payload(raw: bytes) -> bytes:
    """Fully validate Schema2's unchanged account contract before any write."""

    try:
        if len(raw) > _inventory.MAX_INVENTORY_BYTES or b"\x00" in raw:
            _raise("inventory.store_schema_invalid")
        parsed = _inventory._load_strict_yaml(raw.decode("utf-8"))
        top = _inventory._mapping(
            parsed,
            frozenset({"schema_version", "google_accounts"}),
            frozenset({"schema_version", "google_accounts"}),
        )
        version = top["schema_version"]
        if type(version) is not _inventory._YamlIntegerLiteral or version.value != "2":
            _raise("inventory.store_schema_invalid")
        # Schema3 has exactly Schema2's account fields. Validation rejects rather
        # than repairing any absent, malformed, duplicate, or foreign field.
        target = dict(top)
        target["schema_version"] = _inventory._YamlIntegerLiteral("3")
        target["authority_generation"] = _inventory._YamlIntegerLiteral("1")
        _inventory._build_document(target)
        payload = yaml.safe_dump(_normalize(target), sort_keys=False).encode("utf-8")
        _inventory._document_from_bytes(payload)
        return payload
    except Exception:
        _raise("inventory.store_schema_invalid")


class _Schema3MigrationPort(_PrivateStoreValue):
    """Single migration effect; deliberately absent from runtime composition."""

    __slots__ = ("_store", "_queen", "_plan", "_consumed")

    def __init__(self, store: GoogleInventoryStore, queen: _Schema3MigrationQueen):
        self._store = store
        self._queen = queen
        self._plan: _Schema3MigrationPlan | None = None
        self._consumed = False

    def plan(
        self, *, queen: _Schema3MigrationQueen, plan_id: str
    ) -> _Schema3MigrationPlan:
        if queen is not self._queen or self._consumed or self._plan is not None:
            _raise("inventory.store_migration_denied")
        if (
            type(plan_id) is not str
            or not plan_id
            or len(plan_id.encode("utf-8")) > 256
        ):
            _raise("inventory.store_migration_denied")
        with _locked_inventory_parent(self._store):
            raw = _read_source_bytes(self._store)
            payload = _schema3_migration_payload(raw)
            source_digest = "sha256:" + sha256(raw).hexdigest()
            result_digest = "sha256:" + sha256(payload).hexdigest()
            binding = json.dumps(
                {
                    "action": "inventory.schema2_to_schema3",
                    "plan_id": plan_id,
                    "source_digest": source_digest,
                    "result_digest": result_digest,
                    "source_schema": 2,
                    "target_schema": 3,
                    "authority_generation": 1,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self._plan = _Schema3MigrationPlan(
                plan_id,
                source_digest,
                result_digest,
                "sha256:" + sha256(binding).hexdigest(),
            )
            return self._plan

    def apply(
        self,
        *,
        queen: _Schema3MigrationQueen,
        plan: _Schema3MigrationPlan,
        plan_digest: str,
    ) -> GoogleInventoryStoreReceipt:
        if (
            queen is not self._queen
            or type(plan) is not _Schema3MigrationPlan
            or plan is not self._plan
            or self._consumed
            or type(plan_digest) is not str
            or plan_digest != plan.plan_digest
        ):
            _raise("inventory.store_migration_denied")
        with _locked_inventory_parent(self._store) as parent_fd:
            if self._consumed:
                _raise("inventory.store_migration_denied")
            raw = _read_source_bytes(self._store)
            if "sha256:" + sha256(raw).hexdigest() != plan.source_digest:
                _raise("inventory.store_source_conflict")
            payload = _schema3_migration_payload(raw)
            if "sha256:" + sha256(payload).hexdigest() != plan.result_digest:
                _raise("inventory.store_result_conflict")
            # Consume before the effect: a durability failure must not enable replay.
            self._consumed = True
            self._store._replace_locked(raw, payload, parent_fd)
            if _read_source_bytes(self._store) != payload:
                _raise("inventory.store_result_conflict")
            result = _inventory._document_from_bytes(payload)
            summary = result.public_projection()
            return GoogleInventoryStoreReceipt(
                schema_version=3,
                authority_generation=1,
                account_count=int(summary["account_count"]),
                project_count=int(summary["project_count"]),
                backup_created=True,
            )


def _schema3_migration_for_test(
    path: Path,
) -> tuple[_Schema3MigrationPort, _Schema3MigrationQueen]:
    """Only construction seam; fixed synthetic basename below /tmp, no live issuer."""

    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or not path.is_relative_to(Path("/tmp"))
        or ".." in path.parts
        or path.name != "synthetic-inventory.yaml"
    ):
        _raise("inventory.store_migration_unavailable")
    queen = _Schema3MigrationQueen()
    return _Schema3MigrationPort(
        GoogleInventoryStore._for_test_path(path), queen
    ), queen
