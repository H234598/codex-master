"""Atomic private YAML updates for Google account inventory."""

from __future__ import annotations

from dataclasses import dataclass
import copy
import fcntl
import os
from pathlib import Path
import stat
import time
from typing import Callable

import yaml

from . import google_account_inventory as _inventory


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
        path = self._path
        try:
            parent = os.lstat(path.parent)
            item = os.lstat(path)
        except OSError:
            _raise("inventory.store_unavailable")
        if (
            not path.is_absolute()
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or bool(stat.S_IMODE(parent.st_mode) & 0o022)
            or not stat.S_ISREG(item.st_mode)
            or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) != 0o600
            or item.st_nlink != 1
        ):
            _raise("inventory.store_permissions")
        descriptor: int | None = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (item.st_dev, item.st_ino):
                _raise("inventory.store_permissions")
            raw = b""
            while len(raw) <= _inventory.MAX_INVENTORY_BYTES:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                raw += chunk
            if len(raw) > _inventory.MAX_INVENTORY_BYTES:
                _raise("inventory.store_unavailable")
            current = os.stat(path, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                _raise("inventory.store_permissions")
        except GoogleInventoryStoreError:
            raise
        except OSError:
            _raise("inventory.store_unavailable")
        finally:
            if descriptor is not None:
                os.close(descriptor)
        try:
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
        def migrate(document: dict[str, object]) -> None:
            if document.get("schema_version") not in {1, 2}:
                _raise("inventory.store_schema_invalid")
            accounts = document.get("google_accounts")
            if type(accounts) is not list:
                _raise("inventory.store_schema_invalid")
            for account in accounts:
                if type(account) is not dict:
                    _raise("inventory.store_schema_invalid")
                projects = account.get("projects")
                if type(projects) is not list:
                    _raise("inventory.store_schema_invalid")
                for project in projects:
                    if type(project) is not dict:
                        _raise("inventory.store_schema_invalid")
                    project.setdefault("project_name", None)
                    project.setdefault("purpose", "hive")
                    project.setdefault("key_name", None)
            document["schema_version"] = 2

        return self.atomic_update(migrate)

    def atomic_update(
        self, transform: Callable[[dict[str, object]], None]
    ) -> GoogleInventoryStoreReceipt:
        path = self._path
        lock_fd: int | None = None
        try:
            lock_fd = os.open(
                path.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            opened_parent = os.fstat(lock_fd)
            current_parent = os.lstat(path.parent)
            if (
                not stat.S_ISDIR(opened_parent.st_mode)
                or opened_parent.st_uid != os.geteuid()
                or bool(stat.S_IMODE(opened_parent.st_mode) & 0o022)
                or (opened_parent.st_dev, opened_parent.st_ino)
                != (current_parent.st_dev, current_parent.st_ino)
            ):
                _raise("inventory.store_permissions")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            return self._atomic_update_locked(transform)
        except GoogleInventoryStoreError:
            raise
        except OSError:
            _raise("inventory.store_unavailable")
        finally:
            if lock_fd is not None:
                try:
                    os.close(lock_fd)
                except OSError:
                    pass

    def _atomic_update_locked(
        self, transform: Callable[[dict[str, object]], None]
    ) -> GoogleInventoryStoreReceipt:
        original, loaded = self._read()
        candidate = copy.deepcopy(loaded)
        try:
            transform(candidate)
            payload = yaml.safe_dump(candidate, sort_keys=False).encode("utf-8")
            if len(payload) > _inventory.MAX_INVENTORY_BYTES:
                _raise("inventory.store_schema_invalid")
            parsed = _inventory._load_strict_yaml(payload.decode("utf-8"))
            validated = _inventory._build_document(parsed)
        except GoogleInventoryStoreError:
            raise
        except Exception:
            _raise("inventory.store_transform_failed")

        path = self._path
        parent_fd: int | None = None
        backup_fd: int | None = None
        temporary_fd: int | None = None
        temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{time.time_ns()}"
        backup = path.parent / f"{path.name}.backup-{time.time_ns()}"
        replaced = False
        try:
            parent_fd = os.open(
                path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
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
            for descriptor in (temporary_fd, backup_fd, parent_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            if not replaced:
                try:
                    temporary.unlink()
                except OSError:
                    pass

        summary = validated.public_projection()
        return GoogleInventoryStoreReceipt(
            schema_version=validated.schema_version,
            account_count=int(summary["account_count"]),
            project_count=int(summary["project_count"]),
            backup_created=True,
        )

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
