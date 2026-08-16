"""Bounded private JSON/JSONL state primitives for the Hive plane."""

from __future__ import annotations

from collections.abc import Mapping
import contextlib
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import tempfile
from threading import RLock, local
from typing import Any


MAX_HIVE_STATE_BYTES = 4 * 1024 * 1024
MAX_HIVE_JSONL_RECORDS = 4096
MAX_RELATIVE_STATE_PART = 128
_PROCESS_LOCKS_GUARD = RLock()
_PROCESS_LOCKS: dict[str, RLock] = {}
_PROCESS_LOCK_HELD = local()


class HiveStateError(ValueError):
    """Raised when private Hive state is unavailable or unsafe."""


def _validate_relative(relative: PurePosixPath) -> PurePosixPath:
    if not isinstance(relative, PurePosixPath) or relative.is_absolute():
        raise HiveStateError("invalid_state_path")
    parts = relative.parts
    if not parts or any(
        not isinstance(part, str)
        or not 1 <= len(part) <= MAX_RELATIVE_STATE_PART
        or part in {".", ".."}
        or any(ord(char) < 32 for char in part)
        for part in parts
    ):
        raise HiveStateError("invalid_state_path")
    return relative


def _ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        current = path.lstat()
    except OSError as exc:
        raise HiveStateError("state_directory_unavailable") from exc
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode) or current.st_mode & 0o077:
        raise HiveStateError("state_directory_untrusted")
    if stat.S_IMODE(current.st_mode) != 0o700:
        try:
            os.chmod(path, 0o700)
        except OSError as exc:
            raise HiveStateError("state_directory_unavailable") from exc


class HiveStateStore:
    """Private state root with no-follow reads and atomic replacement."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise HiveStateError("invalid_state_root")
        self._root = root
        _ensure_private_directory(root)
        self._lock_path = root / ".hive-state.lock"
        descriptor = self._open_private_root()
        try:
            self._root_identity = self._identity(os.fstat(descriptor))
        finally:
            os.close(descriptor)

    def read_json(self, relative: PurePosixPath, *, max_bytes: int) -> Mapping[str, object]:
        self._validate_limit(max_bytes)
        with self._lock():
            return self.read_json_locked(relative, max_bytes=max_bytes)

    def read_json_locked(self, relative: PurePosixPath, *, max_bytes: int) -> Mapping[str, object]:
        """Read while the caller already owns :meth:`locked`."""

        path = self._path(relative)
        self._validate_limit(max_bytes)
        raw = self._read_bytes(path, max_bytes)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise HiveStateError("invalid_state_json") from exc
        if not isinstance(payload, Mapping):
            raise HiveStateError("invalid_state_document")
        return dict(payload)

    def replace_json(self, relative: PurePosixPath, payload: Mapping[str, object]) -> None:
        if not isinstance(payload, Mapping):
            raise HiveStateError("invalid_state_document")
        encoded = self._encode(payload)
        with self._lock():
            self.replace_json_locked(relative, payload, encoded=encoded)

    def replace_json_locked(
        self,
        relative: PurePosixPath,
        payload: Mapping[str, object],
        *,
        encoded: bytes | None = None,
    ) -> None:
        """Replace while the caller already owns :meth:`locked`."""

        path = self._path(relative)
        if not isinstance(payload, Mapping):
            raise HiveStateError("invalid_state_document")
        self._atomic_replace(path, encoded if encoded is not None else self._encode(payload))

    def read_private_bytes(self, relative: PurePosixPath, *, max_bytes: int) -> bytes:
        """Read one private regular file through the store's existing lock."""

        self._validate_limit(max_bytes)
        with self._lock():
            return self._read_private_bytes_locked(relative, max_bytes=max_bytes)

    def replace_private_bytes(self, relative: PurePosixPath, payload: bytes) -> None:
        """Atomically replace one private regular file through the store lock."""

        if type(payload) is not bytes:
            raise HiveStateError("invalid_state_document")
        if len(payload) > MAX_HIVE_STATE_BYTES:
            raise HiveStateError("state_oversize")
        with self._lock():
            self._replace_private_bytes_locked(relative, payload)

    @contextlib.contextmanager
    def locked(self) -> Any:
        """Hold the cross-process state lock for a read/modify/write CAS."""

        with self._lock():
            yield self

    def append_bounded_jsonl(
        self,
        relative: PurePosixPath,
        payload: Mapping[str, object],
        *,
        max_records: int,
        max_bytes: int,
    ) -> None:
        path = self._path(relative)
        if not isinstance(payload, Mapping):
            raise HiveStateError("invalid_state_document")
        if isinstance(max_records, bool) or not 1 <= max_records <= MAX_HIVE_JSONL_RECORDS:
            raise HiveStateError("invalid_state_limit")
        self._validate_limit(max_bytes)
        encoded_line = self._encode(payload).rstrip(b"\n")
        with self._lock():
            existing = b""
            if self._exists(path):
                existing = self._read_bytes(path, max_bytes)
            lines = [line for line in existing.splitlines() if line.strip()]
            if len(lines) >= max_records:
                lines = lines[-(max_records - 1) :]
            candidate = b"\n".join([*lines, encoded_line]) + b"\n"
            if len(candidate) > max_bytes:
                raise HiveStateError("state_oversize")
            self._atomic_replace(path, candidate)

    def read_bounded_jsonl(
        self,
        relative: PurePosixPath,
        *,
        max_records: int,
        max_bytes: int,
    ) -> tuple[dict[str, object], ...]:
        self._validate_jsonl_limits(max_records, max_bytes)
        with self._lock():
            return self.read_bounded_jsonl_locked(
                relative,
                max_records=max_records,
                max_bytes=max_bytes,
            )

    def read_bounded_jsonl_locked(
        self,
        relative: PurePosixPath,
        *,
        max_records: int,
        max_bytes: int,
    ) -> tuple[dict[str, object], ...]:
        """Read bounded JSONL while the caller already owns :meth:`locked`."""

        self._validate_jsonl_limits(max_records, max_bytes)
        path = self._path(relative)
        if not self._exists(path):
            return ()
        raw = self._read_bytes(path, max_bytes)
        records: list[dict[str, object]] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                raise HiveStateError("invalid_state_jsonl") from exc
            if not isinstance(payload, Mapping):
                raise HiveStateError("invalid_state_jsonl")
            records.append(dict(payload))
            if len(records) > max_records:
                raise HiveStateError("state_jsonl_full")
        return tuple(records)

    def _path(self, relative: PurePosixPath) -> Path:
        relative = _validate_relative(relative)
        path = self._root.joinpath(*relative.parts)
        parent = path.parent
        _ensure_private_directory(parent)
        try:
            root_resolved = self._root.resolve(strict=True)
            parent_resolved = parent.resolve(strict=True)
            parent_resolved.relative_to(root_resolved)
        except (OSError, RuntimeError, ValueError):
            raise HiveStateError("state_path_escape") from None
        return path

    @contextlib.contextmanager
    def _private_parent(self, relative: PurePosixPath) -> Any:
        """Open the relative parent without following or repairing existing entries."""

        relative = _validate_relative(relative)
        parts = relative.parts
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.dup(self._held_root_descriptor())
        except OSError as exc:
            raise HiveStateError("state_directory_unavailable") from exc
        try:
            for part in parts[:-1]:
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                        child = os.open(part, flags, dir_fd=descriptor)
                    except OSError as exc:
                        raise HiveStateError("state_directory_unavailable") from exc
                except OSError as exc:
                    raise HiveStateError("state_directory_untrusted") from exc
                try:
                    self._validate_private_directory(os.fstat(child))
                except Exception:
                    os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child
            yield descriptor, parts[-1]
        finally:
            os.close(descriptor)

    def _open_private_root(self) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._root, flags)
        except OSError as exc:
            raise HiveStateError("state_directory_unavailable") from exc
        try:
            self._validate_private_directory(os.fstat(descriptor))
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _verify_bound_root_descriptor(self, descriptor: int) -> None:
        self._validate_private_directory(os.fstat(descriptor))
        if self._identity(os.fstat(descriptor)) != self._root_identity:
            raise HiveStateError("state_root_untrusted")

    def _verify_bound_root_path(self) -> None:
        descriptor = self._open_private_root()
        try:
            self._verify_bound_root_descriptor(descriptor)
        finally:
            os.close(descriptor)

    def _held_root_descriptor(self) -> int:
        held = getattr(_PROCESS_LOCK_HELD, "values", None)
        entry = held.get(str(self._lock_path)) if held is not None else None
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise HiveStateError("state_lock_unavailable")
        _depth, descriptor = entry
        self._verify_bound_root_descriptor(descriptor)
        self._verify_bound_root_path()
        return descriptor

    def _open_lock_descriptor(self, root_descriptor: int) -> int:
        lock_name = self._lock_path.name
        try:
            existing = os.stat(lock_name, dir_fd=root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise HiveStateError("state_lock_unavailable") from exc
        if existing is not None:
            self._validate_private_file(existing, MAX_HIVE_STATE_BYTES)
        try:
            descriptor = os.open(
                lock_name,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=root_descriptor,
            )
        except OSError as exc:
            raise HiveStateError("state_lock_unavailable") from exc
        try:
            opened = os.fstat(descriptor)
            self._validate_private_file(opened, MAX_HIVE_STATE_BYTES)
            if existing is not None and not self._same_file(existing, opened):
                raise HiveStateError("state_lock_unavailable")
            os.fchmod(descriptor, 0o600)
            self._validate_private_file(os.fstat(descriptor), MAX_HIVE_STATE_BYTES)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _validate_private_directory(info: os.stat_result) -> None:
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise HiveStateError("state_directory_untrusted")

    @staticmethod
    def _validate_private_file(info: os.stat_result, max_bytes: int) -> None:
        if info.st_size > max_bytes:
            raise HiveStateError("state_oversize")
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise HiveStateError("state_file_untrusted")

    @staticmethod
    def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
        return HiveStateStore._identity(left) == HiveStateStore._identity(right)

    @staticmethod
    def _identity(info: os.stat_result) -> tuple[int, int]:
        return info.st_dev, info.st_ino

    def _read_private_bytes_locked(self, relative: PurePosixPath, *, max_bytes: int) -> bytes:
        with self._private_parent(relative) as (parent_descriptor, name):
            try:
                descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_descriptor)
            except FileNotFoundError:
                raise HiveStateError("state_not_found") from None
            except OSError as exc:
                raise HiveStateError("state_unavailable") from exc
            try:
                initial = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
                opened = os.fstat(descriptor)
                self._validate_private_file(initial, max_bytes)
                self._validate_private_file(opened, max_bytes)
                if not self._same_file(initial, opened):
                    raise HiveStateError("state_file_untrusted")
                chunks: list[bytes] = []
                remaining = max_bytes + 1
                while remaining:
                    chunk = os.read(descriptor, remaining)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                if len(raw) > max_bytes:
                    raise HiveStateError("state_oversize")
                current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
                self._validate_private_file(current, max_bytes)
                if not self._same_file(opened, current):
                    raise HiveStateError("state_file_untrusted")
                return raw
            except HiveStateError:
                raise
            except OSError as exc:
                raise HiveStateError("state_unavailable") from exc
            finally:
                os.close(descriptor)

    def _replace_private_bytes_locked(self, relative: PurePosixPath, payload: bytes) -> None:
        with self._private_parent(relative) as (parent_descriptor, name):
            try:
                existing = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            except OSError as exc:
                raise HiveStateError("state_unavailable") from exc
            if existing is not None:
                self._validate_private_file(existing, MAX_HIVE_STATE_BYTES)

            temporary = f".{name}.{secrets.token_hex(16)}"
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=parent_descriptor,
                )
                os.fchmod(descriptor, 0o600)
                self._validate_private_file(os.fstat(descriptor), MAX_HIVE_STATE_BYTES)
                offset = 0
                while offset < len(payload):
                    offset += os.write(descriptor, payload[offset:])
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = None

                try:
                    current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    current = None
                if existing is None:
                    if current is not None:
                        raise HiveStateError("state_file_untrusted")
                else:
                    if current is None or not self._same_file(existing, current):
                        raise HiveStateError("state_file_untrusted")
                    self._validate_private_file(current, MAX_HIVE_STATE_BYTES)

                os.replace(temporary, name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
                temporary = ""
                self._validate_private_file(
                    os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False),
                    MAX_HIVE_STATE_BYTES,
                )
                os.fsync(parent_descriptor)
            except HiveStateError:
                raise
            except OSError as exc:
                raise HiveStateError("state_write_failed") from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if temporary:
                    with contextlib.suppress(OSError):
                        os.unlink(temporary, dir_fd=parent_descriptor)

    @staticmethod
    def _validate_limit(max_bytes: int) -> None:
        if isinstance(max_bytes, bool) or not 1 <= max_bytes <= MAX_HIVE_STATE_BYTES:
            raise HiveStateError("invalid_state_limit")

    @classmethod
    def _validate_jsonl_limits(cls, max_records: int, max_bytes: int) -> None:
        if isinstance(max_records, bool) or not 1 <= max_records <= MAX_HIVE_JSONL_RECORDS:
            raise HiveStateError("invalid_state_limit")
        cls._validate_limit(max_bytes)

    @staticmethod
    def _encode(payload: Mapping[str, object]) -> bytes:
        try:
            encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError) as exc:
            raise HiveStateError("invalid_state_document") from exc
        result = (encoded + "\n").encode("utf-8")
        if len(result) > MAX_HIVE_STATE_BYTES:
            raise HiveStateError("state_oversize")
        return result

    @staticmethod
    def _exists(path: Path) -> bool:
        try:
            current = path.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise HiveStateError("state_unavailable") from exc
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            raise HiveStateError("state_file_untrusted")
        return True

    @staticmethod
    def _read_bytes(path: Path, max_bytes: int) -> bytes:
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            raise HiveStateError("state_not_found") from None
        except OSError as exc:
            raise HiveStateError("state_unavailable") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > max_bytes:
                raise HiveStateError("state_file_untrusted" if info.st_size <= max_bytes else "state_oversize")
            raw = os.read(descriptor, max_bytes + 1)
            if len(raw) > max_bytes:
                raise HiveStateError("state_oversize")
            return raw
        except OSError as exc:
            raise HiveStateError("state_unavailable") from exc
        finally:
            os.close(descriptor)

    def _atomic_replace(self, path: Path, encoded: bytes) -> None:
        if len(encoded) > MAX_HIVE_STATE_BYTES:
            raise HiveStateError("state_oversize")
        parent = path.parent
        descriptor: int | None = None
        temporary: Path | None = None
        try:
            if path.exists() or path.is_symlink():
                self._exists(path)
            descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
            temporary = Path(name)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            temporary = None
            parent_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        except HiveStateError:
            raise
        except OSError as exc:
            raise HiveStateError("state_write_failed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                with contextlib.suppress(OSError):
                    temporary.unlink()

    @contextlib.contextmanager
    def _lock(self) -> Any:
        key = str(self._lock_path)
        with _PROCESS_LOCKS_GUARD:
            process_lock = _PROCESS_LOCKS.setdefault(key, RLock())
        held = getattr(_PROCESS_LOCK_HELD, "values", None)
        if held is None:
            held = {}
            _PROCESS_LOCK_HELD.values = held
        process_lock.acquire()
        entry = held.get(key)
        if entry is not None:
            depth, root_descriptor = entry
            try:
                self._verify_bound_root_descriptor(root_descriptor)
                self._verify_bound_root_path()
            except Exception:
                process_lock.release()
                raise
            held[key] = depth + 1, root_descriptor
            try:
                yield
            finally:
                held[key] = depth, root_descriptor
                process_lock.release()
            return

        root_descriptor: int | None = None
        lock_descriptor: int | None = None
        try:
            root_descriptor = self._open_private_root()
            self._verify_bound_root_descriptor(root_descriptor)
            lock_descriptor = self._open_lock_descriptor(root_descriptor)
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            except OSError as exc:
                raise HiveStateError("state_lock_unavailable") from exc
            self._verify_bound_root_descriptor(root_descriptor)
            self._verify_bound_root_path()
            held[key] = 1, root_descriptor
            try:
                yield
            finally:
                held.pop(key, None)
        finally:
            if lock_descriptor is not None:
                with contextlib.suppress(OSError):
                    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
                os.close(lock_descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)
            process_lock.release()


__all__ = ["HiveStateError", "HiveStateStore"]
