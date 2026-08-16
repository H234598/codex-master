"""Bounded private JSON/JSONL state primitives for the Hive plane."""

from __future__ import annotations

from collections.abc import Mapping
import contextlib
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
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
        depth = held.get(key, 0)
        held[key] = depth + 1
        descriptor: int | None = None
        try:
            if depth == 0:
                try:
                    descriptor = os.open(
                        self._lock_path,
                        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                    )
                    os.fchmod(descriptor, 0o600)
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                except OSError as exc:
                    raise HiveStateError("state_lock_unavailable") from exc
            yield
        finally:
            if depth == 0 and descriptor is not None:
                with contextlib.suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            if depth:
                held[key] = depth
            else:
                held.pop(key, None)
            process_lock.release()


__all__ = ["HiveStateError", "HiveStateStore"]
