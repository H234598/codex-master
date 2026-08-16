from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path


ROOT_ROLES = frozenset({"goettin", "goddess"})


class ReporterLeaderBusy(RuntimeError):
    """Another reporter process currently owns the leader lock."""


class ReporterLeaderLease:
    """Process-scoped, kernel-backed single-leader lease."""

    def __init__(self, path: Path):
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("reporter leader path must be absolute")
        self.path = path
        self._fd: int | None = None

    def acquire(self, *, now: datetime | None = None) -> None:
        if self._fd is not None:
            raise RuntimeError("reporter leader lease is already held")
        _assert_real_parent(self.path)
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise ValueError("reporter leader parent must be a real directory")
        os.chmod(self.path.parent, 0o700)
        fd = os.open(
            self.path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise ReporterLeaderBusy("reporter leader is already held") from exc
        os.fchmod(fd, 0o600)
        self._fd = fd
        try:
            self.refresh(now=now)
        except Exception:
            self.release()
            raise

    def refresh(self, *, now: datetime | None = None) -> None:
        if self._fd is None:
            raise RuntimeError("reporter leader lease is not held")
        timestamp = now or datetime.now(UTC)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        payload = json.dumps(
            {"pid": os.getpid(), "heartbeat": timestamp.astimezone(UTC).isoformat()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        os.lseek(self._fd, 0, os.SEEK_SET)
        os.ftruncate(self._fd, 0)
        os.write(self._fd, payload)
        os.fsync(self._fd)

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> "ReporterLeaderLease":
        self.acquire()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.release()


def reporter_leader_active(path: Path) -> bool:
    """Probe lock ownership without claiming the lock."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("reporter leader path must be absolute")
    if not path.exists():
        return False
    if path.is_symlink() or not path.is_file():
        raise ValueError("reporter leader path must be a regular file")
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def _assert_real_parent(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        if current.is_symlink():
            raise ValueError("reporter leader path must not contain symlink ancestors")
        if not current.exists():
            break


def active_reporter_required(
    principals: Iterable[Mapping[str, object]],
    bindings: Iterable[Mapping[str, object]],
    *,
    now: datetime,
) -> bool:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    active_ids = {
        principal.get("id", principal.get("principal_id"))
        for principal in principals
        if (
            (principal.get("active") is True or principal.get("state") == "active")
            and principal.get("role", principal.get("class_id")) in ROOT_ROLES
        )
    }
    for binding in bindings:
        if binding.get("principal_id") not in active_ids:
            continue
        if binding.get("state") not in (None, "active"):
            continue
        expires = binding.get("expires_at", binding.get("expires_at_utc"))
        if isinstance(expires, str):
            try:
                expires = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            except ValueError:
                expires = None
        if isinstance(expires, datetime) and expires.tzinfo is not None and expires.astimezone(UTC) > now.astimezone(UTC):
            return True
    return False
