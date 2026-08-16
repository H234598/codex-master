from __future__ import annotations

import os
import secrets
from datetime import UTC, datetime
from pathlib import Path

def write_hourly_report(
    vault_root: Path,
    bucket_start: datetime,
    content: str,
    *,
    replace: bool = False,
) -> Path:
    if not isinstance(vault_root, Path) or not vault_root.is_absolute():
        raise ValueError("vault root must be absolute")
    if not isinstance(content, str) or len(content.encode("utf-8")) > 2 * 1024 * 1024:
        raise ValueError("report content is invalid")
    if not isinstance(replace, bool):
        raise ValueError("replace must be boolean")
    if bucket_start.tzinfo is None or bucket_start.utcoffset() is None:
        raise ValueError("bucket timestamp must be timezone-aware")
    assert_no_symlink_ancestors(vault_root, label="vault root")
    if vault_root.is_symlink() or (vault_root.exists() and not vault_root.is_dir()):
        raise ValueError("vault root must be a real directory")
    vault_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    bucket = bucket_start.astimezone(UTC)
    directory = vault_root / "Reports" / "Masterjet" / "Göttinnenberichte" / f"{bucket.year:04d}" / f"{bucket.month:02d}" / f"{bucket.day:02d}"
    _mkdir_real(directory)
    target = directory / f"{bucket.hour:02d}-{bucket.minute:02d}+00-00.md"
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise ValueError("report target must be a regular file")
    encoded = content.encode("utf-8")
    if target.exists():
        existing = target.read_bytes()
        if existing == encoded:
            return target
        if not replace:
            raise ValueError("final report already exists; replace is required")
    temporary = directory / f".{target.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary.exists():
            temporary.unlink()
    return target


def _mkdir_real(path: Path) -> None:
    assert_no_symlink_ancestors(path, label="vault report directory")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("vault report directory must be real")


def assert_no_symlink_ancestors(path: Path, *, label: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} must not contain symlink ancestors")
        if not current.exists():
            break
