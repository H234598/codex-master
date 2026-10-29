"""Conservative worktree previews and independently verified local archives."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from typing import Any

from the_hive.fleet_home_v2_cutover import LocalFleetHomeV2Filesystem
from the_hive.worktree_lifecycle import (
    WorktreeBinding,
    WorktreeLifecycleError,
    WorktreeLifecycleStore,
)


class MaintenanceError(ValueError):
    """Raised when maintenance evidence or an operation is unavailable."""


@dataclass(frozen=True, slots=True)
class ProjectPolicy:
    source_root: Path
    allowed_source_roots: tuple[Path, ...]
    archive_root: Path
    inactive_seconds: int = 30 * 86400
    large_inactive_seconds: int = 7 * 86400
    large_bytes: int = 10 * 1024**3
    temporary_age_seconds: int = 7 * 86400


@dataclass(frozen=True, slots=True)
class MaintenanceCandidate:
    source: Path
    reasons: tuple[str, ...]
    eligible: bool
    archive_root: Path | None = None
    binding: WorktreeBinding | None = None
    last_use_ended_at: int | None = None
    allocated_bytes: int | None = None
    source_identity: tuple[int, int, int] | None = None
    source_manifest_sha256: str | None = None
    temporary: bool = False


@dataclass(frozen=True, slots=True)
class ArchiveReceipt:
    archive: Path
    manifest_sha256: str
    entry_count: int
    archive_device: int | None = None
    archive_inode: int | None = None


_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_TREE_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _maintenance_pass_fds(
    lock_fd: int | None, additional_fds: tuple[int, ...]
) -> tuple[int, ...]:
    if lock_fd is not None and (type(lock_fd) is not int or lock_fd < 0):
        raise MaintenanceError("archive_lock_unavailable")
    values = (() if lock_fd is None else (lock_fd,)) + additional_fds
    result = tuple(dict.fromkeys(values))
    try:
        for descriptor in result:
            os.fstat(descriptor)
    except OSError as exc:
        raise MaintenanceError("archive_lock_unavailable") from exc
    return result


def _safe_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise MaintenanceError("archive_member_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        if value != ".":
            raise MaintenanceError("archive_member_path_invalid")
    normalized = path.as_posix()
    if normalized != value and not (value.startswith("./") and normalized == value[2:]):
        raise MaintenanceError("archive_member_path_invalid")
    return normalized


def _validate_tar_archive_fd(descriptor: int, expected: list[dict[str, Any]]) -> None:
    expected_by_path = {entry.get("path"): entry for entry in expected}
    if len(expected_by_path) != len(expected):
        raise MaintenanceError("archive_manifest_invalid")
    seen: dict[str, str] = {}
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as tar_stream:
            with tarfile.open(fileobj=tar_stream, mode="r:*") as archive:
                for index, member in enumerate(archive):
                    if index >= 200_000:
                        raise MaintenanceError("archive_member_limit_exceeded")
                    name = _safe_relative_path(member.name)
                    if name == ".":
                        if not member.isdir():
                            raise MaintenanceError("archive_member_type_invalid")
                        entry = expected_by_path.get(".")
                        if entry is None or entry.get("kind") != "directory":
                            raise MaintenanceError("archive_manifest_mismatch")
                        seen[name] = "directory"
                        continue
                    if name in seen:
                        raise MaintenanceError("archive_member_duplicate")
                    for parent in PurePosixPath(name).parents:
                        if (
                            parent.as_posix() in seen
                            and seen[parent.as_posix()] == "symlink"
                        ):
                            raise MaintenanceError("archive_member_through_symlink")
                    entry = expected_by_path.get(name)
                    if entry is None:
                        raise MaintenanceError("archive_member_unmanifested")
                    if member.isdir():
                        kind = "directory"
                    elif member.isreg():
                        kind = "file"
                    elif member.issym():
                        kind = "symlink"
                        target = member.linkname
                        if (
                            not target
                            or PurePosixPath(target).is_absolute()
                            or "\\" in target
                        ):
                            raise MaintenanceError("archive_symlink_target_invalid")
                        stack = list(PurePosixPath(name).parent.parts)
                        for part in PurePosixPath(target).parts:
                            if part in {"", "."}:
                                continue
                            if part == "..":
                                if not stack:
                                    raise MaintenanceError(
                                        "archive_symlink_target_escape"
                                    )
                                stack.pop()
                            else:
                                stack.append(part)
                        if entry.get("target") != target:
                            raise MaintenanceError("archive_manifest_mismatch")
                    else:
                        raise MaintenanceError("archive_member_type_invalid")
                    if entry.get("kind") != kind:
                        raise MaintenanceError("archive_manifest_mismatch")
                    if kind == "file" and entry.get("size") != member.size:
                        raise MaintenanceError("archive_manifest_mismatch")
                    seen[name] = kind
    except MaintenanceError:
        raise
    except (OSError, tarfile.TarError, ValueError) as exc:
        raise MaintenanceError("archive_tar_invalid") from exc
    if set(seen) != set(expected_by_path):
        raise MaintenanceError("archive_manifest_member_mismatch")
    os.lseek(descriptor, 0, os.SEEK_SET)


def _digest_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as exc:
        raise MaintenanceError("archive_digest_unavailable") from exc
    return digest.hexdigest()


def _snapshot_archive_tar(
    receipt: ArchiveReceipt,
    name: str,
    expected_digest: object,
    expected_entries: list[dict[str, Any]],
) -> Any:
    path = receipt.archive / name
    snapshot = None
    try:
        before = path.lstat()
        source_fd = os.open(path, _FILE_FLAGS)
        opened = os.fstat(source_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise MaintenanceError("archive_data_invalid")
        if (
            shutil.disk_usage(receipt.archive.parent).free
            < opened.st_size + 4 * 1024 * 1024
        ):
            raise MaintenanceError("restore_space_unavailable")
        snapshot = tempfile.TemporaryFile(mode="w+b", dir=receipt.archive.parent)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            snapshot.write(chunk)
        snapshot.flush()
        descriptor = snapshot.fileno()
        snapshot_info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(snapshot_info.st_mode)
            or snapshot_info.st_uid != os.geteuid()
            or snapshot_info.st_nlink != 0
            or _mount_id(descriptor) != _mount_id(source_fd)
            or _digest_fd(descriptor) != expected_digest
        ):
            raise MaintenanceError("archive_digest_mismatch")
        _validate_tar_archive_fd(descriptor, expected_entries)
        return snapshot
    except MaintenanceError:
        if snapshot is not None:
            snapshot.close()
        raise
    except OSError as exc:
        if snapshot is not None:
            snapshot.close()
        raise MaintenanceError("archive_data_invalid") from exc
    finally:
        if "source_fd" in locals():
            os.close(source_fd)


def _validate_archive_gitdir(manifest: Mapping[str, Any]) -> None:
    gitdir = manifest.get("gitdir")
    if not isinstance(gitdir, str) or "\\" in gitdir:
        raise MaintenanceError("archive_gitdir_invalid")
    path = PurePosixPath(gitdir)
    if (
        path.is_absolute()
        or path.as_posix() != gitdir
        or len(path.parts) != 2
        or path.parts[0] != "worktrees"
        or path.parts[1] in {"", ".", ".."}
    ):
        raise MaintenanceError("archive_gitdir_invalid")


def _open_directory_beneath(root_fd: int, relative: str) -> int:
    current_fd = os.dup(root_fd)
    try:
        for component in PurePosixPath(relative).parts:
            next_fd = os.open(component, _TREE_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError as exc:
        os.close(current_fd)
        raise MaintenanceError("archive_staging_path_invalid") from exc


def _validate_git_config_at(
    directory_fd: int, name: str, *, lock_fd: int | None = None
) -> None:
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise MaintenanceError("archive_git_config_invalid") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_size > 1024 * 1024
        ):
            raise MaintenanceError("archive_git_config_invalid")
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
        completed = subprocess.run(
            [
                "git",
                "config",
                "--no-includes",
                "--null",
                "--list",
                "--file",
                f"/proc/self/fd/{fd}",
            ],
            pass_fds=_maintenance_pass_fds(lock_fd, (fd,)),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode:
            raise MaintenanceError("archive_git_config_invalid")
        for record in completed.stdout.split(b"\0"):
            if not record:
                continue
            key, _, value = record.partition(b"\n")
            key_text = key.decode("utf-8", "strict").lower()
            suffix = key_text.rsplit(".", 1)[-1]
            if (
                key_text.startswith("include.")
                or key_text.startswith("includeif.")
                or key_text
                in {
                    "core.fsmonitor",
                    "core.worktree",
                    "core.attributesfile",
                    "core.excludesfile",
                    "core.hookspath",
                    "core.sshcommand",
                }
                or (
                    key_text.startswith("filter.")
                    and suffix in {"clean", "smudge", "process"}
                )
                or (key_text.startswith("diff.") and suffix in {"textconv", "external"})
            ):
                raise MaintenanceError("archive_git_config_unsafe")
            value.decode("utf-8", "strict")
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise MaintenanceError("archive_git_config_invalid") from exc
    finally:
        os.close(fd)


def _write_at(directory_fd: int, name: str, value: str, *, create: bool) -> None:
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_CREAT | os.O_EXCL if create else os.O_TRUNC
    try:
        fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except OSError as exc:
        raise MaintenanceError("archive_metadata_write_failed") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
        ):
            raise MaintenanceError("archive_metadata_target_invalid")
        data = value.encode("utf-8")
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def _mount_id(fd: int) -> int:
    return LocalFleetHomeV2Filesystem.mount_id(fd)


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = _FILE_FLAGS
    fd = os.open(path, flags)
    try:
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def _xattrs(fd: int) -> dict[str, str]:
    try:
        names = os.listxattr(fd)
        result = {}
        for name in sorted(names):
            result[name] = base64.b64encode(os.getxattr(fd, name)).decode("ascii")
        return result
    except MaintenanceError:
        raise
    except OSError as exc:
        raise MaintenanceError("extended_attribute_unavailable") from exc


def _xattrs_at(
    directory_fd: int, name: str, expected: os.stat_result
) -> dict[str, str]:
    path = f"/proc/self/fd/{directory_fd}/{name}"
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (expected.st_dev, expected.st_ino):
            raise MaintenanceError("source_inode_changed")
        result = {
            attr: base64.b64encode(
                os.getxattr(path, attr, follow_symlinks=False)
            ).decode("ascii")
            for attr in sorted(os.listxattr(path, follow_symlinks=False))
        }
        after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (after.st_dev, after.st_ino) != (expected.st_dev, expected.st_ino):
            raise MaintenanceError("source_inode_changed")
        return result
    except MaintenanceError:
        raise
    except OSError as exc:
        raise MaintenanceError("extended_attribute_unavailable") from exc


def _sparse_extents(fd: int, size: int) -> list[list[int]]:
    if not hasattr(os, "SEEK_DATA") or not hasattr(os, "SEEK_HOLE"):
        raise MaintenanceError("sparse_extent_unavailable")
    extents = []
    offset = 0
    while offset < size:
        try:
            data = os.lseek(fd, offset, os.SEEK_DATA)
        except OSError as exc:
            if exc.errno == errno.ENXIO:
                break
            if exc.errno in {errno.EINVAL, errno.ENOTSUP}:
                raise MaintenanceError("sparse_extent_unavailable") from exc
            raise MaintenanceError("sparse_extent_unavailable") from exc
        try:
            hole = os.lseek(fd, data, os.SEEK_HOLE)
        except OSError as exc:
            raise MaintenanceError("sparse_extent_unavailable") from exc
        if hole <= data:
            raise MaintenanceError("sparse_extent_invalid")
        extents.append([data, min(hole, size) - data])
        offset = hole
    return extents


def _tree_manifest(
    root: Path,
    *,
    skip_git: bool = False,
    skip_names: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    try:
        root_fd = os.open(root, _TREE_FLAGS)
        root_info = os.fstat(root_fd)
        root_mount = _mount_id(root_fd)
    except OSError as exc:
        raise MaintenanceError("source_unavailable") from exc
    owner_uid, owner_gid = os.geteuid(), os.getegid()
    if root_info.st_uid != owner_uid or root_info.st_gid != owner_gid:
        os.close(root_fd)
        raise MaintenanceError("foreign_source_owner")
    root_device = root_info.st_dev
    entries: list[dict[str, Any]] = [
        {
            "path": ".",
            "mode": stat.S_IMODE(root_info.st_mode),
            "uid": root_info.st_uid,
            "gid": root_info.st_gid,
            "mtime_ns": root_info.st_mtime_ns,
            "kind": "directory",
            "xattrs": _xattrs(root_fd),
        }
    ]

    def walk(directory_fd: int, prefix: str) -> None:
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as exc:
            raise MaintenanceError("source_unreadable") from exc
        for name in names:
            if name in {".", ".."}:
                raise MaintenanceError("source_path_invalid")
            relative = f"{prefix}/{name}" if prefix else name
            if not prefix and ((skip_git and name == ".git") or name in skip_names):
                continue
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise MaintenanceError("source_changed") from exc
            if (
                info.st_dev != root_device
                or info.st_uid != owner_uid
                or info.st_gid != owner_gid
            ):
                raise MaintenanceError("foreign_or_cross_mount_entry")
            entry: dict[str, Any] = {
                "path": relative,
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mtime_ns": info.st_mtime_ns,
            }
            if stat.S_ISDIR(info.st_mode):
                child_fd = os.open(name, _TREE_FLAGS, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if (
                        opened.st_dev != info.st_dev
                        or opened.st_ino != info.st_ino
                        or _mount_id(child_fd) != root_mount
                    ):
                        raise MaintenanceError("source_mount_or_inode_changed")
                    entry.update(kind="directory", xattrs=_xattrs(child_fd))
                    entries.append(entry)
                    walk(child_fd, relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise MaintenanceError("hardlinked_source_file")
                fd = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
                try:
                    opened = os.fstat(fd)
                    if opened.st_dev != info.st_dev or opened.st_ino != info.st_ino:
                        raise MaintenanceError("source_inode_changed")
                    digest = hashlib.sha256()
                    while True:
                        chunk = os.read(fd, 1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                    entry.update(
                        kind="file",
                        size=opened.st_size,
                        sha256=digest.hexdigest(),
                        xattrs=_xattrs(fd),
                        sparse_extents=_sparse_extents(fd, opened.st_size),
                    )
                finally:
                    os.close(fd)
                entries.append(entry)
            elif stat.S_ISLNK(info.st_mode):
                try:
                    target = os.readlink(name, dir_fd=directory_fd)
                except OSError as exc:
                    raise MaintenanceError("source_changed") from exc
                entry.update(
                    kind="symlink",
                    target=target,
                    xattrs=_xattrs_at(directory_fd, name, info),
                )
                entries.append(entry)
            else:
                raise MaintenanceError("unsupported_source_file_type")

    try:
        walk(root_fd, "")
        after = os.fstat(root_fd)
        if (after.st_dev, after.st_ino) != (root_info.st_dev, root_info.st_ino):
            raise MaintenanceError("source_inode_changed")
        return entries
    finally:
        os.close(root_fd)


def _git_layout(source: Path, binding: WorktreeBinding | None) -> tuple[Path, str]:
    dot_git = source / ".git"
    try:
        info = dot_git.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise MaintenanceError("linked_worktree_metadata_invalid")
        text = dot_git.read_text(encoding="utf-8")
        if not text.startswith("gitdir: ") or not text.endswith("\n"):
            raise MaintenanceError("linked_worktree_metadata_invalid")
        raw_gitdir = Path(text[8:].strip())
        gitdir = (
            raw_gitdir if raw_gitdir.is_absolute() else source / raw_gitdir
        ).resolve(strict=True)
        common_text = (gitdir / "commondir").read_text(encoding="utf-8").strip()
        raw_common = Path(common_text)
        common = (
            raw_common if raw_common.is_absolute() else gitdir / raw_common
        ).resolve(strict=True)
        expected_common = (
            binding.git_common_directory if binding is not None else common
        )
        if common != expected_common or gitdir.parent != common / "worktrees":
            raise MaintenanceError("linked_worktree_metadata_invalid")
        relative = gitdir.relative_to(common).as_posix()
        if (gitdir / "locked").exists():
            raise MaintenanceError("linked_worktree_locked")
        pointer = (gitdir / "gitdir").read_text(encoding="utf-8").strip()
        pointer_path = Path(pointer)
        if not pointer_path.is_absolute():
            pointer_path = gitdir / pointer_path
        if pointer_path.resolve(strict=False) != dot_git.resolve(strict=False):
            raise MaintenanceError("linked_worktree_metadata_invalid")
        return common, relative
    except MaintenanceError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise MaintenanceError("linked_worktree_metadata_invalid") from exc


def _tar_create(
    root_fd: int,
    output: Path,
    *,
    exclude_git: bool,
    lock_fd: int | None = None,
) -> None:
    command = [
        "tar",
        "--create",
        "--file",
        str(output),
        "--format=pax",
        "--acls",
        "--xattrs",
        "--xattrs-include=*",
        "--sparse",
        "--numeric-owner",
        "--one-file-system",
    ]
    if exclude_git:
        command.append("--exclude=./.git")
    command.extend(("--directory", f"/proc/self/fd/{root_fd}", "."))
    try:
        completed = subprocess.run(
            command,
            pass_fds=_maintenance_pass_fds(lock_fd, (root_fd,)),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise MaintenanceError("tar_unavailable") from exc
    if completed.returncode:
        raise MaintenanceError("archive_creation_failed")


def _write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise MaintenanceError("archive_write_failed")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        + b"\n"
    )


def _read_archive_manifest(
    receipt: ArchiveReceipt,
    *,
    verified_tar_files: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        info = receipt.archive.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or (
                receipt.archive_device is not None
                and info.st_dev != receipt.archive_device
            )
            or (
                receipt.archive_inode is not None
                and info.st_ino != receipt.archive_inode
            )
        ):
            raise MaintenanceError("archive_identity_invalid")
        manifest_path = receipt.archive / "manifest.json"
        manifest_info = manifest_path.lstat()
        if (
            not stat.S_ISREG(manifest_info.st_mode)
            or manifest_info.st_uid != os.geteuid()
            or manifest_info.st_nlink != 1
        ):
            raise MaintenanceError("archive_manifest_invalid")
        raw = manifest_path.read_bytes()
        if (
            len(raw) > _MAX_MANIFEST_BYTES
            or hashlib.sha256(raw).hexdigest() != receipt.manifest_sha256
        ):
            raise MaintenanceError("archive_manifest_digest_mismatch")
        manifest = json.loads(raw)
        if not isinstance(manifest, dict) or manifest.get("format") != 1:
            raise MaintenanceError("archive_manifest_invalid")
        if manifest.get("kind") == "temporary_tree":
            source_entries = manifest.get("source_entries")
            if not isinstance(source_entries, list) or any(
                not isinstance(entry, dict) for entry in source_entries
            ):
                raise MaintenanceError("archive_manifest_invalid")
            tar_file = _snapshot_archive_tar(
                receipt,
                "temporary.tar",
                manifest.get("archives", {}).get("temporary.tar"),
                source_entries,
            )
            if verified_tar_files is None:
                tar_file.close()
            else:
                verified_tar_files["temporary.tar"] = tar_file
            return manifest
        _validate_archive_gitdir(manifest)
        source_entries = manifest.get("source_entries")
        common_entries = manifest.get("common_entries")
        if not isinstance(source_entries, list) or not isinstance(common_entries, list):
            raise MaintenanceError("archive_manifest_invalid")
        if any(
            not isinstance(entry, dict) for entry in (*source_entries, *common_entries)
        ):
            raise MaintenanceError("archive_manifest_invalid")
        if any(entry.get("path") == ".git" for entry in source_entries):
            raise MaintenanceError("archive_manifest_git_metadata_invalid")
        common_by_path = {entry.get("path"): entry for entry in common_entries}
        gitdir = manifest["gitdir"]
        if (
            common_by_path.get(gitdir, {}).get("kind") != "directory"
            or common_by_path.get(f"{gitdir}/gitdir", {}).get("kind") != "file"
        ):
            raise MaintenanceError("archive_gitdir_invalid")
        for name in ("worktree.tar", "git-common.tar"):
            expected_entries = (
                source_entries if name == "worktree.tar" else common_entries
            )
            tar_file = _snapshot_archive_tar(
                receipt, name, manifest.get("archives", {}).get(name), expected_entries
            )
            if verified_tar_files is None:
                tar_file.close()
            else:
                verified_tar_files[name] = tar_file
        return manifest
    except MaintenanceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as exc:
        raise MaintenanceError("archive_manifest_invalid") from exc


def _open_tree(path: Path) -> tuple[int, os.stat_result, int]:
    try:
        fd = os.open(path, _TREE_FLAGS)
        info = os.fstat(fd)
        mount = _mount_id(fd)
    except OSError as exc:
        raise MaintenanceError("source_unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_gid != os.getegid()
    ):
        os.close(fd)
        raise MaintenanceError("foreign_source_owner")
    return fd, info, mount


def _validate_private_parent_chain(path: Path) -> None:
    for parent in reversed((path, *path.parents)):
        try:
            info = parent.stat(follow_symlinks=False)
        except OSError as exc:
            raise MaintenanceError("private_parent_unavailable") from exc
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise MaintenanceError("private_parent_untrusted")


def _allocated_bytes(root: Path) -> int:
    entries = _tree_manifest(root, skip_git=True)
    total = 0
    for entry in entries:
        if entry.get("kind") != "file":
            continue
        try:
            info = (root / entry["path"]).lstat()
        except OSError as exc:
            raise MaintenanceError("source_changed") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise MaintenanceError("source_changed")
        total += info.st_blocks * 512
    return total


def _run_tar_create(
    root_fd: int, output: Path, *, exclude_git: bool, lock_fd: int | None = None
) -> None:
    _tar_create(root_fd, output, exclude_git=exclude_git, lock_fd=lock_fd)


def _run_tar_extract(
    archive: Path,
    destination_fd: int,
    *,
    lock_fd: int | None = None,
    archive_fd: int | None = None,
) -> None:
    archive_path = str(archive) if archive_fd is None else f"/proc/self/fd/{archive_fd}"
    command = [
        "tar",
        "--extract",
        "--file",
        archive_path,
        "--directory",
        f"/proc/self/fd/{destination_fd}",
        "--no-same-owner",
        "--same-permissions",
        "--acls",
        "--xattrs",
        "--xattrs-include=*",
        "--sparse",
        "--delay-directory-restore",
    ]
    try:
        completed = subprocess.run(
            command,
            pass_fds=_maintenance_pass_fds(
                lock_fd,
                (destination_fd,)
                if archive_fd is None
                else (destination_fd, archive_fd),
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise MaintenanceError("tar_unavailable") from exc
    if completed.returncode:
        raise MaintenanceError("archive_extraction_failed")


def _verify_manifest_tree(
    root: Path,
    expected: list[dict[str, Any]],
    *,
    skip_git: bool,
    skip_names: frozenset[str] = frozenset(),
) -> None:
    actual = _tree_manifest(root, skip_git=skip_git, skip_names=skip_names)
    if actual != expected:
        raise MaintenanceError("archive_restore_manifest_mismatch")


def _verify_root_metadata(root_fd: int, expected: Mapping[str, Any]) -> None:
    info = os.fstat(root_fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != expected.get("mode")
        or info.st_uid != expected.get("uid")
        or info.st_gid != expected.get("gid")
        or info.st_mtime_ns != expected.get("mtime_ns")
        or _xattrs(root_fd) != expected.get("xattrs")
    ):
        raise MaintenanceError("archive_restore_root_metadata_mismatch")


def _git_status(
    path: Path,
    *,
    pass_fd: int | None = None,
    lock_fd: int | None = None,
) -> tuple[str, str, str]:
    inherited = _maintenance_pass_fds(lock_fd, () if pass_fd is None else (pass_fd,))
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_CONFIG_")
        and key
        not in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        }
    }
    environment.update(
        GIT_OPTIONAL_LOCKS="0",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
    )
    try:
        status = subprocess.run(
            [
                "git",
                "-C",
                str(path),
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--ignored=matching",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=inherited,
            env=environment,
        ).stdout
        head = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=inherited,
            env=environment,
        ).stdout.strip()
        index = subprocess.run(
            [
                "git",
                "-C",
                str(path),
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "index",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=inherited,
            env=environment,
        ).stdout.strip()
        return status, head, _digest_file(Path(index))
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "")
        raise MaintenanceError(f"git_restore_verification_failed:{detail}") from exc


def _remove_private_tree(
    parent_fd: int, name: str, expected_fd: int | None = None
) -> None:
    if not shutil.rmtree.avoids_symlink_attacks:
        raise MaintenanceError("safe_staging_cleanup_unavailable")
    child_fd = -1
    try:
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise MaintenanceError("staging_identity_invalid")
        child_fd = os.open(name, _TREE_FLAGS, dir_fd=parent_fd)
        opened = os.fstat(child_fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise MaintenanceError("staging_identity_changed")
        if expected_fd is not None:
            expected = os.fstat(expected_fd)
            if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
                raise MaintenanceError("staging_identity_changed")
        shutil.rmtree(name, dir_fd=parent_fd)
    except MaintenanceError:
        raise
    except OSError as exc:
        raise MaintenanceError("staging_cleanup_failed") from exc
    finally:
        if child_fd >= 0:
            os.close(child_fd)


def _archive_candidate(
    candidate: MaintenanceCandidate,
    *,
    policy: ProjectPolicy,
    lifecycle: WorktreeLifecycleStore,
    claim: object | None = None,
) -> ArchiveReceipt:
    if candidate.temporary:
        raise MaintenanceError("temporary_candidate_archive_unsupported")
    if (
        type(candidate) is not MaintenanceCandidate
        or not candidate.eligible
        or not isinstance(policy, ProjectPolicy)
        or not isinstance(lifecycle, WorktreeLifecycleStore)
        or type(candidate.binding) is not WorktreeBinding
    ):
        raise MaintenanceError("candidate_not_eligible")
    if claim is not None:
        try:
            lifecycle.assert_claim(claim)
        except Exception as exc:
            raise MaintenanceError("maintenance_claim_unavailable") from exc
    archive_root = policy.archive_root
    if not isinstance(archive_root, Path) or not archive_root.is_absolute():
        raise MaintenanceError("archive_path_invalid")
    if (
        candidate.archive_root is None
        or candidate.archive_root.resolve(strict=False)
        != archive_root.resolve(strict=False)
        or policy.archive_root.resolve(strict=False)
        != archive_root.resolve(strict=False)
    ):
        raise MaintenanceError("archive_path_unbound")
    source = candidate.source.resolve(strict=True)
    source_fd, source_info, _source_mount = _open_tree(source)
    source_identity = (source_info.st_dev, source_info.st_ino, _source_mount)
    try:
        policy_source = policy.source_root.resolve(strict=True)
        allowed_roots = tuple(
            root.resolve(strict=True) for root in policy.allowed_source_roots
        )
        current_entries = _tree_manifest(source, skip_git=True)
        current_manifest_digest = hashlib.sha256(
            _json_bytes(current_entries)
        ).hexdigest()
        allocated_now = _allocated_bytes(source)
    except (OSError, MaintenanceError) as exc:
        os.close(source_fd)
        raise MaintenanceError("candidate_source_unavailable") from exc
    if (
        policy_source != source
        or not any(source == root or root in source.parents for root in allowed_roots)
        or current_manifest_digest != candidate.source_manifest_sha256
        or allocated_now != candidate.allocated_bytes
    ):
        os.close(source_fd)
        raise MaintenanceError("candidate_stale_or_unbound")
    try:
        fresh_binding = lifecycle.binding_for_source(source)
        fresh_end = (
            lifecycle.last_use_ended_at(candidate.binding)
            if claim is None
            else lifecycle.last_use_ended_at_for_claim(candidate.binding, claim)
        )
        snapshot = lifecycle.snapshot()
    except Exception as exc:
        os.close(source_fd)
        raise MaintenanceError("candidate_lifecycle_unavailable") from exc
    if (
        fresh_binding != candidate.binding
        or fresh_end is None
        or fresh_end != candidate.last_use_ended_at
        or candidate.source_identity != source_identity
        or any(use.binding == candidate.binding for use in snapshot.active_uses)
        or any(
            active.candidate == candidate.binding
            and (claim is None or active.claim_id != getattr(claim, "claim_id", None))
            for active in snapshot.maintenance_claims
        )
    ):
        os.close(source_fd)
        raise MaintenanceError("candidate_stale_or_active")
    age = int(time.time()) - fresh_end
    if age < 0 or not (
        age >= policy.inactive_seconds
        or (
            candidate.allocated_bytes is not None
            and candidate.allocated_bytes >= policy.large_bytes
            and age >= policy.large_inactive_seconds
        )
    ):
        os.close(source_fd)
        raise MaintenanceError("candidate_below_threshold")
    common, gitdir_relative = _git_layout(source, candidate.binding)
    common_fd, common_info, common_mount = _open_tree(common)
    try:
        common_allocated = _allocated_bytes(common)
        available = shutil.disk_usage(archive_root.parent).free
    except (OSError, MaintenanceError) as exc:
        os.close(source_fd)
        os.close(common_fd)
        raise MaintenanceError("archive_space_unavailable") from exc
    required_bytes = 2 * (allocated_now + common_allocated) + 4 * 1024 * 1024
    if available < required_bytes:
        os.close(source_fd)
        os.close(common_fd)
        raise MaintenanceError("archive_space_unavailable")
    root_parent = archive_root.parent.resolve(strict=True)
    _validate_private_parent_chain(root_parent)
    parent_info = root_parent.stat(follow_symlinks=False)
    if (
        parent_info.st_uid != os.geteuid()
        or parent_info.st_gid != os.getegid()
        or parent_info.st_mode & 0o022
    ):
        os.close(source_fd)
        os.close(common_fd)
        raise MaintenanceError("archive_parent_untrusted")
    parent_fd = os.open(root_parent, _TREE_FLAGS)
    try:
        try:
            os.mkdir(archive_root.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise MaintenanceError("archive_root_unavailable") from exc
        root_fd = os.open(archive_root, _TREE_FLAGS)
        stage_fd = -1
        stage_name = ""
        stage_published = False
        try:
            root_info = os.fstat(root_fd)
            root_mount = _mount_id(root_fd)
            if (
                root_info.st_uid != os.geteuid()
                or root_info.st_gid != os.getegid()
                or stat.S_IMODE(root_info.st_mode) != 0o700
                or root_info.st_dev != parent_info.st_dev
                or root_info.st_dev != common_info.st_dev
                or root_mount != common_mount
            ):
                raise MaintenanceError("archive_root_untrusted")
            fcntl.flock(root_fd, fcntl.LOCK_EX)
            if claim is not None:
                lifecycle._bind_maintenance_archive_lock(claim, archive_root, root_fd)
            if shutil.disk_usage(root_parent).free < required_bytes:
                raise MaintenanceError("archive_space_unavailable")
            stage_name = f".stage-{secrets.token_hex(12)}"
            os.mkdir(stage_name, 0o700, dir_fd=root_fd)
            stage_fd = os.open(stage_name, _TREE_FLAGS, dir_fd=root_fd)
            stage_path = archive_root / stage_name
            try:
                source_entries = current_entries
                source_gitdir_fd = _open_directory_beneath(common_fd, gitdir_relative)
                try:
                    _validate_git_config_at(common_fd, "config", lock_fd=root_fd)
                    _validate_git_config_at(source_gitdir_fd, "config", lock_fd=root_fd)
                    _validate_git_config_at(
                        source_gitdir_fd, "config.worktree", lock_fd=root_fd
                    )
                finally:
                    os.close(source_gitdir_fd)
                git_status, git_head, git_index_sha256 = _git_status(
                    source, lock_fd=root_fd
                )
                common_entries = _tree_manifest(common)
                _run_tar_create(
                    source_fd,
                    stage_path / "worktree.tar",
                    exclude_git=True,
                    lock_fd=root_fd,
                )
                _run_tar_create(
                    common_fd,
                    stage_path / "git-common.tar",
                    exclude_git=False,
                    lock_fd=root_fd,
                )
                if _tree_manifest(source, skip_git=True) != source_entries:
                    raise MaintenanceError("source_changed_during_archive")
                if _tree_manifest(common) != common_entries:
                    raise MaintenanceError("git_common_changed_during_archive")
                source_now = os.fstat(source_fd)
                common_now = os.fstat(common_fd)
                if (source_now.st_dev, source_now.st_ino) != (
                    source_info.st_dev,
                    source_info.st_ino,
                ):
                    raise MaintenanceError("source_identity_changed")
                if (common_now.st_dev, common_now.st_ino) != (
                    common_info.st_dev,
                    common_info.st_ino,
                ):
                    raise MaintenanceError("git_common_identity_changed")
                manifest = {
                    "format": 1,
                    "source": str(source),
                    "source_device": source_info.st_dev,
                    "source_inode": source_info.st_ino,
                    "source_mode": stat.S_IMODE(source_info.st_mode),
                    "source_mtime_ns": source_info.st_mtime_ns,
                    "git_common_device": common_info.st_dev,
                    "git_common_inode": common_info.st_ino,
                    "gitdir": gitdir_relative,
                    "git_status": git_status,
                    "git_head": git_head,
                    "git_index_sha256": git_index_sha256,
                    "source_entries": source_entries,
                    "common_entries": common_entries,
                    "archives": {
                        "worktree.tar": _digest_file(stage_path / "worktree.tar"),
                        "git-common.tar": _digest_file(stage_path / "git-common.tar"),
                    },
                }
                manifest_bytes = _json_bytes(manifest)
                if len(manifest_bytes) > _MAX_MANIFEST_BYTES:
                    raise MaintenanceError("archive_manifest_oversize")
                manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
                count = len(source_entries) + len(common_entries)
                _write_bytes(stage_path / "manifest.json", manifest_bytes)
                _write_bytes(
                    stage_path / "receipt.json",
                    _json_bytes(
                        {"manifest_sha256": manifest_digest, "entry_count": count}
                    ),
                )
                os.fsync(stage_fd)
                stage_identity = os.fstat(stage_fd)
            except Exception:
                raise
            temporary_receipt = ArchiveReceipt(
                archive=stage_path,
                manifest_sha256=manifest_digest,
                entry_count=count,
                archive_device=stage_identity.st_dev,
                archive_inode=stage_identity.st_ino,
            )
            verify_name = f".verify-{secrets.token_hex(12)}"
            verify_path = archive_root / verify_name
            try:
                _restore_archive_unlocked(
                    temporary_receipt, verify_path, lock_fd=root_fd
                )
                _remove_private_tree(root_fd, verify_name)
            except Exception:
                raise
            final_name = f"archive-{source_info.st_dev:x}-{source_info.st_ino:x}-{secrets.token_hex(8)}"
            LocalFleetHomeV2Filesystem().rename_noreplace_at(
                root_fd, stage_name, final_name
            )
            stage_published = True
            LocalFleetHomeV2Filesystem.fsync_directory(root_fd)
            final_info = os.stat(final_name, dir_fd=root_fd, follow_symlinks=False)
            return ArchiveReceipt(
                archive=archive_root / final_name,
                manifest_sha256=manifest_digest,
                entry_count=count,
                archive_device=final_info.st_dev,
                archive_inode=final_info.st_ino,
            )
        finally:
            if stage_fd >= 0:
                if not stage_published:
                    _remove_private_tree(root_fd, stage_name, stage_fd)
                os.close(stage_fd)
            os.close(root_fd)
    finally:
        os.close(parent_fd)
        os.close(source_fd)
        os.close(common_fd)


def archive_temporary_candidate(
    candidate: MaintenanceCandidate,
    *,
    policy: ProjectPolicy,
    lifecycle: WorktreeLifecycleStore,
    claim: object | None = None,
) -> ArchiveReceipt:
    """Archive one ended G5 temp producer without interpreting it as a worktree."""
    if (
        type(candidate) is not MaintenanceCandidate
        or not candidate.eligible
        or not candidate.temporary
        or type(candidate.binding) is not WorktreeBinding
        or not isinstance(policy, ProjectPolicy)
        or not isinstance(lifecycle, WorktreeLifecycleStore)
    ):
        raise MaintenanceError("temporary_candidate_not_eligible")
    if claim is not None:
        try:
            lifecycle.assert_claim(claim)
        except Exception as exc:
            raise MaintenanceError("maintenance_claim_unavailable") from exc
        if getattr(claim, "candidate", None) != candidate.binding:
            raise MaintenanceError("maintenance_claim_binding_mismatch")
    archive_root = policy.archive_root.resolve(strict=False)
    if (
        candidate.archive_root is None
        or candidate.archive_root.resolve(strict=False) != archive_root
    ):
        raise MaintenanceError("archive_path_unbound")
    source = candidate.source.resolve(strict=True)
    source_fd, source_info, source_mount = _open_tree(source)
    try:
        current_entries = _tree_manifest(source)
        digest = hashlib.sha256(_json_bytes(current_entries)).hexdigest()
        allocated = _allocated_bytes(source)
        producer = next(
            (
                item
                for item in lifecycle.temporary_producers(
                    candidate.binding, claim=claim
                )
                if item.get("path") == str(source)
            ),
            None,
        )
        snapshot = lifecycle.snapshot()
    except Exception as exc:
        os.close(source_fd)
        raise MaintenanceError("temporary_producer_unavailable") from exc
    current_identity = (source_info.st_dev, source_info.st_ino, source_mount)
    if (
        producer is None
        or producer.get("ended_at") != candidate.last_use_ended_at
        or candidate.source_identity != current_identity
        or candidate.source_manifest_sha256 != digest
        or candidate.allocated_bytes != allocated
        or any(use.binding == candidate.binding for use in snapshot.active_uses)
        or any(
            active.candidate == candidate.binding
            and (claim is None or active.claim_id != getattr(claim, "claim_id", None))
            for active in snapshot.maintenance_claims
        )
        or int(time.time()) - int(producer["ended_at"]) < policy.temporary_age_seconds
    ):
        os.close(source_fd)
        raise MaintenanceError("temporary_candidate_stale_or_active")
    project_fd = common_fd = -1
    try:
        project_fd, project_info, project_mount = _open_tree(
            policy.source_root.resolve(strict=True)
        )
        common_fd, common_info, common_mount = _open_tree(
            candidate.binding.git_common_directory
        )
        available = shutil.disk_usage(archive_root.parent).free
    except (OSError, MaintenanceError) as exc:
        if common_fd >= 0:
            os.close(common_fd)
        if project_fd >= 0:
            os.close(project_fd)
        os.close(source_fd)
        raise MaintenanceError("archive_space_unavailable") from exc
    try:
        required = 2 * allocated + 4 * 1024 * 1024
        if available < required:
            raise MaintenanceError("archive_space_unavailable")
        parent = archive_root.parent.resolve(strict=True)
        _validate_private_parent_chain(parent)
        parent_info = parent.stat(follow_symlinks=False)
        if (
            parent_info.st_uid != os.geteuid()
            or parent_info.st_gid != os.getegid()
            or parent_info.st_mode & 0o022
            or parent_info.st_dev != project_info.st_dev
            or common_info.st_dev != project_info.st_dev
            or common_mount != project_mount
        ):
            raise MaintenanceError("archive_filesystem_untrusted")
        parent_fd = os.open(parent, _TREE_FLAGS)
        try:
            if _mount_id(parent_fd) != project_mount:
                raise MaintenanceError("archive_filesystem_untrusted")
            try:
                os.mkdir(archive_root.name, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
            root_fd = os.open(archive_root, _TREE_FLAGS)
            stage_fd = -1
            published = False
            stage_name = f".stage-{secrets.token_hex(12)}"
            try:
                root_info = os.fstat(root_fd)
                if (
                    root_info.st_uid != os.geteuid()
                    or root_info.st_gid != os.getegid()
                    or stat.S_IMODE(root_info.st_mode) != 0o700
                    or root_info.st_dev != project_info.st_dev
                    or _mount_id(root_fd) != project_mount
                ):
                    raise MaintenanceError("archive_root_untrusted")
                fcntl.flock(root_fd, fcntl.LOCK_EX)
                if claim is not None:
                    lifecycle._bind_maintenance_archive_lock(
                        claim, archive_root, root_fd
                    )
                if _tree_manifest(source) != current_entries:
                    raise MaintenanceError("source_changed_during_archive")
                os.mkdir(stage_name, 0o700, dir_fd=root_fd)
                stage_fd = os.open(stage_name, _TREE_FLAGS, dir_fd=root_fd)
                stage_path = archive_root / stage_name
                _run_tar_create(
                    source_fd,
                    stage_path / "temporary.tar",
                    exclude_git=False,
                    lock_fd=root_fd,
                )
                if _tree_manifest(source) != current_entries:
                    raise MaintenanceError("source_changed_during_archive")
                source_now = source.stat(follow_symlinks=False)
                if (
                    (source_now.st_dev, source_now.st_ino)
                    != (source_info.st_dev, source_info.st_ino)
                    or source.resolve(strict=True) != source
                    or _mount_id(source_fd) != source_mount
                ):
                    raise MaintenanceError("temporary_source_identity_changed")
                manifest = {
                    "format": 1,
                    "kind": "temporary_tree",
                    "source": str(source),
                    "source_device": source_info.st_dev,
                    "source_inode": source_info.st_ino,
                    "source_mount_id": source_mount,
                    "producer_lease_id": producer["lease_id"],
                    "producer_ended_at": producer["ended_at"],
                    "source_mode": stat.S_IMODE(source_info.st_mode),
                    "source_entries": current_entries,
                    "archives": {
                        "temporary.tar": _digest_file(stage_path / "temporary.tar")
                    },
                }
                manifest_bytes = _json_bytes(manifest)
                if len(manifest_bytes) > _MAX_MANIFEST_BYTES:
                    raise MaintenanceError("archive_manifest_oversize")
                manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
                count = len(current_entries)
                _write_bytes(stage_path / "manifest.json", manifest_bytes)
                _write_bytes(
                    stage_path / "receipt.json",
                    _json_bytes(
                        {"manifest_sha256": manifest_digest, "entry_count": count}
                    ),
                )
                os.fsync(stage_fd)
                stage_info = os.fstat(stage_fd)
                temporary_receipt = ArchiveReceipt(
                    stage_path,
                    manifest_digest,
                    count,
                    stage_info.st_dev,
                    stage_info.st_ino,
                )
                verify_path = archive_root / f".verify-{secrets.token_hex(12)}"
                _restore_archive_unlocked(
                    temporary_receipt, verify_path, lock_fd=root_fd
                )
                verify_fd = os.open(verify_path, _TREE_FLAGS)
                try:
                    _remove_private_tree(root_fd, verify_path.name, verify_fd)
                finally:
                    os.close(verify_fd)
                try:
                    source_before_publish = source.stat(follow_symlinks=False)
                    fresh_entries = _tree_manifest(source)
                    fresh_producer = next(
                        (
                            item
                            for item in lifecycle.temporary_producers(
                                candidate.binding, claim=claim
                            )
                            if item.get("path") == str(source)
                        ),
                        None,
                    )
                    fresh_snapshot = lifecycle.snapshot()
                except Exception as exc:
                    raise MaintenanceError(
                        "temporary_source_changed_before_publish"
                    ) from exc
                if (
                    (source_before_publish.st_dev, source_before_publish.st_ino)
                    != (source_info.st_dev, source_info.st_ino)
                    or _mount_id(source_fd) != source_mount
                    or source.resolve(strict=True) != source
                    or fresh_entries != current_entries
                    or fresh_producer is None
                    or fresh_producer.get("ended_at") != producer.get("ended_at")
                    or any(
                        use.binding == candidate.binding
                        for use in fresh_snapshot.active_uses
                    )
                    or any(
                        active.candidate == candidate.binding
                        and (
                            claim is None
                            or active.claim_id != getattr(claim, "claim_id", None)
                        )
                        for active in fresh_snapshot.maintenance_claims
                    )
                ):
                    raise MaintenanceError("temporary_source_changed_before_publish")
                final_name = f"temporary-{source_info.st_dev:x}-{source_info.st_ino:x}-{secrets.token_hex(8)}"
                LocalFleetHomeV2Filesystem().rename_noreplace_at(
                    root_fd, stage_name, final_name
                )
                published = True
                LocalFleetHomeV2Filesystem.fsync_directory(root_fd)
                final_info = os.stat(final_name, dir_fd=root_fd, follow_symlinks=False)
                return ArchiveReceipt(
                    archive_root / final_name,
                    manifest_digest,
                    count,
                    final_info.st_dev,
                    final_info.st_ino,
                )
            finally:
                if stage_fd >= 0:
                    if not published:
                        _remove_private_tree(root_fd, stage_name, stage_fd)
                    os.close(stage_fd)
                os.close(root_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.close(project_fd)
        os.close(common_fd)
        os.close(source_fd)


def restore_archive(archive: ArchiveReceipt, destination: Path) -> Path:
    """Restore under an exclusive lock on the project archive directory."""
    if not isinstance(archive, ArchiveReceipt) or not isinstance(archive.archive, Path):
        raise MaintenanceError("restore_arguments_invalid")
    lock_fd = -1
    try:
        lock_fd = os.open(archive.archive.parent, _TREE_FLAGS)
        info = os.fstat(lock_fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise MaintenanceError("archive_root_untrusted")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        return _restore_archive_unlocked(archive, destination, lock_fd=lock_fd)
    except OSError as exc:
        raise MaintenanceError("archive_lock_unavailable") from exc
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)


def _recover_maintenance_claim_under_archive_lock(
    lifecycle: WorktreeLifecycleStore,
    binding: WorktreeBinding,
    *,
    now: int,
) -> object:
    """Fence a dead archive writer only after its archive-root lock is exclusive."""
    if (
        not isinstance(lifecycle, WorktreeLifecycleStore)
        or type(binding) is not WorktreeBinding
    ):
        raise MaintenanceError("maintenance_recovery_arguments_invalid")
    lock_fd = -1
    try:
        archive_root, expected_device, expected_inode, expected_mount = (
            lifecycle._maintenance_archive_lock_for_recovery(binding)
        )
        canonical = archive_root.resolve(strict=True)
        if canonical != archive_root:
            raise MaintenanceError("archive_root_untrusted")
        lock_fd = os.open(archive_root, _TREE_FLAGS)
        info = os.fstat(lock_fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or (info.st_dev, info.st_ino) != (expected_device, expected_inode)
            or _mount_id(lock_fd) != expected_mount
        ):
            raise MaintenanceError("archive_root_untrusted")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        current_root = lifecycle._maintenance_archive_lock_for_recovery(binding)
        if current_root != (
            archive_root,
            expected_device,
            expected_inode,
            expected_mount,
        ):
            raise MaintenanceError("maintenance_archive_lock_changed")
        return lifecycle.recover_maintenance_claim(binding, now=now)
    except MaintenanceError:
        raise
    except (OSError, WorktreeLifecycleError) as exc:
        raise MaintenanceError("maintenance_recovery_unavailable") from exc
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)


def recover_temporary_source_after_hold(
    lifecycle: WorktreeLifecycleStore, claim: object
) -> Path:
    """Restore one intact temporary producer from a held, fenced operation."""
    if not isinstance(lifecycle, WorktreeLifecycleStore):
        raise MaintenanceError("maintenance_recovery_arguments_invalid")
    try:
        operation = lifecycle.maintenance_operation_for_recovery(claim)
        binding = getattr(claim, "candidate", None)
        if (
            type(binding) is not WorktreeBinding
            or operation.get("operation_kind") != "temporary"
        ):
            raise MaintenanceError("maintenance_recovery_not_temporary")
        lock_path, expected_device, expected_inode, expected_mount = (
            lifecycle._maintenance_archive_lock_for_recovery(binding)
        )
        archive = Path(str(operation["archive_path"]))
        if archive.parent != lock_path:
            raise MaintenanceError("maintenance_archive_lock_mismatch")
        lock_fd = os.open(lock_path, _TREE_FLAGS)
    except MaintenanceError:
        raise
    except Exception as exc:
        raise MaintenanceError("maintenance_recovery_unavailable") from exc
    try:
        lock_info = os.fstat(lock_fd)
        if (lock_info.st_dev, lock_info.st_ino) != (
            expected_device,
            expected_inode,
        ) or _mount_id(lock_fd) != expected_mount:
            raise MaintenanceError("maintenance_archive_lock_changed")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if lifecycle._maintenance_archive_lock_for_recovery(binding) != (
            lock_path,
            expected_device,
            expected_inode,
            expected_mount,
        ):
            raise MaintenanceError("maintenance_archive_lock_changed")
        archive_info = archive.lstat()
        if archive_info.st_dev != operation.get(
            "archive_device"
        ) or archive_info.st_ino != operation.get("archive_inode"):
            raise MaintenanceError("maintenance_archive_identity_changed")
        receipt = ArchiveReceipt(
            archive=archive,
            manifest_sha256=str(operation.get("archive_manifest_sha256")),
            entry_count=0,
            archive_device=archive_info.st_dev,
            archive_inode=archive_info.st_ino,
        )
        manifest = _read_archive_manifest(receipt)
        if (
            manifest.get("kind") != "temporary_tree"
            or manifest.get("source") != operation.get("temporary_source_path")
            or manifest.get("source_device") != operation.get("temporary_source_device")
            or manifest.get("source_inode") != operation.get("temporary_source_inode")
            or manifest.get("source_mount_id")
            != operation.get("temporary_source_mount_id")
            or manifest.get("producer_lease_id")
            != operation.get("temporary_producer_lease_id")
        ):
            raise MaintenanceError("maintenance_receipt_binding_mismatch")
        receipt = ArchiveReceipt(
            archive=archive,
            manifest_sha256=receipt.manifest_sha256,
            entry_count=len(manifest["source_entries"]),
            archive_device=archive_info.st_dev,
            archive_inode=archive_info.st_ino,
        )
        source = Path(str(operation["temporary_source_path"]))
        if not source.is_absolute() or source.resolve(strict=False) != source:
            raise MaintenanceError("maintenance_source_restore_mismatch")
        parent_fd = os.open(source.parent, _TREE_FLAGS)
        quarantine_root_fd = quarantine_fd = source_fd = -1
        filesystem = LocalFleetHomeV2Filesystem()
        try:
            try:
                source_fd = os.open(source.name, _TREE_FLAGS, dir_fd=parent_fd)
            except FileNotFoundError:
                source_fd = -1
            try:
                quarantine_root_fd = os.open(
                    ".hive-quarantine", _TREE_FLAGS, dir_fd=parent_fd
                )
            except FileNotFoundError:
                quarantine_root_fd = -1
            if quarantine_root_fd >= 0:
                quarantine_root_info = os.fstat(quarantine_root_fd)
                if (
                    quarantine_root_info.st_uid != os.geteuid()
                    or stat.S_IMODE(quarantine_root_info.st_mode) != 0o700
                    or quarantine_root_info.st_dev
                    != operation.get("temporary_source_device")
                    or _mount_id(quarantine_root_fd)
                    != operation.get("temporary_source_mount_id")
                ):
                    raise MaintenanceError("maintenance_quarantine_identity_changed")
            try:
                if quarantine_root_fd >= 0:
                    quarantine_fd = os.open(
                        claim.claim_id, _TREE_FLAGS, dir_fd=quarantine_root_fd
                    )
            except FileNotFoundError:
                quarantine_fd = -1
            if source_fd >= 0 and quarantine_fd >= 0:
                raise MaintenanceError("maintenance_source_restore_ambiguous")
            if source_fd >= 0:
                info = os.fstat(source_fd)
                if (info.st_dev, info.st_ino) != (
                    operation.get("temporary_source_device"),
                    operation.get("temporary_source_inode"),
                ) or _mount_id(source_fd) != operation.get("temporary_source_mount_id"):
                    raise MaintenanceError("maintenance_source_restore_mismatch")
                _verify_manifest_tree(
                    source, manifest["source_entries"], skip_git=False
                )
            else:
                if quarantine_root_fd < 0 or quarantine_fd < 0:
                    raise MaintenanceError("maintenance_source_restore_unavailable")
                source_mount = int(operation["temporary_source_mount_id"])
                q_info = os.fstat(quarantine_fd)
                if (
                    q_info.st_uid != os.geteuid()
                    or stat.S_IMODE(q_info.st_mode) != 0o700
                    or q_info.st_dev != operation.get("temporary_source_device")
                    or _mount_id(quarantine_fd) != source_mount
                ):
                    raise MaintenanceError("maintenance_quarantine_identity_changed")
                moved_name = "temporary"
                moved_fd = os.open(moved_name, _TREE_FLAGS, dir_fd=quarantine_fd)
                try:
                    moved_info = os.fstat(moved_fd)
                    if (moved_info.st_dev, moved_info.st_ino) != (
                        operation.get("temporary_source_device"),
                        operation.get("temporary_source_inode"),
                    ):
                        raise MaintenanceError(
                            "maintenance_quarantine_identity_changed"
                        )
                    _verify_manifest_tree(
                        source.parent
                        / ".hive-quarantine"
                        / claim.claim_id
                        / moved_name,
                        manifest["source_entries"],
                        skip_git=False,
                    )
                finally:
                    os.close(moved_fd)
                try:
                    os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise MaintenanceError("maintenance_source_restore_ambiguous")
                filesystem.rename_noreplace_between_at(
                    quarantine_fd, moved_name, parent_fd, source.name
                )
                filesystem.fsync_directory(quarantine_fd)
                filesystem.fsync_directory(parent_fd)
                os.close(quarantine_fd)
                quarantine_fd = -1
                os.rmdir(claim.claim_id, dir_fd=quarantine_root_fd)
                filesystem.fsync_directory(quarantine_root_fd)
            lifecycle.record_maintenance_source_restored(claim, receipt)
            lifecycle.finish_maintenance(claim, outcome="source_restored")
            return source
        finally:
            for descriptor in (source_fd, quarantine_fd, quarantine_root_fd, parent_fd):
                if descriptor >= 0:
                    os.close(descriptor)
    except MaintenanceError:
        raise
    except Exception as exc:
        raise MaintenanceError("maintenance_recovery_unavailable") from exc
    finally:
        os.close(lock_fd)


def _restore_archive_unlocked(
    archive: ArchiveReceipt, destination: Path, *, lock_fd: int | None = None
) -> Path:
    """Snapshot and verify archive members before restoring from those same bytes."""
    if (
        not isinstance(archive, ArchiveReceipt)
        or not isinstance(destination, Path)
        or not destination.is_absolute()
    ):
        raise MaintenanceError("restore_arguments_invalid")
    verified_tar_files: dict[str, Any] = {}
    try:
        manifest = _read_archive_manifest(
            archive, verified_tar_files=verified_tar_files
        )
        if archive.entry_count != len(manifest.get("source_entries", [])) + len(
            manifest.get("common_entries", [])
        ):
            raise MaintenanceError("archive_entry_count_mismatch")
        if manifest.get("kind") == "temporary_tree":
            return _restore_temporary_archive_unlocked(
                archive,
                destination,
                manifest,
                tar_file=verified_tar_files["temporary.tar"],
                lock_fd=lock_fd,
            )
        return _restore_archive_payload_unlocked(
            archive,
            destination,
            manifest=manifest,
            verified_tar_files=verified_tar_files,
            lock_fd=lock_fd,
        )
    finally:
        for tar_file in verified_tar_files.values():
            tar_file.close()


def _restore_archive_payload_unlocked(
    archive: ArchiveReceipt,
    destination: Path,
    *,
    manifest: Mapping[str, Any],
    verified_tar_files: Mapping[str, Any],
    lock_fd: int | None,
) -> Path:
    """Restore a validated linked-worktree bundle from private tar snapshots."""
    if archive.entry_count != len(manifest.get("source_entries", [])) + len(
        manifest.get("common_entries", [])
    ):
        raise MaintenanceError("archive_entry_count_mismatch")
    parent = destination.parent.resolve(strict=True)
    _validate_private_parent_chain(parent)
    restore_bytes = sum(
        sum(extent[1] for extent in entry.get("sparse_extents", []))
        for entry in (*manifest["source_entries"], *manifest["common_entries"])
        if entry.get("kind") == "file"
    )
    if shutil.disk_usage(parent).free < restore_bytes + 4 * 1024 * 1024:
        raise MaintenanceError("restore_space_unavailable")
    parent_info = parent.stat(follow_symlinks=False)
    if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
        raise MaintenanceError("restore_parent_untrusted")
    parent_fd = os.open(parent, _TREE_FLAGS)
    stage_name = f".restore-{secrets.token_hex(12)}"
    stage_fd = -1
    payload_fd = -1
    common_fd = -1
    gitdir_fd = -1
    try:
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise MaintenanceError("restore_destination_exists")
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
        stage_fd = os.open(stage_name, _TREE_FLAGS, dir_fd=parent_fd)
        stage_path = Path(f"/proc/self/fd/{stage_fd}")
        worktree_name = "worktree"
        common_name = "git-common"
        os.mkdir(worktree_name, 0o700, dir_fd=stage_fd)
        payload_fd = os.open(worktree_name, _TREE_FLAGS, dir_fd=stage_fd)
        payload_path = stage_path / worktree_name
        _run_tar_extract(
            archive.archive / "worktree.tar",
            payload_fd,
            lock_fd=lock_fd,
            archive_fd=verified_tar_files["worktree.tar"].fileno(),
        )
        os.mkdir(common_name, 0o700, dir_fd=stage_fd)
        common_fd = os.open(common_name, _TREE_FLAGS, dir_fd=stage_fd)
        common_path = stage_path / common_name
        try:
            _run_tar_extract(
                archive.archive / "git-common.tar",
                common_fd,
                lock_fd=lock_fd,
                archive_fd=verified_tar_files["git-common.tar"].fileno(),
            )
            _verify_manifest_tree(
                payload_path, manifest["source_entries"], skip_git=True
            )
            _verify_manifest_tree(
                common_path, manifest["common_entries"], skip_git=False
            )
            gitdir_fd = _open_directory_beneath(common_fd, manifest["gitdir"])
            _validate_git_config_at(common_fd, "config", lock_fd=lock_fd)
            _validate_git_config_at(gitdir_fd, "config", lock_fd=lock_fd)
            _validate_git_config_at(gitdir_fd, "config.worktree", lock_fd=lock_fd)
            _write_at(
                gitdir_fd,
                "gitdir",
                str(destination / worktree_name / ".git") + "\n",
                create=False,
            )
            _write_at(
                payload_fd,
                ".git",
                f"gitdir: ../{common_name}/{manifest['gitdir']}\n",
                create=True,
            )
        except OSError as exc:
            raise MaintenanceError("archive_staging_path_invalid") from exc
        status, head, index_digest = _git_status(
            payload_path, pass_fd=stage_fd, lock_fd=lock_fd
        )
        if (
            status != manifest.get("git_status")
            or head != manifest.get("git_head")
            or index_digest != manifest.get("git_index_sha256")
        ):
            raise MaintenanceError(
                f"git_restore_verification_failed:{status!r}:{manifest.get('git_status')!r}:"
                f"{head!r}:{manifest.get('git_head')!r}:"
                f"{index_digest!r}:{manifest.get('git_index_sha256')!r}"
            )
        os.chmod(payload_fd, manifest["source_mode"])
        os.utime(
            payload_path,
            ns=(manifest["source_mtime_ns"], manifest["source_mtime_ns"]),
            follow_symlinks=False,
        )
        os.fsync(payload_fd)
        os.fsync(stage_fd)
        source_root_entry = next(
            entry for entry in manifest["source_entries"] if entry.get("path") == "."
        )
        common_root_entry = next(
            entry for entry in manifest["common_entries"] if entry.get("path") == "."
        )
        _verify_root_metadata(payload_fd, source_root_entry)
        _verify_root_metadata(common_fd, common_root_entry)
        stage_identity = os.fstat(stage_fd)
        LocalFleetHomeV2Filesystem().rename_noreplace_at(
            parent_fd, stage_name, destination.name
        )
        LocalFleetHomeV2Filesystem.fsync_directory(parent_fd)
        published = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        if (published.st_dev, published.st_ino) != (
            stage_identity.st_dev,
            stage_identity.st_ino,
        ):
            raise MaintenanceError("restore_publication_mismatch")
        return destination / worktree_name
    finally:
        if gitdir_fd >= 0:
            os.close(gitdir_fd)
        if common_fd >= 0:
            os.close(common_fd)
        if payload_fd >= 0:
            os.close(payload_fd)
        if stage_fd >= 0:
            _remove_private_tree(parent_fd, stage_name, stage_fd)
            os.close(stage_fd)
        os.close(parent_fd)


def _restore_temporary_archive_unlocked(
    archive: ArchiveReceipt,
    destination: Path,
    manifest: Mapping[str, Any],
    *,
    tar_file: Any,
    lock_fd: int | None,
) -> Path:
    parent = destination.parent.resolve(strict=True)
    _validate_private_parent_chain(parent)
    entries = manifest["source_entries"]
    if (
        shutil.disk_usage(parent).free
        < sum(entry.get("size", 0) for entry in entries if entry.get("kind") == "file")
        + 4 * 1024 * 1024
    ):
        raise MaintenanceError("restore_space_unavailable")
    parent_fd = os.open(parent, _TREE_FLAGS)
    stage_name = f".restore-{secrets.token_hex(12)}"
    stage_fd = -1
    published = False
    try:
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise MaintenanceError("restore_destination_exists")
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
        stage_fd = os.open(stage_name, _TREE_FLAGS, dir_fd=parent_fd)
        _run_tar_extract(
            archive.archive / "temporary.tar",
            stage_fd,
            lock_fd=lock_fd,
            archive_fd=tar_file.fileno(),
        )
        _verify_manifest_tree(parent / stage_name, entries, skip_git=False)
        root = next((entry for entry in entries if entry.get("path") == "."), None)
        if root is None:
            raise MaintenanceError("archive_manifest_invalid")
        os.fchmod(stage_fd, root["mode"])
        _verify_root_metadata(stage_fd, root)
        os.fsync(stage_fd)
        stage_identity = os.fstat(stage_fd)
        LocalFleetHomeV2Filesystem().rename_noreplace_at(
            parent_fd, stage_name, destination.name
        )
        published = True
        LocalFleetHomeV2Filesystem.fsync_directory(parent_fd)
        final = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        if (final.st_dev, final.st_ino) != (
            stage_identity.st_dev,
            stage_identity.st_ino,
        ):
            raise MaintenanceError("restore_publication_mismatch")
        return destination
    finally:
        if stage_fd >= 0:
            if not published:
                _remove_private_tree(parent_fd, stage_name, stage_fd)
            os.close(stage_fd)
        os.close(parent_fd)


def scan_candidates(
    projects: tuple[ProjectPolicy, ...], lifecycle: object, *, now: int
) -> tuple[MaintenanceCandidate, ...]:
    """Preview only attested, inactive worktrees with measured age and size."""
    result = []
    for policy in projects:
        source = policy.source_root
        reasons = []
        binding = None
        ended_at = None
        allocated = None
        identity = None
        source_manifest_digest = None
        try:
            canonical = source.resolve(strict=True)
            info = canonical.stat(follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                reasons.append("source_not_directory")
            allowed = any(
                canonical == root.resolve(strict=True)
                or root.resolve(strict=True) in canonical.parents
                for root in policy.allowed_source_roots
            )
            if not allowed:
                reasons.append("source_outside_allowed_roots")
        except OSError:
            canonical = source
            reasons.append("source_unavailable")
        archive_root = policy.archive_root.resolve(strict=False)
        if canonical == archive_root or archive_root in canonical.parents:
            reasons.append("archive_path_excluded")
        try:
            binding = lifecycle.binding_for_source(canonical)
            if binding is None or binding.canonical_source_path != canonical:
                reasons.append("worktree_origin_unattested")
            else:
                ended_at = lifecycle.last_use_ended_at(binding)
                if ended_at is None:
                    reasons.append("runtime_end_evidence_unavailable")
                snapshot = lifecycle.snapshot()
                if any(use.binding == binding for use in snapshot.active_uses):
                    reasons.append("worktree_in_use")
                if any(
                    claim.candidate == binding for claim in snapshot.maintenance_claims
                ):
                    reasons.append("maintenance_claim_active")
                _git_layout(canonical, binding)
                entries = _tree_manifest(canonical, skip_git=True)
                source_manifest_digest = hashlib.sha256(
                    _json_bytes(entries)
                ).hexdigest()
                allocated = _allocated_bytes(canonical)
                common = binding.git_common_directory
                _tree_manifest(common)
                source_fd, source_info, source_mount = _open_tree(canonical)
                os.close(source_fd)
                identity = (source_info.st_dev, source_info.st_ino, source_mount)
                if ended_at is not None:
                    age = now - ended_at
                    if age < 0:
                        reasons.append("runtime_end_time_in_future")
                    elif age >= policy.inactive_seconds:
                        reasons.append("inactive_30_days")
                    elif (
                        allocated >= policy.large_bytes
                        and age >= policy.large_inactive_seconds
                    ):
                        reasons.append("large_inactive_7_days")
                    else:
                        reasons.append("below_inactivity_threshold")
        except Exception as exc:
            del exc
            reasons.append("lifecycle_or_source_unavailable")
        threshold_reasons = {"inactive_30_days", "large_inactive_7_days"}
        eligible = any(reason in threshold_reasons for reason in reasons) and not any(
            reason not in threshold_reasons | {"below_inactivity_threshold"}
            for reason in reasons
        )
        if eligible:
            reasons.append("eligible_for_archive_review")
        result.append(
            MaintenanceCandidate(
                source=canonical,
                reasons=tuple(reasons),
                eligible=eligible,
                archive_root=archive_root,
                binding=binding,
                last_use_ended_at=ended_at,
                allocated_bytes=allocated,
                source_identity=identity,
                source_manifest_sha256=source_manifest_digest,
            )
        )
        if binding is not None:
            try:
                lifecycle_snapshot = lifecycle.snapshot()
                binding_busy = any(
                    use.binding == binding for use in lifecycle_snapshot.active_uses
                ) or any(
                    claim.candidate == binding
                    for claim in lifecycle_snapshot.maintenance_claims
                )
                if not binding_busy:
                    for producer in lifecycle.temporary_producers(binding):
                        temp_path = Path(str(producer["path"]))
                        ended_at = producer.get("ended_at")
                        if type(ended_at) is not int or now < ended_at:
                            continue
                        age = now - ended_at
                        if age < policy.temporary_age_seconds:
                            continue
                        try:
                            entries = _tree_manifest(temp_path)
                            digest = hashlib.sha256(_json_bytes(entries)).hexdigest()
                            temp_info = temp_path.stat(follow_symlinks=False)
                            temp_mount = int(producer["mount_id"])
                            temp_identity = (
                                temp_info.st_dev,
                                temp_info.st_ino,
                                temp_mount,
                            )
                            reasons = (
                                "temporary_producer_7_days",
                                "eligible_for_archive_review",
                            )
                            result.append(
                                MaintenanceCandidate(
                                    source=temp_path,
                                    reasons=reasons,
                                    eligible=True,
                                    archive_root=archive_root,
                                    binding=binding,
                                    last_use_ended_at=ended_at,
                                    allocated_bytes=_allocated_bytes(temp_path),
                                    source_identity=temp_identity,
                                    source_manifest_sha256=digest,
                                    temporary=True,
                                )
                            )
                        except (OSError, MaintenanceError, ValueError, TypeError):
                            continue
            except (WorktreeLifecycleError, OSError, AttributeError, TypeError):
                pass
    return tuple(result)


def apply_candidate(
    candidate: MaintenanceCandidate,
    lifecycle: WorktreeLifecycleStore,
    *,
    policy: ProjectPolicy,
    claim: object,
    now: int,
) -> ArchiveReceipt:
    """Archive, restore-verify, then remove only the claimed linked worktree."""
    del now
    try:
        lifecycle.assert_claim(claim)
    except Exception as exc:
        raise MaintenanceError("maintenance_claim_unavailable") from exc
    if getattr(claim, "candidate", None) != candidate.binding:
        raise MaintenanceError("maintenance_claim_binding_mismatch")
    lifecycle.advance_maintenance_phase(claim, phase="archiving")
    try:
        if candidate.temporary:
            receipt = archive_temporary_candidate(
                candidate, policy=policy, lifecycle=lifecycle, claim=claim
            )
        else:
            receipt = _archive_candidate(
                candidate, policy=policy, lifecycle=lifecycle, claim=claim
            )
        lifecycle.record_maintenance_archive(claim, receipt)
        manifest = _read_archive_manifest(receipt)
        if candidate.temporary:
            _quarantine_and_remove_claimed_temporary_source(
                candidate, claim, receipt, manifest, lifecycle
            )
        else:
            _quarantine_and_remove_claimed_source(
                candidate, claim, receipt, manifest, lifecycle
            )
        return receipt
    except Exception:
        try:
            lifecycle.hold_maintenance_claim(claim)
        except Exception:
            pass
        raise


def _quarantine_and_remove_claimed_temporary_source(
    candidate: MaintenanceCandidate,
    claim: object,
    receipt: ArchiveReceipt,
    manifest: Mapping[str, Any],
    lifecycle: WorktreeLifecycleStore,
) -> None:
    """Remove one ended producer only through its persisted claim and origin."""
    if not candidate.temporary or candidate.binding is None:
        raise MaintenanceError("maintenance_claim_binding_mismatch")
    operation = lifecycle.maintenance_operation_for_claim(claim)
    source = candidate.source
    if (
        operation.get("operation_kind") != "temporary"
        or operation.get("phase") != "archive_verified"
        or operation.get("temporary_source_path") != str(source)
        or operation.get("temporary_source_device") != manifest.get("source_device")
        or operation.get("temporary_source_inode") != manifest.get("source_inode")
        or operation.get("temporary_source_mount_id") != manifest.get("source_mount_id")
        or operation.get("temporary_producer_lease_id")
        != manifest.get("producer_lease_id")
        or operation.get("archive_path") != str(receipt.archive)
        or operation.get("archive_manifest_sha256") != receipt.manifest_sha256
    ):
        raise MaintenanceError("maintenance_receipt_binding_mismatch")
    producer = next(
        (
            row
            for row in lifecycle.temporary_producers(candidate.binding, claim=claim)
            if row.get("path") == str(source)
        ),
        None,
    )
    if (
        producer is None
        or producer.get("lease_id") != manifest.get("producer_lease_id")
        or producer.get("ended_at") != manifest.get("producer_ended_at")
    ):
        raise MaintenanceError("temporary_producer_unavailable")
    entries = manifest.get("source_entries")
    if not isinstance(entries, list):
        raise MaintenanceError("archive_manifest_invalid")
    parent_fd = source_fd = quarantine_root_fd = quarantine_fd = -1
    source_moved = False
    filesystem = LocalFleetHomeV2Filesystem()
    claim_id = getattr(claim, "claim_id", None)
    if not isinstance(claim_id, str):
        raise MaintenanceError("maintenance_claim_invalid")
    source_name = source.name
    quarantine_path = source.parent / ".hive-quarantine" / claim_id / "temporary"

    def rollback_if_safe() -> None:
        nonlocal quarantine_fd, source_moved
        if not source_moved or quarantine_fd < 0 or parent_fd < 0:
            return
        operation = lifecycle.maintenance_operation_for_claim(claim)
        if operation.get("phase") not in {"quarantine_started", "quarantined"}:
            return
        try:
            os.stat(source_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            source_is_free = True
        else:
            source_is_free = False
        moved = filesystem.identity_at(quarantine_fd, "temporary")
        if not source_is_free:
            source_parent = os.fstat(parent_fd)
            quarantine_parent = os.fstat(quarantine_fd)
            lifecycle.record_maintenance_collision_hold(
                claim,
                evidence={
                    "reason": "source_name_occupied_after_handoff",
                    "source_name": source_name,
                    "quarantine_name": "temporary",
                    "source_parent_device": source_parent.st_dev,
                    "source_parent_inode": source_parent.st_ino,
                    "quarantine_parent_device": quarantine_parent.st_dev,
                    "quarantine_parent_inode": quarantine_parent.st_ino,
                    "moved_device": moved.device,
                    "moved_inode": moved.inode,
                },
            )
            return
        filesystem.rename_noreplace_between_at(
            quarantine_fd, "temporary", parent_fd, source_name
        )
        filesystem.fsync_directory(quarantine_fd)
        filesystem.fsync_directory(parent_fd)
        source_moved = False
        returned = filesystem.identity_at(parent_fd, source_name)
        if (returned.device, returned.inode) != (
            manifest.get("source_device"),
            manifest.get("source_inode"),
        ):
            os.close(quarantine_fd)
            quarantine_fd = -1
            os.rmdir(claim_id, dir_fd=quarantine_root_fd)
            filesystem.fsync_directory(quarantine_root_fd)
            lifecycle.hold_maintenance_claim(claim)
            return
        _verify_manifest_tree(source, entries, skip_git=False)
        os.close(quarantine_fd)
        quarantine_fd = -1
        os.rmdir(claim_id, dir_fd=quarantine_root_fd)
        filesystem.fsync_directory(quarantine_root_fd)
        lifecycle.record_maintenance_source_restored(claim, receipt)
        lifecycle.finish_maintenance(claim, outcome="source_restored")

    try:
        parent_fd = os.open(source.parent, _TREE_FLAGS)
        _assert_no_open_tree_references((source,))
        source_fd = os.open(source_name, _TREE_FLAGS, dir_fd=parent_fd)
        source_info = os.fstat(source_fd)
        source_mount = _mount_id(source_fd)
        if (
            (source_info.st_dev, source_info.st_ino)
            != (manifest.get("source_device"), manifest.get("source_inode"))
            or source_mount != manifest.get("source_mount_id")
            or source.resolve(strict=True) != source
        ):
            raise MaintenanceError("temporary_source_identity_changed")
        _verify_manifest_tree(source, entries, skip_git=False)
        quarantine_root_fd = _private_quarantine_fd(
            parent_fd, ".hive-quarantine", source_info.st_dev, source_mount
        )
        quarantine_fd = _private_quarantine_fd(
            quarantine_root_fd, claim_id, source_info.st_dev, source_mount
        )
        try:
            os.stat("temporary", dir_fd=quarantine_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise MaintenanceError("quarantine_destination_exists")
        lifecycle.advance_maintenance_phase(claim, phase="quarantine_started")
        current = filesystem.identity_at(parent_fd, source_name)
        if (current.device, current.inode) != (source_info.st_dev, source_info.st_ino):
            raise MaintenanceError("temporary_source_identity_changed")
        filesystem.rename_noreplace_between_at(
            parent_fd, source_name, quarantine_fd, "temporary"
        )
        source_moved = True
        filesystem.fsync_directory(parent_fd)
        filesystem.fsync_directory(quarantine_fd)
        os.close(source_fd)
        source_fd = -1
        lifecycle.advance_maintenance_phase(claim, phase="quarantined")
        moved = filesystem.identity_at(quarantine_fd, "temporary")
        if (moved.device, moved.inode) != (
            source_info.st_dev,
            source_info.st_ino,
        ) or moved.uid != os.geteuid():
            raise MaintenanceError("quarantine_identity_changed")
        _assert_no_open_tree_references((quarantine_path,))
        _verify_manifest_tree(quarantine_path, entries, skip_git=False)
        lifecycle.advance_maintenance_phase(claim, phase="deleting")
        _assert_no_open_tree_references((quarantine_path,))
        _verify_manifest_tree(quarantine_path, entries, skip_git=False)
        _remove_quarantined_tree_at(
            quarantine_fd,
            "temporary",
            expected_device=source_info.st_dev,
            expected_inode=source_info.st_ino,
            expected_mount=source_mount,
            grave_name=f".hive-remove-{secrets.token_hex(12)}",
        )
        source_moved = False
        os.close(quarantine_fd)
        quarantine_fd = -1
        os.rmdir(claim_id, dir_fd=quarantine_root_fd)
        filesystem.fsync_directory(quarantine_root_fd)
        lifecycle.record_maintenance_removal(claim, receipt)
        lifecycle.finish_maintenance(claim, outcome="archived_and_removed")
    except MaintenanceError:
        rollback_if_safe()
        raise
    except (OSError, WorktreeLifecycleError) as exc:
        rollback_if_safe()
        raise MaintenanceError("temporary_quarantine_or_removal_failed") from exc
    finally:
        for descriptor in (quarantine_fd, quarantine_root_fd, source_fd, parent_fd):
            if descriptor >= 0:
                os.close(descriptor)


def _private_quarantine_fd(
    parent_fd: int, name: str, expected_device: int, expected_mount: int
) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError as exc:
        raise MaintenanceError("quarantine_unavailable") from exc
    try:
        fd = os.open(name, _TREE_FLAGS, dir_fd=parent_fd)
        info = os.fstat(fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_dev != expected_device
            or _mount_id(fd) != expected_mount
        ):
            os.close(fd)
            raise MaintenanceError("quarantine_identity_invalid")
        return fd
    except MaintenanceError:
        raise
    except OSError as exc:
        raise MaintenanceError("quarantine_unavailable") from exc


def _remove_quarantined_contents(directory_fd: int, device: int, mount: int) -> None:
    filesystem = LocalFleetHomeV2Filesystem()
    names = os.listdir(directory_fd)
    grab_name = f".hive-remove-{secrets.token_hex(12)}"
    grab_fd = filesystem.mkdir_private_at(
        directory_fd, grab_name, os.geteuid(), os.getegid()
    )
    try:
        for name in names:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if before.st_dev != device:
                raise MaintenanceError("quarantine_mount_boundary")
            filesystem.rename_noreplace_between_at(directory_fd, name, grab_fd, name)
            moved = os.stat(name, dir_fd=grab_fd, follow_symlinks=False)
            if (before.st_dev, before.st_ino, before.st_mode) != (
                moved.st_dev,
                moved.st_ino,
                moved.st_mode,
            ):
                try:
                    filesystem.rename_noreplace_between_at(
                        grab_fd, name, directory_fd, name
                    )
                except Exception:
                    pass
                raise MaintenanceError("quarantine_entry_changed")
            if stat.S_ISDIR(moved.st_mode):
                child_fd = os.open(name, _TREE_FLAGS, dir_fd=grab_fd)
                try:
                    child_info = os.fstat(child_fd)
                    if (child_info.st_dev, child_info.st_ino) != (
                        moved.st_dev,
                        moved.st_ino,
                    ) or _mount_id(child_fd) != mount:
                        raise MaintenanceError("quarantine_entry_changed")
                    _remove_quarantined_contents(child_fd, device, mount)
                finally:
                    os.close(child_fd)
                after = os.stat(name, dir_fd=grab_fd, follow_symlinks=False)
                if (after.st_dev, after.st_ino) != (moved.st_dev, moved.st_ino):
                    raise MaintenanceError("quarantine_entry_changed")
                os.rmdir(name, dir_fd=grab_fd)
            elif stat.S_ISREG(moved.st_mode) and moved.st_nlink == 1:
                fd = os.open(name, _FILE_FLAGS, dir_fd=grab_fd)
                try:
                    opened = os.fstat(fd)
                    if (opened.st_dev, opened.st_ino) != (moved.st_dev, moved.st_ino):
                        raise MaintenanceError("quarantine_entry_changed")
                finally:
                    os.close(fd)
                after = os.stat(name, dir_fd=grab_fd, follow_symlinks=False)
                if (after.st_dev, after.st_ino) != (moved.st_dev, moved.st_ino):
                    raise MaintenanceError("quarantine_entry_changed")
                os.unlink(name, dir_fd=grab_fd)
            elif stat.S_ISLNK(moved.st_mode):
                after = os.stat(name, dir_fd=grab_fd, follow_symlinks=False)
                if (after.st_dev, after.st_ino) != (moved.st_dev, moved.st_ino):
                    raise MaintenanceError("quarantine_entry_changed")
                os.unlink(name, dir_fd=grab_fd)
            else:
                raise MaintenanceError("quarantine_entry_type_unsupported")
    finally:
        os.close(grab_fd)
    os.rmdir(grab_name, dir_fd=directory_fd)


def _remove_quarantined_tree_at(
    parent_fd: int,
    name: str,
    *,
    expected_device: int,
    expected_inode: int,
    expected_mount: int,
    grave_name: str,
) -> None:
    filesystem = LocalFleetHomeV2Filesystem()
    before = filesystem.identity_at(parent_fd, name)
    if (before.device, before.inode) != (expected_device, expected_inode):
        raise MaintenanceError("quarantine_identity_changed")
    filesystem.rename_noreplace_at(parent_fd, name, grave_name)
    moved = filesystem.identity_at(parent_fd, grave_name)
    if (moved.device, moved.inode) != (expected_device, expected_inode):
        try:
            filesystem.rename_noreplace_at(parent_fd, grave_name, name)
        except Exception:
            pass
        raise MaintenanceError("quarantine_identity_changed")
    root_fd = os.open(grave_name, _TREE_FLAGS, dir_fd=parent_fd)
    try:
        root_info = os.fstat(root_fd)
        if (root_info.st_dev, root_info.st_ino) != (
            expected_device,
            expected_inode,
        ) or _mount_id(root_fd) != expected_mount:
            raise MaintenanceError("quarantine_identity_changed")
        _remove_quarantined_contents(root_fd, expected_device, expected_mount)
    finally:
        os.close(root_fd)
    after = filesystem.identity_at(parent_fd, grave_name)
    if (after.device, after.inode) != (expected_device, expected_inode):
        raise MaintenanceError("quarantine_identity_changed")
    os.rmdir(grave_name, dir_fd=parent_fd)


def _tree_inode_identities(root: Path) -> set[tuple[int, int]]:
    identities: set[tuple[int, int]] = set()
    root_fd, root_info, root_mount = _open_tree(root)

    def walk(directory_fd: int) -> None:
        for name in os.listdir(directory_fd):
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if info.st_dev != root_info.st_dev:
                raise MaintenanceError("maintenance_reference_mount_boundary")
            identities.add((info.st_dev, info.st_ino))
            if stat.S_ISDIR(info.st_mode):
                child_fd = os.open(name, _TREE_FLAGS, dir_fd=directory_fd)
                try:
                    child_info = os.fstat(child_fd)
                    if (child_info.st_dev, child_info.st_ino) != (
                        info.st_dev,
                        info.st_ino,
                    ) or _mount_id(child_fd) != root_mount:
                        raise MaintenanceError("maintenance_reference_tree_changed")
                    walk(child_fd)
                finally:
                    os.close(child_fd)

    try:
        identities.add((root_info.st_dev, root_info.st_ino))
        walk(root_fd)
    except MaintenanceError:
        raise
    except OSError as exc:
        raise MaintenanceError("maintenance_reference_tree_unavailable") from exc
    finally:
        os.close(root_fd)
    return identities


def _assert_no_open_tree_references(roots: tuple[Path, ...]) -> None:
    identities: set[tuple[int, int]] = set()
    try:
        for root in roots:
            identities.update(_tree_inode_identities(root))
        pids = [name for name in os.listdir("/proc") if name.isdecimal()]
    except OSError as exc:
        raise MaintenanceError("maintenance_reference_inventory_unavailable") from exc
    current_pid = str(os.getpid())
    pids.sort(key=lambda value: (value != current_pid, int(value)))

    def check_reference(path: str) -> bool:
        try:
            info = os.stat(path)
        except FileNotFoundError:
            return False
        except ProcessLookupError:
            return False
        except PermissionError as exc:
            raise MaintenanceError(
                "maintenance_reference_inventory_unavailable"
            ) from exc
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                return False
            raise MaintenanceError(
                "maintenance_reference_inventory_unavailable"
            ) from exc
        return (info.st_dev, info.st_ino) in identities

    for pid in pids:
        process = f"/proc/{pid}"
        try:
            process_info = os.stat(process)
            if process_info.st_uid != os.geteuid():
                continue
            fd_dir = os.scandir(f"{process}/fd")
            try:
                for entry in fd_dir:
                    if check_reference(entry.path):
                        raise MaintenanceError("maintenance_open_reference_active")
            finally:
                fd_dir.close()
            for entry_name in ("cwd", "root"):
                if check_reference(f"{process}/{entry_name}"):
                    raise MaintenanceError("maintenance_open_reference_active")
            map_dir = os.scandir(f"{process}/map_files")
            try:
                for entry in map_dir:
                    if check_reference(entry.path):
                        raise MaintenanceError("maintenance_open_reference_active")
            finally:
                map_dir.close()
        except MaintenanceError:
            raise
        except FileNotFoundError:
            continue
        except ProcessLookupError:
            continue
        except PermissionError as exc:
            raise MaintenanceError(
                "maintenance_reference_inventory_unavailable"
            ) from exc
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                continue
            raise MaintenanceError(
                "maintenance_reference_inventory_unavailable"
            ) from exc


def _expected_subtree_manifest(
    entries: list[dict[str, Any]], relative_root: str
) -> list[dict[str, Any]]:
    prefix = relative_root + "/"
    selected = []
    for entry in entries:
        path = entry.get("path")
        if path == relative_root:
            selected.append({**entry, "path": "."})
        elif isinstance(path, str) and path.startswith(prefix):
            selected.append({**entry, "path": path[len(prefix) :]})
    return sorted(selected, key=lambda entry: entry.get("path", ""))


def _assert_receipt_tree_matches(
    source: Path, gitdir: Path, manifest: Mapping[str, Any], relative_gitdir: str
) -> None:
    try:
        source_entries = manifest["source_entries"]
        common_entries = manifest["common_entries"]
        expected_admin = _expected_subtree_manifest(common_entries, relative_gitdir)
        if (
            _tree_manifest(source, skip_git=True) != source_entries
            or _tree_manifest(gitdir) != expected_admin
        ):
            raise MaintenanceError("source_changed_after_archive")
    except MaintenanceError:
        raise
    except Exception as exc:
        raise MaintenanceError("source_changed_after_archive") from exc


def _quarantine_and_remove_claimed_source(
    candidate: MaintenanceCandidate,
    claim: object,
    receipt: ArchiveReceipt,
    manifest: Mapping[str, Any],
    lifecycle: WorktreeLifecycleStore,
) -> None:
    binding = candidate.binding
    if binding is None:
        raise MaintenanceError("maintenance_claim_binding_mismatch")
    source = binding.canonical_source_path
    common = binding.git_common_directory
    gitdir_relative = manifest.get("gitdir")
    if not isinstance(gitdir_relative, str):
        raise MaintenanceError("archive_gitdir_invalid")
    gitdir = common / gitdir_relative
    worktrees = gitdir.parent
    try:
        operation = lifecycle.maintenance_operation_for_claim(claim)
    except Exception as exc:
        raise MaintenanceError("maintenance_claim_unavailable") from exc
    if (
        operation.get("phase") != "archive_verified"
        or operation.get("source_device") != binding.device
        or operation.get("source_inode") != binding.inode
        or operation.get("source_mount_id") != binding.mount_id
        or operation.get("gitdir_relative") != gitdir_relative
        or operation.get("archive_path") != str(receipt.archive)
        or operation.get("archive_manifest_sha256") != receipt.manifest_sha256
        or operation.get("archive_device") != receipt.archive_device
        or operation.get("archive_inode") != receipt.archive_inode
    ):
        raise MaintenanceError("maintenance_receipt_binding_mismatch")
    source_parent_fd = common_parent_fd = common_fd = source_quarantine_fd = (
        common_quarantine_fd
    ) = -1
    filesystem = LocalFleetHomeV2Filesystem()
    try:
        source_parent_fd = os.open(source.parent, _TREE_FLAGS)
        common_parent_fd = os.open(worktrees, _TREE_FLAGS)
        common_fd = os.open(common, _TREE_FLAGS)
        source_parent_info = os.fstat(source_parent_fd)
        common_parent_info = os.fstat(common_parent_fd)
        common_info = os.fstat(common_fd)
        source_mount = _mount_id(source_parent_fd)
        common_mount = _mount_id(common_parent_fd)
        if (
            source_parent_info.st_dev != binding.device
            or source_mount != binding.mount_id
            or common_parent_info.st_dev != common_info.st_dev
            or common_mount != _mount_id(common_fd)
        ):
            raise MaintenanceError("quarantine_filesystem_mismatch")
        source_quarantine_root_fd = _private_quarantine_fd(
            source_parent_fd, ".hive-quarantine", binding.device, binding.mount_id
        )
        common_quarantine_root_fd = _private_quarantine_fd(
            common_parent_fd,
            ".hive-quarantine",
            common_parent_info.st_dev,
            common_mount,
        )
        try:
            claim_id = getattr(claim, "claim_id")
            source_quarantine_fd = _private_quarantine_fd(
                source_quarantine_root_fd, claim_id, binding.device, binding.mount_id
            )
            common_quarantine_fd = _private_quarantine_fd(
                common_quarantine_root_fd,
                claim_id,
                common_parent_info.st_dev,
                common_mount,
            )
        finally:
            os.close(source_quarantine_root_fd)
            os.close(common_quarantine_root_fd)
        source_name = source.name
        gitdir_name = gitdir.name
        source_identity = filesystem.identity_at(source_parent_fd, source_name)
        gitdir_identity = filesystem.identity_at(common_parent_fd, gitdir_name)
        if (
            (source_identity.device, source_identity.inode)
            != (binding.device, binding.inode)
            or operation.get("git_common_device") != common_info.st_dev
            or operation.get("git_common_inode") != common_info.st_ino
            or gitdir_identity.device != common_parent_info.st_dev
            or operation.get("gitdir_device") != gitdir_identity.device
            or operation.get("gitdir_inode") != gitdir_identity.inode
            or gitdir_identity.uid != os.geteuid()
        ):
            raise MaintenanceError("quarantine_source_identity_changed")
        _assert_no_open_tree_references((source, gitdir))
        _assert_receipt_tree_matches(source, gitdir, manifest, gitdir_relative)
        lifecycle.advance_maintenance_phase(claim, phase="quarantine_started")
        current_source = filesystem.identity_at(source_parent_fd, source_name)
        current_gitdir = filesystem.identity_at(common_parent_fd, gitdir_name)
        if (current_source.device, current_source.inode) != (
            source_identity.device,
            source_identity.inode,
        ) or (current_gitdir.device, current_gitdir.inode) != (
            gitdir_identity.device,
            gitdir_identity.inode,
        ):
            raise MaintenanceError("quarantine_source_identity_changed")
        filesystem.rename_noreplace_between_at(
            source_parent_fd, source_name, source_quarantine_fd, "worktree"
        )
        filesystem.fsync_directory(source_parent_fd)
        filesystem.fsync_directory(source_quarantine_fd)
        filesystem.rename_noreplace_between_at(
            common_parent_fd, gitdir_name, common_quarantine_fd, "gitdir"
        )
        filesystem.fsync_directory(common_parent_fd)
        filesystem.fsync_directory(common_quarantine_fd)
        lifecycle.advance_maintenance_phase(claim, phase="quarantined")
        moved_source = filesystem.identity_at(source_quarantine_fd, "worktree")
        moved_gitdir = filesystem.identity_at(common_quarantine_fd, "gitdir")
        if (moved_source.device, moved_source.inode) != (
            binding.device,
            binding.inode,
        ) or (moved_gitdir.device, moved_gitdir.inode) != (
            gitdir_identity.device,
            gitdir_identity.inode,
        ):
            raise MaintenanceError("quarantine_identity_changed")
        quarantined_source = source.parent / ".hive-quarantine" / claim_id / "worktree"
        quarantined_gitdir = (
            common / "worktrees" / ".hive-quarantine" / claim_id / "gitdir"
        )
        _assert_no_open_tree_references((quarantined_source, quarantined_gitdir))
        _assert_receipt_tree_matches(
            quarantined_source,
            quarantined_gitdir,
            manifest,
            gitdir_relative,
        )
        _assert_no_open_tree_references((quarantined_source, quarantined_gitdir))
        lifecycle.advance_maintenance_phase(claim, phase="deleting")
        _remove_quarantined_tree_at(
            source_quarantine_fd,
            "worktree",
            expected_device=source_identity.device,
            expected_inode=source_identity.inode,
            expected_mount=binding.mount_id,
            grave_name=f"grave-worktree-{claim_id}",
        )
        _remove_quarantined_tree_at(
            common_quarantine_fd,
            "gitdir",
            expected_device=gitdir_identity.device,
            expected_inode=gitdir_identity.inode,
            expected_mount=common_mount,
            grave_name=f"grave-gitdir-{claim_id}",
        )
        os.close(common_quarantine_fd)
        common_quarantine_fd = -1
        os.close(source_quarantine_fd)
        source_quarantine_fd = -1
        for parent_fd, expected_device, expected_mount in (
            (source_parent_fd, binding.device, binding.mount_id),
            (common_parent_fd, common_info.st_dev, common_mount),
        ):
            root_fd = _private_quarantine_fd(
                parent_fd, ".hive-quarantine", expected_device, expected_mount
            )
            try:
                os.rmdir(claim_id, dir_fd=root_fd)
            finally:
                os.close(root_fd)
            try:
                os.rmdir(".hive-quarantine", dir_fd=parent_fd)
            except OSError as exc:
                if exc.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
                    raise
        lifecycle.record_maintenance_removal(claim, receipt)
        lifecycle.finish_maintenance(claim, outcome="archived_and_removed")
    except MaintenanceError:
        raise
    except Exception as exc:
        raise MaintenanceError("quarantine_or_removal_failed") from exc
    finally:
        for fd in (
            common_quarantine_fd,
            source_quarantine_fd,
            common_fd,
            common_parent_fd,
            source_parent_fd,
        ):
            if fd >= 0:
                os.close(fd)
