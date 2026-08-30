"""Immutable, fail-closed paths for the single codex-master runtime image."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from typing import Any


class LayoutError(ValueError):
    """The runtime image is not a private, complete regular-file image."""


_MAX_IMAGE_FILE_BYTES = 1024 * 1024
_MAX_METADATA_BYTES = 256 * 1024
_ROOT_MODE = 0o700
_REQUIRED_FILES: tuple[tuple[str, int], ...] = (
    ("bin/codex-master-mcp", 0o755),
    ("bin/codex-master-hive-hourly-probe", 0o755),
    (".codex-plugin/plugin.json", 0o644),
    (".mcp.json", 0o644),
    (".app.json", 0o644),
    ("hooks/hooks.json", 0o644),
    ("skills/codex-master-fleet/SKILL.md", 0o644),
    ("codex-hive.json", 0o644),
    ("codex-agent-classes.json", 0o644),
)


def _invalid() -> LayoutError:
    return LayoutError("runtime_layout_invalid")


def _lstat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise _invalid() from exc


def _validate_root(root: Path) -> None:
    if not isinstance(root, Path) or not root.is_absolute():
        raise _invalid()
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current = current / part
        if stat.S_ISLNK(_lstat(current).st_mode):
            raise _invalid()
    info = _lstat(root)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != _ROOT_MODE
    ):
        raise _invalid()


def _relative_parts(relative_path: str) -> tuple[str, ...]:
    if not isinstance(relative_path, str) or not relative_path:
        raise _invalid()
    parts = tuple(relative_path.split("/"))
    if any(not part or part in {".", ".."} for part in parts):
        raise _invalid()
    return parts


def _image_path(root: Path, relative_path: str) -> Path:
    current = root
    parts = _relative_parts(relative_path)
    for index, part in enumerate(parts):
        current = current / part
        info = _lstat(current)
        if stat.S_ISLNK(info.st_mode):
            raise _invalid()
        if index < len(parts) - 1 and (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != _ROOT_MODE
        ):
            raise _invalid()
    return current


def _validate_regular(root: Path, relative_path: str, mode: int) -> Path:
    path = _image_path(root, relative_path)
    info = _lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != mode
        or not 0 < info.st_size <= _MAX_IMAGE_FILE_BYTES
    ):
        raise _invalid()
    return path


def _read_regular_text(root: Path, relative_path: str, *, max_bytes: int) -> str:
    path = _image_path(root, relative_path)
    expected = _lstat(path)
    if (
        not stat.S_ISREG(expected.st_mode)
        or expected.st_nlink != 1
        or expected.st_uid != os.geteuid()
        or expected.st_size > max_bytes
    ):
        raise _invalid()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_uid != expected.st_uid
            or current.st_dev != expected.st_dev
            or current.st_ino != expected.st_ino
            or current.st_size != expected.st_size
            or current.st_size > max_bytes
        ):
            raise _invalid()
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != current.st_size or len(raw) > max_bytes:
            raise _invalid()
        return raw.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise _invalid() from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_json_object(root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_read_regular_text(root, relative_path, max_bytes=_MAX_METADATA_BYTES))
    except json.JSONDecodeError as exc:
        raise _invalid() from exc
    if not isinstance(value, dict):
        raise _invalid()
    return value


def _exact_relative_reference(value: object, expected: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise _invalid()
    if not value.startswith("./") or ".." in value.split("/"):
        raise _invalid()


def _validate_metadata(root: Path) -> None:
    plugin = _read_json_object(root, ".codex-plugin/plugin.json")
    if plugin.get("name") != "codex-master" or not isinstance(plugin.get("version"), str):
        raise _invalid()
    _exact_relative_reference(plugin.get("skills"), "./skills/")
    _exact_relative_reference(plugin.get("mcpServers"), "./.mcp.json")
    _exact_relative_reference(plugin.get("apps"), "./.app.json")
    _exact_relative_reference(plugin.get("hooks"), "./hooks/hooks.json")

    mcp = _read_json_object(root, ".mcp.json")
    servers = mcp.get("mcpServers")
    if not isinstance(servers, dict):
        raise _invalid()
    server = servers.get("codex-master-mcp")
    if not isinstance(server, dict):
        raise _invalid()
    _exact_relative_reference(server.get("command"), "./bin/codex-master-mcp")
    if server.get("args") != []:
        raise _invalid()
    if "cwd" in server and server["cwd"] != ".":
        raise _invalid()

    apps = _read_json_object(root, ".app.json").get("apps")
    if not isinstance(apps, dict) or not isinstance(apps.get("codex-master"), dict):
        raise _invalid()
    hooks = _read_json_object(root, "hooks/hooks.json").get("hooks")
    if not isinstance(hooks, dict):
        raise _invalid()
    _read_json_object(root, "codex-hive.json")
    _read_json_object(root, "codex-agent-classes.json")
    if not _read_regular_text(root, "skills/codex-master-fleet/SKILL.md", max_bytes=_MAX_METADATA_BYTES).strip():
        raise _invalid()


def _validate_layout_values(
    root: Path,
    mcp_entrypoint: Path,
    probe_entrypoint: Path,
    metadata_root: Path,
) -> None:
    _validate_root(root)
    if (
        not isinstance(mcp_entrypoint, Path)
        or not isinstance(probe_entrypoint, Path)
        or not isinstance(metadata_root, Path)
        or mcp_entrypoint != root / "bin" / "codex-master-mcp"
        or probe_entrypoint != root / "bin" / "codex-master-hive-hourly-probe"
        or metadata_root != root
    ):
        raise _invalid()
    for relative_path, mode in _REQUIRED_FILES:
        _validate_regular(root, relative_path, mode)
    _validate_metadata(root)


@dataclass(frozen=True, slots=True)
class RuntimeLayout:
    """Validated paths of one complete, immutable runtime image."""

    root: Path
    mcp_entrypoint: Path
    probe_entrypoint: Path
    metadata_root: Path

    def __post_init__(self) -> None:
        _validate_layout_values(
            self.root,
            self.mcp_entrypoint,
            self.probe_entrypoint,
            self.metadata_root,
        )

    @classmethod
    def from_runtime_root(cls, root: Path) -> RuntimeLayout:
        if not isinstance(root, Path) or not root.is_absolute():
            raise _invalid()
        return cls(
            root=root,
            mcp_entrypoint=root / "bin" / "codex-master-mcp",
            probe_entrypoint=root / "bin" / "codex-master-hive-hourly-probe",
            metadata_root=root,
        )

    @classmethod
    def from_module_path(cls, module_path: Path) -> RuntimeLayout:
        if not isinstance(module_path, Path) or not module_path.is_absolute():
            raise _invalid()
        current = module_path.parent
        while current != current.parent:
            if current.name == "src":
                root = current.parent
                try:
                    relative = module_path.relative_to(root)
                except ValueError as exc:
                    raise _invalid() from exc
                if len(relative.parts) >= 3 and relative.parts[:2] == ("src", "codex_master"):
                    _validate_regular(root, relative.as_posix(), 0o644)
                    return cls.from_runtime_root(root)
            current = current.parent
        raise _invalid()


def validate_runtime_metadata(layout: RuntimeLayout) -> None:
    """Revalidate image files and metadata immediately before an MCP probe."""

    if not isinstance(layout, RuntimeLayout):
        raise _invalid()
    _validate_layout_values(
        layout.root,
        layout.mcp_entrypoint,
        layout.probe_entrypoint,
        layout.metadata_root,
    )


__all__ = ["LayoutError", "RuntimeLayout", "validate_runtime_metadata"]
