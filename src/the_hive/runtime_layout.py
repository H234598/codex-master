"""Immutable, fail-closed paths for the single The Hive runtime image."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any


class LayoutError(ValueError):
    """The runtime image is not a private, complete regular-file image."""


_MAX_IMAGE_FILE_BYTES = 2 * 1024 * 1024
_MAX_METADATA_BYTES = 256 * 1024
_ROOT_MODE = 0o700
_MANIFEST_NAME = ".the-hive-runtime-manifest.json"
_RELEASE_POINTERS_NAME = ".the-hive-release-pointers.json"
_RELEASE_GENERATIONS_NAME = "generations"
_RUNTIME_SPAWN_HELPER = "src/the_hive/_runtime_spawn_helper.so"
_R2_BASE_COMMIT = "5defcac83030e91b39188c8b055adb97d5f51e98"
_R2_BASE_TREE = "6c872289709de2a0bfe69d8392ce91b49f3855f3"
_D73_COMMIT = "f6f9348a4348d1a18bb3c4b591a93c393dfda838"
_D73_TREE = "d4f9620d25b0053763a6d20d0dfacbb8bd9a40ff"
_F25_D69_COMMIT = "f25f60f6010d7b74b82a57f6471618e16df3e1a6"
_F25_D69_TREE = "0f459eea9d8e13bd54e74e699272c53cddaecb1d"
_C4_COMMIT = "c4b72abcfe0e8b208b05f90cc4f8275def851581"
_D69_DYNAMIC_POOL_BLOB = "36c1e4a2716f808dc2ac89fe0d604249b1639ddd"
_SUCCESSOR_WITNESS_PATH = "src/the_hive/dynamic_pool.py"
_SUCCESSOR_WITNESS_SHA256 = (
    "e8e9056cfde2c51af7a3a86d16c3220831f5cc4b8b5dc337df70489e38974a5c"
)
_HISTORICAL_LINEAGE = {
    "d69": {
        "commit": _F25_D69_COMMIT,
        "tree": _F25_D69_TREE,
        "parent": _C4_COMMIT,
        "dynamic_pool_blob": _D69_DYNAMIC_POOL_BLOB,
    },
    "d73": {
        "commit": _D73_COMMIT,
        "tree": _D73_TREE,
        "parent": _F25_D69_COMMIT,
    },
}
_STABLE_MCP_LAUNCHER_SOURCE = "bin/the-hive-mcp-stable"
_STABLE_MCP_COMMAND = "/home/teladi/.local/lib/the-hive-runtime/the-hive-mcp"
_STABLE_MCP_NOTE = (
    "Local data-sparse Codex Masterjet MCP server. Controls the sleeping "
    "Agentinnen pool through tmux and does not return raw terminal output by default."
)
_REQUIRED_FILES: tuple[tuple[str, int], ...] = (
    ("bin/the-hive-mcp", 0o755),
    (_STABLE_MCP_LAUNCHER_SOURCE, 0o755),
    ("bin/the-hive-resource-monitor", 0o755),
    ("bin/the-hive-hive-hourly-probe", 0o755),
    (".codex-plugin/plugin.json", 0o644),
    (".mcp.json", 0o644),
    (".app.json", 0o644),
    ("hooks/hooks.json", 0o644),
    ("skills/the-hive-fleet/SKILL.md", 0o644),
    ("codex-hive.json", 0o644),
    ("codex-agent-classes.json", 0o644),
    ("systemd/user/the-hive-resource-monitor.service", 0o644),
    ("systemd/user/the-hive.slice", 0o644),
    (_RUNTIME_SPAWN_HELPER, 0o755),
    (_MANIFEST_NAME, 0o644),
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


def _read_regular_bytes(root: Path, relative_path: str, *, max_bytes: int) -> bytes:
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
        return raw
    except OSError as exc:
        raise _invalid() from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_regular_text(root: Path, relative_path: str, *, max_bytes: int) -> str:
    try:
        return _read_regular_bytes(root, relative_path, max_bytes=max_bytes).decode(
            "utf-8"
        )
    except UnicodeError as exc:
        raise _invalid() from exc


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def _read_json_object(root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_regular_text(root, relative_path, max_bytes=_MAX_METADATA_BYTES),
            object_pairs_hook=_unique_json_object,
        )
    except json.JSONDecodeError as exc:
        raise _invalid() from exc
    if not isinstance(value, dict):
        raise _invalid()
    return value


def _manifest_digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _exact_relative_reference(value: object, expected: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise _invalid()
    if not value.startswith("./") or ".." in value.split("/"):
        raise _invalid()


def _validate_metadata(root: Path) -> None:
    plugin = _read_json_object(root, ".codex-plugin/plugin.json")
    if plugin.get("name") != "the-hive" or not isinstance(plugin.get("version"), str):
        raise _invalid()
    _exact_relative_reference(plugin.get("skills"), "./skills/")
    _exact_relative_reference(plugin.get("mcpServers"), "./.mcp.json")
    _exact_relative_reference(plugin.get("apps"), "./.app.json")
    _exact_relative_reference(plugin.get("hooks"), "./hooks/hooks.json")

    mcp = _read_json_object(root, ".mcp.json")
    if set(mcp) != {"mcpServers"}:
        raise _invalid()
    servers = mcp.get("mcpServers")
    if not isinstance(servers, dict) or set(servers) != {"the-hive-mcp"}:
        raise _invalid()
    server = servers.get("the-hive-mcp")
    if not isinstance(server, dict) or set(server) != {
        "command",
        "args",
        "startup_timeout_sec",
        "note",
    }:
        raise _invalid()
    if (
        server.get("command") != _STABLE_MCP_COMMAND
        or server.get("args") != []
        or server.get("startup_timeout_sec") != 120
        or server.get("note") != _STABLE_MCP_NOTE
    ):
        raise _invalid()

    apps = _read_json_object(root, ".app.json").get("apps")
    if not isinstance(apps, dict) or not isinstance(apps.get("the-hive"), dict):
        raise _invalid()
    hooks = _read_json_object(root, "hooks/hooks.json").get("hooks")
    if not isinstance(hooks, dict):
        raise _invalid()
    _read_json_object(root, "codex-hive.json")
    _read_json_object(root, "codex-agent-classes.json")
    if not _read_regular_text(
        root, "skills/the-hive-fleet/SKILL.md", max_bytes=_MAX_METADATA_BYTES
    ).strip():
        raise _invalid()


def _release_metadata(manifest: dict[str, object]) -> dict[str, object]:
    expected_release = {
        "stable_launchers": [
            _STABLE_MCP_LAUNCHER_SOURCE,
            "bin/the-hive-mcp",
            "bin/the-hive-resource-monitor",
        ],
        "python_tree": "src/the_hive",
        "monitor_entrypoint": "bin/the-hive-resource-monitor",
        "h4_units": [
            "systemd/user/the-hive-resource-monitor.service",
            "systemd/user/the-hive.slice",
        ],
        "bind_sources": [
            "bin/the-hive-resource-monitor",
            "src/the_hive",
            "codex-agent-classes.json",
            "codex-hive.json",
            "%h/.local/state/codex-master-mcp/hive",
        ],
    }
    commit = manifest.get("commit")
    generation = manifest.get("generation")
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
        or not isinstance(generation, str)
        or not generation
        or "/" in generation
        or generation in {".", ".."}
        or manifest.get("r2_base") != {"commit": _R2_BASE_COMMIT, "tree": _R2_BASE_TREE}
        or manifest.get("historical_lineage") != _HISTORICAL_LINEAGE
        or manifest.get("successor_witness")
        != {
            "path": _SUCCESSOR_WITNESS_PATH,
            "sha256": _SUCCESSOR_WITNESS_SHA256,
        }
        or manifest.get("release") != expected_release
    ):
        raise _invalid()
    return {
        "commit": commit,
        "generation": generation,
        "r2_base": {"commit": _R2_BASE_COMMIT, "tree": _R2_BASE_TREE},
        "historical_lineage": _HISTORICAL_LINEAGE,
        "successor_witness": {
            "path": _SUCCESSOR_WITNESS_PATH,
            "sha256": _SUCCESSOR_WITNESS_SHA256,
        },
        "release": expected_release,
    }


def _runtime_manifest_payload(
    root: Path, metadata: dict[str, object]
) -> dict[str, object]:
    directories: dict[str, dict[str, int]] = {}
    files: dict[str, dict[str, object]] = {}
    for directory, child_directories, file_names in os.walk(root):
        current = Path(directory)
        relative = current.relative_to(root).as_posix() if current != root else "."
        current_info = _lstat(current)
        if (
            stat.S_ISLNK(current_info.st_mode)
            or not stat.S_ISDIR(current_info.st_mode)
            or current_info.st_uid != os.geteuid()
            or stat.S_IMODE(current_info.st_mode) != _ROOT_MODE
        ):
            raise _invalid()
        directories[relative] = {
            "mode": stat.S_IMODE(current_info.st_mode),
            "nlink": current_info.st_nlink,
        }
        child_directories[:] = sorted(child_directories)
        for name in child_directories:
            _image_path(root, (current / name).relative_to(root).as_posix())
        for name in sorted(file_names):
            path = current / name
            relative_path = path.relative_to(root).as_posix()
            if relative_path == _MANIFEST_NAME:
                continue
            info = _lstat(path)
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o022
                or not 0 < info.st_size <= _MAX_IMAGE_FILE_BYTES
            ):
                raise _invalid()
            raw = _read_regular_bytes(
                root, relative_path, max_bytes=_MAX_IMAGE_FILE_BYTES
            )
            files[relative_path] = {
                "mode": stat.S_IMODE(info.st_mode),
                "nlink": info.st_nlink,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
    return {"schema_version": 2, **metadata, "directories": directories, "files": files}


def _validated_manifest(
    root: Path, *, expected_digest: str | None = None
) -> tuple[dict[str, object], str]:
    raw = _read_regular_bytes(root, _MANIFEST_NAME, max_bytes=_MAX_METADATA_BYTES)
    digest = _manifest_digest(raw)
    if expected_digest is not None and digest != expected_digest:
        raise _invalid()
    try:
        manifest = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_json_object
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _invalid() from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 2:
        raise _invalid()
    metadata = _release_metadata(manifest)
    expected = _runtime_manifest_payload(root, metadata)
    if manifest != expected:
        raise _invalid()
    files = manifest.get("files")
    witness = files.get(_SUCCESSOR_WITNESS_PATH) if isinstance(files, dict) else None
    if (
        not isinstance(witness, dict)
        or witness.get("sha256") != _SUCCESSOR_WITNESS_SHA256
    ):
        raise _invalid()
    return manifest, digest


def _spawn_helper_digest(manifest: dict[str, object]) -> str:
    files = manifest["files"]
    if not isinstance(files, dict):
        raise _invalid()
    helper = files.get(_RUNTIME_SPAWN_HELPER)
    if not isinstance(helper, dict):
        raise _invalid()
    digest = helper.get("sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise _invalid()
    return digest


def _validate_layout_values(
    root: Path,
    mcp_entrypoint: Path,
    probe_entrypoint: Path,
    metadata_root: Path,
    spawn_helper: Path,
    spawn_helper_digest: str,
    root_device: int,
    root_inode: int,
    manifest_digest: str,
) -> None:
    _validate_root(root)
    root_stat = _lstat(root)
    if (
        type(root_device) is not int
        or type(root_inode) is not int
        or (root_stat.st_dev, root_stat.st_ino) != (root_device, root_inode)
        or not isinstance(manifest_digest, str)
        or not manifest_digest.startswith("sha256:")
        or len(manifest_digest) != 71
        or any(character not in "0123456789abcdef" for character in manifest_digest[7:])
    ):
        raise _invalid()
    if (
        not isinstance(mcp_entrypoint, Path)
        or not isinstance(probe_entrypoint, Path)
        or not isinstance(metadata_root, Path)
        or mcp_entrypoint != root / "bin" / "the-hive-mcp"
        or probe_entrypoint != root / "bin" / "the-hive-hive-hourly-probe"
        or metadata_root != root
        or spawn_helper != root / _RUNTIME_SPAWN_HELPER
    ):
        raise _invalid()
    for relative_path, mode in _REQUIRED_FILES:
        _validate_regular(root, relative_path, mode)
    _validate_metadata(root)
    manifest, actual_manifest_digest = _validated_manifest(
        root, expected_digest=manifest_digest
    )
    if (
        actual_manifest_digest != manifest_digest
        or spawn_helper_digest != _spawn_helper_digest(manifest)
    ):
        raise _invalid()


@dataclass(frozen=True, slots=True)
class RuntimeLayout:
    """Validated paths of one complete, immutable runtime image."""

    root: Path
    mcp_entrypoint: Path
    probe_entrypoint: Path
    metadata_root: Path
    spawn_helper: Path
    spawn_helper_digest: str
    root_device: int
    root_inode: int
    manifest_digest: str

    def __post_init__(self) -> None:
        _validate_layout_values(
            self.root,
            self.mcp_entrypoint,
            self.probe_entrypoint,
            self.metadata_root,
            self.spawn_helper,
            self.spawn_helper_digest,
            self.root_device,
            self.root_inode,
            self.manifest_digest,
        )

    @classmethod
    def from_runtime_root(cls, root: Path) -> RuntimeLayout:
        if not isinstance(root, Path) or not root.is_absolute():
            raise _invalid()
        _validate_root(root)
        root_stat = _lstat(root)
        manifest, manifest_digest = _validated_manifest(root)
        return cls(
            root=root,
            mcp_entrypoint=root / "bin" / "the-hive-mcp",
            probe_entrypoint=root / "bin" / "the-hive-hive-hourly-probe",
            metadata_root=root,
            spawn_helper=root / _RUNTIME_SPAWN_HELPER,
            spawn_helper_digest=_spawn_helper_digest(manifest),
            root_device=root_stat.st_dev,
            root_inode=root_stat.st_ino,
            manifest_digest=manifest_digest,
        )

    @classmethod
    def from_current_release(
        cls, release_root: Path, generation: str, manifest_digest: str
    ) -> RuntimeLayout:
        """Attest an explicit generation against the one atomic pointer pair."""

        return cls._from_release_pointer(
            release_root, generation, manifest_digest, pointer_name="current"
        )

    @classmethod
    def from_previous_release(
        cls, release_root: Path, generation: str, manifest_digest: str
    ) -> RuntimeLayout:
        """Attest an explicit rollback target against the same pointer pair."""

        return cls._from_release_pointer(
            release_root, generation, manifest_digest, pointer_name="previous"
        )

    @classmethod
    def _from_release_pointer(
        cls,
        release_root: Path,
        generation: str,
        manifest_digest: str,
        *,
        pointer_name: str,
    ) -> RuntimeLayout:

        if (
            not isinstance(release_root, Path)
            or not isinstance(generation, str)
            or not generation
            or "/" in generation
            or generation in {".", ".."}
            or not isinstance(manifest_digest, str)
        ):
            raise _invalid()
        _validate_root(release_root)
        try:
            raw = _read_regular_bytes(
                release_root, _RELEASE_POINTERS_NAME, max_bytes=_MAX_METADATA_BYTES
            )
            pointers = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_unique_json_object
            )
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise _invalid() from exc
        if (
            not isinstance(pointers, dict)
            or set(pointers) != {"schema_version", "current", "previous"}
            or pointers.get("schema_version") != 1
        ):
            raise _invalid()

        def attest(value: object) -> dict[str, object] | None:
            if value is None:
                return None
            if not isinstance(value, dict) or set(value) != {
                "generation",
                "manifest_digest",
            }:
                raise _invalid()
            listed_generation = value.get("generation")
            listed_digest = value.get("manifest_digest")
            if (
                not isinstance(listed_generation, str)
                or not listed_generation
                or "/" in listed_generation
                or listed_generation in {".", ".."}
                or not isinstance(listed_digest, str)
            ):
                raise _invalid()
            layout = cls.from_runtime_root(
                release_root / _RELEASE_GENERATIONS_NAME / listed_generation
            )
            if layout.manifest_digest != listed_digest:
                raise _invalid()
            return {"generation": listed_generation, "manifest_digest": listed_digest}

        current = attest(pointers["current"])
        previous = attest(pointers["previous"])
        if pointer_name not in {"current", "previous"}:
            raise _invalid()
        selected = current if pointer_name == "current" else previous
        if selected != {"generation": generation, "manifest_digest": manifest_digest}:
            raise _invalid()
        return cls.from_runtime_root(
            release_root / _RELEASE_GENERATIONS_NAME / generation
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
                if len(relative.parts) >= 3 and relative.parts[:2] == (
                    "src",
                    "the_hive",
                ):
                    _validate_regular(root, relative.as_posix(), 0o644)
                    return cls.from_runtime_root(root)
            current = current.parent
        raise _invalid()

    def read_attested_file(self, relative_path: str) -> bytes:
        """Read one manifest-pinned image member through no-follow descriptors."""

        manifest, _digest = _validated_manifest(
            self.root, expected_digest=self.manifest_digest
        )
        files = manifest.get("files")
        entry = files.get(relative_path) if isinstance(files, dict) else None
        expected = entry.get("sha256") if isinstance(entry, dict) else None
        if (
            not isinstance(expected, str)
            or len(expected) != 64
            or any(character not in "0123456789abcdef" for character in expected)
        ):
            raise _invalid()
        raw = _read_regular_bytes(
            self.root, relative_path, max_bytes=_MAX_IMAGE_FILE_BYTES
        )
        if hashlib.sha256(raw).hexdigest() != expected:
            raise _invalid()
        validate_runtime_metadata(self)
        return raw


def validate_runtime_metadata(layout: RuntimeLayout) -> None:
    """Revalidate image files and metadata immediately before an MCP probe."""

    if not isinstance(layout, RuntimeLayout):
        raise _invalid()
    _validate_layout_values(
        layout.root,
        layout.mcp_entrypoint,
        layout.probe_entrypoint,
        layout.metadata_root,
        layout.spawn_helper,
        layout.spawn_helper_digest,
        layout.root_device,
        layout.root_inode,
        layout.manifest_digest,
    )


__all__ = [
    "LayoutError",
    "RuntimeLayout",
    "validate_runtime_metadata",
]
