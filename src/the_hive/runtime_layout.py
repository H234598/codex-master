"""Immutable, fail-closed paths for the single codex-master runtime image."""

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
_MANIFEST_NAME = ".codex-master-runtime-manifest.json"
_RELEASE_POINTERS_NAME = ".codex-master-release-pointers.json"
_RELEASE_GENERATIONS_NAME = "generations"
_RUNTIME_SPAWN_HELPER = "src/the_hive/_runtime_spawn_helper.so"
_F25_COMMIT = "f25f60f6010d7b74b82a57f6471618e16df3e1a6"
_C4_COMMIT = "c4b72abcfe0e8b208b05f90cc4f8275def851581"
_D69_RUNTIME_PATHS = (
    "src/the_hive/admission.py", "src/the_hive/admission_runtime.py",
    "src/the_hive/dynamic_pool.py", "src/the_hive/hive/__init__.py",
    "src/the_hive/hive/admission.py", "src/the_hive/hive/dispatch.py",
    "src/the_hive/hive/principals.py", "src/the_hive/selection.py",
    "src/the_hive/selection_service.py", "src/the_hive/server.py",
)
_D69_ANCHOR_PATH = "src/the_hive/dynamic_pool.py"
_D69_ANCHOR_SHA256 = "1c3e2e8ff7c0c14294af2dee044b6dfd3a072caad0d117b49dfc8d360d8efef4"
_STABLE_MCP_LAUNCHER_SOURCE = "bin/codex-master-mcp-stable"
_STABLE_MCP_COMMAND = "/home/teladi/.local/lib/codex-master-runtime/codex-master-mcp"
_STABLE_MCP_NOTE = (
    "Local data-sparse Codex Masterjet MCP server. Controls the sleeping "
    "Agentinnen pool through tmux and does not return raw terminal output by default."
)
_F25_D69_SOURCE_SHA256 = {
    "src/the_hive/admission.py": "ad2609dc0022b4bcc8937ee2c2ce17ef553c602eb02849103840d7279f773bd4",
    "src/the_hive/admission_runtime.py": "0babae1ca3fda111a623c56cb0f230f901981585dda7bec9dbf33b87b0a88e6f",
    "src/the_hive/dynamic_pool.py": _D69_ANCHOR_SHA256,
    "src/the_hive/hive/__init__.py": "28b14addc149512d68782b416c26b5191c823095fade0318bc3d7338dee1c4a8",
    "src/the_hive/hive/admission.py": "4d97e5f73005068833d2181d1751c59f7861f0bcf24fdc6ad04b1aa882cf34ca",
    "src/the_hive/hive/dispatch.py": "d164865c2285eaae6d2aa9a3f50555c0bb8f3ab2d7529308431438273cba8ba6",
    "src/the_hive/hive/principals.py": "4b9912390c2f7c198338245c0912f8c195fb027e4c14f5184d3ec5dfae62fcee",
    "src/the_hive/selection.py": "c575dc16bb553fc3a34e566f23486e71b324f7de640762b459868c275b8d1c8e",
    "src/the_hive/selection_service.py": "486dce3f357f40377042b28791da48db67ece5a7d6dd86c6e6c0cec3f5744f4f",
    "src/the_hive/server.py": "3e22e18b67f8407e895816b40452ba8c32db7f5817e9af47ff57c88c60818942",
}
_F25_C4_SUBSET_SHA256 = {
    "bin/codex-master-mcp": "7374a1e82c7308a8836f973646658e368a3996b41461d8a7722c100d27f0ccbe",
    "bin/codex-master-resource-monitor": "b630d3f7e01288c1b8509062d98e3c6a900228bd07972d5f0ec7c76281183ab3",
    "systemd/user/codex-master.slice": "4771a0a12b219b3053b0f88dc32caf071244ddf8c4a2efbec26892c79078f290",
    "systemd/user/codex-master-resource-monitor.service": "73f44183861aa5d950de525ad1517bbf928fe59b4b40cc9c471a5f59e7d2242f",
    "src/the_hive/resource_cgroup.py": "c49ce367a96a4f3e422989a3d6e51ab372864206f1d820124e4fe72866287024",
    "src/the_hive/resource_monitor.py": "7d2f4c7efad196166dd2c0e924d3dda8645ee853ff8ce11449755e4aa2d3bce4",
}
_REQUIRED_FILES: tuple[tuple[str, int], ...] = (
    ("bin/codex-master-mcp", 0o755),
    (_STABLE_MCP_LAUNCHER_SOURCE, 0o755),
    ("bin/codex-master-resource-monitor", 0o755),
    ("bin/codex-master-hive-hourly-probe", 0o755),
    (".codex-plugin/plugin.json", 0o644),
    (".mcp.json", 0o644),
    (".app.json", 0o644),
    ("hooks/hooks.json", 0o644),
    ("skills/codex-master-fleet/SKILL.md", 0o644),
    ("codex-hive.json", 0o644),
    ("codex-agent-classes.json", 0o644),
    ("systemd/user/codex-master-resource-monitor.service", 0o644),
    ("systemd/user/codex-master.slice", 0o644),
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
        return _read_regular_bytes(root, relative_path, max_bytes=max_bytes).decode("utf-8")
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
    if plugin.get("name") != "codex-master" or not isinstance(plugin.get("version"), str):
        raise _invalid()
    _exact_relative_reference(plugin.get("skills"), "./skills/")
    _exact_relative_reference(plugin.get("mcpServers"), "./.mcp.json")
    _exact_relative_reference(plugin.get("apps"), "./.app.json")
    _exact_relative_reference(plugin.get("hooks"), "./hooks/hooks.json")

    mcp = _read_json_object(root, ".mcp.json")
    if set(mcp) != {"mcpServers"}:
        raise _invalid()
    servers = mcp.get("mcpServers")
    if not isinstance(servers, dict) or set(servers) != {"codex-master-mcp"}:
        raise _invalid()
    server = servers.get("codex-master-mcp")
    if not isinstance(server, dict) or set(server) != {
        "command", "args", "startup_timeout_sec", "note"
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
    if not isinstance(apps, dict) or not isinstance(apps.get("codex-master"), dict):
        raise _invalid()
    hooks = _read_json_object(root, "hooks/hooks.json").get("hooks")
    if not isinstance(hooks, dict):
        raise _invalid()
    _read_json_object(root, "codex-hive.json")
    _read_json_object(root, "codex-agent-classes.json")
    if not _read_regular_text(root, "skills/codex-master-fleet/SKILL.md", max_bytes=_MAX_METADATA_BYTES).strip():
        raise _invalid()


def _release_metadata(manifest: dict[str, object]) -> dict[str, object]:
    expected_release = {
        "stable_launchers": [
            _STABLE_MCP_LAUNCHER_SOURCE,
            "bin/codex-master-mcp",
            "bin/codex-master-resource-monitor",
        ],
        "python_tree": "src/the_hive",
        "monitor_entrypoint": "bin/codex-master-resource-monitor",
        "h4_units": [
            "systemd/user/codex-master-resource-monitor.service",
            "systemd/user/codex-master.slice",
        ],
        "bind_sources": [
            "bin/codex-master-resource-monitor", "src/the_hive",
            "codex-agent-classes.json", "codex-hive.json",
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
        or manifest.get("f25_base_commit") != _F25_COMMIT
        or manifest.get("d69") != {"commit": _F25_COMMIT, "parent": _C4_COMMIT}
        or manifest.get("d69_paths") != list(_D69_RUNTIME_PATHS)
        or manifest.get("d69_anchor") != {
            "path": _D69_ANCHOR_PATH,
            "sha256": _D69_ANCHOR_SHA256,
        }
        or manifest.get("f25_d69_source_sha256") != _F25_D69_SOURCE_SHA256
        or manifest.get("f25_c4_subset_sha256") != _F25_C4_SUBSET_SHA256
        or manifest.get("release") != expected_release
    ):
        raise _invalid()
    return {
        "commit": commit,
        "f25_base_commit": _F25_COMMIT,
        "generation": generation,
        "d69": {"commit": _F25_COMMIT, "parent": _C4_COMMIT},
        "d69_paths": list(_D69_RUNTIME_PATHS),
        "d69_anchor": {"path": _D69_ANCHOR_PATH, "sha256": _D69_ANCHOR_SHA256},
        "f25_d69_source_sha256": _F25_D69_SOURCE_SHA256,
        "f25_c4_subset_sha256": _F25_C4_SUBSET_SHA256,
        "release": expected_release,
    }


def _runtime_manifest_payload(root: Path, metadata: dict[str, object]) -> dict[str, object]:
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


def _validated_manifest(root: Path, *, expected_digest: str | None = None) -> tuple[dict[str, object], str]:
    raw = _read_regular_bytes(root, _MANIFEST_NAME, max_bytes=_MAX_METADATA_BYTES)
    digest = _manifest_digest(raw)
    if expected_digest is not None and digest != expected_digest:
        raise _invalid()
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _invalid() from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 2:
        raise _invalid()
    metadata = _release_metadata(manifest)
    expected = _runtime_manifest_payload(root, metadata)
    if manifest != expected:
        raise _invalid()
    files = manifest.get("files")
    expected_d69 = (
        _F25_D69_SOURCE_SHA256
        if metadata["commit"] == _F25_COMMIT
        else {_D69_ANCHOR_PATH: _D69_ANCHOR_SHA256}
    )
    if not isinstance(files, dict) or any(
        not isinstance(files.get(path), dict)
        or files[path].get("sha256") != digest
        for path, digest in expected_d69.items()
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
        or mcp_entrypoint != root / "bin" / "codex-master-mcp"
        or probe_entrypoint != root / "bin" / "codex-master-hive-hourly-probe"
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
            mcp_entrypoint=root / "bin" / "codex-master-mcp",
            probe_entrypoint=root / "bin" / "codex-master-hive-hourly-probe",
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
            pointers = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object)
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
            if not isinstance(value, dict) or set(value) != {"generation", "manifest_digest"}:
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
        return cls.from_runtime_root(release_root / _RELEASE_GENERATIONS_NAME / generation)

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
                if len(relative.parts) >= 3 and relative.parts[:2] == ("src", "the_hive"):
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
