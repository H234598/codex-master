"""Immutable, fail-closed paths for the single The Hive runtime image."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any
import weakref


class LayoutError(ValueError):
    """The runtime image is not a private, complete regular-file image."""


_MAX_IMAGE_FILE_BYTES = 2 * 1024 * 1024
_MAX_METADATA_BYTES = 256 * 1024
_ROOT_MODE = 0o700
_MANIFEST_NAME = ".the-hive-runtime-manifest.json"
_RELEASE_BINDING_NAME = "release-binding.json"
_PLUGIN_BUNDLE_DIRECTORY = "TheHivePluginBundleV1"
_ROOT_INSTALL_PLAN_NAME = "root-install-plan.json"
_HOOK_ABI_V1_LAUNCHER = "/usr/local/libexec/the-hive/hook-abi/v1/launcher"
_HOOK_ABI_V1_COMPANION = (
    "/usr/local/libexec/the-hive/hook-abi/v1/hook_session_pin_store.py"
)
_HOOK_ABI_V1_CORE = "/usr/local/libexec/the-hive/hook-abi/v1/hook_abi_v1_core.py"
_RELEASE_POINTERS_NAME = ".the-hive-release-pointers.json"
_RELEASE_GENERATIONS_NAME = "generations"
_RUNTIME_SPAWN_HELPER = "src/the_hive/_runtime_spawn_helper.so"
_STATE_DIRECTORY_ENV = "STATE_DIRECTORY"
_STATE_DIRECTORY_BASENAME = "the-hive-ga-i2d-quiescence"
_STATE_DIRECTORY_MODE = 0o700
_STATE_LAYOUT_FACTORY_PROVENANCE: dict[
    int, weakref.ReferenceType[RuntimeStateLayoutV1]
] = {}
_RESERVED_STATE_PARENTS = frozenset(
    {
        "admin",
        "codex-master-admin",
        "codex-master-vault",
        "image",
        "runtime",
        "runtime-image",
        "the-hive-runtime",
        "vault",
    }
)
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
_STABLE_HOOK_LAUNCHER_SOURCE = "bin/the-hive-plugin-hook-stable"
_HOOK_BINDING_ENTRYPOINTS = {
    "native_bee_event": "hooks/native_bee_event.py",
    "native_spawn_admission": "hooks/native_spawn_admission.py",
}
_PLUGIN_BUNDLE_REQUIRED_FILES: tuple[tuple[str, int], ...] = (
    (".codex-plugin/plugin.json", 0o644),
    (".mcp.json", 0o644),
    (".app.json", 0o644),
    ("hooks/hooks.json", 0o644),
    ("hooks/native_bee_event.py", 0o644),
    ("hooks/native_spawn_admission.py", 0o644),
    ("skills/the-hive-fleet/SKILL.md", 0o644),
)
_STABLE_MCP_COMMAND = "/home/teladi/.local/lib/the-hive-runtime/the-hive-mcp"
_STABLE_MCP_NOTE = (
    "Local data-sparse Codex Masterjet MCP server. Controls the sleeping "
    "Agentinnen pool through tmux and does not return raw terminal output by default."
)
_REQUIRED_FILES: tuple[tuple[str, int], ...] = (
    ("bin/the-hive-mcp", 0o755),
    (_STABLE_MCP_LAUNCHER_SOURCE, 0o755),
    (_STABLE_HOOK_LAUNCHER_SOURCE, 0o755),
    ("bin/the-hive-resource-monitor", 0o755),
    ("bin/the-hive-hive-hourly-probe", 0o755),
    (".codex-plugin/plugin.json", 0o644),
    (".mcp.json", 0o644),
    (".app.json", 0o644),
    ("hooks/hooks.json", 0o644),
    ("hooks/native_bee_event.py", 0o644),
    ("hooks/native_spawn_admission.py", 0o644),
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


def _state_invalid() -> LayoutError:
    return LayoutError("runtime_state_layout_invalid")


def _remember_state_layout_factory_provenance(layout: RuntimeStateLayoutV1) -> None:
    identity = id(layout)

    def forget(reference: weakref.ReferenceType[RuntimeStateLayoutV1]) -> None:
        if _STATE_LAYOUT_FACTORY_PROVENANCE.get(identity) is reference:
            _STATE_LAYOUT_FACTORY_PROVENANCE.pop(identity, None)

    _STATE_LAYOUT_FACTORY_PROVENANCE[identity] = weakref.ref(layout, forget)


def _require_state_layout_factory_provenance(layout: object) -> None:
    if type(layout) is not RuntimeStateLayoutV1:
        raise _state_invalid()
    reference = _STATE_LAYOUT_FACTORY_PROVENANCE.get(id(layout))
    if reference is None or reference() is not layout:
        raise _state_invalid()


def _is_canonical_state_directory_entry(entry: str) -> bool:
    if not entry.startswith("/") or entry == "/" or entry.endswith("/"):
        return False
    parts = entry.split("/")
    return all(part and part not in {".", ".."} for part in parts[1:])


def _lstat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise _invalid() from exc


def _state_lstat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise _state_invalid() from exc


def _validate_state_directory_path(path: Path) -> os.stat_result:
    if not isinstance(path, Path) or not path.is_absolute():
        raise _state_invalid()
    if path.name != _STATE_DIRECTORY_BASENAME:
        raise _state_invalid()
    if any(part in {".", ".."} for part in path.parts):
        raise _state_invalid()

    def reserved(part: str) -> bool:
        normalized = part.casefold().replace("_", "-")
        return (
            normalized in _RESERVED_STATE_PARENTS
            or "admin" in normalized
            or "vault" in normalized
            or "runtime-image" in normalized
            or normalized.endswith("-runtime")
        )

    if any(reserved(part) for part in path.parts[:-1]):
        raise _state_invalid()

    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        info = _state_lstat(current)
        if stat.S_ISLNK(info.st_mode):
            raise _state_invalid()
    info = _state_lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != _STATE_DIRECTORY_MODE
    ):
        raise _state_invalid()
    return info


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
        "hook_abi_source": _STABLE_HOOK_LAUNCHER_SOURCE,
        "hook_abi": _HOOK_ABI_V1_LAUNCHER,
        "hook_abi_companion": _HOOK_ABI_V1_COMPANION,
        "hook_abi_core": _HOOK_ABI_V1_CORE,
        "hook_entrypoints": list(_HOOK_BINDING_ENTRYPOINTS.values()),
        "plugin_bundle": _PLUGIN_BUNDLE_DIRECTORY,
        "root_install_plan": _ROOT_INSTALL_PLAN_NAME,
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


def release_binding_bytes(manifest: dict[str, object], manifest_digest: str) -> bytes:
    """Build the one canonical bundle descriptor for an attested release."""

    metadata = _release_metadata(manifest)
    generation = metadata["generation"]
    files = manifest.get("files")
    if (
        not isinstance(generation, str)
        or not isinstance(files, dict)
        or not isinstance(manifest_digest, str)
        or len(manifest_digest) != 71
        or not manifest_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in manifest_digest[7:])
    ):
        raise _invalid()
    hook_digests: dict[str, str] = {}
    for hook_name, entrypoint in _HOOK_BINDING_ENTRYPOINTS.items():
        entry = files.get(f"{_PLUGIN_BUNDLE_DIRECTORY}/{entrypoint}")
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise _invalid()
        hook_digests[hook_name] = f"sha256:{digest}"
    descriptor = {
        "schema": "TheHivePluginBundleV1",
        "plugin_id": "the-hive",
        "generation": generation,
        "runtime_manifest_digest": manifest_digest,
        "launcher_abi": _HOOK_ABI_V1_LAUNCHER,
        "hooks": hook_digests,
    }
    try:
        return (
            json.dumps(
                descriptor, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise _invalid() from exc


def root_install_plan_bytes(manifest: dict[str, object], manifest_digest: str) -> bytes:
    """Build the source-only, digest-bound immutable ABI-v1 installation plan."""

    metadata = _release_metadata(manifest)
    generation = metadata["generation"]
    files = manifest.get("files")
    if (
        not isinstance(generation, str)
        or not isinstance(files, dict)
        or not isinstance(manifest_digest, str)
        or len(manifest_digest) != 71
        or not manifest_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in manifest_digest[7:])
    ):
        raise _invalid()

    def source(name: str, target: str) -> dict[str, str]:
        entry = files.get(name)
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise _invalid()
        return {"source": name, "target": target, "sha256": f"sha256:{digest}"}

    plan = {
        "schema": "RootInstallPlanV1",
        "plugin_id": "the-hive",
        "generation": generation,
        "runtime_manifest_digest": manifest_digest,
        "launcher": source(_STABLE_HOOK_LAUNCHER_SOURCE, _HOOK_ABI_V1_LAUNCHER),
        "companion": source(
            "src/the_hive/hook_session_pin_store.py", _HOOK_ABI_V1_COMPANION
        ),
        "core": source("src/the_hive/hook_abi_v1_core.py", _HOOK_ABI_V1_CORE),
    }
    try:
        return (
            json.dumps(plan, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise _invalid() from exc


def _is_sha256_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def dispatch_allowlist_bytes(
    manifest: dict[str, object], manifest_digest: str
) -> bytes:
    """Build the private, canonical D320 dispatch allowlist record."""

    metadata = _release_metadata(manifest)
    generation = metadata["generation"]
    files = manifest.get("files")
    if (
        not isinstance(generation, str)
        or not isinstance(files, dict)
        or not _is_sha256_digest(manifest_digest)
    ):
        raise _invalid()
    hook_digests: dict[str, str] = {}
    for hook_name, entrypoint in _HOOK_BINDING_ENTRYPOINTS.items():
        entry = files.get(f"{_PLUGIN_BUNDLE_DIRECTORY}/{entrypoint}")
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise _invalid()
        hook_digests[hook_name] = f"sha256:{digest}"
    descriptor = release_binding_bytes(manifest, manifest_digest)
    root_install_plan = root_install_plan_bytes(manifest, manifest_digest)
    allowlist = {
        "schema": "D320DispatchAllowlistV1",
        "plugin_id": "the-hive",
        "generation": generation,
        "runtime_manifest_digest": manifest_digest,
        "launcher_abi": _HOOK_ABI_V1_LAUNCHER,
        "descriptor_sha256": _manifest_digest(descriptor),
        "root_install_plan_sha256": _manifest_digest(root_install_plan),
        "hooks": hook_digests,
    }
    try:
        return (
            json.dumps(
                allowlist, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise _invalid() from exc


def _validate_dispatch_allowlist(
    raw: bytes,
    manifest: dict[str, object],
    manifest_digest: str,
    descriptor: bytes,
    root_install_plan: bytes,
) -> None:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= _MAX_METADATA_BYTES:
        raise _invalid()
    try:
        allowlist = json.loads(
            raw.decode("ascii"), object_pairs_hook=_unique_json_object
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _invalid() from exc
    if not isinstance(allowlist, dict) or set(allowlist) != {
        "schema",
        "plugin_id",
        "generation",
        "runtime_manifest_digest",
        "launcher_abi",
        "descriptor_sha256",
        "root_install_plan_sha256",
        "hooks",
    }:
        raise _invalid()
    generation = allowlist.get("generation")
    if (
        allowlist.get("schema") != "D320DispatchAllowlistV1"
        or allowlist.get("plugin_id") != "the-hive"
        or not isinstance(generation, str)
        or not generation
        or "/" in generation
        or generation in {".", ".."}
        or not _is_sha256_digest(allowlist.get("runtime_manifest_digest"))
        or not _is_sha256_digest(allowlist.get("descriptor_sha256"))
        or not _is_sha256_digest(allowlist.get("root_install_plan_sha256"))
        or allowlist.get("launcher_abi") != _HOOK_ABI_V1_LAUNCHER
    ):
        raise _invalid()
    hooks = allowlist.get("hooks")
    if (
        not isinstance(hooks, dict)
        or set(hooks) != set(_HOOK_BINDING_ENTRYPOINTS)
        or any(not _is_sha256_digest(hooks.get(name)) for name in hooks)
    ):
        raise _invalid()
    expected_descriptor = release_binding_bytes(manifest, manifest_digest)
    expected_root_install_plan = root_install_plan_bytes(manifest, manifest_digest)
    if (
        descriptor != expected_descriptor
        or root_install_plan != expected_root_install_plan
        or raw != dispatch_allowlist_bytes(manifest, manifest_digest)
    ):
        raise _invalid()


def _validate_release_binding(
    root: Path, manifest: dict[str, object], manifest_digest: str
) -> None:
    descriptor = _read_regular_bytes(
        root,
        f"{_PLUGIN_BUNDLE_DIRECTORY}/{_RELEASE_BINDING_NAME}",
        max_bytes=_MAX_METADATA_BYTES,
    )
    if descriptor != release_binding_bytes(manifest, manifest_digest):
        raise _invalid()


def _validate_root_install_plan(
    root: Path, manifest: dict[str, object], manifest_digest: str
) -> None:
    plan = _read_regular_bytes(
        root, _ROOT_INSTALL_PLAN_NAME, max_bytes=_MAX_METADATA_BYTES
    )
    if plan != root_install_plan_bytes(manifest, manifest_digest):
        raise _invalid()


def _validate_plugin_bundle(
    root: Path, manifest: dict[str, object], manifest_digest: str
) -> None:
    """Cross-check the non-manifested native bundle against the sealed image."""

    bundle_root = _image_path(root, _PLUGIN_BUNDLE_DIRECTORY)
    bundle_info = _lstat(bundle_root)
    if (
        not stat.S_ISDIR(bundle_info.st_mode)
        or stat.S_ISLNK(bundle_info.st_mode)
        or bundle_info.st_uid != os.geteuid()
        or stat.S_IMODE(bundle_info.st_mode) != _ROOT_MODE
    ):
        raise _invalid()
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise _invalid()
    expected_files = {relative for relative, _mode in _PLUGIN_BUNDLE_REQUIRED_FILES}
    expected_files.update(
        relative
        for relative in files
        if relative.startswith(("skills/the-hive-fleet/", "src/the_hive/"))
    )
    expected_files.add(_RELEASE_BINDING_NAME)
    observed_files: set[str] = set()
    for directory, child_directories, file_names in os.walk(bundle_root):
        current = Path(directory)
        current_info = _lstat(current)
        if (
            stat.S_ISLNK(current_info.st_mode)
            or not stat.S_ISDIR(current_info.st_mode)
            or current_info.st_uid != os.geteuid()
            or stat.S_IMODE(current_info.st_mode) != _ROOT_MODE
        ):
            raise _invalid()
        child_directories[:] = sorted(child_directories)
        for name in child_directories:
            _image_path(
                root,
                f"{_PLUGIN_BUNDLE_DIRECTORY}/"
                f"{(current / name).relative_to(bundle_root).as_posix()}",
            )
        for name in sorted(file_names):
            relative = (current / name).relative_to(bundle_root).as_posix()
            observed_files.add(relative)
    if observed_files != expected_files:
        raise _invalid()
    for relative, mode in _PLUGIN_BUNDLE_REQUIRED_FILES:
        source = _validate_regular(root, relative, mode)
        bundle = _validate_regular(root, f"{_PLUGIN_BUNDLE_DIRECTORY}/{relative}", mode)
        if _read_regular_bytes(
            root, relative, max_bytes=_MAX_IMAGE_FILE_BYTES
        ) != _read_regular_bytes(
            root,
            f"{_PLUGIN_BUNDLE_DIRECTORY}/{relative}",
            max_bytes=_MAX_IMAGE_FILE_BYTES,
        ):
            raise _invalid()
        if source == bundle:
            raise _invalid()
    for relative in expected_files - {_RELEASE_BINDING_NAME}:
        if relative not in files:
            raise _invalid()
        source = _read_regular_bytes(root, relative, max_bytes=_MAX_IMAGE_FILE_BYTES)
        bundle = _read_regular_bytes(
            root,
            f"{_PLUGIN_BUNDLE_DIRECTORY}/{relative}",
            max_bytes=_MAX_IMAGE_FILE_BYTES,
        )
        if source != bundle:
            raise _invalid()
    _validate_release_binding(root, manifest, manifest_digest)


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
            # The descriptor binds this manifest's digest, so including its
            # own hash here would create an unresolvable digest cycle.  It is
            # instead revalidated byte-for-byte against this manifest below.
            if relative_path in {
                _MANIFEST_NAME,
                _ROOT_INSTALL_PLAN_NAME,
                f"{_PLUGIN_BUNDLE_DIRECTORY}/{_RELEASE_BINDING_NAME}",
            }:
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
    _validate_root_install_plan(root, manifest, digest)
    _validate_plugin_bundle(root, manifest, digest)
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


@dataclass(frozen=True, slots=True, init=False, weakref_slot=True)
class RuntimeStateLayoutV1:
    """The independently owned systemd state directory for GA-I2d P0."""

    state_root: Path
    state_root_device: int
    state_root_inode: int

    def __new__(cls) -> RuntimeStateLayoutV1:
        del cls
        raise _state_invalid()

    @classmethod
    def from_systemd_state_directory(cls) -> RuntimeStateLayoutV1:
        """Select one exact, already materialized systemd state entry."""

        if cls is not RuntimeStateLayoutV1:
            raise _state_invalid()
        raw = os.environ.get(_STATE_DIRECTORY_ENV)
        if not isinstance(raw, str) or not raw:
            raise _state_invalid()
        raw_entries = raw.split(":")
        if any(
            not entry
            or any(character.isspace() for character in entry)
            or not _is_canonical_state_directory_entry(entry)
            for entry in raw_entries
        ):
            raise _state_invalid()
        entries = [Path(entry) for entry in raw_entries]
        if any(not entry.is_absolute() for entry in entries):
            raise _state_invalid()
        candidates = [
            entry
            for entry in entries
            if entry.is_absolute() and entry.name == _STATE_DIRECTORY_BASENAME
        ]
        if len(candidates) != 1:
            raise _state_invalid()
        state_root = candidates[0]
        if any(
            other != state_root and (state_root == other or other in state_root.parents)
            for other in entries
        ):
            raise _state_invalid()
        metadata = _validate_state_directory_path(state_root)
        layout = object.__new__(cls)
        object.__setattr__(layout, "state_root", state_root)
        object.__setattr__(layout, "state_root_device", metadata.st_dev)
        object.__setattr__(layout, "state_root_inode", metadata.st_ino)
        _remember_state_layout_factory_provenance(layout)
        return layout

    @property
    def state_directory(self) -> Path:
        return self.state_root

    @property
    def basename(self) -> str:
        return self.state_root.name

    @property
    def device(self) -> int:
        return self.state_root_device

    @property
    def inode(self) -> int:
        return self.state_root_inode

    @property
    def state_device(self) -> int:
        return self.state_root_device

    @property
    def state_inode(self) -> int:
        return self.state_root_inode

    def validate(self) -> None:
        _require_state_layout_factory_provenance(self)
        metadata = _validate_state_directory_path(self.state_root)
        if (metadata.st_dev, metadata.st_ino) != (
            self.state_root_device,
            self.state_root_inode,
        ):
            raise _state_invalid()

    def open_dirfd(self) -> int:
        """Open and re-attest the exact final state directory without following
        links."""

        _require_state_layout_factory_provenance(self)
        expected = _validate_state_directory_path(self.state_root)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        if (
            not getattr(os, "O_NOFOLLOW", 0)
            or not getattr(os, "O_DIRECTORY", 0)
            or not getattr(os, "O_CLOEXEC", 0)
        ):
            raise _state_invalid()
        descriptor = -1
        try:
            descriptor = os.open(Path(self.state_root.anchor), flags)
            for part in self.state_root.parts[1:]:
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            actual = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(actual.st_mode)
                or actual.st_uid != os.geteuid()
                or stat.S_IMODE(actual.st_mode) != _STATE_DIRECTORY_MODE
                or (actual.st_dev, actual.st_ino)
                != (self.state_root_device, self.state_root_inode)
                or (expected.st_dev, expected.st_ino)
                != (self.state_root_device, self.state_root_inode)
            ):
                raise _state_invalid()
            return descriptor
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise _state_invalid() from exc
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            raise


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
