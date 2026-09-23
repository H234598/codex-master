"""Fixed ABI-v1 hook dispatch core.

The root-installation gate copies these exact bytes beside the immutable hook
launcher.  This module never imports a mutable release generation: callers
provide already-derived absolute roots and it validates the cache bundle,
release generation, root-install plan, and session binding before returning
held file-descriptor capabilities for the selected hook.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any
import types


class HookAbiV1Error(ValueError):
    """An ABI-v1 hook input, bundle, release, or capability is untrusted."""


_BUNDLE_SCHEMA = "TheHivePluginBundleV1"
_PLAN_SCHEMA = "RootInstallPlanV1"
_PLUGIN_ID = "the-hive"
_BUNDLE_DIRECTORY = "TheHivePluginBundleV1"
_DESCRIPTOR_NAME = "release-binding.json"
_MANIFEST_NAME = ".the-hive-runtime-manifest.json"
_PLAN_NAME = "root-install-plan.json"
_POINTER_NAME = ".the-hive-release-pointers.json"
_ABI_ROOT = "/usr/local/libexec/the-hive/hook-abi/v1"
_LAUNCHER_TARGET = f"{_ABI_ROOT}/launcher"
_PIN_STORE_TARGET = f"{_ABI_ROOT}/hook_session_pin_store.py"
_CORE_TARGET = f"{_ABI_ROOT}/hook_abi_v1_core.py"
_MAX_EVENT_BYTES = 64 * 1024
_MAX_METADATA_BYTES = 512 * 1024
_MAX_HOOK_BYTES = 2 * 1024 * 1024
_MAX_ALLOWLIST_BYTES = 512 * 1024
_ALLOWLIST_DIRECTORY = "allowlists"
_ALLOWLIST_DIRECTORY_PARTS = (
    "usr",
    "local",
    "libexec",
    "the-hive",
    "hook-abi",
    "v1",
    _ALLOWLIST_DIRECTORY,
)
_RUNTIME_LAYOUT_RELATIVE = f"{_BUNDLE_DIRECTORY}/src/the_hive/runtime_layout.py"
_ALLOWED_HOOKS = frozenset({"native_bee_event", "native_spawn_admission"})
_HOOK_EVENTS = {
    "native_bee_event": frozenset(
        {
            "PreToolUse",
            "PostToolUse",
            "SessionStart",
            "UserPromptSubmit",
            "SubagentStart",
            "SubagentStop",
            "Stop",
            "SessionEnd",
        }
    ),
    "native_spawn_admission": frozenset({"PreToolUse"}),
}


def _invalid() -> HookAbiV1Error:
    return HookAbiV1Error("hook_abi_v1_invalid")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def _safe_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _safe_generation(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and "/" not in value
        and value not in {".", ".."}
        and "\x00" not in value
    )


def _safe_session_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= 256
        and "\x00" not in value
        and not any(ord(character) < 0x20 for character in value)
    )


def _safe_absolute(path: Path) -> None:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise _invalid()


def _open_checked_directory(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int | None = None,
    protected_parts: tuple[str, ...] = (),
) -> int:
    """Return a held no-follow directory capability for an absolute path."""

    _safe_absolute(path)
    if protected_parts and (
        owner_gid is None
        or tuple(path.parts[-len(protected_parts) :]) != protected_parts
    ):
        raise _invalid()
    protected_anchor = bool(protected_parts) and path.parts == (
        path.anchor,
        *protected_parts,
    )
    protected_start = len(path.parts) - len(protected_parts)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = -1
    handed_off = False
    try:
        descriptor = os.open(path.anchor, flags)
        anchor_info = os.fstat(descriptor)
        if protected_anchor and (
            not stat.S_ISDIR(anchor_info.st_mode)
            or anchor_info.st_uid != owner_uid
            or anchor_info.st_gid != owner_gid
            or stat.S_IMODE(anchor_info.st_mode) & 0o022
        ):
            raise _invalid()
        for index, part in enumerate(path.parts[1:], start=1):
            child = os.open(part, flags, dir_fd=descriptor)
            child_info = os.fstat(child)
            if (
                not stat.S_ISDIR(child_info.st_mode)
                or (
                    index >= protected_start
                    and (
                        child_info.st_uid != owner_uid
                        or child_info.st_gid != owner_gid
                        or stat.S_IMODE(child_info.st_mode) & 0o022
                    )
                )
            ):
                os.close(child)
                raise _invalid()
            os.close(descriptor)
            descriptor = child
        item = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(item.st_mode)
            or item.st_uid != owner_uid
            or (owner_gid is not None and item.st_gid != owner_gid)
            or stat.S_IMODE(item.st_mode) & 0o022
        ):
            raise _invalid()
        handed_off = True
        return descriptor
    except HookAbiV1Error:
        raise
    except OSError as exc:
        raise _invalid() from exc
    finally:
        if descriptor >= 0 and not handed_off:
            os.close(descriptor)


def _checked_directory(path: Path, *, owner_uid: int | None = None) -> None:
    descriptor = _open_checked_directory(
        path, owner_uid=os.geteuid() if owner_uid is None else owner_uid
    )
    os.close(descriptor)


def _read_regular(
    path: Path,
    *,
    modes: set[int],
    maximum: int,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
    directory_owner_gid: int | None = None,
    directory_protected_parts: tuple[str, ...] = (),
) -> bytes:
    expected_owner = os.geteuid() if owner_uid is None else owner_uid
    directory = -1
    descriptor = -1
    try:
        directory = _open_checked_directory(
            path.parent,
            owner_uid=expected_owner,
            owner_gid=directory_owner_gid,
            protected_parts=directory_protected_parts,
        )
        try:
            descriptor = os.open(
                path.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory
            )
        except OSError as exc:
            raise _invalid() from exc
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_owner
            or (owner_gid is not None and before.st_gid != owner_gid)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in modes
            or not 0 < before.st_size <= maximum
        ):
            raise _invalid()
        chunks: list[bytes] = []
        remaining = before.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    except HookAbiV1Error:
        raise
    except OSError as exc:
        raise _invalid() from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0:
            os.close(directory)
    if (
        len(raw) != before.st_size
        or (owner_gid is not None and after.st_gid != owner_gid)
        or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
        )
    ):
        raise _invalid()
    return raw


def _read_json(path: Path, *, maximum: int = _MAX_METADATA_BYTES) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_regular(path, modes={0o644}, maximum=maximum).decode("utf-8"),
            object_pairs_hook=_unique_object,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _invalid() from exc
    if not isinstance(value, dict):
        raise _invalid()
    return value


def _descriptor(value: object) -> dict[str, object]:
    expected = {
        "schema",
        "plugin_id",
        "generation",
        "runtime_manifest_digest",
        "launcher_abi",
        "hooks",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise _invalid()
    hooks = value.get("hooks")
    if (
        value.get("schema") != _BUNDLE_SCHEMA
        or value.get("plugin_id") != _PLUGIN_ID
        or not _safe_generation(value.get("generation"))
        or not _safe_digest(value.get("runtime_manifest_digest"))
        or value.get("launcher_abi") != _LAUNCHER_TARGET
        or not isinstance(hooks, dict)
        or set(hooks) != _ALLOWED_HOOKS
        or any(not _safe_digest(hooks.get(name)) for name in _ALLOWED_HOOKS)
    ):
        raise _invalid()
    return dict(value)


def _binding_descriptor(binding: dict[str, object]) -> dict[str, object]:
    value = {
        "schema": _BUNDLE_SCHEMA,
        "plugin_id": _PLUGIN_ID,
        "generation": binding.get("generation"),
        "runtime_manifest_digest": binding.get("runtime_manifest_digest"),
        "launcher_abi": binding.get("launcher_abi"),
        "hooks": binding.get("hooks"),
    }
    return _descriptor(value)


def _manifest_hook_digest(manifest: dict[str, Any], relative: str) -> str:
    files = manifest.get("files")
    entry = files.get(relative) if isinstance(files, dict) else None
    digest = entry.get("sha256") if isinstance(entry, dict) else None
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise _invalid()
    return f"sha256:{digest}"


def _manifest_directory(manifest: dict[str, Any], relative: str) -> dict[str, int]:
    directories = manifest.get("directories")
    entry = directories.get(relative) if isinstance(directories, dict) else None
    if (
        not isinstance(entry, dict)
        or set(entry) != {"mode", "nlink"}
        or type(entry.get("mode")) is not int
        or entry["mode"] != 0o700
        or type(entry.get("nlink")) is not int
        or entry["nlink"] < 2
    ):
        raise _invalid()
    return {"mode": entry["mode"], "nlink": entry["nlink"]}


def _manifest_bundle_directory(manifest: dict[str, Any]) -> dict[str, int]:
    return _manifest_directory(manifest, _BUNDLE_DIRECTORY)


def _manifest_file(manifest: dict[str, Any], relative: str) -> dict[str, int | str]:
    files = manifest.get("files")
    entry = files.get(relative) if isinstance(files, dict) else None
    if (
        not isinstance(entry, dict)
        or set(entry) != {"mode", "nlink", "size", "sha256"}
        or type(entry.get("mode")) is not int
        or entry["mode"] < 0
        or entry["mode"] > 0o777
        or entry["mode"] & 0o022
        or entry.get("nlink") != 1
        or type(entry.get("size")) is not int
        or not 0 < entry["size"] <= _MAX_HOOK_BYTES
        or not isinstance(entry.get("sha256"), str)
        or len(entry["sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in entry["sha256"])
    ):
        raise _invalid()
    return {
        "mode": entry["mode"],
        "nlink": entry["nlink"],
        "size": entry["size"],
        "sha256": entry["sha256"],
    }


def _plan_source(
    plan: dict[str, Any],
    *,
    name: str,
    source: str,
    target: str,
    manifest: dict[str, Any],
) -> str:
    entry = plan.get(name)
    if (
        not isinstance(entry, dict)
        or set(entry) != {"source", "target", "sha256"}
        or entry.get("source") != source
        or entry.get("target") != target
        or not _safe_digest(entry.get("sha256"))
    ):
        raise _invalid()
    expected = _manifest_hook_digest(manifest, source)
    if entry["sha256"] != expected:
        raise _invalid()
    return expected


def _attest_plan(
    *,
    generation_root: Path,
    descriptor: dict[str, object],
    manifest: dict[str, Any],
    abi_root: Path,
    abi_owner_uid: int,
) -> tuple[bytes, bytes]:
    plan_raw = _read_regular(
        generation_root / _PLAN_NAME, modes={0o644}, maximum=_MAX_METADATA_BYTES
    )
    try:
        plan = json.loads(
            plan_raw.decode("utf-8"), object_pairs_hook=_unique_object
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _invalid() from exc
    if not isinstance(plan, dict):
        raise _invalid()
    if (
        set(plan)
        != {
            "schema",
            "plugin_id",
            "generation",
            "runtime_manifest_digest",
            "launcher",
            "companion",
            "core",
        }
        or plan.get("schema") != _PLAN_SCHEMA
        or plan.get("plugin_id") != _PLUGIN_ID
        or plan.get("generation") != descriptor["generation"]
        or plan.get("runtime_manifest_digest") != descriptor["runtime_manifest_digest"]
    ):
        raise _invalid()
    expected_launcher = _plan_source(
        plan,
        name="launcher",
        source="bin/the-hive-plugin-hook-stable",
        target=_LAUNCHER_TARGET,
        manifest=manifest,
    )
    expected_store = _plan_source(
        plan,
        name="companion",
        source="src/the_hive/hook_session_pin_store.py",
        target=_PIN_STORE_TARGET,
        manifest=manifest,
    )
    expected_core = _plan_source(
        plan,
        name="core",
        source="src/the_hive/hook_abi_v1_core.py",
        target=_CORE_TARGET,
        manifest=manifest,
    )
    _checked_directory(abi_root, owner_uid=abi_owner_uid)
    launcher_raw = _read_regular(
        abi_root / "launcher",
        modes={0o755},
        maximum=_MAX_HOOK_BYTES,
        owner_uid=abi_owner_uid,
    )
    companion_raw = _read_regular(
        abi_root / "hook_session_pin_store.py",
        modes={0o644},
        maximum=_MAX_HOOK_BYTES,
        owner_uid=abi_owner_uid,
    )
    core_raw = _read_regular(
        abi_root / "hook_abi_v1_core.py",
        modes={0o644},
        maximum=_MAX_HOOK_BYTES,
        owner_uid=abi_owner_uid,
    )
    actual = {
        "launcher": hashlib.sha256(launcher_raw).hexdigest(),
        "companion": hashlib.sha256(companion_raw).hexdigest(),
        "core": hashlib.sha256(core_raw).hexdigest(),
    }
    if actual != {
        "launcher": expected_launcher[7:],
        "companion": expected_store[7:],
        "core": expected_core[7:],
    }:
        raise _invalid()
    return companion_raw, plan_raw


def _attest_release(
    *,
    release_root: Path,
    descriptor: dict[str, object],
    abi_root: Path,
    abi_owner_uid: int,
) -> tuple[Path, dict[str, Any], bytes, bytes, bytes]:
    _checked_directory(release_root)
    generation = descriptor["generation"]
    assert isinstance(generation, str)
    generation_root = release_root / "generations" / generation
    _checked_directory(generation_root)
    manifest_raw = _read_regular(
        generation_root / _MANIFEST_NAME, modes={0o644}, maximum=_MAX_METADATA_BYTES
    )
    if (
        "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
        != descriptor["runtime_manifest_digest"]
    ):
        raise _invalid()
    try:
        manifest = json.loads(
            manifest_raw.decode("utf-8"), object_pairs_hook=_unique_object
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _invalid() from exc
    if not isinstance(manifest, dict):
        raise _invalid()
    bundle_root = generation_root / _BUNDLE_DIRECTORY
    _checked_directory(bundle_root)
    release_descriptor_raw = _read_regular(
        bundle_root / _DESCRIPTOR_NAME, modes={0o644}, maximum=_MAX_METADATA_BYTES
    )
    try:
        release_descriptor = _descriptor(
            json.loads(
                release_descriptor_raw.decode("utf-8"), object_pairs_hook=_unique_object
            )
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _invalid() from exc
    if release_descriptor != descriptor:
        raise _invalid()
    for name in _ALLOWED_HOOKS:
        relative = f"{_BUNDLE_DIRECTORY}/hooks/{name}.py"
        if _manifest_hook_digest(manifest, relative) != descriptor["hooks"][name]:
            raise _invalid()
        raw = _read_regular(
            bundle_root / "hooks" / f"{name}.py",
            modes={0o644},
            maximum=_MAX_HOOK_BYTES,
        )
        if "sha256:" + hashlib.sha256(raw).hexdigest() != descriptor["hooks"][name]:
            raise _invalid()
    companion_raw, plan_raw = _attest_plan(
        generation_root=generation_root,
        descriptor=descriptor,
        manifest=manifest,
        abi_root=abi_root,
        abi_owner_uid=abi_owner_uid,
    )
    return bundle_root, manifest, companion_raw, release_descriptor_raw, plan_raw


def _pin_store_api(companion_raw: bytes) -> tuple[type[object], type[ValueError]]:
    """Load only the already-attested fixed-ABI companion bytes.

    The ABI is executed with ``python -I``.  Loading source directly from the
    attested byte string avoids a mutable ``sys.path`` lookup and closes the
    check-to-load path race.  The generated module name is content-addressed
    so dataclass metadata remains stable while every dispatch receives the
    exact companion bytes that its release plan attested.
    """

    digest = hashlib.sha256(companion_raw).hexdigest()
    name = f"_the_hive_hook_session_pin_store_v1_{digest}"
    module = types.ModuleType(name)
    module.__file__ = _PIN_STORE_TARGET
    sys.modules[name] = module
    try:
        exec(compile(companion_raw, _PIN_STORE_TARGET, "exec"), module.__dict__)
    except (SyntaxError, ValueError, TypeError) as exc:
        sys.modules.pop(name, None)
        raise _invalid() from exc
    store_type = getattr(module, "HookSessionPinStoreV1", None)
    error_type = getattr(module, "HookSessionPinStoreError", None)
    if not isinstance(store_type, type) or not isinstance(error_type, type):
        raise _invalid()
    if not issubclass(error_type, ValueError):
        raise _invalid()
    return store_type, error_type


def _plugin_descriptor(plugin_root: Path) -> tuple[dict[str, object], bytes]:
    _checked_directory(plugin_root)
    raw = _read_regular(
        plugin_root / _DESCRIPTOR_NAME, modes={0o644}, maximum=_MAX_METADATA_BYTES
    )
    try:
        return _descriptor(
            json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        ), raw
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _invalid() from exc


def _attest_dispatch_allowlist(
    *,
    abi_root: Path,
    abi_owner_uid: int,
    bundle_root: Path,
    manifest: dict[str, Any],
    descriptor: dict[str, object],
    descriptor_raw: bytes,
    root_install_plan: bytes,
) -> None:
    """Validate the root-owned S1 allowlist before any pin or hook FD escapes."""

    if not isinstance(descriptor_raw, bytes) or not isinstance(
        root_install_plan, bytes
    ):
        raise _invalid()
    allowlist_name = f"{hashlib.sha256(descriptor_raw).hexdigest()}.json"
    allowlist_raw = _read_regular(
        abi_root / _ALLOWLIST_DIRECTORY / allowlist_name,
        modes={0o644},
        maximum=_MAX_ALLOWLIST_BYTES,
        owner_uid=abi_owner_uid,
        owner_gid=abi_owner_uid,
        directory_owner_gid=abi_owner_uid,
        directory_protected_parts=_ALLOWLIST_DIRECTORY_PARTS,
    )
    layout_raw = _read_regular(
        bundle_root / "src" / "the_hive" / "runtime_layout.py",
        modes={0o644},
        maximum=_MAX_HOOK_BYTES,
    )
    if (
        "sha256:" + hashlib.sha256(layout_raw).hexdigest()
        != _manifest_hook_digest(manifest, _RUNTIME_LAYOUT_RELATIVE)
    ):
        raise _invalid()
    module_name = (
        f"_the_hive_dispatch_allowlist_v1_{hashlib.sha256(layout_raw).hexdigest()}"
    )
    module = types.ModuleType(module_name)
    module.__file__ = f"{bundle_root}/src/the_hive/runtime_layout.py"
    sys.modules[module_name] = module
    try:
        exec(compile(layout_raw, module.__file__, "exec"), module.__dict__)
        validator = getattr(module, "_validate_dispatch_allowlist", None)
        if not callable(validator):
            raise _invalid()
        validator(
            allowlist_raw,
            manifest,
            descriptor["runtime_manifest_digest"],
            descriptor_raw,
            root_install_plan,
        )
    except HookAbiV1Error:
        raise
    except Exception as exc:
        raise _invalid() from exc
    finally:
        sys.modules.pop(module_name, None)


def _pointer_binding(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"generation", "manifest_digest"}
        or not _safe_generation(value.get("generation"))
        or not _safe_digest(value.get("manifest_digest"))
    ):
        raise _invalid()
    return {
        "generation": value["generation"],
        "manifest_digest": value["manifest_digest"],
    }


def _attest_first_session_start_pointer(
    *, release_root: Path, descriptor: dict[str, object]
) -> None:
    """Bind a new session only to the one current transactional generation.

    D319's stable launcher treated the pointer file as its release authority.
    Existing session pins are separately attestable retained generations, but
    the first binding must not originate from a previous or stale cache
    descriptor.
    """

    try:
        value = json.loads(
            _read_regular(
                release_root / _POINTER_NAME,
                modes={0o644},
                maximum=_MAX_METADATA_BYTES,
            ).decode("utf-8"),
            object_pairs_hook=_unique_object,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _invalid() from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "current", "previous"}
        or value.get("schema_version") != 1
    ):
        raise _invalid()
    current = _pointer_binding(value.get("current"))
    _pointer_binding(value.get("previous"))
    if current != {
        "generation": descriptor["generation"],
        "manifest_digest": descriptor["runtime_manifest_digest"],
    }:
        raise _invalid()


def _event(stdin_bytes: bytes, *, hook_name: str) -> tuple[str, str]:
    if hook_name not in _ALLOWED_HOOKS or not isinstance(stdin_bytes, bytes):
        raise _invalid()
    if not 0 < len(stdin_bytes) <= _MAX_EVENT_BYTES:
        raise _invalid()
    try:
        value = json.loads(
            stdin_bytes.decode("utf-8"), object_pairs_hook=_unique_object
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _invalid() from exc
    if not isinstance(value, dict):
        raise _invalid()
    session_id = value.get("session_id")
    event_name = value.get("hook_event_name")
    if not _safe_session_id(session_id) or event_name not in _HOOK_EVENTS[hook_name]:
        raise _invalid()
    return session_id, event_name


def _checked_directory_info(item: os.stat_result, expected: dict[str, int]) -> None:
    if (
        not stat.S_ISDIR(item.st_mode)
        or item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) != expected["mode"]
        or item.st_nlink != expected["nlink"]
    ):
        raise _invalid()


def _read_manifest_regular_at(
    parent_fd: int, name: str, expected: dict[str, int | str]
) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != expected["nlink"]
            or stat.S_IMODE(before.st_mode) != expected["mode"]
            or before.st_size != expected["size"]
        ):
            raise _invalid()
        chunks: list[bytes] = []
        remaining = before.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    except HookAbiV1Error:
        raise
    except OSError as exc:
        raise _invalid() from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        len(raw) != before.st_size
        or hashlib.sha256(raw).hexdigest() != expected["sha256"]
        or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
        )
    ):
        raise _invalid()


def _attest_bundle_source_tree(bundle_fd: int, manifest: dict[str, Any]) -> None:
    """Attest the complete importable bundle source tree through held FDs.

    Hooks prepend ``PLUGIN_ROOT/src`` to ``sys.path``.  Therefore each direct
    and transitive member beneath that source root must be an exact member of
    the external immutable runtime manifest before a hook capability escapes.
    """

    prefix = f"{_BUNDLE_DIRECTORY}/src"
    package_relative = f"{prefix}/the_hive"
    directories = manifest.get("directories")
    files = manifest.get("files")
    if not isinstance(directories, dict) or not isinstance(files, dict):
        raise _invalid()
    expected_directories: dict[tuple[str, ...], dict[str, int]] = {}
    for relative in directories:
        if relative == prefix or relative.startswith(prefix + "/"):
            suffix = relative.removeprefix(prefix).lstrip("/")
            parts = () if not suffix else tuple(suffix.split("/"))
            if any(not part or part in {".", ".."} for part in parts):
                raise _invalid()
            expected_directories[parts] = _manifest_directory(manifest, relative)
    expected_files: dict[tuple[str, ...], dict[str, int | str]] = {}
    for relative in files:
        if relative.startswith(prefix + "/"):
            suffix = relative.removeprefix(prefix + "/")
            parts = tuple(suffix.split("/"))
            if any(not part or part in {".", ".."} for part in parts):
                raise _invalid()
            expected_files[parts] = _manifest_file(manifest, relative)
    if () not in expected_directories or ("the_hive",) not in expected_directories:
        raise _invalid()
    if any(
        parts and parts[:-1] not in expected_directories
        for parts in expected_directories
    ):
        raise _invalid()
    if any(parts[:-1] not in expected_directories for parts in expected_files):
        raise _invalid()
    if not any(parts[:1] == ("the_hive",) for parts in expected_files):
        raise _invalid()

    def attest_directory(parent_fd: int, name: str, parts: tuple[str, ...]) -> None:
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            before = os.fstat(descriptor)
            _checked_directory_info(before, expected_directories[parts])
            names = set(os.listdir(descriptor))
            expected_names = {
                item[-1]
                for item in expected_directories
                if len(item) == len(parts) + 1 and item[:-1] == parts
            }
            expected_names.update(
                item[-1] for item in expected_files if item[:-1] == parts
            )
            if names != expected_names:
                raise _invalid()
            for child in sorted(
                item for item in expected_directories if item[:-1] == parts and item
            ):
                attest_directory(descriptor, child[-1], child)
            for child in sorted(item for item in expected_files if item[:-1] == parts):
                _read_manifest_regular_at(descriptor, child[-1], expected_files[child])
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_nlink,
            ):
                raise _invalid()
        except HookAbiV1Error:
            raise
        except OSError as exc:
            raise _invalid() from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    attest_directory(bundle_fd, "src", ())
    _manifest_directory(manifest, package_relative)


def _open_hook_capabilities(
    bundle_root: Path, *, manifest: dict[str, Any], hook_name: str, digest: str
) -> tuple[int, int]:
    bundle_fd = -1
    hook_fd = -1
    hooks_fd = -1
    handed_off = False
    try:
        bundle_fd = _open_checked_directory(bundle_root, owner_uid=os.geteuid())
        bundle_info = os.fstat(bundle_fd)
        expected_bundle = _manifest_bundle_directory(manifest)
        if (
            not stat.S_ISDIR(bundle_info.st_mode)
            or bundle_info.st_uid != os.geteuid()
            or stat.S_IMODE(bundle_info.st_mode) != expected_bundle["mode"]
            or bundle_info.st_nlink != expected_bundle["nlink"]
        ):
            raise _invalid()
        _attest_bundle_source_tree(bundle_fd, manifest)
        hooks_fd = os.open(
            "hooks",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=bundle_fd,
        )
        hook_fd = os.open(
            f"{hook_name}.py",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=hooks_fd,
        )
        hook_info = os.fstat(hook_fd)
        if (
            not stat.S_ISREG(hook_info.st_mode)
            or hook_info.st_uid != os.geteuid()
            or hook_info.st_nlink != 1
            or stat.S_IMODE(hook_info.st_mode) != 0o644
            or not 0 < hook_info.st_size <= _MAX_HOOK_BYTES
        ):
            raise _invalid()
        raw = os.read(hook_fd, hook_info.st_size + 1)
        after = os.fstat(hook_fd)
        if (
            len(raw) != hook_info.st_size
            or "sha256:" + hashlib.sha256(raw).hexdigest() != digest
            or (hook_info.st_dev, hook_info.st_ino, hook_info.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
        ):
            raise _invalid()
        os.lseek(hook_fd, 0, os.SEEK_SET)
        os.set_inheritable(bundle_fd, True)
        os.set_inheritable(hook_fd, True)
        handed_off = True
        return bundle_fd, hook_fd
    except HookAbiV1Error:
        raise
    except OSError as exc:
        raise _invalid() from exc
    finally:
        if hooks_fd >= 0:
            os.close(hooks_fd)
        if hook_fd >= 0 and not handed_off:
            os.close(hook_fd)
        if bundle_fd >= 0 and not handed_off:
            os.close(bundle_fd)


@dataclass(slots=True)
class AttestedHookDispatchV1:
    """Held immutable capabilities and untouched input for one hook exec."""

    hook_fd: int
    bundle_fd: int
    stdin_bytes: bytes
    generation: str
    runtime_manifest_digest: str
    hook_name: str

    def close(self) -> None:
        for descriptor in (self.hook_fd, self.bundle_fd):
            if descriptor >= 0:
                os.close(descriptor)
        self.hook_fd = -1
        self.bundle_fd = -1


def dispatch_hook_v1(
    *,
    plugin_root: Path,
    release_root: Path,
    state_root: Path,
    abi_root: Path,
    abi_owner_uid: int,
    hook_name: str,
    stdin_bytes: bytes,
    now_unix_ns: int,
) -> AttestedHookDispatchV1:
    """Attest and pin one hook, returning only held capabilities for dispatch.

    All root inputs are explicit to make direct temporary-root tests possible.
    The fixed ABI launcher derives production roots and supplies them; no
    environment-configured runtime or cache path is accepted here.
    """

    if (
        type(now_unix_ns) is not int
        or now_unix_ns < 0
        or type(abi_owner_uid) is not int
        or abi_owner_uid < 0
    ):
        raise _invalid()
    session_id, event_name = _event(stdin_bytes, hook_name=hook_name)
    descriptor, cache_descriptor_raw = _plugin_descriptor(plugin_root)
    (
        current_bundle,
        current_manifest,
        companion_raw,
        current_descriptor_raw,
        current_plan_raw,
    ) = _attest_release(
        release_root=release_root,
        descriptor=descriptor,
        abi_root=abi_root,
        abi_owner_uid=abi_owner_uid,
    )
    if cache_descriptor_raw != current_descriptor_raw:
        raise _invalid()
    _attest_dispatch_allowlist(
        abi_root=abi_root,
        abi_owner_uid=abi_owner_uid,
        bundle_root=current_bundle,
        manifest=current_manifest,
        descriptor=descriptor,
        descriptor_raw=cache_descriptor_raw,
        root_install_plan=current_plan_raw,
    )
    try:
        store_type, _store_error = _pin_store_api(companion_raw)
        store = (
            store_type.create_at(state_root)
            if event_name == "SessionStart"
            else store_type.open_at(state_root)
        )
        existing = store.bindings().get(session_id)
    except (AttributeError, TypeError, ValueError) as exc:
        raise _invalid() from exc
    if existing is None:
        if event_name != "SessionStart":
            raise _invalid()
        _attest_first_session_start_pointer(
            release_root=release_root, descriptor=descriptor
        )
        selected = descriptor
        try:
            store.bind_session(
                session_id=session_id,
                generation=selected["generation"],
                runtime_manifest_digest=selected["runtime_manifest_digest"],
                hooks=selected["hooks"],
                now_unix_ns=now_unix_ns,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise _invalid() from exc
        selected_bundle = current_bundle
        selected_manifest = current_manifest
    else:
        selected = _binding_descriptor(existing)
        (
            selected_bundle,
            selected_manifest,
            _selected_companion_raw,
            selected_descriptor_raw,
            selected_plan_raw,
        ) = _attest_release(
            release_root=release_root,
            descriptor=selected,
            abi_root=abi_root,
            abi_owner_uid=abi_owner_uid,
        )
        _attest_dispatch_allowlist(
            abi_root=abi_root,
            abi_owner_uid=abi_owner_uid,
            bundle_root=selected_bundle,
            manifest=selected_manifest,
            descriptor=selected,
            descriptor_raw=selected_descriptor_raw,
            root_install_plan=selected_plan_raw,
        )
        try:
            if event_name == "SessionEnd":
                store.end_session(session_id=session_id, now_unix_ns=now_unix_ns)
            else:
                store.bind_session(
                    session_id=session_id,
                    generation=selected["generation"],
                    runtime_manifest_digest=selected["runtime_manifest_digest"],
                    hooks=selected["hooks"],
                    now_unix_ns=now_unix_ns,
                )
        except (AttributeError, TypeError, ValueError) as exc:
            raise _invalid() from exc
    generation = selected["generation"]
    manifest_digest = selected["runtime_manifest_digest"]
    hooks = selected["hooks"]
    if (
        not isinstance(generation, str)
        or not isinstance(manifest_digest, str)
        or not isinstance(hooks, dict)
        or not isinstance(hooks.get(hook_name), str)
    ):
        raise _invalid()
    bundle_fd = -1
    hook_fd = -1
    try:
        bundle_fd, hook_fd = _open_hook_capabilities(
            selected_bundle,
            manifest=selected_manifest,
            hook_name=hook_name,
            digest=hooks[hook_name],
        )
        return AttestedHookDispatchV1(
            hook_fd=hook_fd,
            bundle_fd=bundle_fd,
            stdin_bytes=stdin_bytes,
            generation=generation,
            runtime_manifest_digest=manifest_digest,
            hook_name=hook_name,
        )
    except Exception:
        if hook_fd >= 0:
            os.close(hook_fd)
        if bundle_fd >= 0:
            os.close(bundle_fd)
        raise


__all__ = ["AttestedHookDispatchV1", "HookAbiV1Error", "dispatch_hook_v1"]
