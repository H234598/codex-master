from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys

import pytest

import the_hive.hook_abi_v1_core as hook_core
from the_hive.hook_abi_v1_core import HookAbiV1Error, dispatch_hook_v1
from the_hive.runtime_layout import dispatch_allowlist_bytes


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


def _installer() -> dict[str, object]:
    return runpy.run_path(str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install"))


def _stage(installer: dict[str, object], root: Path, generation: str) -> Path:
    stage = root / f".stage-{generation}"
    stage.mkdir(mode=0o700)
    installer["_build_runtime_image"](  # type: ignore[operator]
        repository=ROOT, stage=stage, generation=generation, commit=COMMIT
    )
    return stage


def _rewrite_manifest(
    installer: dict[str, object], stage: Path, generation: str
) -> None:
    (stage / ".the-hive-runtime-manifest.json").unlink()
    installer["_write_runtime_image_manifest"](  # type: ignore[operator]
        root=stage, generation=generation, commit=COMMIT
    )


def _copy_abi(abi_root: Path) -> None:
    abi_root.mkdir(mode=0o700, exist_ok=True)
    sources = {
        "launcher": ROOT / "bin" / "the-hive-plugin-hook-stable",
        "hook_session_pin_store.py": ROOT
        / "src"
        / "the_hive"
        / "hook_session_pin_store.py",
        "hook_abi_v1_core.py": ROOT / "src" / "the_hive" / "hook_abi_v1_core.py",
    }
    for target, source in sources.items():
        shutil.copy2(source, abi_root / target)
        (abi_root / target).chmod(0o755 if target == "launcher" else 0o644)


def _allowlist_path(abi_root: Path, descriptor: bytes) -> Path:
    return abi_root / "allowlists" / f"{hashlib.sha256(descriptor).hexdigest()}.json"


def _write_allowlist(release_root: Path, plugin_root: Path, abi_root: Path) -> Path:
    descriptor = (plugin_root / "release-binding.json").read_bytes()
    generation = json.loads(descriptor.decode("utf-8"))["generation"]
    assert isinstance(generation, str)
    manifest_path = (
        release_root / "generations" / generation / ".the-hive-runtime-manifest.json"
    )
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8"))
    assert isinstance(manifest, dict)
    path = _allowlist_path(abi_root, descriptor)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_bytes(
        dispatch_allowlist_bytes(
            manifest, f"sha256:{hashlib.sha256(manifest_raw).hexdigest()}"
        )
    )
    path.chmod(0o644)
    return path


def _write_pointers(
    release_root: Path, *, current: str, previous: str | None = None
) -> None:
    def binding(generation: str | None) -> dict[str, str] | None:
        if generation is None:
            return None
        descriptor = json.loads(
            (
                release_root
                / "generations"
                / generation
                / "TheHivePluginBundleV1"
                / "release-binding.json"
            ).read_text(encoding="utf-8")
        )
        return {
            "generation": descriptor["generation"],
            "manifest_digest": descriptor["runtime_manifest_digest"],
        }

    (release_root / ".the-hive-release-pointers.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "current": binding(current),
                "previous": binding(previous),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    (release_root / ".the-hive-release-pointers.json").chmod(0o644)


def _fixture(
    tmp_path: Path, *, hook_server_stub: str | None = None
) -> tuple[dict[str, object], Path, Path, Path, Path]:
    installer = _installer()
    release_root = tmp_path / "release"
    (release_root / "generations").mkdir(mode=0o700, parents=True)
    first = _stage(installer, tmp_path, "one")
    if hook_server_stub is not None:
        server = first / "src" / "the_hive" / "server.py"
        server.write_text(hook_server_stub, encoding="utf-8")
        server.chmod(0o644)
        _rewrite_manifest(installer, first, "one")
    first.rename(release_root / "generations" / "one")
    _write_pointers(release_root, current="one")
    plugin_root = tmp_path / "plugin-root"
    shutil.copytree(
        release_root / "generations" / "one" / "TheHivePluginBundleV1", plugin_root
    )
    abi_root = tmp_path / "abi-root" / "usr"
    abi_root.mkdir(mode=0o700, parents=True)
    abi_root.chmod(0o700)
    for part in ("local", "libexec", "the-hive", "hook-abi", "v1"):
        abi_root /= part
        abi_root.mkdir(mode=0o700)
        abi_root.chmod(0o700)
    _copy_abi(abi_root)
    _write_allowlist(release_root, plugin_root, abi_root)
    state_root = tmp_path / "state" / "hook-session-pins-v1"
    return installer, release_root, plugin_root, abi_root, state_root


def _dispatch(
    *,
    release_root: Path,
    plugin_root: Path,
    abi_root: Path,
    state_root: Path,
    payload: bytes,
    now: int,
    hook_name: str = "native_bee_event",
):
    return dispatch_hook_v1(
        plugin_root=plugin_root,
        release_root=release_root,
        state_root=state_root,
        abi_root=abi_root,
        abi_owner_uid=os.geteuid(),
        hook_name=hook_name,
        stdin_bytes=payload,
        now_unix_ns=now,
    )


def test_core_returns_held_attested_capabilities_and_original_event_bytes(
    tmp_path: Path,
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    payload = b'{"session_id":"session-one","hook_event_name":"SessionStart"}'

    result = _dispatch(
        release_root=release_root,
        plugin_root=plugin_root,
        abi_root=abi_root,
        state_root=state_root,
        payload=payload,
        now=10,
    )
    try:
        assert result.generation == "one"
        assert result.stdin_bytes is payload
        assert result.hook_name == "native_bee_event"
        assert os.get_inheritable(result.hook_fd)
        assert os.get_inheritable(result.bundle_fd)
        assert os.read(result.hook_fd, 16)
    finally:
        result.close()


def test_core_rejects_an_absent_allowlist_before_pin_or_hook_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    _allowlist_path(
        abi_root, (plugin_root / "release-binding.json").read_bytes()
    ).unlink()

    def unexpected_hook_handoff(*_args: object, **_kwargs: object) -> object:
        pytest.fail("hook FD handoff must not run without an allowlist")

    monkeypatch.setattr(hook_core, "_open_hook_capabilities", unexpected_hook_handoff)
    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )

    assert not state_root.exists()


def test_core_rejects_layout_validator_source_drift_before_pin(
    tmp_path: Path,
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    layout_source = (
        release_root
        / "generations"
        / "one"
        / "TheHivePluginBundleV1"
        / "src"
        / "the_hive"
        / "runtime_layout.py"
    )
    layout_source.write_bytes(layout_source.read_bytes() + b"\n")
    layout_source.chmod(0o644)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )

    assert not state_root.exists()


@pytest.mark.parametrize("kind", ("symlink", "hardlink", "mode", "parent_mode"))
def test_core_rejects_untrusted_allowlist_files_and_parents(
    tmp_path: Path, kind: str
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    path = _allowlist_path(
        abi_root, (plugin_root / "release-binding.json").read_bytes()
    )
    if kind == "symlink":
        replacement = path.with_name("replacement.json")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o644)
        path.unlink()
        path.symlink_to(replacement.name)
    elif kind == "hardlink":
        replacement = path.with_name("replacement.json")
        os.link(path, replacement)
    elif kind == "mode":
        path.chmod(0o600)
    else:
        path.parent.chmod(0o775)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )

    assert not state_root.exists()


@pytest.mark.parametrize("phase", ("before", "after"))
def test_core_rejects_allowlist_owner_drift_before_pin_or_hook_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    path = _allowlist_path(
        abi_root, (plugin_root / "release-binding.json").read_bytes()
    )
    original_fstat = hook_core.os.fstat
    allowlist_fstat_calls = 0

    def fstat_with_foreign_allowlist_owner(descriptor: int) -> os.stat_result:
        nonlocal allowlist_fstat_calls
        item = original_fstat(descriptor)
        if os.readlink(f"/proc/self/fd/{descriptor}") == str(path):
            allowlist_fstat_calls += 1
            if (phase == "before" and allowlist_fstat_calls == 1) or (
                phase == "after" and allowlist_fstat_calls == 2
            ):
                values = list(item)
                values[4] = item.st_uid + 1
                return os.stat_result(values)
        return item

    def unexpected_pin_store_api(*_args: object, **_kwargs: object) -> object:
        pytest.fail("pin API must not run with a foreign allowlist owner")

    def unexpected_hook_handoff(*_args: object, **_kwargs: object) -> object:
        pytest.fail("hook FD handoff must not run with a foreign allowlist owner")

    monkeypatch.setattr(hook_core.os, "fstat", fstat_with_foreign_allowlist_owner)
    monkeypatch.setattr(hook_core, "_pin_store_api", unexpected_pin_store_api)
    monkeypatch.setattr(hook_core, "_open_hook_capabilities", unexpected_hook_handoff)
    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )

    assert allowlist_fstat_calls == (1 if phase == "before" else 2)
    assert not state_root.exists()


@pytest.mark.parametrize("phase", ("matching", "before", "after"))
def test_read_regular_enforces_the_requested_owner_before_and_after_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    path = tmp_path / "allowlist.json"
    contents = b'{"schema":"D320DispatchAllowlistV1"}\n'
    path.write_bytes(contents)
    path.chmod(0o644)
    expected_uid = path.stat().st_uid
    original_fstat = hook_core.os.fstat
    target_fstat_calls = 0

    def fstat_with_owner_drift(descriptor: int) -> os.stat_result:
        nonlocal target_fstat_calls
        item = original_fstat(descriptor)
        if os.readlink(f"/proc/self/fd/{descriptor}") == str(path):
            target_fstat_calls += 1
            if (phase == "before" and target_fstat_calls == 1) or (
                phase == "after" and target_fstat_calls == 2
            ):
                values = list(item)
                values[4] = expected_uid ^ 1
                return os.stat_result(values)
        return item

    monkeypatch.setattr(hook_core.os, "fstat", fstat_with_owner_drift)

    if phase == "matching":
        assert (
            hook_core._read_regular(
                path,
                modes={0o644},
                maximum=512 * 1024,
                owner_uid=expected_uid,
            )
            == contents
        )
        assert target_fstat_calls == 2
    else:
        with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
            hook_core._read_regular(
                path,
                modes={0o644},
                maximum=512 * 1024,
                owner_uid=expected_uid,
            )
        assert target_fstat_calls == (1 if phase == "before" else 2)


@pytest.mark.parametrize("phase", ("matching", "before", "after"))
def test_read_regular_enforces_the_requested_group_before_and_after_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    path = tmp_path / "allowlist.json"
    contents = b'{"schema":"D320DispatchAllowlistV1"}\n'
    path.write_bytes(contents)
    path.chmod(0o644)
    expected_gid = path.stat().st_gid
    original_fstat = hook_core.os.fstat
    target_fstat_calls = 0

    def fstat_with_group_drift(descriptor: int) -> os.stat_result:
        nonlocal target_fstat_calls
        item = original_fstat(descriptor)
        if os.readlink(f"/proc/self/fd/{descriptor}") == str(path):
            target_fstat_calls += 1
            if (phase == "before" and target_fstat_calls == 1) or (
                phase == "after" and target_fstat_calls == 2
            ):
                values = list(item)
                values[5] = expected_gid ^ 1
                return os.stat_result(values)
        return item

    monkeypatch.setattr(hook_core.os, "fstat", fstat_with_group_drift)

    if phase == "matching":
        assert (
            hook_core._read_regular(
                path,
                modes={0o644},
                maximum=512 * 1024,
                owner_gid=expected_gid,
            )
            == contents
        )
        assert target_fstat_calls == 2
    else:
        with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
            hook_core._read_regular(
                path,
                modes={0o644},
                maximum=512 * 1024,
                owner_gid=expected_gid,
            )
        assert target_fstat_calls == (1 if phase == "before" else 2)


@pytest.mark.parametrize("drift", ("uid", "gid", "mode"))
def test_open_checked_directory_rejects_protected_intermediate_parent_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    # Defect caught: accepting a protected chain when a held intermediate FD
    # reports a foreign owner/group or a writable mode during no-follow walk.
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    target = protected / "target"
    target.mkdir(mode=0o700)
    target_info = target.stat()
    original_fstat = hook_core.os.fstat
    protected_fstat_calls = 0

    def fstat_with_protected_parent_drift(descriptor: int) -> os.stat_result:
        nonlocal protected_fstat_calls
        item = original_fstat(descriptor)
        if os.readlink(f"/proc/self/fd/{descriptor}") == str(protected):
            protected_fstat_calls += 1
            values = list(item)
            if drift == "uid":
                values[4] = item.st_uid + 1
            elif drift == "gid":
                values[5] = item.st_gid + 1
            else:
                values[0] = item.st_mode | 0o020
            return os.stat_result(values)
        return item

    monkeypatch.setattr(hook_core.os, "fstat", fstat_with_protected_parent_drift)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        hook_core._open_checked_directory(
            target,
            owner_uid=target_info.st_uid,
            owner_gid=target_info.st_gid,
            protected_parts=("protected", "target"),
        )

    assert protected_fstat_calls == 1


@pytest.mark.parametrize("drift", ("uid", "gid", "mode"))
def test_open_checked_directory_rejects_protected_anchor_drift(
    monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    # Defect caught: accepting the held / capability when it is foreign or
    # writable lets an untrusted anchor precede the fixed allowlist chain.
    path = Path("/usr/local/libexec/the-hive/hook-abi/v1/allowlists")
    opened_paths: list[str] = []
    descriptors = iter(range(100, 100 + len(path.parts)))

    def open_synthetic_directory(
        name: str, _flags: int, _mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        if dir_fd is None:
            assert name == "/"
        else:
            assert name in path.parts[1:]
        opened_paths.append(name)
        return next(descriptors)

    def fstat_with_anchor_drift(descriptor: int) -> os.stat_result:
        mode = stat.S_IFDIR | 0o755
        uid = 0
        gid = 0
        if descriptor == 100:
            if drift == "uid":
                uid = 1
            elif drift == "gid":
                gid = 1
            else:
                mode |= 0o020
        return os.stat_result((mode, descriptor, 1, 1, uid, gid, 0, 0, 0, 0))

    monkeypatch.setattr(hook_core.os, "open", open_synthetic_directory)
    monkeypatch.setattr(hook_core.os, "fstat", fstat_with_anchor_drift)
    monkeypatch.setattr(hook_core.os, "close", lambda _descriptor: None)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        hook_core._open_checked_directory(
            path,
            owner_uid=0,
            owner_gid=0,
            protected_parts=hook_core._ALLOWLIST_DIRECTORY_PARTS,
        )

    assert opened_paths == ["/"]


@pytest.mark.parametrize("phase", ("before", "after"))
def test_core_rejects_allowlist_group_drift_before_pin_or_hook_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    path = _allowlist_path(
        abi_root, (plugin_root / "release-binding.json").read_bytes()
    )
    original_fstat = hook_core.os.fstat
    allowlist_fstat_calls = 0

    def fstat_with_foreign_allowlist_group(descriptor: int) -> os.stat_result:
        nonlocal allowlist_fstat_calls
        item = original_fstat(descriptor)
        if os.readlink(f"/proc/self/fd/{descriptor}") == str(path):
            allowlist_fstat_calls += 1
            if (phase == "before" and allowlist_fstat_calls == 1) or (
                phase == "after" and allowlist_fstat_calls == 2
            ):
                values = list(item)
                values[5] = item.st_gid + 1
                return os.stat_result(values)
        return item

    def unexpected_hook_handoff(*_args: object, **_kwargs: object) -> object:
        pytest.fail("hook FD handoff must not run with a foreign allowlist group")

    monkeypatch.setattr(hook_core.os, "fstat", fstat_with_foreign_allowlist_group)
    monkeypatch.setattr(hook_core, "_open_hook_capabilities", unexpected_hook_handoff)
    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )

    assert not state_root.exists()


@pytest.mark.parametrize("kind", ("gid", "group_write", "other_write"))
def test_core_rejects_an_untrusted_intermediate_allowlist_parent_before_pin_or_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    # Defect caught: checking only allowlists/ misses a foreign or writable
    # hook-abi/ parent while resolving the fixed allowlist directory chain.
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    intermediate = abi_root.parent
    if kind == "group_write":
        intermediate.chmod(0o770)
    elif kind == "other_write":
        intermediate.chmod(0o707)
    else:
        original_fstat = hook_core.os.fstat

        def fstat_with_foreign_intermediate_group(
            descriptor: int,
        ) -> os.stat_result:
            item = original_fstat(descriptor)
            if os.readlink(f"/proc/self/fd/{descriptor}") == str(intermediate):
                values = list(item)
                values[5] = item.st_gid + 1
                return os.stat_result(values)
            return item

        monkeypatch.setattr(
            hook_core.os, "fstat", fstat_with_foreign_intermediate_group
        )

    def unexpected_hook_handoff(*_args: object, **_kwargs: object) -> object:
        pytest.fail("hook FD handoff must not run with an unsafe allowlist parent")

    monkeypatch.setattr(hook_core, "_open_hook_capabilities", unexpected_hook_handoff)
    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )

    assert not state_root.exists()


def test_attest_plan_directly_returns_exact_held_plan_raw_bytes(
    tmp_path: Path,
) -> None:
    _installer_value, release_root, plugin_root, abi_root, _state_root = _fixture(
        tmp_path
    )
    descriptor, _descriptor_raw = hook_core._plugin_descriptor(plugin_root)
    generation = descriptor["generation"]
    assert isinstance(generation, str)
    generation_root = release_root / "generations" / generation
    manifest = json.loads(
        (generation_root / ".the-hive-runtime-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert isinstance(manifest, dict)
    plan_path = generation_root / "root-install-plan.json"
    expected_plan_raw = plan_path.read_bytes().rstrip(b"\n") + b" \t\n"
    plan_path.write_bytes(expected_plan_raw)
    plan_path.chmod(0o644)
    expected_companion_raw = (abi_root / "hook_session_pin_store.py").read_bytes()

    companion_raw, plan_raw = hook_core._attest_plan(
        generation_root=generation_root,
        descriptor=descriptor,
        manifest=manifest,
        abi_root=abi_root,
        abi_owner_uid=os.geteuid(),
    )

    assert companion_raw == expected_companion_raw
    assert plan_raw == expected_plan_raw


def test_attest_plan_directly_rejects_a_core_digest_drift(tmp_path: Path) -> None:
    _installer_value, release_root, plugin_root, abi_root, _state_root = _fixture(
        tmp_path
    )
    descriptor, _descriptor_raw = hook_core._plugin_descriptor(plugin_root)
    generation = descriptor["generation"]
    assert isinstance(generation, str)
    generation_root = release_root / "generations" / generation
    manifest = json.loads(
        (generation_root / ".the-hive-runtime-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert isinstance(manifest, dict)
    plan_path = generation_root / "root-install-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert isinstance(plan, dict)
    core = plan["core"]
    assert isinstance(core, dict)
    core["sha256"] = "sha256:" + "0" * 64
    plan_path.write_text(json.dumps(plan, sort_keys=True) + "\n", encoding="utf-8")
    plan_path.chmod(0o644)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        hook_core._attest_plan(
            generation_root=generation_root,
            descriptor=descriptor,
            manifest=manifest,
            abi_root=abi_root,
            abi_owner_uid=os.geteuid(),
        )


def test_attest_release_directly_rejects_a_release_descriptor_drift(
    tmp_path: Path,
) -> None:
    _installer_value, release_root, plugin_root, abi_root, _state_root = _fixture(
        tmp_path
    )
    descriptor, _descriptor_raw = hook_core._plugin_descriptor(plugin_root)
    release_descriptor_path = (
        release_root
        / "generations"
        / "one"
        / "TheHivePluginBundleV1"
        / "release-binding.json"
    )
    release_descriptor = json.loads(release_descriptor_path.read_text(encoding="utf-8"))
    assert isinstance(release_descriptor, dict)
    release_descriptor["generation"] = "other"
    release_descriptor_path.write_text(
        json.dumps(release_descriptor, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    release_descriptor_path.chmod(0o644)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        hook_core._attest_release(
            release_root=release_root,
            descriptor=descriptor,
            abi_root=abi_root,
            abi_owner_uid=os.geteuid(),
        )


def test_attest_dispatch_allowlist_directly_rejects_binding_drift(
    tmp_path: Path,
) -> None:
    _installer_value, release_root, plugin_root, abi_root, _state_root = _fixture(
        tmp_path
    )
    descriptor, descriptor_raw = hook_core._plugin_descriptor(plugin_root)
    bundle_root, manifest, _companion_raw, _release_raw, plan_raw = (
        hook_core._attest_release(
            release_root=release_root,
            descriptor=descriptor,
            abi_root=abi_root,
            abi_owner_uid=os.geteuid(),
        )
    )
    path = _allowlist_path(abi_root, descriptor_raw)
    allowlist = json.loads(path.read_text(encoding="ascii"))
    assert isinstance(allowlist, dict)
    allowlist["launcher_abi"] = "/usr/local/libexec/the-hive/hook-abi/v1/not-launcher"
    path.write_text(
        json.dumps(allowlist, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    path.chmod(0o644)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        hook_core._attest_dispatch_allowlist(
            abi_root=abi_root,
            abi_owner_uid=os.geteuid(),
            bundle_root=bundle_root,
            manifest=manifest,
            descriptor=descriptor,
            descriptor_raw=descriptor_raw,
            root_install_plan=plan_raw,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("descriptor_sha256", "sha256:" + "0" * 64),
        ("runtime_manifest_digest", "sha256:" + "1" * 64),
        ("root_install_plan_sha256", "sha256:" + "2" * 64),
        ("launcher_abi", "/usr/local/libexec/the-hive/hook-abi/v1/not-launcher"),
    ),
)
def test_core_rejects_allowlist_binding_field_drift(
    tmp_path: Path, field: str, value: str
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    path = _allowlist_path(
        abi_root, (plugin_root / "release-binding.json").read_bytes()
    )
    allowlist = json.loads(path.read_text(encoding="ascii"))
    allowlist[field] = value
    path.write_text(
        json.dumps(allowlist, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    path.chmod(0o644)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )

    assert not state_root.exists()


@pytest.mark.parametrize("hook_name", ("native_bee_event", "native_spawn_admission"))
def test_core_rejects_each_allowlist_hook_digest_drift(
    tmp_path: Path, hook_name: str
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    path = _allowlist_path(
        abi_root, (plugin_root / "release-binding.json").read_bytes()
    )
    allowlist = json.loads(path.read_text(encoding="ascii"))
    allowlist["hooks"][hook_name] = "sha256:" + "3" * 64
    path.write_text(
        json.dumps(allowlist, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    path.chmod(0o644)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )

    assert not state_root.exists()


def test_core_uses_the_exact_descriptor_bytes_for_the_allowlist_name(
    tmp_path: Path,
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    descriptor = (plugin_root / "release-binding.json").read_bytes() + b" "
    (plugin_root / "release-binding.json").write_bytes(descriptor)
    release_descriptor = (
        release_root
        / "generations"
        / "one"
        / "TheHivePluginBundleV1"
        / "release-binding.json"
    )
    release_descriptor.write_bytes(descriptor)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )

    assert not state_root.exists()


def test_core_pins_a_session_across_a_new_current_bundle(tmp_path: Path) -> None:
    installer, release_root, plugin_root, abi_root, state_root = _fixture(tmp_path)
    started = _dispatch(
        release_root=release_root,
        plugin_root=plugin_root,
        abi_root=abi_root,
        state_root=state_root,
        payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
        now=10,
    )
    started.close()
    second = _stage(installer, tmp_path, "two")
    second.rename(release_root / "generations" / "two")
    _write_pointers(release_root, current="two", previous="one")
    shutil.rmtree(plugin_root)
    shutil.copytree(
        release_root / "generations" / "two" / "TheHivePluginBundleV1", plugin_root
    )
    _write_allowlist(release_root, plugin_root, abi_root)

    resumed = _dispatch(
        release_root=release_root,
        plugin_root=plugin_root,
        abi_root=abi_root,
        state_root=state_root,
        payload=b'{"session_id":"session-one","hook_event_name":"UserPromptSubmit"}',
        now=20,
    )
    try:
        assert resumed.generation == "one"
    finally:
        resumed.close()


def test_core_reads_the_retained_allowlist_for_an_active_pinned_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer, release_root, plugin_root, abi_root, state_root = _fixture(tmp_path)
    started = _dispatch(
        release_root=release_root,
        plugin_root=plugin_root,
        abi_root=abi_root,
        state_root=state_root,
        payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
        now=10,
    )
    started.close()
    retained_descriptor = (
        release_root
        / "generations"
        / "one"
        / "TheHivePluginBundleV1"
        / "release-binding.json"
    ).read_bytes()
    retained_allowlist = _allowlist_path(abi_root, retained_descriptor)
    retained_stat = retained_allowlist.stat()
    retained_identity = (
        retained_stat.st_dev,
        retained_stat.st_ino,
        retained_stat.st_mode,
        retained_stat.st_uid,
        retained_stat.st_gid,
        retained_stat.st_nlink,
        retained_stat.st_size,
    )
    retained_bytes = retained_allowlist.read_bytes()
    second = _stage(installer, tmp_path, "two")
    second.rename(release_root / "generations" / "two")
    _write_pointers(release_root, current="two", previous="one")
    shutil.rmtree(plugin_root)
    shutil.copytree(
        release_root / "generations" / "two" / "TheHivePluginBundleV1", plugin_root
    )
    _write_allowlist(release_root, plugin_root, abi_root)
    reads: list[Path] = []
    original_read_regular = hook_core._read_regular

    def record_retained_allowlist(path: Path, **kwargs: object) -> bytes:
        if path == retained_allowlist:
            reads.append(path)
        return original_read_regular(path, **kwargs)

    monkeypatch.setattr(hook_core, "_read_regular", record_retained_allowlist)
    resumed = _dispatch(
        release_root=release_root,
        plugin_root=plugin_root,
        abi_root=abi_root,
        state_root=state_root,
        payload=b'{"session_id":"session-one","hook_event_name":"UserPromptSubmit"}',
        now=20,
    )
    try:
        assert resumed.generation == "one"
    finally:
        resumed.close()

    assert reads == [retained_allowlist]
    after = retained_allowlist.stat()
    assert (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
        after.st_size,
    ) == retained_identity
    assert retained_allowlist.read_bytes() == retained_bytes


def test_core_rejects_a_root_plan_core_digest_mismatch_before_dispatch(
    tmp_path: Path,
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    plan_path = release_root / "generations" / "one" / "root-install-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["core"]["sha256"] = "sha256:" + "0" * 64
    plan_path.write_text(json.dumps(plan, sort_keys=True) + "\n", encoding="utf-8")
    plan_path.chmod(0o644)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )

    assert not state_root.exists()


def test_core_rejects_held_bundle_fd_when_manifest_nlink_drifts(
    tmp_path: Path,
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    (
        release_root / "generations" / "one" / "TheHivePluginBundleV1" / "unexpected"
    ).mkdir(mode=0o700)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )


def test_first_session_start_rejects_a_descriptor_not_at_current_pointer(
    tmp_path: Path,
) -> None:
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path
    )
    _write_pointers(release_root, current="one")
    pointer = json.loads(
        (release_root / ".the-hive-release-pointers.json").read_text(encoding="utf-8")
    )
    pointer["current"]["generation"] = "other"
    (release_root / ".the-hive-release-pointers.json").write_text(
        json.dumps(pointer, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (release_root / ".the-hive-release-pointers.json").chmod(0o644)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )


def test_fd_backed_bundle_executes_both_hooks_with_its_bundled_server_source(
    tmp_path: Path,
) -> None:
    stub = """\
def activate_native_agent_resume(payload):
    return {"allowed": False, "error_code": "fd_bundled_server",
            "reason_codes": ["bundled_source"]}


def reserve_native_agent_spawn(payload):
    return {"allowed": False, "error_code": "fd_bundled_server",
            "reason_codes": ["bundled_source"]}
"""
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path, hook_server_stub=stub
    )
    started = _dispatch(
        release_root=release_root,
        plugin_root=plugin_root,
        abi_root=abi_root,
        state_root=state_root,
        payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
        now=10,
    )
    started.close()
    agent_state = tmp_path / "agent-state"
    agent_state.mkdir(mode=0o700)
    (agent_state / "native-agents.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "agents": [{"session_id": "session-one", "agent_id": "agent-one"}],
                "sessions": [],
                "reservations": [],
            }
        ),
        encoding="utf-8",
    )
    cases = (
        (
            "native_bee_event",
            b'{"session_id":"session-one","hook_event_name":"PreToolUse","tool_name":"send_input","tool_input":{"target":"agent-one"}}',
        ),
        (
            "native_spawn_admission",
            b'{"session_id":"session-one","hook_event_name":"PreToolUse","tool_name":"spawn_agent","tool_input":{},"cwd":"/tmp"}',
        ),
    )
    for index, (hook_name, payload) in enumerate(cases, start=20):
        result = _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            hook_name=hook_name,
            payload=payload,
            now=index,
        )
        try:
            completed = subprocess.run(
                [sys.executable, "-I", "-B", f"/proc/self/fd/{result.hook_fd}"],
                check=False,
                input=result.stdin_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "PATH": "/usr/bin:/bin",
                    "PLUGIN_ROOT": f"/proc/self/fd/{result.bundle_fd}",
                    "CODEX_MASTER_MCP_STATE": str(agent_state),
                },
                pass_fds=(result.hook_fd, result.bundle_fd),
            )
        finally:
            result.close()
        assert completed.returncode == 0, completed.stderr.decode("utf-8")
        assert b"fd_bundled_server" in completed.stdout
        assert b"bundled_source" in completed.stdout


def test_core_rejects_same_shape_mutated_bundle_server_before_dispatch(
    tmp_path: Path,
) -> None:
    stub = """\
def activate_native_agent_resume(payload):
    return {"allowed": False, "error_code": "fd_bundled_server",
            "reason_codes": ["bundled_source"]}


def reserve_native_agent_spawn(payload):
    return {"allowed": False, "error_code": "fd_bundled_server",
            "reason_codes": ["bundled_source"]}
"""
    _installer_value, release_root, plugin_root, abi_root, state_root = _fixture(
        tmp_path, hook_server_stub=stub
    )
    server = (
        release_root
        / "generations"
        / "one"
        / "TheHivePluginBundleV1"
        / "src"
        / "the_hive"
        / "server.py"
    )
    original = server.read_bytes()
    mutated = original.replace(b"fd_bundled_server", b"fd_bundled_source", 1)
    assert len(mutated) == len(original)
    server.write_bytes(mutated)
    server.chmod(0o644)

    with pytest.raises(HookAbiV1Error, match="hook_abi_v1_invalid"):
        _dispatch(
            release_root=release_root,
            plugin_root=plugin_root,
            abi_root=abi_root,
            state_root=state_root,
            payload=b'{"session_id":"session-one","hook_event_name":"SessionStart"}',
            now=10,
        )
