from __future__ import annotations

import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

import pytest

from the_hive.hook_abi_v1_core import HookAbiV1Error, dispatch_hook_v1


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
    abi_root.mkdir(mode=0o700)
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
    abi_root = tmp_path / "abi-v1"
    _copy_abi(abi_root)
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
    return {"allowed": False, "error_code": "fd_bundled_server", "reason_codes": ["bundled_source"]}


def reserve_native_agent_spawn(payload):
    return {"allowed": False, "error_code": "fd_bundled_server", "reason_codes": ["bundled_source"]}
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
    return {"allowed": False, "error_code": "fd_bundled_server", "reason_codes": ["bundled_source"]}


def reserve_native_agent_spawn(payload):
    return {"allowed": False, "error_code": "fd_bundled_server", "reason_codes": ["bundled_source"]}
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
