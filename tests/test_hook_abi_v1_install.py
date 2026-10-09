"""Small root-gate fixtures; all writes stay below pytest's temporary directory."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import tempfile

import pytest
from the_hive.hook_abi_v1_core import HookAbiV1Error, dispatch_hook_v1


ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/the-hive-hook-abi-v1-install"))
GENERATION = "a" * 40


@pytest.fixture
def safe_tmp_path(monkeypatch):
    # Model trusted deployment ancestors without changing host permissions.
    # Only these exact directory inodes are substituted; fixture descendants
    # still pass through the real ownership and mode checks.
    real_fstat = os.fstat
    sandbox_ancestors = {(p.stat().st_dev, p.stat().st_ino) for p in (Path('/'), Path('/home'))}
    temporary_ancestor = Path(tempfile.gettempdir()).stat()
    temporary_identity = (temporary_ancestor.st_dev, temporary_ancestor.st_ino)
    def sandbox_fstat(fd):
        result = real_fstat(fd)
        identity = (result.st_dev, result.st_ino)
        if identity in sandbox_ancestors or identity == temporary_identity:
            values = list(result)
            values[4:6] = [0, 0]
            if identity == temporary_identity:
                values[0] = stat.S_IFDIR | 0o755
            return os.stat_result(values)
        return result
    monkeypatch.setattr(os, 'fstat', sandbox_fstat)
    with tempfile.TemporaryDirectory(prefix="hook-abi-gate-test-", dir=ROOT) as path:
        yield Path(path)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _put(path, raw, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def _fixture(tmp_path):
    home = tmp_path / "home"
    release = home / ".local/lib/the-hive-runtime"
    generation = release / "generations" / GENERATION
    generation.mkdir(mode=0o700, parents=True)
    files = {}
    sources = {
        "bin/the-hive-plugin-hook-stable": (b"#!/usr/bin/python3\n", 0o755),
        "src/the_hive/hook_session_pin_store.py": (b"STORE = 1\n", 0o644),
        "src/the_hive/hook_abi_v1_core.py": (b"CORE = 1\n", 0o644),
        "TheHivePluginBundleV1/hooks/native_bee_event.py": (b"EVENT = 1\n", 0o644),
        "TheHivePluginBundleV1/hooks/native_spawn_admission.py": (b"SPAWN = 1\n", 0o644),
    }
    for name, (raw, mode) in sources.items():
        _put(generation / name, raw, mode)
        files[name] = {"mode": mode, "nlink": 1, "size": len(raw), "sha256": _sha(raw)}
    for directory in (release, release / "generations", generation,
                      generation / "bin", generation / "src", generation / "src/the_hive",
                      generation / "TheHivePluginBundleV1", generation / "TheHivePluginBundleV1/hooks"):
        directory.chmod(0o700)
    manifest = GATE["_canonical"]({"schema_version": 2, "generation": GENERATION, "files": files})
    pin = "sha256:" + _sha(manifest)
    _put(generation / ".the-hive-runtime-manifest.json", manifest)
    _put(release / ".the-hive-release-pointers.json", GATE["_canonical"]({
        "schema_version": 1, "current": {"generation": GENERATION, "manifest_digest": pin},
        "previous": None,
    }))
    targets = {
        "launcher": GATE["ABI"],
        "companion": GATE["ABI"].replace("/launcher", "/hook_session_pin_store.py"),
        "core": GATE["ABI"].replace("/launcher", "/hook_abi_v1_core.py"),
    }
    plan = {"schema": "RootInstallPlanV1", "plugin_id": "the-hive",
            "generation": GENERATION, "runtime_manifest_digest": pin}
    for key, name in zip(targets, list(sources)[:3]):
        plan[key] = {"source": name, "target": targets[key], "sha256": "sha256:" + files[name]["sha256"]}
    _put(generation / "root-install-plan.json", GATE["_canonical"](plan))
    hooks = {"native_bee_event": "sha256:" + files[list(sources)[3]]["sha256"],
             "native_spawn_admission": "sha256:" + files[list(sources)[4]]["sha256"]}
    descriptor = {"schema": "TheHivePluginBundleV1", "plugin_id": "the-hive",
                  "generation": GENERATION, "runtime_manifest_digest": pin,
                  "launcher_abi": GATE["ABI"], "hooks": hooks}
    _put(generation / "TheHivePluginBundleV1/release-binding.json", GATE["_canonical"](descriptor))
    parent = tmp_path / "root" / "hook-abi"
    parent.mkdir(mode=0o755, parents=True)
    return home, parent, generation, pin


def _install(home, parent, pin):
    return GATE["install"](home, os.getuid(), GENERATION, pin, parent_path=parent,
                           root_uid=os.getuid(), root_gid=os.getgid())


def test_install_is_atomic_and_idempotent(safe_tmp_path):
    home, parent, generation, pin = _fixture(safe_tmp_path)
    assert _install(home, parent, pin) == "installed"
    installed = parent / "v1"
    expected = {"launcher", "hook_session_pin_store.py", "hook_abi_v1_core.py", "allowlists"}
    assert {p.name for p in installed.iterdir()} == expected
    allow = next((installed / "allowlists").iterdir())
    assert allow.name.endswith(".json")
    assert json.loads(allow.read_text())["runtime_manifest_digest"] == pin
    before = {p: (p.stat().st_ino, p.read_bytes()) for p in installed.rglob("*") if p.is_file()}
    assert _install(home, parent, pin) == "already_installed"
    assert before == {p: (p.stat().st_ino, p.read_bytes()) for p in installed.rglob("*") if p.is_file()}
    assert stat.S_IMODE(installed.stat().st_mode) == 0o755
    assert stat.S_IMODE((installed / "launcher").stat().st_mode) == 0o755
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o644 for p in before if p.name != "launcher")


@pytest.mark.parametrize("mode", [0o770, 0o777])
def test_writable_fixture_ancestor_never_publishes(safe_tmp_path, mode):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    (home / ".local").chmod(mode)
    with pytest.raises(GATE["GateError"]):
        _install(home, parent, pin)
    assert list(parent.iterdir()) == []


@pytest.mark.parametrize("defect", ["digest", "plan_target", "source_symlink", "source_hardlink", "source_mode", "source_owner"])
def test_untrusted_input_never_publishes(safe_tmp_path, monkeypatch, defect):
    home, parent, generation, pin = _fixture(safe_tmp_path)
    source = generation / "src/the_hive/hook_abi_v1_core.py"
    if defect == "digest":
        pin = "sha256:" + "0" * 64
    elif defect == "plan_target":
        plan = generation / "root-install-plan.json"
        plan.write_bytes(plan.read_bytes().replace(b"/hook_abi_v1_core.py", b"/wrong.py"))
    elif defect == "source_symlink":
        source.unlink()
        source.symlink_to(generation / "bin/the-hive-plugin-hook-stable")
    elif defect == "source_hardlink":
        other = source.with_name("second-link.py")
        os.link(source, other)
    elif defect == "source_mode":
        source.chmod(0o666)
    else:
        real_fstat = os.fstat
        def foreign_owner(fd):
            result = real_fstat(fd)
            if stat.S_ISREG(result.st_mode) and result.st_size == len(b"CORE = 1\n"):
                values = list(result)
                values[4] += 1
                return os.stat_result(values)
            return result
        monkeypatch.setattr(os, "fstat", foreign_owner)
    with pytest.raises((GATE["GateError"], OSError)):
        _install(home, parent, pin)
    assert list(parent.iterdir()) == []


def test_publish_failure_cleans_own_stage(safe_tmp_path, monkeypatch):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    real_fsync = os.fsync
    def fail_stage(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected stage fsync failure")
        return real_fsync(fd)
    monkeypatch.setattr(os, "fsync", fail_stage)
    with pytest.raises(OSError, match="injected"):
        _install(home, parent, pin)
    assert list(parent.iterdir()) == []


def test_source_path_swap_rejects_before_publication(safe_tmp_path, monkeypatch):
    home, parent, generation, pin = _fixture(safe_tmp_path)
    source = generation / "src/the_hive/hook_abi_v1_core.py"
    real_open = os.open
    swapped = False
    def swap_after_open(path, flags, *args, **kwargs):
        nonlocal swapped
        fd = real_open(path, flags, *args, **kwargs)
        if path == source.name and not swapped:
            swapped = True
            source.rename(source.with_name("parked.py"))
            _put(source, b"ATTACK = 1\n")
        return fd
    monkeypatch.setattr(os, "open", swap_after_open)
    with pytest.raises(GATE["GateError"]):
        _install(home, parent, pin)
    assert swapped
    assert list(parent.iterdir()) == []


def test_existing_extra_allowlist_holds_without_removal(safe_tmp_path):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    assert _install(home, parent, pin) == "installed"
    allow = parent / "v1/allowlists"
    existing = next(allow.iterdir())
    extra = allow / ("b" * 64 + ".json")
    _put(extra, existing.read_bytes())
    extra_inode = extra.stat().st_ino
    with pytest.raises(GATE["GateError"]):
        _install(home, parent, pin)
    assert extra.stat().st_ino == extra_inode


def test_existing_target_drift_is_rejected_without_repair(safe_tmp_path):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    assert _install(home, parent, pin) == "installed"
    launcher = parent / "v1/launcher"
    launcher.write_bytes(b"tampered\n")
    with pytest.raises(GATE["GateError"]):
        _install(home, parent, pin)
    assert launcher.read_bytes() == b"tampered\n"


def test_racing_target_is_not_replaced(safe_tmp_path):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    original = GATE["_existing"]
    def race(parent_fd, payload, uid, gid, name="v1"):
        original(parent_fd, payload, uid, gid, name)
        if name != "v1":
            os.mkdir("v1", mode=0o755, dir_fd=parent_fd)
    GATE["_publish"].__globals__["_existing"] = race
    try:
        with pytest.raises(OSError):
            _install(home, parent, pin)
    finally:
        GATE["_publish"].__globals__["_existing"] = original
    assert {p.name for p in parent.iterdir()} == {"v1"}
    assert list((parent / "v1").iterdir()) == []


def test_parent_fsync_error_reports_complete_visibility(safe_tmp_path, monkeypatch):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    parent_inode = parent.stat().st_ino
    real_fsync = os.fsync
    def fail_parent(fd):
        if os.fstat(fd).st_ino == parent_inode:
            raise OSError("injected parent fsync failure")
        return real_fsync(fd)
    monkeypatch.setattr(os, "fsync", fail_parent)
    with pytest.raises(GATE["GateError"], match="durability_unknown"):
        _install(home, parent, pin)
    assert {p.name for p in parent.iterdir()} == {"v1"}
    assert {p.name for p in (parent / "v1").iterdir()} == {
        "launcher", "hook_session_pin_store.py", "hook_abi_v1_core.py", "allowlists"
    }


def test_gate_installed_abi_is_consumed_by_dispatcher(tmp_path, safe_tmp_path):
    installer = runpy.run_path(str(ROOT / "scripts/the-hive-hive-hourly-probe-install"))
    home = safe_tmp_path / "home"
    release = tmp_path / "release"
    generations = release / "generations"
    generations.mkdir(mode=0o700, parents=True)
    release.chmod(0o700)
    generations.chmod(0o700)
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    installer["_build_runtime_image"](
        repository=ROOT, stage=stage, generation=GENERATION, commit=GENERATION
    )
    generation = generations / GENERATION
    stage.rename(generation)
    manifest = (generation / ".the-hive-runtime-manifest.json").read_bytes()
    pin = "sha256:" + _sha(manifest)
    _put(release / ".the-hive-release-pointers.json", GATE["_canonical"]({
        "schema_version": 1, "current": {"generation": GENERATION, "manifest_digest": pin},
        "previous": None,
    }))
    shutil.copytree(release, home / ".local/lib/the-hive-runtime")
    plugin = tmp_path / "plugin-root"
    shutil.copytree(generation / "TheHivePluginBundleV1", plugin)
    parent = safe_tmp_path / "root/usr/local/libexec/the-hive/hook-abi"
    parent.mkdir(mode=0o755, parents=True)
    assert _install(home, parent, pin) == "installed"
    abi = parent / "v1"
    descriptor = (plugin / "release-binding.json").read_bytes()
    allow = abi / "allowlists" / (_sha(descriptor) + ".json")

    def dispatch(state):
        return dispatch_hook_v1(
            plugin_root=plugin, release_root=release, state_root=state,
            abi_root=abi, abi_owner_uid=os.getuid(), hook_name="native_bee_event",
            stdin_bytes=b'{"session_id":"s1","hook_event_name":"SessionStart"}',
            now_unix_ns=10,
        )

    result = dispatch(tmp_path / "state-good/pins")
    try:
        assert result.generation == GENERATION
        assert result.hook_name == "native_bee_event"
    finally:
        result.close()
    original = allow.read_bytes()
    allow.unlink()
    missing_state = tmp_path / "state-missing/pins"
    with pytest.raises(HookAbiV1Error):
        dispatch(missing_state)
    assert not missing_state.exists()
    _put(allow, original.replace(b'D320DispatchAllowlistV1', b'wrong-allowlist-schema!'))
    wrong_state = tmp_path / "state-wrong/pins"
    with pytest.raises(HookAbiV1Error):
        dispatch(wrong_state)
    assert not wrong_state.exists()
