"""Small root-gate fixtures; all writes stay below pytest's temporary directory."""

import hashlib
import json
import os
import fcntl
from pathlib import Path
import runpy
import shutil
import stat
import sys
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
    sandbox_ancestors = {
        (p.stat().st_dev, p.stat().st_ino) for p in (Path("/"), Path("/home"))
    }
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

    monkeypatch.setattr(os, "fstat", sandbox_fstat)
    with tempfile.TemporaryDirectory(
        prefix="hook-abi-gate-test-", dir=tempfile.gettempdir()
    ) as path:
        yield Path(path)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _put(path, raw, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def _fixture(tmp_path, generation_id=GENERATION):
    home = tmp_path / "home"
    release = home / ".local/lib/the-hive-runtime"
    generation = release / "generations" / generation_id
    generation.mkdir(mode=0o700, parents=True)
    files = {}
    sources = {
        "bin/the-hive-plugin-hook-stable": (b"#!/usr/bin/python3\n", 0o755),
        "src/the_hive/hook_session_pin_store.py": (b"STORE = 1\n", 0o644),
        "src/the_hive/hook_abi_v1_core.py": (b"CORE = 1\n", 0o644),
        "TheHivePluginBundleV1/hooks/native_bee_event.py": (b"EVENT = 1\n", 0o644),
        "TheHivePluginBundleV1/hooks/native_spawn_admission.py": (
            b"SPAWN = 1\n",
            0o644,
        ),
    }
    for name, (raw, mode) in sources.items():
        _put(generation / name, raw, mode)
        files[name] = {"mode": mode, "nlink": 1, "size": len(raw), "sha256": _sha(raw)}
    for directory in (
        release,
        release / "generations",
        generation,
        generation / "bin",
        generation / "src",
        generation / "src/the_hive",
        generation / "TheHivePluginBundleV1",
        generation / "TheHivePluginBundleV1/hooks",
    ):
        directory.chmod(0o700)
    manifest = GATE["_canonical"](
        {"schema_version": 2, "generation": generation_id, "files": files}
    )
    pin = "sha256:" + _sha(manifest)
    _put(generation / ".the-hive-runtime-manifest.json", manifest)
    _put(
        release / ".the-hive-release-pointers.json",
        GATE["_canonical"](
            {
                "schema_version": 1,
                "current": {"generation": generation_id, "manifest_digest": pin},
                "previous": None,
            }
        ),
    )
    targets = {
        "launcher": GATE["ABI"],
        "companion": GATE["ABI"].replace("/launcher", "/hook_session_pin_store.py"),
        "core": GATE["ABI"].replace("/launcher", "/hook_abi_v1_core.py"),
    }
    plan = {
        "schema": "RootInstallPlanV1",
        "plugin_id": "the-hive",
        "generation": generation_id,
        "runtime_manifest_digest": pin,
    }
    for key, name in zip(targets, list(sources)[:3]):
        plan[key] = {
            "source": name,
            "target": targets[key],
            "sha256": "sha256:" + files[name]["sha256"],
        }
    _put(generation / "root-install-plan.json", GATE["_canonical"](plan))
    hooks = {
        "native_bee_event": "sha256:" + files[list(sources)[3]]["sha256"],
        "native_spawn_admission": "sha256:" + files[list(sources)[4]]["sha256"],
    }
    descriptor = {
        "schema": "TheHivePluginBundleV1",
        "plugin_id": "the-hive",
        "generation": generation_id,
        "runtime_manifest_digest": pin,
        "launcher_abi": GATE["ABI"],
        "hooks": hooks,
    }
    _put(
        generation / "TheHivePluginBundleV1/release-binding.json",
        GATE["_canonical"](descriptor),
    )
    parent = tmp_path / "root" / "hook-abi"
    parent.mkdir(mode=0o755, parents=True)
    return home, parent, generation, pin


def _install(
    home, parent, pin, generation_id=GENERATION, expected_root_state_sha256=None
):
    if expected_root_state_sha256 is None:
        snapshot = GATE["_inspect_root_state"](
            parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
        )
        expected_root_state_sha256 = snapshot["root_state_sha256"]
        if snapshot["root_state"].get("upgrade_state", {}).get("present"):
            parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                raw, _state = GATE["_file_state"](
                    parent_fd,
                    ".root-hook-abi-upgrade-v1.json",
                    os.getuid(),
                    os.getgid(),
                    0o644,
                )
            finally:
                os.close(parent_fd)
            upgrade = json.loads(raw)
            if upgrade.get("status") == "pending":
                expected_root_state_sha256 = upgrade["expected_root_state_sha256"]
    return GATE["install"](
        home,
        os.getuid(),
        generation_id,
        pin,
        parent_path=parent,
        root_uid=os.getuid(),
        root_gid=os.getgid(),
        expected_root_state_sha256=expected_root_state_sha256,
    )


def test_install_is_atomic_and_idempotent(safe_tmp_path):
    home, parent, generation, pin = _fixture(safe_tmp_path)
    assert _install(home, parent, pin) == "installed"
    installed = parent / "v1"
    expected = {
        "launcher",
        "hook_session_pin_store.py",
        "hook_abi_v1_core.py",
        "allowlists",
    }
    assert {p.name for p in installed.iterdir()} == expected
    allow = next((installed / "allowlists").iterdir())
    assert allow.name.endswith(".json")
    assert json.loads(allow.read_text())["runtime_manifest_digest"] == pin
    before = {
        p: (p.stat().st_ino, p.read_bytes())
        for p in installed.rglob("*")
        if p.is_file()
    }
    assert _install(home, parent, pin) == "already_installed"
    assert before == {
        p: (p.stat().st_ino, p.read_bytes())
        for p in installed.rglob("*")
        if p.is_file()
    }
    assert stat.S_IMODE(installed.stat().st_mode) == 0o755
    assert stat.S_IMODE((installed / "launcher").stat().st_mode) == 0o755
    assert all(
        stat.S_IMODE(p.stat().st_mode) == 0o644 for p in before if p.name != "launcher"
    )


def test_root_owner_upgrades_from_an_exact_read_only_snapshot_pin(safe_tmp_path):
    home, parent, _generation, old_pin = _fixture(safe_tmp_path)
    assert _install(home, parent, old_pin) == "installed"
    old_payload = GATE["_payload"](home, os.getuid(), GENERATION, old_pin)
    snapshot = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )
    next_generation = "c" * 40
    next_home, _other_parent, _next_path, next_pin = _fixture(
        safe_tmp_path / "next", next_generation
    )

    result = GATE["install"](
        next_home,
        os.getuid(),
        next_generation,
        next_pin,
        parent_path=parent,
        root_uid=os.getuid(),
        root_gid=os.getgid(),
        expected_root_state_sha256=snapshot["root_state_sha256"],
    )

    assert result == "upgraded"
    upgrade_state = json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())
    assert upgrade_state["status"] == "committed"
    backup_name = upgrade_state["backup_name"]
    assert isinstance(backup_name, str)
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        GATE["_existing"](parent_fd, old_payload, os.getuid(), os.getgid(), backup_name)
    finally:
        os.close(parent_fd)
    current = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )
    assert current["root_state"]["binding"]["generation"] == next_generation
    assert current["root_state"]["upgrade_state"]["present"] is True


def test_root_owner_upgrade_rejects_stale_snapshot_without_effect(safe_tmp_path):
    home, parent, _generation, old_pin = _fixture(safe_tmp_path)
    assert _install(home, parent, old_pin) == "installed"
    next_generation = "d" * 40
    next_home, _other_parent, _next_path, next_pin = _fixture(
        safe_tmp_path / "next", next_generation
    )
    before = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )

    with pytest.raises(GATE["GateError"], match="hook_abi_gate_snapshot_changed"):
        GATE["install"](
            next_home,
            os.getuid(),
            next_generation,
            next_pin,
            parent_path=parent,
            root_uid=os.getuid(),
            root_gid=os.getgid(),
            expected_root_state_sha256="0" * 64,
        )

    after = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )
    assert after == before


def test_root_owner_resumes_after_exchange_without_a_second_exchange(safe_tmp_path):
    home, parent, _generation, old_pin = _fixture(safe_tmp_path)
    assert _install(home, parent, old_pin) == "installed"
    snapshot = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )
    next_generation = "e" * 40
    next_home, _other_parent, _next_path, next_pin = _fixture(
        safe_tmp_path / "next", next_generation
    )
    write_receipt = GATE["_write_effect_receipt"]

    def crash_after_exchange(*_args, **_kwargs):
        raise GATE["GateError"]("injected_crash_after_exchange")

    GATE["install"].__globals__["_write_effect_receipt"] = crash_after_exchange
    try:
        with pytest.raises(GATE["GateError"], match="injected_crash_after_exchange"):
            GATE["install"](
                next_home,
                os.getuid(),
                next_generation,
                next_pin,
                parent_path=parent,
                root_uid=os.getuid(),
                root_gid=os.getgid(),
                expected_root_state_sha256=snapshot["root_state_sha256"],
            )
    finally:
        GATE["install"].__globals__["_write_effect_receipt"] = write_receipt

    pending = json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())
    assert pending["status"] == "pending"
    target_before_resume = (parent / "v1").stat()
    backup = parent / pending["stage_name"]
    assert backup.stat().st_ino == pending["old_target"]["ino"]
    assert (
        json.loads(next((parent / "v1/allowlists").iterdir()).read_bytes())[
            "generation"
        ]
        == next_generation
    )

    assert (
        _install(
            next_home,
            parent,
            next_pin,
            generation_id=next_generation,
            expected_root_state_sha256=snapshot["root_state_sha256"],
        )
        == "already_installed"
    )

    target_after_resume = (parent / "v1").stat()
    assert (target_after_resume.st_dev, target_after_resume.st_ino) == (
        target_before_resume.st_dev,
        target_before_resume.st_ino,
    )
    assert backup.stat().st_ino == pending["old_target"]["ino"]
    committed = json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())
    assert committed["status"] == "committed"
    assert committed["generation"] == next_generation
    assert (
        json.loads((parent / GATE["ROOT_EFFECT_RECEIPT"]).read_bytes())["generation"]
        == next_generation
    )
    committed_snapshot = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )
    assert (
        _install(
            next_home,
            parent,
            next_pin,
            generation_id=next_generation,
            expected_root_state_sha256=committed_snapshot["root_state_sha256"],
        )
        == "already_installed"
    )
    target_after_second_resume = (parent / "v1").stat()
    assert (target_after_second_resume.st_dev, target_after_second_resume.st_ino) == (
        target_before_resume.st_dev,
        target_before_resume.st_ino,
    )


def test_root_owner_persists_reservation_before_first_publish(safe_tmp_path):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    before = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )
    write_state = GATE["_write_upgrade_state"]

    def crash_after_reservation(*args, **kwargs):
        state = args[1]
        result = write_state(*args, **kwargs)
        if state["status"] == "pending":
            raise GATE["GateError"]("injected_crash_after_reservation")
        return result

    GATE["install"].__globals__["_write_upgrade_state"] = crash_after_reservation
    try:
        with pytest.raises(GATE["GateError"], match="injected_crash_after_reservation"):
            _install(
                home,
                parent,
                pin,
                expected_root_state_sha256=before["root_state_sha256"],
            )
    finally:
        GATE["install"].__globals__["_write_upgrade_state"] = write_state

    pending = json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())
    stage = parent / pending["stage_name"]
    stage_info = stage.stat()
    assert pending["status"] == "pending"
    assert pending["old_target"] == {"present": False}
    assert not (parent / "v1").exists()
    assert (stage_info.st_dev, stage_info.st_ino) == (
        pending["target"]["dev"],
        pending["target"]["ino"],
    )

    assert (
        _install(
            home, parent, pin, expected_root_state_sha256=before["root_state_sha256"]
        )
        == "already_installed"
    )
    target = (parent / "v1").stat()
    assert (target.st_dev, target.st_ino) == (stage_info.st_dev, stage_info.st_ino)
    assert not stage.exists()
    assert (
        json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())["status"]
        == "committed"
    )


def test_root_owner_resumes_upgrade_reserved_before_exchange(safe_tmp_path):
    home, parent, _generation, old_pin = _fixture(safe_tmp_path)
    assert _install(home, parent, old_pin) == "installed"
    before = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )
    old_target = (parent / "v1").stat()
    next_generation = "f" * 40
    next_home, _other_parent, _next_path, next_pin = _fixture(
        safe_tmp_path / "next", next_generation
    )
    write_state = GATE["_write_upgrade_state"]

    def crash_after_upgrade_reservation(*args, **kwargs):
        state = args[1]
        result = write_state(*args, **kwargs)
        if state["status"] == "pending":
            raise GATE["GateError"]("injected_crash_before_exchange")
        return result

    GATE["install"].__globals__["_write_upgrade_state"] = (
        crash_after_upgrade_reservation
    )
    try:
        with pytest.raises(GATE["GateError"], match="injected_crash_before_exchange"):
            _install(
                next_home,
                parent,
                next_pin,
                generation_id=next_generation,
                expected_root_state_sha256=before["root_state_sha256"],
            )
    finally:
        GATE["install"].__globals__["_write_upgrade_state"] = write_state

    pending = json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())
    staged_new = parent / pending["stage_name"]
    staged_info = staged_new.stat()
    still_old = (parent / "v1").stat()
    assert pending["status"] == "pending"
    assert (still_old.st_dev, still_old.st_ino) == (
        old_target.st_dev,
        old_target.st_ino,
    )
    assert (staged_info.st_dev, staged_info.st_ino) == (
        pending["target"]["dev"],
        pending["target"]["ino"],
    )
    assert (parent / pending["stage_name"]).exists()

    assert (
        _install(
            next_home,
            parent,
            next_pin,
            generation_id=next_generation,
            expected_root_state_sha256=before["root_state_sha256"],
        )
        == "already_installed"
    )
    published = (parent / "v1").stat()
    assert (published.st_dev, published.st_ino) == (
        staged_info.st_dev,
        staged_info.st_ino,
    )
    committed = json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())
    backup = parent / committed["backup_name"]
    backup_info = backup.stat()
    assert (backup_info.st_dev, backup_info.st_ino) == (
        old_target.st_dev,
        old_target.st_ino,
    )
    assert committed["status"] == "committed"


def test_root_owner_resumes_when_receipt_rename_parent_flush_fails(
    safe_tmp_path, monkeypatch
):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    parent_info = parent.stat()
    real_fsync = os.fsync
    failed = False
    successful_parent_flushes = 0

    def fail_after_receipt_rename(fd):
        nonlocal failed, successful_parent_flushes
        info = os.fstat(fd)
        receipt_visible = (parent / GATE["ROOT_EFFECT_RECEIPT"]).exists()
        marker = parent / ".root-hook-abi-upgrade-v1.json"
        pending_visible = (
            marker.exists() and json.loads(marker.read_bytes())["status"] == "pending"
        )
        if (
            not failed
            and (info.st_dev, info.st_ino) == (parent_info.st_dev, parent_info.st_ino)
            and receipt_visible
            and pending_visible
        ):
            failed = True
            raise OSError("injected receipt rename parent flush failure")
        result = real_fsync(fd)
        if failed and (info.st_dev, info.st_ino) == (
            parent_info.st_dev,
            parent_info.st_ino,
        ):
            successful_parent_flushes += 1
        return result

    committed_upgrade_state = GATE["_committed_upgrade_state"]

    def require_durable_parent_before_commit(*args, **kwargs):
        assert successful_parent_flushes > 0
        return committed_upgrade_state(*args, **kwargs)

    monkeypatch.setattr(os, "fsync", fail_after_receipt_rename)
    GATE["install"].__globals__["_committed_upgrade_state"] = (
        require_durable_parent_before_commit
    )
    try:
        with pytest.raises(
            GATE["GateError"], match="hook_abi_gate_receipt_durability_unknown"
        ):
            _install(home, parent, pin)
        assert failed
        pending = json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())
        receipt_info = (parent / GATE["ROOT_EFFECT_RECEIPT"]).stat()
        target_info = (parent / "v1").stat()
        assert pending["status"] == "pending"
        assert pending["target"]["ino"] == target_info.st_ino
        assert _install(home, parent, pin) == "already_installed"
    finally:
        GATE["install"].__globals__["_committed_upgrade_state"] = (
            committed_upgrade_state
        )
    assert successful_parent_flushes > 0
    assert (parent / GATE["ROOT_EFFECT_RECEIPT"]).stat().st_ino == receipt_info.st_ino
    assert (
        json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())["status"]
        == "committed"
    )


def test_root_owner_resumes_after_durable_receipt_before_commit_marker(
    safe_tmp_path, monkeypatch
):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    commit_state = GATE["_committed_upgrade_state"]

    def crash_before_commit(*_args, **_kwargs):
        raise GATE["GateError"]("injected_crash_before_commit_marker")

    GATE["install"].__globals__["_committed_upgrade_state"] = crash_before_commit
    try:
        with pytest.raises(
            GATE["GateError"], match="injected_crash_before_commit_marker"
        ):
            _install(home, parent, pin)
    finally:
        GATE["install"].__globals__["_committed_upgrade_state"] = commit_state

    marker_path = parent / ".root-hook-abi-upgrade-v1.json"
    pending = json.loads(marker_path.read_bytes())
    receipt_info = (parent / GATE["ROOT_EFFECT_RECEIPT"]).stat()
    assert pending["status"] == "pending"
    assert pending["target"]["ino"] == (parent / "v1").stat().st_ino
    assert _install(home, parent, pin) == "already_installed"
    committed = json.loads(marker_path.read_bytes())
    assert committed["status"] == "committed"
    assert committed["receipt"]["ino"] == receipt_info.st_ino


def test_root_owner_commit_visible_after_final_parent_flush_failure(
    safe_tmp_path, monkeypatch
):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    parent_info = parent.stat()
    real_fsync = os.fsync
    failed = False

    def fail_after_commit_rename(fd):
        nonlocal failed
        info = os.fstat(fd)
        marker = parent / ".root-hook-abi-upgrade-v1.json"
        committed_visible = (
            marker.exists() and json.loads(marker.read_bytes())["status"] == "committed"
        )
        if (
            not failed
            and (info.st_dev, info.st_ino) == (parent_info.st_dev, parent_info.st_ino)
            and committed_visible
        ):
            failed = True
            raise OSError("injected committed marker parent flush failure")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_after_commit_rename)
    with pytest.raises(
        GATE["GateError"], match="hook_abi_gate_upgrade_durability_unknown"
    ):
        _install(home, parent, pin)
    assert failed
    committed = json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())
    assert committed["status"] == "committed"
    snapshot = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )
    assert (
        _install(
            home, parent, pin, expected_root_state_sha256=snapshot["root_state_sha256"]
        )
        == "already_installed"
    )


def test_root_owner_resumes_when_commit_rename_reverts_to_pending_inode(safe_tmp_path):
    home, parent, _generation, old_pin = _fixture(safe_tmp_path)
    assert _install(home, parent, old_pin) == "installed"
    before = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )
    old_target = (parent / "v1").stat()
    next_generation = "9" * 40
    next_home, _other_parent, _next_path, next_pin = _fixture(
        safe_tmp_path / "next", next_generation
    )
    write_state = GATE["_write_upgrade_state"]
    pending_marker_identity = None

    def commit_then_restore_durable_pending(*args, **kwargs):
        nonlocal pending_marker_identity
        state = args[1]
        if state["status"] != "committed":
            return write_state(*args, **kwargs)
        marker = parent / ".root-hook-abi-upgrade-v1.json"
        saved_pending = parent / ".fixture-held-pending-marker"
        pending_before = marker.stat()
        pending_bytes = marker.read_bytes()
        os.link(marker, saved_pending, follow_symlinks=False)
        write_state(*args, **kwargs)
        os.replace(saved_pending, marker)
        pending_after = marker.stat()
        pending_marker_identity = (pending_after.st_dev, pending_after.st_ino)
        assert pending_bytes == marker.read_bytes()
        assert (pending_before.st_dev, pending_before.st_ino) == pending_marker_identity
        raise GATE["GateError"]("injected_crash_commit_reverted_to_pending")

    GATE["install"].__globals__["_write_upgrade_state"] = (
        commit_then_restore_durable_pending
    )
    try:
        with pytest.raises(
            GATE["GateError"], match="injected_crash_commit_reverted_to_pending"
        ):
            _install(
                next_home,
                parent,
                next_pin,
                generation_id=next_generation,
                expected_root_state_sha256=before["root_state_sha256"],
            )
    finally:
        GATE["install"].__globals__["_write_upgrade_state"] = write_state

    pending_path = parent / ".root-hook-abi-upgrade-v1.json"
    pending = json.loads(pending_path.read_bytes())
    pending_info = pending_path.stat()
    assert pending["status"] == "pending"
    assert (pending_info.st_dev, pending_info.st_ino) == pending_marker_identity
    assert (parent / "v1").stat().st_ino != old_target.st_ino
    assert (parent / pending["stage_name"]).stat().st_ino == old_target.st_ino
    visible = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )
    assert visible["root_state"]["upgrade_state"]["present"] is True

    target_before_resume = (parent / "v1").stat()
    assert (
        _install(
            next_home,
            parent,
            next_pin,
            generation_id=next_generation,
            expected_root_state_sha256=before["root_state_sha256"],
        )
        == "already_installed"
    )
    target_after_resume = (parent / "v1").stat()
    assert (target_after_resume.st_dev, target_after_resume.st_ino) == (
        target_before_resume.st_dev,
        target_before_resume.st_ino,
    )
    committed = json.loads(pending_path.read_bytes())
    assert committed["status"] == "committed"
    backup = parent / committed["backup_name"]
    assert (backup.stat().st_dev, backup.stat().st_ino) == (
        old_target.st_dev,
        old_target.st_ino,
    )


def test_root_owner_missing_lock_race_keeps_snapshot_read_only(
    safe_tmp_path, monkeypatch
):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    lock_path = parent / GATE["ROOT_OWNER_LOCK"]
    assert not lock_path.exists()
    snapshot = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )
    assert not lock_path.exists()
    real_open = os.open
    injected = False

    def race_lock_creation(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal injected
        if path == GATE["ROOT_OWNER_LOCK"] and flags & os.O_EXCL and not injected:
            injected = True
            competing = real_open(path, flags, mode, dir_fd=dir_fd)
            os.fchmod(competing, 0o644)
            os.close(competing)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", race_lock_creation)
    with pytest.raises(GATE["GateError"], match="hook_abi_gate_snapshot_changed"):
        _install(
            home, parent, pin, expected_root_state_sha256=snapshot["root_state_sha256"]
        )
    assert injected
    assert (parent / GATE["ROOT_OWNER_LOCK"]).is_file()
    assert not (parent / "v1").exists()
    assert not (parent / ".root-hook-abi-upgrade-v1.json").exists()


def test_root_owner_receipt_is_written_after_verified_install(safe_tmp_path):
    home, parent, _generation, pin = _fixture(safe_tmp_path)

    assert _install(home, parent, pin) == "installed"

    receipt_path = parent / "root-hook-effect-receipt-v1.json"
    receipt = json.loads(receipt_path.read_bytes())
    assert receipt == {
        "effect": "root_hook_abi_verified_present",
        "files": {
            "allowlists/" + next((parent / "v1/allowlists").iterdir()).name: {
                "mode": 0o644,
                "nlink": 1,
                "sha256": _sha(next((parent / "v1/allowlists").iterdir()).read_bytes()),
                "size": next((parent / "v1/allowlists").iterdir()).stat().st_size,
            },
            "hook_abi_v1_core.py": {
                "mode": 0o644,
                "nlink": 1,
                "sha256": _sha((parent / "v1/hook_abi_v1_core.py").read_bytes()),
                "size": (parent / "v1/hook_abi_v1_core.py").stat().st_size,
            },
            "hook_session_pin_store.py": {
                "mode": 0o644,
                "nlink": 1,
                "sha256": _sha((parent / "v1/hook_session_pin_store.py").read_bytes()),
                "size": (parent / "v1/hook_session_pin_store.py").stat().st_size,
            },
            "launcher": {
                "mode": 0o755,
                "nlink": 1,
                "sha256": _sha((parent / "v1/launcher").read_bytes()),
                "size": (parent / "v1/launcher").stat().st_size,
            },
        },
        "generation": GENERATION,
        "issued_at_unix_ns": receipt["issued_at_unix_ns"],
        "manifest_digest": pin,
        "owner": "root_hook_abi_v1",
        "root_uid": os.getuid(),
        "schema_version": 1,
        "source_uid": os.getuid(),
        "target": GATE["ABI"].rsplit("/", 1)[0],
    }
    assert isinstance(receipt["issued_at_unix_ns"], int)
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o644
    assert receipt_path.stat().st_nlink == 1
    upgrade_path = parent / ".root-hook-abi-upgrade-v1.json"
    upgrade = json.loads(upgrade_path.read_bytes())
    target_info = (parent / "v1").stat()
    receipt_info = receipt_path.stat()
    assert upgrade["schema"] == "RootHookAbiUpgradeStateV1"
    assert upgrade["status"] == "committed"
    assert upgrade["generation"] == GENERATION
    assert upgrade["manifest_digest"] == pin
    assert upgrade["target"]["dev"] == target_info.st_dev
    assert upgrade["target"]["ino"] == target_info.st_ino
    assert upgrade["receipt"]["dev"] == receipt_info.st_dev
    assert upgrade["receipt"]["ino"] == receipt_info.st_ino
    assert upgrade["receipt"]["sha256"] == _sha(receipt_path.read_bytes())
    assert {p.name for p in (parent / "v1").iterdir()} == {
        "launcher",
        "hook_session_pin_store.py",
        "hook_abi_v1_core.py",
        "allowlists",
    }


def test_root_state_inspection_returns_a_closed_read_only_snapshot(safe_tmp_path):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    assert _install(home, parent, pin) == "installed"
    before = {
        str(path.relative_to(parent)): (
            path.stat().st_dev,
            path.stat().st_ino,
            path.stat().st_mode,
            path.read_bytes(),
        )
        for path in parent.rglob("*")
        if path.is_file()
    }

    snapshot = GATE["_inspect_root_state"](
        parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
    )

    assert set(snapshot) == {
        "schema",
        "status",
        "root_state",
        "root_state_sha256",
        "mutation_performed",
        "raw_output",
    }
    assert snapshot["schema"] == "RootHookAbiStateSnapshotV1"
    assert snapshot["status"] == "complete"
    assert snapshot["mutation_performed"] is False
    assert snapshot["raw_output"] == "not_returned"
    root_state = snapshot["root_state"]
    assert set(root_state) == {
        "parent",
        "owner_lock",
        "target",
        "receipt",
        "upgrade_state",
        "binding",
    }
    assert snapshot["root_state_sha256"] == _sha(GATE["_canonical"](root_state))
    assert root_state["binding"]["generation"] == GENERATION
    assert root_state["binding"]["manifest_digest"] == pin
    after = {
        str(path.relative_to(parent)): (
            path.stat().st_dev,
            path.stat().st_ino,
            path.stat().st_mode,
            path.read_bytes(),
        )
        for path in parent.rglob("*")
        if path.is_file()
    }
    assert after == before


@pytest.mark.parametrize("raw", [b'{"value":NaN}', b'{"value":Infinity}'])
def test_root_json_rejects_nonfinite_numbers(raw):
    with pytest.raises(GATE["GateError"], match="hook_abi_gate_invalid"):
        GATE["_json"](raw)


def test_root_state_inspection_cli_emits_read_only_snapshot(
    safe_tmp_path, monkeypatch, capsys
):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    assert _install(home, parent, pin) == "installed"
    before = sorted(path.name for path in parent.iterdir())
    globals_ = GATE["main"].__globals__
    inspect = GATE["_inspect_root_state"]
    monkeypatch.setitem(globals_, "ROOT_HOOK_ABI_PARENT", parent)
    monkeypatch.setitem(
        globals_,
        "_inspect_root_state",
        lambda **_kwargs: inspect(
            parent_path=parent, root_uid=os.getuid(), root_gid=os.getgid()
        ),
    )
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getegid", lambda: 0)
    monkeypatch.setattr(
        sys, "argv", ["the-hive-hook-abi-v1-install", "--inspect-root-state"]
    )

    assert GATE["main"]() == 0
    result = json.loads(capsys.readouterr().out)

    assert result["schema"] == "RootHookAbiStateSnapshotV1"
    assert result["mutation_performed"] is False
    assert sorted(path.name for path in parent.iterdir()) == before


def test_root_owner_revalidates_effect_before_receipt_retry_after_crash(
    safe_tmp_path, monkeypatch
):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    write_receipt = GATE["_write_effect_receipt"]

    def crash_before_receipt(*_args):
        raise GATE["GateError"]("injected_receipt_crash")

    GATE["install"].__globals__["_write_effect_receipt"] = crash_before_receipt
    try:
        with pytest.raises(GATE["GateError"], match="injected_receipt_crash"):
            _install(home, parent, pin)
    finally:
        GATE["install"].__globals__["_write_effect_receipt"] = write_receipt

    assert (parent / "v1").is_dir()
    assert not (parent / "root-hook-effect-receipt-v1.json").exists()
    assert _install(home, parent, pin) == "already_installed"
    receipt = json.loads((parent / "root-hook-effect-receipt-v1.json").read_bytes())
    assert receipt["generation"] == GENERATION
    assert receipt["manifest_digest"] == pin


def test_root_owner_preserves_foreign_receipt_without_overwrite(safe_tmp_path):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    assert _install(home, parent, pin) == "installed"
    receipt = parent / "root-hook-effect-receipt-v1.json"
    original = b"foreign receipt\n"
    receipt.write_bytes(original)

    with pytest.raises(GATE["GateError"]):
        _install(home, parent, pin)

    assert receipt.read_bytes() == original


def test_root_owner_refreshes_stale_receipt_after_verified_readback(safe_tmp_path):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    assert _install(home, parent, pin) == "installed"
    receipt = parent / "root-hook-effect-receipt-v1.json"
    value = json.loads(receipt.read_bytes())
    value["issued_at_unix_ns"] = 1
    receipt.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    receipt.chmod(0o644)

    assert _install(home, parent, pin) == "already_installed"

    refreshed = json.loads(receipt.read_bytes())
    assert refreshed["issued_at_unix_ns"] > 1
    assert (parent / "v1").is_dir()


def test_root_owner_lock_creation_ignores_umask_but_keeps_reader_mode(safe_tmp_path):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    previous_umask = os.umask(0o077)
    try:
        assert _install(home, parent, pin) == "installed"
    finally:
        os.umask(previous_umask)

    lock = parent / GATE["ROOT_OWNER_LOCK"]
    assert stat.S_IMODE(lock.stat().st_mode) == 0o644
    reader = os.open(lock, os.O_RDONLY)
    try:
        fcntl.flock(reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
    finally:
        fcntl.flock(reader, fcntl.LOCK_UN)
        os.close(reader)


def test_root_owner_does_not_repair_existing_private_lock(safe_tmp_path):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    lock = parent / GATE["ROOT_OWNER_LOCK"]
    lock.write_bytes(b"foreign private lock\n")
    lock.chmod(0o600)
    original = lock.read_bytes()

    with pytest.raises(GATE["GateError"], match="hook_abi_gate_owner_lock_untrusted"):
        _install(home, parent, pin)

    assert lock.read_bytes() == original
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    assert not (parent / "v1").exists()


@pytest.mark.parametrize("mode", [0o770, 0o777])
def test_writable_fixture_ancestor_never_publishes(safe_tmp_path, mode):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    (home / ".local").chmod(mode)
    with pytest.raises(GATE["GateError"]):
        _install(home, parent, pin)
    assert list(parent.iterdir()) == []


@pytest.mark.parametrize(
    "defect",
    [
        "digest",
        "plan_target",
        "source_symlink",
        "source_hardlink",
        "source_mode",
        "source_owner",
    ],
)
def test_untrusted_input_never_publishes(safe_tmp_path, monkeypatch, defect):
    home, parent, generation, pin = _fixture(safe_tmp_path)
    source = generation / "src/the_hive/hook_abi_v1_core.py"
    if defect == "digest":
        pin = "sha256:" + "0" * 64
    elif defect == "plan_target":
        plan = generation / "root-install-plan.json"
        plan.write_bytes(
            plan.read_bytes().replace(b"/hook_abi_v1_core.py", b"/wrong.py")
        )
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
    directory_fsyncs = 0

    def fail_stage(fd):
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs > 1:
                raise OSError("injected stage fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_stage)
    with pytest.raises(OSError, match="injected"):
        _install(home, parent, pin)
    assert {path.name for path in parent.iterdir()} == {GATE["ROOT_OWNER_LOCK"]}


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
    assert {path.name for path in parent.iterdir()} == {GATE["ROOT_OWNER_LOCK"]}


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
    assert {p.name for p in parent.iterdir()} == {
        "v1",
        GATE["ROOT_OWNER_LOCK"],
        ".root-hook-abi-upgrade-v1.json",
        next(name for name in os.listdir(parent) if name.startswith(".v1.stage-")),
    }
    assert (
        json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())["status"]
        == "pending"
    )
    assert list((parent / "v1").iterdir()) == []


def test_parent_fsync_error_reports_complete_visibility(safe_tmp_path, monkeypatch):
    home, parent, _generation, pin = _fixture(safe_tmp_path)
    parent_inode = parent.stat().st_ino
    real_fsync = os.fsync
    parent_fsyncs = 0

    def fail_parent(fd):
        nonlocal parent_fsyncs
        if os.fstat(fd).st_ino == parent_inode:
            parent_fsyncs += 1
            if parent_fsyncs > 1:
                raise OSError("injected parent fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_parent)
    with pytest.raises(GATE["GateError"], match="durability_unknown"):
        _install(home, parent, pin)
    assert {p.name for p in parent.iterdir()} == {
        GATE["ROOT_OWNER_LOCK"],
        ".root-hook-abi-upgrade-v1.json",
        next(name for name in os.listdir(parent) if name.startswith(".v1.stage-")),
    }
    assert (
        json.loads((parent / ".root-hook-abi-upgrade-v1.json").read_bytes())["status"]
        == "pending"
    )


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
    _put(
        release / ".the-hive-release-pointers.json",
        GATE["_canonical"](
            {
                "schema_version": 1,
                "current": {"generation": GENERATION, "manifest_digest": pin},
                "previous": None,
            }
        ),
    )
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
            plugin_root=plugin,
            release_root=release,
            state_root=state,
            abi_root=abi,
            abi_owner_uid=os.getuid(),
            hook_name="native_bee_event",
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
    _put(
        allow, original.replace(b"D320DispatchAllowlistV1", b"wrong-allowlist-schema!")
    )
    wrong_state = tmp_path / "state-wrong/pins"
    with pytest.raises(HookAbiV1Error):
        dispatch(wrong_state)
    assert not wrong_state.exists()
