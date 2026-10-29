from __future__ import annotations

import hashlib
import fcntl
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install-the-hive-resource-scope-gate"


def _consumer() -> dict[str, object]:
    namespace = runpy.run_path(str(SCRIPT))
    return namespace["main"].__globals__


def _write(path: Path, raw: bytes, mode: int) -> None:
    path.write_bytes(raw)
    path.chmod(mode)


def _fixture(tmp_path: Path) -> dict[str, object]:
    consumer = _consumer()
    uid = os.getuid()
    home = tmp_path / "home"
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    generation = "a" * 40
    generation_root = release_root / "generations" / generation
    bin_root = generation_root / "bin"
    for directory in (
        home,
        home / ".local",
        home / ".local" / "lib",
        release_root,
        release_root / "generations",
        generation_root,
        bin_root,
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)

    gate = (ROOT / "bin" / "the-hive-resource-scope-gate").read_bytes()
    gate_digest = hashlib.sha256(gate).hexdigest()
    manifest = {
        "schema_version": 2,
        "generation": generation,
        "commit": generation,
        "directories": {".": {"mode": 0o700}, "bin": {"mode": 0o700}},
        "files": {
            "bin/the-hive-resource-scope-gate": {
                "mode": 0o755,
                "nlink": 1,
                "size": len(gate),
                "sha256": gate_digest,
            }
        },
    }
    manifest_raw = consumer["_canonical_json"](manifest)
    manifest_digest = hashlib.sha256(manifest_raw).hexdigest()
    pointer = {
        "schema_version": 1,
        "current": {
            "generation": generation,
            "manifest_digest": f"sha256:{manifest_digest}",
        },
        "previous": None,
    }
    _write(
        release_root / ".the-hive-release-pointers.json",
        consumer["_canonical_json"](pointer),
        0o644,
    )
    _write(release_root / ".the-hive-release-publish.lock", b"", 0o600)
    _write(generation_root / ".the-hive-runtime-manifest.json", manifest_raw, 0o644)
    _write(bin_root / "the-hive-resource-scope-gate", gate, 0o755)
    return {
        "consumer": consumer,
        "uid": uid,
        "home": home,
        "release_root": release_root,
        "generation_root": generation_root,
        "bin_root": bin_root,
        "generation": generation,
        "manifest_digest": manifest_digest,
        "manifest": manifest,
        "gate": gate,
        "gate_digest": gate_digest,
    }


def _read_fixture_gate(fixture: dict[str, object], **overrides: object) -> bytes:
    consumer = fixture["consumer"]
    release_root = fixture["release_root"]
    release_fd, release_info, lock_fd = consumer["_open_release_read_lease"](
        release_root, uid=fixture["uid"]
    )
    pins = {
        "uid": fixture["uid"],
        "generation": fixture["generation"],
        "manifest_sha256": fixture["manifest_digest"],
    }
    pins.update(overrides)
    try:
        return consumer["_read_pinned_gate"](
            release_root,
            **pins,
            release_fd=release_fd,
            release_info=release_info,
            lock_fd=lock_fd,
        )
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        os.close(release_fd)


def _prepare_private_root_install(
    consumer: dict[str, object],
    fixture: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> list[bytes]:
    class _RootOS:
        def __getattr__(self, name: str) -> object:
            return getattr(os, name)

        @staticmethod
        def geteuid() -> int:
            return 0

    monkeypatch.setitem(consumer, "os", _RootOS())
    monkeypatch.setitem(
        consumer,
        "pwd",
        SimpleNamespace(
            getpwuid=lambda _uid: SimpleNamespace(pw_dir=str(fixture["home"]))
        ),
    )
    published: list[bytes] = []

    def publish(_fd: int, raw: bytes, _digest: str, *, verify_source=None) -> str:
        if verify_source is not None:
            verify_source()
        published.append(raw)
        return "installed"

    monkeypatch.setitem(consumer, "_publish_gate", publish)
    return published


def _install_private_fixture(
    consumer: dict[str, object], fixture: dict[str, object]
) -> str:
    return consumer["_install_for_uid"](
        fixture["uid"], fixture["generation"], fixture["manifest_digest"]
    )


def test_root_consumer_rejects_release_root_rebind_after_lock_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    consumer = fixture["consumer"]
    published = _prepare_private_root_install(consumer, fixture, monkeypatch)
    original = consumer["_open_release_read_lease"]
    release_root = fixture["release_root"]
    displaced_root = release_root.with_name("the-hive-runtime-locked")

    def lock_then_rebind(root: Path, *, uid: int):
        lease = original(root, uid=uid)
        root.rename(displaced_root)
        shutil.copytree(displaced_root, root, copy_function=shutil.copy2)
        return lease

    monkeypatch.setitem(consumer, "_open_release_read_lease", lock_then_rebind)
    with pytest.raises(consumer["GateInstallError"], match="release_source_changed"):
        _install_private_fixture(consumer, fixture)
    assert published == []


def test_root_consumer_rejects_release_lock_rebind_after_lock_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    consumer = fixture["consumer"]
    published = _prepare_private_root_install(consumer, fixture, monkeypatch)
    original = consumer["_open_release_read_lease"]
    release_root = fixture["release_root"]
    lock_path = release_root / ".the-hive-release-publish.lock"

    def lock_then_replace_name(root: Path, *, uid: int):
        lease = original(root, uid=uid)
        lock_path.unlink()
        _write(lock_path, b"", 0o600)
        return lease

    monkeypatch.setitem(consumer, "_open_release_read_lease", lock_then_replace_name)
    with pytest.raises(
        consumer["GateInstallError"], match="release_publish_lock_changed"
    ):
        _install_private_fixture(consumer, fixture)
    assert published == []


def test_root_publisher_revalidates_release_lease_before_target_mutation(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    consumer = fixture["consumer"]
    release_root = fixture["release_root"]
    release_fd, root_info, lock_fd = consumer["_open_release_read_lease"](
        release_root, uid=fixture["uid"]
    )
    target_dir = tmp_path / "usr" / "libexec"
    target_dir.mkdir(parents=True, mode=0o755)
    target_fd = os.open(target_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    lock_path = release_root / ".the-hive-release-publish.lock"
    try:
        raw = consumer["_read_pinned_gate"](
            release_root,
            uid=fixture["uid"],
            generation=fixture["generation"],
            manifest_sha256=fixture["manifest_digest"],
            release_fd=release_fd,
            release_info=root_info,
            lock_fd=lock_fd,
        )
        lock_path.unlink()
        _write(lock_path, b"", 0o600)
        with pytest.raises(
            consumer["GateInstallError"], match="release_publish_lock_changed"
        ):
            consumer["_publish_gate"](
                target_fd,
                raw,
                hashlib.sha256(raw).hexdigest(),
                verify_source=lambda: consumer["_assert_release_lease"](
                    release_root,
                    release_fd=release_fd,
                    release_info=root_info,
                    lock_fd=lock_fd,
                    uid=fixture["uid"],
                ),
            )
        assert list(target_dir.iterdir()) == []
    finally:
        os.close(target_fd)
        os.close(release_fd)
        os.close(lock_fd)


def test_root_consumer_reads_only_operator_pinned_current_gate(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    assert _read_fixture_gate(fixture) == fixture["gate"]


@pytest.mark.parametrize("pin", ("uid", "generation", "manifest_digest"))
def test_root_consumer_rejects_wrong_operator_pin(tmp_path: Path, pin: str) -> None:
    fixture = _fixture(tmp_path)
    arguments = {
        "uid": fixture["uid"],
        "generation": fixture["generation"],
        "manifest_sha256": fixture["manifest_digest"],
    }
    arguments[
        {
            "uid": "uid",
            "generation": "generation",
            "manifest_digest": "manifest_sha256",
        }[pin]
    ] = {
        "uid": fixture["uid"] + 1,
        "generation": "b" * 40,
        "manifest_digest": "0" * 64,
    }[pin]
    with pytest.raises(fixture["consumer"]["GateInstallError"]):
        _read_fixture_gate(fixture, **arguments)


def test_root_consumer_rejects_wrong_current_pointer_without_touching_gate(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    pointer_path = fixture["release_root"] / ".the-hive-release-pointers.json"
    pointer = json.loads(pointer_path.read_bytes())
    pointer["current"]["generation"] = "b" * 40
    _write(pointer_path, fixture["consumer"]["_canonical_json"](pointer), 0o644)

    with pytest.raises(fixture["consumer"]["GateInstallError"]):
        _read_fixture_gate(fixture)
    assert (
        fixture["bin_root"] / "the-hive-resource-scope-gate"
    ).read_bytes() == fixture["gate"]


def test_root_consumer_rejects_changed_gate_bytes_and_wrong_mode(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    gate_path = fixture["bin_root"] / "the-hive-resource-scope-gate"
    _write(gate_path, fixture["gate"] + b"changed", 0o755)
    with pytest.raises(fixture["consumer"]["GateInstallError"]):
        _read_fixture_gate(fixture)

    _write(gate_path, fixture["gate"], 0o700)
    with pytest.raises(fixture["consumer"]["GateInstallError"]):
        _read_fixture_gate(fixture)

    target = fixture["bin_root"] / "gate-target"
    target.write_bytes(fixture["gate"])
    gate_path.unlink()
    gate_path.symlink_to(target)
    with pytest.raises(fixture["consumer"]["GateInstallError"]):
        _read_fixture_gate(fixture)


def test_root_consumer_rejects_hardlinked_gate_member(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    gate_path = fixture["bin_root"] / "the-hive-resource-scope-gate"
    os.link(gate_path, fixture["bin_root"] / "gate-alias")
    with pytest.raises(fixture["consumer"]["GateInstallError"]):
        _read_fixture_gate(fixture)


def test_root_consumer_rejects_untrusted_release_publish_lock(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    lock = fixture["release_root"] / ".the-hive-release-publish.lock"
    _write(lock, b"", 0o644)
    with pytest.raises(fixture["consumer"]["GateInstallError"]):
        fixture["consumer"]["_open_release_read_lease"](
            fixture["release_root"], uid=fixture["uid"]
        )


def test_root_consumer_rejects_manifest_digest_and_manifest_metadata_changes(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    manifest_path = fixture["generation_root"] / ".the-hive-runtime-manifest.json"
    raw = manifest_path.read_bytes()
    _write(manifest_path, raw + b" ", 0o644)
    with pytest.raises(fixture["consumer"]["GateInstallError"]):
        _read_fixture_gate(fixture)

    _write(manifest_path, raw, 0o600)
    with pytest.raises(fixture["consumer"]["GateInstallError"]):
        _read_fixture_gate(fixture)


def test_root_consumer_rejects_pointer_swap_after_initial_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    consumer = fixture["consumer"]
    original = consumer["_read_regular_at"]
    pointer_path = fixture["release_root"] / ".the-hive-release-pointers.json"
    calls = 0

    def swap_pointer(*args: object, **kwargs: object):
        nonlocal calls
        result = original(*args, **kwargs)
        if args[1] == ".the-hive-release-pointers.json":
            calls += 1
            if calls == 1:
                pointer = json.loads(pointer_path.read_bytes())
                pointer["current"]["generation"] = "b" * 40
                _write(pointer_path, consumer["_canonical_json"](pointer), 0o644)
        return result

    monkeypatch.setitem(consumer, "_read_regular_at", swap_pointer)
    with pytest.raises(consumer["GateInstallError"]):
        _read_fixture_gate(fixture)


def test_root_consumer_rejects_gate_path_rebind_after_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    consumer = fixture["consumer"]
    original = consumer["_read_regular_at"]
    gate_path = fixture["bin_root"] / "the-hive-resource-scope-gate"
    calls = 0

    def swap_gate(*args: object, **kwargs: object):
        nonlocal calls
        result = original(*args, **kwargs)
        if args[1] == "the-hive-resource-scope-gate":
            calls += 1
            if calls == 1:
                gate_path.rename(fixture["bin_root"] / "gate-old")
                _write(gate_path, fixture["gate"], 0o755)
        return result

    monkeypatch.setitem(consumer, "_read_regular_at", swap_gate)
    with pytest.raises(consumer["GateInstallError"], match="release_source_changed"):
        _read_fixture_gate(fixture)


def _publish(consumer: dict[str, object], directory: Path, gate: bytes) -> str:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return consumer["_publish_gate"](
            descriptor, gate, hashlib.sha256(gate).hexdigest()
        )
    finally:
        os.close(descriptor)


def test_root_publisher_is_atomic_and_idempotent_on_private_fixture(
    tmp_path: Path,
) -> None:
    consumer = _consumer()
    target_dir = tmp_path / "usr" / "libexec"
    target_dir.mkdir(parents=True, mode=0o755)
    gate = b"private fixture executable\n"

    assert _publish(consumer, target_dir, gate) == "installed"
    target = target_dir / "the-hive-resource-scope-gate"
    assert target.read_bytes() == gate
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert target.stat().st_nlink == 1
    assert _publish(consumer, target_dir, gate) == "already_installed"


def test_root_publisher_preserves_racing_foreign_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    consumer = _consumer()
    target_dir = tmp_path / "usr" / "libexec"
    target_dir.mkdir(parents=True, mode=0o755)
    gate = b"private fixture executable\n"
    foreign = b"foreign target\n"
    original = consumer["_rename_noreplace"]
    target = target_dir / "the-hive-resource-scope-gate"

    def race(directory_fd: int, source: str, destination: str) -> None:
        fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o755,
            dir_fd=directory_fd,
        )
        try:
            os.write(fd, foreign)
            os.fchmod(fd, 0o755)
        finally:
            os.close(fd)
        original(directory_fd, source, destination)

    monkeypatch.setitem(consumer, "_rename_noreplace", race)
    with pytest.raises(consumer["GateInstallError"], match="gate_target_untrusted"):
        _publish(consumer, target_dir, gate)
    assert target.read_bytes() == foreign
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


@pytest.mark.parametrize("target_kind", ("foreign", "symlink", "hardlink"))
def test_root_publisher_refuses_existing_untrusted_target(
    tmp_path: Path, target_kind: str
) -> None:
    consumer = _consumer()
    target_dir = tmp_path / "usr" / "libexec"
    target_dir.mkdir(parents=True, mode=0o755)
    target = target_dir / "the-hive-resource-scope-gate"
    foreign = b"foreign target\n"
    if target_kind == "symlink":
        outside = tmp_path / "outside"
        outside.write_bytes(foreign)
        target.symlink_to(outside)
    else:
        target.write_bytes(foreign)
        target.chmod(0o755)
        if target_kind == "hardlink":
            os.link(target, target_dir / "outside-link")

    with pytest.raises(consumer["GateInstallError"]):
        _publish(consumer, target_dir, b"approved gate\n")
    if target_kind == "symlink":
        assert target.is_symlink()
        assert target.resolve().read_bytes() == foreign
    else:
        assert target.read_bytes() == foreign


def test_root_publisher_resumes_a_complete_stage_after_publish_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    consumer = _consumer()
    target_dir = tmp_path / "usr" / "libexec"
    target_dir.mkdir(parents=True, mode=0o755)
    gate = b"private fixture executable\n"

    def fail_publish(*_args: object) -> None:
        raise consumer["GateInstallError"]("atomic_noreplace_unavailable")

    monkeypatch.setitem(consumer, "_rename_noreplace", fail_publish)
    with pytest.raises(
        consumer["GateInstallError"], match="atomic_noreplace_unavailable"
    ):
        _publish(consumer, target_dir, gate)
    assert list(target_dir.glob(".the-hive-resource-scope-gate.*.stage"))

    monkeypatch.setitem(consumer, "_rename_noreplace", _consumer()["_rename_noreplace"])
    assert _publish(consumer, target_dir, gate) == "installed"
    assert (target_dir / "the-hive-resource-scope-gate").read_bytes() == gate


def test_root_consumer_cli_requires_root_and_has_no_target_option(
    capsys: pytest.CaptureFixture[str],
) -> None:
    if os.geteuid() == 0:
        pytest.skip("root_cli_test_would_mutate_the_fixed_target")
    consumer = _consumer()
    result = consumer["main"](
        ["--uid", "1000", "--generation", "a" * 40, "--manifest-sha256", "0" * 64]
    )
    assert result == 1
    assert json.loads(capsys.readouterr().out) == {"error": "root_required"}
    with pytest.raises(SystemExit) as failure:
        consumer["main"](
            [
                "--uid",
                "1000",
                "--generation",
                "a" * 40,
                "--manifest-sha256",
                "0" * 64,
                "--target",
                "/tmp/gate",
            ]
        )
    assert failure.value.code == 2


def test_isolated_root_script_does_not_import_user_pythonpath_before_denial(
    tmp_path: Path,
) -> None:
    if os.geteuid() == 0:
        pytest.skip("root_cli_test_would_mutate_the_fixed_target")
    shadow = tmp_path / "shadow"
    package = shadow / "the_hive"
    package.mkdir(parents=True)
    marker = tmp_path / "user_imported"
    (package / "__init__.py").write_text(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('loaded')\n",
        encoding="utf-8",
    )
    environment = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(shadow),
        "HOME": str(tmp_path),
    }

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(SCRIPT),
            "--uid",
            str(os.getuid()),
            "--generation",
            "a" * 40,
            "--manifest-sha256",
            "0" * 64,
        ],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert json.loads(result.stdout) == {"error": "root_required"}
    assert result.stderr == ""
    assert not marker.exists()
