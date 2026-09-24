from __future__ import annotations

import base64
import copy
import hashlib
import subprocess
import sys
import fcntl
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "the-hive-runtime-service"
sys.path.insert(0, str(ROOT / "src"))

from the_hive import runtime_lifecycle  # noqa: E402


def _identity(path: Path) -> tuple[int, int, int, int, int, bytes]:
    info = path.stat()
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode & 0o777,
        info.st_nlink,
        path.read_bytes(),
    )


def _lifecycle_state(home: Path) -> None:
    leaf = home / ".local" / "state" / "codex-master-mcp" / "hive"
    leaf.mkdir(parents=True, mode=0o700)
    for directory in (
        home / ".local",
        home / ".local" / "state",
        home / ".local" / "state" / "codex-master-mcp",
        leaf,
    ):
        directory.chmod(0o700)


def _bound_failure_fixture(
    tmp_path: Path,
) -> tuple[runtime_lifecycle._BoundCutover, dict[str, dict[str, str]]]:
    """Create the complete pre-cutover private state for phase-failure tests."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    release = home / ".local" / "lib" / "the-hive-runtime"
    units = home / ".config" / "systemd" / "user"
    state = home / ".local" / "state" / "codex-master-mcp"
    launcher = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    for directory in (
        home / ".local",
        home / ".local" / "lib",
        release,
        home / ".config",
        home / ".config" / "systemd",
        units,
        home / ".local" / "state",
        state,
        home / ".local" / "libexec",
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    originals = (
        (release / ".the-hive-release-pointers.json", b'{"old":true}\n', 0o644),
        (release / "the-hive-mcp", b"old-mcp\n", 0o755),
        (launcher, b"old-launcher\n", 0o755),
        (state / "runtime-lifecycle-probe-observation.json", b'{"old":true}\n', 0o600),
        (units / "the-hive-hive-hourly-probe.service", b"new-service\n", 0o644),
        (units / "the-hive-hive-hourly-probe.timer", b"new-timer\n", 0o644),
        (units / "codex-master-hive-hourly-probe.service", b"legacy-service\n", 0o644),
        (units / "codex-master-hive-hourly-probe.timer", b"legacy-timer\n", 0o644),
    )
    for path, content, mode in originals:
        path.write_bytes(content)
        path.chmod(mode)
    states = {
        "the-hive-hive-hourly-probe.service": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        },
        "the-hive-hive-hourly-probe.timer": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        },
        "codex-master-hive-hourly-probe.service": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "active",
        },
        "codex-master-hive-hourly-probe.timer": {
            "LoadState": "loaded",
            "UnitFileState": "enabled",
            "ActiveState": "active",
        },
    }
    return (
        runtime_lifecycle._BoundCutover(
            home=home,
            release_root=release,
            units=units,
            state_root=state,
            files=originals,
            source_digests=(),
            source_commit="a" * 40,
            generations_before=frozenset({"a" * 40}),
            legacy_present=True,
            states=tuple(states.items()),
        ),
        states,
    )


def _mutate_bound_files(bound: runtime_lifecycle._BoundCutover) -> None:
    for path, _content, mode in bound.files:
        path.write_bytes(b"mutated-by-failed-cutover\n")
        path.chmod(mode)


def _assert_bound_files_restored(bound: runtime_lifecycle._BoundCutover) -> None:
    for path, content, mode in bound.files:
        assert content is not None
        device, inode, owner, restored_mode, nlink, bytes_value = _identity(path)
        assert device == path.parent.stat().st_dev
        assert inode > 0
        assert owner == path.parent.stat().st_uid
        assert restored_mode == mode
        assert nlink == 1
        assert bytes_value == content


def _allow_postinstall_attestation(monkeypatch) -> None:
    post_install = object()
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_post_install", lambda _home: post_install
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_revalidate_post_install", lambda _bound, _home: None
    )


def test_public_runtime_lifecycle_surface_exposes_only_cutover_status_and_verify() -> (
    None
):
    completed = subprocess.run(
        [SCRIPT, "--help"], check=False, capture_output=True, text=True
    )

    assert completed.returncode == 0
    assert "cutover" in completed.stdout
    assert "status" in completed.stdout
    assert "verify" in completed.stdout
    assert "rollback" not in completed.stdout


def test_legacy_installer_cli_rejects_a_second_mutating_operator_route(
    tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [
            ROOT / "scripts" / "the-hive-hive-hourly-probe-install",
            "--home",
            tmp_path / "home",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert completed.stdout == (
        '{"raw_output": "not_returned", '
        '"status": "runtime_lifecycle_cutover_required"}\n'
    )
    assert not (tmp_path / "home").exists()


def test_d300_consumer_producer_contract_accepts_only_named_06542_identity() -> None:
    """Catches a runtime image that retains the retired .541 pin or a fallback."""

    valid = (
        b'_PRODUCER_VERSION = "0.6.542"\n'
        b'_PRODUCER_SOURCE_MANIFEST_SHA256 = "8da41af5293cf4816a04db5443b14c718d496756c666ea8854f8b053021f14f0"\n'
        b'_PRODUCER_RELEASE_ID = "0.6.542-8da41af5293cf481"\n'
        b'if python_directory[2] != "python3.14":\n    raise ValueError()\n'
    )
    retired = valid.replace(b'"0.6.542"', b'"0.6.541"')
    other_version = valid.replace(b'"0.6.542"', b'"0.6.543"')
    other_manifest = valid.replace(
        b"8da41af5293cf4816a04db5443b14c718d496756c666ea8854f8b053021f14f0",
        b"0" * 64,
    )
    heuristic_only = b"# " + valid

    assert runtime_lifecycle._consumer_producer_contract(valid) is True
    assert runtime_lifecycle._consumer_producer_contract(retired) is False
    assert runtime_lifecycle._consumer_producer_contract(other_version) is False
    assert runtime_lifecycle._consumer_producer_contract(other_manifest) is False
    assert runtime_lifecycle._consumer_producer_contract(heuristic_only) is False


def test_verify_is_read_only_and_reports_separate_timer_states(tmp_path: Path) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    timer = units / "the-hive-hive-hourly-probe.timer"
    timer.write_text(
        "[Timer]\n"
        "OnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n"
        "[Install]\nWantedBy=timers.target\n",
        encoding="utf-8",
    )
    timer.chmod(0o644)
    (units / "the-hive-hive-hourly-probe.service").write_text(
        "[Service]\nType=oneshot\n", encoding="utf-8"
    )
    (units / "the-hive-hive-hourly-probe.service").chmod(0o644)
    calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        assert arguments[0] == "show"
        return {
            "LoadState": "loaded",
            "UnitFileState": "enabled",
            "ActiveState": "active",
            "Result": "success",
            "ExecMainStatus": "0",
        }

    result = runtime_lifecycle.verify(home=home, systemctl=systemctl)

    assert result["installed"] is False
    assert result["enabled"] is False
    assert result["active"] is False
    assert result["observed"] is False
    assert result["error_code"] == "runtime_lifecycle_runtime_identity_invalid"
    assert result["status"] == "runtime_lifecycle_red"
    assert calls == []


def test_verify_rejects_a_timer_with_any_term_beyond_the_exact_eight_utc_contract(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    timer = units / "the-hive-hive-hourly-probe.timer"
    timer.write_text(
        "[Timer]\n"
        "OnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n"
        "OnCalendar=*-*-* 01:00:00 UTC\n",
        encoding="utf-8",
    )
    timer.chmod(0o644)
    (units / "the-hive-hive-hourly-probe.service").write_text(
        "[Service]\n", encoding="utf-8"
    )
    (units / "the-hive-hive-hourly-probe.service").chmod(0o644)

    result = runtime_lifecycle.verify(
        home=home,
        systemctl=lambda _arguments: {
            "LoadState": "not-found",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
            "Result": "success",
            "ExecMainStatus": "0",
        },
    )

    assert result["checks"]["eight_utc_terms"] is False


def test_verify_rejects_hardlinked_or_symlinked_unit_files(tmp_path: Path) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    source = tmp_path / "unit-source"
    source.write_text(
        "[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n",
        encoding="utf-8",
    )
    source.chmod(0o644)
    (units / "the-hive-hive-hourly-probe.timer").hardlink_to(source)
    (units / "the-hive-hive-hourly-probe.service").symlink_to(source)

    result = runtime_lifecycle.verify(
        home=home,
        systemctl=lambda _arguments: {
            "LoadState": "not-found",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
            "Result": "failed",
            "ExecMainStatus": "1",
        },
    )

    assert result["installed"] is False
    assert result["checks"]["unit_files"] is False


def test_verify_returns_a_stable_binding_error_without_later_unbound_reads(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    target = tmp_path / "untrusted-units"
    target.mkdir(mode=0o700)
    units_parent = home / ".config" / "systemd"
    units_parent.mkdir(parents=True, mode=0o700)
    for directory in (home / ".config", units_parent):
        directory.chmod(0o700)
    (units_parent / "user").symlink_to(target)
    calls: list[tuple[str, ...]] = []

    result = runtime_lifecycle.verify(
        home=home, systemctl=lambda arguments: calls.append(arguments) or {}
    )

    assert result["status"] == "runtime_lifecycle_red"
    assert result["error_code"] == "runtime_lifecycle_binding_invalid"
    assert result["installed"] is False
    assert result["enabled"] is False
    assert result["active"] is False
    assert result["observed"] is False
    assert calls == []


@pytest.mark.parametrize(
    ("service_bytes", "timer_bytes"),
    (
        (
            b"[Service]\nExecStart=/malicious\n",
            b"[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n",
        ),
        (
            b"[Service]\nExecStart=/attested\n",
            (
                b"[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n"
                b"Persistent=false\nUnit=malicious.service\n"
            ),
        ),
    ),
    ids=("malicious-service", "eight-term-timer-wrong-semantics"),
)
def test_verify_rejects_units_not_exactly_derived_from_attested_runtime(
    tmp_path: Path, monkeypatch, service_bytes: bytes, timer_bytes: bytes
) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    for directory in (home, home / ".config", home / ".config" / "systemd", units):
        directory.chmod(0o700)
    (units / "the-hive-hive-hourly-probe.service").write_bytes(service_bytes)
    (units / "the-hive-hive-hourly-probe.timer").write_bytes(timer_bytes)
    for path in units.iterdir():
        path.chmod(0o644)
    identity = {
        "generation": "a" * 40,
        "manifest_digest": "sha256:" + "b" * 64,
        "consumer_pin": True,
    }
    monkeypatch.setattr(runtime_lifecycle, "_runtime_identity", lambda _root: identity)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_attested_hourly_unit_bytes",
        lambda **_kwargs: (
            b"[Service]\nExecStart=/attested\n",
            b"[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n",
        ),
    )
    monkeypatch.setattr(runtime_lifecycle, "_d296_and_v2_accepted", lambda: True)
    monkeypatch.setattr(runtime_lifecycle, "_parse_health", lambda _root: (True, True))
    monkeypatch.setattr(runtime_lifecycle, "_probe_gate_allowed", lambda _root: True)
    monkeypatch.setattr(runtime_lifecycle, "_observation_matches", lambda **_kwargs: True)
    calls: list[tuple[str, ...]] = []

    result = runtime_lifecycle.verify(
        home=home, systemctl=lambda arguments: calls.append(arguments) or {}
    )

    assert result["status"] == "runtime_lifecycle_red"
    assert result["error_code"] == "runtime_lifecycle_unit_attestation_invalid"
    assert result["checks"]["unit_files"] is False
    assert calls == []


def test_cutover_rejects_parallel_lifecycle_lock_before_systemd(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".local" / "state" / "codex-master-mcp" / "hive").mkdir(
        parents=True, mode=0o700
    )
    for directory in (
        home / ".local",
        home / ".local" / "state",
        home / ".local" / "state" / "codex-master-mcp",
        home / ".local" / "state" / "codex-master-mcp" / "hive",
    ):
        directory.chmod(0o700)
    lock = (
        home
        / ".local"
        / "state"
        / "codex-master-mcp"
        / "hive"
        / ".runtime-lifecycle.lock"
    )
    lock.write_text("held", encoding="utf-8")
    lock.chmod(0o600)
    calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        return {}

    with lock.open("r", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = runtime_lifecycle.cutover(home=home, systemctl=systemctl)

    assert result == {
        "status": "runtime_lifecycle_busy",
        "raw_output": "not_returned",
    }
    assert calls == []


def test_cutover_rejects_a_symlinked_lifecycle_lock_before_any_mutation(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    lock_root = home / ".local" / "state" / "codex-master-mcp" / "hive"
    lock_root.mkdir(parents=True, mode=0o700)
    for directory in (
        home / ".local",
        home / ".local" / "state",
        home / ".local" / "state" / "codex-master-mcp",
        lock_root,
    ):
        directory.chmod(0o700)
    target = tmp_path / "target"
    target.write_text("target", encoding="utf-8")
    (lock_root / ".runtime-lifecycle.lock").symlink_to(target)
    calls: list[tuple[str, ...]] = []

    result = runtime_lifecycle.cutover(
        home=home,
        systemctl=lambda arguments: calls.append(arguments) or {},
    )

    assert result == {
        "status": "runtime_lifecycle_lock_invalid",
        "raw_output": "not_returned",
    }
    assert calls == []


def test_lifecycle_lock_creates_only_the_missing_private_hive_leaf(tmp_path: Path) -> None:
    home = tmp_path / "home"
    parent = home / ".local" / "state" / "codex-master-mcp"
    parent.mkdir(parents=True, mode=0o700)
    for directory in (
        home / ".local",
        home / ".local" / "state",
        parent,
    ):
        directory.chmod(0o700)

    with runtime_lifecycle._lifecycle_lock(home):
        lock = parent / "hive" / ".runtime-lifecycle.lock"
        assert lock.is_file()
        assert lock.lstat().st_mode & 0o777 == 0o600

    assert (parent / "hive").lstat().st_mode & 0o777 == 0o700


def test_verify_never_derives_observation_from_systemd_health_or_gate(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    for name, text in (
        ("the-hive-hive-hourly-probe.service", "[Service]\n"),
        (
            "the-hive-hive-hourly-probe.timer",
            "[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n",
        ),
    ):
        path = units / name
        path.write_text(text, encoding="utf-8")
        path.chmod(0o644)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_runtime_identity",
        lambda _root: {
            "generation": "a" * 40,
            "manifest_digest": "sha256:" + "b" * 64,
            "consumer_pin": True,
        },
    )
    monkeypatch.setattr(runtime_lifecycle, "_d296_and_v2_accepted", lambda: True)
    monkeypatch.setattr(runtime_lifecycle, "_parse_health", lambda _root: (True, True))
    monkeypatch.setattr(runtime_lifecycle, "_probe_gate_allowed", lambda _root: True)
    monkeypatch.setattr(runtime_lifecycle, "_observation_matches", lambda **_kwargs: False)

    result = runtime_lifecycle.verify(
        home=home,
        systemctl=lambda arguments: (
            {
                "LoadState": "not-found",
                "UnitFileState": "disabled",
                "ActiveState": "inactive",
                "Result": "success",
                "ExecMainStatus": "0",
            }
            if arguments[1].startswith("codex-master-")
            else {
                "LoadState": "loaded",
                "UnitFileState": "enabled",
                "ActiveState": "active",
                "Result": "success",
                "ExecMainStatus": "0",
            }
        ),
    )

    assert result["observed"] is False
    assert result["status"] == "runtime_lifecycle_red"


def test_cutover_records_only_a_zero_exit_argumentless_probe_observation(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _lifecycle_state(home)
    snapshot = object()
    monkeypatch.setattr(runtime_lifecycle, "_bind_cutover_inputs", lambda _home: snapshot)
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_systemd_states", lambda received, _systemctl: received
    )
    monkeypatch.setattr(runtime_lifecycle, "_revalidate_cutover_inputs", lambda _snapshot: None)
    monkeypatch.setattr(runtime_lifecycle, "_install_attested_runtime", lambda _home: None)
    _allow_postinstall_attestation(monkeypatch)
    monkeypatch.setattr(runtime_lifecycle, "_legacy_requires_migration", lambda _bound: False)
    monkeypatch.setattr(runtime_lifecycle, "_legacy_requires_migration", lambda _snapshot: True)
    monkeypatch.setattr(runtime_lifecycle, "_revalidate_legacy_units", lambda _snapshot: None)
    monkeypatch.setattr(runtime_lifecycle, "_remove_legacy_hourly_units", lambda _snapshot: None)
    monkeypatch.setattr(
        runtime_lifecycle,
        "verify",
        lambda **_kwargs: {
            "status": "runtime_lifecycle_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_observe_argumentless_installed_probe",
        lambda _home: (_ for _ in ()).throw(
            runtime_lifecycle.RuntimeLifecycleError("runtime_lifecycle_probe_failed")
        ),
    )
    restored: list[object] = []
    monkeypatch.setattr(
        runtime_lifecycle, "_restore_bound_state", lambda received, _systemctl: restored.append(received) or True
    )

    result = runtime_lifecycle.cutover(home=home, systemctl=lambda _arguments: {})

    assert result == {
        "status": "runtime_lifecycle_probe_failed",
        "raw_output": "not_returned",
    }
    assert restored == [snapshot]


def test_observation_receipt_requires_a_real_zero_exit_argumentless_launcher_run(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    state_root = home / ".local" / "state" / "codex-master-mcp"
    state_root.mkdir(parents=True, mode=0o700)
    for directory in (home / ".local", home / ".local" / "state", state_root):
        directory.chmod(0o700)
    binding = runtime_lifecycle._ProbeObservationBinding(
        generation="a" * 40,
        manifest_digest="sha256:" + "b" * 64,
        launcher_sha256="c" * 64,
        launcher=home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py",
        runtime_layout=object(),
    )
    identity = {
        "generation": binding.generation,
        "manifest_digest": binding.manifest_digest,
        "consumer_pin": True,
    }
    monkeypatch.setattr(runtime_lifecycle, "_runtime_identity", lambda _root: identity)
    monkeypatch.setattr(
        runtime_lifecycle, "_probe_observation_binding", lambda **_kwargs: binding
    )

    assert (
        runtime_lifecycle._observation_matches(
            home=home, state_root=state_root, identity=identity
        )
        is False
    )
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        runtime_lifecycle,
        "run_bounded",
        lambda arguments, **_kwargs: calls.append(tuple(arguments))
        or SimpleNamespace(returncode=1, stdout="", stderr=""),
    )
    try:
        runtime_lifecycle._observe_argumentless_installed_probe(home)
    except runtime_lifecycle.RuntimeLifecycleError as exc:
        assert str(exc) == "runtime_lifecycle_probe_failed"
    else:
        raise AssertionError("a non-zero launcher must fail closed")
    assert calls == [(str(binding.launcher),)]
    assert not (state_root / "runtime-lifecycle-probe-observation.json").exists()

    monkeypatch.setattr(
        runtime_lifecycle,
        "run_bounded",
        lambda arguments, **_kwargs: calls.append(tuple(arguments))
        or SimpleNamespace(returncode=0, stdout="{}", stderr=""),
    )
    runtime_lifecycle._observe_argumentless_installed_probe(home)

    assert calls == [(str(binding.launcher),), (str(binding.launcher),)]
    assert (
        runtime_lifecycle._observation_matches(
            home=home, state_root=state_root, identity=identity
        )
        is True
    )


def test_observation_does_not_write_a_receipt_when_the_bounded_launcher_fails(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    state_root = home / ".local" / "state" / "codex-master-mcp"
    state_root.mkdir(parents=True, mode=0o700)
    for directory in (home / ".local", home / ".local" / "state", state_root):
        directory.chmod(0o700)
    binding = runtime_lifecycle._ProbeObservationBinding(
        generation="a" * 40,
        manifest_digest="sha256:" + "b" * 64,
        launcher_sha256="c" * 64,
        launcher=home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py",
        runtime_layout=object(),
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_runtime_identity",
        lambda _root: {
            "generation": binding.generation,
            "manifest_digest": binding.manifest_digest,
            "consumer_pin": True,
        },
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_probe_observation_binding", lambda **_kwargs: binding
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "run_bounded",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            runtime_lifecycle.BoundedProcessError("command_timeout")
        ),
    )

    try:
        runtime_lifecycle._observe_argumentless_installed_probe(home)
    except runtime_lifecycle.RuntimeLifecycleError as exc:
        assert str(exc) == "runtime_lifecycle_probe_observation_failed"
    else:
        raise AssertionError("a bounded launcher failure must fail closed")
    assert not (state_root / "runtime-lifecycle-probe-observation.json").exists()


def test_status_and_verify_are_read_only_even_when_all_postconditions_are_red(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    state = home / ".local" / "state" / "codex-master-mcp"
    for directory in (
        home,
        home / ".config",
        home / ".config" / "systemd",
        units,
        home / ".local",
        home / ".local" / "state",
        state,
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    for name in (
        "the-hive-hive-hourly-probe.service",
        "the-hive-hive-hourly-probe.timer",
    ):
        path = units / name
        path.write_text("[Unit]\n", encoding="utf-8")
        path.chmod(0o644)
    before = {path: _identity(path) for path in home.rglob("*") if path.is_file()}
    def systemctl(_arguments: tuple[str, ...]) -> dict[str, str]:
        return {
            "LoadState": "not-found",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        }

    assert runtime_lifecycle.status(home=home, systemctl=systemctl)["status"] == (
        "runtime_lifecycle_red"
    )
    assert runtime_lifecycle.verify(home=home, systemctl=systemctl)["status"] == (
        "runtime_lifecycle_red"
    )
    assert {path: _identity(path) for path in home.rglob("*") if path.is_file()} == before


def test_cutover_uses_one_bound_transaction_and_never_touches_foreign_units(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _lifecycle_state(home)
    calls: list[tuple[str, ...]] = []
    snapshot = object()

    monkeypatch.setattr(
        runtime_lifecycle, "_bind_cutover_inputs", lambda _home: snapshot
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_systemd_states", lambda received, _systemctl: received
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_revalidate_cutover_inputs", lambda _snapshot: None
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_install_attested_runtime", lambda _home: None
    )
    post_install = object()
    revalidations: list[object] = []
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_post_install", lambda _home: post_install
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_revalidate_post_install",
        lambda received, _home: revalidations.append(received),
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_legacy_requires_migration", lambda _snapshot: True
    )
    monkeypatch.setattr(runtime_lifecycle, "_revalidate_legacy_units", lambda _snapshot: None)
    monkeypatch.setattr(
        runtime_lifecycle, "_remove_legacy_hourly_units", lambda _snapshot: None
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_observe_argumentless_installed_probe", lambda _home: None
    )
    verification = ["runtime_lifecycle_red", "runtime_lifecycle_green"]

    def verify(**_kwargs):
        status = verification.pop(0)
        return {
            "status": status,
            "installed": True,
            "enabled": True,
            "active": True,
            "observed": True,
            "checks": {},
            "raw_output": "not_returned",
        }

    monkeypatch.setattr(runtime_lifecycle, "verify", verify)

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        return {}

    result = runtime_lifecycle.cutover(home=home, systemctl=systemctl)

    assert result["status"] == "runtime_lifecycle_green"
    assert calls == [
        ("daemon-reload",),
        ("stop", "codex-master-hive-hourly-probe.service"),
        ("disable", "--now", "codex-master-hive-hourly-probe.timer"),
        ("enable", "--now", "the-hive-hive-hourly-probe.timer"),
        ("start", "the-hive-hive-hourly-probe.service"),
        ("daemon-reload",),
    ]
    # Six user-manager mutations plus the bounded probe observation are each
    # preceded by a fresh binding check of the post-installer Runtime/unit pair.
    assert revalidations == [post_install] * (len(calls) + 1)
    assert all("codex-usage" not in call and "watchdog" not in call for call in calls)


def test_cutover_is_idempotent_when_verify_is_already_green(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _lifecycle_state(home)
    snapshot = object()
    green = {
        "status": "runtime_lifecycle_green",
        "installed": True,
        "enabled": True,
        "active": True,
        "observed": True,
        "checks": {},
        "raw_output": "not_returned",
    }
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_cutover_inputs", lambda _home: snapshot
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_systemd_states", lambda received, _systemctl: received
    )
    monkeypatch.setattr(runtime_lifecycle, "verify", lambda **_kwargs: green)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_install_attested_runtime",
        lambda _home: (_ for _ in ()).throw(AssertionError("installer must not run")),
    )

    result = runtime_lifecycle.cutover(
        home=home,
        systemctl=lambda _arguments: (_ for _ in ()).throw(
            AssertionError("systemctl must not run")
        ),
    )

    assert result is green


def test_cutover_rebind_before_installer_fails_without_systemd_or_rollback_mutation(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _lifecycle_state(home)
    snapshot = object()
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_cutover_inputs", lambda _home: snapshot
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_systemd_states", lambda received, _systemctl: received
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "verify",
        lambda **_kwargs: {"status": "runtime_lifecycle_red"},
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_revalidate_cutover_inputs",
        lambda _snapshot: (_ for _ in ()).throw(
            runtime_lifecycle.RuntimeLifecycleError("runtime_lifecycle_input_changed")
        ),
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_install_attested_runtime",
        lambda _home: (_ for _ in ()).throw(AssertionError("installer must not run")),
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_restore_bound_state",
        lambda _snapshot, _systemctl: (_ for _ in ()).throw(
            AssertionError("rollback must not run")
        ),
    )

    result = runtime_lifecycle.cutover(
        home=home,
        systemctl=lambda _arguments: (_ for _ in ()).throw(
            AssertionError("systemctl must not run")
        ),
    )

    assert result == {
        "status": "runtime_lifecycle_input_changed",
        "raw_output": "not_returned",
    }


def test_installer_source_entry_rebind_rejects_before_runpy_loader(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(runtime_lifecycle, "_source_tree_binding", lambda _repo: ("a" * 40, "b" * 64))

    @runtime_lifecycle.contextmanager
    def broken_entry(_repository: Path):
        raise runtime_lifecycle.RuntimeLifecycleError("runtime_lifecycle_source_entry_changed")
        yield  # pragma: no cover

    monkeypatch.setattr(runtime_lifecycle, "_bound_installer_entry", broken_entry)
    monkeypatch.setattr(
        runtime_lifecycle,
        "runpy",
        type(
            "NoRunpy",
            (), {
                "run_path": staticmethod(
                    lambda _path: (_ for _ in ()).throw(AssertionError("must not load"))
                )
            },
        ),
    )

    try:
        runtime_lifecycle._install_attested_runtime(home)
    except runtime_lifecycle.RuntimeLifecycleError as exc:
        assert str(exc) == "runtime_lifecycle_source_entry_changed"
    else:
        raise AssertionError("a rebound installer entry must be rejected")


def test_cutover_postinstall_rebind_fails_before_any_user_manager_mutation(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _lifecycle_state(home)
    snapshot = object()
    monkeypatch.setattr(runtime_lifecycle, "_bind_cutover_inputs", lambda _home: snapshot)
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_systemd_states", lambda received, _systemctl: received
    )
    monkeypatch.setattr(runtime_lifecycle, "_revalidate_cutover_inputs", lambda _bound: None)
    monkeypatch.setattr(
        runtime_lifecycle, "verify", lambda **_kwargs: {"status": "runtime_lifecycle_red"}
    )
    monkeypatch.setattr(runtime_lifecycle, "_install_attested_runtime", lambda _home: None)
    monkeypatch.setattr(runtime_lifecycle, "_legacy_requires_migration", lambda _bound: False)
    monkeypatch.setattr(runtime_lifecycle, "_bind_post_install", lambda _home: object())
    monkeypatch.setattr(
        runtime_lifecycle,
        "_revalidate_post_install",
        lambda _post, _home: (_ for _ in ()).throw(
            runtime_lifecycle.RuntimeLifecycleError("runtime_lifecycle_postinstall_changed")
        ),
    )
    restored: list[object] = []
    monkeypatch.setattr(
        runtime_lifecycle,
        "_restore_bound_state",
        lambda received, _systemctl: restored.append(received) or True,
    )
    calls: list[tuple[str, ...]] = []

    result = runtime_lifecycle.cutover(
        home=home, systemctl=lambda arguments: calls.append(arguments) or {}
    )

    assert result["status"] == "runtime_lifecycle_postinstall_changed"
    assert calls == []
    assert restored == [snapshot]


def test_cutover_legacy_rebind_fails_before_any_user_manager_mutation(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _lifecycle_state(home)
    snapshot = object()
    monkeypatch.setattr(runtime_lifecycle, "_bind_cutover_inputs", lambda _home: snapshot)
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_systemd_states", lambda received, _systemctl: received
    )
    monkeypatch.setattr(runtime_lifecycle, "_revalidate_cutover_inputs", lambda _bound: None)
    monkeypatch.setattr(
        runtime_lifecycle, "verify", lambda **_kwargs: {"status": "runtime_lifecycle_red"}
    )
    monkeypatch.setattr(runtime_lifecycle, "_install_attested_runtime", lambda _home: None)
    _allow_postinstall_attestation(monkeypatch)
    monkeypatch.setattr(runtime_lifecycle, "_legacy_requires_migration", lambda _bound: True)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_revalidate_legacy_units",
        lambda _bound: (_ for _ in ()).throw(
            runtime_lifecycle.RuntimeLifecycleError("runtime_lifecycle_legacy_changed")
        ),
    )
    monkeypatch.setattr(runtime_lifecycle, "_restore_bound_state", lambda *_args: True)
    calls: list[tuple[str, ...]] = []

    result = runtime_lifecycle.cutover(
        home=home, systemctl=lambda arguments: calls.append(arguments) or {}
    )

    assert result["status"] == "runtime_lifecycle_legacy_changed"
    assert calls == []


def test_postinstall_binding_rejects_syntactically_eight_term_malicious_units(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    for directory in (home, home / ".config", home / ".config" / "systemd", units):
        directory.chmod(0o700)
    service = units / "the-hive-hive-hourly-probe.service"
    timer = units / "the-hive-hive-hourly-probe.timer"
    service.write_bytes(b"[Service]\nExecStart=/malicious\n")
    timer.write_bytes(
        b"[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n"
    )
    service.chmod(0o644)
    timer.chmod(0o644)
    identity = {
        "generation": "a" * 40,
        "manifest_digest": "sha256:" + "b" * 64,
        "consumer_pin": True,
    }
    monkeypatch.setattr(runtime_lifecycle, "_runtime_identity", lambda _root: identity)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_attested_hourly_unit_bytes",
        lambda **_kwargs: (
            b"[Service]\nExecStart=/attested\n",
            b"[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n",
        ),
    )

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_postinstall_invalid",
    ):
        runtime_lifecycle._bind_post_install(home)


def test_failed_cutover_restores_bound_state_and_reports_rollback_failure(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _lifecycle_state(home)
    snapshot = object()
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_cutover_inputs", lambda _home: snapshot
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_systemd_states", lambda received, _systemctl: received
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_revalidate_cutover_inputs", lambda _snapshot: None
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_install_attested_runtime", lambda _home: None
    )
    _allow_postinstall_attestation(monkeypatch)
    monkeypatch.setattr(runtime_lifecycle, "_legacy_requires_migration", lambda _bound: False)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_systemctl_mutate",
        lambda _systemctl, _arguments: (_ for _ in ()).throw(
            runtime_lifecycle.RuntimeLifecycleError("runtime_lifecycle_systemd_failed")
        ),
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_restore_bound_state", lambda _snapshot, _systemctl: False
    )
    published: list[object] = []
    monkeypatch.setattr(
        runtime_lifecycle,
        "_publish_rollback_failure",
        lambda received: published.append(received) or True,
    )

    result = runtime_lifecycle.cutover(home=home, systemctl=lambda _arguments: {})

    assert result == {
        "status": "runtime_lifecycle_rollback_failed",
        "raw_output": "not_returned",
    }
    assert published == [snapshot]


def test_rollback_alarm_publication_failure_is_never_silently_swallowed(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _lifecycle_state(home)
    snapshot = object()
    monkeypatch.setattr(runtime_lifecycle, "_bind_cutover_inputs", lambda _home: snapshot)
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_systemd_states", lambda received, _systemctl: received
    )
    monkeypatch.setattr(runtime_lifecycle, "verify", lambda **_kwargs: {"status": "runtime_lifecycle_red"})
    monkeypatch.setattr(runtime_lifecycle, "_revalidate_cutover_inputs", lambda _bound: None)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_install_attested_runtime",
        lambda _home: (_ for _ in ()).throw(
            runtime_lifecycle.RuntimeLifecycleError("runtime_lifecycle_install_failed")
        ),
    )
    monkeypatch.setattr(runtime_lifecycle, "_restore_bound_state", lambda *_args: False)
    monkeypatch.setattr(runtime_lifecycle, "_publish_rollback_failure", lambda _bound: False)

    result = runtime_lifecycle.cutover(home=home, systemctl=lambda _arguments: {})

    assert result == {
        "status": "runtime_lifecycle_rollback_alarm_failed",
        "raw_output": "not_returned",
    }


def test_restore_bound_state_restores_preexisting_runtime_pointer_units_and_receipt(
    tmp_path: Path,
) -> None:
    """A failed migration returns every preexisting private object byte-for-byte."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    release = home / ".local" / "lib" / "the-hive-runtime"
    units = home / ".config" / "systemd" / "user"
    state = home / ".local" / "state" / "codex-master-mcp"
    launcher = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    for directory in (
        home / ".local",
        home / ".local" / "lib",
        release,
        home / ".config",
        home / ".config" / "systemd",
        units,
        home / ".local" / "state",
        state,
        home / ".local" / "libexec",
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    originals = {
        release / ".the-hive-release-pointers.json": (b'{"old":true}\n', 0o644),
        release / "the-hive-mcp": (b"old-mcp\n", 0o755),
        launcher: (b"old-launcher\n", 0o755),
        state / "runtime-lifecycle-probe-observation.json": (b'{"old":true}\n', 0o600),
        units / "the-hive-hive-hourly-probe.service": (b"old-new-service\n", 0o644),
        units / "the-hive-hive-hourly-probe.timer": (b"old-new-timer\n", 0o644),
        units / "codex-master-hive-hourly-probe.service": (b"old-legacy-service\n", 0o644),
        units / "codex-master-hive-hourly-probe.timer": (b"old-legacy-timer\n", 0o644),
    }
    for path, (content, mode) in originals.items():
        path.write_bytes(content)
        path.chmod(mode)
    states = {
        "the-hive-hive-hourly-probe.service": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        },
        "the-hive-hive-hourly-probe.timer": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        },
        "codex-master-hive-hourly-probe.service": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "active",
        },
        "codex-master-hive-hourly-probe.timer": {
            "LoadState": "loaded",
            "UnitFileState": "enabled",
            "ActiveState": "active",
        },
    }
    bound = runtime_lifecycle._BoundCutover(
        home=home,
        release_root=release,
        units=units,
        state_root=state,
        files=tuple((path, content, mode) for path, (content, mode) in originals.items()),
        source_digests=(),
        source_commit="a" * 40,
        generations_before=frozenset({"a" * 40}),
        legacy_present=True,
        states=tuple(states.items()),
    )
    for path, (_content, mode) in originals.items():
        path.write_bytes(b"new-state\n")
        path.chmod(mode)
    mutated = {path: _identity(path) for path in originals}
    calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    assert runtime_lifecycle._restore_bound_state(bound, systemctl) is True
    assert {path: path.read_bytes() for path in originals} == {
        path: content for path, (content, _mode) in originals.items()
    }
    restored = {path: _identity(path) for path in originals}
    for path, (content, mode) in originals.items():
        device, inode, owner, restored_mode, nlink, bytes_value = restored[path]
        assert device == mutated[path][0]
        assert inode != mutated[path][1]
        assert owner == mutated[path][2]
        assert restored_mode == mode
        assert nlink == 1
        assert bytes_value == content
    assert ("daemon-reload",) in calls
    assert ("disable", "--now", "the-hive-hive-hourly-probe.timer") in calls
    assert ("start", "codex-master-hive-hourly-probe.service") in calls
    assert ("enable", "--now", "codex-master-hive-hourly-probe.timer") in calls


def test_restore_bound_state_removes_new_runtime_units_pointer_and_receipt(
    tmp_path: Path,
) -> None:
    """A first-cutover failure also restores the fully absent pre-cutover state."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    release = home / ".local" / "lib" / "the-hive-runtime"
    units = home / ".config" / "systemd" / "user"
    state = home / ".local" / "state" / "codex-master-mcp"
    launcher = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    for directory in (
        home / ".local",
        home / ".local" / "lib",
        release,
        home / ".config",
        home / ".config" / "systemd",
        units,
        home / ".local" / "state",
        state,
        home / ".local" / "libexec",
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    paths = (
        release / ".the-hive-release-pointers.json",
        release / "the-hive-mcp",
        launcher,
        state / "runtime-lifecycle-probe-observation.json",
        units / "the-hive-hive-hourly-probe.service",
        units / "the-hive-hive-hourly-probe.timer",
        units / "codex-master-hive-hourly-probe.service",
        units / "codex-master-hive-hourly-probe.timer",
    )
    for path in paths:
        path.write_bytes(b"new-state\n")
        path.chmod(0o600 if path.name.endswith("observation.json") else 0o644)
    bound = runtime_lifecycle._BoundCutover(
        home=home,
        release_root=release,
        units=units,
        state_root=state,
        files=tuple(
            (path, None, 0o600 if path.name.endswith("observation.json") else 0o644)
            for path in paths
        ),
        source_digests=(),
        source_commit="a" * 40,
        generations_before=frozenset({"a" * 40}),
        legacy_present=False,
        states=tuple(
            (
                name,
                    {
                        "LoadState": "not-found",
                        "UnitFileState": "disabled",
                        "ActiveState": "inactive",
                    },
            )
            for name in (
                "the-hive-hive-hourly-probe.service",
                "the-hive-hive-hourly-probe.timer",
                "codex-master-hive-hourly-probe.service",
                "codex-master-hive-hourly-probe.timer",
            )
        ),
    )

    assert (
        runtime_lifecycle._restore_bound_state(
            bound,
            lambda arguments: (
                {
                    "LoadState": "not-found",
                    "UnitFileState": "disabled",
                    "ActiveState": "inactive",
                }
                if arguments[0] == "show"
                else {}
            ),
        )
        is True
    )
    assert all(not path.exists() for path in paths)


def test_restore_does_not_operate_on_units_bound_as_not_found(tmp_path: Path) -> None:
    bound, _states = _bound_failure_fixture(tmp_path)
    absent = {
        name: {
            "LoadState": "not-found",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        }
        for name in (
            "the-hive-hive-hourly-probe.service",
            "the-hive-hive-hourly-probe.timer",
            "codex-master-hive-hourly-probe.service",
            "codex-master-hive-hourly-probe.timer",
        )
    }
    bound = runtime_lifecycle.replace(bound, states=tuple(absent.items()))
    calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        return absent[arguments[1]] if arguments[0] == "show" else {}

    assert runtime_lifecycle._restore_bound_state(bound, systemctl) is True
    assert calls == [
        ("daemon-reload",),
        *(
            ("show", name, "--property=LoadState,UnitFileState,ActiveState,Result,ExecMainStatus")
            for name in absent
        ),
    ]


def test_cutover_installer_failure_restores_the_bound_preexisting_state(
    tmp_path: Path, monkeypatch
) -> None:
    bound, states = _bound_failure_fixture(tmp_path)
    monkeypatch.setattr(runtime_lifecycle, "_bind_cutover_inputs", lambda _home: bound)
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_systemd_states", lambda received, _systemctl: received
    )
    monkeypatch.setattr(runtime_lifecycle, "_revalidate_cutover_inputs", lambda _bound: None)
    monkeypatch.setattr(
        runtime_lifecycle, "verify", lambda **_kwargs: {"status": "runtime_lifecycle_red"}
    )

    def fail_installer(_home: Path) -> None:
        _mutate_bound_files(bound)
        raise runtime_lifecycle.RuntimeLifecycleError("runtime_lifecycle_install_failed")

    monkeypatch.setattr(runtime_lifecycle, "_install_attested_runtime", fail_installer)
    result = runtime_lifecycle.cutover(
        home=bound.home,
        systemctl=lambda arguments: states[arguments[1]] if arguments[0] == "show" else {},
    )

    assert result["status"] == "runtime_lifecycle_install_failed"
    _assert_bound_files_restored(bound)


@pytest.mark.parametrize(
    ("stage", "failing_call"),
    (
        ("before_activation_reload", ("daemon-reload",)),
        ("legacy_service_stop", ("stop", "codex-master-hive-hourly-probe.service")),
        (
            "legacy_timer_disable",
            ("disable", "--now", "codex-master-hive-hourly-probe.timer"),
        ),
        ("new_timer_enable", ("enable", "--now", "the-hive-hive-hourly-probe.timer")),
        ("new_service_start", ("start", "the-hive-hive-hourly-probe.service")),
        ("after_unit_removal_reload", ("daemon-reload",)),
    ),
    ids=(
        "before-activation-reload",
        "legacy-service-stop",
        "legacy-timer-disable",
        "new-timer-enable",
        "new-service-start",
        "after-unit-removal-reload",
    ),
)
def test_cutover_each_user_manager_phase_failure_restores_bound_state(
    tmp_path: Path, monkeypatch, stage: str, failing_call: tuple[str, ...]
) -> None:
    bound, states = _bound_failure_fixture(tmp_path)
    monkeypatch.setattr(runtime_lifecycle, "_bind_cutover_inputs", lambda _home: bound)
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_systemd_states", lambda received, _systemctl: received
    )
    monkeypatch.setattr(runtime_lifecycle, "_revalidate_cutover_inputs", lambda _bound: None)
    monkeypatch.setattr(
        runtime_lifecycle, "verify", lambda **_kwargs: {"status": "runtime_lifecycle_red"}
    )

    def install(_home: Path) -> None:
        for path, _content, mode in bound.files:
            if path.parent != bound.units:
                path.write_bytes(b"installer-mutated\n")
                path.chmod(mode)

    monkeypatch.setattr(runtime_lifecycle, "_install_attested_runtime", install)
    _allow_postinstall_attestation(monkeypatch)
    monkeypatch.setattr(
        runtime_lifecycle, "_observe_argumentless_installed_probe", lambda _home: None
    )
    injected = False
    reloads = 0

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        nonlocal injected, reloads
        if arguments[0] == "show":
            return states[arguments[1]]
        if arguments == ("daemon-reload",):
            reloads += 1
        matches = arguments == failing_call and (
            failing_call != ("daemon-reload",)
            or (stage == "before_activation_reload" and reloads == 1)
            or (stage == "after_unit_removal_reload" and reloads == 2)
        )
        if matches and not injected:
            injected = True
            raise runtime_lifecycle.RuntimeLifecycleError("runtime_lifecycle_systemd_failed")
        return {}

    result = runtime_lifecycle.cutover(home=bound.home, systemctl=systemctl)

    assert injected is True
    assert result["status"] == "runtime_lifecycle_systemd_failed"
    _assert_bound_files_restored(bound)


def test_cutover_bounded_probe_failure_restores_bound_state(tmp_path: Path, monkeypatch) -> None:
    bound, states = _bound_failure_fixture(tmp_path)
    monkeypatch.setattr(runtime_lifecycle, "_bind_cutover_inputs", lambda _home: bound)
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_systemd_states", lambda received, _systemctl: received
    )
    monkeypatch.setattr(runtime_lifecycle, "_revalidate_cutover_inputs", lambda _bound: None)
    monkeypatch.setattr(
        runtime_lifecycle, "verify", lambda **_kwargs: {"status": "runtime_lifecycle_red"}
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_install_attested_runtime",
        lambda _home: _mutate_bound_files(bound),
    )
    _allow_postinstall_attestation(monkeypatch)
    monkeypatch.setattr(runtime_lifecycle, "_legacy_requires_migration", lambda _bound: False)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_observe_argumentless_installed_probe",
        lambda _home: (_ for _ in ()).throw(
            runtime_lifecycle.RuntimeLifecycleError(
                "runtime_lifecycle_probe_observation_failed"
            )
        ),
    )
    result = runtime_lifecycle.cutover(
        home=bound.home,
        systemctl=lambda arguments: states[arguments[1]] if arguments[0] == "show" else {},
    )

    assert result["status"] == "runtime_lifecycle_probe_observation_failed"
    _assert_bound_files_restored(bound)


# D332: pure D320CutoverJournalV1 source-only contract tests.


def _d332_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _d332_blob(kind: str, raw: bytes = b"evidence") -> dict[str, object]:
    return {
        "kind": kind,
        "format": "application/octet-stream",
        "bytes_b64": base64.b64encode(raw).decode("ascii"),
        "sha256": _d332_digest(raw),
        "size": len(raw),
    }


def _d332_snapshot(
    name: str, raw: bytes | None = None, *, present: bool = True
) -> dict[str, object]:
    if not present:
        return {
            "name": name,
            "path": f"/precutover/{name}",
            "present": False,
            "bytes_b64": None,
            "sha256": None,
            "dev": None,
            "ino": None,
            "uid": None,
            "gid": None,
            "mode": None,
            "nlink": None,
            "size": None,
        }
    assert raw is not None
    return {
        "name": name,
        "path": f"/precutover/{name}",
        "present": True,
        "bytes_b64": base64.b64encode(raw).decode("ascii"),
        "sha256": _d332_digest(raw),
        "dev": 1,
        "ino": 2,
        "uid": 3,
        "gid": 4,
        "mode": 0o644,
        "nlink": 1,
        "size": len(raw),
    }


def _d332_step(
    *,
    index: int = 0,
    status: str = "VERIFIED",
    inverse: bool = True,
) -> dict[str, object]:
    preconditions = _d332_blob("preconditions")
    verified = status in {"VERIFIED", "INVERSE_INTENT", "INVERSE_VERIFIED"}
    started = status in {
        "EFFECT_STARTED",
        "VERIFIED",
        "INVERSE_INTENT",
        "INVERSE_VERIFIED",
    }
    inverse_phase = status in {"INVERSE_INTENT", "INVERSE_VERIFIED"}
    return {
        "index": index,
        "operation": f"operation-{index}",
        "status": status,
        "preconditions": preconditions,
        "intent_unix_ms": 11,
        "effect_started_unix_ms": 12 if started else None,
        "effect_ended_unix_ms": 13 if verified else None,
        "readback": _d332_blob("readback") if verified else None,
        "file_fsync": True if verified else None,
        "parent_fsync": True if verified else None,
        "adapter_receipt": _d332_blob("receipt") if verified else None,
        "inverse": _d332_blob("inverse") if inverse or inverse_phase else None,
    }


def _d332_history(state: str) -> list[dict[str, object]]:
    states = (
        "PREFLIGHTED",
        "ROOT_ABI_VERIFIED",
        "NATIVE_PREPARED_DISABLED",
        "NATIVE_TRUST_VERIFIED_DISABLED",
        "NATIVE_COMMITTED_DISABLED",
        "USER_CUTOVER_IN_PROGRESS",
        "USER_CUTOVER_VERIFIED",
    )
    previous = "ABSENT"
    history: list[dict[str, object]] = []
    for sequence, current in enumerate(states, start=1):
        history.append(
            {
                "sequence": sequence,
                "from": previous,
                "to": current,
                "at_unix_ms": 100 + sequence,
                "reason_code": "transition",
            }
        )
        previous = current
        if current == state:
            return history
    raise AssertionError(f"unsupported test state: {state}")


def _d333_lock_trace(state: str, sequence: int) -> list[dict[str, object]]:
    if state == "ABSENT":
        return []
    trace: list[dict[str, object]] = [
        {
            "event": "ACQUIRE",
            "lock": "D324-Journallock",
            "state": "PREFLIGHTED",
            "sequence": 1,
        }
    ]
    if state in {"ROLLED_BACK", "BLOCKED", "LIVE_GRANTED"}:
        trace.append(
            {
                "event": "RELEASE",
                "lock": "D324-Journallock",
                "state": state,
                "sequence": sequence,
            }
        )
    return trace


def _d332_payload(
    *,
    state: str = "ABSENT",
    sequence: int = 0,
    recovery_count: int = 0,
    steps: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    snapshots = {
        name: _d332_snapshot(
            name,
            None if name == "legacy_launcher" else f"old-{name}".encode("ascii"),
            present=name != "legacy_launcher",
        )
        for name in (
            "pointer",
            "mcp_launcher",
            "user_launcher",
            "legacy_launcher",
            "service",
            "timer",
            "config_binding",
        )
    }
    postcutover = {
        name: _d332_snapshot(name, f"new-{name}".encode("ascii"), present=True)
        for name in (
            "pointer",
            "mcp_launcher",
            "user_launcher",
            "legacy_launcher",
            "service",
            "timer",
            "config_binding",
        )
    }
    history = [] if state == "ABSENT" else _d332_history(state)
    return {
        "schema": "D320CutoverJournalV1",
        "journal_id": "journal-1",
        "sequence": sequence,
        "state": state,
        "controller": "controller-1",
        "created_unix_ms": 100,
        "updated_unix_ms": 100 + sequence,
        "recovery_count": recovery_count,
        "source": {
            "commit": "a" * 40,
            "tree": "b" * 40,
            "plan_sha256": "c" * 64,
            "decision_sha256": "d" * 64,
            "generation": "generation-1",
        },
        "digests": {
            "runtime_manifest_sha256": "e" * 64,
            "descriptor_sha256": "f" * 64,
            "root_install_plan_sha256": "1" * 64,
            "dispatch_allowlist_sha256": "2" * 64,
            "hooks": {
                "native_bee_event": "3" * 64,
                "native_spawn_admission": "4" * 64,
            },
        },
        "abi": {
            "version": 1,
            "expected_mode": 0o755,
            "root_receipt": {
                "dev": 1,
                "ino": 2,
                "uid": 0,
                "gid": 0,
                "mode": 0o755,
                "nlink": 1,
                "size": 3,
                "sha256": "5" * 64,
                "parent_chain": [
                    {
                        "path": "/usr",
                        "dev": 1,
                        "ino": 2,
                        "uid": 0,
                        "gid": 0,
                        "mode": 0o755,
                        "nlink": 2,
                    }
                ],
                "file_fsync": True,
                "parent_fsync": True,
            },
        },
        "native": {
            "marketplace": _d332_blob("marketplace"),
            "plugin": _d332_blob("plugin"),
            "cache": _d332_blob("cache"),
            "hook_definition": _d332_blob("hook_definition"),
            "trust": _d332_blob("trust"),
            "adapter_version": "adapter-1",
            "request_id": "request-1",
            "receipt_sha256": "6" * 64,
            "disabled": True,
            "inverse": _d332_blob("native_inverse"),
        },
        "precutover": {**snapshots, "unit_status": _d332_blob("unit_status")},
        "postcutover": {
            **postcutover,
            "unit_status": _d332_blob("unit_status", b"new-unit-status"),
        },
        "pins": {"current": ["generation-1"], "previous": [], "retained": []},
        "history": history,
        "steps": [] if steps is None else steps,
        "lock_trace": _d333_lock_trace(state, sequence),
    }


def _d332_new_snapshots(
    payload: dict[str, object],
) -> dict[str, object]:
    postcutover = payload["postcutover"]
    assert isinstance(postcutover, dict)
    result: dict[str, object] = {}
    for name in (
        "pointer",
        "mcp_launcher",
        "user_launcher",
        "legacy_launcher",
        "service",
        "timer",
        "config_binding",
    ):
        result[name] = runtime_lifecycle.ByteSnapshotV1.from_mapping(
            postcutover[name]
        )
    result["unit_status"] = runtime_lifecycle.EvidenceBlobV1.from_mapping(
        postcutover["unit_status"]
    )
    return result


def _d332_old_snapshots(
    payload: dict[str, object],
) -> dict[str, object]:
    precutover = payload["precutover"]
    assert isinstance(precutover, dict)
    result: dict[str, object] = {
        name: runtime_lifecycle.ByteSnapshotV1.from_mapping(precutover[name])
        for name in (
            "pointer",
            "mcp_launcher",
            "user_launcher",
            "legacy_launcher",
            "service",
            "timer",
            "config_binding",
        )
    }
    result["unit_status"] = runtime_lifecycle.EvidenceBlobV1.from_mapping(
        precutover["unit_status"]
    )
    return result


def test_d332_evidence_blob_and_snapshot_are_purely_validated() -> None:
    blob = _d332_blob("blob", b"bytes")
    snapshot = _d332_snapshot("pointer", b"pointer")

    assert runtime_lifecycle.EvidenceBlobV1.from_mapping(blob).to_mapping() == blob
    assert (
        runtime_lifecycle.ByteSnapshotV1.from_mapping(snapshot).to_mapping()
        == snapshot
    )

    malformed = copy.deepcopy(blob)
    malformed["bytes_b64"] = "not-base64"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.EvidenceBlobV1.from_mapping(malformed)

    absent = _d332_snapshot("legacy_launcher", present=False)
    assert runtime_lifecycle.ByteSnapshotV1.from_mapping(absent).present is False
    absent["size"] = 0
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.ByteSnapshotV1.from_mapping(absent)


def test_d332_transition_and_step_require_exact_phase_data() -> None:
    transition = {
        "sequence": 1,
        "from": "ABSENT",
        "to": "PREFLIGHTED",
        "at_unix_ms": 101,
        "reason_code": "preflight",
    }
    assert (
        runtime_lifecycle.TransitionV1.from_mapping(transition).to_mapping()
        == transition
    )

    verified = _d332_step()
    assert runtime_lifecycle.StepV1.from_mapping(verified).to_mapping() == verified

    partial = _d332_step(status="EFFECT_STARTED")
    partial["effect_ended_unix_ms"] = 13
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.StepV1.from_mapping(partial)

    inverse_intent = _d332_step(status="INVERSE_INTENT", inverse=True)
    assert (
        runtime_lifecycle.StepV1.from_mapping(inverse_intent).status
        == "INVERSE_INTENT"
    )


def test_d332_journal_emits_exact_canonical_envelope_and_round_trips() -> None:
    payload = _d332_payload()
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    raw = journal.to_bytes()

    assert raw.endswith(b"\n")
    assert raw.count(b"\n") == 1
    assert raw == (
        b'{"content_sha256":"'
        + hashlib.sha256(journal.payload_bytes).hexdigest().encode("ascii")
        + b'","payload":'
        + journal.payload_bytes
        + b"}\n"
    )
    assert runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw).payload == payload


@pytest.mark.parametrize(
    "mutation",
    (
        lambda payload: payload.__setitem__("unknown", None),
        lambda payload: payload.__setitem__("sequence", True),
        lambda payload: payload.__setitem__("sequence", 1.5),
        lambda payload: payload["precutover"]["pointer"].__setitem__(
            "path", "/not/nfc-e\u0301"
        ),
    ),
)
def test_d332_journal_rejects_unknown_noncanonical_and_noninteger_payloads(
    mutation,
) -> None:
    payload = _d332_payload()
    mutation(payload)

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)


def test_d332_journal_rejects_duplicate_digest_and_size_violations() -> None:
    payload = _d332_payload()
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    duplicate = (
        b'{"content_sha256":"'
        + hashlib.sha256(journal.payload_bytes).hexdigest().encode("ascii")
        + b'","content_sha256":"'
        + hashlib.sha256(journal.payload_bytes).hexdigest().encode("ascii")
        + b'","payload":'
        + journal.payload_bytes
        + b"}\n"
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(duplicate)

    tampered = bytearray(journal.to_bytes())
    tampered[-2] = ord(" ")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(bytes(tampered))

    oversized = b"x" * (4_194_304 + 1)
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(oversized)

    aggregate = _d332_payload()
    huge = b"x" * 1_048_576
    for name in ("marketplace", "plugin", "cache", "hook_definition"):
        aggregate["native"][name] = _d332_blob(name, huge)
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(aggregate)


def test_d332_history_graph_sequence_and_recovery_counter_are_monotone() -> None:
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())

    successor_payload = _d332_payload(state="PREFLIGHTED", sequence=1)
    successor_payload["updated_unix_ms"] = 101
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(successor_payload)
    runtime_lifecycle.validate_d320_journal_successor(previous, successor)

    wrong_sequence = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload(state="PREFLIGHTED", sequence=2)
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(previous, wrong_sequence)

    recovery = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload(sequence=1, recovery_count=1)
    )
    runtime_lifecycle.validate_d320_journal_successor(
        previous, recovery, recovery_entry=True
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(previous, recovery)


def test_d332_lock_order_rejects_inversions_and_multiple_instances() -> None:
    trace = _d333_complete_lock_trace()
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    runtime_lifecycle.validate_d324_lock_order(
        trace, state="ROLLED_BACK", sequence=3, history=history
    )

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            list(reversed(trace)), state="ROLLED_BACK", sequence=3, history=history
        )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            trace + [trace[-1]], state="ROLLED_BACK", sequence=3, history=history
        )


def test_d337_public_primitive_boundaries_reject_overridable_subtypes() -> None:
    class ExplodingText(str):
        def encode(self, *args: object, **kwargs: object) -> bytes:
            raise RuntimeError("unexpected text encode")

    class ExplodingInteger(int):
        def __lt__(self, other: object) -> bool:
            raise RuntimeError("unexpected integer comparison")

    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError, match="d320_text_invalid"
    ):
        runtime_lifecycle.validate_d324_lock_order(
            [], state=ExplodingText("ABSENT"), sequence=0, history=[]
        )
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError, match="d320_integer_required"
    ):
        runtime_lifecycle.validate_d324_lock_order(
            [], state="ABSENT", sequence=ExplodingInteger(0), history=[]
        )


def test_d337_successor_revalidates_carriers_and_exact_recovery_entry() -> None:
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())
    successor_payload = _d332_payload(state="PREFLIGHTED", sequence=1)
    successor_payload["updated_unix_ms"] = 101
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(successor_payload)

    class ExplodingJournal(runtime_lifecycle.D320CutoverJournalV1):
        def to_bytes(self) -> bytes:
            raise RuntimeError("unexpected journal serialization")

    class ExplodingRecoveryEntry:
        def __bool__(self) -> bool:
            raise RuntimeError("unexpected recovery truthiness")

    runtime_lifecycle.validate_d320_journal_successor(
        ExplodingJournal(previous.payload_bytes), successor
    )
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_recovery_entry_invalid",
    ):
        runtime_lifecycle.validate_d320_journal_successor(
            previous, successor, recovery_entry=ExplodingRecoveryEntry()  # type: ignore[arg-type]
        )


def test_d338_journal_factories_reject_subclass_dispatch() -> None:
    payload = _d332_payload()
    expected = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)

    class ExplodingJournal(runtime_lifecycle.D320CutoverJournalV1):
        def to_bytes(self) -> bytes:
            raise RuntimeError("unexpected journal serialization")

    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_journal_factory_type_invalid",
    ):
        ExplodingJournal.from_payload(payload)
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_journal_factory_type_invalid",
    ):
        ExplodingJournal.from_bytes(expected.to_bytes())

    assert runtime_lifecycle.D320CutoverJournalV1.from_payload(payload).to_bytes() == (
        expected.to_bytes()
    )
    assert runtime_lifecycle.D320CutoverJournalV1.from_bytes(
        expected.to_bytes()
    ).payload_bytes == expected.payload_bytes


def test_d338_carrier_base_views_ignore_subclass_accessor_overrides() -> None:
    evidence_mapping = _d332_blob("evidence")
    snapshot_mapping = _d332_snapshot("pointer", b"pointer")
    transition_mapping = {
        "sequence": 1,
        "from": "ABSENT",
        "to": "PREFLIGHTED",
        "at_unix_ms": 1,
        "reason_code": "preflight",
    }
    step_mapping = _d332_step(status="INTENT", inverse=False)
    journal_mapping = _d332_payload()

    class ExplodingEvidence(runtime_lifecycle.EvidenceBlobV1):
        def to_mapping(self) -> dict[str, object]:
            raise RuntimeError("unexpected evidence mapping")

    class ExplodingSnapshot(runtime_lifecycle.ByteSnapshotV1):
        def to_mapping(self) -> dict[str, object]:
            raise RuntimeError("unexpected snapshot mapping")

    class ExplodingTransition(runtime_lifecycle.TransitionV1):
        def to_mapping(self) -> dict[str, object]:
            raise RuntimeError("unexpected transition mapping")

    class ExplodingStep(runtime_lifecycle.StepV1):
        def to_mapping(self) -> dict[str, object]:
            raise RuntimeError("unexpected step mapping")

    class ExplodingJournal(runtime_lifecycle.D320CutoverJournalV1):
        @property
        def payload(self) -> dict[str, object]:
            raise RuntimeError("unexpected journal payload")

    evidence = ExplodingEvidence(
        runtime_lifecycle._d320_canonical_json(evidence_mapping)
    )
    snapshot = ExplodingSnapshot(
        runtime_lifecycle._d320_canonical_json(snapshot_mapping)
    )
    transition = ExplodingTransition(
        runtime_lifecycle._d320_canonical_json(transition_mapping)
    )
    step = ExplodingStep(runtime_lifecycle._d320_canonical_json(step_mapping))
    expected_journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        journal_mapping
    )
    journal = ExplodingJournal(expected_journal.payload_bytes)

    assert runtime_lifecycle.EvidenceBlobV1.to_mapping(evidence) == evidence_mapping
    assert snapshot.present is True
    assert runtime_lifecycle.ByteSnapshotV1.to_mapping(snapshot) == snapshot_mapping
    assert runtime_lifecycle.TransitionV1.to_mapping(transition) == transition_mapping
    assert (step.status, step.index, step.has_inverse) == ("INTENT", 0, False)
    assert runtime_lifecycle.StepV1.to_mapping(step) == step_mapping
    assert journal.payload_bytes == expected_journal.payload_bytes
    assert journal.to_bytes() == expected_journal.to_bytes()
    assert (
        runtime_lifecycle.D320CutoverJournalV1.payload.fget(journal)
        == journal_mapping
    )


@pytest.mark.parametrize(
    ("carrier", "mapping"),
    (
        (runtime_lifecycle.EvidenceBlobV1, _d332_blob("wrapper-evidence")),
        (
            runtime_lifecycle.ByteSnapshotV1,
            _d332_snapshot("pointer", b"wrapper-snapshot"),
        ),
        (
            runtime_lifecycle.TransitionV1,
            {
                "sequence": 1,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "preflight",
            },
        ),
        (
            runtime_lifecycle.StepV1,
            _d332_step(status="INTENT", inverse=False),
        ),
    ),
)
@pytest.mark.parametrize("behavior", ("raises", "forges"))
def test_d339_wrapper_factories_reject_subclass_factory_dispatch(
    carrier,
    mapping: dict[str, object],
    behavior: str,
) -> None:
    calls: list[bytes] = []

    def overridden_factory(cls, payload_bytes: bytes) -> object:
        calls.append(payload_bytes)
        if behavior == "raises":
            raise RuntimeError("factory dynamic dispatch")
        return bytes.__new__(cls, b"{}")

    subclass = type(
        f"Exploding{carrier.__name__}",
        (carrier,),
        {"_from_validated": classmethod(overridden_factory)},
    )

    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_wrapper_factory_type_invalid",
    ):
        subclass.from_mapping(mapping)
    assert calls == []


@pytest.mark.parametrize(
    ("carrier", "mapping", "view", "expected"),
    (
        (
            runtime_lifecycle.EvidenceBlobV1,
            _d332_blob("base-evidence"),
            runtime_lifecycle.EvidenceBlobV1.to_mapping,
            _d332_blob("base-evidence"),
        ),
        (
            runtime_lifecycle.ByteSnapshotV1,
            _d332_snapshot("pointer", b"base-snapshot"),
            lambda wrapper: (
                runtime_lifecycle.ByteSnapshotV1.present.fget(wrapper),
                runtime_lifecycle.ByteSnapshotV1.to_mapping(wrapper),
            ),
            (True, _d332_snapshot("pointer", b"base-snapshot")),
        ),
        (
            runtime_lifecycle.TransitionV1,
            {
                "sequence": 1,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "preflight",
            },
            runtime_lifecycle.TransitionV1.to_mapping,
            {
                "sequence": 1,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "preflight",
            },
        ),
        (
            runtime_lifecycle.StepV1,
            _d332_step(status="INTENT", inverse=False),
            lambda wrapper: (
                runtime_lifecycle.StepV1.status.fget(wrapper),
                runtime_lifecycle.StepV1.index.fget(wrapper),
                runtime_lifecycle.StepV1.has_inverse.fget(wrapper),
                runtime_lifecycle.StepV1.to_mapping(wrapper),
            ),
            ("INTENT", 0, False, _d332_step(status="INTENT", inverse=False)),
        ),
    ),
)
def test_d339_wrapper_base_factories_emit_revalidated_canonical_carriers(
    carrier,
    mapping: dict[str, object],
    view,
    expected: object,
) -> None:
    wrapper = carrier.from_mapping(mapping)

    assert type(wrapper) is carrier
    assert bytes(wrapper) == runtime_lifecycle._d320_canonical_json(mapping)
    assert view(wrapper) == expected


def test_d340_recovery_revalidates_forged_carriers_without_dispatch() -> None:
    payload = _d332_payload_with_history(
        runtime_lifecycle._D320_NORMAL_STATES[1:]
    )
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    observed = _d332_new_snapshots(payload)
    snapshot_mapping = runtime_lifecycle.ByteSnapshotV1.to_mapping(
        observed["pointer"]
    )
    evidence_mapping = runtime_lifecycle.EvidenceBlobV1.to_mapping(
        observed["unit_status"]
    )
    journal_bytes = journal.to_bytes()
    calls = {"snapshot": 0, "evidence": 0, "journal": 0}

    class ForgedSnapshot(runtime_lifecycle.ByteSnapshotV1):
        def to_mapping(self) -> dict[str, object]:
            calls["snapshot"] += 1
            return snapshot_mapping

    class ForgedEvidence(runtime_lifecycle.EvidenceBlobV1):
        def to_mapping(self) -> dict[str, object]:
            calls["evidence"] += 1
            return evidence_mapping

    class ForgedJournal(runtime_lifecycle.D320CutoverJournalV1):
        def to_bytes(self) -> bytes:
            calls["journal"] += 1
            return journal_bytes

    forged_observed: dict[str, object] = {
        name: bytes.__new__(ForgedSnapshot, b"{}")
        for name in runtime_lifecycle._D320_SNAPSHOT_NAMES
    }
    forged_observed["unit_status"] = bytes.__new__(ForgedEvidence, b"{}")

    classification = runtime_lifecycle.classify_d320_recovery(
        journal, observed=forged_observed
    )
    assert (classification.kind, classification.state) == (
        "UNREADABLE_BLOCKED",
        "BLOCKED",
    )
    assert calls == {"snapshot": 0, "evidence": 0, "journal": 0}

    classification = runtime_lifecycle.classify_d320_recovery(
        bytes.__new__(ForgedJournal, b"{}"), observed=observed
    )
    assert (classification.kind, classification.state) == (
        "UNREADABLE_BLOCKED",
        "BLOCKED",
    )
    assert calls == {"snapshot": 0, "evidence": 0, "journal": 0}

    previous_payload = _d334_normal_payload("PREFLIGHTED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        previous_payload
    )
    blocked = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(previous_payload, reason="unreadable")
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            blocked,
            observed={
                **_d332_old_snapshots(previous_payload),
                "pointer": bytes.__new__(ForgedSnapshot, b"{}"),
            },
        )
    assert calls == {"snapshot": 0, "evidence": 0, "journal": 0}


def test_d341_d320_byte_entries_ignore_forged_bytes_dispatch() -> None:
    payload = _d334_normal_payload("LIVE_GRANTED")
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    envelope_bytes = journal.to_bytes()
    payload_bytes = journal.payload_bytes
    observed = _d332_new_snapshots(payload)
    assert runtime_lifecycle.classify_d320_recovery(
        journal, observed=observed
    ).kind == "ALL_NEW_VERIFIED"

    calls = {
        "envelope": 0,
        "evidence": 0,
        "snapshot": 0,
        "transition": 0,
        "step": 0,
        "journal": 0,
    }

    class ForgedEnvelope(bytes):
        def __bytes__(self) -> bytes:
            calls["envelope"] += 1
            return envelope_bytes

    forged_envelope = bytes.__new__(ForgedEnvelope, b"{}")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(forged_envelope)
    assert runtime_lifecycle.classify_d320_recovery(
        forged_envelope, observed=observed
    ).kind == "UNREADABLE_BLOCKED"
    restored = runtime_lifecycle.D320CutoverJournalV1.from_bytes(envelope_bytes)
    assert type(restored) is runtime_lifecycle.D320CutoverJournalV1
    assert restored.payload == journal.payload

    constructors = (
        (
            "evidence",
            runtime_lifecycle.EvidenceBlobV1,
            runtime_lifecycle._d320_canonical_json(_d332_blob("r18-evidence")),
        ),
        (
            "snapshot",
            runtime_lifecycle.ByteSnapshotV1,
            runtime_lifecycle._d320_canonical_json(
                _d332_snapshot("pointer", b"r18-snapshot")
            ),
        ),
        (
            "transition",
            runtime_lifecycle.TransitionV1,
            runtime_lifecycle._d320_canonical_json(
                {
                    "sequence": 1,
                    "from": "ABSENT",
                    "to": "PREFLIGHTED",
                    "at_unix_ms": 1,
                    "reason_code": "r18-transition",
                }
            ),
        ),
        (
            "step",
            runtime_lifecycle.StepV1,
            runtime_lifecycle._d320_canonical_json(
                _d332_step(status="INTENT", inverse=False)
            ),
        ),
        (
            "journal",
            runtime_lifecycle.D320CutoverJournalV1,
            payload_bytes,
        ),
    )
    for name, constructor, replacement in constructors:
        class ForgedCarrier(bytes):
            def __bytes__(self) -> bytes:
                calls[name] += 1
                return replacement

        forged = bytes.__new__(ForgedCarrier, b"{}")
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            constructor(forged)
        valid = constructor(replacement)
        assert type(valid) is constructor

    assert calls == {
        "envelope": 0,
        "evidence": 0,
        "snapshot": 0,
        "transition": 0,
        "step": 0,
        "journal": 0,
    }


def test_d340_from_bytes_uses_one_cumulative_traversal_budget(monkeypatch) -> None:
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())
    raw = journal.to_bytes()
    visits: list[tuple[int, int]] = []
    visit = runtime_lifecycle._d320_visit_json_entry

    def instrumented_visit(budget) -> None:
        visit(budget)
        visits.append((id(budget), budget.entries))

    monkeypatch.setattr(runtime_lifecycle, "_d320_visit_json_entry", instrumented_visit)
    runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)
    cumulative_entries = max(entries for _identifier, entries in visits)
    assert {identifier for identifier, _entries in visits} == {visits[0][0]}

    envelope = runtime_lifecycle._d320_parse_json(raw[:-1])
    assert isinstance(envelope, dict)
    payload = envelope["payload"]
    phase_entries: list[int] = []
    for action in (
        lambda budget: runtime_lifecycle._d320_json_value(
            envelope, semantic=False, budget=budget
        ),
        lambda budget: runtime_lifecycle._d320_syntax_json(payload, budget=budget),
        lambda budget: runtime_lifecycle._d320_canonical_json(payload, budget=budget),
        lambda budget: runtime_lifecycle.D320CutoverJournalV1(
            runtime_lifecycle._d320_canonical_json(payload), budget=budget
        ),
    ):
        budget = runtime_lifecycle._D320JsonTraversalBudget()
        action(budget)
        phase_entries.append(budget.entries)

    assert max(phase_entries) < cumulative_entries
    monkeypatch.setattr(
        runtime_lifecycle,
        "_D320_MAX_JSON_ENTRIES",
        cumulative_entries + 1,
    )
    runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)

    monkeypatch.setattr(
        runtime_lifecycle,
        "_D320_MAX_JSON_ENTRIES",
        max(phase_entries) + 1,
    )
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_json_entries_invalid",
    ):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)


def test_d332_recovery_classifies_all_old_and_all_new_without_effects() -> None:
    old_payload = _d332_payload()
    old_journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(old_payload)
    old = _d332_old_snapshots(old_payload)

    all_old = runtime_lifecycle.classify_d320_recovery(old_journal, observed=old)
    assert (all_old.kind, all_old.state, all_old.inverse_step_indexes) == (
        "ALL_OLD_VERIFIED",
        "ROLLED_BACK",
        (),
    )

    new_payload = _d332_payload(
        state="USER_CUTOVER_VERIFIED",
        sequence=7,
        steps=[_d332_step()],
    )
    new_journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(new_payload)
    all_new = runtime_lifecycle.classify_d320_recovery(
        new_journal,
        observed=_d332_new_snapshots(new_payload),
    )
    assert (all_new.kind, all_new.state, all_new.inverse_step_indexes) == (
        "ALL_NEW_VERIFIED",
        "USER_CUTOVER_VERIFIED",
        (),
    )


def test_d332_recovery_classifies_mixed_and_all_block_classes() -> None:
    payload = _d332_payload(
        state="USER_CUTOVER_VERIFIED",
        sequence=7,
        steps=[_d332_step(index=0, inverse=True), _d332_step(index=1, inverse=True)],
    )
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    old = _d332_old_snapshots(payload)
    new = _d332_new_snapshots(payload)
    mixed = dict(old)
    mixed["pointer"] = new["pointer"]

    invertible = runtime_lifecycle.classify_d320_recovery(journal, observed=mixed)
    assert (invertible.kind, invertible.state, invertible.inverse_step_indexes) == (
        "MIXED_INVERTIBLE",
        "ABORTING",
        (1, 0),
    )

    noninvertible_payload = copy.deepcopy(payload)
    noninvertible_payload["steps"][1]["inverse"] = None
    noninvertible = runtime_lifecycle.classify_d320_recovery(
        runtime_lifecycle.D320CutoverJournalV1.from_payload(noninvertible_payload),
        observed=mixed,
    )
    assert noninvertible.kind == "NONINVERTIBLE_BLOCKED"
    assert noninvertible.state == "BLOCKED"

    unknown = dict(mixed)
    unknown["pointer"] = runtime_lifecycle.ByteSnapshotV1.from_mapping(
        _d332_snapshot("pointer", b"neither-old-nor-new")
    )
    blocked = runtime_lifecycle.classify_d320_recovery(journal, observed=unknown)
    assert blocked.kind == "MIXED_BLOCKED"
    assert blocked.state == "BLOCKED"

    unreadable = runtime_lifecycle.classify_d320_recovery(
        b"not-a-journal\n", observed=mixed
    )
    assert (unreadable.kind, unreadable.state) == ("UNREADABLE_BLOCKED", "BLOCKED")


@pytest.mark.parametrize(
    ("status", "expected"),
    (
        ("INTENT", ("NONINVERTIBLE_BLOCKED", "BLOCKED", ())),
        ("EFFECT_STARTED", ("NONINVERTIBLE_BLOCKED", "BLOCKED", ())),
        ("VERIFIED", ("MIXED_INVERTIBLE", "ABORTING", (0,))),
        ("INVERSE_INTENT", ("NONINVERTIBLE_BLOCKED", "BLOCKED", ())),
        ("INVERSE_VERIFIED", ("NONINVERTIBLE_BLOCKED", "BLOCKED", ())),
    ),
)
def test_d332_hard_abort_at_every_modeled_commitpoint_is_pure(
    status: str, expected: tuple[str, str, tuple[int, ...]]
) -> None:
    payload = (
        _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
        if status in {"INVERSE_INTENT", "INVERSE_VERIFIED"}
        else _d332_payload(
            state="USER_CUTOVER_IN_PROGRESS",
            sequence=6,
        )
    )
    payload["steps"] = [_d332_step(status=status, inverse=True)]
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    old = _d332_old_snapshots(payload)
    new = _d332_new_snapshots(payload)
    observed = dict(old)
    observed["pointer"] = new["pointer"]

    result = runtime_lifecycle.classify_d320_recovery(journal, observed=observed)

    assert (result.kind, result.state, result.inverse_step_indexes) == expected


def test_d332_model_never_calls_existing_mutators(monkeypatch) -> None:
    payload = _d332_payload()
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    old = _d332_old_snapshots(payload)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("mutator reached")

    for name in (
        "cutover",
        "_install_attested_runtime",
        "_systemctl_mutate",
        "_restore_bound_state",
        "_discard_new_generation",
        "_write_observation",
        "_publish_rollback_failure",
        "_atomic_restore",
        "_remove_legacy_hourly_units",
        "_revalidate_legacy_units",
        "_lifecycle_lock",
        "_private_directory",
        "_systemctl_default",
        "_observe_argumentless_installed_probe",
    ):
        monkeypatch.setattr(runtime_lifecycle, name, forbidden)

    assert (
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(journal.to_bytes())
        == journal
    )
    assert runtime_lifecycle.D320CutoverJournalV1.from_payload(payload) == journal
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload(state="PREFLIGHTED", sequence=1)
    )
    runtime_lifecycle.validate_d320_journal_successor(journal, successor)
    runtime_lifecycle.validate_d324_lock_order(
        payload["lock_trace"], state="ABSENT", sequence=0, history=[]
    )
    assert runtime_lifecycle.classify_d320_recovery(
        journal, observed=old
    ).kind == "ALL_OLD_VERIFIED"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload({"invalid": None})
    assert runtime_lifecycle.classify_d320_recovery(
        b"invalid\n", observed=old
    ).kind == "UNREADABLE_BLOCKED"


@pytest.mark.parametrize(
    "mutation",
    (
        lambda payload: payload["source"].__setitem__("commit", "A" * 40),
        lambda payload: payload["digests"]["hooks"].__setitem__(
            "native_bee_event", "a" * 63
        ),
        lambda payload: payload["abi"].__setitem__("version", 2),
        lambda payload: payload["abi"]["root_receipt"].__setitem__(
            "parent_chain", []
        ),
        lambda payload: payload["native"].__setitem__("disabled", 1),
        lambda payload: payload["native"].__setitem__(
            "adapter_version", "a" * 129
        ),
        lambda payload: payload["precutover"]["pointer"].__setitem__(
            "mode", 0o10000
        ),
        lambda payload: payload["pins"].__setitem__(
            "current", ["generation-1", "generation-1"]
        ),
        lambda payload: payload.__setitem__("steps", [_d332_step(index=1)]),
    ),
)
def test_d332_payload_rejects_invalid_nested_areas_and_bounds(mutation) -> None:
    payload = _d332_payload()
    mutation(payload)

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)


def _d332_history_for_states(states: tuple[str, ...]) -> list[dict[str, object]]:
    previous = "ABSENT"
    result: list[dict[str, object]] = []
    for sequence, state in enumerate(states, start=1):
        result.append(
            {
                "sequence": sequence,
                "from": previous,
                "to": state,
                "at_unix_ms": 100 + sequence,
                "reason_code": "unreadable" if state == "BLOCKED" else "transition",
            }
        )
        previous = state
    return result


def _d333_complete_lock_trace() -> list[dict[str, object]]:
    acquired = [
        {
            "event": "ACQUIRE",
            "lock": lock,
            "state": "PREFLIGHTED",
            "sequence": 1,
        }
        for lock in runtime_lifecycle.D324_LOCK_ORDER
    ]
    released = [
        {
            "event": "RELEASE",
            "lock": lock,
            "state": "ROLLED_BACK",
            "sequence": 3,
        }
        for lock in reversed(runtime_lifecycle.D324_LOCK_ORDER)
    ]
    return acquired + released


def _d332_payload_with_history(states: tuple[str, ...]) -> dict[str, object]:
    payload = _d332_payload(sequence=len(states))
    payload["state"] = states[-1]
    payload["history"] = _d332_history_for_states(states)
    payload["lock_trace"] = _d333_lock_trace(states[-1], len(states))
    if states[-1] in (
        "USER_CUTOVER_VERIFIED",
        "ISOLATED_HOOK_PROBE_VERIFIED",
        "MCP_HANDSHAKE_VERIFIED",
        "LIVE_GRANTED",
    ):
        payload["steps"] = [_d332_step()]
    return payload


def _d334_normal_payload(state: str) -> dict[str, object]:
    if state == "ABSENT":
        return _d332_payload()
    index = runtime_lifecycle._D320_NORMAL_STATES.index(state)
    return _d332_payload_with_history(
        runtime_lifecycle._D320_NORMAL_STATES[1 : index + 1]
    )


def _d334_blocked_successor(
    previous: dict[str, object], *, reason: str
) -> dict[str, object]:
    successor = copy.deepcopy(previous)
    successor["sequence"] = int(previous["sequence"]) + 1
    successor["updated_unix_ms"] = int(previous["updated_unix_ms"]) + 1
    successor["state"] = "BLOCKED"
    history = successor["history"]
    assert isinstance(history, list)
    history.append(
        {
            "sequence": successor["sequence"],
            "from": previous["state"],
            "to": "BLOCKED",
            "at_unix_ms": successor["updated_unix_ms"],
            "reason_code": reason,
        }
    )
    if previous["state"] != "ABSENT":
        trace = successor["lock_trace"]
        assert isinstance(trace, list)
        trace.append(
            {
                "event": "RELEASE",
                "lock": "D324-Journallock",
                "state": "BLOCKED",
                "sequence": successor["sequence"],
            }
        )
    return successor


def test_d332_history_covers_bound_graph_and_rejects_a_gap() -> None:
    normal = (
        "PREFLIGHTED",
        "ROOT_ABI_VERIFIED",
        "NATIVE_PREPARED_DISABLED",
        "NATIVE_TRUST_VERIFIED_DISABLED",
        "NATIVE_COMMITTED_DISABLED",
        "USER_CUTOVER_IN_PROGRESS",
        "USER_CUTOVER_VERIFIED",
        "ISOLATED_HOOK_PROBE_VERIFIED",
        "MCP_HANDSHAKE_VERIFIED",
        "LIVE_GRANTED",
    )
    runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload_with_history(normal)
    )
    runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload_with_history(
            normal[:7] + ("ABORTING", "ROLLED_BACK")
        )
    )
    runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload_with_history(("PREFLIGHTED", "BLOCKED"))
    )

    invalid = _d332_payload_with_history(("ROOT_ABI_VERIFIED",))
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(invalid)


@pytest.mark.parametrize(
    ("before", "after"),
    (
        ("ABSENT", "PREFLIGHTED"),
        ("PREFLIGHTED", "ROOT_ABI_VERIFIED"),
        ("ROOT_ABI_VERIFIED", "NATIVE_PREPARED_DISABLED"),
        ("NATIVE_PREPARED_DISABLED", "NATIVE_TRUST_VERIFIED_DISABLED"),
        ("NATIVE_TRUST_VERIFIED_DISABLED", "NATIVE_COMMITTED_DISABLED"),
        ("NATIVE_COMMITTED_DISABLED", "USER_CUTOVER_IN_PROGRESS"),
        ("USER_CUTOVER_IN_PROGRESS", "USER_CUTOVER_VERIFIED"),
        ("USER_CUTOVER_VERIFIED", "ISOLATED_HOOK_PROBE_VERIFIED"),
        ("ISOLATED_HOOK_PROBE_VERIFIED", "MCP_HANDSHAKE_VERIFIED"),
        ("MCP_HANDSHAKE_VERIFIED", "LIVE_GRANTED"),
        ("PREFLIGHTED", "ABORTING"),
        ("ABORTING", "ROLLED_BACK"),
        ("PREFLIGHTED", "BLOCKED"),
    ),
)
def test_d332_each_bound_transition_is_valid(before: str, after: str) -> None:
    transition = {
        "sequence": 0,
        "from": before,
        "to": after,
        "at_unix_ms": 1,
        "reason_code": "unreadable" if after == "BLOCKED" else "transition",
    }

    assert (
        runtime_lifecycle.TransitionV1.from_mapping(transition).to_mapping()
        == transition
    )


@pytest.mark.parametrize(
    "status",
    ("INTENT", "EFFECT_STARTED", "VERIFIED", "INVERSE_INTENT", "INVERSE_VERIFIED"),
)
def test_d332_each_step_phase_is_individually_validated(status: str) -> None:
    assert runtime_lifecycle.StepV1.from_mapping(
        _d332_step(status=status, inverse=True)
    ).status == status


@pytest.mark.parametrize("index", range(len(_d333_complete_lock_trace())))
def test_d332_each_lock_duplicate_is_rejected(index: int) -> None:
    trace = _d333_complete_lock_trace()
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    trace.insert(index, trace[index])

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            trace, state="ROLLED_BACK", sequence=3, history=history
        )


@pytest.mark.parametrize("index", range(len(runtime_lifecycle.D324_LOCK_ORDER) - 1))
def test_d332_each_adjacent_lock_inversion_is_rejected(index: int) -> None:
    trace = _d333_complete_lock_trace()
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    trace[index], trace[index + 1] = trace[index + 1], trace[index]

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            trace, state="ROLLED_BACK", sequence=3, history=history
        )


def test_d333_postcutover_and_unit_status_are_bound_recovery_inputs() -> None:
    payload = _d332_payload(
        state="USER_CUTOVER_VERIFIED",
        sequence=7,
        steps=[_d332_step()],
    )
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    observed = _d332_new_snapshots(payload)
    assert runtime_lifecycle.classify_d320_recovery(
        journal, observed=observed
    ).kind == "ALL_NEW_VERIFIED"

    unit_drift = dict(observed)
    unit_drift["unit_status"] = runtime_lifecycle.EvidenceBlobV1.from_mapping(
        _d332_blob("unit_status", b"unit-drift")
    )
    assert runtime_lifecycle.classify_d320_recovery(
        journal, observed=unit_drift
    ).kind == "MIXED_BLOCKED"
    missing_unit = dict(observed)
    del missing_unit["unit_status"]
    assert runtime_lifecycle.classify_d320_recovery(
        journal, observed=missing_unit
    ).kind == "UNREADABLE_BLOCKED"

    substituted = copy.deepcopy(payload)
    substituted["postcutover"]["pointer"] = _d332_snapshot(
        "pointer", b"substituted-new"
    )
    assert runtime_lifecycle.classify_d320_recovery(
        runtime_lifecycle.D320CutoverJournalV1.from_payload(substituted),
        observed=observed,
    ).kind == "MIXED_BLOCKED"
    missing_postcutover = copy.deepcopy(payload)
    del missing_postcutover["postcutover"]
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(missing_postcutover)
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(
            _d332_payload(state="USER_CUTOVER_VERIFIED", sequence=7)
        )


@pytest.mark.parametrize(
    "state",
    (
        "USER_CUTOVER_VERIFIED",
        "ISOLATED_HOOK_PROBE_VERIFIED",
        "MCP_HANDSHAKE_VERIFIED",
        "LIVE_GRANTED",
    ),
)
def test_d336_all_new_recovery_stays_verified_after_each_gate(state: str) -> None:
    payload = _d334_normal_payload(state)
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)

    classification = runtime_lifecycle.classify_d320_recovery(
        journal, observed=_d332_new_snapshots(payload)
    )

    assert classification.kind == "ALL_NEW_VERIFIED"
    assert classification.state == "USER_CUTOVER_VERIFIED"
    assert classification.inverse_step_indexes == ()


def test_d333_wrappers_and_exported_paths_revalidate_fail_closed() -> None:
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1(b"{}")
    for wrapper in (
        runtime_lifecycle.ByteSnapshotV1,
        runtime_lifecycle.EvidenceBlobV1,
        runtime_lifecycle.StepV1,
        runtime_lifecycle.TransitionV1,
    ):
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            wrapper({"invalid": None})

    forged = bytes.__new__(runtime_lifecycle.D320CutoverJournalV1, b"{}")
    payload = _d332_payload()
    observed = _d332_old_snapshots(payload)
    assert runtime_lifecycle.classify_d320_recovery(
        forged, observed=observed
    ).kind == "UNREADABLE_BLOCKED"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(forged, forged)

    forged_snapshot = bytes.__new__(runtime_lifecycle.ByteSnapshotV1, b"{}")
    observed_with_forgery = dict(observed)
    observed_with_forgery["pointer"] = forged_snapshot
    assert runtime_lifecycle.classify_d320_recovery(
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload),
        observed=observed_with_forgery,
    ).kind == "UNREADABLE_BLOCKED"

    forged_evidence = bytes.__new__(runtime_lifecycle.EvidenceBlobV1, b"{}")
    forged_step = bytes.__new__(runtime_lifecycle.StepV1, b"{}")
    forged_transition = bytes.__new__(runtime_lifecycle.TransitionV1, b"{}")
    for wrapper in (forged_evidence, forged_step, forged_transition):
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            wrapper.to_mapping()
    observed_with_forged_unit = dict(observed)
    observed_with_forged_unit["unit_status"] = forged_evidence
    assert runtime_lifecycle.classify_d320_recovery(
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload),
        observed=observed_with_forged_unit,
    ).kind == "UNREADABLE_BLOCKED"


@pytest.mark.parametrize("wrapper", ("evidence", "snapshot", "transition", "step"))
def test_d335_mapping_wrappers_are_semantically_immutable(wrapper: str) -> None:
    values: dict[str, tuple[object, str, object, object]] = {
        "evidence": (_d332_blob("blob"), "kind", "before", "after"),
        "snapshot": (
            _d332_snapshot("pointer", b"pointer"),
            "name",
            "before_pointer",
            "after_pointer",
        ),
        "transition": (
            {
                "sequence": 0,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "transition",
            },
            "reason_code",
            "before",
            "after",
        ),
        "step": (_d332_step(status="INTENT"), "operation", "before", "after"),
    }
    factories = {
        "evidence": runtime_lifecycle.EvidenceBlobV1,
        "snapshot": runtime_lifecycle.ByteSnapshotV1,
        "transition": runtime_lifecycle.TransitionV1,
        "step": runtime_lifecycle.StepV1,
    }
    value, field, before, after = values[wrapper]
    assert isinstance(value, dict)
    value[field] = before
    expected = copy.deepcopy(value)
    instance = factories[wrapper].from_mapping(value)

    value[field] = after
    returned = instance.to_mapping()
    returned[field] = "mapping-copy-mutation"

    assert instance.to_mapping() == expected
    assert isinstance(instance, bytes)
    assert not hasattr(instance, "__dict__")


def test_d336_carriers_have_no_writable_truth_slot() -> None:
    journal_payload = _d332_payload()
    carriers: tuple[tuple[type[bytes], object, object], ...] = (
        (
            runtime_lifecycle.EvidenceBlobV1,
            runtime_lifecycle.EvidenceBlobV1.from_mapping(_d332_blob("blob")),
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.ByteSnapshotV1,
            runtime_lifecycle.ByteSnapshotV1.from_mapping(
                _d332_snapshot("pointer", b"pointer")
            ),
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.TransitionV1,
            runtime_lifecycle.TransitionV1.from_mapping(
                {
                    "sequence": 0,
                    "from": "ABSENT",
                    "to": "PREFLIGHTED",
                    "at_unix_ms": 1,
                    "reason_code": "transition",
                }
            ),
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.StepV1,
            runtime_lifecycle.StepV1.from_mapping(_d332_step(status="INTENT")),
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.D320CutoverJournalV1,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(journal_payload),
            lambda carrier: carrier.payload,
        ),
    )
    for carrier_type, carrier, view in carriers:
        assert isinstance(carrier, carrier_type)
        assert isinstance(carrier, bytes)
        assert not hasattr(carrier, "__dict__")
        assert not hasattr(carrier, "_payload_bytes")
        expected = view(carrier)
        with pytest.raises(AttributeError):
            object.__setattr__(carrier, "_payload_bytes", b"{}")
        assert view(carrier) == expected
        with pytest.raises(TypeError):
            object.__new__(carrier_type)
        forged = bytes.__new__(carrier_type, b"{}")
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            view(forged)


def test_d335_public_mapping_inputs_are_bounded_and_cycle_safe() -> None:
    factories = (
        runtime_lifecycle.D320CutoverJournalV1.from_payload,
        runtime_lifecycle.EvidenceBlobV1.from_mapping,
        runtime_lifecycle.ByteSnapshotV1.from_mapping,
        runtime_lifecycle.TransitionV1.from_mapping,
        runtime_lifecycle.StepV1.from_mapping,
    )
    deep: object = []
    for _index in range(2_000):
        deep = [deep]
    cycle_list: list[object] = []
    cycle_list.append(cycle_list)
    cycle_map: dict[str, object] = {}
    cycle_map["self"] = cycle_map
    for invalid in ({"unexpected": deep}, {"unexpected": cycle_list}, cycle_map):
        for factory in factories:
            with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
                factory(invalid)

    node_limited = {
        "unexpected": [
            [] for _index in range(runtime_lifecycle._D320_MAX_CONTAINER_NODES)
        ]
    }
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(node_limited)


def test_d336_public_mapping_entry_budget_consumes_only_the_surplus() -> None:
    class ForeignMapping(Mapping[str, object]):
        def __init__(self, *, finite: bool) -> None:
            self.finite = finite
            self.visited = 0

        def __len__(self) -> int:
            return 1

        def __iter__(self):
            while (
                not self.finite
                or self.visited <= runtime_lifecycle._D320_MAX_JSON_ENTRIES
            ):
                self.visited += 1
                yield f"entry-{self.visited}"

        def __getitem__(self, _key: str) -> object:
            return None

    for finite in (True, False):
        foreign = ForeignMapping(finite=finite)
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            runtime_lifecycle.D320CutoverJournalV1.from_payload(foreign)
        assert foreign.visited == runtime_lifecycle._D320_MAX_JSON_ENTRIES + 1


def test_d336_syntax_digest_precedes_semantic_surrogate_rejection() -> None:
    surrogate_payload = b'{"sequence":"\\ud800"}'
    raw = (
        b'{"content_sha256":"'
        + b"0" * 64
        + b'","payload":'
        + surrogate_payload
        + b"}\n"
    )
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_envelope_digest_invalid",
    ):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)

    valid_payload = runtime_lifecycle._d320_canonical_json(_d332_payload())
    assert (
        runtime_lifecycle._d320_syntax_json(
            runtime_lifecycle._d320_parse_json(valid_payload)
        )
        == valid_payload
    )


def test_d336_recovery_observed_budget_is_shared_across_all_artifacts() -> None:
    class StatefulArtifactMapping(dict[str, object]):
        def __init__(self, value: Mapping[str, object]) -> None:
            super().__init__(value)
            self.first_items_call = True
            self.visited = 0

        def items(self):
            if not self.first_items_call:
                return super().items()
            self.first_items_call = False

            def oversized_items():
                for index in range(runtime_lifecycle._D320_MAX_JSON_ENTRIES):
                    self.visited += 1
                    yield (f"entry-{index}", None)

            return oversized_items()

    payload = _d334_normal_payload("LIVE_GRANTED")
    observed = _d332_new_snapshots(payload)
    stateful_observed = {
        name: StatefulArtifactMapping(value.to_mapping())
        for name, value in observed.items()
    }

    classification = runtime_lifecycle.classify_d320_recovery(
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload),
        observed=stateful_observed,
    )

    assert classification.kind == "UNREADABLE_BLOCKED"
    assert sum(value.visited for value in stateful_observed.values()) == (
        runtime_lifecycle._D320_MAX_JSON_ENTRIES
        - len(runtime_lifecycle._D320_ARTIFACT_NAMES)
        + 1
    )


def test_d336_blocked_successor_normalizes_observed_once_under_one_budget() -> None:
    class StatefulArtifactMapping(dict[str, object]):
        def __init__(self) -> None:
            super().__init__(_d332_snapshot("pointer", b"old-pointer"))
            self.items_calls = 0
            self.visited = 0

        def items(self):
            self.items_calls += 1

            def forty_thousand_items():
                for index in range(40_000):
                    self.visited += 1
                    yield (f"entry-{self.items_calls}-{index}", None)

            return forty_thousand_items()

    previous_payload = _d334_normal_payload("PREFLIGHTED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(previous_payload)
    reference_successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(
            previous_payload, reason="mixed_without_complete_inverse"
        )
    )
    reference_observed = _d332_old_snapshots(previous_payload)
    reference_observed["pointer"] = runtime_lifecycle.ByteSnapshotV1.from_mapping(
        _d332_snapshot("pointer", b"neither-old-nor-new")
    )
    runtime_lifecycle.validate_d320_journal_successor(
        previous, reference_successor, observed=reference_observed
    )

    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(previous_payload, reason="unreadable")
    )

    observed = _d332_old_snapshots(previous_payload)
    stateful = StatefulArtifactMapping()
    observed["pointer"] = stateful
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_json_entries_invalid",
    ):
        runtime_lifecycle.validate_d320_journal_successor(
            previous, successor, observed=observed
        )
    assert stateful.items_calls == 1
    assert stateful.visited == 40_000


def test_d336_envelope_limit_applies_to_factory_and_direct_constructor() -> None:
    payload = _d332_payload(
        state="USER_CUTOVER_VERIFIED",
        sequence=7,
        steps=[_d332_step(index=index) for index in range(256)],
    )
    raw = b"x" * 3_000
    for step in payload["steps"]:
        assert isinstance(step, dict)
        index = int(step["index"])
        for field in ("preconditions", "readback", "adapter_receipt", "inverse"):
            step[field] = _d332_blob(f"{field}-{index}", raw)
    payload_bytes = runtime_lifecycle._d320_canonical_json(payload)
    assert (
        len(payload_bytes) + runtime_lifecycle._D320_ENVELOPE_FIXED_BYTES
        > runtime_lifecycle._D320_MAX_ENVELOPE_BYTES
    )

    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_envelope_too_large",
    ):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_envelope_too_large",
    ):
        runtime_lifecycle.D320CutoverJournalV1(payload_bytes)


def test_d336_forged_list_journal_carrier_fails_closed_at_every_public_view() -> None:
    forged = bytes.__new__(runtime_lifecycle.D320CutoverJournalV1, b"[]")
    valid = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())

    for view in (
        lambda: forged.payload,
        lambda: forged.payload_bytes,
        lambda: forged.to_bytes(),
    ):
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            view()
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(forged, valid)


def test_d335_json_and_foreign_mapping_inputs_fail_closed() -> None:
    payload = b'{"unexpected":' + b"[" * 65 + b"0" + b"]" * 65 + b"}"
    raw = (
        b'{"content_sha256":"'
        + hashlib.sha256(payload).hexdigest().encode("ascii")
        + b'","payload":'
        + payload
        + b"}\n"
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)

    oversized_integer_payload = b'{"value":' + b"9" * 5_000 + b"}"
    oversized_integer_envelope = (
        b'{"content_sha256":"'
        + hashlib.sha256(oversized_integer_payload).hexdigest().encode("ascii")
        + b'","payload":'
        + oversized_integer_payload
        + b"}\n"
    )
    assert len(oversized_integer_envelope) < runtime_lifecycle._D320_MAX_ENVELOPE_BYTES
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(
            oversized_integer_envelope
        )

    class ExplodingMapping(dict):
        def items(self):
            raise RuntimeError("foreign mapping failure")

    for factory in (
        runtime_lifecycle.D320CutoverJournalV1.from_payload,
        runtime_lifecycle.EvidenceBlobV1.from_mapping,
        runtime_lifecycle.ByteSnapshotV1.from_mapping,
        runtime_lifecycle.TransitionV1.from_mapping,
        runtime_lifecycle.StepV1.from_mapping,
    ):
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            factory(ExplodingMapping())

    class ExplodingSequence(Sequence[object]):
        def __len__(self) -> int:
            raise RuntimeError("foreign sequence failure")

        def __getitem__(self, _index: int) -> object:
            raise AssertionError("must not be reached")

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            ExplodingSequence(), state="ABSENT", sequence=0, history=[]
        )


def test_d336_lock_order_normalizes_foreign_mappings_before_validation() -> None:
    class ForeignMapping(Mapping[str, object]):
        def __init__(self, value: Mapping[str, object]) -> None:
            self.value = value
            self.items_calls = 0
            self.iter_calls = 0

        def __getitem__(self, key: str) -> object:
            return self.value[key]

        def __iter__(self):
            self.iter_calls += 1
            return iter(self.value)

        def __len__(self) -> int:
            return len(self.value)

        def items(self):
            self.items_calls += 1
            return self.value.items()

    history = ForeignMapping(
        {
            "sequence": 1,
            "from": "ABSENT",
            "to": "PREFLIGHTED",
            "at_unix_ms": 1,
            "reason_code": "preflight",
        }
    )
    trace = ForeignMapping(
        {
            "event": "ACQUIRE",
            "lock": "D324-Journallock",
            "state": "PREFLIGHTED",
            "sequence": 1,
        }
    )

    runtime_lifecycle.validate_d324_lock_order(
        [trace], state="PREFLIGHTED", sequence=1, history=[history]
    )

    assert (history.items_calls, history.iter_calls) == (1, 0)
    assert (trace.items_calls, trace.iter_calls) == (1, 0)


def test_d336_lock_order_split_truth_mapping_keeps_first_truth() -> None:
    class SplitTruthTransition(Mapping[str, object]):
        first = {
            "sequence": 1,
            "from": "ABSENT",
            "to": "PREFLIGHTED",
            "at_unix_ms": 1,
            "reason_code": "preflight",
        }
        second = {**first, "at_unix_ms": 2, "reason_code": "second"}

        def __init__(self) -> None:
            self.items_calls = 0
            self.iter_calls = 0
            self.getitem_calls = 0

        def __getitem__(self, key: str) -> object:
            self.getitem_calls += 1
            return self.second[key]

        def __iter__(self):
            self.iter_calls += 1
            return iter(self.second)

        def __len__(self) -> int:
            return len(self.first)

        def items(self):
            self.items_calls += 1
            return self.first.items()

    transition = SplitTruthTransition()
    runtime_lifecycle.validate_d324_lock_order(
        [
            {
                "event": "ACQUIRE",
                "lock": "D324-Journallock",
                "state": "PREFLIGHTED",
                "sequence": 1,
            }
        ],
        state="PREFLIGHTED",
        sequence=1,
        history=[transition],
    )

    assert (
        transition.items_calls,
        transition.iter_calls,
        transition.getitem_calls,
    ) == (
        1,
        0,
        0,
    )


def test_d336_lock_order_rejects_sequence_length_iterator_disagreement() -> None:
    class ContradictorySequence(Sequence[object]):
        def __init__(self) -> None:
            self.iter_calls = 0

        def __getitem__(self, _index: int) -> object:
            raise AssertionError("iterator must be used")

        def __iter__(self):
            self.iter_calls += 1
            yield {"unexpected": None}

        def __len__(self) -> int:
            return 0

    history = ContradictorySequence()
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            [], state="ABSENT", sequence=0, history=history
        )
    assert history.iter_calls == 1


@pytest.mark.parametrize(
    ("carrier", "payload_bytes"),
    (
        (
            runtime_lifecycle.EvidenceBlobV1,
            runtime_lifecycle._d320_canonical_json(_d332_blob("evidence")),
        ),
        (
            runtime_lifecycle.ByteSnapshotV1,
            runtime_lifecycle._d320_canonical_json(
                _d332_snapshot("pointer", b"pointer")
            ),
        ),
        (
            runtime_lifecycle.TransitionV1,
            runtime_lifecycle._d320_canonical_json(
                {
                    "sequence": 1,
                    "from": "ABSENT",
                    "to": "PREFLIGHTED",
                    "at_unix_ms": 1,
                    "reason_code": "preflight",
                }
            ),
        ),
        (
            runtime_lifecycle.StepV1,
            runtime_lifecycle._d320_canonical_json(
                _d332_step(status="INTENT", inverse=False)
            ),
        ),
        (
            runtime_lifecycle.D320CutoverJournalV1,
            runtime_lifecycle._d320_canonical_json(_d332_payload()),
        ),
    ),
)
def test_d336_direct_carriers_copy_foreign_bytes_before_parsing(
    carrier,
    payload_bytes: bytes,
) -> None:
    class ExplodingBytes(bytes):
        def decode(self, *_args, **_kwargs):
            raise TypeError("foreign decode must not run")

    assert isinstance(carrier(ExplodingBytes(payload_bytes)), carrier)


def test_d336_journal_from_bytes_copies_foreign_bytes_before_checks() -> None:
    class ExplodingEnvelopeBytes(bytes):
        def endswith(self, *_args, **_kwargs):
            raise RuntimeError("foreign endswith must not run")

        def count(self, *_args, **_kwargs):
            raise RuntimeError("foreign count must not run")

    payload = _d332_payload()
    raw = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload).to_bytes()

    assert runtime_lifecycle.D320CutoverJournalV1.from_bytes(
        ExplodingEnvelopeBytes(raw)
    ).payload == payload


@pytest.mark.parametrize(
    ("factory", "first", "second", "field", "view"),
    (
        (
            runtime_lifecycle.EvidenceBlobV1.from_mapping,
            _d332_blob("first"),
            _d332_blob("second"),
            "kind",
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.ByteSnapshotV1.from_mapping,
            _d332_snapshot("pointer", b"first"),
            _d332_snapshot("pointer", b"second"),
            "sha256",
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.TransitionV1.from_mapping,
            {
                "sequence": 1,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "first",
            },
            {
                "sequence": 1,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "second",
            },
            "reason_code",
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.StepV1.from_mapping,
            {**_d332_step(status="INTENT", inverse=False), "operation": "first"},
            {**_d332_step(status="INTENT", inverse=False), "operation": "second"},
            "operation",
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.D320CutoverJournalV1.from_payload,
            {**_d332_payload(), "journal_id": "first-journal"},
            {**_d332_payload(), "journal_id": "second-journal"},
            "journal_id",
            lambda carrier: carrier.payload,
        ),
    ),
)
def test_d336_mapping_factories_keep_the_first_split_truth(
    factory,
    first: dict[str, object],
    second: dict[str, object],
    field: str,
    view,
) -> None:
    class SplitTruthDict(dict[str, object]):
        def __init__(self) -> None:
            super().__init__(second)
            self.items_calls = 0

        def items(self):
            self.items_calls += 1
            if self.items_calls == 1:
                return first.items()
            return super().items()

    value = SplitTruthDict()
    carrier = factory(value)

    assert view(carrier)[field] == first[field]
    assert value.items_calls == 1


def test_d335_successor_rejects_cyclic_observed_artifact() -> None:
    previous_payload = _d334_normal_payload("PREFLIGHTED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(previous_payload)
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(previous_payload, reason="unreadable")
    )
    observed = _d332_old_snapshots(previous_payload)
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    observed["unit_status"] = cyclic

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous, successor, observed=observed
        )
    assert runtime_lifecycle.classify_d320_recovery(
        previous, observed=observed
    ).kind == "UNREADABLE_BLOCKED"


def test_d333_successor_is_append_only_and_phase_ordered() -> None:
    preflight = _d332_payload(state="PREFLIGHTED", sequence=1)
    intent = copy.deepcopy(preflight)
    intent["sequence"] = 2
    intent["updated_unix_ms"] = 102
    intent["steps"] = [_d332_step(status="INTENT")]
    started = copy.deepcopy(intent)
    started["sequence"] = 3
    started["updated_unix_ms"] = 103
    started["steps"][0] = _d332_step(status="EFFECT_STARTED")
    verified = copy.deepcopy(started)
    verified["sequence"] = 4
    verified["updated_unix_ms"] = 104
    verified["steps"][0] = _d332_step(status="VERIFIED")
    transitioned = copy.deepcopy(verified)
    transitioned["sequence"] = 5
    transitioned["updated_unix_ms"] = 105
    transitioned["state"] = "ROOT_ABI_VERIFIED"
    transitioned["history"].append(
        {
            "sequence": 5,
            "from": "PREFLIGHTED",
            "to": "ROOT_ABI_VERIFIED",
            "at_unix_ms": 105,
            "reason_code": "transition",
        }
    )
    journals = [
        runtime_lifecycle.D320CutoverJournalV1.from_payload(value)
        for value in (preflight, intent, started, verified, transitioned)
    ]
    for previous, successor in zip(journals, journals[1:]):
        runtime_lifecycle.validate_d320_journal_successor(previous, successor)

    skipped = copy.deepcopy(intent)
    skipped["sequence"] = 3
    skipped["updated_unix_ms"] = 103
    skipped["steps"][0] = _d332_step(status="VERIFIED")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            journals[1],
            runtime_lifecycle.D320CutoverJournalV1.from_payload(skipped),
        )
    rewritten = copy.deepcopy(intent)
    rewritten["sequence"] = 3
    rewritten["updated_unix_ms"] = 103
    rewritten["history"][0]["reason_code"] = "rewritten"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            journals[1],
            runtime_lifecycle.D320CutoverJournalV1.from_payload(rewritten),
        )

    premature_next = copy.deepcopy(started)
    premature_next["sequence"] = 4
    premature_next["updated_unix_ms"] = 104
    premature_next["steps"].append(_d332_step(index=1, status="INTENT"))
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            journals[2],
            runtime_lifecycle.D320CutoverJournalV1.from_payload(premature_next),
        )
    simultaneous_transition = copy.deepcopy(started)
    simultaneous_transition["sequence"] = 4
    simultaneous_transition["updated_unix_ms"] = 104
    simultaneous_transition["steps"][0] = _d332_step(status="VERIFIED")
    simultaneous_transition["state"] = "ROOT_ABI_VERIFIED"
    simultaneous_transition["history"].append(
        {
            "sequence": 4,
            "from": "PREFLIGHTED",
            "to": "ROOT_ABI_VERIFIED",
            "at_unix_ms": 104,
            "reason_code": "transition",
        }
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            journals[2],
            runtime_lifecycle.D320CutoverJournalV1.from_payload(
                simultaneous_transition
            ),
        )


@pytest.mark.parametrize(
    ("before_status", "next_status", "skipped_status", "state"),
    (
        ("INTENT", "EFFECT_STARTED", "VERIFIED", "PREFLIGHTED"),
        ("VERIFIED", "INVERSE_INTENT", "INVERSE_VERIFIED", "ABORTING"),
    ),
)
def test_d333_successor_rejects_each_skipped_step_phase(
    before_status: str,
    next_status: str,
    skipped_status: str,
    state: str,
) -> None:
    payload = (
        _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
        if state == "ABORTING"
        else _d332_payload(state=state, sequence=1)
    )
    payload["steps"] = [_d332_step(status=before_status)]
    next_payload = copy.deepcopy(payload)
    next_payload["sequence"] = int(payload["sequence"]) + 1
    next_payload["updated_unix_ms"] = int(payload["updated_unix_ms"]) + 1
    next_payload["steps"][0] = _d332_step(status=next_status)
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    valid_next = runtime_lifecycle.D320CutoverJournalV1.from_payload(next_payload)
    runtime_lifecycle.validate_d320_journal_successor(previous, valid_next)

    skipped = copy.deepcopy(next_payload)
    skipped["steps"][0] = _d332_step(status=skipped_status)

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(skipped),
        )


@pytest.mark.parametrize(
    "field",
    (
        "operation",
        "preconditions",
        "intent_unix_ms",
        "effect_started_unix_ms",
        "inverse",
    ),
)
def test_d334_repair3_successor_preserves_every_persisted_forward_field(
    field: str,
) -> None:
    started = _d332_payload(state="PREFLIGHTED", sequence=1)
    started["steps"] = [_d332_step(status="EFFECT_STARTED")]
    verified = copy.deepcopy(started)
    verified["sequence"] = 2
    verified["updated_unix_ms"] = 102
    verified["steps"][0] = _d332_step(status="VERIFIED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(started)
    valid_successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(verified)
    runtime_lifecycle.validate_d320_journal_successor(previous, valid_successor)

    rewritten = copy.deepcopy(verified)
    replacements: dict[str, object] = {
        "operation": "rewritten-operation",
        "preconditions": _d332_blob("preconditions", b"rewritten"),
        "intent_unix_ms": 20,
        "effect_started_unix_ms": 20,
        "inverse": _d332_blob("inverse", b"rewritten"),
    }
    rewritten["steps"][0][field] = replacements[field]
    if field == "effect_started_unix_ms":
        rewritten["steps"][0]["effect_ended_unix_ms"] = 21

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(rewritten),
        )


def test_d335_index_is_rejected_before_the_successor_validator() -> None:
    started = _d332_payload(state="PREFLIGHTED", sequence=1)
    started["steps"] = [_d332_step(status="EFFECT_STARTED")]
    verified = copy.deepcopy(started)
    verified["sequence"] = 2
    verified["updated_unix_ms"] = 102
    verified["steps"][0] = _d332_step(status="VERIFIED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(started)
    valid_successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(verified)
    runtime_lifecycle.validate_d320_journal_successor(previous, valid_successor)

    invalid_record = copy.deepcopy(verified)
    invalid_record["steps"][0]["index"] = 1
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(invalid_record)


def test_d334_repair3_successor_rejects_cleared_persisted_forward_evidence() -> None:
    started = _d332_payload(state="PREFLIGHTED", sequence=1)
    started["steps"] = [_d332_step(status="EFFECT_STARTED")]
    verified = copy.deepcopy(started)
    verified["sequence"] = 2
    verified["updated_unix_ms"] = 102
    verified["steps"][0] = _d332_step(status="VERIFIED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(started)

    cleared_inverse = copy.deepcopy(verified)
    cleared_inverse["steps"][0]["inverse"] = None
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(cleared_inverse),
        )
    cleared_start = copy.deepcopy(verified)
    cleared_start["steps"][0]["effect_started_unix_ms"] = None
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(cleared_start)


def test_d334_repair3_inverse_phase_preserves_forward_evidence() -> None:
    rollback = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    rollback["steps"] = [_d332_step(status="VERIFIED")]
    inverse_intent = copy.deepcopy(rollback)
    inverse_intent["sequence"] = 3
    inverse_intent["updated_unix_ms"] = 103
    inverse_intent["steps"][0] = _d332_step(status="INVERSE_INTENT")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(rollback)
    valid_successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        inverse_intent
    )
    runtime_lifecycle.validate_d320_journal_successor(previous, valid_successor)

    rewritten = copy.deepcopy(inverse_intent)
    rewritten["steps"][0]["effect_started_unix_ms"] = 20
    rewritten["steps"][0]["effect_ended_unix_ms"] = 21
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(rewritten),
        )


def test_d337_inverse_intent_fills_only_previously_absent_inverse_evidence() -> None:
    rollback = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    rollback["steps"] = [_d332_step(status="VERIFIED", inverse=False)]
    inverse_intent = copy.deepcopy(rollback)
    inverse_intent["sequence"] = 3
    inverse_intent["updated_unix_ms"] = 103
    inverse_intent["steps"][0] = _d332_step(status="INVERSE_INTENT")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(rollback)
    valid_successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        inverse_intent
    )
    runtime_lifecycle.validate_d320_journal_successor(previous, valid_successor)

    rewritten = copy.deepcopy(inverse_intent)
    rewritten["steps"][0]["operation"] = "rewritten-operation"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(rewritten),
        )


def test_d333_rollback_inverts_only_the_last_uninverted_step() -> None:
    rollback = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    rollback["steps"] = [_d332_step(index=0), _d332_step(index=1)]
    first_inverse = copy.deepcopy(rollback)
    first_inverse["sequence"] = 3
    first_inverse["updated_unix_ms"] = 103
    first_inverse["steps"][1] = _d332_step(index=1, status="INVERSE_INTENT")
    first_inverse_verified = copy.deepcopy(first_inverse)
    first_inverse_verified["sequence"] = 4
    first_inverse_verified["updated_unix_ms"] = 104
    first_inverse_verified["steps"][1] = _d332_step(
        index=1, status="INVERSE_VERIFIED"
    )
    second_inverse = copy.deepcopy(first_inverse_verified)
    second_inverse["sequence"] = 5
    second_inverse["updated_unix_ms"] = 105
    second_inverse["steps"][0] = _d332_step(index=0, status="INVERSE_INTENT")
    second_inverse_verified = copy.deepcopy(second_inverse)
    second_inverse_verified["sequence"] = 6
    second_inverse_verified["updated_unix_ms"] = 106
    second_inverse_verified["steps"][0] = _d332_step(
        index=0, status="INVERSE_VERIFIED"
    )
    rolled_back = copy.deepcopy(second_inverse_verified)
    rolled_back["sequence"] = 7
    rolled_back["updated_unix_ms"] = 107
    rolled_back["state"] = "ROLLED_BACK"
    rolled_back["history"].append(
        {
            "sequence": 7,
            "from": "ABORTING",
            "to": "ROLLED_BACK",
            "at_unix_ms": 107,
            "reason_code": "rollback",
        }
    )
    rolled_back["lock_trace"] = _d333_lock_trace("ROLLED_BACK", 7)
    journals = [
        runtime_lifecycle.D320CutoverJournalV1.from_payload(value)
        for value in (
            rollback,
            first_inverse,
            first_inverse_verified,
            second_inverse,
            second_inverse_verified,
            rolled_back,
        )
    ]
    for previous, successor in zip(journals, journals[1:]):
        runtime_lifecycle.validate_d320_journal_successor(previous, successor)

    out_of_order = copy.deepcopy(rollback)
    out_of_order["sequence"] = 3
    out_of_order["updated_unix_ms"] = 103
    out_of_order["steps"][0] = _d332_step(index=0, status="INVERSE_INTENT")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            journals[0],
            runtime_lifecycle.D320CutoverJournalV1.from_payload(out_of_order),
        )


@pytest.mark.parametrize(
    "state",
    runtime_lifecycle._D320_NORMAL_STATES[:-1],
)
def test_d333_every_nonterminal_aborts_to_rolled_back(state: str) -> None:
    abort = {
        "sequence": 1,
        "from": state,
        "to": "ABORTING",
        "at_unix_ms": 1,
        "reason_code": "abort",
    }
    rolled_back = {
        "sequence": 2,
        "from": "ABORTING",
        "to": "ROLLED_BACK",
        "at_unix_ms": 2,
        "reason_code": "rollback",
    }
    runtime_lifecycle.TransitionV1.from_mapping(abort)
    runtime_lifecycle.TransitionV1.from_mapping(rolled_back)


@pytest.mark.parametrize(
    "reason",
    ("unreadable", "mixed_without_complete_inverse", "noninvertible"),
)
def test_d333_aborting_blocked_requires_a_bound_reason(reason: str) -> None:
    transition = {
        "sequence": 1,
        "from": "ABORTING",
        "to": "BLOCKED",
        "at_unix_ms": 1,
        "reason_code": reason,
    }
    runtime_lifecycle.TransitionV1.from_mapping(transition)
    transition["reason_code"] = "arbitrary"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.TransitionV1.from_mapping(transition)


@pytest.mark.parametrize("state", runtime_lifecycle._D320_NORMAL_STATES[:-1])
@pytest.mark.parametrize(
    ("kind", "reason"),
    (
        ("UNREADABLE_BLOCKED", "unreadable"),
        ("MIXED_BLOCKED", "mixed_without_complete_inverse"),
        ("NONINVERTIBLE_BLOCKED", "noninvertible"),
    ),
)
def test_d334_each_nonlive_normal_state_blocks_only_with_bound_evidence(
    state: str, kind: str, reason: str
) -> None:
    previous_payload = _d334_normal_payload(state)
    if kind == "NONINVERTIBLE_BLOCKED" and previous_payload["steps"]:
        previous_payload["steps"][0]["inverse"] = None
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(previous_payload)
    successor_payload = _d334_blocked_successor(previous_payload, reason=reason)
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        successor_payload
    )
    observed = _d332_old_snapshots(previous_payload)
    if kind == "UNREADABLE_BLOCKED":
        observed["unit_status"] = {"invalid": None}
    elif kind == "MIXED_BLOCKED":
        observed["pointer"] = runtime_lifecycle.ByteSnapshotV1.from_mapping(
            _d332_snapshot("pointer", b"neither-old-nor-new")
        )
    else:
        observed["pointer"] = _d332_new_snapshots(previous_payload)["pointer"]

    runtime_lifecycle.validate_d320_journal_successor(
        previous, successor, observed=observed
    )


def test_d334_live_granted_cannot_transition_to_blocked() -> None:
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.TransitionV1.from_mapping(
            {
                "sequence": 1,
                "from": "LIVE_GRANTED",
                "to": "BLOCKED",
                "at_unix_ms": 1,
                "reason_code": "noninvertible",
            }
        )


@pytest.mark.parametrize("state", runtime_lifecycle._D320_NORMAL_STATES[:-1])
def test_d334_repair3_each_direct_normal_blocked_transition_rejects_arbitrary_reason(
    state: str,
) -> None:
    transition = {
        "sequence": 1,
        "from": state,
        "to": "BLOCKED",
        "at_unix_ms": 1,
        "reason_code": "arbitrary",
    }
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.TransitionV1.from_mapping(transition)

    payload = _d334_normal_payload(state)
    blocked = _d334_blocked_successor(payload, reason="arbitrary")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(blocked)


def test_d334_repair3_aborting_blocked_rejects_bad_reason() -> None:
    payload = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    blocked = _d334_blocked_successor(payload, reason="arbitrary")

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(blocked)


@pytest.mark.parametrize(
    ("kind", "reason"),
    (
        ("UNREADABLE_BLOCKED", "unreadable"),
        ("MIXED_BLOCKED", "mixed_without_complete_inverse"),
        ("NONINVERTIBLE_BLOCKED", "noninvertible"),
    ),
)
def test_d334_aborting_blocked_requires_the_matching_recovery_kind(
    kind: str, reason: str
) -> None:
    previous_payload = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(previous_payload)
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(previous_payload, reason=reason)
    )
    observed = _d332_old_snapshots(previous_payload)
    if kind == "UNREADABLE_BLOCKED":
        observed["unit_status"] = {"invalid": None}
    elif kind == "MIXED_BLOCKED":
        observed["pointer"] = runtime_lifecycle.ByteSnapshotV1.from_mapping(
            _d332_snapshot("pointer", b"neither-old-nor-new")
        )
    else:
        observed["pointer"] = _d332_new_snapshots(previous_payload)["pointer"]

    runtime_lifecycle.validate_d320_journal_successor(
        previous, successor, observed=observed
    )


def test_d334_block_evidence_is_required_and_exclusive() -> None:
    aborting = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(aborting)
    blocked = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(aborting, reason="noninvertible")
    )
    observed = _d332_old_snapshots(aborting)
    observed["pointer"] = _d332_new_snapshots(aborting)["pointer"]

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(previous, blocked)
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous, blocked, observed=_d332_old_snapshots(aborting)
        )
    mismatched = _d332_old_snapshots(aborting)
    mismatched["pointer"] = runtime_lifecycle.ByteSnapshotV1.from_mapping(
        _d332_snapshot("pointer", b"neither-old-nor-new")
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous, blocked, observed=mismatched
        )

    preflight = _d332_payload(state="PREFLIGHTED", sequence=1)
    next_payload = _d332_payload(state="ROOT_ABI_VERIFIED", sequence=2)
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            runtime_lifecycle.D320CutoverJournalV1.from_payload(preflight),
            runtime_lifecycle.D320CutoverJournalV1.from_payload(next_payload),
            observed=observed,
        )


def test_d334_step_phases_are_bound_to_rollback_states() -> None:
    normal = _d332_payload(
        state="USER_CUTOVER_IN_PROGRESS",
        sequence=6,
        steps=[_d332_step(status="INVERSE_INTENT")],
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(normal)

    aborting = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    aborting["steps"] = [
        _d332_step(index=0, status="VERIFIED"),
        _d332_step(index=1, status="INVERSE_INTENT"),
        _d332_step(index=2, status="INVERSE_VERIFIED"),
    ]
    runtime_lifecycle.D320CutoverJournalV1.from_payload(aborting)
    blocked = _d334_blocked_successor(
        aborting, reason="mixed_without_complete_inverse"
    )
    runtime_lifecycle.D320CutoverJournalV1.from_payload(blocked)

    malformed = copy.deepcopy(aborting)
    malformed["steps"][0] = _d332_step(index=0, status="EFFECT_STARTED")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(malformed)

    rolled_back = _d332_payload_with_history(
        ("PREFLIGHTED", "ABORTING", "ROLLED_BACK")
    )
    rolled_back["steps"] = [_d332_step(status="INVERSE_VERIFIED")]
    runtime_lifecycle.D320CutoverJournalV1.from_payload(rolled_back)
    rolled_back["steps"][0] = _d332_step(status="VERIFIED")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(rolled_back)


def test_d334_rejects_an_effectless_cutover_record() -> None:
    payload = _d332_payload()
    payload["postcutover"] = copy.deepcopy(payload["precutover"])

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)


def test_d334_lock_events_bind_to_history_and_current_terminal_record() -> None:
    payload = _d332_payload_with_history(
        ("PREFLIGHTED", "ABORTING", "ROLLED_BACK")
    )
    runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    history = payload["history"]
    assert isinstance(history, list)
    trace = payload["lock_trace"]
    assert isinstance(trace, list)
    runtime_lifecycle.validate_d324_lock_order(
        trace,
        state="ROLLED_BACK",
        sequence=3,
        history=history,
    )

    unknown_state = copy.deepcopy(payload)
    unknown_state["lock_trace"][0]["state"] = "ROOT_ABI_VERIFIED"
    above_record = copy.deepcopy(payload)
    above_record["lock_trace"][0]["sequence"] = 4
    foreign_terminal = copy.deepcopy(payload)
    foreign_terminal["lock_trace"][-1]["state"] = "LIVE_GRANTED"
    old_terminal = copy.deepcopy(payload)
    old_terminal["lock_trace"][-1]["sequence"] = 2
    for invalid in (unknown_state, above_record, foreign_terminal, old_terminal):
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            runtime_lifecycle.D320CutoverJournalV1.from_payload(invalid)

    reversed_trace = _d333_complete_lock_trace()
    reversed_trace[1]["sequence"] = 1
    reversed_trace[1]["state"] = "ABORTING"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            reversed_trace,
            state="ROLLED_BACK",
            sequence=3,
            history=_d332_history_for_states(
                ("PREFLIGHTED", "ABORTING", "ROLLED_BACK")
            ),
        )


def test_d333_digest_precedes_payload_semantics() -> None:
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())
    payload_bytes = journal.payload_bytes.replace(b'"sequence":0', b'"sequence":true')
    raw = b'{"content_sha256":"' + b"0" * 64 + b'","payload":' + payload_bytes + b"}\n"

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError) as raised:
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)
    assert raised.value.args == ("d320_envelope_digest_invalid",)


def test_d335_digest_precedes_finite_float_semantics() -> None:
    float_payload = b'{"sequence":1.0}'
    raw = (
        b'{"content_sha256":"'
        + b"0" * 64
        + b'","payload":'
        + float_payload
        + b"}\n"
    )

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError) as raised:
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)
    assert raised.value.args == ("d320_envelope_digest_invalid",)


def test_d335_single_record_rejects_nonterminal_predecessor_step() -> None:
    payload = _d332_payload(state="PREFLIGHTED", sequence=1)
    payload["steps"] = [
        _d332_step(index=0, status="INTENT"),
        _d332_step(index=1, status="INTENT"),
    ]

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)


def test_d335_record_generation_binds_history_and_appended_lockevents() -> None:
    previous_payload = _d332_payload(state="PREFLIGHTED", sequence=1)
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(previous_payload)
    successor_payload = copy.deepcopy(previous_payload)
    successor_payload["sequence"] = 2
    successor_payload["updated_unix_ms"] = 102
    successor_payload["state"] = "ROOT_ABI_VERIFIED"
    successor_payload["history"].append(
        {
            "sequence": 2,
            "from": "PREFLIGHTED",
            "to": "ROOT_ABI_VERIFIED",
            "at_unix_ms": 102,
            "reason_code": "transition",
        }
    )
    successor_payload["lock_trace"].append(
        {
            "event": "ACQUIRE",
            "lock": "Lifecycle-Lock",
            "state": "ROOT_ABI_VERIFIED",
            "sequence": 2,
        }
    )
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        successor_payload
    )
    runtime_lifecycle.validate_d320_journal_successor(previous, successor)

    stale_lockevent = copy.deepcopy(successor_payload)
    stale_lockevent["lock_trace"][-1].update(
        {"state": "PREFLIGHTED", "sequence": 1}
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(stale_lockevent),
        )

    skewed_record = copy.deepcopy(previous_payload)
    skewed_record["sequence"] = 99
    skewed_record["updated_unix_ms"] = 199
    skewed_record["history"][0]["sequence"] = 0
    skewed_record["lock_trace"][0]["sequence"] = 0
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(skewed_record)


def test_d335_observed_shape_stops_after_one_surplus_key() -> None:
    class OverlongObservedMapping(Mapping[str, object]):
        def __init__(self) -> None:
            self.key_visits = 0

        def __len__(self) -> int:
            return len(runtime_lifecycle._D320_ARTIFACT_NAMES)

        def __iter__(self):
            for name in runtime_lifecycle._D320_ARTIFACT_NAMES:
                self.key_visits += 1
                yield name
            for index in range(65_537 - len(runtime_lifecycle._D320_ARTIFACT_NAMES)):
                self.key_visits += 1
                yield f"surplus-{index}"

        def __getitem__(self, key: str) -> object:
            raise KeyError(key)

    observed = OverlongObservedMapping()
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())
    assert runtime_lifecycle.classify_d320_recovery(
        journal, observed=observed
    ).kind == "UNREADABLE_BLOCKED"
    assert observed.key_visits == len(runtime_lifecycle._D320_ARTIFACT_NAMES) + 1


@pytest.mark.parametrize(
    "mutation",
    (
        lambda trace: trace.pop(),
        lambda trace: trace.__setitem__(
            1,
            {
                "event": "RELEASE",
                "lock": "D324-Journallock",
                "state": "PREFLIGHTED",
                "sequence": 1,
            },
        ),
        lambda trace: trace.append(
            {
                "event": "ACQUIRE",
                "lock": "D324-Journallock",
                "state": "PREFLIGHTED",
                "sequence": 3,
            }
        ),
    ),
)
def test_d333_lock_trace_rejects_early_release_reacquire_and_missing_hold(
    mutation,
) -> None:
    trace = _d333_complete_lock_trace()
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    runtime_lifecycle.validate_d324_lock_order(
        trace, state="ROLLED_BACK", sequence=3, history=history
    )
    mutation(trace)

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            trace, state="ROLLED_BACK", sequence=3, history=history
        )


@pytest.mark.parametrize("lock", runtime_lifecycle.D324_LOCK_ORDER[1:])
def test_d335_each_sublock_release_and_reacquire_is_rejected(lock: str) -> None:
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    journal_acquire = {
        "event": "ACQUIRE",
        "lock": "D324-Journallock",
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    lock_acquire = {
        "event": "ACQUIRE",
        "lock": lock,
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    lock_release = {
        "event": "RELEASE",
        "lock": lock,
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    journal_release = {
        "event": "RELEASE",
        "lock": "D324-Journallock",
        "state": "ROLLED_BACK",
        "sequence": 3,
    }
    reference = [journal_acquire, lock_acquire, lock_release, journal_release]
    runtime_lifecycle.validate_d324_lock_order(
        reference, state="ROLLED_BACK", sequence=3, history=history
    )

    reacquired = [
        journal_acquire,
        lock_acquire,
        lock_release,
        lock_acquire,
        lock_release,
        journal_release,
    ]
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            reacquired, state="ROLLED_BACK", sequence=3, history=history
        )


def test_d335_lock_trace_rejects_later_acquire_after_sublock_release() -> None:
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    journal = {
        "event": "ACQUIRE",
        "lock": "D324-Journallock",
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    lifecycle = {
        "event": "ACQUIRE",
        "lock": "Lifecycle-Lock",
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    lifecycle_release = {**lifecycle, "event": "RELEASE"}
    journal_release = {
        "event": "RELEASE",
        "lock": "D324-Journallock",
        "state": "ROLLED_BACK",
        "sequence": 3,
    }
    reference = [journal, lifecycle, lifecycle_release, journal_release]
    runtime_lifecycle.validate_d324_lock_order(
        reference, state="ROLLED_BACK", sequence=3, history=history
    )

    rootexecutor = {
        "event": "ACQUIRE",
        "lock": "Rootexecutor-Lock",
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    nonreverse = [
        journal,
        lifecycle,
        lifecycle_release,
        rootexecutor,
        {**rootexecutor, "event": "RELEASE"},
        journal_release,
    ]
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            nonreverse, state="ROLLED_BACK", sequence=3, history=history
        )


def test_d335_step_and_history_times_are_record_bound() -> None:
    reversed_step = _d332_step(status="EFFECT_STARTED")
    reversed_step["effect_started_unix_ms"] = 10
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.StepV1.from_mapping(reversed_step)

    future_step = _d332_payload(state="PREFLIGHTED", sequence=1)
    future_step["steps"] = [_d332_step(status="INTENT")]
    future_step["steps"][0]["intent_unix_ms"] = 102
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(future_step)

    payload = _d332_payload(state="ROOT_ABI_VERIFIED", sequence=2)
    payload["history"][1]["at_unix_ms"] = 99
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)

    payload = _d332_payload(state="ROOT_ABI_VERIFIED", sequence=2)
    payload["history"][1]["at_unix_ms"] = 103
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
