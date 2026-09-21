from __future__ import annotations

import subprocess
import sys
import fcntl
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


def test_d299_consumer_producer_contract_accepts_only_named_06541_identity() -> None:
    """Catches a runtime image that retains the retired .540 pin or a fallback."""

    valid = (
        b'_PRODUCER_VERSION = "0.6.541"\n'
        b'_PRODUCER_SOURCE_MANIFEST_SHA256 = "4cb02fabfb5a4b306e789cf685a6a83838e7fdd7f42e7f1af3491afd1723c7ce"\n'
        b'_PRODUCER_RELEASE_ID = "0.6.541-4cb02fabfb5a4b30"\n'
        b'if python_directory[2] != "python3.14":\n    raise ValueError()\n'
    )
    retired = valid.replace(b'"0.6.541"', b'"0.6.540"')
    other_version = valid.replace(b'"0.6.541"', b'"0.6.542"')
    other_manifest = valid.replace(
        b"4cb02fabfb5a4b306e789cf685a6a83838e7fdd7f42e7f1af3491afd1723c7ce",
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
