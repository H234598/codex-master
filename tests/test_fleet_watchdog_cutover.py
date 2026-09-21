from __future__ import annotations

import os
from pathlib import Path
import runpy
import stat
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "the-hive-fleet-watchdog"
OLD_UNITS = (
    "codex-master-watchdog.service",
    "codex-master-watchdog.timer",
)
NEW_UNITS = ("the-hive-watchdog.service", "the-hive-watchdog.timer")


def _script() -> dict[str, object]:
    return runpy.run_path(str(SCRIPT))


def _write_private_unit(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o644)


def _setup_legacy_tree(tmp_path: Path) -> tuple[Path, Path, dict[str, bytes]]:
    """Build the real user-unit files; systemd itself remains faked below."""

    home = tmp_path / "home"
    (home / ".local" / "state" / "codex-master-mcp").mkdir(mode=0o700, parents=True)
    units = home / ".config" / "systemd" / "user"
    units.mkdir(mode=0o700, parents=True)
    old = {
        "codex-master-watchdog.service": (
            b"[Service]\nExecStart=/old/codex-master-mcp watchdog active "
            b"--idle-seconds 60 --poll-interval-seconds 15 "
            b"--report-grace-seconds 15 --action stop --manage-unclaimed --quiet\n"
        ),
        "codex-master-watchdog.timer": (
            b"[Timer]\nOnUnitActiveSec=15s\nUnit=codex-master-watchdog.service\n"
        ),
    }
    for name, content in old.items():
        _write_private_unit(units / name, content)
        wants = units / "timers.target.wants"
        wants.mkdir(mode=0o700, exist_ok=True)
        (wants / name).symlink_to(units / name)
    return home, units, old


class _FakeSystemd:
    """A narrow fake for the public systemd-user boundary, never systemd."""

    def __init__(self) -> None:
        self.enabled = set(OLD_UNITS)
        self.active = set(OLD_UNITS)
        self.calls: list[tuple[str, ...]] = []
        self.fail_on: tuple[str, ...] | None = None
        self.fail_once_on: tuple[str, ...] | None = None

    def __call__(self, *arguments: str) -> None:
        self.calls.append(arguments)
        if arguments == self.fail_once_on:
            self.fail_once_on = None
            raise RuntimeError("injected_systemd_failure")
        if arguments == self.fail_on:
            raise RuntimeError("injected_systemd_failure")
        if arguments == ("daemon-reload",):
            return
        if len(arguments) == 2 and arguments[0] == "stop":
            self.active.discard(arguments[1])
            return
        if len(arguments) == 2 and arguments[0] == "disable":
            self.enabled.discard(arguments[1])
            return
        if len(arguments) == 2 and arguments[0] == "enable":
            self.enabled.add(arguments[1])
            return
        if len(arguments) == 2 and arguments[0] == "start":
            self.active.add(arguments[1])
            return
        raise AssertionError(f"unexpected systemd command: {arguments!r}")

    def state(self, unit: str) -> tuple[bool, bool]:
        return unit in self.enabled, unit in self.active


def _bound_runtime() -> dict[str, object]:
    return {
        "generation": "a" * 40,
        "manifest_digest": "sha256:" + "b" * 64,
        "mcp_path": "/home/test/.local/lib/the-hive-runtime/the-hive-mcp",
        "identity": (1, 2, 0o755, os.geteuid(), 1),
    }


def _successor_units() -> dict[str, bytes]:
    return {
        "the-hive-watchdog.service": (
            b"[Service]\nExecStart=%h/.local/lib/the-hive-runtime/the-hive-mcp watchdog active "
            b"--idle-seconds 60 --poll-interval-seconds 15 --report-grace-seconds 15 "
            b"--action stop --manage-unclaimed --quiet\n"
        ),
        "the-hive-watchdog.timer": (
            b"[Timer]\nOnBootSec=15s\nOnUnitActiveSec=15s\nAccuracySec=1s\n"
            b"Unit=the-hive-watchdog.service\nPersistent=false\n"
        ),
    }


def _regular_identity(path: Path) -> tuple[int, int, int, int, int, bytes]:
    item = path.stat()
    return (
        item.st_dev,
        item.st_ino,
        item.st_uid,
        stat.S_IMODE(item.st_mode),
        item.st_nlink,
        path.read_bytes(),
    )


def _link_identity(path: Path) -> tuple[int, int, int, int, int, str]:
    item = path.lstat()
    return (
        item.st_dev,
        item.st_ino,
        item.st_uid,
        stat.S_IMODE(item.st_mode),
        item.st_nlink,
        os.readlink(path),
    )


def test_public_successor_source_binds_the_attested_stable_launcher_and_fleet_semantics() -> None:
    """Break caught: a successor unit points at a non-attested launcher or changes Fleet policy."""

    module = _script()

    units = module["_source_units"]()

    assert b"%h/.local/lib/the-hive-runtime/the-hive-mcp watchdog active" in units[
        "the-hive-watchdog.service"
    ]
    assert b"--idle-seconds 60" in units["the-hive-watchdog.service"]
    assert b"--poll-interval-seconds 15" in units["the-hive-watchdog.service"]
    assert b"--report-grace-seconds 15" in units["the-hive-watchdog.service"]
    assert b"--action stop" in units["the-hive-watchdog.service"]
    assert b"--manage-unclaimed" in units["the-hive-watchdog.service"]
    assert b"--quiet" in units["the-hive-watchdog.service"]
    assert b"OnUnitActiveSec=15s" in units["the-hive-watchdog.timer"]


def test_source_contract_rejects_extra_or_conflicting_watchdog_directives() -> None:
    """Break caught: substring matching accepts an altered Fleet command or timer cadence."""

    module = _script()
    conflicting = _successor_units()
    conflicting[NEW_UNITS[0]] = conflicting[NEW_UNITS[0]].replace(
        b"--manage-unclaimed --quiet\n", b"--manage-unclaimed --quiet --foreign-flag\n",
    )
    conflicting[NEW_UNITS[1]] += b"OnUnitActiveSec=1s\n"

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_untrusted"):
        module["_validate_successor_units"](conflicting)


def test_bounded_observer_uses_the_target_home_not_an_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a watchdog observation reads another user's state through a wrong HOME."""

    module = _script()
    home = tmp_path / "home"
    (home / ".local" / "state" / "codex-master-mcp").mkdir(mode=0o700, parents=True)
    launcher = home / ".local" / "lib" / "the-hive-runtime" / "the-hive-mcp"
    observed: dict[str, object] = {}

    def completed(arguments: list[str], **kwargs: object) -> SimpleNamespace:
        observed["arguments"] = arguments
        observed["environment"] = kwargs["env"]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(module["subprocess"], "run", completed)
    module["_default_observe"]((str(launcher), "watchdog", "active"))

    assert observed["arguments"] == [str(launcher), "watchdog", "active"]
    assert observed["environment"] == {"HOME": str(home), "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"}


def test_cutover_replaces_the_legacy_fleet_supervisor_without_a_parallel_timer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: enabling the successor before stopping legacy duplicates supervision."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    observed: list[tuple[str, ...]] = []

    def observe(command: tuple[str, ...]) -> None:
        assert command == (
            "/home/test/.local/lib/the-hive-runtime/the-hive-mcp", "watchdog", "active",
            "--idle-seconds", "60", "--poll-interval-seconds", "15",
            "--report-grace-seconds", "15", "--action", "stop", "--manage-unclaimed", "--quiet",
        )
        assert not set(OLD_UNITS).intersection(systemd.active)
        assert not set(OLD_UNITS).intersection(systemd.enabled)
        assert "the-hive-watchdog.timer" in systemd.active
        observed.append(command)

    result = module["cutover"](home=home, systemctl=systemd, observe=observe, state=systemd.state)

    assert result["status"] == "cutover_complete"
    assert observed
    assert systemd.calls.index(("stop", "codex-master-watchdog.timer")) < systemd.calls.index(
        ("stop", "codex-master-watchdog.service")
    )
    assert systemd.enabled == {"the-hive-watchdog.timer"}
    assert systemd.active == {"the-hive-watchdog.timer"}
    assert not any((units / name).exists() for name in OLD_UNITS)
    assert not any((units / "timers.target.wants" / name).exists() for name in OLD_UNITS)
    assert not any((units / "timers.target.wants" / name).is_symlink() for name in OLD_UNITS)
    service = (units / "the-hive-watchdog.service").read_text(encoding="utf-8")
    assert "--manage-unclaimed" in service
    assert "--action stop" in service
    assert "--report-grace-seconds 15" in service
    assert stat.S_IMODE((units / "the-hive-watchdog.timer").stat().st_mode) == 0o644


def test_cutover_accepts_and_binds_the_successor_want_created_by_systemd_enable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a real enable-created timer want is rejected as unmodelled drift."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = systemd
    successor_want = units / "timers.target.wants" / "the-hive-watchdog.timer"

    def enable_creates_want(*arguments: str) -> None:
        original(*arguments)
        if arguments == ("enable", "the-hive-watchdog.timer"):
            successor_want.symlink_to(units / "the-hive-watchdog.timer")

    result = module["cutover"](
        home=home, systemctl=enable_creates_want, observe=lambda _command: None, state=systemd.state,
    )

    assert result["status"] == "cutover_complete"
    assert successor_want.is_symlink()
    assert os.readlink(successor_want) == str(units / "the-hive-watchdog.timer")


def test_cutover_rejects_a_systemd_created_successor_want_with_a_foreign_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a manager-created want can redirect the successor timer to a foreign unit."""

    module = _script()
    home, units, legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = systemd
    successor_want = units / "timers.target.wants" / "the-hive-watchdog.timer"

    def enable_creates_foreign_want(*arguments: str) -> None:
        original(*arguments)
        if arguments == ("enable", "the-hive-watchdog.timer"):
            successor_want.symlink_to("/foreign/the-hive-watchdog.timer")

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](
            home=home, systemctl=enable_creates_foreign_want, observe=lambda _command: None,
            state=systemd.state,
        )

    assert {name: (units / name).read_bytes() for name in OLD_UNITS} == legacy
    assert successor_want.is_symlink()
    assert os.readlink(successor_want) == "/foreign/the-hive-watchdog.timer"


def test_rollback_preserves_a_rebound_successor_want_instead_of_unlinking_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: wants rollback unlinks a foreign replacement after accepted enablement."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = systemd
    successor_want = units / "timers.target.wants" / NEW_UNITS[1]

    def enable_creates_bound_want(*arguments: str) -> None:
        original(*arguments)
        if arguments == ("enable", NEW_UNITS[1]):
            successor_want.symlink_to(units / NEW_UNITS[1])

    def rebind_want_then_fail(_command: tuple[str, ...]) -> None:
        successor_want.unlink()
        successor_want.symlink_to("/foreign/rebound.timer")
        raise RuntimeError("observation failed")

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](
            home=home, systemctl=enable_creates_bound_want, observe=rebind_want_then_fail,
            state=systemd.state,
        )

    assert successor_want.is_symlink()
    assert os.readlink(successor_want) == "/foreign/rebound.timer"


def test_cutover_restores_bound_legacy_files_and_systemd_state_when_observation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: failed successor observation strands Fleet supervision disabled."""

    module = _script()
    home, units, legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rolled_back"):
        module["cutover"](
            home=home, systemctl=systemd,
            observe=lambda _command: (_ for _ in ()).throw(RuntimeError("observer_failed")), state=systemd.state,
        )

    assert systemd.enabled == set(OLD_UNITS)
    assert systemd.active == set(OLD_UNITS)
    assert {name: (units / name).read_bytes() for name in OLD_UNITS} == legacy
    assert not any((units / name).exists() for name in NEW_UNITS)


@pytest.mark.parametrize("failure", ("observation", "systemd"))
def test_postmutation_failure_removes_the_private_rollback_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """Break caught: a failed live transaction leaks its private rollback namespace."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    if failure == "systemd":
        systemd.fail_once_on = ("enable", NEW_UNITS[1])
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    observe = (
        (lambda _command: (_ for _ in ()).throw(RuntimeError("observation failed")))
        if failure == "observation"
        else lambda _command: None
    )

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rolled_back"):
        module["cutover"](home=home, systemctl=systemd, observe=observe, state=systemd.state)

    assert not list(units.glob(".the-hive-watchdog.rollback.*"))


def test_postmutation_rollback_reports_cleanup_failure_as_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a failed rollback directory cleanup is reported as successful recovery."""

    module = _script()
    home, _units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    monkeypatch.setitem(
        module["cutover"].__globals__,
        "_remove_empty_backup_directory",
        lambda *_arguments: (_ for _ in ()).throw(RuntimeError("cleanup failed")),
    )

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](
            home=home,
            systemctl=systemd,
            observe=lambda _command: (_ for _ in ()).throw(RuntimeError("observe failed")),
            state=systemd.state,
        )


def test_cutover_restores_legacy_wants_and_state_when_commit_reload_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a post-removal reload failure leaves the Fleet timer without its old want."""

    module = _script()
    home, units, legacy = _setup_legacy_tree(tmp_path)
    legacy_identity = {
        name: ((units / name).stat().st_dev, (units / name).stat().st_ino)
        for name in OLD_UNITS
    }
    legacy_wants_identity = {
        name: ((units / "timers.target.wants" / name).lstat().st_dev, (units / "timers.target.wants" / name).lstat().st_ino)
        for name in OLD_UNITS
    }
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = systemd

    def fail_second_reload(*arguments: str) -> None:
        if arguments == ("daemon-reload",) and original.calls.count(arguments) == 1:
            original.fail_once_on = arguments
        original(*arguments)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rolled_back"):
        module["cutover"](home=home, systemctl=fail_second_reload, observe=lambda _command: None, state=systemd.state)

    assert systemd.enabled == set(OLD_UNITS)
    assert systemd.active == set(OLD_UNITS)
    assert {name: (units / name).read_bytes() for name in OLD_UNITS} == legacy
    assert all((units / "timers.target.wants" / name).is_symlink() for name in OLD_UNITS)
    assert {
        name: ((units / name).stat().st_dev, (units / name).stat().st_ino)
        for name in OLD_UNITS
    } == legacy_identity
    assert {
        name: ((units / "timers.target.wants" / name).lstat().st_dev, (units / "timers.target.wants" / name).lstat().st_ino)
        for name in OLD_UNITS
    } == legacy_wants_identity


def test_final_postcondition_readback_rejects_successor_drift_after_commit_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a final reload race reports commit although its timer bytes changed."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = systemd

    def drift_after_commit_reload(*arguments: str) -> None:
        original(*arguments)
        if arguments == ("daemon-reload",) and original.calls.count(arguments) == 2:
            replacement = units / "foreign-successor.timer"
            replacement.write_bytes(b"foreign after final reload\n")
            replacement.chmod(0o644)
            os.replace(replacement, units / "the-hive-watchdog.timer")

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](
            home=home, systemctl=drift_after_commit_reload, observe=lambda _command: None,
            state=systemd.state,
        )

    assert (units / "the-hive-watchdog.timer").read_bytes() == b"foreign after final reload\n"


def test_commit_failure_restores_every_bound_old_new_unit_and_want_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: any rollback path replaces a bound object with merely equivalent bytes."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    prior_new = {
        "the-hive-watchdog.service": b"[Service]\nExecStart=/prior/new-service\n",
        "the-hive-watchdog.timer": b"[Timer]\nUnit=prior-new.service\n",
    }
    for name, content in prior_new.items():
        _write_private_unit(units / name, content)
        want = units / "timers.target.wants" / name
        want.symlink_to(units / name)
    all_units = (*OLD_UNITS, *NEW_UNITS)
    before_units = {name: _regular_identity(units / name) for name in all_units}
    before_wants = {
        name: _link_identity(units / "timers.target.wants" / name) for name in all_units
    }
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = systemd

    def fail_commit_reload(*arguments: str) -> None:
        if arguments == ("daemon-reload",) and original.calls.count(arguments) == 1:
            original.fail_once_on = arguments
        original(*arguments)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rolled_back"):
        module["cutover"](
            home=home, systemctl=fail_commit_reload, observe=lambda _command: None,
            state=systemd.state,
        )

    assert {name: _regular_identity(units / name) for name in all_units} == before_units
    assert {
        name: _link_identity(units / "timers.target.wants" / name) for name in all_units
    } == before_wants


def test_observation_failure_restores_every_bound_old_new_unit_and_want_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: pre-commit observation failure loses a preexisting successor identity."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    prior_new = {
        "the-hive-watchdog.service": b"[Service]\nExecStart=/prior/observation-service\n",
        "the-hive-watchdog.timer": b"[Timer]\nUnit=prior-observation.service\n",
    }
    for name, content in prior_new.items():
        _write_private_unit(units / name, content)
        (units / "timers.target.wants" / name).symlink_to(units / name)
    all_units = (*OLD_UNITS, *NEW_UNITS)
    before_units = {name: _regular_identity(units / name) for name in all_units}
    before_wants = {
        name: _link_identity(units / "timers.target.wants" / name) for name in all_units
    }
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rolled_back"):
        module["cutover"](
            home=home, systemctl=systemd,
            observe=lambda _command: (_ for _ in ()).throw(RuntimeError("observation failed")),
            state=systemd.state,
        )

    assert {name: _regular_identity(units / name) for name in all_units} == before_units
    assert {
        name: _link_identity(units / "timers.target.wants" / name) for name in all_units
    } == before_wants


def test_systemd_failure_restores_every_bound_old_new_unit_and_want_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a systemd activation failure replaces any bound prestate object."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    prior_new = {
        "the-hive-watchdog.service": b"[Service]\nExecStart=/prior/systemd-service\n",
        "the-hive-watchdog.timer": b"[Timer]\nUnit=prior-systemd.service\n",
    }
    for name, content in prior_new.items():
        _write_private_unit(units / name, content)
        (units / "timers.target.wants" / name).symlink_to(units / name)
    all_units = (*OLD_UNITS, *NEW_UNITS)
    before_units = {name: _regular_identity(units / name) for name in all_units}
    before_wants = {
        name: _link_identity(units / "timers.target.wants" / name) for name in all_units
    }
    systemd = _FakeSystemd()
    systemd.fail_once_on = ("enable", "the-hive-watchdog.timer")
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rolled_back"):
        module["cutover"](
            home=home, systemctl=systemd, observe=lambda _command: None, state=systemd.state,
        )

    assert {name: _regular_identity(units / name) for name in all_units} == before_units
    assert {
        name: _link_identity(units / "timers.target.wants" / name) for name in all_units
    } == before_wants


def test_cutover_rejects_a_rebound_legacy_unit_before_any_systemd_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: TOCTOU replacement permits a foreign legacy unit to be removed."""

    module = _script()
    home, units, legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = module["_revalidate_phase"]

    def rebind_then_validate(*arguments: object, **kwargs: object) -> None:
        target = units / "codex-master-watchdog.service"
        replacement = target.with_name("replacement.service")
        replacement.write_bytes(b"foreign\n")
        replacement.chmod(0o644)
        os.replace(replacement, target)
        original(*arguments, **kwargs)

    monkeypatch.setitem(module["cutover"].__globals__, "_revalidate_phase", rebind_then_validate)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_changed"):
        module["cutover"](home=home, systemctl=systemd, observe=lambda _command: None, state=systemd.state)

    assert systemd.calls == []
    assert (units / "codex-master-watchdog.service").read_bytes() == b"foreign\n"
    assert (units / "codex-master-watchdog.timer").read_bytes() == legacy["codex-master-watchdog.timer"]


def test_cutover_rejects_successor_unit_source_drift_before_any_systemd_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: source drift changes the staged supervisor after it was bound."""

    module = _script()
    home, _units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    values = [_successor_units(), {**_successor_units(), "the-hive-watchdog.timer": b"foreign\n"}]

    def source_units() -> dict[str, bytes]:
        return values.pop(0)

    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", source_units)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_changed"):
        module["cutover"](home=home, systemctl=systemd, observe=lambda _command: None, state=systemd.state)

    assert systemd.calls == []


def test_precommit_refusal_does_not_leak_a_rollback_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: an input refusal leaves transaction material in the unit namespace."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    values = [_successor_units(), {**_successor_units(), NEW_UNITS[1]: b"foreign\n"}]

    def source_units() -> dict[str, bytes]:
        return values.pop(0)

    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", source_units)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_changed"):
        module["cutover"](home=home, systemctl=systemd, observe=lambda _command: None, state=systemd.state)

    assert not list(units.glob(".the-hive-watchdog.rollback.*"))


def test_directory_rebind_before_backup_creation_does_not_create_in_the_foreign_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: backup mkdir follows a rebound user-unit directory after validation."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original_create = module["_create_backup_directory"]

    def rebind_before_backup_create(directory: object) -> object:
        original_units = units.with_name("bound-user")
        os.replace(units, original_units)
        units.mkdir(mode=0o700)
        return original_create(directory)

    monkeypatch.setitem(module["cutover"].__globals__, "_create_backup_directory", rebind_before_backup_create)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_changed"):
        module["cutover"](home=home, systemctl=systemd, observe=lambda _command: None, state=systemd.state)

    assert systemd.calls == []
    assert not list(units.glob(".the-hive-watchdog.rollback.*"))


def test_lifecycle_lock_rejects_a_state_root_rebind_without_creating_in_the_foreign_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: lifecycle lock creation follows a rebound state root outside its namespace."""

    module = _script()
    home, _units, _legacy = _setup_legacy_tree(tmp_path)
    state_root = home / ".local" / "state" / "codex-master-mcp"
    systemd = _FakeSystemd()
    original_open = module["_open_bound_directory"]
    rebound = False

    def rebind_after_root_fd_open(directory: object) -> int:
        nonlocal rebound
        descriptor = original_open(directory)
        if not rebound and directory.path == state_root:
            rebound = True
            os.replace(state_root, state_root.with_name("bound-codex-master-mcp"))
            state_root.mkdir(mode=0o700)
        return descriptor

    monkeypatch.setitem(module["cutover"].__globals__, "_open_bound_directory", rebind_after_root_fd_open)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_changed"):
        module["cutover"](home=home, systemctl=systemd, observe=lambda _command: None, state=systemd.state)

    assert systemd.calls == []
    assert not (state_root / ".the-hive-watchdog-cutover.lock").exists()


def test_cutover_never_unlinks_or_overwrites_a_legacy_unit_rebound_during_the_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a late TOCTOU swap makes rollback delete an unbound foreign unit."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    target = units / "codex-master-watchdog.service"

    def rebind_after_activation(_command: tuple[str, ...]) -> None:
        replacement = target.with_name("foreign.service")
        replacement.write_bytes(b"foreign after activation\n")
        replacement.chmod(0o644)
        os.replace(replacement, target)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](home=home, systemctl=systemd, observe=rebind_after_activation, state=systemd.state)

    assert target.read_bytes() == b"foreign after activation\n"


def test_rollback_never_unlinks_a_successor_unit_rebound_after_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: rollback removes an attacker replacement of a staged successor file."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    target = units / "the-hive-watchdog.service"

    def rebind_then_fail(_command: tuple[str, ...]) -> None:
        replacement = target.with_name("foreign-successor.service")
        replacement.write_bytes(b"foreign successor\n")
        replacement.chmod(0o644)
        os.replace(replacement, target)
        raise RuntimeError("observation failed")

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](home=home, systemctl=systemd, observe=rebind_then_fail, state=systemd.state)

    assert target.read_bytes() == b"foreign successor\n"


def test_cutover_rolls_back_when_the_successor_timer_does_not_become_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a successful systemctl return is mistaken for an active Fleet scheduler."""

    module = _script()
    home, units, legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = systemd

    def start_without_activation(*arguments: str) -> None:
        if arguments == ("start", "the-hive-watchdog.timer"):
            original.calls.append(arguments)
            return
        original(*arguments)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rolled_back"):
        module["cutover"](home=home, systemctl=start_without_activation, observe=lambda _command: None, state=systemd.state)

    assert systemd.enabled == set(OLD_UNITS)
    assert systemd.active == set(OLD_UNITS)
    assert {name: (units / name).read_bytes() for name in OLD_UNITS} == legacy


def test_cutover_is_idempotent_for_an_already_exclusive_green_successor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a retry turns an already green successor back into a legacy migration."""

    module = _script()
    home = tmp_path / "home"
    (home / ".local" / "state" / "codex-master-mcp").mkdir(mode=0o700, parents=True)
    units = home / ".config" / "systemd" / "user"
    units.mkdir(mode=0o700, parents=True)
    for name, content in _successor_units().items():
        _write_private_unit(units / name, content)
    systemd = _FakeSystemd()
    systemd.enabled = {"the-hive-watchdog.timer"}
    systemd.active = {"the-hive-watchdog.timer"}
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    observed: list[tuple[str, ...]] = []

    result = module["cutover"](
        home=home, systemctl=systemd, observe=observed.append, state=systemd.state
    )

    assert result["status"] == "cutover_complete"
    assert observed
    assert systemd.calls == []


def test_status_with_a_missing_unit_directory_never_creates_a_namespace_or_changes_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: read-only status creates `~/.config/systemd/user` as a side effect."""

    module = _script()
    home = tmp_path / "home"
    systemd_root = home / ".config" / "systemd"
    systemd_root.mkdir(mode=0o700, parents=True)
    before = systemd_root.stat()
    systemd = _FakeSystemd()
    systemd.enabled.clear()
    systemd.active.clear()
    monkeypatch.setitem(module["status"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())

    result = module["status"](home=home, state=systemd.state)

    assert result["status"] == "ok"
    assert result["legacy_present"] is False
    assert result["successor_present"] is False
    after = systemd_root.stat()
    assert (after.st_dev, after.st_ino, stat.S_IMODE(after.st_mode)) == (
        before.st_dev,
        before.st_ino,
        stat.S_IMODE(before.st_mode),
    )
    assert not (systemd_root / "user").exists()


def test_actual_public_status_does_not_emit_runtime_import_bytecode_or_mutate_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: read-only status leaves a runtime import cache or local state behind."""

    module = _script()
    home = tmp_path / "home"
    runtime = home / ".local" / "lib" / "the-hive-runtime"
    runtime.mkdir(mode=0o700, parents=True)
    cache = tmp_path / "pycache-prefix"
    home_before = {
        path.relative_to(home): (path.lstat().st_dev, path.lstat().st_ino, path.lstat().st_mode)
        for path in home.rglob("*")
    }
    sys.modules.pop("the_hive.runtime_layout", None)
    monkeypatch.setattr(sys, "pycache_prefix", str(cache))
    monkeypatch.setattr(sys, "dont_write_bytecode", False)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_untrusted"):
        module["status"](home=home, state=lambda _unit: (False, False))

    assert not list(cache.rglob("*.pyc"))
    assert {
        path.relative_to(home): (path.lstat().st_dev, path.lstat().st_ino, path.lstat().st_mode)
        for path in home.rglob("*")
    } == home_before


def test_cutover_migrates_real_legacy_0600_units_without_rewriting_them_before_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: the installed legacy 0600 watchdog pair is rejected as if untrusted."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    for name in OLD_UNITS:
        (units / name).chmod(0o600)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)

    result = module["cutover"](home=home, systemctl=systemd, observe=lambda _command: None, state=systemd.state)

    assert result["status"] == "cutover_complete"
    assert stat.S_IMODE((units / "the-hive-watchdog.service").stat().st_mode) == 0o644


def test_rollback_restores_the_bound_legacy_0600_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: rollback replaces real legacy 0600 units with a broader 0644 mode."""

    module = _script()
    home, units, legacy = _setup_legacy_tree(tmp_path)
    for name in OLD_UNITS:
        (units / name).chmod(0o600)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rolled_back"):
        module["cutover"](
            home=home, systemctl=systemd,
            observe=lambda _command: (_ for _ in ()).throw(RuntimeError("observe failed")),
            state=systemd.state,
        )

    assert {name: (units / name).read_bytes() for name in OLD_UNITS} == legacy
    assert {name: stat.S_IMODE((units / name).stat().st_mode) for name in OLD_UNITS} == {
        name: 0o600 for name in OLD_UNITS
    }


def test_rollback_restores_bound_preexisting_successor_files_byte_for_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: staging overwrites a prior successor file that rollback cannot restore."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    prior = {
        "the-hive-watchdog.service": b"[Service]\nExecStart=/prior/safe-watchdog\n",
        "the-hive-watchdog.timer": b"[Timer]\nUnit=prior.service\n",
    }
    for name, content in prior.items():
        _write_private_unit(units / name, content)
    prior_identity = {
        name: ((units / name).stat().st_dev, (units / name).stat().st_ino)
        for name in NEW_UNITS
    }
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rolled_back"):
        module["cutover"](
            home=home, systemctl=systemd,
            observe=lambda _command: (_ for _ in ()).throw(RuntimeError("observe failed")),
            state=systemd.state,
        )

    assert {name: (units / name).read_bytes() for name in NEW_UNITS} == prior
    assert {
        name: ((units / name).stat().st_dev, (units / name).stat().st_ino)
        for name in NEW_UNITS
    } == prior_identity


def test_rollback_never_restores_a_backup_over_a_rebound_preexisting_successor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: rollback overwrites a successor rebound after its original was backed up."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    for name, content in {
        NEW_UNITS[0]: b"[Service]\nExecStart=/previous\n",
        NEW_UNITS[1]: b"[Timer]\nUnit=previous.service\n",
    }.items():
        _write_private_unit(units / name, content)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    target = units / NEW_UNITS[0]

    def rebind_after_backup(_command: tuple[str, ...]) -> None:
        replacement = units / "foreign-preexisting.service"
        replacement.write_bytes(b"foreign after backup\n")
        replacement.chmod(0o644)
        os.replace(replacement, target)
        raise RuntimeError("observe failed")

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](
            home=home, systemctl=systemd, observe=rebind_after_backup, state=systemd.state,
        )

    assert target.read_bytes() == b"foreign after backup\n"


def test_backup_restats_its_named_entry_after_parent_fd_open_before_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a bound-parent FD still renames a leaf swapped after that FD opened."""

    module = _script()
    parent = tmp_path / "units"
    parent.mkdir(mode=0o700)
    target = parent / "codex-master-watchdog.service"
    _write_private_unit(target, b"bound legacy\n")
    backup_parent = module["_bind_directory"](parent)
    backup = module["_create_backup_directory"](backup_parent)
    expected = module["_maybe_file"](target)
    original_open = module["_open_bound_directory"]
    opened = False

    def swap_after_source_parent_open(directory: object) -> int:
        nonlocal opened
        descriptor = original_open(directory)
        if not opened and directory == backup_parent:
            opened = True
            replacement = parent / "foreign.service"
            replacement.write_bytes(b"foreign after fd open\n")
            replacement.chmod(0o644)
            os.replace(replacement, target)
        return descriptor

    monkeypatch.setitem(module["_backup_file"].__globals__, "_open_bound_directory", swap_after_source_parent_open)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_changed"):
        module["_backup_file"](
            target, expected, backup.path, {}, source_directory=backup_parent, backup_directory=backup,
        )

    assert target.read_bytes() == b"foreign after fd open\n"
    assert not list(backup.path.iterdir())


def test_backup_cleanup_does_not_rmdir_a_rebound_empty_leaf_after_parent_fd_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: cleanup rmdir deletes a foreign empty backup-name directory after rebind."""

    module = _script()
    parent_path = tmp_path / "units"
    parent_path.mkdir(mode=0o700)
    parent = module["_bind_directory"](parent_path)
    backup = module["_create_backup_directory"](parent)
    original_open = module["_open_bound_directory"]
    rebound = False

    def rebind_backup_after_parent_open(directory: object) -> int:
        nonlocal rebound
        descriptor = original_open(directory)
        if not rebound and directory == parent:
            rebound = True
            os.replace(backup.path, parent_path / "bound-backup")
            backup.path.mkdir(mode=0o700)
        return descriptor

    monkeypatch.setitem(
        module["_remove_empty_backup_directory"].__globals__,
        "_open_bound_directory",
        rebind_backup_after_parent_open,
    )

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_verification_failed"):
        module["_remove_empty_backup_directory"](backup, parent)

    assert backup.path.is_dir()


def test_old_want_parent_rebind_before_backup_fd_open_leaves_foreign_directory_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: old want backup follows a rebound wants directory after phase validation."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original_backup = module["_backup_link"]
    rebound = False
    wants = units / "timers.target.wants"

    def rebind_before_backup(*arguments: object, **kwargs: object) -> None:
        nonlocal rebound
        if not rebound:
            rebound = True
            os.replace(wants, units / "bound-wants")
            wants.mkdir(mode=0o700)
        original_backup(*arguments, **kwargs)

    monkeypatch.setitem(module["cutover"].__globals__, "_backup_link", rebind_before_backup)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](home=home, systemctl=systemd, observe=lambda _command: None, state=systemd.state)

    assert wants.is_dir()
    assert not list(wants.iterdir())


def test_cutover_rejects_an_initially_active_successor_service_before_any_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: migration starts a second supervisor beside an already active successor."""

    module = _script()
    home, _units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    systemd.active.add("the-hive-watchdog.service")
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_mixed_prestate"):
        module["cutover"](home=home, systemctl=systemd, observe=lambda _command: None, state=systemd.state)

    assert systemd.calls == []


def test_phase_revalidation_rejects_a_legacy_rebind_before_the_first_systemd_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: staging succeeds, then a rebound legacy file reaches daemon-reload."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = module["_revalidate_phase"]
    calls = 0

    def rebind_before_first_systemd(*arguments: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            target = units / "codex-master-watchdog.timer"
            replacement = target.with_name("foreign.timer")
            replacement.write_bytes(b"foreign timer\n")
            replacement.chmod(0o600)
            os.replace(replacement, target)
        original(*arguments, **kwargs)

    monkeypatch.setitem(module["cutover"].__globals__, "_revalidate_phase", rebind_before_first_systemd)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_changed"):
        module["cutover"](home=home, systemctl=systemd, observe=lambda _command: None, state=systemd.state)

    assert systemd.calls == []
    assert (units / "codex-master-watchdog.timer").read_bytes() == b"foreign timer\n"


def test_stage_replace_revalidates_after_temp_creation_before_replacing_a_bound_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a rebind between mkstemp and replace reaches any live mutation."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = module["_revalidate_phase"]
    calls = 0

    def rebind_before_stage_replace(*arguments: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 4:
            target = units / OLD_UNITS[0]
            replacement = units / "foreign-between-temp-and-replace.service"
            replacement.write_bytes(b"foreign between temp and replace\n")
            replacement.chmod(0o600)
            os.replace(replacement, target)
        original(*arguments, **kwargs)

    monkeypatch.setitem(module["cutover"].__globals__, "_revalidate_phase", rebind_before_stage_replace)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_changed"):
        module["cutover"](home=home, systemctl=systemd, observe=lambda _command: None, state=systemd.state)

    assert systemd.calls == []
    assert (units / OLD_UNITS[0]).read_bytes() == b"foreign between temp and replace\n"
    assert not list(units.glob(".the-hive-watchdog.rollback.*"))
    assert not list(units.glob(".the-hive-watchdog.*"))


def test_phase_revalidation_rejects_systemd_state_drift_before_the_first_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a changed user-manager state is acted on without a fresh bound check."""

    module = _script()
    home, _units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    reads = 0

    def drift_after_capture(unit: str) -> tuple[bool, bool]:
        nonlocal reads
        reads += 1
        if reads > 4 and unit == "codex-master-watchdog.timer":
            return False, False
        return systemd.state(unit)

    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_state_changed"):
        module["cutover"](home=home, systemctl=systemd, observe=lambda _command: None, state=drift_after_capture)

    assert systemd.calls == []


def test_rollback_fails_closed_when_independent_bound_state_verification_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: rollback reports success although the original scheduler state was not restored."""

    module = _script()
    home, _units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    monkeypatch.setitem(module["cutover"].__globals__, "_restore_states", lambda *_arguments: None)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](
            home=home, systemctl=systemd,
            observe=lambda _command: (_ for _ in ()).throw(RuntimeError("observe failed")),
            state=systemd.state,
        )


def test_restore_wants_rechecks_the_bound_leaf_after_parent_fd_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: rollback unlink removes a foreign want swapped after its parent FD opened."""

    module = _script()
    home, units, _legacy = _setup_legacy_tree(tmp_path)
    monkeypatch.setitem(module["_bind"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    binding = module["_bind"](home, lambda _name: (False, False), create_unit_dir=True)
    want = units / "timers.target.wants" / NEW_UNITS[1]
    want.symlink_to(units / NEW_UNITS[1])
    expected_wants = {item.path: item for item in binding.wants}
    expected_wants[want] = module["_maybe_link"](want)
    bound_parent = binding.want_directories[want.parent]
    original_open = module["_open_bound_directory"]
    swapped = False

    def swap_leaf_after_parent_open(directory: object) -> int:
        nonlocal swapped
        descriptor = original_open(directory)
        if not swapped and directory == bound_parent:
            swapped = True
            want.unlink()
            want.symlink_to("/foreign/after-parent-fd-open")
        return descriptor

    monkeypatch.setitem(
        module["_restore_wants"].__globals__, "_open_bound_directory", swap_leaf_after_parent_open,
    )

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_verification_failed"):
        module["_restore_wants"](binding, expected_wants)

    assert os.readlink(want) == "/foreign/after-parent-fd-open"


def test_remove_rechecks_the_bound_leaf_after_parent_fd_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: removal unlinks a foreign file swapped after its parent FD opened."""

    module = _script()
    parent_path = tmp_path / "units"
    parent_path.mkdir(mode=0o700)
    target = parent_path / "the-hive-watchdog.service"
    _write_private_unit(target, b"bound successor\n")
    expected = module["_maybe_file"](target)
    parent = module["_bind_directory"](parent_path)
    original_open = module["_open_bound_directory"]
    swapped = False

    def swap_leaf_after_parent_open(directory: object) -> int:
        nonlocal swapped
        descriptor = original_open(directory)
        if not swapped and directory == parent:
            swapped = True
            replacement = parent_path / "foreign.service"
            replacement.write_bytes(b"foreign after parent fd open\n")
            replacement.chmod(0o600)
            os.replace(replacement, target)
        return descriptor

    monkeypatch.setitem(module["_remove"].__globals__, "_open_bound_directory", swap_leaf_after_parent_open)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_changed"):
        module["_remove"](target, expected=expected, directory=parent)

    assert target.read_bytes() == b"foreign after parent fd open\n"


def test_write_unit_rechecks_an_initially_absent_destination_before_fd_replace(
    tmp_path: Path,
) -> None:
    """Break caught: a foreign destination inserted after staging is overwritten by replace."""

    module = _script()
    parent_path = tmp_path / "units"
    parent_path.mkdir(mode=0o700)
    parent = module["_bind_directory"](parent_path)
    target = parent_path / "the-hive-watchdog.service"
    callbacks = 0

    def insert_foreign_after_temp() -> None:
        nonlocal callbacks
        callbacks += 1
        if callbacks == 2:
            target.write_bytes(b"foreign destination\n")
            target.chmod(0o600)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_input_changed"):
        module["_write_unit"](
            target,
            b"intended successor\n",
            directory=parent,
            expected_destination=module["_File"](target, None, None),
            before_mutation=insert_foreign_after_temp,
        )

    assert target.read_bytes() == b"foreign destination\n"


def test_lifecycle_lock_rejects_a_second_namespace_after_root_rebind(
    tmp_path: Path,
) -> None:
    """Break caught: rebinding the lock root permits a parallel transaction in a new namespace."""

    module = _script()
    home = tmp_path / "home"
    root = home / ".local" / "state" / "codex-master-mcp"
    root.mkdir(mode=0o700, parents=True)
    first = module["_acquire_lifecycle_lock"](home)
    try:
        os.replace(root, root.parent / "bound-transaction-root")
        root.mkdir(mode=0o700)

        with pytest.raises(module["CutoverError"], match="watchdog_cutover_in_progress"):
            module["_acquire_lifecycle_lock"](home)
    finally:
        os.close(first.descriptor)
        os.close(first.root_descriptor)
        os.close(first.guard_descriptor)
        os.close(first.guard_parent_descriptor)
        os.close(first.anchor_descriptor)
        os.close(first.anchor_parent_descriptor)


def test_committed_backup_cleanup_rechecks_every_leaf_after_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: cleanup unlinks a foreign backup leaf swapped after listdir."""

    module = _script()
    parent_path = tmp_path / "units"
    parent_path.mkdir(mode=0o700)
    parent = module["_bind_directory"](parent_path)
    backup = module["_create_backup_directory"](parent)
    leaf = backup.path / "codex-master-watchdog.service"
    _write_private_unit(leaf, b"bound backup\n")
    target = parent_path / "codex-master-watchdog.service"
    target.write_bytes(b"original target\n")
    target.chmod(0o600)
    original_listdir = module["os"].listdir
    swapped = False

    def swap_after_list(descriptor: object) -> list[str]:
        nonlocal swapped
        result = original_listdir(descriptor)
        if not swapped:
            swapped = True
            replacement = backup.path / "foreign-backup.service"
            replacement.write_bytes(b"foreign listed replacement\n")
            replacement.chmod(0o600)
            os.replace(replacement, leaf)
        return result

    monkeypatch.setattr(module["os"], "listdir", swap_after_list)

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_verification_failed"):
        module["_discard_committed_backups"](
            {target: module["_Backup"](leaf, module["_maybe_file"](leaf).identity, False)},
            backup,
            parent,
        )

    assert leaf.read_bytes() == b"foreign listed replacement\n"


def test_observe_phase_rechecks_the_lifecycle_namespace_after_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a root rebind after start reaches the stop-capable watchdog observer."""

    module = _script()
    home, _units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = systemd
    observed: list[tuple[str, ...]] = []
    competing_lock_rejected = False

    def rebind_after_start(*arguments: str) -> None:
        nonlocal competing_lock_rejected
        original(*arguments)
        if arguments == ("start", NEW_UNITS[1]):
            root = home / ".local" / "state" / "codex-master-mcp"
            os.replace(root, root.parent / "bound-start-root")
            root.mkdir(mode=0o700)
            with pytest.raises(module["CutoverError"], match="watchdog_cutover_in_progress"):
                module["_acquire_lifecycle_lock"](home)
            competing_lock_rejected = True

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](
            home=home,
            systemctl=rebind_after_start,
            observe=lambda command: observed.append(command),
            state=systemd.state,
        )

    assert competing_lock_rejected
    assert not observed


def test_observe_phase_rechecks_the_guard_parent_namespace_after_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: rebinding the guard parent opens a parallel lock namespace before observe."""

    module = _script()
    home, _units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = systemd
    observed: list[tuple[str, ...]] = []
    competing_lock_rejected = False

    def rebind_guard_parent_after_start(*arguments: str) -> None:
        nonlocal competing_lock_rejected
        original(*arguments)
        if arguments == ("start", NEW_UNITS[1]):
            local = home / ".local"
            state = local / "state"
            os.replace(state, local / "bound-state-parent")
            state.mkdir(mode=0o700)
            (state / "codex-master-mcp").mkdir(mode=0o700)
            with pytest.raises(module["CutoverError"], match="watchdog_cutover_in_progress"):
                module["_acquire_lifecycle_lock"](home)
            competing_lock_rejected = True

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](
            home=home,
            systemctl=rebind_guard_parent_after_start,
            observe=lambda command: observed.append(command),
            state=systemd.state,
        )

    assert competing_lock_rejected
    assert not observed


def test_create_backup_directory_uses_one_real_bound_parent_fd_creation_without_a_leak(
    tmp_path: Path,
) -> None:
    """Break caught: the actual openat backup path retries its just-created name and fails."""

    module = _script()
    parent_path = tmp_path / "units"
    parent_path.mkdir(mode=0o700)
    parent = module["_bind_directory"](parent_path)

    backup = module["_create_backup_directory"](parent)

    item = backup.path.stat()
    assert backup.path.parent == parent_path
    assert backup.identity == (
        item.st_dev, item.st_ino, stat.S_IMODE(item.st_mode), item.st_uid,
    )
    assert stat.S_IMODE(item.st_mode) == 0o700
    assert [path.name for path in parent_path.iterdir()] == [backup.path.name]

    module["_remove_empty_backup_directory"](backup, parent)

    assert not list(parent_path.iterdir())


def test_rollback_systemd_phase_rejects_manager_drift_before_its_next_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: a rollback keeps mutating systemd after an intervening manager-state drift."""

    module = _script()
    home, _units, _legacy = _setup_legacy_tree(tmp_path)
    systemd = _FakeSystemd()
    monkeypatch.setitem(module["cutover"].__globals__, "_bind_runtime", lambda _home: _bound_runtime())
    monkeypatch.setitem(module["cutover"].__globals__, "_source_units", _successor_units)
    original = systemd
    rollback_stop_seen = False

    def drift_after_first_rollback_stop(*arguments: str) -> None:
        nonlocal rollback_stop_seen
        original(*arguments)
        if arguments == ("stop", NEW_UNITS[1]) and not rollback_stop_seen:
            rollback_stop_seen = True
            systemd.active.add(OLD_UNITS[0])

    with pytest.raises(module["CutoverError"], match="watchdog_cutover_rollback_failed"):
        module["cutover"](
            home=home,
            systemctl=drift_after_first_rollback_stop,
            observe=lambda _command: (_ for _ in ()).throw(RuntimeError("observe failed")),
            state=systemd.state,
        )

    assert rollback_stop_seen
    rollback_stop = ("stop", NEW_UNITS[1])
    assert rollback_stop in systemd.calls
    assert ("disable", NEW_UNITS[1]) not in systemd.calls[systemd.calls.index(rollback_stop) + 1:]
