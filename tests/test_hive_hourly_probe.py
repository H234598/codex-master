from __future__ import annotations

import json
import runpy
import errno
from datetime import UTC, datetime
from pathlib import Path
import stat
import subprocess
import threading

import pytest

from codex_master.hive import hourly_probe as hourly_probe_module
from codex_master.hive.hourly_probe import (
    DETERMINISTIC_PROBE_HOURS_UTC,
    MAX_PROBE_AGE_SECONDS,
    evaluate,
    probe_spawn_gate,
    read_probe_gate,
    run_probe,
)
from codex_master.runtime_layout import RuntimeLayout


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 30, 12, tzinfo=UTC)


def green_probe(checked_at: str) -> dict[str, object]:
    return {
        "schema_version": 2,
        "functional": True,
        "checks": {"runtime_layout": True, "hive_runtime": True, "hive_doctor": True},
        "checked_at": checked_at,
        "commands": {"runtime_status": True, "hive_status": True, "hive_doctor": True},
    }


def green_runtime_status() -> dict[str, object]:
    return {
        "ok": True,
        "metadata": {"ok": True, "reason_code": "ok"},
        "mcp_surface": {
            "ok": True,
            "initialize": True,
            "tools_list": True,
            "tool_count": 1,
            "reason_code": "ok",
        },
        "raw_output": "not_returned",
    }


def green_hive_runtime() -> dict[str, object]:
    return {
        "schema_version": 1,
        "mode": "enforced",
        "counts": {"principals": 2, "repositories": 1},
        "checks": {"authority": "ready", "repository": "ready", "state": "ready"},
        "config_digest": "sha256:" + "a" * 64,
        "catalog_digest": "sha256:" + "b" * 64,
        "repository": "ready",
        "principal": "ready",
        "authority": "ready",
        "state": "ready",
        "pilot": "ready",
        "reason_codes": [],
        "mutation_performed": False,
        "raw_output": "not_returned",
    }


def runtime_layout(tmp_path: Path) -> RuntimeLayout:
    root = tmp_path / "codex-master-runtime"
    root.mkdir(mode=0o700)

    def write(relative: str, content: str, mode: int = 0o644) -> None:
        path = root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(mode)

    write("bin/codex-master-mcp", "#!/bin/sh\nexit 0\n", 0o755)
    write("bin/codex-master-hive-hourly-probe", "#!/bin/sh\nexit 0\n", 0o755)
    write(
        ".codex-plugin/plugin.json",
        json.dumps({"name": "codex-master", "version": "0", "skills": "./skills/", "mcpServers": "./.mcp.json", "apps": "./.app.json", "hooks": "./hooks/hooks.json"}),
    )
    write(".mcp.json", json.dumps({"mcpServers": {"codex-master-mcp": {"command": "./bin/codex-master-mcp", "args": []}}}))
    write(".app.json", json.dumps({"apps": {"codex-master": {}}}))
    write("hooks/hooks.json", json.dumps({"hooks": {}}))
    write("skills/codex-master-fleet/SKILL.md", "---\nname: codex-master-fleet\n---\n")
    write("codex-hive.json", "{}")
    write("codex-agent-classes.json", "{}")
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o700)
    return RuntimeLayout.from_runtime_root(root)


def test_probe_evaluation_is_fail_closed_for_runtime_status_and_hive_evidence() -> None:
    result = evaluate(
        {"ok": False},
        {"mode": "shadow", "authority": "fail_closed", "state": "not_configured"},
        {"healthy": True, "checks": {"authority": "fail_closed", "repository": "not_configured", "state": "not_configured"}},
    )

    assert result["functional"] is False
    assert result["checks"] == {
        "runtime_layout": False,
        "hive_runtime": False,
        "hive_doctor": False,
    }


def test_probe_evaluation_requires_all_canonical_hive_evidence_fields() -> None:
    base = green_hive_runtime()
    doctor = {
        "healthy": True,
        "checks": {"authority": "ready", "repository": "ready", "state": "ready"},
    }
    for missing in base:
        hive = {key: value for key, value in base.items() if key != missing}
        result = evaluate(
            green_runtime_status(),
            hive,
            doctor,
        )
        assert result["functional"] is False
        assert result["checks"]["hive_runtime"] is False


def test_probe_evaluation_rejects_unknown_canonical_hive_evidence_states() -> None:
    base = green_hive_runtime()
    doctor = {
        "healthy": True,
        "checks": {"authority": "ready", "repository": "ready", "state": "ready"},
    }

    for field in ("authority", "repository", "principal", "state", "pilot"):
        result = evaluate(
            green_runtime_status(),
            {**base, field: "unexpected"},
            doctor,
        )
        assert result["functional"] is False
        assert result["checks"]["hive_runtime"] is False

    result = evaluate(
        green_runtime_status(),
        {**base, "unexpected": "field"},
        doctor,
    )
    assert result["functional"] is False
    assert result["checks"]["hive_runtime"] is False


def test_probe_has_exactly_eight_deterministic_utc_slots() -> None:
    assert DETERMINISTIC_PROBE_HOURS_UTC == (0, 3, 6, 9, 12, 15, 18, 21)
    assert len(DETERMINISTIC_PROBE_HOURS_UTC) == 8


def test_spawn_gate_accepts_only_a_fresh_complete_green_v2_record() -> None:
    fresh = green_probe(NOW.isoformat())
    assert probe_spawn_gate(fresh, now=NOW)["allowed"] is True
    assert probe_spawn_gate({"functional": True}, now=NOW)["reason_code"] == "probe_ambiguous"
    assert probe_spawn_gate({**fresh, "functional": False}, now=NOW)["reason_code"] == "probe_red"
    assert probe_spawn_gate({**fresh, "checks": {"runtime_layout": True, "hive_runtime": True}}, now=NOW)["allowed"] is False
    assert probe_spawn_gate({**fresh, "schema_version": 1}, now=NOW)["allowed"] is False
    assert probe_spawn_gate({**fresh, "commands": {**fresh["commands"], "runtime_status": False}}, now=NOW)["allowed"] is False
    stale = NOW.replace(hour=0).isoformat()
    assert probe_spawn_gate(green_probe(stale), now=NOW)["reason_code"] == "probe_stale"
    assert MAX_PROBE_AGE_SECONDS == 4 * 60 * 60


def test_spawn_gate_reads_only_private_state_and_never_creates_missing_state(tmp_path: Path) -> None:
    state_file = tmp_path / "missing" / "hive-hourly-health.json"
    result = read_probe_gate(state_file=state_file, now=NOW)
    assert result == {"allowed": False, "reason_code": "probe_missing", "raw_output": "not_returned"}
    assert not state_file.parent.exists()

    state_file.parent.mkdir(mode=0o700)
    state_file.write_text(json.dumps(green_probe(NOW.isoformat())), encoding="utf-8")
    state_file.chmod(0o644)
    result = read_probe_gate(state_file=state_file, now=NOW)
    assert result["allowed"] is False
    assert result["reason_code"] == "probe_invalid"


def test_run_probe_persists_only_one_schema_v2_health_record(tmp_path: Path) -> None:
    state_directory = tmp_path / "state"
    layout = runtime_layout(tmp_path)
    calls: list[tuple[str, ...]] = []
    green = {
        "hive runtime-status": (green_runtime_status(), True),
        "hive status": (
            green_hive_runtime(),
            True,
        ),
        "hive doctor": (
            {"healthy": True, "checks": {"authority": "ready", "repository": "ready", "state": "ready"}},
            True,
        ),
    }

    def runner(_command: Path, *arguments: str) -> tuple[dict[str, object], bool]:
        calls.append(arguments)
        return green[" ".join(arguments)]

    result = run_probe(
        layout=layout,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=runner,
    )
    assert result["functional"] is True
    assert result["schema_version"] == 2
    assert calls == [("hive", "runtime-status"), ("hive", "status"), ("hive", "doctor")]
    assert read_probe_gate(state_file=state_directory / "hive-hourly-health.json", now=NOW)["allowed"] is True
    assert not (state_directory / "hive-functional").exists()
    assert not (state_directory / "hive-hourly-alarm.json").exists()

    def red_runner(_command: Path, *arguments: str) -> tuple[dict[str, object], bool]:
        if arguments == ("hive", "runtime-status"):
            return {"ok": False}, True
        return green[" ".join(arguments)]

    result = run_probe(
        layout=layout,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=red_runner,
    )
    assert result["functional"] is False
    assert not (state_directory / "hive-functional").exists()
    assert not (state_directory / "hive-hourly-alarm.json").exists()


def test_hourly_probe_unit_runs_only_the_runtime_image_entrypoint() -> None:
    timer = ROOT / "systemd" / "user" / "codex-master-hive-hourly-probe.timer"
    service = ROOT / "systemd" / "user" / "codex-master-hive-hourly-probe.service"
    timer_text = timer.read_text(encoding="utf-8")
    service_text = service.read_text(encoding="utf-8")
    assert "OnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00" in timer_text
    assert "RandomizedDelaySec" not in timer_text
    assert "CODEX_MASTER_PROBE_REPOSITORY" not in service_text
    assert "%h/codex-master/src" not in service_text
    assert "%h/codex-master/bin/codex-master-mcp" not in service_text
    assert "%h/codex-master/codex-agent-classes.json" not in service_text
    assert "%h/codex-master/codex-hive.json" not in service_text
    assert "%h/.local/lib/codex-master-runtime:%h/.local/lib/codex-master-runtime:norbind" in service_text
    assert "BindPaths=%h/.local/state/codex-master-mcp:%h/.local/state/codex-master-mcp:norbind" in service_text
    assert "ExecStart=%h/.local/lib/codex-master-runtime/bin/codex-master-hive-hourly-probe --json" in service_text
    assert "libexec" not in service_text
    assert "codex-master-hive-probe" not in service_text


def test_hourly_probe_direct_entrypoint_requires_json_mode(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        hourly_probe_module,
        "run_probe",
        lambda: {"functional": True, "checks": {"runtime_layout": True, "hive_runtime": True, "hive_doctor": True}},
    )

    assert hourly_probe_module.main(["--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "checks": {"runtime_layout": True, "hive_runtime": True, "hive_doctor": True},
        "functional": True,
    }
    assert hourly_probe_module.main([]) == 2
    assert capsys.readouterr().out == ""


def test_probe_cold_installer_materializes_one_complete_regular_runtime_image(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    installed = subprocess.run(
        [ROOT / "scripts" / "codex-master-hive-hourly-probe-install", "--home", home],
        check=False,
        capture_output=True,
        text=True,
    )
    assert installed.returncode == 0, installed.stderr
    runtime_root = home / ".local" / "lib" / "codex-master-runtime"
    entrypoint = runtime_root / "bin" / "codex-master-hive-hourly-probe"
    entrypoint_stat = entrypoint.lstat()
    assert stat.S_ISREG(entrypoint_stat.st_mode)
    assert not entrypoint.is_symlink()
    assert stat.S_IMODE(entrypoint_stat.st_mode) == 0o755
    assert stat.S_IMODE((home / ".local" / "state" / "codex-master-mcp").stat().st_mode) == 0o700
    assert stat.S_IMODE(
        (home / ".config" / "systemd" / "user" / "codex-master-hive-hourly-probe.service").stat().st_mode
    ) == 0o644
    installed_cli = runtime_root / "bin" / "codex-master-mcp"
    installed_source = runtime_root / "src" / "codex_master" / "hive" / "hourly_probe.py"
    for path, mode in (
        (installed_cli, 0o755),
        (installed_source, 0o644),
        (runtime_root / ".codex-plugin" / "plugin.json", 0o644),
        (runtime_root / ".mcp.json", 0o644),
        (runtime_root / ".app.json", 0o644),
        (runtime_root / "hooks" / "hooks.json", 0o644),
        (runtime_root / "skills" / "codex-master-fleet" / "SKILL.md", 0o644),
        (runtime_root / "codex-hive.json", 0o644),
        (runtime_root / "codex-agent-classes.json", 0o644),
    ):
        item = path.lstat()
        assert stat.S_ISREG(item.st_mode)
        assert not path.is_symlink()
        assert stat.S_IMODE(item.st_mode) == mode
    assert not any(path.is_symlink() for path in runtime_root.rglob("*"))
    assert stat.S_IMODE(runtime_root.lstat().st_mode) == 0o700
    for path in runtime_root.rglob("*"):
        item = path.lstat()
        if stat.S_ISDIR(item.st_mode):
            assert stat.S_IMODE(item.st_mode) == 0o700
        else:
            assert stat.S_ISREG(item.st_mode)
            assert item.st_nlink == 1
    assert not (home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py").exists()
    assert not (home / ".local" / "lib" / "codex-master-hive-probe").exists()
    assert not (home / ".local" / "bin" / "codex-master-mcp").exists()

    environment = {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
    }
    completed = subprocess.run(
        [entrypoint, "--json"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
    )
    assert completed.returncode in {0, 1}, completed.stderr
    assert set(json.loads(completed.stdout)) == {"checks", "functional"}
    runtime_status = subprocess.run(
        [installed_cli, "hive", "runtime-status"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
    )
    assert runtime_status.returncode == 0, runtime_status.stderr
    assert json.loads(runtime_status.stdout)["ok"] is True
    health = home / ".local" / "state" / "codex-master-mcp" / "hive-hourly-health.json"
    health_stat = health.lstat()
    assert stat.S_ISREG(health_stat.st_mode)
    assert not health.is_symlink()
    assert stat.S_IMODE(health_stat.st_mode) == 0o600
    assert json.loads(health.read_text(encoding="utf-8"))["checks"]["runtime_layout"] is True
    assert not list(runtime_root.rglob("__pycache__"))


def test_installer_source_reader_is_no_follow_descriptor_bounded(tmp_path: Path) -> None:
    installer = runpy.run_path(str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install"))
    source_bytes = installer["_source_bytes"]
    install_error = installer["InstallError"]
    regular = tmp_path / "regular.py"
    regular.write_text("x = 1\n", encoding="utf-8")
    linked = tmp_path / "linked.py"
    linked.symlink_to(regular)
    oversized = tmp_path / "oversized.py"
    oversized.write_bytes(b"x" * (installer["_MAX_SOURCE_BYTES"] + 1))

    assert source_bytes(regular) == b"x = 1\n"
    with pytest.raises(install_error, match="install_source_untrusted"):
        source_bytes(linked)
    with pytest.raises(install_error, match="install_source_untrusted"):
        source_bytes(oversized)
    assert ".read_bytes(" not in (ROOT / "scripts" / "codex-master-hive-hourly-probe-install").read_text(
        encoding="utf-8"
    )


def test_runtime_image_stage_validation_runs_only_the_three_v2_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install"))
    stage = tmp_path / "stage"
    stage.mkdir()
    observed: list[tuple[str, ...]] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.append(tuple(command))
        diagnostic = command[-1]
        payload: dict[str, object] = {"status": "ready"}
        if diagnostic == "runtime-status":
            payload = {"ok": True}
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    monkeypatch.setattr(installer["subprocess"], "run", run)
    installer["_validate_runtime_image_stage"](stage=stage, home=tmp_path / "home")

    entrypoint = str(stage / "bin" / "codex-master-mcp")
    assert observed == [
        (entrypoint, "hive", "runtime-status"),
        (entrypoint, "hive", "status"),
        (entrypoint, "hive", "doctor"),
    ]


def test_runtime_image_publish_failure_leaves_the_previous_complete_image_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install"))
    install_error = installer["InstallError"]
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = library / "codex-master-runtime"
    target.mkdir(mode=0o700)
    (target / "old-complete-image").write_text("old\n", encoding="utf-8")
    stage = library / ".codex-master-runtime.stage.test"
    stage.mkdir(mode=0o700)
    (stage / "new-complete-image").write_text("new\n", encoding="utf-8")

    def renameat2(*_args: object) -> int:
        return -1

    class FailedExchange:
        pass

    failed_exchange = FailedExchange()
    failed_exchange.renameat2 = renameat2  # type: ignore[attr-defined]
    monkeypatch.setattr(installer["ctypes"], "CDLL", lambda *_args, **_kwargs: failed_exchange)
    monkeypatch.setattr(installer["ctypes"], "get_errno", lambda: errno.EIO)

    with pytest.raises(install_error, match="install_swap_failed"):
        installer["_publish_runtime_image"](stage=stage, target=target)

    assert (target / "old-complete-image").read_text(encoding="utf-8") == "old\n"
    assert not (target / "new-complete-image").exists()
    assert (stage / "new-complete-image").read_text(encoding="utf-8") == "new\n"


def test_runtime_image_build_failure_never_publishes_a_partial_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install"))
    install_error = installer["InstallError"]
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = library / "codex-master-runtime"
    target.mkdir(mode=0o700)
    (target / "old-complete-image").write_text("old\n", encoding="utf-8")
    stage = library / ".codex-master-runtime.stage.test"
    stage.mkdir(mode=0o700)

    def fail_copy(*_args: object, **_kwargs: object) -> None:
        raise install_error("install_source_untrusted")

    monkeypatch.setitem(installer["_build_runtime_image"].__globals__, "_install_regular", fail_copy)
    with pytest.raises(install_error, match="install_source_untrusted"):
        installer["_build_runtime_image"](repository=ROOT, stage=stage)

    assert (target / "old-complete-image").read_text(encoding="utf-8") == "old\n"
    assert not (target / "new-complete-image").exists()
    assert stage.is_dir()
    assert not (stage / "new-complete-image").exists()


def test_runtime_image_publish_exchange_exposes_only_complete_directory_generations(
    tmp_path: Path,
) -> None:
    installer = runpy.run_path(str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install"))
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = library / "codex-master-runtime"
    target.mkdir(mode=0o700)
    (target / "old-complete-image").write_text("old\n", encoding="utf-8")
    stage = library / ".codex-master-runtime.stage.test"
    stage.mkdir(mode=0o700)
    (stage / "new-complete-image").write_text("new\n", encoding="utf-8")

    installer["_publish_runtime_image"](stage=stage, target=target)

    assert (target / "new-complete-image").read_text(encoding="utf-8") == "new\n"
    assert not (target / "old-complete-image").exists()
    assert not stage.exists()


def test_probe_capacity_guard_serializes_the_health_record_publication(
    tmp_path: Path,
) -> None:
    state_directory = tmp_path / "state"
    layout = runtime_layout(tmp_path)
    healthy = {
        "hive runtime-status": (green_runtime_status(), True),
        "hive status": (green_hive_runtime(), True),
        "hive doctor": (
            {"healthy": True, "checks": {"authority": "ready", "repository": "ready", "state": "ready"}},
            True,
        ),
    }

    def green_runner(_command: Path, *arguments: str) -> tuple[dict[str, object], bool]:
        return healthy[" ".join(arguments)]

    run_probe(
        layout=layout,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=green_runner,
    )
    writer_started = threading.Event()
    writer_finished = threading.Event()

    def publish_red() -> None:
        writer_started.set()
        run_probe(
            layout=layout,
            state_directory=state_directory,
            now=lambda: NOW,
            runner=lambda _command, *_arguments: ({}, False),
        )
        writer_finished.set()

    state_file = state_directory / "hive-hourly-health.json"
    with hourly_probe_module.probe_capacity_guard(state_file=state_file, now=NOW) as gate:
        assert gate["allowed"] is True
        writer = threading.Thread(target=publish_red)
        writer.start()
        assert writer_started.wait(timeout=1)
        assert not writer_finished.wait(timeout=0.2)
    writer.join(timeout=1)
    assert writer_finished.is_set()
    assert read_probe_gate(state_file=state_file, now=NOW)["reason_code"] == "probe_red"


@pytest.mark.parametrize("error_type", (OSError, ValueError))
def test_probe_capacity_guard_preserves_body_exceptions(
    tmp_path: Path, error_type: type[Exception]
) -> None:
    state_directory = tmp_path / "state"
    layout = runtime_layout(tmp_path)
    healthy = {
        "hive runtime-status": (green_runtime_status(), True),
        "hive status": (green_hive_runtime(), True),
        "hive doctor": (
            {"healthy": True, "checks": {"authority": "ready", "repository": "ready", "state": "ready"}},
            True,
        ),
    }
    run_probe(
        layout=layout,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=lambda _command, *arguments: healthy[" ".join(arguments)],
    )
    error = error_type("body failure")

    with pytest.raises(error_type) as raised:
        with hourly_probe_module.probe_capacity_guard(
            state_file=state_directory / "hive-hourly-health.json", now=NOW
        ):
            raise error

    assert raised.value is error
