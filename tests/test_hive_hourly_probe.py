from __future__ import annotations

import json
import runpy
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
    build_hive_probe_alarm,
    evaluate,
    probe_spawn_gate,
    read_probe_gate,
    run_probe,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 30, 12, tzinfo=UTC)


def green_probe(checked_at: str) -> dict[str, object]:
    return {
        "functional": True,
        "checks": {"namespace": True, "plugin": True, "hive_runtime": True, "hive_doctor": True},
        "alarm": None,
        "checked_at": checked_at,
        "commands": {"namespace": True, "plugin": True, "hive_status": True, "hive_doctor": True},
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


def test_probe_evaluation_is_fail_closed_and_emits_hive_wide_alarm_without_secrets() -> None:
    marker = "local-secret-path-account-token"
    result = evaluate(
        {"ok": True, "namespace_ready": True},
        {"ok": True},
        {"mode": "shadow", "authority": "fail_closed", "state": marker},
        {"healthy": True, "checks": {"authority": "fail_closed", "repository": "not_configured", "state": "not_configured"}},
    )

    assert result["functional"] is False
    assert result["checks"] == {
        "namespace": True,
        "plugin": True,
        "hive_runtime": False,
        "hive_doctor": False,
    }
    assert result["alarm"]["scope"] == "hive"
    assert result["alarm"]["route"] == ["queen-codex-master", "active_queen", "native_recovery_queen"]
    assert result["alarm"]["token_telemetry"] == "unknown"
    assert marker not in json.dumps(result, sort_keys=True)


def test_probe_evaluation_requires_all_canonical_hive_evidence_fields() -> None:
    base = green_hive_runtime()
    doctor = {
        "healthy": True,
        "checks": {"authority": "ready", "repository": "ready", "state": "ready"},
    }
    for missing in base:
        hive = {key: value for key, value in base.items() if key != missing}
        result = evaluate(
            {"ok": True, "namespace_ready": True},
            {"ok": True},
            hive,
            doctor,
        )
        assert result["functional"] is False
        assert result["checks"]["hive_runtime"] is False
        assert result["alarm"]["scope"] == "hive"


def test_probe_evaluation_rejects_unknown_canonical_hive_evidence_states() -> None:
    base = green_hive_runtime()
    doctor = {
        "healthy": True,
        "checks": {"authority": "ready", "repository": "ready", "state": "ready"},
    }

    for field in ("authority", "repository", "principal", "state", "pilot"):
        result = evaluate(
            {"ok": True, "namespace_ready": True},
            {"ok": True},
            {**base, field: "unexpected"},
            doctor,
        )
        assert result["functional"] is False
        assert result["checks"]["hive_runtime"] is False
        assert result["alarm"]["scope"] == "hive"

    result = evaluate(
        {"ok": True, "namespace_ready": True},
        {"ok": True},
        {**base, "unexpected": "field"},
        doctor,
    )
    assert result["functional"] is False
    assert result["checks"]["hive_runtime"] is False


def test_probe_alarm_is_bounded_and_data_sparse() -> None:
    alarm = build_hive_probe_alarm(("hive_runtime_unavailable", "hive_doctor_unavailable"))
    assert alarm == {
        "schema_version": 1,
        "scope": "hive",
        "event": "hourly_probe_failed",
        "reason_codes": ["hive_runtime_unavailable", "hive_doctor_unavailable"],
        "route": ["queen-codex-master", "active_queen", "native_recovery_queen"],
        "token_telemetry": "unknown",
        "raw_output": "not_returned",
    }


def test_probe_has_exactly_eight_deterministic_utc_slots() -> None:
    assert DETERMINISTIC_PROBE_HOURS_UTC == (0, 3, 6, 9, 12, 15, 18, 21)
    assert len(DETERMINISTIC_PROBE_HOURS_UTC) == 8


def test_spawn_gate_rejects_red_missing_stale_and_ambiguous_probe_records() -> None:
    fresh = green_probe(NOW.isoformat())
    assert probe_spawn_gate(fresh, now=NOW)["allowed"] is True
    assert probe_spawn_gate({"functional": True}, now=NOW)["reason_code"] == "probe_ambiguous"
    assert probe_spawn_gate({**fresh, "functional": False}, now=NOW)["reason_code"] == "probe_red"
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


def test_run_probe_persists_bounded_health_and_replaces_stale_alarm(tmp_path: Path) -> None:
    state_directory = tmp_path / "state"
    command = tmp_path / "repo" / "bin" / "codex-master-mcp"
    command.parent.mkdir(parents=True)
    calls: list[tuple[str, ...]] = []
    green = {
        "namespace-status": ({"ok": True, "namespace_ready": True}, True),
        "plugin-status": ({"ok": True}, True),
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
        repository=tmp_path / "repo",
        command=command,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=runner,
    )
    assert result["functional"] is True
    assert calls == [("namespace-status",), ("plugin-status",), ("hive", "status"), ("hive", "doctor")]
    assert read_probe_gate(state_file=state_directory / "hive-hourly-health.json", now=NOW)["allowed"] is True
    assert (state_directory / "hive-functional").is_file()
    assert (state_directory / "hive-functional").read_text(encoding="utf-8") == NOW.isoformat() + "\n"

    def red_runner(_command: Path, *arguments: str) -> tuple[dict[str, object], bool]:
        if arguments == ("namespace-status",):
            return {"ok": False, "namespace_ready": False}, True
        return green[" ".join(arguments)]

    result = run_probe(
        repository=tmp_path / "repo",
        command=command,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=red_runner,
    )
    assert result["functional"] is False
    assert (state_directory / "hive-hourly-alarm.json").is_file()
    assert not (state_directory / "hive-functional").exists()


def test_tracked_probe_source_and_timer_contract_are_installable() -> None:
    source = ROOT / "systemd" / "libexec" / "codex_master_hive_hourly_probe.py"
    timer = ROOT / "systemd" / "user" / "codex-master-hive-hourly-probe.timer"
    service = ROOT / "systemd" / "user" / "codex-master-hive-hourly-probe.service"
    assert source.is_file() and not source.is_symlink()
    assert stat.S_IMODE(source.stat().st_mode) == 0o755
    index = subprocess.run(
        ["git", "ls-files", "-s", "systemd/libexec/codex_master_hive_hourly_probe.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert index.stdout.startswith("100755 ")
    timer_text = timer.read_text(encoding="utf-8")
    service_text = service.read_text(encoding="utf-8")
    assert "OnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00" in timer_text
    assert "RandomizedDelaySec" not in timer_text
    assert "CODEX_MASTER_PROBE_REPOSITORY" not in service_text
    assert "%h/codex-master/src" not in service_text
    assert "%h/codex-master/bin/codex-master-mcp" not in service_text
    assert "%h/codex-master/codex-agent-classes.json" not in service_text
    assert "%h/codex-master/codex-hive.json" not in service_text
    assert (
        "BindReadOnlyPaths=%h/.local/libexec/"
        "codex_master_hive_hourly_probe.py:%h/.local/libexec/"
        "codex_master_hive_hourly_probe.py:norbind"
    ) in service_text
    assert (
        "%h/.local/lib/codex-master-hive-probe:%h/.local/lib/"
        "codex-master-hive-probe:norbind"
    ) in service_text
    assert "BindPaths=%h/.local/state/codex-master-mcp:%h/.local/state/codex-master-mcp:norbind" in service_text
    assert "ExecStart=%h/.local/libexec/codex_master_hive_hourly_probe.py --json" in service_text


def test_hourly_probe_direct_entrypoint_requires_json_mode(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        hourly_probe_module,
        "run_probe",
        lambda: {"functional": True, "checks": {"hive_runtime": True}, "alarm": None},
    )

    assert hourly_probe_module.main(["--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "alarm": None,
        "checks": {"hive_runtime": True},
        "functional": True,
    }
    assert hourly_probe_module.main([]) == 2
    assert capsys.readouterr().out == ""


def test_probe_cold_installer_materializes_an_autonomous_regular_host_tree(
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
    entrypoint = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    entrypoint_stat = entrypoint.lstat()
    assert stat.S_ISREG(entrypoint_stat.st_mode)
    assert not entrypoint.is_symlink()
    assert stat.S_IMODE(entrypoint_stat.st_mode) == 0o755
    assert stat.S_IMODE((home / ".local" / "state" / "codex-master-mcp").stat().st_mode) == 0o700
    assert stat.S_IMODE(
        (home / ".config" / "systemd" / "user" / "codex-master-hive-hourly-probe.service").stat().st_mode
    ) == 0o644
    install_root = home / ".local" / "lib" / "codex-master-hive-probe"
    installed_cli = install_root / "bin" / "codex-master-mcp"
    installed_source = install_root / "src" / "codex_master" / "hive" / "hourly_probe.py"
    for path, mode in (
        (installed_cli, 0o755),
        (installed_source, 0o644),
        (install_root / "codex-hive.json", 0o644),
        (install_root / "codex-agent-classes.json", 0o644),
    ):
        item = path.lstat()
        assert stat.S_ISREG(item.st_mode)
        assert not path.is_symlink()
        assert stat.S_IMODE(item.st_mode) == mode
    assert not any(path.is_symlink() for path in install_root.rglob("*"))

    environment = {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "CODEX_MASTER_MCP_STATE": str(home / ".local" / "state" / "codex-master-mcp"),
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
    assert set(json.loads(completed.stdout)) == {"alarm", "checks", "functional"}
    health = home / ".local" / "state" / "codex-master-mcp" / "hive-hourly-health.json"
    health_stat = health.lstat()
    assert stat.S_ISREG(health_stat.st_mode)
    assert not health.is_symlink()
    assert stat.S_IMODE(health_stat.st_mode) == 0o600


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


def test_probe_capacity_guard_serializes_the_health_record_publication(
    tmp_path: Path,
) -> None:
    state_directory = tmp_path / "state"
    command = tmp_path / "repository" / "bin" / "codex-master-mcp"
    command.parent.mkdir(parents=True)
    healthy = {
        "namespace-status": ({"ok": True, "namespace_ready": True}, True),
        "plugin-status": ({"ok": True}, True),
        "hive status": (green_hive_runtime(), True),
        "hive doctor": (
            {"healthy": True, "checks": {"authority": "ready", "repository": "ready", "state": "ready"}},
            True,
        ),
    }

    def green_runner(_command: Path, *arguments: str) -> tuple[dict[str, object], bool]:
        return healthy[" ".join(arguments)]

    run_probe(
        repository=tmp_path / "repository",
        command=command,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=green_runner,
    )
    writer_started = threading.Event()
    writer_finished = threading.Event()

    def publish_red() -> None:
        writer_started.set()
        run_probe(
            repository=tmp_path / "repository",
            command=command,
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
    command = tmp_path / "repository" / "bin" / "codex-master-mcp"
    command.parent.mkdir(parents=True)
    healthy = {
        "namespace-status": ({"ok": True, "namespace_ready": True}, True),
        "plugin-status": ({"ok": True}, True),
        "hive status": (green_hive_runtime(), True),
        "hive doctor": (
            {"healthy": True, "checks": {"authority": "ready", "repository": "ready", "state": "ready"}},
            True,
        ),
    }
    run_probe(
        repository=tmp_path / "repository",
        command=command,
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
