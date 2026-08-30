from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
import stat

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
        "hive status": ({"mode": "enforced", "authority": "ready"}, True),
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
    timer_text = timer.read_text(encoding="utf-8")
    service_text = service.read_text(encoding="utf-8")
    assert "OnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00" in timer_text
    assert "RandomizedDelaySec" not in timer_text
    assert "Environment=CODEX_MASTER_PROBE_REPOSITORY=%h/.local" in service_text
    assert "BindReadOnlyPaths=" in service_text
    assert "ExecStart=%h/.local/libexec/codex_master_hive_hourly_probe.py" in service_text
