from __future__ import annotations

import json
import math
import runpy
import errno
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
import stat
import subprocess
import threading

import pytest

from conftest import seal_runtime_image
from the_hive.hive import hourly_probe as hourly_probe_module
from the_hive.hive.hourly_probe import (
    DETERMINISTIC_PROBE_HOURS_UTC,
    MAX_PROBE_AGE_SECONDS,
    evaluate,
    probe_spawn_gate,
    read_probe_gate,
    run_probe,
)
from the_hive.runtime_layout import RuntimeLayout
from the_hive.runtime_process import BoundedProcessError, BoundedProcessResult


ROOT = Path(__file__).resolve().parents[1]
TEST_NON_F25_COMMIT = "a" * 40
NOW = datetime(2026, 8, 30, 12, tzinfo=UTC)


def _write_authorized_queen_registry(home: Path) -> None:
    registry = home / ".local" / "state" / "codex-master-mcp" / "teamleaders.json"
    registry.parent.mkdir(mode=0o700, parents=True)
    active_home = (home / ".codex").resolve(strict=False)
    digest = hashlib.sha256(
        b"codex-master-teamleader-v1\0" + str(active_home).encode("utf-8")
    ).hexdigest()
    registry.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "principals": [
                    {"digest": digest, "class": "koenigin", "agent_id": None}
                ],
            }
        ),
        encoding="utf-8",
    )
    registry.chmod(0o600)


def test_runtime_image_probe_time_contract_composes_each_bounded_phase() -> None:
    """A complete image probe has a named total budget, never a 10-s wrapper."""

    assert hourly_probe_module.RUNTIME_IMAGE_PROBE_PHASE_TIMEOUTS == (
        ("direct_mcp", 10.0),
        ("direct_mcp_cleanup", 0.5),
        ("hive_status", 45.0),
        ("hive_status_cleanup", 0.5),
        ("hive_doctor", 45.0),
        ("hive_doctor_cleanup", 0.5),
        ("startup_and_publish", 5.0),
    )
    assert hourly_probe_module.RUNTIME_IMAGE_PROBE_TOTAL_TIMEOUT_SECONDS == 106.5


def green_probe(checked_at: str) -> dict[str, object]:
    return {
        "schema_version": 3,
        "checks": {"runtime_layout": True, "hive_runtime": True, "hive_doctor": True},
        "checked_at": checked_at,
        "commands": {"runtime_status": True, "hive_status": True, "hive_doctor": True},
        "diagnostics": {
            "runtime_status": {
                "code": "ok",
                "exit_code": 0,
                "stderr": {
                    "state": "empty",
                    "excerpt": "",
                    "redaction_applied": False,
                },
            },
            "hive_status": {
                "code": "ok",
                "exit_code": 0,
                "stderr": {
                    "state": "empty",
                    "excerpt": "",
                    "redaction_applied": False,
                },
            },
            "hive_doctor": {
                "code": "ok",
                "exit_code": 0,
                "stderr": {
                    "state": "empty",
                    "excerpt": "",
                    "redaction_applied": False,
                },
            },
        },
        "alarm": {
            "scope": "hive",
            "status": "cleared",
            "reason_codes": [],
            "owner": {
                "principal_id": "queen-codex-master",
                "class_id": "koenigin",
                "repo_id": "codex-master",
            },
        },
        "global_pilot_readiness": {
            "schema_version": 1,
            "pilot": "ready",
            "generation_id": "a" * 32,
            "freshness": "fresh",
            "candidate_count": 1,
            "reason_codes": [],
            "raw_output": "not_returned",
        },
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
        "global_pilot_readiness": green_probe(NOW.isoformat())[
            "global_pilot_readiness"
        ],
        "reason_codes": [],
        "mutation_performed": False,
        "raw_output": "not_returned",
    }


def runtime_layout(tmp_path: Path) -> RuntimeLayout:
    root = tmp_path / "the-hive-runtime"
    root.mkdir(mode=0o700)

    def write(relative: str, content: str, mode: int = 0o644) -> None:
        path = root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(mode)

    write("bin/the-hive-mcp", "#!/bin/sh\nexit 0\n", 0o755)
    write("bin/the-hive-mcp-stable", "#!/bin/sh\nexit 0\n", 0o755)
    write("bin/the-hive-hive-hourly-probe", "#!/bin/sh\nexit 0\n", 0o755)
    write("bin/the-hive-resource-monitor", "#!/bin/sh\nexit 0\n", 0o755)
    write("systemd/user/the-hive-resource-monitor.service", "[Service]\n")
    write("systemd/user/the-hive.slice", "[Slice]\n")
    write(
        ".codex-plugin/plugin.json",
        json.dumps(
            {
                "name": "the-hive",
                "version": "0",
                "skills": "./skills/",
                "mcpServers": "./.mcp.json",
                "apps": "./.app.json",
                "hooks": "./hooks/hooks.json",
            }
        ),
    )
    write(
        ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "the-hive-mcp": {
                        "command": "/home/teladi/.local/lib/the-hive-runtime/the-hive-mcp",
                        "args": [],
                        "startup_timeout_sec": 120,
                        "note": "Local data-sparse Codex Masterjet MCP server. Controls the sleeping Agentinnen pool through tmux and does not return raw terminal output by default.",
                    }
                }
            }
        ),
    )
    write(".app.json", json.dumps({"apps": {"the-hive": {}}}))
    write("hooks/hooks.json", json.dumps({"hooks": {}}))
    write("skills/the-hive-fleet/SKILL.md", "---\nname: the-hive-fleet\n---\n")
    write(
        "codex-hive.json",
        json.dumps(
            {
                "schema_version": 1,
                "mode": "enforced",
                "principals": [
                    {
                        "principal_id": "queen-codex-master",
                        "class_id": "koenigin",
                        "parent_principal_id": "godbee-main",
                        "repo_id": "codex-master",
                    }
                ],
                "repositories": [
                    {
                        "repo_id": "codex-master",
                        "remote_identity": "https://example.invalid/the-hive.git",
                        "default_branch": "main",
                        "config_digest": "sha256:" + "c" * 64,
                    }
                ],
            }
        ),
    )
    write("codex-agent-classes.json", "{}")
    for relative in (
        "admission.py",
        "admission_runtime.py",
        "dynamic_pool.py",
        "hive/__init__.py",
        "hive/admission.py",
        "hive/dispatch.py",
        "hive/principals.py",
        "selection.py",
        "selection_service.py",
        "server.py",
    ):
        write(
            f"src/the_hive/{relative}",
            (ROOT / "src" / "the_hive" / relative).read_text(encoding="utf-8"),
        )
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o700)
    seal_runtime_image(root)
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    (root / ".the-hive-runtime-manifest.json").unlink()
    installer["_write_runtime_image_manifest"](root=root, commit=TEST_NON_F25_COMMIT)
    return RuntimeLayout.from_runtime_root(root)


def test_probe_evaluation_is_fail_closed_for_runtime_status_and_hive_evidence() -> None:
    result = evaluate(
        {"ok": False},
        {"mode": "shadow", "authority": "fail_closed", "state": "not_configured"},
        {
            "healthy": True,
            "checks": {
                "authority": "fail_closed",
                "repository": "not_configured",
                "state": "not_configured",
            },
        },
    )

    assert set(result) == {"checks", "global_pilot_readiness"}
    assert result["checks"] == {
        "runtime_layout": False,
        "hive_runtime": False,
        "hive_doctor": False,
    }
    assert result["global_pilot_readiness"]["pilot"] == "blocked"


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
        assert set(result) == {"checks", "global_pilot_readiness"}
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
        assert set(result) == {"checks", "global_pilot_readiness"}
        assert result["checks"]["hive_runtime"] is False

    result = evaluate(
        green_runtime_status(),
        {**base, "unexpected": "field"},
        doctor,
    )
    assert set(result) == {"checks", "global_pilot_readiness"}
    assert result["checks"]["hive_runtime"] is False


def test_bounded_global_pilot_readiness_drops_generation_id_for_malformed_input() -> (
    None
):
    malformed = green_probe(NOW.isoformat())["global_pilot_readiness"]
    assert isinstance(malformed, dict)
    malformed["reason_codes"] = "not-a-list"

    bounded = hourly_probe_module._bounded_global_pilot_readiness(malformed)

    assert bounded["pilot"] == "blocked"
    assert bounded["generation_id"] is None
    assert bounded["reason_codes"] == ["usage_invalid"]


def test_probe_has_exactly_eight_deterministic_utc_slots() -> None:
    assert DETERMINISTIC_PROBE_HOURS_UTC == (0, 3, 6, 9, 12, 15, 18, 21)
    assert len(DETERMINISTIC_PROBE_HOURS_UTC) == 8


def test_spawn_gate_accepts_only_a_fresh_complete_green_v3_record() -> None:
    fresh = green_probe(NOW.isoformat())
    assert probe_spawn_gate(fresh, now=NOW)["allowed"] is True
    assert probe_spawn_gate({"checks": {}}, now=NOW)["reason_code"] == "probe_ambiguous"
    assert (
        probe_spawn_gate({**fresh, "unexpected": True}, now=NOW)["reason_code"]
        == "probe_ambiguous"
    )
    assert (
        probe_spawn_gate(
            {**fresh, "checks": {"runtime_layout": True, "hive_runtime": True}}, now=NOW
        )["allowed"]
        is False
    )
    assert probe_spawn_gate({**fresh, "schema_version": 1}, now=NOW)["allowed"] is False
    assert (
        probe_spawn_gate(
            {**fresh, "commands": {**fresh["commands"], "runtime_status": False}},
            now=NOW,
        )["allowed"]
        is False
    )
    stale = NOW.replace(hour=0).isoformat()
    assert probe_spawn_gate(green_probe(stale), now=NOW)["reason_code"] == "probe_stale"
    assert MAX_PROBE_AGE_SECONDS == 4 * 60 * 60


def test_spawn_gate_reads_only_private_state_and_never_creates_missing_state(
    tmp_path: Path,
) -> None:
    state_file = tmp_path / "missing" / "hive-hourly-health.json"
    result = read_probe_gate(state_file=state_file, now=NOW)
    assert result == {
        "allowed": False,
        "reason_code": "probe_missing",
        "raw_output": "not_returned",
    }
    assert not state_file.parent.exists()

    state_file.parent.mkdir(mode=0o700)
    state_file.write_text(json.dumps(green_probe(NOW.isoformat())), encoding="utf-8")
    state_file.chmod(0o644)
    result = read_probe_gate(state_file=state_file, now=NOW)
    assert result["allowed"] is False
    assert result["reason_code"] == "probe_invalid"


def test_atomic_write_never_unlinks_a_foreign_temp_swapped_before_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_file = tmp_path / "hive-hourly-health.json"
    foreign_contents = b"foreign-probe-state-sentinel\x00preserve"
    displaced_private: Path | None = None
    foreign_temporary: Path | None = None

    def fail_after_swapping_temporary(source: Path, _destination: Path) -> None:
        nonlocal displaced_private, foreign_temporary
        displaced_private = source.with_name(f"{source.name}.private")
        source.rename(displaced_private)
        source.write_bytes(foreign_contents)
        foreign_temporary = source
        raise OSError(errno.EIO, "controlled replace failure")

    monkeypatch.setattr(
        hourly_probe_module.os, "replace", fail_after_swapping_temporary
    )

    with pytest.raises(ValueError, match="probe_state_write_failed"):
        hourly_probe_module._atomic_write(state_file, green_probe(NOW.isoformat()))

    assert displaced_private is not None and displaced_private.is_file()
    assert foreign_temporary is not None
    assert foreign_temporary.read_bytes() == foreign_contents


def test_run_probe_persists_only_one_schema_v3_health_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_directory = tmp_path / "state"
    layout = runtime_layout(tmp_path)
    calls: list[tuple[str, ...]] = []
    direct_status = green_runtime_status()
    green = {
        "hive status": (
            green_hive_runtime(),
            True,
        ),
        "hive doctor": (
            {
                "healthy": True,
                "checks": {
                    "authority": "ready",
                    "repository": "ready",
                    "state": "ready",
                },
            },
            True,
        ),
    }

    def runner(_command: Path, *arguments: str) -> tuple[dict[str, object], bool]:
        calls.append(arguments)
        return green[" ".join(arguments)]

    monkeypatch.setattr(
        hourly_probe_module, "runtime_status", lambda *, layout: direct_status
    )

    result = run_probe(
        layout=layout,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=runner,
    )
    assert set(result) == {
        "schema_version",
        "checked_at",
        "checks",
        "commands",
        "diagnostics",
        "alarm",
        "global_pilot_readiness",
    }
    assert result["schema_version"] == 3
    assert calls == [("hive", "status"), ("hive", "doctor")]
    assert (
        read_probe_gate(
            state_file=state_directory / "hive-hourly-health.json", now=NOW
        )["allowed"]
        is True
    )
    assert not (state_directory / "hive-hourly-alarm.json").exists()

    def red_runner(_command: Path, *arguments: str) -> tuple[dict[str, object], bool]:
        return green[" ".join(arguments)]

    direct_status = {"ok": False}
    result = run_probe(
        layout=layout,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=red_runner,
    )
    assert set(result) == {
        "schema_version",
        "checked_at",
        "checks",
        "commands",
        "diagnostics",
        "alarm",
        "global_pilot_readiness",
    }
    published = json.loads(
        (state_directory / "hive-hourly-health.json").read_text(encoding="utf-8")
    )
    assert published["alarm"] == {
        "scope": "hive",
        "status": "active",
        "reason_codes": ["runtime_layout"],
        "owner": {
            "principal_id": "queen-codex-master",
            "class_id": "koenigin",
            "repo_id": "codex-master",
        },
    }
    assert published["diagnostics"]["runtime_status"]["code"] == "runtime_status_red"
    assert not (state_directory / "hive-hourly-alarm.json").exists()


def test_run_probe_calls_runtime_status_outside_the_two_bounded_hive_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stage = runtime_layout(tmp_path)
    release_root = tmp_path / "release-root"
    generations = release_root / "generations"
    release_root.mkdir(mode=0o700)
    generations.mkdir(mode=0o700)
    generation = json.loads(
        (stage.root / ".the-hive-runtime-manifest.json").read_text(encoding="utf-8")
    )["generation"]
    assert isinstance(generation, str)
    target = generations / generation
    os.replace(stage.root, target)
    pointers = {
        "schema_version": 1,
        "current": {"generation": generation, "manifest_digest": stage.manifest_digest},
        "previous": None,
    }
    pointer = release_root / ".the-hive-release-pointers.json"
    pointer.write_text(json.dumps(pointers), encoding="utf-8")
    pointer.chmod(0o644)
    layout = RuntimeLayout.from_current_release(
        release_root, generation, stage.manifest_digest
    )
    status_layouts: list[RuntimeLayout] = []
    bounded_commands: list[tuple[tuple[str, ...], str]] = []

    def direct_status(*, layout: RuntimeLayout) -> dict[str, object]:
        status_layouts.append(layout)
        return green_runtime_status()

    def bounded(
        _layout: RuntimeLayout, _command: Path, *arguments: str, phase: str
    ) -> tuple[dict[str, object], bool]:
        bounded_commands.append((arguments, phase))
        binding = (str(release_root), generation, layout.manifest_digest)
        if arguments == (*binding, "hive", "status"):
            return green_hive_runtime(), True
        assert arguments == (*binding, "hive", "doctor")
        return (
            {
                "healthy": True,
                "checks": {
                    "authority": "ready",
                    "repository": "ready",
                    "state": "ready",
                },
            },
            True,
        )

    monkeypatch.setattr(hourly_probe_module, "runtime_status", direct_status)
    monkeypatch.setattr(hourly_probe_module, "_run_json", bounded)

    result = run_probe(
        layout=layout,
        state_directory=tmp_path / "state",
        now=lambda: NOW,
    )

    assert status_layouts == [layout]
    assert bounded_commands == [
        (
            (str(release_root), generation, layout.manifest_digest, "hive", "status"),
            "hive_status",
        ),
        (
            (str(release_root), generation, layout.manifest_digest, "hive", "doctor"),
            "hive_doctor",
        ),
    ]
    assert result["commands"]["runtime_status"] is True


def test_run_probe_emits_the_named_direct_mcp_timeout_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    layout = runtime_layout(tmp_path)
    monkeypatch.setattr(
        hourly_probe_module,
        "runtime_status",
        lambda *, layout: {
            **green_runtime_status(),
            "ok": False,
            "mcp_surface": {
                **green_runtime_status()["mcp_surface"],
                "ok": False,
                "reason_code": "mcp_timeout",
            },
        },
    )

    result = run_probe(
        layout=layout,
        state_directory=tmp_path / "state",
        now=lambda: NOW,
        runner=lambda _command, *arguments: (
            green_hive_runtime()
            if arguments == ("hive", "status")
            else {
                "healthy": True,
                "checks": {
                    "authority": "ready",
                    "repository": "ready",
                    "state": "ready",
                },
            },
            True,
        ),
    )

    assert result["checks"]["runtime_layout"] is False
    assert capsys.readouterr().err == (
        "runtime_image_probe_phase_timeout phase=direct_mcp limit_seconds=10\n"
    )


def test_bounded_hive_diagnostic_names_the_timed_out_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    layout = runtime_layout(tmp_path)

    def timed_out(*_args: object, **_kwargs: object) -> object:
        raise BoundedProcessError("command_timeout")

    monkeypatch.setattr(hourly_probe_module, "run_bounded", timed_out)

    assert hourly_probe_module._run_json(
        layout, layout.mcp_entrypoint, "hive", "doctor", phase="hive_doctor"
    ) == (
        {},
        False,
        {
            "code": "command_timeout",
            "exit_code": None,
            "stderr": {
                "state": "not_returned",
                "excerpt": "",
                "redaction_applied": False,
            },
        },
    )
    assert capsys.readouterr().err == (
        "runtime_image_probe_phase_timeout phase=hive_doctor limit_seconds=45\n"
    )


@pytest.mark.parametrize(
    ("completed", "expected"),
    (
        (
            BoundedProcessResult(returncode=7, stdout="{}", stderr="bounded error"),
            {
                "code": "command_exit_nonzero",
                "exit_code": 7,
                "stderr": {
                    "state": "present",
                    "excerpt": "bounded error",
                    "redaction_applied": False,
                },
            },
        ),
        (
            BoundedProcessResult(returncode=0, stdout="{", stderr=""),
            {
                "code": "command_json_invalid",
                "exit_code": 0,
                "stderr": {
                    "state": "empty",
                    "excerpt": "",
                    "redaction_applied": False,
                },
            },
        ),
    ),
)
def test_bounded_hive_diagnostic_persists_a_safe_command_cause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    completed: BoundedProcessResult,
    expected: dict[str, object],
) -> None:
    layout = runtime_layout(tmp_path)
    monkeypatch.setattr(
        hourly_probe_module, "run_bounded", lambda *_args, **_kwargs: completed
    )

    assert hourly_probe_module._run_json(
        layout, layout.mcp_entrypoint, "hive", "doctor", phase="hive_doctor"
    ) == ({}, False, expected)


def test_successful_hive_json_with_stderr_is_redacted_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catch a probe that treats a successful child warning as invisibly green."""

    layout = runtime_layout(tmp_path)
    monkeypatch.setattr(
        hourly_probe_module,
        "run_bounded",
        lambda *_args, **_kwargs: BoundedProcessResult(
            returncode=0,
            stdout="{}",
            stderr="api_token=supersecretvalue /private/path",
        ),
    )

    assert hourly_probe_module._run_json(
        layout, layout.mcp_entrypoint, "hive", "doctor", phase="hive_doctor"
    ) == (
        {},
        False,
        {
            "code": "command_stderr_warning",
            "exit_code": 0,
            "stderr": {
                "state": "present",
                "excerpt": "api_token=<redacted> /<redacted>",
                "redaction_applied": True,
            },
        },
    )


def test_hourly_probe_unit_remains_an_explicit_th_r3_boundary() -> None:
    timer = ROOT / "systemd" / "user" / "the-hive-hive-hourly-probe.timer"
    service = ROOT / "systemd" / "user" / "the-hive-hive-hourly-probe.service"
    timer_text = timer.read_text(encoding="utf-8")
    service_text = service.read_text(encoding="utf-8")
    service_lines = service_text.splitlines()
    assert "OnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC" in timer_text
    assert "RandomizedDelaySec" not in timer_text
    assert [line for line in service_lines if line.startswith("ProtectHome=")] == [
        "ProtectHome=tmpfs"
    ]
    assert [line for line in service_lines if "%t" in line] == [
        "BindReadOnlyPaths=%t:%t:norbind"
    ]
    assert "CODEX_MASTER_PROBE_REPOSITORY" not in service_text
    assert "%h/codex-master/src" not in service_text
    assert "%h/codex-master/bin/codex-master-mcp" not in service_text
    assert "%h/codex-master/codex-agent-classes.json" not in service_text
    assert "%h/codex-master/codex-hive.json" not in service_text
    assert (
        "BindReadOnlyPaths=%h/.local/lib/the-hive-runtime:%h/.local/lib/the-hive-runtime:norbind"
        in service_text
    )
    assert (
        "%h/.local/lib/the-hive-runtime/generations/@MASTERJET_GENERATION@:"
        not in service_text
    )
    assert "BindReadOnlyPaths=%h/.local:%h/.local" not in service_text
    assert (
        "BindPaths=%h/.local/state/codex-master-mcp:%h/.local/state/codex-master-mcp:norbind"
        in service_text
    )
    assert (
        "ExecStart=%h/.local/lib/the-hive-runtime/generations/@MASTERJET_GENERATION@/bin/the-hive-hive-hourly-probe %h/.local/lib/the-hive-runtime @MASTERJET_GENERATION@ @MASTERJET_MANIFEST_DIGEST@ --json"
        in service_text
    )
    assert "libexec" not in service_text
    assert "codex-master-hive-probe" not in service_text


def test_hourly_probe_service_renderer_rejects_a_generation_only_sandbox() -> None:
    """Installer must refuse a unit whose sandbox hides the release pointer authority."""

    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    template = (
        (ROOT / "systemd" / "user" / "the-hive-hive-hourly-probe.service")
        .read_bytes()
        .replace(
            b"BindReadOnlyPaths=%h/.local/lib/the-hive-runtime:%h/.local/lib/the-hive-runtime:norbind",
            b"BindReadOnlyPaths=%h/.local/lib/the-hive-runtime/generations/@MASTERJET_GENERATION@:%h/.local/lib/the-hive-runtime/generations/@MASTERJET_GENERATION@:norbind",
        )
    )

    with pytest.raises(install_error, match="install_release_template_invalid"):
        installer["_render_hourly_probe_service"](
            template,
            generation="a" * 40,
            manifest_digest="sha256:" + "b" * 64,
        )


def test_hourly_probe_runtime_wrapper_reports_each_local_failure_with_bounded_stderr(
    tmp_path: Path,
) -> None:
    """The service wrapper never turns a local attestation failure into silent exit 64."""

    wrapper = ROOT / "bin" / "the-hive-hive-hourly-probe"
    missing_arguments = subprocess.run(
        [wrapper], check=False, capture_output=True, text=True
    )
    invalid_arguments = subprocess.run(
        [wrapper, "relative-root", "generation", "sha256:" + "a" * 64],
        check=False,
        capture_output=True,
        text=True,
    )
    unavailable_layout = subprocess.run(
        [
            wrapper,
            str(tmp_path / "missing-release-root"),
            "generation",
            "sha256:" + "a" * 64,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    release_root = tmp_path / "release-root"
    generation = "generation"
    source = release_root / "generations" / generation / "src" / "the_hive"
    source.mkdir(mode=0o700, parents=True)
    (source / "__init__.py").write_text("", encoding="utf-8")
    (source / "runtime_layout.py").write_text(
        "\n".join(
            (
                "from pathlib import Path",
                "class RuntimeLayout:",
                "    @classmethod",
                "    def from_current_release(cls, root, generation, manifest_digest):",
                "        return type('Layout', (), {'root': Path('/different-root')})()",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    mismatched_layout = subprocess.run(
        [wrapper, str(release_root), generation, "sha256:" + "a" * 64],
        check=False,
        capture_output=True,
        text=True,
    )
    (source / "runtime_layout.py").write_text(
        "\n".join(
            (
                "from pathlib import Path",
                "class RuntimeLayout:",
                "    @classmethod",
                "    def from_current_release(cls, root, generation, manifest_digest):",
                "        return type('Layout', (), {'root': Path(root) / 'generations' / generation})()",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    probe_import_failure = subprocess.run(
        [wrapper, str(release_root), generation, "sha256:" + "a" * 64],
        check=False,
        capture_output=True,
        text=True,
    )

    for completed, code in (
        (missing_arguments, "arguments_missing"),
        (invalid_arguments, "arguments_invalid"),
        (unavailable_layout, "runtime_layout_unavailable"),
        (mismatched_layout, "runtime_layout_mismatch"),
        (probe_import_failure, "hourly_probe_load_failed"),
    ):
        assert completed.returncode == 64
        assert completed.stdout == ""
        assert completed.stderr == f"hive_hourly_probe_error code={code}\n"
        assert len(completed.stderr.encode("utf-8")) <= 128


def test_hourly_probe_direct_entrypoint_runs_without_an_argument(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        hourly_probe_module,
        "run_probe",
        lambda: {
            "checks": {
                "runtime_layout": True,
                "hive_runtime": True,
                "hive_doctor": True,
            }
        },
    )

    assert hourly_probe_module.main([]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "checks": {"runtime_layout": True, "hive_runtime": True, "hive_doctor": True},
        "global_pilot_readiness": {
            "schema_version": 1,
            "pilot": "blocked",
            "generation_id": None,
            "freshness": "unknown",
            "candidate_count": 0,
            "reason_codes": ["usage_missing"],
            "raw_output": "not_returned",
        },
    }


def test_hourly_probe_direct_entrypoint_reports_invalid_arguments(capsys) -> None:
    assert hourly_probe_module.main(["--unexpected"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "hive_hourly_probe_error code=arguments_invalid expected=--json\n"
    )


def test_hourly_probe_direct_entrypoint_explains_a_red_result(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        hourly_probe_module,
        "run_probe",
        lambda: {
            "checks": {
                "runtime_layout": True,
                "hive_runtime": False,
                "hive_doctor": True,
            },
            "global_pilot_readiness": {
                "schema_version": 1,
                "pilot": "blocked",
                "generation_id": None,
                "freshness": "fresh",
                "candidate_count": 1,
                "reason_codes": ["usage_generation_missing"],
                "raw_output": "not_returned",
            },
        },
    )

    assert hourly_probe_module.main([]) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "checks": {"runtime_layout": True, "hive_runtime": False, "hive_doctor": True},
        "global_pilot_readiness": {
            "schema_version": 1,
            "pilot": "blocked",
            "generation_id": None,
            "freshness": "fresh",
            "candidate_count": 1,
            "reason_codes": ["usage_generation_missing"],
            "raw_output": "not_returned",
        },
    }
    assert captured.err == "hive_hourly_probe_red failed_checks=hive_runtime\n"


def test_red_probe_publishes_a_hive_wide_alarm_for_the_repository_queen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_directory = tmp_path / "state"
    layout = runtime_layout(tmp_path)
    monkeypatch.setattr(
        hourly_probe_module, "runtime_status", lambda *, layout: {"ok": False}
    )

    result = run_probe(
        layout=layout,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=lambda _command, *arguments: (
            green_hive_runtime()
            if arguments == ("hive", "status")
            else {
                "healthy": True,
                "checks": {
                    "authority": "ready",
                    "repository": "ready",
                    "state": "ready",
                },
            },
            True,
        ),
    )

    assert result["checks"]["runtime_layout"] is False
    published = json.loads(
        (state_directory / "hive-hourly-health.json").read_text(encoding="utf-8")
    )
    assert published["alarm"] == {
        "scope": "hive",
        "status": "active",
        "reason_codes": ["runtime_layout"],
        "owner": {
            "principal_id": "queen-codex-master",
            "class_id": "koenigin",
            "repo_id": "codex-master",
        },
    }
    assert published["diagnostics"]["runtime_status"] == {
        "code": "runtime_status_red",
        "exit_code": None,
        "stderr": {
            "state": "not_returned",
            "excerpt": "",
            "redaction_applied": False,
        },
    }
    assert not (state_directory / "hive-hourly-alarm.json").exists()


def test_lifecycle_rollback_failure_publishes_the_same_fail_closed_hive_alarm(
    tmp_path: Path,
) -> None:
    state_directory = tmp_path / "state"
    layout = runtime_layout(tmp_path)

    result = hourly_probe_module.publish_lifecycle_failure(
        layout=layout,
        state_directory=state_directory,
        reason_code="runtime_lifecycle_rollback_failed",
        now=lambda: NOW,
    )

    assert result["checks"] == {
        "runtime_layout": False,
        "hive_runtime": False,
        "hive_doctor": False,
    }
    assert result["alarm"]["status"] == "active"
    assert result["alarm"]["owner"]["principal_id"] == "queen-codex-master"
    assert (
        result["diagnostics"]["runtime_status"]["code"]
        == "runtime_lifecycle_rollback_failed"
    )
    assert (
        read_probe_gate(
            state_file=state_directory / "hive-hourly-health.json", now=NOW
        )["allowed"]
        is False
    )


def test_spawn_gate_rejects_a_health_record_without_a_consistent_global_alarm() -> None:
    healthy = green_probe(NOW.isoformat())
    assert probe_spawn_gate(healthy, now=NOW)["allowed"] is True

    without_alarm = {key: value for key, value in healthy.items() if key != "alarm"}
    assert probe_spawn_gate(without_alarm, now=NOW)["reason_code"] == "probe_ambiguous"

    inconsistent = {
        **healthy,
        "alarm": {**healthy["alarm"], "status": "active", "reason_codes": []},
    }
    assert probe_spawn_gate(inconsistent, now=NOW)["reason_code"] == "probe_red"


def test_a_green_probe_closes_the_global_alarm_in_its_same_health_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_directory = tmp_path / "state"
    layout = runtime_layout(tmp_path)
    direct_status: dict[str, object] = {"ok": False}
    monkeypatch.setattr(
        hourly_probe_module, "runtime_status", lambda *, layout: direct_status
    )

    def runner(_command: Path, *arguments: str) -> tuple[dict[str, object], bool]:
        if arguments == ("hive", "status"):
            return green_hive_runtime(), True
        return (
            {
                "healthy": True,
                "checks": {
                    "authority": "ready",
                    "repository": "ready",
                    "state": "ready",
                },
            },
            True,
        )

    run_probe(
        layout=layout, state_directory=state_directory, now=lambda: NOW, runner=runner
    )
    direct_status = green_runtime_status()
    result = run_probe(
        layout=layout, state_directory=state_directory, now=lambda: NOW, runner=runner
    )

    assert result["alarm"]["status"] == "cleared"
    state_file = state_directory / "hive-hourly-health.json"
    assert read_probe_gate(state_file=state_file, now=NOW)["allowed"] is True
    assert (
        json.loads(state_file.read_text(encoding="utf-8"))["alarm"]["reason_codes"]
        == []
    )


def test_internal_attested_runtime_api_materializes_one_complete_regular_runtime_image(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    installer["_install_attested_runtime"].__globals__["_verified_release_commit"] = (
        lambda _repository: (  # type: ignore[index]
            "a" * 40
        )
    )
    installed = installer["_install_attested_runtime"](home=home)  # type: ignore[operator]
    assert installed["status"] == "installed"
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    pointers = json.loads(
        (release_root / ".the-hive-release-pointers.json").read_text(encoding="utf-8")
    )
    generation = pointers["current"]["generation"]
    runtime_root = release_root / "generations" / generation
    entrypoint = runtime_root / "bin" / "the-hive-hive-hourly-probe"
    entrypoint_stat = entrypoint.lstat()
    assert stat.S_ISREG(entrypoint_stat.st_mode)
    assert not entrypoint.is_symlink()
    assert stat.S_IMODE(entrypoint_stat.st_mode) == 0o755
    assert (
        stat.S_IMODE((home / ".local" / "state" / "codex-master-mcp").stat().st_mode)
        == 0o700
    )
    assert (
        stat.S_IMODE(
            (
                home
                / ".config"
                / "systemd"
                / "user"
                / "the-hive-hive-hourly-probe.service"
            )
            .stat()
            .st_mode
        )
        == 0o644
    )
    installed_service = (
        home / ".config" / "systemd" / "user" / "the-hive-hive-hourly-probe.service"
    )
    assert (
        f"TimeoutStartSec={math.ceil(hourly_probe_module.RUNTIME_IMAGE_PROBE_TOTAL_TIMEOUT_SECONDS)}s"
        in installed_service.read_text(encoding="utf-8")
    )
    installed_service_text = installed_service.read_text(encoding="utf-8")
    assert "@MASTERJET_" not in installed_service_text
    assert (
        "BindReadOnlyPaths=%h/.local/lib/the-hive-runtime:%h/.local/lib/the-hive-runtime:norbind"
        in installed_service_text
    )
    assert (
        f"BindReadOnlyPaths=%h/.local/lib/the-hive-runtime/generations/{generation}:"
        not in installed_service_text
    )
    assert "BindReadOnlyPaths=%h/.local:%h/.local" not in installed_service_text
    assert (
        "ExecStart=%h/.local/lib/the-hive-runtime/generations/"
        f"{generation}/bin/the-hive-hive-hourly-probe "
        "%h/.local/lib/the-hive-runtime "
        f"{generation} {installed['manifest_digest']} --json"
    ) in installed_service_text
    installed_cli = runtime_root / "bin" / "the-hive-mcp"
    installed_source = runtime_root / "src" / "the_hive" / "hive" / "hourly_probe.py"
    for path, mode in (
        (installed_cli, 0o755),
        (installed_source, 0o644),
        (
            runtime_root / "src" / "the_hive" / "runtime_spawn_helper.c",
            0o644,
        ),
        (
            runtime_root / "src" / "the_hive" / "_runtime_spawn_helper.so",
            0o755,
        ),
        (runtime_root / ".codex-plugin" / "plugin.json", 0o644),
        (runtime_root / ".mcp.json", 0o644),
        (runtime_root / ".app.json", 0o644),
        (runtime_root / "hooks" / "hooks.json", 0o644),
        (runtime_root / "skills" / "the-hive-fleet" / "SKILL.md", 0o644),
        (runtime_root / "codex-hive.json", 0o644),
        (runtime_root / "codex-agent-classes.json", 0o644),
    ):
        item = path.lstat()
        assert stat.S_ISREG(item.st_mode)
        assert not path.is_symlink()
        assert stat.S_IMODE(item.st_mode) == mode
    assert not any(path.is_symlink() for path in runtime_root.rglob("*"))
    assert stat.S_IMODE(release_root.lstat().st_mode) == 0o700
    assert stat.S_IMODE(runtime_root.lstat().st_mode) == 0o700
    for path in runtime_root.rglob("*"):
        item = path.lstat()
        if stat.S_ISDIR(item.st_mode):
            assert stat.S_IMODE(item.st_mode) == 0o700
        else:
            assert stat.S_ISREG(item.st_mode)
            assert item.st_nlink == 1
    legacy_probe = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    assert legacy_probe.is_file()
    assert not legacy_probe.is_symlink()
    assert stat.S_IMODE(legacy_probe.lstat().st_mode) == 0o755
    assert not (home / ".local" / "lib" / "codex-master-hive-probe").exists()
    assert not (home / ".local" / "bin" / "codex-master-mcp").exists()

    environment = {
        "HOME": str(home),
        "PATH": "/attacker/path",
        "PYTHONPATH": "/attacker/python",
        "CODEX_HOME": str(tmp_path / "attacker-codex-home"),
        "CODEX_MASTER_MCP_STATE": str(tmp_path / "attacker-state"),
    }
    runtime_status = subprocess.run(
        [
            installed_cli,
            release_root,
            generation,
            installed["manifest_digest"],
            "hive",
            "runtime-status",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
    )
    assert runtime_status.returncode == 0, runtime_status.stderr
    assert json.loads(runtime_status.stdout)["ok"] is True
    direct_mcp = subprocess.run(
        [installed_cli, release_root, generation, installed["manifest_digest"]],
        check=False,
        capture_output=True,
        input=(
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}\n'
            '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'
            '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
        ),
        text=True,
        env=environment,
        cwd=tmp_path,
    )
    assert direct_mcp.returncode == 0, direct_mcp.stderr
    responses = [json.loads(line) for line in direct_mcp.stdout.splitlines()]
    tools_response = next(response for response in responses if response.get("id") == 2)
    tool_names = {tool["name"] for tool in tools_response["result"]["tools"]}
    assert tool_names == {"runtime_status"}
    legacy_completed = subprocess.run(
        [legacy_probe],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
    )
    assert legacy_completed.returncode in {0, 1}, legacy_completed.stderr
    assert set(json.loads(legacy_completed.stdout)) == {"checks"}
    if legacy_completed.returncode == 1:
        assert legacy_completed.stderr.startswith(
            "hive_hourly_probe_red failed_checks="
        )
    else:
        assert legacy_completed.stderr == ""
    assert not list(runtime_root.rglob("__pycache__"))


def test_probe_installer_upgrades_a_valid_83_generation_only_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exact 83abaae unit is replaced, never accepted as post-install authority."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    release_commit = {"value": "a" * 40}
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,
        "_verified_release_commit",
        lambda _repository: release_commit["value"],
    )
    first = installer["_install_attested_runtime"](home=home)
    first_generation = first["generation"]
    assert isinstance(first_generation, str)
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    service = (
        home / ".config" / "systemd" / "user" / "the-hive-hive-hourly-probe.service"
    )
    root_binding = (
        "BindReadOnlyPaths=%h/.local/lib/the-hive-runtime:"
        "%h/.local/lib/the-hive-runtime:norbind"
    )
    legacy_binding = (
        "BindReadOnlyPaths=%h/.local/lib/the-hive-runtime/generations/"
        f"{first_generation}:%h/.local/lib/the-hive-runtime/generations/"
        f"{first_generation}:norbind"
    )
    current_service = service.read_text(encoding="utf-8")
    legacy_service = current_service.replace(
        "# RuntimeLayout attests the release pointer and both retained generations.\n"
        + root_binding,
        legacy_binding,
    )
    assert legacy_service != current_service
    service.write_text(legacy_service, encoding="utf-8")
    service.chmod(0o644)
    with pytest.raises(
        installer["InstallError"], match="install_release_retention_failed"
    ):
        installer["_unit_bound_generation"](release_root=release_root, source=service)

    release_commit["value"] = "b" * 40
    upgraded = installer["_install_attested_runtime"](home=home)

    upgraded_generation = upgraded["generation"]
    assert upgraded_generation == "b" * 40
    upgraded_service = service.read_text(encoding="utf-8")
    assert root_binding in upgraded_service
    assert legacy_binding not in upgraded_service
    assert (
        installer["_unit_bound_generation"](release_root=release_root, source=service)
        == upgraded_generation
    )
    pointers = json.loads(
        (release_root / ".the-hive-release-pointers.json").read_text(encoding="utf-8")
    )
    assert pointers["current"]["generation"] == upgraded_generation
    assert pointers["previous"]["generation"] == first_generation


def test_internal_attested_runtime_api_rolls_back_unit_pair_after_timer_materialization_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed timer replacement leaves a complete old pair and a retryable release."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    release_commit = {"value": "a" * 40}
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,
        "_verified_release_commit",
        lambda _repository: release_commit["value"],
    )
    first = installer["_install_attested_runtime"](home=home)
    first_generation = first["generation"]
    assert isinstance(first_generation, str)
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    units = home / ".config" / "systemd" / "user"
    service = units / "the-hive-hive-hourly-probe.service"
    timer = units / "the-hive-hive-hourly-probe.timer"
    old_service = service.read_bytes()
    old_timer = timer.read_bytes()
    old_pointers = (release_root / ".the-hive-release-pointers.json").read_bytes()
    install_attested_bytes = installer["_install_attested_bytes"]

    def fail_timer(target: Path, content: bytes, *, mode: int) -> None:
        if target == timer:
            raise installer["InstallError"]("install_target_untrusted")
        install_attested_bytes(target, content, mode=mode)

    release_commit["value"] = "b" * 40
    monkeypatch.setitem(
        installer["_materialize_hourly_probe_units"].__globals__,
        "_install_attested_bytes",
        fail_timer,
    )
    with pytest.raises(installer["InstallError"], match="install_target_untrusted"):
        installer["_install_attested_runtime"](home=home)

    assert service.read_bytes() == old_service
    assert timer.read_bytes() == old_timer
    assert (
        release_root / ".the-hive-release-pointers.json"
    ).read_bytes() == old_pointers
    assert not (release_root / "generations" / ("b" * 40)).exists()

    monkeypatch.setitem(
        installer["_materialize_hourly_probe_units"].__globals__,
        "_install_attested_bytes",
        install_attested_bytes,
    )
    retried = installer["_install_attested_runtime"](home=home)

    assert retried["generation"] == "b" * 40
    assert (
        installer["_unit_bound_generation"](release_root=release_root, source=service)
        == retried["generation"]
    )


def test_legacy_probe_refuses_tampered_release_metadata_before_running_the_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,
        "_verified_release_commit",
        lambda _repository: "a" * 40,
    )
    installed = installer["_install_attested_runtime"](home=home)
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    pointer = release_root / ".the-hive-release-pointers.json"
    pointer_original = pointer.read_bytes()
    pointer_mode = stat.S_IMODE(pointer.lstat().st_mode)
    generation = installed["generation"]
    assert isinstance(generation, str)
    entrypoint = (
        release_root / "generations" / generation / "bin" / "the-hive-hive-hourly-probe"
    )
    entrypoint_original = entrypoint.read_bytes()
    legacy_probe = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    pointer.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "current": {
                    "generation": generation,
                    "manifest_digest": installed["manifest_digest"],
                },
                "previous": {
                    "generation": "b" * 40,
                    "manifest_digest": "sha256:" + "b" * 64,
                },
            }
        ),
        encoding="utf-8",
    )
    pointer.chmod(pointer_mode)
    environment = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    corrupted_pointer = subprocess.run(
        [legacy_probe], check=False, capture_output=True, text=True, env=environment
    )
    assert corrupted_pointer.returncode == 2
    assert corrupted_pointer.stdout == ""
    assert corrupted_pointer.stderr == (
        "hive_hourly_probe_error code=legacy_probe_attestation_failed\n"
    )

    pointer.write_bytes(pointer_original)
    pointer.chmod(pointer_mode)
    entrypoint.write_text("#!/bin/sh\nprintf 'entrypoint-ran\\n'\n", encoding="utf-8")
    entrypoint.chmod(0o755)
    corrupted_entrypoint = subprocess.run(
        [legacy_probe], check=False, capture_output=True, text=True, env=environment
    )
    assert corrupted_entrypoint.returncode == 2
    assert corrupted_entrypoint.stdout == ""
    assert corrupted_entrypoint.stderr == (
        "hive_hourly_probe_error code=legacy_probe_attestation_failed\n"
    )

    entrypoint.write_bytes(entrypoint_original)
    entrypoint.chmod(0o755)


def test_legacy_probe_never_imports_runtime_image_before_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catch a launcher that executes a tampered image attester before rejection."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,
        "_verified_release_commit",
        lambda _repository: "a" * 40,
    )
    installed = installer["_install_attested_runtime"](home=home)
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    generation = installed["generation"]
    assert isinstance(generation, str)
    marker = tmp_path / "runtime-image-imported"
    runtime_layout = (
        release_root
        / "generations"
        / generation
        / "src"
        / "the_hive"
        / "runtime_layout.py"
    )
    runtime_layout.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    runtime_layout.chmod(0o644)
    legacy_probe = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"

    completed = subprocess.run(
        [legacy_probe],
        check=False,
        capture_output=True,
        text=True,
        env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr == (
        "hive_hourly_probe_error code=legacy_probe_attestation_failed\n"
    )
    assert not marker.exists()


def test_legacy_probe_rejects_preexisting_image_bytecode_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catch a launcher that permits unmanifested bytecode into the image."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,
        "_verified_release_commit",
        lambda _repository: "a" * 40,
    )
    installed = installer["_install_attested_runtime"](home=home)
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    generation = installed["generation"]
    assert isinstance(generation, str)
    bytecode = (
        release_root / "generations" / generation / "src" / "the_hive" / "__pycache__"
    )
    bytecode.mkdir(mode=0o700)
    (bytecode / "runtime_layout.cpython-313.pyc").write_bytes(b"untrusted")
    (bytecode / "runtime_layout.cpython-313.pyc").chmod(0o644)
    legacy_probe = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"

    completed = subprocess.run(
        [legacy_probe],
        check=False,
        capture_output=True,
        text=True,
        env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr == (
        "hive_hourly_probe_error code=legacy_probe_attestation_failed\n"
    )


def test_legacy_probe_executes_the_attested_entry_by_pinned_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catch a post-attestation path swap before a legacy probe can execute it."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,
        "_verified_release_commit",
        lambda _repository: "a" * 40,
    )
    installed = installer["_install_attested_runtime"](home=home)
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    generation = installed["generation"]
    assert isinstance(generation, str)
    entrypoint = (
        release_root / "generations" / generation / "bin" / "the-hive-hive-hourly-probe"
    )
    original = entrypoint.stat()
    legacy_probe = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    shim = runpy.run_path(str(legacy_probe), run_name="legacy_probe_fd_test")

    class PinnedExec(BaseException):
        pass

    class UnexpectedPathExecution(BaseException):
        pass

    def unexpected_run_module(*_args: object, **_kwargs: object) -> object:
        raise UnexpectedPathExecution

    def pinned_exec(
        path: str, _arguments: list[str], _environment: dict[str, str]
    ) -> None:
        replacement = entrypoint.with_name(".probe-entrypoint-replacement")
        replacement.write_text("#!/usr/bin/bash\nexit 99\n", encoding="utf-8")
        replacement.chmod(0o755)
        os.replace(replacement, entrypoint)
        descriptor = int(Path(path).name)
        pinned = os.fstat(descriptor)
        assert path == f"/proc/self/fd/{descriptor}"
        assert (pinned.st_dev, pinned.st_ino) == (original.st_dev, original.st_ino)
        raise PinnedExec

    monkeypatch.setattr(runpy, "run_module", unexpected_run_module)
    monkeypatch.setattr(shim["os"], "execve", pinned_exec)
    monkeypatch.setattr(shim["sys"], "argv", [str(legacy_probe)])

    with pytest.raises(PinnedExec):
        shim["main"]()


def test_stage_validation_uses_the_shared_hive_diagnostic_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    layout = runtime_layout(tmp_path)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    observed_timeouts: list[float] = []

    monkeypatch.setattr(
        installer["hourly_probe"], "HIVE_DIAGNOSTIC_TIMEOUT_SECONDS", 7.25
    )
    installer["_validate_runtime_image_stage"].__globals__["_mcp_surface"] = (
        lambda *_args: {"ok": True}
    )

    def bounded(*_args: object, timeout_seconds: float, **_kwargs: object) -> object:
        observed_timeouts.append(timeout_seconds)
        return BoundedProcessResult(returncode=0, stdout="{}", stderr="")

    installer["_validate_runtime_image_stage"].__globals__["run_bounded"] = bounded

    installer["_validate_runtime_image_stage"](stage=layout.root, home=home)

    assert observed_timeouts == [7.25, 7.25, 7.25]


def test_hourly_probe_from_a_complete_image_checks_runtime_status_without_recursion(
    tmp_path: Path, runtime_image
) -> None:
    """The image's real probe must keep runtime-status outside a second runner."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    environment = {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    release_root = tmp_path / "the-hive-runtime"
    generations = release_root / "generations"
    release_root.mkdir(mode=0o700)
    generations.mkdir(mode=0o700)
    generation = json.loads(
        (runtime_image.root / ".the-hive-runtime-manifest.json").read_text(
            encoding="utf-8"
        )
    )["generation"]
    assert isinstance(generation, str)
    target = generations / generation
    os.replace(runtime_image.root, target)
    pointers = {
        "schema_version": 1,
        "current": {
            "generation": generation,
            "manifest_digest": runtime_image.manifest_digest,
        },
        "previous": None,
    }
    pointer = release_root / ".the-hive-release-pointers.json"
    pointer.write_text(json.dumps(pointers), encoding="utf-8")
    pointer.chmod(0o644)

    try:
        completed = subprocess.run(
            [
                target / "bin" / "the-hive-hive-hourly-probe",
                release_root,
                generation,
                runtime_image.manifest_digest,
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
            cwd=tmp_path,
            env=environment,
            timeout=hourly_probe_module.RUNTIME_IMAGE_PROBE_TOTAL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        phase_limits = ", ".join(
            f"{name}={seconds:g}s"
            for name, seconds in hourly_probe_module.RUNTIME_IMAGE_PROBE_PHASE_TIMEOUTS
        )
        pytest.fail(f"runtime_image_probe_total_timeout ({phase_limits}): {exc}")

    assert completed.returncode in {0, 1}, completed.stderr
    assert json.loads(completed.stdout)["checks"]["runtime_layout"] is True
    state = json.loads(
        (
            home / ".local" / "state" / "codex-master-mcp" / "hive-hourly-health.json"
        ).read_text(encoding="utf-8")
    )
    assert state["commands"]["runtime_status"] is True


def test_installer_source_reader_is_no_follow_descriptor_bounded(
    tmp_path: Path,
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
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
    assert ".read_bytes(" not in (
        ROOT / "scripts" / "the-hive-hive-hourly-probe-install"
    ).read_text(encoding="utf-8")


def test_install_regular_failure_never_unlinks_a_swapped_foreign_unit_tempfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    source = tmp_path / "source.service"
    source.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    target = tmp_path / "units" / "codex-master-hive-hourly-probe.service"
    target.parent.mkdir(mode=0o700)
    displaced_private_temp = tmp_path / "displaced-private-unit-temp"
    foreign_sentinel = b"foreign unit sentinel\n"
    swapped: list[Path] = []
    replace = os.replace

    def swap_then_fail(source_path: Path, _target_path: Path) -> None:
        temporary = Path(source_path)
        replace(temporary, displaced_private_temp)
        temporary.write_bytes(foreign_sentinel)
        swapped.append(temporary)
        raise OSError(errno.EIO, "injected replace failure")

    monkeypatch.setattr(installer["os"], "replace", swap_then_fail)

    with pytest.raises(install_error, match="install_target_untrusted"):
        installer["_install_regular"](source, target, mode=0o644)

    assert len(swapped) == 1
    assert swapped[0].read_bytes() == foreign_sentinel
    assert displaced_private_temp.read_text(encoding="utf-8").startswith("[Service]")


def test_manifest_failure_never_unlinks_a_swapped_foreign_manifest_tempfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    root = tmp_path / "runtime-image"
    root.mkdir(mode=0o700)
    installer["_build_runtime_image"](
        repository=ROOT, stage=root, commit=TEST_NON_F25_COMMIT
    )
    (root / ".the-hive-runtime-manifest.json").unlink()
    displaced_private_temp = tmp_path / "displaced-private-manifest-temp"
    foreign_sentinel = b"foreign manifest sentinel\n"
    swapped: list[Path] = []
    replace = os.replace

    def swap_then_fail(source_path: Path, _target_path: Path) -> None:
        temporary = Path(source_path)
        replace(temporary, displaced_private_temp)
        temporary.write_bytes(foreign_sentinel)
        swapped.append(temporary)
        raise OSError(errno.EIO, "injected replace failure")

    monkeypatch.setattr(installer["os"], "replace", swap_then_fail)

    with pytest.raises(install_error, match="install_target_untrusted"):
        installer["_write_runtime_image_manifest"](
            root=root, commit=TEST_NON_F25_COMMIT
        )

    assert len(swapped) == 1
    assert swapped[0].read_bytes() == foreign_sentinel
    assert displaced_private_temp.exists()


def test_runtime_spawn_helper_build_fails_closed_before_image_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)

    class FailedCompiler:
        returncode = 1

    monkeypatch.setattr(
        installer["subprocess"], "run", lambda *_args, **_kwargs: FailedCompiler()
    )

    with pytest.raises(install_error, match="install_runtime_helper_unavailable"):
        installer["_compile_runtime_spawn_helper"](stage=stage)

    assert not (stage / "src" / "the_hive" / "_runtime_spawn_helper.so").exists()


def test_image_only_install_publishes_a_validated_stage_with_an_authorized_queen_home(
    tmp_path: Path,
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _write_authorized_queen_registry(home)
    library = home / ".local" / "lib"
    library.mkdir(mode=0o700, parents=True)
    legacy_root = library / "codex-master-hive-probe"
    legacy_root.mkdir(mode=0o700)
    legacy_marker = legacy_root / "foreign-marker"
    legacy_marker.write_text("legacy root\n", encoding="utf-8")
    legacy_libexec = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    legacy_libexec.parent.mkdir(mode=0o700, parents=True)
    legacy_libexec.write_text("legacy libexec\n", encoding="utf-8")
    foreign_bin_target = home / "foreign-mcp"
    foreign_bin_target.write_text("legacy bin target\n", encoding="utf-8")
    legacy_bin = home / ".local" / "bin" / "codex-master-mcp"
    legacy_bin.parent.mkdir(mode=0o700, parents=True)
    legacy_bin.symlink_to(foreign_bin_target)

    installer["_install_attested_runtime"].__globals__["_verified_release_commit"] = (
        lambda _repository: (  # type: ignore[index]
            "a" * 40
        )
    )
    result = installer["_install_attested_runtime"](home=home)

    runtime_root = library / "the-hive-runtime"
    generation = result["generation"]
    assert result["status"] == "installed"
    assert result["raw_output"] == "not_returned"
    assert isinstance(generation, str)
    assert (
        runtime_root / "generations" / generation / "bin" / "the-hive-mcp"
    ).is_file()
    assert (
        RuntimeLayout.from_current_release(
            runtime_root, generation, result["manifest_digest"]
        ).root
        == runtime_root / "generations" / generation
    )
    assert legacy_marker.read_text(encoding="utf-8") == "legacy root\n"
    assert legacy_libexec.read_text(encoding="utf-8") != "legacy libexec\n"
    assert not legacy_libexec.is_symlink()
    assert stat.S_IMODE(legacy_libexec.lstat().st_mode) == 0o755
    assert legacy_bin.is_symlink()
    assert legacy_bin.readlink() == foreign_bin_target


def test_d89_successor_witness_has_no_dynamic_historical_checkout_contract() -> None:
    installer_path = ROOT / "scripts" / "the-hive-hive-hourly-probe-install"
    installer = runpy.run_path(str(installer_path))
    source = installer_path.read_text(encoding="utf-8")
    assert "23510da" not in source
    assert "git show" not in source
    assert installer["_HISTORICAL_LINEAGE"] == {
        "d69": {
            "commit": "f25f60f6010d7b74b82a57f6471618e16df3e1a6",
            "tree": "0f459eea9d8e13bd54e74e699272c53cddaecb1d",
            "parent": "c4b72abcfe0e8b208b05f90cc4f8275def851581",
            "dynamic_pool_blob": "36c1e4a2716f808dc2ac89fe0d604249b1639ddd",
        },
        "d73": {
            "commit": "f6f9348a4348d1a18bb3c4b591a93c393dfda838",
            "tree": "d4f9620d25b0053763a6d20d0dfacbb8bd9a40ff",
            "parent": "f25f60f6010d7b74b82a57f6471618e16df3e1a6",
        },
    }


def test_runtime_image_stage_validation_runs_only_the_three_v2_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    installer["_build_runtime_image"](
        repository=ROOT, stage=stage, commit=TEST_NON_F25_COMMIT
    )
    observed: list[tuple[str, ...]] = []

    class Completed:
        def __init__(self, returncode: int, stdout: str) -> None:
            self.returncode = returncode
            self.stdout = stdout

    def run(command: list[str], **_kwargs: object) -> Completed:
        observed.append(tuple(command))
        return Completed(0, json.dumps({"status": "ready"}))

    monkeypatch.setitem(
        installer["_validate_runtime_image_stage"].__globals__, "run_bounded", run
    )
    monkeypatch.setitem(
        installer["_validate_runtime_image_stage"].__globals__,
        "_mcp_surface",
        lambda *_args: {"ok": True},
    )
    installer["_validate_runtime_image_stage"](stage=stage, home=tmp_path / "home")

    stage_server = (
        "import runpy, sys\n"
        "from pathlib import Path\n"
        "root = Path(sys.argv[1])\n"
        "sys.path.insert(0, str(root / 'src'))\n"
        "sys.argv = [str(root / 'src' / 'the_hive' / 'server.py'), *sys.argv[2:]]\n"
        "runpy.run_module('the_hive.server', run_name='__main__', alter_sys=True)\n"
    )
    assert observed == [
        (
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            stage_server,
            str(stage),
            "--runtime-status-mcp",
        ),
        (
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            stage_server,
            str(stage),
            "hive",
            "status",
        ),
        (
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            stage_server,
            str(stage),
            "hive",
            "doctor",
        ),
    ]


def test_named_runtime_generation_publish_failure_keeps_the_attested_current_pointer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    release_root = tmp_path / "the-hive-runtime"
    first = tmp_path / ".the-hive-runtime.stage.first"
    first.mkdir(mode=0o700)
    installer["_build_runtime_image"](
        repository=ROOT, stage=first, generation="first", commit=TEST_NON_F25_COMMIT
    )
    installer["_publish_runtime_generation"](stage=first, release_root=release_root)
    old_pointers = (release_root / ".the-hive-release-pointers.json").read_bytes()
    second = tmp_path / ".the-hive-runtime.stage.second"
    second.mkdir(mode=0o700)
    installer["_build_runtime_image"](
        repository=ROOT, stage=second, generation="second", commit=TEST_NON_F25_COMMIT
    )

    def fail_pointer(*_args: object, **_kwargs: object) -> None:
        raise installer["InstallError"]("install_release_pointer_write_failed")

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,
        "_write_release_pointers",
        fail_pointer,
    )
    with pytest.raises(
        installer["InstallError"], match="install_release_pointer_write_failed"
    ):
        installer["_publish_runtime_generation"](
            stage=second, release_root=release_root
        )

    assert (
        release_root / ".the-hive-release-pointers.json"
    ).read_bytes() == old_pointers
    current = json.loads(old_pointers)["current"]
    assert (
        RuntimeLayout.from_current_release(
            release_root, current["generation"], current["manifest_digest"]
        ).root
        == release_root / "generations" / "first"
    )


def test_runtime_image_build_failure_never_publishes_a_partial_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = library / "the-hive-runtime"
    target.mkdir(mode=0o700)
    (target / "old-complete-image").write_text("old\n", encoding="utf-8")
    stage = library / ".the-hive-runtime.stage.test"
    stage.mkdir(mode=0o700)

    def fail_copy(*_args: object, **_kwargs: object) -> None:
        raise install_error("install_source_untrusted")

    monkeypatch.setitem(
        installer["_build_runtime_image"].__globals__, "_install_regular", fail_copy
    )
    with pytest.raises(install_error, match="install_source_untrusted"):
        installer["_build_runtime_image"](
            repository=ROOT, stage=stage, commit=TEST_NON_F25_COMMIT
        )

    assert (target / "old-complete-image").read_text(encoding="utf-8") == "old\n"
    assert not (target / "new-complete-image").exists()
    assert stage.is_dir()
    assert not (stage / "new-complete-image").exists()


def test_probe_capacity_guard_serializes_the_health_record_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_directory = tmp_path / "state"
    layout = runtime_layout(tmp_path)
    healthy = {
        "hive runtime-status": (green_runtime_status(), True),
        "hive status": (green_hive_runtime(), True),
        "hive doctor": (
            {
                "healthy": True,
                "checks": {
                    "authority": "ready",
                    "repository": "ready",
                    "state": "ready",
                },
            },
            True,
        ),
    }

    def green_runner(_command: Path, *arguments: str) -> tuple[dict[str, object], bool]:
        return healthy[" ".join(arguments)]

    monkeypatch.setattr(
        hourly_probe_module, "runtime_status", lambda *, layout: green_runtime_status()
    )

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
    with hourly_probe_module.probe_capacity_guard(
        state_file=state_file, now=NOW
    ) as gate:
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
    tmp_path: Path, error_type: type[Exception], monkeypatch: pytest.MonkeyPatch
) -> None:
    state_directory = tmp_path / "state"
    layout = runtime_layout(tmp_path)
    healthy = {
        "hive runtime-status": (green_runtime_status(), True),
        "hive status": (green_hive_runtime(), True),
        "hive doctor": (
            {
                "healthy": True,
                "checks": {
                    "authority": "ready",
                    "repository": "ready",
                    "state": "ready",
                },
            },
            True,
        ),
    }
    monkeypatch.setattr(
        hourly_probe_module, "runtime_status", lambda *, layout: green_runtime_status()
    )
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
