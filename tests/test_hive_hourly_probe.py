from __future__ import annotations

import json
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
        json.dumps(
            {
                "name": "codex-master",
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
                    "codex-master-mcp": {
                        "command": "./bin/codex-master-mcp",
                        "args": [],
                    }
                }
            }
        ),
    )
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
        {
            "healthy": True,
            "checks": {
                "authority": "fail_closed",
                "repository": "not_configured",
                "state": "not_configured",
            },
        },
    )

    assert set(result) == {"checks"}
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
        assert set(result) == {"checks"}
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
        assert set(result) == {"checks"}
        assert result["checks"]["hive_runtime"] is False

    result = evaluate(
        green_runtime_status(),
        {**base, "unexpected": "field"},
        doctor,
    )
    assert set(result) == {"checks"}
    assert result["checks"]["hive_runtime"] is False


def test_probe_has_exactly_eight_deterministic_utc_slots() -> None:
    assert DETERMINISTIC_PROBE_HOURS_UTC == (0, 3, 6, 9, 12, 15, 18, 21)
    assert len(DETERMINISTIC_PROBE_HOURS_UTC) == 8


def test_spawn_gate_accepts_only_a_fresh_complete_green_v2_record() -> None:
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

    result = run_probe(
        layout=layout,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=runner,
    )
    assert set(result) == {"schema_version", "checked_at", "checks", "commands"}
    assert result["schema_version"] == 2
    assert calls == [("hive", "runtime-status"), ("hive", "status"), ("hive", "doctor")]
    assert (
        read_probe_gate(
            state_file=state_directory / "hive-hourly-health.json", now=NOW
        )["allowed"]
        is True
    )
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
    assert set(result) == {"schema_version", "checked_at", "checks", "commands"}
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
    assert (
        "%h/.local/lib/codex-master-runtime:%h/.local/lib/codex-master-runtime:norbind"
        in service_text
    )
    assert (
        "BindPaths=%h/.local/state/codex-master-mcp:%h/.local/state/codex-master-mcp:norbind"
        in service_text
    )
    assert (
        "ExecStart=%h/.local/lib/codex-master-runtime/bin/codex-master-hive-hourly-probe --json"
        in service_text
    )
    assert "libexec" not in service_text
    assert "codex-master-hive-probe" not in service_text


def test_hourly_probe_direct_entrypoint_requires_json_mode(monkeypatch, capsys) -> None:
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

    assert hourly_probe_module.main(["--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "checks": {"runtime_layout": True, "hive_runtime": True, "hive_doctor": True},
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
                / "codex-master-hive-hourly-probe.service"
            )
            .stat()
            .st_mode
        )
        == 0o644
    )
    installed_cli = runtime_root / "bin" / "codex-master-mcp"
    installed_source = (
        runtime_root / "src" / "codex_master" / "hive" / "hourly_probe.py"
    )
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
    assert not (
        home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    ).exists()
    assert not (home / ".local" / "lib" / "codex-master-hive-probe").exists()
    assert not (home / ".local" / "bin" / "codex-master-mcp").exists()

    environment = {
        "HOME": str(home),
        "PATH": "/attacker/path",
        "PYTHONPATH": "/attacker/python",
        "CODEX_HOME": str(tmp_path / "attacker-codex-home"),
        "CODEX_MASTER_MCP_STATE": str(tmp_path / "attacker-state"),
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
    assert set(json.loads(completed.stdout)) == {"checks"}
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
    direct_mcp = subprocess.run(
        [installed_cli],
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
    health = home / ".local" / "state" / "codex-master-mcp" / "hive-hourly-health.json"
    health_stat = health.lstat()
    assert stat.S_ISREG(health_stat.st_mode)
    assert not health.is_symlink()
    assert stat.S_IMODE(health_stat.st_mode) == 0o600
    assert (
        json.loads(health.read_text(encoding="utf-8"))["checks"]["runtime_layout"]
        is True
    )
    assert not list(runtime_root.rglob("__pycache__"))


def test_installer_source_reader_is_no_follow_descriptor_bounded(
    tmp_path: Path,
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
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
        ROOT / "scripts" / "codex-master-hive-hourly-probe-install"
    ).read_text(encoding="utf-8")


def _sealed_publish_image(
    installer: dict[str, object], root: Path, marker: str
) -> Path:
    root.mkdir(mode=0o700)
    payload = root / marker
    payload.write_text(marker + "\n", encoding="utf-8")
    payload.chmod(0o644)
    installer["_write_runtime_image_manifest"](root=root)  # type: ignore[operator]
    return root


def _legacy_cleanup_parents(home: Path) -> None:
    for relative in (".local/lib", ".local/libexec", ".local/bin"):
        (home / relative).mkdir(mode=0o700, parents=True, exist_ok=True)


def test_runtime_image_publish_rejects_a_foreign_sentinel_before_exchange(
    tmp_path: Path,
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = _sealed_publish_image(
        installer, library / "codex-master-runtime", "old-image"
    )
    foreign = target / "foreign-sentinel"
    foreign.write_text("do-not-delete\n", encoding="utf-8")
    foreign.chmod(0o644)
    stage = _sealed_publish_image(
        installer, library / ".codex-master-runtime.stage.test", "new-image"
    )

    with pytest.raises(install_error, match="install_target_untrusted"):
        installer["_publish_runtime_image"](stage=stage, target=target)

    assert foreign.read_text(encoding="utf-8") == "do-not-delete\n"
    assert (stage / "new-image").read_text(encoding="utf-8") == "new-image\n"


def test_runtime_image_publish_refuses_the_unmanifested_pre_cutover_candidate(
    tmp_path: Path,
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = library / "codex-master-runtime"
    target.mkdir(mode=0o700)
    candidate = target / "candidate-without-manifest"
    candidate.write_text("do-not-adopt\n", encoding="utf-8")
    candidate.chmod(0o644)
    stage = _sealed_publish_image(
        installer, library / ".codex-master-runtime.stage.test", "new-image"
    )

    with pytest.raises(install_error, match="install_target_untrusted"):
        installer["_publish_runtime_image"](stage=stage, target=target)

    assert candidate.read_text(encoding="utf-8") == "do-not-adopt\n"
    assert (stage / "new-image").read_text(encoding="utf-8") == "new-image\n"


@pytest.mark.parametrize(
    "legacy_relative",
    (
        ".local/lib/codex-master-hive-probe",
        ".local/libexec/codex_master_hive_hourly_probe.py",
        ".local/bin/codex-master-mcp",
    ),
)
@pytest.mark.parametrize("entry_kind", ("file", "symlink", "directory"))
def test_install_rejects_foreign_legacy_entries_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    legacy_relative: str,
    entry_kind: str,
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    legacy = home / legacy_relative
    legacy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if entry_kind == "file":
        legacy.write_text("foreign\n", encoding="utf-8")
        legacy.chmod(0o600)
    elif entry_kind == "symlink":
        foreign = home / "foreign-target"
        foreign.write_text("foreign\n", encoding="utf-8")
        foreign.chmod(0o600)
        legacy.symlink_to(foreign)
    else:
        legacy.mkdir(mode=0o700)
        (legacy / "foreign-sentinel").write_text("foreign\n", encoding="utf-8")
    published: list[Path] = []
    globals_dict = installer["install"].__globals__  # type: ignore[index]
    monkeypatch.setitem(globals_dict, "_build_runtime_image", lambda **_kwargs: None)
    monkeypatch.setitem(
        globals_dict, "_validate_runtime_image_stage", lambda **_kwargs: None
    )
    monkeypatch.setitem(
        globals_dict,
        "_publish_runtime_image",
        lambda *, stage, target: published.append(target),
    )

    with pytest.raises(install_error, match="install_legacy_untrusted"):
        installer["install"](home=home)

    assert legacy.exists() or legacy.is_symlink()
    assert not published


def test_runtime_image_cleanup_refuses_an_old_root_changed_after_prevalidation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = _sealed_publish_image(
        installer, library / "codex-master-runtime", "old-image"
    )
    stage = _sealed_publish_image(
        installer, library / ".codex-master-runtime.stage.test", "new-image"
    )
    exchange = installer["_rename_exchange"]

    def change_old_root_after_exchange(*arguments: object) -> None:
        exchange(*arguments)
        (stage / "foreign-sentinel").write_text("do-not-delete\n", encoding="utf-8")

    monkeypatch.setitem(
        installer["_publish_runtime_image"].__globals__,
        "_rename_exchange",
        change_old_root_after_exchange,
    )
    with pytest.raises(install_error, match="install_old_image_changed"):
        installer["_publish_runtime_image"](stage=stage, target=target)

    assert (target / "new-image").read_text(encoding="utf-8") == "new-image\n"
    assert (stage / "foreign-sentinel").read_text(encoding="utf-8") == "do-not-delete\n"


def test_runtime_image_cleanup_rebinds_a_reopened_root_before_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = _sealed_publish_image(
        installer, library / "codex-master-runtime", "old-image"
    )
    stage = _sealed_publish_image(
        installer, library / ".codex-master-runtime.stage.test", "new-image"
    )
    replacement = _sealed_publish_image(
        installer, library / ".replacement", "old-image"
    )
    displaced_old_root = library / ".displaced-old-root"
    original_validate = installer["_validated_image_at"]
    original_exchange = installer["_rename_exchange"]
    exchanged = False

    def exchange_then_mark(*arguments: object) -> None:
        nonlocal exchanged
        original_exchange(*arguments)
        exchanged = True

    def validate_then_replace(
        parent_fd: int, name: str, *, error_code: str
    ) -> tuple[int, int, str]:
        identity = original_validate(parent_fd, name, error_code=error_code)
        if (
            exchanged
            and name == stage.name
            and error_code == "install_old_image_changed"
        ):
            os.rename(stage, displaced_old_root)
            os.rename(replacement, stage)
        return identity

    globals_dict = installer["_publish_runtime_image"].__globals__  # type: ignore[index]
    monkeypatch.setitem(globals_dict, "_rename_exchange", exchange_then_mark)
    monkeypatch.setitem(globals_dict, "_validated_image_at", validate_then_replace)

    with pytest.raises(install_error, match="install_old_image_changed"):
        installer["_publish_runtime_image"](stage=stage, target=target)

    assert (target / "new-image").read_text(encoding="utf-8") == "new-image\n"
    assert (stage / "old-image").read_text(encoding="utf-8") == "old-image\n"
    assert (displaced_old_root / "old-image").read_text(
        encoding="utf-8"
    ) == "old-image\n"


@pytest.mark.parametrize(
    ("kind", "relative"),
    (
        ("probe_root", ".local/lib/codex-master-hive-probe"),
        ("libexec", ".local/libexec/codex_master_hive_hourly_probe.py"),
        ("bin", ".local/bin/codex-master-mcp"),
    ),
)
def test_legacy_cleanup_refuses_a_name_replaced_after_preflight_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, relative: str
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _legacy_cleanup_parents(home)
    legacy = home / relative
    legacy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if kind == "probe_root":
        legacy.mkdir(mode=0o700)
        owned = legacy / "owned"
        owned.write_text("owned\n", encoding="utf-8")
        owned.chmod(0o644)
        replacement = legacy.with_name("replacement")
        replacement.mkdir(mode=0o700)
        replacement_owned = replacement / "owned"
        replacement_owned.write_text("owned\n", encoding="utf-8")
        replacement_owned.chmod(0o644)
        owned_digest = hashlib.sha256(b"owned\n").hexdigest()
        payload = {
            "schema_version": 1,
            "directories": ["."],
            "files": {
                "owned": {
                    "mode": 0o644,
                    "nlink": 1,
                    "size": len(b"owned\n"),
                    "sha256": owned_digest,
                }
            },
        }
        identity_digest = hashlib.sha256(
            installer["_canonical_json"](payload)
        ).hexdigest()
        legacy_stat = legacy.stat()
        identity = (legacy_stat.st_dev, legacy_stat.st_ino, identity_digest)
        validator_name = "_validated_legacy_probe_root"
        monkeypatch.setitem(
            installer["_remove_legacy_probe_root"].__globals__,
            "_legacy_probe_payload",
            lambda _fd: payload,
        )
    else:
        legacy.write_text("owned\n", encoding="utf-8")
        legacy.chmod(0o755 if kind == "libexec" else 0o644)
        replacement = legacy.with_name("replacement")
        replacement.write_text("foreign\n", encoding="utf-8")
        replacement.chmod(0o755 if kind == "libexec" else 0o644)
        legacy_stat = legacy.stat()
        identity = (legacy_stat.st_dev, legacy_stat.st_ino, "f" * 64)
        validator_name = (
            "_validated_legacy_libexec"
            if kind == "libexec"
            else "_validated_legacy_bin"
        )

    calls = 0

    def validate_after_preflight(
        *_args: object, **_kwargs: object
    ) -> tuple[int, int, str]:
        nonlocal calls
        calls += 1
        if calls == 2:
            displaced = legacy.with_name("displaced")
            os.rename(legacy, displaced)
            os.rename(replacement, legacy)
        return identity

    globals_dict = installer["_remove_preflighted_legacy"].__globals__  # type: ignore[index]
    monkeypatch.setitem(globals_dict, validator_name, validate_after_preflight)
    entries = installer["_preflight_legacy_paths"](
        library=home / ".local" / "lib",
        libexec=home / ".local" / "libexec",
        user_bin=home / ".local" / "bin",
        repository=ROOT,
    )

    with pytest.raises(install_error, match="install_legacy_cleanup_failed"):
        installer["_remove_preflighted_legacy"](entries, repository=ROOT)

    assert legacy.exists()
    if kind == "probe_root":
        assert (legacy / "owned").read_text(encoding="utf-8") == "owned\n"
    else:
        assert legacy.read_text(encoding="utf-8") == "foreign\n"


@pytest.mark.parametrize(
    ("kind", "relative"),
    (
        ("probe_root", ".local/lib/codex-master-hive-probe"),
        ("libexec", ".local/libexec/codex_master_hive_hourly_probe.py"),
        ("bin", ".local/bin/codex-master-mcp"),
    ),
)
def test_legacy_cleanup_keeps_a_replaced_parent_name_out_of_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, relative: str
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _legacy_cleanup_parents(home)
    legacy = home / relative
    legacy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if kind == "probe_root":
        legacy.mkdir(mode=0o700)
        (legacy / "owned").write_text("owned\n", encoding="utf-8")
        (legacy / "owned").chmod(0o644)
        owned_digest = hashlib.sha256(b"owned\n").hexdigest()
        payload = {
            "schema_version": 1,
            "directories": ["."],
            "files": {
                "owned": {"mode": 0o644, "nlink": 1, "size": 6, "sha256": owned_digest}
            },
        }
        identity_digest = hashlib.sha256(
            installer["_canonical_json"](payload)
        ).hexdigest()
        validator_name = "_validated_legacy_probe_root"
        monkeypatch.setitem(
            installer["_remove_legacy_probe_root"].__globals__,
            "_legacy_probe_payload",
            lambda _fd: payload,
        )
    else:
        legacy.write_text("owned\n", encoding="utf-8")
        legacy.chmod(0o755 if kind == "libexec" else 0o644)
        validator_name = (
            "_validated_legacy_libexec"
            if kind == "libexec"
            else "_validated_legacy_bin"
        )
        identity_digest = "f" * 64
    legacy_stat = legacy.stat()
    identity = (legacy_stat.st_dev, legacy_stat.st_ino, identity_digest)
    monkeypatch.setitem(
        installer["_remove_preflighted_legacy"].__globals__,
        validator_name,
        lambda *_args, **_kwargs: identity,
    )
    entries = installer["_preflight_legacy_paths"](
        library=home / ".local" / "lib",
        libexec=home / ".local" / "libexec",
        user_bin=home / ".local" / "bin",
        repository=ROOT,
    )
    original_parent = legacy.parent
    relocated_parent = original_parent.with_name(original_parent.name + "-relocated")
    os.rename(original_parent, relocated_parent)
    original_parent.mkdir(mode=0o700)
    foreign = original_parent / legacy.name
    if kind == "probe_root":
        foreign.mkdir(mode=0o700)
        (foreign / "foreign").write_text("foreign\n", encoding="utf-8")
    else:
        foreign.write_text("foreign\n", encoding="utf-8")
        foreign.chmod(0o755 if kind == "libexec" else 0o644)

    installer["_remove_preflighted_legacy"](entries, repository=ROOT)

    assert foreign.exists()
    if kind == "probe_root":
        assert (foreign / "foreign").read_text(encoding="utf-8") == "foreign\n"
    else:
        assert foreign.read_text(encoding="utf-8") == "foreign\n"


def _materialize_23510da_legacy_probe(
    installer: dict[str, object], root: Path
) -> dict[str, object]:
    listed = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "23510da"],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    historical_files = [
        name
        for name in listed.stdout.splitlines()
        if (name.startswith("src/codex_master/") and name.endswith(".py"))
        or name
        in {"bin/codex-master-mcp", "codex-hive.json", "codex-agent-classes.json"}
    ]
    root.mkdir(mode=0o700)
    for historical in historical_files:
        if historical.startswith("src/codex_master/"):
            destination = (
                root
                / "src"
                / "codex_master"
                / Path(historical).relative_to("src/codex_master")
            )
        else:
            destination = root / historical
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in (destination.parent, *destination.parent.parents):
            if directory == root.parent:
                break
            directory.chmod(0o700)
        content = subprocess.run(
            ["git", "show", f"23510da:{historical}"],
            check=True,
            capture_output=True,
            cwd=ROOT,
        ).stdout
        destination.write_bytes(content)
        destination.chmod(0o755 if historical == "bin/codex-master-mcp" else 0o644)
    root_fd = installer["_open_absolute_directory"](
        root, error_code="install_legacy_untrusted"
    )
    try:
        payload = installer["_legacy_probe_payload"](root_fd)
    finally:
        os.close(root_fd)

    assert len(payload["directories"]) == 6
    assert len(payload["files"]) == 143
    return payload


def test_legacy_probe_manifest_digest_has_a_23510da_provenance_regression_contract(
    tmp_path: Path,
) -> None:
    installer_path = ROOT / "scripts" / "codex-master-hive-hourly-probe-install"
    installer = runpy.run_path(str(installer_path))
    source = installer_path.read_text(encoding="utf-8")
    assert "Provenance: canonical 23510da legacy probe payload" in source
    payload = _materialize_23510da_legacy_probe(installer, tmp_path / "legacy-probe")
    assert (
        hashlib.sha256(installer["_canonical_json"](payload)).hexdigest()
        == installer["_LEGACY_PROBE_MANIFEST_DIGEST"]
    )


def test_runtime_image_publish_refuses_a_hardlinked_prevalidated_file(
    tmp_path: Path,
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = _sealed_publish_image(
        installer, library / "codex-master-runtime", "old-image"
    )
    hardlink = tmp_path / "outside-hardlink"
    os.link(target / "old-image", hardlink)
    stage = _sealed_publish_image(
        installer, library / ".codex-master-runtime.stage.test", "new-image"
    )

    with pytest.raises(install_error, match="install_target_untrusted"):
        installer["_publish_runtime_image"](stage=stage, target=target)

    assert hardlink.read_text(encoding="utf-8") == "old-image\n"
    assert (target / "old-image").read_text(encoding="utf-8") == "old-image\n"
    assert (stage / "new-image").read_text(encoding="utf-8") == "new-image\n"


@pytest.mark.parametrize("kind", ("probe_root", "libexec", "bin"))
def test_legacy_preflight_refuses_hardlinked_entries(tmp_path: Path, kind: str) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _legacy_cleanup_parents(home)
    if kind == "probe_root":
        legacy = home / ".local" / "lib" / "codex-master-hive-probe"
        _materialize_23510da_legacy_probe(installer, legacy)
        source = legacy / "src" / "codex_master" / "__init__.py"
        os.link(source, tmp_path / "outside-hardlink")
    elif kind == "libexec":
        legacy = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
        legacy.write_bytes(
            subprocess.run(
                [
                    "git",
                    "show",
                    "23510da:systemd/libexec/codex_master_hive_hourly_probe.py",
                ],
                check=True,
                capture_output=True,
                cwd=ROOT,
            ).stdout
        )
        legacy.chmod(0o755)
        os.link(legacy, tmp_path / "outside-hardlink")
    else:
        legacy = home / ".local" / "bin" / "codex-master-mcp"
        legacy.symlink_to(ROOT / "bin" / "codex-master-mcp")
        os.link(legacy, tmp_path / "outside-hardlink", follow_symlinks=False)

    with pytest.raises(install_error, match="install_legacy_untrusted"):
        installer["_preflight_legacy_paths"](
            library=home / ".local" / "lib",
            libexec=home / ".local" / "libexec",
            user_bin=home / ".local" / "bin",
            repository=ROOT,
        )

    assert legacy.exists() or legacy.is_symlink()


def test_runtime_image_cleanup_aborts_with_a_private_stage_trace_on_mid_cleanup_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = _sealed_publish_image(
        installer, library / "codex-master-runtime", "old-one"
    )
    (target / "old-two").write_text("old-two\n", encoding="utf-8")
    (target / "old-two").chmod(0o644)
    (target / installer["_MANIFEST_NAME"]).unlink()
    installer["_write_runtime_image_manifest"](root=target)
    stage = _sealed_publish_image(
        installer, library / ".codex-master-runtime.stage.test", "new-image"
    )
    original_unlink = installer["_unlink_verified_regular_at"]
    mutated = False

    def unlink_then_mutate(*args: object, **kwargs: object) -> None:
        nonlocal mutated
        original_unlink(*args, **kwargs)
        if not mutated:
            mutated = True
            (stage / "foreign-after-publish").write_text(
                "do-not-delete\n", encoding="utf-8"
            )
            (stage / "foreign-after-publish").chmod(0o644)

    monkeypatch.setitem(
        installer["_remove_validated_image"].__globals__,
        "_unlink_verified_regular_at",
        unlink_then_mutate,
    )

    with pytest.raises(install_error, match="install_old_image_changed"):
        installer["_publish_runtime_image"](stage=stage, target=target)

    assert (target / "new-image").read_text(encoding="utf-8") == "new-image\n"
    assert (stage / "foreign-after-publish").read_text(
        encoding="utf-8"
    ) == "do-not-delete\n"


def test_install_preserves_a_mutated_legacy_trace_after_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _legacy_cleanup_parents(home)
    legacy_root = home / ".local" / "lib" / "codex-master-hive-probe"
    _materialize_23510da_legacy_probe(installer, legacy_root)
    legacy_libexec = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    legacy_libexec.write_bytes(
        subprocess.run(
            [
                "git",
                "show",
                "23510da:systemd/libexec/codex_master_hive_hourly_probe.py",
            ],
            check=True,
            capture_output=True,
            cwd=ROOT,
        ).stdout
    )
    legacy_libexec.chmod(0o755)
    legacy_bin = home / ".local" / "bin" / "codex-master-mcp"
    legacy_bin.symlink_to(ROOT / "bin" / "codex-master-mcp")
    original_publish = installer["_publish_runtime_image"]
    changed = legacy_root / "src" / "codex_master" / "__init__.py"

    def publish_then_mutate(*, stage: Path, target: Path) -> None:
        original_publish(stage=stage, target=target)
        changed.write_text("mutated after publish\n", encoding="utf-8")
        changed.chmod(0o644)

    monkeypatch.setitem(
        installer["install"].__globals__, "_publish_runtime_image", publish_then_mutate
    )

    with pytest.raises(install_error, match="install_legacy_untrusted"):
        installer["install"](home=home)

    runtime_root = home / ".local" / "lib" / "codex-master-runtime"
    assert runtime_root.is_dir()
    assert (
        home / ".config" / "systemd" / "user" / "codex-master-hive-hourly-probe.service"
    ).is_file()
    assert changed.read_text(encoding="utf-8") == "mutated after publish\n"
    assert legacy_libexec.is_file()
    assert legacy_bin.is_symlink()


def test_runtime_image_stage_validation_runs_only_the_three_v2_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    stage = tmp_path / "stage"
    stage.mkdir()
    observed: list[tuple[str, ...]] = []

    class Completed:
        def __init__(self, returncode: int, stdout: str) -> None:
            self.returncode = returncode
            self.stdout = stdout

    def run(command: list[str], **_kwargs: object) -> Completed:
        observed.append(tuple(command))
        diagnostic = command[-1]
        payload: dict[str, object] = {"status": "ready"}
        if diagnostic == "runtime-status":
            payload = {"ok": True}
        return Completed(0, json.dumps(payload))

    monkeypatch.setitem(
        installer["_validate_runtime_image_stage"].__globals__, "run_bounded", run
    )
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
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    install_error = installer["InstallError"]
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = _sealed_publish_image(
        installer, library / "codex-master-runtime", "old-complete-image"
    )
    stage = _sealed_publish_image(
        installer, library / ".codex-master-runtime.stage.test", "new-complete-image"
    )

    def renameat2(*_args: object) -> int:
        return -1

    class FailedExchange:
        pass

    failed_exchange = FailedExchange()
    failed_exchange.renameat2 = renameat2  # type: ignore[attr-defined]
    monkeypatch.setattr(
        installer["ctypes"], "CDLL", lambda *_args, **_kwargs: failed_exchange
    )
    monkeypatch.setattr(installer["ctypes"], "get_errno", lambda: errno.EIO)

    with pytest.raises(install_error, match="install_swap_failed"):
        installer["_publish_runtime_image"](stage=stage, target=target)

    assert (target / "old-complete-image").read_text(
        encoding="utf-8"
    ) == "old-complete-image\n"
    assert not (target / "new-complete-image").exists()
    assert (stage / "new-complete-image").read_text(
        encoding="utf-8"
    ) == "new-complete-image\n"


def test_runtime_image_build_failure_never_publishes_a_partial_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
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

    monkeypatch.setitem(
        installer["_build_runtime_image"].__globals__, "_install_regular", fail_copy
    )
    with pytest.raises(install_error, match="install_source_untrusted"):
        installer["_build_runtime_image"](repository=ROOT, stage=stage)

    assert (target / "old-complete-image").read_text(encoding="utf-8") == "old\n"
    assert not (target / "new-complete-image").exists()
    assert stage.is_dir()
    assert not (stage / "new-complete-image").exists()


def test_runtime_image_publish_exchange_exposes_only_complete_directory_generations(
    tmp_path: Path,
) -> None:
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    library = tmp_path / "lib"
    library.mkdir(mode=0o700)
    target = _sealed_publish_image(
        installer, library / "codex-master-runtime", "old-complete-image"
    )
    stage = _sealed_publish_image(
        installer, library / ".codex-master-runtime.stage.test", "new-complete-image"
    )

    installer["_publish_runtime_image"](stage=stage, target=target)

    assert (target / "new-complete-image").read_text(
        encoding="utf-8"
    ) == "new-complete-image\n"
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
    tmp_path: Path, error_type: type[Exception]
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
