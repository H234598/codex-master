from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_master import server
from codex_master.fleet_registry import AgentDescriptor, Provider, RunnerKind
from codex_master.fleet_service import FleetConflictError


def _runner(root: Path) -> Path:
    path = root / "runner"
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def test_series_plan_is_read_only_and_redacted() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ):
            result = server.fleet_series_plan(
                prefix="d", count=3, runner="codex_cli", provider="ollama_local",
                model="local-model", account_id=None, expected_generation=1,
            )
        assert result["mutation_performed"] is False
        assert result["create_count"] == 3
        assert result["pool_root"] == "not_returned"
        assert not (root / "state").exists()
        assert not (root / "pool").exists()


def test_series_apply_grows_only_the_tail_and_publishes_inventory() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ), server.temporary_agent_inventory(None):
            first = server.fleet_series_apply(
                prefix="d", count=3, runner="codex_cli", provider="ollama_local",
                model="local-model", account_id=None, expected_generation=1,
                codex_executable=executable,
            )
            before = {
                path.name: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
                for path in (root / "pool" / "d1").iterdir()
            }
            second = server.fleet_series_apply(
                prefix="d", count=5, runner="codex_cli", provider="ollama_local",
                model="local-model", account_id=None, expected_generation=2,
                codex_executable=executable,
            )
            after = {
                path.name: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
                for path in (root / "pool" / "d1").iterdir()
            }
            inventory = server.current_agent_inventory()
        assert first["created_count"] == 3
        assert second["created_count"] == 2
        assert before == after
        assert inventory.agent_ids == ("d1", "d2", "d3", "d4", "d5")
        assert json.loads((root / "pool" / server.FLEET_POOL_MARKER_FILE).read_text())[
            "kind"
        ] == "codex_master_fleet_pool"


def test_ollama_home_uses_bounded_codex_profile_and_model_catalog() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ), server.temporary_agent_inventory(None):
            server.fleet_series_apply(
                prefix="d", count=1, runner="codex_cli", provider="ollama_local",
                model="llama3.2:3b", account_id=None, expected_generation=1,
                codex_executable=executable,
            )
        home = root / "pool" / "d1"
        config = (home / "config.toml").read_text(encoding="utf-8")
        catalog = json.loads((home / "model.json").read_text(encoding="utf-8"))
    assert 'model_provider = "ollama-launch"' in config
    assert f'model_catalog_json = "{home / "model.json"}"' in config
    assert 'base_url = "http://127.0.0.1:11434/v1/"' in config
    assert 'wire_api = "responses"' in config
    assert catalog["models"][0]["slug"] == "llama3.2:3b"
    assert catalog["models"][0]["context_window"] == 131072
    assert catalog["models"][0]["supports_parallel_tool_calls"] is False


def test_series_disable_is_registry_only_and_removes_from_dispatch_inventory() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ), server.temporary_agent_inventory(None):
            server.fleet_series_apply(
                prefix="d", count=1, runner="codex_cli", provider="ollama_local",
                model="local-model", account_id=None, expected_generation=1,
                codex_executable=executable,
            )
            result = server.fleet_series_disable(prefix="d", expected_generation=2)
            inventory = server.current_agent_inventory()
        assert result["generation"] == 3
        assert inventory.agents["d1"].enabled is False
        assert (root / "pool" / "d1").exists()


def test_series_disable_scales_shared_deadline_for_all_agents() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ), server.temporary_agent_inventory(None):
            server.fleet_series_apply(
                prefix="d", count=2, runner="codex_cli", provider="ollama_local",
                model="local-model", account_id=None, expected_generation=1,
                codex_executable=executable,
            )
            stopped: list[tuple[str, float | None]] = []

            def slow_stop(agent: str, *, force: bool, timeout_seconds: float | None = None) -> dict[str, object]:
                assert force is True
                stopped.append((agent, timeout_seconds))
                import time
                time.sleep(0.02)
                return {"agent": agent, "status": "stopped", "raw_output": "not_returned"}

            with patch.object(server, "stop_agent", side_effect=slow_stop), patch.object(
                server, "update_watchdog_marker"
            ), patch.object(server, "SERIES_DISABLE_TIMEOUT_SECONDS", 0.02):
                with pytest.raises(server.AgentLifecycleLockBusyError):
                    server.fleet_series_disable(prefix="d", expected_generation=2)
            snapshot = server.current_fleet_service().load()

    assert [item[0] for item in stopped] == ["d1", "d2"]
    assert all(item[1] is not None and 0 < item[1] <= 0.04 for item in stopped[1:])
    assert stopped[0][1] is not None and 0 < stopped[0][1] <= 0.04
    assert snapshot.series[0].enabled is True


def test_provider_wrapper_keeps_only_provider_secret() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        agent = AgentDescriptor(
            "d1", "d", 1, "D 1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
            "model", "SENTINEL-ACCOUNT-ID", root / "home", "session", True,
        )
        text = server.fleet_wrapper_text(agent, root / "gemini")
    assert "GEMINI_CLI_HOME" in text
    assert "unset CODEX_HOME" in text
    assert "HF_TOKEN" in text
    assert "SENTINEL-ACCOUNT-ID" not in text


def test_series_apply_updates_overlapping_homes_and_recreates_missing_homes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ), server.temporary_agent_inventory(None):
            server.fleet_series_apply(
                prefix="d", count=2, runner="codex_cli", provider="ollama_local",
                model="model-one", account_id=None, expected_generation=1,
                codex_executable=executable,
            )
            updated = server.fleet_series_apply(
                prefix="d", count=2, runner="codex_cli", provider="ollama_local",
                model="model-two", account_id=None, expected_generation=2,
                codex_executable=executable,
            )
            (root / "pool" / "d2").rename(root / "pool" / "d2-missing")
            recreated = server.fleet_series_apply(
                prefix="d", count=2, runner="codex_cli", provider="ollama_local",
                model="model-two", account_id=None, expected_generation=3,
                codex_executable=executable,
            )
        assert updated["updated_count"] == 2
        assert recreated["created_count"] == 1
        assert (root / "pool" / "d2" / "config.toml").read_text().find("model-two") >= 0


def test_series_shrink_and_delete_reap_tombstones_after_commit() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ), server.temporary_agent_inventory(None):
            server.fleet_series_apply(
                prefix="d", count=2, runner="codex_cli", provider="ollama_local",
                model="model", account_id=None, expected_generation=1,
                codex_executable=executable,
            )
            shrunk = server.fleet_series_apply(
                prefix="d", count=1, runner="codex_cli", provider="ollama_local",
                model="model", account_id=None, expected_generation=2,
                confirmed_remove_ids=["d2"], codex_executable=executable,
            )
            server.fleet_series_disable(prefix="d", expected_generation=3)
            deleted = server.fleet_series_delete(
                prefix="d", expected_generation=4, confirmed_remove_ids=["d1"]
            )
        hidden = list((root / "pool").glob(".codex-fleet-remove-*"))
        assert shrunk["cleanup_pending"] is False
        assert deleted["cleanup_pending"] is False
        assert hidden == []


def test_series_update_restores_home_when_registry_commit_conflicts() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ), server.temporary_agent_inventory(None):
            server.fleet_series_apply(
                prefix="d", count=1, runner="codex_cli", provider="ollama_local",
                model="old-model", account_id=None, expected_generation=1,
                codex_executable=executable,
            )
            config = root / "pool" / "d1" / "config.toml"
            marker = root / "pool" / "d1" / server.FLEET_AGENT_MARKER_FILE
            before_config = config.read_bytes()
            before_marker = marker.read_bytes()
            with patch.object(
                server.FleetService,
                "commit_snapshot",
                side_effect=FleetConflictError("generation_conflict"),
            ):
                try:
                    server.fleet_series_apply(
                        prefix="d", count=1, runner="codex_cli", provider="ollama_local",
                        model="new-model", account_id=None, expected_generation=2,
                        codex_executable=executable,
                    )
                except server.AgentError as exc:
                    assert str(exc) == "generation_conflict"
                else:
                    raise AssertionError("expected generation conflict")
            assert server.fleet_recovery_status()["state"] == "ready"
        assert config.read_bytes() == before_config
        assert marker.read_bytes() == before_marker


def test_series_retry_finishes_after_crash_between_verify_and_publish() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ), server.temporary_agent_inventory(None):
            server.fleet_series_apply(
                prefix="d", count=1, runner="codex_cli", provider="ollama_local",
                model="model", account_id=None, expected_generation=1,
                codex_executable=executable,
            )
            with patch.object(
                server,
                "publish_agent_inventory",
                side_effect=BaseException("simulated_process_crash"),
            ):
                try:
                    server.fleet_series_apply(
                        prefix="d", count=1, runner="codex_cli", provider="ollama_local",
                        model="new-model", account_id=None, expected_generation=2,
                        codex_executable=executable,
                    )
                except BaseException as exc:
                    assert str(exc) == "simulated_process_crash"
                else:
                    raise AssertionError("expected simulated crash")
            assert server.fleet_recovery_status()["state"] == "verified"
            assert server.fleet_recovery_retry()["state"] == "ready"
            assert server.current_fleet_service().load().generation == 3


def test_series_retry_restores_durable_update_backup_before_cas() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ), server.temporary_agent_inventory(None):
            server.fleet_series_apply(
                prefix="d", count=1, runner="codex_cli", provider="ollama_local",
                model="old-model", account_id=None, expected_generation=1,
                codex_executable=executable,
            )
            config = root / "pool" / "d1" / "config.toml"
            before = config.read_bytes()
            with patch.object(
                server.FleetService,
                "commit_snapshot",
                side_effect=BaseException("simulated_process_crash"),
            ):
                try:
                    server.fleet_series_apply(
                        prefix="d", count=1, runner="codex_cli", provider="ollama_local",
                        model="new-model", account_id=None, expected_generation=2,
                        codex_executable=executable,
                    )
                except BaseException as exc:
                    assert str(exc) == "simulated_process_crash"
                else:
                    raise AssertionError("expected simulated crash")
            assert server.fleet_recovery_status()["state"] == "cas_pending"
            assert server.fleet_recovery_retry()["state"] == "ready"
            assert config.read_bytes() == before
            assert list((root / "pool").glob(".codex-fleet-remove-*")) == []


def test_series_retry_discards_create_intent_before_home_creation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ), server.temporary_agent_inventory(None):
            with patch.object(
                server,
                "_fleet_write_home",
                side_effect=BaseException("simulated_process_crash"),
            ):
                try:
                    server.fleet_series_apply(
                        prefix="d", count=1, runner="codex_cli", provider="ollama_local",
                        model="model", account_id=None, expected_generation=1,
                        codex_executable=executable,
                    )
                except BaseException as exc:
                    assert str(exc) == "simulated_process_crash"
                else:
                    raise AssertionError("expected simulated crash")
            assert server.fleet_recovery_status()["state"] == "materializing"
            assert server.fleet_recovery_retry()["state"] == "ready"
            assert not (root / "pool" / "d1").exists()


CRASH_POINTS = (
    "after_journal_before_pool",
    "after_intent_before_filesystem",
    "after_filesystem_before_applied",
    "after_materialization_before_cas",
    "after_cas_before_reload",
    "between_reconciliation_actions",
    "after_verify_before_publish",
    "after_publish_before_complete",
    "after_complete_before_remove",
)


_FRESH_RECOVERY_CHILD = r'''
import json
import sys
from pathlib import Path
from unittest.mock import patch

from codex_master import server

mode, root_text, executable_text, crash_point = sys.argv[1:]
root = Path(root_text)
executable = Path(executable_text)
state_root = root / "state"
pool_root = root / "pool"

with patch.object(server, "STATE_ROOT", state_root), patch.object(
    server, "AGENT_POOL_ROOT", pool_root
), server.temporary_agent_inventory(None):
    if mode == "crash":
        active_point = (
            "after_filesystem_before_applied"
            if crash_point == "between_reconciliation_actions"
            else crash_point
        )
        fired = False

        def crash_hook(marker: str) -> None:
            nonlocal_fired[0] = nonlocal_fired[0] or marker == active_point
            if marker == active_point and nonlocal_fired[0] is True and not raised[0]:
                raised[0] = True
                raise BaseException("fresh_process_crash")

        nonlocal_fired = [False]
        raised = [False]
        try:
            with patch.object(server, "_fleet_recovery_crash_point", side_effect=crash_hook):
                server.fleet_series_apply(
                    prefix="d", count=2 if crash_point == "between_reconciliation_actions" else 1,
                    runner="codex_cli", provider="ollama_local", model="model",
                    account_id=None, expected_generation=1, codex_executable=executable,
                )
        except BaseException as exc:
            if str(exc) != "fresh_process_crash" or not raised[0]:
                raise
        else:
            raise AssertionError("fresh crash hook did not fire")
        print(json.dumps({"mode": mode, "crashed": True}, sort_keys=True))
    elif mode == "recover":
        if crash_point == "between_reconciliation_actions":
            raised = [False]

            def retry_crash_hook(marker: str) -> None:
                if marker == crash_point and not raised[0]:
                    raised[0] = True
                    raise BaseException("fresh_process_crash")

            with patch.object(server, "_fleet_recovery_crash_point", side_effect=retry_crash_hook):
                try:
                    server.fleet_recovery_retry()
                except BaseException as exc:
                    if str(exc) != "fresh_process_crash" or not raised[0]:
                        raise
                else:
                    raise AssertionError("fresh retry crash hook did not fire")
        first = server.fleet_recovery_retry()
        second = server.fleet_recovery_retry()
        if first.get("state") != "ready" or second.get("state") != "ready":
            raise AssertionError((first, second))
        if (state_root / "fleet" / "recovery.json").exists():
            raise AssertionError("recovery journal was not removed")
        print(json.dumps({"mode": mode, "state": second["state"]}, sort_keys=True))
    else:
        raise AssertionError("unknown child mode")
'''


@pytest.mark.parametrize("crash_point", CRASH_POINTS)
def test_series_crash_points_recover_idempotently(crash_point: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        crashed = False
        active_point = (
            "after_filesystem_before_applied"
            if crash_point == "between_reconciliation_actions"
            else crash_point
        )

        def crash_hook(marker: str) -> None:
            nonlocal crashed
            if marker == active_point and not crashed:
                crashed = True
                raise BaseException("simulated_process_crash")

        with patch.object(server, "STATE_ROOT", root / "state"), patch.object(
            server, "AGENT_POOL_ROOT", root / "pool"
        ), server.temporary_agent_inventory(None), patch.object(
            server, "_fleet_recovery_crash_point", side_effect=crash_hook
        ):
            try:
                server.fleet_series_apply(
                    prefix="d", count=2 if crash_point == "between_reconciliation_actions" else 1,
                    runner="codex_cli", provider="ollama_local", model="model",
                    account_id=None, expected_generation=1, codex_executable=executable,
                )
            except BaseException as exc:
                assert str(exc) == "simulated_process_crash"
            else:
                raise AssertionError(f"crash hook did not raise for {crash_point}")
            assert crashed is True, f"crash hook never fired for {crash_point}"
            if crash_point == "between_reconciliation_actions":
                active_point = crash_point
                crashed = False
            if crash_point == "after_complete_before_remove":
                assert server.fleet_recovery_status()["blocking"] is False
            else:
                assert server.fleet_recovery_status()["blocking"] is True
            if crash_point == "between_reconciliation_actions":
                try:
                    server.fleet_recovery_retry()
                except BaseException as exc:
                    assert str(exc) == "simulated_process_crash"
                else:
                    raise AssertionError("crash hook did not raise during retry")
                assert crashed is True, "crash hook never fired for between_reconciliation_actions"
            first_retry = server.fleet_recovery_retry()
            second_retry = server.fleet_recovery_retry()

        assert first_retry["state"] == "ready"
        assert second_retry["state"] == "ready"
        assert not (root / "state" / "fleet" / "recovery.json").exists()


@pytest.mark.parametrize("crash_point", CRASH_POINTS)
def test_series_crash_points_recover_across_fresh_processes(crash_point: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = _runner(root)
        environment = os.environ.copy()
        environment.pop("CODEX_HOME", None)
        environment.pop("CODEX_AGENT_BIN", None)
        repo_root = Path(__file__).resolve().parents[1]
        source_path = str(repo_root / "src")
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            source_path
            if not existing_pythonpath
            else source_path + os.pathsep + existing_pythonpath
        )

        def child(mode: str) -> dict[str, object]:
            completed = subprocess.run(
                [
                    sys.executable, "-c", _FRESH_RECOVERY_CHILD,
                    mode, str(root), str(executable), crash_point,
                ],
                cwd=repo_root,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            return json.loads(completed.stdout.strip().splitlines()[-1])

        assert child("crash") == {"crashed": True, "mode": "crash"}
        assert child("recover") == {"mode": "recover", "state": "ready"}


def test_rollback_keeps_recovery_backups_when_home_restore_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pool = tmp_path / "pool"
    pool.mkdir(mode=0o700)
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", pool)
    cleanup_calls: list[object] = []

    def fail_restore(_home: Path, _backup: dict[str, bytes]) -> None:
        raise server.AgentError("fleet_home_rollback_failed")

    monkeypatch.setattr(server, "_fleet_restore_home", fail_restore)
    monkeypatch.setattr(
        server,
        "_fleet_cleanup_tombstones",
        lambda *_args: cleanup_calls.append(True) or False,
    )

    result = server._fleet_rollback_mutation(
        [],
        [(Path("d1"), {})],
        [],
        [(Path("d1"), Path(".codex-fleet-recovery-d1"))],
    )

    assert result is False
    assert cleanup_calls == []
