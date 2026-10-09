"""Focused Codex 0.161 daemon isolation contracts for managed Hive homes."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import os
import shutil
import socket
import subprocess
import tomllib

import pytest

from the_hive import server
from the_hive.fleet_registry import AgentDescriptor, Provider, RunnerKind


def _agent(home: Path) -> AgentDescriptor:
    return AgentDescriptor(
        "q1", "q", 1, "Q 1", RunnerKind.CODEX_CLI,
        Provider.OPENAI_CHATGPT, "gpt-6-sol", None,
        home, "session-q1", True, skill_profile="generic",
    )


def _write_config(home: Path, text: str = "[features]\ndaemon_auto_start = false\n") -> Path:
    path = home / "config.toml"
    path.write_text(text)
    path.chmod(0o600)
    return path


def test_codex_runner_and_materialized_configs_disable_daemon(tmp_path: Path) -> None:
    agent = _agent(tmp_path / "q1")
    args = server.agent_base_args("gpt-6-sol", "xhigh", service_tier="default")
    assert args[0] == "--no-daemon"
    assert args[args.index("-c") + 1] == 'model="gpt-6-sol"'
    assert 'service_tier="default"' in args

    with patch.object(server, "_runtime_mcp_entrypoint", return_value=tmp_path / "mcp"):
        _, fleet_text = server.fleet_minimal_config(agent)
    pool_text = server.pool_minimal_config(agent.home)
    for text, model in ((fleet_text, "gpt-6-sol"), (pool_text, server.DEFAULT_AGENT_MODEL)):
        document = tomllib.loads(text)
        assert document["features"]["daemon_auto_start"] is False
        assert document["model"] == model
        assert document["projects"][str(agent.home)]["trust_level"] == "trusted"

    refreshed = server._home_refresh_config(
        agent.home, fleet_text.encode(), model="gpt-6-sol", reasoning_effort="xhigh"
    )
    assert tomllib.loads(refreshed.decode())["features"]["daemon_auto_start"] is False


@pytest.mark.parametrize("artifact", (
    "app-server-daemon/daemon.pid",
    "app-server-daemon/daemon-updater.pid",
    "app-server-daemon/daemon-updater.sock",
    "ipc/ipc.sock",
))
@pytest.mark.parametrize("kind", ("file", "dangling_symlink"))
def test_bound_home_daemon_artifact_blocks_even_if_stale(
    tmp_path: Path, artifact: str, kind: str,
) -> None:
    home = tmp_path / "q1"
    target = home / artifact
    target.parent.mkdir(parents=True)
    home.chmod(0o700)
    target.parent.chmod(0o700)
    if kind == "file":
        target.write_text("999999\n")
    else:
        target.symlink_to("missing")

    with pytest.raises(server.AgentError, match="managed_codex_daemon_artifact_present"):
        server._require_managed_codex_daemon_free(home)
    assert target.is_symlink() or target.read_text() == "999999\n"


def test_clean_home_ignores_personal_artifacts(tmp_path: Path) -> None:
    personal = tmp_path / "personal"
    hive = tmp_path / "hive"
    (personal / "app-server-daemon").mkdir(parents=True)
    (personal / "app-server-daemon" / "daemon.pid").write_text("42\n")
    hive.mkdir()
    hive.chmod(0o700)
    _write_config(hive)
    server._require_managed_codex_daemon_free(hive)
    assert (personal / "app-server-daemon" / "daemon.pid").read_text() == "42\n"


@pytest.mark.parametrize("kind", ("parent_symlink", "wrong_mode", "unreadable", "live_socket"))
def test_daemon_guard_fails_closed_on_ambiguous_home_state(
    tmp_path: Path, kind: str,
) -> None:
    home = tmp_path / "hive"
    home.mkdir(mode=0o700)
    if kind == "parent_symlink":
        foreign = tmp_path / "foreign"
        foreign.mkdir(mode=0o700)
        (home / "ipc").symlink_to(foreign, target_is_directory=True)
        error = "managed_codex_daemon_home_unknown"
    elif kind == "wrong_mode":
        (home / "ipc").mkdir(mode=0o755)
        error = "managed_codex_daemon_home_unknown"
    elif kind == "unreadable":
        (home / "ipc").mkdir(mode=0o700)
        (home / "ipc").chmod(0o000)
        error = "managed_codex_daemon_home_unknown"
    else:
        (home / "ipc").mkdir(mode=0o700)
        sock = socket.socket(socket.AF_UNIX)
        try:
            sock.bind(str(home / "ipc" / "ipc.sock"))
            with pytest.raises(server.AgentError, match="managed_codex_daemon_artifact_present"):
                server._require_managed_codex_daemon_free(home)
        finally:
            sock.close()
        return
    with pytest.raises(server.AgentError, match=error):
        server._require_managed_codex_daemon_free(home)
    if kind == "unreadable":
        (home / "ipc").chmod(0o700)


def test_home_refresh_rejects_daemon_feature_override(tmp_path: Path) -> None:
    config = b'model = "gpt-6-sol"\n[features]\ndaemon_auto_start = true\n'
    with pytest.raises(server.AgentError, match="agent_class_materialization_invalid"):
        server._home_refresh_config(
            tmp_path, config, model="gpt-6-sol", reasoning_effort="xhigh"
        )


@pytest.mark.parametrize("config", (None, "", "[features]\ndaemon_auto_start = true\n"))
def test_bound_home_config_must_explicitly_disable_daemon(
    tmp_path: Path, config: str | None,
) -> None:
    home = tmp_path / "hive"
    home.mkdir(mode=0o700)
    if config is not None:
        _write_config(home, config)
    with pytest.raises(server.AgentError, match="managed_codex_daemon_config_invalid"):
        server._require_managed_codex_daemon_free(home)
    assert (home / "config.toml").exists() is (config is not None)


@pytest.mark.parametrize("raced_path", ("home", "config"))
def test_daemon_guard_rechecks_privacy_after_config_read(
    tmp_path: Path, raced_path: str,
) -> None:
    home = tmp_path / "hive"
    home.mkdir(mode=0o700)
    config = _write_config(home)
    original_read = server._fleet_read_private_file_at

    def change_permissions_after_read(*args: object, **kwargs: object):
        result = original_read(*args, **kwargs)
        (home if raced_path == "home" else config).chmod(
            0o777 if raced_path == "home" else 0o666
        )
        return result

    try:
        with patch.object(
            server, "_fleet_read_private_file_at", side_effect=change_permissions_after_read
        ):
            with pytest.raises(
                server.AgentError,
                match=(
                    "managed_codex_daemon_home_unknown"
                    if raced_path == "home"
                    else "managed_codex_daemon_config_invalid"
                ),
            ):
                server._require_managed_codex_daemon_free(home)
    finally:
        home.chmod(0o700)
        config.chmod(0o600)


@pytest.mark.parametrize("race", ("artifact", "parent_mode", "parent_replaced"))
def test_daemon_guard_rechecks_artifact_parent_after_config_read(
    tmp_path: Path, race: str,
) -> None:
    home = tmp_path / "hive"
    parent = home / "app-server-daemon"
    parent.mkdir(parents=True, mode=0o700)
    home.chmod(0o700)
    _write_config(home)
    original_read = server._fleet_read_private_file_at

    def race_after_read(*args: object, **kwargs: object):
        result = original_read(*args, **kwargs)
        if race == "artifact":
            (parent / "daemon.pid").write_text("999999\n")
        elif race == "parent_mode":
            parent.chmod(0o777)
        else:
            parent.rename(home / "old-app-server-daemon")
            parent.mkdir(mode=0o700)
        return result

    try:
        with patch.object(server, "_fleet_read_private_file_at", side_effect=race_after_read):
            with pytest.raises(
                server.AgentError,
                match=(
                    "managed_codex_daemon_artifact_present"
                    if race == "artifact"
                    else "managed_codex_daemon_home_unknown"
                ),
            ):
                server._require_managed_codex_daemon_free(home)
    finally:
        if parent.exists():
            parent.chmod(0o700)
    if race == "artifact":
        assert (parent / "daemon.pid").read_text() == "999999\n"


@pytest.mark.parametrize("race", ("symlink", "unsafe_mode"))
def test_daemon_guard_rechecks_home_parent_chain_after_config_read(
    tmp_path: Path, race: str,
) -> None:
    pool = tmp_path / "pool"
    home = pool / "hive"
    home.mkdir(parents=True, mode=0o700)
    _write_config(home)
    moved = tmp_path / "moved-pool"
    original_read = server._fleet_read_private_file_at

    def replace_parent_with_symlink(*args: object, **kwargs: object):
        result = original_read(*args, **kwargs)
        if race == "symlink":
            pool.rename(moved)
            pool.symlink_to(moved, target_is_directory=True)
        else:
            pool.chmod(0o777)
        return result

    try:
        with patch.object(
            server, "_fleet_read_private_file_at", side_effect=replace_parent_with_symlink
        ):
            with pytest.raises(server.AgentError, match="managed_codex_daemon_home_unknown"):
                server._require_managed_codex_daemon_free(home)
    finally:
        if pool.is_symlink():
            pool.unlink()
            moved.rename(pool)
        else:
            pool.chmod(0o700)


def test_pool_wrapper_prepends_flag_to_start_and_resume(tmp_path: Path) -> None:
    home = tmp_path / "hive"
    home.mkdir(mode=0o700)
    _write_config(home)
    fake = tmp_path / "fake-codex"
    fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    fake.chmod(0o700)
    wrapper = tmp_path / "wrapper"
    wrapper.write_text(server.pool_wrapper_text("q1", home, str(fake)))
    wrapper.chmod(0o700)
    env = dict(os.environ)
    env.pop("CODEX_AGENT_BIN", None)
    for args in ((), ("resume", "--last")):
        result = subprocess.run(
            [str(wrapper), *args], env=env, capture_output=True, text=True,
            timeout=5, check=True,
        )
        assert result.stdout.splitlines() == ["--no-daemon", *args]


@pytest.mark.parametrize("wrapper_kind", ("pool", "fleet"))
@pytest.mark.parametrize("args", ((), ("resume", "--last")))
def test_direct_wrapper_blocks_daemon_artifact_before_child(
    tmp_path: Path, args: tuple[str, ...], wrapper_kind: str,
) -> None:
    home = tmp_path / "hive"
    (home / "app-server-daemon").mkdir(parents=True)
    home.chmod(0o700)
    (home / "app-server-daemon").chmod(0o700)
    artifact = home / "app-server-daemon" / "daemon.pid"
    artifact.write_text("999999\n")
    _write_config(home)
    marker = tmp_path / "child-ran"
    fake = tmp_path / "fake-codex"
    fake.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
    fake.chmod(0o700)
    wrapper = tmp_path / "wrapper"
    wrapper.write_text(
        server.pool_wrapper_text("q1", home, str(fake))
        if wrapper_kind == "pool"
        else server.fleet_wrapper_text(_agent(home), fake)
    )
    wrapper.chmod(0o700)

    result = subprocess.run(
        [str(wrapper), *args], capture_output=True, text=True, timeout=10,
        env={key: value for key, value in os.environ.items() if key != "CODEX_AGENT_BIN"},
    )
    assert result.returncode == 76
    assert "managed_codex_daemon_artifact_present" in result.stderr
    assert not marker.exists()
    assert artifact.read_text() == "999999\n"


@pytest.mark.parametrize("wrapper_kind", ("pool", "fleet"))
@pytest.mark.parametrize("config", (None, "[features]\ndaemon_auto_start = true\n"))
def test_direct_wrapper_blocks_unhardened_config_before_child(
    tmp_path: Path, wrapper_kind: str, config: str | None,
) -> None:
    home = tmp_path / "hive"
    home.mkdir(mode=0o700)
    if config is not None:
        _write_config(home, config)
    marker = tmp_path / "child-ran"
    fake = tmp_path / "fake-codex"
    fake.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
    fake.chmod(0o700)
    wrapper = tmp_path / "wrapper"
    wrapper.write_text(
        server.pool_wrapper_text("q1", home, str(fake))
        if wrapper_kind == "pool"
        else server.fleet_wrapper_text(_agent(home), fake)
    )
    wrapper.chmod(0o700)
    result = subprocess.run(
        [str(wrapper), "resume", "--last"], capture_output=True, text=True,
        timeout=10,
        env={key: value for key, value in os.environ.items() if key != "CODEX_AGENT_BIN"},
    )
    assert result.returncode == 76
    assert "managed_codex_daemon_config_invalid" in result.stderr
    assert not marker.exists()
    assert (home / "config.toml").exists() is (config is not None)


def test_codex_0161_parser_rejects_path_launcher_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher_directory = tmp_path / "bin"
    launcher_directory.mkdir(mode=0o700)
    marker = tmp_path / "launcher-executed"
    launcher = launcher_directory / "codex"
    launcher.write_text(
        '#!/bin/sh\nprintf executed > "$CODEX_TEST_WRAPPER_MARKER"\n'
        'case "$1" in\n'
        "  features) printf 'daemon_auto_start stable false\\n' ;;\n"
        "  *) printf 'codex-cli 0.161.0\\n' ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    launcher.chmod(0o700)
    monkeypatch.setenv("PATH", f"{launcher_directory}:/usr/bin:/bin")
    monkeypatch.setenv("CODEX_TEST_WRAPPER_MARKER", str(marker))

    with pytest.raises(pytest.skip.Exception, match="PATH launcher rejected"):
        test_codex_0161_parser_accepts_start_and_resume_flag(tmp_path)

    assert not marker.exists()


def test_codex_0161_parser_accepts_start_and_resume_flag(tmp_path: Path) -> None:
    codex = shutil.which("codex")
    if codex is None:
        pytest.skip("Codex CLI unavailable")
    try:
        with Path(codex).open("rb") as candidate:
            native_header = candidate.read(4)
    except OSError:
        pytest.skip("native Codex CLI unavailable")
    if native_header != b"\x7fELF":
        pytest.skip("native Codex CLI unavailable (PATH launcher rejected)")
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    env = dict(os.environ, CODEX_HOME=str(home))
    version = subprocess.run(
        [codex, "--version"], env=env, capture_output=True, text=True, timeout=10,
        check=True,
    )
    if version.stdout.strip() != "codex-cli 0.161.0":
        pytest.skip("Codex CLI 0.161.0 unavailable")
    for args in (("--no-daemon", "--version"), ("--no-daemon", "resume", "--help")):
        result = subprocess.run(
            [codex, *args], env=env, capture_output=True, text=True,
            timeout=10, check=True,
        )
        assert "0.161.0" in result.stdout or "--no-daemon" in result.stdout
    assert not any(home.iterdir())
    (home / "config.toml").write_text("[features]\ndaemon_auto_start = false\n")
    features = subprocess.run(
        [codex, "features", "list"], env=env, capture_output=True, text=True,
        timeout=10, check=True,
    )
    assert any(
        line.split()[-1] == "false" for line in features.stdout.splitlines()
        if line.lstrip().startswith("daemon_auto_start ")
    )


def test_daemon_artifact_blocks_start_before_enrollment(tmp_path: Path) -> None:
    pool = tmp_path / "pool"
    home = pool / "q1"
    (home / "ipc").mkdir(parents=True)
    home.chmod(0o700)
    (home / "ipc").chmod(0o700)
    (home / "ipc" / "ipc.sock").touch()
    descriptor = _agent(home)
    with (
        patch.object(server, "AGENT_POOL_ROOT", pool),
        patch.object(server, "require_fleet_recovery_ready"),
        patch.object(server, "canonical_agent_id", return_value="q1"),
        patch.object(server, "_reject_legacy_teamlead_start_target"),
        patch.object(server, "_ollama_descriptor", return_value=None),
        patch.object(server, "ensure_state"),
        patch.object(server, "agent_config", return_value={"runner": home / "codex", "home": home, "session": "s"}),
        patch.object(server, "current_agent_inventory", return_value=SimpleNamespace(agents={"q1": descriptor})),
        patch.object(server, "enroll_managed_principal") as enroll,
    ):
        with pytest.raises(server.AgentError, match="managed_codex_daemon_artifact_present"):
            server._start_agent_unlocked("q1", agent_class="teamleiterin")
    enroll.assert_not_called()


@pytest.mark.parametrize("config", (None, "[features]\ndaemon_auto_start = true\n"))
def test_unhardened_config_blocks_start_before_enrollment(
    tmp_path: Path, config: str | None,
) -> None:
    pool = tmp_path / "pool"
    home = pool / "q1"
    home.mkdir(parents=True, mode=0o700)
    if config is not None:
        _write_config(home, config)
    descriptor = _agent(home)
    with (
        patch.object(server, "AGENT_POOL_ROOT", pool),
        patch.object(server, "require_fleet_recovery_ready"),
        patch.object(server, "canonical_agent_id", return_value="q1"),
        patch.object(server, "_reject_legacy_teamlead_start_target"),
        patch.object(server, "_ollama_descriptor", return_value=None),
        patch.object(server, "ensure_state"),
        patch.object(server, "agent_config", return_value={"runner": home / "codex", "home": home, "session": "s"}),
        patch.object(server, "current_agent_inventory", return_value=SimpleNamespace(agents={"q1": descriptor})),
        patch.object(server, "enroll_managed_principal") as enroll,
    ):
        with pytest.raises(server.AgentError, match="managed_codex_daemon_config_invalid"):
            server._start_agent_unlocked("q1", agent_class="teamleiterin")
    enroll.assert_not_called()
    assert (home / "config.toml").exists() is (config is not None)
