from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from conftest import seal_runtime_image
import codex_master.server as server
from codex_master.runtime_layout import RuntimeLayout


def _write(root: Path, relative: str, content: str, mode: int = 0o644) -> None:
    path = root / relative
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def runtime_layout(tmp_path: Path) -> RuntimeLayout:
    root = tmp_path / "codex-master-runtime"
    root.mkdir(mode=0o700)
    _write(root, "bin/codex-master-mcp", "#!/bin/sh\nexit 0\n", 0o755)
    _write(root, "bin/codex-master-hive-hourly-probe", "#!/bin/sh\nexit 0\n", 0o755)
    _write(
        root,
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
    _write(
        root,
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
    _write(root, ".app.json", json.dumps({"apps": {"codex-master": {}}}))
    _write(root, "hooks/hooks.json", json.dumps({"hooks": {}}))
    _write(root, "skills/codex-master-fleet/SKILL.md", "# Fleet\n")
    _write(root, "codex-hive.json", "{}")
    _write(root, "codex-agent-classes.json", "{}")
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o700)
    seal_runtime_image(root)
    return RuntimeLayout.from_runtime_root(root)


class _PinnedMcpBinding:
    def __init__(self) -> None:
        self.command_path = Path("/proc/self/fd/71")
        self.config_path = Path("/proc/self/fd/73/config.toml")
        self.environment = {"HOME": "/proc/self/fd/72", "PATH": "/usr/bin:/bin"}
        self.pass_fds = (71, 72)
        self.revalidate = Mock()


def test_interactive_registration_uses_the_validated_image_entrypoint(
    tmp_path: Path,
) -> None:
    layout = runtime_layout(tmp_path)
    binding = _PinnedMcpBinding()
    startup = {"ok": True, "raw_output": "not_returned"}
    current = {
        "registered": False,
        "lookup_status": "not_registered",
        "command_matches": False,
        "startup_timeout_ok": False,
        "ok": False,
    }
    timeout = {"status": "updated", "_config_snapshot": None}

    with (
        patch.object(server, "_runtime_layout", return_value=layout),
        patch.object(server, "assert_install_context_allows_master_registration"),
        patch.object(
            server, "enroll_current_teamleader", return_value={"changed": False}
        ),
        patch.object(server, "ensure_applet_action_key"),
        patch.object(server, "mcp_command_startup_self_test", return_value=startup),
        patch.object(server, "check_mcp_registration", return_value=current),
        patch.object(
            server, "_codex_mcp_binding", return_value=contextlib.nullcontext(binding)
        ),
        patch.object(server, "install_lock", return_value=contextlib.nullcontext()),
        patch.object(
            server, "ensure_mcp_startup_timeout_configured", return_value=timeout
        ),
        patch.object(server, "run_command") as run,
    ):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = server.install(register=True, sync_plugin_cache=False)

    run.assert_called_once_with(
        [
            str(binding.command_path),
            "mcp",
            "add",
            server.MCP_SERVER_NAME,
            "--",
            str(layout.mcp_entrypoint),
        ],
        env=binding.environment,
        pass_fds=binding.pass_fds,
    )
    assert result["runtime_entrypoint"] == "not_returned"
    assert "symlink" not in result
    assert result["mcp"]["status"] == "registered"


def test_interactive_unregistration_only_removes_matching_image_registration(
    tmp_path: Path,
) -> None:
    layout = runtime_layout(tmp_path)
    binding = _PinnedMcpBinding()
    current = {
        "registered": True,
        "lookup_status": "registered",
        "command_matches": True,
    }

    with (
        patch.object(server, "_runtime_layout", return_value=layout),
        patch.object(server, "check_mcp_registration", return_value=current),
        patch.object(
            server, "_codex_mcp_binding", return_value=contextlib.nullcontext(binding)
        ),
        patch.object(server, "install_lock", return_value=contextlib.nullcontext()),
        patch.object(
            server, "revoke_current_teamleader", return_value={"changed": False}
        ),
        patch.object(server, "run_command") as run,
    ):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = server.uninstall()

    run.assert_called_once_with(
        [str(binding.command_path), "mcp", "remove", server.MCP_SERVER_NAME],
        env=binding.environment,
        pass_fds=binding.pass_fds,
    )
    assert result["mcp"] == "removed"
    assert "symlink" not in result


def test_registration_inspection_uses_canonical_cli_with_a_sterile_image_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _PinnedMcpBinding()
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    completed = subprocess.CompletedProcess(
        [str(binding.command_path), "mcp", "get", server.MCP_SERVER_NAME],
        0,
        "\n".join(
            [
                server.MCP_SERVER_NAME,
                "  command: /runtime/bin/codex-master-mcp",
                "  startup_timeout_sec: 120",
            ]
        ),
        "",
    )

    with (
        patch.object(
            server, "_codex_mcp_binding", return_value=contextlib.nullcontext(binding)
        ),
        patch.object(server, "run_command", return_value=completed) as run,
        patch.object(
            server.shutil,
            "which",
            side_effect=AssertionError("registration inspection must not resolve PATH"),
        ),
    ):
        result = server.check_mcp_registration(Path("/runtime/bin/codex-master-mcp"))

    run.assert_called_once_with(
        [str(binding.command_path), "mcp", "get", server.MCP_SERVER_NAME],
        env=binding.environment,
        pass_fds=binding.pass_fds,
    )
    assert result["lookup_status"] == "registered"
    assert result["ok"] is True


def test_registration_inspection_fails_closed_without_a_valid_canonical_cli() -> None:
    with (
        patch.object(
            server,
            "_canonical_codex_cli_path",
            side_effect=server.AgentError("canonical_codex_cli_unavailable"),
        ),
        patch.object(server.shutil, "which", return_value="/tmp/attacker/codex"),
        patch.object(server, "run_command") as run,
    ):
        result = server.check_mcp_registration(Path("/runtime/bin/codex-master-mcp"))

    run.assert_not_called()
    assert result == {
        "registered": False,
        "lookup_status": "unavailable",
        "ok": False,
        "reason": "canonical Codex CLI unavailable",
    }


def test_registration_inspection_uses_only_the_pinned_cli_and_client_home(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _PinnedMcpBinding()
    monkeypatch.setenv("HOME", "/tmp/attacker-home")
    monkeypatch.setenv("CODEX_HOME", "/tmp/attacker-codex-home")
    completed = subprocess.CompletedProcess(
        [str(binding.command_path), "mcp", "get", server.MCP_SERVER_NAME],
        0,
        "\n".join(
            [
                server.MCP_SERVER_NAME,
                "  command: /runtime/bin/codex-master-mcp",
                "  startup_timeout_sec: 120",
            ]
        ),
        "",
    )

    with (
        patch.object(server, "run_command", return_value=completed) as run,
        patch.object(
            server,
            "_canonical_codex_cli_path",
            side_effect=AssertionError("a pinned binding must not resolve again"),
        ),
    ):
        result = server.check_mcp_registration(
            Path("/runtime/bin/codex-master-mcp"), binding=binding
        )

    run.assert_called_once_with(
        [str(binding.command_path), "mcp", "get", server.MCP_SERVER_NAME],
        env=binding.environment,
        pass_fds=binding.pass_fds,
    )
    assert result["ok"] is True
    assert binding.revalidate.call_count == 2


@pytest.mark.parametrize("register", (True, False))
def test_install_rejects_unavailable_binding_before_any_applet_or_registry_mutation(
    tmp_path: Path,
    register: bool,
) -> None:
    action_key = tmp_path / "state" / "applet-action.key"
    layout = runtime_layout(tmp_path)
    binding_error = server.AgentError("canonical_codex_cli_unavailable")

    with (
        patch.object(
            server,
            "_codex_mcp_binding",
            side_effect=binding_error,
        ),
        patch.object(server, "install_lock") as lock,
        patch.object(server, "assert_install_context_allows_master_registration") as context,
        patch.object(server, "_runtime_layout", return_value=layout),
        patch.object(server, "enroll_current_teamleader") as enroll,
        patch.object(server, "ensure_applet_action_key") as ensure_key,
        patch.object(
            server,
            "install_fleet_desktop_entry",
            return_value=({"status": "installed"}, {"changed": False}),
        ) as desktop,
        patch.object(server, "ensure_mcp_startup_timeout_configured") as config,
        patch.object(
            server,
            "mcp_command_startup_self_test",
            return_value={"ok": True},
        ),
        patch.object(
            server,
            "check_mcp_registration",
            return_value={"lookup_status": "unavailable"},
        ),
        patch.object(server, "APPLET_ACTION_KEY_FILE", action_key),
    ):
        with pytest.raises(server.AgentError):
            server.install(register=register, install_desktop=True)

    context.assert_not_called()
    lock.assert_not_called()
    enroll.assert_not_called()
    ensure_key.assert_not_called()
    desktop.assert_not_called()
    config.assert_not_called()
    assert not action_key.exists()


@pytest.mark.parametrize("unregister", (True, False))
def test_uninstall_rejects_unavailable_binding_before_desktop_or_registry_mutation(
    unregister: bool,
) -> None:
    binding_error = server.AgentError("canonical_codex_mcp_binding_unavailable")

    with (
        patch.object(server, "_codex_mcp_binding", side_effect=binding_error),
        patch.object(server, "install_lock") as lock,
        patch.object(server, "remove_fleet_desktop_entry") as desktop,
        patch.object(server, "revoke_current_teamleader") as revoke,
    ):
        with pytest.raises(server.AgentError, match="canonical_codex_mcp_binding_unavailable"):
            server.uninstall(unregister=unregister, remove_desktop=True)

    lock.assert_not_called()
    desktop.assert_not_called()
    revoke.assert_not_called()


def test_force_rollback_reuses_one_pinned_cli_and_client_home_after_add_failure(
    tmp_path: Path,
) -> None:
    layout = runtime_layout(tmp_path)
    binding = _PinnedMcpBinding()
    current = {
        "registered": True,
        "lookup_status": "registered",
        "command_matches": False,
        "startup_timeout_ok": True,
        "ok": False,
        "_registered_command": "/previous/codex-master-mcp",
    }
    completed = [
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 1, "", ""),
        subprocess.CompletedProcess([], 0, "", ""),
    ]

    with (
        patch.object(
            server,
            "_codex_mcp_binding",
            return_value=contextlib.nullcontext(binding),
        ) as bind,
        patch.object(server, "install_lock", return_value=contextlib.nullcontext()),
        patch.object(server, "_runtime_layout", return_value=layout),
        patch.object(server, "assert_install_context_allows_master_registration"),
        patch.object(
            server, "enroll_current_teamleader", return_value={"changed": False}
        ),
        patch.object(server, "ensure_applet_action_key"),
        patch.object(server, "mcp_command_startup_self_test", return_value={"ok": True}),
        patch.object(server, "check_mcp_registration", return_value=current) as check,
        patch.object(
            server,
            "codex_client_mcp_config_status",
            return_value={
                "startup_timeout_ok": True,
                "default_tools_approval_mode_ok": True,
            },
        ),
        patch.object(
            server,
            "_canonical_codex_cli_path",
            side_effect=AssertionError("force transaction must not resolve again"),
        ),
        patch.object(server, "run_command", side_effect=completed) as run,
    ):
        with pytest.raises(server.AgentError, match="codex mcp add failed"):
            server.install(register=True, force=True, sync_plugin_cache=False)

    bind.assert_called_once_with(create_config_directory=True)
    check.assert_called_once_with(
        layout.mcp_entrypoint, include_command=True, binding=binding
    )
    assert [call.args[0][0] for call in run.call_args_list] == [
        str(binding.command_path),
        str(binding.command_path),
        str(binding.command_path),
    ]
    assert all(call.kwargs["env"] == binding.environment for call in run.call_args_list)
    assert all(call.kwargs["pass_fds"] == binding.pass_fds for call in run.call_args_list)
    assert binding.revalidate.call_count == 6


def test_binding_pins_cli_and_client_home_across_a_filesystem_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "main-home"
    home.mkdir(mode=0o700)
    (home / ".codex").mkdir(mode=0o700)
    executable = tmp_path / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    moved_home = tmp_path / "main-home-pinned"
    replacement_home = tmp_path / "replacement-home"
    replacement_home.mkdir(mode=0o700)
    (replacement_home / ".codex").mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(replacement_home))
    monkeypatch.setenv("CODEX_HOME", str(replacement_home / ".codex"))
    completed = subprocess.CompletedProcess([], 0, "", "")

    with (
        patch.object(server.os, "geteuid", return_value=1000),
        patch.object(
            server.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))
        ),
        patch.object(server, "_canonical_codex_cli_path", return_value=executable),
        patch.object(server, "run_command", return_value=completed) as run,
    ):
        with server._codex_mcp_binding() as binding:
            first_home = binding.environment["HOME"]
            first_cli = str(binding.command_path)
            first_pass_fds = binding.pass_fds
            configured = server.ensure_mcp_startup_timeout_configured(
                binding.config_path
            )
            assert configured["status"] == "updated"
            status = server.codex_client_mcp_config_status(
                binding.config_path,
                command_path=Path("/runtime/bin/codex-master-mcp"),
            )
            assert status["path_state"] == "set"
            server._run_bound_codex_mcp_command(
                binding, "get", server.MCP_SERVER_NAME
            )
            home.rename(moved_home)
            replacement_home.rename(home)
            server._run_bound_codex_mcp_command(
                binding, "remove", server.MCP_SERVER_NAME
            )

    assert [call.args[0][0] for call in run.call_args_list] == [first_cli, first_cli]
    assert all(call.kwargs["env"]["HOME"] == first_home for call in run.call_args_list)
    assert all("CODEX_HOME" not in call.kwargs["env"] for call in run.call_args_list)
    assert all(call.kwargs["pass_fds"] == first_pass_fds for call in run.call_args_list)
    assert (moved_home / ".codex" / "config.toml").is_file()
    assert not (home / ".codex" / "config.toml").exists()


def test_binding_creates_a_missing_client_config_directory_through_the_pinned_home(
    tmp_path: Path,
) -> None:
    home = tmp_path / "main-home"
    home.mkdir(mode=0o700)
    executable = tmp_path / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)

    with (
        patch.object(server.os, "geteuid", return_value=1000),
        patch.object(
            server.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))
        ),
        patch.object(server, "_canonical_codex_cli_path", return_value=executable),
    ):
        with server._codex_mcp_binding(create_config_directory=True) as binding:
            assert binding.config_path.parent.resolve() == home / ".codex"
            assert Path(binding.environment["HOME"]).resolve() == home

    config_home = home / ".codex"
    assert config_home.is_dir()
    assert not config_home.is_symlink()
    assert config_home.stat().st_mode & 0o777 == 0o700


def test_registration_inspection_does_not_create_a_missing_client_config_directory(
    tmp_path: Path,
) -> None:
    home = tmp_path / "main-home"
    home.mkdir(mode=0o700)
    executable = tmp_path / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)

    with (
        patch.object(server.os, "geteuid", return_value=1000),
        patch.object(
            server.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))
        ),
        patch.object(server, "_canonical_codex_cli_path", return_value=executable),
        patch.object(server, "run_command") as run,
    ):
        result = server.check_mcp_registration(
            Path("/runtime/bin/codex-master-mcp")
        )

    run.assert_not_called()
    assert result["lookup_status"] == "unavailable"
    assert not (home / ".codex").exists()


def test_binding_rejects_a_symlinked_client_config_directory(tmp_path: Path) -> None:
    home = tmp_path / "main-home"
    home.mkdir(mode=0o700)
    target = tmp_path / "attacker-config"
    target.mkdir(mode=0o700)
    (home / ".codex").symlink_to(target, target_is_directory=True)
    executable = tmp_path / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)

    with (
        patch.object(server.os, "geteuid", return_value=1000),
        patch.object(
            server.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))
        ),
        patch.object(server, "_canonical_codex_cli_path", return_value=executable),
    ):
        with pytest.raises(server.AgentError, match="canonical_codex_mcp_binding_unavailable"):
            with server._codex_mcp_binding():
                pass


def test_canonical_codex_cli_uses_the_documented_system_absolute_location() -> None:
    canonical = Path("/usr/local/bin/codex")
    resolved = Path("/opt/codex/bin/codex")

    with (
        patch.dict(server.os.environ, {"HOME": "/tmp/attacker-home"}),
        patch.object(
            server, "trusted_runner_executable", return_value=resolved
        ) as validate,
        patch.object(
            server.shutil,
            "which",
            side_effect=AssertionError("canonical CLI must not resolve PATH"),
        ),
    ):
        assert server._canonical_codex_cli_path() == resolved

    validate.assert_called_once_with(canonical)


def test_canonical_codex_cli_rejects_an_untrusted_fixed_location() -> None:
    with (
        patch.object(
            server,
            "trusted_runner_executable",
            side_effect=server.AgentError("fleet_executable_invalid"),
        ),
    ):
        with pytest.raises(server.AgentError, match="canonical_codex_cli_unavailable"):
            server._canonical_codex_cli_path()


def test_executable_directory_trust_uses_the_effective_user_identity(
    tmp_path: Path,
) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    executable = trusted / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)

    with (
        patch.object(server.os, "geteuid", return_value=os.geteuid()),
        patch.object(server.os, "getuid", return_value=os.geteuid() + 1),
    ):
        assert server.executable_directory_chain_is_trusted(trusted)
        assert server.trusted_runner_executable(executable) == executable


def test_interactive_cli_exposes_no_path_or_symlink_override() -> None:
    with pytest.raises(SystemExit):
        server.main_cli(["install", "--path", "/tmp/other"])
    with pytest.raises(SystemExit):
        server.main_cli(["uninstall", "--remove-symlink"])


def test_runtime_cutover_source_has_no_legacy_registration_path() -> None:
    source = Path(server.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "DEFAULT_INSTALL_PATH",
        "repo_wrapper_path",
        "replace_install_symlink",
        "remove_install_symlink",
        "restore_install_symlink",
        "--remove-symlink",
    ):
        assert forbidden not in source


def test_agent_pool_installer_uses_only_the_runtime_image_entrypoint() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "install-agent-pool"
    source = script.read_text(encoding="utf-8")

    assert (
        '"${HOME}/.local/lib/codex-master-runtime/bin/codex-master-mcp" pool install'
        in source
    )
    assert "repo_root" not in source
    assert "/.local/bin/codex-master-mcp" not in source


def test_unauthorized_runtime_surface_stays_sterile_until_a_principal_is_verified(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "runtime_status", "arguments": {}},
        },
        {"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "agent_start", "arguments": {"agent": "a1"}},
        },
    ]
    responses: list[dict[str, object]] = []
    unauthenticated = {
        "authorized": False,
        "role": "non_teamleader",
        "principal_class": None,
        "visible_tool_count": 0,
        "raw_output": "not_returned",
    }
    runtime_payload = {
        "ok": False,
        "metadata": {"ok": False, "reason_code": "metadata_invalid"},
        "mcp_surface": {"ok": False, "reason_code": "metadata_invalid"},
        "raw_output": "not_returned",
    }

    with (
        patch.object(server, "STATE_ROOT", state_root),
        patch.object(server, "RAW_DIR", state_root / "raw"),
        patch.object(server, "META_DIR", state_root / "meta"),
        patch.object(server, "LOCK_DIR", state_root / "locks"),
        patch.object(server, "LEASE_DIR", state_root / "leases"),
        patch.object(server, "master_tool_access_status", return_value=unauthenticated),
        patch.object(server, "runtime_status", return_value=runtime_payload),
        patch.object(server, "ensure_state") as ensure_state,
        patch.object(server, "prune_raw_logs") as prune_raw_logs,
        patch.object(server, "_fleet_initialize_recovery_startup_state") as recovery,
        patch.object(server, "_publish_startup_fleet_inventory") as publish,
        patch.object(server, "read_message", side_effect=[*requests, None]),
        patch.object(server, "write_message", side_effect=responses.append),
    ):
        assert server.serve_mcp() == 0

    ensure_state.assert_not_called()
    prune_raw_logs.assert_not_called()
    recovery.assert_not_called()
    publish.assert_not_called()
    assert not state_root.exists()
    tools = next(response for response in responses if response.get("id") == 2)
    assert tools["result"] == {"tools": [server.TOOLS[0]]}
    runtime = next(response for response in responses if response.get("id") == 3)
    assert runtime["result"]["isError"] is False
    blocked_resources = next(
        response for response in responses if response.get("id") == 4
    )
    assert blocked_resources["error"]["message"] == "teamleader authorization required"
    blocked_tool = next(response for response in responses if response.get("id") == 5)
    assert blocked_tool["result"]["isError"] is True
    assert str(tmp_path) not in json.dumps(blocked_tool)


def test_unauthorized_stdio_runtime_status_creates_no_private_state(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    requests = (
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "runtime_status", "arguments": {}},
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "agent_start", "arguments": {"agent": "a1"}},
        },
    )
    completed = subprocess.run(
        [Path(__file__).resolve().parents[1] / "bin" / "codex-master-mcp"],
        input="".join(
            json.dumps(request, separators=(",", ":")) + "\n" for request in requests
        ),
        text=True,
        capture_output=True,
        check=False,
        cwd=tmp_path,
        env={
            "HOME": str(home),
            "PATH": "/attacker/path",
            "PYTHONPATH": "/attacker/python",
            "CODEX_HOME": str(tmp_path / "attacker"),
        },
    )

    assert completed.returncode == 0, completed.stderr
    responses = [json.loads(line) for line in completed.stdout.splitlines()]
    tools = next(response for response in responses if response.get("id") == 2)
    assert [tool["name"] for tool in tools["result"]["tools"]] == ["runtime_status"]
    runtime = next(response for response in responses if response.get("id") == 3)
    assert runtime["result"]["isError"] is False
    blocked = next(response for response in responses if response.get("id") == 4)
    assert blocked["result"]["isError"] is True
    assert str(tmp_path) not in json.dumps(blocked)
    assert not (home / ".local" / "state" / "codex-master-mcp").exists()


def test_authorized_mcp_request_initializes_the_regular_server_state() -> None:
    authorized = {
        "authorized": True,
        "role": "koenigin",
        "principal_class": "koenigin",
        "visible_tool_count": len(server.TOOLS),
        "raw_output": "not_returned",
    }
    with (
        patch.object(server, "master_tool_access_status", return_value=authorized),
        patch.object(server, "ensure_state") as ensure_state,
        patch.object(server, "_fleet_initialize_recovery_startup_state"),
        patch.object(server, "_publish_startup_fleet_inventory"),
        patch.object(
            server,
            "read_message",
            side_effect=[
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                None,
            ],
        ),
        patch.object(server, "write_message"),
    ):
        assert server.serve_mcp() == 0

    ensure_state.assert_called_once()
