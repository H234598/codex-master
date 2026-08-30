from __future__ import annotations

import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

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
    return RuntimeLayout.from_runtime_root(root)


def test_interactive_registration_uses_the_validated_image_entrypoint(
    tmp_path: Path,
) -> None:
    layout = runtime_layout(tmp_path)
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
            server, "ensure_mcp_startup_timeout_configured", return_value=timeout
        ),
        patch.object(server, "run_command") as run,
    ):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = server.install(register=True, sync_plugin_cache=False)

    run.assert_called_once_with(
        [
            "codex",
            "mcp",
            "add",
            server.MCP_SERVER_NAME,
            "--",
            str(layout.mcp_entrypoint),
        ]
    )
    assert result["runtime_entrypoint"] == "not_returned"
    assert "symlink" not in result
    assert result["mcp"]["status"] == "registered"


def test_interactive_unregistration_only_removes_matching_image_registration(
    tmp_path: Path,
) -> None:
    layout = runtime_layout(tmp_path)
    current = {
        "registered": True,
        "lookup_status": "registered",
        "command_matches": True,
    }

    with (
        patch.object(server, "_runtime_layout", return_value=layout),
        patch.object(server, "check_mcp_registration", return_value=current),
        patch.object(
            server, "revoke_current_teamleader", return_value={"changed": False}
        ),
        patch.object(server, "run_command") as run,
    ):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = server.uninstall()

    run.assert_called_once_with(["codex", "mcp", "remove", server.MCP_SERVER_NAME])
    assert result["mcp"] == "removed"
    assert "symlink" not in result


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
