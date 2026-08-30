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


def test_interactive_registration_uses_the_validated_image_entrypoint(tmp_path: Path) -> None:
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

    with patch.object(server, "_runtime_layout", return_value=layout), patch.object(
        server, "assert_install_context_allows_master_registration"
    ), patch.object(server, "enroll_current_teamleader", return_value={"changed": False}), patch.object(
        server, "ensure_applet_action_key"
    ), patch.object(server, "mcp_command_startup_self_test", return_value=startup), patch.object(
        server, "check_mcp_registration", return_value=current
    ), patch.object(server, "ensure_mcp_startup_timeout_configured", return_value=timeout), patch.object(
        server, "run_command"
    ) as run:
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = server.install(register=True, sync_plugin_cache=False)

    run.assert_called_once_with(
        ["codex", "mcp", "add", server.MCP_SERVER_NAME, "--", str(layout.mcp_entrypoint)]
    )
    assert result["runtime_entrypoint"] == "not_returned"
    assert "symlink" not in result
    assert result["mcp"]["status"] == "registered"


def test_interactive_unregistration_only_removes_matching_image_registration(tmp_path: Path) -> None:
    layout = runtime_layout(tmp_path)
    current = {"registered": True, "lookup_status": "registered", "command_matches": True}

    with patch.object(server, "_runtime_layout", return_value=layout), patch.object(
        server, "check_mcp_registration", return_value=current
    ), patch.object(server, "revoke_current_teamleader", return_value={"changed": False}), patch.object(
        server, "run_command"
    ) as run:
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

    assert '"${HOME}/.local/lib/codex-master-runtime/bin/codex-master-mcp" pool install' in source
    assert "repo_root" not in source
    assert "/.local/bin/codex-master-mcp" not in source
