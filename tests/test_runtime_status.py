from __future__ import annotations

import importlib
import json
from pathlib import Path


def _runtime_modules():
    try:
        layout = importlib.import_module("codex_master.runtime_layout")
        status = importlib.import_module("codex_master.runtime_status")
    except ModuleNotFoundError:
        return None
    return layout, status


def _write_file(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def materialize_runtime_image(tmp_path: Path, *, mcp_mode: str = "healthy") -> Path:
    root = tmp_path / "codex-master-runtime"
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.mkdir(mode=0o700)
    mcp = root / "bin" / "codex-master-mcp"
    _write_file(
        mcp,
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "mode = " + repr(mcp_mode) + "\n"
        "if any(name in os.environ for name in ('CODEX_HOME', 'PYTHONPATH', 'CODEX_MASTER_RUNTIME_ROOT')):\n"
        "    raise SystemExit(9)\n"
        "for raw in sys.stdin:\n"
        "    request = json.loads(raw)\n"
        "    if request.get('method') == 'initialize':\n"
        "        print(json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'serverInfo': {'name': 'codex-master-mcp'}}}), flush=True)\n"
        "    elif request.get('method') == 'tools/list' and mode == 'healthy':\n"
        "        print(json.dumps({'jsonrpc': '2.0', 'id': 2, 'result': {'tools': [{'name': 'hive_status'}]}}), flush=True)\n"
        "    elif request.get('method') == 'tools/list' and mode == 'empty-tools':\n"
        "        print(json.dumps({'jsonrpc': '2.0', 'id': 2, 'result': {'tools': []}}), flush=True)\n"
        "if mode == 'exit-error':\n"
        "    raise SystemExit(1)\n",
        0o755,
    )
    _write_file(root / "bin" / "codex-master-hive-hourly-probe", "#!/bin/sh\nexit 0\n", 0o755)
    _write_file(
        root / ".codex-plugin" / "plugin.json",
        json.dumps(
            {
                "name": "codex-master",
                "version": "0.10.5",
                "skills": "./skills/",
                "mcpServers": "./.mcp.json",
                "apps": "./.app.json",
                "hooks": "./hooks/hooks.json",
            }
        ),
    )
    _write_file(
        root / ".mcp.json",
        json.dumps(
            {"mcpServers": {"codex-master-mcp": {"command": "./bin/codex-master-mcp", "args": []}}}
        ),
    )
    _write_file(root / ".app.json", json.dumps({"apps": {"codex-master": {"id": "connector"}}}))
    _write_file(root / "hooks" / "hooks.json", json.dumps({"hooks": {}}))
    _write_file(root / "skills" / "codex-master-fleet" / "SKILL.md", "---\nname: codex-master-fleet\n---\n")
    _write_file(root / "codex-hive.json", json.dumps({"schema_version": 1, "mode": "shadow"}))
    _write_file(root / "codex-agent-classes.json", json.dumps({"schema_version": 1, "classes": []}))
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o700)
    return root


def test_runtime_status_checks_validated_metadata_and_direct_mcp_surface(tmp_path: Path) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules
    layout = layout_module.RuntimeLayout.from_runtime_root(materialize_runtime_image(tmp_path))

    result = status_module.runtime_status(layout=layout)

    assert result["ok"] is True
    assert result["metadata"] == {"ok": True, "reason_code": "ok"}
    assert result["mcp_surface"] == {
        "ok": True,
        "initialize": True,
        "tools_list": True,
        "tool_count": 1,
        "reason_code": "ok",
    }
    assert result["raw_output"] == "not_returned"


def test_runtime_status_sanitizes_client_layout_environment(tmp_path: Path, monkeypatch) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules
    layout = layout_module.RuntimeLayout.from_runtime_root(materialize_runtime_image(tmp_path))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "client-home"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "checkout"))
    monkeypatch.setenv("CODEX_MASTER_RUNTIME_ROOT", str(tmp_path / "untrusted-runtime"))
    (tmp_path / "client-home" / ".codex").mkdir(parents=True)
    (tmp_path / "client-home" / ".codex" / "config.toml").write_text("[mcp_servers]\n", encoding="utf-8")

    result = status_module.runtime_status(layout=layout)

    assert result["ok"] is True
    assert result["mcp_surface"]["ok"] is True


def test_runtime_status_rejects_invalid_metadata_without_starting_mcp(tmp_path: Path) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules
    root = materialize_runtime_image(tmp_path)
    layout = layout_module.RuntimeLayout.from_runtime_root(root)
    (root / ".mcp.json").write_text("[]", encoding="utf-8")

    result = status_module.runtime_status(layout=layout)

    assert result["ok"] is False
    assert result["metadata"]["ok"] is False
    assert result["mcp_surface"] == {
        "ok": False,
        "initialize": False,
        "tools_list": False,
        "tool_count": 0,
        "reason_code": "metadata_invalid",
    }


def test_runtime_status_rejects_mcp_start_and_incomplete_tools_surface(tmp_path: Path) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules

    start_failure = layout_module.RuntimeLayout.from_runtime_root(
        materialize_runtime_image(tmp_path / "start", mcp_mode="exit-error")
    )
    incomplete = layout_module.RuntimeLayout.from_runtime_root(
        materialize_runtime_image(tmp_path / "tools", mcp_mode="missing-tools")
    )

    for layout in (start_failure, incomplete):
        result = status_module.runtime_status(layout=layout)
        assert result["ok"] is False
        assert result["metadata"]["ok"] is True
        assert result["mcp_surface"]["ok"] is False
        assert result["mcp_surface"]["tools_list"] is False
        assert result["raw_output"] == "not_returned"


def test_runtime_status_accepts_an_empty_direct_tool_list(tmp_path: Path) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules
    layout = layout_module.RuntimeLayout.from_runtime_root(
        materialize_runtime_image(tmp_path, mcp_mode="empty-tools")
    )

    result = status_module.runtime_status(layout=layout)

    assert result["ok"] is True
    assert result["mcp_surface"] == {
        "ok": True,
        "initialize": True,
        "tools_list": True,
        "tool_count": 0,
        "reason_code": "ok",
    }
