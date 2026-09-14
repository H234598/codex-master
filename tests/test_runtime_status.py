from __future__ import annotations

import importlib
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from the_hive.runtime_process import BoundedProcessError


pytestmark = pytest.mark.usefixtures("runtime_spawn_helper")


def _runtime_modules():
    try:
        layout = importlib.import_module("the_hive.runtime_layout")
        status = importlib.import_module("the_hive.runtime_status")
    except ModuleNotFoundError:
        return None
    return layout, status


def _named_release_layout(tmp_path: Path, runtime_image) -> object:
    """Copy the complete fixture under an explicitly current named release."""

    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = tmp_path / "the-hive-runtime"
    root.mkdir(mode=0o700)
    generations = root / "generations"
    generations.mkdir(mode=0o700)
    stage = tmp_path / "stage"
    shutil.copytree(runtime_image.root, stage)
    manifest = json.loads(
        (stage / ".the-hive-runtime-manifest.json").read_text(encoding="utf-8")
    )
    generation = manifest["generation"]
    assert isinstance(generation, str)
    target = generations / generation
    os.replace(stage, target)
    digest = "sha256:" + hashlib.sha256(
        (target / ".the-hive-runtime-manifest.json").read_bytes()
    ).hexdigest()
    pointers = {
        "schema_version": 1,
        "current": {"generation": generation, "manifest_digest": digest},
        "previous": None,
    }
    pointer = root / ".the-hive-release-pointers.json"
    pointer.write_text(json.dumps(pointers), encoding="utf-8")
    pointer.chmod(0o644)
    return runtime_image.__class__.from_current_release(root, generation, digest)


def _healthy_mcp_result() -> SimpleNamespace:
    return SimpleNamespace(
        returncode=0,
        stdout="\n".join(
            json.dumps(payload)
            for payload in (
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                        "serverInfo": {"name": "the-hive-mcp", "version": "1"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "tools": [
                            {
                                "name": "runtime_status",
                                "description": "Runtime status",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {},
                                    "additionalProperties": False,
                                },
                            }
                        ]
                    },
                },
            )
        ),
    )


def _write_authorized_queen_registry(home: Path) -> None:
    """Materialize the valid principal state that previously expanded a stage."""

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


def test_runtime_status_uses_its_sterile_surface_with_an_authorized_queen_home(
    runtime_image, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modules = _runtime_modules()
    assert modules is not None
    _layout_module, status_module = modules
    home = tmp_path / "authorized-home"
    home.mkdir(mode=0o700)
    _write_authorized_queen_registry(home)
    monkeypatch.setenv("CODEX_HOME", str(home / ".codex"))

    result = status_module.runtime_status(
        layout=_named_release_layout(tmp_path, runtime_image), home=home
    )

    assert result["ok"] is True
    assert result["mcp_surface"] == {
        "ok": True,
        "initialize": True,
        "tools_list": True,
        "tool_count": 1,
        "reason_code": "ok",
    }


def test_runtime_status_checks_validated_metadata_and_direct_mcp_surface(
    runtime_image, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules
    layout = _named_release_layout(tmp_path, runtime_image)
    monkeypatch.setattr(status_module, "run_bounded", lambda *_args, **_kwargs: _healthy_mcp_result())

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


def test_runtime_status_sanitizes_client_layout_environment(
    runtime_image, tmp_path: Path, monkeypatch
) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules
    layout = _named_release_layout(tmp_path, runtime_image)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "client-home"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "checkout"))
    monkeypatch.setenv("CODEX_MASTER_RUNTIME_ROOT", str(tmp_path / "untrusted-runtime"))
    (tmp_path / "client-home" / ".codex").mkdir(parents=True)
    (tmp_path / "client-home" / ".codex" / "config.toml").write_text(
        "[mcp_servers]\n", encoding="utf-8"
    )

    result = status_module.runtime_status(layout=layout)

    assert result["ok"] is True
    assert result["mcp_surface"]["ok"] is True


def test_runtime_status_rejects_invalid_metadata_without_starting_mcp(
    runtime_image, tmp_path: Path,
) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules
    layout = _named_release_layout(tmp_path, runtime_image)
    root = layout.root
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


def test_runtime_status_rejects_mcp_start_and_incomplete_tools_surface(
    runtime_image, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules

    start_failure = _named_release_layout(tmp_path / "start", runtime_image)
    incomplete = _named_release_layout(tmp_path / "tools", runtime_image)

    responses = iter(
        (
            BoundedProcessError("command_failed"),
            SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                            "serverInfo": {"name": "the-hive-mcp", "version": "1"},
                        },
                    }
                ),
            ),
        )
    )

    def direct_failure(*_args: object, **_kwargs: object) -> object:
        result = next(responses)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(status_module, "run_bounded", direct_failure)
    for layout in (start_failure, incomplete):
        result = status_module.runtime_status(layout=layout)
        assert result["ok"] is False
        assert result["metadata"]["ok"] is True
        assert result["mcp_surface"]["ok"] is False
        assert result["mcp_surface"]["tools_list"] is False
        assert result["raw_output"] == "not_returned"


def test_runtime_status_reports_a_bounded_direct_mcp_cleanup_timeout(
    runtime_image, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules
    layout = _named_release_layout(tmp_path, runtime_image)

    def cleanup_bounded(*_args: object, **_kwargs: object) -> object:
        raise BoundedProcessError("command_cleanup_bounded")

    monkeypatch.setattr(status_module, "run_bounded", cleanup_bounded)

    result = status_module.runtime_status(layout=layout)

    assert result["mcp_surface"] == {
        "ok": False,
        "initialize": False,
        "tools_list": False,
        "tool_count": 0,
        "reason_code": "mcp_cleanup_timeout",
    }


def test_runtime_status_rejects_an_empty_direct_tool_list(
    runtime_image, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules
    layout = _named_release_layout(tmp_path, runtime_image)
    empty_tools = _healthy_mcp_result()
    output = [json.loads(line) for line in empty_tools.stdout.splitlines()]
    output[1]["result"] = {"tools": []}
    empty_tools.stdout = "\n".join(json.dumps(value) for value in output)
    monkeypatch.setattr(status_module, "run_bounded", lambda *_args, **_kwargs: empty_tools)

    result = status_module.runtime_status(layout=layout)

    assert result["ok"] is False
    assert result["mcp_surface"] == {
        "ok": False,
        "initialize": True,
        "tools_list": True,
        "tool_count": 0,
        "reason_code": "mcp_surface_invalid",
    }


def test_runtime_status_passes_only_the_explicit_current_release_binding_to_mcp(
    runtime_image, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modules = _runtime_modules()
    assert modules is not None
    _layout_module, status_module = modules
    layout = _named_release_layout(tmp_path, runtime_image)
    received: dict[str, object] = {}

    def observe(argv: list[str], **kwargs: object) -> SimpleNamespace:
        received["argv"] = argv
        received["kwargs"] = kwargs
        return _healthy_mcp_result()

    monkeypatch.setattr(status_module, "run_bounded", observe)

    result = status_module.runtime_status(layout=layout)

    assert result["ok"] is True
    assert received["argv"] == [
        str(layout.mcp_entrypoint),
        str(layout.root.parent.parent),
        layout.root.name,
        layout.manifest_digest,
        status_module.AUTONOMOUS_RUNTIME_STATUS_MCP_ARGUMENT,
    ]
    assert received["kwargs"]["cwd"] == layout.root


def test_runtime_status_rejects_plain_stage_layout_before_starting_mcp(
    runtime_image, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modules = _runtime_modules()
    assert modules is not None
    layout_module, status_module = modules
    stage = layout_module.RuntimeLayout.from_runtime_root(runtime_image.root)
    attempted = False

    def should_not_run(*_args: object, **_kwargs: object) -> object:
        nonlocal attempted
        attempted = True
        return _healthy_mcp_result()

    monkeypatch.setattr(status_module, "run_bounded", should_not_run)

    result = status_module.runtime_status(layout=stage)

    assert attempted is False
    assert result["ok"] is False
    assert result["metadata"] == {"ok": True, "reason_code": "ok"}
    assert result["mcp_surface"] == {
        "ok": False,
        "initialize": False,
        "tools_list": False,
        "tool_count": 0,
        "reason_code": "mcp_unavailable",
    }


def test_runtime_status_fails_closed_on_current_pointer_or_digest_drift(
    runtime_image, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modules = _runtime_modules()
    assert modules is not None
    _layout_module, status_module = modules
    layout = _named_release_layout(tmp_path, runtime_image)
    pointer = layout.root.parent.parent / ".the-hive-release-pointers.json"
    original = json.loads(pointer.read_text(encoding="utf-8"))
    attempted = 0

    def should_not_run(*_args: object, **_kwargs: object) -> object:
        nonlocal attempted
        attempted += 1
        return _healthy_mcp_result()

    monkeypatch.setattr(status_module, "run_bounded", should_not_run)
    for current in (
        {"generation": "unattested", "manifest_digest": layout.manifest_digest},
        {"generation": layout.root.name, "manifest_digest": "sha256:" + "0" * 64},
    ):
        pointer.write_text(
            json.dumps({**original, "current": current}), encoding="utf-8"
        )
        result = status_module.runtime_status(layout=layout)
        assert result["ok"] is False
        assert result["metadata"] == {"ok": True, "reason_code": "ok"}
        assert result["mcp_surface"] == {
            "ok": False,
            "initialize": False,
            "tools_list": False,
            "tool_count": 0,
            "reason_code": "mcp_unavailable",
        }
    assert attempted == 0


def test_runtime_status_ignores_dirty_cwd_and_pythonpath_for_its_binding(
    runtime_image, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modules = _runtime_modules()
    assert modules is not None
    _layout_module, status_module = modules
    layout = _named_release_layout(tmp_path / "release", runtime_image)
    dirty_checkout = tmp_path / "dirty-checkout"
    dirty_checkout.mkdir(mode=0o700)
    monkeypatch.chdir(dirty_checkout)
    monkeypatch.setenv("PYTHONPATH", str(dirty_checkout / "src"))
    received: list[str] = []

    def observe(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        received[:] = argv
        return _healthy_mcp_result()

    monkeypatch.setattr(status_module, "run_bounded", observe)

    result = status_module.runtime_status(layout=layout)

    assert result["ok"] is True
    assert received[1:4] == [
        str(layout.root.parent.parent),
        layout.root.name,
        layout.manifest_digest,
    ]
    assert str(dirty_checkout) not in received


def test_runtime_status_rejects_any_noncanonical_runtime_status_tool_surface() -> None:
    modules = _runtime_modules()
    assert modules is not None
    _layout_module, status_module = modules
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "the-hive-mcp", "version": "1"},
        },
    }
    canonical_tool = {
        "name": "runtime_status",
        "description": "Runtime status",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    }
    malformed_variants = (
        [{**canonical_tool}, {**canonical_tool, "name": "agent_start"}],
        [{**canonical_tool}, {**canonical_tool}],
        [{**canonical_tool, "inputSchema": {"type": "object", "properties": {}}}],
        [
            {
                **canonical_tool,
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": 0,
                },
            }
        ],
        [{"name": "runtime_status", "inputSchema": canonical_tool["inputSchema"]}],
        [{**canonical_tool, "unexpected": True}],
    )
    for tools in malformed_variants:
        output = "\n".join(
            json.dumps(payload)
            for payload in (
                initialize,
                {"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}},
            )
        )
        surface = status_module._mcp_surface(0, output)
        assert surface["ok"] is False
        assert surface["reason_code"] == "mcp_surface_invalid"

    competing = "\n".join(
        json.dumps(payload)
        for payload in (
            initialize,
            {"jsonrpc": "2.0", "id": 2, "result": {"tools": [canonical_tool]}},
            {"jsonrpc": "2.0", "id": 2, "result": {"tools": [canonical_tool]}},
        )
    )
    surface = status_module._mcp_surface(0, competing)
    assert surface["ok"] is False
    assert surface["reason_code"] == "mcp_surface_invalid"


def test_runtime_status_rejects_out_of_order_and_duplicate_key_responses() -> None:
    modules = _runtime_modules()
    assert modules is not None
    _layout_module, status_module = modules
    initialize_result = {
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
        "serverInfo": {"name": "the-hive-mcp", "version": "1"},
    }
    tools_result = {
        "tools": [
            {
                "name": "runtime_status",
                "description": "Runtime status",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
        ]
    }
    initialize = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": initialize_result},
        separators=(",", ":"),
    )
    tools = json.dumps(
        {"jsonrpc": "2.0", "id": 2, "result": tools_result},
        separators=(",", ":"),
    )
    duplicate_key_initialize = (
        '{"jsonrpc":"2.0","id":1,"id":1,"result":'
        + json.dumps(initialize_result, separators=(",", ":"))
        + "}"
    )
    duplicate_nested_initialize = initialize.replace(
        '"tools":{}', '"tools":{},"tools":{}', 1
    )

    for output in (
        "\n".join((tools, initialize)),
        "\n".join((duplicate_key_initialize, tools)),
        "\n".join((duplicate_nested_initialize, tools)),
    ):
        surface = status_module._mcp_surface(0, output)
        assert surface["ok"] is False
        assert surface["reason_code"] == "mcp_surface_invalid"
