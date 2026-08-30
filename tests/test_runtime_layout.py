from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import importlib
import json
import os
from pathlib import Path
import stat

import pytest


def _runtime_layout_module():
    try:
        return importlib.import_module("codex_master.runtime_layout")
    except ModuleNotFoundError:
        return None


def _write_file(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def materialize_runtime_image(tmp_path: Path) -> Path:
    root = tmp_path / "codex-master-runtime"
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.mkdir(mode=0o700)
    _write_file(root / "bin" / "codex-master-mcp", "#!/bin/sh\nexit 0\n", 0o755)
    _write_file(
        root / "bin" / "codex-master-hive-hourly-probe",
        "#!/bin/sh\nexit 0\n",
        0o755,
    )
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
    _write_file(root / ".app.json", json.dumps({"apps": {"codex-master": {"id": "connector"}}}))
    _write_file(root / "hooks" / "hooks.json", json.dumps({"hooks": {}}))
    _write_file(root / "skills" / "codex-master-fleet" / "SKILL.md", "---\nname: codex-master-fleet\n---\n")
    _write_file(root / "codex-hive.json", json.dumps({"schema_version": 1, "mode": "shadow"}))
    _write_file(root / "codex-agent-classes.json", json.dumps({"schema_version": 1, "classes": []}))
    _write_file(root / "src" / "codex_master" / "_runtime_spawn_helper.so", "test helper", 0o755)
    _write_file(root / "src" / "codex_master" / "hive" / "cli.py", "# image module\n")
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o700)
    directories: dict[str, dict[str, int]] = {}
    files: dict[str, dict[str, object]] = {}
    for directory, _child_directories, file_names in os.walk(root):
        current = Path(directory)
        relative = current.relative_to(root).as_posix() if current != root else "."
        info = current.lstat()
        directories[relative] = {"mode": stat.S_IMODE(info.st_mode), "nlink": info.st_nlink}
        for name in file_names:
            path = current / name
            raw = path.read_bytes()
            item = path.lstat()
            files[path.relative_to(root).as_posix()] = {
                "mode": stat.S_IMODE(item.st_mode),
                "nlink": item.st_nlink,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
    _write_file(
        root / ".codex-master-runtime-manifest.json",
        json.dumps({"schema_version": 1, "directories": directories, "files": files}),
    )
    return root


def test_runtime_layout_is_immutable_and_derived_only_from_a_valid_image(tmp_path: Path) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)

    layout = module.RuntimeLayout.from_runtime_root(root)

    assert layout.root == root
    assert layout.mcp_entrypoint == root / "bin" / "codex-master-mcp"
    assert layout.probe_entrypoint == root / "bin" / "codex-master-hive-hourly-probe"
    assert layout.metadata_root == root
    assert layout.spawn_helper == root / "src" / "codex_master" / "_runtime_spawn_helper.so"
    assert len(layout.spawn_helper_digest) == 64
    with pytest.raises(FrozenInstanceError):
        layout.root = root.parent  # type: ignore[misc]


def test_runtime_layout_rejects_relative_and_nonprivate_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)

    monkeypatch.chdir(tmp_path)
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(Path(root.name))
    root.chmod(0o755)
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_an_image_reached_through_a_linked_parent(tmp_path: Path) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path / "actual")
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path / "actual", target_is_directory=True)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(linked_parent / root.name)


@pytest.mark.parametrize(
    "relative_path",
    (
        "bin/codex-master-mcp",
        "bin/codex-master-hive-hourly-probe",
        ".codex-plugin/plugin.json",
        ".mcp.json",
        ".app.json",
        "hooks/hooks.json",
        "skills/codex-master-fleet/SKILL.md",
        "codex-hive.json",
        "codex-agent-classes.json",
        "src/codex_master/_runtime_spawn_helper.so",
        ".codex-master-runtime-manifest.json",
    ),
)
def test_runtime_layout_rejects_missing_required_image_members(tmp_path: Path, relative_path: str) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    (root / relative_path).unlink()

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_linked_and_outside_entrypoints(tmp_path: Path) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    entrypoint = root / "bin" / "codex-master-mcp"
    target = tmp_path / "outside-mcp"
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o755)
    entrypoint.unlink()
    entrypoint.symlink_to(target)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)

    restored = materialize_runtime_image(tmp_path / "another")
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout(
            root=restored,
            mcp_entrypoint=target,
            probe_entrypoint=restored / "bin" / "codex-master-hive-hourly-probe",
            metadata_root=restored,
            spawn_helper=restored / "src" / "codex_master" / "_runtime_spawn_helper.so",
            spawn_helper_digest="0" * 64,
        )


def test_runtime_layout_rejects_a_helper_or_manifest_digest_deviation(tmp_path: Path) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    helper = root / "src" / "codex_master" / "_runtime_spawn_helper.so"
    helper.write_bytes(b"swapped helper")

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)

    root = materialize_runtime_image(tmp_path / "manifest")
    manifest = root / ".codex-master-runtime-manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_a_nonprivate_image_subdirectory(tmp_path: Path) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    (root / "bin").chmod(0o755)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_escaping_metadata_references(tmp_path: Path) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    plugin = root / ".codex-plugin" / "plugin.json"
    plugin.write_text(
        json.dumps(
            {
                "name": "codex-master",
                "version": "0.10.5",
                "skills": "./skills/",
                "mcpServers": "../.mcp.json",
                "apps": "./.app.json",
                "hooks": "./hooks/hooks.json",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_legacy_python_mcp_manifest_commands(tmp_path: Path) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "codex-master-mcp": {
                        "command": "python3",
                        "args": ["-c", "import sys; sys.path.insert(0, 'src')"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_derives_from_a_module_path_without_environment_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "untrusted-codex-home"))
    monkeypatch.setenv("CODEX_MASTER_RUNTIME_ROOT", str(tmp_path / "untrusted-runtime"))

    layout = module.RuntimeLayout.from_module_path(root / "src" / "codex_master" / "hive" / "cli.py")

    assert layout.root == root
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_module_path(tmp_path / "not-an-image.py")
