from __future__ import annotations

from collections.abc import Callable
from dataclasses import FrozenInstanceError
import importlib
import json
import os
from pathlib import Path
import runpy

import pytest


def _runtime_layout_module():
    try:
        return importlib.import_module("the_hive.runtime_layout")
    except ModuleNotFoundError:
        return None


def _write_file(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def materialize_runtime_image(
    tmp_path: Path, *, before_manifest: Callable[[Path], None] | None = None
) -> Path:
    root = tmp_path / "the-hive-runtime"
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.mkdir(mode=0o700)
    _write_file(root / "bin" / "the-hive-mcp", "#!/bin/sh\nexit 0\n", 0o755)
    _write_file(root / "bin" / "the-hive-mcp-stable", "#!/bin/sh\nexit 0\n", 0o755)
    _write_file(
        root / "bin" / "the-hive-plugin-hook-stable", "#!/bin/sh\nexit 0\n", 0o755
    )
    _write_file(
        root / "bin" / "the-hive-hive-hourly-probe",
        "#!/bin/sh\nexit 0\n",
        0o755,
    )
    _write_file(
        root / "bin" / "the-hive-resource-monitor", "#!/bin/sh\nexit 0\n", 0o755
    )
    _write_file(
        root / "systemd" / "user" / "the-hive-resource-monitor.service", "[Service]\n"
    )
    _write_file(root / "systemd" / "user" / "the-hive.slice", "[Slice]\n")
    _write_file(
        root / ".codex-plugin" / "plugin.json",
        json.dumps(
            {
                "name": "the-hive",
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
    _write_file(
        root / ".app.json", json.dumps({"apps": {"the-hive": {"id": "connector"}}})
    )
    _write_file(root / "hooks" / "hooks.json", json.dumps({"hooks": {}}))
    _write_file(root / "hooks" / "native_bee_event.py", "# hook\n")
    _write_file(root / "hooks" / "native_spawn_admission.py", "# hook\n")
    _write_file(
        root / "skills" / "the-hive-fleet" / "SKILL.md",
        "---\nname: the-hive-fleet\n---\n",
    )
    _write_file(
        root / "codex-hive.json", json.dumps({"schema_version": 1, "mode": "shadow"})
    )
    _write_file(
        root / "codex-agent-classes.json",
        json.dumps({"schema_version": 1, "classes": []}),
    )
    _write_file(
        root / "src" / "the_hive" / "_runtime_spawn_helper.so", "test helper", 0o755
    )
    _write_file(root / "src" / "the_hive" / "hive" / "cli.py", "# image module\n")
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
        "hook_abi_v1_core.py",
        "server.py",
        "hook_session_pin_store.py",
    ):
        _write_file(
            root / "src" / "the_hive" / relative,
            (
                Path(__file__).resolve().parents[1] / "src" / "the_hive" / relative
            ).read_text(encoding="utf-8"),
        )
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o700)
    installer = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "the-hive-hive-hourly-probe-install"
        )
    )
    if before_manifest is not None:
        before_manifest(root)
    installer["_write_runtime_image_manifest"](root=root, commit="a" * 40)
    return root


def test_runtime_layout_is_immutable_and_derived_only_from_a_valid_image(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)

    layout = module.RuntimeLayout.from_runtime_root(root)

    assert layout.root == root
    assert layout.mcp_entrypoint == root / "bin" / "the-hive-mcp"
    assert layout.probe_entrypoint == root / "bin" / "the-hive-hive-hourly-probe"
    assert layout.metadata_root == root
    assert layout.spawn_helper == root / "src" / "the_hive" / "_runtime_spawn_helper.so"
    assert len(layout.spawn_helper_digest) == 64
    assert layout.manifest_digest.startswith("sha256:")
    with pytest.raises(FrozenInstanceError):
        layout.root = root.parent  # type: ignore[misc]


def test_runtime_layout_rejects_relative_and_nonprivate_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)

    monkeypatch.chdir(tmp_path)
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(Path(root.name))
    root.chmod(0o755)
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_an_image_reached_through_a_linked_parent(
    tmp_path: Path,
) -> None:
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
        "bin/the-hive-mcp",
        "bin/the-hive-plugin-hook-stable",
        "bin/the-hive-hive-hourly-probe",
        ".codex-plugin/plugin.json",
        ".mcp.json",
        ".app.json",
        "hooks/hooks.json",
        "hooks/native_bee_event.py",
        "hooks/native_spawn_admission.py",
        "TheHivePluginBundleV1/release-binding.json",
        "root-install-plan.json",
        "skills/the-hive-fleet/SKILL.md",
        "codex-hive.json",
        "codex-agent-classes.json",
        "src/the_hive/_runtime_spawn_helper.so",
        ".the-hive-runtime-manifest.json",
    ),
)
def test_runtime_layout_rejects_missing_required_image_members(
    tmp_path: Path, relative_path: str
) -> None:
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
    entrypoint = root / "bin" / "the-hive-mcp"
    target = tmp_path / "outside-mcp"
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o755)
    entrypoint.unlink()
    entrypoint.symlink_to(target)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)

    restored = materialize_runtime_image(tmp_path / "another")
    valid_layout = module.RuntimeLayout.from_runtime_root(restored)
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout(
            root=restored,
            mcp_entrypoint=target,
            probe_entrypoint=restored / "bin" / "the-hive-hive-hourly-probe",
            metadata_root=restored,
            spawn_helper=restored / "src" / "the_hive" / "_runtime_spawn_helper.so",
            spawn_helper_digest="0" * 64,
            root_device=valid_layout.root_device,
            root_inode=valid_layout.root_inode,
            manifest_digest=valid_layout.manifest_digest,
        )


def test_runtime_layout_rejects_a_helper_or_manifest_digest_deviation(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    helper = root / "src" / "the_hive" / "_runtime_spawn_helper.so"
    helper.write_bytes(b"swapped helper")

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_witness_file_drift_after_valid_manifest(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    layout = module.RuntimeLayout.from_runtime_root(root)
    witness = root / "src" / "the_hive" / "dynamic_pool.py"
    witness.write_bytes(witness.read_bytes() + b"\n# drift after manifest\n")
    witness.chmod(0o644)

    with pytest.raises(module.LayoutError):
        module.validate_runtime_metadata(layout)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        (("successor_witness", "sha256"), "0" * 64),
        (("historical_lineage", "d73", "parent"), "0" * 40),
    ),
)
def test_runtime_layout_rejects_a_deviating_d89_successor_binding(
    tmp_path: Path, field: tuple[str, ...], replacement: str
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    manifest_path = root / ".the-hive-runtime-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    target = manifest
    for part in field[:-1]:
        target = target[part]
    target[field[-1]] = replacement
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_a_replaced_generation_or_manifest_digest(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    layout = module.RuntimeLayout.from_runtime_root(root)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout(
            root=layout.root,
            mcp_entrypoint=layout.mcp_entrypoint,
            probe_entrypoint=layout.probe_entrypoint,
            metadata_root=layout.metadata_root,
            spawn_helper=layout.spawn_helper,
            spawn_helper_digest=layout.spawn_helper_digest,
            root_device=layout.root_device,
            root_inode=layout.root_inode,
            manifest_digest="sha256:" + "0" * 64,
        )

    root.rename(tmp_path / "retired-generation")
    materialize_runtime_image(tmp_path)
    with pytest.raises(module.LayoutError):
        module.validate_runtime_metadata(layout)

    root = materialize_runtime_image(tmp_path / "manifest")
    manifest = root / ".the-hive-runtime-manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_a_release_binding_not_exactly_attested_by_manifest(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    descriptor = root / "TheHivePluginBundleV1" / "release-binding.json"
    binding = json.loads(descriptor.read_text(encoding="utf-8"))
    binding["hooks"]["native_bee_event"] = "sha256:" + "0" * 64
    descriptor.write_text(json.dumps(binding), encoding="utf-8")
    descriptor.chmod(0o644)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_a_root_install_plan_not_bound_to_abi_source_bytes(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    plan_path = root / "root-install-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["companion"]["sha256"] = "sha256:" + "0" * 64
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    plan_path.chmod(0o644)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_image_repository_root_is_not_public_or_registry_compatible(
    tmp_path: Path,
) -> None:
    from the_hive.hive.repositories import (
        RepositoryBinding,
        RepositoryError,
        RepositoryRegistry,
    )

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    layout = module.RuntimeLayout.from_runtime_root(root)

    assert "RuntimeImageRepositoryRoot" not in module.__all__
    assert not hasattr(module, "RuntimeImageRepositoryRoot")
    with pytest.raises(ImportError):
        exec("from the_hive.runtime_layout import RuntimeImageRepositoryRoot", {})
    with pytest.raises(AttributeError):
        module.RuntimeImageRepositoryRoot(layout)  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        getattr(layout, "repository_root")
    with pytest.raises(RepositoryError, match="invalid_repository_root"):
        RepositoryBinding(
            "runtime-image",
            "https://github.com/example/runtime-image.git",
            layout,
            "main",
            RepositoryRegistry.config_digest(b"runtime-image-binding"),
        )


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
                "name": "the-hive",
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


@pytest.mark.parametrize("legacy_binding", ("plugin_name", "app_key", "skill_path"))
def test_runtime_layout_rejects_legacy_plugin_skill_metadata_bindings(
    tmp_path: Path, legacy_binding: str
) -> None:
    module = _runtime_layout_module()
    assert module is not None

    def add_legacy_binding(root: Path) -> None:
        if legacy_binding == "plugin_name":
            plugin_path = root / ".codex-plugin" / "plugin.json"
            plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
            plugin["name"] = "codex-master"
            plugin_path.write_text(json.dumps(plugin), encoding="utf-8")
        elif legacy_binding == "app_key":
            app_path = root / ".app.json"
            app_path.write_text(
                json.dumps({"apps": {"codex-master": {"id": "connector"}}}),
                encoding="utf-8",
            )
        else:
            target = root / "skills" / "the-hive-fleet"
            target.rename(root / "skills" / "codex-master-fleet")

    if legacy_binding == "skill_path":
        root = materialize_runtime_image(tmp_path)
        (root / "skills" / "the-hive-fleet").rename(
            root / "skills" / "codex-master-fleet"
        )
        with pytest.raises(module.LayoutError):
            module.RuntimeLayout.from_runtime_root(root)
        return
    else:
        root = materialize_runtime_image(tmp_path, before_manifest=add_legacy_binding)
    manifest, digest = module._validated_manifest(root)
    assert manifest["schema_version"] == 2
    assert digest.startswith("sha256:")

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_legacy_python_mcp_manifest_commands(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "the-hive-mcp": {
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


def test_runtime_layout_requires_the_external_stable_mcp_launcher_shape(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    mcp_path = root / ".mcp.json"
    payload = json.loads(mcp_path.read_text(encoding="utf-8"))
    payload["mcpServers"]["the-hive-mcp"]["cwd"] = "/tmp/attacker"
    mcp_path.write_text(json.dumps(payload), encoding="utf-8")
    installer = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "the-hive-hive-hourly-probe-install"
        )
    )
    (root / ".the-hive-runtime-manifest.json").unlink()
    installer["_write_runtime_image_manifest"](root=root, commit="a" * 40)

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

    layout = module.RuntimeLayout.from_module_path(
        root / "src" / "the_hive" / "hive" / "cli.py"
    )

    assert layout.root == root
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_module_path(tmp_path / "not-an-image.py")


def test_runtime_state_layout_requires_the_exact_parameterless_state_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", str(state_directory))

    layout = module.RuntimeStateLayoutV1.from_systemd_state_directory()

    assert layout.state_directory == state_directory
    assert layout.basename == "the-hive-ga-i2d-quiescence"


def test_runtime_state_layout_exposes_only_the_canonical_systemd_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", str(state_directory))

    namespace: dict[str, object] = {}
    exec("from the_hive.runtime_layout import *", namespace)

    assert "RuntimeStateLayoutV1" not in namespace
    assert not hasattr(module.RuntimeStateLayoutV1, "from_environment")
    assert (
        module.RuntimeStateLayoutV1.from_systemd_state_directory().state_root
        == state_directory
    )


def test_runtime_state_layout_selects_one_exact_systemd_entry_and_is_not_constructible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    unrelated = tmp_path / "codex-master-admin"
    unrelated.mkdir(mode=0o700)
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", f"{unrelated}:{state_directory}")

    layout = module.RuntimeStateLayoutV1.from_systemd_state_directory()

    assert layout.state_root == state_directory
    assert layout.state_root_device == state_directory.stat().st_dev
    assert layout.state_root_inode == state_directory.stat().st_ino
    layout.validate()
    with pytest.raises(module.LayoutError):
        module.RuntimeStateLayoutV1()
    with pytest.raises(TypeError):
        module.RuntimeStateLayoutV1(state_directory)  # type: ignore[call-arg]


def test_runtime_state_layout_rejects_an_unattested_object_new_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    monkeypatch.delenv("STATE_DIRECTORY", raising=False)
    forged = object.__new__(module.RuntimeStateLayoutV1)
    object.__setattr__(forged, "state_root", state_directory)
    object.__setattr__(forged, "state_root_device", state_directory.stat().st_dev)
    object.__setattr__(forged, "state_root_inode", state_directory.stat().st_ino)

    with pytest.raises(module.LayoutError):
        forged.open_dirfd()


@pytest.mark.parametrize("representation", ("double_root", "trailing_slash"))
def test_runtime_state_layout_rejects_noncanonical_raw_systemd_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, representation: str
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    if representation == "double_root":
        raw_entry = "//" + str(state_directory).lstrip("/")
    else:
        raw_entry = f"{state_directory}/"
    monkeypatch.setenv("STATE_DIRECTORY", raw_entry)

    with pytest.raises(module.LayoutError):
        module.RuntimeStateLayoutV1.from_systemd_state_directory()


def test_runtime_state_layout_rejects_relative_entries_and_missing_safe_dirfd_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", f"relative:{state_directory}")
    with pytest.raises(module.LayoutError):
        module.RuntimeStateLayoutV1.from_systemd_state_directory()

    monkeypatch.setenv("STATE_DIRECTORY", str(state_directory))
    layout = module.RuntimeStateLayoutV1.from_systemd_state_directory()
    monkeypatch.delattr(os, "O_CLOEXEC", raising=False)
    with pytest.raises(module.LayoutError):
        layout.open_dirfd()


def test_runtime_state_layout_rejects_missing_o_nofollow_and_component_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "private-state" / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700, parents=True)
    monkeypatch.setenv("STATE_DIRECTORY", str(state_directory))
    layout = module.RuntimeStateLayoutV1.from_systemd_state_directory()
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    with pytest.raises(module.LayoutError):
        layout.open_dirfd()

    monkeypatch.undo()
    target_parent = tmp_path / "actual-state"
    target_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-state"
    linked_parent.symlink_to(target_parent, target_is_directory=True)
    linked_state = linked_parent / "the-hive-ga-i2d-quiescence"
    (target_parent / "the-hive-ga-i2d-quiescence").mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", str(linked_state))
    with pytest.raises(module.LayoutError):
        module.RuntimeStateLayoutV1.from_systemd_state_directory()


def test_runtime_state_layout_rejects_a_final_dirfd_inode_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "private-state" / "the-hive-ga-i2d-quiescence"
    replacement = tmp_path / "replacement-state"
    state_directory.mkdir(mode=0o700, parents=True)
    replacement.mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", str(state_directory))
    layout = module.RuntimeStateLayoutV1.from_systemd_state_directory()
    original_open = os.open

    def race_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if path == state_directory.name and "dir_fd" in kwargs:
            return original_open(replacement, flags)
        return original_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", race_open)
    with pytest.raises(module.LayoutError):
        layout.open_dirfd()
