from __future__ import annotations

import hashlib
import json
from pathlib import Path
import runpy

import pytest

from the_hive.hook_session_pin_store import HookSessionPinStoreV1


ROOT = Path(__file__).resolve().parents[1]
TEST_MANIFEST_COMMIT = "a" * 40


def _installer() -> dict[str, object]:
    return runpy.run_path(str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install"))


def _stage(installer: dict[str, object], root: Path, generation: str) -> Path:
    stage = root / f".the-hive-runtime.stage.{generation}"
    stage.mkdir(mode=0o700)
    installer["_build_runtime_image"](  # type: ignore[operator]
        repository=ROOT,
        stage=stage,
        generation=generation,
        commit=TEST_MANIFEST_COMMIT,
    )
    return stage


def _rewrite_manifest(
    installer: dict[str, object], stage: Path, generation: str
) -> None:
    (stage / ".the-hive-runtime-manifest.json").unlink()
    installer["_write_runtime_image_manifest"](  # type: ignore[operator]
        root=stage,
        generation=generation,
        commit=TEST_MANIFEST_COMMIT,
    )


def _release_root(root: Path) -> Path:
    home = root / "home"
    (home / ".local" / "lib").mkdir(mode=0o700, parents=True)
    HookSessionPinStoreV1.create_at(
        home / ".local" / "state" / "the-hive" / "hook-session-pins-v1"
    )
    return home / ".local" / "lib" / "the-hive-runtime"


def _pin_store(release_root: Path) -> HookSessionPinStoreV1:
    return HookSessionPinStoreV1.open_at(
        release_root.parents[2]
        / ".local"
        / "state"
        / "the-hive"
        / "hook-session-pins-v1"
    )


def test_native_plugin_bundle_and_abi_plan_are_manifest_attested_without_cache_publish(
    tmp_path: Path,
) -> None:
    installer = _installer()
    stage = _stage(installer, tmp_path, "one")
    manifest = json.loads(
        (stage / ".the-hive-runtime-manifest.json").read_text(encoding="utf-8")
    )

    assert manifest["release"]["hook_abi_source"] == "bin/the-hive-plugin-hook-stable"
    assert manifest["release"]["hook_abi"] == (
        "/usr/local/libexec/the-hive/hook-abi/v1/launcher"
    )
    assert manifest["release"]["hook_abi_core"] == (
        "/usr/local/libexec/the-hive/hook-abi/v1/hook_abi_v1_core.py"
    )
    assert manifest["release"]["plugin_bundle"] == "TheHivePluginBundleV1"
    assert manifest["release"]["root_install_plan"] == "root-install-plan.json"
    assert manifest["release"]["hook_entrypoints"] == [
        "hooks/native_bee_event.py",
        "hooks/native_spawn_admission.py",
    ]
    assert (
        "bin/the-hive-plugin-hook-stable" not in manifest["release"]["stable_launchers"]
    )
    for path in (
        "bin/the-hive-plugin-hook-stable",
        "hooks/native_bee_event.py",
        "hooks/native_spawn_admission.py",
    ):
        assert path in manifest["files"]

    bundle = stage / "TheHivePluginBundleV1"
    for path in (
        ".codex-plugin/plugin.json",
        ".mcp.json",
        ".app.json",
        "hooks/hooks.json",
        "hooks/native_bee_event.py",
        "hooks/native_spawn_admission.py",
        "skills/the-hive-fleet/SKILL.md",
        "src/the_hive/server.py",
        "release-binding.json",
    ):
        assert (bundle / path).is_file()
    assert "TheHivePluginBundleV1/release-binding.json" not in manifest["files"]
    assert "TheHivePluginBundleV1/hooks/native_bee_event.py" in manifest["files"]
    source_entries = {
        path for path in manifest["files"] if path.startswith("src/the_hive/")
    }
    assert source_entries
    assert {f"TheHivePluginBundleV1/{path}" for path in source_entries}.issubset(
        manifest["files"]
    )
    for source in source_entries:
        assert (bundle / source).read_bytes() == (stage / source).read_bytes()
    plan = json.loads((stage / "root-install-plan.json").read_text(encoding="utf-8"))
    assert plan["schema"] == "RootInstallPlanV1"
    assert (
        plan["launcher"]["target"] == "/usr/local/libexec/the-hive/hook-abi/v1/launcher"
    )
    assert plan["companion"]["target"] == (
        "/usr/local/libexec/the-hive/hook-abi/v1/hook_session_pin_store.py"
    )
    assert plan["core"]["target"] == (
        "/usr/local/libexec/the-hive/hook-abi/v1/hook_abi_v1_core.py"
    )
    assert plan["launcher"]["sha256"] == (
        "sha256:" + manifest["files"]["bin/the-hive-plugin-hook-stable"]["sha256"]
    )
    assert plan["companion"]["sha256"] == (
        "sha256:"
        + manifest["files"]["src/the_hive/hook_session_pin_store.py"]["sha256"]
    )
    assert plan["core"]["sha256"] == (
        "sha256:" + manifest["files"]["src/the_hive/hook_abi_v1_core.py"]["sha256"]
    )
    binding_bytes = (bundle / "release-binding.json").read_bytes()

    release_root = _release_root(tmp_path)
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=stage, release_root=release_root
    )
    assert not (release_root / "the-hive-plugin-hook-stable").exists()
    published_bundle = release_root / "generations" / "one" / "TheHivePluginBundleV1"
    assert (published_bundle / "release-binding.json").read_bytes() == binding_bytes


def test_runtime_image_materializes_a_canonical_release_binding_descriptor(
    tmp_path: Path,
) -> None:
    installer = _installer()
    stage = _stage(installer, tmp_path, "descriptor")
    manifest_raw = (stage / ".the-hive-runtime-manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    binding = json.loads(
        (stage / "TheHivePluginBundleV1" / "release-binding.json").read_text(
            encoding="utf-8"
        )
    )

    assert binding == {
        "schema": "TheHivePluginBundleV1",
        "plugin_id": "the-hive",
        "generation": "descriptor",
        "runtime_manifest_digest": "sha256:" + hashlib.sha256(manifest_raw).hexdigest(),
        "launcher_abi": "/usr/local/libexec/the-hive/hook-abi/v1/launcher",
        "hooks": {
            "native_bee_event": "sha256:"
            + manifest["files"]["TheHivePluginBundleV1/hooks/native_bee_event.py"][
                "sha256"
            ],
            "native_spawn_admission": "sha256:"
            + manifest["files"][
                "TheHivePluginBundleV1/hooks/native_spawn_admission.py"
            ]["sha256"],
        },
    }
    assert "TheHivePluginBundleV1/release-binding.json" not in manifest["files"]
    assert not (stage / "release-binding.json").exists()


def test_publisher_reads_the_canonical_pin_store_without_an_injected_pin_default(
    tmp_path: Path,
) -> None:
    installer = _installer()
    release_root = _release_root(tmp_path)
    for generation in ("one", "two", "three"):
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=_stage(installer, tmp_path, generation), release_root=release_root
        )
    one_manifest = (
        release_root / "generations" / "one" / ".the-hive-runtime-manifest.json"
    )
    one_digest = "sha256:" + hashlib.sha256(one_manifest.read_bytes()).hexdigest()

    _pin_store(release_root).bind_session(
        session_id="session-one",
        generation="one",
        runtime_manifest_digest=one_digest,
        hooks={
            "native_bee_event": "sha256:" + "a" * 64,
            "native_spawn_admission": "sha256:" + "b" * 64,
        },
        now_unix_ns=1,
    )
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "four"), release_root=release_root
    )

    assert {item.name for item in (release_root / "generations").iterdir()} == {
        "one",
        "two",
        "three",
        "four",
    }
    pointer = release_root / ".the-hive-release-pointers.json"
    stable_mcp = release_root / "the-hive-mcp"
    before = (pointer.read_bytes(), stable_mcp.read_bytes())

    store_path = _pin_store(release_root).state_root
    for item in store_path.iterdir():
        item.unlink()
    with pytest.raises(
        installer["InstallError"], match="install_release_retention_failed"
    ):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=_stage(installer, tmp_path, "five"), release_root=release_root
        )

    assert (pointer.read_bytes(), stable_mcp.read_bytes()) == before
    assert not (release_root / "generations" / "five").exists()


def test_fresh_first_publish_needs_no_store_and_never_creates_one(
    tmp_path: Path,
) -> None:
    installer = _installer()
    home = tmp_path / "home"
    (home / ".local" / "lib").mkdir(mode=0o700, parents=True)
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    stage = _stage(installer, tmp_path, "first")

    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=stage, release_root=release_root
    )

    assert not stage.exists()
    assert (release_root / "generations" / "first").is_dir()
    assert not (home / ".local" / "state" / "the-hive").exists()


def test_failing_fresh_stage_leaves_no_release_root_and_valid_retry_bootstraps(
    tmp_path: Path,
) -> None:
    installer = _installer()
    home = tmp_path / "home"
    (home / ".local" / "lib").mkdir(mode=0o700, parents=True)
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    invalid = _stage(installer, tmp_path, "invalid-first")
    descriptor = invalid / "TheHivePluginBundleV1" / "release-binding.json"
    descriptor.write_text("{}\n", encoding="utf-8")
    descriptor.chmod(0o644)

    with pytest.raises(
        installer["InstallError"], match="install_stage_validation_failed"
    ):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=invalid, release_root=release_root
        )

    assert invalid.exists()
    assert not release_root.exists()
    assert not (home / ".local" / "state" / "the-hive").exists()

    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "valid-first"), release_root=release_root
    )

    assert (release_root / "generations" / "valid-first").is_dir()
    assert not (home / ".local" / "state" / "the-hive").exists()


def test_fresh_rename_failure_removes_only_publish_artifacts_for_valid_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    home = tmp_path / "home"
    (home / ".local" / "lib").mkdir(mode=0o700, parents=True)
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    failed_stage = _stage(installer, tmp_path, "rename-failure")
    rename = installer["os"].rename  # type: ignore[index]

    def fail_stage_rename(source: Path, target: Path) -> None:
        if source == failed_stage:
            raise OSError("fault injected rename failure")
        rename(source, target)

    monkeypatch.setattr(installer["os"], "rename", fail_stage_rename)  # type: ignore[index]
    with pytest.raises(installer["InstallError"], match="install_swap_failed"):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=failed_stage, release_root=release_root
        )

    assert failed_stage.exists()
    assert not release_root.exists()
    assert not (home / ".local" / "state" / "the-hive").exists()

    monkeypatch.setattr(installer["os"], "rename", rename)  # type: ignore[index]
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "rename-retry"), release_root=release_root
    )
    assert (release_root / "generations" / "rename-retry").is_dir()


def test_fresh_pointer_rollback_removes_only_publish_artifacts_for_valid_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    home = tmp_path / "home"
    (home / ".local" / "lib").mkdir(mode=0o700, parents=True)
    release_root = home / ".local" / "lib" / "the-hive-runtime"

    def fail_pointer(*_args: object, **_kwargs: object) -> None:
        raise installer["InstallError"]("install_release_pointer_write_failed")  # type: ignore[index]

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,  # type: ignore[index]
        "_write_release_pointers",
        fail_pointer,
    )
    with pytest.raises(
        installer["InstallError"], match="install_release_pointer_write_failed"
    ):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=_stage(installer, tmp_path, "pointer-failure"),
            release_root=release_root,
        )

    assert not release_root.exists()
    assert not (home / ".local" / "state" / "the-hive").exists()

    monkeypatch.undo()
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "pointer-retry"), release_root=release_root
    )
    assert (release_root / "generations" / "pointer-retry").is_dir()


def test_existing_release_root_without_canonical_pin_store_fails_pre_visible(
    tmp_path: Path,
) -> None:
    installer = _installer()
    home = tmp_path / "home"
    (home / ".local" / "lib" / "the-hive-runtime").mkdir(mode=0o700, parents=True)
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    stage = _stage(installer, tmp_path, "missing-store")

    with pytest.raises(
        installer["InstallError"], match="install_release_retention_failed"
    ):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=stage, release_root=release_root
        )

    assert stage.exists()
    assert not (release_root / "generations" / "missing-store").exists()
    assert not (release_root / ".the-hive-release-pointers.json").exists()


def test_prune_fault_cannot_run_after_cutover_because_publisher_retains_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = _release_root(tmp_path)
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "one"), release_root=release_root
    )

    def destructive_prune(*_args: object, **_kwargs: object) -> None:
        raise installer["InstallError"]("destructive_prune_called")  # type: ignore[index]

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,
        "_prune_release_generations",
        destructive_prune,
    )
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "two"), release_root=release_root
    )

    assert {item.name for item in (release_root / "generations").iterdir()} == {
        "one",
        "two",
    }


def test_pre_visible_unit_staging_failure_keeps_stage_and_release_unpublished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = _release_root(tmp_path)
    units = tmp_path / "units"
    units.mkdir(mode=0o700)
    stage = _stage(installer, tmp_path, "staging-failure")

    def fail_staging(*_args: object, **_kwargs: object) -> tuple[bytes, bytes]:
        raise installer["InstallError"]("install_release_template_invalid")  # type: ignore[index]

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,
        "_staged_hourly_probe_unit_bytes",
        fail_staging,
    )
    with pytest.raises(
        installer["InstallError"], match="install_stage_validation_failed"
    ):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=stage, release_root=release_root, live_unit_dir=units
        )

    assert stage.exists()
    assert not (release_root / "generations" / "staging-failure").exists()
    assert not (release_root / ".the-hive-release-pointers.json").exists()
    assert not tuple(units.iterdir())


def test_post_visibility_pointer_failure_restores_pointer_mcp_and_units(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = _release_root(tmp_path)
    units = tmp_path / "units"
    units.mkdir(mode=0o700)
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "one"),
        release_root=release_root,
        live_unit_dir=units,
    )
    pointer = release_root / ".the-hive-release-pointers.json"
    stable_mcp = release_root / "the-hive-mcp"
    names = (
        "the-hive-hive-hourly-probe.service",
        "the-hive-hive-hourly-probe.timer",
    )
    before = (
        pointer.read_bytes(),
        stable_mcp.read_bytes(),
        *((units / name).read_bytes() for name in names),
    )
    second = _stage(installer, tmp_path, "two")
    for path in (second / "bin" / "the-hive-mcp-stable",):
        path.write_bytes(path.read_bytes() + b"\n# next generation\n")
        path.chmod(0o755)
    _rewrite_manifest(installer, second, "two")

    def fail_pointer(*_args: object, **_kwargs: object) -> None:
        raise installer["InstallError"]("install_release_pointer_write_failed")  # type: ignore[index]

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,
        "_write_release_pointers",
        fail_pointer,
    )
    with pytest.raises(
        installer["InstallError"], match="install_release_pointer_write_failed"
    ):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=second, release_root=release_root
        )
    assert (
        pointer.read_bytes(),
        stable_mcp.read_bytes(),
        *((units / name).read_bytes() for name in names),
    ) == before


def test_late_pointer_failure_restores_the_prior_hourly_unit_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = _release_root(tmp_path)
    units = tmp_path / "units"
    units.mkdir(mode=0o700)
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "one"),
        release_root=release_root,
        live_unit_dir=units,
    )
    names = (
        "the-hive-hive-hourly-probe.service",
        "the-hive-hive-hourly-probe.timer",
    )
    before = tuple((units / name).read_bytes() for name in names)
    second = _stage(installer, tmp_path, "two")

    def fail_pointer(*_args: object, **_kwargs: object) -> None:
        raise installer["InstallError"]("install_release_pointer_write_failed")  # type: ignore[index]

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,
        "_write_release_pointers",
        fail_pointer,
    )
    with pytest.raises(
        installer["InstallError"], match="install_release_pointer_write_failed"
    ):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=second, release_root=release_root, live_unit_dir=units
        )

    assert tuple((units / name).read_bytes() for name in names) == before


def test_legacy_launcher_write_failure_rolls_back_the_complete_cutover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = _release_root(tmp_path)
    units = tmp_path / "units"
    units.mkdir(mode=0o700)
    libexec = release_root.parents[2] / ".local" / "libexec"
    libexec.mkdir(mode=0o700, parents=True)
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "one"),
        release_root=release_root,
        live_unit_dir=units,
        live_libexec=libexec,
    )
    pointer = release_root / ".the-hive-release-pointers.json"
    stable_mcp = release_root / "the-hive-mcp"
    launcher = libexec / "codex_master_hive_hourly_probe.py"
    names = (
        "the-hive-hive-hourly-probe.service",
        "the-hive-hive-hourly-probe.timer",
    )
    before = (
        pointer.read_bytes(),
        stable_mcp.read_bytes(),
        *((units / name).read_bytes() for name in names),
        launcher.read_bytes(),
    )
    install = installer["_install_attested_bytes"]  # type: ignore[index]
    failed = False

    def fail_legacy_once(target: Path, content: bytes, *, mode: int) -> None:
        nonlocal failed
        if target == launcher and not failed:
            failed = True
            raise installer["InstallError"]("injected_legacy_launcher_write_failure")  # type: ignore[index]
        install(target, content, mode=mode)

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,  # type: ignore[index]
        "_install_attested_bytes",
        fail_legacy_once,
    )
    with pytest.raises(
        installer["InstallError"], match="injected_legacy_launcher_write_failure"
    ):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=_stage(installer, tmp_path, "two"),
            release_root=release_root,
            live_unit_dir=units,
            live_libexec=libexec,
        )

    assert failed
    assert (
        pointer.read_bytes(),
        stable_mcp.read_bytes(),
        *((units / name).read_bytes() for name in names),
        launcher.read_bytes(),
    ) == before
    assert not (release_root / "generations" / "two").exists()


def test_post_launcher_unit_attestation_failure_rolls_back_complete_cutover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = _release_root(tmp_path)
    units = tmp_path / "units"
    units.mkdir(mode=0o700)
    libexec = release_root.parents[2] / ".local" / "libexec"
    libexec.mkdir(mode=0o700, parents=True)
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "one"),
        release_root=release_root,
        live_unit_dir=units,
        live_libexec=libexec,
    )
    pointer = release_root / ".the-hive-release-pointers.json"
    stable_mcp = release_root / "the-hive-mcp"
    launcher = libexec / "codex_master_hive_hourly_probe.py"
    names = (
        "the-hive-hive-hourly-probe.service",
        "the-hive-hive-hourly-probe.timer",
    )
    before = (
        pointer.read_bytes(),
        stable_mcp.read_bytes(),
        *((units / name).read_bytes() for name in names),
        launcher.read_bytes(),
    )

    def fail_post_launcher_unit_attestation(**_kwargs: object) -> None:
        return None

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,  # type: ignore[index]
        "_unit_bound_generation",
        fail_post_launcher_unit_attestation,
    )
    with pytest.raises(
        installer["InstallError"], match="install_release_retention_failed"
    ):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=_stage(installer, tmp_path, "two"),
            release_root=release_root,
            live_unit_dir=units,
            live_libexec=libexec,
        )

    assert (
        pointer.read_bytes(),
        stable_mcp.read_bytes(),
        *((units / name).read_bytes() for name in names),
        launcher.read_bytes(),
    ) == before
    assert not (release_root / "generations" / "two").exists()


def test_legacy_launcher_snapshot_rejects_a_symlink_before_generation_visibility(
    tmp_path: Path,
) -> None:
    installer = _installer()
    release_root = _release_root(tmp_path)
    libexec = release_root.parents[2] / ".local" / "libexec"
    libexec.mkdir(mode=0o700, parents=True)
    launcher = libexec / "codex_master_hive_hourly_probe.py"
    launcher.symlink_to(tmp_path / "untrusted-launcher")
    stage = _stage(installer, tmp_path, "symlinked-launcher")

    with pytest.raises(
        installer["InstallError"], match="install_release_triplet_invalid"
    ):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=stage,
            release_root=release_root,
            live_libexec=libexec,
        )

    assert stage.exists()
    assert launcher.is_symlink()
    assert not (release_root / "generations" / "symlinked-launcher").exists()
    assert not (release_root / ".the-hive-release-pointers.json").exists()


def test_missing_manifest_attested_hook_fails_before_generation_publication(
    tmp_path: Path,
) -> None:
    installer = _installer()
    stage = _stage(installer, tmp_path, "missing-hook")
    (stage / "hooks" / "native_bee_event.py").unlink()
    release_root = _release_root(tmp_path)

    with pytest.raises(installer["InstallError"], match="install_source_untrusted"):  # type: ignore[index]
        _rewrite_manifest(installer, stage, "missing-hook")

    assert not (release_root / ".the-hive-release-pointers.json").exists()
    assert not (release_root / "generations" / "missing-hook").exists()
