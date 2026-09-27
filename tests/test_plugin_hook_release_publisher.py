from __future__ import annotations

import hashlib
import json
from pathlib import Path
import runpy
import shutil
import stat

import pytest

import the_hive.runtime_layout as runtime_layout
from the_hive.hook_session_pin_store import HookSessionPinStoreV1
from the_hive.runtime_layout import (
    RuntimeLayout,
    attest_pre_pricing_legacy_runtime,
)


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


def _pre_pricing_legacy_stage(
    installer: dict[str, object], root: Path, generation: str
) -> tuple[Path, str]:
    """Build the exact predecessor layout from the complete current fixture."""

    stage = root / f".the-hive-runtime.stage.{generation}"
    stage.mkdir(mode=0o700)
    installer["_build_runtime_image"](  # type: ignore[operator]
        repository=ROOT, stage=stage, generation=generation, commit=generation
    )
    for relative in (
        "bin/the-hive-plugin-hook-stable",
        "bin/the-hive-openai-pricing-inventory",
        "bin/the-hive-openai-pricing-inventory-stable",
        "systemd/user/the-hive-openai-pricing.service",
        "systemd/user/the-hive-openai-pricing.timer",
        ".the-hive-runtime-manifest.json",
        "root-install-plan.json",
    ):
        (stage / relative).unlink()
    shutil.rmtree(stage / "TheHivePluginBundleV1")
    manifest = installer["_runtime_manifest_payload"](  # type: ignore[operator]
        stage, generation=generation, commit=generation
    )
    manifest["release"] = {
        "stable_launchers": [
            "bin/the-hive-mcp-stable",
            "bin/the-hive-mcp",
            "bin/the-hive-resource-monitor",
        ],
        "python_tree": "src/the_hive",
        "monitor_entrypoint": "bin/the-hive-resource-monitor",
        "h4_units": [
            "systemd/user/the-hive-resource-monitor.service",
            "systemd/user/the-hive.slice",
        ],
        "bind_sources": [
            "bin/the-hive-resource-monitor",
            "src/the_hive",
            "codex-agent-classes.json",
            "codex-hive.json",
            "%h/.local/state/codex-master-mcp/hive",
        ],
    }
    manifest_raw = installer["_canonical_json"](manifest)  # type: ignore[operator]
    manifest_path = stage / ".the-hive-runtime-manifest.json"
    manifest_path.write_bytes(manifest_raw)
    manifest_path.chmod(0o644)
    digest = "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
    return stage, digest


def _materialize_pre_pricing_legacy_release(
    installer: dict[str, object],
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, bytes]:
    """Install the sole observed pre-pricing pointer pair privately."""

    home.chmod(0o700)
    (home / ".local").chmod(0o700)
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    generations = release_root / "generations"
    generations.mkdir(parents=True, mode=0o700)
    release_root.chmod(0o700)
    generations.chmod(0o700)
    entries: dict[str, dict[str, str]] = {}
    for name in (
        "c7efc03f00eee1933f86808902d109f81bad446e",
        "83abaae0ee21959b17cec1fe18002c4d80776296",
    ):
        stage, digest = _pre_pricing_legacy_stage(installer, home.parent, name)
        runtime = generations / name
        stage.rename(runtime)
        monkeypatch.setitem(runtime_layout._PRE_PRICING_LEGACY_DIGESTS, name, digest)
        assert attest_pre_pricing_legacy_runtime(runtime, expected_digest=digest) == {
            "generation": name,
            "manifest_digest": digest,
        }
        entries[name] = {"generation": name, "manifest_digest": digest}
    pair = {
        "current": entries["c7efc03f00eee1933f86808902d109f81bad446e"],
        "previous": entries["83abaae0ee21959b17cec1fe18002c4d80776296"],
    }
    monkeypatch.setitem(
        installer["_attested_pre_pricing_legacy_pointers"].__globals__,  # type: ignore[index]
        "_PRE_PRICING_LEGACY_POINTER_PAIR",
        pair,
    )
    pointer = release_root / ".the-hive-release-pointers.json"
    pointer.write_bytes(
        (
            json.dumps(
                {
                    "schema_version": 1,
                    **pair,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    )
    pointer.chmod(0o644)
    return release_root, pointer.read_bytes()


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


def test_pre_pricing_legacy_release_without_pin_store_upgrades_to_current_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only an attested predecessor may consume the absent-store upgrade path."""

    installer = _installer()
    home = tmp_path / "home"
    home.mkdir(mode=0o755)
    (home / ".local").mkdir(mode=0o755)
    (home / ".local" / "lib").mkdir(mode=0o700)
    generation = "c7efc03f00eee1933f86808902d109f81bad446e"
    release_root, old_pointer = _materialize_pre_pricing_legacy_release(
        installer, home, monkeypatch
    )
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    assert stat.S_IMODE((home / ".local").stat().st_mode) == 0o700
    old_runtime = release_root / "generations" / generation
    with pytest.raises(ValueError):
        RuntimeLayout.from_runtime_root(old_runtime)

    release_commit = {"value": "b" * 40}
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,  # type: ignore[index]
        "_verified_release_commit",
        lambda _repository: release_commit["value"],
    )
    upgraded = installer["_install_attested_runtime"](home=home)  # type: ignore[operator]
    assert upgraded["generation"] == "b" * 40
    pointer = release_root / ".the-hive-release-pointers.json"
    upgraded_pointer = json.loads(pointer.read_text(encoding="utf-8"))
    assert upgraded_pointer["current"]["generation"] == "b" * 40
    assert upgraded_pointer["previous"] is None
    assert pointer.read_bytes() != old_pointer
    assert (home / ".local" / "bin" / "the-hive-openai-pricing-inventory").is_file()
    for name in (
        "the-hive-openai-pricing.service",
        "the-hive-openai-pricing.timer",
    ):
        assert (home / ".config" / "systemd" / "user" / name).is_file()
    assert RuntimeLayout.from_current_release(
        release_root,
        upgraded_pointer["current"]["generation"],
        upgraded_pointer["current"]["manifest_digest"],
    ).root == (release_root / "generations" / ("b" * 40))

    HookSessionPinStoreV1.create_at(
        home / ".local" / "state" / "the-hive" / "hook-session-pins-v1"
    )
    release_commit["value"] = "c" * 40
    subsequent = installer["_install_attested_runtime"](home=home)  # type: ignore[operator]
    assert subsequent["generation"] == "c" * 40
    subsequent_pointer = json.loads(pointer.read_text(encoding="utf-8"))
    assert subsequent_pointer["current"]["generation"] == "c" * 40
    assert subsequent_pointer["previous"] == upgraded_pointer["current"]
    assert RuntimeLayout.from_previous_release(
        release_root,
        subsequent_pointer["previous"]["generation"],
        subsequent_pointer["previous"]["manifest_digest"],
    ).root == (release_root / "generations" / ("b" * 40))


@pytest.mark.parametrize("variant", ["missing", "reversed", "mixed"])
def test_pre_pricing_legacy_upgrade_rejects_any_nonobserved_pointer_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    """The one-way exception admits neither a subset nor another ordering."""

    installer = _installer()
    home = tmp_path / "home"
    (home / ".local" / "lib").mkdir(mode=0o700, parents=True)
    release_root, _old_pointer = _materialize_pre_pricing_legacy_release(
        installer, home, monkeypatch
    )
    pointer = release_root / ".the-hive-release-pointers.json"
    invalid = json.loads(pointer.read_text(encoding="utf-8"))
    if variant == "missing":
        invalid["previous"] = None
    elif variant == "reversed":
        invalid["current"], invalid["previous"] = (
            invalid["previous"],
            invalid["current"],
        )
    else:
        invalid["previous"] = invalid["current"]
    invalid_bytes = (
        json.dumps(
            invalid, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        + "\n"
    ).encode("ascii")
    pointer.write_bytes(invalid_bytes)
    pointer.chmod(0o644)
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,  # type: ignore[index]
        "_verified_release_commit",
        lambda _repository: "b" * 40,
    )

    with pytest.raises(
        installer["InstallError"], match="install_release_pointer_invalid"  # type: ignore[index]
    ):
        installer["_install_attested_runtime"](home=home)  # type: ignore[operator]

    assert pointer.read_bytes() == invalid_bytes
    assert not (release_root / "generations" / ("b" * 40)).exists()


def test_pre_pricing_legacy_attestation_binds_generation_to_known_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A complete lookalike must not substitute for the observed predecessor."""

    installer = _installer()
    generation = "c7efc03f00eee1933f86808902d109f81bad446e"
    stage, original_digest = _pre_pricing_legacy_stage(
        installer, tmp_path, generation
    )
    runtime = tmp_path / "generations" / generation
    runtime.parent.mkdir(mode=0o700)
    stage.rename(runtime)
    monkeypatch.setitem(
        runtime_layout._PRE_PRICING_LEGACY_DIGESTS, generation, original_digest
    )
    assert attest_pre_pricing_legacy_runtime(
        runtime, expected_digest=original_digest
    ) == {"generation": generation, "manifest_digest": original_digest}

    extra = runtime / "src" / "the_hive" / "legacy-compat-lookalike.py"
    extra.write_text("marker = 'not the observed image'\n", encoding="ascii")
    extra.chmod(0o644)
    manifest_path = runtime / ".the-hive-runtime-manifest.json"
    old_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_path.unlink()
    altered_manifest = installer["_runtime_manifest_payload"](  # type: ignore[operator]
        runtime, generation=generation, commit=generation
    )
    altered_manifest["release"] = old_manifest["release"]
    altered_raw = installer["_canonical_json"](  # type: ignore[operator]
        altered_manifest
    )
    manifest_path.write_bytes(altered_raw)
    manifest_path.chmod(0o644)
    altered_digest = "sha256:" + hashlib.sha256(altered_raw).hexdigest()

    with pytest.raises(ValueError):
        attest_pre_pricing_legacy_runtime(runtime, expected_digest=altered_digest)

    monkeypatch.setitem(
        runtime_layout._PRE_PRICING_LEGACY_DIGESTS, generation, altered_digest
    )
    assert attest_pre_pricing_legacy_runtime(
        runtime, expected_digest=altered_digest
    ) == {"generation": generation, "manifest_digest": altered_digest}


def test_pre_pricing_legacy_upgrade_rejects_untrusted_generation_pre_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A legacy compatibility claim never bypasses regular-file attestation."""

    installer = _installer()
    home = tmp_path / "home"
    (home / ".local" / "lib").mkdir(mode=0o700, parents=True)
    generation = "c7efc03f00eee1933f86808902d109f81bad446e"
    release_root, old_pointer = _materialize_pre_pricing_legacy_release(
        installer, home, monkeypatch
    )
    old_runtime = release_root / "generations" / generation
    target = old_runtime / "bin" / "the-hive-mcp"
    target.chmod(0o777)
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,  # type: ignore[index]
        "_verified_release_commit",
        lambda _repository: "b" * 40,
    )

    with pytest.raises(
        installer["InstallError"], match="install_release_pointer_invalid"  # type: ignore[index]
    ):
        installer["_install_attested_runtime"](home=home)  # type: ignore[operator]

    assert (
        release_root / ".the-hive-release-pointers.json"
    ).read_bytes() == old_pointer
    assert not (release_root / "generations" / ("b" * 40)).exists()


@pytest.mark.parametrize(
    ("relative_path", "kind"),
    [
        ("root-install-plan.json", "file"),
        ("TheHivePluginBundleV1", "directory"),
    ],
)
def test_pre_pricing_legacy_upgrade_rejects_physical_current_era_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    kind: str,
) -> None:
    """Manifest-exempt files and directories cannot pass the legacy branch."""

    installer = _installer()
    home = tmp_path / "home"
    (home / ".local" / "lib").mkdir(mode=0o700, parents=True)
    generation = "c7efc03f00eee1933f86808902d109f81bad446e"
    release_root, old_pointer = _materialize_pre_pricing_legacy_release(
        installer, home, monkeypatch
    )
    old_runtime = release_root / "generations" / generation
    artifact = old_runtime / relative_path
    if kind == "file":
        artifact.write_text("unexpected\n", encoding="ascii")
        artifact.chmod(0o644)
    else:
        artifact.mkdir(mode=0o700)
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,  # type: ignore[index]
        "_verified_release_commit",
        lambda _repository: "b" * 40,
    )

    with pytest.raises(
        installer["InstallError"], match="install_release_pointer_invalid"  # type: ignore[index]
    ):
        installer["_install_attested_runtime"](home=home)  # type: ignore[operator]

    assert (
        release_root / ".the-hive-release-pointers.json"
    ).read_bytes() == old_pointer
    assert not (release_root / "generations" / ("b" * 40)).exists()


def test_pre_pricing_legacy_upgrade_rolls_back_postrename_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed compatibility upgrade restores its original legacy pointer."""

    installer = _installer()
    home = tmp_path / "home"
    (home / ".local" / "lib").mkdir(mode=0o700, parents=True)
    generation = "c7efc03f00eee1933f86808902d109f81bad446e"
    release_root, old_pointer = _materialize_pre_pricing_legacy_release(
        installer, home, monkeypatch
    )
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,  # type: ignore[index]
        "_verified_release_commit",
        lambda _repository: "b" * 40,
    )

    def fail_pointer(
        _root: Path, _pointers: dict[str, dict[str, str] | None]
    ) -> None:
        raise installer["InstallError"]("injected_pointer_failure")  # type: ignore[index]

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,  # type: ignore[index]
        "_write_release_pointers",
        fail_pointer,
    )
    with pytest.raises(installer["InstallError"], match="injected_pointer_failure"):  # type: ignore[index]
        installer["_install_attested_runtime"](home=home)  # type: ignore[operator]

    assert (
        release_root / ".the-hive-release-pointers.json"
    ).read_bytes() == old_pointer
    assert not (release_root / "generations" / ("b" * 40)).exists()
    assert not (home / ".local" / "bin" / "the-hive-openai-pricing-inventory").exists()
    assert not (
        home / ".config" / "systemd" / "user" / "the-hive-openai-pricing.service"
    ).exists()


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
