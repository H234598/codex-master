from __future__ import annotations

import hashlib
import json
import fcntl
import os
from pathlib import Path
import runpy
import shutil
import subprocess

import pytest

from the_hive.hook_session_pin_store import HookSessionPinStoreV1
import the_hive.runtime_layout as runtime_layout_module
from the_hive.runtime_layout import LayoutError, RuntimeLayout


ROOT = Path(__file__).resolve().parents[1]
F25 = "f25f60f6010d7b74b82a57f6471618e16df3e1a6"
C4 = "c4b72abcfe0e8b208b05f90cc4f8275def851581"
D73 = "f6f9348a4348d1a18bb3c4b591a93c393dfda838"
R2_BASE = "5defcac83030e91b39188c8b055adb97d5f51e98"
F25_TREE = "0f459eea9d8e13bd54e74e699272c53cddaecb1d"
D73_TREE = "d4f9620d25b0053763a6d20d0dfacbb8bd9a40ff"
R2_BASE_TREE = "6c872289709de2a0bfe69d8392ce91b49f3855f3"
D69_DYNAMIC_POOL_BLOB = "36c1e4a2716f808dc2ac89fe0d604249b1639ddd"
# Structural identity for private manifest fixtures only.  It is deliberately
# not presented as a Git commit; real publication calls _verified_release_commit.
TEST_MANIFEST_COMMIT = "a" * 40
SUCCESSOR_WITNESS_SHA256 = (
    "e8e9056cfde2c51af7a3a86d16c3220831f5cc4b8b5dc337df70489e38974a5c"
)


def _installer() -> dict[str, object]:
    return runpy.run_path(str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install"))


def _stage(
    installer: dict[str, object],
    root: Path,
    generation: str,
    *,
    commit: str = TEST_MANIFEST_COMMIT,
) -> Path:
    stage = root / f".the-hive-runtime.stage.{generation}"
    stage.mkdir(mode=0o700, parents=True)
    installer["_build_runtime_image"](  # type: ignore[operator]
        repository=ROOT, stage=stage, generation=generation, commit=commit
    )
    return stage


def _publisher_release_root(tmp_path: Path) -> Path:
    """Create only the canonical temporary pin authority for publisher tests."""

    home = tmp_path / "publisher-home"
    home.mkdir(mode=0o700)
    (home / ".local" / "lib").mkdir(mode=0o700, parents=True)
    HookSessionPinStoreV1.create_at(
        home / ".local" / "state" / "the-hive" / "hook-session-pins-v1"
    )
    return home / ".local" / "lib" / "the-hive-runtime"


def test_d89_successor_witness_binds_only_the_final_the_hive_anchor_and_git_lineage(
    tmp_path: Path,
) -> None:
    installer = _installer()
    assert installer["_SUCCESSOR_WITNESS_SHA256"] == SUCCESSOR_WITNESS_SHA256
    assert (
        runtime_layout_module._SUCCESSOR_WITNESS_SHA256  # type: ignore[attr-defined]
        == SUCCESSOR_WITNESS_SHA256
    )
    stage = _stage(installer, tmp_path, "successor")
    manifest = json.loads(
        (stage / ".the-hive-runtime-manifest.json").read_text(encoding="utf-8")
    )
    layout = RuntimeLayout.from_runtime_root(stage)

    assert manifest["schema_version"] == 2
    assert manifest["r2_base"] == {"commit": R2_BASE, "tree": R2_BASE_TREE}
    assert manifest["historical_lineage"] == {
        "d69": {
            "commit": F25,
            "tree": F25_TREE,
            "parent": C4,
            "dynamic_pool_blob": D69_DYNAMIC_POOL_BLOB,
        },
        "d73": {"commit": D73, "tree": D73_TREE, "parent": F25},
    }
    assert manifest["successor_witness"] == {
        "path": "src/the_hive/dynamic_pool.py",
        "sha256": SUCCESSOR_WITNESS_SHA256,
    }
    assert layout.root == stage
    assert layout.manifest_digest == (
        "sha256:"
        + hashlib.sha256(
            (stage / ".the-hive-runtime-manifest.json").read_bytes()
        ).hexdigest()
    )
    assert "d69_anchor" not in manifest
    assert "f25_d69_source_sha256" not in manifest
    assert "f25_c4_subset_sha256" not in manifest
    assert (
        manifest["files"]["src/the_hive/dynamic_pool.py"]["sha256"]
        == manifest["successor_witness"]["sha256"]
    )
    assert {
        "bin/the-hive-mcp-stable",
        "bin/the-hive-mcp",
        "bin/the-hive-resource-monitor",
    } == set(manifest["release"]["stable_launchers"])
    assert manifest["release"]["h4_units"] == [
        "systemd/user/the-hive-resource-monitor.service",
        "systemd/user/the-hive.slice",
    ]
    invalid_stage = tmp_path / "invalid-commit"
    invalid_stage.mkdir(mode=0o700)
    with pytest.raises(
        installer["InstallError"], match="install_release_identity_invalid"
    ):  # type: ignore[index]
        installer["_build_runtime_image"](  # type: ignore[operator]
            repository=ROOT,
            stage=invalid_stage,
            generation="invalid",
            commit="not-a-sha",
        )


def test_d89_successor_witness_rejects_a_regenerated_anchor_blob(
    tmp_path: Path,
) -> None:
    installer = _installer()
    stage = _stage(installer, tmp_path, "successor")
    anchor = stage / "src" / "the_hive" / "dynamic_pool.py"
    anchor.write_text(
        anchor.read_text(encoding="utf-8") + "\n# altered\n", encoding="utf-8"
    )
    anchor.chmod(0o644)
    (stage / ".the-hive-runtime-manifest.json").unlink()

    with pytest.raises(
        installer["InstallError"], match="install_release_binding_drift"
    ):  # type: ignore[index]
        installer["_write_runtime_image_manifest"](  # type: ignore[operator]
            root=stage, generation="successor", commit=TEST_MANIFEST_COMMIT
        )


def test_dirty_successor_source_cannot_claim_a_release_before_pointer_mutation(
    tmp_path: Path,
) -> None:
    installer = _installer()
    repository = tmp_path / "dirty-repository"
    shutil.copytree(
        ROOT,
        repository,
        ignore=shutil.ignore_patterns(".git", ".local", ".pytest_cache", "__pycache__"),
    )
    dirty = repository / "src" / "the_hive" / "dynamic_pool.py"
    dirty.write_text(
        dirty.read_text(encoding="utf-8") + "\n# dirty\n", encoding="utf-8"
    )
    stage = tmp_path / ".the-hive-runtime.stage.dirty"
    stage.mkdir(mode=0o700)
    release_root = tmp_path / "release-root"

    with pytest.raises(
        installer["InstallError"], match="install_release_binding_drift"
    ):  # type: ignore[index]
        installer["_build_runtime_image"](
            repository=repository, stage=stage, generation="dirty"
        )  # type: ignore[operator]
    assert not release_root.exists()


def test_production_publish_rechecks_clean_r2_base_descendant_after_stage_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A changed D69 source between provenance checks cannot reach Current."""

    installer = _installer()
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    identities = iter((TEST_MANIFEST_COMMIT, "b" * 40))
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,
        "_verified_release_commit",
        lambda _repository: next(identities),
    )
    with pytest.raises(
        installer["InstallError"], match="install_release_checkout_changed"
    ):  # type: ignore[index]
        installer["_install_attested_runtime"](home=home)  # type: ignore[operator]
    release_root = home / ".local" / "lib" / "the-hive-runtime"
    assert not (release_root / ".the-hive-release-pointers.json").exists()


def test_verified_release_commit_accepts_only_clean_r2_base_descended_git_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installer = _installer()
    descendant = "b" * 40

    def clean_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if command[3] == "status":
            return subprocess.CompletedProcess(command, 0, b"", b"")
        if command[3] == "rev-parse":
            return subprocess.CompletedProcess(
                command, 0, (descendant + "\n").encode(), b""
            )
        assert command[3] == "merge-base"
        assert command[4:] == ["--is-ancestor", R2_BASE, descendant]
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(installer["subprocess"], "run", clean_run)
    assert installer["_verified_release_commit"](ROOT) == descendant  # type: ignore[operator]

    def dirty_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if command[3] == "status":
            return subprocess.CompletedProcess(
                command, 0, b" M src/the_hive/server.py\0", b""
            )
        return subprocess.CompletedProcess(
            command, 0, (descendant + "\n").encode(), b""
        )

    monkeypatch.setattr(installer["subprocess"], "run", dirty_run)
    with pytest.raises(
        installer["InstallError"], match="install_release_checkout_dirty"
    ):  # type: ignore[index]
        installer["_verified_release_commit"](ROOT)  # type: ignore[operator]


def test_dirty_provenance_is_rejected_before_stage_or_pointer_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    built: list[object] = []

    def dirty(_repository: Path) -> str:
        raise installer["InstallError"]("install_release_checkout_dirty")  # type: ignore[index]

    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,
        "_verified_release_commit",
        dirty,
    )
    monkeypatch.setitem(
        installer["_install_attested_runtime"].__globals__,
        "_build_runtime_image",
        lambda **_kwargs: built.append("stage"),
    )
    with pytest.raises(
        installer["InstallError"], match="install_release_checkout_dirty"
    ):  # type: ignore[index]
        installer["_install_attested_runtime"](home=home)  # type: ignore[operator]
    assert built == []
    assert not (home / ".local" / "lib" / "the-hive-runtime").exists()


def test_named_generation_pointer_pair_rejects_manifest_mode_and_pointer_drift(
    tmp_path: Path,
) -> None:
    installer = _installer()
    release_root = _publisher_release_root(tmp_path)
    first = _stage(installer, tmp_path, "first")
    installer["_publish_runtime_generation"](stage=first, release_root=release_root)  # type: ignore[operator]
    digest = (
        "sha256:"
        + hashlib.sha256(
            (
                release_root
                / "generations"
                / "first"
                / ".the-hive-runtime-manifest.json"
            ).read_bytes()
        ).hexdigest()
    )
    layout = RuntimeLayout.from_current_release(release_root, "first", digest)
    assert layout.root == release_root / "generations" / "first"
    changed = layout.root / "src" / "the_hive" / "resource_monitor.py"
    changed.chmod(0o755)
    with pytest.raises(LayoutError):
        RuntimeLayout.from_current_release(release_root, "first", digest)
    changed.chmod(0o644)
    pointers = release_root / ".the-hive-release-pointers.json"
    value = json.loads(pointers.read_text(encoding="utf-8"))
    value["current"]["manifest_digest"] = "sha256:" + "0" * 64
    pointers.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(LayoutError):
        RuntimeLayout.from_current_release(release_root, "first", digest)


def test_publish_lock_fsync_failure_is_atomic_and_retention_keeps_live_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = _publisher_release_root(tmp_path)
    plugin_cache = tmp_path / "plugin-cache-sentinel"
    plugin_cache.mkdir()
    sentinel = plugin_cache / "untouched"
    sentinel.write_text("native cache", encoding="utf-8")
    first = _stage(installer, tmp_path, "first")
    installer["_publish_runtime_generation"](stage=first, release_root=release_root)  # type: ignore[operator]
    old_pointers = (release_root / ".the-hive-release-pointers.json").read_bytes()
    second = _stage(installer, tmp_path, "second")
    observed: list[Path] = []
    lock_operations: list[int] = []
    original_fsync = installer["_fsync_directory"]
    original_flock = installer["fcntl"].flock

    failed = False

    def fail_pointer(path: Path) -> None:
        nonlocal failed
        observed.append(path)
        if path == release_root and not failed:
            failed = True
            raise installer["InstallError"]("install_fsync_failed")  # type: ignore[operator]
        original_fsync(path)  # type: ignore[operator]

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,
        "_fsync_directory",
        fail_pointer,
    )  # type: ignore[index]
    monkeypatch.setattr(
        installer["fcntl"],
        "flock",
        lambda descriptor, operation: (
            lock_operations.append(operation),
            original_flock(descriptor, operation),
        )[1],
    )
    with pytest.raises(installer["InstallError"], match="install_fsync_failed"):  # type: ignore[index]
        installer["_publish_runtime_generation"](
            stage=second, release_root=release_root
        )  # type: ignore[operator]
    assert (
        release_root / ".the-hive-release-pointers.json"
    ).read_bytes() == old_pointers
    assert release_root in observed
    assert installer["fcntl"].LOCK_EX in lock_operations
    assert installer["fcntl"].LOCK_UN in lock_operations
    assert (release_root / "generations" / "first").is_dir()
    assert sentinel.read_text(encoding="utf-8") == "native cache"
    assert [path.relative_to(plugin_cache) for path in plugin_cache.rglob("*")] == [
        Path("untouched")
    ]


def test_pointer_post_replace_fsync_failure_restores_the_prior_durable_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = _publisher_release_root(tmp_path)
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "first"), release_root=release_root
    )
    pointer = release_root / ".the-hive-release-pointers.json"
    old = pointer.read_bytes()
    current = json.loads(old)["current"]
    original_fsync = installer["_fsync_directory"]
    failed = False

    def fail_once(path: Path) -> None:
        nonlocal failed
        if path == release_root and not failed:
            failed = True
            raise installer["InstallError"]("install_fsync_failed")  # type: ignore[operator]
        original_fsync(path)  # type: ignore[operator]

    monkeypatch.setitem(
        installer["_write_release_pointers"].__globals__, "_fsync_directory", fail_once
    )
    with pytest.raises(
        installer["InstallError"], match="install_release_pointer_write_failed"
    ):  # type: ignore[index]
        installer["_write_release_pointers"](  # type: ignore[operator]
            release_root, {"current": current, "previous": current}
        )
    assert failed is True
    assert pointer.read_bytes() == old


def test_pointer_fsync_failure_restores_the_complete_stable_mcp_launcher_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = _publisher_release_root(tmp_path)
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "first"), release_root=release_root
    )
    pointer = release_root / ".the-hive-release-pointers.json"
    stable_mcp = release_root / "the-hive-mcp"
    old_pointer = pointer.read_bytes()
    old_mcp = stable_mcp.read_bytes()
    second = _stage(installer, tmp_path, "second")
    staged_stable = second / "bin" / "the-hive-mcp-stable"
    staged_stable.write_bytes(staged_stable.read_bytes() + b"\n# second release\n")
    staged_stable.chmod(0o755)
    (second / ".the-hive-runtime-manifest.json").unlink()
    installer["_write_runtime_image_manifest"](  # type: ignore[operator]
        root=second, generation="second", commit=TEST_MANIFEST_COMMIT
    )
    original_fsync = installer["_fsync_directory"]
    root_fsyncs = 0

    def fail_pointer_fsync(path: Path) -> None:
        nonlocal root_fsyncs
        if path == release_root:
            root_fsyncs += 1
            if root_fsyncs == 3:
                raise installer["InstallError"]("install_fsync_failed")  # type: ignore[index]
        original_fsync(path)  # type: ignore[operator]

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,
        "_fsync_directory",
        fail_pointer_fsync,
    )
    with pytest.raises(
        installer["InstallError"], match="install_release_pointer_write_failed"
    ):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=second, release_root=release_root
        )
    assert root_fsyncs >= 6
    assert pointer.read_bytes() == old_pointer
    assert stable_mcp.read_bytes() == old_mcp
    current = json.loads(old_pointer)["current"]
    assert (
        RuntimeLayout.from_current_release(
            release_root, current["generation"], current["manifest_digest"]
        ).root
        == release_root / "generations" / "first"
    )


def test_publisher_does_not_prune_after_a_visible_immutable_cutover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = _publisher_release_root(tmp_path)
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "first"), release_root=release_root
    )
    pointer = release_root / ".the-hive-release-pointers.json"
    stable = release_root / "the-hive-mcp"
    old_pointer = pointer.read_bytes()
    old_stable = stable.read_bytes()
    second = _stage(installer, tmp_path, "second")
    prune_called = False

    def fail_prune(*_args: object, **_kwargs: object) -> None:
        nonlocal prune_called
        prune_called = True
        raise installer["InstallError"]("install_release_retention_failed")  # type: ignore[index]

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,
        "_prune_release_generations",
        fail_prune,
    )
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=second, release_root=release_root
    )
    assert prune_called is False
    assert pointer.read_bytes() != old_pointer
    assert stable.read_bytes() == old_stable
    current = json.loads(pointer.read_bytes())["current"]
    assert (
        RuntimeLayout.from_current_release(
            release_root, current["generation"], current["manifest_digest"]
        ).root
        == release_root / "generations" / "second"
    )


def test_retention_keeps_attested_unit_bound_generations_without_visible_pruning(
    tmp_path: Path,
) -> None:
    installer = _installer()
    release_root = _publisher_release_root(tmp_path)
    units = tmp_path / "units"
    units.mkdir(mode=0o700)
    for generation in ("one", "two"):
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=_stage(installer, tmp_path, generation),
            release_root=release_root,
        )
    one_manifest = (
        release_root / "generations" / "one" / ".the-hive-runtime-manifest.json"
    )
    one_digest = "sha256:" + hashlib.sha256(one_manifest.read_bytes()).hexdigest()
    (units / "the-hive-resource-monitor.service").write_text(
        "\n".join(
            (
                "[Service]",
                "BindReadOnlyPaths=%h/.local/lib/the-hive-runtime/generations/one/bin/the-hive-resource-monitor:%h/.local/bin/the-hive-resource-monitor:norbind %h/.local/lib/the-hive-runtime/generations/one/src:%h/.local/src:norbind %h/.local/lib/the-hive-runtime/generations/one/codex-agent-classes.json:%h/.local/codex-agent-classes.json:norbind %h/.local/lib/the-hive-runtime/generations/one/codex-hive.json:%h/.local/codex-hive.json:norbind",
                "ExecStart=%h/.local/bin/the-hive-resource-monitor %h/.local/lib/the-hive-runtime one "
                + one_digest,
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (units / "the-hive-resource-monitor.service").chmod(0o644)
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "three"),
        release_root=release_root,
        live_unit_dir=units,
    )
    pointers = json.loads(
        (release_root / ".the-hive-release-pointers.json").read_text(encoding="utf-8")
    )
    assert pointers["current"]["generation"] == "three"
    assert pointers["previous"]["generation"] == "two"
    assert {item.name for item in (release_root / "generations").iterdir()} == {
        "one",
        "two",
        "three",
    }
    previous = pointers["previous"]
    assert (
        RuntimeLayout.from_previous_release(
            release_root, previous["generation"], previous["manifest_digest"]
        ).root
        == release_root / "generations" / "two"
    )
    pointers["previous"] = {
        "generation": "one",
        "manifest_digest": previous["manifest_digest"],
    }
    (release_root / ".the-hive-release-pointers.json").write_text(
        json.dumps(pointers), encoding="utf-8"
    )
    with pytest.raises(LayoutError):
        RuntimeLayout.from_previous_release(
            release_root, "one", previous["manifest_digest"]
        )
    # Restore only the fully-attested pair.  Pre-pointer pruning deliberately
    # keeps the old Previous through this transition, then removes it on the
    # following transition without risking a failure after pointer replacement.
    pointers["previous"] = previous
    (release_root / ".the-hive-release-pointers.json").write_text(
        json.dumps(pointers), encoding="utf-8"
    )
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "four"),
        release_root=release_root,
        live_unit_dir=units,
    )
    assert {item.name for item in (release_root / "generations").iterdir()} == {
        "one",
        "two",
        "three",
        "four",
    }
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "five"),
        release_root=release_root,
        live_unit_dir=units,
    )
    assert {item.name for item in (release_root / "generations").iterdir()} == {
        "one",
        "two",
        "three",
        "four",
        "five",
    }


def test_publish_lock_is_exclusive_and_does_not_use_a_plugin_cache_path(
    tmp_path: Path,
) -> None:
    installer = _installer()
    release_root = tmp_path / "release-root"
    release_root.mkdir(mode=0o700)
    with installer["_release_publish_lock"](release_root):  # type: ignore[operator]
        descriptor = os.open(release_root / ".the-hive-release-publish.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
    assert not list((tmp_path / "plugin-cache").glob("**/*"))
