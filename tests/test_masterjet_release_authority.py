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

from codex_master.runtime_layout import LayoutError, RuntimeLayout


ROOT = Path(__file__).resolve().parents[1]
F25 = "f25f60f6010d7b74b82a57f6471618e16df3e1a6"
C4 = "c4b72abcfe0e8b208b05f90cc4f8275def851581"
# Structural identity for private manifest fixtures only.  It is deliberately
# not presented as a Git commit; real publication calls _verified_release_commit.
TEST_MANIFEST_COMMIT = "a" * 40


def _installer() -> dict[str, object]:
    return runpy.run_path(str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install"))


def _stage(
    installer: dict[str, object], root: Path, generation: str, *, commit: str = TEST_MANIFEST_COMMIT
) -> Path:
    stage = root / f".codex-master-runtime.stage.{generation}"
    stage.mkdir(mode=0o700, parents=True)
    installer["_build_runtime_image"](  # type: ignore[operator]
        repository=ROOT, stage=stage, generation=generation, commit=commit
    )
    return stage


def _f25_d69_source(repository: Path) -> None:
    """Replace exactly the D69 source set with immutable F25 blobs for a fixture."""

    for path in (
        "src/codex_master/admission.py",
        "src/codex_master/admission_runtime.py",
        "src/codex_master/dynamic_pool.py",
        "src/codex_master/hive/__init__.py",
        "src/codex_master/hive/admission.py",
        "src/codex_master/hive/dispatch.py",
        "src/codex_master/hive/principals.py",
        "src/codex_master/selection.py",
        "src/codex_master/selection_service.py",
        "src/codex_master/server.py",
    ):
        source = subprocess.run(
            ["git", "show", f"{F25}:{path}"], cwd=ROOT, check=True, capture_output=True
        ).stdout
        target = repository / path
        target.write_bytes(source)
        target.chmod(0o644)


def test_f25_d69_provenance_map_binds_the_h4_payload_and_c4_blob_subset(tmp_path: Path) -> None:
    installer = _installer()
    repository = tmp_path / "f25-d69-source"
    shutil.copytree(
        ROOT,
        repository,
        ignore=shutil.ignore_patterns(".git", ".local", ".pytest_cache", "__pycache__"),
    )
    _f25_d69_source(repository)
    stage = tmp_path / ".codex-master-runtime.stage.f25"
    stage.mkdir(mode=0o700)
    installer["_build_runtime_image"](  # type: ignore[operator]
        repository=repository, stage=stage, generation=F25, commit=F25
    )
    manifest = json.loads((stage / ".codex-master-runtime-manifest.json").read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 2
    assert manifest["commit"] == F25
    assert manifest["f25_base_commit"] == F25
    assert manifest["d69"] == {"commit": F25, "parent": C4}
    assert manifest["d69_anchor"] == {
        "path": "src/codex_master/dynamic_pool.py",
        "sha256": hashlib.sha256(
            subprocess.run(
                ["git", "show", f"{F25}:src/codex_master/dynamic_pool.py"],
                cwd=ROOT, check=True, capture_output=True,
            ).stdout
        ).hexdigest(),
    }
    assert manifest["f25_d69_source_sha256"] == {
        path: hashlib.sha256(
            subprocess.run(
                ["git", "show", f"{F25}:{path}"], cwd=ROOT, check=True, capture_output=True
            ).stdout
        ).hexdigest()
        for path in manifest["d69_paths"]
    }
    c4_subset = (
        "bin/codex-master-mcp",
        "bin/codex-master-resource-monitor",
        "systemd/user/codex-master.slice",
        "systemd/user/codex-master-resource-monitor.service",
        "src/codex_master/resource_cgroup.py",
        "src/codex_master/resource_monitor.py",
    )
    expected_c4_subset = {
        path: hashlib.sha256(
            subprocess.run(
                ["git", "show", f"{F25}:{path}"], cwd=ROOT, check=True, capture_output=True
            ).stdout
        ).hexdigest()
        for path in c4_subset
    }
    assert manifest["f25_c4_subset_sha256"] == expected_c4_subset
    for path, digest in expected_c4_subset.items():
        c4_bytes = subprocess.run(
            ["git", "show", f"{C4}:{path}"], cwd=ROOT, check=True, capture_output=True
        ).stdout
        assert hashlib.sha256(c4_bytes).hexdigest() == digest
    assert set(manifest["d69_paths"]).issubset(set(manifest["files"]))
    assert {
        "bin/codex-master-mcp-stable",
        "bin/codex-master-mcp",
        "bin/codex-master-resource-monitor",
    } == set(manifest["release"]["stable_launchers"])
    assert manifest["release"]["h4_units"] == [
        "systemd/user/codex-master-resource-monitor.service",
        "systemd/user/codex-master.slice",
    ]
    for path in ("src/codex_master/resource_cgroup.py", "src/codex_master/resource_monitor.py"):
        assert manifest["files"][path]["sha256"] == expected_c4_subset[path]
    invalid_stage = tmp_path / "invalid-commit"
    invalid_stage.mkdir(mode=0o700)
    with pytest.raises(installer["InstallError"], match="install_release_identity_invalid"):  # type: ignore[index]
        installer["_build_runtime_image"](  # type: ignore[operator]
            repository=ROOT, stage=invalid_stage, generation="invalid", commit="not-a-sha"
        )


def test_f25_manifest_rejects_a_regenerated_nonanchor_d69_server_blob(
    tmp_path: Path,
) -> None:
    installer = _installer()
    repository = tmp_path / "f25-d69-source"
    shutil.copytree(
        ROOT,
        repository,
        ignore=shutil.ignore_patterns(".git", ".local", ".pytest_cache", "__pycache__"),
    )
    _f25_d69_source(repository)
    stage = tmp_path / ".codex-master-runtime.stage.f25"
    stage.mkdir(mode=0o700)
    installer["_build_runtime_image"](  # type: ignore[operator]
        repository=repository, stage=stage, generation=F25, commit=F25
    )
    server = stage / "src" / "codex_master" / "server.py"
    server.write_text(server.read_text(encoding="utf-8") + "\n# altered\n", encoding="utf-8")
    server.chmod(0o644)
    (stage / ".codex-master-runtime-manifest.json").unlink()

    with pytest.raises(installer["InstallError"], match="install_release_binding_drift"):  # type: ignore[index]
        installer["_write_runtime_image_manifest"](  # type: ignore[operator]
            root=stage, generation=F25, commit=F25
        )


def test_dirty_d69_source_cannot_claim_the_f25_release_before_pointer_mutation(tmp_path: Path) -> None:
    installer = _installer()
    repository = tmp_path / "dirty-repository"
    shutil.copytree(
        ROOT,
        repository,
        ignore=shutil.ignore_patterns(".git", ".local", ".pytest_cache", "__pycache__"),
    )
    dirty = repository / "src" / "codex_master" / "dynamic_pool.py"
    dirty.write_text(dirty.read_text(encoding="utf-8") + "\n# dirty\n", encoding="utf-8")
    stage = tmp_path / ".codex-master-runtime.stage.dirty"
    stage.mkdir(mode=0o700)
    release_root = tmp_path / "release-root"

    with pytest.raises(installer["InstallError"], match="install_release_binding_drift"):  # type: ignore[index]
        installer["_build_runtime_image"](repository=repository, stage=stage, generation="dirty")  # type: ignore[operator]
    assert not release_root.exists()


def test_production_publish_rechecks_clean_f25_descendant_after_stage_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A changed D69 source between provenance checks cannot reach Current."""

    installer = _installer()
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    identities = iter((TEST_MANIFEST_COMMIT, "b" * 40))
    monkeypatch.setitem(
        installer["install"].__globals__,
        "_verified_release_commit",
        lambda _repository: next(identities),
    )
    with pytest.raises(installer["InstallError"], match="install_release_checkout_changed"):  # type: ignore[index]
        installer["install"](home=home)  # type: ignore[operator]
    release_root = home / ".local" / "lib" / "codex-master-runtime"
    assert not (release_root / ".codex-master-release-pointers.json").exists()


def test_verified_release_commit_accepts_only_clean_f25_descended_git_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installer = _installer()
    descendant = "b" * 40

    def clean_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if command[3] == "status":
            return subprocess.CompletedProcess(command, 0, b"", b"")
        if command[3] == "rev-parse":
            return subprocess.CompletedProcess(command, 0, (descendant + "\n").encode(), b"")
        assert command[3] == "merge-base"
        assert command[4:] == ["--is-ancestor", F25, descendant]
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(installer["subprocess"], "run", clean_run)
    assert installer["_verified_release_commit"](ROOT) == descendant  # type: ignore[operator]

    def dirty_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if command[3] == "status":
            return subprocess.CompletedProcess(command, 0, b" M src/codex_master/server.py\0", b"")
        return subprocess.CompletedProcess(command, 0, (descendant + "\n").encode(), b"")

    monkeypatch.setattr(installer["subprocess"], "run", dirty_run)
    with pytest.raises(installer["InstallError"], match="install_release_checkout_dirty"):  # type: ignore[index]
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

    monkeypatch.setitem(installer["install"].__globals__, "_verified_release_commit", dirty)
    monkeypatch.setitem(
        installer["install"].__globals__,
        "_build_runtime_image",
        lambda **_kwargs: built.append("stage"),
    )
    with pytest.raises(installer["InstallError"], match="install_release_checkout_dirty"):  # type: ignore[index]
        installer["install"](home=home)  # type: ignore[operator]
    assert built == []
    assert not (home / ".local" / "lib" / "codex-master-runtime").exists()


def test_named_generation_pointer_pair_rejects_manifest_mode_and_pointer_drift(tmp_path: Path) -> None:
    installer = _installer()
    release_root = tmp_path / "codex-master-runtime"
    first = _stage(installer, tmp_path, "first")
    installer["_publish_runtime_generation"](stage=first, release_root=release_root)  # type: ignore[operator]
    digest = "sha256:" + hashlib.sha256(
        (release_root / "generations" / "first" / ".codex-master-runtime-manifest.json").read_bytes()
    ).hexdigest()
    layout = RuntimeLayout.from_current_release(release_root, "first", digest)
    assert layout.root == release_root / "generations" / "first"
    changed = layout.root / "src" / "codex_master" / "resource_monitor.py"
    changed.chmod(0o755)
    with pytest.raises(LayoutError):
        RuntimeLayout.from_current_release(release_root, "first", digest)
    changed.chmod(0o644)
    pointers = release_root / ".codex-master-release-pointers.json"
    value = json.loads(pointers.read_text(encoding="utf-8"))
    value["current"]["manifest_digest"] = "sha256:" + "0" * 64
    pointers.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(LayoutError):
        RuntimeLayout.from_current_release(release_root, "first", digest)


def test_publish_lock_fsync_failure_is_atomic_and_retention_keeps_live_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = tmp_path / "codex-master-runtime"
    plugin_cache = tmp_path / "plugin-cache-sentinel"
    plugin_cache.mkdir()
    sentinel = plugin_cache / "untouched"
    sentinel.write_text("native cache", encoding="utf-8")
    first = _stage(installer, tmp_path, "first")
    installer["_publish_runtime_generation"](stage=first, release_root=release_root)  # type: ignore[operator]
    old_pointers = (release_root / ".codex-master-release-pointers.json").read_bytes()
    second = _stage(installer, tmp_path, "second")
    observed: list[Path] = []
    lock_operations: list[int] = []
    original_fsync = installer["_fsync_directory"]
    original_flock = installer["fcntl"].flock

    def fail_pointer(path: Path) -> None:
        observed.append(path)
        if path == release_root:
            raise installer["InstallError"]("install_fsync_failed")  # type: ignore[operator]
        original_fsync(path)  # type: ignore[operator]

    monkeypatch.setitem(installer["_publish_runtime_generation"].__globals__, "_fsync_directory", fail_pointer)  # type: ignore[index]
    monkeypatch.setattr(
        installer["fcntl"],
        "flock",
        lambda descriptor, operation: (lock_operations.append(operation), original_flock(descriptor, operation))[1],
    )
    with pytest.raises(installer["InstallError"], match="install_fsync_failed"):  # type: ignore[index]
        installer["_publish_runtime_generation"](stage=second, release_root=release_root, live_generations=("first",))  # type: ignore[operator]
    assert (release_root / ".codex-master-release-pointers.json").read_bytes() == old_pointers
    assert release_root in observed
    assert installer["fcntl"].LOCK_EX in lock_operations
    assert installer["fcntl"].LOCK_UN in lock_operations
    assert (release_root / "generations" / "first").is_dir()
    assert sentinel.read_text(encoding="utf-8") == "native cache"
    assert [path.relative_to(plugin_cache) for path in plugin_cache.rglob("*")] == [Path("untouched")]


def test_pointer_post_replace_fsync_failure_restores_the_prior_durable_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = tmp_path / "codex-master-runtime"
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "first"), release_root=release_root
    )
    pointer = release_root / ".codex-master-release-pointers.json"
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
    with pytest.raises(installer["InstallError"], match="install_release_pointer_write_failed"):  # type: ignore[index]
        installer["_write_release_pointers"](  # type: ignore[operator]
            release_root, {"current": current, "previous": current}
        )
    assert failed is True
    assert pointer.read_bytes() == old


def test_pointer_fsync_failure_restores_the_paired_stable_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = tmp_path / "codex-master-runtime"
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "first"), release_root=release_root
    )
    pointer = release_root / ".codex-master-release-pointers.json"
    stable = release_root / "codex-master-mcp"
    old_pointer = pointer.read_bytes()
    old_stable = stable.read_bytes()
    second = _stage(installer, tmp_path, "second")
    staged_stable = second / "bin" / "codex-master-mcp-stable"
    staged_stable.write_bytes(staged_stable.read_bytes() + b"\n# second release\n")
    staged_stable.chmod(0o755)
    (second / ".codex-master-runtime-manifest.json").unlink()
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
    with pytest.raises(installer["InstallError"], match="install_release_pointer_write_failed"):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=second, release_root=release_root
        )
    assert root_fsyncs >= 5
    assert pointer.read_bytes() == old_pointer
    assert stable.read_bytes() == old_stable
    current = json.loads(old_pointer)["current"]
    assert RuntimeLayout.from_current_release(
        release_root, current["generation"], current["manifest_digest"]
    ).root == release_root / "generations" / "first"


def test_prune_failure_precedes_pointer_launcher_pair_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = _installer()
    release_root = tmp_path / "codex-master-runtime"
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "first"), release_root=release_root
    )
    pointer = release_root / ".codex-master-release-pointers.json"
    stable = release_root / "codex-master-mcp"
    old_pointer = pointer.read_bytes()
    old_stable = stable.read_bytes()
    second = _stage(installer, tmp_path, "second")

    def fail_prune(*_args: object, **_kwargs: object) -> None:
        raise installer["InstallError"]("install_release_retention_failed")  # type: ignore[index]

    monkeypatch.setitem(
        installer["_publish_runtime_generation"].__globals__,
        "_prune_release_generations",
        fail_prune,
    )
    with pytest.raises(installer["InstallError"], match="install_release_retention_failed"):  # type: ignore[index]
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=second, release_root=release_root
        )
    assert pointer.read_bytes() == old_pointer
    assert stable.read_bytes() == old_stable
    current = json.loads(old_pointer)["current"]
    assert RuntimeLayout.from_current_release(
        release_root, current["generation"], current["manifest_digest"]
    ).root == release_root / "generations" / "first"


def test_retention_keeps_attested_unit_bound_generations_and_prunes_expired_ones(
    tmp_path: Path,
) -> None:
    installer = _installer()
    release_root = tmp_path / "codex-master-runtime"
    units = tmp_path / "units"
    units.mkdir(mode=0o700)
    for generation in ("one", "two"):
        installer["_publish_runtime_generation"](  # type: ignore[operator]
            stage=_stage(installer, tmp_path, generation),
            release_root=release_root,
        )
    one_manifest = release_root / "generations" / "one" / ".codex-master-runtime-manifest.json"
    one_digest = "sha256:" + hashlib.sha256(one_manifest.read_bytes()).hexdigest()
    (units / "codex-master-resource-monitor.service").write_text(
        "\n".join(
                (
                    "[Service]",
                    "BindReadOnlyPaths=%h/.local/lib/codex-master-runtime/generations/one/bin/codex-master-resource-monitor:%h/.local/bin/codex-master-resource-monitor:norbind %h/.local/lib/codex-master-runtime/generations/one/src:%h/.local/src:norbind %h/.local/lib/codex-master-runtime/generations/one/codex-agent-classes.json:%h/.local/codex-agent-classes.json:norbind %h/.local/lib/codex-master-runtime/generations/one/codex-hive.json:%h/.local/codex-hive.json:norbind",
                "ExecStart=%h/.local/bin/codex-master-resource-monitor %h/.local/lib/codex-master-runtime one " + one_digest,
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (units / "codex-master-resource-monitor.service").chmod(0o644)
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "three"),
        release_root=release_root,
        live_unit_dir=units,
    )
    pointers = json.loads(
        (release_root / ".codex-master-release-pointers.json").read_text(encoding="utf-8")
    )
    assert pointers["current"]["generation"] == "three"
    assert pointers["previous"]["generation"] == "two"
    assert {item.name for item in (release_root / "generations").iterdir()} == {"one", "two", "three"}
    previous = pointers["previous"]
    assert RuntimeLayout.from_previous_release(
        release_root, previous["generation"], previous["manifest_digest"]
    ).root == release_root / "generations" / "two"
    pointers["previous"] = {"generation": "one", "manifest_digest": previous["manifest_digest"]}
    (release_root / ".codex-master-release-pointers.json").write_text(
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
    (release_root / ".codex-master-release-pointers.json").write_text(
        json.dumps(pointers), encoding="utf-8"
    )
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "four"),
        release_root=release_root,
        live_unit_dir=units,
    )
    assert {item.name for item in (release_root / "generations").iterdir()} == {"one", "two", "three", "four"}
    installer["_publish_runtime_generation"](  # type: ignore[operator]
        stage=_stage(installer, tmp_path, "five"),
        release_root=release_root,
        live_unit_dir=units,
    )
    assert {item.name for item in (release_root / "generations").iterdir()} == {
        "one", "three", "four", "five"
    }


def test_publish_lock_is_exclusive_and_does_not_use_a_plugin_cache_path(tmp_path: Path) -> None:
    installer = _installer()
    release_root = tmp_path / "release-root"
    release_root.mkdir(mode=0o700)
    with installer["_release_publish_lock"](release_root):  # type: ignore[operator]
        descriptor = os.open(
            release_root / ".codex-master-release-publish.lock", os.O_RDWR
        )
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
    assert not list((tmp_path / "plugin-cache").glob("**/*"))
