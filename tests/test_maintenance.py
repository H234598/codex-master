from __future__ import annotations

import subprocess
import os
import multiprocessing
import fcntl
import io
import sys
import hashlib
import json
import secrets
import mmap
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import tarfile
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from the_hive.maintenance import (
    ArchiveReceipt,
    MaintenanceCandidate,
    MaintenanceError,
    ProjectPolicy,
    apply_candidate,
    _archive_candidate,
    _tree_manifest,
    _verify_root_metadata,
    _xattrs,
    restore_archive,
    scan_candidates,
)
from the_hive.headless_write_scope import HeadlessWriteScopeStore
from the_hive.hive.state import HiveStateStore
from the_hive import runtime_process
from the_hive import server as server_module
from the_hive import maintenance as maintenance_module
from the_hive import worktree_lifecycle as lifecycle_module
from the_hive.resource_cgroup import PreparedAgentScope
from the_hive.worktree_lifecycle import (
    G5ScopeBindingEvidence,
    RuntimeEndEvidence,
    WorktreeBinding,
    WorktreeLifecycleStore,
)
from the_hive.worktree_lifecycle import WorktreeLifecycleError


def _git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()


def _restore_worker(receipt: ArchiveReceipt, destination: Path, results: object) -> None:
    try:
        results.put(restore_archive(receipt, destination).as_posix())
    except Exception as exc:
        results.put(f"ERROR:{type(exc).__name__}:{exc}")


def _archive_writer_crashes_with_locked_child(
    state_root: str,
    binding: WorktreeBinding,
    archive_root: str,
    release_marker: str,
    channel: object,
) -> None:
    lifecycle = WorktreeLifecycleStore(HiveStateStore(Path(state_root)))
    claim = lifecycle.claim_maintenance(binding, now=100)
    lifecycle.advance_maintenance_phase(claim, phase="archiving")
    lock_fd = os.open(archive_root, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    lifecycle._bind_maintenance_archive_lock(
        claim, Path(archive_root), lock_fd
    )
    child_code = (
        "import os,sys,time; marker=sys.argv[1]; "
        "exec('while not os.path.exists(marker):\\n time.sleep(0.01)')"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", child_code, release_marker],
        pass_fds=maintenance_module._maintenance_pass_fds(lock_fd, ()),
        close_fds=True,
    )
    channel.send((os.getpid(), child.pid, claim.revision, claim.fence))
    os._exit(0)


def _recover_after_archive_lock(
    state_root: str,
    binding: WorktreeBinding,
    archive_root: str,
    channel: object,
) -> None:
    lifecycle = WorktreeLifecycleStore(HiveStateStore(Path(state_root)))
    channel.send("waiting")
    claim = maintenance_module._recover_maintenance_claim_under_archive_lock(
        lifecycle, binding, now=200
    )
    try:
        lifecycle.maintenance_operation_for_claim(claim)
    except Exception as exc:
        operation_error = str(exc)
    else:
        operation_error = "operation unexpectedly available"
    try:
        lifecycle.finish_maintenance(claim, outcome="recovered")
    except Exception as exc:
        finish_error = str(exc)
    else:
        finish_error = "finish unexpectedly succeeded"
    channel.send((claim.revision, claim.fence, operation_error, finish_error))


def _temporary_handoff_writer_crashes_with_locked_child(
    state_root: str,
    producer: Path,
    candidate: MaintenanceCandidate,
    policy: ProjectPolicy,
    release_marker: str,
    channel: object,
) -> None:
    lifecycle = WorktreeLifecycleStore(HiveStateStore(Path(state_root)))
    claim = lifecycle.claim_maintenance(candidate.binding, now=int(time.time()))
    lifecycle.advance_maintenance_phase(claim, phase="archiving")
    receipt = maintenance_module.archive_temporary_candidate(
        candidate, policy=policy, lifecycle=lifecycle, claim=claim
    )
    lifecycle.record_maintenance_archive(claim, receipt)
    lifecycle.advance_maintenance_phase(claim, phase="quarantine_started")
    quarantine_root = producer.parent / ".hive-quarantine"
    quarantine_root.mkdir(mode=0o700)
    quarantine_claim = quarantine_root / claim.claim_id
    quarantine_claim.mkdir(mode=0o700)
    producer.rename(quarantine_claim / "temporary")
    lifecycle.advance_maintenance_phase(claim, phase="quarantined")
    lifecycle.hold_maintenance_claim(claim)

    lock_fd = os.open(policy.archive_root, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    child_code = (
        "import os,sys,time; marker=sys.argv[1]; "
        "exec('while not os.path.exists(marker):\\n time.sleep(0.01)')"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", child_code, release_marker],
        pass_fds=maintenance_module._maintenance_pass_fds(lock_fd, ()),
        close_fds=True,
    )
    channel.send((os.getpid(), child.pid, claim.claim_id, claim.revision, claim.fence))
    os.close(lock_fd)
    os._exit(0)


def _run_temporary_recovery_cli_process(
    project_root: str,
    state_root: str,
    producer: str,
    channel: object,
) -> None:
    root = Path(project_root)
    store_root = Path(state_root)
    server_module.repo_root = lambda: root
    server_module.STATE_ROOT = store_root.parent
    server_module._worktree_lifecycle_store = lambda **_kwargs: WorktreeLifecycleStore(
        HiveStateStore(store_root)
    )
    original_flock = fcntl.flock
    announced = False

    def announce_lock_attempt(descriptor: int, operation: int) -> None:
        nonlocal announced
        if operation == fcntl.LOCK_EX and not announced:
            announced = True
            channel.send("flock_attempting")
        original_flock(descriptor, operation)

    maintenance_module.fcntl.flock = announce_lock_attempt
    captured = io.StringIO()
    previous_stdout = sys.stdout
    sys.stdout = captured
    try:
        exit_code = server_module.main_cli(
            [
                "worktree-maintenance",
                "recover",
                "--repository-id",
                "codex-master",
                "--source",
                producer,
            ]
        )
    except Exception as exc:
        channel.send(("error", type(exc).__name__, str(exc)))
    else:
        channel.send(("cli", exit_code, captured.getvalue()))
    finally:
        sys.stdout = previous_stdout


def _file_snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def _finish_fixture_use(
    lifecycle: WorktreeLifecycleStore, binding: WorktreeBinding, *, now: int
) -> None:
    lease = lifecycle.begin_use(
        binding,
        principal_id="principal.fixture",
        session_id="session.fixture",
        assignment_id="assignment.fixture",
        now=now,
    )
    unit = f"the-hive-resource-{secrets.token_hex(16)}.scope"
    group = f"/the-hive.slice/{unit}"
    cgroup_root = binding.canonical_source_path.parent / "fixture-cgroups"
    cgroup = cgroup_root / "the-hive.slice" / unit
    cgroup.mkdir(parents=True)
    (cgroup / "cgroup.events").write_text("populated 1\nfrozen 0\n", encoding="ascii")
    (cgroup / "cgroup.procs").write_text("777\n", encoding="ascii")
    invocation = secrets.token_hex(16)

    def fake_systemctl(_args, *, environment, deadline):
        del environment, deadline
        return f"ControlGroup={group}\nInvocationID={invocation}\nLoadState=loaded\n".encode()

    scope = PreparedAgentScope(
        unit_name=unit,
        socket_name=f"g5-{secrets.token_hex(8)}",
        session_name=f"worktree-{secrets.token_hex(5)}",
        control_group=group,
        gate_pid=os.getpid(),
        challenge=secrets.token_hex(32),
    )
    with (
        patch.object(runtime_process, "_CGROUP_ROOT", cgroup_root),
        patch.object(runtime_process, "_systemctl", fake_systemctl),
    ):
        evidence = G5ScopeBindingEvidence.capture(lease, scope, now=now + 1)
        lease = lifecycle.bind_g5_runtime(lease, evidence, now=now + 1)
        (cgroup / "cgroup.events").write_text("populated 0\nfrozen 0\n", encoding="ascii")
        (cgroup / "cgroup.procs").write_text("", encoding="ascii")
        end_evidence = RuntimeEndEvidence.observe(lease, now=now + 2)
        lifecycle.end_use(lease, end_evidence, now=now + 3)


def _create_ended_temp_producer(
    lifecycle: WorktreeLifecycleStore,
    binding: WorktreeBinding,
    temp_root: Path,
    *,
    now: int,
) -> Path:
    lease = lifecycle.begin_use(
        binding,
        principal_id="principal.temp-owner-fixture",
        session_id="session.temp-owner-fixture",
        assignment_id=f"assignment.temp-owner-{secrets.token_hex(5)}",
        now=now - 8 * 86400,
    )
    with patch.object(tempfile, "gettempdir", lambda: str(temp_root)):
        producer = lifecycle.create_temporary_producer(lease, now=now - 8 * 86400)
    unit = f"the-hive-resource-{secrets.token_hex(16)}.scope"
    group = f"/the-hive.slice/{unit}"
    cgroup_root = binding.canonical_source_path.parent / f"cgroups-{secrets.token_hex(5)}"
    cgroup = cgroup_root / "the-hive.slice" / unit
    cgroup.mkdir(parents=True)
    (cgroup / "cgroup.events").write_text("populated 1\nfrozen 0\n", encoding="ascii")
    (cgroup / "cgroup.procs").write_text("777\n", encoding="ascii")
    invocation = secrets.token_hex(16)

    def fake_systemctl(_args, *, environment, deadline):
        del environment, deadline
        return f"ControlGroup={group}\nInvocationID={invocation}\nLoadState=loaded\n".encode()

    scope = PreparedAgentScope(
        unit_name=unit,
        socket_name=f"g5-{secrets.token_hex(8)}",
        session_name=f"worktree-{secrets.token_hex(5)}",
        control_group=group,
        gate_pid=os.getpid(),
        challenge=secrets.token_hex(32),
    )
    with (
        patch.object(runtime_process, "_CGROUP_ROOT", cgroup_root),
        patch.object(runtime_process, "_systemctl", fake_systemctl),
    ):
        evidence = G5ScopeBindingEvidence.capture(lease, scope, now=now - 8 * 86400 + 1)
        lease = lifecycle.bind_g5_runtime(lease, evidence, now=now - 8 * 86400 + 1)
        (cgroup / "cgroup.events").write_text("populated 0\nfrozen 0\n", encoding="ascii")
        (cgroup / "cgroup.procs").write_text("", encoding="ascii")
        end_evidence = RuntimeEndEvidence.observe(lease, now=now - 8 * 86400 + 2)
        lifecycle.end_use(lease, end_evidence, now=now - 8 * 86400 + 3)
    return producer


def _small_linked_worktree_fixture(
    project: Path, source_parent: Path, state_root: Path
) -> tuple[Path, WorktreeBinding, WorktreeLifecycleStore, ProjectPolicy]:
    origin = project / "origin"
    origin.mkdir()
    _git(origin, "init", "-q")
    _git(origin, "config", "user.email", "test@example.invalid")
    _git(origin, "config", "user.name", "Fixture")
    (origin / "tracked.txt").write_text("original\n")
    _git(origin, "add", ".")
    _git(origin, "commit", "-qm", "base")
    source = source_parent / "worktree"
    _git(origin, "worktree", "add", "-qb", "fixture", str(source))
    attestation = HeadlessWriteScopeStore(state_root / "origin-evidence").create(
        "fixture", source.resolve(), source.resolve(), base_ref=None
    )
    binding = WorktreeBinding.from_creation_attestation(attestation)
    lifecycle = WorktreeLifecycleStore(HiveStateStore(state_root / "lifecycle"))
    lifecycle._record_created_worktree(binding, attestation)
    _finish_fixture_use(lifecycle, binding, now=int(time.time()) - 31 * 86400)
    policy = ProjectPolicy(source, (source_parent, project), project / ".hive-archive")
    return source, binding, lifecycle, policy


def _temporary_archive_fixture(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    source_parent = tmp_path / "sources"
    source_parent.mkdir()
    source, binding, lifecycle, policy = _small_linked_worktree_fixture(
        project, source_parent, tmp_path / "state"
    )
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    producer = _create_ended_temp_producer(
        lifecycle, binding, temp_root, now=int(time.time())
    )
    (producer / "payload.txt").write_text("attested producer output\n", encoding="utf-8")
    candidate = next(
        item
        for item in scan_candidates((policy,), lifecycle, now=int(time.time()))
        if item.temporary and item.source == producer
    )
    return producer, candidate, policy, lifecycle


def _canonical_temp_owner_fixture(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    checkout = Path(server_module.__file__).resolve().parents[2]
    shutil.copy2(checkout / "codex-hive.json", root / "codex-hive.json")
    shutil.copy2(checkout / "codex-agent-classes.json", root / "codex-agent-classes.json")
    _git(root, "init", "-qb", "main")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Fixture")
    _git(root, "remote", "add", "origin", "https://github.com/H234598/codex-master.git")
    (root / "tracked.txt").write_text("base\n")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "base")
    worktree_root = root / ".codex-master-worktrees"
    worktree_root.mkdir()
    worktree = worktree_root / "worker"
    _git(root, "worktree", "add", "-qb", "fixture", str(worktree))
    attestation = HeadlessWriteScopeStore(tmp_path / "origin-evidence").create(
        "fixture", root, worktree, base_ref=None
    )
    lifecycle = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state" / "hive"))
    binding = WorktreeBinding.from_creation_attestation(attestation)
    lifecycle._record_created_worktree(binding, attestation)
    return root, worktree, worktree_root, lifecycle, binding


def _control_reference_inventory(
    monkeypatch: pytest.MonkeyPatch, *, mapped_path: Path | None = None
) -> None:
    original_listdir = os.listdir
    original_scandir = os.scandir

    def fixture_listdir(path: str | os.PathLike[str] | int) -> list[str]:
        if path == "/proc":
            return [str(os.getpid())]
        return original_listdir(path)

    class Entries:
        def __init__(self, paths: list[str]) -> None:
            self.paths = paths

        def __iter__(self):
            return iter(SimpleNamespace(path=path) for path in self.paths)

        def close(self) -> None:
            return None

    def fixture_scandir(path: str | os.PathLike[str] | int):
        value = os.fspath(path) if not isinstance(path, int) else ""
        if value.endswith("/map_files"):
            paths = [str(mapped_path)] if mapped_path is not None else []
            return Entries(paths)
        return original_scandir(path)

    monkeypatch.setattr(os, "listdir", fixture_listdir)
    monkeypatch.setattr(os, "scandir", fixture_scandir)


@pytest.mark.parametrize("swap_kind", ["rename", "rewrite"])
def test_temp_restore_uses_the_tar_file_that_was_validated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_kind: str
) -> None:
    producer, candidate, policy, lifecycle = _temporary_archive_fixture(tmp_path)
    receipt = maintenance_module.archive_temporary_candidate(
        candidate, policy=policy, lifecycle=lifecycle
    )
    expected = _file_snapshot(producer)
    tar_path = receipt.archive / "temporary.tar"
    saved_tar = receipt.archive / "temporary.saved"
    evil_tar = tmp_path / "replacement.tar"
    with tarfile.open(evil_tar, "w") as archive:
        data = b"replacement from swapped path"
        member = tarfile.TarInfo("evil.txt")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    original_extract = maintenance_module._run_tar_extract

    def swap_tar_then_extract(archive_path, destination_fd, *, lock_fd=None, archive_fd=None):
        if swap_kind == "rename":
            tar_path.rename(saved_tar)
            shutil.copyfile(evil_tar, tar_path)
        else:
            with tar_path.open("r+b") as stream:
                stream.seek(0)
                stream.write(evil_tar.read_bytes())
                stream.truncate()
        kwargs = {} if archive_fd is None else {"archive_fd": archive_fd}
        return original_extract(
            archive_path, destination_fd, lock_fd=lock_fd, **kwargs
        )

    monkeypatch.setattr(maintenance_module, "_run_tar_extract", swap_tar_then_extract)
    restored = restore_archive(receipt, tmp_path / "restored")

    assert _file_snapshot(restored) == expected
    assert not (restored / "evil.txt").exists()


def test_temp_archive_rechecks_source_after_independent_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    producer, candidate, policy, lifecycle = _temporary_archive_fixture(tmp_path)
    original_restore = maintenance_module._restore_archive_unlocked

    def restore_then_change_source(*args, **kwargs):
        result = original_restore(*args, **kwargs)
        (producer / "payload.txt").write_text("changed after verification\n", encoding="utf-8")
        return result

    monkeypatch.setattr(
        maintenance_module, "_restore_archive_unlocked", restore_then_change_source
    )

    with pytest.raises(MaintenanceError, match="temporary_source_changed_before_publish"):
        maintenance_module.archive_temporary_candidate(
            candidate, policy=policy, lifecycle=lifecycle
        )


def test_server_archive_owner_composes_from_repository_id_and_source_path() -> None:
    assert callable(server_module._archive_worktree_by_id)
    with pytest.raises(Exception, match="repository_unknown"):
        server_module._archive_worktree_by_id("missing", Path("/tmp/worktree"))


def test_worktree_maintenance_without_subcommand_defaults_to_read_only_plan(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    preview = {"operation": "plan", "preview_digest": "sha256:fixture"}
    monkeypatch.setattr(
        server_module, "_worktree_maintenance_plan", lambda: preview, raising=False
    )

    exit_code = server_module.main_cli(["worktree-maintenance"])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == preview


def test_maintenance_service_uses_no_filesystem_namespace_bind_mounts() -> None:
    unit = Path(__file__).parents[1] / "systemd/user/the-hive-worktree-maintenance.service"
    text = unit.read_text(encoding="utf-8")

    assert "ProtectSystem=strict" not in text
    assert "ReadWritePaths=" not in text
    assert "PrivateTmp=yes" not in text
    assert "PrivateDevices=yes" not in text
    assert "ProtectClock=yes" not in text
    assert "ProtectControlGroups=yes" not in text
    assert "ProtectHostname=yes" not in text
    assert "ProtectKernelLogs=yes" not in text
    assert "ProtectKernelModules=yes" not in text
    assert "ProtectKernelTunables=yes" not in text
    assert "NoNewPrivileges=yes" in text
    assert "UMask=0077" in text
    assert "CapabilityBoundingSet=" not in text


def test_worktree_maintenance_contract_ignores_candidate_age_and_membership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = {
        "repository_id": "codex-master",
        "repository_config_digest": "sha256:project-config",
        "repository_root": "/project",
        "repository_device": 1,
        "repository_inode": 2,
        "worktree_root": "/project/worktrees",
        "worktree_root_identity": {"device": 1, "inode": 3},
        "archive_root": "/project/.hive-archive",
        "archive_identity": {"device": 1, "inode": 4},
        "thresholds": {
            "inactive_seconds": 30 * 86400,
            "large_inactive_seconds": 7 * 86400,
            "large_bytes": 10 * 1024**3,
            "temporary_age_seconds": 7 * 86400,
        },
    }
    monkeypatch.setattr(server_module, "_maintenance_code_digest", lambda: "sha256:code")
    coverage = {"complete": False, "protocol": "fixture"}

    first = server_module._worktree_maintenance_contract_digest([project], coverage)
    second = server_module._worktree_maintenance_contract_digest([project], coverage)

    assert first == second


def test_worktree_maintenance_contract_changes_with_code_or_target_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = {
        "repository_id": "codex-master",
        "repository_config_digest": "sha256:project-config",
        "repository_root": "/project",
        "repository_device": 1,
        "repository_inode": 2,
        "worktree_root": "/project/worktrees",
        "worktree_root_identity": {"device": 1, "inode": 3},
        "archive_root": "/project/.hive-archive",
        "archive_identity": {"device": 1, "inode": 4},
        "thresholds": {"inactive_seconds": 30 * 86400},
    }
    monkeypatch.setattr(server_module, "_maintenance_code_digest", lambda: "sha256:code-a")
    first = server_module._worktree_maintenance_contract_digest(
        [project], {"complete": False}
    )
    monkeypatch.setattr(server_module, "_maintenance_code_digest", lambda: "sha256:code-b")
    changed_code = server_module._worktree_maintenance_contract_digest(
        [project], {"complete": False}
    )
    changed_target = dict(project, archive_root="/project/.hive-archive-v2")
    same_code = server_module._worktree_maintenance_contract_digest(
        [changed_target], {"complete": False}
    )
    changed_physical_observation = dict(
        project,
        repository_device=17,
        repository_inode=18,
        mount_namespace_inode=19,
        repository_mount_id=20,
        archive_identity={"device": 21, "inode": 22},
        archive_mount_id=23,
    )
    monkeypatch.setattr(server_module, "_maintenance_code_digest", lambda: "sha256:code-a")
    stable_physical_contract = server_module._worktree_maintenance_contract_digest(
        [changed_physical_observation], {"complete": False}
    )

    assert changed_code != first
    assert same_code != first
    assert stable_physical_contract == first


def test_worktree_lifecycle_read_only_fallback_does_not_create_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root = tmp_path / "missing-state"
    monkeypatch.setattr(server_module, "STATE_ROOT", state_root)

    with pytest.raises(Exception, match="state_not_found"):
        server_module._worktree_lifecycle_store(read_only=True)

    assert not state_root.exists()


def test_worktree_maintenance_run_without_approval_never_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preview = {
        "contract_digest": "sha256:" + "a" * 64,
        "preview_digest": "sha256:" + "b" * 64,
        "caller_coverage": {"complete": True},
        "candidates": [{"eligible": True, "repository_id": "codex-master", "source": "/fixture/worktree"}],
    }
    applied = []
    monkeypatch.setattr(server_module, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server_module, "_worktree_maintenance_plan", lambda: preview)
    monkeypatch.setattr(server_module, "_read_worktree_maintenance_approval", lambda: None)
    monkeypatch.setattr(server_module, "_apply_worktree_by_id", lambda *args: applied.append(args))

    result = server_module._run_worktree_maintenance()

    assert result["reason"] == "maintenance_approval_required"
    assert applied == []


def test_worktree_maintenance_run_with_incomplete_caller_coverage_never_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = "sha256:" + "a" * 64
    preview = {
        "contract_digest": contract,
        "preview_digest": "sha256:" + "b" * 64,
        "caller_coverage": {"complete": False, "reason": "unattested"},
        "candidates": [{"eligible": True, "repository_id": "codex-master", "source": "/fixture/worktree"}],
    }
    applied = []
    monkeypatch.setattr(server_module, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server_module, "_worktree_maintenance_plan", lambda: preview)
    monkeypatch.setattr(
        server_module,
        "_read_worktree_maintenance_approval",
        lambda: {"contract_digest": contract, "preview_digest": preview["preview_digest"]},
    )
    monkeypatch.setattr(server_module, "_apply_worktree_by_id", lambda *args: applied.append(args))

    result = server_module._run_worktree_maintenance()

    assert result["reason"] == "caller_coverage_unavailable"
    assert applied == []


def test_overlapping_maintenance_cli_run_never_claims_or_changes_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(server_module, "STATE_ROOT", tmp_path / "state")
    lifecycle = WorktreeLifecycleStore(HiveStateStore(tmp_path / "lifecycle"))
    before = lifecycle.snapshot()
    claims = []
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda **_kwargs: lifecycle)
    monkeypatch.setattr(server_module, "_claim_worktree_maintenance", lambda *args, **kwargs: claims.append(args))

    with server_module._worktree_maintenance_run_guard():
        exit_code = server_module.main_cli(["worktree-maintenance", "run"])

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["reason"] == "maintenance_run_overlapping"
    assert claims == []
    assert lifecycle.snapshot() == before


def test_project_share_failure_during_cli_run_leaves_lifecycle_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(server_module, "STATE_ROOT", tmp_path / "state")
    lifecycle = WorktreeLifecycleStore(HiveStateStore(tmp_path / "lifecycle"))
    before = lifecycle.snapshot()
    claims = []
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda **_kwargs: lifecycle)
    monkeypatch.setattr(
        server_module,
        "_worktree_maintenance_plan",
        lambda: (_ for _ in ()).throw(server_module.AgentError("maintenance_project_scan_unavailable")),
    )
    monkeypatch.setattr(server_module, "_claim_worktree_maintenance", lambda *args, **kwargs: claims.append(args))

    exit_code = server_module.main_cli(["worktree-maintenance", "run"])

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["reason"] == "maintenance_project_scan_unavailable"
    assert claims == []
    assert lifecycle.snapshot() == before


@pytest.mark.parametrize("mountpoint_exists", [False, True])
def test_missing_project_share_during_cli_run_is_bounded_before_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mountpoint_exists: bool,
) -> None:
    monkeypatch.setattr(server_module, "STATE_ROOT", tmp_path / "state")
    project_root = tmp_path / "removed-project"
    if mountpoint_exists:
        project_root.mkdir()
    monkeypatch.setattr(server_module, "repo_root", lambda: project_root)
    lifecycle = WorktreeLifecycleStore(HiveStateStore(tmp_path / "lifecycle"))
    before = lifecycle.snapshot()
    claims = []
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda **_kwargs: lifecycle)
    monkeypatch.setattr(server_module, "_claim_worktree_maintenance", lambda *args, **kwargs: claims.append(args))

    exit_code = server_module.main_cli(["worktree-maintenance", "run"])

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["reason"] == (
        "maintenance_repository_configuration_unavailable"
        if mountpoint_exists
        else "maintenance_repository_root_unavailable"
    )
    assert claims == []
    assert lifecycle.snapshot() == before


def test_worktree_maintenance_rejects_archive_root_inode_swap_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _worktree, _worktree_root, lifecycle, _binding = _canonical_temp_owner_fixture(tmp_path)
    state_root = tmp_path / "state"
    archive_root = root / ".hive-archive"
    archive_root.mkdir(mode=0o700)
    monkeypatch.setattr(server_module, "repo_root", lambda: root)
    monkeypatch.setattr(server_module, "STATE_ROOT", state_root)
    monkeypatch.setattr(
        server_module,
        "_worktree_lifecycle_store",
        lambda **_kwargs: lifecycle,
    )

    preview = server_module._worktree_maintenance_plan()
    project = next(item for item in preview["projects"] if item["repository_id"] == "codex-master")
    original_identity = project["archive_identity"]
    assert original_identity == {
        "device": archive_root.stat(follow_symlinks=False).st_dev,
        "inode": archive_root.stat(follow_symlinks=False).st_ino,
    }
    approval = server_module._approve_worktree_maintenance(preview["preview_digest"])
    assert approval["approval"]["contract_digest"] == preview["contract_digest"]
    before = lifecycle.snapshot()

    displaced_root = root / ".hive-archive.displaced"
    archive_root.rename(displaced_root)
    archive_root.mkdir(mode=0o700)
    replacement_info = archive_root.stat(follow_symlinks=False)
    assert (replacement_info.st_dev, replacement_info.st_ino) != (
        original_identity["device"], original_identity["inode"]
    )

    changed_preview = server_module._worktree_maintenance_plan()
    result = server_module._run_worktree_maintenance()

    assert changed_preview["contract_digest"] == preview["contract_digest"]
    assert result["reason"] == "caller_coverage_unavailable"
    assert lifecycle.snapshot() == before
    assert displaced_root.stat(follow_symlinks=False).st_ino == original_identity["inode"]
    assert list(displaced_root.iterdir()) == []
    assert list(archive_root.iterdir()) == []


@pytest.mark.parametrize("scenario", ["new_namespace"])
def test_maintenance_approval_is_stable_but_share_swap_fails_before_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
) -> None:
    if shutil.which("unshare") is None or shutil.which("mount") is None:
        pytest.skip("user/mount namespace tools are unavailable")
    root, _worktree, _worktree_root, lifecycle, binding = _canonical_temp_owner_fixture(tmp_path)
    state_root = tmp_path / "state"
    archive_root = root / ".hive-archive"
    archive_root.mkdir(mode=0o700)
    monkeypatch.setattr(server_module, "repo_root", lambda: root)
    monkeypatch.setattr(server_module, "STATE_ROOT", state_root)
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda **_kwargs: lifecycle)
    monkeypatch.setattr(
        server_module,
        "_maintenance_caller_coverage",
        lambda: {"complete": True, "protocol": "fixture-only"},
    )
    monkeypatch.setattr(maintenance_module, "_assert_no_open_tree_references", lambda _roots: None)
    preview = server_module._worktree_maintenance_plan()
    assert preview["caller_coverage"]["complete"] is True
    approval = server_module._approve_worktree_maintenance(preview["preview_digest"])
    before = lifecycle.snapshot()
    parent_namespace = os.stat("/proc/self/ns/mnt").st_ino

    probe = r"""
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from the_hive import server, maintenance
from the_hive.hive.state import HiveStateStore
from the_hive.worktree_lifecycle import WorktreeLifecycleStore

root = Path(sys.argv[1])
state_root = Path(sys.argv[2])
scenario = sys.argv[3]
source = Path(sys.argv[4])
archive_root = root / ".hive-archive"
server.repo_root = lambda: root
server.STATE_ROOT = state_root
server._worktree_lifecycle_store = lambda **_kwargs: WorktreeLifecycleStore(
    HiveStateStore(state_root / "hive")
)
server._maintenance_caller_coverage = lambda: {"complete": True, "protocol": "fixture-only"}
maintenance._assert_no_open_tree_references = lambda _roots: None
original_plan = server._worktree_maintenance_plan
mount_ids = {}
preview_rows = []
capture = io.StringIO()
previous_stdout = sys.stdout
sys.stdout = capture
try:
    exit_code = server.main_cli(["worktree-maintenance", "run"])
finally:
    sys.stdout = previous_stdout
result = json.loads(capture.getvalue())
store = WorktreeLifecycleStore(HiveStateStore(state_root / "hive"))
print(json.dumps({
    "exit_code": exit_code,
    "result": result,
    "claim_count": len(store.snapshot().maintenance_claims),
    "mount_ids": mount_ids,
    "preview_rows": preview_rows,
    "namespace_inode": os.stat("/proc/self/ns/mnt").st_ino,
    "contract_digest": original_plan()["contract_digest"],
}, sort_keys=True))
"""
    completed = subprocess.run(
        [
            "unshare", "--user", "--map-root-user", "--mount",
            sys.executable, "-c", probe,
            str(root), str(state_root), scenario, str(binding.canonical_source_path),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode and any(
        marker in completed.stderr.lower()
        for marker in ("operation not permitted", "permission denied", "unshare failed")
    ):
        pytest.skip("user/mount namespace is unavailable")
    assert completed.returncode == 0, completed.stderr
    outcome = json.loads(completed.stdout)

    assert outcome["namespace_inode"] != parent_namespace
    assert outcome["contract_digest"] == approval["approval"]["contract_digest"]
    assert outcome["claim_count"] == 0
    assert lifecycle.snapshot() == before
    assert outcome["exit_code"] == 0
    assert outcome["result"]["reason"] == "no_eligible_candidates"
    assert outcome["mount_ids"] == {}


def test_archive_share_swap_in_same_namespace_fails_before_claim(tmp_path: Path) -> None:
    if shutil.which("unshare") is None or shutil.which("mount") is None:
        pytest.skip("user/mount namespace tools are unavailable")
    root, source, _worktree_root, _lifecycle, _binding = _canonical_temp_owner_fixture(tmp_path)
    archive_root = root / ".hive-archive"
    archive_root.mkdir(mode=0o700)
    state_root = tmp_path / "same-namespace-state"
    probe = r"""
import io
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch
from the_hive import server, maintenance, runtime_process
from the_hive.headless_write_scope import HeadlessWriteScopeStore
from the_hive.hive.state import HiveStateStore
from the_hive.resource_cgroup import PreparedAgentScope
from the_hive.worktree_lifecycle import (
    G5ScopeBindingEvidence, RuntimeEndEvidence, WorktreeBinding,
    WorktreeLifecycleStore,
)

root, source, state_root = map(Path, sys.argv[1:4])
archive_root = root / ".hive-archive"
server.repo_root = lambda: root
server.STATE_ROOT = state_root
server._maintenance_caller_coverage = lambda: {"complete": True, "protocol": "fixture-only"}
server._read_native_agent_registry_read_only = lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready")
server.retained_pin_session_ids = lambda _now: set()
maintenance._assert_no_open_tree_references = lambda _roots: None
lifecycle = WorktreeLifecycleStore(HiveStateStore(state_root / "hive"))
server._worktree_lifecycle_store = lambda **_kwargs: lifecycle
attestation = HeadlessWriteScopeStore(state_root / "origin").create(
    "fixture", root, source, base_ref=None
)
binding = WorktreeBinding.from_creation_attestation(attestation)
lifecycle._record_created_worktree(binding, attestation)
now = int(time.time()) - 31 * 86400
lease = lifecycle.begin_use(
    binding, principal_id="principal.fixture", session_id="session.fixture",
    assignment_id="assignment.fixture", now=now,
)
unit = f"the-hive-resource-{secrets.token_hex(16)}.scope"
group = f"/the-hive.slice/{unit}"
cgroup_root = source.parent / "fixture-cgroups"
cgroup_runtime = state_root / "runtime"
cgroup_runtime.mkdir(parents=True, mode=0o700)
cgroup = cgroup_root / "the-hive.slice" / unit
cgroup.mkdir(parents=True)
(cgroup / "cgroup.events").write_text("populated 1\nfrozen 0\n", encoding="ascii")
(cgroup / "cgroup.procs").write_text("777\n", encoding="ascii")
invocation = secrets.token_hex(16)
def fake_systemctl(_args, *, environment, deadline):
    del environment, deadline
    return f"ControlGroup={group}\nInvocationID={invocation}\nLoadState=loaded\n".encode()
scope = PreparedAgentScope(
    unit_name=unit, socket_name=f"g5-{secrets.token_hex(8)}",
    session_name=f"worktree-{secrets.token_hex(5)}", control_group=group,
    gate_pid=os.getpid(), challenge=secrets.token_hex(32),
)
with patch.object(runtime_process, "_CGROUP_ROOT", cgroup_root), patch.object(runtime_process, "_systemctl", fake_systemctl), patch.object(runtime_process, "_runtime_directory", lambda **_kwargs: cgroup_runtime):
    evidence = G5ScopeBindingEvidence.capture(lease, scope, now=now + 1)
    lease = lifecycle.bind_g5_runtime(lease, evidence, now=now + 1)
    (cgroup / "cgroup.events").write_text("populated 0\nfrozen 0\n", encoding="ascii")
    (cgroup / "cgroup.procs").write_text("", encoding="ascii")
    lifecycle.end_use(lease, RuntimeEndEvidence.observe(lease, now=now + 2), now=now + 3)

preview = server._worktree_maintenance_plan()
assert any(item.get("source") == str(source) and item.get("eligible") for item in preview["candidates"]), preview["candidates"]
server._approve_worktree_maintenance(preview["preview_digest"])
before = lifecycle.snapshot()
original_plan = server._worktree_maintenance_plan
mount_ids = {}
def plan_then_swap():
    result = original_plan()
    if not mount_ids:
        fd, _info, before_mount = maintenance._open_tree(archive_root)
        os.close(fd)
        subprocess.run(["mount", "--bind", str(archive_root), str(archive_root)], check=True)
        fd, _info, after_mount = maintenance._open_tree(archive_root)
        os.close(fd)
        mount_ids.update(before=before_mount, after=after_mount)
    return result
server._worktree_maintenance_plan = plan_then_swap
capture = io.StringIO()
old_stdout = sys.stdout
sys.stdout = capture
try:
    exit_code = server.main_cli(["worktree-maintenance", "apply", "--repository-id", "codex-master", "--source", str(source)])
finally:
    sys.stdout = old_stdout
result = json.loads(capture.getvalue())
print(json.dumps({
    "exit_code": exit_code, "result": result,
    "claim_count": len(lifecycle.snapshot().maintenance_claims),
    "unchanged_state": lifecycle.snapshot() == before,
    "mount_ids": mount_ids,
    "namespace_inode": os.stat("/proc/self/ns/mnt").st_ino,
}, sort_keys=True))
"""
    completed = subprocess.run(
        [
            "unshare", "--user", "--map-root-user", "--mount",
            sys.executable, "-c", probe,
            str(root), str(source), str(state_root),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode and any(
        marker in completed.stderr.lower()
        for marker in ("operation not permitted", "permission denied", "unshare failed")
    ):
        pytest.skip("user/mount namespace is unavailable")
    assert completed.returncode == 0, completed.stderr
    outcome = json.loads(completed.stdout)
    assert outcome["exit_code"] == 1
    assert outcome["result"]["error"] == "maintenance_archive_filesystem_mismatch"
    assert outcome["claim_count"] == 0
    assert outcome["unchanged_state"] is True
    assert outcome["mount_ids"]["before"] != outcome["mount_ids"]["after"]


def test_worktree_maintenance_approval_gate_requires_same_contract_and_coverage() -> None:
    contract = "sha256:" + "a" * 64
    preview = {"contract_digest": contract, "caller_coverage": {"complete": True}}
    approval = {"contract_digest": contract}

    assert server_module._worktree_maintenance_approval_allows(preview, approval)
    assert not server_module._worktree_maintenance_approval_allows(preview, None)
    assert not server_module._worktree_maintenance_approval_allows(
        preview, {"contract_digest": "sha256:" + "b" * 64}
    )
    assert not server_module._worktree_maintenance_approval_allows(
        {**preview, "caller_coverage": {"complete": False}}, approval
    )


def test_approved_cli_apply_reaches_existing_owner_on_controlled_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    checkout = Path(server_module.__file__).resolve().parents[2]
    shutil.copy2(checkout / "codex-hive.json", root / "codex-hive.json")
    shutil.copy2(checkout / "codex-agent-classes.json", root / "codex-agent-classes.json")
    _git(root, "init", "-qb", "main")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Fixture")
    _git(root, "remote", "add", "origin", "https://github.com/H234598/codex-master.git")
    (root / "tracked.txt").write_text("base\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "base")
    source_root = root / ".codex-master-worktrees"
    source_root.mkdir()
    source = source_root / "worker"
    _git(root, "worktree", "add", "-qb", "fixture", str(source))

    monkeypatch.setattr(server_module, "repo_root", lambda: root)
    monkeypatch.setattr(server_module, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(
        server_module,
        "_maintenance_caller_coverage",
        lambda: {"complete": True, "protocol": "fixture-only"},
    )
    monkeypatch.setattr(
        maintenance_module, "_assert_no_open_tree_references", lambda roots: None
    )
    attestation = HeadlessWriteScopeStore(tmp_path / "origin-evidence").create(
        "fixture", root, source, base_ref=None
    )
    lifecycle = server_module._worktree_lifecycle_store()
    binding = WorktreeBinding.from_creation_attestation(attestation)
    lifecycle._record_created_worktree(binding, attestation)
    _finish_fixture_use(lifecycle, binding, now=int(time.time()) - 31 * 86400)
    monkeypatch.setattr(
        server_module, "_worktree_lifecycle_store", lambda **_kwargs: lifecycle
    )
    monkeypatch.setattr(
        server_module,
        "_read_native_agent_registry_read_only",
        lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready"),
    )
    monkeypatch.setattr(server_module, "retained_pin_session_ids", lambda _now: set())

    preview = server_module._worktree_maintenance_plan()
    assert any(
        candidate.get("source") == str(source) and candidate.get("eligible") is True
        for candidate in preview["candidates"]
    ), [(item["source"], item["reasons"], item["host_gate"]) for item in preview["candidates"]]
    monkeypatch.setattr(
        server_module,
        "_read_worktree_maintenance_approval",
        lambda: {"contract_digest": preview["contract_digest"]},
    )
    exit_code = server_module.main_cli(
        [
            "worktree-maintenance",
            "apply",
            "--repository-id",
            "codex-master",
            "--source",
            str(source),
        ]
    )

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert Path(result["archive"]).is_dir()
    assert not source.exists()


def test_worktree_maintenance_restore_dispatch_never_falls_through_to_apply(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    applied = []
    monkeypatch.setattr(
        server_module,
        "_apply_worktree_by_id",
        lambda *args: applied.append(args),
    )
    monkeypatch.setattr(
        server_module,
        "_restore_worktree_archive_by_id",
        lambda *args: Path("/fixture/restored"),
    )

    exit_code = server_module.main_cli(
        [
            "worktree-maintenance",
            "restore",
            "--repository-id",
            "codex-master",
            "--archive-id",
            "archive-fixture",
            "--destination-name",
            "restored-fixture",
        ]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == {
        "operation": "restore",
        "restored": "/fixture/restored",
    }
    assert applied == []


def test_worktree_maintenance_recover_dispatch_never_falls_through_to_apply(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    applied = []
    monkeypatch.setattr(
        server_module,
        "_apply_worktree_by_id",
        lambda *args: applied.append(args),
    )
    monkeypatch.setattr(
        server_module,
        "_recover_worktree_maintenance_by_id",
        lambda *args: {
            "operation": "recover",
            "recovered": True,
            "phase": "recovery_hold",
            "claim_id": "fixture-claim",
            "source": "/fixture/worktree",
        },
    )

    exit_code = server_module.main_cli(
        [
            "worktree-maintenance",
            "recover",
            "--repository-id",
            "codex-master",
            "--source",
            "/fixture/worktree",
        ]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == {
        "operation": "recover",
        "recovered": True,
        "phase": "recovery_hold",
        "claim_id": "fixture-claim",
        "source": "/fixture/worktree",
    }
    assert applied == []


def test_g5_temporary_producer_requires_verified_end_and_expires_after_seven_days(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    now = int(time.time())
    project = tmp_path / "project"
    project.mkdir()
    source_parent = tmp_path / "sources"
    source_parent.mkdir()
    source, binding, lifecycle, policy = _small_linked_worktree_fixture(
        project, source_parent, tmp_path / "state"
    )
    monkeypatch.setattr(tempfile, "gettempdir", lambda: "/tmp")
    lease = lifecycle.begin_use(
        binding,
        principal_id="principal.temp-fixture",
        session_id="session.temp-fixture",
        assignment_id="assignment.temp-fixture",
        now=now - 8 * 86400,
    )
    producer_path = lifecycle.create_temporary_producer(lease, now=now - 8 * 86400)
    assert lifecycle.binding_for_temporary_source(producer_path) == binding
    producer_identity = (producer_path.stat().st_dev, producer_path.stat().st_ino)
    request.addfinalizer(
        lambda: shutil.rmtree(producer_path)
        if producer_path.exists()
        and (producer_path.stat().st_dev, producer_path.stat().st_ino) == producer_identity
        else None
    )
    assert producer_path.parent == Path(tempfile.gettempdir()).resolve()
    assert producer_path.stat().st_mode & 0o777 == 0o700
    assert producer_path.stat().st_dev != project.stat().st_dev
    assert lifecycle.temporary_producers(binding) == ()

    unit = f"the-hive-resource-{secrets.token_hex(16)}.scope"
    group = f"/the-hive.slice/{unit}"
    cgroup_root = tmp_path / "cgroups"
    cgroup = cgroup_root / "the-hive.slice" / unit
    cgroup.mkdir(parents=True)
    (cgroup / "cgroup.events").write_text("populated 1\nfrozen 0\n", encoding="ascii")
    (cgroup / "cgroup.procs").write_text("777\n", encoding="ascii")
    invocation = secrets.token_hex(16)

    def fake_systemctl(_args, *, environment, deadline):
        del environment, deadline
        return f"ControlGroup={group}\nInvocationID={invocation}\nLoadState=loaded\n".encode()

    scope = PreparedAgentScope(
        unit_name=unit,
        socket_name=f"g5-{secrets.token_hex(8)}",
        session_name=f"worktree-{secrets.token_hex(5)}",
        control_group=group,
        gate_pid=os.getpid(),
        challenge=secrets.token_hex(32),
    )
    with (
        patch.object(runtime_process, "_CGROUP_ROOT", cgroup_root),
        patch.object(runtime_process, "_systemctl", fake_systemctl),
    ):
        evidence = G5ScopeBindingEvidence.capture(lease, scope, now=now - 8 * 86400 + 1)
        lease = lifecycle.bind_g5_runtime(lease, evidence, now=now - 8 * 86400 + 1)
        (cgroup / "cgroup.events").write_text("populated 0\nfrozen 0\n", encoding="ascii")
        (cgroup / "cgroup.procs").write_text("", encoding="ascii")
        end_evidence = RuntimeEndEvidence.observe(lease, now=now - 8 * 86400 + 2)
        lifecycle.end_use(lease, end_evidence, now=now - 8 * 86400 + 3)

    candidates = scan_candidates((policy,), lifecycle, now=now)
    temp_candidates = [candidate for candidate in candidates if candidate.source == producer_path]
    assert len(temp_candidates) == 1
    assert temp_candidates[0].eligible is True
    assert "temporary_producer_7_days" in temp_candidates[0].reasons
    assert temp_candidates[0].temporary is True
    (producer_path / "nested").mkdir()
    (producer_path / "payload.bin").write_bytes(b"g5 temporary data\x00\xff")
    (producer_path / "nested" / "state.txt").write_text("verified end\n", encoding="utf-8")
    os.setxattr(producer_path, "user.temp-root-fixture", b"root-metadata")
    temp_candidate = next(
        candidate
        for candidate in scan_candidates((policy,), lifecycle, now=now)
        if candidate.source == producer_path
    )
    (producer_path / "payload.bin").write_bytes(b"changed after preview")
    with pytest.raises(MaintenanceError, match="temporary_candidate_stale_or_active"):
        maintenance_module.archive_temporary_candidate(
            temp_candidate, policy=policy, lifecycle=lifecycle
        )
    temp_candidate = next(
        candidate
        for candidate in scan_candidates((policy,), lifecycle, now=now)
        if candidate.source == producer_path
    )
    backup_source = producer_path.with_name(f"{producer_path.name}.saved")
    original_tar_create = maintenance_module._run_tar_create

    def tar_then_swap_source(root_fd, output, *, exclude_git, lock_fd=None):
        original_tar_create(root_fd, output, exclude_git=exclude_git, lock_fd=lock_fd)
        producer_path.rename(backup_source)
        shutil.copytree(backup_source, producer_path, copy_function=shutil.copy2)
        shutil.copystat(backup_source, producer_path)

    try:
        with monkeypatch.context() as swap_patch:
            swap_patch.setattr(maintenance_module, "_run_tar_create", tar_then_swap_source)
            with pytest.raises(MaintenanceError, match="temporary_source_identity_changed"):
                maintenance_module.archive_temporary_candidate(
                    temp_candidate, policy=policy, lifecycle=lifecycle
                )
    finally:
        if producer_path.exists():
            shutil.rmtree(producer_path)
        if backup_source.exists():
            backup_source.rename(producer_path)
    temp_candidate = next(
        candidate
        for candidate in scan_candidates((policy,), lifecycle, now=now)
        if candidate.source == producer_path
    )
    before = _file_snapshot(producer_path)
    receipt = maintenance_module.archive_temporary_candidate(
        temp_candidate, policy=policy, lifecycle=lifecycle
    )
    restored = restore_archive(receipt, tmp_path / "restored-temp")
    assert restored == tmp_path / "restored-temp"
    assert _file_snapshot(restored) == before
    assert os.getxattr(restored, "user.temp-root-fixture") == b"root-metadata"
    assert receipt.archive.parent == policy.archive_root
    assert not any(
        candidate.source == producer_path
        for candidate in scan_candidates((policy,), lifecycle, now=now - 2 * 86400)
    )

    active = lifecycle.begin_use(
        binding,
        principal_id="principal.active-fixture",
        session_id="session.active-fixture",
        assignment_id="assignment.active-fixture",
        now=now,
    )
    assert active.lease_id != lease.lease_id
    assert lifecycle.temporary_producers(binding) == ()
    with pytest.raises(MaintenanceError, match="temporary_candidate_stale_or_active"):
        maintenance_module.archive_temporary_candidate(
            temp_candidate, policy=policy, lifecycle=lifecycle
        )
    assert not any(candidate.source == producer_path for candidate in scan_candidates((policy,), lifecycle, now=now))


def test_temp_apply_claims_archives_restores_and_removes_only_bound_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    producer, candidate, policy, lifecycle = _temporary_archive_fixture(tmp_path)
    before = _file_snapshot(producer)
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda: lifecycle)
    monkeypatch.setattr(
        server_module,
        "_read_native_agent_registry_read_only",
        lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready"),
    )
    monkeypatch.setattr(server_module, "retained_pin_session_ids", lambda _now: set())
    _control_reference_inventory(monkeypatch)
    claim = server_module._claim_worktree_maintenance(candidate.binding, now=int(time.time()))

    receipt = apply_candidate(
        candidate,
        lifecycle,
        policy=policy,
        claim=claim,
        now=int(time.time()),
    )

    assert not producer.exists()
    assert receipt.archive.exists()
    restored = restore_archive(receipt, tmp_path / "temp-apply-restored")
    assert _file_snapshot(restored) == before
    assert lifecycle.temporary_producers(candidate.binding) == ()
    with pytest.raises(WorktreeLifecycleError, match="maintenance_claim_inactive"):
        lifecycle.assert_claim(claim)


def test_archive_lock_fd_is_included_in_writer_child_inheritance(tmp_path: Path) -> None:
    archive_root = tmp_path / "archive"
    archive_root.mkdir(mode=0o700)
    lock_fd = os.open(archive_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        inherited = maintenance_module._maintenance_pass_fds(lock_fd, ())
        assert lock_fd in inherited
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


@pytest.mark.parametrize("fail_parent_call", [False, True])
def test_restore_lock_remains_held_by_child_after_parent_finally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_parent_call: bool,
) -> None:
    archive_root = tmp_path / "archive"
    archive_root.mkdir(mode=0o700)
    release_marker = tmp_path / "release-child"
    child_processes: list[subprocess.Popen[bytes]] = []

    def spawn_child_then_return_or_fail(
        _receipt: ArchiveReceipt, destination: Path, *, lock_fd: int
    ) -> Path:
        child_code = (
            "import os,sys,time; marker=sys.argv[1]; "
            "exec('while not os.path.exists(marker):\\n time.sleep(0.01)')"
        )
        child = subprocess.Popen(
            [sys.executable, "-c", child_code, str(release_marker)],
            pass_fds=maintenance_module._maintenance_pass_fds(lock_fd, ()),
        )
        child_processes.append(child)
        if fail_parent_call:
            raise MaintenanceError("restore_fixture_failure")
        return destination

    monkeypatch.setattr(
        maintenance_module, "_restore_archive_unlocked", spawn_child_then_return_or_fail
    )
    receipt = ArchiveReceipt(archive_root / "unused", "0" * 64, 0)
    challenger_fd = -1
    try:
        if fail_parent_call:
            with pytest.raises(MaintenanceError, match="restore_fixture_failure"):
                restore_archive(receipt, tmp_path / "restore-bundle")
        else:
            assert restore_archive(receipt, tmp_path / "restore-bundle") == tmp_path / "restore-bundle"
        child = child_processes[0]
        assert child.poll() is None
        challenger_fd = os.open(archive_root, os.O_RDONLY | os.O_DIRECTORY)
        with pytest.raises(BlockingIOError):
            fcntl.flock(challenger_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        release_marker.write_text("release", encoding="ascii")
        assert child.wait() == 0
        fcntl.flock(challenger_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        release_marker.touch(exist_ok=True)
        for child in child_processes:
            if child.poll() is None:
                child.wait()
        if challenger_fd >= 0:
            os.close(challenger_fd)


def test_archive_and_restore_subprocesses_all_inherit_project_archive_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source_parent = tmp_path / "sources"
    source_parent.mkdir()
    _source, _binding_value, lifecycle, policy = _small_linked_worktree_fixture(
        project, source_parent, tmp_path / "state"
    )
    candidate = scan_candidates((policy,), lifecycle, now=int(time.time()))[0]
    original_run = subprocess.run
    original_flock = fcntl.flock
    lock_identity: tuple[int, int] | None = None
    child_lock_checks: list[tuple[str, bool]] = []

    def record_flock(descriptor: int, operation: int) -> None:
        nonlocal lock_identity
        if operation == fcntl.LOCK_EX:
            info = os.fstat(descriptor)
            try:
                root_info = policy.archive_root.stat(follow_symlinks=False)
            except FileNotFoundError:
                root_info = None
            if root_info is not None and (info.st_dev, info.st_ino) == (
                root_info.st_dev,
                root_info.st_ino,
            ):
                lock_identity = (info.st_dev, info.st_ino)
        original_flock(descriptor, operation)

    def record_run(*args, **kwargs):
        command = args[0]
        fd_values = kwargs.get("pass_fds", ())
        has_lock = False
        for descriptor in fd_values:
            info = os.fstat(descriptor)
            if lock_identity == (info.st_dev, info.st_ino):
                has_lock = True
                break
        child_lock_checks.append((Path(str(command[0])).name, has_lock))
        return original_run(*args, **kwargs)

    monkeypatch.setattr(maintenance_module.subprocess, "run", record_run)
    monkeypatch.setattr(maintenance_module.fcntl, "flock", record_flock)
    receipt = _archive_candidate(candidate, policy=policy, lifecycle=lifecycle)
    assert receipt.archive.is_dir()
    assert child_lock_checks
    assert all(has_lock for _command, has_lock in child_lock_checks)


def test_archive_error_finally_keeps_lock_until_started_child_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source_parent = tmp_path / "sources"
    source_parent.mkdir()
    _source, _binding_value, lifecycle, policy = _small_linked_worktree_fixture(
        project, source_parent, tmp_path / "state"
    )
    candidate = scan_candidates((policy,), lifecycle, now=int(time.time()))[0]
    release_marker = tmp_path / "release-archive-child"
    child_processes: list[subprocess.Popen[bytes]] = []

    def tar_child_then_fail(
        root_fd: int,
        _output: Path,
        *,
        exclude_git: bool,
        lock_fd: int | None = None,
    ) -> None:
        del exclude_git
        child_code = (
            "import os,sys,time; marker=sys.argv[1]; "
            "exec('while not os.path.exists(marker):\\n time.sleep(0.01)')"
        )
        child_processes.append(
            subprocess.Popen(
                [sys.executable, "-c", child_code, str(release_marker)],
                pass_fds=maintenance_module._maintenance_pass_fds(
                    lock_fd, (root_fd,)
                ),
            )
        )
        raise MaintenanceError("archive_fixture_failure")

    monkeypatch.setattr(maintenance_module, "_run_tar_create", tar_child_then_fail)
    challenger_fd = -1
    try:
        with pytest.raises(MaintenanceError, match="archive_fixture_failure"):
            _archive_candidate(candidate, policy=policy, lifecycle=lifecycle)
        assert len(child_processes) == 1 and child_processes[0].poll() is None
        challenger_fd = os.open(policy.archive_root, os.O_RDONLY | os.O_DIRECTORY)
        with pytest.raises(BlockingIOError):
            fcntl.flock(challenger_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        release_marker.write_text("release", encoding="ascii")
        assert child_processes[0].wait() == 0
        fcntl.flock(challenger_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        release_marker.touch(exist_ok=True)
        for child in child_processes:
            if child.poll() is None:
                child.wait()
        if challenger_fd >= 0:
            os.close(challenger_fd)


def test_archive_child_keeps_lock_after_writer_crash_until_handoff_to_hold(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("fork")
    project = tmp_path / "project"
    project.mkdir()
    source_parent = tmp_path / "sources"
    source_parent.mkdir()
    source, binding, lifecycle, policy = _small_linked_worktree_fixture(
        project, source_parent, tmp_path / "state"
    )
    del source, lifecycle
    archive_root = policy.archive_root
    archive_root.mkdir(mode=0o700)
    state_root = tmp_path / "state" / "lifecycle"
    release_marker = tmp_path / "release-child"
    writer_recv, writer_send = context.Pipe(duplex=False)
    writer = context.Process(
        target=_archive_writer_crashes_with_locked_child,
        args=(str(state_root), binding, str(archive_root), str(release_marker), writer_send),
    )
    writer.start()
    writer_send.close()
    assert writer_recv.poll(10), "writer did not report its child lock"
    old_pid, child_pid, old_revision, old_fence = writer_recv.recv()
    writer.join()
    assert writer.exitcode == 0
    writer_recv.close()

    lock_fd = os.open(archive_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recovery_recv, recovery_send = context.Pipe(duplex=False)
        recovery = context.Process(
            target=_recover_after_archive_lock,
            args=(str(state_root), binding, str(archive_root), recovery_send),
        )
        recovery.start()
        recovery_send.close()
        assert recovery_recv.poll(10), "recovery worker did not report its lock attempt"
        assert recovery_recv.recv() == "waiting"
        with pytest.raises(BlockingIOError):
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        release_marker.write_text("release", encoding="ascii")
        revision, fence, operation_error, finish_error = recovery_recv.recv()
        recovery.join()
        recovery_recv.close()
        assert recovery.exitcode == 0
    finally:
        os.close(lock_fd)

    assert child_pid > 0
    assert revision > old_revision
    assert fence > old_fence
    assert operation_error == "maintenance_recovery_hold"
    assert finish_error == "maintenance_operation_incomplete"
    reopened = WorktreeLifecycleStore(HiveStateStore(state_root))
    claim = reopened.snapshot().maintenance_claims[0]
    assert claim.owner_process.pid != old_pid


def test_recovery_rejects_caller_selected_private_root_while_archive_child_lives(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("fork")
    project = tmp_path / "project"
    project.mkdir()
    source_parent = tmp_path / "sources"
    source_parent.mkdir()
    _source, binding, _lifecycle, policy = _small_linked_worktree_fixture(
        project, source_parent, tmp_path / "state"
    )
    archive_root = policy.archive_root
    archive_root.mkdir(mode=0o700)
    wrong_root = project / ".wrong-private-root"
    wrong_root.mkdir(mode=0o700)
    state_root = tmp_path / "state" / "lifecycle"
    release_marker = tmp_path / "release-child"
    writer_recv, writer_send = context.Pipe(duplex=False)
    writer = context.Process(
        target=_archive_writer_crashes_with_locked_child,
        args=(str(state_root), binding, str(archive_root), str(release_marker), writer_send),
    )
    writer.start()
    writer_send.close()
    assert writer_recv.poll(10), "writer did not report its child lock"
    _old_pid, child_pid, _revision, _fence = writer_recv.recv()
    writer.join()
    writer_recv.close()
    assert writer.exitcode == 0

    lock_fd = os.open(archive_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lifecycle = WorktreeLifecycleStore(HiveStateStore(state_root))
        try:
            maintenance_module._recover_maintenance_claim_under_archive_lock(
                wrong_root, lifecycle, binding, now=200
            )
        except (MaintenanceError, TypeError):
            denied = True
        else:
            denied = False
        assert denied, "recovery accepted a caller-selected private root"
        root_record = lifecycle._maintenance_archive_lock_for_recovery(binding)
        assert root_record[0] == archive_root
        assert lifecycle.snapshot().maintenance_claims[0].owner_process.pid == _old_pid
    finally:
        release_marker.write_text("release", encoding="ascii")
        os.close(lock_fd)
    assert child_pid > 0


def test_server_archive_owner_derives_policy_and_lifecycle_from_canonical_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    canonical_checkout = Path(server_module.__file__).resolve().parents[2]
    shutil.copy2(canonical_checkout / "codex-hive.json", root / "codex-hive.json")
    shutil.copy2(canonical_checkout / "codex-agent-classes.json", root / "codex-agent-classes.json")
    _git(root, "init", "-qb", "main")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Fixture")
    _git(root, "remote", "add", "origin", "https://github.com/H234598/codex-master.git")
    (root / "tracked.txt").write_text("base\n")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "base")
    source_root = root / ".codex-master-worktrees"
    source_root.mkdir()
    source = source_root / "worker"
    _git(root, "worktree", "add", "-qb", "fixture", str(source))

    monkeypatch.setattr(server_module, "repo_root", lambda: root)
    monkeypatch.setattr(server_module, "STATE_ROOT", tmp_path / "state")
    attestation = HeadlessWriteScopeStore(tmp_path / "origin-evidence").create(
        "fixture", root, source, base_ref=None
    )
    lifecycle = server_module._worktree_lifecycle_store()
    binding = WorktreeBinding.from_creation_attestation(attestation)
    lifecycle._record_created_worktree(binding, attestation)
    _finish_fixture_use(lifecycle, binding, now=1000)

    exit_code = server_module.main_cli(
        [
            "worktree-maintenance",
            "archive",
            "--repository-id",
            "codex-master",
            "--source",
            str(source),
        ]
    )
    assert exit_code == 0
    receipt_payload = json.loads(capsys.readouterr().out)

    assert Path(receipt_payload["archive"]).is_dir()
    archive_root = root / ".hive-archive"
    archive_info = archive_root.stat(follow_symlinks=False)
    assert Path(receipt_payload["archive"]).parent == archive_root
    assert archive_info.st_uid == os.geteuid()
    assert archive_info.st_mode & 0o7777 == 0o700
    assert not (tmp_path / "state" / "worktree-maintenance").exists()
    restore_exit = server_module.main_cli(
        [
            "worktree-maintenance",
            "restore",
            "--repository-id",
            "codex-master",
            "--archive-id",
            Path(receipt_payload["archive"]).name,
            "--destination-name",
            "restored-worktree",
        ]
    )
    assert restore_exit == 0
    restore_payload = json.loads(capsys.readouterr().out)
    restored_worktree = Path(restore_payload["restored"])
    assert restored_worktree.is_dir()
    assert (restored_worktree / ".git").is_file()

    temp_root = Path("/tmp")
    producer = _create_ended_temp_producer(lifecycle, binding, temp_root, now=int(time.time()))
    producer_identity = (producer.stat().st_dev, producer.stat().st_ino)
    assert producer.stat().st_dev != root.stat().st_dev
    (producer / "runner-state.json").write_text('{"result":"done"}\n', encoding="utf-8")
    temp_exit = server_module.main_cli(
        [
            "worktree-maintenance",
            "archive-temp",
            "--repository-id",
            "codex-master",
            "--source",
            str(producer),
        ]
    )
    assert temp_exit == 0
    temp_receipt = json.loads(capsys.readouterr().out)
    assert Path(temp_receipt["archive"]).parent == archive_root
    restored = restore_archive(
        ArchiveReceipt(
            Path(temp_receipt["archive"]),
            temp_receipt["manifest_sha256"],
            temp_receipt["entry_count"],
            Path(temp_receipt["archive"]).stat().st_dev,
            Path(temp_receipt["archive"]).stat().st_ino,
        ),
        tmp_path / "temp-restore",
    )
    assert _file_snapshot(restored) == _file_snapshot(producer)
    unknown_temp = tmp_path / "unregistered-temp"
    unknown_temp.mkdir()
    with pytest.raises(Exception, match="maintenance_source_unattested"):
        server_module._archive_temporary_by_id("codex-master", unknown_temp)
    if producer.exists() and (producer.stat().st_dev, producer.stat().st_ino) == producer_identity:
        shutil.rmtree(producer)
    with pytest.raises(Exception, match="maintenance_selection_invalid"):
        server_module._archive_worktree_by_id("codex-master", ArchiveReceipt(Path("/archive"), "sha256:x", 0))


def test_server_cli_applies_only_attested_temp_producer_after_read_only_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root, worktree, _worktree_root, lifecycle, binding = _canonical_temp_owner_fixture(tmp_path)
    monkeypatch.setattr(server_module, "repo_root", lambda: root)
    monkeypatch.setattr(server_module, "STATE_ROOT", tmp_path / "state")
    _control_reference_inventory(monkeypatch)
    temp_root = tmp_path / "tmpfs-fixture"
    temp_root.mkdir()
    with patch.object(tempfile, "gettempdir", lambda: str(temp_root)):
        producer = _create_ended_temp_producer(
            lifecycle, binding, temp_root, now=int(time.time())
        )
    (producer / "state.json").write_text("verified producer output\n")
    monkeypatch.setattr(server_module, "_require_worktree_maintenance_approval", lambda *_args: None)
    monkeypatch.setattr(
        server_module,
        "_read_native_agent_registry_read_only",
        lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready"),
    )
    monkeypatch.setattr(server_module, "retained_pin_session_ids", lambda _now: set())

    exit_code = server_module.main_cli(
        [
            "worktree-maintenance",
            "apply",
            "--repository-id",
            "codex-master",
            "--source",
            str(producer),
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert not producer.exists()
    receipt = ArchiveReceipt(
        Path(payload["archive"]),
        payload["manifest_sha256"],
        payload["entry_count"],
        Path(payload["archive"]).stat().st_dev,
        Path(payload["archive"]).stat().st_ino,
    )
    restored = restore_archive(receipt, tmp_path / "cli-temp-restored")
    assert _file_snapshot(restored) == {"state.json": b"verified producer output\n"}
    assert not lifecycle.snapshot().maintenance_claims


@pytest.mark.parametrize("reference_kind", ["fd", "cwd", "mapping"])
def test_temp_apply_holds_when_open_reference_remains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reference_kind: str,
) -> None:
    producer, candidate, policy, lifecycle = _temporary_archive_fixture(tmp_path)
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda: lifecycle)
    monkeypatch.setattr(
        server_module,
        "_read_native_agent_registry_read_only",
        lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready"),
    )
    monkeypatch.setattr(server_module, "retained_pin_session_ids", lambda _now: set())
    claim = server_module._claim_worktree_maintenance(candidate.binding, now=int(time.time()))
    payload = producer / "payload.txt"
    fd = mapping = None
    old_cwd = Path.cwd()
    try:
        if reference_kind == "fd":
            fd = os.open(payload, os.O_RDONLY)
        elif reference_kind == "cwd":
            os.chdir(producer)
        else:
            fd = os.open(payload, os.O_RDONLY)
            mapping = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
        _control_reference_inventory(
            monkeypatch,
            mapped_path=payload if reference_kind == "mapping" else None,
        )
        with pytest.raises(MaintenanceError, match="maintenance_open_reference_active"):
            apply_candidate(candidate, lifecycle, policy=policy, claim=claim, now=int(time.time()))
        assert producer.exists()
        assert (producer / "payload.txt").read_text(encoding="utf-8") == "attested producer output\n"
        assert any(item.claim_id == claim.claim_id for item in lifecycle.snapshot().maintenance_claims)
    finally:
        os.chdir(old_cwd)
        if mapping is not None:
            mapping.close()
        if fd is not None:
            os.close(fd)


def test_temp_cli_unreadable_reference_inventory_is_no_mutation_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _worktree, _worktree_root, lifecycle, binding = _canonical_temp_owner_fixture(tmp_path)
    monkeypatch.setattr(server_module, "repo_root", lambda: root)
    monkeypatch.setattr(server_module, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda **_kwargs: lifecycle)
    monkeypatch.setattr(server_module, "_require_worktree_maintenance_approval", lambda *_args: None)
    monkeypatch.setattr(
        server_module,
        "_read_native_agent_registry_read_only",
        lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready"),
    )
    monkeypatch.setattr(server_module, "retained_pin_session_ids", lambda _now: set())
    temp_root = tmp_path / "tmp-source"
    temp_root.mkdir()
    with patch.object(tempfile, "gettempdir", lambda: str(temp_root)):
        producer = _create_ended_temp_producer(
            lifecycle, binding, temp_root, now=int(time.time())
        )
    (producer / "payload.txt").write_text("keep on unavailable inventory\n")
    original_listdir = os.listdir
    original_scandir = os.scandir

    def fixture_process_inventory(path: str | os.PathLike[str] | int) -> list[str]:
        if path == "/proc":
            return [str(os.getpid())]
        return original_listdir(path)

    def unreadable_own_fd_dir(path: str | os.PathLike[str] | int):
        if path == f"/proc/{os.getpid()}/fd":
            raise PermissionError("fixture inventory unavailable")
        return original_scandir(path)

    monkeypatch.setattr(os, "listdir", fixture_process_inventory)
    monkeypatch.setattr(os, "scandir", unreadable_own_fd_dir)
    before = lifecycle.snapshot()
    with pytest.raises(MaintenanceError, match="maintenance_reference_inventory_unavailable"):
        server_module._apply_worktree_by_id("codex-master", producer)
    assert lifecycle.snapshot() == before
    assert (producer / "payload.txt").read_text(encoding="utf-8") == "keep on unavailable inventory\n"


def test_temp_apply_rejects_identity_swap_after_archive_without_deleting_either_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    producer, candidate, policy, lifecycle = _temporary_archive_fixture(tmp_path)
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda: lifecycle)
    monkeypatch.setattr(
        server_module,
        "_read_native_agent_registry_read_only",
        lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready"),
    )
    monkeypatch.setattr(server_module, "retained_pin_session_ids", lambda _now: set())
    _control_reference_inventory(monkeypatch)
    claim = server_module._claim_worktree_maintenance(candidate.binding, now=int(time.time()))
    original_archive = maintenance_module.archive_temporary_candidate
    saved = producer.with_name(producer.name + ".saved")

    def archive_then_swap(*args, **kwargs):
        receipt = original_archive(*args, **kwargs)
        producer.rename(saved)
        producer.mkdir(mode=0o700)
        (producer / "replacement.txt").write_text("replacement must survive\n")
        return receipt

    monkeypatch.setattr(maintenance_module, "archive_temporary_candidate", archive_then_swap)
    with pytest.raises(WorktreeLifecycleError, match="maintenance_receipt_binding_mismatch"):
        apply_candidate(candidate, lifecycle, policy=policy, claim=claim, now=int(time.time()))
    assert (saved / "payload.txt").read_text(encoding="utf-8") == "attested producer output\n"
    assert (producer / "replacement.txt").read_text(encoding="utf-8") == "replacement must survive\n"
    assert any(item.claim_id == claim.claim_id for item in lifecycle.snapshot().maintenance_claims)


def test_temp_apply_restores_name_swapped_tree_before_holding_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    producer, candidate, policy, lifecycle = _temporary_archive_fixture(tmp_path)
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda: lifecycle)
    monkeypatch.setattr(
        server_module,
        "_read_native_agent_registry_read_only",
        lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready"),
    )
    monkeypatch.setattr(server_module, "retained_pin_session_ids", lambda _now: set())
    _control_reference_inventory(monkeypatch)
    claim = server_module._claim_worktree_maintenance(candidate.binding, now=int(time.time()))
    filesystem = maintenance_module.LocalFleetHomeV2Filesystem
    rename = filesystem.rename_noreplace_between_at
    displaced_original = producer.with_name(producer.name + ".original")
    raced = False

    def swap_after_identity_check(self, source_parent_fd, source_name, target_parent_fd, target_name):
        nonlocal raced
        if source_name == producer.name and target_name == "temporary" and not raced:
            producer.rename(displaced_original)
            producer.mkdir(mode=0o700)
            (producer / "replacement.txt").write_text("replacement tree\n")
            raced = True
        return rename(self, source_parent_fd, source_name, target_parent_fd, target_name)

    monkeypatch.setattr(filesystem, "rename_noreplace_between_at", swap_after_identity_check)
    with pytest.raises(MaintenanceError, match="quarantine_identity_changed"):
        apply_candidate(candidate, lifecycle, policy=policy, claim=claim, now=int(time.time()))

    assert raced
    assert (displaced_original / "payload.txt").read_text(encoding="utf-8") == "attested producer output\n"
    assert (producer / "replacement.txt").read_text(encoding="utf-8") == "replacement tree\n"
    assert not (producer.parent / ".hive-quarantine" / claim.claim_id).exists()
    assert any(item.claim_id == claim.claim_id for item in lifecycle.snapshot().maintenance_claims)


@pytest.mark.parametrize("source_conflict", [False, True])
def test_temp_handoff_identity_read_failure_restores_or_records_collision_hold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_conflict: bool,
) -> None:
    producer, candidate, policy, lifecycle = _temporary_archive_fixture(tmp_path)
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda: lifecycle)
    monkeypatch.setattr(
        server_module,
        "_read_native_agent_registry_read_only",
        lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready"),
    )
    monkeypatch.setattr(server_module, "retained_pin_session_ids", lambda _now: set())
    _control_reference_inventory(monkeypatch)
    claim = server_module._claim_worktree_maintenance(candidate.binding, now=int(time.time()))
    filesystem = maintenance_module.LocalFleetHomeV2Filesystem
    rename = filesystem.rename_noreplace_between_at
    identity_at = filesystem.identity_at
    displaced_original = producer.with_name(producer.name + ".original")
    moved = False
    injected = False

    def race_rename(self, source_parent_fd, source_name, target_parent_fd, target_name):
        nonlocal moved
        if source_name == producer.name and target_name == "temporary" and not moved:
            producer.rename(displaced_original)
            producer.mkdir(mode=0o700)
            (producer / "replacement.txt").write_text("replacement tree\n")
            result = rename(self, source_parent_fd, source_name, target_parent_fd, target_name)
            if source_conflict:
                producer.mkdir(mode=0o700)
                (producer / "later.txt").write_text("later occupant\n")
            moved = True
            return result
        return rename(self, source_parent_fd, source_name, target_parent_fd, target_name)

    def fail_first_quarantine_identity(directory_fd, name):
        nonlocal injected
        if moved and name == "temporary" and not injected:
            injected = True
            raise OSError("fixture identity read failure immediately after rename")
        return identity_at(directory_fd, name)

    monkeypatch.setattr(filesystem, "rename_noreplace_between_at", race_rename)
    monkeypatch.setattr(filesystem, "identity_at", staticmethod(fail_first_quarantine_identity))
    with pytest.raises(MaintenanceError, match="temporary_quarantine_or_removal_failed"):
        apply_candidate(candidate, lifecycle, policy=policy, claim=claim, now=int(time.time()))

    assert moved and injected
    assert (displaced_original / "payload.txt").read_text(encoding="utf-8") == "attested producer output\n"
    operation = lifecycle.maintenance_operation_for_recovery(claim)
    if source_conflict:
        quarantined = producer.parent / ".hive-quarantine" / claim.claim_id / "temporary"
        assert (producer / "later.txt").read_text(encoding="utf-8") == "later occupant\n"
        assert (quarantined / "replacement.txt").read_text(encoding="utf-8") == "replacement tree\n"
        evidence = operation["collision_evidence"]
        assert evidence["source_name"] == producer.name
        assert evidence["quarantine_name"] == "temporary"
        assert evidence["moved_inode"] == quarantined.stat().st_ino
        assert evidence["moved_device"] == quarantined.stat().st_dev
    else:
        assert (producer / "replacement.txt").read_text(encoding="utf-8") == "replacement tree\n"
        assert not (producer.parent / ".hive-quarantine" / claim.claim_id).exists()
        assert operation["collision_evidence"] is None


def test_temp_apply_failure_after_quarantine_restores_source_and_releases_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    producer, candidate, policy, lifecycle = _temporary_archive_fixture(tmp_path)
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda: lifecycle)
    monkeypatch.setattr(
        server_module,
        "_read_native_agent_registry_read_only",
        lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready"),
    )
    monkeypatch.setattr(server_module, "retained_pin_session_ids", lambda _now: set())
    _control_reference_inventory(monkeypatch)
    claim = server_module._claim_worktree_maintenance(candidate.binding, now=int(time.time()))
    advance = lifecycle.advance_maintenance_phase

    def fail_after_quarantine(claim_arg, *, phase):
        advance(claim_arg, phase=phase)
        if phase == "quarantined":
            raise OSError("fixture crash after durable quarantine phase")

    monkeypatch.setattr(lifecycle, "advance_maintenance_phase", fail_after_quarantine)
    with pytest.raises(MaintenanceError, match="temporary_quarantine_or_removal_failed"):
        apply_candidate(candidate, lifecycle, policy=policy, claim=claim, now=int(time.time()))
    assert producer.exists()
    assert (producer / "payload.txt").read_text(encoding="utf-8") == "attested producer output\n"
    assert not (producer.parent / ".hive-quarantine" / claim.claim_id).exists()
    assert not lifecycle.snapshot().maintenance_claims


def test_temp_recovery_restores_quarantined_source_after_writer_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    producer, candidate, policy, lifecycle = _temporary_archive_fixture(tmp_path)
    original = _file_snapshot(producer)
    claim = lifecycle.claim_maintenance(candidate.binding, now=int(time.time()))
    lifecycle.advance_maintenance_phase(claim, phase="archiving")
    receipt = maintenance_module.archive_temporary_candidate(
        candidate, policy=policy, lifecycle=lifecycle, claim=claim
    )
    lifecycle.record_maintenance_archive(claim, receipt)
    lifecycle.advance_maintenance_phase(claim, phase="quarantine_started")
    quarantine_root = producer.parent / ".hive-quarantine"
    quarantine_root.mkdir(mode=0o700)
    quarantine_claim = quarantine_root / claim.claim_id
    quarantine_claim.mkdir(mode=0o700)
    producer.rename(quarantine_claim / "temporary")
    lifecycle.advance_maintenance_phase(claim, phase="quarantined")
    lifecycle.hold_maintenance_claim(claim)

    with monkeypatch.context() as recovery_patch:
        recovery_patch.setattr(lifecycle_module, "_process_is_active", lambda _identity: False)
        recovered_claim = maintenance_module._recover_maintenance_claim_under_archive_lock(
            lifecycle, candidate.binding, now=int(time.time())
        )
    restored = maintenance_module.recover_temporary_source_after_hold(
        lifecycle, recovered_claim
    )

    assert restored == producer
    assert _file_snapshot(producer) == original
    assert not quarantine_claim.exists()
    assert not lifecycle.snapshot().maintenance_claims


@pytest.mark.parametrize("source_conflict", [False, True])
def test_temp_recovery_waits_for_crashed_writer_child_lock_and_preserves_inode(
    tmp_path: Path, source_conflict: bool
) -> None:
    context = multiprocessing.get_context("fork")
    root, _worktree, worktree_root, lifecycle, binding = _canonical_temp_owner_fixture(tmp_path)
    temp_root = tmp_path / "tmp-source"
    temp_root.mkdir()
    producer = _create_ended_temp_producer(
        lifecycle, binding, temp_root, now=int(time.time())
    )
    payload = producer / "state.json"
    payload.write_text("restore only after the archive writer child exits\n", encoding="utf-8")
    policy = ProjectPolicy(
        source_root=binding.canonical_source_path,
        allowed_source_roots=(worktree_root,),
        archive_root=root / ".hive-archive",
    )
    candidate = next(
        item
        for item in scan_candidates((policy,), lifecycle, now=int(time.time()))
        if item.temporary and item.source == producer
    )
    original_inode = producer.stat(follow_symlinks=False).st_ino
    original_content = payload.read_bytes()
    release_marker = tmp_path / "release-maintenance-lock-child"
    writer_recv, writer_send = context.Pipe(duplex=False)
    writer = context.Process(
        target=_temporary_handoff_writer_crashes_with_locked_child,
        args=(
            str(tmp_path / "state" / "hive"),
            producer,
            candidate,
            policy,
            str(release_marker),
            writer_send,
        ),
    )
    writer.start()
    writer_send.close()
    assert writer_recv.poll(30), "writer did not report its inherited lock child"
    old_pid, child_pid, claim_id, old_revision, old_fence = writer_recv.recv()
    writer.join()
    assert writer.exitcode == 0
    writer_recv.close()

    quarantine_root = producer.parent / ".hive-quarantine"
    quarantine_claim = quarantine_root / claim_id
    quarantined = quarantine_claim / "temporary"
    assert not producer.exists()
    assert quarantined.stat(follow_symlinks=False).st_ino == original_inode
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state" / "hive"))
    old_claim = store.snapshot().maintenance_claims[0]
    assert old_claim.owner_process.pid == old_pid
    assert old_claim.revision == old_revision
    assert old_claim.fence == old_fence

    recovery_recv, recovery_send = context.Pipe(duplex=False)
    recovery = context.Process(
        target=_run_temporary_recovery_cli_process,
        args=(str(root), str(tmp_path / "state" / "hive"), str(producer), recovery_send),
    )
    recovery.start()
    recovery_send.close()
    assert recovery_recv.poll(30), "canonical recovery owner did not announce its attempt"
    assert recovery_recv.recv() == "flock_attempting"
    locked_fd = os.open(policy.archive_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(locked_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current_claim = store.snapshot().maintenance_claims[0]
        assert current_claim.owner_process.pid == old_pid
        assert not producer.exists()
        assert quarantined.stat(follow_symlinks=False).st_ino == original_inode

        if source_conflict:
            producer.mkdir(mode=0o700)
            (producer / "occupant.txt").write_text("keep this occupant\n", encoding="utf-8")
        release_marker.write_text("release", encoding="ascii")
        assert recovery_recv.poll(30), "recovery did not finish after lock child exit"
        result = recovery_recv.recv()
        recovery.join()
        assert recovery.exitcode == 0
        fcntl.flock(locked_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(locked_fd, fcntl.LOCK_UN)
    finally:
        release_marker.touch(exist_ok=True)
        os.close(locked_fd)
        if recovery.is_alive():
            recovery.join()
        recovery_recv.close()

    if source_conflict:
        assert result[0] == "cli"
        assert result[1] == 1
        assert json.loads(result[2]) == {"error": "maintenance_source_restore_ambiguous"}
        assert (producer / "occupant.txt").read_text(encoding="utf-8") == "keep this occupant\n"
        assert quarantined.stat(follow_symlinks=False).st_ino == original_inode
        held = store.snapshot().maintenance_claims[0]
        assert held.claim_id == claim_id
        with store._state.locked():
            document = store._state.read_json_locked(
                PurePosixPath("worktree-lifecycle-v1.json"), max_bytes=1024 * 1024
            )
        operation = next(iter(document["worktrees"].values()))["maintenance_operation"]
        assert operation["phase"] == "recovery_hold"
    else:
        assert result[0] == "cli"
        assert result[1] == 0
        cli_result = json.loads(result[2])
        assert cli_result["phase"] == "source_restored"
        assert producer.stat(follow_symlinks=False).st_ino == original_inode
        assert payload.read_bytes() == original_content
        assert not quarantine_claim.exists()
        assert not store.snapshot().maintenance_claims
        with store._state.locked():
            document = store._state.read_json_locked(
                PurePosixPath("worktree-lifecycle-v1.json"), max_bytes=1024 * 1024
            )
        history = next(iter(document["worktrees"].values()))["maintenance_history"]
        finished = next(row for row in history if row["claim_id"] == claim_id)
        assert finished["outcome"] == "source_restored"
        assert finished["revision"] > old_revision
        assert finished["fence"] > old_fence
    assert child_pid > 0


def test_temp_recover_cli_restores_quarantined_source_by_canonical_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root, _worktree, worktree_root, lifecycle, binding = _canonical_temp_owner_fixture(tmp_path)
    monkeypatch.setattr(server_module, "repo_root", lambda: root)
    monkeypatch.setattr(server_module, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda **_kwargs: lifecycle)
    temp_root = tmp_path / "tmp-source"
    temp_root.mkdir()
    producer = _create_ended_temp_producer(
        lifecycle, binding, temp_root, now=int(time.time())
    )
    (producer / "state.json").write_text("restore after writer crash\n")
    policy = ProjectPolicy(
        source_root=binding.canonical_source_path,
        allowed_source_roots=(worktree_root,),
        archive_root=root / ".hive-archive",
    )
    candidate = next(
        item
        for item in scan_candidates((policy,), lifecycle, now=int(time.time()))
        if item.temporary and item.source == producer
    )
    claim = lifecycle.claim_maintenance(binding, now=int(time.time()))
    lifecycle.advance_maintenance_phase(claim, phase="archiving")
    receipt = maintenance_module.archive_temporary_candidate(
        candidate, policy=policy, lifecycle=lifecycle, claim=claim
    )
    lifecycle.record_maintenance_archive(claim, receipt)
    lifecycle.advance_maintenance_phase(claim, phase="quarantine_started")
    quarantine_root = producer.parent / ".hive-quarantine"
    quarantine_root.mkdir(mode=0o700)
    quarantine_claim = quarantine_root / claim.claim_id
    quarantine_claim.mkdir(mode=0o700)
    producer.rename(quarantine_claim / "temporary")
    lifecycle.advance_maintenance_phase(claim, phase="quarantined")
    lifecycle.hold_maintenance_claim(claim)

    recover_claim = maintenance_module._recover_maintenance_claim_under_archive_lock

    def recover_dead_writer(*args, **kwargs):
        with patch.object(lifecycle_module, "_process_is_active", lambda _identity: False):
            return recover_claim(*args, **kwargs)

    monkeypatch.setattr(
        maintenance_module,
        "_recover_maintenance_claim_under_archive_lock",
        recover_dead_writer,
    )
    exit_code = server_module.main_cli(
        [
            "worktree-maintenance",
            "recover",
            "--repository-id",
            "codex-master",
            "--source",
            str(producer),
        ]
    )

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["phase"] == "source_restored"
    assert (producer / "state.json").read_text(encoding="utf-8") == "restore after writer crash\n"
    assert not quarantine_claim.exists()
    assert not lifecycle.snapshot().maintenance_claims


def test_manifest_records_posix_acl_and_sparse_extents(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    sparse = source / "sparse.bin"
    with sparse.open("wb") as stream:
        stream.truncate(8 * 1024 * 1024)
        stream.seek(0)
        stream.write(b"head")
        stream.seek(7 * 1024 * 1024)
        stream.write(b"tail")
    acl = subprocess.run(
        ["setfacl", "-m", "u:65534:r--", str(sparse)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if acl.returncode:
        pytest.skip("fixture filesystem does not support POSIX ACLs")

    entries = _tree_manifest(source)
    entry = next(item for item in entries if item["path"] == "sparse.bin")

    assert "system.posix_acl_access" in entry["xattrs"]
    assert entry["sparse_extents"]


def test_manifest_records_security_xattrs(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_text("data")
    fd = os.open(source, os.O_RDONLY)
    try:
        attrs = _xattrs(fd)
    finally:
        os.close(fd)
    if "security.selinux" not in attrs:
        pytest.skip("fixture filesystem does not expose a security xattr")
    assert attrs["security.selinux"]


def test_manifest_records_symlink_security_xattrs(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    target = source / "target"
    target.write_text("data")
    link = source / "link"
    link.symlink_to("target")

    entry = next(item for item in _tree_manifest(source) if item["path"] == "link")

    assert "security.selinux" in entry["xattrs"]


def test_manifest_records_root_acl_and_xattrs_for_both_trees(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    common = tmp_path / "common"
    worktree.mkdir()
    common.mkdir()
    for root in (worktree, common):
        subprocess.run(
            ["setfacl", "-m", "u:65534:r-x", str(root)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.setxattr(root, "user.root-fixture", root.name.encode())

    worktree_root = next(item for item in _tree_manifest(worktree) if item["path"] == ".")
    common_root = next(item for item in _tree_manifest(common) if item["path"] == ".")

    for entry in (worktree_root, common_root):
        assert entry["kind"] == "directory"
        assert "system.posix_acl_access" in entry["xattrs"]
        assert entry["xattrs"]["user.root-fixture"]


def test_preview_is_read_only_and_protects_missing_lifecycle_age(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    marker = source / "keep.txt"
    marker.write_text("unchanged")
    policy = ProjectPolicy(source, (tmp_path,), tmp_path / "archive")
    before = _file_snapshot(tmp_path)

    preview = scan_candidates((policy,), object(), now=10**12)

    assert _file_snapshot(tmp_path) == before
    assert not preview[0].eligible
    assert "lifecycle_or_source_unavailable" in preview[0].reasons


@pytest.mark.parametrize(
    ("age", "allocated", "expected_reason"),
    (
        (30 * 86400, 1, "inactive_30_days"),
        (7 * 86400, 10 * 1024**3, "large_inactive_7_days"),
        (7 * 86400, 10 * 1024**3 - 1, "below_inactivity_threshold"),
    ),
)
def test_preview_uses_exact_age_and_allocated_size_thresholds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    age: int,
    allocated: int,
    expected_reason: str,
) -> None:
    import the_hive.maintenance as maintenance

    source = tmp_path / "worktree"
    source.mkdir()
    common = tmp_path / "common"
    common.mkdir()
    binding = SimpleNamespace(
        canonical_source_path=source,
        git_common_directory=common,
    )
    lifecycle = SimpleNamespace(
        binding_for_source=lambda path: binding,
        last_use_ended_at=lambda bound: 100,
        snapshot=lambda: SimpleNamespace(active_uses=(), maintenance_claims=()),
    )
    monkeypatch.setattr(maintenance, "_git_layout", lambda path, bound: (common, "worktrees/x"))
    monkeypatch.setattr(maintenance, "_tree_manifest", lambda path, **kwargs: [])
    monkeypatch.setattr(maintenance, "_allocated_bytes", lambda path: allocated)
    preview = scan_candidates(
        (ProjectPolicy(source, (tmp_path,), tmp_path / "archive"),),
        lifecycle,
        now=100 + age,
    )[0]

    assert preview.eligible is (expected_reason != "below_inactivity_threshold")
    assert expected_reason in preview.reasons


@pytest.mark.parametrize("active_field", ("active_use", "maintenance_claim"))
def test_old_end_history_does_not_override_current_lifecycle_exclusions(
    tmp_path: Path,
    active_field: str,
) -> None:
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q")
    _git(origin, "config", "user.email", "fixture@example.invalid")
    _git(origin, "config", "user.name", "Fixture")
    (origin / "tracked.txt").write_text("base\n")
    _git(origin, "add", ".")
    _git(origin, "commit", "-qm", "base")
    source = tmp_path / "worktree"
    _git(origin, "worktree", "add", "-qb", "fixture", str(source))
    attestation = HeadlessWriteScopeStore(tmp_path / "origin-evidence").create(
        "fixture", source.resolve(), source.resolve(), base_ref=None
    )
    binding = WorktreeBinding.from_creation_attestation(attestation)
    lifecycle = WorktreeLifecycleStore(HiveStateStore(tmp_path / "lifecycle-state"))
    lifecycle._record_created_worktree(binding, attestation)
    _finish_fixture_use(lifecycle, binding, now=1)
    assert lifecycle.last_use_ended_at(binding) == 3
    if active_field == "active_use":
        lifecycle.begin_use(
            binding,
            principal_id="principal.fixture",
            session_id="session.active",
            assignment_id="assignment.active",
            now=5,
        )
    else:
        lifecycle.claim_maintenance(binding, now=5)

    preview = scan_candidates(
        (ProjectPolicy(source, (tmp_path,), tmp_path / "archive"),),
        lifecycle,
        now=4 + 30 * 86400,
    )[0]

    assert "worktree_in_use" in preview.reasons or "maintenance_claim_active" in preview.reasons
    assert not preview.eligible


def test_unattested_archive_candidate_cannot_touch_source_or_existing_archive(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "keep.txt").write_text("source")
    archive_root = tmp_path / "archive"
    archive_root.mkdir()
    old_archive = archive_root / "prior.zip"
    old_archive.write_bytes(b"old receipt")
    foreign_verify = archive_root / "foreign.verify"
    foreign_verify.mkdir()
    (foreign_verify / "keep").write_text("foreign")
    policy = ProjectPolicy(source, (tmp_path,), archive_root)
    candidate = scan_candidates((policy,), object(), now=1)[0]
    before = _file_snapshot(tmp_path)

    with pytest.raises(MaintenanceError, match="candidate_not_eligible"):
        _archive_candidate(candidate, policy=ProjectPolicy(candidate.source, (tmp_path,), archive_root), lifecycle=object())

    assert _file_snapshot(tmp_path) == before
    assert old_archive.read_bytes() == b"old receipt"


def test_forged_eligible_boolean_does_not_open_archive_writer(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "keep.txt").write_text("source")
    archive_root = tmp_path / "archive"
    candidate = MaintenanceCandidate(source, (), True)

    with pytest.raises(MaintenanceError, match="candidate_not_eligible"):
        _archive_candidate(candidate, policy=ProjectPolicy(candidate.source, (tmp_path,), archive_root), lifecycle=object())

    assert not archive_root.exists()
    assert (source / "keep.txt").read_text() == "source"


def test_ineligible_linked_git_worktree_remains_untouched(
    tmp_path: Path,
) -> None:
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q")
    _git(origin, "config", "user.email", "test@example.invalid")
    _git(origin, "config", "user.name", "Fixture")
    (origin / ".gitignore").write_text("ignored.dat\n")
    (origin / "tracked.txt").write_text("base\n")
    _git(origin, "add", ".")
    _git(origin, "commit", "-qm", "base")
    work = tmp_path / "work"
    _git(origin, "worktree", "add", "-qb", "fixture", str(work))
    (work / "staged.txt").write_text("staged\n")
    _git(work, "add", "staged.txt")
    (work / "tracked.txt").write_text("unstaged\n")
    (work / "untracked.txt").write_text("untracked\n")
    (work / "ignored.dat").write_text("ignored\n")
    _git(work, "config", "maintenance.fixture", "preserved")
    status = _git(work, "status", "--porcelain")
    head = _git(work, "rev-parse", "HEAD")
    index = (origin / ".git" / "worktrees" / work.name / "index").read_bytes()
    policy = ProjectPolicy(work, (tmp_path,), tmp_path / "archive")
    candidate = scan_candidates((policy,), object(), now=1)[0]
    before = _file_snapshot(tmp_path)

    with pytest.raises(MaintenanceError, match="candidate_not_eligible"):
        _archive_candidate(candidate, policy=policy, lifecycle=object())

    assert _file_snapshot(tmp_path) == before
    assert _git(work, "status", "--porcelain") == status
    assert _git(work, "rev-parse", "HEAD") == head
    assert (origin / ".git" / "worktrees" / work.name / "index").read_bytes() == index
    assert not policy.archive_root.exists()


def test_invalid_restore_receipt_preserves_existing_and_missing_targets(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "existing.zip"
    archive_path.write_bytes(b"untrusted fixture")
    receipt = ArchiveReceipt(archive_path, "0" * 64, 1)
    destination = tmp_path / "existing"
    destination.mkdir()
    foreign = destination / "keep"
    foreign.write_text("foreign")
    missing_destination = tmp_path / "missing"

    with pytest.raises(MaintenanceError, match="archive_identity_invalid"):
        restore_archive(receipt, destination)
    with pytest.raises(MaintenanceError, match="archive_identity_invalid"):
        restore_archive(receipt, missing_destination)

    assert archive_path.read_bytes() == b"untrusted fixture"
    assert foreign.read_text() == "foreign"
    assert not missing_destination.exists()


def test_restore_rejects_manifest_gitdir_escape_before_any_write(tmp_path: Path) -> None:
    archive_dir = tmp_path / "untrusted-archive"
    archive_dir.mkdir(mode=0o700)
    os.chmod(archive_dir, 0o700)
    for name in ("worktree.tar", "git-common.tar"):
        with tarfile.open(archive_dir / name, "w"):
            pass
    archives = {
        name: hashlib.sha256((archive_dir / name).read_bytes()).hexdigest()
        for name in ("worktree.tar", "git-common.tar")
    }
    manifest = {
        "format": 1,
        "gitdir": "../../escape",
        "source_entries": [],
        "common_entries": [],
        "archives": archives,
    }
    raw_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    (archive_dir / "manifest.json").write_bytes(raw_manifest)
    info = archive_dir.stat()
    receipt = ArchiveReceipt(
        archive_dir,
        hashlib.sha256(raw_manifest).hexdigest(),
        0,
        info.st_dev,
        info.st_ino,
    )
    escape = tmp_path / "escape"
    escape.mkdir()
    destination = tmp_path / "restored"

    with pytest.raises(MaintenanceError, match="archive_gitdir_invalid"):
        restore_archive(receipt, destination)

    assert list(escape.iterdir()) == []
    assert not destination.exists()


def test_git_config_validator_blocks_fsmonitor_commands(tmp_path: Path) -> None:
    import the_hive.maintenance as maintenance

    config = tmp_path / "config"
    marker = tmp_path / "fsmonitor-ran"
    subprocess.run(
        ["git", "config", "--file", str(config), "core.fsmonitor", f"!touch {marker}"],
        check=True,
    )
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(MaintenanceError, match="archive_git_config_unsafe"):
            maintenance._validate_git_config_at(directory_fd, "config")
    finally:
        os.close(directory_fd)

    assert not marker.exists()


def test_restore_validates_real_linked_worktree_config_before_git_status(tmp_path: Path) -> None:
    import the_hive.maintenance as maintenance

    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q")
    _git(origin, "config", "user.email", "fixture@example.invalid")
    _git(origin, "config", "user.name", "Fixture")
    (origin / "tracked.txt").write_text("base\n")
    _git(origin, "add", ".")
    _git(origin, "commit", "-qm", "base")
    worktree = tmp_path / "worktree"
    _git(origin, "worktree", "add", "-qb", "fixture", str(worktree))
    common, gitdir = maintenance._git_layout(worktree, None)
    expected_status, head, index_digest = maintenance._git_status(worktree)
    marker = tmp_path / "fsmonitor-ran"
    _git(origin, "config", "core.fsmonitor", f"! touch {marker}")

    archive_dir = tmp_path / "archive"
    archive_dir.mkdir(mode=0o700)
    os.chmod(archive_dir, 0o700)

    worktree_fd = os.open(worktree, os.O_RDONLY | os.O_DIRECTORY)
    common_fd = os.open(common, os.O_RDONLY | os.O_DIRECTORY)
    try:
        maintenance._tar_create(worktree_fd, archive_dir / "worktree.tar", exclude_git=True)
        maintenance._tar_create(common_fd, archive_dir / "git-common.tar", exclude_git=False)
    finally:
        os.close(worktree_fd)
        os.close(common_fd)
    source_entries = maintenance._tree_manifest(worktree, skip_git=True)
    common_entries = maintenance._tree_manifest(common)
    source_info = worktree.stat()
    common_info = common.stat()
    manifest = {
        "format": 1,
        "source": str(worktree),
        "source_device": source_info.st_dev,
        "source_inode": source_info.st_ino,
        "source_mode": source_info.st_mode & 0o7777,
        "source_mtime_ns": source_info.st_mtime_ns,
        "git_common_device": common_info.st_dev,
        "git_common_inode": common_info.st_ino,
        "gitdir": gitdir,
        "git_status": expected_status,
        "git_head": head,
        "git_index_sha256": index_digest,
        "source_entries": source_entries,
        "common_entries": common_entries,
        "archives": {
            name: hashlib.sha256((archive_dir / name).read_bytes()).hexdigest()
            for name in ("worktree.tar", "git-common.tar")
        },
    }
    raw_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    (archive_dir / "manifest.json").write_bytes(raw_manifest)
    archive_info = archive_dir.stat()
    receipt = ArchiveReceipt(
        archive_dir,
        hashlib.sha256(raw_manifest).hexdigest(),
        len(source_entries) + len(common_entries),
        archive_info.st_dev,
        archive_info.st_ino,
    )
    destination = tmp_path / "restored-bundle"

    with pytest.raises(MaintenanceError, match="archive_git_config_unsafe"):
        restore_archive(receipt, destination)

    assert not marker.exists()
    assert not destination.exists()
    assert not list(tmp_path.glob(".restore-*"))


def test_restore_rejects_tar_symlink_escape_before_extraction(tmp_path: Path) -> None:
    import the_hive.maintenance as maintenance

    archive_dir = tmp_path / "untrusted-archive"
    archive_dir.mkdir(mode=0o700)
    os.chmod(archive_dir, 0o700)
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / "escape-link").symlink_to("../../outside")
    common = tmp_path / "common"
    gitdir = common / "worktrees" / "fixture"
    gitdir.mkdir(parents=True)
    (gitdir / "gitdir").write_text("/unused/.git\n")
    with tarfile.open(archive_dir / "worktree.tar", "w") as bundle:
        bundle.add(worktree, arcname=".")
    with tarfile.open(archive_dir / "git-common.tar", "w") as bundle:
        bundle.add(common, arcname=".")
    manifest = {
        "format": 1,
        "gitdir": "worktrees/fixture",
        "source_entries": maintenance._tree_manifest(worktree, skip_git=True),
        "common_entries": maintenance._tree_manifest(common),
        "archives": {
            name: hashlib.sha256((archive_dir / name).read_bytes()).hexdigest()
            for name in ("worktree.tar", "git-common.tar")
        },
    }
    raw_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    (archive_dir / "manifest.json").write_bytes(raw_manifest)
    info = archive_dir.stat()
    receipt = ArchiveReceipt(
        archive_dir,
        hashlib.sha256(raw_manifest).hexdigest(),
        len(manifest["source_entries"]) + len(manifest["common_entries"]),
        info.st_dev,
        info.st_ino,
    )
    destination = tmp_path / "restored"

    with pytest.raises(MaintenanceError, match="archive_symlink_target_escape"):
        restore_archive(receipt, destination)

    assert not destination.exists()


def test_apply_candidate_requires_a_live_lifecycle_claim(tmp_path: Path) -> None:
    policy = ProjectPolicy(tmp_path, (tmp_path,), tmp_path / "archive")
    candidate = scan_candidates((policy,), object(), now=1)[0]
    with pytest.raises(MaintenanceError, match="maintenance_claim_unavailable"):
        apply_candidate(candidate, object(), policy=policy, claim=object(), now=1)


def test_apply_refuses_open_fd_write_after_archive_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    with tempfile.TemporaryDirectory(prefix="hive-apply-fd-", dir="/tmp") as raw:
        source_parent = Path(raw)
        source, binding, lifecycle, policy = _small_linked_worktree_fixture(
            project, source_parent, tmp_path / "state"
        )
        candidate = scan_candidates((policy,), lifecycle, now=int(time.time()))[0]
        assert candidate.eligible
        tracked = source / "tracked.txt"
        writer_fd = os.open(tracked, os.O_WRONLY | os.O_APPEND)
        monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda: lifecycle)
        monkeypatch.setattr(
            server_module,
            "_read_native_agent_registry_read_only",
            lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready"),
        )
        monkeypatch.setattr(server_module, "retained_pin_session_ids", lambda _now: set())
        claim = server_module._claim_worktree_maintenance(binding, now=int(time.time()))
        try:
            with pytest.raises(MaintenanceError, match="maintenance_open_reference_active"):
                apply_candidate(
                    candidate,
                    lifecycle,
                    policy=policy,
                    claim=claim,
                    now=int(time.time()),
                )
            assert source.exists()
            assert tracked.read_bytes() == b"original\n"
            with pytest.raises(WorktreeLifecycleError, match="maintenance_operation_incomplete"):
                lifecycle.finish_maintenance(claim, outcome="incorrectly-finished")
            with lifecycle._state.locked():
                document = lifecycle._state.read_json_locked(
                    PurePosixPath("worktree-lifecycle-v1.json"), max_bytes=1024 * 1024
                )
            operation = next(iter(document["worktrees"].values()))["maintenance_operation"]
            assert operation["phase"] == "recovery_hold"
        finally:
            os.close(writer_fd)


def test_apply_holds_when_proc_reference_inventory_is_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    with tempfile.TemporaryDirectory(prefix="hive-apply-proc-", dir="/tmp") as raw:
        source, binding, lifecycle, policy = _small_linked_worktree_fixture(
            project, Path(raw), tmp_path / "state"
        )
        candidate = scan_candidates((policy,), lifecycle, now=int(time.time()))[0]
        monkeypatch.setattr(server_module, "_worktree_lifecycle_store", lambda: lifecycle)
        monkeypatch.setattr(
            server_module,
            "_read_native_agent_registry_read_only",
            lambda: ({"agents": {}, "sessions": {}, "reservations": {}}, "ready"),
        )
        monkeypatch.setattr(server_module, "retained_pin_session_ids", lambda _now: set())
        claim = server_module._claim_worktree_maintenance(binding, now=int(time.time()))
        with pytest.raises(
            MaintenanceError, match="maintenance_reference_inventory_unavailable"
        ):
            apply_candidate(
                candidate,
                lifecycle,
                policy=policy,
                claim=claim,
                now=int(time.time()),
            )
        assert source.exists()


def test_linked_worktree_archive_restores_after_original_cross_fs_fixture_is_removed(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    archive_root = project / ".hive-archive"
    with tempfile.TemporaryDirectory(prefix="hive-maintenance-source-", dir="/tmp") as raw:
        source_parent = Path(raw)
        origin = project / "origin"
        origin.mkdir()
        _git(origin, "init", "-q")
        _git(origin, "config", "user.email", "test@example.invalid")
        _git(origin, "config", "user.name", "Fixture")
        (origin / ".gitignore").write_text("ignored.dat\n")
        (origin / "tracked.txt").write_text("base\n")
        _git(origin, "add", ".")
        _git(origin, "commit", "-qm", "base")
        source = source_parent / "worktree"
        _git(origin, "worktree", "add", "-qb", "fixture", str(source))
        other_worktree = project / "other-worktree"
        _git(origin, "worktree", "add", "-qb", "other", str(other_worktree))
        (other_worktree / "other-only.txt").write_text("other worktree stays\n")
        _git(other_worktree, "add", "other-only.txt")
        other_status = _git(other_worktree, "status", "--porcelain")
        other_head = _git(other_worktree, "rev-parse", "HEAD")
        other_gitdir = (
            other_worktree
            / (other_worktree / ".git").read_text(encoding="utf-8").strip().removeprefix("gitdir: ")
        ).resolve(strict=True)
        attestation = HeadlessWriteScopeStore(tmp_path / "origin-evidence").create(
            "fixture", source.resolve(), source.resolve(), base_ref=None
        )
        common = Path(
            _git(source, "rev-parse", "--path-format=absolute", "--git-common-dir")
        )
        for root, label in ((source, b"worktree"), (common, b"common")):
            subprocess.run(
                ["setfacl", "-m", "u:65534:r-x", str(root)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            os.setxattr(root, "user.root-fixture", label)
        (source / "staged.txt").write_text("staged\n")
        _git(source, "add", "staged.txt")
        (source / "tracked.txt").write_text("unstaged\n")
        (source / "untracked.txt").write_text("untracked\n")
        (source / "ignored.dat").write_text("ignored\n")
        subprocess.run(
            ["setfacl", "-m", "u:65534:r--", str(source / "tracked.txt")],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.setxattr(source / "tracked.txt", "user.maintenance-fixture", b"preserved")
        (source / "tracked-link").symlink_to("tracked.txt")
        with (source / "sparse.dat").open("wb") as stream:
            stream.truncate(8 * 1024 * 1024)
            stream.seek(0)
            stream.write(b"head")
            stream.seek(7 * 1024 * 1024)
            stream.write(b"tail")
        _git(source, "config", "maintenance.fixture", "preserved")
        original_status = _git(source, "status", "--porcelain", "--untracked-files=all", "--ignored=matching")
        original_head = _git(source, "rev-parse", "HEAD")
        index_path = Path(_git(source, "rev-parse", "--path-format=absolute", "--git-path", "index"))
        if not index_path.is_absolute():
            index_path = source / index_path
        original_index = index_path.read_bytes()
        original_files = _file_snapshot(source)
        original_manifest = _tree_manifest(source, skip_git=True)
        original_common_manifest = _tree_manifest(common)
        original_root = source.stat()
        assert os.stat(source).st_dev != os.stat(project).st_dev

        binding = WorktreeBinding.from_creation_attestation(attestation)
        lifecycle = WorktreeLifecycleStore(HiveStateStore(tmp_path / "lifecycle-state"))
        lifecycle._record_created_worktree(binding, attestation)
        ended_at = int(time.time()) - 31 * 86400
        _finish_fixture_use(lifecycle, binding, now=ended_at)
        policy = ProjectPolicy(source, (source_parent, project), archive_root)
        candidate = scan_candidates((policy,), lifecycle, now=int(time.time()))[0]
        assert candidate.eligible
        assert candidate.binding == binding
        (source / "ignored.dat").write_text("changed after preview\n")
        with pytest.raises(MaintenanceError, match="candidate_stale_or_unbound"):
            _archive_candidate(candidate, policy=policy, lifecycle=lifecycle)
        assert not archive_root.exists()
        (source / "ignored.dat").write_text("ignored\n")
        original_manifest = _tree_manifest(source, skip_git=True)
        candidate = scan_candidates((policy,), lifecycle, now=int(time.time()))[0]
        assert candidate.eligible
        with patch(
            "the_hive.maintenance.shutil.disk_usage",
            return_value=SimpleNamespace(total=1, used=1, free=0),
        ):
            with pytest.raises(MaintenanceError, match="archive_space_unavailable"):
                _archive_candidate(candidate, policy=policy, lifecycle=lifecycle)
        assert not archive_root.exists()
        candidate = scan_candidates((policy,), lifecycle, now=int(time.time()))[0]
        gitdir_text = (source / ".git").read_text(encoding="utf-8").strip()
        gitdir = (source / gitdir_text.removeprefix("gitdir: ")).resolve(strict=True)
        swapped_gitdir = gitdir.with_name("fixture-swapped")
        gitdir.rename(swapped_gitdir)
        assert not scan_candidates((policy,), lifecycle, now=int(time.time()))[0].eligible
        swapped_gitdir.rename(gitdir)
        swapped_source = source.with_name("worktree-swapped")
        source.rename(swapped_source)
        with pytest.raises(WorktreeLifecycleError):
            lifecycle.claim_maintenance(binding, now=int(time.time()))
        assert not source.exists()
        swapped_source.rename(source)
        candidate = scan_candidates((policy,), lifecycle, now=int(time.time()))[0]
        assert candidate.eligible
        receipt = _archive_candidate(candidate, policy=policy, lifecycle=lifecycle)
        assert receipt.entry_count > 0
        assert receipt.archive.is_dir()
        assert list(archive_root.iterdir()) == [receipt.archive]
        assert source.is_dir()
        assert other_worktree.is_dir()
        assert _git(other_worktree, "status", "--porcelain") == other_status
        assert _git(other_worktree, "rev-parse", "HEAD") == other_head
        assert other_gitdir.is_dir()
        assert (common / "objects").is_dir()
        assert lifecycle.snapshot().maintenance_claims == ()
        context = multiprocessing.get_context("fork")
        results = context.Queue()
        restores = [
            context.Process(
                target=_restore_worker,
                args=(receipt, project / f"parallel-restore-{index}", results),
            )
            for index in range(2)
        ]
        for process in restores:
            process.start()
        restored_paths = [results.get() for _ in restores]
        for process in restores:
            process.join()
            assert process.exitcode == 0
        assert set(restored_paths) == {
            (project / "parallel-restore-0" / "worktree").as_posix(),
            (project / "parallel-restore-1" / "worktree").as_posix(),
        }
        denied_restore = project / "restore-no-space"
        with patch(
            "the_hive.maintenance.shutil.disk_usage",
            return_value=SimpleNamespace(total=1, used=1, free=0),
        ):
            with pytest.raises(MaintenanceError, match="restore_space_unavailable"):
                restore_archive(receipt, denied_restore)
        assert not denied_restore.exists()

        _git(origin, "worktree", "remove", "--force", str(other_worktree))
        shutil.rmtree(origin)
        restored_bundle = project / "restored-bundle"
        destination = restore_archive(receipt, restored_bundle)
        assert {path.name for path in restored_bundle.iterdir()} == {"worktree", "git-common"}
        assert not list(project.glob(".restored-bundle.git-common-*"))

        restored_index_path = Path(_git(destination, "rev-parse", "--path-format=absolute", "--git-path", "index"))
        if not restored_index_path.is_absolute():
            restored_index_path = destination / restored_index_path
        assert restored_index_path.read_bytes() == original_index
        restored_root = destination.stat()
        assert restored_root.st_mode & 0o7777 == original_root.st_mode & 0o7777
        assert restored_root.st_mtime_ns == original_root.st_mtime_ns
        assert _git(destination, "status", "--porcelain", "--untracked-files=all", "--ignored=matching") == original_status
        assert _git(destination, "rev-parse", "HEAD") == original_head
        assert _git(destination, "config", "maintenance.fixture") == "preserved"
        assert _tree_manifest(destination, skip_git=True) == original_manifest
        restored_common_fd = os.open(
            restored_bundle / "git-common", os.O_RDONLY | os.O_DIRECTORY
        )
        try:
            _verify_root_metadata(restored_common_fd, original_common_manifest[0])
        finally:
            os.close(restored_common_fd)
        assert {
            path: value
            for path, value in _file_snapshot(destination).items()
            if path != ".git" and not path.startswith(".hive-git-common/")
        } == {path: value for path, value in original_files.items() if path != ".git"}
