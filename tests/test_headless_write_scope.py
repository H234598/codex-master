from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codex_master.headless_write_scope import (
    HeadlessWriteScopeFailure,
    HeadlessWriteScopeStore,
)


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.email", "test@example.invalid")
    _git(repository, "config", "user.name", "Headless Test")
    (repository / "README.md").write_text("baseline\n", encoding="utf-8")
    _git(repository, "add", "README.md")
    _git(repository, "commit", "--quiet", "-m", "baseline")
    worktree = repository / ".codex-master-worktrees" / "worktree"
    worktree.parent.mkdir()
    _git(repository, "worktree", "add", "--quiet", "-b", "agent-a", str(worktree))
    return repository, worktree


def test_clean_attestation_binds_and_attributes_allowed_file(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")

    attestation = store.create("a", repository, worktree, base_ref=None)
    assert attestation.lifecycle == "available"
    assert attestation.baseline_commit == _git(worktree, "rev-parse", "HEAD").strip()

    binding = store.bind(
        "a",
        repository,
        ["src/new.py"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    assert binding.worktree_path == worktree.resolve()
    store.revalidate(binding, repository, provider_generation=4)

    (worktree / "src").mkdir()
    (worktree / "src" / "new.py").write_text("new\n", encoding="utf-8")
    result = store.finalize(binding)

    assert result.ok is True
    assert result.code == "ok"
    assert result.changed_count == 1
    assert store.read(attestation.attestation_id).lifecycle == "consumed"


def test_missing_attestation_keeps_headless_write_fail_closed(tmp_path: Path) -> None:
    repository, _worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_write_scope_unenforced") as exc_info:
        store.bind(
            "a",
            repository,
            ["src/new.py"],
            assignment_id="assignment-1",
            provider_generation=4,
        )

    assert exc_info.value.code == "headless_write_scope_unenforced"


def test_directory_declaration_attributes_nested_changes(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    (worktree / "src").mkdir()
    store = HeadlessWriteScopeStore(tmp_path / "state")
    attestation = store.create("a", repository, worktree, base_ref=None)

    binding = store.bind(
        "a",
        repository,
        ["src"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    assert binding.declared_write_paths == (("src", True),)
    (worktree / "src" / "nested.py").write_text("nested\n", encoding="utf-8")

    assert store.finalize(binding).ok is True
    assert store.read(attestation.attestation_id).lifecycle == "consumed"


@pytest.mark.parametrize("write_path", ["../escape.py", "/tmp/escape.py", "src/../escape.py", "src//file.py", "."])
def test_declared_write_path_rejects_ambiguous_or_absolute_target(
    tmp_path: Path, write_path: str
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_write_path_invalid") as exc_info:
        store.bind(
            "a",
            repository,
            [write_path],
            assignment_id="assignment-1",
            provider_generation=4,
        )

    assert exc_info.value.code == "headless_write_path_invalid"


@pytest.mark.parametrize("base_ref", ["-c", "origin/main branch", "origin/main\x00"])
def test_creation_rejects_unsafe_base_ref(tmp_path: Path, base_ref: str) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.create("a", repository, worktree, base_ref=base_ref)


def test_declared_write_path_rejects_symlink_traversal(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (worktree / "link").symlink_to(outside, target_is_directory=True)
    _git(worktree, "add", "link")
    _git(worktree, "commit", "--quiet", "-m", "tracked symlink")
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_write_path_invalid"):
        store.bind(
            "a",
            repository,
            ["link/new.py"],
            assignment_id="assignment-1",
            provider_generation=4,
        )


@pytest.mark.parametrize("dirty_kind", ["tracked", "untracked"])
def test_dirty_worktree_rejects_assignment_before_binding(
    tmp_path: Path, dirty_kind: str
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    if dirty_kind == "tracked":
        (worktree / "README.md").write_text("changed\n", encoding="utf-8")
    else:
        (worktree / "untracked.txt").write_text("untracked\n", encoding="utf-8")

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_worktree_dirty"):
        store.bind(
            "a",
            repository,
            ["src/new.py"],
            assignment_id="assignment-1",
            provider_generation=4,
        )


def test_provider_generation_change_rejects_revalidation(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["src/new.py"],
        assignment_id="assignment-1",
        provider_generation=4,
    )

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_assignment_generation_changed"):
        store.revalidate(binding, repository, provider_generation=5)


def test_repository_identity_change_rejects_binding(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    other_repository, _other_worktree = _repository(tmp_path / "other")
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.bind(
            "a",
            other_repository,
            ["src/new.py"],
            assignment_id="assignment-1",
            provider_generation=4,
        )


def test_out_of_scope_tracked_and_untracked_changes_fail_closed(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["src/allowed.py"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    (worktree / "src").mkdir()
    (worktree / "src" / "allowed.py").write_text("allowed\n", encoding="utf-8")
    (worktree / "outside.py").write_text("outside\n", encoding="utf-8")

    result = store.finalize(binding)

    assert result.ok is False
    assert result.code == "headless_write_scope_violation"
    assert result.changed_count == 2
    assert result.out_of_scope_count == 1
    assert store.read(binding.attestation_id).lifecycle == "consumed"


def test_rename_requires_attribution_of_both_paths(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md", "RENAMED.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    _git(worktree, "mv", "README.md", "RENAMED.md")

    result = store.finalize(binding)

    assert result.ok is True
    assert result.changed_count == 2


def test_revalidation_rejects_branch_change(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["src/new.py"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    _git(worktree, "checkout", "--quiet", "-b", "changed")

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.revalidate(binding, repository, provider_generation=4)


def test_finalize_rejects_worktree_filesystem_identity_swap(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["src/new.py"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    moved = worktree.with_name("moved-worktree")
    worktree.rename(moved)
    worktree.symlink_to(moved, target_is_directory=True)

    result = store.finalize(binding)

    assert result.ok is False
    assert result.code == "headless_attestation_invalid"
    assert store.read(binding.attestation_id).lifecycle == "consumed"


def test_finalize_rejects_declared_directory_type_change(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    (worktree / "src").mkdir()
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["src"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    (worktree / "src").rmdir()
    (worktree / "src").write_text("not a directory\n", encoding="utf-8")

    result = store.finalize(binding)

    assert result.ok is False
    assert result.code == "headless_attestation_invalid"
    assert store.read(binding.attestation_id).lifecycle == "consumed"


def test_finalize_rejects_malformed_git_status_and_consumes_attestation(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    real_store = HeadlessWriteScopeStore(tmp_path / "state")
    real_store.create("a", repository, worktree, base_ref=None)
    binding = real_store.bind(
        "a",
        repository,
        ["src/new.py"],
        assignment_id="assignment-1",
        provider_generation=4,
    )

    def malformed_status(args: list[str], *, cwd: Path, timeout: float) -> subprocess.CompletedProcess[str]:
        if len(args) > 1 and args[1] == "status":
            return subprocess.CompletedProcess(args, 0, "not porcelain", "")
        return _git_process(args, cwd, timeout)

    store = HeadlessWriteScopeStore(tmp_path / "state", git_runner=malformed_status)
    result = store.finalize(binding)

    assert result.ok is False
    assert result.code == "headless_write_attribution_unverified"
    assert store.read(binding.attestation_id).lifecycle == "consumed"


def test_finalize_rejects_unresolved_git_conflict_and_consumes_attestation(
    tmp_path: Path,
) -> None:
    repository, worktree = _repository(tmp_path)
    real_store = HeadlessWriteScopeStore(tmp_path / "state")
    real_store.create("a", repository, worktree, base_ref=None)
    binding = real_store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )

    def conflict_status(
        args: list[str], *, cwd: Path, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        if len(args) > 1 and args[1] == "status":
            return subprocess.CompletedProcess(args, 0, "UU README.md\0", "")
        return _git_process(args, cwd, timeout)

    store = HeadlessWriteScopeStore(tmp_path / "state", git_runner=conflict_status)
    result = store.finalize(binding)

    assert result.ok is False
    assert result.code == "headless_write_attribution_unverified"
    assert store.read(binding.attestation_id).lifecycle == "consumed"


def _git_process(args: list[str], cwd: Path, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_second_unused_attestation_for_same_agent_is_ambiguous(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    store.create("a", repository, worktree, base_ref=None)

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_ambiguous"):
        store.bind(
            "a",
            repository,
            ["src/new.py"],
            assignment_id="assignment-1",
            provider_generation=4,
        )


def test_malformed_persisted_attestation_fails_closed(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    attestation = store.create("a", repository, worktree, base_ref=None)
    record_path = tmp_path / "state" / f"attestation-{attestation.attestation_id}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["declared_write_paths"] = [["src", "yes"]]
    record_path.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.read(attestation.attestation_id)


def test_repository_common_git_identity_is_rechecked_at_binding(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    attestation = store.create("a", repository, worktree, base_ref=None)
    alternate_common = tmp_path / "alternate-common"
    alternate_common.mkdir()
    record_path = tmp_path / "state" / f"attestation-{attestation.attestation_id}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["common_git_dir"] = str(alternate_common)
    record_path.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.bind(
            "a",
            repository,
            ["src/new.py"],
            assignment_id="assignment-1",
            provider_generation=4,
        )
