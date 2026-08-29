from __future__ import annotations

import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
import threading

import pytest

import codex_master.headless_write_scope as headless_write_scope
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


def test_git_verification_does_not_inherit_config_override_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, worktree = _repository(tmp_path)
    captured: dict[str, str] = {}

    def recording_runner(
        args: list[str],
        *,
        cwd: Path,
        timeout: float,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if env is not None:
            captured.update(env)
        return _git_process(args, cwd, timeout, env=env)

    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/tmp/attacker-global-config")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/tmp/attacker-system-config")
    store = HeadlessWriteScopeStore(
        tmp_path / "state", git_runner=recording_runner
    )

    store.create("a", repository, worktree, base_ref=None)

    assert "GIT_CONFIG_GLOBAL" not in captured
    assert "GIT_CONFIG_SYSTEM" not in captured
    assert captured["GIT_CONFIG_NOGLOBAL"] == "1"
    assert captured["GIT_CONFIG_NOSYSTEM"] == "1"
    assert captured["GIT_NO_REPLACE_OBJECTS"] == "1"


def test_git_verification_rejects_boolean_returncode(tmp_path: Path) -> None:
    _repository(tmp_path)

    def malformed_runner(
        args: list[str],
        *,
        cwd: Path,
        timeout: float,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, timeout, env
        return subprocess.CompletedProcess(args, False, "", "")

    store = HeadlessWriteScopeStore(
        tmp_path / "state", git_runner=malformed_runner
    )

    with pytest.raises(
        HeadlessWriteScopeFailure,
        match="headless_write_attribution_unverified",
    ) as raised:
        store._git(["rev-parse", "--verify", "HEAD^{commit}"], tmp_path)

    assert raised.value.code == "headless_write_attribution_unverified"


def test_creation_rejects_non_normal_index_flag(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)

    def non_normal_index(
        args: list[str],
        *,
        cwd: Path,
        timeout: float,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if len(args) > 1 and args[1] == "ls-files":
            return subprocess.CompletedProcess(args, 0, "M README.md\0", "")
        return _git_process(args, cwd, timeout, env=env)

    store = HeadlessWriteScopeStore(tmp_path / "state", git_runner=non_normal_index)

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.create("a", repository, worktree, base_ref=None)


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


def test_revalidation_rejects_binding_worktree_tampering(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    alternate = tmp_path / "alternate-worktree"
    _git(repository, "worktree", "add", "--quiet", "-b", "alternate", str(alternate))
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["src/new.py"],
        assignment_id="assignment-1",
        provider_generation=4,
    )

    tampered = replace(binding, worktree_path=alternate)

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.revalidate(tampered, repository, provider_generation=4)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attestation_id", "0" * 32),
        ("agent_id", "other-agent"),
        ("assignment_id", "other-assignment"),
        ("repository_root", Path("/tmp/other-repository")),
        ("worktree_path", Path("/tmp/other-worktree")),
        ("baseline_commit", "1" * 40),
        ("provider_generation", 5),
        ("declared_write_paths", (("other.py", False),)),
    ],
)
def test_revalidation_rejects_every_binding_identity_field_tampering(
    tmp_path: Path, field: str, value: object
) -> None:
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

    tampered = replace(binding, **{field: value})

    with pytest.raises(HeadlessWriteScopeFailure):
        store.revalidate(tampered, repository, provider_generation=4)


@pytest.mark.parametrize(
    "field",
    [
        "worktree_device",
        "worktree_inode",
        "common_git_dir",
        "common_git_device",
        "common_git_inode",
        "branch",
        "detached",
        "requested_base_ref",
        "creation_generation",
        "created_at_utc",
    ],
)
def test_revalidation_rejects_every_persisted_worktree_field_tampering(
    tmp_path: Path, field: str
) -> None:
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
    replacements: dict[str, object] = {
        "worktree_device": binding.worktree_device + 1,
        "worktree_inode": binding.worktree_inode + 1,
        "common_git_dir": binding.common_git_dir / "changed",
        "common_git_device": binding.common_git_device + 1,
        "common_git_inode": binding.common_git_inode + 1,
        "branch": "changed-branch",
        "detached": not binding.detached,
        "requested_base_ref": "changed-ref",
        "creation_generation": "changed-generation",
        "created_at_utc": "2000-01-01T00:00:00+00:00",
    }
    tampered = replace(binding, **{field: replacements[field]})

    with pytest.raises(HeadlessWriteScopeFailure):
        store.revalidate(tampered, repository, provider_generation=4)


@pytest.mark.parametrize("field", ["history_reflog_count", "history_reflog_digest", "history_reflog_anchor"])
def test_revalidation_rejects_history_evidence_binding_tampering(
    tmp_path: Path, field: str
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    replacements: dict[str, object] = {
        "history_reflog_count": binding.history_reflog_count + 1,
        "history_reflog_digest": "0" * 64,
        "history_reflog_anchor": "tampered",
    }

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.revalidate(
            replace(binding, **{field: replacements[field]}),
            repository,
            provider_generation=4,
        )


def test_revalidation_rejects_persisted_index_evidence_tampering(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.revalidate(
            replace(binding, index_flags=(("README.md", "h"),)),
            repository,
            provider_generation=4,
        )


def test_revalidation_rejects_injected_persisted_index_path(
    tmp_path: Path,
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    attestation = store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    record_path = tmp_path / "state" / f"attestation-{attestation.attestation_id}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["index_flags"].append(["injected.py", "H"])
    record_path.write_text(json.dumps(record), encoding="utf-8")
    tampered = replace(
        binding,
        index_flags=binding.index_flags + (("injected.py", "H"),),
    )

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.revalidate(tampered, repository, provider_generation=4)


def test_revalidation_rejects_persisted_git_metadata_evidence_tampering(
    tmp_path: Path,
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.revalidate(
            replace(binding, git_metadata_digest="0" * 64),
            repository,
            provider_generation=4,
        )


def test_expired_available_attestation_is_not_bindable(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    attestation = store.create("a", repository, worktree, base_ref=None)
    record_path = tmp_path / "state" / f"attestation-{attestation.attestation_id}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["created_at_utc"] = "2000-01-01T00:00:00+00:00"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    assert store.has_available("a") is False
    assert store.read(attestation.attestation_id).lifecycle == "consumed"


def test_ttl_does_not_consume_bound_attestation(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    attestation = store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["src/new.py"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    record_path = tmp_path / "state" / f"attestation-{attestation.attestation_id}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["created_at_utc"] = "2000-01-01T00:00:00+00:00"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    assert store.read(binding.attestation_id).lifecycle == "bound"


def test_cumulative_serialized_write_path_size_is_bounded(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    write_paths = [
        f"p{index:03d}/" + "/".join("x" * 220 for _ in range(3))
        for index in range(100)
    ]

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_write_path_invalid"):
        store.bind(
            "a",
            repository,
            write_paths,
            assignment_id="assignment-1",
            provider_generation=4,
        )


def test_attestation_record_requires_private_single_link_owner_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    attestation = store.create("a", repository, worktree, base_ref=None)
    record_path = tmp_path / "state" / f"attestation-{attestation.attestation_id}.json"

    record_path.chmod(0o644)
    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.read(attestation.attestation_id)

    record_path.chmod(0o600)
    hardlink = tmp_path / "state" / "attestation-hardlink.json"
    os.link(record_path, hardlink)
    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.read(attestation.attestation_id)

    actual_owner = record_path.stat().st_uid
    monkeypatch.setattr(headless_write_scope.os, "getuid", lambda: actual_owner + 1)
    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.read(attestation.attestation_id)


def test_attestation_lock_requires_private_single_link_owner_file(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    attestation = store.create("a", repository, worktree, base_ref=None)
    lock_path = tmp_path / "state" / "store.lock"

    lock_path.chmod(0o644)
    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.read(attestation.attestation_id)

    lock_path.chmod(0o600)
    hardlink = tmp_path / "state" / "lock-hardlink"
    os.link(lock_path, hardlink)
    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.read(attestation.attestation_id)


def test_attestation_state_permission_failure_is_not_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")

    def deny_chmod(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("chmod denied")

    monkeypatch.setattr(headless_write_scope.os, "chmod", deny_chmod)
    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.create("a", repository, worktree, base_ref=None)


def test_existing_unsafe_journal_directory_mode_is_not_silently_fixed(
    tmp_path: Path,
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    attestation = store.create("a", repository, worktree, base_ref=None)
    state_root = tmp_path / "state"
    state_root.chmod(0o755)

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.read(attestation.attestation_id)

    assert state_root.stat().st_mode & 0o777 == 0o755


def test_record_owner_failure_isolated_from_journal_directory_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    attestation = store.create("a", repository, worktree, base_ref=None)
    store._ensure_state_dir()
    monkeypatch.setattr(store, "_ensure_state_dir", lambda: None)
    monkeypatch.setattr(store, "_verify_journal_directory_fd", lambda _fd: None)
    monkeypatch.setattr(store, "_verify_journal_regular_fd", lambda *_args: None)
    actual_owner = (tmp_path / "state" / f"attestation-{attestation.attestation_id}.json").stat().st_uid
    monkeypatch.setattr(headless_write_scope.os, "getuid", lambda: actual_owner + 1)

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.read(attestation.attestation_id)


def test_lock_owner_failure_isolated_from_record_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    attestation = store.create("a", repository, worktree, base_ref=None)
    store._ensure_state_dir()
    monkeypatch.setattr(store, "_ensure_state_dir", lambda: None)
    monkeypatch.setattr(store, "_verify_journal_directory_fd", lambda _fd: None)
    actual_owner = (tmp_path / "state" / "store.lock").stat().st_uid
    monkeypatch.setattr(headless_write_scope.os, "getuid", lambda: actual_owner + 1)

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.read(attestation.attestation_id)


def test_journal_directory_owner_failure_isolated_from_ensure_state_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    store._ensure_state_dir()
    monkeypatch.setattr(store, "_ensure_state_dir", lambda: None)
    actual_owner = store.state_root.stat().st_uid
    monkeypatch.setattr(headless_write_scope.os, "getuid", lambda: actual_owner + 1)

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.read("0" * 32)


def test_journal_record_listing_uses_pinned_directory_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    original_glob = Path.glob

    def reject_path_listing(path: Path, pattern: str):
        if path == store.state_root:
            raise AssertionError("journal listing escaped its pinned directory fd")
        return original_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", reject_path_listing)

    assert store.has_available("a") is True


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


@pytest.mark.parametrize("field", ["repository_device", "repository_inode"])
def test_revalidation_rejects_repository_identity_binding_tampering(
    tmp_path: Path, field: str
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    replacement = getattr(binding, field) + 1

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.revalidate(
            replace(binding, **{field: replacement}),
            repository,
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


def test_finalize_attributes_allowed_worker_commit(tmp_path: Path) -> None:
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
    (worktree / "src").mkdir()
    (worktree / "src" / "new.py").write_text("committed\n", encoding="utf-8")
    _git(worktree, "add", "src/new.py")
    _git(worktree, "commit", "--quiet", "-m", "worker result")

    result = store.finalize(binding)

    assert result.ok is True
    assert result.code == "ok"
    assert result.changed_count == 1


def test_finalize_attributes_both_paths_of_committed_rename(tmp_path: Path) -> None:
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
    _git(worktree, "commit", "--quiet", "-m", "worker rename")

    result = store.finalize(binding)

    assert result.ok is True
    assert result.changed_count == 2


def test_finalize_attributes_both_paths_of_committed_copy(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md", "COPIED.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    subprocess.run(
        ("cp", "README.md", "COPIED.md"),
        cwd=worktree,
        check=True,
        capture_output=True,
        text=True,
    )
    _git(worktree, "add", "COPIED.md")
    _git(worktree, "commit", "--quiet", "-m", "worker copy")

    result = store.finalize(binding)

    assert result.ok is True
    assert result.changed_count == 2


def test_finalize_rejects_committed_out_of_scope_change_even_after_revert(
    tmp_path: Path,
) -> None:
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
    (worktree / "outside.py").write_text("outside\n", encoding="utf-8")
    _git(worktree, "add", "outside.py")
    _git(worktree, "commit", "--quiet", "-m", "out of scope")
    _git(worktree, "revert", "--quiet", "--no-edit", "HEAD")

    result = store.finalize(binding)

    assert result.ok is False
    assert result.code == "headless_write_scope_violation"
    assert result.out_of_scope_count == 1


def test_finalize_rejects_out_of_scope_commit_then_reset_to_baseline(
    tmp_path: Path,
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    (worktree / "outside.py").write_text("outside\n", encoding="utf-8")
    _git(worktree, "add", "outside.py")
    _git(worktree, "commit", "--quiet", "-m", "out of scope")
    _git(worktree, "reset", "--hard", binding.baseline_commit)

    result = store.finalize(binding)

    assert result.ok is False
    assert result.code in {
        "headless_attestation_invalid",
        "headless_write_attribution_unverified",
    }


def test_finalize_attributes_allowed_commit_and_regular_revert(
    tmp_path: Path,
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    (worktree / "README.md").write_text("worker change\n", encoding="utf-8")
    _git(worktree, "add", "README.md")
    _git(worktree, "commit", "--quiet", "-m", "allowed change")
    _git(worktree, "revert", "--no-edit", "HEAD")

    result = store.finalize(binding)

    assert result.ok is True
    assert result.code == "ok"
    assert result.changed_count == 1


def test_finalize_rejects_git_replace_that_hides_malicious_commit(
    tmp_path: Path,
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    (worktree / "outside.py").write_text("outside\n", encoding="utf-8")
    _git(worktree, "add", "outside.py")
    _git(worktree, "commit", "--quiet", "-m", "malicious commit")
    malicious = _git(worktree, "rev-parse", "HEAD").strip()
    baseline_tree = _git(worktree, "rev-parse", f"{binding.baseline_commit}^{{tree}}").strip()
    harmless = subprocess.run(
        [
            "git",
            "commit-tree",
            baseline_tree,
            "-p",
            binding.baseline_commit,
            "-m",
            "harmless replacement",
        ],
        cwd=worktree,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    _git(worktree, "replace", malicious, harmless)

    result = store.finalize(binding)

    assert result.ok is False
    assert result.code in {
        "headless_attestation_invalid",
        "headless_write_attribution_unverified",
    }


def test_creation_rejects_graft_metadata(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    grafts = Path(_git(worktree, "rev-parse", "--git-path", "info/grafts").strip())
    if not grafts.is_absolute():
        grafts = worktree / grafts
    grafts.parent.mkdir(parents=True, exist_ok=True)
    grafts.write_text("", encoding="utf-8")
    store = HeadlessWriteScopeStore(tmp_path / "state")

    with pytest.raises(HeadlessWriteScopeFailure) as raised:
        store.create("a", repository, worktree, base_ref=None)

    assert raised.value.code in {
        "headless_attestation_invalid",
        "headless_write_attribution_unverified",
    }


@pytest.mark.parametrize("index_flag", ["--assume-unchanged", "--skip-worktree"])
def test_finalize_rejects_index_flag_hiding_tracked_change(
    tmp_path: Path, index_flag: str
) -> None:
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
    (worktree / "README.md").write_text("hidden out of scope\n", encoding="utf-8")
    _git(worktree, "update-index", index_flag, "README.md")

    result = store.finalize(binding)

    assert result.ok is False
    assert result.code in {
        "headless_attestation_invalid",
        "headless_write_attribution_unverified",
    }


def test_finalize_rejects_ignore_metadata_change_hiding_untracked_file(
    tmp_path: Path,
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    exclude_path = Path(_git(worktree, "rev-parse", "--git-path", "info/exclude").strip())
    if not exclude_path.is_absolute():
        exclude_path = worktree / exclude_path
    exclude_path.parent.mkdir(parents=True, exist_ok=True)
    exclude_path.write_text("outside.py\n", encoding="utf-8")
    (worktree / "outside.py").write_text("hidden\n", encoding="utf-8")

    result = store.finalize(binding)

    assert result.ok is False
    assert result.code in {
        "headless_attestation_invalid",
        "headless_write_attribution_unverified",
    }


@pytest.mark.parametrize(
    ("config_key", "config_value"),
    [("core.fsmonitor", "true"), ("core.sparseCheckout", "true")],
)
def test_finalize_rejects_attribution_relevant_git_config_change(
    tmp_path: Path, config_key: str, config_value: str
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    _git(worktree, "config", config_key, config_value)

    result = store.finalize(binding)

    assert result.ok is False
    assert result.code == "headless_attestation_invalid"


def test_preexisting_ignore_metadata_is_attested_and_allowed(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    exclude_path = Path(_git(worktree, "rev-parse", "--git-path", "info/exclude").strip())
    if not exclude_path.is_absolute():
        exclude_path = worktree / exclude_path
    exclude_path.parent.mkdir(parents=True, exist_ok=True)
    exclude_path.write_text("preexisting.txt\n", encoding="utf-8")
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )

    result = store.finalize(binding)

    assert result.ok is True


def test_finalize_rejects_changed_external_excludes_file(
    tmp_path: Path,
) -> None:
    repository, worktree = _repository(tmp_path)
    excludes = tmp_path / "external-excludes"
    excludes.write_text("\n", encoding="utf-8")
    _git(worktree, "config", "core.excludesFile", str(excludes))
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    excludes.write_text("outside.py\n", encoding="utf-8")
    (worktree / "outside.py").write_text("hidden\n", encoding="utf-8")

    result = store.finalize(binding)

    assert result.ok is False
    assert result.code in {
        "headless_attestation_invalid",
        "headless_write_attribution_unverified",
    }


def test_creation_rejects_active_local_config_include(
    tmp_path: Path,
) -> None:
    repository, worktree = _repository(tmp_path)
    included = tmp_path / "included.gitconfig"
    included.write_text("[core]\n\texcludesFile = ignored\n", encoding="utf-8")
    _git(worktree, "config", "include.path", str(included))
    store = HeadlessWriteScopeStore(tmp_path / "state")

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_invalid"):
        store.create("a", repository, worktree, base_ref=None)


def test_finalize_rejects_history_rewrite_with_foreign_baseline(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    tree = _git(worktree, "rev-parse", "HEAD^{tree}").strip()
    unrelated = subprocess.run(
        ["git", "commit-tree", tree, "-m", "foreign history"],
        cwd=worktree,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    _git(worktree, "reset", "--hard", unrelated)

    result = store.finalize(binding)

    assert result.ok is False
    assert result.code == "headless_attestation_invalid"


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

    def malformed_status(
        args: list[str], *, cwd: Path, timeout: float, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        if len(args) > 1 and args[1] == "status":
            return subprocess.CompletedProcess(args, 0, "not porcelain", "")
        return _git_process(args, cwd, timeout, env=env)

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
        args: list[str], *, cwd: Path, timeout: float, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        if len(args) > 1 and args[1] == "status":
            return subprocess.CompletedProcess(args, 0, "UU README.md\0", "")
        return _git_process(args, cwd, timeout, env=env)

    store = HeadlessWriteScopeStore(tmp_path / "state", git_runner=conflict_status)
    result = store.finalize(binding)

    assert result.ok is False
    assert result.code == "headless_write_attribution_unverified"
    assert store.read(binding.attestation_id).lifecycle == "consumed"


@pytest.mark.parametrize("conflict_code", ["DD", "AU", "UD", "UA", "DU", "AA", "UU"])
def test_finalize_rejects_every_unmerged_porcelain_state(
    tmp_path: Path, conflict_code: str
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
        args: list[str], *, cwd: Path, timeout: float, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        if len(args) > 1 and args[1] == "status":
            return subprocess.CompletedProcess(args, 0, f"{conflict_code} README.md\0", "")
        return _git_process(args, cwd, timeout, env=env)

    store = HeadlessWriteScopeStore(tmp_path / "state", git_runner=conflict_status)
    result = store.finalize(binding)

    assert result.ok is False
    assert result.code == "headless_write_attribution_unverified"


def _git_process(
    args: list[str],
    cwd: Path,
    timeout: float,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def test_second_active_attestation_for_same_agent_is_rejected(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_attestation_active"):
        store.create("a", repository, worktree, base_ref=None)


def test_consumed_attestation_cannot_be_reused(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    binding = store.bind(
        "a",
        repository,
        ["README.md"],
        assignment_id="assignment-1",
        provider_generation=4,
    )
    assert store.finalize(binding).ok is True

    with pytest.raises(HeadlessWriteScopeFailure, match="headless_write_scope_unenforced"):
        store.bind(
            "a",
            repository,
            ["README.md"],
            assignment_id="assignment-2",
            provider_generation=4,
        )


def test_concurrent_bind_has_exactly_one_winner(tmp_path: Path) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    store.create("a", repository, worktree, base_ref=None)
    barrier = threading.Barrier(2)
    bindings: list[object] = []
    failures: list[HeadlessWriteScopeFailure] = []

    def bind(index: int) -> None:
        barrier.wait()
        try:
            bindings.append(
                store.bind(
                    "a",
                    repository,
                    ["src/new.py"],
                    assignment_id=f"assignment-{index}",
                    provider_generation=4,
                )
            )
        except HeadlessWriteScopeFailure as exc:
            failures.append(exc)

    threads = [threading.Thread(target=bind, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(bindings) == 1
    assert len(failures) == 1
    assert failures[0].code == "headless_write_scope_unenforced"


def test_pruning_removes_old_terminal_records_but_keeps_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    for index in range(3):
        store.create("a", repository, worktree, base_ref=None)
        binding = store.bind(
            "a",
            repository,
            ["README.md"],
            assignment_id=f"assignment-{index}",
            provider_generation=4,
        )
        assert store.finalize(binding).ok is True
    available = store.create("a", repository, worktree, base_ref=None)
    monkeypatch.setattr(headless_write_scope, "MAX_RECORDS", 2)

    assert store.has_available("a") is True
    assert store.read(available.attestation_id).lifecycle == "available"
    assert len(list((tmp_path / "state").glob("attestation-*.json"))) == 2


def test_create_prunes_terminal_records_before_new_record(tmp_path: Path, monkeypatch) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    monkeypatch.setattr(headless_write_scope, "MAX_RECORDS", 2)

    for index in range(2):
        store.create("a", repository, worktree, base_ref=None)
        binding = store.bind(
            "a",
            repository,
            ["README.md"],
            assignment_id=f"assignment-{index}",
            provider_generation=4,
        )
        assert store.finalize(binding).ok is True

    store.create("a", repository, worktree, base_ref=None)

    assert len(list((tmp_path / "state").glob("attestation-*.json"))) == 2


def test_create_cleans_expired_available_record_before_pruning(
    tmp_path: Path, monkeypatch
) -> None:
    repository, worktree = _repository(tmp_path)
    store = HeadlessWriteScopeStore(tmp_path / "state")
    monkeypatch.setattr(headless_write_scope, "MAX_RECORDS", 1)
    expired = store.create("a", repository, worktree, base_ref=None)
    record_path = tmp_path / "state" / f"attestation-{expired.attestation_id}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["created_at_utc"] = "2000-01-01T00:00:00+00:00"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    replacement = store.create("a", repository, worktree, base_ref=None)

    assert replacement.attestation_id != expired.attestation_id
    assert len(list((tmp_path / "state").glob("attestation-*.json"))) == 1


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
