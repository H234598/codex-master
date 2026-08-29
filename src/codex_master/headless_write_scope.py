"""Attested, agent-bound write boundaries for headless worktree runs.

This module owns the small trust boundary needed between Masterjet assignment
and a headless process.  It deliberately has no server imports: Git/process
access is injected so the boundary can be tested without a live MCP.
"""

from __future__ import annotations

from contextlib import contextmanager
import contextvars
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
from typing import Any, Callable, Iterator, Mapping


MAX_RECORD_BYTES = 64 * 1024
MAX_GIT_OUTPUT_BYTES = 256 * 1024
MAX_DECLARED_PATHS = 100
MAX_PATH_CHARS = 1000
MAX_ASSIGNMENT_ID_CHARS = 200
MAX_RECORDS = 256
MAX_RECORD_SCAN = MAX_RECORDS * 4
MAX_DECLARED_PATH_BYTES = 32 * 1024
ATTESTATION_TTL_SECONDS = 60 * 60
ATTESTATION_SCHEMA_VERSION = 2
MAX_HISTORY_REFLOG_ENTRIES = 128
MAX_HISTORY_REFLOG_BYTES = 64 * 1024
MAX_INDEX_EVIDENCE_ENTRIES = 8192
MAX_INDEX_EVIDENCE_BYTES = 32 * 1024
MAX_GIT_METADATA_BYTES = 64 * 1024
MAX_GIT_METADATA_FILE_BYTES = 16 * 1024
_ATTESTATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_GIT_OBJECT_ID_RE = re.compile(r"^[0-9a-f]{40,64}$")
_UNMERGED_PORCELAIN_STATES = {"DD", "AU", "UD", "UA", "DU", "AA", "UU"}


class HeadlessWriteScopeFailure(RuntimeError):
    """Expected, path-free failure at the headless write boundary."""

    def __init__(self, code: str, explanation: str, action: str) -> None:
        super().__init__(code)
        self.code = code
        self.explanation = explanation
        self.action = action


@dataclass(frozen=True)
class ScopeAttestation:
    attestation_id: str
    agent_id: str
    repository_root: Path
    repository_device: int
    repository_inode: int
    worktree_path: Path
    worktree_device: int
    worktree_inode: int
    common_git_dir: Path
    common_git_device: int
    common_git_inode: int
    branch: str | None
    detached: bool
    baseline_commit: str
    requested_base_ref: str | None
    creation_generation: str
    created_at_utc: str
    history_reflog_count: int
    history_reflog_digest: str
    history_reflog_anchor: str
    index_flags: tuple[tuple[str, str], ...]
    git_metadata_digest: str
    lifecycle: str
    assignment_id: str | None = None
    provider_generation: int | str | None = None
    declared_write_paths: tuple[tuple[str, bool], ...] = ()


@dataclass(frozen=True)
class ScopeBinding:
    attestation_id: str
    agent_id: str
    assignment_id: str
    repository_root: Path
    repository_device: int
    repository_inode: int
    worktree_path: Path
    baseline_commit: str
    provider_generation: int | str
    declared_write_paths: tuple[tuple[str, bool], ...]
    worktree_device: int
    worktree_inode: int
    common_git_dir: Path
    common_git_device: int
    common_git_inode: int
    branch: str | None
    detached: bool
    requested_base_ref: str | None
    creation_generation: str
    created_at_utc: str
    history_reflog_count: int
    history_reflog_digest: str
    history_reflog_anchor: str
    index_flags: tuple[tuple[str, str], ...]
    git_metadata_digest: str


@dataclass(frozen=True)
class ScopeResult:
    ok: bool
    code: str
    changed_count: int
    attributed_count: int
    out_of_scope_count: int


GitRunner = Callable[..., subprocess.CompletedProcess[str]]


def _default_git_runner(
    args: list[str],
    *,
    cwd: Path,
    timeout: float = 30,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=dict(env) if env is not None else None,
    )


class HeadlessWriteScopeStore:
    """Persist and consume one-time worktree attestations."""

    def __init__(
        self,
        state_root: Path,
        *,
        git_runner: GitRunner | None = None,
    ) -> None:
        self.state_root = Path(state_root).expanduser()
        if not self.state_root.is_absolute():
            self.state_root = Path.cwd() / self.state_root
        self.state_root = Path(os.path.abspath(self.state_root))
        self.git_runner = git_runner or _default_git_runner
        self._journal_state_fd: contextvars.ContextVar[int | None] = contextvars.ContextVar(
            "headless_write_scope_journal_state_fd", default=None
        )

    def create(
        self,
        agent_id: str,
        repository_root: Path,
        worktree_path: Path,
        *,
        base_ref: str | None,
    ) -> ScopeAttestation:
        agent_id = self._require_text(agent_id, "agent_id", 200)
        repository = self._real_directory(repository_root)
        worktree = self._real_directory(worktree_path)
        if not self._is_within(worktree, repository):
            raise self._failure(
                "headless_attestation_invalid",
                "worktree is outside the attested repository",
                "create a Masterjet-managed worktree inside the repository",
            )
        repo_identity = self._git_identity(repository)
        worktree_identity = self._git_identity(worktree)
        if repo_identity["top"] != repository or worktree_identity["top"] != worktree:
            raise self._failure(
                "headless_attestation_invalid",
                "Git repository root does not match the requested worktree",
                "recreate the worktree through Masterjet",
            )
        if repo_identity["common"] != worktree_identity["common"]:
            raise self._failure(
                "headless_attestation_invalid",
                "worktree is not attached to the requested Git repository",
                "recreate the worktree through Masterjet",
            )
        if worktree_identity["status"]:
            raise self._failure(
                "headless_worktree_dirty",
                "worktree is dirty at attestation creation",
                "use a clean Masterjet-created worktree",
            )
        if base_ref is not None:
            base_ref = self._require_text(base_ref, "base_ref", 200)
            if base_ref.startswith("-") or any(
                char.isspace() for char in base_ref
            ) or "\x00" in base_ref:
                raise self._failure(
                    "headless_attestation_invalid",
                    "requested baseline ref is unsafe",
                    "create the worktree from a plain Git ref or commit",
                )
            resolved_base = self._git_output(
                repository, ["rev-parse", "--verify", f"{base_ref}^{{commit}}"]
            )
            if resolved_base != worktree_identity["head"]:
                raise self._failure(
                    "headless_attestation_invalid",
                    "worktree HEAD does not equal the requested baseline",
                    "recreate the worktree from the requested baseline",
                )
        history_evidence = self._capture_history_evidence(
            worktree, worktree_identity["head"]
        )
        index_flags = self._capture_index_flags(worktree)
        git_metadata_digest = self._capture_git_metadata_digest(worktree)
        repository_info = repository.lstat()
        info = worktree.lstat()
        attestation = ScopeAttestation(
            attestation_id=secrets.token_hex(16),
            agent_id=agent_id,
            repository_root=repository,
            repository_device=int(repository_info.st_dev),
            repository_inode=int(repository_info.st_ino),
            worktree_path=worktree,
            worktree_device=int(info.st_dev),
            worktree_inode=int(info.st_ino),
            common_git_dir=worktree_identity["common"],
            common_git_device=worktree_identity["common_device"],
            common_git_inode=worktree_identity["common_inode"],
            branch=worktree_identity["branch"],
            detached=worktree_identity["branch"] is None,
            baseline_commit=worktree_identity["head"],
            requested_base_ref=base_ref,
            creation_generation=secrets.token_hex(16),
            created_at_utc=datetime.now(timezone.utc).isoformat(),
            history_reflog_count=history_evidence["count"],
            history_reflog_digest=history_evidence["digest"],
            history_reflog_anchor=history_evidence["anchor"],
            index_flags=index_flags,
            git_metadata_digest=git_metadata_digest,
            lifecycle="available",
        )
        with self._locked():
            records = self._load_records_unlocked()
            self._expire_available_unlocked(records)
            self._prune_terminal_unlocked(records, max_records=MAX_RECORDS - 1)
            if any(
                item.agent_id == agent_id and item.lifecycle in {"available", "bound"}
                for _path, item in records
            ):
                raise self._failure(
                    "headless_attestation_active",
                    "agent already has an active worktree attestation",
                    "consume or release the existing attestation before creating another",
                )
            self._write_unlocked(attestation)
        return attestation

    def has_available(self, agent_id: str) -> bool:
        return bool(self._available(agent_id))

    def bind(
        self,
        agent_id: str,
        repository_root: Path,
        write_paths: list[str] | tuple[str, ...],
        *,
        assignment_id: str,
        provider_generation: int | str,
    ) -> ScopeBinding:
        agent_id = self._require_text(agent_id, "agent_id", 200)
        assignment_id = self._require_text(
            assignment_id, "assignment_id", MAX_ASSIGNMENT_ID_CHARS
        )
        self._require_generation(provider_generation)
        declarations = self._normalize_declared_paths(write_paths)
        repository = self._real_directory(repository_root)
        with self._locked():
            available = self._available_unlocked(agent_id)
            if not available:
                raise self._failure(
                    "headless_write_scope_unenforced",
                    "headless writes lack isolated worktree and diff attribution",
                    "use an isolated worktree or submit a read-only headless assignment",
                )
            if len(available) != 1:
                raise self._failure(
                    "headless_attestation_ambiguous",
                    "more than one unused worktree attestation matches the agent",
                    "leave exactly one unused Masterjet worktree for the assignment",
                )
            attestation = available[0]
            self._verify_attestation(attestation, agent_id, repository)
            self._verify_clean_worktree(attestation)
            declarations = self._verify_declared_paths(attestation.worktree_path, declarations)
            updated = self._replace(
                attestation,
                lifecycle="bound",
                assignment_id=assignment_id,
                provider_generation=provider_generation,
                declared_write_paths=declarations,
            )
            self._write_unlocked(updated)
        return ScopeBinding(
            attestation_id=updated.attestation_id,
            agent_id=updated.agent_id,
            assignment_id=assignment_id,
            repository_root=updated.repository_root,
            repository_device=updated.repository_device,
            repository_inode=updated.repository_inode,
            worktree_path=updated.worktree_path,
            baseline_commit=updated.baseline_commit,
            provider_generation=provider_generation,
            declared_write_paths=declarations,
            worktree_device=updated.worktree_device,
            worktree_inode=updated.worktree_inode,
            common_git_dir=updated.common_git_dir,
            common_git_device=updated.common_git_device,
            common_git_inode=updated.common_git_inode,
            branch=updated.branch,
            detached=updated.detached,
            requested_base_ref=updated.requested_base_ref,
            creation_generation=updated.creation_generation,
            created_at_utc=updated.created_at_utc,
            history_reflog_count=updated.history_reflog_count,
            history_reflog_digest=updated.history_reflog_digest,
            history_reflog_anchor=updated.history_reflog_anchor,
            index_flags=updated.index_flags,
            git_metadata_digest=updated.git_metadata_digest,
        )

    def revalidate(
        self,
        binding: ScopeBinding,
        repository_root: Path,
        *,
        provider_generation: int | str,
    ) -> ScopeAttestation:
        self._require_generation(provider_generation)
        if provider_generation != binding.provider_generation:
            raise self._failure(
                "headless_assignment_generation_changed",
                "provider generation changed after assignment binding",
                "discard the assignment and create a fresh binding",
            )
        with self._locked():
            attestation = self._read_unlocked(binding.attestation_id)
            if attestation.lifecycle != "bound" or attestation.assignment_id != binding.assignment_id:
                raise self._failure(
                    "headless_attestation_invalid",
                    "attestation is stale, consumed, or bound to another assignment",
                    "create a fresh Masterjet worktree attestation",
                )
            self._verify_binding_identity(
                attestation,
                binding,
                repository=self._real_directory(repository_root),
            )
            self._verify_clean_worktree(attestation)
            checked = self._verify_declared_paths(
                attestation.worktree_path, binding.declared_write_paths
            )
            if checked != binding.declared_write_paths:
                raise self._failure(
                    "headless_attestation_invalid",
                    "declared path filesystem type changed after binding",
                    "create a fresh Masterjet worktree attestation",
                )
            return attestation

    def finalize(self, binding: ScopeBinding) -> ScopeResult:
        result: ScopeResult | None = None
        with self._locked():
            attestation = self._read_unlocked(binding.attestation_id)
            try:
                if (
                    attestation.lifecycle != "bound"
                    or attestation.assignment_id != binding.assignment_id
                    or attestation.agent_id != binding.agent_id
                ):
                    raise self._failure(
                        "headless_attestation_invalid",
                        "attestation is stale, consumed, or bound to another assignment",
                        "create a fresh Masterjet worktree attestation",
                    )
                current = self._verify_binding_identity(
                    attestation, binding, allow_descendant=True
                )
                checked = self._verify_declared_paths(
                    attestation.worktree_path, binding.declared_write_paths
                )
                if checked != binding.declared_write_paths:
                    raise self._failure(
                        "headless_attestation_invalid",
                        "declared path filesystem type changed after binding",
                        "create a fresh Masterjet worktree attestation",
                    )
                changed = self._git_history_paths(
                    attestation.worktree_path,
                    attestation.baseline_commit,
                    current["head"],
                )
                changed.extend(self._git_status(attestation.worktree_path))
                changed = list(dict.fromkeys(changed))
                out_of_scope: list[str] = []
                for path in changed:
                    declared = self._path_is_declared(
                        path, binding.declared_write_paths
                    )
                    changed_target = attestation.worktree_path.joinpath(
                        *PurePosixPath(path).parts
                    )
                    self._verify_no_symlink_path(
                        attestation.worktree_path, changed_target
                    )
                    if not declared:
                        out_of_scope.append(path)
                if out_of_scope:
                    result = ScopeResult(
                        False,
                        "headless_write_scope_violation",
                        len(changed),
                        len(changed) - len(out_of_scope),
                        len(out_of_scope),
                    )
                else:
                    result = ScopeResult(True, "ok", len(changed), len(changed), 0)
            except HeadlessWriteScopeFailure as exc:
                result = ScopeResult(False, exc.code, 0, 0, 0)
            finally:
                terminal_code = result.code if result is not None else "headless_write_attribution_unverified"
                consumed = self._replace(
                    attestation,
                    lifecycle="consumed",
                    assignment_id=attestation.assignment_id,
                )
                record = self._record(consumed)
                record["terminal_code"] = terminal_code
                self._write_record_unlocked(record)
        assert result is not None
        return result

    def read(self, attestation_id: str) -> ScopeAttestation:
        with self._locked():
            attestation = self._read_unlocked(attestation_id)
            if attestation.lifecycle == "available" and self._is_expired(attestation):
                consumed = self._replace(attestation, lifecycle="consumed")
                record = self._record(consumed)
                record["terminal_code"] = "headless_attestation_expired"
                self._write_record_unlocked(record)
                return consumed
            return attestation

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._ensure_state_dir()
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            directory_fd = self._open_state_directory_fd(directory_flags)
            self._verify_journal_directory_fd(directory_fd)
            fd = os.open(
                "store.lock",
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            self._verify_journal_regular_fd(fd, "attestation lock")
        except (OSError, HeadlessWriteScopeFailure) as exc:
            with_context_close(locals().get("fd", -1))
            with_context_close(locals().get("directory_fd", -1))
            if isinstance(exc, HeadlessWriteScopeFailure):
                raise
            raise self._failure(
                "headless_attestation_invalid",
                "attestation journal lock is unsafe or unavailable",
                "repair the Masterjet attestation store before retrying",
            ) from exc
        journal_token = self._journal_state_fd.set(directory_fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        except OSError as exc:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation journal lock operation failed",
                "repair the Masterjet attestation store before retrying",
            ) from exc
        finally:
            with_context_close(fd)
            self._journal_state_fd.reset(journal_token)
            with_context_close(directory_fd)

    def _open_state_directory_fd(self, flags: int) -> int:
        fd = -1
        try:
            fd = os.open(self.state_root.anchor, flags)
            for part in self.state_root.parts[1:]:
                child_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child_fd
            return fd
        except OSError as exc:
            if fd >= 0:
                with_context_close(fd)
            raise self._failure(
                "headless_attestation_invalid",
                "attestation state directory is unsafe or unavailable",
                "repair the Masterjet attestation store before retrying",
            ) from exc

    def _ensure_state_dir(self) -> None:
        created = False
        try:
            self.state_root.mkdir(parents=True, exist_ok=False)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation state directory could not be created",
                "repair the Masterjet attestation store before retrying",
            ) from exc
        current = self.state_root
        while current != current.parent:
            try:
                info = current.lstat()
            except OSError as exc:
                raise self._failure(
                    "headless_attestation_invalid",
                    "attestation state directory is missing or unreadable",
                    "repair the Masterjet attestation store before retrying",
                ) from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise self._failure(
                    "headless_attestation_invalid",
                    "attestation state directory is not a real directory",
                    "repair the Masterjet state directory before retrying",
                )
            if current == Path(current.anchor):
                break
            current = current.parent
        try:
            if created:
                os.chmod(self.state_root, 0o700)
            info = self.state_root.lstat()
        except OSError as exc:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation state directory permissions could not be hardened",
                "repair the Masterjet attestation store before retrying",
            ) from exc
        if (
            info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or not stat.S_ISDIR(info.st_mode)
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "attestation state directory has unsafe ownership or mode",
                "repair the Masterjet attestation store before retrying",
            )

    def _verify_journal_directory_fd(self, fd: int) -> None:
        try:
            info = os.fstat(fd)
        except OSError as exc:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation state directory could not be inspected",
                "repair the Masterjet attestation store before retrying",
            ) from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "attestation state directory has unsafe ownership or mode",
                "repair the Masterjet attestation store before retrying",
            )

    def _verify_journal_regular_fd(self, fd: int, label: str) -> None:
        try:
            info = os.fstat(fd)
        except OSError as exc:
            raise self._failure(
                "headless_attestation_invalid",
                f"{label} could not be inspected",
                "repair the Masterjet attestation store before retrying",
            ) from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise self._failure(
                "headless_attestation_invalid",
                f"{label} has unsafe ownership, mode, type, or link count",
                "repair the Masterjet attestation store before retrying",
            )

    def _available(self, agent_id: str) -> list[ScopeAttestation]:
        with self._locked():
            return self._available_unlocked(agent_id)

    def _available_unlocked(self, agent_id: str) -> list[ScopeAttestation]:
        loaded = self._load_records_unlocked()
        self._expire_available_unlocked(loaded)
        self._prune_terminal_unlocked(loaded)
        records = [
            attestation
            for _path, attestation in loaded
            if attestation.agent_id == agent_id and attestation.lifecycle == "available"
        ]
        return records

    def _expire_available_unlocked(
        self, records: list[tuple[Path, ScopeAttestation]]
    ) -> None:
        for index, (path, attestation) in enumerate(records):
            if attestation.lifecycle != "available" or not self._is_expired(attestation):
                continue
            consumed = self._replace(attestation, lifecycle="consumed")
            record = self._record(consumed)
            record["terminal_code"] = "headless_attestation_expired"
            self._write_record_unlocked(record)
            records[index] = (path, consumed)

    def _load_records_unlocked(self) -> list[tuple[Path, ScopeAttestation]]:
        directory_fd = self._journal_state_fd.get()
        if directory_fd is None:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation journal directory is not pinned",
                "repair the Masterjet attestation store before retrying",
            )
        try:
            names = os.listdir(directory_fd)
        except OSError as exc:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation records could not be listed",
                "repair the Masterjet attestation store before retrying",
            ) from exc
        paths = sorted(
            self.state_root / name
            for name in names
            if name.startswith("attestation-") and name.endswith(".json")
        )
        if len(paths) > MAX_RECORD_SCAN:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation store exceeds its bounded scan limit",
                "remove malformed or excessive attestation records through Masterjet",
            )
        return [
            (path, self._from_record(self._read_record_path(path))) for path in paths
        ]

    @staticmethod
    def _is_expired(attestation: ScopeAttestation) -> bool:
        try:
            created = datetime.fromisoformat(attestation.created_at_utc)
        except ValueError as exc:
            raise HeadlessWriteScopeFailure(
                "headless_attestation_invalid",
                "attestation creation time is malformed",
                "repair the Masterjet attestation store before retrying",
            ) from exc
        if created.tzinfo is None:
            raise HeadlessWriteScopeFailure(
                "headless_attestation_invalid",
                "attestation creation time lacks a timezone",
                "repair the Masterjet attestation store before retrying",
            )
        age = (datetime.now(timezone.utc) - created).total_seconds()
        return age > ATTESTATION_TTL_SECONDS

    def _prune_terminal_unlocked(
        self,
        records: list[tuple[Path, ScopeAttestation]],
        *,
        max_records: int | None = None,
    ) -> None:
        limit = MAX_RECORDS if max_records is None else max_records
        excess = len(records) - limit
        if excess <= 0:
            return
        terminal = sorted(
            (
                attestation.created_at_utc,
                attestation.attestation_id,
                path,
            )
            for path, attestation in records
            if attestation.lifecycle == "consumed"
        )
        if len(terminal) < excess:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation store exceeds its bounded record limit without enough terminal records",
                "consume terminal attestations before creating more worktrees",
            )
        for _created, _attestation_id, path in terminal[:excess]:
            try:
                directory_fd = self._journal_state_fd.get()
                if directory_fd is None:
                    raise OSError("journal directory is not pinned")
                os.unlink(path.name, dir_fd=directory_fd)
            except OSError as exc:
                raise self._failure(
                    "headless_attestation_invalid",
                    "terminal attestation record could not be pruned",
                    "repair the Masterjet attestation store before retrying",
                ) from exc

    def _read_unlocked(self, attestation_id: str) -> ScopeAttestation:
        if not isinstance(attestation_id, str) or _ATTESTATION_ID_RE.fullmatch(attestation_id) is None:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation identifier is malformed",
                "create a fresh Masterjet worktree attestation",
            )
        return self._from_record(self._read_record_path(self._record_path(attestation_id)))

    def _write_unlocked(self, attestation: ScopeAttestation) -> None:
        self._write_record_unlocked(self._record(attestation))

    def _write_record_unlocked(self, record: Mapping[str, Any]) -> None:
        raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(raw) > MAX_RECORD_BYTES:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation record exceeds its bounded size",
                "create a fresh Masterjet worktree attestation",
            )
        attestation_id = record.get("attestation_id")
        if not isinstance(attestation_id, str) or _ATTESTATION_ID_RE.fullmatch(attestation_id) is None:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation record identifier is malformed",
                "create a fresh Masterjet worktree attestation",
            )
        directory_fd = self._journal_state_fd.get()
        if directory_fd is None:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation journal directory is not pinned",
                "repair the Masterjet attestation store before retrying",
        )
        temporary_name = f".attestation-{secrets.token_hex(16)}.tmp"
        fd = -1
        try:
            fd = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            os.fchmod(fd, 0o600)
            self._verify_journal_regular_fd(fd, "temporary attestation record")
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(
                temporary_name,
                self._record_path(attestation_id).name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            self._read_record_path(self._record_path(attestation_id))
            os.fsync(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise self._failure(
                    "headless_attestation_invalid",
                    "temporary attestation record could not be removed",
                    "repair the Masterjet attestation store before retrying",
                ) from exc

    def _read_record_path(self, path: Path) -> dict[str, Any]:
        if path.parent != self.state_root or path.name == "":
            raise self._failure(
                "headless_attestation_invalid",
                "attestation record path is outside the pinned journal",
                "repair the Masterjet attestation store before retrying",
            )
        directory_fd = self._journal_state_fd.get()
        if directory_fd is None:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation journal directory is not pinned",
                "repair the Masterjet attestation store before retrying",
            )
        try:
            info = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation record is missing or unreadable",
                "create a fresh Masterjet worktree attestation",
            )
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_size > MAX_RECORD_BYTES
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "attestation record is not a bounded regular file",
                "repair the Masterjet attestation store before retrying",
            )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path.name, flags, dir_fd=directory_fd)
            opened = os.fstat(fd)
            if (
                opened.st_ino != info.st_ino
                or opened.st_dev != info.st_dev
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_nlink != 1
            ):
                raise OSError("attestation record changed while opening")
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                raw = stream.read(MAX_RECORD_BYTES + 1)
        except (OSError, ValueError):
            raise self._failure(
                "headless_attestation_invalid",
                "attestation record is unreadable",
                "repair the Masterjet attestation store before retrying",
            )
        finally:
            if "fd" in locals() and fd >= 0:
                os.close(fd)
        if len(raw) > MAX_RECORD_BYTES:
            raise self._failure(
                "headless_attestation_invalid",
                "attestation record exceeds its bounded size",
                "repair the Masterjet attestation store before retrying",
            )
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise self._failure(
                "headless_attestation_invalid",
                "attestation record is malformed",
                "repair the Masterjet attestation store before retrying",
            )
        if not isinstance(value, dict):
            raise self._failure(
                "headless_attestation_invalid",
                "attestation record is malformed",
                "repair the Masterjet attestation store before retrying",
            )
        return value

    def _record_path(self, attestation_id: str) -> Path:
        return self.state_root / f"attestation-{attestation_id}.json"

    def _record(self, attestation: ScopeAttestation) -> dict[str, Any]:
        return {
            "schema_version": ATTESTATION_SCHEMA_VERSION,
            "attestation_id": attestation.attestation_id,
            "agent_id": attestation.agent_id,
            "repository_root": str(attestation.repository_root),
            "repository_device": attestation.repository_device,
            "repository_inode": attestation.repository_inode,
            "worktree_path": str(attestation.worktree_path),
            "worktree_device": attestation.worktree_device,
            "worktree_inode": attestation.worktree_inode,
            "common_git_dir": str(attestation.common_git_dir),
            "common_git_device": attestation.common_git_device,
            "common_git_inode": attestation.common_git_inode,
            "branch": attestation.branch,
            "detached": attestation.detached,
            "baseline_commit": attestation.baseline_commit,
            "requested_base_ref": attestation.requested_base_ref,
            "creation_generation": attestation.creation_generation,
            "created_at_utc": attestation.created_at_utc,
            "history_reflog_count": attestation.history_reflog_count,
            "history_reflog_digest": attestation.history_reflog_digest,
            "history_reflog_anchor": attestation.history_reflog_anchor,
            "index_flags": [list(item) for item in attestation.index_flags],
            "git_metadata_digest": attestation.git_metadata_digest,
            "lifecycle": attestation.lifecycle,
            "assignment_id": attestation.assignment_id,
            "provider_generation": attestation.provider_generation,
            "declared_write_paths": [list(item) for item in attestation.declared_write_paths],
        }

    def _from_record(self, record: Mapping[str, Any]) -> ScopeAttestation:
        try:
            if record.get("schema_version") != ATTESTATION_SCHEMA_VERSION:
                raise ValueError
            attestation_id = record["attestation_id"]
            if not isinstance(attestation_id, str) or _ATTESTATION_ID_RE.fullmatch(attestation_id) is None:
                raise ValueError
            agent_id = self._require_text(record["agent_id"], "agent_id", 200)
            lifecycle = record["lifecycle"]
            if lifecycle not in {"available", "bound", "consumed"}:
                raise ValueError
            paths_raw = record.get("declared_write_paths", [])
            if not isinstance(paths_raw, list):
                raise ValueError
            paths_list: list[tuple[str, bool]] = []
            for item in paths_raw:
                if (
                    not isinstance(item, list)
                    or len(item) != 2
                    or not isinstance(item[0], str)
                    or type(item[1]) is not bool
                ):
                    raise ValueError
                paths_list.append((item[0], item[1]))
            paths = tuple(paths_list)
            if paths:
                normalized_paths = self._normalize_declared_paths(
                    [item[0] for item in paths_list]
                )
                if tuple(item[0] for item in normalized_paths) != tuple(
                    item[0] for item in paths_list
                ):
                    raise ValueError
            repository_root = Path(record["repository_root"])
            worktree_path = Path(record["worktree_path"])
            common_git_dir = Path(record["common_git_dir"])
            if not repository_root.is_absolute() or not worktree_path.is_absolute() or not common_git_dir.is_absolute():
                raise ValueError
            repository_device = self._require_device(record["repository_device"])
            repository_inode = self._require_inode(record["repository_inode"])
            worktree_device = record["worktree_device"]
            worktree_inode = record["worktree_inode"]
            if (
                type(worktree_device) is not int
                or type(worktree_inode) is not int
                or worktree_device < 0
                or worktree_inode <= 0
            ):
                raise ValueError
            common_git_device = self._require_device(record["common_git_device"])
            common_git_inode = self._require_inode(record["common_git_inode"])
            detached = record["detached"]
            if type(detached) is not bool:
                raise ValueError
            branch = record["branch"]
            if branch is not None and (
                not isinstance(branch, str) or not branch or any(char.isspace() for char in branch)
            ):
                raise ValueError
            if detached != (branch is None):
                raise ValueError
            assignment_id = record["assignment_id"]
            if assignment_id is not None:
                self._require_text(assignment_id, "assignment_id", MAX_ASSIGNMENT_ID_CHARS)
            provider_generation = record.get("provider_generation")
            if provider_generation is not None:
                self._require_generation(provider_generation)
            requested_base_ref = record["requested_base_ref"]
            if requested_base_ref is not None:
                requested_base_ref = self._require_text(
                    requested_base_ref, "requested_base_ref", 200
                )
                if requested_base_ref.startswith("-") or any(
                    char.isspace() for char in requested_base_ref
                ) or "\x00" in requested_base_ref:
                    raise ValueError
            history_reflog_count = record["history_reflog_count"]
            if (
                type(history_reflog_count) is not int
                or history_reflog_count < 1
                or history_reflog_count > MAX_HISTORY_REFLOG_ENTRIES
            ):
                raise ValueError
            history_reflog_digest = record["history_reflog_digest"]
            if (
                not isinstance(history_reflog_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", history_reflog_digest) is None
            ):
                raise ValueError
            history_reflog_anchor = self._require_text(
                record["history_reflog_anchor"],
                "history_reflog_anchor",
                MAX_HISTORY_REFLOG_BYTES,
            )
            index_flags_raw = record["index_flags"]
            if not isinstance(index_flags_raw, list):
                raise ValueError
            index_flags: list[tuple[str, str]] = []
            seen_index_paths: set[str] = set()
            serialized_index_size = 0
            for item in index_flags_raw:
                if (
                    not isinstance(item, list)
                    or len(item) != 2
                    or not isinstance(item[0], str)
                    or not isinstance(item[1], str)
                    or len(item[1]) != 1
                ):
                    raise ValueError
                index_path = self._require_text(item[0], "index path", MAX_PATH_CHARS)
                if (
                    index_path.startswith("/")
                    or any(part in {"", ".", ".."} for part in index_path.split("/"))
                    or index_path in seen_index_paths
                ):
                    raise ValueError
                seen_index_paths.add(index_path)
                serialized_index_size += len(index_path.encode("utf-8")) + 2
                if serialized_index_size > MAX_INDEX_EVIDENCE_BYTES:
                    raise ValueError
                index_flags.append((index_path, item[1]))
            if len(index_flags) > MAX_INDEX_EVIDENCE_ENTRIES:
                raise ValueError
            git_metadata_digest = record["git_metadata_digest"]
            if (
                not isinstance(git_metadata_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", git_metadata_digest) is None
            ):
                raise ValueError
            return ScopeAttestation(
                attestation_id=attestation_id,
                agent_id=agent_id,
                repository_root=repository_root,
                repository_device=repository_device,
                repository_inode=repository_inode,
                worktree_path=worktree_path,
                worktree_device=worktree_device,
                worktree_inode=worktree_inode,
                common_git_dir=common_git_dir,
                common_git_device=common_git_device,
                common_git_inode=common_git_inode,
                branch=branch,
                detached=detached,
                baseline_commit=self._require_text(record["baseline_commit"], "baseline_commit", 200),
                requested_base_ref=requested_base_ref,
                creation_generation=self._require_text(record["creation_generation"], "creation_generation", 100),
                created_at_utc=self._require_text(record["created_at_utc"], "created_at_utc", 100),
                history_reflog_count=history_reflog_count,
                history_reflog_digest=history_reflog_digest,
                history_reflog_anchor=history_reflog_anchor,
                index_flags=tuple(index_flags),
                git_metadata_digest=git_metadata_digest,
                lifecycle=lifecycle,
                assignment_id=assignment_id,
                provider_generation=provider_generation,
                declared_write_paths=paths,
            )
        except (HeadlessWriteScopeFailure, KeyError, TypeError, ValueError, OSError):
            raise self._failure(
                "headless_attestation_invalid",
                "attestation record is malformed",
                "repair the Masterjet attestation store before retrying",
            )

    def _git_identity(self, cwd: Path) -> dict[str, Any]:
        top = self._real_directory(Path(self._git_output(cwd, ["rev-parse", "--show-toplevel"])))
        common_raw = self._git_output(cwd, ["rev-parse", "--git-common-dir"])
        common_path = Path(common_raw)
        if not common_path.is_absolute():
            common_path = cwd / common_path
        common = self._real_directory(common_path)
        try:
            common_info = common.lstat()
        except OSError as exc:
            raise self._failure(
                "headless_attestation_invalid",
                "Git common directory identity could not be verified",
                "recreate the worktree through Masterjet",
            ) from exc
        head = self._git_output(cwd, ["rev-parse", "--verify", "HEAD^{commit}"])
        branch_result = self._git(["symbolic-ref", "--quiet", "--short", "HEAD"], cwd)
        branch: str | None
        if branch_result.returncode == 0:
            branch = self._bounded_output(branch_result.stdout, "branch").strip()
            if not branch or any(char.isspace() for char in branch):
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git branch identity is malformed",
                    "recreate the worktree through Masterjet",
                )
        elif branch_result.returncode == 1:
            branch = None
        else:
            raise self._failure(
                "headless_attestation_invalid",
                "Git branch identity could not be verified",
                "recreate the worktree through Masterjet",
            )
        status = self._git_status(cwd)
        return {
            "top": top,
            "common": common,
            "common_device": int(common_info.st_dev),
            "common_inode": int(common_info.st_ino),
            "head": head,
            "branch": branch,
            "status": status,
        }

    def _git_status(self, cwd: Path) -> list[str]:
        output = self._git_output(
            cwd,
            ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
            max_bytes=MAX_GIT_OUTPUT_BYTES,
            strip_output=False,
        )
        if not output:
            return []
        fields = output.split("\0")
        paths: list[str] = []
        index = 0
        while index < len(fields):
            entry = fields[index]
            index += 1
            if not entry:
                continue
            if len(entry) < 4 or entry[2] != " ":
                raise self._failure(
                    "headless_write_attribution_unverified",
                    "Git status output is malformed",
                    "retry after repairing the worktree Git state",
                )
            status = entry[:2]
            if status in _UNMERGED_PORCELAIN_STATES:
                raise self._failure(
                    "headless_write_attribution_unverified",
                    "Git reports an unresolved conflict state",
                    "resolve the worktree conflict before retrying",
                )
            first_path = entry[3:]
            if not first_path or "\0" in first_path:
                raise self._failure(
                    "headless_write_attribution_unverified",
                    "Git status contains an invalid path",
                    "retry after repairing the worktree Git state",
                )
            paths.append(first_path)
            if "R" in status or "C" in status:
                if index >= len(fields) or not fields[index]:
                    raise self._failure(
                        "headless_write_attribution_unverified",
                        "Git rename/copy status is incomplete",
                        "retry after repairing the worktree Git state",
                    )
                paths.append(fields[index])
                index += 1
        return paths

    def _git_output(
        self,
        cwd: Path,
        args: list[str],
        *,
        max_bytes: int = 4096,
        strip_output: bool = True,
    ) -> str:
        result = self._git(args, cwd)
        if result.returncode != 0:
            raise self._failure(
                "headless_write_attribution_unverified",
                "Git verification failed",
                "repair the worktree Git state before retrying",
            )
        output = self._bounded_output(result.stdout, "Git output", max_bytes=max_bytes)
        return output.strip() if strip_output else output

    def _git(self, args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        for name in (
            "GIT_CONFIG",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_CONFIG_PARAMETERS",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_NAMESPACE",
            "GIT_REPLACE_REF_BASE",
            "GIT_GRAFT_FILE",
            "GIT_SHALLOW_FILE",
        ):
            environment.pop(name, None)
        environment.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_NOGLOBAL": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_CONFIG_COUNT": "2",
                "GIT_CONFIG_KEY_0": "core.fsmonitor",
                "GIT_CONFIG_VALUE_0": "false",
                "GIT_CONFIG_KEY_1": "core.untrackedCache",
                "GIT_CONFIG_VALUE_1": "false",
            }
        )
        try:
            result = self.git_runner(
                ["git", *args], cwd=cwd, timeout=30, env=environment
            )
        except Exception as exc:
            raise self._failure(
                "headless_write_attribution_unverified",
                "Git verification could not be executed",
                "repair the worktree Git state before retrying",
            ) from exc
        if not isinstance(getattr(result, "returncode", None), int) or isinstance(
            result.returncode, bool
        ):
            raise self._failure(
                "headless_write_attribution_unverified",
                "Git verification returned malformed process data",
                "repair the worktree Git state before retrying",
            )
        return result

    def _verify_attestation(
        self, attestation: ScopeAttestation, agent_id: str, repository: Path
    ) -> None:
        if attestation.agent_id != agent_id or attestation.repository_root != repository:
            raise self._failure(
                "headless_attestation_invalid",
                "agent or repository identity does not match the attestation",
                "create a fresh Masterjet worktree attestation",
            )
        self._verify_repository_identity(attestation)
        self._verify_worktree_identity(attestation)

    def _verify_repository_identity(self, attestation: ScopeAttestation) -> None:
        try:
            self._real_directory(attestation.repository_root.parent)
            repository_info = attestation.repository_root.lstat()
        except HeadlessWriteScopeFailure:
            raise
        except OSError as exc:
            raise self._failure(
                "headless_attestation_invalid",
                "repository filesystem identity could not be verified",
                "create a fresh Masterjet worktree attestation",
            ) from exc
        if (
            stat.S_ISLNK(repository_info.st_mode)
            or not stat.S_ISDIR(repository_info.st_mode)
            or repository_info.st_dev != attestation.repository_device
            or repository_info.st_ino != attestation.repository_inode
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "repository filesystem identity does not match the attestation",
                "create a fresh Masterjet worktree attestation",
            )
        repository_identity = self._git_identity(attestation.repository_root)
        if (
            repository_identity["top"] != attestation.repository_root
            or repository_identity["common"] != attestation.common_git_dir
            or repository_identity["common_device"] != attestation.common_git_device
            or repository_identity["common_inode"] != attestation.common_git_inode
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "repository Git identity does not match the attestation",
                "create a fresh Masterjet worktree attestation",
            )

    def _verify_binding_identity(
        self,
        attestation: ScopeAttestation,
        binding: ScopeBinding,
        *,
        repository: Path | None = None,
        allow_descendant: bool = False,
    ) -> dict[str, Any]:
        if (
            binding.attestation_id != attestation.attestation_id
            or binding.agent_id != attestation.agent_id
            or binding.assignment_id != attestation.assignment_id
            or binding.repository_root != attestation.repository_root
            or binding.repository_device != attestation.repository_device
            or binding.repository_inode != attestation.repository_inode
            or binding.worktree_path != attestation.worktree_path
            or binding.baseline_commit != attestation.baseline_commit
            or binding.provider_generation != attestation.provider_generation
            or binding.declared_write_paths != attestation.declared_write_paths
            or binding.worktree_device != attestation.worktree_device
            or binding.worktree_inode != attestation.worktree_inode
            or binding.common_git_dir != attestation.common_git_dir
            or binding.common_git_device != attestation.common_git_device
            or binding.common_git_inode != attestation.common_git_inode
            or binding.branch != attestation.branch
            or binding.detached != attestation.detached
            or binding.requested_base_ref != attestation.requested_base_ref
            or binding.creation_generation != attestation.creation_generation
            or binding.created_at_utc != attestation.created_at_utc
            or binding.history_reflog_count != attestation.history_reflog_count
            or binding.history_reflog_digest != attestation.history_reflog_digest
            or binding.history_reflog_anchor != attestation.history_reflog_anchor
            or binding.index_flags != attestation.index_flags
            or binding.git_metadata_digest != attestation.git_metadata_digest
            or (repository is not None and repository != attestation.repository_root)
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "persisted attestation and assignment binding differ",
                "create a fresh assignment binding",
            )
        self._verify_repository_identity(attestation)
        return self._verify_worktree_identity(
            attestation, allow_descendant=allow_descendant
        )

    def _verify_worktree_identity(
        self, attestation: ScopeAttestation, *, allow_descendant: bool = False
    ) -> dict[str, Any]:
        try:
            self._real_directory(attestation.worktree_path.parent)
            info = attestation.worktree_path.lstat()
        except OSError:
            raise self._failure(
                "headless_attestation_invalid",
                "attested worktree is missing",
                "create a fresh Masterjet worktree attestation",
            )
        if (
            info.st_dev != attestation.worktree_device
            or info.st_ino != attestation.worktree_inode
            or not stat.S_ISDIR(info.st_mode)
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "attested worktree filesystem identity changed",
                "create a fresh Masterjet worktree attestation",
            )
        current = self._git_identity(attestation.worktree_path)
        if (
            current["top"] != attestation.worktree_path
            or current["common"] != attestation.common_git_dir
            or current["common_device"] != attestation.common_git_device
            or current["common_inode"] != attestation.common_git_inode
            or current["branch"] != attestation.branch
            or (current["branch"] is None) != attestation.detached
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "attested Git identity changed",
                "create a fresh Masterjet worktree attestation",
            )
        self._verify_git_metadata(attestation)
        self._verify_index_flags(attestation, allow_descendant=allow_descendant)
        self._verify_history_evidence(
            attestation,
            current["head"],
        )
        if not allow_descendant and current["head"] != attestation.baseline_commit:
            raise self._failure(
                "headless_attestation_invalid",
                "attested Git HEAD changed before the headless process started",
                "create a fresh Masterjet worktree attestation",
            )
        if allow_descendant:
            self._verify_baseline_ancestor(
                attestation.worktree_path,
                attestation.baseline_commit,
                current["head"],
            )
        return current

    def _capture_history_evidence(self, cwd: Path, head: str) -> dict[str, Any]:
        self._verify_history_overrides(cwd)
        entries = self._git_reflog_entries(cwd)
        if not entries or entries[0][0] != head:
            raise self._failure(
                "headless_attestation_invalid",
                "Git HEAD reflog evidence is missing or does not match HEAD",
                "enable a local HEAD reflog and recreate the worktree attestation",
            )
        serialized = tuple(self._serialize_reflog_entry(entry) for entry in entries)
        digest = hashlib.sha256("\n".join(serialized).encode("utf-8")).hexdigest()
        return {
            "count": len(serialized),
            "digest": digest,
            "anchor": serialized[0],
        }

    def _capture_index_flags(self, cwd: Path) -> tuple[tuple[str, str], ...]:
        output = self._git_output(
            cwd,
            ["ls-files", "-v", "-z"],
            max_bytes=MAX_GIT_OUTPUT_BYTES,
            strip_output=False,
        )
        entries: list[tuple[str, str]] = []
        seen: set[str] = set()
        serialized_size = 0
        for raw_entry in output.split("\x00"):
            if not raw_entry:
                continue
            if len(raw_entry) < 3 or raw_entry[1] != " ":
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git index flag output is malformed",
                    "repair the worktree Git index before retrying",
                )
            flag = raw_entry[0]
            path = raw_entry[2:]
            if (
                not path
                or path.startswith("/")
                or any(part in {"", ".", ".."} for part in path.split("/"))
                or path in seen
            ):
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git index contains an ambiguous path",
                    "repair the worktree Git index before retrying",
                )
            if flag != "H":
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git index uses a flag that can hide tracked changes",
                    "clear assume-unchanged or skip-worktree flags before retrying",
                )
            seen.add(path)
            serialized_size += len(path.encode("utf-8")) + 2
            if (
                len(entries) >= MAX_INDEX_EVIDENCE_ENTRIES
                or serialized_size > MAX_INDEX_EVIDENCE_BYTES
            ):
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git index flag evidence exceeds its bound",
                    "use a smaller bounded worktree index before retrying",
                )
            entries.append((path, flag))
        return tuple(entries)

    def _verify_index_flags(
        self, attestation: ScopeAttestation, *, allow_descendant: bool = False
    ) -> None:
        current = dict(self._capture_index_flags(attestation.worktree_path))
        expected = dict(attestation.index_flags)
        if not allow_descendant and current == expected:
            return
        if not allow_descendant or set(expected) != self._git_tree_paths(
            attestation.worktree_path, attestation.baseline_commit
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "Git index flag state changed after binding",
                "restore the bound Git index flags and retry",
            )
        if any(
            path in current and current[path] != flag
            for path, flag in expected.items()
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "Git index flag state changed after binding",
                "restore the bound Git index flags and retry",
            )

    def _git_tree_paths(self, cwd: Path, commit: str) -> set[str]:
        output = self._git_output(
            cwd,
            ["ls-tree", "-r", "-z", "--name-only", commit],
            max_bytes=MAX_GIT_OUTPUT_BYTES,
            strip_output=False,
        )
        paths: set[str] = set()
        for path in output.split("\x00"):
            if not path:
                continue
            if (
                path.startswith("/")
                or any(part in {"", ".", ".."} for part in path.split("/"))
                or path in paths
            ):
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git baseline tree contains an ambiguous path",
                    "repair the attested Git baseline before retrying",
                )
            paths.add(path)
            if len(paths) > MAX_INDEX_EVIDENCE_ENTRIES:
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git baseline tree exceeds its bounded index evidence",
                    "use a smaller bounded worktree before retrying",
                )
        return paths

    def _capture_git_metadata_digest(self, cwd: Path) -> str:
        git_dir = self._real_directory(
            self._git_path_output(cwd, ["rev-parse", "--git-dir"])
        )
        common_dir = self._real_directory(
            self._git_path_output(cwd, ["rev-parse", "--git-common-dir"])
        )
        self._reject_local_config_includes(cwd)
        fixed_files = (
            ("gitdir/config", git_dir / "config"),
            ("common/config", common_dir / "config"),
            ("gitdir/config.worktree", git_dir / "config.worktree"),
            ("common/config.worktree", common_dir / "config.worktree"),
            ("gitdir/info/exclude", git_dir / "info" / "exclude"),
            ("common/info/exclude", common_dir / "info" / "exclude"),
            (
                "gitdir/info/sparse-checkout",
                git_dir / "info" / "sparse-checkout",
            ),
            (
                "common/info/sparse-checkout",
                common_dir / "info" / "sparse-checkout",
            ),
            ("gitdir/info/attributes", git_dir / "info" / "attributes"),
            ("common/info/attributes", common_dir / "info" / "attributes"),
        )
        tokens: list[str] = []
        total_bytes = 0
        seen: set[Path] = set()
        for label, path in fixed_files:
            path = Path(os.path.abspath(path))
            if path in seen:
                continue
            seen.add(path)
            token, size = self._git_metadata_token(label, path)
            total_bytes += size
            if total_bytes > MAX_GIT_METADATA_BYTES:
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git metadata evidence exceeds its bound",
                    "use bounded Git metadata before retrying",
                )
            tokens.append(token)
        external_excludes = self._configured_external_excludes_file(cwd)
        if external_excludes is not None and external_excludes not in seen:
            token, size = self._git_metadata_token(
                "external/core.excludesFile", external_excludes
            )
            total_bytes += size
            if total_bytes > MAX_GIT_METADATA_BYTES:
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git metadata evidence exceeds its bound",
                    "use bounded Git metadata before retrying",
                )
            tokens.append(token)
        return hashlib.sha256("\n".join(tokens).encode("utf-8")).hexdigest()

    def _reject_local_config_includes(self, cwd: Path) -> None:
        result = self._git(
            ["config", "--local", "--includes", "--get-regexp", "^include"],
            cwd,
        )
        if result.returncode == 1:
            return
        if result.returncode != 0:
            raise self._failure(
                "headless_attestation_invalid",
                "Git local include configuration could not be verified",
                "remove local Git include directives before retrying",
            )
        if self._bounded_output(
            result.stdout, "Git local include configuration", max_bytes=4096
        ).strip():
            raise self._failure(
                "headless_attestation_invalid",
                "Git local include configuration can alter attribution",
                "remove local Git include directives before retrying",
            )

    def _configured_external_excludes_file(self, cwd: Path) -> Path | None:
        result = self._git(
            ["config", "--local", "--get", "core.excludesFile"], cwd
        )
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise self._failure(
                "headless_attestation_invalid",
                "Git excludes configuration could not be verified",
                "repair the worktree Git configuration before retrying",
            )
        value = self._bounded_output(
            result.stdout, "Git excludes configuration", max_bytes=MAX_PATH_CHARS
        ).strip()
        if not value or "\x00" in value or "\n" in value or "\r" in value:
            raise self._failure(
                "headless_attestation_invalid",
                "Git excludes configuration is malformed",
                "repair the worktree Git configuration before retrying",
            )
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = cwd / path
        path = Path(os.path.abspath(path))
        self._verify_metadata_parent_chain(path.parent)
        return path

    def _git_path_output(self, cwd: Path, args: list[str]) -> Path:
        path = Path(self._git_output(cwd, args))
        if not path.is_absolute():
            path = cwd / path
        return Path(os.path.abspath(path))

    def _git_metadata_token(self, label: str, path: Path) -> tuple[str, int]:
        self._verify_metadata_parent_chain(path.parent)
        try:
            info = path.lstat()
        except FileNotFoundError:
            return f"{label}\0missing", len(label) + 8
        except OSError as exc:
            raise self._failure(
                "headless_attestation_invalid",
                "Git metadata could not be inspected",
                "repair the worktree Git metadata before retrying",
            ) from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_size > MAX_GIT_METADATA_FILE_BYTES
            or info.st_nlink != 1
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "Git attribution metadata is not a bounded regular file",
                "repair the worktree Git metadata before retrying",
            )
        fd = -1
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            opened = os.fstat(fd)
            if (
                opened.st_dev != info.st_dev
                or opened.st_ino != info.st_ino
                or opened.st_uid != info.st_uid
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(info.st_mode)
            ):
                raise OSError("Git metadata changed while opening")
            data = os.read(fd, MAX_GIT_METADATA_FILE_BYTES + 1)
        except OSError as exc:
            raise self._failure(
                "headless_attestation_invalid",
                "Git metadata could not be read safely",
                "repair the worktree Git metadata before retrying",
            ) from exc
        finally:
            if fd >= 0:
                os.close(fd)
        if len(data) > MAX_GIT_METADATA_FILE_BYTES:
            raise self._failure(
                "headless_attestation_invalid",
                "Git metadata evidence exceeds its bound",
                "use bounded Git metadata before retrying",
            )
        digest = hashlib.sha256(data).hexdigest()
        token = f"{label}\0{stat.S_IMODE(info.st_mode):o}\0{info.st_uid}\0{digest}"
        return token, len(data) + len(token)

    def _verify_metadata_parent_chain(self, path: Path) -> None:
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                return
            except OSError as exc:
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git metadata parent could not be inspected",
                    "repair the worktree Git metadata before retrying",
                ) from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git metadata parent is not a real directory",
                    "repair the worktree Git metadata before retrying",
                )

    def _verify_git_metadata(self, attestation: ScopeAttestation) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", attestation.git_metadata_digest) is None:
            raise self._failure(
                "headless_attestation_invalid",
                "persisted Git metadata evidence is malformed",
                "create a fresh Masterjet worktree attestation",
            )
        if self._capture_git_metadata_digest(attestation.worktree_path) != (
            attestation.git_metadata_digest
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "Git attribution metadata changed after binding",
                "restore the bound Git metadata and retry",
            )

    def _verify_history_evidence(
        self, attestation: ScopeAttestation, current_head: str
    ) -> None:
        if (
            type(attestation.history_reflog_count) is not int
            or not 1 <= attestation.history_reflog_count <= MAX_HISTORY_REFLOG_ENTRIES
            or re.fullmatch(r"[0-9a-f]{64}", attestation.history_reflog_digest)
            is None
            or not isinstance(attestation.history_reflog_anchor, str)
        ):
            raise self._failure(
                "headless_attestation_invalid",
                "persisted Git history evidence is malformed",
                "create a fresh Masterjet worktree attestation",
            )
        self._verify_history_overrides(attestation.worktree_path)
        entries = self._git_reflog_entries(attestation.worktree_path)
        serialized = tuple(self._serialize_reflog_entry(entry) for entry in entries)
        if not serialized or serialized[0].split("\x00", 1)[0] != current_head:
            raise self._failure(
                "headless_attestation_invalid",
                "Git HEAD reflog no longer matches the attested HEAD",
                "restore the attested Git history and retry",
            )
        count = attestation.history_reflog_count
        matching_offsets = [
            offset
            for offset, entry in enumerate(serialized)
            if entry == attestation.history_reflog_anchor
            and offset + count <= len(serialized)
            and hashlib.sha256(
                "\n".join(serialized[offset : offset + count]).encode("utf-8")
            ).hexdigest()
            == attestation.history_reflog_digest
        ]
        if len(matching_offsets) != 1:
            raise self._failure(
                "headless_attestation_invalid",
                "Git HEAD reflog evidence is missing, shortened, or replaced",
                "restore the attested reflog history and retry",
            )
        binding_offset = matching_offsets[0]
        for index in range(binding_offset):
            old_head = serialized[index + 1].split("\x00", 1)[0]
            new_head = serialized[index].split("\x00", 1)[0]
            if old_head == new_head or not self._is_ancestor(
                attestation.worktree_path, old_head, new_head
            ):
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git history after binding is not an append-only descendant sequence",
                    "restore append-only Git history from the attested baseline and retry",
                )

    def _git_reflog_entries(
        self, cwd: Path
    ) -> tuple[tuple[str, str], ...]:
        output = self._git_output(
            cwd,
            [
                "reflog",
                "show",
                "--format=%H%x00%gs",
                f"--max-count={MAX_HISTORY_REFLOG_ENTRIES + 1}",
                "HEAD",
            ],
            max_bytes=MAX_HISTORY_REFLOG_BYTES,
            strip_output=False,
        )
        raw_entries = output.splitlines()
        if not raw_entries or len(raw_entries) > MAX_HISTORY_REFLOG_ENTRIES:
            raise self._failure(
                "headless_attestation_invalid",
                "Git HEAD reflog evidence is missing or exceeds its bound",
                "recreate the worktree with a bounded local HEAD reflog",
            )
        entries: list[tuple[str, str]] = []
        serialized_size = 0
        for raw_entry in raw_entries:
            fields = raw_entry.split("\x00")
            if len(fields) != 2:
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git HEAD reflog evidence is malformed",
                    "repair the worktree Git reflog and retry",
                )
            oid, subject = fields
            if (
                _GIT_OBJECT_ID_RE.fullmatch(oid) is None
                or "\x00" in subject
            ):
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git HEAD reflog evidence is malformed",
                    "repair the worktree Git reflog and retry",
                )
            serialized_size += len(raw_entry.encode("utf-8")) + 1
            if serialized_size > MAX_HISTORY_REFLOG_BYTES:
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git HEAD reflog evidence exceeds its bound",
                    "recreate the worktree with a bounded local HEAD reflog",
                )
            entries.append((oid, subject))
        return tuple(entries)

    def _verify_history_overrides(self, cwd: Path) -> None:
        replace_refs = self._git(
            ["for-each-ref", "--format=%(refname)", "refs/replace"], cwd
        )
        if replace_refs.returncode != 0:
            raise self._failure(
                "headless_attestation_invalid",
                "Git replacement references could not be verified",
                "remove history replacement configuration and retry",
            )
        if self._bounded_output(
            replace_refs.stdout, "Git replacement references", max_bytes=4096
        ).strip():
            raise self._failure(
                "headless_attestation_invalid",
                "Git replacement objects are active in the attested worktree",
                "remove refs/replace entries before retrying",
            )
        git_dir = Path(self._git_output(cwd, ["rev-parse", "--git-dir"]))
        common_dir = Path(
            self._git_output(cwd, ["rev-parse", "--git-common-dir"])
        )
        if not git_dir.is_absolute():
            git_dir = cwd / git_dir
        if not common_dir.is_absolute():
            common_dir = cwd / common_dir
        fixed_overrides = (
            git_dir / "refs" / "replace",
            common_dir / "refs" / "replace",
            git_dir / "info" / "grafts",
            common_dir / "info" / "grafts",
            git_dir / "shallow",
            common_dir / "shallow",
            git_dir / "objects" / "info" / "alternates",
            common_dir / "objects" / "info" / "alternates",
        )
        seen: set[Path] = set()
        for candidate in fixed_overrides:
            candidate = Path(os.path.abspath(candidate))
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise self._failure(
                    "headless_attestation_invalid",
                    "Git history override metadata could not be inspected",
                    "remove or repair the worktree Git metadata before retrying",
                ) from exc
            raise self._failure(
                "headless_attestation_invalid",
                "Git history override metadata is present",
                "remove replacement, graft, shallow, or alternate-object metadata before retrying",
            )

    @staticmethod
    def _serialize_reflog_entry(entry: tuple[str, str]) -> str:
        return "\x00".join(entry)

    def _is_ancestor(self, cwd: Path, old_head: str, new_head: str) -> bool:
        result = self._git(
            ["merge-base", "--is-ancestor", old_head, new_head], cwd
        )
        return result.returncode == 0

    def _verify_baseline_ancestor(
        self, cwd: Path, baseline: str, head: str
    ) -> None:
        result = self._git(
            ["merge-base", "--is-ancestor", baseline, head], cwd
        )
        if result.returncode != 0:
            raise self._failure(
                "headless_attestation_invalid",
                "current Git history is not based on the attested baseline",
                "restore the attested baseline ancestry and retry",
            )

    def _git_history_paths(self, cwd: Path, baseline: str, head: str) -> list[str]:
        if baseline == head:
            return []
        commits = self._git_output(
            cwd,
            ["log", "--format=%H", "--reverse", f"{baseline}..{head}"],
            max_bytes=MAX_GIT_OUTPUT_BYTES,
        ).splitlines()
        paths: list[str] = []
        for commit in commits:
            if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
                raise self._failure(
                    "headless_write_attribution_unverified",
                    "Git history contains a malformed commit identity",
                    "repair the worktree Git history before retrying",
                )
            output = self._git_output(
                cwd,
                [
                    "diff-tree",
                    "--root",
                    "--no-commit-id",
                    "--name-status",
                    "-z",
                    "-r",
                    "--find-renames",
                    "--find-copies-harder",
                    "-m",
                    commit,
                ],
                max_bytes=MAX_GIT_OUTPUT_BYTES,
                strip_output=False,
            )
            fields = output.split("\0")
            index = 0
            while index < len(fields):
                field = fields[index]
                index += 1
                if not field:
                    continue
                if "\t" in field:
                    status, first_path = field.split("\t", 1)
                else:
                    status = field
                    if index >= len(fields):
                        raise self._failure(
                            "headless_write_attribution_unverified",
                            "Git history path output is incomplete",
                            "repair the worktree Git history before retrying",
                        )
                    first_path = fields[index]
                    index += 1
                if not status or not first_path:
                    raise self._failure(
                        "headless_write_attribution_unverified",
                        "Git history path output is malformed",
                        "repair the worktree Git history before retrying",
                    )
                paths.append(first_path)
                if status[0] in {"R", "C"}:
                    if index >= len(fields) or not fields[index]:
                        raise self._failure(
                            "headless_write_attribution_unverified",
                            "Git history rename/copy output is incomplete",
                            "repair the worktree Git history before retrying",
                        )
                    paths.append(fields[index])
                    index += 1
        return paths

    def _verify_clean_worktree(self, attestation: ScopeAttestation) -> None:
        if self._git_status(attestation.worktree_path):
            raise self._failure(
                "headless_worktree_dirty",
                "worktree contains changes before the headless process starts",
                "use a clean Masterjet-created worktree",
            )

    def _normalize_declared_paths(
        self, write_paths: list[str] | tuple[str, ...]
    ) -> tuple[tuple[str, bool], ...]:
        if not isinstance(write_paths, (list, tuple)) or not write_paths or len(write_paths) > MAX_DECLARED_PATHS:
            raise self._failure(
                "headless_write_path_invalid",
                "headless write paths must be a bounded non-empty list",
                "declare explicit repository-relative write paths",
            )
        normalized: list[tuple[str, bool]] = []
        seen: set[str] = set()
        serialized_size = 0
        for raw in write_paths:
            if not isinstance(raw, str) or not raw or len(raw) > MAX_PATH_CHARS or "\x00" in raw:
                raise self._failure(
                    "headless_write_path_invalid",
                    "headless write path is malformed",
                    "declare explicit repository-relative write paths",
                )
            if raw.startswith("/") or raw.startswith("~"):
                raise self._failure(
                    "headless_write_path_invalid",
                    "headless write paths must be repository-relative",
                    "declare explicit repository-relative write paths",
                )
            components = raw.split("/")
            if any(not component or component in {".", ".."} for component in components):
                raise self._failure(
                    "headless_write_path_invalid",
                    "headless write path contains traversal or ambiguous components",
                    "declare explicit repository-relative write paths",
                )
            normalized_path = PurePosixPath(*components).as_posix()
            serialized_size += len(normalized_path.encode("utf-8")) + 1
            if serialized_size > MAX_DECLARED_PATH_BYTES:
                raise self._failure(
                    "headless_write_path_invalid",
                    "cumulative serialized headless write paths exceed their bound",
                    "declare fewer or shorter repository-relative write paths",
                )
            if normalized_path in seen:
                raise self._failure(
                    "headless_write_path_invalid",
                    "headless write paths contain a duplicate alias",
                    "declare each repository-relative path once",
                )
            seen.add(normalized_path)
            normalized.append((normalized_path, False))
        return tuple(normalized)

    def _verify_declared_paths(
        self, worktree: Path, declarations: tuple[tuple[str, bool], ...]
    ) -> tuple[tuple[str, bool], ...]:
        checked: list[tuple[str, bool]] = []
        for relative, _directory in declarations:
            target = worktree.joinpath(*PurePosixPath(relative).parts)
            self._verify_no_symlink_path(worktree, target)
            is_directory = False
            try:
                info = target.lstat()
            except FileNotFoundError:
                info = None
            except OSError:
                raise self._failure(
                    "headless_write_path_invalid",
                    "declared write path could not be inspected",
                    "declare paths with a readable worktree parent",
                )
            if info is not None:
                if stat.S_ISLNK(info.st_mode):
                    raise self._failure(
                        "headless_write_path_invalid",
                        "declared write path is a symlink",
                        "declare a real worktree path",
                    )
                is_directory = stat.S_ISDIR(info.st_mode)
            checked.append((relative, is_directory))
        return tuple(checked)

    def _verify_no_symlink_path(self, root: Path, target: Path) -> None:
        root_parts = root.parts
        target_parts = target.parts
        if target_parts[: len(root_parts)] != root_parts:
            raise self._failure(
                "headless_write_path_invalid",
                "declared write path escapes the worktree",
                "declare explicit repository-relative write paths",
            )
        current = Path(root.anchor)
        for part in target_parts[1:]:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            except OSError:
                raise self._failure(
                    "headless_write_path_invalid",
                    "declared write path could not be inspected",
                    "declare paths with a readable worktree parent",
                )
            if stat.S_ISLNK(info.st_mode):
                raise self._failure(
                    "headless_write_path_invalid",
                    "declared write path crosses a symlink",
                    "declare a real worktree path",
                )

    def _path_is_declared(
        self, path: str, declarations: tuple[tuple[str, bool], ...]
    ) -> bool:
        if path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/")):
            raise self._failure(
                "headless_write_attribution_unverified",
                "Git reported an ambiguous path",
                "retry after repairing the worktree Git state",
            )
        for declared, is_directory in declarations:
            if path == declared or (is_directory and path.startswith(declared + "/")):
                return True
        return False

    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _real_directory(self, value: Path) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        path = Path(os.path.abspath(path))
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            try:
                info = current.lstat()
            except OSError:
                raise self._failure(
                    "headless_attestation_invalid",
                    "attested path is missing or unreadable",
                    "create a fresh Masterjet worktree attestation",
                )
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise self._failure(
                    "headless_attestation_invalid",
                    "attested path must be a real directory",
                    "create a fresh Masterjet worktree attestation",
                )
        return path

    @staticmethod
    def _require_device(value: Any) -> int:
        if type(value) is not int or value < 0:
            raise ValueError
        return value

    @staticmethod
    def _require_inode(value: Any) -> int:
        if type(value) is not int or value <= 0:
            raise ValueError
        return value

    @staticmethod
    def _require_text(value: Any, field: str, maximum: int) -> str:
        if not isinstance(value, str) or not value or len(value) > maximum:
            raise HeadlessWriteScopeFailure(
                "headless_attestation_invalid",
                f"{field} is malformed",
                "create a fresh Masterjet worktree attestation",
            )
        return value

    @staticmethod
    def _require_generation(value: Any) -> None:
        if isinstance(value, bool) or not isinstance(value, (int, str)) or not value:
            raise HeadlessWriteScopeFailure(
                "headless_assignment_generation_invalid",
                "provider generation is malformed",
                "retry with the current provider/account generation",
            )

    @staticmethod
    def _bounded_output(value: Any, field: str, *, max_bytes: int = 4096) -> str:
        if not isinstance(value, str) or len(value.encode("utf-8", "replace")) > max_bytes:
            raise HeadlessWriteScopeFailure(
                "headless_write_attribution_unverified",
                f"{field} is malformed or exceeds its bound",
                "repair the worktree Git state before retrying",
            )
        return value

    @staticmethod
    def _replace(attestation: ScopeAttestation, **changes: Any) -> ScopeAttestation:
        return replace(attestation, **changes)

    @staticmethod
    def _failure(code: str, explanation: str, action: str) -> HeadlessWriteScopeFailure:
        return HeadlessWriteScopeFailure(code, explanation, action)


def with_context_close(fd: int) -> None:
    if fd < 0:
        return
    try:
        os.close(fd)
    except OSError as exc:
        raise HeadlessWriteScopeFailure(
            "headless_attestation_invalid",
            "attestation journal descriptor could not be closed",
            "repair the Masterjet attestation store before retrying",
        ) from exc
