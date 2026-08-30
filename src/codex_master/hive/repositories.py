"""Repository identity and path-isolation checks for Hive admissions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

from codex_master.hive.types import HiveValidationError, validate_identifier


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BRANCH_RE = re.compile(r"[A-Za-z0-9._/-]{1,128}\Z")
MAX_REMOTE_LENGTH = 512
MAX_GIT_OUTPUT = 64 * 1024
GIT_TIMEOUT_SECONDS = 5
_GIT_ENV = {
    "GIT_CONFIG_COUNT": "0",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": os.defpath,
}


class RepositoryError(ValueError):
    """Raised for an unknown or unsafe repository binding."""


@dataclass(frozen=True, slots=True)
class RepositoryBinding:
    repo_id: str
    remote_identity: str
    local_root: Path
    default_branch: str
    config_digest: str

    def __post_init__(self) -> None:
        try:
            validate_identifier(self.repo_id, field="repo")
        except HiveValidationError as exc:
            raise RepositoryError("invalid_repository_id") from exc
        if (
            not isinstance(self.remote_identity, str)
            or not 1 <= len(self.remote_identity) <= MAX_REMOTE_LENGTH
            or any(ord(char) < 32 for char in self.remote_identity)
        ):
            raise RepositoryError("invalid_remote_identity")
        if not isinstance(self.local_root, Path) or not self.local_root.is_absolute():
            raise RepositoryError("invalid_repository_root")
        if not isinstance(self.default_branch, str) or not _BRANCH_RE.fullmatch(self.default_branch):
            raise RepositoryError("invalid_default_branch")
        if not isinstance(self.config_digest, str) or not _DIGEST_RE.fullmatch(self.config_digest):
            raise RepositoryError("invalid_repository_config_digest")


@dataclass(frozen=True, slots=True)
class RepositoryValidation:
    repo_id: str
    allowed: bool
    reason_code: str

    def public(self) -> dict[str, object]:
        return {
            "repo_id": self.repo_id,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "root": "not_returned",
            "remote": "not_returned",
        }


def _directory_chain_is_real(path: Path) -> bool:
    current = path
    chain: list[Path] = []
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for item in reversed(chain):
        try:
            stat_result = item.lstat()
        except OSError:
            return False
        if not item.is_dir() or (
            stat_result.st_mode & 0o022 and not stat_result.st_mode & stat.S_ISVTX
        ):
            return False
        if item.is_symlink():
            return False
    return True


def _normalize_remote(value: str) -> str:
    text = value.strip()
    if text.startswith("git@") and ":" in text:
        host, path = text[4:].split(":", 1)
        text = f"ssh://git@{host.lower()}/{path}"
    elif "://" in text:
        scheme, rest = text.split("://", 1)
        host, separator, path = rest.partition("/")
        text = f"{scheme.lower()}://{host.lower()}{separator}{path}"
    return text.rstrip("/").removesuffix(".git")


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass


class RepositoryRegistry:
    """Immutable-in-memory registry with fresh read-only git validation."""

    def __init__(self, bindings: Iterable[RepositoryBinding]) -> None:
        values = tuple(bindings)
        if len({item.repo_id for item in values}) != len(values):
            raise RepositoryError("duplicate_repository_id")
        self._bindings = {item.repo_id: item for item in values}

    def get(self, repo_id: str) -> RepositoryBinding:
        try:
            validate_identifier(repo_id, field="repo")
            return self._bindings[repo_id]
        except (HiveValidationError, KeyError) as exc:
            raise RepositoryError("unknown_repository") from exc

    def validate(self, repo_id: str) -> RepositoryValidation:
        binding = self.get(repo_id)
        root = binding.local_root
        try:
            root_stat = root.lstat()
            resolved_root = root.resolve(strict=True)
        except (OSError, RuntimeError):
            return RepositoryValidation(repo_id, False, "repository_root_unavailable")
        if root_stat.st_mode & 0o022 or root.is_symlink() or not root.is_dir():
            return RepositoryValidation(repo_id, False, "repository_root_untrusted")
        if not _directory_chain_is_real(root):
            return RepositoryValidation(repo_id, False, "repository_parent_untrusted")
        if resolved_root != root:
            return RepositoryValidation(repo_id, False, "repository_root_changed")
        top_level = self._git(root, "rev-parse", "--show-toplevel")
        if top_level is None:
            return RepositoryValidation(repo_id, False, "repository_git_unavailable")
        try:
            if Path(top_level).resolve(strict=True) != root:
                return RepositoryValidation(repo_id, False, "repository_root_mismatch")
        except (OSError, RuntimeError):
            return RepositoryValidation(repo_id, False, "repository_root_changed")
        remote = self._git(root, "config", "--get", "remote.origin.url")
        if remote is None or _normalize_remote(remote) != _normalize_remote(binding.remote_identity):
            return RepositoryValidation(repo_id, False, "repository_remote_mismatch")
        branch = self._git(root, "symbolic-ref", "--quiet", "--short", "HEAD")
        if branch != binding.default_branch:
            return RepositoryValidation(repo_id, False, "repository_branch_mismatch")
        commit = self._git(
            root,
            "rev-parse",
            "--verify",
            "--quiet",
            f"refs/heads/{binding.default_branch}^{{commit}}",
        )
        if commit is None:
            return RepositoryValidation(repo_id, False, "repository_commit_unavailable")
        if self._git(root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}") != commit:
            return RepositoryValidation(repo_id, False, "repository_branch_mismatch")
        return RepositoryValidation(repo_id, True, "repository_verified")

    def resolve_path(self, repo_id: str, value: str) -> Path:
        binding = self.get(repo_id)
        if (
            not isinstance(value, str)
            or not value
            or "\\" in value
            or value.startswith(("/", "~"))
            or "://" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
        ):
            raise RepositoryError("repository_path_escape")
        try:
            root = binding.local_root.resolve(strict=True)
            candidate = (root / value).resolve(strict=False)
            candidate.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            raise RepositoryError("repository_path_escape") from None
        return candidate

    def public_status(self, repo_id: str) -> dict[str, object]:
        return self.validate(repo_id).public()

    def scope_digest(self, repo_id: str, mode: str, paths: Iterable[str]) -> str:
        """Return the canonical digest used to bind an admission scope."""

        if mode not in {"read", "write"}:
            raise RepositoryError("invalid_scope_mode")
        canonical = tuple(sorted(os.fspath(self.resolve_path(repo_id, value).relative_to(self.get(repo_id).local_root.resolve(strict=True))) for value in paths))
        if not canonical:
            raise RepositoryError("invalid_scope_paths")
        payload = f"{repo_id}\0{mode}\0" + "\0".join(canonical)
        return f"sha256:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"

    @staticmethod
    def config_digest(payload: bytes) -> str:
        if not isinstance(payload, bytes):
            raise RepositoryError("invalid_repository_config")
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"

    @staticmethod
    def _git(root: Path, *args: str) -> str | None:
        process: subprocess.Popen[bytes] | None = None
        selector: selectors.BaseSelector | None = None
        try:
            process = subprocess.Popen(
                ["git", "-C", os.fspath(root), *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                env=_GIT_ENV,
                start_new_session=True,
            )
            if process.stdout is None:
                return None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            chunks: list[bytes] = []
            output_size = 0
            deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _terminate_process_group(process)
                    return None
                events = selector.select(remaining)
                if not events:
                    _terminate_process_group(process)
                    return None
                for key, _ in events:
                    chunk = os.read(key.fd, min(65536, MAX_GIT_OUTPUT + 1 - output_size))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output_size += len(chunk)
                    if output_size > MAX_GIT_OUTPUT:
                        _terminate_process_group(process)
                        return None
                    chunks.append(chunk)
            try:
                returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                _terminate_process_group(process)
                return None
            if returncode != 0:
                return None
            try:
                output = b"".join(chunks).decode("utf-8")
            except UnicodeError:
                return None
        except (OSError, subprocess.SubprocessError):
            if process is not None:
                _terminate_process_group(process)
            return None
        finally:
            if selector is not None:
                selector.close()
            if process is not None and process.stdout is not None:
                process.stdout.close()
        value = output.strip()
        return value or None


__all__ = [
    "RepositoryBinding",
    "RepositoryError",
    "RepositoryRegistry",
    "RepositoryValidation",
]
