"""Lease-bound, temporary runtime homes for logical Hive Queens.

Queen identity and memory remain in the control plane.  This module only owns
the short-lived process home required by a real CLI runtime.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Iterator


DEFAULT_QUEEN_HOME_ROOT = Path("/home/teladi/.codex-agents/Queens")
DEFAULT_STATE_ROOT = Path.home() / ".local/state/codex-master-mcp"
_IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
_HOME_RE = re.compile(r"^Queen([1-9][0-9]{0,8})$")


class QueenRuntimeError(RuntimeError):
    """A Queen runtime home cannot be safely materialized or cleaned."""


@dataclass(frozen=True, slots=True)
class QueenRuntimeHome:
    ordinal: int
    principal_id: str
    repository_id: str
    lease_id: str
    fence: str
    generation: int
    path: Path


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and bool(_IDENTIFIER_RE.fullmatch(value))


def _private_directory(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700, parents=True)
    if not path.is_dir() or path.is_symlink():
        raise QueenRuntimeError("queen_runtime_root_invalid")
    os.chmod(path, 0o700)


class QueenRuntimeHomeManager:
    """Materialize and reap numbered Queen homes under one private root."""

    def __init__(
        self,
        *,
        root: Path = DEFAULT_QUEEN_HOME_ROOT,
        state_root: Path = DEFAULT_STATE_ROOT,
    ) -> None:
        self.root = Path(root)
        self.state_root = Path(state_root)
        self._registry_path = self.state_root / "queen-runtime-homes.json"
        self._lock_path = self.state_root / "queen-runtime-homes.lock"

    @contextmanager
    def _locked(self) -> Iterator[None]:
        _private_directory(self.state_root)
        handle = self._lock_path.open("a+", encoding="utf-8")
        try:
            os.chmod(self._lock_path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def _load_registry(self) -> dict[str, Any]:
        try:
            raw = json.loads(self._registry_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schema_version": 1, "next_ordinal": 1, "homes": {}}
        except (OSError, TypeError, ValueError) as exc:
            raise QueenRuntimeError("queen_runtime_registry_invalid") from exc
        if (
            not isinstance(raw, dict)
            or raw.get("schema_version") != 1
            or not isinstance(raw.get("next_ordinal"), int)
            or raw["next_ordinal"] < 1
            or not isinstance(raw.get("homes"), dict)
        ):
            raise QueenRuntimeError("queen_runtime_registry_invalid")
        return raw

    def _save_registry(self, registry: dict[str, Any]) -> None:
        temporary = self._registry_path.with_name(self._registry_path.name + ".tmp")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(registry, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._registry_path)
            os.chmod(self._registry_path, 0o600)
        except Exception:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    @staticmethod
    def _entry(runtime: QueenRuntimeHome, *, state: str) -> dict[str, Any]:
        return {
            "state": state,
            "principal_id": runtime.principal_id,
            "repository_id": runtime.repository_id,
            "lease_id": runtime.lease_id,
            "fence": runtime.fence,
            "generation": runtime.generation,
            "home_name": runtime.path.name,
        }

    def materialize(
        self,
        *,
        principal_id: str,
        repository_id: str,
        lease_id: str,
        fence: str,
        generation: int,
    ) -> QueenRuntimeHome:
        """Create one new numbered home, atomically bound to its lease."""
        if not all(_valid_identifier(item) for item in (principal_id, repository_id, lease_id, fence)):
            raise QueenRuntimeError("invalid_queen_runtime_binding")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise QueenRuntimeError("invalid_queen_runtime_generation")
        with self._locked():
            _private_directory(self.root)
            registry = self._load_registry()
            ordinal = registry["next_ordinal"]
            if ordinal > 999_999_999:
                raise QueenRuntimeError("queen_runtime_ordinal_exhausted")
            path = self.root / f"Queen{ordinal}"
            if path.exists() or path.is_symlink():
                raise QueenRuntimeError("queen_runtime_home_collision")
            runtime = QueenRuntimeHome(ordinal, principal_id, repository_id, lease_id, fence, generation, path)
            registry["next_ordinal"] = ordinal + 1
            registry["homes"][str(ordinal)] = self._entry(runtime, state="allocating")
            self._save_registry(registry)
            staging = Path(tempfile.mkdtemp(prefix=".Queen-staging-", dir=self.root))
            try:
                os.chmod(staging, 0o700)
                codex_home = staging / "codex-home"
                codex_home.mkdir(mode=0o700)
                metadata = staging / ".queen-runtime.json"
                metadata.write_text(json.dumps(self._entry(runtime, state="active"), sort_keys=True) + "\n", encoding="utf-8")
                os.chmod(metadata, 0o600)
                os.replace(staging, path)
                registry["homes"][str(ordinal)] = self._entry(runtime, state="active")
                self._save_registry(registry)
            except Exception as exc:
                registry["homes"][str(ordinal)] = self._entry(runtime, state="quarantined")
                self._save_registry(registry)
                if staging.exists():
                    shutil.rmtree(staging, ignore_errors=True)
                raise QueenRuntimeError("queen_runtime_materialization_failed") from exc
            return runtime

    def release(self, runtime: QueenRuntimeHome) -> dict[str, Any]:
        """Remove only a matching active home; preserve any mismatch for review."""
        with self._locked():
            registry = self._load_registry()
            entry = registry["homes"].get(str(runtime.ordinal))
            if not isinstance(entry, dict) or entry != self._entry(runtime, state="active"):
                raise QueenRuntimeError("queen_runtime_binding_mismatch")
            if runtime.path.parent != self.root or not _HOME_RE.fullmatch(runtime.path.name):
                raise QueenRuntimeError("queen_runtime_path_invalid")
            try:
                metadata = json.loads((runtime.path / ".queen-runtime.json").read_text(encoding="utf-8"))
            except (OSError, TypeError, ValueError):
                metadata = None
            if metadata != self._entry(runtime, state="active"):
                registry["homes"][str(runtime.ordinal)] = self._entry(runtime, state="quarantined")
                self._save_registry(registry)
                return {"released": False, "quarantined": True, "reason": "queen_runtime_metadata_mismatch"}
            try:
                shutil.rmtree(runtime.path)
            except OSError:
                registry["homes"][str(runtime.ordinal)] = self._entry(runtime, state="quarantined")
                self._save_registry(registry)
                return {"released": False, "quarantined": True, "reason": "queen_runtime_cleanup_failed"}
            registry["homes"][str(runtime.ordinal)] = self._entry(runtime, state="released")
            self._save_registry(registry)
            return {"released": True, "quarantined": False, "reason": None}


__all__ = ["DEFAULT_QUEEN_HOME_ROOT", "QueenRuntimeError", "QueenRuntimeHome", "QueenRuntimeHomeManager"]
