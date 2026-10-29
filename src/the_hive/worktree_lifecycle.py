"""Persistent worktree-use leases and fenced maintenance claims."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import hashlib
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import subprocess
import tempfile
import time

from the_hive.hive.state import (
    MAX_HIVE_STATE_BYTES,
    HiveStateError,
    HiveStateStore,
)
from the_hive.resource_cgroup import PreparedAgentScope
from the_hive.runtime_process import (
    G5ScopeIdentity,
    bind_g5_scope,
    g5_scope_is_empty,
)


_STATE_PATH = PurePosixPath("worktree-lifecycle-v1.json")
_MAX_HISTORY_PER_WORKTREE = 128
_RUNTIME_BINDING_SEAL = object()
_G5_SCOPE_BINDING_SEAL = object()
_END_EVIDENCE_SEAL = object()
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class WorktreeLifecycleError(ValueError):
    """Raised when worktree lifecycle evidence or state is invalid."""


def _required_text(value: object, *, maximum: int = 512) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and not any(ord(char) < 32 for char in value)
    )


def _valid_integer(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


def _require_text(value: object, *, code: str, maximum: int = 512) -> None:
    if not _required_text(value, maximum=maximum):
        raise WorktreeLifecycleError(code)


def _require_integer(value: object, *, code: str, minimum: int = 0) -> None:
    if not _valid_integer(value, minimum=minimum):
        raise WorktreeLifecycleError(code)


def _require_canonical_absolute_path(value: object, *, code: str) -> None:
    if not isinstance(value, Path) or not value.is_absolute():
        raise WorktreeLifecycleError(code)
    if str(value) != os.path.normpath(str(value)):
        raise WorktreeLifecycleError(code)


@dataclass(frozen=True, slots=True)
class WorktreeBinding:
    repository_id: str
    canonical_source_path: Path
    git_common_directory: Path
    device: int
    inode: int
    mount_id: int

    @classmethod
    def from_creation_attestation(cls, attestation: object) -> WorktreeBinding:
        fields = (
            "repository_device",
            "repository_inode",
            "worktree_path",
            "worktree_device",
            "worktree_inode",
            "common_git_dir",
        )
        if any(not hasattr(attestation, field) for field in fields):
            raise WorktreeLifecycleError("worktree_origin_evidence_invalid")
        source = attestation.worktree_path
        if not isinstance(source, Path):
            raise WorktreeLifecycleError("worktree_origin_evidence_invalid")
        return cls(
            repository_id=(
                f"repo:{attestation.repository_device:x}:"
                f"{attestation.repository_inode:x}"
            ),
            canonical_source_path=source,
            git_common_directory=attestation.common_git_dir,
            device=attestation.worktree_device,
            inode=attestation.worktree_inode,
            mount_id=_mount_id(source),
        )

    def __post_init__(self) -> None:
        _require_text(self.repository_id, code="worktree_binding_invalid", maximum=128)
        _require_canonical_absolute_path(
            self.canonical_source_path, code="worktree_binding_invalid"
        )
        _require_canonical_absolute_path(
            self.git_common_directory, code="worktree_binding_invalid"
        )
        _require_integer(self.device, code="worktree_binding_invalid")
        _require_integer(self.inode, code="worktree_binding_invalid", minimum=1)
        _require_integer(self.mount_id, code="worktree_binding_invalid", minimum=1)


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    start_time_ticks: int
    boot_id: str

    def __post_init__(self) -> None:
        _require_integer(self.pid, code="process_identity_invalid", minimum=1)
        _require_integer(self.start_time_ticks, code="process_identity_invalid")
        _require_text(self.boot_id, code="process_identity_invalid", maximum=64)


@dataclass(frozen=True, slots=True)
class RuntimeProcessIdentity:
    pid: int
    start_time_ticks: int
    boot_id: str
    process_group_id: int
    cgroup_digest: str

    def __post_init__(self) -> None:
        _require_integer(self.pid, code="runtime_identity_invalid", minimum=1)
        _require_integer(self.start_time_ticks, code="runtime_identity_invalid")
        _require_text(self.boot_id, code="runtime_identity_invalid", maximum=64)
        _require_integer(
            self.process_group_id, code="runtime_identity_invalid", minimum=1
        )
        if len(self.cgroup_digest) != 64 or any(
            char not in "0123456789abcdef" for char in self.cgroup_digest
        ):
            raise WorktreeLifecycleError("runtime_identity_invalid")


@dataclass(frozen=True, slots=True)
class UseLease:
    lease_id: str
    binding: WorktreeBinding
    principal_id: str
    session_id: str
    assignment_id: str
    revision: int
    fence: int
    owner_process: ProcessIdentity
    runtime_process: RuntimeProcessIdentity | None
    runtime_scope: G5ScopeIdentity | None
    started_at: int

    def __post_init__(self) -> None:
        if type(self.binding) is not WorktreeBinding:
            raise WorktreeLifecycleError("use_lease_invalid")
        if type(self.owner_process) is not ProcessIdentity:
            raise WorktreeLifecycleError("use_lease_invalid")
        if (
            self.runtime_process is not None
            and type(self.runtime_process) is not RuntimeProcessIdentity
        ):
            raise WorktreeLifecycleError("use_lease_invalid")
        if (
            self.runtime_scope is not None
            and type(self.runtime_scope) is not G5ScopeIdentity
        ):
            raise WorktreeLifecycleError("use_lease_invalid")
        _require_text(self.lease_id, code="use_lease_invalid", maximum=128)
        for value in (self.principal_id, self.session_id, self.assignment_id):
            _require_text(value, code="use_lease_invalid")
        _require_integer(self.revision, code="use_lease_invalid", minimum=1)
        _require_integer(self.fence, code="use_lease_invalid", minimum=1)
        _require_integer(self.started_at, code="use_lease_invalid")


@dataclass(frozen=True, slots=True)
class MaintenanceClaim:
    claim_id: str
    candidate: WorktreeBinding
    revision: int
    fence: int
    owner_process: ProcessIdentity
    claimed_at: int

    def __post_init__(self) -> None:
        if type(self.candidate) is not WorktreeBinding:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        if type(self.owner_process) is not ProcessIdentity:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        _require_text(self.claim_id, code="maintenance_claim_invalid", maximum=128)
        _require_integer(self.revision, code="maintenance_claim_invalid", minimum=1)
        _require_integer(self.fence, code="maintenance_claim_invalid", minimum=1)
        _require_integer(self.claimed_at, code="maintenance_claim_invalid")


@dataclass(frozen=True, slots=True)
class WorktreeLifecycleSnapshot:
    revision: int
    active_uses: tuple[UseLease, ...]
    maintenance_claims: tuple[MaintenanceClaim, ...]


@dataclass(frozen=True, slots=True, init=False)
class RuntimeBindingEvidence:
    """Sealed capture of a running child process returned by a launcher."""

    lease_id: str
    binding_key: str
    principal_id: str
    session_id: str
    assignment_id: str
    runtime_process: RuntimeProcessIdentity | None
    observed_at: int
    _seal: object

    @classmethod
    def capture(
        cls,
        lease: UseLease,
        process: subprocess.Popen[object],
        *,
        now: int,
    ) -> RuntimeBindingEvidence:
        if type(lease) is not UseLease or not isinstance(process, subprocess.Popen):
            raise WorktreeLifecycleError("runtime_binding_evidence_invalid")
        _require_integer(now, code="runtime_binding_evidence_invalid")
        if now < lease.started_at or process.poll() is not None:
            raise WorktreeLifecycleError("runtime_process_not_active")
        identity = _runtime_process_identity(process.pid)
        if identity.process_group_id != identity.pid:
            raise WorktreeLifecycleError("runtime_process_not_isolated")
        evidence = object.__new__(cls)
        object.__setattr__(evidence, "lease_id", lease.lease_id)
        object.__setattr__(evidence, "binding_key", _binding_key(lease.binding))
        object.__setattr__(evidence, "principal_id", lease.principal_id)
        object.__setattr__(evidence, "session_id", lease.session_id)
        object.__setattr__(evidence, "assignment_id", lease.assignment_id)
        object.__setattr__(evidence, "runtime_process", identity)
        object.__setattr__(evidence, "observed_at", now)
        object.__setattr__(evidence, "_seal", _RUNTIME_BINDING_SEAL)
        return evidence


@dataclass(frozen=True, slots=True, init=False)
class G5ScopeBindingEvidence:
    lease_id: str
    binding_key: str
    principal_id: str
    session_id: str
    assignment_id: str
    runtime_scope: G5ScopeIdentity
    observed_at: int
    _seal: object

    @classmethod
    def capture(
        cls, lease: UseLease, scope: PreparedAgentScope, *, now: int
    ) -> G5ScopeBindingEvidence:
        if type(lease) is not UseLease or type(scope) is not PreparedAgentScope:
            raise WorktreeLifecycleError("runtime_binding_evidence_invalid")
        _require_integer(now, code="runtime_binding_evidence_invalid")
        if now < lease.started_at:
            raise WorktreeLifecycleError("runtime_binding_evidence_invalid")
        try:
            identity = bind_g5_scope(scope.unit_name, scope.control_group)
        except Exception as exc:
            raise WorktreeLifecycleError("runtime_cgroup_binding_unavailable") from exc
        evidence = object.__new__(cls)
        object.__setattr__(evidence, "lease_id", lease.lease_id)
        object.__setattr__(evidence, "binding_key", _binding_key(lease.binding))
        object.__setattr__(evidence, "principal_id", lease.principal_id)
        object.__setattr__(evidence, "session_id", lease.session_id)
        object.__setattr__(evidence, "assignment_id", lease.assignment_id)
        object.__setattr__(evidence, "runtime_scope", identity)
        object.__setattr__(evidence, "observed_at", now)
        object.__setattr__(evidence, "_seal", _G5_SCOPE_BINDING_SEAL)
        return evidence


@dataclass(frozen=True, slots=True, init=False)
class RuntimeEndEvidence:
    """Opaque evidence that the bound runtime process has exited."""

    lease_id: str
    binding_key: str
    principal_id: str
    session_id: str
    assignment_id: str
    runtime_process: RuntimeProcessIdentity | None
    runtime_scope: G5ScopeIdentity | None
    observed_at: int
    _seal: object

    @classmethod
    def observe(cls, lease: UseLease, *, now: int) -> RuntimeEndEvidence:
        if type(lease) is not UseLease:
            raise WorktreeLifecycleError("end_evidence_invalid")
        _require_integer(now, code="end_evidence_invalid")
        if lease.runtime_scope is not None:
            if not g5_scope_is_empty(lease.runtime_scope):
                raise WorktreeLifecycleError("runtime_process_active")
        elif lease.runtime_process is None:
            raise WorktreeLifecycleError("runtime_binding_pending")
        else:
            if _runtime_process_is_active(lease.runtime_process):
                raise WorktreeLifecycleError("runtime_process_active")
            raise WorktreeLifecycleError("runtime_reference_boundary_unavailable")
        if now < lease.started_at or (
            lease.runtime_process is not None
            and _runtime_process_is_active(lease.runtime_process)
        ):
            raise WorktreeLifecycleError("runtime_process_active")
        evidence = object.__new__(cls)
        object.__setattr__(evidence, "lease_id", lease.lease_id)
        object.__setattr__(evidence, "binding_key", _binding_key(lease.binding))
        object.__setattr__(evidence, "principal_id", lease.principal_id)
        object.__setattr__(evidence, "session_id", lease.session_id)
        object.__setattr__(evidence, "assignment_id", lease.assignment_id)
        object.__setattr__(evidence, "runtime_process", lease.runtime_process)
        object.__setattr__(evidence, "runtime_scope", lease.runtime_scope)
        object.__setattr__(evidence, "observed_at", now)
        object.__setattr__(evidence, "_seal", _END_EVIDENCE_SEAL)
        return evidence


@dataclass(frozen=True, slots=True)
class _TreeState:
    binding: WorktreeBinding
    origin: Mapping[str, object] | None
    revision: int
    fence: int
    active_uses: tuple[UseLease, ...]
    maintenance_claim: MaintenanceClaim | None
    use_history: tuple[Mapping[str, object], ...]
    maintenance_history: tuple[Mapping[str, object], ...]
    maintenance_operation: Mapping[str, object] | None


def _boot_id() -> str:
    try:
        value = (
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        )
    except OSError as exc:
        raise WorktreeLifecycleError("process_identity_unavailable") from exc
    _require_text(value, code="process_identity_unavailable", maximum=64)
    return value


def _read_process_stat(pid: int) -> tuple[str, int, int] | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise WorktreeLifecycleError("process_identity_unavailable") from exc
    right_paren = text.rfind(")")
    if right_paren < 0:
        raise WorktreeLifecycleError("process_identity_unavailable")
    fields = text[right_paren + 1 :].split()
    if len(fields) <= 19 or len(fields[0]) != 1:
        raise WorktreeLifecycleError("process_identity_unavailable")
    try:
        start_time_ticks = int(fields[19])
        process_group_id = int(fields[2])
    except ValueError as exc:
        raise WorktreeLifecycleError("process_identity_unavailable") from exc
    return fields[0], start_time_ticks, process_group_id


def _current_process_identity() -> ProcessIdentity:
    info = _read_process_stat(os.getpid())
    if info is None:
        raise WorktreeLifecycleError("process_identity_unavailable")
    return ProcessIdentity(os.getpid(), info[1], _boot_id())


def _process_is_active(identity: ProcessIdentity) -> bool:
    if _boot_id() != identity.boot_id:
        return False
    info = _read_process_stat(identity.pid)
    if info is None or info[1] != identity.start_time_ticks:
        return False
    return info[0] not in {"Z", "X"}


def _cgroup_digest(pid: int) -> str:
    try:
        content = Path(f"/proc/{pid}/cgroup").read_bytes()
    except OSError as exc:
        raise WorktreeLifecycleError("runtime_cgroup_unavailable") from exc
    if not content:
        raise WorktreeLifecycleError("runtime_cgroup_unavailable")
    return hashlib.sha256(content).hexdigest()


def _runtime_process_identity(pid: int) -> RuntimeProcessIdentity:
    info = _read_process_stat(pid)
    if info is None or info[0] in {"Z", "X"}:
        raise WorktreeLifecycleError("runtime_process_not_active")
    return RuntimeProcessIdentity(
        pid=pid,
        start_time_ticks=info[1],
        boot_id=_boot_id(),
        process_group_id=info[2],
        cgroup_digest=_cgroup_digest(pid),
    )


def _runtime_process_is_active(identity: RuntimeProcessIdentity) -> bool:
    if _boot_id() != identity.boot_id:
        return False
    info = _read_process_stat(identity.pid)
    if info is not None and info[1] == identity.start_time_ticks:
        if _cgroup_digest(identity.pid) != identity.cgroup_digest:
            return True
        if info[0] not in {"Z", "X"}:
            return True
    # A Popen leader cannot prove that descendants in other sessions exited.
    return True


def _mount_id(path: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            text = Path(f"/proc/self/fdinfo/{descriptor}").read_text(encoding="ascii")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise WorktreeLifecycleError("worktree_mount_identity_unavailable") from exc
    for line in text.splitlines():
        if line.startswith("mnt_id:"):
            try:
                return int(line.partition(":")[2].strip())
            except ValueError as exc:
                raise WorktreeLifecycleError(
                    "worktree_mount_identity_unavailable"
                ) from exc
    raise WorktreeLifecycleError("worktree_mount_identity_unavailable")


def _validate_live_binding(binding: WorktreeBinding) -> None:
    try:
        source = binding.canonical_source_path
        common = binding.git_common_directory
        if (
            source.resolve(strict=True) != source
            or common.resolve(strict=True) != common
        ):
            raise WorktreeLifecycleError("worktree_binding_changed")
        source_info = source.stat(follow_symlinks=False)
        common_info = common.stat(follow_symlinks=False)
    except WorktreeLifecycleError:
        raise
    except OSError as exc:
        raise WorktreeLifecycleError("worktree_binding_unavailable") from exc
    if (
        not stat.S_ISDIR(source_info.st_mode)
        or not stat.S_ISDIR(common_info.st_mode)
        or source_info.st_dev != binding.device
        or source_info.st_ino != binding.inode
        or _mount_id(source) != binding.mount_id
    ):
        raise WorktreeLifecycleError("worktree_binding_changed")
    actual_common = _git_common_directory(source)
    if actual_common != common:
        raise WorktreeLifecycleError("worktree_git_common_mismatch")


def _git_common_directory(source: Path) -> Path:
    metadata = source / ".git"
    try:
        info = metadata.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise WorktreeLifecycleError("worktree_git_metadata_untrusted")
        if stat.S_ISDIR(info.st_mode):
            git_directory = metadata.resolve(strict=True)
        elif stat.S_ISREG(info.st_mode):
            content = metadata.read_text(encoding="utf-8").strip()
            if not content.startswith("gitdir:"):
                raise WorktreeLifecycleError("worktree_git_metadata_invalid")
            target = Path(content.partition(":")[2].strip())
            git_directory = (
                target if target.is_absolute() else source / target
            ).resolve(strict=True)
        else:
            raise WorktreeLifecycleError("worktree_git_metadata_invalid")
        common_file = git_directory / "commondir"
        if common_file.exists():
            common_target = Path(common_file.read_text(encoding="utf-8").strip())
            common = (
                common_target
                if common_target.is_absolute()
                else git_directory / common_target
            ).resolve(strict=True)
        else:
            common = git_directory
        if not common.is_dir():
            raise WorktreeLifecycleError("worktree_git_metadata_invalid")
        return common
    except WorktreeLifecycleError:
        raise
    except (OSError, UnicodeError) as exc:
        raise WorktreeLifecycleError("worktree_git_metadata_invalid") from exc


def _binding_payload(binding: WorktreeBinding) -> dict[str, object]:
    return {
        "repository_id": binding.repository_id,
        "canonical_source_path": str(binding.canonical_source_path),
        "git_common_directory": str(binding.git_common_directory),
        "device": binding.device,
        "inode": binding.inode,
        "mount_id": binding.mount_id,
    }


def _binding_from_payload(payload: object) -> WorktreeBinding:
    if not isinstance(payload, Mapping) or set(payload) != {
        "repository_id",
        "canonical_source_path",
        "git_common_directory",
        "device",
        "inode",
        "mount_id",
    }:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    if not isinstance(payload["canonical_source_path"], str) or not isinstance(
        payload["git_common_directory"], str
    ):
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    return WorktreeBinding(
        repository_id=payload["repository_id"],
        canonical_source_path=Path(payload["canonical_source_path"]),
        git_common_directory=Path(payload["git_common_directory"]),
        device=payload["device"],
        inode=payload["inode"],
        mount_id=payload["mount_id"],
    )


def _binding_key(binding: WorktreeBinding) -> str:
    encoded = json.dumps(
        {"device": binding.device, "inode": binding.inode},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _process_payload(identity: ProcessIdentity) -> dict[str, object]:
    return {
        "pid": identity.pid,
        "start_time_ticks": identity.start_time_ticks,
        "boot_id": identity.boot_id,
    }


def _process_from_payload(payload: object) -> ProcessIdentity:
    if not isinstance(payload, Mapping) or set(payload) != {
        "pid",
        "start_time_ticks",
        "boot_id",
    }:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    return ProcessIdentity(
        pid=payload["pid"],
        start_time_ticks=payload["start_time_ticks"],
        boot_id=payload["boot_id"],
    )


def _runtime_process_payload(
    identity: RuntimeProcessIdentity,
) -> dict[str, object]:
    return {
        "pid": identity.pid,
        "start_time_ticks": identity.start_time_ticks,
        "boot_id": identity.boot_id,
        "process_group_id": identity.process_group_id,
        "cgroup_digest": identity.cgroup_digest,
    }


def _runtime_process_from_payload(payload: object) -> RuntimeProcessIdentity:
    if not isinstance(payload, Mapping) or set(payload) != {
        "pid",
        "start_time_ticks",
        "boot_id",
        "process_group_id",
        "cgroup_digest",
    }:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    return RuntimeProcessIdentity(
        pid=payload["pid"],
        start_time_ticks=payload["start_time_ticks"],
        boot_id=payload["boot_id"],
        process_group_id=payload["process_group_id"],
        cgroup_digest=payload["cgroup_digest"],
    )


def _runtime_scope_payload(identity: G5ScopeIdentity) -> dict[str, object]:
    return {
        "unit_name": identity.unit_name,
        "control_group": identity.control_group,
        "invocation_id": identity.invocation_id,
        "device": identity.device,
        "inode": identity.inode,
    }


def _runtime_scope_from_payload(payload: object) -> G5ScopeIdentity:
    if not isinstance(payload, Mapping) or set(payload) != {
        "unit_name",
        "control_group",
        "invocation_id",
        "device",
        "inode",
    }:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    try:
        return G5ScopeIdentity(
            unit_name=payload["unit_name"],
            control_group=payload["control_group"],
            invocation_id=payload["invocation_id"],
            device=payload["device"],
            inode=payload["inode"],
        )
    except Exception as exc:
        raise WorktreeLifecycleError("lifecycle_state_invalid") from exc


def _lease_payload(lease: UseLease) -> dict[str, object]:
    return {
        "lease_id": lease.lease_id,
        "principal_id": lease.principal_id,
        "session_id": lease.session_id,
        "assignment_id": lease.assignment_id,
        "revision": lease.revision,
        "fence": lease.fence,
        "owner_process": _process_payload(lease.owner_process),
        "runtime_process": (
            None
            if lease.runtime_process is None
            else _runtime_process_payload(lease.runtime_process)
        ),
        "runtime_scope": (
            None
            if lease.runtime_scope is None
            else _runtime_scope_payload(lease.runtime_scope)
        ),
        "started_at": lease.started_at,
    }


def _lease_from_payload(binding: WorktreeBinding, payload: object) -> UseLease:
    legacy_fields = {
        "lease_id",
        "principal_id",
        "session_id",
        "assignment_id",
        "revision",
        "fence",
        "owner_process",
        "runtime_process",
        "started_at",
    }
    if not isinstance(payload, Mapping) or frozenset(payload) not in {
        frozenset(legacy_fields),
        frozenset(legacy_fields | {"runtime_scope"}),
    }:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    return UseLease(
        lease_id=payload["lease_id"],
        binding=binding,
        principal_id=payload["principal_id"],
        session_id=payload["session_id"],
        assignment_id=payload["assignment_id"],
        revision=payload["revision"],
        fence=payload["fence"],
        owner_process=_process_from_payload(payload["owner_process"]),
        runtime_process=(
            None
            if payload["runtime_process"] is None
            else _runtime_process_from_payload(payload["runtime_process"])
        ),
        runtime_scope=(
            None
            if payload.get("runtime_scope") is None
            else _runtime_scope_from_payload(payload.get("runtime_scope"))
        ),
        started_at=payload["started_at"],
    )


def _claim_payload(claim: MaintenanceClaim) -> dict[str, object]:
    return {
        "claim_id": claim.claim_id,
        "revision": claim.revision,
        "fence": claim.fence,
        "owner_process": _process_payload(claim.owner_process),
        "claimed_at": claim.claimed_at,
    }


def _claim_from_payload(
    candidate: WorktreeBinding, payload: object
) -> MaintenanceClaim:
    if not isinstance(payload, Mapping) or set(payload) != {
        "claim_id",
        "revision",
        "fence",
        "owner_process",
        "claimed_at",
    }:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    return MaintenanceClaim(
        claim_id=payload["claim_id"],
        candidate=candidate,
        revision=payload["revision"],
        fence=payload["fence"],
        owner_process=_process_from_payload(payload["owner_process"]),
        claimed_at=payload["claimed_at"],
    )


def _runtime_reference_count(
    document: Mapping[str, object], identity: RuntimeProcessIdentity
) -> int:
    expected = _runtime_process_payload(identity)
    count = 0
    for tree in document["worktrees"].values():
        for lease in tree["active_uses"]:
            if lease["runtime_process"] == expected:
                count += 1
    return count


def _g5_scope_reference_count(
    document: Mapping[str, object], identity: G5ScopeIdentity
) -> int:
    expected = _runtime_scope_payload(identity)
    count = 0
    for tree in document["worktrees"].values():
        for lease in tree["active_uses"]:
            if lease["runtime_scope"] == expected:
                count += 1
    return count


def _empty_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "revision": 0,
        "worktrees": {},
        "native_references": [],
    }


def _empty_tree(
    binding: WorktreeBinding,
    origin: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "binding": _binding_payload(binding),
        "origin": None if origin is None else dict(origin),
        "revision": 0,
        "fence": 0,
        "active_uses": [],
        "maintenance_claim": None,
        "maintenance_operation": None,
        "use_history": [],
        "maintenance_history": [],
    }


def _tree_state(key: str, value: object) -> _TreeState:
    if not isinstance(value, Mapping) or frozenset(value) not in {
        frozenset(
            {
                "binding",
                "revision",
                "fence",
                "active_uses",
                "maintenance_claim",
                "use_history",
                "maintenance_history",
            }
        ),
        frozenset(
            {
                "binding",
                "origin",
                "revision",
                "fence",
                "active_uses",
                "maintenance_claim",
                "use_history",
                "maintenance_history",
            }
        ),
        frozenset(
            {
                "binding",
                "revision",
                "fence",
                "active_uses",
                "maintenance_claim",
                "maintenance_operation",
                "use_history",
                "maintenance_history",
            }
        ),
        frozenset(
            {
                "binding",
                "origin",
                "revision",
                "fence",
                "active_uses",
                "maintenance_claim",
                "maintenance_operation",
                "use_history",
                "maintenance_history",
            }
        ),
    }:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    binding = _binding_from_payload(value["binding"])
    if _binding_key(binding) != key:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    _require_integer(value["revision"], code="lifecycle_state_invalid")
    _require_integer(value["fence"], code="lifecycle_state_invalid")
    origin = value.get("origin")
    if origin is not None and (
        not isinstance(origin, Mapping)
        or set(origin)
        != {
            "attestation_id",
            "agent_id",
            "repository_device",
            "repository_inode",
            "worktree_device",
            "worktree_inode",
            "common_git_device",
            "common_git_inode",
            "creation_generation",
            "created_at_utc",
        }
        or not _required_text(origin["attestation_id"], maximum=64)
        or not _required_text(origin["agent_id"], maximum=200)
        or not _valid_integer(origin["repository_device"])
        or not _valid_integer(origin["repository_inode"], minimum=1)
        or not _valid_integer(origin["worktree_device"])
        or not _valid_integer(origin["worktree_inode"], minimum=1)
        or not _valid_integer(origin["common_git_device"])
        or not _valid_integer(origin["common_git_inode"], minimum=1)
        or not _required_text(origin["creation_generation"], maximum=64)
        or not _required_text(origin["created_at_utc"], maximum=64)
    ):
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    if origin is not None:
        try:
            repository_id = (
                f"repo:{origin['repository_device']:x}:{origin['repository_inode']:x}"
            )
            origin_matches_binding = (
                binding.repository_id == repository_id
                and origin["worktree_device"] == binding.device
                and origin["worktree_inode"] == binding.inode
            )
        except (KeyError, TypeError, ValueError):
            origin_matches_binding = False
        if not origin_matches_binding:
            raise WorktreeLifecycleError("lifecycle_state_invalid")
    if not isinstance(value["active_uses"], list):
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    uses = tuple(_lease_from_payload(binding, row) for row in value["active_uses"])
    if len({lease.lease_id for lease in uses}) != len(uses):
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    raw_claim = value["maintenance_claim"]
    claim = None if raw_claim is None else _claim_from_payload(binding, raw_claim)
    if claim is not None and (
        uses or claim.revision != value["revision"] or claim.fence != value["fence"]
    ):
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    operation = value.get("maintenance_operation")
    if operation is not None:
        operation_keys = {
            "claim_id",
            "phase",
            "operation_kind",
            "source_device",
            "source_inode",
            "source_mount_id",
            "git_common_device",
            "git_common_inode",
            "archive_path",
            "archive_manifest_sha256",
            "archive_device",
            "archive_inode",
            "gitdir_relative",
            "gitdir_device",
            "gitdir_inode",
            "archive_lock_path",
            "archive_lock_device",
            "archive_lock_inode",
            "archive_lock_mount_id",
            "temporary_source_path",
            "temporary_source_device",
            "temporary_source_inode",
            "temporary_source_mount_id",
            "temporary_producer_lease_id",
            "collision_evidence",
        }
        current_legacy_operation_keys = operation_keys - {
            "archive_lock_path",
            "archive_lock_device",
            "archive_lock_inode",
            "archive_lock_mount_id",
        }
        previous_operation_keys = operation_keys - {
            "operation_kind",
            "temporary_source_path",
            "temporary_source_device",
            "temporary_source_inode",
            "temporary_source_mount_id",
            "temporary_producer_lease_id",
        }
        accepted_operation_keys = {
            frozenset(current_legacy_operation_keys),
            frozenset(current_legacy_operation_keys - {"collision_evidence"}),
            frozenset(operation_keys),
            frozenset(operation_keys - {"collision_evidence"}),
            frozenset(previous_operation_keys),
            frozenset(previous_operation_keys - {"collision_evidence"}),
            frozenset(
                previous_operation_keys
                - {
                    "archive_lock_path",
                    "archive_lock_device",
                    "archive_lock_inode",
                    "archive_lock_mount_id",
                }
            ),
            frozenset(
                previous_operation_keys
                - {
                    "archive_lock_path",
                    "archive_lock_device",
                    "archive_lock_inode",
                    "archive_lock_mount_id",
                    "collision_evidence",
                }
            ),
        }
        raw_operation_keys = (
            frozenset(operation) if isinstance(operation, Mapping) else frozenset()
        )
        phase = operation.get("phase") if isinstance(operation, Mapping) else None
        archive_recorded = phase in {
            "archive_verified",
            "quarantine_started",
            "quarantined",
            "deleting",
            "removed",
            "restored",
        } or (phase == "recovery_hold" and operation.get("archive_path") is not None)
        if (
            claim is None
            or not isinstance(operation, Mapping)
            or raw_operation_keys not in accepted_operation_keys
            or operation.get("claim_id") != claim.claim_id
            or phase
            not in {
                "claimed",
                "archiving",
                "archive_verified",
                "quarantine_started",
                "quarantined",
                "deleting",
                "removed",
                "restored",
                "recovery_hold",
            }
            or operation.get("source_device") != binding.device
            or operation.get("source_inode") != binding.inode
            or operation.get("source_mount_id") != binding.mount_id
            or operation.get("operation_kind", "worktree")
            not in {"worktree", "temporary"}
            or (
                "collision_evidence" in operation
                and operation.get("collision_evidence") is not None
                and (
                    not isinstance(operation.get("collision_evidence"), Mapping)
                    or set(operation["collision_evidence"])
                    != {
                        "reason",
                        "source_name",
                        "quarantine_name",
                        "source_parent_device",
                        "source_parent_inode",
                        "quarantine_parent_device",
                        "quarantine_parent_inode",
                        "moved_device",
                        "moved_inode",
                    }
                    or operation["collision_evidence"].get("reason")
                    != "source_name_occupied_after_handoff"
                    or operation["collision_evidence"].get("source_name")
                    != Path(operation.get("temporary_source_path", "")).name
                    or operation["collision_evidence"].get("quarantine_name")
                    != "temporary"
                    or any(
                        not _valid_integer(
                            operation["collision_evidence"].get(key), minimum=1
                        )
                        for key in (
                            "source_parent_device",
                            "source_parent_inode",
                            "quarantine_parent_device",
                            "quarantine_parent_inode",
                            "moved_device",
                            "moved_inode",
                        )
                    )
                    or phase != "recovery_hold"
                )
            )
            or not _valid_integer(operation.get("git_common_device"))
            or not _valid_integer(operation.get("git_common_inode"), minimum=1)
            or archive_recorded != (isinstance(operation.get("archive_path"), str))
            or archive_recorded
            != (isinstance(operation.get("archive_manifest_sha256"), str))
            or archive_recorded != _valid_integer(operation.get("archive_device"))
            or archive_recorded
            != _valid_integer(operation.get("archive_inode"), minimum=1)
            or archive_recorded
            != (
                isinstance(operation.get("gitdir_relative"), str)
                if operation.get("operation_kind", "worktree") == "worktree"
                else operation.get("gitdir_relative") is None
            )
            or archive_recorded
            != (
                _valid_integer(operation.get("gitdir_device"))
                if operation.get("operation_kind", "worktree") == "worktree"
                else operation.get("gitdir_device") is None
            )
            or archive_recorded
            != (
                _valid_integer(operation.get("gitdir_inode"), minimum=1)
                if operation.get("operation_kind", "worktree") == "worktree"
                else operation.get("gitdir_inode") is None
            )
            or (
                operation.get("operation_kind", "worktree") == "temporary"
                and (
                    not isinstance(operation.get("temporary_source_path"), str)
                    or not Path(operation["temporary_source_path"]).is_absolute()
                    or not _valid_integer(operation.get("temporary_source_device"))
                    or not _valid_integer(
                        operation.get("temporary_source_inode"), minimum=1
                    )
                    or not _valid_integer(
                        operation.get("temporary_source_mount_id"), minimum=1
                    )
                    or not isinstance(operation.get("temporary_producer_lease_id"), str)
                )
            )
            or (
                raw_operation_keys == frozenset(operation_keys)
                and (
                    not (
                        operation.get("archive_lock_path") is None
                        and operation.get("archive_lock_device") is None
                        and operation.get("archive_lock_inode") is None
                        and operation.get("archive_lock_mount_id") is None
                    )
                    and not (
                        isinstance(operation.get("archive_lock_path"), str)
                        and Path(operation["archive_lock_path"]).is_absolute()
                        and str(Path(operation["archive_lock_path"]))
                        == os.path.normpath(operation["archive_lock_path"])
                        and _valid_integer(operation.get("archive_lock_device"))
                        and _valid_integer(
                            operation.get("archive_lock_inode"), minimum=1
                        )
                        and _valid_integer(
                            operation.get("archive_lock_mount_id"), minimum=1
                        )
                    )
                )
            )
        ):
            raise WorktreeLifecycleError("lifecycle_state_invalid")
    if claim is not None and operation is None:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    use_history = value["use_history"]
    maintenance_history = value["maintenance_history"]
    if (
        not isinstance(use_history, list)
        or not isinstance(maintenance_history, list)
        or len(use_history) > _MAX_HISTORY_PER_WORKTREE
        or len(maintenance_history) > _MAX_HISTORY_PER_WORKTREE
        or any(not isinstance(row, Mapping) for row in use_history)
        or any(not isinstance(row, Mapping) for row in maintenance_history)
    ):
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    return _TreeState(
        binding=binding,
        origin=None if origin is None else dict(origin),
        revision=value["revision"],
        fence=value["fence"],
        active_uses=uses,
        maintenance_claim=claim,
        use_history=tuple(dict(row) for row in use_history),
        maintenance_history=tuple(dict(row) for row in maintenance_history),
        maintenance_operation=(None if operation is None else dict(operation)),
    )


def _validate_document(document: object) -> dict[str, object]:
    if not isinstance(document, Mapping) or frozenset(document) not in {
        frozenset({"schema_version", "revision", "worktrees"}),
        frozenset({"schema_version", "revision", "worktrees", "native_references"}),
    }:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    if document["schema_version"] != 1 or type(document["schema_version"]) is not int:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    _require_integer(document["revision"], code="lifecycle_state_invalid")
    worktrees = document["worktrees"]
    if not isinstance(worktrees, Mapping):
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    references = document.get("native_references", [])
    if not isinstance(references, list) or len(references) > 4096:
        raise WorktreeLifecycleError("lifecycle_state_invalid")
    reference_ids: set[str] = set()
    for reference in references:
        if (
            not isinstance(reference, Mapping)
            or set(reference) != {"reference_id", "created_at"}
            or not _required_text(reference["reference_id"], maximum=128)
            or not _valid_integer(reference["created_at"])
            or reference["reference_id"] in reference_ids
        ):
            raise WorktreeLifecycleError("lifecycle_state_invalid")
        reference_ids.add(reference["reference_id"])
    physical_keys: set[str] = set()
    for key, value in worktrees.items():
        if not _required_text(key, maximum=64):
            raise WorktreeLifecycleError("lifecycle_state_invalid")
        tree = _tree_state(key, value)
        physical_key = _binding_key(tree.binding)
        if physical_key in physical_keys:
            raise WorktreeLifecycleError("lifecycle_state_invalid")
        physical_keys.add(physical_key)
    result = dict(document)
    result["native_references"] = (
        []
        if not references
        else [
            {
                "reference_id": "native-opaque-pending",
                "created_at": min(row["created_at"] for row in references),
            }
        ]
    )
    return result


class WorktreeLifecycleStore:
    """Store active worktree uses and exclusive maintenance claims."""

    def __init__(self, state: HiveStateStore) -> None:
        if not isinstance(state, HiveStateStore):
            raise WorktreeLifecycleError("lifecycle_state_store_invalid")
        self._state = state

    def snapshot(self) -> WorktreeLifecycleSnapshot:
        with self._state.locked():
            document = self._read_locked()
        uses: list[UseLease] = []
        claims: list[MaintenanceClaim] = []
        for key, value in document["worktrees"].items():
            tree = _tree_state(key, value)
            uses.extend(tree.active_uses)
            if tree.maintenance_claim is not None:
                claims.append(tree.maintenance_claim)
        return WorktreeLifecycleSnapshot(
            revision=document["revision"],
            active_uses=tuple(
                sorted(
                    uses, key=lambda item: (item.binding.repository_id, item.lease_id)
                )
            ),
            maintenance_claims=tuple(
                sorted(
                    claims,
                    key=lambda item: (item.candidate.repository_id, item.claim_id),
                )
            ),
        )

    def create_temporary_producer(self, lease: UseLease, *, now: int) -> Path:
        """Create and persist a private temp root for one active G5 use lease."""
        if type(lease) is not UseLease:
            raise WorktreeLifecycleError("use_lease_invalid")
        _require_integer(now, code="lifecycle_time_invalid")
        if now < lease.started_at:
            raise WorktreeLifecycleError("lifecycle_time_invalid")
        _validate_live_binding(lease.binding)
        key = _binding_key(lease.binding)
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(document, key, lease.binding, create=False)
            if tree is None or tree.get("maintenance_claim") is not None:
                raise WorktreeLifecycleError("use_lease_inactive")
            expected = _lease_payload(lease)
            if sum(row == expected for row in tree["active_uses"]) != 1:
                raise WorktreeLifecycleError("use_lease_stale")
            base = Path(tempfile.gettempdir()).resolve(strict=True)
            path = Path(tempfile.mkdtemp(prefix="the-hive-g5-", dir=base))
            try:
                info = path.stat(follow_symlinks=False)
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or path.parent != base
                ):
                    raise WorktreeLifecycleError("temporary_producer_identity_invalid")
                mount_id = _mount_id(path)
                tree["use_history"].append(
                    {
                        "lease_id": lease.lease_id,
                        "event": "temporary_producer_started",
                        "path": str(path),
                        "device": info.st_dev,
                        "inode": info.st_ino,
                        "mount_id": mount_id,
                        "created_at": now,
                    }
                )
                del tree["use_history"][:-_MAX_HISTORY_PER_WORKTREE]
                document["revision"] += 1
                self._write_locked(document)
                return path
            except Exception:
                # Leave an unrecorded directory protected; path-based cleanup
                # cannot prove ownership after a concurrent replacement.
                raise

    def temporary_producers(
        self,
        binding: WorktreeBinding,
        *,
        claim: MaintenanceClaim | None = None,
    ) -> tuple[Mapping[str, object], ...]:
        """Return only temp roots whose persisted directory identity still matches."""
        if type(binding) is not WorktreeBinding:
            raise WorktreeLifecycleError("worktree_binding_invalid")
        _validate_live_binding(binding)
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(binding), binding, create=False
            )
            if tree is None or tree.get("origin") is None:
                return ()
            if tree["active_uses"]:
                return ()
            if claim is None:
                if tree.get("maintenance_claim") is not None:
                    return ()
            elif (
                type(claim) is not MaintenanceClaim
                or claim.candidate != binding
                or tree.get("maintenance_claim") != _claim_payload(claim)
            ):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            rows = [dict(row) for row in tree["use_history"]]
        ended = {
            row.get("lease_id"): row
            for row in rows
            if row.get("event") == "process_exit_observed"
        }
        result = []
        for row in rows:
            if row.get("event") != "temporary_producer_started":
                continue
            lease_id = row.get("lease_id")
            end = ended.get(lease_id)
            path_text = row.get("path")
            if not isinstance(path_text, str) or end is None:
                continue
            path = Path(path_text)
            try:
                info = path.stat(follow_symlinks=False)
                if (
                    path.resolve(strict=True) != path
                    or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or info.st_dev != row.get("device")
                    or info.st_ino != row.get("inode")
                    or _mount_id(path) != row.get("mount_id")
                ):
                    continue
            except OSError:
                continue
            result.append({**row, "ended_at": end.get("observed_at")})
        return tuple(result)

    def abort_temporary_producer_before_spawn(
        self, lease: UseLease, producer_path: Path, *, now: int
    ) -> None:
        """Discard one empty producer only while its G5 runner was never bound."""
        if type(lease) is not UseLease or not isinstance(producer_path, Path):
            raise WorktreeLifecycleError("pre_spawn_abort_invalid")
        _require_integer(now, code="lifecycle_time_invalid")
        if now < lease.started_at:
            raise WorktreeLifecycleError("pre_spawn_abort_invalid")
        if lease.runtime_scope is not None or lease.runtime_process is not None:
            raise WorktreeLifecycleError("pre_spawn_abort_runtime_bound")
        _validate_live_binding(lease.binding)
        with self._state.locked():
            document = self._read_locked()
            key = _binding_key(lease.binding)
            tree = self._get_tree(document, key, lease.binding, create=False)
            if tree is None or tree.get("maintenance_claim") is not None:
                raise WorktreeLifecycleError("use_lease_inactive")
            expected = _lease_payload(lease)
            active = [row for row in tree["active_uses"] if row == expected]
            if len(active) != 1:
                raise WorktreeLifecycleError("use_lease_stale")
            matches = [
                row
                for row in tree["use_history"]
                if row.get("event") == "temporary_producer_started"
                and row.get("lease_id") == lease.lease_id
                and row.get("path") == str(producer_path)
            ]
            if len(matches) != 1:
                raise WorktreeLifecycleError("temporary_producer_identity_invalid")
            row = matches[0]
            if any(
                item.get("event") == "process_exit_observed"
                and item.get("lease_id") == lease.lease_id
                for item in tree["use_history"]
            ):
                raise WorktreeLifecycleError("pre_spawn_abort_runtime_bound")
            parent = producer_path.parent.resolve(strict=True)
            if producer_path.resolve(strict=True) != producer_path:
                raise WorktreeLifecycleError("temporary_producer_identity_invalid")
            parent_fd = os.open(parent, _DIRECTORY_FLAGS)
            try:
                child_fd = os.open(
                    producer_path.name, _DIRECTORY_FLAGS, dir_fd=parent_fd
                )
                try:
                    info = os.fstat(child_fd)
                    if (
                        not stat.S_ISDIR(info.st_mode)
                        or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) != 0o700
                        or info.st_dev != row.get("device")
                        or info.st_ino != row.get("inode")
                        or _mount_id(producer_path) != row.get("mount_id")
                        or os.listdir(child_fd)
                    ):
                        raise WorktreeLifecycleError(
                            "temporary_producer_identity_invalid"
                        )
                finally:
                    os.close(child_fd)
                os.rmdir(producer_path.name, dir_fd=parent_fd)
            except OSError as exc:
                raise WorktreeLifecycleError(
                    "temporary_producer_identity_invalid"
                ) from exc
            finally:
                os.close(parent_fd)
            tree["active_uses"].remove(active[0])
            tree["use_history"].remove(row)
            tree["use_history"].append(
                {
                    "lease_id": lease.lease_id,
                    "event": "launch_aborted_before_spawn",
                    "observed_at": now,
                }
            )
            del tree["use_history"][:-_MAX_HISTORY_PER_WORKTREE]
            tree["revision"] += 1
            tree["fence"] += 1
            document["revision"] += 1
            self._write_locked(document)

    def last_use_ended_at(self, binding: WorktreeBinding) -> int | None:
        """Return only a recorded, verified runtime-end observation."""
        if type(binding) is not WorktreeBinding:
            raise WorktreeLifecycleError("worktree_binding_invalid")
        _validate_live_binding(binding)
        key = _binding_key(binding)
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(document, key, binding, create=False)
        if tree is None or tree.get("origin") is None:
            return None
        if tree["active_uses"] or tree["maintenance_claim"] is not None:
            return None
        ended = [
            row["observed_at"]
            for row in tree["use_history"]
            if row.get("event") == "process_exit_observed"
            and isinstance(row.get("observed_at"), int)
            and not isinstance(row.get("observed_at"), bool)
        ]
        return max(ended) if ended else None

    def last_use_ended_at_for_claim(
        self, binding: WorktreeBinding, claim: MaintenanceClaim
    ) -> int | None:
        if type(claim) is not MaintenanceClaim or claim.candidate != binding:
            raise WorktreeLifecycleError("maintenance_claim_mismatch")
        _validate_live_binding(binding)
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(binding), binding, create=False
            )
            if (
                tree is None
                or tree.get("maintenance_claim") != _claim_payload(claim)
                or tree["active_uses"]
                or tree.get("origin") is None
            ):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            ended = [
                row["observed_at"]
                for row in tree["use_history"]
                if row.get("event") == "process_exit_observed"
                and _valid_integer(row.get("observed_at"))
            ]
            return max(ended) if ended else None

    def binding_for_source(self, source: Path) -> WorktreeBinding | None:
        if not isinstance(source, Path) or not source.is_absolute():
            raise WorktreeLifecycleError("worktree_binding_invalid")
        canonical = source.resolve(strict=True)
        try:
            if not stat.S_ISDIR(canonical.stat(follow_symlinks=False).st_mode):
                raise WorktreeLifecycleError("worktree_binding_invalid")
        except WorktreeLifecycleError:
            raise
        except OSError as exc:
            raise WorktreeLifecycleError("worktree_binding_unavailable") from exc
        with self._state.locked():
            document = self._read_locked()
        matches = []
        for key, value in document["worktrees"].items():
            if not isinstance(value, Mapping) or not isinstance(
                value.get("binding"), Mapping
            ):
                continue
            tree = _tree_state(key, value)
            root = tree.binding.canonical_source_path
            if canonical == root or root in canonical.parents:
                nearest_git_root = None
                for parent in (canonical, *canonical.parents):
                    try:
                        parent.joinpath(".git").lstat()
                    except FileNotFoundError:
                        continue
                    except OSError as exc:
                        raise WorktreeLifecycleError(
                            "worktree_git_metadata_invalid"
                        ) from exc
                    nearest_git_root = parent
                    break
                if nearest_git_root == root:
                    matches.append(tree)
        if len(matches) > 1:
            raise WorktreeLifecycleError("worktree_binding_ambiguous")
        if not matches or matches[0].origin is None:
            return None
        _validate_live_binding(matches[0].binding)
        return matches[0].binding

    def binding_for_temporary_source(self, source: Path) -> WorktreeBinding | None:
        """Resolve an exact producer path to its persisted project binding."""
        if not isinstance(source, Path) or not source.is_absolute():
            raise WorktreeLifecycleError("temporary_source_invalid")
        try:
            canonical = source.resolve(strict=True)
        except FileNotFoundError:
            try:
                canonical = source.resolve(strict=False)
            except OSError as exc:
                raise WorktreeLifecycleError("temporary_source_unavailable") from exc
        except OSError as exc:
            raise WorktreeLifecycleError("temporary_source_unavailable") from exc
        with self._state.locked():
            document = self._read_locked()
        matches: list[WorktreeBinding] = []
        for key, value in document["worktrees"].items():
            tree = _tree_state(key, value)
            if tree.origin is None:
                continue
            if any(
                row.get("event") == "temporary_producer_started"
                and row.get("path") == str(canonical)
                for row in tree.use_history
            ):
                matches.append(tree.binding)
        if len(matches) > 1:
            raise WorktreeLifecycleError("temporary_source_ambiguous")
        return matches[0] if matches else None

    def active_use_for_assignment(self, assignment_id: str) -> UseLease | None:
        _require_text(assignment_id, code="use_identity_invalid")
        return next(
            (
                lease
                for lease in self.snapshot().active_uses
                if lease.assignment_id == assignment_id
            ),
            None,
        )

    def _record_created_worktree(
        self, binding: WorktreeBinding, attestation: object
    ) -> None:
        """Record only a freshly created worktree after the server verified its producer."""
        if type(binding) is not WorktreeBinding:
            raise WorktreeLifecycleError("worktree_binding_invalid")
        fields = (
            "attestation_id",
            "agent_id",
            "repository_device",
            "repository_inode",
            "worktree_path",
            "worktree_device",
            "worktree_inode",
            "common_git_dir",
            "common_git_device",
            "common_git_inode",
            "creation_generation",
            "created_at_utc",
            "lifecycle",
        )
        if any(not hasattr(attestation, field) for field in fields):
            raise WorktreeLifecycleError("worktree_origin_evidence_invalid")
        if (
            attestation.lifecycle != "available"
            or attestation.worktree_path != binding.canonical_source_path
            or attestation.common_git_dir != binding.git_common_directory
            or attestation.worktree_device != binding.device
            or attestation.worktree_inode != binding.inode
            or not _required_text(attestation.attestation_id, maximum=64)
            or not _required_text(attestation.agent_id, maximum=200)
            or not _required_text(attestation.creation_generation, maximum=64)
            or not _required_text(attestation.created_at_utc, maximum=64)
        ):
            raise WorktreeLifecycleError("worktree_origin_evidence_invalid")
        _validate_live_binding(binding)
        origin = {
            "attestation_id": attestation.attestation_id,
            "agent_id": attestation.agent_id,
            "repository_device": attestation.repository_device,
            "repository_inode": attestation.repository_inode,
            "worktree_device": attestation.worktree_device,
            "worktree_inode": attestation.worktree_inode,
            "common_git_device": attestation.common_git_device,
            "common_git_inode": attestation.common_git_inode,
            "creation_generation": attestation.creation_generation,
            "created_at_utc": attestation.created_at_utc,
        }
        with self._state.locked():
            document = self._read_locked()
            key = _binding_key(binding)
            if key in document["worktrees"]:
                raise WorktreeLifecycleError("worktree_origin_already_recorded")
            document["worktrees"][key] = _empty_tree(binding, origin)
            document["revision"] += 1
            self._write_locked(document)

    def begin_use(
        self,
        binding: WorktreeBinding,
        *,
        principal_id: str,
        session_id: str,
        assignment_id: str,
        now: int,
    ) -> UseLease:
        if type(binding) is not WorktreeBinding:
            raise WorktreeLifecycleError("worktree_binding_invalid")
        for value in (principal_id, session_id, assignment_id):
            _require_text(value, code="use_identity_invalid")
        _require_integer(now, code="lifecycle_time_invalid")
        _validate_live_binding(binding)
        owner_process = _current_process_identity()
        with self._state.locked():
            document = self._read_locked()
            key = _binding_key(binding)
            tree = self._get_tree(document, key, binding)
            if tree["maintenance_claim"] is not None:
                raise WorktreeLifecycleError("maintenance_claim_active")
            tree["revision"] += 1
            tree["fence"] += 1
            document["revision"] += 1
            lease = UseLease(
                lease_id=secrets.token_urlsafe(24),
                binding=binding,
                principal_id=principal_id,
                session_id=session_id,
                assignment_id=assignment_id,
                revision=tree["revision"],
                fence=tree["fence"],
                owner_process=owner_process,
                runtime_process=None,
                runtime_scope=None,
                started_at=now,
            )
            tree["active_uses"].append(_lease_payload(lease))
            self._write_locked(document)
            return lease

    def bind_runtime(
        self,
        lease: UseLease,
        evidence: RuntimeBindingEvidence,
        *,
        now: int,
    ) -> UseLease:
        if type(lease) is not UseLease or type(evidence) is not RuntimeBindingEvidence:
            raise WorktreeLifecycleError("runtime_binding_evidence_invalid")
        if getattr(evidence, "_seal", None) is not _RUNTIME_BINDING_SEAL:
            raise WorktreeLifecycleError("runtime_binding_evidence_invalid")
        if lease.runtime_process is not None:
            raise WorktreeLifecycleError("runtime_binding_already_set")
        _require_integer(now, code="lifecycle_time_invalid")
        if now < evidence.observed_at or evidence.observed_at < lease.started_at:
            raise WorktreeLifecycleError("runtime_binding_evidence_invalid")
        if (
            evidence.lease_id != lease.lease_id
            or evidence.binding_key != _binding_key(lease.binding)
            or evidence.principal_id != lease.principal_id
            or evidence.session_id != lease.session_id
            or evidence.assignment_id != lease.assignment_id
        ):
            raise WorktreeLifecycleError("runtime_binding_evidence_mismatch")
        if not _runtime_process_is_active(evidence.runtime_process):
            raise WorktreeLifecycleError("runtime_process_not_active")
        with self._state.locked():
            document = self._read_locked()
            key = _binding_key(lease.binding)
            tree = self._get_tree(document, key, lease.binding, create=False)
            if tree is None:
                raise WorktreeLifecycleError("use_lease_inactive")
            expected = _lease_payload(lease)
            matches = [row for row in tree["active_uses"] if row == expected]
            if len(matches) != 1:
                raise WorktreeLifecycleError("use_lease_stale")
            if _runtime_reference_count(document, evidence.runtime_process) != 0:
                raise WorktreeLifecycleError("runtime_reference_already_bound")
            tree["revision"] += 1
            tree["fence"] += 1
            document["revision"] += 1
            bound_lease = replace(
                lease,
                revision=tree["revision"],
                fence=tree["fence"],
                runtime_process=evidence.runtime_process,
                runtime_scope=None,
            )
            tree["active_uses"].remove(matches[0])
            tree["active_uses"].append(_lease_payload(bound_lease))
            self._write_locked(document)
            return bound_lease

    def bind_g5_runtime(
        self,
        lease: UseLease,
        evidence: G5ScopeBindingEvidence,
        *,
        now: int,
    ) -> UseLease:
        if type(lease) is not UseLease or type(evidence) is not G5ScopeBindingEvidence:
            raise WorktreeLifecycleError("runtime_binding_evidence_invalid")
        if getattr(evidence, "_seal", None) is not _G5_SCOPE_BINDING_SEAL:
            raise WorktreeLifecycleError("runtime_binding_evidence_invalid")
        if lease.runtime_process is not None or lease.runtime_scope is not None:
            raise WorktreeLifecycleError("runtime_binding_already_set")
        _require_integer(now, code="runtime_binding_evidence_invalid")
        if now < evidence.observed_at or evidence.observed_at < lease.started_at:
            raise WorktreeLifecycleError("runtime_binding_evidence_invalid")
        if (
            evidence.lease_id != lease.lease_id
            or evidence.binding_key != _binding_key(lease.binding)
            or evidence.principal_id != lease.principal_id
            or evidence.session_id != lease.session_id
            or evidence.assignment_id != lease.assignment_id
        ):
            raise WorktreeLifecycleError("runtime_binding_evidence_mismatch")
        with self._state.locked():
            document = self._read_locked()
            key = _binding_key(lease.binding)
            tree = self._get_tree(document, key, lease.binding, create=False)
            if tree is None:
                raise WorktreeLifecycleError("use_lease_inactive")
            expected = _lease_payload(lease)
            matches = [row for row in tree["active_uses"] if row == expected]
            if len(matches) != 1:
                raise WorktreeLifecycleError("use_lease_stale")
            if _g5_scope_reference_count(document, evidence.runtime_scope) != 0:
                raise WorktreeLifecycleError("runtime_reference_already_bound")
            tree["revision"] += 1
            tree["fence"] += 1
            document["revision"] += 1
            bound_lease = replace(
                lease,
                revision=tree["revision"],
                fence=tree["fence"],
                runtime_scope=evidence.runtime_scope,
            )
            tree["active_uses"].remove(matches[0])
            tree["active_uses"].append(_lease_payload(bound_lease))
            self._write_locked(document)
            return bound_lease

    def end_use(
        self, lease: UseLease, evidence: RuntimeEndEvidence, *, now: int
    ) -> None:
        if type(lease) is not UseLease or type(evidence) is not RuntimeEndEvidence:
            raise WorktreeLifecycleError("end_evidence_invalid")
        if getattr(evidence, "_seal", None) is not _END_EVIDENCE_SEAL:
            raise WorktreeLifecycleError("end_evidence_invalid")
        if lease.runtime_scope is None:
            if lease.runtime_process is None:
                raise WorktreeLifecycleError("runtime_binding_pending")
            raise WorktreeLifecycleError("runtime_reference_boundary_unavailable")
        if evidence.runtime_scope != lease.runtime_scope:
            raise WorktreeLifecycleError("runtime_binding_pending")
        _require_integer(now, code="lifecycle_time_invalid")
        if now < evidence.observed_at or evidence.observed_at < lease.started_at:
            raise WorktreeLifecycleError("end_evidence_invalid")
        if (
            evidence.lease_id != lease.lease_id
            or evidence.binding_key != _binding_key(lease.binding)
            or evidence.principal_id != lease.principal_id
            or evidence.session_id != lease.session_id
            or evidence.assignment_id != lease.assignment_id
            or evidence.runtime_process != lease.runtime_process
            or evidence.runtime_scope != lease.runtime_scope
        ):
            raise WorktreeLifecycleError("end_evidence_binding_mismatch")
        if not g5_scope_is_empty(lease.runtime_scope):
            raise WorktreeLifecycleError("runtime_process_active")
        with self._state.locked():
            document = self._read_locked()
            key = _binding_key(lease.binding)
            tree = self._get_tree(document, key, lease.binding, create=False)
            if tree is None:
                raise WorktreeLifecycleError("use_lease_inactive")
            expected = _lease_payload(lease)
            matches = [row for row in tree["active_uses"] if row == expected]
            if len(matches) != 1:
                raise WorktreeLifecycleError("use_lease_stale")
            if _g5_scope_reference_count(document, lease.runtime_scope) != 1:
                raise WorktreeLifecycleError("runtime_reference_active")
            tree["active_uses"].remove(matches[0])
            tree["use_history"].append(
                {
                    "lease_id": lease.lease_id,
                    "event": "process_exit_observed",
                    "observed_at": evidence.observed_at,
                }
            )
            del tree["use_history"][:-_MAX_HISTORY_PER_WORKTREE]
            tree["revision"] += 1
            tree["fence"] += 1
            document["revision"] += 1
            self._write_locked(document)

    def claim_maintenance(
        self, binding: WorktreeBinding, *, now: int
    ) -> MaintenanceClaim:
        if type(binding) is not WorktreeBinding:
            raise WorktreeLifecycleError("worktree_binding_invalid")
        _require_integer(now, code="lifecycle_time_invalid")
        _validate_live_binding(binding)
        owner_process = _current_process_identity()
        with self._state.locked():
            document = self._read_locked()
            if document["native_references"]:
                raise WorktreeLifecycleError("native_reference_active")
            key = _binding_key(binding)
            tree = self._get_tree(document, key, binding, create=False)
            if tree is None:
                raise WorktreeLifecycleError("worktree_binding_unknown")
            if tree["active_uses"]:
                raise WorktreeLifecycleError("worktree_in_use")
            if tree.get("origin") is None:
                raise WorktreeLifecycleError("worktree_origin_unattested")
            if not tree["use_history"]:
                raise WorktreeLifecycleError("worktree_binding_unknown")
            if tree["maintenance_claim"] is not None:
                raise WorktreeLifecycleError("maintenance_claim_active")
            tree["revision"] += 1
            tree["fence"] += 1
            document["revision"] += 1
            claim = MaintenanceClaim(
                claim_id=secrets.token_urlsafe(24),
                candidate=binding,
                revision=tree["revision"],
                fence=tree["fence"],
                owner_process=owner_process,
                claimed_at=now,
            )
            tree["maintenance_claim"] = _claim_payload(claim)
            common_info = binding.git_common_directory.stat(follow_symlinks=False)
            tree["maintenance_operation"] = {
                "claim_id": claim.claim_id,
                "phase": "claimed",
                "operation_kind": "worktree",
                "source_device": binding.device,
                "source_inode": binding.inode,
                "source_mount_id": binding.mount_id,
                "git_common_device": common_info.st_dev,
                "git_common_inode": common_info.st_ino,
                "archive_path": None,
                "archive_manifest_sha256": None,
                "archive_device": None,
                "archive_inode": None,
                "gitdir_relative": None,
                "gitdir_device": None,
                "gitdir_inode": None,
                "archive_lock_path": None,
                "archive_lock_device": None,
                "archive_lock_inode": None,
                "archive_lock_mount_id": None,
                "temporary_source_path": None,
                "temporary_source_device": None,
                "temporary_source_inode": None,
                "temporary_source_mount_id": None,
                "temporary_producer_lease_id": None,
                "collision_evidence": None,
            }
            self._write_locked(document)
            return claim

    def reserve_native_reference(self, *, reference_id: str, now: int) -> None:
        """Persist an opaque native use before its external side effect.

        Until a separately verified runtime retirement protocol exists, this
        one stable broad reference remains pending and excludes every maintenance
        claim. Per-admission IDs are validated but deliberately not retained.
        """
        _require_text(reference_id, code="native_reference_invalid", maximum=128)
        _require_integer(now, code="lifecycle_time_invalid")
        with self._state.locked():
            document = self._read_locked()
            if any(
                isinstance(value, Mapping)
                and value.get("maintenance_claim") is not None
                for value in document["worktrees"].values()
            ):
                raise WorktreeLifecycleError("maintenance_claim_active")
            references = document["native_references"]
            if references:
                return
            references.append(
                {"reference_id": "native-opaque-pending", "created_at": now}
            )
            document["revision"] += 1
            self._write_locked(document)

    def assert_claim(self, claim: MaintenanceClaim) -> None:
        if type(claim) is not MaintenanceClaim:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        self._assert_claim_owner(claim)
        with self._state.locked():
            document = self._read_locked()
            key = _binding_key(claim.candidate)
            tree = self._get_tree(document, key, claim.candidate, create=False)
            if tree is None or tree["maintenance_claim"] is None:
                raise WorktreeLifecycleError("maintenance_claim_inactive")
            if tree["maintenance_claim"] != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            operation = tree.get("maintenance_operation")
            if (
                isinstance(operation, Mapping)
                and operation.get("phase") == "recovery_hold"
            ):
                raise WorktreeLifecycleError("maintenance_recovery_hold")

    def _bind_maintenance_archive_lock(
        self, claim: MaintenanceClaim, archive_root: Path, lock_fd: int
    ) -> None:
        """Persist the physical archive-lock identity before writer subprocesses."""
        if (
            type(claim) is not MaintenanceClaim
            or not isinstance(archive_root, Path)
            or type(lock_fd) is not int
            or lock_fd < 0
        ):
            raise WorktreeLifecycleError("maintenance_archive_lock_invalid")
        self._assert_claim_owner(claim)
        try:
            canonical = archive_root.resolve(strict=True)
            info = os.fstat(lock_fd)
            path_info = archive_root.stat(follow_symlinks=False)
            mount_id = _mount_id(archive_root)
        except OSError as exc:
            raise WorktreeLifecycleError(
                "maintenance_archive_lock_unavailable"
            ) from exc
        if (
            canonical != archive_root
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
        ):
            raise WorktreeLifecycleError("maintenance_archive_lock_invalid")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(claim.candidate), claim.candidate, create=False
            )
            if tree is None or tree.get("maintenance_claim") != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            operation = tree.get("maintenance_operation")
            if (
                not isinstance(operation, Mapping)
                or operation.get("claim_id") != claim.claim_id
                or operation.get("phase") != "archiving"
                or operation.get("archive_lock_path") is not None
            ):
                raise WorktreeLifecycleError("maintenance_archive_lock_already_bound")
            tree["maintenance_operation"] = {
                **operation,
                "archive_lock_path": str(archive_root),
                "archive_lock_device": info.st_dev,
                "archive_lock_inode": info.st_ino,
                "archive_lock_mount_id": mount_id,
            }
            document["revision"] += 1
            self._write_locked(document)

    def _maintenance_archive_lock_for_recovery(
        self, binding: WorktreeBinding
    ) -> tuple[Path, int, int, int]:
        if type(binding) is not WorktreeBinding:
            raise WorktreeLifecycleError("worktree_binding_invalid")
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(binding), binding, create=False
            )
            if tree is None or tree.get("maintenance_claim") is None:
                raise WorktreeLifecycleError("maintenance_claim_inactive")
            claim = _claim_from_payload(binding, tree["maintenance_claim"])
            operation = tree.get("maintenance_operation")
            if (
                not isinstance(operation, Mapping)
                or operation.get("claim_id") != claim.claim_id
                or not isinstance(operation.get("archive_lock_path"), str)
                or not _valid_integer(operation.get("archive_lock_device"))
                or not _valid_integer(operation.get("archive_lock_inode"), minimum=1)
                or not _valid_integer(operation.get("archive_lock_mount_id"), minimum=1)
            ):
                raise WorktreeLifecycleError("maintenance_archive_lock_unavailable")
            path = Path(operation["archive_lock_path"])
            if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
                raise WorktreeLifecycleError("maintenance_archive_lock_invalid")
            if (
                operation.get("archive_path") is not None
                and Path(operation["archive_path"]).parent != path
            ):
                raise WorktreeLifecycleError("maintenance_archive_lock_mismatch")
            return (
                path,
                operation["archive_lock_device"],
                operation["archive_lock_inode"],
                operation["archive_lock_mount_id"],
            )

    def record_maintenance_archive(
        self, claim: MaintenanceClaim, receipt: object
    ) -> None:
        """Bind only a freshly verified archive receipt to the active claim."""
        if type(claim) is not MaintenanceClaim:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        self._assert_claim_owner(claim)
        try:
            from the_hive.maintenance import ArchiveReceipt, _read_archive_manifest

            if type(receipt) is not ArchiveReceipt:
                raise WorktreeLifecycleError("maintenance_receipt_invalid")
            manifest = _read_archive_manifest(receipt)
        except WorktreeLifecycleError:
            raise
        except Exception as exc:
            raise WorktreeLifecycleError("maintenance_receipt_invalid") from exc
        binding = claim.candidate
        temporary = manifest.get("kind") == "temporary_tree"
        producer = None
        if temporary:
            producer = next(
                (
                    row
                    for row in self.temporary_producers(binding, claim=claim)
                    if row.get("path") == manifest.get("source")
                ),
                None,
            )
            if (
                producer is None
                or manifest.get("source_device") != producer.get("device")
                or manifest.get("source_inode") != producer.get("inode")
                or manifest.get("source_mount_id") != producer.get("mount_id")
                or manifest.get("producer_lease_id") != producer.get("lease_id")
                or manifest.get("producer_ended_at") != producer.get("ended_at")
            ):
                raise WorktreeLifecycleError("maintenance_receipt_binding_mismatch")
        elif (
            manifest.get("source") != str(binding.canonical_source_path)
            or manifest.get("source_device") != binding.device
            or manifest.get("source_inode") != binding.inode
            or manifest.get("git_common_device")
            != os.stat(binding.git_common_directory, follow_symlinks=False).st_dev
            or manifest.get("git_common_inode")
            != os.stat(binding.git_common_directory, follow_symlinks=False).st_ino
        ):
            raise WorktreeLifecycleError("maintenance_receipt_binding_mismatch")
        try:
            archive_info = receipt.archive.lstat()
            if temporary:
                gitdir_relative = None
                gitdir_info = None
                binding.git_common_directory.stat(follow_symlinks=False)
            else:
                gitdir_relative = manifest["gitdir"]
                gitdir = binding.git_common_directory / gitdir_relative
                gitdir_info = gitdir.stat(follow_symlinks=False)
                if (
                    not stat.S_ISDIR(gitdir_info.st_mode)
                    or gitdir_info.st_uid != os.geteuid()
                    or _mount_id(gitdir) != _mount_id(binding.git_common_directory)
                ):
                    raise WorktreeLifecycleError("maintenance_gitdir_invalid")
                binding.git_common_directory.stat(follow_symlinks=False)
        except WorktreeLifecycleError:
            raise
        except (KeyError, OSError, TypeError) as exc:
            raise WorktreeLifecycleError("maintenance_gitdir_invalid") from exc
        with self._state.locked():
            document = self._read_locked()
            key = _binding_key(binding)
            tree = self._get_tree(document, key, binding, create=False)
            if tree is None or tree["maintenance_claim"] != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            operation = tree.get("maintenance_operation")
            if not isinstance(operation, Mapping) or operation.get("phase") not in {
                "claimed",
                "archiving",
            }:
                raise WorktreeLifecycleError("maintenance_phase_invalid")
            tree["maintenance_operation"] = {
                **operation,
                "operation_kind": "temporary" if temporary else "worktree",
                "phase": "archive_verified",
                "archive_path": str(receipt.archive),
                "archive_manifest_sha256": receipt.manifest_sha256,
                "archive_device": archive_info.st_dev,
                "archive_inode": archive_info.st_ino,
                "gitdir_relative": gitdir_relative,
                "gitdir_device": None if gitdir_info is None else gitdir_info.st_dev,
                "gitdir_inode": None if gitdir_info is None else gitdir_info.st_ino,
                "temporary_source_path": None if producer is None else producer["path"],
                "temporary_source_device": None
                if producer is None
                else producer["device"],
                "temporary_source_inode": None
                if producer is None
                else producer["inode"],
                "temporary_source_mount_id": None
                if producer is None
                else producer["mount_id"],
                "temporary_producer_lease_id": None
                if producer is None
                else producer["lease_id"],
            }
            document["revision"] += 1
            self._write_locked(document)

    def maintenance_operation_for_claim(
        self, claim: MaintenanceClaim
    ) -> Mapping[str, object]:
        if type(claim) is not MaintenanceClaim:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        self._assert_claim_owner(claim)
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(claim.candidate), claim.candidate, create=False
            )
            if tree is None or tree.get("maintenance_claim") != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            operation = tree.get("maintenance_operation")
            if (
                not isinstance(operation, Mapping)
                or operation.get("phase") == "recovery_hold"
            ):
                raise WorktreeLifecycleError("maintenance_recovery_hold")
            return dict(operation)

    def maintenance_operation_for_recovery(
        self, claim: MaintenanceClaim
    ) -> Mapping[str, object]:
        """Read a held operation only through its fenced recovery owner."""
        if type(claim) is not MaintenanceClaim:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        self._assert_claim_owner(claim)
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(claim.candidate), claim.candidate, create=False
            )
            if tree is None or tree.get("maintenance_claim") != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            operation = tree.get("maintenance_operation")
            if (
                not isinstance(operation, Mapping)
                or operation.get("phase") != "recovery_hold"
            ):
                raise WorktreeLifecycleError("maintenance_recovery_hold")
            return dict(operation)

    def advance_maintenance_phase(self, claim: MaintenanceClaim, *, phase: str) -> None:
        transitions = {
            "claimed": "archiving",
            "archive_verified": "quarantine_started",
            "quarantine_started": "quarantined",
            "quarantined": "deleting",
        }
        if phase not in set(transitions.values()):
            raise WorktreeLifecycleError("maintenance_phase_invalid")
        if type(claim) is not MaintenanceClaim:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        self._assert_claim_owner(claim)
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(claim.candidate), claim.candidate, create=False
            )
            if tree is None or tree.get("maintenance_claim") != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            operation = tree.get("maintenance_operation")
            if (
                not isinstance(operation, Mapping)
                or transitions.get(operation.get("phase")) != phase
            ):
                raise WorktreeLifecycleError("maintenance_phase_invalid")
            tree["maintenance_operation"] = {**operation, "phase": phase}
            document["revision"] += 1
            self._write_locked(document)

    def hold_maintenance_claim(self, claim: MaintenanceClaim) -> None:
        if type(claim) is not MaintenanceClaim:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        self._assert_claim_owner(claim)
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(claim.candidate), claim.candidate, create=False
            )
            if tree is None or tree.get("maintenance_claim") != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            operation = tree.get("maintenance_operation")
            if not isinstance(operation, Mapping):
                raise WorktreeLifecycleError("maintenance_journal_invalid")
            tree["maintenance_operation"] = {**operation, "phase": "recovery_hold"}
            document["revision"] += 1
            self._write_locked(document)

    def record_maintenance_collision_hold(
        self, claim: MaintenanceClaim, *, evidence: Mapping[str, object]
    ) -> None:
        """Persist a no-overwrite handoff collision for diagnosis only."""
        if type(claim) is not MaintenanceClaim:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        required = {
            "reason",
            "source_name",
            "quarantine_name",
            "source_parent_device",
            "source_parent_inode",
            "quarantine_parent_device",
            "quarantine_parent_inode",
            "moved_device",
            "moved_inode",
        }
        if (
            not isinstance(evidence, Mapping)
            or set(evidence) != required
            or evidence.get("reason") != "source_name_occupied_after_handoff"
            or evidence.get("quarantine_name") != "temporary"
            or any(
                not _valid_integer(evidence.get(key), minimum=1)
                for key in required - {"reason", "source_name", "quarantine_name"}
            )
        ):
            raise WorktreeLifecycleError("maintenance_collision_evidence_invalid")
        self._assert_claim_owner(claim)
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(claim.candidate), claim.candidate, create=False
            )
            if tree is None or tree.get("maintenance_claim") != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            operation = tree.get("maintenance_operation")
            if (
                not isinstance(operation, Mapping)
                or operation.get("operation_kind") != "temporary"
                or not isinstance(operation.get("temporary_source_path"), str)
                or evidence.get("source_name")
                != Path(operation["temporary_source_path"]).name
                or operation.get("phase")
                not in {"quarantine_started", "quarantined", "recovery_hold"}
            ):
                raise WorktreeLifecycleError("maintenance_phase_invalid")
            tree["maintenance_operation"] = {
                **operation,
                "phase": "recovery_hold",
                "collision_evidence": dict(evidence),
            }
            document["revision"] += 1
            self._write_locked(document)

    def record_maintenance_removal(
        self, claim: MaintenanceClaim, receipt: object
    ) -> None:
        if type(claim) is not MaintenanceClaim:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        self._assert_claim_owner(claim)
        try:
            from the_hive.maintenance import ArchiveReceipt, _read_archive_manifest

            if type(receipt) is not ArchiveReceipt:
                raise WorktreeLifecycleError("maintenance_receipt_invalid")
            manifest = _read_archive_manifest(receipt)
        except WorktreeLifecycleError:
            raise
        except Exception as exc:
            raise WorktreeLifecycleError("maintenance_receipt_invalid") from exc
        binding = claim.candidate
        if manifest.get("kind") == "temporary_tree":
            operation = self.maintenance_operation_for_claim(claim)
            source_text = operation.get("temporary_source_path")
            if (
                operation.get("operation_kind") != "temporary"
                or not isinstance(source_text, str)
                or manifest.get("source") != source_text
                or manifest.get("source_device")
                != operation.get("temporary_source_device")
                or manifest.get("source_inode")
                != operation.get("temporary_source_inode")
                or manifest.get("source_mount_id")
                != operation.get("temporary_source_mount_id")
                or manifest.get("producer_lease_id")
                != operation.get("temporary_producer_lease_id")
            ):
                raise WorktreeLifecycleError("maintenance_receipt_binding_mismatch")
            source = Path(source_text)
            try:
                source.lstat()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise WorktreeLifecycleError("maintenance_removal_unverified") from exc
            else:
                raise WorktreeLifecycleError("maintenance_removal_incomplete")
            quarantine = source.parent / ".hive-quarantine" / claim.claim_id
            try:
                quarantine.lstat()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise WorktreeLifecycleError("maintenance_removal_unverified") from exc
            else:
                raise WorktreeLifecycleError("maintenance_removal_incomplete")
            with self._state.locked():
                document = self._read_locked()
                tree = self._get_tree(
                    document, _binding_key(binding), binding, create=False
                )
                if tree is None or tree.get("maintenance_claim") != _claim_payload(
                    claim
                ):
                    raise WorktreeLifecycleError("maintenance_claim_mismatch")
                current = tree.get("maintenance_operation")
                if (
                    not isinstance(current, Mapping)
                    or current.get("phase") != "deleting"
                    or current.get("operation_kind") != "temporary"
                    or current.get("archive_path") != str(receipt.archive)
                    or current.get("archive_manifest_sha256") != receipt.manifest_sha256
                ):
                    raise WorktreeLifecycleError("maintenance_phase_invalid")
                tree["maintenance_operation"] = {**current, "phase": "removed"}
                document["revision"] += 1
                self._write_locked(document)
            return
        gitdir_relative = manifest.get("gitdir")
        if not isinstance(gitdir_relative, str):
            raise WorktreeLifecycleError("maintenance_receipt_invalid")
        try:
            common_info = binding.git_common_directory.stat(follow_symlinks=False)
        except OSError as exc:
            raise WorktreeLifecycleError("maintenance_common_identity_changed") from exc
        if (
            manifest.get("source") != str(binding.canonical_source_path)
            or manifest.get("source_device") != binding.device
            or manifest.get("source_inode") != binding.inode
            or manifest.get("git_common_device") != common_info.st_dev
            or manifest.get("git_common_inode") != common_info.st_ino
        ):
            raise WorktreeLifecycleError("maintenance_receipt_binding_mismatch")
        absent_paths = (
            binding.canonical_source_path,
            binding.git_common_directory / gitdir_relative,
            binding.canonical_source_path.parent / ".hive-quarantine" / claim.claim_id,
            binding.git_common_directory
            / "worktrees"
            / ".hive-quarantine"
            / claim.claim_id,
        )
        for path in absent_paths:
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise WorktreeLifecycleError("maintenance_removal_unverified") from exc
            raise WorktreeLifecycleError("maintenance_removal_incomplete")
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(binding), binding, create=False
            )
            if tree is None or tree.get("maintenance_claim") != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            operation = tree.get("maintenance_operation")
            if (
                not isinstance(operation, Mapping)
                or operation.get("phase") != "deleting"
                or operation.get("archive_path") != str(receipt.archive)
                or operation.get("archive_manifest_sha256") != receipt.manifest_sha256
                or operation.get("gitdir_relative") != gitdir_relative
            ):
                raise WorktreeLifecycleError("maintenance_phase_invalid")
            tree["maintenance_operation"] = {**operation, "phase": "removed"}
            document["revision"] += 1
            self._write_locked(document)

    def finish_maintenance(self, claim: MaintenanceClaim, *, outcome: str) -> None:
        if type(claim) is not MaintenanceClaim:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        _require_text(outcome, code="maintenance_outcome_invalid", maximum=512)
        self._assert_claim_owner(claim)
        with self._state.locked():
            document = self._read_locked()
            key = _binding_key(claim.candidate)
            tree = self._get_tree(document, key, claim.candidate, create=False)
            if tree is None or tree["maintenance_claim"] is None:
                raise WorktreeLifecycleError("maintenance_claim_inactive")
            if tree["maintenance_claim"] != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            operation = tree.get("maintenance_operation")
            if not isinstance(operation, Mapping) or operation.get("phase") not in {
                "removed",
                "restored",
            }:
                raise WorktreeLifecycleError("maintenance_operation_incomplete")
            if operation.get("phase") == "restored" and outcome != "source_restored":
                raise WorktreeLifecycleError("maintenance_operation_incomplete")
            tree["maintenance_history"].append(
                {
                    "claim_id": claim.claim_id,
                    "revision": claim.revision,
                    "fence": claim.fence,
                    "outcome": outcome,
                    "operation": tree.get("maintenance_operation"),
                    "finished_at": time.time_ns(),
                }
            )
            del tree["maintenance_history"][:-_MAX_HISTORY_PER_WORKTREE]
            tree["maintenance_claim"] = None
            tree["maintenance_operation"] = None
            tree["revision"] += 1
            tree["fence"] += 1
            document["revision"] += 1
            self._write_locked(document)

    def record_maintenance_source_restored(
        self, claim: MaintenanceClaim, receipt: object
    ) -> None:
        """Close a temp claim only after its exact quarantined tree is restored."""
        if type(claim) is not MaintenanceClaim:
            raise WorktreeLifecycleError("maintenance_claim_invalid")
        self._assert_claim_owner(claim)
        try:
            from the_hive.maintenance import (
                ArchiveReceipt,
                _read_archive_manifest,
                _verify_manifest_tree,
            )

            if type(receipt) is not ArchiveReceipt:
                raise WorktreeLifecycleError("maintenance_receipt_invalid")
            manifest = _read_archive_manifest(receipt)
        except WorktreeLifecycleError:
            raise
        except Exception as exc:
            raise WorktreeLifecycleError("maintenance_receipt_invalid") from exc
        if manifest.get("kind") != "temporary_tree":
            raise WorktreeLifecycleError("maintenance_receipt_invalid")
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(claim.candidate), claim.candidate, create=False
            )
            if tree is None or tree.get("maintenance_claim") != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            operation = tree.get("maintenance_operation")
            if not isinstance(operation, Mapping):
                raise WorktreeLifecycleError("maintenance_journal_invalid")
        source_text = operation.get("temporary_source_path")
        if (
            operation.get("operation_kind") != "temporary"
            or operation.get("phase")
            not in {"quarantine_started", "quarantined", "recovery_hold"}
            or not isinstance(source_text, str)
            or manifest.get("source") != source_text
            or operation.get("archive_path") != str(receipt.archive)
            or operation.get("archive_manifest_sha256") != receipt.manifest_sha256
        ):
            raise WorktreeLifecycleError("maintenance_phase_invalid")
        source = Path(source_text)
        if (
            manifest.get("source_device") != operation.get("temporary_source_device")
            or manifest.get("source_inode") != operation.get("temporary_source_inode")
            or manifest.get("source_mount_id")
            != operation.get("temporary_source_mount_id")
            or manifest.get("producer_lease_id")
            != operation.get("temporary_producer_lease_id")
        ):
            raise WorktreeLifecycleError("maintenance_receipt_binding_mismatch")
        try:
            info = source.stat(follow_symlinks=False)
        except OSError as exc:
            raise WorktreeLifecycleError("maintenance_source_restore_mismatch") from exc
        try:
            if (
                (info.st_dev, info.st_ino)
                != (
                    operation.get("temporary_source_device"),
                    operation.get("temporary_source_inode"),
                )
                or _mount_id(source) != operation.get("temporary_source_mount_id")
                or source.resolve(strict=True) != source
            ):
                raise WorktreeLifecycleError("maintenance_source_restore_mismatch")
            _verify_manifest_tree(source, manifest["source_entries"], skip_git=False)
        except WorktreeLifecycleError:
            raise
        except Exception as exc:
            raise WorktreeLifecycleError("maintenance_source_restore_mismatch") from exc
        try:
            (source.parent / ".hive-quarantine" / claim.claim_id).lstat()
        except FileNotFoundError:
            pass
        except Exception as exc:
            raise WorktreeLifecycleError("maintenance_source_restore_mismatch") from exc
        else:
            raise WorktreeLifecycleError("maintenance_source_restore_incomplete")
        with self._state.locked():
            document = self._read_locked()
            tree = self._get_tree(
                document, _binding_key(claim.candidate), claim.candidate, create=False
            )
            if tree is None or tree.get("maintenance_claim") != _claim_payload(claim):
                raise WorktreeLifecycleError("maintenance_claim_mismatch")
            current = tree.get("maintenance_operation")
            if (
                not isinstance(current, Mapping)
                or current.get("phase")
                not in {"quarantine_started", "quarantined", "recovery_hold"}
                or current.get("temporary_source_path") != source_text
                or current.get("archive_manifest_sha256") != receipt.manifest_sha256
            ):
                raise WorktreeLifecycleError("maintenance_phase_invalid")
            tree["maintenance_operation"] = {**current, "phase": "restored"}
            document["revision"] += 1
            self._write_locked(document)

    def recover_maintenance_claim(
        self, binding: WorktreeBinding, *, now: int
    ) -> MaintenanceClaim:
        """Fence a dead writer and preserve its journal for explicit recovery."""
        if type(binding) is not WorktreeBinding:
            raise WorktreeLifecycleError("worktree_binding_invalid")
        _require_integer(now, code="lifecycle_time_invalid")
        _validate_live_binding(binding)
        with self._state.locked():
            document = self._read_locked()
            key = _binding_key(binding)
            tree = self._get_tree(document, key, binding, create=False)
            if tree is None or tree.get("maintenance_claim") is None:
                raise WorktreeLifecycleError("maintenance_claim_inactive")
            claim = _claim_from_payload(binding, tree["maintenance_claim"])
            if _process_is_active(claim.owner_process):
                raise WorktreeLifecycleError("maintenance_claim_owner_active")
            operation = tree.get("maintenance_operation")
            if (
                not isinstance(operation, Mapping)
                or operation.get("claim_id") != claim.claim_id
            ):
                raise WorktreeLifecycleError("maintenance_journal_invalid")
            recovered = MaintenanceClaim(
                claim_id=claim.claim_id,
                candidate=binding,
                revision=tree["revision"] + 1,
                fence=tree["fence"] + 1,
                owner_process=_current_process_identity(),
                claimed_at=claim.claimed_at,
            )
            tree["revision"] += 1
            tree["fence"] += 1
            document["revision"] += 1
            tree["maintenance_claim"] = _claim_payload(recovered)
            tree["maintenance_operation"] = {**operation, "phase": "recovery_hold"}
            self._write_locked(document)
            return recovered

    def _assert_claim_owner(self, claim: MaintenanceClaim) -> None:
        if claim.owner_process != _current_process_identity():
            raise WorktreeLifecycleError("maintenance_claim_owner_mismatch")
        if not _process_is_active(claim.owner_process):
            raise WorktreeLifecycleError("maintenance_claim_owner_unavailable")

    def _read_locked(self) -> dict[str, object]:
        try:
            document = self._state.read_json_locked(
                _STATE_PATH, max_bytes=MAX_HIVE_STATE_BYTES
            )
        except HiveStateError as exc:
            if str(exc) == "state_not_found":
                return _empty_document()
            raise
        return _validate_document(document)

    def _write_locked(self, document: dict[str, object]) -> None:
        encoded = json.dumps(
            document, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        if len(encoded) > MAX_HIVE_STATE_BYTES:
            raise WorktreeLifecycleError("lifecycle_state_oversize")
        self._state.replace_json_locked(_STATE_PATH, document)

    @staticmethod
    def _get_tree(
        document: dict[str, object],
        key: str,
        binding: WorktreeBinding,
        *,
        create: bool = True,
    ) -> dict[str, object] | None:
        worktrees = document["worktrees"]
        tree = worktrees.get(key)
        if tree is None:
            if not create:
                return None
            tree = _empty_tree(binding)
            worktrees[key] = tree
        elif not isinstance(tree, Mapping) or tree.get("binding") != _binding_payload(
            binding
        ):
            raise WorktreeLifecycleError("worktree_binding_alias")
        return tree
