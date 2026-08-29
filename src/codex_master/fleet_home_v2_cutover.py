"""One-way, whole-directory Fleet Home V2 cutover.

This module owns Linux mutation boundary. Planning accepts only bound registry
authority. Active-home swap is ``renameat2(RENAME_EXCHANGE)`` or nothing.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping


MARKER_FILE = ".codex-fleet-agent.json"
MAX_TARGETS = 27
_AGENT_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_OPERATION_ID_RE = re.compile(r"[0-9a-f]{48}\Z")
_MARKER_FIELDS = frozenset(
    {
        "schema_version", "kind", "agent_id", "prefix", "runner", "provider",
        "model", "common_policy", "managed_files", "files",
    }
)
_MARKER_RUNTIME_FIELD = "runtime_skill_profile"
_POLICY_FIELDS = frozenset({"schema_version", "generation", "digest"})
_JOURNAL_STATES = (
    "planned", "staged", "exchanged", "backup-bound", "cutover-complete",
    "rollback-exchanged", "rolled-back",
)
_RESERVED_OPERATION_IDS: set[str] = set()
_RESERVED_OPERATION_IDS_LOCK = threading.Lock()
_BOUND_PLANS: dict[str, tuple["FleetHomeV2PlanHandle", "FleetHomeV2Plan"]] = {}
_BOUND_PLANS_LOCK = threading.Lock()
_MAX_BOUND_PLANS = 128


class FleetHomeV2CutoverError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class FleetHomeV2Artifact:
    relative_path: str
    data: bytes
    mode: int


@dataclass(frozen=True, slots=True)
class FleetHomeV2Policy:
    schema_version: int
    generation: int
    digest: str


@dataclass(frozen=True, slots=True)
class FleetHomeV2Authority:
    agent_id: str
    prefix: str
    provider: str
    runner: str
    model: str
    home: Path
    registry_generation: int
    policy: FleetHomeV2Policy
    owner_uid: int
    owner_gid: int
    authority_generation: int
    lease_generation: str
    process_generation: str
    artifacts: tuple[FleetHomeV2Artifact, ...]
    runtime_skill_profile: str | None = None


@dataclass(frozen=True, slots=True)
class FleetHomeV2Inventory:
    generation: int
    homes: Mapping[str, FleetHomeV2Authority]


@dataclass(frozen=True, slots=True)
class _FilesystemIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    mtime_ns: int


@dataclass(frozen=True, slots=True)
class FleetHomeV2Quiescence:
    agent_id: str
    home_identity: _FilesystemIdentity
    registry_generation: int
    policy_generation: int
    authority_generation: int
    lease_generation: str
    process_generation: str
    observation_generation: int
    observed_monotonic_ns: int
    stopped: bool
    lease_state: str
    process_scan_available: bool
    managed_processes: int
    external_processes: int


class FleetHomeV2AuthorityPort:
    """Concrete authority boundary. Production subclasses refresh internally."""

    def snapshot(self) -> FleetHomeV2Inventory:
        raise NotImplementedError


class FleetHomeV2SnapshotAuthorityPort(FleetHomeV2AuthorityPort):
    """Fixed authority port for local, offline verification."""

    def __init__(self, snapshot: FleetHomeV2Inventory) -> None:
        self._snapshot = snapshot

    def snapshot(self) -> FleetHomeV2Inventory:
        return self._snapshot

    def replace_snapshot(self, snapshot: FleetHomeV2Inventory) -> None:
        self._snapshot = snapshot


class FleetHomeV2QuiescencePort:
    """Data-only quiescence boundary; no caller supplied permissive callback."""

    def __init__(
        self,
        *,
        stopped: bool = True,
        lease_state: str = "none",
        process_scan_available: bool = True,
        managed_processes: int = 0,
        external_processes: int = 0,
        agent_id: str | None = None,
        lease_generation: str | None = None,
        process_generation: str | None = None,
    ) -> None:
        self.stopped = stopped
        self.lease_state = lease_state
        self.process_scan_available = process_scan_available
        self.managed_processes = managed_processes
        self.external_processes = external_processes
        self.agent_id = agent_id
        self.lease_generation = lease_generation
        self.process_generation = process_generation
        self._generation = 0

    def observe(
        self, authority: FleetHomeV2Authority, home_identity: _FilesystemIdentity
    ) -> FleetHomeV2Quiescence:
        self._generation += 1
        return FleetHomeV2Quiescence(
            agent_id=self.agent_id or authority.agent_id,
            home_identity=home_identity,
            registry_generation=authority.registry_generation,
            policy_generation=authority.policy.generation,
            authority_generation=authority.authority_generation,
            lease_generation=self.lease_generation or authority.lease_generation,
            process_generation=self.process_generation or authority.process_generation,
            observation_generation=self._generation,
            observed_monotonic_ns=time.monotonic_ns(),
            stopped=self.stopped,
            lease_state=self.lease_state,
            process_scan_available=self.process_scan_available,
            managed_processes=self.managed_processes,
            external_processes=self.external_processes,
        )


class FleetHomeV2EntropyPort:
    def token_hex(self, bytes_count: int) -> str:
        return secrets.token_hex(bytes_count)


class LocalFleetHomeV2Filesystem:
    """Linux dirfd operations. There is intentionally no path rename method."""

    def checkpoint(self, _point: str) -> None:
        return None

    @staticmethod
    def identity_from_stat(value: os.stat_result) -> _FilesystemIdentity:
        return _FilesystemIdentity(
            value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns,
        )

    @classmethod
    def identity_at(cls, parent_fd: int, name: str) -> _FilesystemIdentity:
        try:
            return cls.identity_from_stat(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid") from exc

    @classmethod
    def parent_identity(cls, parent_fd: int) -> _FilesystemIdentity:
        try:
            return cls.identity_from_stat(os.fstat(parent_fd))
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid") from exc

    @staticmethod
    def mount_id(directory_fd: int) -> int:
        try:
            with open(f"/proc/self/fdinfo/{directory_fd}", encoding="utf-8") as source:
                for line in source:
                    if line.startswith("mnt_id:"):
                        return int(line.partition(":")[2].strip())
        except (OSError, ValueError) as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc
        raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")

    @staticmethod
    def open_parent(parent: Path) -> int:
        try:
            return os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid") from exc

    @staticmethod
    def _open_dir_at(parent_fd: int, name: str) -> int:
        try:
            return os.open(
                name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed") from exc

    @staticmethod
    def _private_directory(identity: _FilesystemIdentity, uid: int, gid: int) -> bool:
        return (
            stat.S_ISDIR(identity.mode)
            and stat.S_IMODE(identity.mode) == 0o700
            and identity.uid == uid
            and identity.gid == gid
        )

    @staticmethod
    def _lstat_absent(parent_fd: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid") from exc
        return False

    def mkdir_private_at(self, parent_fd: int, name: str, uid: int, gid: int) -> int:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            os.chown(name, uid, gid, dir_fd=parent_fd, follow_symlinks=False)
            os.chmod(name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc
        child_fd = self._open_dir_at(parent_fd, name)
        if not self._private_directory(self.parent_identity(child_fd), uid, gid):
            os.close(child_fd)
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
        return child_fd

    def write_file_at(
        self, parent_fd: int, name: str, data: bytes, mode: int, uid: int, gid: int
    ) -> None:
        try:
            file_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=parent_fd,
            )
        except FileExistsError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_cutover_collision") from exc
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc
        try:
            view = memoryview(data)
            while view:
                written = os.write(file_fd, view)
                if written <= 0:
                    raise OSError(errno.EIO, "short write")
                view = view[written:]
            os.fchmod(file_fd, mode)
            os.fchown(file_fd, uid, gid)
            os.fsync(file_fd)
            current = self.identity_from_stat(os.fstat(file_fd))
            if (
                not stat.S_ISREG(current.mode) or stat.S_IMODE(current.mode) != mode
                or current.uid != uid or current.gid != gid or current.nlink != 1
                or current.size != len(data)
            ):
                raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
        except FleetHomeV2CutoverError:
            raise
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc
        finally:
            os.close(file_fd)

    def fsync_tree_at(self, directory_fd: int) -> None:
        """Flush files then every directory bottom-up without symlink traversal."""
        try:
            names = os.listdir(directory_fd)
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc
        for name in sorted(names):
            current = self.identity_at(directory_fd, name)
            if stat.S_ISDIR(current.mode):
                child_fd = self._open_dir_at(directory_fd, name)
                try:
                    self.fsync_tree_at(child_fd)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(current.mode) and current.nlink == 1:
                file_fd = -1
                try:
                    file_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
                    os.fsync(file_fd)
                except OSError as exc:
                    raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc
                finally:
                    if file_fd >= 0:
                        os.close(file_fd)
            else:
                raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc

    @staticmethod
    def fsync_directory(parent_fd: int) -> None:
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc

    @staticmethod
    def _renameat2(parent_fd: int, source: str, target: str, flags: int) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise FleetHomeV2CutoverError("fleet_home_v2_exchange_unavailable")
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        if renameat2(parent_fd, os.fsencode(source), parent_fd, os.fsencode(target), flags) != 0:
            current_errno = ctypes.get_errno()
            if current_errno in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL}:
                raise FleetHomeV2CutoverError("fleet_home_v2_exchange_unavailable")
            if current_errno == errno.EEXIST:
                raise FleetHomeV2CutoverError("fleet_home_v2_cutover_collision")
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")

    def exchange_at(self, parent_fd: int, source: str, target: str) -> None:
        self._renameat2(parent_fd, source, target, 2)  # RENAME_EXCHANGE

    def rename_noreplace_at(self, parent_fd: int, source: str, target: str) -> None:
        self._renameat2(parent_fd, source, target, 1)  # RENAME_NOREPLACE

    @staticmethod
    def unlink_at(parent_fd: int, name: str) -> None:
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required") from exc

    def remove_tree_at(self, parent_fd: int, name: str) -> None:
        directory_fd = self._open_dir_at(parent_fd, name)
        try:
            self._remove_tree_contents(directory_fd)
        finally:
            os.close(directory_fd)
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required") from exc

    def _remove_tree_contents(self, directory_fd: int) -> None:
        try:
            names = os.listdir(directory_fd)
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required") from exc
        for name in names:
            current = self.identity_at(directory_fd, name)
            if stat.S_ISDIR(current.mode):
                child_fd = self._open_dir_at(directory_fd, name)
                try:
                    self._remove_tree_contents(child_fd)
                finally:
                    os.close(child_fd)
                try:
                    os.rmdir(name, dir_fd=directory_fd)
                except OSError as exc:
                    raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required") from exc
            elif stat.S_ISREG(current.mode) and current.nlink == 1:
                self.unlink_at(directory_fd, name)
            else:
                raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")


@dataclass(frozen=True, slots=True)
class FleetHomeV2TargetPlan:
    authority: FleetHomeV2Authority
    home_identity: _FilesystemIdentity
    parent_identity: _FilesystemIdentity
    manifest_digest: str
    already_current: bool


@dataclass(frozen=True, slots=True)
class FleetHomeV2Plan:
    operation_id: str
    registry_generation: int
    targets: tuple[FleetHomeV2TargetPlan, ...]
    digest: str


class FleetHomeV2PlanHandle:
    """Opaque capability returned only by :meth:`FleetHomeV2CutoverService.plan`."""

    __slots__ = ("_operation_id",)

    def __init__(self, operation_id: str) -> None:
        self._operation_id = operation_id

    @property
    def operation_id(self) -> str:
        return self._operation_id


@dataclass(frozen=True, slots=True)
class FleetHomeV2Result:
    agent_id: str
    state: str
    code: str | None = None


class FleetHomeV2CutoverService:
    def __init__(
        self,
        *,
        authority_port: FleetHomeV2AuthorityPort,
        quiescence_port: FleetHomeV2QuiescencePort,
        filesystem: LocalFleetHomeV2Filesystem | None = None,
        entropy: FleetHomeV2EntropyPort | None = None,
    ) -> None:
        if not isinstance(authority_port, FleetHomeV2AuthorityPort):
            raise TypeError("authority_port must be FleetHomeV2AuthorityPort")
        if not isinstance(quiescence_port, FleetHomeV2QuiescencePort):
            raise TypeError("quiescence_port must be FleetHomeV2QuiescencePort")
        self._authority_port = authority_port
        self._quiescence_port = quiescence_port
        self._filesystem = filesystem or LocalFleetHomeV2Filesystem()
        self._entropy = entropy or FleetHomeV2EntropyPort()
        self._observations: dict[str, int] = {}
        self._observations_lock = threading.Lock()

    def plan(self, target_ids: tuple[str, ...]) -> FleetHomeV2PlanHandle:
        if not isinstance(target_ids, tuple) or any(type(item) is not str for item in target_ids):
            raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")
        operation_id = self._reserve_operation_id()
        snapshot = self._snapshot()
        targets = self._build_targets(snapshot, target_ids)
        plan = FleetHomeV2Plan(
            operation_id,
            snapshot.generation,
            targets,
            self._plan_digest(operation_id, snapshot.generation, targets),
        )
        handle = FleetHomeV2PlanHandle(operation_id)
        with _BOUND_PLANS_LOCK:
            if len(_BOUND_PLANS) >= _MAX_BOUND_PLANS:
                raise FleetHomeV2CutoverError("fleet_home_v2_operation_collision")
            _BOUND_PLANS[operation_id] = (handle, plan)
        return handle

    def apply(self, handle: FleetHomeV2PlanHandle) -> tuple[FleetHomeV2Result, ...]:
        plan = self._resolve_handle(handle)
        self._validate_plan(plan, require_source=True)
        results: list[FleetHomeV2Result] = []
        for target in plan.targets:
            try:
                if target.already_current:
                    self._require_current_v2(target)
                    results.append(FleetHomeV2Result(target.authority.agent_id, "already-current", "fleet_home_v2_already_current"))
                else:
                    self._validate_plan(plan, require_source=True)
                    results.append(self._apply_target(plan, target))
            except FleetHomeV2CutoverError as exc:
                results.append(self._result_for_error(target.authority.agent_id, exc.code))
        return tuple(results)

    def recover(self, handle: FleetHomeV2PlanHandle) -> tuple[FleetHomeV2Result, ...]:
        plan = self._resolve_handle(handle)
        self._validate_plan(plan, require_source=False)
        results: list[FleetHomeV2Result] = []
        for target in plan.targets:
            try:
                results.append(self._recover_target(plan, target))
            except FleetHomeV2CutoverError as exc:
                results.append(FleetHomeV2Result(target.authority.agent_id, "recovery-required", self._recovery_code(exc.code)))
        return tuple(results)

    def verify(self, handle: FleetHomeV2PlanHandle) -> tuple[FleetHomeV2Result, ...]:
        plan = self._resolve_handle(handle)
        self._validate_plan(plan, require_source=False)
        results: list[FleetHomeV2Result] = []
        for target in plan.targets:
            mutation_possible = False
            parent_fd = -1
            try:
                if target.already_current:
                    self._require_current_v2(target)
                    results.append(FleetHomeV2Result(target.authority.agent_id, "already-current"))
                    continue
                parent_fd = self._open_bound_parent(target)
                try:
                    journal = self._load_journal(parent_fd, plan, target)
                    if self._journal_state(journal) != "cutover-complete":
                        raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
                    self._require_v2_and_backup(parent_fd, target, journal)
                except FleetHomeV2CutoverError:
                    mutation_possible = self._mutation_possible(
                        parent_fd, target, self._names(plan, target)
                    )
                    raise
                finally:
                    if parent_fd >= 0:
                        os.close(parent_fd)
                        parent_fd = -1
                results.append(FleetHomeV2Result(target.authority.agent_id, "cutover-complete"))
            except FleetHomeV2CutoverError as exc:
                if parent_fd >= 0:
                    mutation_possible = self._mutation_possible(
                        parent_fd, target, self._names(plan, target)
                    )
                    os.close(parent_fd)
                    parent_fd = -1
                state = "recovery-required" if mutation_possible else "failed-terminal"
                results.append(FleetHomeV2Result(target.authority.agent_id, state, self._recovery_code(exc.code)))
        return tuple(results)

    def rollback(self, handle: FleetHomeV2PlanHandle) -> tuple[FleetHomeV2Result, ...]:
        plan = self._resolve_handle(handle)
        self._validate_plan(plan, require_source=False)
        results: list[FleetHomeV2Result] = []
        for target in plan.targets:
            try:
                results.append(self._rollback_target(plan, target))
            except FleetHomeV2CutoverError as exc:
                results.append(FleetHomeV2Result(target.authority.agent_id, "recovery-required", self._recovery_code(exc.code)))
        return tuple(results)

    def _snapshot(self) -> FleetHomeV2Inventory:
        snapshot = self._authority_port.snapshot()
        if not isinstance(snapshot, FleetHomeV2Inventory) or type(snapshot.generation) is not int or snapshot.generation <= 0:
            raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")
        return snapshot

    @staticmethod
    def _resolve_handle(handle: FleetHomeV2PlanHandle) -> FleetHomeV2Plan:
        if not isinstance(handle, FleetHomeV2PlanHandle):
            raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")
        with _BOUND_PLANS_LOCK:
            bound = _BOUND_PLANS.get(handle.operation_id)
        if bound is None or bound[0] is not handle:
            raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")
        return bound[1]

    def _reserve_operation_id(self) -> str:
        for _attempt in range(8):
            operation_id = self._entropy.token_hex(24)
            if _OPERATION_ID_RE.fullmatch(operation_id) is None:
                continue
            with _RESERVED_OPERATION_IDS_LOCK:
                if operation_id not in _RESERVED_OPERATION_IDS:
                    _RESERVED_OPERATION_IDS.add(operation_id)
                    return operation_id
        raise FleetHomeV2CutoverError("fleet_home_v2_operation_collision")

    def _build_targets(self, snapshot: FleetHomeV2Inventory, target_ids: tuple[str, ...]) -> tuple[FleetHomeV2TargetPlan, ...]:
        if not target_ids or len(target_ids) > MAX_TARGETS or len(set(target_ids)) != len(target_ids):
            raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")
        if any(_AGENT_ID_RE.fullmatch(item) is None for item in target_ids):
            raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")
        ordered = tuple(sorted(target_ids, key=lambda item: (item != "g1", item)))
        targets: list[FleetHomeV2TargetPlan] = []
        for agent_id in ordered:
            authority = snapshot.homes.get(agent_id)
            if not isinstance(authority, FleetHomeV2Authority) or authority.agent_id != agent_id:
                raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")
            self._validate_authority(authority, snapshot.generation)
            parent_fd = self._filesystem.open_parent(authority.home.parent)
            try:
                parent_identity = self._filesystem.parent_identity(parent_fd)
                home_identity = self._filesystem.identity_at(parent_fd, authority.home.name)
                if not self._filesystem._private_directory(parent_identity, authority.owner_uid, authority.owner_gid):
                    raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid")
                if not self._filesystem._private_directory(home_identity, authority.owner_uid, authority.owner_gid):
                    raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid")
                already_current = self._attest_tree_at(parent_fd, authority.home.name, authority)
            finally:
                os.close(parent_fd)
            targets.append(FleetHomeV2TargetPlan(authority, home_identity, parent_identity, self._manifest_digest(authority), already_current))
        return tuple(targets)

    def _validate_plan(self, plan: FleetHomeV2Plan, *, require_source: bool) -> None:
        if (
            not isinstance(plan, FleetHomeV2Plan) or _OPERATION_ID_RE.fullmatch(plan.operation_id) is None
            or not isinstance(plan.targets, tuple) or not plan.targets or len(plan.targets) > MAX_TARGETS
            or not isinstance(plan.digest, str)
        ):
            raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")
        ids = tuple(target.authority.agent_id for target in plan.targets if isinstance(target, FleetHomeV2TargetPlan))
        if len(ids) != len(plan.targets) or ids != tuple(sorted(ids, key=lambda item: (item != "g1", item))):
            raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")
        snapshot = self._snapshot()
        if snapshot.generation != plan.registry_generation:
            raise FleetHomeV2CutoverError("fleet_home_v2_generation_stale")
        if require_source:
            expected = self._build_targets(snapshot, ids)
            if any(
                current.authority != planned.authority
                or current.home_identity != planned.home_identity
                or not self._same_parent(current.parent_identity, planned.parent_identity)
                or current.manifest_digest != planned.manifest_digest
                or current.already_current != planned.already_current
                for current, planned in zip(expected, plan.targets, strict=True)
            ) or self._plan_digest(plan.operation_id, plan.registry_generation, plan.targets) != plan.digest:
                raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")
            return
        for target in plan.targets:
            current = snapshot.homes.get(target.authority.agent_id)
            if current != target.authority or self._manifest_digest(target.authority) != target.manifest_digest:
                raise FleetHomeV2CutoverError("fleet_home_v2_generation_stale")
        if self._plan_digest(plan.operation_id, plan.registry_generation, plan.targets) != plan.digest:
            raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")

    def _validate_authority(self, authority: FleetHomeV2Authority, generation: int) -> None:
        if (
            _AGENT_ID_RE.fullmatch(authority.agent_id) is None or authority.home.name != authority.agent_id
            or authority.registry_generation != generation or authority.authority_generation <= 0
            or authority.policy.schema_version != 2 or authority.policy.generation <= 0
            or re.fullmatch(r"[0-9a-f]{64}", authority.policy.digest) is None
            or not authority.lease_generation or not authority.process_generation
            or type(authority.owner_uid) is not int or type(authority.owner_gid) is not int
        ):
            raise FleetHomeV2CutoverError("fleet_home_v2_plan_invalid")
        self._artifact_map(authority)

    def _apply_target(self, plan: FleetHomeV2Plan, target: FleetHomeV2TargetPlan) -> FleetHomeV2Result:
        parent_fd = self._open_bound_parent(target)
        mutated = False
        try:
            names = self._names(plan, target)
            self._require_quiescent(target, target.home_identity)
            self._acquire_home_lock(parent_fd, plan, target, names)
            self._require_operation_absent(parent_fd, names)
            journal = self._new_journal(plan, target, names)
            self._store_journal(parent_fd, names["journal"], journal, previous_identity=None)
            self._filesystem.checkpoint("after-journal-planned")
            stage_fd = self._filesystem.mkdir_private_at(parent_fd, names["stage"], target.authority.owner_uid, target.authority.owner_gid)
            try:
                self._write_stage(stage_fd, target.authority)
                self._filesystem.fsync_tree_at(stage_fd)
                stage_identity = self._filesystem.parent_identity(stage_fd)
            finally:
                os.close(stage_fd)
            if not self._filesystem._private_directory(stage_identity, target.authority.owner_uid, target.authority.owner_gid):
                raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
            self._filesystem.fsync_directory(parent_fd)
            if not self._attest_tree_at(parent_fd, names["stage"], target.authority):
                raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed")
            journal = self._advance_journal(journal, "staged", stage_identity)
            self._store_journal(parent_fd, names["journal"], journal, self._filesystem.identity_at(parent_fd, names["journal"]))
            self._filesystem.checkpoint("after-stage-fsync")
            self._validate_plan(plan, require_source=True)
            self._require_quiescent(target, target.home_identity)
            if self._filesystem.identity_at(parent_fd, target.authority.home.name) != target.home_identity:
                raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid")
            if self._filesystem.identity_at(parent_fd, names["stage"]) != stage_identity:
                raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
            self._filesystem.exchange_at(parent_fd, target.authority.home.name, names["stage"])
            mutated = True
            try:
                if (
                    self._filesystem.identity_at(parent_fd, target.authority.home.name) != stage_identity
                    or self._filesystem.identity_at(parent_fd, names["stage"]) != target.home_identity
                ):
                    raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
            except FleetHomeV2CutoverError:
                if self._restore_exchange_if_bound(parent_fd, target, names, stage_identity):
                    mutated = False
                    raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid") from None
                raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required") from None
            self._filesystem.fsync_directory(parent_fd)
            journal = self._advance_journal(journal, "exchanged", stage_identity)
            self._store_journal(parent_fd, names["journal"], journal, self._filesystem.identity_at(parent_fd, names["journal"]))
            self._filesystem.checkpoint("after-exchange")
            self._filesystem.rename_noreplace_at(parent_fd, names["stage"], names["backup"])
            if self._filesystem.identity_at(parent_fd, names["backup"]) != target.home_identity:
                raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
            self._filesystem.fsync_directory(parent_fd)
            journal = self._advance_journal(journal, "backup-bound", stage_identity)
            self._store_journal(parent_fd, names["journal"], journal, self._filesystem.identity_at(parent_fd, names["journal"]))
            self._filesystem.checkpoint("after-stage-to-backup")
            self._require_v2_and_backup(parent_fd, target, journal)
            journal = self._advance_journal(journal, "cutover-complete", stage_identity)
            self._store_journal(parent_fd, names["journal"], journal, self._filesystem.identity_at(parent_fd, names["journal"]))
            self._filesystem.checkpoint("after-v2-verify")
            return FleetHomeV2Result(target.authority.agent_id, "cutover-complete")
        except FleetHomeV2CutoverError as exc:
            if mutated:
                raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required") from exc
            raise
        finally:
            os.close(parent_fd)

    def _recover_target(self, plan: FleetHomeV2Plan, target: FleetHomeV2TargetPlan) -> FleetHomeV2Result:
        if target.already_current:
            self._require_current_v2(target)
            return FleetHomeV2Result(target.authority.agent_id, "already-current")
        parent_fd = self._open_bound_parent(target)
        try:
            names = self._names(plan, target)
            self._acquire_home_lock(parent_fd, plan, target, names)
            journal = self._load_journal(parent_fd, plan, target)
            state = self._journal_state(journal)
            home = self._optional_identity(parent_fd, target.authority.home.name)
            stage = self._optional_identity(parent_fd, names["stage"])
            backup = self._optional_identity(parent_fd, names["backup"])
            archive = self._optional_identity(parent_fd, names["archive"])
            if (
                state == "planned"
                and home == target.home_identity
                and stage is None
                and backup is None
                and archive is None
            ):
                self._require_quiescent(target, target.home_identity)
                self._filesystem.unlink_at(parent_fd, names["journal"])
                self._release_home_lock(parent_fd, plan, target, names)
                return FleetHomeV2Result(target.authority.agent_id, "failed-retryable", "fleet_home_v2_cutover_failed")
            v2_identity = self._journal_v2_identity(journal)
            if home == v2_identity and backup == target.home_identity and stage is None:
                self._require_quiescent(target, v2_identity)
                journal = self._advance_until(parent_fd, names["journal"], journal, "cutover-complete", v2_identity)
                self._require_v2_and_backup(parent_fd, target, journal)
                return FleetHomeV2Result(target.authority.agent_id, "cutover-complete")
            if home == v2_identity and stage == target.home_identity and backup is None:
                self._require_quiescent(target, v2_identity)
                journal = self._advance_until(parent_fd, names["journal"], journal, "exchanged", v2_identity)
                self._filesystem.rename_noreplace_at(parent_fd, names["stage"], names["backup"])
                self._filesystem.fsync_directory(parent_fd)
                journal = self._advance_until(parent_fd, names["journal"], journal, "backup-bound", v2_identity)
                self._require_v2_and_backup(parent_fd, target, journal)
                journal = self._advance_until(parent_fd, names["journal"], journal, "cutover-complete", v2_identity)
                return FleetHomeV2Result(target.authority.agent_id, "cutover-complete")
            if home == target.home_identity and backup == v2_identity and archive is None:
                self._require_quiescent(target, target.home_identity)
                journal = self._advance_until(parent_fd, names["journal"], journal, "rollback-exchanged", v2_identity)
                self._filesystem.rename_noreplace_at(parent_fd, names["backup"], names["archive"])
                self._filesystem.fsync_directory(parent_fd)
                journal = self._advance_until(parent_fd, names["journal"], journal, "rolled-back", v2_identity)
                return FleetHomeV2Result(target.authority.agent_id, "rolled-back")
            if home == target.home_identity and backup is None and archive == v2_identity:
                self._require_quiescent(target, target.home_identity)
                journal = self._advance_until(parent_fd, names["journal"], journal, "rolled-back", v2_identity)
                return FleetHomeV2Result(target.authority.agent_id, "rolled-back")
            if (
                state == "staged"
                and home == target.home_identity
                and stage == v2_identity
                and backup is None
                and archive is None
            ):
                if not self._attest_tree_at(parent_fd, names["stage"], target.authority):
                    raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
                self._require_quiescent(target, target.home_identity)
                self._filesystem.remove_tree_at(parent_fd, names["stage"])
                self._filesystem.unlink_at(parent_fd, names["journal"])
                self._release_home_lock(parent_fd, plan, target, names)
                return FleetHomeV2Result(target.authority.agent_id, "failed-retryable", "fleet_home_v2_cutover_failed")
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
        finally:
            os.close(parent_fd)

    def _rollback_target(self, plan: FleetHomeV2Plan, target: FleetHomeV2TargetPlan) -> FleetHomeV2Result:
        if target.already_current:
            raise FleetHomeV2CutoverError("fleet_home_v2_rollback_failed")
        parent_fd = self._open_bound_parent(target)
        mutated = False
        try:
            names = self._names(plan, target)
            journal = self._load_journal(parent_fd, plan, target)
            v2_identity = self._journal_v2_identity(journal)
            if self._journal_state(journal) != "cutover-complete":
                raise FleetHomeV2CutoverError("fleet_home_v2_rollback_failed")
            self._require_v2_and_backup(parent_fd, target, journal)
            if not self._filesystem._lstat_absent(parent_fd, names["archive"]):
                raise FleetHomeV2CutoverError("fleet_home_v2_rollback_failed")
            self._require_quiescent(target, v2_identity)
            self._filesystem.exchange_at(parent_fd, target.authority.home.name, names["backup"])
            mutated = True
            if (
                self._filesystem.identity_at(parent_fd, target.authority.home.name) != target.home_identity
                or self._filesystem.identity_at(parent_fd, names["backup"]) != v2_identity
            ):
                raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
            self._filesystem.fsync_directory(parent_fd)
            journal = self._advance_journal(journal, "rollback-exchanged", v2_identity)
            self._store_journal(parent_fd, names["journal"], journal, self._filesystem.identity_at(parent_fd, names["journal"]))
            self._filesystem.checkpoint("after-rollback-exchange")
            self._filesystem.rename_noreplace_at(parent_fd, names["backup"], names["archive"])
            self._filesystem.fsync_directory(parent_fd)
            journal = self._advance_journal(journal, "rolled-back", v2_identity)
            self._store_journal(parent_fd, names["journal"], journal, self._filesystem.identity_at(parent_fd, names["journal"]))
            self._filesystem.checkpoint("after-v2-archive")
            return FleetHomeV2Result(target.authority.agent_id, "rolled-back")
        except FleetHomeV2CutoverError as exc:
            if mutated:
                raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required") from exc
            raise
        finally:
            os.close(parent_fd)

    def _open_bound_parent(self, target: FleetHomeV2TargetPlan) -> int:
        parent_fd = self._filesystem.open_parent(target.authority.home.parent)
        if not self._same_parent(self._filesystem.parent_identity(parent_fd), target.parent_identity):
            os.close(parent_fd)
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
        return parent_fd

    @staticmethod
    def _same_parent(current: _FilesystemIdentity, expected: _FilesystemIdentity) -> bool:
        return (current.device, current.inode, current.mode, current.uid, current.gid) == (
            expected.device, expected.inode, expected.mode, expected.uid, expected.gid,
        )

    def _require_quiescent(
        self, target: FleetHomeV2TargetPlan, active_identity: _FilesystemIdentity
    ) -> None:
        evidence = self._quiescence_port.observe(target.authority, active_identity)
        now = time.monotonic_ns()
        with self._observations_lock:
            previous = self._observations.get(target.authority.agent_id, 0)
            if (
                not isinstance(evidence, FleetHomeV2Quiescence)
                or evidence.agent_id != target.authority.agent_id
                or evidence.home_identity != active_identity
                or evidence.registry_generation != target.authority.registry_generation
                or evidence.policy_generation != target.authority.policy.generation
                or evidence.authority_generation != target.authority.authority_generation
                or evidence.lease_generation != target.authority.lease_generation
                or evidence.process_generation != target.authority.process_generation
                or evidence.observation_generation <= previous
                or evidence.observed_monotonic_ns > now
                or now - evidence.observed_monotonic_ns > 5_000_000_000
            ):
                raise FleetHomeV2CutoverError("fleet_home_v2_quiescence_invalid")
            self._observations[target.authority.agent_id] = evidence.observation_generation
        if not evidence.process_scan_available:
            raise FleetHomeV2CutoverError("fleet_home_v2_process_scan_unavailable")
        if (
            not evidence.stopped or evidence.lease_state not in {"none", "released"}
            or evidence.managed_processes != 0 or evidence.external_processes != 0
        ):
            raise FleetHomeV2CutoverError("fleet_home_v2_target_not_quiescent")

    def _require_operation_absent(self, parent_fd: int, names: Mapping[str, str]) -> None:
        for key, name in names.items():
            if key == "lock":
                continue
            if not self._filesystem._lstat_absent(parent_fd, name):
                if name == names["journal"]:
                    raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
                raise FleetHomeV2CutoverError("fleet_home_v2_cutover_collision")
        prefix = ".fleet-home-v2-cutover-"
        try:
            existing = os.listdir(parent_fd)
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid") from exc
        agent_id = names["lock"].removeprefix(prefix).removesuffix(".lock")
        for name in existing:
            if name.startswith(prefix) and f"-{agent_id}." in name and name not in names.values():
                raise FleetHomeV2CutoverError("fleet_home_v2_operation_active")

    def _acquire_home_lock(
        self,
        parent_fd: int,
        plan: FleetHomeV2Plan,
        target: FleetHomeV2TargetPlan,
        names: Mapping[str, str],
    ) -> None:
        document = {
            "schema_version": 2,
            "kind": "fleet_home_v2_cutover_lock",
            "operation_id": plan.operation_id,
            "plan_digest": plan.digest,
            "agent_id": target.authority.agent_id,
            "home_identity": self._identity_document(target.home_identity),
            "parent_identity": self._identity_document(target.parent_identity),
            "journal": names["journal"],
        }
        encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        try:
            self._filesystem.write_file_at(
                parent_fd,
                names["lock"],
                encoded,
                0o600,
                target.authority.owner_uid,
                target.authority.owner_gid,
            )
            self._filesystem.fsync_directory(parent_fd)
            return
        except FleetHomeV2CutoverError as exc:
            if exc.code != "fleet_home_v2_cutover_collision":
                raise
        try:
            identity = self._filesystem.identity_at(parent_fd, names["lock"])
            if (
                not stat.S_ISREG(identity.mode)
                or stat.S_IMODE(identity.mode) != 0o600
                or identity.uid != target.authority.owner_uid
                or identity.gid != target.authority.owner_gid
                or identity.nlink != 1
            ):
                raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
            lock_fd = os.open(
                names["lock"], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd
            )
            try:
                data = b"".join(iter(lambda: os.read(lock_fd, 64 * 1024), b""))
                if self._filesystem.identity_from_stat(os.fstat(lock_fd)) != identity:
                    raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
            finally:
                os.close(lock_fd)
            if json.loads(data.decode("utf-8")) == document:
                return
        except FleetHomeV2CutoverError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid") from exc
        raise FleetHomeV2CutoverError("fleet_home_v2_operation_active")

    def _release_home_lock(
        self,
        parent_fd: int,
        plan: FleetHomeV2Plan,
        target: FleetHomeV2TargetPlan,
        names: Mapping[str, str],
    ) -> None:
        self._acquire_home_lock(parent_fd, plan, target, names)
        self._filesystem.unlink_at(parent_fd, names["lock"])
        self._filesystem.fsync_directory(parent_fd)

    def _write_stage(self, stage_fd: int, authority: FleetHomeV2Authority) -> None:
        for artifact in self._artifact_map(authority).values():
            parent_fd = stage_fd
            opened: list[int] = []
            try:
                parts = PurePosixPath(artifact.relative_path).parts
                for part in parts[:-1]:
                    if self._filesystem._lstat_absent(parent_fd, part):
                        child_fd = self._filesystem.mkdir_private_at(parent_fd, part, authority.owner_uid, authority.owner_gid)
                    else:
                        child_fd = self._filesystem._open_dir_at(parent_fd, part)
                        if not self._filesystem._private_directory(self._filesystem.parent_identity(child_fd), authority.owner_uid, authority.owner_gid):
                            os.close(child_fd)
                            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
                    opened.append(child_fd)
                    parent_fd = child_fd
                self._filesystem.write_file_at(parent_fd, parts[-1], artifact.data, artifact.mode, authority.owner_uid, authority.owner_gid)
            finally:
                for fd in reversed(opened):
                    os.close(fd)

    def _artifact_map(self, authority: FleetHomeV2Authority) -> dict[str, FleetHomeV2Artifact]:
        artifacts: dict[str, FleetHomeV2Artifact] = {}
        for artifact in authority.artifacts:
            path = PurePosixPath(artifact.relative_path)
            if (
                not isinstance(artifact.data, bytes) or not artifact.relative_path or path.is_absolute()
                or path.as_posix() != artifact.relative_path or any(part in {"", ".", ".."} for part in path.parts)
                or artifact.mode not in {0o600, 0o700} or artifact.relative_path in artifacts
            ):
                raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
            artifacts[artifact.relative_path] = artifact
        marker = artifacts.get(MARKER_FILE)
        if marker is None or marker.mode != 0o600:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
        self._validate_marker(marker.data, authority, artifacts)
        return artifacts

    def _attest_tree_at(self, parent_fd: int, name: str, authority: FleetHomeV2Authority) -> bool:
        try:
            root_fd = self._filesystem._open_dir_at(parent_fd, name)
        except FleetHomeV2CutoverError:
            return False
        try:
            if not self._filesystem._private_directory(self._filesystem.parent_identity(root_fd), authority.owner_uid, authority.owner_gid):
                return False
            expected = self._artifact_map(authority)
            observed: dict[str, tuple[bytes, _FilesystemIdentity]] = {}
            observed_directories: set[str] = set()
            root_identity = self._filesystem.parent_identity(root_fd)
            root_mount_id = self._filesystem.mount_id(root_fd)
            self._attest_directory(
                root_fd,
                "",
                authority,
                observed,
                observed_directories,
                root_identity.device,
                root_mount_id,
            )
            expected_directories = {
                parent.as_posix()
                for artifact in expected
                if (parent := PurePosixPath(artifact).parent).as_posix() != "."
            }
            if set(observed) != set(expected) or observed_directories != expected_directories:
                return False
            for relative, artifact in expected.items():
                data, current = observed[relative]
                if (
                    data != artifact.data or not stat.S_ISREG(current.mode)
                    or stat.S_IMODE(current.mode) != artifact.mode or current.uid != authority.owner_uid
                    or current.gid != authority.owner_gid or current.nlink != 1 or current.size != len(artifact.data)
                ):
                    return False
            self._validate_marker(observed[MARKER_FILE][0], authority, expected)
            return True
        except FleetHomeV2CutoverError:
            return False
        finally:
            os.close(root_fd)

    def _attest_directory(
        self,
        directory_fd: int,
        prefix: str,
        authority: FleetHomeV2Authority,
        observed: dict[str, tuple[bytes, _FilesystemIdentity]],
        observed_directories: set[str],
        root_device: int,
        root_mount_id: int,
    ) -> None:
        try:
            names = os.listdir(directory_fd)
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed") from exc
        for name in names:
            relative = f"{prefix}/{name}" if prefix else name
            current = self._filesystem.identity_at(directory_fd, name)
            if current.device != root_device:
                raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed")
            if stat.S_ISDIR(current.mode):
                if not self._filesystem._private_directory(current, authority.owner_uid, authority.owner_gid):
                    raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed")
                child_fd = self._filesystem._open_dir_at(directory_fd, name)
                try:
                    if self._filesystem.mount_id(child_fd) != root_mount_id:
                        raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed")
                    observed_directories.add(relative)
                    self._attest_directory(
                        child_fd,
                        relative,
                        authority,
                        observed,
                        observed_directories,
                        root_device,
                        root_mount_id,
                    )
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(current.mode) or current.nlink != 1:
                raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed")
            file_fd = -1
            try:
                file_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
                chunks: list[bytes] = []
                while chunk := os.read(file_fd, 64 * 1024):
                    chunks.append(chunk)
                opened = self._filesystem.identity_from_stat(os.fstat(file_fd))
                if self._filesystem.mount_id(file_fd) != root_mount_id:
                    raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed")
            except OSError as exc:
                raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed") from exc
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
            if opened != current:
                raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed")
            observed[relative] = (b"".join(chunks), current)

    def _validate_marker(self, marker_bytes: bytes, authority: FleetHomeV2Authority, artifacts: Mapping[str, FleetHomeV2Artifact]) -> None:
        try:
            marker = json.loads(marker_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_marker_invalid") from exc
        expected_fields = _MARKER_FIELDS | ({_MARKER_RUNTIME_FIELD} if authority.runtime_skill_profile is not None else set())
        expected_files = {name: hashlib.sha256(item.data).hexdigest() for name, item in artifacts.items() if name != MARKER_FILE}
        policy = {"schema_version": authority.policy.schema_version, "generation": authority.policy.generation, "digest": authority.policy.digest}
        if (
            not isinstance(marker, dict) or set(marker) != expected_fields
            or marker.get("schema_version") != 2 or marker.get("kind") != "codex_master_fleet_agent"
            or marker.get("agent_id") != authority.agent_id or marker.get("prefix") != authority.prefix
            or marker.get("runner") != authority.runner or marker.get("provider") != authority.provider
            or marker.get("model") != authority.model or marker.get("common_policy") != policy
            or not isinstance(marker.get("common_policy"), dict) or set(marker["common_policy"]) != _POLICY_FIELDS
            or marker.get("managed_files") != sorted(expected_files) or marker.get("files") != expected_files
            or (authority.runtime_skill_profile is not None and marker.get(_MARKER_RUNTIME_FIELD) != authority.runtime_skill_profile)
        ):
            raise FleetHomeV2CutoverError("fleet_home_v2_marker_invalid")

    def _manifest_digest(self, authority: FleetHomeV2Authority) -> str:
        artifacts = self._artifact_map(authority)
        return self._digest(
            {
                "agent_id": authority.agent_id, "prefix": authority.prefix, "provider": authority.provider,
                "runner": authority.runner, "model": authority.model, "registry_generation": authority.registry_generation,
                "policy": asdict(authority.policy), "authority_generation": authority.authority_generation,
                "lease_generation": authority.lease_generation, "process_generation": authority.process_generation,
                "artifacts": [(name, hashlib.sha256(item.data).hexdigest(), item.mode) for name, item in sorted(artifacts.items())],
            }
        )

    def _plan_digest(self, operation_id: str, generation: int, targets: tuple[FleetHomeV2TargetPlan, ...]) -> str:
        return self._digest(
            {
                "operation_id": operation_id, "registry_generation": generation,
                "targets": [
                    {
                        "agent_id": target.authority.agent_id,
                        "authority": self._authority_document(target.authority),
                        "home_identity": self._identity_document(target.home_identity),
                        "parent_identity": self._identity_document(target.parent_identity),
                        "manifest_digest": target.manifest_digest, "already_current": target.already_current,
                    }
                    for target in targets
                ],
            }
        )

    def _names(self, plan: FleetHomeV2Plan, target: FleetHomeV2TargetPlan) -> dict[str, str]:
        stem = f".fleet-home-v2-cutover-{plan.operation_id}-{target.authority.agent_id}"
        return {
            "stage": f"{stem}.stage",
            "backup": f"{stem}.backup",
            "archive": f"{stem}.rollback-v2",
            "journal": f"{stem}.journal.json",
            "lock": f".fleet-home-v2-cutover-{target.authority.agent_id}.lock",
        }

    def _new_journal(self, plan: FleetHomeV2Plan, target: FleetHomeV2TargetPlan, names: Mapping[str, str]) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": 2, "kind": "fleet_home_v2_cutover_journal", "operation_id": plan.operation_id,
            "plan_digest": plan.digest, "agent_id": target.authority.agent_id,
            "registry_generation": target.authority.registry_generation, "policy_generation": target.authority.policy.generation,
            "authority_generation": target.authority.authority_generation, "lease_generation": target.authority.lease_generation,
            "process_generation": target.authority.process_generation, "manifest_digest": target.manifest_digest,
            "home_identity": self._identity_document(target.home_identity), "parent_identity": self._identity_document(target.parent_identity),
            "stage": names["stage"], "backup": names["backup"], "archive": names["archive"], "v2_identity": None, "history": [],
        }
        return self._append_journal_state(document, "planned")

    def _load_journal(self, parent_fd: int, plan: FleetHomeV2Plan, target: FleetHomeV2TargetPlan) -> dict[str, object]:
        names = self._names(plan, target)
        try:
            identity = self._filesystem.identity_at(parent_fd, names["journal"])
            if (
                not stat.S_ISREG(identity.mode) or stat.S_IMODE(identity.mode) != 0o600
                or identity.uid != target.authority.owner_uid or identity.gid != target.authority.owner_gid or identity.nlink != 1
            ):
                raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
            file_fd = os.open(names["journal"], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            try:
                data = b"".join(iter(lambda: os.read(file_fd, 64 * 1024), b""))
                if self._filesystem.identity_from_stat(os.fstat(file_fd)) != identity:
                    raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
            finally:
                os.close(file_fd)
            document = json.loads(data.decode("utf-8"))
        except FleetHomeV2CutoverError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid") from exc
        self._validate_journal(document, plan, target, names)
        return document

    def _validate_journal(self, document: object, plan: FleetHomeV2Plan, target: FleetHomeV2TargetPlan, names: Mapping[str, str]) -> None:
        fields = {
            "schema_version", "kind", "operation_id", "plan_digest", "agent_id", "registry_generation", "policy_generation",
            "authority_generation", "lease_generation", "process_generation", "manifest_digest", "home_identity", "parent_identity",
            "stage", "backup", "archive", "v2_identity", "history",
        }
        if not isinstance(document, dict) or set(document) != fields:
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        expected = self._new_journal(plan, target, names)
        for field in set(expected) - {"history", "v2_identity"}:
            if document.get(field) != expected[field]:
                raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        if document.get("v2_identity") is not None:
            self._identity_from_document(document["v2_identity"])
        history = document.get("history")
        if not isinstance(history, list) or not history:
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        binding = self._digest(
            {
                field: value
                for field, value in document.items()
                if field not in {"history", "v2_identity"}
            }
        )
        previous = binding
        previous_state: str | None = None
        for generation, entry in enumerate(history):
            if not isinstance(entry, dict) or set(entry) != {
                "generation", "state", "previous_digest", "identities", "digest"
            }:
                raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
            state = entry.get("state")
            try:
                identities = self._journal_identities(document, state)
            except FleetHomeV2CutoverError:
                raise
            if (
                type(entry.get("generation")) is not int or entry["generation"] != generation or state not in _JOURNAL_STATES
                or entry.get("previous_digest") != previous
                or entry.get("identities") != identities
                or entry.get("digest") != self._digest(
                    {
                        "binding": binding,
                        "generation": generation,
                        "state": state,
                        "previous_digest": previous,
                        "identities": identities,
                    }
                )
                or (previous_state is not None and _JOURNAL_STATES.index(state) != _JOURNAL_STATES.index(previous_state) + 1)
            ):
                raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
            previous, previous_state = entry["digest"], state
        if (
            history[0].get("state") != "planned"
            or (previous_state == "planned" and document.get("v2_identity") is not None)
            or (previous_state != "planned" and document.get("v2_identity") is None)
        ):
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")

    def _advance_journal(self, document: dict[str, object], state: str, v2_identity: _FilesystemIdentity) -> dict[str, object]:
        current = self._journal_state(document)
        if current == state:
            return document
        if _JOURNAL_STATES.index(state) != _JOURNAL_STATES.index(current) + 1:
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        clone = dict(document)
        clone["v2_identity"] = self._identity_document(v2_identity)
        clone["history"] = list(document["history"])
        return self._append_journal_state(clone, state)

    def _advance_until(self, parent_fd: int, journal_name: str, document: dict[str, object], state: str, v2_identity: _FilesystemIdentity) -> dict[str, object]:
        while self._journal_state(document) != state:
            next_state = _JOURNAL_STATES[_JOURNAL_STATES.index(self._journal_state(document)) + 1]
            document = self._advance_journal(document, next_state, v2_identity)
            self._store_journal(parent_fd, journal_name, document, self._filesystem.identity_at(parent_fd, journal_name))
        return document

    def _append_journal_state(self, document: dict[str, object], state: str) -> dict[str, object]:
        history = list(document["history"])
        binding = self._digest(
            {
                field: value
                for field, value in document.items()
                if field not in {"history", "v2_identity"}
            }
        )
        previous = history[-1]["digest"] if history else binding
        generation = len(history)
        identities = self._journal_identities(document, state)
        history.append(
            {
                "generation": generation,
                "state": state,
                "previous_digest": previous,
                "identities": identities,
                "digest": self._digest(
                    {
                        "binding": binding,
                        "generation": generation,
                        "state": state,
                        "previous_digest": previous,
                        "identities": identities,
                    }
                ),
            }
        )
        document["history"] = history
        return document

    def _journal_identities(self, document: Mapping[str, object], state: object) -> dict[str, object]:
        if state not in _JOURNAL_STATES:
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        home = document.get("home_identity")
        if not isinstance(home, dict):
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        self._identity_from_document(home)
        v2 = document.get("v2_identity")
        if state == "planned":
            return {"active": home, "stage": None, "backup": None, "archive": None, "v2": None}
        if v2 is None:
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        self._identity_from_document(v2)
        if state == "staged":
            return {"active": home, "stage": v2, "backup": None, "archive": None, "v2": v2}
        if state == "exchanged":
            return {"active": v2, "stage": home, "backup": None, "archive": None, "v2": v2}
        if state in {"backup-bound", "cutover-complete"}:
            return {"active": v2, "stage": None, "backup": home, "archive": None, "v2": v2}
        if state == "rollback-exchanged":
            return {"active": home, "stage": None, "backup": v2, "archive": None, "v2": v2}
        return {"active": home, "stage": None, "backup": None, "archive": v2, "v2": v2}

    def _store_journal(self, parent_fd: int, journal_name: str, document: dict[str, object], previous_identity: _FilesystemIdentity | None) -> None:
        encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = f".{journal_name}.{self._entropy.token_hex(16)}.tmp"
        if not self._filesystem._lstat_absent(parent_fd, temporary):
            raise FleetHomeV2CutoverError("fleet_home_v2_operation_collision")
        home_document = document["home_identity"]
        if not isinstance(home_document, dict):
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        self._filesystem.write_file_at(parent_fd, temporary, encoded, 0o600, int(home_document["uid"]), int(home_document["gid"]))
        if previous_identity is None:
            self._filesystem.rename_noreplace_at(parent_fd, temporary, journal_name)
        else:
            self._filesystem.exchange_at(parent_fd, temporary, journal_name)
            if self._filesystem.identity_at(parent_fd, temporary) != previous_identity:
                raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
            self._filesystem.unlink_at(parent_fd, temporary)
        self._filesystem.fsync_directory(parent_fd)

    def _journal_state(self, document: Mapping[str, object]) -> str:
        history = document["history"]
        if not isinstance(history, list) or not history or not isinstance(history[-1], dict):
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        state = history[-1].get("state")
        if state not in _JOURNAL_STATES:
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        return state

    def _journal_v2_identity(self, document: Mapping[str, object]) -> _FilesystemIdentity:
        value = document.get("v2_identity")
        if value is None:
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
        return self._identity_from_document(value)

    def _require_v2_and_backup(self, parent_fd: int, target: FleetHomeV2TargetPlan, journal: Mapping[str, object]) -> None:
        v2_identity = self._journal_v2_identity(journal)
        if self._filesystem.identity_at(parent_fd, target.authority.home.name) != v2_identity:
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
        if self._filesystem.identity_at(parent_fd, str(journal["backup"])) != target.home_identity:
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
        if not self._attest_tree_at(parent_fd, target.authority.home.name, target.authority):
            raise FleetHomeV2CutoverError("fleet_home_v2_marker_invalid")

    def _require_current_v2(self, target: FleetHomeV2TargetPlan) -> None:
        parent_fd = self._open_bound_parent(target)
        try:
            if self._filesystem.identity_at(parent_fd, target.authority.home.name) != target.home_identity or not self._attest_tree_at(parent_fd, target.authority.home.name, target.authority):
                raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid")
        finally:
            os.close(parent_fd)

    def _restore_exchange_if_bound(self, parent_fd: int, target: FleetHomeV2TargetPlan, names: Mapping[str, str], v2_identity: _FilesystemIdentity) -> bool:
        if (
            self._optional_identity(parent_fd, target.authority.home.name) == v2_identity
            and self._optional_identity(parent_fd, names["stage"]) == target.home_identity
        ):
            self._filesystem.exchange_at(parent_fd, target.authority.home.name, names["stage"])
            self._filesystem.fsync_directory(parent_fd)
            return True
        return False

    def _optional_identity(self, parent_fd: int, name: str) -> _FilesystemIdentity | None:
        try:
            return self._filesystem.identity_from_stat(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required") from exc

    def _mutation_possible(
        self, parent_fd: int, target: FleetHomeV2TargetPlan, names: Mapping[str, str]
    ) -> bool:
        try:
            home = self._optional_identity(parent_fd, target.authority.home.name)
            return home != target.home_identity or any(
                self._optional_identity(parent_fd, names[key]) is not None
                for key in ("stage", "backup", "archive")
            )
        except FleetHomeV2CutoverError:
            return True

    @staticmethod
    def _identity_document(value: _FilesystemIdentity) -> dict[str, int]:
        return {"device": value.device, "inode": value.inode, "mode": value.mode, "uid": value.uid, "gid": value.gid, "nlink": value.nlink, "size": value.size, "mtime_ns": value.mtime_ns}

    @staticmethod
    def _identity_from_document(value: object) -> _FilesystemIdentity:
        fields = {"device", "inode", "mode", "uid", "gid", "nlink", "size", "mtime_ns"}
        if not isinstance(value, dict) or set(value) != fields or any(type(value[field]) is not int for field in fields):
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        return _FilesystemIdentity(**value)

    @staticmethod
    def _authority_document(value: FleetHomeV2Authority) -> dict[str, object]:
        return {
            "agent_id": value.agent_id, "prefix": value.prefix, "provider": value.provider, "runner": value.runner,
            "model": value.model, "home": str(value.home), "registry_generation": value.registry_generation,
            "policy": asdict(value.policy), "owner_uid": value.owner_uid, "owner_gid": value.owner_gid,
            "authority_generation": value.authority_generation, "lease_generation": value.lease_generation,
            "process_generation": value.process_generation, "runtime_skill_profile": value.runtime_skill_profile,
        }

    @staticmethod
    def _digest(value: object) -> str:
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @staticmethod
    def _recovery_code(code: str) -> str:
        return "fleet_home_v2_recovery_required" if code != "fleet_home_v2_journal_invalid" else code

    @staticmethod
    def _result_for_error(agent_id: str, code: str) -> FleetHomeV2Result:
        if code in {
            "fleet_home_v2_journal_invalid", "fleet_home_v2_marker_invalid", "fleet_home_v2_artifact_attestation_failed",
            "fleet_home_v2_stage_invalid", "fleet_home_v2_source_invalid", "fleet_home_v2_plan_invalid",
            "fleet_home_v2_exchange_unavailable", "fleet_home_v2_operation_collision",
            "fleet_home_v2_operation_active",
        }:
            return FleetHomeV2Result(agent_id, "failed-terminal", code)
        if code == "fleet_home_v2_recovery_required":
            return FleetHomeV2Result(agent_id, "recovery-required", code)
        return FleetHomeV2Result(agent_id, "failed-retryable", code)
