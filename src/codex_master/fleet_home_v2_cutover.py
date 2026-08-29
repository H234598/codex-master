"""Offline, one-way rebuild of one Fleet home into a Marker V2 home.

This module never discovers authority from an existing home.  Callers provide
the registry/policy snapshot and explicit filesystem and quiescence ports.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from pathlib import PurePosixPath


MARKER_FILE = ".codex-fleet-agent.json"
MAX_TARGETS = 27
_OPERATION_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{15,95}\Z")
_JOURNAL_GENERATIONS = {
    "planned": 0,
    "staged": 1,
    "old-moved": 2,
    "cutover-complete": 3,
    "failed-retryable": 4,
    "rolled-back": 4,
}


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
    provider: str
    runner: str
    home: Path
    registry_generation: int
    policy: FleetHomeV2Policy
    owner_uid: int
    owner_gid: int
    artifacts: tuple[FleetHomeV2Artifact, ...]


@dataclass(frozen=True, slots=True)
class FleetHomeV2Inventory:
    generation: int
    homes: Mapping[str, FleetHomeV2Authority]


@dataclass(frozen=True, slots=True)
class FleetHomeV2Quiescence:
    stopped: bool
    lease_state: str
    process_scan_available: bool
    managed_processes: int
    external_processes: int


@dataclass(frozen=True, slots=True)
class _FilesystemIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int


class LocalFleetHomeV2Filesystem:
    """Explicit local filesystem port for offline tests and controlled callers."""

    def canonical(self, path: Path) -> Path:
        try:
            return path.resolve(strict=True)
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid") from exc

    def identity(self, path: Path) -> _FilesystemIdentity:
        try:
            value = path.lstat()
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid") from exc
        return _FilesystemIdentity(
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
        )

    @staticmethod
    def exists(path: Path) -> bool:
        return path.exists() or path.is_symlink()

    @staticmethod
    def is_symlink(path: Path) -> bool:
        return path.is_symlink()

    def is_directory(self, path: Path) -> bool:
        return stat.S_ISDIR(self.identity(path).mode)

    def make_private_directory(self, path: Path) -> None:
        try:
            path.mkdir(mode=0o700)
            os.chmod(path, 0o700)
            self.fsync_directory(path.parent)
        except FileExistsError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_cutover_collision") from exc
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc

    def write_private(self, path: Path, data: bytes, mode: int, uid: int, gid: int) -> None:
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.parent.chmod(0o700)
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                mode,
            )
            try:
                offset = 0
                while offset < len(data):
                    written = os.write(descriptor, data[offset:])
                    if written <= 0:
                        raise OSError("short write")
                    offset += written
                os.fchmod(descriptor, mode)
                os.fchown(descriptor, uid, gid)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except FileExistsError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_cutover_collision") from exc
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc

    def read(self, path: Path) -> bytes:
        try:
            return path.read_bytes()
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc

    def entries(self, path: Path) -> tuple[Path, ...]:
        try:
            return tuple(path.iterdir())
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc

    def rename(self, source: Path, target: Path) -> None:
        try:
            if target.exists() or target.is_symlink():
                raise FleetHomeV2CutoverError("fleet_home_v2_cutover_collision")
            source.rename(target)
            self.fsync_directory(target.parent)
        except FleetHomeV2CutoverError:
            raise
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_cutover_failed") from exc

    def replace_atomic(self, source: Path, target: Path) -> None:
        os.replace(source, target)
        self.fsync_directory(target.parent)

    def fsync_directory(self, path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc

    def checkpoint(self, _point: str) -> None:
        """Fault-injection port; local execution has no injected crash."""


@dataclass(frozen=True, slots=True)
class FleetHomeV2TargetPlan:
    authority: FleetHomeV2Authority
    home_identity: _FilesystemIdentity
    parent_identity: _FilesystemIdentity
    already_current: bool


@dataclass(frozen=True, slots=True)
class FleetHomeV2Plan:
    operation_id: str
    registry_generation: int
    targets: tuple[FleetHomeV2TargetPlan, ...]


@dataclass(frozen=True, slots=True)
class FleetHomeV2Result:
    agent_id: str
    state: str
    code: str | None = None


class FleetHomeV2CutoverService:
    def __init__(
        self,
        *,
        inventory: Callable[[], FleetHomeV2Inventory],
        filesystem: LocalFleetHomeV2Filesystem,
        quiescence: Callable[[FleetHomeV2Authority], FleetHomeV2Quiescence],
        attest_current: Callable[[FleetHomeV2Authority], bool],
    ) -> None:
        self._inventory = inventory
        self._filesystem = filesystem
        self._quiescence = quiescence
        self._attest_current = attest_current

    def plan(
        self, target_ids: tuple[str, ...], *, operation_id: str
    ) -> FleetHomeV2Plan:
        if not _OPERATION_ID_RE.fullmatch(operation_id):
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        if not target_ids or len(target_ids) > MAX_TARGETS:
            raise FleetHomeV2CutoverError("fleet_home_v2_batch_limit")
        if len(set(target_ids)) != len(target_ids):
            raise FleetHomeV2CutoverError("fleet_home_v2_inventory_changed")
        snapshot = self._inventory()
        if type(snapshot.generation) is not int or snapshot.generation <= 0:
            raise FleetHomeV2CutoverError("fleet_home_v2_inventory_changed")
        try:
            authorities = [snapshot.homes[agent_id] for agent_id in target_ids]
        except KeyError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_inventory_changed") from exc
        authorities.sort(key=lambda authority: (authority.agent_id != "g1", authority.agent_id))
        targets: list[FleetHomeV2TargetPlan] = []
        for authority in authorities:
            if (
                authority.agent_id not in snapshot.homes
                or snapshot.homes[authority.agent_id] != authority
                or authority.registry_generation != snapshot.generation
            ):
                raise FleetHomeV2CutoverError("fleet_home_v2_inventory_changed")
            artifacts = self._artifact_map(authority)
            self._attest_marker(artifacts[MARKER_FILE].data, authority, artifacts)
            home = self._filesystem.canonical(authority.home)
            if home != authority.home or not self._filesystem.is_directory(home):
                raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid")
            parent = self._filesystem.canonical(home.parent)
            targets.append(
                FleetHomeV2TargetPlan(
                    authority,
                    self._filesystem.identity(home),
                    self._filesystem.identity(parent),
                    self._attest_current(authority),
                )
            )
        return FleetHomeV2Plan(operation_id, snapshot.generation, tuple(targets))

    def apply(self, plan: FleetHomeV2Plan) -> tuple[FleetHomeV2Result, ...]:
        self._validate_plan(plan)
        results: list[FleetHomeV2Result] = []
        for target in plan.targets:
            try:
                if target.already_current:
                    self._revalidate_target(target)
                    if not self._attest_current(target.authority):
                        raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid")
                    results.append(
                        FleetHomeV2Result(
                            target.authority.agent_id,
                            "already-current",
                            "fleet_home_v2_already_current",
                        )
                    )
                    continue
                results.append(self._apply_target(plan, target))
            except FleetHomeV2CutoverError as exc:
                state = (
                    "recovery-required"
                    if exc.code == "fleet_home_v2_recovery_required"
                    else "failed-retryable"
                )
                results.append(FleetHomeV2Result(target.authority.agent_id, state, exc.code))
        return tuple(results)

    def recover(self, plan: FleetHomeV2Plan) -> tuple[FleetHomeV2Result, ...]:
        self._validate_plan(plan)
        results: list[FleetHomeV2Result] = []
        for target in plan.targets:
            try:
                results.append(self._recover_target(plan, target))
            except FleetHomeV2CutoverError as exc:
                results.append(
                    FleetHomeV2Result(
                        target.authority.agent_id,
                        "recovery-required",
                        exc.code,
                    )
                )
        return tuple(results)

    def rollback(self, plan: FleetHomeV2Plan) -> tuple[FleetHomeV2Result, ...]:
        self._validate_plan(plan)
        results: list[FleetHomeV2Result] = []
        for target in plan.targets:
            try:
                results.append(self._rollback_target(plan, target))
            except FleetHomeV2CutoverError as exc:
                results.append(
                    FleetHomeV2Result(
                        target.authority.agent_id,
                        "recovery-required",
                        exc.code,
                    )
                )
        return tuple(results)

    def verify(self, plan: FleetHomeV2Plan) -> tuple[FleetHomeV2Result, ...]:
        self._validate_plan(plan)
        results: list[FleetHomeV2Result] = []
        for target in plan.targets:
            authority = target.authority
            parent = authority.home.parent
            stage = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.stage"
            backup = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.backup"
            journal = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.json"
            try:
                if self._load_journal(journal, plan, target, stage, backup) != "cutover-complete":
                    raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
                if (
                    self._path_exists(stage)
                    or not self._path_exists(backup)
                    or self._filesystem.identity(backup) != target.home_identity
                    or not self._same_parent(
                        self._filesystem.identity(parent), target.parent_identity
                    )
                ):
                    raise FleetHomeV2CutoverError("fleet_home_v2_mixed_generation")
                self._attest_stage(authority.home, authority, parent)
            except FleetHomeV2CutoverError as exc:
                results.append(FleetHomeV2Result(authority.agent_id, "failed-terminal", exc.code))
            else:
                results.append(FleetHomeV2Result(authority.agent_id, "cutover-complete"))
        return tuple(results)

    def _validate_plan(self, plan: FleetHomeV2Plan) -> None:
        if (
            not isinstance(plan, FleetHomeV2Plan)
            or not _OPERATION_ID_RE.fullmatch(plan.operation_id)
            or not plan.targets
            or len(plan.targets) > MAX_TARGETS
        ):
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        snapshot = self._inventory()
        if snapshot.generation != plan.registry_generation:
            raise FleetHomeV2CutoverError("fleet_home_v2_generation_stale")
        for target in plan.targets:
            current = snapshot.homes.get(target.authority.agent_id)
            if current != target.authority:
                raise FleetHomeV2CutoverError("fleet_home_v2_generation_stale")

    def _apply_target(
        self, plan: FleetHomeV2Plan, target: FleetHomeV2TargetPlan
    ) -> FleetHomeV2Result:
        authority = target.authority
        home = authority.home
        parent = home.parent
        stage = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.stage"
        backup = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.backup"
        journal = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.json"
        self._revalidate_target(target)
        self._require_quiescent(authority)
        self._require_absent(stage, backup, journal)
        self._store_journal(journal, plan, target, "planned", stage, backup)
        self._filesystem.checkpoint("after-journal-planned")
        self._filesystem.make_private_directory(stage)
        self._write_stage(stage, authority)
        self._attest_stage(stage, authority, parent)
        self._filesystem.fsync_directory(stage)
        self._store_journal(journal, plan, target, "staged", stage, backup)
        self._filesystem.checkpoint("after-stage-fsync")
        self._revalidate_target(target)
        self._require_quiescent(authority)
        self._attest_stage(stage, authority, parent)
        try:
            self._filesystem.rename(home, backup)
        except FleetHomeV2CutoverError:
            self._store_journal(journal, plan, target, "failed-retryable", stage, backup)
            raise
        self._filesystem.checkpoint("after-old-to-backup")
        try:
            self._store_journal(journal, plan, target, "old-moved", stage, backup)
        except FleetHomeV2CutoverError:
            self._restore_backup(home, backup)
            raise
        try:
            self._filesystem.rename(stage, home)
            self._filesystem.checkpoint("after-stage-to-home")
            self._attest_stage(home, authority, parent)
            self._filesystem.checkpoint("after-v2-verify")
        except FleetHomeV2CutoverError as exc:
            self._restore_backup(home, backup)
            self._store_journal(journal, plan, target, "failed-retryable", stage, backup)
            raise exc
        self._store_journal(journal, plan, target, "cutover-complete", stage, backup)
        return FleetHomeV2Result(authority.agent_id, "cutover-complete")

    def _recover_target(
        self, plan: FleetHomeV2Plan, target: FleetHomeV2TargetPlan
    ) -> FleetHomeV2Result:
        authority = target.authority
        home = authority.home
        parent = home.parent
        stage = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.stage"
        backup = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.backup"
        journal = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.json"
        journal_state = self._load_journal(journal, plan, target, stage, backup)
        if not self._same_parent(self._filesystem.identity(parent), target.parent_identity):
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
        home_exists = self._path_exists(home)
        stage_exists = self._path_exists(stage)
        backup_exists = self._path_exists(backup)
        if not backup_exists:
            if (
                home_exists
                and self._filesystem.identity(home) == target.home_identity
                and journal_state in {"planned", "staged", "failed-retryable"}
            ):
                self._store_journal(
                    journal, plan, target, "failed-retryable", stage, backup
                )
                return FleetHomeV2Result(
                    authority.agent_id,
                    "failed-retryable",
                    "fleet_home_v2_cutover_failed",
                )
            if home_exists and not stage_exists:
                self._attest_stage(home, authority, parent)
                self._store_journal(
                    journal, plan, target, "cutover-complete", stage, backup
                )
                return FleetHomeV2Result(authority.agent_id, "cutover-complete")
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
        if self._filesystem.identity(backup) != target.home_identity:
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
        if not home_exists and stage_exists:
            self._require_quiescent(authority)
            self._attest_stage(stage, authority, parent)
            self._filesystem.rename(stage, home)
            self._attest_stage(home, authority, parent)
            self._store_journal(journal, plan, target, "cutover-complete", stage, backup)
            return FleetHomeV2Result(authority.agent_id, "cutover-complete")
        if not home_exists and not stage_exists:
            self._require_quiescent(authority)
            self._filesystem.rename(backup, home)
            self._store_journal(journal, plan, target, "rolled-back", stage, backup)
            return FleetHomeV2Result(authority.agent_id, "rolled-back")
        if home_exists and not stage_exists:
            self._attest_stage(home, authority, parent)
            self._store_journal(journal, plan, target, "cutover-complete", stage, backup)
            return FleetHomeV2Result(authority.agent_id, "cutover-complete")
        raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")

    def _rollback_target(
        self, plan: FleetHomeV2Plan, target: FleetHomeV2TargetPlan
    ) -> FleetHomeV2Result:
        authority = target.authority
        home = authority.home
        parent = home.parent
        stage = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.stage"
        backup = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.backup"
        journal = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.json"
        archive = parent / f".fleet-home-v2-cutover-{plan.operation_id}-{authority.agent_id}.rollback-v2"
        state = self._load_journal(journal, plan, target, stage, backup)
        if state != "cutover-complete" or self._filesystem.exists(stage):
            raise FleetHomeV2CutoverError("fleet_home_v2_rollback_failed")
        if (
            not self._path_exists(home)
            or not self._path_exists(backup)
            or self._path_exists(archive)
            or self._filesystem.identity(backup) != target.home_identity
            or not self._same_parent(
                self._filesystem.identity(parent), target.parent_identity
            )
        ):
            raise FleetHomeV2CutoverError("fleet_home_v2_rollback_failed")
        self._require_quiescent(authority)
        self._attest_stage(home, authority, parent)
        try:
            self._filesystem.rename(home, archive)
            self._filesystem.checkpoint("after-rollback-v2-archive")
            self._filesystem.rename(backup, home)
        except FleetHomeV2CutoverError as exc:
            if not self._path_exists(home) and self._path_exists(archive):
                try:
                    self._filesystem.rename(archive, home)
                except FleetHomeV2CutoverError:
                    raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required") from exc
            raise FleetHomeV2CutoverError("fleet_home_v2_rollback_failed") from exc
        self._store_journal(journal, plan, target, "rolled-back", stage, backup)
        return FleetHomeV2Result(authority.agent_id, "rolled-back")

    def _revalidate_target(self, target: FleetHomeV2TargetPlan) -> None:
        authority = target.authority
        home = authority.home
        if (
            self._filesystem.canonical(home) != home
            or self._filesystem.identity(home) != target.home_identity
            or not self._same_parent(
                self._filesystem.identity(home.parent), target.parent_identity
            )
        ):
            raise FleetHomeV2CutoverError("fleet_home_v2_source_invalid")

    @staticmethod
    def _same_parent(
        current: _FilesystemIdentity, expected: _FilesystemIdentity
    ) -> bool:
        return (
            current.device,
            current.inode,
            current.mode,
            current.uid,
            current.gid,
        ) == (
            expected.device,
            expected.inode,
            expected.mode,
            expected.uid,
            expected.gid,
        )

    def _require_quiescent(self, authority: FleetHomeV2Authority) -> None:
        evidence = self._quiescence(authority)
        if not evidence.process_scan_available:
            raise FleetHomeV2CutoverError("fleet_home_v2_process_scan_unavailable")
        if (
            not evidence.stopped
            or evidence.lease_state not in {"none", "released"}
            or evidence.managed_processes != 0
            or evidence.external_processes != 0
        ):
            raise FleetHomeV2CutoverError("fleet_home_v2_target_not_quiescent")

    def _require_absent(self, *paths: Path) -> None:
        for path in paths:
            if self._filesystem.exists(path):
                raise FleetHomeV2CutoverError("fleet_home_v2_cutover_collision")

    def _path_exists(self, path: Path) -> bool:
        return self._filesystem.exists(path)

    def _write_stage(self, stage: Path, authority: FleetHomeV2Authority) -> None:
        artifacts = self._artifact_map(authority)
        for name, artifact in artifacts.items():
            path = stage.joinpath(*PurePosixPath(name).parts)
            self._filesystem.write_private(
                path,
                artifact.data,
                artifact.mode,
                authority.owner_uid,
                authority.owner_gid,
            )

    def _artifact_map(
        self, authority: FleetHomeV2Authority
    ) -> dict[str, FleetHomeV2Artifact]:
        artifacts: dict[str, FleetHomeV2Artifact] = {}
        for artifact in authority.artifacts:
            path = PurePosixPath(artifact.relative_path)
            if (
                not artifact.relative_path
                or path.is_absolute()
                or any(part in {"", ".", ".."} for part in path.parts)
                or artifact.relative_path != path.as_posix()
                or artifact.mode & ~0o777
                or artifact.mode & 0o022
                or not isinstance(artifact.data, bytes)
                or artifact.relative_path in artifacts
            ):
                raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
            artifacts[artifact.relative_path] = artifact
        if MARKER_FILE not in artifacts:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
        return artifacts

    def _attest_stage(
        self, stage: Path, authority: FleetHomeV2Authority, parent: Path
    ) -> None:
        if self._filesystem.identity(stage).device != self._filesystem.identity(parent).device:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
        expected = self._artifact_map(authority)
        actual: set[str] = set()
        self._attest_tree(stage, stage, expected, authority, actual)
        if actual != set(expected):
            raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed")
        self._attest_marker(expected[MARKER_FILE].data, authority, expected)

    def _attest_tree(
        self,
        root: Path,
        current: Path,
        expected: Mapping[str, FleetHomeV2Artifact],
        authority: FleetHomeV2Authority,
        actual: set[str],
    ) -> None:
        for entry in self._filesystem.entries(current):
            relative = entry.relative_to(root).as_posix()
            identity = self._filesystem.identity(entry)
            if stat.S_ISLNK(identity.mode):
                raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed")
            if stat.S_ISDIR(identity.mode):
                if (
                    not any(name.startswith(f"{relative}/") for name in expected)
                    or (
                    stat.S_IMODE(identity.mode) != 0o700
                    or identity.uid != authority.owner_uid
                    or identity.gid != authority.owner_gid
                    )
                ):
                    raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed")
                self._attest_tree(root, entry, expected, authority, actual)
                continue
            artifact = expected.get(relative)
            if (
                artifact is None
                or not stat.S_ISREG(identity.mode)
                or stat.S_IMODE(identity.mode) != artifact.mode
                or identity.uid != authority.owner_uid
                or identity.gid != authority.owner_gid
                or identity.nlink != 1
                or identity.size != len(artifact.data)
                or self._filesystem.read(entry) != artifact.data
            ):
                raise FleetHomeV2CutoverError("fleet_home_v2_artifact_attestation_failed")
            actual.add(relative)

    def _attest_marker(
        self,
        marker_bytes: bytes,
        authority: FleetHomeV2Authority,
        artifacts: Mapping[str, FleetHomeV2Artifact],
    ) -> None:
        try:
            marker = json.loads(marker_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid") from exc
        expected_files = {
            name: hashlib.sha256(artifact.data).hexdigest()
            for name, artifact in artifacts.items()
            if name != MARKER_FILE
        }
        expected_policy = {
            "schema_version": authority.policy.schema_version,
            "generation": authority.policy.generation,
            "digest": authority.policy.digest,
        }
        if (
            not isinstance(marker, dict)
            or marker.get("schema_version") != 2
            or marker.get("agent_id") != authority.agent_id
            or marker.get("provider") != authority.provider
            or marker.get("runner") != authority.runner
            or marker.get("common_policy") != expected_policy
            or marker.get("files") != expected_files
            or marker.get("managed_files") != sorted(expected_files)
        ):
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")

    def _manifest_digest(self, authority: FleetHomeV2Authority) -> str:
        artifacts = self._artifact_map(authority)
        document = {
            "agent_id": authority.agent_id,
            "provider": authority.provider,
            "runner": authority.runner,
            "owner_uid": authority.owner_uid,
            "owner_gid": authority.owner_gid,
            "policy": asdict(authority.policy),
            "artifacts": [
                {
                    "path": name,
                    "digest": hashlib.sha256(artifact.data).hexdigest(),
                    "size": len(artifact.data),
                    "mode": artifact.mode,
                }
                for name, artifact in sorted(artifacts.items())
            ],
        }
        return hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def _store_journal(
        self,
        journal: Path,
        plan: FleetHomeV2Plan,
        target: FleetHomeV2TargetPlan,
        state: str,
        stage: Path,
        backup: Path,
    ) -> None:
        if self._filesystem.exists(journal):
            self._load_journal(journal, plan, target, stage, backup)
        document = {
            "schema_version": 2,
            "operation_id": plan.operation_id,
            "agent_id": target.authority.agent_id,
            "registry_generation": plan.registry_generation,
            "policy_generation": target.authority.policy.generation,
            "policy_digest": target.authority.policy.digest,
            "artifact_manifest_digest": self._manifest_digest(target.authority),
            "home_identity": asdict(target.home_identity),
            "parent_identity": asdict(target.parent_identity),
            "stage": stage.name,
            "backup": backup.name,
            "journal_generation": self._journal_generation(state),
            "state": state,
        }
        encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = journal.with_name(f".{journal.name}.tmp")
        self._filesystem.write_private(
            temporary,
            encoded,
            0o600,
            target.authority.owner_uid,
            target.authority.owner_gid,
        )
        try:
            if self._filesystem.is_symlink(journal):
                raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
            self._filesystem.replace_atomic(temporary, journal)
        except FleetHomeV2CutoverError:
            raise
        except OSError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid") from exc

    def _load_journal(
        self,
        journal: Path,
        plan: FleetHomeV2Plan,
        target: FleetHomeV2TargetPlan,
        stage: Path,
        backup: Path,
    ) -> str:
        try:
            identity = self._filesystem.identity(journal)
            if (
                not stat.S_ISREG(identity.mode)
                or stat.S_IMODE(identity.mode) != 0o600
                or identity.uid != target.authority.owner_uid
                or identity.gid != target.authority.owner_gid
                or identity.nlink != 1
            ):
                raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
            document = json.loads(self._filesystem.read(journal).decode("utf-8"))
        except FleetHomeV2CutoverError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid") from exc
        if not isinstance(document, dict):
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        state = document.get("state")
        expected = {
            "schema_version": 2,
            "operation_id": plan.operation_id,
            "agent_id": target.authority.agent_id,
            "registry_generation": plan.registry_generation,
            "policy_generation": target.authority.policy.generation,
            "policy_digest": target.authority.policy.digest,
            "artifact_manifest_digest": self._manifest_digest(target.authority),
            "home_identity": asdict(target.home_identity),
            "parent_identity": asdict(target.parent_identity),
            "stage": stage.name,
            "backup": backup.name,
            "journal_generation": self._journal_generation(state),
        }
        if (
            set(document) != {*expected, "state"}
            or any(document.get(key) != value for key, value in expected.items())
        ):
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        return state

    @staticmethod
    def _journal_generation(state: object) -> int:
        if not isinstance(state, str) or state not in _JOURNAL_GENERATIONS:
            raise FleetHomeV2CutoverError("fleet_home_v2_journal_invalid")
        return _JOURNAL_GENERATIONS[state]

    def _restore_backup(self, home: Path, backup: Path) -> None:
        if self._filesystem.exists(home):
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required")
        try:
            self._filesystem.rename(backup, home)
        except FleetHomeV2CutoverError as exc:
            raise FleetHomeV2CutoverError("fleet_home_v2_recovery_required") from exc
