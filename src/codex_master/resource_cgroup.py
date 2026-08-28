"""Cgroup profile, preflight, and G5 released-scope contracts."""

from __future__ import annotations

import math
from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import stat
import struct
import subprocess
import time
from typing import Protocol


GIB = 1024**3
MAX_CGROUP_READ_BYTES = 4096
MAX_CPU_INDEX = 4095
MAX_MEMORY_TOTAL_BYTES = (1 << 63) - 1
REQUIRED_CONTROLLERS = frozenset({"cpu", "cpuset", "memory", "pids", "io"})
CPU_PRESENT_PATH = Path("/sys/devices/system/cpu/present")
CPU_TOPOLOGY_ROOT = Path("/sys/devices/system/cpu")
CGROUP_ROOT = Path("/sys/fs/cgroup")
PROC_ROOT = Path("/proc")
SYSTEMD_RUN_PATH = "/usr/bin/systemd-run"
SYSTEMCTL_PATH = "/usr/bin/systemctl"
RESOURCE_SCOPE_GATE_PATH = "/usr/libexec/codex-master-resource-scope-gate"
CODEX_MASTER_SLICE = "codex-master.slice"
MAX_COMMAND_STDOUT_BYTES = 1024
MAX_COMMAND_STDERR_BYTES = 1024
COMMAND_TIMEOUT_SECONDS = 5.0
_COMMAND_KILL_WAIT_SECONDS = 1.0
_GATE_CHALLENGE_BYTES = 32
_GATE_COMMIT_BYTES = 16
_GATE_SESSION_ID_BYTES = 21
_GATE_READY_BYTES = len(b"READY ") + (_GATE_CHALLENGE_BYTES * 2) + 1
_GATE_RELEASE_BYTES = len(b"RELEASE ") + (_GATE_CHALLENGE_BYTES * 2) + 1
_GATE_ACK_BYTES = len(b"ACK ") + (_GATE_CHALLENGE_BYTES * 2) + 1 + (_GATE_COMMIT_BYTES * 2) + 1
_GATE_ATTEST_REQUEST_BYTES = (
    len(b"ATTEST ") + (_GATE_CHALLENGE_BYTES * 2) + 1 + (_GATE_COMMIT_BYTES * 2) + 1
)
_GATE_HANDOFF_MAX_BYTES = (
    len(b"HANDOFF ")
    + (_GATE_CHALLENGE_BYTES * 2)
    + 1
    + (_GATE_COMMIT_BYTES * 2)
    + 1
    + _GATE_SESSION_ID_BYTES
    + 1
    + 10
    + 1
    + 10
    + 1
)
_GATE_ATTEST_MAX_BYTES = (
    len(b"ATTEST ")
    + (_GATE_CHALLENGE_BYTES * 2)
    + 1
    + (_GATE_COMMIT_BYTES * 2)
    + 1
    + _GATE_SESSION_ID_BYTES
    + 1
    + 10
    + 1
    + 10
    + 1
)
_GATE_PROTOCOL_MAX_BYTES = max(_GATE_HANDOFF_MAX_BYTES, _GATE_ATTEST_MAX_BYTES)
_GATE_SOCKET_PREFIX = "\0codex-master-g5-"
_GATE_SOCKET_MAX_BYTES = 107
_UNSET_TARGET_SLICE_CONTROL_GROUP = object()
_CPU_SET_PART = re.compile(r"(?:0|[1-9][0-9]*)(?:-(?:[1-9][0-9]*))?")
_UNIT_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
_CHALLENGE = re.compile(r"^[a-f0-9]{64}$")
_COMMIT = re.compile(r"^[a-f0-9]{32}$")
_TMUX_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_TMUX_SESSION_ID = re.compile(r"^\$[0-9]{1,20}$")
_CGROUP_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")
_PSI_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")

CpuSet = tuple[int, ...]
APPROVED_CPUSET: CpuSet = tuple(range(4, 12))


class CgroupPreflightError(ValueError):
    """Raised for every fail-closed cgroup preflight violation."""


def _fail() -> None:
    raise CgroupPreflightError("cgroup_preflight_failed")


def _canonical_cpu_set(value: object, *, allow_empty: bool = False) -> CpuSet:
    if not isinstance(value, tuple) or (not allow_empty and not value):
        _fail()
    if any(type(cpu) is not int or not 0 <= cpu <= MAX_CPU_INDEX for cpu in value):
        _fail()
    if tuple(sorted(value)) != value or len(set(value)) != len(value):
        _fail()
    return value


def _format_cpu_set(cpus: CpuSet) -> str:
    ranges: list[str] = []
    start = end = cpus[0]
    for cpu in cpus[1:]:
        if cpu == end + 1:
            end = cpu
            continue
        ranges.append(str(start) if start == end else f"{start}-{end}")
        start = end = cpu
    ranges.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(ranges)


@dataclass(frozen=True, slots=True)
class CpuTopologyV1:
    physical_cores: tuple[CpuSet, ...]
    efficiency_cpus: CpuSet

    def __post_init__(self) -> None:
        if not isinstance(self.physical_cores, tuple) or len(self.physical_cores) > 256:
            _fail()
        normalized = tuple(_canonical_cpu_set(core) for core in self.physical_cores)
        all_cpus = tuple(cpu for core in normalized for cpu in core)
        if not all_cpus or len(set(all_cpus)) != len(all_cpus) or tuple(sorted(all_cpus)) != all_cpus:
            _fail()
        efficiency = _canonical_cpu_set(self.efficiency_cpus, allow_empty=True)
        if not set(efficiency).issubset(all_cpus):
            _fail()
        for core in normalized:
            if set(core) & set(efficiency) and not set(core).issubset(efficiency):
                _fail()
        object.__setattr__(self, "physical_cores", normalized)
        object.__setattr__(self, "efficiency_cpus", efficiency)


@dataclass(frozen=True, slots=True)
class CgroupProfileV1:
    cpuset_cpus: CpuSet
    cpu_quota_percent: int
    cpu_weight: int
    memory_high_bytes: int
    memory_max_bytes: int
    memory_swap_max_bytes: int
    io_weight: int

    def __post_init__(self) -> None:
        cpuset = _canonical_cpu_set(self.cpuset_cpus)
        values = (
            self.cpu_quota_percent,
            self.cpu_weight,
            self.memory_high_bytes,
            self.memory_max_bytes,
            self.memory_swap_max_bytes,
            self.io_weight,
        )
        if any(type(value) is not int for value in values):
            _fail()
        if (self.cpu_quota_percent, self.cpu_weight, self.io_weight) != (750, 50, 50):
            _fail()
        if not 0 < self.memory_high_bytes < self.memory_max_bytes <= MAX_MEMORY_TOTAL_BYTES:
            _fail()
        if self.memory_swap_max_bytes != 8 * GIB:
            _fail()
        object.__setattr__(self, "cpuset_cpus", cpuset)

    @property
    def cpuset_expression(self) -> str:
        return _format_cpu_set(self.cpuset_cpus)


@dataclass(frozen=True, slots=True)
class CgroupPreflightV1:
    unified_v2: bool
    controllers: frozenset[str]
    subtree_controllers: frozenset[str]
    parent_effective_cpuset: CpuSet
    io_physical_isolation_proven: bool

    def __post_init__(self) -> None:
        if self.unified_v2 is not True:
            _fail()
        if not isinstance(self.controllers, frozenset) or not isinstance(self.subtree_controllers, frozenset):
            _fail()
        if not REQUIRED_CONTROLLERS.issubset(self.controllers):
            _fail()
        if not REQUIRED_CONTROLLERS.issubset(self.subtree_controllers):
            _fail()
        if self.io_physical_isolation_proven is not False:
            _fail()
        object.__setattr__(self, "parent_effective_cpuset", _canonical_cpu_set(self.parent_effective_cpuset))


@dataclass(frozen=True, slots=True)
class PreparedAgentScope:
    unit_name: str
    socket_name: str
    session_name: str
    control_group: str
    gate_pid: int
    challenge: str

    def __post_init__(self) -> None:
        if not isinstance(self.unit_name, str) or not _UNIT_NAME.fullmatch(self.unit_name):
            _fail()
        _validate_tmux_name(self.socket_name)
        _validate_tmux_name(self.session_name)
        if type(self.gate_pid) is not int or self.gate_pid <= 0:
            _fail()
        if not isinstance(self.challenge, str) or not _CHALLENGE.fullmatch(self.challenge):
            _fail()
        control_group = _canonical_control_group(
            self.control_group if self.control_group.startswith("/") else f"/{self.control_group}"
        )
        if control_group.rsplit("/", 1)[-1] != self.unit_name:
            _fail()
        object.__setattr__(self, "control_group", control_group)


@dataclass(frozen=True, slots=True)
class RunnerExecutionTargetV1:
    owner_pid: int
    fd: int
    device: int
    inode: int

    def __post_init__(self) -> None:
        if (
            type(self.owner_pid) is not int
            or type(self.fd) is not int
            or type(self.device) is not int
            or type(self.inode) is not int
            or self.owner_pid != os.getpid()
            or self.fd <= 0
            or self.device <= 0
            or self.inode <= 0
        ):
            _fail()
        self._validate()

    def _validate(self) -> None:
        try:
            opened = os.fstat(self.fd)
            source_text = os.readlink(f"/proc/{self.owner_pid}/fd/{self.fd}")
            source_path = Path(source_text)
            source = os.stat(source_path, follow_symlinks=False)
        except (OSError, ValueError) as exc:
            raise CgroupPreflightError("cgroup_preflight_failed") from exc
        if (
            not source_path.is_absolute()
            or source_text.endswith(" (deleted)")
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not stat.S_ISREG(source.st_mode)
            or source.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (self.device, self.inode)
            or (source.st_dev, source.st_ino) != (self.device, self.inode)
        ):
            _fail()

    def verify_for_scope_start(self) -> None:
        self._validate()


@dataclass(frozen=True, slots=True)
class CommandResultV1:
    returncode: int
    stdout: bytes
    stderr: bytes

    def __post_init__(self) -> None:
        if type(self.returncode) is not int or type(self.stdout) is not bytes or type(self.stderr) is not bytes:
            _fail()


class SystemdUserCommandRunner(Protocol):
    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> CommandResultV1: ...

class CgroupSystemAdapter(Protocol):
    def read_bounded_cgroup_bytes(self, path: Path, *, max_bytes: int) -> bytes: ...

    def read_optional_cpu_topology_bytes(self, path: Path, *, max_bytes: int) -> bytes | None: ...

    def capture_cpu_topology_snapshot(self, cpus: CpuSet) -> object: ...

    def inspect_preflight(self) -> CgroupPreflightV1: ...

    def start_released_scope(
        self,
        *,
        profile: CgroupProfileV1,
        socket_name: str,
        session_name: str,
        runner_target: RunnerExecutionTargetV1,
    ) -> PreparedAgentScope: ...

    def verify_scope(self, scope: PreparedAgentScope, profile: CgroupProfileV1) -> None: ...

    def confirm_scope(self, scope: PreparedAgentScope) -> int: ...

    def cleanup_new_scope(self, scope: PreparedAgentScope) -> None: ...

    def read_hive_io_pressure(self) -> CgroupIoPressureEvidenceV1 | None: ...

    def clear_target_slice_control_group_cache(self) -> None: ...


@dataclass(frozen=True, slots=True)
class CgroupIoPressureEvidenceV1:
    some_avg10: float
    full_avg10: float
    full_avg60: float

    def __post_init__(self) -> None:
        for value in (self.some_avg10, self.full_avg10, self.full_avg60):
            if type(value) is bool or not isinstance(value, (float, int)) or not math.isfinite(
                value
            ):
                _fail()
            if value < 0.0 or value > 100.0:
                _fail()


@dataclass(frozen=True, slots=True)
class _BoundDirectory:
    path: Path
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _ProcessIdentity:
    pid: int
    start_ticks: int

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid <= 0 or type(self.start_ticks) is not int or self.start_ticks <= 0:
            _fail()


@dataclass(slots=True)
class _GateHandoff:
    commit: str
    session_id: str
    tmux_pid: int
    pane_pid: int
    connection: socket.socket | None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.commit, str)
            or not _COMMIT.fullmatch(self.commit)
            or not isinstance(self.session_id, str)
            or not _TMUX_SESSION_ID.fullmatch(self.session_id)
            or type(self.tmux_pid) is not int
            or self.tmux_pid <= 0
            or type(self.pane_pid) is not int
            or self.pane_pid <= 0
        ):
            _fail()


@dataclass(slots=True)
class _OwnedScope:
    scope: PreparedAgentScope
    runner_target: RunnerExecutionTargetV1
    slice_control_group: str
    tmux_server: _ProcessIdentity | None = None
    pane: _ProcessIdentity | None = None
    handoff: _GateHandoff | None = None
    confirmed: bool = False


def _validate_tmux_name(value: object) -> str:
    if not isinstance(value, str) or not _TMUX_NAME.fullmatch(value) or ".." in value:
        _fail()
    return value


def _canonical_control_group(value: object) -> str:
    if not isinstance(value, str) or not 2 <= len(value) <= 512 or not value.startswith("/"):
        _fail()
    parts = value[1:].split("/")
    if not parts or any(not _CGROUP_COMPONENT.fullmatch(part) for part in parts):
        _fail()
    return "/".join(parts)


def _bind_directory(path: Path) -> _BoundDirectory:
    if not hasattr(os, "O_NOFOLLOW"):
        _fail()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                _fail()
            return _BoundDirectory(path=path, device=metadata.st_dev, inode=metadata.st_ino)
        finally:
            os.close(descriptor)
    except (OSError, ValueError) as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc


def _read_bounded_under(
    bound: _BoundDirectory, path: Path, *, max_bytes: int
) -> bytes | None:
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_CGROUP_READ_BYTES:
        _fail()
    if not hasattr(os, "O_NOFOLLOW"):
        _fail()
    try:
        relative = path.relative_to(bound.path)
    except ValueError:
        _fail()
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _fail()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        root_descriptor = os.open(bound.path, directory_flags)
        descriptors.append(root_descriptor)
        root_metadata = os.fstat(root_descriptor)
        if (root_metadata.st_dev, root_metadata.st_ino) != (bound.device, bound.inode):
            _fail()
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=descriptors[-1])
            descriptors.append(child)
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                _fail()
        descriptor = os.open(parts[-1], file_flags, dir_fd=descriptors[-1])
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            _fail()
        payload = bytearray()
        while len(payload) <= max_bytes:
            chunk = os.read(descriptor, min(1024, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if len(payload) > max_bytes or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            _fail()
        root_after = os.fstat(root_descriptor)
        if (root_after.st_dev, root_after.st_ino) != (bound.device, bound.inode):
            _fail()
        return bytes(payload)
    except (OSError, ValueError) as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _cpu_topology_identity_under(
    bound: _BoundDirectory, path: Path, *, directory: bool
) -> tuple[int, int]:
    try:
        relative = path.relative_to(bound.path)
    except ValueError:
        _fail()
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _fail()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        root_descriptor = os.open(bound.path, directory_flags)
        descriptors.append(root_descriptor)
        root_metadata = os.fstat(root_descriptor)
        if (root_metadata.st_dev, root_metadata.st_ino) != (bound.device, bound.inode):
            _fail()
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            descriptor = os.open(
                part,
                directory_flags if not final or directory else file_flags,
                dir_fd=descriptors[-1],
            )
            descriptors.append(descriptor)
        metadata = os.fstat(descriptors[-1])
        if directory:
            if not stat.S_ISDIR(metadata.st_mode):
                _fail()
        elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            _fail()
        root_after = os.fstat(root_descriptor)
        if (root_after.st_dev, root_after.st_ino) != (bound.device, bound.inode):
            _fail()
        return metadata.st_dev, metadata.st_ino
    except (OSError, ValueError) as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_optional_core_type_under(
    bound: _BoundDirectory, path: Path, *, max_bytes: int
) -> bytes | None:
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_CGROUP_READ_BYTES:
        _fail()
    try:
        relative = path.relative_to(bound.path)
    except ValueError:
        _fail()
    parts = relative.parts
    if len(parts) != 3 or parts[1:] != ("topology", "core_type"):
        _fail()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        root_descriptor = os.open(bound.path, directory_flags)
        descriptors.append(root_descriptor)
        root_before = os.fstat(root_descriptor)
        if (root_before.st_dev, root_before.st_ino) != (bound.device, bound.inode):
            _fail()
        cpu_descriptor = os.open(parts[0], directory_flags, dir_fd=root_descriptor)
        descriptors.append(cpu_descriptor)
        cpu_before = os.fstat(cpu_descriptor)
        if not stat.S_ISDIR(cpu_before.st_mode):
            _fail()
        topology_descriptor = os.open(parts[1], directory_flags, dir_fd=cpu_descriptor)
        descriptors.append(topology_descriptor)
        topology_before = os.fstat(topology_descriptor)
        if not stat.S_ISDIR(topology_before.st_mode):
            _fail()
        parent_descriptors = (root_descriptor, cpu_descriptor, topology_descriptor)
        parent_identities = tuple(
            (metadata.st_dev, metadata.st_ino)
            for metadata in (root_before, cpu_before, topology_before)
        )
        try:
            leaf_before = os.stat(parts[2], dir_fd=topology_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            try:
                os.stat(parts[2], dir_fd=topology_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if tuple((metadata.st_dev, metadata.st_ino) for metadata in map(os.fstat, parent_descriptors)) != parent_identities:
                    _fail()
                return None
            _fail()
        if not stat.S_ISREG(leaf_before.st_mode) or leaf_before.st_nlink != 1:
            _fail()
        descriptor = os.open(parts[2], file_flags, dir_fd=topology_descriptor)
        descriptors.append(descriptor)
        leaf_opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(leaf_opened.st_mode)
            or leaf_opened.st_nlink != 1
            or (leaf_opened.st_dev, leaf_opened.st_ino) != (leaf_before.st_dev, leaf_before.st_ino)
        ):
            _fail()
        payload = bytearray()
        while len(payload) <= max_bytes:
            chunk = os.read(descriptor, min(1024, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        leaf_after = os.fstat(descriptor)
        if len(payload) > max_bytes or (leaf_before.st_dev, leaf_before.st_ino) != (
            leaf_after.st_dev,
            leaf_after.st_ino,
        ):
            _fail()
        if tuple((metadata.st_dev, metadata.st_ino) for metadata in map(os.fstat, parent_descriptors)) != parent_identities:
            _fail()
        return bytes(payload)
    except (OSError, ValueError) as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _bounded_process_environment() -> dict[str, str]:
    runtime = f"/run/user/{os.getuid()}"
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_RUNTIME_DIR": runtime,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
    }


def _released_scope_argv(
    *,
    profile: CgroupProfileV1,
    unit_name: str,
    socket_name: str,
    session_name: str,
    runner_target: RunnerExecutionTargetV1,
    challenge: str,
) -> tuple[str, ...]:
    if (
        not isinstance(profile, CgroupProfileV1)
        or not isinstance(runner_target, RunnerExecutionTargetV1)
        or not isinstance(unit_name, str)
        or not _UNIT_NAME.fullmatch(unit_name)
        or not isinstance(challenge, str)
        or not _CHALLENGE.fullmatch(challenge)
    ):
        _fail()
    _validate_tmux_name(socket_name)
    _validate_tmux_name(session_name)
    runner_target.verify_for_scope_start()
    return (
        SYSTEMD_RUN_PATH,
        "--user",
        "--scope",
        "--no-block",
        "--quiet",
        "--collect",
        f"--unit={unit_name}",
        f"--slice={CODEX_MASTER_SLICE}",
        "--property=Delegate=cpu cpuset memory pids io",
        f"--property=AllowedCPUs={profile.cpuset_expression}",
        f"--property=CPUQuota={profile.cpu_quota_percent}%",
        f"--property=CPUWeight={profile.cpu_weight}",
        f"--property=MemoryHigh={profile.memory_high_bytes}",
        f"--property=MemoryMax={profile.memory_max_bytes}",
        f"--property=MemorySwapMax={profile.memory_swap_max_bytes}",
        f"--property=IOWeight={profile.io_weight}",
        RESOURCE_SCOPE_GATE_PATH,
        "--socket",
        socket_name,
        "--session",
        session_name,
        "--owner-pid",
        str(runner_target.owner_pid),
        "--runner-fd",
        str(runner_target.fd),
        "--device",
        str(runner_target.device),
        "--inode",
        str(runner_target.inode),
        "--challenge",
        challenge,
    )


def _gate_socket_address(socket_name: str) -> str:
    _validate_tmux_name(socket_name)
    address = _GATE_SOCKET_PREFIX + socket_name
    if len(address.encode("ascii")) > _GATE_SOCKET_MAX_BYTES:
        _fail()
    return address


def _create_gate_listener(socket_name: str) -> socket.socket:
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.settimeout(COMMAND_TIMEOUT_SECONDS)
        listener.bind(_gate_socket_address(socket_name))
        listener.listen(1)
        return listener
    except OSError as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc


def _read_exact_socket(connection: socket.socket, size: int) -> bytes:
    if type(size) is not int or not 0 < size <= _GATE_RELEASE_BYTES:
        _fail()
    payload = bytearray()
    while len(payload) < size:
        try:
            chunk = connection.recv(size - len(payload))
        except OSError as exc:
            raise CgroupPreflightError("cgroup_preflight_failed") from exc
        if not chunk:
            _fail()
        payload.extend(chunk)
    return bytes(payload)


def _read_socket_line(connection: socket.socket, *, max_bytes: int) -> bytes:
    if type(max_bytes) is not int or not 1 <= max_bytes <= _GATE_PROTOCOL_MAX_BYTES:
        _fail()
    payload = bytearray()
    while len(payload) < max_bytes:
        try:
            chunk = connection.recv(1)
        except OSError as exc:
            raise CgroupPreflightError("cgroup_preflight_failed") from exc
        if not chunk:
            _fail()
        payload.extend(chunk)
        if chunk == b"\n":
            return bytes(payload)
    _fail()


def _parse_gate_handoff(raw: bytes, challenge: str) -> tuple[str, str, int, int]:
    if type(raw) is not bytes or not isinstance(challenge, str) or not _CHALLENGE.fullmatch(challenge):
        _fail()
    expected_prefix = f"HANDOFF {challenge} ".encode("ascii")
    if not raw.startswith(expected_prefix) or not raw.endswith(b"\n"):
        _fail()
    try:
        values = raw[len(expected_prefix) : -1].decode("ascii").split(" ")
    except UnicodeDecodeError:
        _fail()
    if (
        len(values) != 4
        or not _COMMIT.fullmatch(values[0])
        or not _TMUX_SESSION_ID.fullmatch(values[1])
    ):
        _fail()
    return values[0], values[1], _parse_positive_pid(values[2]), _parse_positive_pid(values[3])


def _attest_gate_handoff(handoff: _GateHandoff, *, challenge: str) -> tuple[str, int, int]:
    if not isinstance(handoff, _GateHandoff) or not isinstance(challenge, str) or not _CHALLENGE.fullmatch(challenge):
        _fail()
    connection = handoff.connection
    if connection is None:
        _fail()
    try:
        connection.sendall(f"ATTEST {challenge} {handoff.commit}\n".encode("ascii"))
        raw = _read_socket_line(connection, max_bytes=_GATE_ATTEST_MAX_BYTES)
        expected_prefix = f"ATTEST {challenge} {handoff.commit} ".encode("ascii")
        if not raw.startswith(expected_prefix) or not raw.endswith(b"\n"):
            _fail()
        values = raw[len(expected_prefix) : -1].decode("ascii").split(" ")
        if len(values) != 3 or not _TMUX_SESSION_ID.fullmatch(values[0]):
            _fail()
        tmux_pid = _parse_positive_pid(values[1])
        pane_pid = _parse_positive_pid(values[2])
        if (values[0], tmux_pid, pane_pid) != (
            handoff.session_id,
            handoff.tmux_pid,
            handoff.pane_pid,
        ):
            _fail()
        return values[0], tmux_pid, pane_pid
    except (OSError, UnicodeDecodeError) as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc


def _close_gate_handoff(handoff: _GateHandoff) -> None:
    if not isinstance(handoff, _GateHandoff):
        _fail()
    connection = handoff.connection
    handoff.connection = None
    if connection is not None:
        try:
            connection.close()
        except OSError as exc:
            raise CgroupPreflightError("cgroup_preflight_failed") from exc


def _commit_gate_handoff(handoff: _GateHandoff, *, challenge: str) -> None:
    if not isinstance(handoff, _GateHandoff) or not isinstance(challenge, str) or not _CHALLENGE.fullmatch(challenge):
        _fail()
    connection = handoff.connection
    if connection is None:
        _fail()
    try:
        connection.sendall(f"ACK {challenge} {handoff.commit}\n".encode("ascii"))
    except OSError as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc
    finally:
        _close_gate_handoff(handoff)


def _accept_gate_handoff(
    listener: socket.socket, *, gate_pid: int, owner_pid: int, challenge: str
) -> _GateHandoff:
    if (
        not isinstance(listener, socket.socket)
        or type(gate_pid) is not int
        or gate_pid <= 0
        or type(owner_pid) is not int
        or owner_pid != os.getpid()
        or not isinstance(challenge, str)
        or not _CHALLENGE.fullmatch(challenge)
        or not hasattr(socket, "SO_PEERCRED")
    ):
        _fail()
    connection: socket.socket | None = None
    try:
        connection, _address = listener.accept()
        connection.settimeout(COMMAND_TIMEOUT_SECONDS)
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12
        )
        if type(credentials) is not bytes or len(credentials) != 12:
            _fail()
        peer_pid, peer_uid, _peer_gid = struct.unpack("3i", credentials)
        if peer_pid != gate_pid or peer_uid != os.getuid():
            _fail()
        if _read_exact_socket(connection, _GATE_READY_BYTES) != f"READY {challenge}\n".encode(
            "ascii"
        ):
            _fail()
        connection.sendall(f"RELEASE {challenge}\n".encode("ascii"))
        commit, session_id, tmux_pid, pane_pid = _parse_gate_handoff(
            _read_socket_line(connection, max_bytes=_GATE_HANDOFF_MAX_BYTES),
            challenge,
        )
        handoff = _GateHandoff(
            commit=commit,
            session_id=session_id,
            tmux_pid=tmux_pid,
            pane_pid=pane_pid,
            connection=connection,
        )
        connection = None
        return handoff
    except (OSError, struct.error) as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc
    finally:
        if connection is not None:
            connection.close()
        listener.close()


def _close_command_streams(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def _stop_command_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=_COMMAND_KILL_WAIT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc


def _read_bounded_command_output(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> tuple[bytes, bytes]:
    if (
        process.stdout is None
        or process.stderr is None
        or not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
        or type(max_stdout_bytes) is not int
        or type(max_stderr_bytes) is not int
        or not 0 < max_stdout_bytes <= MAX_COMMAND_STDOUT_BYTES
        or not 0 < max_stderr_bytes <= MAX_COMMAND_STDERR_BYTES
    ):
        _fail()
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    limits = {stdout_fd: max_stdout_bytes, stderr_fd: max_stderr_bytes}
    buffers = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    active = set(buffers)
    selector = selectors.DefaultSelector()
    try:
        for descriptor in active:
            selector.register(descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        while active:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail()
            events = selector.select(remaining)
            if not events:
                _fail()
            for key, _mask in events:
                descriptor = key.fd
                buffer = buffers[descriptor]
                chunk = os.read(descriptor, (limits[descriptor] + 1) - len(buffer))
                if not chunk:
                    selector.unregister(descriptor)
                    active.remove(descriptor)
                    continue
                buffer.extend(chunk)
                if len(buffer) > limits[descriptor]:
                    _fail()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail()
        process.wait(timeout=remaining)
        return bytes(buffers[stdout_fd]), bytes(buffers[stderr_fd])
    except (OSError, subprocess.SubprocessError) as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc
    finally:
        selector.close()


class _SubprocessSystemdUserRunner:
    def _popen(self, argv: tuple[str, ...]) -> subprocess.Popen[bytes]:
        if not argv or any(type(argument) is not str or not argument for argument in argv):
            _fail()
        return subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
            env=_bounded_process_environment(),
        )

    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> CommandResultV1:
        process: subprocess.Popen[bytes] | None = None
        try:
            process = self._popen(argv)
            stdout, stderr = _read_bounded_command_output(
                process,
                timeout_seconds=timeout_seconds,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=max_stderr_bytes,
            )
            return CommandResultV1(
                returncode=process.returncode,
                stdout=stdout,
                stderr=stderr,
            )
        except Exception as exc:
            if process is not None:
                try:
                    _stop_command_process(process)
                except CgroupPreflightError:
                    pass
            raise CgroupPreflightError("cgroup_preflight_failed") from exc
        finally:
            if process is not None:
                _close_command_streams(process)


class SystemdUserCgroupAdapter:
    """Concrete G5 released-scope adapter; G5 alone may inject it into admission."""

    __slots__ = ("_runner", "_cgroup_root", "_owned", "_target_slice_control_group_path")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SystemdUserCgroupAdapter bindings are immutable")

    def __init__(self, *, runner: SystemdUserCommandRunner | None = None) -> None:
        bound_runner = _SubprocessSystemdUserRunner() if runner is None else runner
        bound_root = _bind_directory(CGROUP_ROOT)
        object.__setattr__(self, "_runner", bound_runner)
        object.__setattr__(self, "_cgroup_root", bound_root)
        object.__setattr__(self, "_owned", {})
        object.__setattr__(self, "_target_slice_control_group_path", _UNSET_TARGET_SLICE_CONTROL_GROUP)

    def _run(self, argv: tuple[str, ...]) -> CommandResultV1:
        try:
            result = self._runner.run(
                argv,
                timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                max_stdout_bytes=MAX_COMMAND_STDOUT_BYTES,
                max_stderr_bytes=MAX_COMMAND_STDERR_BYTES,
            )
        except Exception as exc:
            raise CgroupPreflightError("cgroup_preflight_failed") from exc
        if (
            not isinstance(result, CommandResultV1)
            or len(result.stdout) > MAX_COMMAND_STDOUT_BYTES
            or len(result.stderr) > MAX_COMMAND_STDERR_BYTES
        ):
            _fail()
        return result

    def _read_cgroup_file(self, control_group: str, name: str) -> bytes:
        if not _CGROUP_COMPONENT.fullmatch(name):
            _fail()
        if control_group == ".":
            candidate = self._cgroup_root.path / name
        else:
            canonical = _canonical_control_group(f"/{control_group}")
            candidate = self._cgroup_root.path / canonical / name
        payload = _read_bounded_under(
            self._cgroup_root,
            candidate,
            max_bytes=MAX_CGROUP_READ_BYTES,
        )
        if payload is None:
            _fail()
        return payload

    def read_bounded_cgroup_bytes(self, path: Path, *, max_bytes: int) -> bytes:
        candidate = Path(path)
        try:
            candidate.relative_to(CGROUP_ROOT)
        except ValueError:
            try:
                candidate.relative_to(CPU_TOPOLOGY_ROOT)
            except ValueError:
                _fail()
            payload = _read_bounded_under(
                _bind_directory(CPU_TOPOLOGY_ROOT), candidate, max_bytes=max_bytes
            )
        else:
            payload = _read_bounded_under(self._cgroup_root, candidate, max_bytes=max_bytes)
        if payload is None:
            _fail()
        return payload

    def read_optional_cpu_topology_bytes(self, path: Path, *, max_bytes: int) -> bytes | None:
        candidate = Path(path)
        try:
            relative = candidate.relative_to(CPU_TOPOLOGY_ROOT)
        except ValueError:
            _fail()
        if (
            len(relative.parts) != 3
            or relative.parts[1:] != ("topology", "core_type")
            or not relative.parts[0].startswith("cpu")
        ):
            _fail()
        cpu_text = relative.parts[0][3:]
        if (
            not cpu_text
            or len(cpu_text) > len(str(MAX_CPU_INDEX))
            or str(_parse_decimal(cpu_text)) != cpu_text
        ):
            _fail()
        return _read_optional_core_type_under(
            _bind_directory(CPU_TOPOLOGY_ROOT), candidate, max_bytes=max_bytes
        )

    def capture_cpu_topology_snapshot(self, cpus: CpuSet) -> object:
        canonical = _canonical_cpu_set(cpus)
        bound = _bind_directory(CPU_TOPOLOGY_ROOT)
        present = _cpu_topology_identity_under(bound, CPU_PRESENT_PATH, directory=False)
        parents = tuple(
            (
                cpu,
                _cpu_topology_identity_under(
                    bound, CPU_TOPOLOGY_ROOT / f"cpu{cpu}", directory=True
                ),
                _cpu_topology_identity_under(
                    bound, CPU_TOPOLOGY_ROOT / f"cpu{cpu}" / "topology", directory=True
                ),
            )
            for cpu in canonical
        )
        return present, parents

    def _target_slice_control_group(self, *, allow_missing: bool = False) -> str | None:
        cached = self._target_slice_control_group_path
        if cached is not _UNSET_TARGET_SLICE_CONTROL_GROUP:
            if cached is None:
                if allow_missing:
                    return None
                _fail()
            return cached
        result = self._run(
            (
                SYSTEMCTL_PATH,
                "--user",
                "--no-pager",
                "show",
                CODEX_MASTER_SLICE,
                "--property=ControlGroup",
            )
        )
        if result.returncode == 4 and allow_missing:
            object.__setattr__(self, "_target_slice_control_group_path", None)
            return None
        if result.returncode != 0 or result.stderr:
            _fail()
        line = _read_single_line(result.stdout)
        key, separator, value = line.partition("=")
        if key != "ControlGroup" or not separator:
            _fail()
        if value == "":
            if allow_missing:
                object.__setattr__(self, "_target_slice_control_group_path", None)
                return None
            _fail()
        control_group = _canonical_control_group(value)
        object.__setattr__(self, "_target_slice_control_group_path", control_group)
        return control_group

    def _target_slice_evidence(self, *, allow_missing: bool = False) -> tuple[str, frozenset[str], frozenset[str], CpuSet] | None:
        control_group = self._target_slice_control_group(allow_missing=allow_missing)
        if control_group is None:
            return None
        return (
            control_group,
            _parse_controller_set(self._read_cgroup_file(control_group, "cgroup.controllers")),
            _parse_controller_set(self._read_cgroup_file(control_group, "cgroup.subtree_control")),
            _parse_cpu_set(_read_single_line(self._read_cgroup_file(control_group, "cpuset.cpus.effective"))),
        )

    def clear_target_slice_control_group_cache(self) -> None:
        object.__setattr__(
            self,
            "_target_slice_control_group_path",
            _UNSET_TARGET_SLICE_CONTROL_GROUP,
        )

    def bind_target_slice_control_group(self) -> str:
        """Re-bind the dynamic target cgroup once for this typed flow."""

        self.clear_target_slice_control_group_cache()
        return self._target_slice_control_group()

    def read_hive_io_pressure(self) -> CgroupIoPressureEvidenceV1 | None:
        try:
            control_group = self._target_slice_control_group()
            raw = self._read_cgroup_file(control_group, "io.pressure")
        except Exception:
            return None
        try:
            return _parse_cgroup_pressure(raw)
        except Exception:
            return None

    def inspect_preflight(self) -> CgroupPreflightV1:
        evidence = self._target_slice_evidence()
        if evidence is None:
            _fail()
        _control_group, controllers, subtree_controllers, parent_effective_cpuset = evidence
        return CgroupPreflightV1(
            unified_v2=True,
            controllers=controllers,
            subtree_controllers=subtree_controllers,
            parent_effective_cpuset=parent_effective_cpuset,
            io_physical_isolation_proven=False,
        )

    def _user_bus_socket_present(self) -> bool:
        bus = Path("/run/user") / str(os.getuid()) / "bus"
        try:
            metadata = os.lstat(bus)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise CgroupPreflightError("cgroup_preflight_failed") from exc
        if not stat.S_ISSOCK(metadata.st_mode):
            _fail()
        return True

    def integration_precondition_reason(self) -> str | None:
        """Return only proven absent H2 prerequisites; malformed evidence raises."""

        if not self._user_bus_socket_present():
            return "requires_user_systemd_bus"
        evidence = self._target_slice_evidence(allow_missing=True)
        if evidence is None:
            return "requires_target_slice"
        _control_group, controllers, subtree_controllers, _parent_effective_cpuset = evidence
        if not REQUIRED_CONTROLLERS.issubset(controllers) or not REQUIRED_CONTROLLERS.issubset(
            subtree_controllers
        ):
            return "requires_delegated_controllers"
        return None

    def user_bus_available(self) -> bool:
        try:
            return self._user_bus_socket_present()
        except CgroupPreflightError:
            return False

    def _show_scope(self, unit_name: str, *, expected_slice_control_group: str) -> tuple[str, int]:
        result = self._run(
            (
                SYSTEMCTL_PATH,
                "--user",
                "--no-pager",
                "show",
                unit_name,
                "--property=ControlGroup",
                "--property=MainPID",
                "--property=DelegateControllers",
            )
        )
        if result.returncode != 0:
            _fail()
        try:
            lines = result.stdout.decode("ascii").splitlines()
        except UnicodeDecodeError:
            _fail()
        if len(lines) != 3 or any("=" not in line for line in lines):
            _fail()
        values = dict(line.split("=", 1) for line in lines)
        if set(values) != {"ControlGroup", "MainPID", "DelegateControllers"} or len(
            values
        ) != len(lines):
            _fail()
        control_group = _canonical_control_group(values["ControlGroup"])
        gate_pid = _parse_positive_pid(values["MainPID"])
        delegated = _parse_controller_set(f"{values['DelegateControllers']}\n".encode("ascii"))
        if control_group != f"{expected_slice_control_group}/{unit_name}":
            _fail()
        if delegated != REQUIRED_CONTROLLERS:
            _fail()
        return control_group, gate_pid

    def _stop_new_unit(self, unit_name: str) -> None:
        self._run((SYSTEMCTL_PATH, "--user", "--no-pager", "stop", unit_name))

    def start_released_scope(
        self,
        *,
        profile: CgroupProfileV1,
        socket_name: str,
        session_name: str,
        runner_target: RunnerExecutionTargetV1,
    ) -> PreparedAgentScope:
        _validate_tmux_name(socket_name)
        _validate_tmux_name(session_name)
        runner_target.verify_for_scope_start()
        slice_evidence = self._target_slice_evidence()
        if slice_evidence is None:
            _fail()
        slice_control_group, _controllers, _subtree_controllers, _parent_effective_cpuset = slice_evidence
        unit_name = f"codex-master-resource-{secrets.token_hex(16)}.scope"
        if not _UNIT_NAME.fullmatch(unit_name) or unit_name in self._owned:
            _fail()
        collision = self._run(
            (SYSTEMCTL_PATH, "--user", "--no-pager", "show", unit_name, "--property=Id")
        )
        if collision.returncode != 4:
            _fail()
        challenge = secrets.token_hex(_GATE_CHALLENGE_BYTES)
        if not _CHALLENGE.fullmatch(challenge):
            _fail()
        listener = _create_gate_listener(socket_name)
        scope: PreparedAgentScope | None = None
        handoff: _GateHandoff | None = None
        started = False
        try:
            result = self._run(
                _released_scope_argv(
                    profile=profile,
                    unit_name=unit_name,
                    socket_name=socket_name,
                    session_name=session_name,
                    runner_target=runner_target,
                    challenge=challenge,
                )
            )
            started = True
            if result.returncode != 0 or result.stdout or result.stderr:
                _fail()
            control_group, gate_pid = self._show_scope(
                unit_name,
                expected_slice_control_group=slice_control_group,
            )
            scope = PreparedAgentScope(
                unit_name=unit_name,
                socket_name=socket_name,
                session_name=session_name,
                control_group=control_group,
                gate_pid=gate_pid,
                challenge=challenge,
            )
            self._owned[unit_name] = _OwnedScope(
                scope=scope,
                runner_target=runner_target,
                slice_control_group=slice_control_group,
            )
            self.verify_scope(scope, profile)
            handoff = _accept_gate_handoff(
                listener,
                gate_pid=scope.gate_pid,
                owner_pid=runner_target.owner_pid,
                challenge=scope.challenge,
            )
            tmux_pid = handoff.tmux_pid
            pane_pid = handoff.pane_pid
            members = _parse_pid_lines(self._read_cgroup_file(scope.control_group, "cgroup.procs"))
            if tmux_pid not in members or pane_pid not in members:
                _fail()
            owned = self._owned_scope(scope)
            owned.tmux_server = _process_identity(tmux_pid)
            owned.pane = _process_identity(pane_pid)
            owned.handoff = handoff
            handoff = None
            return scope
        except Exception as exc:
            if handoff is not None:
                try:
                    _close_gate_handoff(handoff)
                except CgroupPreflightError:
                    pass
            if scope is not None and scope.unit_name in self._owned:
                owned = self._owned.pop(scope.unit_name)
                if owned.handoff is not None:
                    try:
                        _close_gate_handoff(owned.handoff)
                    except CgroupPreflightError:
                        pass
            if started:
                try:
                    self._stop_new_unit(unit_name)
                except Exception:
                    pass
            if isinstance(exc, CgroupPreflightError):
                raise
            raise CgroupPreflightError("cgroup_preflight_failed") from exc
        finally:
            listener.close()

    def _owned_scope(self, scope: PreparedAgentScope) -> _OwnedScope:
        owned = self._owned.get(scope.unit_name)
        if owned is None or owned.scope != scope:
            _fail()
        return owned

    def verify_scope(self, scope: PreparedAgentScope, profile: CgroupProfileV1) -> None:
        owned = self._owned_scope(scope)
        expected = {
            "cpuset.cpus.effective": f"{profile.cpuset_expression}\n".encode(),
            "cpu.max": f"{profile.cpu_quota_percent * 1000} 100000\n".encode(),
            "memory.high": f"{profile.memory_high_bytes}\n".encode(),
            "memory.max": f"{profile.memory_max_bytes}\n".encode(),
            "memory.swap.max": f"{profile.memory_swap_max_bytes}\n".encode(),
            "io.weight": f"{profile.io_weight}\n".encode(),
        }
        for name, payload in expected.items():
            if self._read_cgroup_file(scope.control_group, name) != payload:
                _fail()
        pids = _parse_pid_lines(self._read_cgroup_file(scope.control_group, "cgroup.procs"))
        if scope.gate_pid not in pids:
            _fail()
        parent = owned.slice_control_group
        if scope.control_group != f"{parent}/{scope.unit_name}":
            _fail()
        controllers = _parse_controller_set(self._read_cgroup_file(parent, "cgroup.controllers"))
        delegated = _parse_controller_set(self._read_cgroup_file(parent, "cgroup.subtree_control"))
        parent_mask = _parse_cpu_set(_read_single_line(self._read_cgroup_file(parent, "cpuset.cpus.effective")))
        if (
            not REQUIRED_CONTROLLERS.issubset(controllers)
            or not REQUIRED_CONTROLLERS.issubset(delegated)
            or not set(profile.cpuset_cpus).issubset(parent_mask)
        ):
            _fail()

    def _attest_pane_runner(self, pane_pid: int, runner_target: RunnerExecutionTargetV1) -> None:
        try:
            descriptor = os.open(f"/proc/{pane_pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
        except OSError as exc:
            raise CgroupPreflightError("cgroup_preflight_failed") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or (metadata.st_dev, metadata.st_ino)
                != (runner_target.device, runner_target.inode)
                or os.pread(descriptor, 4, 0) != b"\x7fELF"
            ):
                _fail()
        except OSError as exc:
            raise CgroupPreflightError("cgroup_preflight_failed") from exc
        finally:
            os.close(descriptor)

    def confirm_scope(self, scope: PreparedAgentScope) -> int:
        owned = self._owned_scope(scope)
        if owned.confirmed or owned.tmux_server is None or owned.pane is None or owned.handoff is None:
            _fail()
        handoff = owned.handoff
        _session_id, tmux_pid, pane_pid = _attest_gate_handoff(handoff, challenge=scope.challenge)
        if tmux_pid != owned.tmux_server.pid or pane_pid != owned.pane.pid:
            _fail()
        if _process_identity(tmux_pid) != owned.tmux_server or _process_identity(pane_pid) != owned.pane:
            _fail()
        members = _parse_pid_lines(self._read_cgroup_file(scope.control_group, "cgroup.procs"))
        if tmux_pid not in members or pane_pid not in members:
            _fail()
        self._attest_pane_runner(pane_pid, owned.runner_target)
        self._attest_tmux_membership_and_inheritance(scope, tmux_pid)
        _commit_gate_handoff(handoff, challenge=scope.challenge)
        owned.handoff = None
        owned.confirmed = True
        return tmux_pid

    def _read_tmux_children(self, tmux_pid: int) -> tuple[int, ...]:
        bound = _bind_directory(PROC_ROOT)
        raw = _read_bounded_under(
            bound,
            bound.path / str(tmux_pid) / "task" / str(tmux_pid) / "children",
            max_bytes=MAX_CGROUP_READ_BYTES,
        )
        text = _read_single_line(raw)
        if not text:
            _fail()
        children = tuple(_parse_positive_pid(value) for value in text.split(" "))
        if len(set(children)) != len(children):
            _fail()
        return children

    def _attest_tmux_membership_and_inheritance(self, scope: PreparedAgentScope, tmux_pid: int) -> None:
        if type(tmux_pid) is not int or tmux_pid <= 0:
            _fail()
        members = _parse_pid_lines(self._read_cgroup_file(scope.control_group, "cgroup.procs"))
        if tmux_pid not in members:
            _fail()
        children = self._read_tmux_children(tmux_pid)
        if not set(children).issubset(members):
            _fail()

    def cleanup_new_scope(self, scope: PreparedAgentScope) -> None:
        owned = self._owned_scope(scope)
        del self._owned[scope.unit_name]
        if owned.handoff is not None:
            _close_gate_handoff(owned.handoff)
        self._stop_new_unit(scope.unit_name)


def _read_single_line(raw: bytes) -> str:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_CGROUP_READ_BYTES:
        _fail()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        _fail()
    if not text.endswith("\n") or text.count("\n") != 1:
        _fail()
    return text[:-1]


def _parse_controller_set(raw: bytes) -> frozenset[str]:
    text = _read_single_line(raw)
    values = text.split(" ")
    if (
        not values
        or any(not _CGROUP_COMPONENT.fullmatch(value) for value in values)
        or len(values) != len(set(values))
    ):
        _fail()
    return frozenset(values)


def _parse_positive_pid(value: str) -> int:
    if not value or not value.isascii() or not value.isdecimal() or (len(value) > 1 and value[0] == "0"):
        _fail()
    parsed = int(value)
    if parsed <= 0 or parsed > (1 << 31) - 1:
        _fail()
    return parsed


def _parse_pid_lines(raw: bytes) -> frozenset[int]:
    if type(raw) is not bytes or not 2 <= len(raw) <= MAX_CGROUP_READ_BYTES:
        _fail()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        _fail()
    if not text.endswith("\n") or not text[:-1] or "\n\n" in text:
        _fail()
    values = tuple(_parse_positive_pid(value) for value in text[:-1].split("\n"))
    if len(values) > 256 or len(set(values)) != len(values):
        _fail()
    return frozenset(values)


def _process_identity(pid: int) -> _ProcessIdentity:
    if type(pid) is not int or pid <= 0:
        _fail()
    bound = _bind_directory(PROC_ROOT)
    raw = _read_bounded_under(
        bound,
        bound.path / str(pid) / "stat",
        max_bytes=MAX_CGROUP_READ_BYTES,
    )
    if not raw.endswith(b"\n"):
        _fail()
    closing = raw.rfind(b") ")
    if closing <= 0:
        _fail()
    fields = raw[closing + 2 : -1].split(b" ")
    if len(fields) < 20 or not fields[19].isdigit():
        _fail()
    start_ticks = int(fields[19])
    if start_ticks <= 0 or start_ticks > (1 << 63) - 1:
        _fail()
    return _ProcessIdentity(pid=pid, start_ticks=start_ticks)


def _read_text(backend: CgroupSystemAdapter, path: Path) -> str:
    try:
        raw = backend.read_bounded_cgroup_bytes(path, max_bytes=MAX_CGROUP_READ_BYTES)
    except Exception as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_CGROUP_READ_BYTES:
        _fail()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        _fail()
    if not text.endswith("\n") or text.count("\n") != 1:
        _fail()
    return text[:-1]


def _read_optional_cpu_topology_text(
    backend: CgroupSystemAdapter, path: Path
) -> str | None:
    try:
        raw = backend.read_optional_cpu_topology_bytes(
            path, max_bytes=MAX_CGROUP_READ_BYTES
        )
    except Exception as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc
    if raw is None:
        return None
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_CGROUP_READ_BYTES:
        _fail()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        _fail()
    if not text.endswith("\n") or text.count("\n") != 1:
        _fail()
    return text[:-1]


def _parse_cgroup_pressure(raw: bytes) -> CgroupIoPressureEvidenceV1:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_CGROUP_READ_BYTES:
        _fail()
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _fail()
    if len(lines) != 2:
        _fail()
    some: dict[str, float] | None = None
    full: dict[str, float] | None = None
    seen: set[str] = set()
    for line in lines:
        fields = line.split()
        if len(fields) != 5 or fields[0] not in {"some", "full"} or fields[0] in seen:
            _fail()
        seen.add(fields[0])
        values: dict[str, str] = {}
        for field in fields[1:]:
            key, separator, value = field.partition("=")
            if separator != "=" or key in values:
                _fail()
            values[key] = value
        if set(values) != {"avg10", "avg60", "avg300", "total"}:
            _fail()
        for key in ("avg10", "avg60", "avg300"):
            if not _PSI_DECIMAL.fullmatch(values[key]):
                _fail()
        if not values["total"].isdigit() or int(values["total"]) > (1 << 63) - 1:
            _fail()
        parsed_line = {
            "avg10": float(values["avg10"]),
            "avg60": float(values["avg60"]),
            "avg300": float(values["avg300"]),
        }
        if not all(math.isfinite(value) for value in parsed_line.values()):
            _fail()
        if fields[0] == "some":
            some = parsed_line
        else:
            full = parsed_line
    if some is None or full is None:
        _fail()
    return CgroupIoPressureEvidenceV1(
        some_avg10=some["avg10"],
        full_avg10=full["avg10"],
        full_avg60=full["avg60"],
    )


def read_hive_io_pressure(*, adapter: CgroupSystemAdapter) -> CgroupIoPressureEvidenceV1 | None:
    try:
        return adapter.read_hive_io_pressure()
    except Exception:
        return None


def _parse_decimal(value: str) -> int:
    if not value or not value.isascii() or not value.isdecimal() or (len(value) > 1 and value[0] == "0"):
        _fail()
    parsed = int(value)
    if parsed > MAX_CPU_INDEX:
        _fail()
    return parsed


def _parse_cpu_set(value: str) -> CpuSet:
    if not value or len(value) > 1024:
        _fail()
    result: list[int] = []
    previous = -1
    for part in value.split(","):
        if not _CPU_SET_PART.fullmatch(part):
            _fail()
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = _parse_decimal(start_text), _parse_decimal(end_text)
            if start >= end or end - start > 256:
                _fail()
            values = range(start, end + 1)
        else:
            values = (_parse_decimal(part),)
        for cpu in values:
            if cpu <= previous:
                _fail()
            result.append(cpu)
            previous = cpu
            if len(result) > 256:
                _fail()
    return _canonical_cpu_set(tuple(result))


def parse_cpu_topology(backend: CgroupSystemAdapter) -> CpuTopologyV1:
    """Parse only bounded, injected CPU-topology evidence."""

    cpus = _parse_cpu_set(_read_text(backend, CPU_PRESENT_PATH))
    snapshot_before = backend.capture_cpu_topology_snapshot(cpus)
    groups: dict[tuple[int, int], list[int]] = {}
    kinds: dict[tuple[int, int], str] = {}
    present_kinds = 0
    missing_kinds = 0
    for cpu in cpus:
        root = CPU_TOPOLOGY_ROOT / f"cpu{cpu}" / "topology"
        package = _parse_decimal(_read_text(backend, root / "physical_package_id"))
        core = _parse_decimal(_read_text(backend, root / "core_id"))
        kind = _read_optional_cpu_topology_text(backend, root / "core_type")
        key = package, core
        if kind is None:
            missing_kinds += 1
        else:
            present_kinds += 1
            if kind not in {"performance", "efficiency"}:
                _fail()
            prior = kinds.setdefault(key, kind)
            if prior != kind:
                _fail()
        groups.setdefault(key, []).append(cpu)
    if _parse_cpu_set(_read_text(backend, CPU_PRESENT_PATH)) != cpus:
        _fail()
    if backend.capture_cpu_topology_snapshot(cpus) != snapshot_before:
        _fail()
    if present_kinds and missing_kinds:
        _fail()
    physical_cores = tuple(tuple(cpus) for _key, cpus in sorted(groups.items()))
    efficiency = tuple(
        cpu
        for key, cpus in sorted(groups.items())
        if kinds.get(key) == "efficiency"
        for cpu in cpus
    )
    return CpuTopologyV1(physical_cores=physical_cores, efficiency_cpus=efficiency)


def derive_cgroup_profile(
    topology: CpuTopologyV1, *, approved_cpuset: CpuSet, mem_total_bytes: int
) -> CgroupProfileV1:
    if not isinstance(topology, CpuTopologyV1) or type(mem_total_bytes) is not int:
        _fail()
    approved = _canonical_cpu_set(approved_cpuset)
    if len(topology.physical_cores) <= 2:
        _fail()
    if topology.efficiency_cpus:
        expected = topology.efficiency_cpus
    else:
        expected = tuple(cpu for core in topology.physical_cores[2:] for cpu in core)
    if approved != expected or not 7 * GIB < mem_total_bytes <= MAX_MEMORY_TOTAL_BYTES:
        _fail()
    return CgroupProfileV1(
        cpuset_cpus=approved,
        cpu_quota_percent=750,
        cpu_weight=50,
        memory_high_bytes=mem_total_bytes - 7 * GIB,
        memory_max_bytes=mem_total_bytes - 4 * GIB,
        memory_swap_max_bytes=8 * GIB,
        io_weight=50,
    )


def _read_host_memory_total_bytes() -> int:
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        page_count = os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, OSError, TypeError, ValueError):
        _fail()
    if (
        type(page_size) is not int
        or type(page_count) is not int
        or page_size <= 0
        or page_count <= 0
    ):
        _fail()
    return page_size * page_count


@dataclass(frozen=True, slots=True)
class ApprovedCgroupRuntimeV1:
    profile: CgroupProfileV1
    adapter: SystemdUserCgroupAdapter
    preflight: CgroupPreflightV1


def build_approved_cgroup_runtime(
    *,
    runner: SystemdUserCommandRunner | None = None,
    mem_total_bytes: int | None = None,
) -> ApprovedCgroupRuntimeV1:
    """Build one validated profile and adapter from the approved host plan."""

    approved = _canonical_cpu_set(APPROVED_CPUSET)
    adapter = SystemdUserCgroupAdapter(runner=runner)
    if type(adapter) is not SystemdUserCgroupAdapter:
        _fail()
    adapter.bind_target_slice_control_group()
    topology = parse_cpu_topology(adapter)
    memory_total = _read_host_memory_total_bytes() if mem_total_bytes is None else mem_total_bytes
    profile = derive_cgroup_profile(
        topology,
        approved_cpuset=approved,
        mem_total_bytes=memory_total,
    )
    preflight = require_cgroup_preflight(adapter, profile)
    if type(preflight) is not CgroupPreflightV1:
        _fail()
    return ApprovedCgroupRuntimeV1(
        profile=profile,
        adapter=adapter,
        preflight=preflight,
    )


def require_cgroup_preflight(adapter: CgroupSystemAdapter, profile: CgroupProfileV1) -> CgroupPreflightV1:
    if not isinstance(profile, CgroupProfileV1):
        _fail()
    try:
        preflight = adapter.inspect_preflight()
    except Exception as exc:
        raise CgroupPreflightError("cgroup_preflight_failed") from exc
    if not isinstance(preflight, CgroupPreflightV1) or not set(profile.cpuset_cpus).issubset(
        preflight.parent_effective_cpuset
    ):
        _fail()
    return preflight


def start_released_scope(
    adapter: CgroupSystemAdapter,
    *,
    profile: CgroupProfileV1,
    socket_name: str,
    session_name: str,
    runner_target: RunnerExecutionTargetV1,
) -> PreparedAgentScope:
    """Prepare one private G5 scope; dispatch remains outside this function."""

    if not isinstance(profile, CgroupProfileV1) or not isinstance(
        runner_target, RunnerExecutionTargetV1
    ):
        _fail()
    _validate_tmux_name(socket_name)
    _validate_tmux_name(session_name)
    runner_target.verify_for_scope_start()
    scope: PreparedAgentScope | None = None
    try:
        require_cgroup_preflight(adapter, profile)
        scope = adapter.start_released_scope(
            profile=profile,
            socket_name=socket_name,
            session_name=session_name,
            runner_target=runner_target,
        )
        if (
            not isinstance(scope, PreparedAgentScope)
            or scope.socket_name != socket_name
            or scope.session_name != session_name
        ):
            _fail()
        adapter.verify_scope(scope, profile)
        return scope
    except Exception as exc:
        if scope is not None:
            try:
                adapter.cleanup_new_scope(scope)
            except Exception:
                pass
        if isinstance(exc, CgroupPreflightError):
            raise
        raise CgroupPreflightError("cgroup_preflight_failed") from exc


def confirm_verified_scope(adapter: CgroupSystemAdapter, scope: PreparedAgentScope) -> None:
    """Confirm exactly one dispatched G5 pane against its prepared scope."""

    if not isinstance(scope, PreparedAgentScope):
        _fail()
    try:
        tmux_pid = adapter.confirm_scope(scope)
        if type(tmux_pid) is not int or tmux_pid <= 0:
            _fail()
    except Exception as exc:
        try:
            adapter.cleanup_new_scope(scope)
        except Exception:
            pass
        if isinstance(exc, CgroupPreflightError):
            raise
        raise CgroupPreflightError("cgroup_preflight_failed") from exc
