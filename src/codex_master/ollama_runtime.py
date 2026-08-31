"""Bounded local Ollama path, process, and readiness runtime."""

from __future__ import annotations

from dataclasses import astuple, dataclass, field
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import NoReturn, Protocol
import weakref

from codex_master.ollama_registry import OllamaInstanceV1, OllamaRegistryV1
from codex_master.resource_cgroup import (
    OllamaCpuProfile,
    ResourceCgroupError,
)


SYSTEMD_RUN_PATH = "/usr/bin/systemd-run"
SYSTEMCTL_PATH = "/usr/bin/systemctl"
CGROUP_ROOT = Path("/sys/fs/cgroup")
OLLAMA_SLICE = "codex-master.slice"
PROBE_TIMEOUT_SECONDS = 2.0
MAX_TAG_RESPONSE_BYTES = 64 * 1024
_MAX_CGROUP_BYTES = 4096
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_EXEC_HELPER_SOURCE = r'''
import fcntl, hashlib, json, os, stat, sys
MAX_BYTES = 512 * 1024 * 1024
PATH_KEYS = {"path", "device", "inode", "mode", "owner_uid", "owner_gid", "link_count", "size", "mtime_ns", "ctime_ns", "sha256", "ancestors"}
ANCESTOR_KEYS = {"path", "device", "inode", "mode", "owner_uid", "owner_gid"}

def fail():
    raise RuntimeError

def integer(value, minimum=0, maximum=(1 << 63) - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        fail()
    return value

def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)

def evidence_identity(value):
    return tuple(integer(value[name]) for name in ("device", "inode", "mode", "owner_uid", "owner_gid", "link_count", "size", "mtime_ns", "ctime_ns"))

def effective_access(metadata, host, read=False, execute=False):
    mode = stat.S_IMODE(metadata.st_mode)
    required = (4 if read else 0) | (1 if execute else 0)
    if host[0] == 0:
        return not execute or bool(mode & 0o111)
    if metadata.st_uid == host[0]:
        granted = (mode >> 6) & 7
    elif metadata.st_gid in {host[1], *host[2]}:
        granted = (mode >> 3) & 7
    else:
        granted = mode & 7
    return granted & required == required

def validate_ancestor(path, metadata, host, expected):
    if type(expected) is not dict or set(expected) != ANCESTOR_KEYS or expected["path"] != path:
        fail()
    actual = {"path": path, "device": metadata.st_dev, "inode": metadata.st_ino, "mode": metadata.st_mode, "owner_uid": metadata.st_uid, "owner_gid": metadata.st_gid}
    if actual != expected:
        fail()
    mode = stat.S_IMODE(metadata.st_mode)
    writable = bool(mode & 0o022)
    trusted_sticky = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {0, host[0]} or not effective_access(metadata, host, execute=True) or (writable and not trusted_sticky):
        fail()

def open_validated(value, expected, host, kind):
    if type(value) is not str or type(expected) is not dict or set(expected) != PATH_KEYS or expected["path"] != value or not value.startswith("/") or "\0" in value:
        fail()
    parts = value.split("/")[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        fail()
    ancestors = expected["ancestors"]
    if type(ancestors) is not list or len(ancestors) != len(parts) or len(ancestors) > 64:
        fail()
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    current = "/"
    try:
        for index, part in enumerate(parts):
            metadata = os.fstat(descriptor)
            validate_ancestor(current, metadata, host, ancestors[index])
            final = index == len(parts) - 1
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if not final or kind == "models":
                flags |= os.O_DIRECTORY
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            current = (current.rstrip("/") + "/" + part)
        metadata = os.fstat(descriptor)
        if identity(metadata) != evidence_identity(expected):
            fail()
        mode = stat.S_IMODE(metadata.st_mode)
        trusted_owner = metadata.st_uid in {0, host[0]}
        if kind == "executable":
            digest = expected["sha256"]
            valid_digest = type(digest) is str and len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)
            valid = stat.S_ISREG(metadata.st_mode) and trusted_owner and not bool(mode & 0o022) and effective_access(metadata, host, read=True, execute=True) and (metadata.st_uid == 0 or metadata.st_nlink == 1) and 0 < metadata.st_size <= MAX_BYTES and valid_digest
        else:
            private = metadata.st_uid == host[0] and mode == 0o700
            administrative = metadata.st_uid == 0 and not bool(mode & 0o022)
            valid = stat.S_ISDIR(metadata.st_mode) and trusted_owner and effective_access(metadata, host, read=True, execute=True) and (private or administrative) and expected["sha256"] is None
        if not valid:
            fail()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

def write_all(descriptor, data):
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            fail()
        offset += written

def pin_executable(source, expected):
    before = os.fstat(source)
    if identity(before) != evidence_identity(expected):
        fail()
    pinned = os.memfd_create("codex-master-ollama-executable", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    digest = hashlib.sha256()
    total = 0
    try:
        os.lseek(source, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source, min(1024 * 1024, MAX_BYTES - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BYTES:
                fail()
            digest.update(chunk)
            write_all(pinned, chunk)
        after = os.fstat(source)
        if total != before.st_size or identity(after) != identity(before) or digest.hexdigest() != expected["sha256"]:
            fail()
        os.fchmod(pinned, 0o500)
        os.lseek(pinned, 0, os.SEEK_SET)
        fcntl.fcntl(pinned, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        return pinned
    except BaseException:
        os.close(pinned)
        raise

try:
    if len(sys.argv) != 2 or len(sys.argv[1].encode("utf-8")) > 65536:
        fail()
    document = json.loads(sys.argv[1])
    if type(document) is not dict or set(document) != {"schema", "executable", "models_directory", "host", "port"} or document["schema"] != 1:
        fail()
    host_document = document["host"]
    if type(host_document) is not dict or set(host_document) != {"available_cpus", "effective_uid", "effective_gid", "supplementary_gids"}:
        fail()
    groups = host_document["supplementary_gids"]
    if type(groups) is not list or any(type(group) is not int or group < 0 for group in groups) or groups != sorted(set(groups)):
        fail()
    host = (integer(host_document["effective_uid"]), integer(host_document["effective_gid"]), tuple(groups))
    if host != (os.geteuid(), os.getegid(), tuple(sorted(set(os.getgroups())))):
        fail()
    port = integer(document["port"], 1, 65535)
    executable = document["executable"]
    models = document["models_directory"]
    source_fd = open_validated(executable.get("path") if type(executable) is dict else None, executable, host, "executable")
    models_fd = open_validated(models.get("path") if type(models) is dict else None, models, host, "models")
    pinned_fd = pin_executable(source_fd, executable)
    os.set_inheritable(models_fd, True)
    os.execve(pinned_fd, (executable["path"], "serve"), {"OLLAMA_HOST": "127.0.0.1:" + str(port), "OLLAMA_MODELS": "/proc/self/fd/" + str(models_fd)})
except BaseException:
    os._exit(125)
'''.strip()
_UNIT_NAME = re.compile(r"^codex-master-ollama-[a-f0-9]{32}\.scope$")
_CPU_PROPERTY = re.compile(
    r"^--property=AllowedCPUs=(?:0|[1-9][0-9]*)(?:-(?:[1-9][0-9]*))?"
    r"(?:,(?:0|[1-9][0-9]*)(?:-(?:[1-9][0-9]*))?)*$"
)
_QUOTA_PROPERTY = re.compile(r"^--property=CPUQuota=([1-9][0-9]{0,4})%$")
_WEIGHT_PROPERTY = re.compile(r"^--property=CPUWeight=([1-9][0-9]{0,4})$")
_LOOPBACK_HOST = re.compile(r"^127\.0\.0\.1:([1-9][0-9]{0,4})$")
_RECORD_LOCK = threading.RLock()
_PLAN_SEAL = object()
_PLAN_RECORDS: dict[
    bytes, tuple[weakref.ReferenceType[object], tuple[object, ...]]
] = {}
_START_SEAL = object()
_START_RECORDS: dict[bytes, tuple[object, tuple[object, ...]]] = {}
_RUNNING_SEAL = object()
_RUNNING_CLAIMS: set[bytes] = set()
_STOP_SEAL = object()
_STOP_RECORDS: dict[bytes, tuple[object, tuple[object, ...]]] = {}
_RUNNING_RECORDS: dict[
    bytes, tuple[weakref.ReferenceType[object], tuple[object, ...]]
] = {}


class OllamaRuntimeError(RuntimeError):
    """Code-only local runtime failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _ObjectIdentity:
    __slots__ = ("value",)

    def __init__(self, value: object) -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _ObjectIdentity) and self.value is other.value


def _fail(code: str) -> NoReturn:
    raise OllamaRuntimeError(code) from None


@dataclass(frozen=True, slots=True)
class OllamaHostSnapshot:
    available_cpus: tuple[int, ...]
    effective_uid: int
    effective_gid: int = field(default_factory=os.getegid)
    supplementary_gids: tuple[int, ...] = field(
        default_factory=lambda: tuple(sorted(set(os.getgroups())))
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(self.available_cpus, tuple)
            or not self.available_cpus
            or any(type(cpu) is not int or cpu < 0 for cpu in self.available_cpus)
            or tuple(sorted(set(self.available_cpus))) != self.available_cpus
            or type(self.effective_uid) is not int
            or self.effective_uid < 0
            or type(self.effective_gid) is not int
            or self.effective_gid < 0
            or not isinstance(self.supplementary_gids, tuple)
            or any(type(group) is not int or group < 0 for group in self.supplementary_gids)
            or tuple(sorted(set(self.supplementary_gids))) != self.supplementary_gids
        ):
            _fail("resource.host_probe_invalid")


def _cpu_profile_matches(
    profile: OllamaCpuProfile,
    instance: OllamaInstanceV1,
    host: OllamaHostSnapshot,
) -> bool:
    try:
        expected = OllamaCpuProfile.parse(
            instance.allowed_cpus,
            instance.cpu_quota_percent,
            instance.cpu_weight,
            available_cpus=host.available_cpus,
        )
    except ResourceCgroupError:
        return False
    return profile == expected


@dataclass(frozen=True, slots=True)
class OllamaAncestorEvidence:
    path: str
    device: int
    inode: int
    mode: int
    owner_uid: int
    owner_gid: int


@dataclass(frozen=True, slots=True)
class OllamaPathEvidence:
    path: str
    device: int
    inode: int
    mode: int
    owner_uid: int
    owner_gid: int
    link_count: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str | None
    ancestors: tuple[OllamaAncestorEvidence, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class OllamaLocalPlan:
    instance: OllamaInstanceV1
    host: OllamaHostSnapshot
    executable: OllamaPathEvidence
    models_directory: OllamaPathEvidence
    cpu_profile: OllamaCpuProfile
    selected_provider_model_ids: tuple[str, ...]
    _provenance: bytes = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self._seal is not _PLAN_SEAL
            or not isinstance(self._provenance, bytes)
            or len(self._provenance) != 32
            or not isinstance(self.instance, OllamaInstanceV1)
            or self.instance.host_ref != "local"
            or not isinstance(self.host, OllamaHostSnapshot)
            or not isinstance(self.executable, OllamaPathEvidence)
            or not isinstance(self.models_directory, OllamaPathEvidence)
            or self.executable.path != self.instance.ollama_executable
            or self.models_directory.path != self.instance.models_directory
            or not isinstance(self.cpu_profile, OllamaCpuProfile)
            or not _cpu_profile_matches(self.cpu_profile, self.instance, self.host)
            or not isinstance(self.selected_provider_model_ids, tuple)
            or len(self.selected_provider_model_ids)
            != len(self.instance.selected_model_refs)
            or any(not isinstance(model_id, str) or not model_id for model_id in self.selected_provider_model_ids)
        ):
            _fail("provider.plan_invalid")


@dataclass(frozen=True, slots=True)
class OllamaStartRequest:
    unit_name: str
    argv: tuple[str, ...]
    launcher_environment: dict[str, str]
    executable: OllamaPathEvidence
    models_directory: OllamaPathEvidence
    host: OllamaHostSnapshot
    port: int
    systemd_properties: tuple[tuple[str, str], ...]
    _provenance: bytes = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        expected_environment = _launcher_environment(self.host.effective_uid)
        if (
            self._seal is not _START_SEAL
            or not isinstance(self._provenance, bytes)
            or len(self._provenance) != 32
            or not _UNIT_NAME.fullmatch(self.unit_name)
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
            or not _valid_systemd_properties(self.systemd_properties)
            or self.launcher_environment != expected_environment
            or self.argv
            != _start_argv(
                self.unit_name,
                self.executable,
                self.models_directory,
                self.host,
                self.port,
                self.systemd_properties,
            )
        ):
            _fail("provider.operation_not_allowed")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RunningOllamaInstance:
    plan: OllamaLocalPlan
    unit_name: str
    port: int
    process: OllamaProcess
    ollama_pid: int
    control_group: str
    process_start_ticks: int
    _provenance: bytes = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self._seal is not _RUNNING_SEAL
            or not isinstance(self.plan, OllamaLocalPlan)
            or not _UNIT_NAME.fullmatch(self.unit_name)
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
            or type(self.ollama_pid) is not int
            or self.ollama_pid < 1
            or not isinstance(self.control_group, str)
            or not self.control_group.startswith("/")
            or "\n" in self.control_group
            or type(self.process_start_ticks) is not int
            or self.process_start_ticks < 1
            or not isinstance(self._provenance, bytes)
            or len(self._provenance) != 32
        ):
            _fail("provider.instance_invalid")


@dataclass(frozen=True, slots=True)
class OllamaStopRequest:
    unit_name: str
    process: OllamaProcess
    ollama_pid: int
    control_group: str
    process_start_ticks: int
    _provenance: bytes = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self._seal is not _STOP_SEAL
            or not isinstance(self._provenance, bytes)
            or len(self._provenance) != 32
            or not _UNIT_NAME.fullmatch(self.unit_name)
            or type(self.ollama_pid) is not int
            or self.ollama_pid < 1
            or not self.control_group.startswith("/")
            or type(self.process_start_ticks) is not int
            or self.process_start_ticks < 1
        ):
            _fail("provider.operation_not_allowed")


@dataclass(frozen=True, slots=True)
class OllamaReadinessStatus:
    ready: bool
    reason_codes: tuple[str, ...]
    process_running: bool
    cgroup_member: bool
    loopback_endpoint_reachable: bool
    available_model_ids: tuple[str, ...]


class OllamaProcess(Protocol):
    pid: int

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...


@dataclass(frozen=True, slots=True)
class _AdoptedProcess:
    pid: int
    start_ticks: int

    def poll(self) -> int | None:
        try:
            return None if _process_start_ticks(self.pid) == self.start_ticks else 0
        except OSError:
            return 0

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("adopted-ollama", timeout)
            time.sleep(0.01)
        return 0


class OllamaRuntime(Protocol):
    def available_cpus(self) -> tuple[int, ...]: ...

    def allocate_loopback_port(self) -> int: ...

    def start_scope(self, request: OllamaStartRequest) -> OllamaProcess: ...

    def resolve_scope(
        self, request: OllamaStartRequest, process: OllamaProcess
    ) -> tuple[int, str, int]: ...

    def process_running(
        self, process: OllamaProcess, pid: int, start_ticks: int
    ) -> bool: ...

    def scope_process_matches(
        self, unit_name: str, pid: int, control_group: str, start_ticks: int
    ) -> bool: ...

    def listener_owned_by(self, pid: int, port: int) -> bool: ...

    def fetch_tags(
        self,
        pid: int,
        port: int,
        *,
        unit_name: str,
        control_group: str,
        start_ticks: int,
        timeout_seconds: float,
        max_bytes: int,
    ) -> set[str] | None: ...

    def cleanup_scope(self, request: OllamaStartRequest, process: OllamaProcess) -> None: ...

    def stop_scope(self, request: OllamaStopRequest) -> None: ...


class SystemOllamaRuntime:
    """Small argv-only adapter around kernel, systemd, and loopback HTTP."""

    def available_cpus(self) -> tuple[int, ...]:
        try:
            return tuple(sorted(os.sched_getaffinity(0)))
        except (AttributeError, OSError):
            _fail("resource.host_probe_unavailable")

    def allocate_loopback_port(self) -> int:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                return int(listener.getsockname()[1])
        except OSError:
            _fail("provider.loopback_allocation_failed")

    def start_scope(self, request: OllamaStartRequest) -> OllamaProcess:
        if not _recorded_start_request(request):
            _fail("provider.operation_not_allowed")
        request.__post_init__()
        try:
            return subprocess.Popen(
                request.argv,
                env=request.launcher_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                shell=False,
            )
        except OSError:
            _fail("provider.process_start_failed")

    def resolve_scope(
        self, request: OllamaStartRequest, process: OllamaProcess
    ) -> tuple[int, str, int]:
        deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
        while time.monotonic() < deadline and process.poll() is None:
            observed = self._scope_observation(request.unit_name)
            if observed is not None and _process_executable_is_pinned(observed[0]):
                return observed
            time.sleep(0.01)
        _fail("resource.scope_membership_invalid")

    def process_running(
        self, process: OllamaProcess, pid: int, start_ticks: int
    ) -> bool:
        try:
            return process.poll() is None and _process_start_ticks(pid) == start_ticks
        except (AttributeError, OSError):
            return False

    def scope_process_matches(
        self, unit_name: str, pid: int, control_group: str, start_ticks: int
    ) -> bool:
        if (
            not _UNIT_NAME.fullmatch(unit_name)
            or type(pid) is not int
            or pid < 1
            or not isinstance(control_group, str)
            or type(start_ticks) is not int
        ):
            return False
        return self._scope_observation(unit_name) == (pid, control_group, start_ticks)

    def _scope_observation(
        self, unit_name: str, *, deadline: float | None = None
    ) -> tuple[int, str, int] | None:
        try:
            timeout = (
                PROBE_TIMEOUT_SECONDS
                if deadline is None
                else _remaining_seconds(deadline)
            )
            result = subprocess.run(
                (
                    SYSTEMCTL_PATH,
                    "--user",
                    "--no-pager",
                    "show",
                    unit_name,
                    "--property=ControlGroup",
                ),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            if result.returncode != 0 or result.stderr or len(result.stdout) > _MAX_CGROUP_BYTES:
                return None
            lines = result.stdout.decode("ascii").splitlines()
            if len(lines) != 1 or any("=" not in line for line in lines):
                return None
            values = dict(line.split("=", 1) for line in lines)
            if set(values) != {"ControlGroup"}:
                return None
            control_group = values["ControlGroup"]
            pids = _cgroup_processes(control_group)
            if len(pids) != 1:
                return None
            leader = pids[0]
            if _process_control_group(leader) != control_group:
                return None
            return leader, control_group, _process_start_ticks(leader)
        except (OSError, ValueError, subprocess.SubprocessError, UnicodeDecodeError):
            return None

    def listener_owned_by(self, pid: int, port: int) -> bool:
        if type(pid) is not int or pid < 1 or type(port) is not int or not 1 <= port <= 65535:
            return False
        try:
            listener_inodes = _loopback_listener_inodes(port)
            return bool(listener_inodes) and _pid_owns_socket_inodes(
                pid, listener_inodes
            )
        except OSError:
            return False

    def fetch_tags(
        self,
        pid: int,
        port: int,
        *,
        unit_name: str,
        control_group: str,
        start_ticks: int,
        timeout_seconds: float,
        max_bytes: int,
    ) -> set[str] | None:
        if (
            type(pid) is not int
            or pid < 1
            or type(port) is not int
            or not 1 <= port <= 65535
            or not isinstance(unit_name, str)
            or _UNIT_NAME.fullmatch(unit_name) is None
            or not isinstance(control_group, str)
            or not control_group.startswith("/")
            or "\n" in control_group
            or type(start_ticks) is not int
            or start_ticks < 1
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= PROBE_TIMEOUT_SECONDS
            or type(max_bytes) is not int
            or not 1 <= max_bytes <= MAX_TAG_RESPONSE_BYTES
        ):
            return None
        deadline = time.monotonic() + float(timeout_seconds)
        try:
            with socket.create_connection(
                ("127.0.0.1", port), timeout=_remaining_seconds(deadline)
            ) as connection:
                client_port = int(connection.getsockname()[1])
                if not self._wait_for_connected_server_identity(
                    unit_name,
                    pid,
                    control_group,
                    start_ticks,
                    server_port=port,
                    client_port=client_port,
                    deadline=deadline,
                ):
                    return None
                connection.settimeout(_remaining_seconds(deadline))
                connection.sendall(
                    b"GET /api/tags HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Connection: close\r\n\r\n"
                )
                encoded = _read_http_response(
                    connection, deadline=deadline, max_body_bytes=max_bytes
                )
            if encoded is None:
                return None
            document = json.loads(encoded.decode("utf-8"))
            if type(document) is not dict or type(document.get("models")) is not list:
                return None
            models = document["models"]
            if len(models) > 1024:
                return None
            tags: set[str] = set()
            for model in models:
                if type(model) is not dict:
                    return None
                model_id = model.get("model", model.get("name"))
                if not isinstance(model_id, str) or not model_id:
                    return None
                tags.add(model_id)
            return tags
        except (OSError, TimeoutError, ValueError, json.JSONDecodeError):
            return None

    def _wait_for_connected_server_identity(
        self,
        unit_name: str,
        pid: int,
        control_group: str,
        start_ticks: int,
        *,
        server_port: int,
        client_port: int,
        deadline: float,
    ) -> bool:
        expected = (pid, control_group, start_ticks)
        while True:
            try:
                inodes = _connected_server_inodes(server_port, client_port)
                if inodes:
                    if self._scope_observation(unit_name, deadline=deadline) != expected:
                        return False
                    if _pid_owns_socket_inodes(pid, inodes):
                        current_start_ticks = _process_start_ticks(pid)
                        current_control_group = _process_control_group(pid)
                        return (
                            current_start_ticks == start_ticks
                            and current_control_group == control_group
                            and _process_start_ticks(pid) == start_ticks
                        )
                remaining = _remaining_seconds(deadline)
            except (OSError, TimeoutError):
                return False
            time.sleep(min(0.005, remaining))

    def cleanup_scope(self, request: OllamaStartRequest, process: OllamaProcess) -> None:
        if not _recorded_start_request(request):
            return
        try:
            self._stop_unit(request.unit_name)
        except OllamaRuntimeError:
            pass
        try:
            process.wait(timeout=1.0)
        except (OSError, subprocess.SubprocessError):
            pass

    def stop_scope(self, request: OllamaStopRequest) -> None:
        if not _recorded_stop_request(request):
            _fail("provider.operation_not_allowed")
        try:
            self._stop_unit(request.unit_name)
            request.process.wait(timeout=5.0)
        except OllamaRuntimeError:
            raise
        except (OSError, subprocess.SubprocessError):
            _fail("provider.process_stop_failed")

    def _stop_unit(self, unit_name: str) -> None:
        try:
            result = subprocess.run(
                (SYSTEMCTL_PATH, "--user", "--no-pager", "stop", unit_name),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5.0,
                check=False,
            )
            if result.returncode != 0:
                _fail("provider.process_stop_failed")
        except OllamaRuntimeError:
            raise
        except (OSError, subprocess.SubprocessError):
            _fail("provider.process_stop_failed")


def probe_ollama_host(*, runtime: OllamaRuntime | None = None) -> OllamaHostSnapshot:
    adapter = runtime or SystemOllamaRuntime()
    return OllamaHostSnapshot(
        available_cpus=adapter.available_cpus(),
        effective_uid=os.geteuid(),
        effective_gid=os.getegid(),
        supplementary_gids=tuple(sorted(set(os.getgroups()))),
    )


def plan_local_instance(
    instance: OllamaInstanceV1,
    host: OllamaHostSnapshot,
    *,
    registry: OllamaRegistryV1,
) -> OllamaLocalPlan:
    if (
        not isinstance(instance, OllamaInstanceV1)
        or instance.host_ref != "local"
        or not isinstance(registry, OllamaRegistryV1)
        or sum(candidate == instance for candidate in registry.instances) != 1
    ):
        _fail("provider.instance_invalid")
    if (
        not isinstance(host, OllamaHostSnapshot)
        or host.effective_uid != os.geteuid()
        or host.effective_gid != os.getegid()
        or host.supplementary_gids != tuple(sorted(set(os.getgroups())))
    ):
        _fail("resource.host_probe_invalid")
    by_ref = {model.ref: model for model in registry.models}
    try:
        selected_models = tuple(by_ref[ref] for ref in instance.selected_model_refs)
    except KeyError:
        _fail("provider.model_unavailable")
    if any(
        not model.installed or not model.hive_enabled or not model.simple_only
        for model in selected_models
    ):
        _fail("provider.model_unavailable")
    selected = tuple(model.provider_model_id for model in selected_models)
    try:
        profile = OllamaCpuProfile.parse(
            instance.allowed_cpus,
            instance.cpu_quota_percent,
            instance.cpu_weight,
            available_cpus=host.available_cpus,
        )
    except ResourceCgroupError as error:
        raise OllamaRuntimeError(str(error)) from None
    provenance = secrets.token_bytes(32)
    plan = OllamaLocalPlan(
        instance=instance,
        host=host,
        executable=_inspect_path(
            instance.ollama_executable,
            host=host,
            kind="executable",
        ),
        models_directory=_inspect_path(
            instance.models_directory,
            host=host,
            kind="models",
        ),
        cpu_profile=profile,
        selected_provider_model_ids=selected,
        _provenance=provenance,
        _seal=_PLAN_SEAL,
    )
    _register_weak(_PLAN_RECORDS, provenance, plan, _plan_state(plan))
    return plan


def start_local_instance(
    plan: OllamaLocalPlan, *, runtime: OllamaRuntime | None = None
) -> RunningOllamaInstance:
    if (
        not isinstance(plan, OllamaLocalPlan)
        or not _consume_weak(
            _PLAN_RECORDS, plan._provenance, plan, _plan_state(plan)
        )
    ):
        _fail("provider.plan_invalid")
    _revalidate_path(plan.executable, plan.host, kind="executable")
    _revalidate_path(plan.models_directory, plan.host, kind="models")
    adapter = runtime or SystemOllamaRuntime()
    port = adapter.allocate_loopback_port()
    if type(port) is not int or not 1 <= port <= 65535:
        _fail("provider.loopback_allocation_failed")
    unit_name = f"codex-master-ollama-{secrets.token_hex(16)}.scope"
    if not _UNIT_NAME.fullmatch(unit_name):
        _fail("resource.scope_invalid")
    properties = tuple(plan.cpu_profile.systemd_properties().items())
    request_provenance = secrets.token_bytes(32)
    request = OllamaStartRequest(
        unit_name=unit_name,
        argv=_start_argv(
            unit_name,
            plan.executable,
            plan.models_directory,
            plan.host,
            port,
            properties,
        ),
        launcher_environment=_launcher_environment(plan.host.effective_uid),
        executable=plan.executable,
        models_directory=plan.models_directory,
        host=plan.host,
        port=port,
        systemd_properties=properties,
        _provenance=request_provenance,
        _seal=_START_SEAL,
    )
    _register_strong(
        _START_RECORDS,
        request_provenance,
        request,
        _start_request_state(request),
    )
    process: OllamaProcess | None = None
    try:
        process = adapter.start_scope(request)
        pid, control_group, start_ticks = adapter.resolve_scope(request, process)
        if not adapter.process_running(process, pid, start_ticks):
            _fail("provider.process_start_failed")
        provenance = secrets.token_bytes(32)
        running = RunningOllamaInstance(
            plan=plan,
            unit_name=unit_name,
            port=port,
            process=process,
            ollama_pid=pid,
            control_group=control_group,
            process_start_ticks=start_ticks,
            _provenance=provenance,
            _seal=_RUNNING_SEAL,
        )
        _register_weak(
            _RUNNING_RECORDS, provenance, running, _running_state(running)
        )
        return running
    except BaseException as error:
        if process is not None:
            try:
                adapter.cleanup_scope(request, process)
            except BaseException:
                pass
        if isinstance(error, OllamaRuntimeError) or not isinstance(error, Exception):
            raise
        _fail("provider.process_start_failed")
    finally:
        _discard_strong(_START_RECORDS, request_provenance, request)


def ollama_plan_digest(plan: OllamaLocalPlan) -> str:
    """Return a stable semantic/evidence digest for a genuine live plan."""
    if not isinstance(plan, OllamaLocalPlan) or not _matches_weak(
        _PLAN_RECORDS, plan._provenance, plan, _plan_state(plan)
    ):
        _fail("provider.plan_invalid")
    encoded = json.dumps(
        _plan_state(plan), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def adopt_running_instance(
    plan: OllamaLocalPlan,
    *,
    unit_name: str,
    port: int,
    ollama_pid: int,
    control_group: str,
    process_start_ticks: int,
    runtime: OllamaRuntime | None = None,
) -> RunningOllamaInstance:
    """Adopt a persisted scope only after fresh plan and live identity checks."""
    if (
        not isinstance(plan, OllamaLocalPlan)
        or not _consume_weak(_PLAN_RECORDS, plan._provenance, plan, _plan_state(plan))
        or not _UNIT_NAME.fullmatch(unit_name)
        or type(port) is not int
        or not 1 <= port <= 65535
        or type(ollama_pid) is not int
        or ollama_pid < 1
        or type(control_group) is not str
        or not control_group.startswith("/")
        or "\n" in control_group
        or type(process_start_ticks) is not int
        or process_start_ticks < 1
    ):
        _fail("provider.instance_invalid")
    _revalidate_path(plan.executable, plan.host, kind="executable")
    _revalidate_path(plan.models_directory, plan.host, kind="models")
    adapter = runtime or SystemOllamaRuntime()
    process = _AdoptedProcess(ollama_pid, process_start_ticks)
    if not adapter.scope_process_matches(
        unit_name, ollama_pid, control_group, process_start_ticks
    ):
        _fail("resource.scope_membership_invalid")
    if not adapter.process_running(process, ollama_pid, process_start_ticks):
        _fail("provider.process_unavailable")
    if not adapter.listener_owned_by(ollama_pid, port):
        _fail("provider.endpoint_identity_invalid")
    provenance = secrets.token_bytes(32)
    running = RunningOllamaInstance(
        plan=plan,
        unit_name=unit_name,
        port=port,
        process=process,
        ollama_pid=ollama_pid,
        control_group=control_group,
        process_start_ticks=process_start_ticks,
        _provenance=provenance,
        _seal=_RUNNING_SEAL,
    )
    _register_weak(_RUNNING_RECORDS, provenance, running, _running_state(running))
    return running


def stop_local_instance(
    instance: RunningOllamaInstance, *, runtime: OllamaRuntime | None = None
) -> None:
    if not _claim_running(instance):
        _fail("provider.instance_invalid")
    adapter = runtime or SystemOllamaRuntime()
    stopped = False
    try:
        if not adapter.scope_process_matches(
            instance.unit_name,
            instance.ollama_pid,
            instance.control_group,
            instance.process_start_ticks,
        ):
            _fail("resource.scope_membership_invalid")
        request_provenance = secrets.token_bytes(32)
        request = OllamaStopRequest(
            unit_name=instance.unit_name,
            process=instance.process,
            ollama_pid=instance.ollama_pid,
            control_group=instance.control_group,
            process_start_ticks=instance.process_start_ticks,
            _provenance=request_provenance,
            _seal=_STOP_SEAL,
        )
        _register_strong(
            _STOP_RECORDS,
            request_provenance,
            request,
            _stop_request_state(request),
        )
        try:
            adapter.stop_scope(request)
        finally:
            _discard_strong(_STOP_RECORDS, request_provenance, request)
        stopped = True
    finally:
        _finish_running_claim(instance, stopped=stopped)


def probe_instance_readiness(
    instance: RunningOllamaInstance, *, runtime: OllamaRuntime | None = None
) -> OllamaReadinessStatus:
    if not _recorded_running(instance):
        _fail("provider.instance_invalid")
    adapter = runtime or SystemOllamaRuntime()
    process_running = adapter.process_running(
        instance.process, instance.ollama_pid, instance.process_start_ticks
    )
    if not process_running:
        return _readiness(reason="provider.process_unavailable")
    cgroup_member = adapter.scope_process_matches(
        instance.unit_name,
        instance.ollama_pid,
        instance.control_group,
        instance.process_start_ticks,
    )
    if not cgroup_member:
        return _readiness(
            reason="resource.scope_membership_invalid", process_running=True
        )
    if not adapter.listener_owned_by(instance.ollama_pid, instance.port):
        return _readiness(
            reason="provider.endpoint_identity_invalid",
            process_running=True,
            cgroup_member=True,
        )
    tags = adapter.fetch_tags(
        instance.ollama_pid,
        instance.port,
        unit_name=instance.unit_name,
        control_group=instance.control_group,
        start_ticks=instance.process_start_ticks,
        timeout_seconds=PROBE_TIMEOUT_SECONDS,
        max_bytes=MAX_TAG_RESPONSE_BYTES,
    )
    if tags is None:
        return _readiness(
            reason="provider.endpoint_unavailable",
            process_running=True,
            cgroup_member=True,
        )
    if not adapter.process_running(
        instance.process, instance.ollama_pid, instance.process_start_ticks
    ):
        return _readiness(reason="provider.process_unavailable")
    if not adapter.scope_process_matches(
        instance.unit_name,
        instance.ollama_pid,
        instance.control_group,
        instance.process_start_ticks,
    ):
        return _readiness(
            reason="resource.scope_membership_invalid", process_running=True
        )
    available = tuple(sorted(tags))
    if not set(instance.plan.selected_provider_model_ids).issubset(tags):
        return _readiness(
            reason="provider.model_unavailable",
            process_running=True,
            cgroup_member=True,
            endpoint=True,
            available=available,
        )
    return OllamaReadinessStatus(
        ready=True,
        reason_codes=(),
        process_running=True,
        cgroup_member=True,
        loopback_endpoint_reachable=True,
        available_model_ids=available,
    )


def _readiness(
    *,
    reason: str,
    process_running: bool = False,
    cgroup_member: bool = False,
    endpoint: bool = False,
    available: tuple[str, ...] = (),
) -> OllamaReadinessStatus:
    return OllamaReadinessStatus(
        ready=False,
        reason_codes=(reason,),
        process_running=process_running,
        cgroup_member=cgroup_member,
        loopback_endpoint_reachable=endpoint,
        available_model_ids=available,
    )


def _canonical_path(value: str) -> Path:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in value.split("/")[1:])
    ):
        _fail("resource.target_path_invalid")
    try:
        path = Path(value)
    except (TypeError, ValueError):
        _fail("resource.target_path_invalid")
    if (
        not path.is_absolute()
        or path == Path("/")
        or str(path) != value
    ):
        _fail("resource.target_path_invalid")
    return path


def _valid_systemd_properties(value: object) -> bool:
    if type(value) is not tuple or len(value) != 3:
        return False
    try:
        allowed, quota, weight = value
        return (
            allowed[0] == "AllowedCPUs"
            and quota[0] == "CPUQuota"
            and weight[0] == "CPUWeight"
            and _CPU_PROPERTY.fullmatch(f"--property=AllowedCPUs={allowed[1]}")
            is not None
            and (quota_match := _QUOTA_PROPERTY.fullmatch(f"--property=CPUQuota={quota[1]}"))
            is not None
            and (weight_match := _WEIGHT_PROPERTY.fullmatch(f"--property=CPUWeight={weight[1]}"))
            is not None
            and int(quota_match.group(1)) <= 10000
            and int(weight_match.group(1)) <= 10000
        )
    except (IndexError, TypeError, ValueError):
        return False


def _launcher_environment(effective_uid: int) -> dict[str, str]:
    runtime_directory = f"/run/user/{effective_uid}"
    return {
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_directory}/bus",
        "XDG_RUNTIME_DIR": runtime_directory,
    }


def _start_argv(
    unit_name: str,
    executable: OllamaPathEvidence,
    models_directory: OllamaPathEvidence,
    host: OllamaHostSnapshot,
    port: int,
    properties: tuple[tuple[str, str], ...],
) -> tuple[str, ...]:
    payload = json.dumps(
        {
            "schema": 1,
            "executable": _path_evidence_document(executable),
            "models_directory": _path_evidence_document(models_directory),
            "host": {
                "available_cpus": list(host.available_cpus),
                "effective_uid": host.effective_uid,
                "effective_gid": host.effective_gid,
                "supplementary_gids": list(host.supplementary_gids),
            },
            "port": port,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return (
        SYSTEMD_RUN_PATH,
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        f"--unit={unit_name}",
        f"--slice={OLLAMA_SLICE}",
        *(f"--property={name}={value}" for name, value in properties),
        f"/proc/{os.getpid()}/exe",
        "-I",
        "-P",
        "-c",
        _EXEC_HELPER_SOURCE,
        payload,
    )


def _path_evidence_document(evidence: OllamaPathEvidence) -> dict[str, object]:
    return {
        "path": evidence.path,
        "device": evidence.device,
        "inode": evidence.inode,
        "mode": evidence.mode,
        "owner_uid": evidence.owner_uid,
        "owner_gid": evidence.owner_gid,
        "link_count": evidence.link_count,
        "size": evidence.size,
        "mtime_ns": evidence.mtime_ns,
        "ctime_ns": evidence.ctime_ns,
        "sha256": evidence.sha256,
        "ancestors": [
            {
                "path": ancestor.path,
                "device": ancestor.device,
                "inode": ancestor.inode,
                "mode": ancestor.mode,
                "owner_uid": ancestor.owner_uid,
                "owner_gid": ancestor.owner_gid,
            }
            for ancestor in evidence.ancestors
        ],
    }


def _recorded_running(instance: object) -> bool:
    if not isinstance(instance, RunningOllamaInstance) or instance._seal is not _RUNNING_SEAL:
        return False
    with _RECORD_LOCK:
        return (
            instance._provenance not in _RUNNING_CLAIMS
            and _matches_weak(
                _RUNNING_RECORDS,
                instance._provenance,
                instance,
                _running_state(instance),
            )
        )


def _recorded_start_request(request: object) -> bool:
    return (
        isinstance(request, OllamaStartRequest)
        and request._seal is _START_SEAL
        and _matches_strong(
            _START_RECORDS,
            request._provenance,
            request,
            _start_request_state(request),
        )
    )


def _recorded_stop_request(request: object) -> bool:
    return (
        isinstance(request, OllamaStopRequest)
        and request._seal is _STOP_SEAL
        and _matches_strong(
            _STOP_RECORDS,
            request._provenance,
            request,
            _stop_request_state(request),
        )
    )


def _register_weak(
    records: dict[bytes, tuple[weakref.ReferenceType[object], tuple[object, ...]]],
    provenance: bytes,
    value: object,
    state: tuple[object, ...],
) -> None:
    def discard(reference: weakref.ReferenceType[object]) -> None:
        with _RECORD_LOCK:
            current = records.get(provenance)
            if current is not None and current[0] is reference:
                records.pop(provenance, None)
                if records is _RUNNING_RECORDS:
                    _RUNNING_CLAIMS.discard(provenance)

    with _RECORD_LOCK:
        records[provenance] = (weakref.ref(value, discard), state)


def _matches_weak(
    records: dict[bytes, tuple[weakref.ReferenceType[object], tuple[object, ...]]],
    provenance: bytes,
    value: object,
    state: tuple[object, ...],
) -> bool:
    with _RECORD_LOCK:
        record = records.get(provenance)
        return record is not None and record[0]() is value and record[1] == state


def _consume_weak(
    records: dict[bytes, tuple[weakref.ReferenceType[object], tuple[object, ...]]],
    provenance: bytes,
    value: object,
    state: tuple[object, ...],
) -> bool:
    with _RECORD_LOCK:
        record = records.get(provenance)
        if record is None or record[0]() is not value or record[1] != state:
            return False
        del records[provenance]
        return True


def _plan_state(plan: OllamaLocalPlan) -> tuple[object, ...]:
    return (
        astuple(plan.instance),
        astuple(plan.host),
        astuple(plan.executable),
        astuple(plan.models_directory),
        astuple(plan.cpu_profile),
        plan.selected_provider_model_ids,
    )


def _running_state(instance: RunningOllamaInstance) -> tuple[object, ...]:
    return (
        _plan_state(instance.plan),
        instance.unit_name,
        instance.port,
        _ObjectIdentity(instance.process),
        instance.ollama_pid,
        instance.control_group,
        instance.process_start_ticks,
    )


def _claim_running(instance: object) -> bool:
    if not isinstance(instance, RunningOllamaInstance) or instance._seal is not _RUNNING_SEAL:
        return False
    with _RECORD_LOCK:
        if (
            instance._provenance in _RUNNING_CLAIMS
            or not _matches_weak(
                _RUNNING_RECORDS,
                instance._provenance,
                instance,
                _running_state(instance),
            )
        ):
            return False
        _RUNNING_CLAIMS.add(instance._provenance)
        return True


def _finish_running_claim(
    instance: RunningOllamaInstance, *, stopped: bool
) -> None:
    with _RECORD_LOCK:
        _RUNNING_CLAIMS.discard(instance._provenance)
        if stopped:
            _RUNNING_RECORDS.pop(instance._provenance, None)


def _register_strong(
    records: dict[bytes, tuple[object, tuple[object, ...]]],
    provenance: bytes,
    value: object,
    state: tuple[object, ...],
) -> None:
    with _RECORD_LOCK:
        records[provenance] = (value, state)


def _matches_strong(
    records: dict[bytes, tuple[object, tuple[object, ...]]],
    provenance: bytes,
    value: object,
    state: tuple[object, ...],
) -> bool:
    with _RECORD_LOCK:
        record = records.get(provenance)
        return record is not None and record[0] is value and record[1] == state


def _discard_strong(
    records: dict[bytes, tuple[object, tuple[object, ...]]],
    provenance: bytes,
    value: object,
) -> None:
    with _RECORD_LOCK:
        record = records.get(provenance)
        if record is not None and record[0] is value:
            records.pop(provenance, None)


def _start_request_state(request: OllamaStartRequest) -> tuple[object, ...]:
    return (
        request.unit_name,
        request.argv,
        tuple(sorted(request.launcher_environment.items())),
        astuple(request.executable),
        astuple(request.models_directory),
        astuple(request.host),
        request.port,
        request.systemd_properties,
    )


def _stop_request_state(request: OllamaStopRequest) -> tuple[object, ...]:
    return (
        request.unit_name,
        _ObjectIdentity(request.process),
        request.ollama_pid,
        request.control_group,
        request.process_start_ticks,
    )


def _inspect_path(value: str, *, host: OllamaHostSnapshot, kind: str) -> OllamaPathEvidence:
    descriptor = -1
    try:
        descriptor, evidence = _open_validated_path(value, host=host, kind=kind)
        return evidence
    except OllamaRuntimeError:
        raise
    except OSError:
        _fail("resource.target_path_invalid")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_validated_path(
    value: str, *, host: OllamaHostSnapshot, kind: str
) -> tuple[int, OllamaPathEvidence]:
    path = _canonical_path(value)
    descriptor, metadata, ancestors = _open_path_chain(
        path, directory=kind == "models", host=host
    )
    try:
        mode = stat.S_IMODE(metadata.st_mode)
        trusted_owner = metadata.st_uid in {0, host.effective_uid}
        if kind == "executable":
            valid = (
                stat.S_ISREG(metadata.st_mode)
                and trusted_owner
                and not bool(mode & 0o022)
                and _effective_access(metadata, host, read=True, execute=True)
                and (metadata.st_uid == 0 or metadata.st_nlink == 1)
                and 0 < metadata.st_size <= _MAX_EXECUTABLE_BYTES
            )
            digest = _digest_descriptor(descriptor, expected=metadata) if valid else None
        else:
            private_user_directory = (
                metadata.st_uid == host.effective_uid and mode == 0o700
            )
            administrative_directory = (
                metadata.st_uid == 0 and not bool(mode & 0o022)
            )
            valid = (
                stat.S_ISDIR(metadata.st_mode)
                and trusted_owner
                and _effective_access(metadata, host, read=True, execute=True)
                and (private_user_directory or administrative_directory)
            )
            digest = None
        if not valid:
            _fail("resource.target_path_invalid")
        evidence = OllamaPathEvidence(
            path=str(path),
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            owner_uid=metadata.st_uid,
            owner_gid=metadata.st_gid,
            link_count=metadata.st_nlink,
            size=metadata.st_size,
            mtime_ns=metadata.st_mtime_ns,
            ctime_ns=metadata.st_ctime_ns,
            sha256=digest,
            ancestors=ancestors,
        )
        return descriptor, evidence
    except Exception:
        os.close(descriptor)
        raise


def _open_path_chain(
    path: Path, *, directory: bool, host: OllamaHostSnapshot
) -> tuple[int, os.stat_result, tuple[OllamaAncestorEvidence, ...]]:
    descriptor = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    ancestors: list[OllamaAncestorEvidence] = []
    current = Path("/")
    try:
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            metadata = os.fstat(descriptor)
            _validate_ancestor(current, metadata, host)
            ancestors.append(_ancestor_evidence(current, metadata))
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if not final or directory:
                flags |= os.O_DIRECTORY
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            current /= part
        metadata = os.fstat(descriptor)
        if stat.S_ISLNK(metadata.st_mode):
            _fail("resource.target_path_invalid")
        return descriptor, metadata, tuple(ancestors)
    except Exception:
        os.close(descriptor)
        raise


def _ancestor_evidence(path: Path, metadata: os.stat_result) -> OllamaAncestorEvidence:
    return OllamaAncestorEvidence(
        path=str(path),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        owner_uid=metadata.st_uid,
        owner_gid=metadata.st_gid,
    )


def _validate_ancestor(
    path: Path, metadata: os.stat_result, host: OllamaHostSnapshot
) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    writable = bool(mode & 0o022)
    trusted_sticky = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, host.effective_uid}
        or not _effective_access(metadata, host, read=False, execute=True)
        or (writable and not trusted_sticky)
        or not path.is_absolute()
    ):
        _fail("resource.target_path_invalid")


def _effective_access(
    metadata: os.stat_result,
    host: OllamaHostSnapshot,
    *,
    read: bool,
    execute: bool,
) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    required = (0o4 if read else 0) | (0o1 if execute else 0)
    if host.effective_uid == 0:
        return (not execute or bool(mode & 0o111))
    if metadata.st_uid == host.effective_uid:
        granted = (mode >> 6) & 0o7
    elif metadata.st_gid in {host.effective_gid, *host.supplementary_gids}:
        granted = (mode >> 3) & 0o7
    else:
        granted = mode & 0o7
    return granted & required == required


def _digest_descriptor(
    descriptor: int, *, expected: os.stat_result
) -> str:
    before = os.fstat(descriptor)
    if _stable_file_identity(before) != _stable_file_identity(expected):
        _fail("resource.target_path_invalid")
    digest = hashlib.sha256()
    total = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(
        descriptor, min(1024 * 1024, _MAX_EXECUTABLE_BYTES - total + 1)
    ):
        total += len(chunk)
        if total > _MAX_EXECUTABLE_BYTES:
            _fail("resource.target_path_invalid")
        digest.update(chunk)
    after = os.fstat(descriptor)
    if (
        total != before.st_size
        or _stable_file_identity(after) != _stable_file_identity(before)
    ):
        _fail("resource.target_path_invalid")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _revalidate_path(
    expected: OllamaPathEvidence, host: OllamaHostSnapshot, *, kind: str
) -> None:
    try:
        current = _inspect_path(expected.path, host=host, kind=kind)
    except OllamaRuntimeError:
        _fail("resource.target_path_changed")
    if current != expected:
        _fail("resource.target_path_changed")


def _exec_pinned(
    executable: OllamaPathEvidence,
    models_directory: OllamaPathEvidence,
    host: OllamaHostSnapshot,
    *,
    port: int,
) -> NoReturn:
    source_fd = -1
    pinned_fd = -1
    models_fd = -1
    try:
        source_fd, current_executable = _open_validated_path(
            executable.path, host=host, kind="executable"
        )
        models_fd, current_models = _open_validated_path(
            models_directory.path, host=host, kind="models"
        )
        if current_executable != executable or current_models != models_directory:
            _fail("resource.target_path_changed")
        pinned_fd = _copy_executable_to_memfd(source_fd, expected=executable)
        os.set_inheritable(models_fd, True)
        os.execve(
            pinned_fd,
            (executable.path, "serve"),
            {
                "OLLAMA_HOST": f"127.0.0.1:{port}",
                "OLLAMA_MODELS": f"/proc/self/fd/{models_fd}",
            },
        )
    except OllamaRuntimeError:
        raise
    except OSError:
        _fail("provider.process_start_failed")
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if pinned_fd >= 0:
            os.close(pinned_fd)
        if models_fd >= 0:
            os.close(models_fd)
    raise AssertionError("unreachable")


def _copy_executable_to_memfd(
    source_fd: int, *, expected: OllamaPathEvidence
) -> int:
    pinned_fd = -1
    try:
        before = os.fstat(source_fd)
        if (
            _stable_file_identity(before)
            != _evidence_file_identity(expected)
            or expected.sha256 is None
        ):
            _fail("resource.target_path_changed")
        pinned_fd = os.memfd_create(
            "codex-master-ollama-executable",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        digest = hashlib.sha256()
        total = 0
        os.lseek(source_fd, 0, os.SEEK_SET)
        while chunk := os.read(
            source_fd, min(1024 * 1024, _MAX_EXECUTABLE_BYTES - total + 1)
        ):
            total += len(chunk)
            if total > _MAX_EXECUTABLE_BYTES:
                _fail("resource.target_path_changed")
            digest.update(chunk)
            _write_all(pinned_fd, chunk)
        after = os.fstat(source_fd)
        if (
            total != before.st_size
            or digest.hexdigest() != expected.sha256
            or _stable_file_identity(after) != _stable_file_identity(before)
        ):
            _fail("resource.target_path_changed")
        os.fchmod(pinned_fd, 0o500)
        os.lseek(pinned_fd, 0, os.SEEK_SET)
        fcntl.fcntl(
            pinned_fd,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
        return pinned_fd
    except BaseException:
        if pinned_fd >= 0:
            os.close(pinned_fd)
        raise


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("short memfd write")
        offset += written


def _evidence_file_identity(evidence: OllamaPathEvidence) -> tuple[int, ...]:
    return (
        evidence.device,
        evidence.inode,
        evidence.mode,
        evidence.owner_uid,
        evidence.owner_gid,
        evidence.link_count,
        evidence.size,
        evidence.mtime_ns,
        evidence.ctime_ns,
    )


def _process_control_group(pid: int) -> str:
    with open(f"/proc/{pid}/cgroup", "rb", buffering=0) as stream:
        raw = stream.read(_MAX_CGROUP_BYTES + 1)
    if len(raw) > _MAX_CGROUP_BYTES:
        raise OSError("cgroup evidence too large")
    lines = raw.decode("ascii").splitlines()
    matches = [line.removeprefix("0::") for line in lines if line.startswith("0::/")]
    if len(matches) != 1:
        raise OSError("cgroup evidence invalid")
    return matches[0]


def _cgroup_processes(control_group: str) -> tuple[int, ...]:
    if (
        not isinstance(control_group, str)
        or not control_group.startswith("/")
        or len(control_group) > 4096
    ):
        raise OSError("control group invalid")
    parts = control_group.removeprefix("/").split("/")
    if (
        not parts
        or len(parts) > 64
        or any(
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}", part)
            for part in parts
        )
    ):
        raise OSError("control group invalid")
    path = CGROUP_ROOT.joinpath(*parts, "cgroup.procs")
    with open(path, "rb", buffering=0) as stream:
        raw = stream.read(_MAX_CGROUP_BYTES + 1)
    if len(raw) > _MAX_CGROUP_BYTES:
        raise OSError("cgroup process evidence too large")
    lines = raw.decode("ascii").splitlines()
    if not lines:
        return ()
    pids = tuple(int(line) for line in lines)
    if any(pid < 1 for pid in pids) or len(set(pids)) != len(pids):
        raise OSError("cgroup process evidence invalid")
    return pids


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _read_http_response(
    connection: socket.socket, *, deadline: float, max_body_bytes: int
) -> bytes | None:
    maximum = 16 * 1024 + max_body_bytes + 16 * 1024
    raw = bytearray()
    while len(raw) <= maximum:
        connection.settimeout(_remaining_seconds(deadline))
        chunk = connection.recv(min(8192, maximum + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
        header_end = raw.find(b"\r\n\r\n")
        if header_end >= 0:
            header = bytes(raw[:header_end])
            if len(header) > 16 * 1024:
                return None
            headers = _http_headers(header)
            if headers is None:
                return None
            body_size = len(raw) - header_end - 4
            length = headers.get("content-length")
            if length is not None and length.isdigit() and body_size >= int(length):
                break
            if headers.get("transfer-encoding") == "chunked" and raw.endswith(b"0\r\n\r\n"):
                break
    if len(raw) > maximum:
        return None
    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0 or header_end > 16 * 1024:
        return None
    headers = _http_headers(bytes(raw[:header_end]))
    if headers is None:
        return None
    body = bytes(raw[header_end + 4 :])
    transfer_encoding = headers.get("transfer-encoding")
    content_length = headers.get("content-length")
    if transfer_encoding is not None:
        if transfer_encoding != "chunked" or content_length is not None:
            return None
        decoded = _decode_chunked_body(body, max_body_bytes)
        if decoded is None:
            return None
        body = decoded
    elif content_length is not None:
        if not content_length.isascii() or not content_length.isdigit():
            return None
        expected = int(content_length)
        if expected > max_body_bytes or len(body) != expected:
            return None
    if len(body) > max_body_bytes:
        return None
    return body


def _http_headers(raw: bytes) -> dict[str, str] | None:
    try:
        lines = raw.decode("ascii").split("\r\n")
    except UnicodeDecodeError:
        return None
    if not lines or lines[0] not in {"HTTP/1.0 200 OK", "HTTP/1.1 200 OK"}:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            return None
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip().lower()
        if not name or name in headers or "\x00" in value:
            return None
        headers[name] = value
    return headers


def _decode_chunked_body(raw: bytes, maximum: int) -> bytes | None:
    offset = 0
    decoded = bytearray()
    while True:
        line_end = raw.find(b"\r\n", offset)
        if line_end < 0 or line_end - offset > 16:
            return None
        size_text = raw[offset:line_end].split(b";", 1)[0]
        try:
            size = int(size_text, 16)
        except ValueError:
            return None
        offset = line_end + 2
        if size == 0:
            return bytes(decoded) if raw[offset:] == b"\r\n" else None
        if size < 0 or len(decoded) + size > maximum or offset + size + 2 > len(raw):
            return None
        decoded.extend(raw[offset : offset + size])
        offset += size
        if raw[offset : offset + 2] != b"\r\n":
            return None
        offset += 2


def _process_start_ticks(pid: int) -> int:
    with open(f"/proc/{pid}/stat", "rb", buffering=0) as stream:
        raw = stream.read(_MAX_CGROUP_BYTES + 1)
    if len(raw) > _MAX_CGROUP_BYTES:
        raise OSError("process evidence too large")
    text = raw.decode("ascii")
    end = text.rfind(")")
    if end < 0:
        raise OSError("process evidence invalid")
    fields = text[end + 2 :].split()
    if len(fields) < 20:
        raise OSError("process evidence invalid")
    start_ticks = int(fields[19])
    if start_ticks < 1:
        raise OSError("process evidence invalid")
    return start_ticks


def _process_executable_is_pinned(pid: int) -> bool:
    try:
        target = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return False
    return target.startswith("/memfd:codex-master-ollama-executable")


def _loopback_listener_inodes(port: int) -> set[str]:
    target = f"0100007F:{port:04X}"
    with open("/proc/net/tcp", "rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise OSError("tcp evidence too large")
    inodes: set[str] = set()
    for line in raw.decode("ascii").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 10 and fields[1] == target and fields[3] == "0A":
            inodes.add(fields[9])
    return inodes


def _connected_server_inodes(server_port: int, client_port: int) -> set[str]:
    local = f"0100007F:{server_port:04X}"
    remote = f"0100007F:{client_port:04X}"
    with open("/proc/net/tcp", "rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise OSError("tcp evidence too large")
    inodes: set[str] = set()
    for line in raw.decode("ascii").splitlines()[1:]:
        fields = line.split()
        if (
            len(fields) >= 10
            and fields[1] == local
            and fields[2] == remote
            and fields[3] == "01"
        ):
            inodes.add(fields[9])
    return inodes


def _pid_owns_socket_inodes(pid: int, inodes: set[str]) -> bool:
    descriptors = tuple((Path("/proc") / str(pid) / "fd").iterdir())
    if len(descriptors) > 4096:
        return False
    for descriptor in descriptors:
        try:
            target = os.readlink(descriptor)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r"socket:\[([0-9]+)\]", target)
        if match is not None and match.group(1) in inodes:
            return True
    return False


def _run_exec_helper(payload: str) -> NoReturn:
    if not isinstance(payload, str) or len(payload.encode("utf-8")) > 64 * 1024:
        _fail("provider.operation_not_allowed")
    try:
        document = json.loads(payload)
        if type(document) is not dict or set(document) != {
            "schema",
            "executable",
            "models_directory",
            "host",
            "port",
        }:
            _fail("provider.operation_not_allowed")
        if document["schema"] != 1:
            _fail("provider.operation_not_allowed")
        host_document = document["host"]
        if type(host_document) is not dict or set(host_document) != {
            "available_cpus",
            "effective_uid",
            "effective_gid",
            "supplementary_gids",
        }:
            _fail("provider.operation_not_allowed")
        available_cpus = host_document["available_cpus"]
        supplementary_gids = host_document["supplementary_gids"]
        if type(available_cpus) is not list or type(supplementary_gids) is not list:
            _fail("provider.operation_not_allowed")
        host = OllamaHostSnapshot(
            available_cpus=tuple(available_cpus),
            effective_uid=_document_int(host_document["effective_uid"]),
            effective_gid=_document_int(host_document["effective_gid"]),
            supplementary_gids=tuple(supplementary_gids),
        )
        if (
            host.effective_uid != os.geteuid()
            or host.effective_gid != os.getegid()
            or host.supplementary_gids != tuple(sorted(set(os.getgroups())))
        ):
            _fail("provider.operation_not_allowed")
        _exec_pinned(
            _path_evidence_from_document(document["executable"]),
            _path_evidence_from_document(document["models_directory"]),
            host,
            port=_document_int(document["port"], maximum=65535, minimum=1),
        )
    except OllamaRuntimeError:
        raise
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        _fail("provider.operation_not_allowed")
    raise AssertionError("unreachable")


def _path_evidence_from_document(value: object) -> OllamaPathEvidence:
    keys = {
        "path",
        "device",
        "inode",
        "mode",
        "owner_uid",
        "owner_gid",
        "link_count",
        "size",
        "mtime_ns",
        "ctime_ns",
        "sha256",
        "ancestors",
    }
    if type(value) is not dict or set(value) != keys:
        _fail("provider.operation_not_allowed")
    ancestors = value["ancestors"]
    if type(ancestors) is not list or not ancestors or len(ancestors) > 64:
        _fail("provider.operation_not_allowed")
    parsed_ancestors: list[OllamaAncestorEvidence] = []
    for ancestor in ancestors:
        if type(ancestor) is not dict or set(ancestor) != {
            "path",
            "device",
            "inode",
            "mode",
            "owner_uid",
            "owner_gid",
        }:
            _fail("provider.operation_not_allowed")
        path = ancestor["path"]
        if not isinstance(path, str) or not path.startswith("/"):
            _fail("provider.operation_not_allowed")
        parsed_ancestors.append(
            OllamaAncestorEvidence(
                path=path,
                device=_document_int(ancestor["device"]),
                inode=_document_int(ancestor["inode"], minimum=1),
                mode=_document_int(ancestor["mode"], minimum=1),
                owner_uid=_document_int(ancestor["owner_uid"]),
                owner_gid=_document_int(ancestor["owner_gid"]),
            )
        )
    path = value["path"]
    sha256 = value["sha256"]
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or (sha256 is not None and (not isinstance(sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", sha256)))
    ):
        _fail("provider.operation_not_allowed")
    return OllamaPathEvidence(
        path=path,
        device=_document_int(value["device"]),
        inode=_document_int(value["inode"], minimum=1),
        mode=_document_int(value["mode"], minimum=1),
        owner_uid=_document_int(value["owner_uid"]),
        owner_gid=_document_int(value["owner_gid"]),
        link_count=_document_int(value["link_count"], minimum=1),
        size=_document_int(value["size"]),
        mtime_ns=_document_int(value["mtime_ns"]),
        ctime_ns=_document_int(value["ctime_ns"]),
        sha256=sha256,
        ancestors=tuple(parsed_ancestors),
    )


def _document_int(value: object, *, minimum: int = 0, maximum: int = (1 << 63) - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("provider.operation_not_allowed")
    return value


def _helper_main(arguments: tuple[str, ...]) -> int:
    if len(arguments) != 2 or arguments[0] != "--exec-pinned":
        return 125
    try:
        _run_exec_helper(arguments[1])
    except OllamaRuntimeError:
        return 125
    except Exception:
        return 126
    return 126


if __name__ == "__main__":
    raise SystemExit(_helper_main(tuple(sys.argv[1:])))
