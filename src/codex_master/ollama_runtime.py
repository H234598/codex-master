"""Bounded local Ollama path, process, and readiness runtime."""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
from typing import Mapping, NoReturn, Protocol

from codex_master.ollama_registry import OllamaInstanceV1
from codex_master.resource_cgroup import (
    OllamaCpuProfile,
    ResourceCgroupError,
)


SYSTEMD_RUN_PATH = "/usr/bin/systemd-run"
SYSTEMCTL_PATH = "/usr/bin/systemctl"
OLLAMA_SLICE = "codex-master.slice"
PROBE_TIMEOUT_SECONDS = 2.0
MAX_TAG_RESPONSE_BYTES = 64 * 1024
_MAX_CGROUP_BYTES = 4096
_UNIT_NAME = re.compile(r"^codex-master-ollama-[a-f0-9]{32}\.scope$")
_CPU_PROPERTY = re.compile(
    r"^--property=AllowedCPUs=(?:0|[1-9][0-9]*)(?:-(?:[1-9][0-9]*))?"
    r"(?:,(?:0|[1-9][0-9]*)(?:-(?:[1-9][0-9]*))?)*$"
)
_QUOTA_PROPERTY = re.compile(r"^--property=CPUQuota=([1-9][0-9]{0,4})%$")
_WEIGHT_PROPERTY = re.compile(r"^--property=CPUWeight=([1-9][0-9]{0,4})$")
_LOOPBACK_HOST = re.compile(r"^127\.0\.0\.1:([1-9][0-9]{0,4})$")


class OllamaRuntimeError(RuntimeError):
    """Code-only local runtime failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> NoReturn:
    raise OllamaRuntimeError(code) from None


@dataclass(frozen=True, slots=True)
class OllamaHostSnapshot:
    available_cpus: tuple[int, ...]
    effective_uid: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.available_cpus, tuple)
            or not self.available_cpus
            or any(type(cpu) is not int or cpu < 0 for cpu in self.available_cpus)
            or tuple(sorted(set(self.available_cpus))) != self.available_cpus
            or type(self.effective_uid) is not int
            or self.effective_uid < 0
        ):
            _fail("resource.host_probe_invalid")


@dataclass(frozen=True, slots=True)
class OllamaPathEvidence:
    path: str
    device: int
    inode: int
    mode: int
    owner_uid: int


@dataclass(frozen=True, slots=True)
class OllamaLocalPlan:
    instance: OllamaInstanceV1
    host: OllamaHostSnapshot
    executable: OllamaPathEvidence
    models_directory: OllamaPathEvidence
    cpu_profile: OllamaCpuProfile
    selected_provider_model_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RunningOllamaInstance:
    plan: OllamaLocalPlan
    unit_name: str
    port: int
    process: OllamaProcess


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


class OllamaRuntime(Protocol):
    def available_cpus(self) -> tuple[int, ...]: ...

    def allocate_loopback_port(self) -> int: ...

    def start_scope(
        self, argv: tuple[str, ...], environment: dict[str, str]
    ) -> OllamaProcess: ...

    def process_running(self, process: object) -> bool: ...

    def scope_contains(self, unit_name: str, pid: int) -> bool: ...

    def fetch_tags(
        self, port: int, *, timeout_seconds: float, max_bytes: int
    ) -> set[str] | None: ...

    def stop_scope(self, unit_name: str, process: object) -> None: ...


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

    def start_scope(
        self, argv: tuple[str, ...], environment: dict[str, str]
    ) -> OllamaProcess:
        if not _allowed_start_operation(argv, environment):
            _fail("provider.operation_not_allowed")
        try:
            return subprocess.Popen(
                argv,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                shell=False,
            )
        except OSError:
            _fail("provider.process_start_failed")

    def process_running(self, process: object) -> bool:
        try:
            return process.poll() is None  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False

    def scope_contains(self, unit_name: str, pid: int) -> bool:
        if not _UNIT_NAME.fullmatch(unit_name) or type(pid) is not int or pid < 1:
            return False
        try:
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
                timeout=PROBE_TIMEOUT_SECONDS,
                check=False,
            )
            if result.returncode != 0 or result.stderr or len(result.stdout) > _MAX_CGROUP_BYTES:
                return False
            line = result.stdout.decode("ascii")
            if not line.startswith("ControlGroup=/") or not line.endswith("\n"):
                return False
            control_group = line.removeprefix("ControlGroup=").removesuffix("\n")
            if "\n" in control_group:
                return False
            with open(f"/proc/{pid}/cgroup", "rb", buffering=0) as stream:
                raw = stream.read(_MAX_CGROUP_BYTES + 1)
            if len(raw) > _MAX_CGROUP_BYTES:
                return False
            entries = raw.decode("ascii").splitlines()
            return f"0::{control_group}" in entries
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError):
            return False

    def fetch_tags(
        self, port: int, *, timeout_seconds: float, max_bytes: int
    ) -> set[str] | None:
        connection: http.client.HTTPConnection | None = None
        try:
            connection = http.client.HTTPConnection(
                "127.0.0.1", port, timeout=timeout_seconds
            )
            connection.request("GET", "/api/tags", headers={"Connection": "close"})
            response = connection.getresponse()
            length = response.getheader("Content-Length")
            if (
                response.status != 200
                or (length is not None and (not length.isascii() or not length.isdigit()))
                or (length is not None and int(length) > max_bytes)
            ):
                return None
            raw = response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                return None
            document = json.loads(raw.decode("utf-8"))
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
        except (OSError, ValueError, json.JSONDecodeError, http.client.HTTPException):
            return None
        finally:
            if connection is not None:
                connection.close()

    def stop_scope(self, unit_name: str, process: object) -> None:
        if not _UNIT_NAME.fullmatch(unit_name):
            _fail("resource.scope_invalid")
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
            process.wait(timeout=5.0)  # type: ignore[attr-defined]
        except OllamaRuntimeError:
            raise
        except (AttributeError, OSError, subprocess.SubprocessError):
            _fail("provider.process_stop_failed")


def probe_ollama_host(*, runtime: OllamaRuntime | None = None) -> OllamaHostSnapshot:
    adapter = runtime or SystemOllamaRuntime()
    return OllamaHostSnapshot(
        available_cpus=adapter.available_cpus(), effective_uid=os.geteuid()
    )


def plan_local_instance(
    instance: OllamaInstanceV1,
    host: OllamaHostSnapshot,
    *,
    selected_provider_model_ids: tuple[str, ...] | None = None,
) -> OllamaLocalPlan:
    if not isinstance(instance, OllamaInstanceV1) or instance.host_ref != "local":
        _fail("provider.instance_invalid")
    if not isinstance(host, OllamaHostSnapshot):
        _fail("resource.host_probe_invalid")
    selected = (
        instance.selected_model_refs
        if selected_provider_model_ids is None
        else selected_provider_model_ids
    )
    if (
        not isinstance(selected, tuple)
        or not selected
        or any(not isinstance(model_id, str) or not model_id for model_id in selected)
        or len(set(selected)) != len(selected)
    ):
        _fail("provider.model_invalid")
    try:
        profile = OllamaCpuProfile.parse(
            instance.allowed_cpus,
            instance.cpu_quota_percent,
            instance.cpu_weight,
            available_cpus=host.available_cpus,
        )
    except ResourceCgroupError as error:
        raise OllamaRuntimeError(str(error)) from None
    return OllamaLocalPlan(
        instance=instance,
        host=host,
        executable=_inspect_path(
            instance.ollama_executable,
            effective_uid=host.effective_uid,
            kind="executable",
        ),
        models_directory=_inspect_path(
            instance.models_directory,
            effective_uid=host.effective_uid,
            kind="models",
        ),
        cpu_profile=profile,
        selected_provider_model_ids=selected,
    )


def start_local_instance(
    plan: OllamaLocalPlan, *, runtime: OllamaRuntime | None = None
) -> RunningOllamaInstance:
    if not isinstance(plan, OllamaLocalPlan):
        _fail("provider.plan_invalid")
    _revalidate_path(plan.executable, plan.host.effective_uid, kind="executable")
    _revalidate_path(plan.models_directory, plan.host.effective_uid, kind="models")
    adapter = runtime or SystemOllamaRuntime()
    port = adapter.allocate_loopback_port()
    if type(port) is not int or not 1 <= port <= 65535:
        _fail("provider.loopback_allocation_failed")
    unit_name = f"codex-master-ollama-{secrets.token_hex(16)}.scope"
    if not _UNIT_NAME.fullmatch(unit_name):
        _fail("resource.scope_invalid")
    properties = plan.cpu_profile.systemd_properties()
    argv = (
        SYSTEMD_RUN_PATH,
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        f"--unit={unit_name}",
        f"--slice={OLLAMA_SLICE}",
        *(f"--property={name}={value}" for name, value in properties.items()),
        plan.instance.ollama_executable,
        "serve",
    )
    environment = {
        "OLLAMA_HOST": f"127.0.0.1:{port}",
        "OLLAMA_MODELS": plan.instance.models_directory,
    }
    process = adapter.start_scope(argv, environment)
    pid = getattr(process, "pid", None)
    if type(pid) is not int or pid < 1 or not adapter.process_running(process):
        _fail("provider.process_start_failed")
    return RunningOllamaInstance(
        plan=plan,
        unit_name=unit_name,
        port=port,
        process=process,
    )


def stop_local_instance(
    instance: RunningOllamaInstance, *, runtime: OllamaRuntime | None = None
) -> None:
    if not isinstance(instance, RunningOllamaInstance):
        _fail("provider.instance_invalid")
    (runtime or SystemOllamaRuntime()).stop_scope(instance.unit_name, instance.process)


def probe_instance_readiness(
    instance: RunningOllamaInstance, *, runtime: OllamaRuntime | None = None
) -> OllamaReadinessStatus:
    if not isinstance(instance, RunningOllamaInstance):
        _fail("provider.instance_invalid")
    adapter = runtime or SystemOllamaRuntime()
    process_running = adapter.process_running(instance.process)
    if not process_running:
        return _readiness(reason="provider.process_unavailable")
    cgroup_member = adapter.scope_contains(instance.unit_name, instance.process.pid)
    if not cgroup_member:
        return _readiness(
            reason="resource.scope_membership_invalid", process_running=True
        )
    tags = adapter.fetch_tags(
        instance.port,
        timeout_seconds=PROBE_TIMEOUT_SECONDS,
        max_bytes=MAX_TAG_RESPONSE_BYTES,
    )
    if tags is None:
        return _readiness(
            reason="provider.endpoint_unavailable",
            process_running=True,
            cgroup_member=True,
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
    try:
        path = Path(value)
    except (TypeError, ValueError):
        _fail("resource.target_path_invalid")
    if (
        not isinstance(value, str)
        or not value
        or not path.is_absolute()
        or path == Path("/")
        or str(path) != value
    ):
        _fail("resource.target_path_invalid")
    return path


def _allowed_start_operation(
    argv: tuple[str, ...], environment: Mapping[str, str]
) -> bool:
    if (
        type(argv) is not tuple
        or len(argv) != 12
        or any(not isinstance(argument, str) for argument in argv)
        or type(environment) is not dict
        or set(environment) != {"OLLAMA_HOST", "OLLAMA_MODELS"}
        or any(not isinstance(value, str) for value in environment.values())
        or argv[:5]
        != (SYSTEMD_RUN_PATH, "--user", "--scope", "--quiet", "--collect")
        or argv[6] != f"--slice={OLLAMA_SLICE}"
        or argv[11] != "serve"
        or not argv[5].startswith("--unit=")
        or not _UNIT_NAME.fullmatch(argv[5].removeprefix("--unit="))
        or not _CPU_PROPERTY.fullmatch(argv[7])
    ):
        return False
    quota = _QUOTA_PROPERTY.fullmatch(argv[8])
    weight = _WEIGHT_PROPERTY.fullmatch(argv[9])
    if (
        quota is None
        or weight is None
        or int(quota.group(1)) > 10000
        or int(weight.group(1)) > 10000
    ):
        return False
    try:
        executable = Path(argv[10])
        models = Path(environment["OLLAMA_MODELS"])
    except (KeyError, TypeError, ValueError):
        return False
    host = _LOOPBACK_HOST.fullmatch(environment.get("OLLAMA_HOST", ""))
    return (
        host is not None
        and int(host.group(1)) <= 65535
        and executable.is_absolute()
        and executable != Path("/")
        and str(executable) == argv[10]
        and models.is_absolute()
        and models != Path("/")
        and str(models) == environment["OLLAMA_MODELS"]
    )


def _inspect_path(
    value: str, *, effective_uid: int, kind: str
) -> OllamaPathEvidence:
    path = _canonical_path(value)
    metadata = _open_absolute_no_symlinks(path, directory=kind == "models")
    mode = stat.S_IMODE(metadata.st_mode)
    trusted_owner = metadata.st_uid in {0, effective_uid}
    if kind == "executable":
        valid = (
            stat.S_ISREG(metadata.st_mode)
            and trusted_owner
            and bool(mode & 0o111)
            and not bool(mode & 0o022)
        )
    else:
        private_user_directory = metadata.st_uid == effective_uid and mode == 0o700
        administrative_directory = (
            metadata.st_uid == 0 and bool(mode & 0o500) and not bool(mode & 0o022)
        )
        valid = stat.S_ISDIR(metadata.st_mode) and trusted_owner and (
            private_user_directory or administrative_directory
        )
    if not valid:
        _fail("resource.target_path_invalid")
    return OllamaPathEvidence(
        path=str(path),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        owner_uid=metadata.st_uid,
    )


def _open_absolute_no_symlinks(path: Path, *, directory: bool) -> os.stat_result:
    descriptor = -1
    try:
        descriptor = os.open(
            "/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            flags = os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
            if not final or directory:
                flags |= os.O_DIRECTORY
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if stat.S_ISLNK(metadata.st_mode):
            _fail("resource.target_path_invalid")
        return metadata
    except OllamaRuntimeError:
        raise
    except OSError:
        _fail("resource.target_path_invalid")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _revalidate_path(
    expected: OllamaPathEvidence, effective_uid: int, *, kind: str
) -> None:
    try:
        current = _inspect_path(
            expected.path, effective_uid=effective_uid, kind=kind
        )
    except OllamaRuntimeError:
        _fail("resource.target_path_changed")
    if (current.device, current.inode) != (expected.device, expected.inode):
        _fail("resource.target_path_changed")
