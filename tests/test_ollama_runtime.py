from __future__ import annotations

from dataclasses import replace
import fcntl
import gc
import os
from pathlib import Path
import re
import socket
import subprocess
import threading
import time

import pytest

from codex_master import ollama_runtime
from codex_master.ollama_registry import (
    OllamaInstanceV1,
    OllamaModelV1,
    OllamaRegistryV1,
)
from codex_master.ollama_runtime import (
    OllamaHostSnapshot,
    OllamaRuntimeError,
    SystemOllamaRuntime,
    plan_local_instance,
    probe_instance_readiness,
    probe_ollama_host,
    start_local_instance,
    stop_local_instance,
)


class FakeProcess:
    pid = 4242

    def poll(self) -> int | None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        return 0


class FakeRuntime:
    def __init__(self) -> None:
        self.started: list[object] = []
        self.stopped: list[object] = []
        self.tags: set[str] | None = {"llama-small", "qwen-small"}
        self.process_up = True
        self.cgroup_matches = True
        self.listener_matches = True
        self.invalidate_scope_after_fetch = False
        self.scope_pid = 4343
        self.scope_control_group = "/user.slice/ollama.scope"
        self.scope_start_ticks = 901
        self.tag_probe_limits: tuple[float, int] | None = None
        self.cleaned: list[str] = []

    def available_cpus(self) -> tuple[int, ...]:
        return (0, 1, 2, 3)

    def allocate_loopback_port(self) -> int:
        return 11435

    def start_scope(self, request: object) -> FakeProcess:
        self.started.append(request)
        return FakeProcess()

    def resolve_scope(self, request: object, process: object) -> tuple[int, str, int]:
        return self.scope_pid, self.scope_control_group, self.scope_start_ticks

    def process_running(
        self, process: object, pid: int | None = None, start_ticks: int | None = None
    ) -> bool:
        return self.process_up

    def scope_process_matches(
        self, unit_name: str, pid: int, control_group: str, start_ticks: int
    ) -> bool:
        return self.cgroup_matches

    def listener_owned_by(self, pid: int, port: int) -> bool:
        return self.listener_matches

    def cleanup_scope(self, request: object, process: object) -> None:
        self.cleaned.append(request.unit_name)  # type: ignore[attr-defined]

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
        assert pid == self.scope_pid
        assert port == 11435
        assert re.fullmatch(
            r"codex-master-ollama-[0-9a-f]{32}\.scope", unit_name
        )
        assert control_group == self.scope_control_group
        assert start_ticks == self.scope_start_ticks
        self.tag_probe_limits = (timeout_seconds, max_bytes)
        if self.invalidate_scope_after_fetch:
            self.cgroup_matches = False
        return self.tags

    def stop_scope(self, request: object) -> None:
        self.stopped.append(request)


def make_executable(path: Path) -> Path:
    path.write_bytes(b"#!/bin/sh\nexit 0\n")
    path.chmod(0o700)
    return path


def test_full_local_fleet_slice_is_idempotent_and_stops_only_failed_unit(
    tmp_path: Path,
) -> None:
    from codex_master.fleet_service import FleetConflictError, FleetPaths, FleetService
    from codex_master.ollama_host_transport import (
        CONTROL_HOST_REF,
        OllamaHostLease,
        OllamaHostTransport,
        Task3LocalOllamaHostAdapter,
    )
    from codex_master.ollama_registry import OllamaRegistryStore
    from codex_master.server import build_fleet_private_io

    executable = make_executable(tmp_path / "fake-ollama")
    models_directory = make_models_directory(tmp_path / "models")
    registry_root = tmp_path / "registry"
    registry = OllamaRegistryStore.for_test(registry_root)
    registry.replace(models=valid_models(), instances=(), expected_generation=0)
    runtime = FakeRuntime()
    lease = OllamaHostLease(
        CONTROL_HOST_REF,
        "lease-" + "a" * 32,
        1,
        7,
        time.monotonic() + 3600,
    )

    class Leases:
        def resolve(self, host_ref: str) -> OllamaHostLease | None:
            return lease if host_ref == CONTROL_HOST_REF else None

    class NoRemoteBroker:
        def exchange(self, *_args: object, **_values: object) -> object:
            raise AssertionError("local fleet slice reached remote broker")

    transport = OllamaHostTransport(
        registry=registry,
        leases=Leases(),
        broker=NoRemoteBroker(),
        local=Task3LocalOllamaHostAdapter(runtime),
    )
    paths = FleetPaths.from_state_root(tmp_path / "fleet-state")
    service = FleetService(
        paths,
        build_fleet_private_io(paths),
        pool_root=tmp_path / "pool",
        ollama_registry=registry,
        ollama_transport=transport,
    )

    def candidate(ref: str) -> OllamaInstanceV1:
        return OllamaInstanceV1(
            ref,
            ref,
            CONTROL_HOST_REF,
            str(executable),
            str(models_directory),
            ("llama", "qwen"),
            "0-3",
            350,
            40,
            "planned",
            "unknown",
        )

    first_plan = service.plan_ollama_instance(
        candidate("ollama-main"), expected_generation=1
    )
    first = service.apply_ollama_instance(
        first_plan.plan_id, expected_generation=1
    )
    reloaded = OllamaRegistryStore.for_test(registry_root).load()
    retried = service.apply_ollama_instance(
        first_plan.plan_id, expected_generation=1
    )

    assert retried is first
    assert reloaded.generation == 2
    assert [lane.model_ref for lane in first.hive_lanes] == ["llama", "qwen"]
    assert len(runtime.started) == 1
    assert runtime.started[0].systemd_properties == (  # type: ignore[attr-defined]
        ("AllowedCPUs", "0-3"),
        ("CPUQuota", "350%"),
        ("CPUWeight", "40"),
    )

    second_plan = service.plan_ollama_instance(
        candidate("ollama-canary"), expected_generation=2
    )
    runtime.tags = {"llama-small"}
    with pytest.raises(FleetConflictError, match="ollama.instance_not_ready"):
        service.apply_ollama_instance(
            second_plan.plan_id, expected_generation=2
        )

    assert len(runtime.started) == 2
    assert [request.unit_name for request in runtime.stopped] == [  # type: ignore[attr-defined]
        runtime.started[1].unit_name  # type: ignore[attr-defined]
    ]
    assert runtime.stopped[0].unit_name != runtime.started[0].unit_name  # type: ignore[attr-defined]


def bind_current_scope_identity(
    runtime: SystemOllamaRuntime,
    monkeypatch: pytest.MonkeyPatch,
    pid: int,
) -> tuple[str, str, int]:
    unit_name = "codex-master-ollama-0123456789abcdef0123456789abcdef.scope"
    control_group = ollama_runtime._process_control_group(pid)
    start_ticks = ollama_runtime._process_start_ticks(pid)
    monkeypatch.setattr(
        runtime,
        "_scope_observation",
        lambda _unit_name, **_kwargs: (pid, control_group, start_ticks),
    )
    return unit_name, control_group, start_ticks


def make_models_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    return path


def valid_instance(
    tmp_path: Path,
    *,
    ollama_executable: str | None = None,
    models_directory: str | None = None,
) -> OllamaInstanceV1:
    executable = ollama_executable or str(make_executable(tmp_path / "ollama"))
    models = models_directory or str(make_models_directory(tmp_path / "models"))
    return OllamaInstanceV1(
        ref="ollama-1",
        label="Ollama 1",
        host_ref="local",
        ollama_executable=executable,
        models_directory=models,
        selected_model_refs=("llama", "qwen"),
        allowed_cpus="0-3",
        cpu_quota_percent=350,
        cpu_weight=40,
        lifecycle_state="stopped",
        readiness_state="unknown",
    )


def valid_models(
    *, qwen_installed: bool = True
) -> tuple[OllamaModelV1, OllamaModelV1]:
    return (
        OllamaModelV1(
            ref="llama",
            provider_model_id="llama-small",
            installed=True,
            hive_enabled=True,
            simple_only=True,
            evidence_at_utc="2026-08-28T12:00:00Z",
        ),
        OllamaModelV1(
            ref="qwen",
            provider_model_id="qwen-small",
            installed=qwen_installed,
            hive_enabled=True,
            simple_only=True,
            evidence_at_utc="2026-08-28T12:00:00Z",
        ),
    )


def host_snapshot() -> OllamaHostSnapshot:
    return OllamaHostSnapshot(available_cpus=(0, 1, 2, 3), effective_uid=os.geteuid())


def planned(tmp_path: Path):
    instance = valid_instance(tmp_path)
    return plan_from_registry(instance)


def plan_from_registry(
    instance: OllamaInstanceV1,
    *,
    models: tuple[OllamaModelV1, ...] | None = None,
):
    registry = OllamaRegistryV1(
        schema_version=1,
        generation=7,
        models=models or valid_models(),
        instances=(instance,),
    )
    return plan_local_instance(instance, host_snapshot(), registry=registry)


def running(tmp_path: Path, runtime: FakeRuntime):
    return start_local_instance(planned(tmp_path), runtime=runtime)


def test_executable_symlink_is_rejected(tmp_path: Path) -> None:
    target = make_executable(tmp_path / "real")
    link = tmp_path / "ollama"
    link.symlink_to(target)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_from_registry(valid_instance(tmp_path, ollama_executable=str(link)))


def test_symlinked_path_ancestor_is_rejected(tmp_path: Path) -> None:
    real = make_models_directory(tmp_path / "real")
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_from_registry(valid_instance(tmp_path, models_directory=str(linked)))


@pytest.mark.parametrize("component", ["./ollama", "child/../ollama"])
def test_dot_or_parent_path_component_is_rejected(
    tmp_path: Path, component: str
) -> None:
    make_executable(tmp_path / "ollama")
    (tmp_path / "child").mkdir()

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_from_registry(
            valid_instance(tmp_path, ollama_executable=f"{tmp_path}/{component}")
        )


def test_executable_must_be_regular_executable_and_not_mutable_by_other_users(
    tmp_path: Path,
) -> None:
    executable = make_executable(tmp_path / "ollama")
    executable.chmod(0o722)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_from_registry(
            valid_instance(tmp_path, ollama_executable=str(executable))
        )


def test_models_directory_must_be_private_or_administratively_owned(
    tmp_path: Path,
) -> None:
    models = make_models_directory(tmp_path / "models")
    models.chmod(0o770)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_from_registry(valid_instance(tmp_path, models_directory=str(models)))


def test_plan_pins_paths_and_maps_validated_cpu_profile(tmp_path: Path) -> None:
    instance = valid_instance(tmp_path)

    plan = plan_from_registry(
        instance,
        models=(
            replace(valid_models()[0], provider_model_id="provider/llama"),
            replace(valid_models()[1], provider_model_id="provider/qwen"),
        ),
    )

    executable = os.stat(instance.ollama_executable, follow_symlinks=False)
    models = os.stat(instance.models_directory, follow_symlinks=False)
    assert (plan.executable.device, plan.executable.inode) == (
        executable.st_dev,
        executable.st_ino,
    )
    assert (plan.models_directory.device, plan.models_directory.inode) == (
        models.st_dev,
        models.st_ino,
    )
    assert plan.cpu_profile.systemd_properties() == {
        "AllowedCPUs": "0-3",
        "CPUQuota": "350%",
        "CPUWeight": "40",
    }
    assert plan.selected_provider_model_ids == ("provider/llama", "provider/qwen")


def test_start_revalidates_pinned_executable_before_runtime_action(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    plan = planned(tmp_path)
    executable = Path(plan.instance.ollama_executable)
    old = executable.with_name("old-ollama")
    executable.rename(old)
    make_executable(executable)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_changed"):
        start_local_instance(plan, runtime=runtime)

    assert runtime.started == []


def test_start_uses_fixed_argv_allowlisted_environment_and_exact_cpu_properties(
    tmp_path: Path,
) -> None:
    runtime = FakeRuntime()
    plan = planned(tmp_path)

    result = start_local_instance(plan, runtime=runtime)

    assert len(runtime.started) == 1
    request = runtime.started[0]
    assert request.argv[:10] == (  # type: ignore[attr-defined]
        "/usr/bin/systemd-run",
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        f"--unit={result.unit_name}",
        "--slice=codex-master.slice",
        "--property=AllowedCPUs=0-3",
        "--property=CPUQuota=350%",
        "--property=CPUWeight=40",
    )
    assert request.argv[10:14] == (  # type: ignore[attr-defined]
        f"/proc/{os.getpid()}/exe",
        "-I",
        "-P",
        "-c",
    )
    assert request.argv[14] == ollama_runtime._EXEC_HELPER_SOURCE  # type: ignore[attr-defined]
    assert request.argv[-2:] != (plan.instance.ollama_executable, "serve")  # type: ignore[attr-defined]
    assert re.fullmatch(r"codex-master-ollama-[a-f0-9]{32}\.scope", result.unit_name)
    assert request.launcher_environment == {  # type: ignore[attr-defined]
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.geteuid()}/bus",
        "XDG_RUNTIME_DIR": f"/run/user/{os.geteuid()}",
    }


def test_plan_accepts_equivalent_noncanonical_cpu_set(tmp_path: Path) -> None:
    instance = replace(valid_instance(tmp_path), allowed_cpus="0,1")

    plan = plan_from_registry(instance)

    assert plan.cpu_profile.systemd_properties()["AllowedCPUs"] == "0-1"


def test_system_runtime_executes_argv_without_shell_or_ambient_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def popen(argv: tuple[str, ...], **kwargs: object) -> FakeProcess:
        calls.append((argv, kwargs))
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", popen)
    runtime = SystemOllamaRuntime()
    monkeypatch.setattr(
        runtime,
        "resolve_scope",
        lambda _request, _process: (4343, "/user.slice/test.scope", 901),
    )
    monkeypatch.setattr(
        runtime,
        "process_running",
        lambda _process, _pid, _start_ticks: True,
    )

    active = start_local_instance(planned(tmp_path), runtime=runtime)

    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv[0] == ollama_runtime.SYSTEMD_RUN_PATH
    assert kwargs == {
        "env": {
            "DBUS_SESSION_BUS_ADDRESS": (
                f"unix:path=/run/user/{active.plan.host.effective_uid}/bus"
            ),
            "XDG_RUNTIME_DIR": f"/run/user/{active.plan.host.effective_uid}",
        },
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        "shell": False,
    }


def test_helper_launch_does_not_import_code_from_configured_module_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_root = tmp_path / "attacker"
    package = fake_root / "codex_master"
    package.mkdir(parents=True)
    marker = tmp_path / "imported"
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "ollama_runtime.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('loaded')\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ollama_runtime,
        "__file__",
        str(package / "ollama_runtime.py"),
    )
    runtime = FakeRuntime()
    lane = tmp_path / "lane"
    lane.mkdir()
    start_local_instance(planned(lane), runtime=runtime)
    request = runtime.started[0]
    assert isinstance(request, ollama_runtime.OllamaStartRequest)

    subprocess.run(
        request.argv[10:],
        cwd=tmp_path,
        env=request.launcher_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5.0,
        check=False,
    )

    assert not marker.exists()


def test_isolated_helper_executes_pinned_elf_from_sealed_memfd(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    instance = valid_instance(tmp_path, ollama_executable="/usr/bin/yes")
    plan = plan_from_registry(instance)
    start_local_instance(plan, runtime=runtime)
    request = runtime.started[0]
    assert isinstance(request, ollama_runtime.OllamaStartRequest)

    process = subprocess.Popen(
        request.argv[10:],
        env=request.launcher_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        deadline = time.monotonic() + 2.0
        executable = ""
        while time.monotonic() < deadline and process.poll() is None:
            executable = os.readlink(f"/proc/{process.pid}/exe")
            if "memfd:codex-master-ollama-executable" in executable:
                break
            time.sleep(0.01)
        assert process.poll() is None
        assert "memfd:codex-master-ollama-executable" in executable
    finally:
        process.terminate()
        process.wait(timeout=5.0)


def test_system_runtime_rejects_non_allowlisted_argv_before_process_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_popen(*_args: object, **_kwargs: object) -> FakeProcess:
        raise AssertionError("non-allowlisted argv reached Popen")

    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)

    with pytest.raises(OllamaRuntimeError, match="provider.operation_not_allowed"):
        SystemOllamaRuntime().start_scope(object())  # type: ignore[arg-type]


def test_system_runtime_rejects_copied_internal_start_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = FakeRuntime()
    running(tmp_path, runtime)
    request = runtime.started[0]
    assert isinstance(request, ollama_runtime.OllamaStartRequest)
    forged = replace(request)

    def forbidden_popen(*_args: object, **_kwargs: object) -> FakeProcess:
        raise AssertionError("copied request reached Popen")

    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)

    with pytest.raises(OllamaRuntimeError, match="provider.operation_not_allowed"):
        SystemOllamaRuntime().start_scope(forged)  # type: ignore[arg-type]


def test_system_runtime_revalidates_mutated_launcher_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = FakeRuntime()
    running(tmp_path, runtime)
    request = runtime.started[0]
    request.launcher_environment["LD_PRELOAD"] = "/tmp/attack.so"  # type: ignore[attr-defined]

    def forbidden_popen(*_args: object, **_kwargs: object) -> FakeProcess:
        raise AssertionError("mutated request reached Popen")

    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)

    with pytest.raises(OllamaRuntimeError, match="provider.operation_not_allowed"):
        SystemOllamaRuntime().start_scope(request)  # type: ignore[arg-type]


def test_lane_is_not_ready_until_all_selected_models_answer(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    runtime.tags = {"llama-small"}
    active = running(tmp_path, runtime)

    status = probe_instance_readiness(active, runtime=runtime)

    assert status.ready is False
    assert status.reason_codes == ("provider.model_unavailable",)


def test_readiness_requires_process_scope_loopback_and_all_models(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    active = running(tmp_path, runtime)

    status = probe_instance_readiness(active, runtime=runtime)

    assert status.ready is True
    assert status.reason_codes == ()
    assert status.process_running is True
    assert status.cgroup_member is True
    assert status.loopback_endpoint_reachable is True
    assert status.available_model_ids == ("llama-small", "qwen-small")
    assert runtime.tag_probe_limits is not None
    timeout_seconds, max_bytes = runtime.tag_probe_limits
    assert 0 < timeout_seconds <= 2.0
    assert 0 < max_bytes <= 64 * 1024


@pytest.mark.parametrize(
    ("process_up", "cgroup_matches", "reason"),
    [
        (False, True, "provider.process_unavailable"),
        (True, False, "resource.scope_membership_invalid"),
    ],
)
def test_readiness_fails_closed_before_endpoint_probe(
    tmp_path: Path, process_up: bool, cgroup_matches: bool, reason: str
) -> None:
    runtime = FakeRuntime()
    active = running(tmp_path, runtime)
    runtime.process_up = process_up
    runtime.cgroup_matches = cgroup_matches

    status = probe_instance_readiness(active, runtime=runtime)

    assert status.ready is False
    assert status.reason_codes == (reason,)
    assert runtime.tag_probe_limits is None


def test_readiness_reports_unreachable_loopback_endpoint(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    runtime.tags = None
    active = running(tmp_path, runtime)

    status = probe_instance_readiness(active, runtime=runtime)

    assert status.ready is False
    assert status.reason_codes == ("provider.endpoint_unavailable",)


def test_stop_targets_only_recorded_transient_unit(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    active = running(tmp_path, runtime)

    stop_local_instance(active, runtime=runtime)

    assert len(runtime.stopped) == 1
    request = runtime.stopped[0]
    assert request.unit_name == active.unit_name  # type: ignore[attr-defined]
    assert request.ollama_pid == active.ollama_pid  # type: ignore[attr-defined]


def test_stop_rechecks_recorded_pid_and_cgroup_before_systemctl(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    active = running(tmp_path, runtime)
    runtime.cgroup_matches = False

    with pytest.raises(OllamaRuntimeError, match="resource.scope_membership_invalid"):
        stop_local_instance(active, runtime=runtime)

    assert runtime.stopped == []


def test_system_runtime_rejects_copied_internal_stop_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = FakeRuntime()
    active = running(tmp_path, runtime)
    stop_local_instance(active, runtime=runtime)
    request = runtime.stopped[0]
    assert isinstance(request, ollama_runtime.OllamaStopRequest)
    forged = replace(
        request,
        unit_name="codex-master-ollama-deadbeefdeadbeefdeadbeefdeadbeef.scope",
    )

    def forbidden_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("copied request reached systemctl")

    monkeypatch.setattr(subprocess, "run", forbidden_run)

    with pytest.raises(OllamaRuntimeError, match="provider.operation_not_allowed"):
        SystemOllamaRuntime().stop_scope(forged)  # type: ignore[arg-type]


def test_host_probe_uses_kernel_affinity_snapshot() -> None:
    snapshot = probe_ollama_host(runtime=FakeRuntime())

    assert snapshot.available_cpus == (0, 1, 2, 3)
    assert snapshot.effective_uid == os.geteuid()


def test_plan_instance_path_cannot_be_decoupled_from_validated_evidence(
    tmp_path: Path,
) -> None:
    runtime = FakeRuntime()
    plan = planned(tmp_path)
    replacement = make_executable(tmp_path / "other-ollama")
    with pytest.raises(OllamaRuntimeError, match="provider.plan_invalid"):
        replace(
            plan,
            instance=replace(plan.instance, ollama_executable=str(replacement)),
        )

    assert runtime.started == []


def test_plan_evidence_from_another_path_cannot_be_substituted(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    runtime = FakeRuntime()
    first = planned(first_root)
    second = planned(second_root)
    with pytest.raises(OllamaRuntimeError, match="provider.plan_invalid"):
        replace(first, executable=second.executable)

    assert runtime.started == []


def test_plan_provenance_rejects_in_place_field_substitution(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    runtime = FakeRuntime()
    first = planned(first_root)
    second = planned(second_root)
    object.__setattr__(first, "instance", second.instance)
    object.__setattr__(first, "executable", second.executable)
    object.__setattr__(first, "models_directory", second.models_directory)

    with pytest.raises(OllamaRuntimeError, match="provider.plan_invalid"):
        start_local_instance(first, runtime=runtime)

    assert runtime.started == []


def test_discarded_plan_releases_provenance_record(tmp_path: Path) -> None:
    plan = planned(tmp_path)
    provenance = plan._provenance

    del plan
    gc.collect()

    assert provenance not in ollama_runtime._PLAN_RECORDS


def test_in_place_executable_mutation_after_plan_is_rejected(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    plan = planned(tmp_path)
    executable = Path(plan.instance.ollama_executable)
    original_inode = executable.stat().st_ino
    executable.write_bytes(b"#!/bin/sh\nexit 1\n")
    executable.chmod(0o700)
    assert executable.stat().st_ino == original_inode

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_changed"):
        start_local_instance(plan, runtime=runtime)


def test_executable_digest_has_hard_byte_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = make_executable(tmp_path / "ollama")
    models = make_models_directory(tmp_path / "models")
    real_read = os.read
    served = 0

    def growing_read(descriptor: int, size: int) -> bytes:
        nonlocal served
        if os.readlink(f"/proc/self/fd/{descriptor}") == str(executable):
            if served >= 4096:
                return b""
            chunk = b"x" * min(size, 1024)
            served += len(chunk)
            return chunk
        return real_read(descriptor, size)

    monkeypatch.setattr(ollama_runtime, "_MAX_EXECUTABLE_BYTES", 2048)
    monkeypatch.setattr(os, "read", growing_read)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_from_registry(
            valid_instance(
                tmp_path,
                ollama_executable=str(executable),
                models_directory=str(models),
            )
        )

    assert served <= 3072


def test_executable_digest_rejects_concurrent_in_place_growth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = make_executable(tmp_path / "ollama")
    models = make_models_directory(tmp_path / "models")
    real_read = os.read
    mutated = False

    def mutating_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        data = real_read(descriptor, size)
        if not mutated and os.readlink(f"/proc/self/fd/{descriptor}") == str(executable):
            mutated = True
            with executable.open("ab") as stream:
                stream.write(b"# concurrent mutation\n")
        return data

    monkeypatch.setattr(os, "read", mutating_read)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_from_registry(
            valid_instance(
                tmp_path,
                ollama_executable=str(executable),
                models_directory=str(models),
            )
        )


def test_user_owned_hardlinked_executable_is_rejected(tmp_path: Path) -> None:
    target = make_executable(tmp_path / "real-ollama")
    alias = tmp_path / "ollama"
    os.link(target, alias)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_from_registry(valid_instance(tmp_path, ollama_executable=str(alias)))


def test_writable_non_sticky_path_ancestor_is_rejected(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o770)
    unsafe.chmod(0o770)
    executable = make_executable(unsafe / "ollama")

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_from_registry(
            valid_instance(tmp_path, ollama_executable=str(executable))
        )


def test_owner_execute_bit_must_match_effective_uid(tmp_path: Path) -> None:
    executable = make_executable(tmp_path / "ollama")
    executable.chmod(0o001)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_from_registry(
            valid_instance(tmp_path, ollama_executable=str(executable))
        )


def test_provider_model_ids_are_derived_from_complete_registry_models(
    tmp_path: Path,
) -> None:
    instance = valid_instance(tmp_path)
    plan = plan_from_registry(instance)

    assert plan.selected_provider_model_ids == ("llama-small", "qwen-small")


def test_registry_instance_cannot_be_decoupled_from_planned_instance(
    tmp_path: Path,
) -> None:
    instance = valid_instance(tmp_path)
    other = replace(instance, label="Other")
    registry = OllamaRegistryV1(1, 7, valid_models(), (other,))

    with pytest.raises(OllamaRuntimeError, match="provider.instance_invalid"):
        plan_local_instance(instance, host_snapshot(), registry=registry)


def test_ineligible_selected_registry_model_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(OllamaRuntimeError, match="provider.model_unavailable"):
        plan_from_registry(
            valid_instance(tmp_path), models=valid_models(qwen_installed=False)
        )


def test_running_identity_uses_scope_leader_not_systemd_run_pid(tmp_path: Path) -> None:
    runtime = FakeRuntime()

    active = running(tmp_path, runtime)

    assert active.process.pid == 4242
    assert active.ollama_pid == 4343
    assert active.control_group == "/user.slice/ollama.scope"
    assert active.process_start_ticks == 901


def test_scope_resolution_waits_for_pinned_target_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeRuntime()
    running(tmp_path, fake)
    request = fake.started[0]
    assert isinstance(request, ollama_runtime.OllamaStartRequest)
    runtime = SystemOllamaRuntime()
    monkeypatch.setattr(
        runtime,
        "_scope_observation",
        lambda _unit_name: (4343, "/user.slice/ollama.scope", 901),
    )
    observations = iter((False, True))
    calls = 0

    def target_exec(_pid: int) -> bool:
        nonlocal calls
        calls += 1
        return next(observations)

    monkeypatch.setattr(
        ollama_runtime,
        "_process_executable_is_pinned",
        target_exec,
        raising=False,
    )
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    assert runtime.resolve_scope(request, FakeProcess()) == (
        4343,
        "/user.slice/ollama.scope",
        901,
    )
    assert calls == 2


def test_system_scope_identity_uses_single_cgroup_procs_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unit = "codex-master-ollama-0123456789abcdef0123456789abcdef.scope"
    control_group = "/user.slice/test.scope"
    cgroup = tmp_path / control_group.removeprefix("/")
    cgroup.mkdir(parents=True)
    (cgroup / "cgroup.procs").write_text("4343\n", encoding="ascii")
    result = subprocess.CompletedProcess(
        args=(),
        returncode=0,
        stdout=f"ControlGroup={control_group}\n".encode("ascii"),
        stderr=b"",
    )
    monkeypatch.setattr(ollama_runtime, "CGROUP_ROOT", tmp_path)
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(ollama_runtime, "_process_control_group", lambda _pid: control_group)
    monkeypatch.setattr(ollama_runtime, "_process_start_ticks", lambda _pid: 901)

    assert SystemOllamaRuntime()._scope_observation(unit) == (
        4343,
        control_group,
        901,
    )


def test_foreign_listener_cannot_make_instance_ready(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    runtime.listener_matches = False
    active = running(tmp_path, runtime)

    status = probe_instance_readiness(active, runtime=runtime)

    assert status.ready is False
    assert status.reason_codes == ("provider.endpoint_identity_invalid",)
    assert runtime.tag_probe_limits is None


def test_readiness_rechecks_scope_identity_after_connected_tags(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    runtime.invalidate_scope_after_fetch = True
    active = running(tmp_path, runtime)

    status = probe_instance_readiness(active, runtime=runtime)

    assert status.ready is False
    assert status.reason_codes == ("resource.scope_membership_invalid",)


def test_forged_running_unit_cannot_be_stopped(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    active = running(tmp_path, runtime)
    forged = replace(
        active,
        unit_name="codex-master-ollama-deadbeefdeadbeefdeadbeefdeadbeef.scope",
    )

    with pytest.raises(OllamaRuntimeError, match="provider.instance_invalid"):
        stop_local_instance(forged, runtime=runtime)

    assert runtime.stopped == []


def test_running_provenance_rejects_in_place_unit_substitution(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    active = running(tmp_path, runtime)
    object.__setattr__(
        active,
        "unit_name",
        "codex-master-ollama-deadbeefdeadbeefdeadbeefdeadbeef.scope",
    )

    with pytest.raises(OllamaRuntimeError, match="provider.instance_invalid"):
        stop_local_instance(active, runtime=runtime)

    assert runtime.stopped == []


def test_discarded_running_instance_releases_provenance_record(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    active = running(tmp_path, runtime)
    provenance = active._provenance

    del active
    gc.collect()

    assert provenance not in ollama_runtime._RUNNING_RECORDS


def test_partial_start_is_cleaned_when_process_dies_immediately(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    runtime.process_up = False

    with pytest.raises(OllamaRuntimeError, match="provider.process_start_failed"):
        start_local_instance(planned(tmp_path), runtime=runtime)

    assert len(runtime.cleaned) == 1


def test_partial_start_is_cleaned_on_baseexception_before_running_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = FakeRuntime()
    plan = planned(tmp_path)
    calls = 0

    def interrupt_running_provenance(length: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise KeyboardInterrupt
        return b"s" * length

    monkeypatch.setattr(ollama_runtime.secrets, "token_bytes", interrupt_running_provenance)

    with pytest.raises(KeyboardInterrupt):
        start_local_instance(plan, runtime=runtime)

    assert len(runtime.cleaned) == 1


def test_exec_helper_holds_validated_executable_and_models_fds_until_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = planned(tmp_path)
    executable_path = Path(plan.instance.ollama_executable)
    original_bytes = executable_path.read_bytes()
    observed: dict[str, object] = {}

    def execve(
        executable_fd: int, argv: tuple[str, ...], environment: dict[str, str]
    ) -> None:
        models_fd = int(environment["OLLAMA_MODELS"].rsplit("/", 1)[1])
        executable_path.write_bytes(b"#!/bin/sh\nexit 99\n")
        observed.update(
            executable_inode=os.fstat(executable_fd).st_ino,
            executable_bytes=os.pread(executable_fd, len(original_bytes) + 32, 0),
            executable_seals=fcntl.fcntl(executable_fd, fcntl.F_GET_SEALS),
            models_inode=os.fstat(models_fd).st_ino,
            argv=argv,
            environment=environment,
            models_inheritable=os.get_inheritable(models_fd),
        )
        raise RuntimeError("exec intercepted")

    monkeypatch.setattr(os, "execve", execve)

    with pytest.raises(RuntimeError, match="exec intercepted"):
        ollama_runtime._exec_pinned(
            plan.executable,
            plan.models_directory,
            plan.host,
            port=11435,
        )

    assert observed["executable_inode"] != plan.executable.inode
    assert observed["executable_bytes"] == original_bytes
    assert observed["executable_seals"] == (
        fcntl.F_SEAL_SEAL
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_WRITE
    )
    assert observed["models_inode"] == plan.models_directory.inode
    assert observed["argv"] == (plan.instance.ollama_executable, "serve")
    environment = observed["environment"]
    assert isinstance(environment, dict)
    assert set(environment) == {"OLLAMA_HOST", "OLLAMA_MODELS"}
    assert environment["OLLAMA_HOST"] == "127.0.0.1:11435"
    assert re.fullmatch(r"/proc/self/fd/[1-9][0-9]*", environment["OLLAMA_MODELS"])
    assert observed["models_inheritable"] is True


def test_exec_helper_payload_round_trip_preserves_pinned_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = FakeRuntime()
    plan = planned(tmp_path)
    start_local_instance(plan, runtime=runtime)
    payload = runtime.started[0].argv[-1]  # type: ignore[attr-defined]
    observed: list[tuple[object, object, object, int]] = []

    def exec_pinned(
        executable: object, models: object, host: object, *, port: int
    ) -> None:
        observed.append((executable, models, host, port))
        raise RuntimeError("helper intercepted")

    monkeypatch.setattr(ollama_runtime, "_exec_pinned", exec_pinned)

    with pytest.raises(RuntimeError, match="helper intercepted"):
        ollama_runtime._run_exec_helper(payload)

    assert observed == [
        (plan.executable, plan.models_directory, plan.host, 11435)
    ]


def test_exec_helper_rejects_malformed_payload_with_code_only_error() -> None:
    with pytest.raises(OllamaRuntimeError, match="provider.operation_not_allowed"):
        ollama_runtime._run_exec_helper('{"schema":1,"executable":"/bin/sh"}')


def test_exec_helper_main_suppresses_unexpected_error_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_payload: str) -> None:
        raise RuntimeError("sensitive path")

    monkeypatch.setattr(ollama_runtime, "_run_exec_helper", fail)

    assert ollama_runtime._helper_main(("--exec-pinned", "payload")) == 126


def test_listener_identity_is_bound_to_owning_pid() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        assert SystemOllamaRuntime().listener_owned_by(os.getpid(), port) is True
        assert SystemOllamaRuntime().listener_owned_by(os.getppid(), port) is False


def test_http_probe_enforces_one_monotonic_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def trickle() -> None:
        connection, _address = listener.accept()
        try:
            connection.recv(4096)
            connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            for byte in b'{"models"':
                time.sleep(0.1)
                try:
                    connection.sendall(bytes((byte,)))
                except OSError:
                    break
        finally:
            connection.close()
            listener.close()

    thread = threading.Thread(target=trickle, daemon=True)
    thread.start()
    started = time.monotonic()
    runtime = SystemOllamaRuntime()
    unit_name, control_group, start_ticks = bind_current_scope_identity(
        runtime, monkeypatch, os.getpid()
    )

    result = runtime.fetch_tags(
        os.getpid(),
        port,
        unit_name=unit_name,
        control_group=control_group,
        start_ticks=start_ticks,
        timeout_seconds=0.2,
        max_bytes=64 * 1024,
    )
    elapsed = time.monotonic() - started

    assert result is None
    assert elapsed < 0.8


@pytest.mark.parametrize("chunked", [False, True])
def test_http_probe_parses_bounded_content_length_and_chunked_tags(
    chunked: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = b'{"models":[{"model":"llama-small"}]}'
    if chunked:
        response = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            + f"{len(body):X}\r\n".encode("ascii")
            + body
            + b"\r\n0\r\n\r\n"
        )
    else:
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        connection, _address = listener.accept()
        try:
            connection.recv(4096)
            connection.sendall(response)
        finally:
            connection.close()
            listener.close()

    threading.Thread(target=serve, daemon=True).start()
    runtime = SystemOllamaRuntime()
    unit_name, control_group, start_ticks = bind_current_scope_identity(
        runtime, monkeypatch, os.getpid()
    )

    assert runtime.fetch_tags(
        os.getpid(),
        port,
        unit_name=unit_name,
        control_group=control_group,
        start_ticks=start_ticks,
        timeout_seconds=0.5,
        max_bytes=64 * 1024,
    ) == {"llama-small"}


def test_http_probe_rejects_connected_server_owned_by_foreign_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b'{"models":[{"model":"llama-small"}]}'
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\nConnection: close\r\n\r\n"
        + body
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        connection, _address = listener.accept()
        try:
            if connection.recv(4096):
                connection.sendall(response)
        finally:
            connection.close()
            listener.close()

    threading.Thread(target=serve, daemon=True).start()
    runtime = SystemOllamaRuntime()
    unit_name, control_group, start_ticks = bind_current_scope_identity(
        runtime, monkeypatch, os.getppid()
    )

    assert runtime.fetch_tags(
        os.getppid(),
        port,
        unit_name=unit_name,
        control_group=control_group,
        start_ticks=start_ticks,
        timeout_seconds=0.5,
        max_bytes=64 * 1024,
    ) is None


def test_http_probe_rejects_reused_pid_identity_before_request_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(1.0)
    port = listener.getsockname()[1]
    received: list[bytes] = []

    def serve() -> None:
        try:
            connection, _address = listener.accept()
        except OSError:
            return
        try:
            connection.settimeout(1.0)
            received.append(connection.recv(4096))
        except OSError:
            received.append(b"timeout")
        finally:
            connection.close()
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    runtime = SystemOllamaRuntime()
    current_start_ticks = ollama_runtime._process_start_ticks(os.getpid())
    monkeypatch.setattr(
        runtime,
        "_scope_observation",
        lambda _unit_name, **_kwargs: (
            os.getpid(),
            "/user.slice/original.scope",
            current_start_ticks,
        ),
    )
    monkeypatch.setattr(
        ollama_runtime,
        "_process_control_group",
        lambda _pid: "/user.slice/original.scope",
    )
    observed_start_ticks = iter((current_start_ticks, current_start_ticks + 1))
    monkeypatch.setattr(
        ollama_runtime,
        "_process_start_ticks",
        lambda _pid: next(observed_start_ticks),
    )
    try:
        result = runtime.fetch_tags(
            os.getpid(),
            port,
            unit_name="codex-master-ollama-0123456789abcdef0123456789abcdef.scope",
            control_group="/user.slice/original.scope",
            start_ticks=current_start_ticks,
            timeout_seconds=0.5,
            max_bytes=64 * 1024,
        )
    finally:
        listener.close()
        thread.join(timeout=2.0)

    assert result is None
    assert received == [b""]
