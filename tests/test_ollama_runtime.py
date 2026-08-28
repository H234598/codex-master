from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess

import pytest

from codex_master.ollama_registry import OllamaInstanceV1
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


class FakeRuntime:
    def __init__(self) -> None:
        self.started: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.stopped: list[tuple[str, object]] = []
        self.tags: set[str] | None = {"llama-small", "qwen-small"}
        self.process_up = True
        self.cgroup_matches = True
        self.tag_probe_limits: tuple[float, int] | None = None

    def available_cpus(self) -> tuple[int, ...]:
        return (0, 1, 2, 3)

    def allocate_loopback_port(self) -> int:
        return 11435

    def start_scope(
        self, argv: tuple[str, ...], environment: dict[str, str]
    ) -> FakeProcess:
        self.started.append((argv, environment))
        return FakeProcess()

    def process_running(self, process: object) -> bool:
        return self.process_up

    def scope_contains(self, unit_name: str, pid: int) -> bool:
        return self.cgroup_matches

    def fetch_tags(
        self, port: int, *, timeout_seconds: float, max_bytes: int
    ) -> set[str] | None:
        assert port == 11435
        self.tag_probe_limits = (timeout_seconds, max_bytes)
        return self.tags

    def stop_scope(self, unit_name: str, process: object) -> None:
        self.stopped.append((unit_name, process))


def make_executable(path: Path) -> Path:
    path.write_bytes(b"#!/bin/sh\nexit 0\n")
    path.chmod(0o700)
    return path


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


def host_snapshot() -> OllamaHostSnapshot:
    return OllamaHostSnapshot(available_cpus=(0, 1, 2, 3), effective_uid=os.geteuid())


def planned(tmp_path: Path):
    return plan_local_instance(
        valid_instance(tmp_path),
        host_snapshot(),
        selected_provider_model_ids=("llama-small", "qwen-small"),
    )


def running(tmp_path: Path, runtime: FakeRuntime):
    return start_local_instance(planned(tmp_path), runtime=runtime)


def test_executable_symlink_is_rejected(tmp_path: Path) -> None:
    target = make_executable(tmp_path / "real")
    link = tmp_path / "ollama"
    link.symlink_to(target)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_local_instance(
            valid_instance(tmp_path, ollama_executable=str(link)), host_snapshot()
        )


def test_symlinked_path_ancestor_is_rejected(tmp_path: Path) -> None:
    real = make_models_directory(tmp_path / "real")
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_local_instance(
            valid_instance(tmp_path, models_directory=str(linked)), host_snapshot()
        )


def test_executable_must_be_regular_executable_and_not_mutable_by_other_users(
    tmp_path: Path,
) -> None:
    executable = make_executable(tmp_path / "ollama")
    executable.chmod(0o722)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_local_instance(
            valid_instance(tmp_path, ollama_executable=str(executable)), host_snapshot()
        )


def test_models_directory_must_be_private_or_administratively_owned(
    tmp_path: Path,
) -> None:
    models = make_models_directory(tmp_path / "models")
    models.chmod(0o770)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_invalid"):
        plan_local_instance(
            valid_instance(tmp_path, models_directory=str(models)), host_snapshot()
        )


def test_plan_pins_paths_and_maps_validated_cpu_profile(tmp_path: Path) -> None:
    instance = valid_instance(tmp_path)

    plan = plan_local_instance(
        instance,
        host_snapshot(),
        selected_provider_model_ids=("provider/llama", "provider/qwen"),
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
    argv, environment = runtime.started[0]
    assert argv == (
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
        plan.instance.ollama_executable,
        "serve",
    )
    assert re.fullmatch(r"codex-master-ollama-[a-f0-9]{32}\.scope", result.unit_name)
    assert environment == {
        "OLLAMA_HOST": "127.0.0.1:11435",
        "OLLAMA_MODELS": plan.instance.models_directory,
    }


def test_system_runtime_executes_argv_without_shell_or_ambient_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def popen(argv: tuple[str, ...], **kwargs: object) -> FakeProcess:
        calls.append((argv, kwargs))
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", popen)
    runtime = SystemOllamaRuntime()
    argv = (
        "/usr/bin/systemd-run",
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "--unit=codex-master-ollama-0123456789abcdef0123456789abcdef.scope",
        "--slice=codex-master.slice",
        "--property=AllowedCPUs=0-3",
        "--property=CPUQuota=350%",
        "--property=CPUWeight=40",
        "/trusted/ollama",
        "serve",
    )
    environment = {
        "OLLAMA_HOST": "127.0.0.1:11435",
        "OLLAMA_MODELS": "/private/models",
    }

    runtime.start_scope(argv, environment)

    assert calls == [
        (
            argv,
            {
                "env": environment,
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "close_fds": True,
                "shell": False,
            },
        )
    ]


def test_system_runtime_rejects_non_allowlisted_argv_before_process_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_popen(*_args: object, **_kwargs: object) -> FakeProcess:
        raise AssertionError("non-allowlisted argv reached Popen")

    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)

    with pytest.raises(OllamaRuntimeError, match="provider.operation_not_allowed"):
        SystemOllamaRuntime().start_scope(
            ("/bin/sh", "-c", "ollama serve"),
            {"OLLAMA_HOST": "127.0.0.1:11435", "OLLAMA_MODELS": "/models"},
        )


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

    assert runtime.stopped == [(active.unit_name, active.process)]


def test_host_probe_uses_kernel_affinity_snapshot() -> None:
    snapshot = probe_ollama_host(runtime=FakeRuntime())

    assert snapshot.available_cpus == (0, 1, 2, 3)
    assert snapshot.effective_uid == os.geteuid()
