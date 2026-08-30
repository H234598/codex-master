from __future__ import annotations

import inspect
import os
import runpy
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

import codex_master.resource_cgroup as resource_cgroup
from codex_master.resource_cgroup import (
    CgroupPreflightError,
    CgroupPreflightV1,
    CgroupProfileV1,
    CgroupIoPressureEvidenceV1,
    CpuTopologyV1,
    OllamaCpuProfile,
    PreparedAgentScope,
    ResourceCgroupError,
    read_hive_io_pressure,
    derive_cgroup_profile,
    parse_cpu_topology,
    require_cgroup_preflight,
    start_verified_scope,
)


GIB = 1024**3
GATE = Path(__file__).parents[1] / "bin" / "codex-master-resource-scope-gate"
REQUIRED_CONTROLLERS = frozenset({"cpu", "cpuset", "memory", "pids", "io"})


class FakeCgroupAdapter:
    def __init__(
        self,
        *,
        documents: dict[Path, bytes] | None = None,
        preflight: CgroupPreflightV1 | None = None,
        fail_at: str | None = None,
        topology_snapshots: list[object] | None = None,
    ) -> None:
        self.documents = documents or {}
        self.preflight = preflight or _preflight()
        self.fail_at = fail_at
        self.topology_snapshots = topology_snapshots or []
        self.events: list[str] = []
        self.cleaned: list[PreparedAgentScope] = []

    def read_bounded_cgroup_bytes(self, path: Path, *, max_bytes: int) -> bytes:
        self.events.append(f"read:{path}")
        if max_bytes != 4096 or path not in self.documents:
            raise CgroupPreflightError("cgroup_preflight_failed")
        return self.documents[path]

    def read_optional_cpu_topology_bytes(self, path: Path, *, max_bytes: int) -> bytes | None:
        self.events.append(f"read-optional:{path}")
        if max_bytes != 4096:
            raise CgroupPreflightError("cgroup_preflight_failed")
        return self.documents.get(path)

    def capture_cpu_topology_snapshot(self, cpus: tuple[int, ...]) -> object:
        self.events.append("snapshot:/sys/devices/system/cpu/present")
        if self.topology_snapshots:
            return self.topology_snapshots.pop(0)
        return ("stable", cpus)

    def inspect_preflight(self) -> CgroupPreflightV1:
        self.events.append("inspect")
        if self.fail_at == "inspect":
            raise CgroupPreflightError("cgroup_preflight_failed")
        return self.preflight

    def start_held_scope(
        self, *, profile: CgroupProfileV1, socket_name: str, session_name: str
    ) -> PreparedAgentScope:
        self.events.append("start")
        if self.fail_at == "start":
            raise CgroupPreflightError("cgroup_preflight_failed")
        return PreparedAgentScope(
            unit_name="codex-master-test.scope",
            socket_name=socket_name,
            session_name=session_name,
            control_group="user.slice/codex-master-test.scope",
            gate_pid=4241,
            challenge="a" * 64,
        )

    def verify_scope(self, scope: PreparedAgentScope, profile: CgroupProfileV1) -> None:
        self.events.append("verify_scope")
        if self.fail_at == "verify_scope":
            raise CgroupPreflightError("cgroup_preflight_failed")

    def release_scope(self, scope: PreparedAgentScope) -> int:
        self.events.append("release")
        if self.fail_at == "release":
            raise CgroupPreflightError("cgroup_preflight_failed")
        return 4242

    def confirm_scope(self, scope: PreparedAgentScope) -> int:
        self.events.append("confirm")
        if self.fail_at == "confirm":
            raise CgroupPreflightError("cgroup_preflight_failed")
        return 4242

    def verify_tmux_membership_and_inheritance(self, scope: PreparedAgentScope, tmux_pid: int) -> None:
        self.events.append("verify_tmux")
        if tmux_pid != 4242 or self.fail_at == "verify_tmux":
            raise CgroupPreflightError("cgroup_preflight_failed")

    def cleanup_new_scope(self, scope: PreparedAgentScope) -> None:
        self.events.append("cleanup")
        self.cleaned.append(scope)

    def read_hive_io_pressure(self) -> CgroupIoPressureEvidenceV1 | None:
        try:
            return resource_cgroup._parse_cgroup_pressure(
                self.read_bounded_cgroup_bytes(
                    Path("/sys/fs/cgroup/user.slice/codex-master.slice/io.pressure"),
                    max_bytes=4096,
                )
            )
        except Exception:
            return None


def _preflight(
    *,
    unified_v2: bool = True,
    controllers: frozenset[str] = REQUIRED_CONTROLLERS,
    subtree: frozenset[str] = REQUIRED_CONTROLLERS,
    parent_cpuset: tuple[int, ...] = tuple(range(12)),
) -> CgroupPreflightV1:
    return CgroupPreflightV1(
        unified_v2=unified_v2,
        controllers=controllers,
        subtree_controllers=subtree,
        parent_effective_cpuset=parent_cpuset,
        io_physical_isolation_proven=False,
    )


def _topology(*, efficiency_cpus: tuple[int, ...] = tuple(range(4, 12))) -> CpuTopologyV1:
    return CpuTopologyV1(
        physical_cores=tuple((cpu,) for cpu in range(12)),
        efficiency_cpus=efficiency_cpus,
    )


def _profile() -> CgroupProfileV1:
    return derive_cgroup_profile(
        _topology(), approved_cpuset=tuple(range(4, 12)), mem_total_bytes=16 * GIB
    )


def _topology_documents(*, present: bytes = b"0-11\n", malformed: bool = False) -> dict[Path, bytes]:
    documents = {Path("/sys/devices/system/cpu/present"): present}
    for cpu in range(12):
        prefix = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
        documents[prefix / "physical_package_id"] = b"0\n"
        documents[prefix / "core_id"] = (b"bad\n" if malformed and cpu == 0 else f"{cpu}\n".encode())
        documents[prefix / "core_type"] = b"efficiency\n" if cpu >= 4 else b"performance\n"
    return documents


def _write_topology_documents(root: Path, documents: dict[Path, bytes]) -> None:
    source_root = Path("/sys/devices/system/cpu")
    for source, payload in documents.items():
        target = root / source.relative_to(source_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)


def _approved_provider_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    runner: _FakeSystemdRunner | None = None,
    present: bytes = b"0-11\n",
    controllers: bytes = b"cpu cpuset memory pids io\n",
    subtree_controllers: bytes = b"cpu cpuset memory pids io\n",
    parent_cpuset: bytes = b"0-11\n",
) -> _FakeSystemdRunner:
    cpu_root = tmp_path / "cpu"
    _write_topology_documents(cpu_root, _topology_documents(present=present))
    cgroup_root = tmp_path / "cgroup"
    slice_root = cgroup_root / "user.slice" / "codex-master.slice"
    slice_root.mkdir(parents=True)
    (slice_root / "cgroup.controllers").write_bytes(controllers)
    (slice_root / "cgroup.subtree_control").write_bytes(subtree_controllers)
    (slice_root / "cpuset.cpus.effective").write_bytes(parent_cpuset)
    monkeypatch.setattr(resource_cgroup, "CPU_TOPOLOGY_ROOT", cpu_root)
    monkeypatch.setattr(resource_cgroup, "CPU_PRESENT_PATH", cpu_root / "present")
    monkeypatch.setattr(resource_cgroup, "CGROUP_ROOT", cgroup_root)
    return runner or _FakeSystemdRunner()


def _write_tmux_children_fact(
    tmp_path: Path, *, tmux_pid: int = 4242, children_payload: bytes | None = b"4243 "
) -> Path:
    proc_root = tmp_path / "proc"
    children = proc_root / str(tmux_pid) / "task" / str(tmux_pid) / "children"
    children.parent.mkdir(parents=True)
    if children_payload is not None:
        children.write_bytes(children_payload)
    return proc_root


def _provide_user_bus_socket_fact(monkeypatch: pytest.MonkeyPatch) -> None:
    bus = Path("/run/user") / str(os.getuid()) / "bus"
    real_lstat = os.lstat
    socket_metadata = os.stat_result((stat.S_IFSOCK | 0o600, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    def lstat(path: os.PathLike[str] | str) -> os.stat_result:
        if Path(path) == bus:
            return socket_metadata
        return real_lstat(path)

    monkeypatch.setattr(resource_cgroup.os, "lstat", lstat)


def _nonhybrid_topology_documents() -> dict[Path, bytes]:
    documents = _topology_documents()
    for cpu in range(12):
        prefix = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
        del documents[prefix / "core_type"]
        documents[prefix / "core_id"] = f"{cpu // 2 if cpu < 4 else cpu}\n".encode()
    return documents


def test_preflight_requires_unified_v2_and_cpu_cpuset_memory_pids_io_delegation() -> None:
    invalid = (
        {"unified_v2": False},
        {"controllers": frozenset({"cpu", "memory", "pids", "io"})},
        {"subtree": frozenset({"cpu", "cpuset", "memory", "pids"})},
    )
    for arguments in invalid:
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            _preflight(**arguments)


def test_resource_cgroup_is_the_only_sys_cpu_topology_cpuset_and_cgroup_parser_owner() -> None:
    adapter = FakeCgroupAdapter(documents=_topology_documents())
    topology = parse_cpu_topology(adapter)

    assert topology.efficiency_cpus == tuple(range(4, 12))
    assert all(event.split(":", 1)[-1].startswith("/sys/devices/system/cpu/") for event in adapter.events)


@pytest.mark.parametrize(
    "method_name",
    (
        "inspect_preflight",
        "bind_monitor_parent_slice_control_group",
        "start_held_scope",
        "verify_scope",
        "release_scope",
        "verify_tmux_membership_and_inheritance",
        "cleanup_new_scope",
    ),
)
def test_systemd_user_cgroup_adapter_disallows_instance_method_shadowing(
    method_name: str,
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _approved_provider_runner(monkeypatch, tmp_path)
    adapter = resource_cgroup.SystemdUserCgroupAdapter(runner=runner)
    descriptor = getattr(resource_cgroup.SystemdUserCgroupAdapter, method_name)

    assert not hasattr(adapter, "__dict__")
    with pytest.raises(AttributeError):
        setattr(adapter, method_name, lambda *args, **kwargs: None)
    assert getattr(resource_cgroup.SystemdUserCgroupAdapter, method_name) is descriptor
    assert getattr(adapter, method_name).__func__ is descriptor


def test_systemd_user_cgroup_adapter_binds_runner_and_root_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _approved_provider_runner(monkeypatch, tmp_path)
    adapter = resource_cgroup.SystemdUserCgroupAdapter(runner=runner)
    bound_root = adapter._cgroup_root

    assert adapter._runner is runner
    assert bound_root.path == tmp_path / "cgroup"
    with pytest.raises(AttributeError):
        adapter._runner = _FakeSystemdRunner()
    with pytest.raises(AttributeError):
        adapter._cgroup_root = bound_root
    assert adapter._runner is runner
    assert adapter._cgroup_root is bound_root


def test_user_bus_available_converts_preflight_failure_to_false(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    adapter = resource_cgroup.SystemdUserCgroupAdapter(
        runner=_approved_provider_runner(monkeypatch, tmp_path)
    )
    monkeypatch.setattr(
        resource_cgroup.SystemdUserCgroupAdapter,
        "_user_bus_socket_present",
        lambda _self: True,
    )
    assert adapter.user_bus_available() is True

    def unavailable(_self: object) -> bool:
        raise resource_cgroup.CgroupPreflightError("cgroup_preflight_failed")

    monkeypatch.setattr(
        resource_cgroup.SystemdUserCgroupAdapter,
        "_user_bus_socket_present",
        unavailable,
    )
    assert adapter.user_bus_available() is False


def test_approved_runtime_provider_constructs_exact_adapter_internally(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _approved_provider_runner(monkeypatch, tmp_path)

    result = resource_cgroup.build_approved_cgroup_runtime(
        runner=runner,
        mem_total_bytes=16 * GIB,
    )

    assert result.profile.cpuset_cpus == tuple(range(4, 12))
    assert result.profile.cpuset_expression == "4-11"
    assert type(result.adapter) is resource_cgroup.SystemdUserCgroupAdapter
    assert result.adapter._runner is runner
    parameters = inspect.signature(resource_cgroup.build_approved_cgroup_runtime).parameters
    assert "adapter" not in parameters
    assert "adapter_factory" not in parameters


def test_approved_runtime_provider_returns_final_immutable_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _approved_provider_runner(monkeypatch, tmp_path)

    result = resource_cgroup.build_approved_cgroup_runtime(
        runner=runner,
        mem_total_bytes=16 * GIB,
    )

    assert result.profile.cpuset_cpus == tuple(range(4, 12))
    assert type(result.adapter) is resource_cgroup.SystemdUserCgroupAdapter
    assert result.adapter._runner is runner
    assert result.preflight == _preflight()
    assert not hasattr(result, "__dict__")
    assignments = (
        (result, "profile", result.profile),
        (result, "adapter", result.adapter),
        (result, "preflight", result.preflight),
        (result.profile, "cpuset_cpus", (0, 1)),
        (result.profile, "cpu_quota_percent", 1),
        (result.profile, "cpu_weight", 1),
        (result.profile, "memory_high_bytes", 1),
        (result.profile, "memory_max_bytes", 2),
        (result.profile, "memory_swap_max_bytes", 0),
        (result.profile, "io_weight", 1),
        (result.preflight, "unified_v2", False),
        (result.preflight, "controllers", frozenset()),
        (result.preflight, "subtree_controllers", frozenset()),
        (result.preflight, "parent_effective_cpuset", (0, 1)),
        (result.preflight, "io_physical_isolation_proven", True),
    )
    for target, field_name, replacement in assignments:
        with pytest.raises(AttributeError):
            setattr(target, field_name, replacement)


def test_approved_monitor_runtime_binds_exact_self_service_parent_without_user_bus(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _approved_provider_runner(monkeypatch, tmp_path)
    proc_root = tmp_path / "proc"
    cgroup = proc_root / str(os.getpid()) / "cgroup"
    cgroup.parent.mkdir(parents=True)
    cgroup.write_bytes(
        b"0::/user.slice/codex-master.slice/codex-master-resource-monitor.service\n"
    )
    monkeypatch.setattr(resource_cgroup, "PROC_ROOT", proc_root)

    result = resource_cgroup.build_approved_cgroup_runtime(
        runner=runner,
        mem_total_bytes=16 * GIB,
        monitor_self_cgroup=True,
    )

    assert result.adapter._target_slice_control_group_path == "user.slice/codex-master.slice"
    assert runner.calls == []


@pytest.mark.parametrize(
    "payload",
    (
        b"0::/user.slice/codex-master.slice/foreign.service\n",
        b"0::/user.slice/other.slice/codex-master-resource-monitor.service\n",
        b"0::/user.slice/codex-master.slice/codex-master-resource-monitor.service\n1::/\n",
        b"1:cpu:/user.slice/codex-master.slice/codex-master-resource-monitor.service\n",
    ),
)
def test_approved_monitor_runtime_rejects_nonexact_self_cgroup_evidence_without_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, payload: bytes
) -> None:
    runner = _approved_provider_runner(monkeypatch, tmp_path)
    proc_root = tmp_path / "proc"
    cgroup = proc_root / str(os.getpid()) / "cgroup"
    cgroup.parent.mkdir(parents=True)
    cgroup.write_bytes(payload)
    monkeypatch.setattr(resource_cgroup, "PROC_ROOT", proc_root)

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        resource_cgroup.build_approved_cgroup_runtime(
            runner=runner,
            mem_total_bytes=16 * GIB,
            monitor_self_cgroup=True,
        )

    assert runner.calls == []


def test_approved_runtime_provider_rejects_topology_missing_approved_cpu(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _approved_provider_runner(
        monkeypatch,
        tmp_path,
        present=b"0-3,5-11\n",
    )

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        resource_cgroup.build_approved_cgroup_runtime(
            runner=runner,
            mem_total_bytes=16 * GIB,
        )


def test_approved_runtime_provider_rejects_parent_mask_missing_approved_cpu(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _approved_provider_runner(
        monkeypatch,
        tmp_path,
        parent_cpuset=b"0-10\n",
    )

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        resource_cgroup.build_approved_cgroup_runtime(
            runner=runner,
            mem_total_bytes=16 * GIB,
        )


def test_topology_uses_nonhybrid_route_only_when_every_core_type_leaf_is_cleanly_missing() -> None:
    documents = _nonhybrid_topology_documents()
    topology = parse_cpu_topology(FakeCgroupAdapter(documents=documents))

    assert topology == CpuTopologyV1(
        physical_cores=((0, 1), (2, 3), (4,), (5,), (6,), (7,), (8,), (9,), (10,), (11,)),
        efficiency_cpus=(),
    )

    documents[Path("/sys/devices/system/cpu/cpu0/topology/core_type")] = b"performance\n"
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        parse_cpu_topology(FakeCgroupAdapter(documents=documents))


def test_topology_requires_stable_cpu_present_and_parent_snapshot() -> None:
    adapter = FakeCgroupAdapter(
        documents=_nonhybrid_topology_documents(),
        topology_snapshots=[("before",), ("after",)],
    )

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        parse_cpu_topology(adapter)


def test_topology_missing_core_type_does_not_hide_unreadable_malformed_or_symlink_leaf(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    malformed = _topology_documents()
    malformed[Path("/sys/devices/system/cpu/cpu0/topology/core_type")] = b"unknown\n"
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        parse_cpu_topology(FakeCgroupAdapter(documents=malformed))

    class _UnreadableCoreTypeAdapter(FakeCgroupAdapter):
        def read_optional_cpu_topology_bytes(
            self, path: Path, *, max_bytes: int
        ) -> bytes | None:
            if path.name == "core_type":
                raise PermissionError("denied")
            return super().read_optional_cpu_topology_bytes(path, max_bytes=max_bytes)

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        parse_cpu_topology(_UnreadableCoreTypeAdapter(documents=_nonhybrid_topology_documents()))

    cgroup_root = tmp_path / "cgroup"
    cpu_root = tmp_path / "cpu"
    topology_root = cpu_root / "cpu0" / "topology"
    cgroup_root.mkdir()
    topology_root.mkdir(parents=True)
    (cpu_root / "present").write_bytes(b"0\n")
    (topology_root / "physical_package_id").write_bytes(b"0\n")
    (topology_root / "core_id").write_bytes(b"0\n")
    monkeypatch.setattr(resource_cgroup, "CGROUP_ROOT", cgroup_root)
    monkeypatch.setattr(resource_cgroup, "CPU_TOPOLOGY_ROOT", cpu_root)
    monkeypatch.setattr(resource_cgroup, "CPU_PRESENT_PATH", cpu_root / "present")
    adapter = resource_cgroup.SystemdUserCgroupAdapter(runner=_FakeSystemdRunner())
    assert parse_cpu_topology(adapter) == CpuTopologyV1(
        physical_cores=((0,),), efficiency_cpus=()
    )

    (topology_root / "target").write_bytes(b"performance\n")
    (topology_root / "core_type").symlink_to("target")
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        parse_cpu_topology(adapter)


def test_topology_rejects_core_type_enoent_after_bound_parent_and_optional_non_leaf_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cgroup_root = tmp_path / "cgroup"
    cpu_root = tmp_path / "cpu"
    topology_root = cpu_root / "cpu0" / "topology"
    cgroup_root.mkdir()
    topology_root.mkdir(parents=True)
    (cpu_root / "present").write_bytes(b"0\n")
    (topology_root / "physical_package_id").write_bytes(b"0\n")
    (topology_root / "core_id").write_bytes(b"0\n")
    (topology_root / "core_type").write_bytes(b"performance\n")
    monkeypatch.setattr(resource_cgroup, "CGROUP_ROOT", cgroup_root)
    monkeypatch.setattr(resource_cgroup, "CPU_TOPOLOGY_ROOT", cpu_root)
    monkeypatch.setattr(resource_cgroup, "CPU_PRESENT_PATH", cpu_root / "present")
    adapter = resource_cgroup.SystemdUserCgroupAdapter(runner=_FakeSystemdRunner())

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        adapter.read_optional_cpu_topology_bytes(cpu_root / "present", max_bytes=4096)

    real_open = resource_cgroup.os.open

    def _race_open(path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        if path == "core_type" and dir_fd is not None:
            raise FileNotFoundError("core_type vanished after parent bind")
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(resource_cgroup.os, "open", _race_open)
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        parse_cpu_topology(adapter)


def test_optional_core_type_rejects_extreme_decimal_cpu_path_with_canonical_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cgroup_root = tmp_path / "cgroup"
    cpu_root = tmp_path / "cpu"
    cgroup_root.mkdir()
    cpu_root.mkdir()
    monkeypatch.setattr(resource_cgroup, "CGROUP_ROOT", cgroup_root)
    monkeypatch.setattr(resource_cgroup, "CPU_TOPOLOGY_ROOT", cpu_root)
    adapter = resource_cgroup.SystemdUserCgroupAdapter(runner=_FakeSystemdRunner())
    path = cpu_root / f"cpu{'9' * 5000}" / "topology" / "core_type"

    with pytest.raises(CgroupPreflightError) as captured:
        adapter.read_optional_cpu_topology_bytes(path, max_bytes=4096)

    assert type(captured.value) is CgroupPreflightError
    assert captured.value.args == ("cgroup_preflight_failed",)


def test_preflight_rejects_missing_subtree_controller_or_effective_parent_cpuset() -> None:
    profile = _profile()
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        require_cgroup_preflight(
            FakeCgroupAdapter(preflight=_preflight(parent_cpuset=tuple(range(4, 11)))), profile
        )
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        _preflight(parent_cpuset=(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10))


def test_topology_rejects_malformed_oversize_and_inconsistent_cpu_records() -> None:
    malformed = FakeCgroupAdapter(documents=_topology_documents(malformed=True))
    oversized = FakeCgroupAdapter(documents=_topology_documents(present=b"0-999999999999999999\n"))
    inconsistent = _topology_documents()
    inconsistent[Path("/sys/devices/system/cpu/cpu4/topology/core_type")] = b"performance\n"
    inconsistent[Path("/sys/devices/system/cpu/cpu5/topology/core_id")] = b"4\n"
    for adapter in (malformed, oversized, FakeCgroupAdapter(documents=inconsistent)):
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            parse_cpu_topology(adapter)


def test_read_hive_io_pressure_reads_valid_pressure_payload() -> None:
    adapter = FakeCgroupAdapter(
        documents={
            Path("/sys/fs/cgroup/user.slice/codex-master.slice/io.pressure"): (
                b"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
                b"full avg10=1.23 avg60=2.34 avg300=3.45 total=4\n"
            )
        }
    )

    assert read_hive_io_pressure(adapter=adapter) == CgroupIoPressureEvidenceV1(
        some_avg10=0.0,
        full_avg10=1.23,
        full_avg60=2.34,
    )


def test_read_hive_io_pressure_rejects_malformed_pressure_payload() -> None:
    payloads = (
        b"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        b"some avg10=invalid avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        b"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=invalid\n",
    )
    for payload in payloads:
        adapter = FakeCgroupAdapter(
            documents={Path("/sys/fs/cgroup/user.slice/codex-master.slice/io.pressure"): payload}
        )
        assert read_hive_io_pressure(adapter=adapter) is None


def test_read_hive_io_pressure_uses_control_group_from_target_slice_systemd_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target_control_group = "/user.slice/user-1000.slice/user@1000.service/codex.slice/codex-master.slice"
    payload = (
        b"some avg10=12.34 avg60=11.11 avg300=10.00 total=7\n"
        b"full avg10=34.56 avg60=7.89 avg300=6.78 total=8\n"
    )
    runner = _FakeSystemdRunner(target_slice_control_group=target_control_group)
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    pressure_file = tmp_path / "cgroup" / target_control_group.lstrip("/") / "io.pressure"
    pressure_file.parent.mkdir(parents=True)
    pressure_file.write_bytes(payload)

    assert adapter.read_hive_io_pressure() == CgroupIoPressureEvidenceV1(
        some_avg10=12.34,
        full_avg10=34.56,
        full_avg60=7.89,
    )


@pytest.mark.parametrize(
    "some_avg10,full_avg10,full_avg60",
    (
        (float("nan"), 0.0, 0.0),
        (0.0, -1.0, 0.0),
        (0.0, 0.0, 101.0),
        (True, 0.0, 0.0),
        (0.0, False, 0.0),
        (0.0, 0.0, True),
    ),
)
def test_hive_io_pressure_evidence_rejects_invalid_pressure_values(
    some_avg10: float, full_avg10: float, full_avg60: float
) -> None:
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        CgroupIoPressureEvidenceV1(
            some_avg10=some_avg10,
            full_avg10=full_avg10,
            full_avg60=full_avg60,
        )


def test_profile_rejects_unapproved_empty_duplicate_hybrid_or_outside_parent_cpu_set() -> None:
    topology = _topology()
    for approved in ((), (4, 4, 5, 6, 7, 8, 9, 10, 11), tuple(range(3, 12))):
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            derive_cgroup_profile(topology, approved_cpuset=approved, mem_total_bytes=16 * GIB)

    profile = _profile()
    outside = _preflight(parent_cpuset=tuple(range(4, 11)))
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        require_cgroup_preflight(FakeCgroupAdapter(preflight=outside), profile)


def test_profile_computes_i5_generic_and_memory_bounds_or_fails_closed() -> None:
    i5 = _profile()
    assert i5.cpuset_cpus == tuple(range(4, 12))
    assert i5.cpuset_expression == "4-11"
    assert (i5.cpu_quota_percent, i5.cpu_weight, i5.io_weight) == (750, 50, 50)
    assert (i5.memory_high_bytes, i5.memory_max_bytes, i5.memory_swap_max_bytes) == (
        9 * GIB,
        12 * GIB,
        8 * GIB,
    )

    generic_hybrid = CpuTopologyV1(
        physical_cores=((0,), (1,), (2,), (3,), (4,), (5,)), efficiency_cpus=(4, 5)
    )
    assert derive_cgroup_profile(
        generic_hybrid, approved_cpuset=(4, 5), mem_total_bytes=16 * GIB
    ).cpuset_cpus == (4, 5)

    generic_nonhybrid = CpuTopologyV1(
        physical_cores=((0, 1), (2, 3), (4, 5), (6, 7)), efficiency_cpus=()
    )
    assert derive_cgroup_profile(
        generic_nonhybrid, approved_cpuset=(4, 5, 6, 7), mem_total_bytes=16 * GIB
    ).cpuset_cpus == (4, 5, 6, 7)

    for topology, approved, memory in (
        (CpuTopologyV1(physical_cores=((0,), (1,)), efficiency_cpus=()), (), 16 * GIB),
        (_topology(), tuple(range(4, 12)), 7 * GIB),
        (_topology(), tuple(range(4, 12)), 1 << 63),
    ):
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            derive_cgroup_profile(topology, approved_cpuset=approved, mem_total_bytes=memory)


def test_profile_rejects_two_physical_core_hybrid_before_efficiency_branch() -> None:
    two_core_hybrid = CpuTopologyV1(
        physical_cores=((0,), (1,)), efficiency_cpus=(1,)
    )

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        derive_cgroup_profile(two_core_hybrid, approved_cpuset=(1,), mem_total_bytes=16 * GIB)


@pytest.mark.parametrize("allowed", ["", "0-", "3-1", "0,0", "all", "4-99"])
def test_ollama_cpu_profile_rejects_invalid_cpuset(allowed: str) -> None:
    with pytest.raises(ResourceCgroupError, match="resource.cgroup_profile_invalid"):
        OllamaCpuProfile.parse(allowed, 200, 50, available_cpus=set(range(12)))


def test_ollama_cpu_profile_maps_exact_systemd_properties() -> None:
    profile = OllamaCpuProfile.parse("4-7", 350, 40, available_cpus=set(range(12)))

    assert profile.systemd_properties() == {
        "AllowedCPUs": "4-7",
        "CPUQuota": "350%",
        "CPUWeight": "40",
    }


@pytest.mark.parametrize("quota,weight", [(0, 50), (10001, 50), (200, 0), (200, 10001)])
def test_ollama_cpu_profile_rejects_out_of_range_cpu_limits(quota: int, weight: int) -> None:
    with pytest.raises(ResourceCgroupError, match="resource.cgroup_profile_invalid"):
        OllamaCpuProfile.parse("4-7", quota, weight, available_cpus=set(range(12)))


def test_scope_runner_uses_held_scope_before_tmux_and_readbacks_every_required_property() -> None:
    adapter = FakeCgroupAdapter()
    scope = start_verified_scope(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )

    assert scope.unit_name == "codex-master-test.scope"
    assert adapter.events == ["inspect", "start", "verify_scope", "release", "confirm", "verify_tmux"]
    assert adapter.cleaned == []


def test_scope_runner_dispatches_command_between_gate_ready_and_elf_attestation() -> None:
    adapter = FakeCgroupAdapter()

    scope = start_verified_scope(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
        after_release=lambda ready_scope: adapter.events.append(
            f"send-keys:{ready_scope.session_name}"
        ),
    )

    assert scope.unit_name == "codex-master-test.scope"
    assert adapter.events == [
        "inspect",
        "start",
        "verify_scope",
        "release",
        "send-keys:scope-session.1",
        "confirm",
        "verify_tmux",
    ]


def test_scope_runner_cleans_when_gate_attestation_fails_after_command_dispatch() -> None:
    adapter = FakeCgroupAdapter(fail_at="confirm")

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        start_verified_scope(
            adapter,
            profile=_profile(),
            socket_name="scope_socket-1",
            session_name="scope-session.1",
            after_release=lambda _ready_scope: adapter.events.append("send-keys"),
        )

    assert adapter.events == [
        "inspect",
        "start",
        "verify_scope",
        "release",
        "send-keys",
        "confirm",
        "cleanup",
    ]


def test_scope_runner_never_uses_shell_sudo_taskset_or_move_existing_pid() -> None:
    adapter = FakeCgroupAdapter()
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        start_verified_scope(
            adapter,
            profile=_profile(),
            socket_name="../scope",
            session_name="scope-session.1",
        )
    assert adapter.events == []


def test_scope_failure_before_publication_cleans_only_new_scope_and_never_touches_existing_pid() -> None:
    adapter = FakeCgroupAdapter(fail_at="verify_scope")
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        start_verified_scope(
            adapter,
            profile=_profile(),
            socket_name="scope_socket-1",
            session_name="scope-session.1",
        )
    assert adapter.events == ["inspect", "start", "verify_scope", "cleanup"]
    assert [scope.unit_name for scope in adapter.cleaned] == ["codex-master-test.scope"]


def test_scope_runner_checks_tmux_pid_cgroup_and_child_inheritance_before_success() -> None:
    adapter = FakeCgroupAdapter(fail_at="verify_tmux")
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        start_verified_scope(
            adapter,
            profile=_profile(),
            socket_name="scope_socket-1",
            session_name="scope-session.1",
        )
    assert adapter.events == ["inspect", "start", "verify_scope", "release", "confirm", "verify_tmux", "cleanup"]


def test_io_weight_is_not_reported_as_proven_physical_isolation_without_evidence() -> None:
    preflight = require_cgroup_preflight(FakeCgroupAdapter(), _profile())
    assert preflight.io_physical_isolation_proven is False
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        CgroupPreflightV1(
            unified_v2=True,
            controllers=REQUIRED_CONTROLLERS,
            subtree_controllers=REQUIRED_CONTROLLERS,
            parent_effective_cpuset=tuple(range(12)),
            io_physical_isolation_proven=True,
        )


def test_scope_gate_rejects_general_launcher_token_and_extra_argv_before_exec() -> None:
    control = "codex-master-resource-" + "a" * 32
    rejected = (
        ("invalid", "socket", "session"),
        (control, "socket", "session", "unexpected"),
        (control, "../socket", "session"),
        (control, "socket", "../session"),
    )
    for arguments in rejected:
        result = subprocess.run(
            [sys.executable, str(GATE), *arguments],
            capture_output=True,
            check=False,
            timeout=5,
        )
        assert result.returncode != 0
        assert result.stdout == b""
        assert result.stderr == b""


class _GateExecveCalled(Exception):
    pass


class _GateExited(Exception):
    pass


class _GateControlSocket:
    def __init__(self, release: bytes) -> None:
        self.address: bytes | None = None
        self.sent = bytearray()
        self.release = bytearray(release)
        self.closed = False

    def connect(self, address: bytes) -> None:
        self.address = address

    def sendall(self, payload: bytes) -> None:
        self.sent.extend(payload)

    def recv(self, max_bytes: int) -> bytes:
        if not self.release:
            return b""
        chunk = bytes(self.release[:max_bytes])
        del self.release[:max_bytes]
        return chunk

    def close(self) -> None:
        self.closed = True


def test_scope_gate_generates_internal_challenge_and_executes_only_fixed_tmux_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    challenge = "c" * 64
    control = "codex-master-resource-" + "d" * 32
    called: dict[str, object] = {}
    control_socket = _GateControlSocket(f"{challenge}\n".encode())

    def _execve(path: str, argv: list[str], env: dict[str, str]) -> None:
        called.update(path=path, argv=argv, env=env)
        raise _GateExecveCalled

    def _exit(_status: int) -> None:
        raise _GateExited

    runner = tmp_path / "runner"
    runner.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    runner.chmod(0o700)
    expected = runner.stat()
    runner_fd = os.open(runner, getattr(os, "O_PATH", os.O_RDONLY))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(GATE),
            control,
            "scope_socket-1",
            "scope-session.1",
            str(os.getpid()),
            str(runner_fd),
            str(expected.st_dev),
            str(expected.st_ino),
        ],
    )
    monkeypatch.setattr(os, "execve", _execve)
    monkeypatch.setattr(os, "fork", lambda: 0)
    monkeypatch.setattr(os, "_exit", _exit)
    monkeypatch.setattr(socket, "socket", lambda family, kind: control_socket)
    import secrets

    monkeypatch.setattr(secrets, "token_hex", lambda size: challenge if size == 32 else "")

    try:
        with pytest.raises(_GateExecveCalled):
            runpy.run_path(str(GATE), run_name="__main__")

        runner_path = called["env"]["CODEX_MASTER_RUNNER_EXEC_PATH"]
        assert runner_path.startswith(f"/proc/{os.getpid()}/fd/")
        gate_fd = int(runner_path.rsplit("/", 1)[1])
        assert gate_fd != runner_fd
        assert os.fstat(gate_fd).st_ino == expected.st_ino
        os.close(gate_fd)
    finally:
        os.close(runner_fd)

    assert control_socket.address == b"\0" + control.encode()
    assert bytes(control_socket.sent) == f"{challenge}\n".encode()
    assert control_socket.closed is True
    assert called == {
        "path": "/usr/bin/tmux",
        "argv": [
            "/usr/bin/tmux",
            "-L",
            "scope_socket-1",
            "new-session",
            "-d",
            "-s",
            "scope-session.1",
        ],
        "env": {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "CODEX_MASTER_RUNNER_EXEC_PATH": runner_path,
        },
    }


def test_scope_gate_rejects_wrong_or_replayed_challenge_without_exec(tmp_path: Path) -> None:
    control = "codex-master-resource-" + "e" * 32
    runner = tmp_path / "runner"
    runner.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    runner.chmod(0o700)
    expected = runner.stat()
    runner_fd = os.open(runner, getattr(os, "O_PATH", os.O_RDONLY))
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(b"\0" + control.encode())
    listener.listen(1)
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                control,
                "scope_socket-1",
                "scope-session.1",
                str(os.getpid()),
                str(runner_fd),
                str(expected.st_dev),
                str(expected.st_ino),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        connection, _address = listener.accept()
        try:
            challenge = connection.recv(65)
            assert len(challenge) == 65
            assert challenge.endswith(b"\n")
            connection.sendall(b"0" * 64 + b"\n")
            connection.shutdown(socket.SHUT_WR)
        finally:
            connection.close()
        assert process.wait(timeout=5) != 0
        assert process.stdout.read() == b""
        assert process.stderr.read() == b""
    finally:
        listener.close()
        os.close(runner_fd)


def test_scope_gate_retains_verified_runner_fd_for_tmux_pane_after_source_replacement(
    tmp_path: Path,
) -> None:
    runner = tmp_path / "runner"
    original = tmp_path / "runner-original"
    shutil.copyfile(sys.executable, runner)
    runner.chmod(0o700)
    expected = runner.stat()
    runner_fd = os.open(runner, getattr(os, "O_PATH", os.O_RDONLY))
    control_name = f"codex-master-resource-{os.urandom(16).hex()}"
    socket_name = f"gatefd{os.urandom(8).hex()}"
    session_name = "gatefd"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(b"\0" + control_name.encode("ascii"))
    listener.listen(1)
    process: subprocess.Popen[bytes] | None = None
    connection: socket.socket | None = None
    gate_accepted = False
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                control_name,
                socket_name,
                session_name,
                str(os.getpid()),
                str(runner_fd),
                str(expected.st_dev),
                str(expected.st_ino),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        listener.settimeout(1)
        try:
            connection, _address = listener.accept()
        except TimeoutError:
            pytest.fail("scope gate did not accept the verified runner target")
        gate_accepted = True
        challenge = connection.recv(65)
        assert len(challenge) == 65
        connection.sendall(challenge)
        connection.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + 3
        while True:
            session = subprocess.run(
                ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", session_name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if session.returncode == 0:
                break
            if time.monotonic() >= deadline:
                pytest.fail("scope gate did not create the tmux session")
            time.sleep(0.02)
        connection.settimeout(1)
        assert connection.recv(len(b"ready\n")) == b"ready\n"
        os.close(runner_fd)
        runner_fd = -1
        runner.rename(original)
        runner.write_text("#!/bin/sh\nprintf '%s\\n' RUNNER_FD_REPLACED\n", encoding="ascii")
        runner.chmod(0o700)
        subprocess.run(
            [
                "/usr/bin/tmux",
                "-L",
                socket_name,
                "send-keys",
                "-t",
                session_name,
                'exec "$CODEX_MASTER_RUNNER_EXEC_PATH" -c \'import time; print("RUNNER_FD_ORIGINAL", flush=True); time.sleep(10)\'',
                "Enter",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        pane = b""
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            captured = subprocess.run(
                ["/usr/bin/tmux", "-L", socket_name, "capture-pane", "-p", "-t", session_name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            pane = captured.stdout
            if b"RUNNER_FD_ORIGINAL" in pane:
                break
            time.sleep(0.02)
        assert b"RUNNER_FD_ORIGINAL" in pane
        assert b"RUNNER_FD_REPLACED" not in pane
        assert process is not None
        assert process.wait(timeout=3) == 0
    finally:
        if connection is not None:
            connection.close()
        listener.close()
        if runner_fd >= 0:
            os.close(runner_fd)
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if process is not None:
            result = process.wait(timeout=3)
            if gate_accepted:
                assert result == 0


@pytest.mark.parametrize("mode", ("timeout", "identity_mismatch"))
def test_scope_gate_cleans_new_session_when_pane_exec_evidence_fails(mode: str, tmp_path: Path) -> None:
    runner = tmp_path / "runner"
    shutil.copyfile(sys.executable, runner)
    runner.chmod(0o700)
    expected = runner.stat()
    runner_fd = os.open(runner, getattr(os, "O_PATH", os.O_RDONLY))
    control_name = f"codex-master-resource-{os.urandom(16).hex()}"
    socket_name = f"gatefd{os.urandom(8).hex()}"
    session_name = "gatefd"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(b"\0" + control_name.encode("ascii"))
    listener.listen(1)
    process: subprocess.Popen[bytes] | None = None
    connection: socket.socket | None = None
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                control_name,
                socket_name,
                session_name,
                str(os.getpid()),
                str(runner_fd),
                str(expected.st_dev),
                str(expected.st_ino),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        listener.settimeout(1)
        connection, _address = listener.accept()
        challenge = connection.recv(65)
        assert len(challenge) == 65
        connection.sendall(challenge)
        connection.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + 3
        while subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", session_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode != 0:
            if time.monotonic() >= deadline:
                pytest.fail("scope gate did not create the tmux session")
            time.sleep(0.02)
        os.close(runner_fd)
        runner_fd = -1
        if mode == "identity_mismatch":
            subprocess.run(
                [
                    "/usr/bin/tmux",
                    "-L",
                    socket_name,
                    "send-keys",
                    "-t",
                    session_name,
                    "exec /usr/bin/sleep 10",
                    "Enter",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
        assert process.wait(timeout=7) == 64
        assert process.stdout.read() == b""
        assert process.stderr.read() == b""
        assert subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", session_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode != 0
    finally:
        if connection is not None:
            connection.close()
        listener.close()
        if runner_fd >= 0:
            os.close(runner_fd)
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=3)


@pytest.mark.parametrize("source_state", ("missing", "identity_mismatch", "symlink"))
def test_scope_gate_rejects_missing_or_replaced_runner_fd(source_state: str, tmp_path: Path) -> None:
    runner = tmp_path / "runner"
    runner.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    runner.chmod(0o700)
    expected = runner.stat()
    source = runner
    flags = getattr(os, "O_PATH", os.O_RDONLY)
    if source_state == "symlink":
        source = tmp_path / "runner-link"
        source.symlink_to(runner)
        flags |= getattr(os, "O_NOFOLLOW", 0)
    runner_fd = os.open(source, flags)
    if source_state == "missing":
        os.close(runner_fd)
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                f"codex-master-resource-{os.urandom(16).hex()}",
                f"gatefd{os.urandom(8).hex()}",
                "gatefd",
                str(os.getpid()),
                str(runner_fd),
                str(expected.st_dev),
                str(expected.st_ino + (1 if source_state == "identity_mismatch" else 0)),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.wait(timeout=3) == 64
        assert process.stdout.read() == b""
        assert process.stderr.read() == b""
    finally:
        if source_state != "missing":
            os.close(runner_fd)


def test_systemd_user_adapter_is_concrete_and_uses_internal_unit_owner() -> None:
    adapter_type = getattr(resource_cgroup, "SystemdUserCgroupAdapter", None)

    assert adapter_type is not None, "missing concrete SystemdUserCgroupAdapter"


class _FakeHeldGate:
    def finish(
        self, *, timeout_seconds: float, max_stdout_bytes: int, max_stderr_bytes: int
    ) -> object:
        assert timeout_seconds > 0
        assert max_stdout_bytes > 0
        assert max_stderr_bytes > 0
        return resource_cgroup.CommandResultV1(returncode=0, stdout=b"", stderr=b"")

    def terminate(self) -> None:
        return None


class _FakeScopeControl:
    instances: list["_FakeScopeControl"] = []

    def __init__(self, name: str) -> None:
        self.name = name
        self.accepted = False
        self.closed = False
        self.releases: list[bytes] = []

    @classmethod
    def open(cls, name: str) -> "_FakeScopeControl":
        assert resource_cgroup._CONTROL_SOCKET_NAME.fullmatch(name)
        control = cls(name)
        cls.instances.append(control)
        return control

    def accept(self, *, timeout_seconds: float) -> None:
        assert timeout_seconds > 0
        self.accepted = True

    def peer_pid(self) -> int:
        assert self.accepted is True
        return 4241

    def read_challenge(self, *, expected_gate_pid: int, timeout_seconds: float) -> str:
        assert self.accepted is True
        assert expected_gate_pid == 4241
        assert timeout_seconds > 0
        return "c" * 64

    def release_once(self, payload: bytes, *, timeout_seconds: float) -> None:
        assert timeout_seconds > 0
        self.releases.append(payload)

    def read_ready(self, *, timeout_seconds: float) -> None:
        assert timeout_seconds > 0
        assert self.releases

    def close(self) -> None:
        self.closed = True


def _scope_control_releases() -> list[bytes]:
    return [payload for control in _FakeScopeControl.instances for payload in control.releases]


def _scope_control_name() -> str:
    return f"codex-master-resource-{os.getpid():032x}"


def test_scope_control_rejects_wrong_peer_pid_and_closes_without_release() -> None:
    control = resource_cgroup._ScopeControl.open(_scope_control_name())
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(b"\0" + _scope_control_name().encode())
        control.accept(timeout_seconds=0.1)
        client.sendall(b"c" * 64 + b"\n")
        assert control.peer_pid() == os.getpid()

        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            control.read_challenge(expected_gate_pid=os.getpid() + 1, timeout_seconds=0.1)
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            control.release_once(b"c" * 64 + b"\n", timeout_seconds=0.1)
    finally:
        control.close()
        client.close()


def test_scope_control_times_out_without_challenge_and_releases_once_only() -> None:
    control = resource_cgroup._ScopeControl.open(_scope_control_name())
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(b"\0" + _scope_control_name().encode())
        control.accept(timeout_seconds=0.1)
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            control.read_challenge(expected_gate_pid=os.getpid(), timeout_seconds=0.01)
    finally:
        control.close()
        client.close()

    control = resource_cgroup._ScopeControl.open(_scope_control_name())
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    challenge = b"c" * 64 + b"\n"
    try:
        client.connect(b"\0" + _scope_control_name().encode())
        control.accept(timeout_seconds=0.1)
        client.sendall(challenge)
        assert control.read_challenge(expected_gate_pid=os.getpid(), timeout_seconds=0.1) == "c" * 64
        control.release_once(challenge, timeout_seconds=0.1)
        assert client.recv(65) == challenge
        client.sendall(b"ready\n")
        control.read_ready(timeout_seconds=0.1)
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            control.release_once(challenge, timeout_seconds=0.1)
    finally:
        control.close()
        client.close()


class _FakeSystemdRunner:
    def __init__(
        self,
        *,
        collision: bool = False,
        control_group: str | None = None,
        target_slice_control_group: str = "/user.slice/codex-master.slice",
        target_slice_missing: bool = False,
        target_slice_stdout: bytes | None = None,
        timeout: bool = False,
        show_stdout: bytes | None = None,
        scope_delegate_controllers: str = "cpu cpuset memory pids io",
        scope_main_pid_omitted: bool = False,
    ) -> None:
        self.collision = collision
        self.control_group = control_group
        self.target_slice_control_group = target_slice_control_group
        self.target_slice_missing = target_slice_missing
        self.target_slice_stdout = target_slice_stdout
        self.timeout = timeout
        self.show_stdout = show_stdout
        self.scope_delegate_controllers = scope_delegate_controllers
        self.scope_main_pid_omitted = scope_main_pid_omitted
        self.calls: list[tuple[str, ...]] = []
        self.started: list[tuple[str, ...]] = []
        self.stopped: list[str] = []
        self.gate = _FakeHeldGate()
        self.unit_name = ""

    def _result(self, *, returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> object:
        return resource_cgroup.CommandResultV1(
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> object:
        assert timeout_seconds > 0
        assert max_stdout_bytes > 0
        assert max_stderr_bytes > 0
        self.calls.append(argv)
        if self.timeout:
            raise TimeoutError("bounded")
        if argv[0] == "/usr/bin/systemctl" and argv[3] == "show" and "--property=LoadState" in argv:
            return self._result(
                returncode=0,
                stdout=self.show_stdout
                or (b"LoadState=loaded\n" if self.collision else b"LoadState=not-found\n"),
            )
        if argv[0] == "/usr/bin/systemctl" and argv[3] == "show" and argv[4] == "codex-master.slice":
            if self.target_slice_missing:
                return self._result(returncode=4)
            if self.target_slice_stdout is not None:
                return self._result(returncode=0, stdout=self.target_slice_stdout)
            return self._result(
                returncode=0,
                stdout=f"ControlGroup={self.target_slice_control_group}\n".encode(),
            )
        if argv[0] == "/usr/bin/systemctl" and argv[3] == "show":
            if self.show_stdout is not None:
                return self._result(returncode=0, stdout=self.show_stdout)
            control_group = self.control_group or f"{self.target_slice_control_group}/{self.unit_name}"
            values = {
                "ControlGroup": control_group,
                "MainPID": "4241",
                "DelegateControllers": self.scope_delegate_controllers,
            }
            properties = tuple(
                argument.split("=", 1)[1]
                for argument in argv
                if argument.startswith("--property=")
            )
            assert properties and all(property_name in values for property_name in properties)
            return self._result(
                returncode=0,
                stdout="".join(
                    f"{property_name}={values[property_name]}\n"
                    for property_name in properties
                    if not (property_name == "MainPID" and self.scope_main_pid_omitted)
                ).encode(),
            )
        if argv[0] == "/usr/bin/systemctl" and argv[3] == "stop":
            self.stopped.append(argv[4])
            return self._result(returncode=0)
        if argv[0] == "/usr/bin/tmux":
            return self._result(returncode=0, stdout=b"4242\n")
        raise AssertionError(f"unexpected command {argv!r}")

    def start_held(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> _FakeHeldGate:
        assert timeout_seconds > 0
        assert max_stdout_bytes == 65
        assert max_stderr_bytes > 0
        self.started.append(argv)
        self.unit_name = next(argument.split("=", 1)[1] for argument in argv if argument.startswith("--unit="))
        return self.gate


class _Systemd259MissingScopeRunner(_FakeSystemdRunner):
    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> object:
        if (
            argv[0] == "/usr/bin/systemctl"
            and argv[3] == "show"
            and argv[4].startswith("codex-master-resource-")
            and argv[4].endswith(".scope")
            and ("--property=Id" in argv or "--property=LoadState" in argv)
        ):
            self.calls.append(argv)
            return self._result(returncode=0, stdout=b"LoadState=not-found\n")
        return super().run(
            argv,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )


def _write_cgroup_documents(
    root: Path,
    *,
    unit_name: str,
    cpu_max: bytes = b"750000 100000\n",
    slice_controllers: bytes = b"cpu cpuset memory pids io\n",
    slice_subtree: bytes = b"cpu cpuset memory pids io\n",
) -> None:
    target = root / "user.slice" / "codex-master.slice" / unit_name
    target.mkdir(parents=True)
    parent = target.parent
    for directory in (root,):
        (directory / "cgroup.controllers").write_bytes(b"cpu cpuset memory pids io\n")
        (directory / "cgroup.subtree_control").write_bytes(b"cpu cpuset memory pids io\n")
        (directory / "cpuset.cpus.effective").write_bytes(b"0-11\n")
    (parent / "cgroup.controllers").write_bytes(slice_controllers)
    (parent / "cgroup.subtree_control").write_bytes(slice_subtree)
    (parent / "cpuset.cpus.effective").write_bytes(b"0-11\n")
    documents = {
        "cpuset.cpus.effective": b"4-11\n",
        "cpu.max": cpu_max,
        "memory.high": f"{9 * GIB}\n".encode(),
        "memory.max": f"{12 * GIB}\n".encode(),
        "memory.swap.max": f"{8 * GIB}\n".encode(),
        "io.weight": b"default 50\n",
        "cgroup.procs": b"4241\n4242\n4243\n",
    }
    for name, payload in documents.items():
        (target / name).write_bytes(payload)


def _systemd_adapter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runner: _FakeSystemdRunner,
    *,
    cpu_max: bytes = b"750000 100000\n",
    slice_controllers: bytes = b"cpu cpuset memory pids io\n",
    slice_subtree: bytes = b"cpu cpuset memory pids io\n",
) -> object:
    unit_name = "codex-master-resource-" + "d" * 32 + ".scope"
    root = tmp_path / "cgroup"
    _write_cgroup_documents(
        root,
        unit_name=unit_name,
        cpu_max=cpu_max,
        slice_controllers=slice_controllers,
        slice_subtree=slice_subtree,
    )
    monkeypatch.setattr(resource_cgroup, "CGROUP_ROOT", root)
    monkeypatch.setattr(resource_cgroup.secrets, "token_hex", lambda size: "d" * (size * 2))
    _FakeScopeControl.instances.clear()
    monkeypatch.setattr(resource_cgroup, "_ScopeControl", _FakeScopeControl)
    return resource_cgroup.SystemdUserCgroupAdapter(runner=runner)


def test_systemd_v259_scope_uses_pid_bound_control_without_pipe_and_one_gate_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    monkeypatch.setattr(resource_cgroup, "PROC_ROOT", _write_tmux_children_fact(tmp_path))

    scope = start_verified_scope(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )

    assert scope.unit_name == "codex-master-resource-" + "d" * 32 + ".scope"
    assert scope.challenge == "c" * 64
    assert runner.started == [
        (
            "/usr/bin/systemd-run",
            "--user",
            "--scope",
            "--quiet",
            "--collect",
            f"--unit={scope.unit_name}",
            "--slice=codex-master.slice",
            "--property=Delegate=cpu cpuset memory pids io",
            "--property=AllowedCPUs=4-11",
            "--property=CPUQuota=750%",
            "--property=CPUWeight=50",
            f"--property=MemoryHigh={9 * GIB}",
            f"--property=MemoryMax={12 * GIB}",
            f"--property=MemorySwapMax={8 * GIB}",
            "--property=IOWeight=50",
            "/usr/libexec/codex-master-resource-scope-gate",
            "codex-master-resource-" + "d" * 32,
            "scope_socket-1",
            "scope-session.1",
        )
    ]
    assert "--pipe" not in runner.started[0]
    assert _scope_control_releases() == [b"c" * 64 + b"\n"]
    assert (
        "/usr/bin/systemctl",
        "--user",
        "--no-pager",
        "show",
        scope.unit_name,
        "--property=ControlGroup",
        "--property=DelegateControllers",
    ) in runner.calls
    assert (
        "/usr/bin/tmux",
        "-L",
        "scope_socket-1",
        "display-message",
        "-p",
        "-t",
        "scope-session.1",
        "#{pid}",
    ) in runner.calls


def test_systemd_adapter_allows_empty_tmux_children_after_membership_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    monkeypatch.setattr(
        resource_cgroup,
        "PROC_ROOT",
        _write_tmux_children_fact(tmp_path, children_payload=b""),
    )

    scope = start_verified_scope(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )

    assert scope.unit_name == "codex-master-resource-" + "d" * 32 + ".scope"


def test_systemd_adapter_accepts_kernel_tmux_children_space_format(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    monkeypatch.setattr(resource_cgroup, "PROC_ROOT", _write_tmux_children_fact(tmp_path))

    scope = start_verified_scope(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )

    assert scope.unit_name == "codex-master-resource-" + "d" * 32 + ".scope"


@pytest.mark.parametrize("children_payload", (None, b"4243\n4244\n", b"malformed\n"))
def test_systemd_adapter_rejects_missing_or_malformed_tmux_children_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, children_payload: bytes | None
) -> None:
    adapter = _systemd_adapter(monkeypatch, tmp_path, _FakeSystemdRunner())
    monkeypatch.setattr(
        resource_cgroup,
        "PROC_ROOT",
        _write_tmux_children_fact(tmp_path, children_payload=children_payload),
    )

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        adapter._read_tmux_children(4242)


def test_systemd_user_scope_without_main_pid_uses_authenticated_gate_peer_pid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner(scope_main_pid_omitted=True)
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    monkeypatch.setattr(resource_cgroup, "PROC_ROOT", _write_tmux_children_fact(tmp_path))

    scope = start_verified_scope(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )

    assert scope.gate_pid == 4241
    assert all(
        "--property=MainPID" not in call
        for call in runner.calls
        if call[:4] == ("/usr/bin/systemctl", "--user", "--no-pager", "show")
        and call[4] == scope.unit_name
    )


def test_systemd_v259_scope_accepts_cgroup_v2_default_io_weight_format(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    monkeypatch.setattr(resource_cgroup, "PROC_ROOT", _write_tmux_children_fact(tmp_path))
    scope_name = "codex-master-resource-" + "d" * 32 + ".scope"
    (tmp_path / "cgroup" / "user.slice" / "codex-master.slice" / scope_name / "io.weight").write_bytes(
        b"default 50\n"
    )

    scope = start_verified_scope(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )

    assert scope.unit_name == scope_name


def test_systemd_v259_missing_scope_is_identified_by_load_state_not_synthetic_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _Systemd259MissingScopeRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)

    scope = adapter.start_held_scope(
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )

    assert scope.unit_name == "codex-master-resource-" + "d" * 32 + ".scope"
    assert (
        "/usr/bin/systemctl",
        "--user",
        "--no-pager",
        "show",
        scope.unit_name,
        "--property=LoadState",
    ) in runner.calls


def test_systemd_adapter_binds_preflight_and_new_scope_to_codex_master_slice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    monkeypatch.setattr(resource_cgroup, "PROC_ROOT", _write_tmux_children_fact(tmp_path))

    start_verified_scope(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )

    assert "--slice=codex-master.slice" in runner.started[0]
    assert (
        "/usr/bin/systemctl",
        "--user",
        "--no-pager",
        "show",
        "codex-master.slice",
        "--property=ControlGroup",
    ) in runner.calls


def test_controller_parser_rejects_duplicate_controller_tokens() -> None:
    for payload in (
        b"cpu cpu cpuset memory pids io\n",
        b"cpu cpuset memory pids io io\n",
    ):
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            resource_cgroup._parse_controller_set(payload)


def test_integration_precondition_classifier_is_not_generic_preflight_skip() -> None:
    classifier = getattr(resource_cgroup.SystemdUserCgroupAdapter, "integration_precondition_reason", None)

    assert classifier is not None, "missing bounded opt-in precondition classifier"


def test_systemd_adapter_denies_missing_wrong_or_non_delegated_target_slice_before_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cases = (
        (_FakeSystemdRunner(target_slice_missing=True), b"cpu cpuset memory pids io\n"),
        (_FakeSystemdRunner(control_group="/user.slice/other.slice/codex-master-resource-" + "d" * 32 + ".scope"), b"cpu cpuset memory pids io\n"),
        (_FakeSystemdRunner(), b"cpu cpuset memory pids\n"),
    )
    for number, (runner, controllers) in enumerate(cases):
        adapter = _systemd_adapter(
            monkeypatch,
            tmp_path / str(number),
            runner,
            slice_controllers=controllers,
        )
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            start_verified_scope(
                adapter,
                profile=_profile(),
                socket_name="scope_socket-1",
                session_name="scope-session.1",
            )
        assert _scope_control_releases() == []
        if number == 1:
            assert runner.stopped == ["codex-master-resource-" + "d" * 32 + ".scope"]
        else:
            assert runner.started == []


def test_systemd_adapter_rejects_scope_delegate_controller_superset_before_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner(
        scope_delegate_controllers="cpu cpuset memory pids io hugetlb"
    )
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        start_verified_scope(
            adapter,
            profile=_profile(),
            socket_name="scope_socket-1",
            session_name="scope-session.1",
        )

    assert len(runner.started) == 1
    assert _scope_control_releases() == []
    assert runner.stopped == ["codex-master-resource-" + "d" * 32 + ".scope"]


def test_systemd_adapter_allows_parent_controller_supersets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(
        monkeypatch,
        tmp_path,
        runner,
        slice_controllers=b"cpu cpuset memory pids io hugetlb\n",
        slice_subtree=b"cpu cpuset memory pids io hugetlb\n",
    )
    monkeypatch.setattr(resource_cgroup, "PROC_ROOT", _write_tmux_children_fact(tmp_path))

    scope = start_verified_scope(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )

    assert scope.unit_name == "codex-master-resource-" + "d" * 32 + ".scope"


@pytest.mark.parametrize(
    ("controllers", "subtree"),
    (
        (b"cpu cpu cpuset memory pids io\n", b"cpu cpuset memory pids io\n"),
        (b"cpu cpuset memory pids io\n", b"cpu cpuset memory pids io io\n"),
    ),
)
def test_systemd_adapter_rejects_duplicate_target_slice_controller_evidence_before_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, controllers: bytes, subtree: bytes
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(
        monkeypatch,
        tmp_path,
        runner,
        slice_controllers=controllers,
        slice_subtree=subtree,
    )

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        start_verified_scope(
            adapter,
            profile=_profile(),
            socket_name="scope_socket-1",
            session_name="scope-session.1",
        )

    assert runner.started == []
    assert _scope_control_releases() == []


def test_integration_precondition_classifier_skips_only_clean_absence_and_fails_readback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _provide_user_bus_socket_fact(monkeypatch)
    missing_runner = _FakeSystemdRunner(target_slice_missing=True)
    missing_adapter = _systemd_adapter(monkeypatch, tmp_path / "missing", missing_runner)
    assert missing_adapter.integration_precondition_reason() == "requires_target_slice"

    no_delegation = _FakeSystemdRunner()
    absent_adapter = _systemd_adapter(
        monkeypatch,
        tmp_path / "absence",
        no_delegation,
        slice_controllers=b"cpu cpuset memory pids\n",
    )
    assert absent_adapter.integration_precondition_reason() == "requires_delegated_controllers"

    malformed_runner = _FakeSystemdRunner()
    malformed_adapter = _systemd_adapter(
        monkeypatch,
        tmp_path / "malformed",
        malformed_runner,
        slice_subtree=b"cpu cpuset memory pids io io\n",
    )
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        malformed_adapter.integration_precondition_reason()


def test_empty_target_slice_control_group_is_missing_only_for_integration_classifier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner(target_slice_stdout=b"ControlGroup=\n")
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    _provide_user_bus_socket_fact(monkeypatch)

    assert adapter.integration_precondition_reason() == "requires_target_slice"
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        adapter.inspect_preflight()


@pytest.mark.parametrize(
    "stdout",
    (
        b"ControlGroup\n",
        b"Other=\n",
        b"ControlGroup=/user.slice/codex-master.slice\nUnexpected=value\n",
    ),
)
def test_integration_precondition_rejects_malformed_target_slice_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stdout: bytes
) -> None:
    runner = _FakeSystemdRunner(target_slice_stdout=stdout)
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    _provide_user_bus_socket_fact(monkeypatch)

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        adapter.integration_precondition_reason()


def test_systemd_adapter_denies_collision_timeout_overflow_and_path_traversal_before_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for number, runner in enumerate(
        (
            _FakeSystemdRunner(collision=True),
            _FakeSystemdRunner(timeout=True),
            _FakeSystemdRunner(show_stdout=b"x" * 1025),
            _FakeSystemdRunner(control_group="/user.slice/../escape"),
        )
    ):
        adapter = _systemd_adapter(monkeypatch, tmp_path / str(number), runner)
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            start_verified_scope(
                adapter,
                profile=_profile(),
                socket_name="scope_socket-1",
                session_name="scope-session.1",
            )
        assert _scope_control_releases() == []
        if number < 3:
            assert runner.started == []
        else:
            assert len(runner.started) == 1
            assert runner.stopped == ["codex-master-resource-" + "d" * 32 + ".scope"]


def test_systemd_adapter_never_releases_on_readback_failure_and_cleans_only_own_unit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner, cpu_max=b"1 1\n")

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        start_verified_scope(
            adapter,
            profile=_profile(),
            socket_name="scope_socket-1",
            session_name="scope-session.1",
        )

    assert _scope_control_releases() == []
    assert runner.stopped == ["codex-master-resource-" + "d" * 32 + ".scope"]


@pytest.mark.parametrize("replacement", ("symlink", "hardlink"))
def test_systemd_adapter_rejects_nonregular_readback_targets_before_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, replacement: str
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    scope = adapter.start_held_scope(
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )
    target = tmp_path / "cgroup" / scope.control_group / "cpu.max"
    target.unlink()
    replacement_target = tmp_path / "replacement"
    replacement_target.write_bytes(b"750000 100000\n")
    if replacement == "symlink":
        target.symlink_to(replacement_target)
    else:
        os.link(replacement_target, target)

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        adapter.verify_scope(scope, _profile())

    assert _scope_control_releases() == []
    adapter.cleanup_new_scope(scope)


def test_systemd_adapter_rejects_cgroup_root_generation_replacement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    root = tmp_path / "cgroup"
    root.rename(tmp_path / "old-cgroup")
    root.mkdir()

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        adapter.inspect_preflight()


def test_systemd_user_cgroup_integration_contract_requires_double_opt_in() -> None:
    if os.environ.get("CODEX_MASTER_CGROUP_IT") != "1":
        pytest.skip("cgroup_it_disabled")
    if os.environ.get("CODEX_MASTER_SYSTEMD_USER_IT") != "1":
        pytest.skip("systemd_user_it_disabled")
    if sys.platform != "linux":
        pytest.skip("requires_linux")
    cgroup_controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    try:
        metadata = cgroup_controllers.lstat()
    except FileNotFoundError:
        pytest.skip("requires_cgroup_v2")
    except OSError as exc:
        pytest.fail(f"cgroup_v2_readback_failed:{type(exc).__name__}")
    if not stat.S_ISREG(metadata.st_mode):
        pytest.fail("cgroup_v2_readback_failed:not_regular")
    approved_text = os.environ.get("CODEX_MASTER_CGROUP_IT_CPUSET")
    if not isinstance(approved_text, str):
        pytest.skip("requires_approved_cpuset")

    adapter = resource_cgroup.SystemdUserCgroupAdapter()
    try:
        reason = adapter.integration_precondition_reason()
    except CgroupPreflightError as exc:
        pytest.fail(f"integration_preflight_readback_failed:{type(exc).__name__}")
    if reason is not None:
        pytest.skip(reason)
    try:
        approved = resource_cgroup._parse_cpu_set(approved_text)
    except CgroupPreflightError as exc:
        pytest.fail(f"approved_cpuset_invalid:{type(exc).__name__}")
    preflight = adapter.inspect_preflight()
    topology = parse_cpu_topology(adapter)
    profile = derive_cgroup_profile(
        topology,
        approved_cpuset=approved,
        mem_total_bytes=os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"),
    )
    if not set(profile.cpuset_cpus).issubset(preflight.parent_effective_cpuset):
        pytest.skip("requires_approved_cpuset")

    scope: PreparedAgentScope | None = None
    try:
        scope = start_verified_scope(
            adapter,
            profile=profile,
            socket_name=f"g4-it-{os.getpid()}",
            session_name=f"g4-it-{os.getpid()}",
        )
        assert scope.gate_pid > 0
    finally:
        if scope is not None:
            adapter.cleanup_new_scope(scope)
