from __future__ import annotations

import inspect
import os
import runpy
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
    PreparedAgentScope,
    read_hive_io_pressure,
    derive_cgroup_profile,
    parse_cpu_topology,
    require_cgroup_preflight,
    confirm_verified_scope,
    start_released_scope,
)


GIB = 1024**3
GATE = Path(__file__).parents[1] / "bin" / "codex-master-resource-scope-gate"
REQUIRED_CONTROLLERS = frozenset({"cpu", "cpuset", "memory", "pids", "io"})


class _FakeGateConnection:
    def __init__(
        self,
        *,
        attestation_commit: str | None = None,
        session_id: str = "$0",
        tmux_pid: int | None = None,
        pane_pid: int | None = None,
    ) -> None:
        self.sent: list[bytes] = []
        self.closed = False
        self._attestation_commit = attestation_commit
        self._session_id = session_id
        self._tmux_pid = os.getpid() if tmux_pid is None else tmux_pid
        self._pane_pid = self._tmux_pid if pane_pid is None else pane_pid
        self._incoming = b""

    def sendall(self, payload: bytes) -> None:
        self.sent.append(payload)
        fields = payload.decode("ascii").strip().split(" ")
        if len(fields) == 3 and fields[0] == "ATTEST":
            commit = fields[2] if self._attestation_commit is None else self._attestation_commit
            self._incoming = (
                f"ATTEST {fields[1]} {commit} {self._session_id} "
                f"{self._tmux_pid} {self._pane_pid}\n"
            ).encode("ascii")

    def recv(self, size: int) -> bytes:
        payload, self._incoming = self._incoming[:size], self._incoming[size:]
        return payload

    def close(self) -> None:
        self.closed = True


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

    def start_released_scope(
        self,
        *,
        profile: CgroupProfileV1,
        socket_name: str,
        session_name: str,
        runner_target: resource_cgroup.RunnerExecutionTargetV1,
    ) -> PreparedAgentScope:
        del runner_target
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

    def confirm_scope(self, scope: PreparedAgentScope) -> int:
        self.events.append("confirm")
        if self.fail_at == "confirm":
            raise CgroupPreflightError("cgroup_preflight_failed")
        return 4242

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


def _start_released_for_test(
    adapter: object,
    *,
    profile: CgroupProfileV1,
    socket_name: str,
    session_name: str,
) -> PreparedAgentScope:
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        target = resource_cgroup.RunnerExecutionTargetV1(
            owner_pid=os.getpid(),
            fd=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        return start_released_scope(
            adapter,
            profile=profile,
            socket_name=socket_name,
            session_name=session_name,
            runner_target=target,
        )
    finally:
        os.close(descriptor)


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


def _write_tmux_children_fact(tmp_path: Path, *, tmux_pid: int = 4242) -> Path:
    proc_root = tmp_path / "proc"
    children = proc_root / str(tmux_pid) / "task" / str(tmux_pid) / "children"
    children.parent.mkdir(parents=True)
    children.write_bytes(b"4243\n")
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
            "start_released_scope",
            "verify_scope",
            "confirm_scope",
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


def test_scope_runner_releases_then_confirms_after_dispatch_and_readbacks_every_required_property() -> None:
    adapter = FakeCgroupAdapter()
    scope = _start_released_for_test(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )
    confirm_verified_scope(adapter, scope)

    assert scope.unit_name == "codex-master-test.scope"
    assert adapter.events == ["inspect", "start", "verify_scope", "confirm"]
    assert adapter.cleaned == []


def test_scope_runner_never_uses_shell_sudo_taskset_or_move_existing_pid() -> None:
    adapter = FakeCgroupAdapter()
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        _start_released_for_test(
            adapter,
            profile=_profile(),
            socket_name="../scope",
            session_name="scope-session.1",
        )
    assert adapter.events == []


def test_scope_failure_before_publication_cleans_only_new_scope_and_never_touches_existing_pid() -> None:
    adapter = FakeCgroupAdapter(fail_at="verify_scope")
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        _start_released_for_test(
            adapter,
            profile=_profile(),
            socket_name="scope_socket-1",
            session_name="scope-session.1",
        )
    assert adapter.events == ["inspect", "start", "verify_scope", "cleanup"]
    assert [scope.unit_name for scope in adapter.cleaned] == ["codex-master-test.scope"]


def test_scope_runner_never_reruns_failure_capable_tmux_attestation_after_ack() -> None:
    adapter = FakeCgroupAdapter()
    scope = _start_released_for_test(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )
    confirm_verified_scope(adapter, scope)
    assert adapter.events == ["inspect", "start", "verify_scope", "confirm"]
    assert adapter.cleaned == []


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


def test_scope_gate_rejects_legacy_and_general_launcher_argv_before_exec() -> None:
    token = "a" * 64
    rejected = (
        (token, "/usr/bin/printf", "general-launcher"),
        (token, sys.executable, "-c", "raise SystemExit(0)"),
        ("b" * 64, "/usr/bin/tmux", "-L", "socket", "new-session", "-d", "-s", "session"),
        ("socket", "session", "unexpected"),
        ("../socket", "session"),
        ("socket", "../session"),
    )
    for arguments in rejected:
        result = subprocess.run(
            [sys.executable, str(GATE), *arguments],
            input=f"release {token}\n".encode(),
            capture_output=True,
            check=False,
            timeout=5,
        )
        assert result.returncode != 0
        assert result.stdout == b""
        assert result.stderr == b""

def test_systemd_user_adapter_is_concrete_and_uses_internal_unit_owner() -> None:
    adapter_type = getattr(resource_cgroup, "SystemdUserCgroupAdapter", None)

    assert adapter_type is not None, "missing concrete SystemdUserCgroupAdapter"


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
    ) -> None:
        self.collision = collision
        self.control_group = control_group
        self.target_slice_control_group = target_slice_control_group
        self.target_slice_missing = target_slice_missing
        self.target_slice_stdout = target_slice_stdout
        self.timeout = timeout
        self.show_stdout = show_stdout
        self.scope_delegate_controllers = scope_delegate_controllers
        self.calls: list[tuple[str, ...]] = []
        self.started: list[tuple[str, ...]] = []
        self.stopped: list[str] = []
        self.unit_name = ""
        self.tmux_pid = 4242
        self.tmux_session_id = "$0"
        self.scope_main_pid = 4241

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
        if argv[0] == "/usr/bin/systemd-run":
            self.started.append(argv)
            self.unit_name = next(
                argument.split("=", 1)[1]
                for argument in argv
                if argument.startswith("--unit=")
            )
            return self._result(returncode=0)
        if argv[0] == "/usr/bin/systemctl" and argv[3] == "show" and "--property=Id" in argv:
            return self._result(
                returncode=0 if self.collision else 4,
                stdout=self.show_stdout or b"",
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
                "MainPID": str(self.scope_main_pid),
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
                    f"{property_name}={values[property_name]}\n" for property_name in properties
                ).encode(),
            )
        if argv[0] == "/usr/bin/systemctl" and argv[3] == "stop":
            self.stopped.append(argv[4])
            return self._result(returncode=0)
        if argv[0] == "/usr/bin/tmux":
            if argv[-1] == "#{session_id}":
                return self._result(returncode=0, stdout=f"{self.tmux_session_id}\n".encode())
            return self._result(returncode=0, stdout=f"{self.tmux_pid}\n".encode())
        raise AssertionError(f"unexpected command {argv!r}")

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
        "io.weight": b"50\n",
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
    monkeypatch.setattr(
        resource_cgroup,
        "_accept_gate_handoff",
        lambda *_args, **_kwargs: resource_cgroup._GateHandoff(
            commit="e" * 32,
            session_id=runner.tmux_session_id,
            tmux_pid=runner.tmux_pid,
            pane_pid=runner.tmux_pid,
            connection=_FakeGateConnection(
                session_id=runner.tmux_session_id,
                tmux_pid=runner.tmux_pid,
            ),
        ),
    )
    monkeypatch.setattr(
        resource_cgroup,
        "_process_identity",
        lambda pid: resource_cgroup._ProcessIdentity(pid=pid, start_ticks=pid),
    )
    monkeypatch.setattr(
        resource_cgroup.SystemdUserCgroupAdapter,
        "_read_tmux_children",
        lambda _self, _tmux_pid: (),
    )
    return resource_cgroup.SystemdUserCgroupAdapter(runner=runner)


def test_systemd_adapter_uses_fixed_argv_internal_unit_and_authenticated_gate_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    scope = _start_released_for_test(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )

    assert scope.unit_name == "codex-master-resource-" + "d" * 32 + ".scope"
    assert len(runner.started) == 1
    argv = runner.started[0]
    assert argv[:6] == (
        "/usr/bin/systemd-run",
        "--user",
        "--scope",
        "--no-block",
        "--quiet",
        "--collect",
    )
    assert "--pipe" not in argv
    assert argv[-15:] == (
        "/usr/libexec/codex-master-resource-scope-gate",
        "--socket",
        "scope_socket-1",
        "--session",
        "scope-session.1",
        "--owner-pid",
        str(os.getpid()),
        "--runner-fd",
        argv[-7],
        "--device",
        argv[-5],
        "--inode",
        argv[-3],
        "--challenge",
        scope.challenge,
    )
    assert (
        "/usr/bin/systemctl",
        "--user",
        "--no-pager",
        "show",
        scope.unit_name,
        "--property=ControlGroup",
        "--property=MainPID",
        "--property=DelegateControllers",
    ) in runner.calls
    assert not any(argv[0] == "/usr/bin/tmux" for argv in runner.calls)


def test_systemd_adapter_binds_preflight_and_new_scope_to_codex_master_slice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    _start_released_for_test(
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
            _start_released_for_test(
                adapter,
                profile=_profile(),
                socket_name="scope_socket-1",
                session_name="scope-session.1",
            )
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
        _start_released_for_test(
            adapter,
            profile=_profile(),
            socket_name="scope_socket-1",
            session_name="scope-session.1",
        )

    assert len(runner.started) == 1
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
    scope = _start_released_for_test(
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
        _start_released_for_test(
            adapter,
            profile=_profile(),
            socket_name="scope_socket-1",
            session_name="scope-session.1",
        )

    assert runner.started == []


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
            _start_released_for_test(
                adapter,
                profile=_profile(),
                socket_name="scope_socket-1",
                session_name="scope-session.1",
            )
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
        _start_released_for_test(
            adapter,
            profile=_profile(),
            socket_name="scope_socket-1",
            session_name="scope-session.1",
        )

    assert runner.stopped == ["codex-master-resource-" + "d" * 32 + ".scope"]


@pytest.mark.parametrize("replacement", ("symlink", "hardlink"))
def test_systemd_adapter_rejects_nonregular_readback_targets_before_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, replacement: str
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    scope = _start_released_for_test(
        adapter,
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


class _G5ContractAdapter:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.cleaned: list[PreparedAgentScope] = []

    def inspect_preflight(self) -> CgroupPreflightV1:
        self.events.append("preflight")
        return _preflight()

    def start_released_scope(
        self,
        *,
        profile: CgroupProfileV1,
        socket_name: str,
        session_name: str,
        runner_target: object,
    ) -> PreparedAgentScope:
        del profile, runner_target
        self.events.append("scope-ready")
        return PreparedAgentScope(
            unit_name="codex-master-g5.scope",
            socket_name=socket_name,
            session_name=session_name,
            control_group="user.slice/codex-master-g5.scope",
            gate_pid=4241,
            challenge="a" * 64,
        )

    def verify_scope(self, scope: PreparedAgentScope, profile: CgroupProfileV1) -> None:
        del scope, profile
        self.events.append("readback")

    def confirm_scope(self, scope: PreparedAgentScope) -> int:
        del scope
        self.events.append("gate-confirm")
        return 4242

    def cleanup_new_scope(self, scope: PreparedAgentScope) -> None:
        self.events.append("cleanup")
        self.cleaned.append(scope)


def test_g5_exports_release_then_confirm_only_after_dispatch_boundary() -> None:
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        target = resource_cgroup.RunnerExecutionTargetV1(
            owner_pid=os.getpid(),
            fd=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        adapter = _G5ContractAdapter()

        scope = resource_cgroup.start_released_scope(
            adapter,
            profile=_profile(),
            socket_name="g5-socket-1",
            session_name="g5-session-1",
            runner_target=target,
        )

        assert adapter.events == ["preflight", "scope-ready", "readback"]
        assert adapter.cleaned == []

        resource_cgroup.confirm_verified_scope(adapter, scope)

        assert adapter.events == [
            "preflight",
            "scope-ready",
            "readback",
            "gate-confirm",
        ]
        assert adapter.cleaned == []
    finally:
        os.close(descriptor)


@pytest.mark.parametrize(
    "overrides",
    (
        {"owner_pid": True},
        {"fd": True},
        {"device": True},
        {"inode": True},
        {"owner_pid": 0},
        {"fd": 0},
        {"fd": -1},
        {"device": 0},
        {"device": -1},
        {"inode": 0},
        {"owner_pid": os.getpid() + 1},
    ),
)
def test_runner_execution_target_rejects_invalid_owner_or_numeric_identity(
    tmp_path: Path, overrides: dict[str, object]
) -> None:
    runner = tmp_path / "runner"
    runner.write_bytes(b"runner")
    descriptor = os.open(runner, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        values: dict[str, object] = {
            "owner_pid": os.getpid(),
            "fd": descriptor,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }
        values.update(overrides)

        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            resource_cgroup.RunnerExecutionTargetV1(**values)  # type: ignore[arg-type]
    finally:
        os.close(descriptor)


def test_runner_execution_target_rejects_closed_nonregular_hardlinked_or_mismatched_fd(
    tmp_path: Path,
) -> None:
    runner = tmp_path / "runner"
    runner.write_bytes(b"runner")
    descriptor = os.open(runner, os.O_RDONLY | os.O_CLOEXEC)
    metadata = os.fstat(descriptor)
    os.close(descriptor)

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        resource_cgroup.RunnerExecutionTargetV1(
            owner_pid=os.getpid(),
            fd=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )

    directory = tmp_path / "directory"
    directory.mkdir()
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        directory_stat = os.fstat(directory_fd)
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            resource_cgroup.RunnerExecutionTargetV1(
                owner_pid=os.getpid(),
                fd=directory_fd,
                device=directory_stat.st_dev,
                inode=directory_stat.st_ino,
            )
    finally:
        os.close(directory_fd)

    os.link(runner, tmp_path / "runner-link")
    descriptor = os.open(runner, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            resource_cgroup.RunnerExecutionTargetV1(
                owner_pid=os.getpid(),
                fd=descriptor,
                device=metadata.st_dev,
                inode=metadata.st_ino,
            )
    finally:
        os.close(descriptor)

    single_link = tmp_path / "single-link"
    single_link.write_bytes(b"single-link")
    descriptor = os.open(single_link, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            resource_cgroup.RunnerExecutionTargetV1(
                owner_pid=os.getpid(),
                fd=descriptor,
                device=metadata.st_dev,
                inode=metadata.st_ino + 1,
            )
    finally:
        os.close(descriptor)


def test_runner_execution_target_rejects_source_path_replacement_before_scope_start(
    tmp_path: Path,
) -> None:
    runner = tmp_path / "runner"
    replacement = tmp_path / "replacement"
    runner.write_bytes(b"original")
    replacement.write_bytes(b"replacement")
    descriptor = os.open(runner, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        target = resource_cgroup.RunnerExecutionTargetV1(
            owner_pid=os.getpid(),
            fd=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        os.replace(replacement, runner)

        with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
            target.verify_for_scope_start()
    finally:
        os.close(descriptor)


def test_scope_gate_reopens_only_pinned_parent_runner_fd() -> None:
    gate_module = runpy.run_path(str(GATE))
    reopen = gate_module["_open_pinned_parent_runner_fd"]
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        gate_fd = reopen(
            owner_pid=os.getpid(),
            parent_fd=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        try:
            opened = os.fstat(gate_fd)
            assert (opened.st_dev, opened.st_ino) == (metadata.st_dev, metadata.st_ino)
            assert os.pread(gate_fd, 4, 0) == b"\x7fELF"
        finally:
            os.close(gate_fd)
    finally:
        os.close(descriptor)


def test_scope_gate_uses_fixed_argv_and_rejects_wrong_release_challenge() -> None:
    socket_name = "g5-socket-1"
    challenge = "a" * 64
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(f"\0codex-master-g5-{socket_name}")
    listener.listen(1)
    listener.settimeout(1)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    process: subprocess.Popen[bytes] | None = None
    try:
        metadata = os.fstat(descriptor)
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                "--socket",
                socket_name,
                "--session",
                "g5-session-1",
                "--owner-pid",
                str(os.getpid()),
                "--runner-fd",
                str(descriptor),
                "--device",
                str(metadata.st_dev),
                "--inode",
                str(metadata.st_ino),
                "--challenge",
                challenge,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        connection, _address = listener.accept()
        with connection:
            assert connection.recv(128) == f"READY {challenge}\n".encode("ascii")
            connection.sendall(f"RELEASE {'b' * 64}\n".encode("ascii"))
        assert process.wait(timeout=1) == 64
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        os.close(descriptor)
        listener.close()


def test_scope_gate_reports_detached_tmux_server_and_pane_handoff() -> None:
    if not Path("/usr/bin/tmux").is_file():
        pytest.skip("requires_tmux")
    socket_name = f"g5-handoff-{os.getpid()}"
    session_name = f"g5-handoff-{os.getpid()}"
    challenge = "e" * 64
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(f"\0codex-master-g5-{socket_name}")
    listener.listen(1)
    listener.settimeout(2)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    process: subprocess.Popen[bytes] | None = None
    try:
        metadata = os.fstat(descriptor)
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                "--socket",
                socket_name,
                "--session",
                session_name,
                "--owner-pid",
                str(os.getpid()),
                "--runner-fd",
                str(descriptor),
                "--device",
                str(metadata.st_dev),
                "--inode",
                str(metadata.st_ino),
                "--challenge",
                challenge,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        connection, _address = listener.accept()
        with connection:
            connection.settimeout(2)
            assert connection.recv(128) == f"READY {challenge}\n".encode("ascii")
            connection.sendall(f"RELEASE {challenge}\n".encode("ascii"))
            handoff = connection.recv(160)
            fields = handoff.decode("ascii").strip().split(" ")
            assert fields[:2] == ["HANDOFF", challenge]
            assert len(fields) == 6
            commit = fields[2]
            assert len(commit) == 32
            assert fields[3].startswith("$")
            assert fields[3][1:].isdecimal()
            session_identity = subprocess.run(
                [
                    "/usr/bin/tmux",
                    "-L",
                    socket_name,
                    "display-message",
                    "-p",
                    "-t",
                    fields[3],
                    "#{session_id}",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                timeout=2,
            )
            assert session_identity.stdout == f"{fields[3]}\n".encode("ascii")
            assert session_identity.stderr == b""
            tmux_pid, pane_pid = (int(fields[4]), int(fields[5]))
            assert tmux_pid > 0
            assert pane_pid > 0
            assert tmux_pid != process.pid
            environment = (Path(f"/proc/{tmux_pid}/environ")).read_bytes().split(b"\0")
            runner_path = next(
                entry.split(b"=", 1)[1].decode("ascii")
                for entry in environment
                if entry.startswith(b"CODEX_MASTER_RUNNER_EXEC_PATH=")
            )
            runner_fd = int(runner_path.removeprefix("/proc/self/fd/"))
            inherited = os.open(f"/proc/{tmux_pid}/fd/{runner_fd}", os.O_RDONLY | os.O_CLOEXEC)
            try:
                assert os.pread(inherited, 4, 0) == b"\x7fELF"
            finally:
                os.close(inherited)
            connection.sendall(f"ATTEST {challenge} {commit}\n".encode("ascii"))
            attestation = connection.recv(160).decode("ascii").strip().split(" ")
            assert attestation == [
                "ATTEST",
                challenge,
                commit,
                fields[3],
                fields[4],
                fields[5],
            ]
            connection.sendall(f"ACK {challenge} {commit}\n".encode("ascii"))
        assert process.wait(timeout=2) == 0
    finally:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        os.close(descriptor)
        listener.close()


def test_scope_gate_reads_handoff_facts_only_through_bound_control_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not Path("/usr/bin/tmux").is_file():
        pytest.skip("requires_tmux")
    socket_name = f"g5-one-control-{os.getpid()}"
    session_name = f"g5-one-control-{os.getpid()}"
    gate = runpy.run_path(str(GATE))
    gate_globals = gate["_start_tmux_and_read_handoff"].__globals__
    original_popen = gate_globals["subprocess"].Popen
    tmux_argvs: list[tuple[str, ...]] = []
    enforce_bound_client = True

    def guard_tmux_popen(argv: object, *args: object, **kwargs: object) -> object:
        if isinstance(argv, tuple) and argv and argv[0] == "/usr/bin/tmux":
            tmux_argvs.append(argv)
            if enforce_bound_client and "-C" not in argv:
                raise AssertionError("unbound tmux client after control start")
        return original_popen(argv, *args, **kwargs)

    monkeypatch.setattr(gate_globals["subprocess"], "Popen", guard_tmux_popen)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    control: object | None = None
    try:
        session_id, tmux_pid, pane_pid, control = gate["_start_tmux_and_read_handoff"](
            descriptor, socket_name, session_name
        )
        assert session_id.startswith("$")
        assert tmux_pid > 0 and pane_pid > 0
        assert len(tmux_argvs) == 1
        assert "-C" in tmux_argvs[0]
    finally:
        enforce_bound_client = False
        if control is not None:
            gate["_cleanup_new_tmux_session"](control)
            gate["_close_tmux_control"](control)
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        os.close(descriptor)


def test_scope_gate_cleans_new_session_when_parent_closes_before_commit() -> None:
    if not Path("/usr/bin/tmux").is_file():
        pytest.skip("requires_tmux")
    socket_name = f"g5-ack-eof-{os.getpid()}"
    session_name = f"g5-ack-eof-{os.getpid()}"
    challenge = "f" * 64
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(f"\0codex-master-g5-{socket_name}")
    listener.listen(1)
    listener.settimeout(2)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    process: subprocess.Popen[bytes] | None = None
    try:
        metadata = os.fstat(descriptor)
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                "--socket",
                socket_name,
                "--session",
                session_name,
                "--owner-pid",
                str(os.getpid()),
                "--runner-fd",
                str(descriptor),
                "--device",
                str(metadata.st_dev),
                "--inode",
                str(metadata.st_ino),
                "--challenge",
                challenge,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        connection, _address = listener.accept()
        with connection:
            connection.settimeout(2)
            assert connection.recv(128) == f"READY {challenge}\n".encode("ascii")
            connection.sendall(f"RELEASE {challenge}\n".encode("ascii"))
            assert connection.recv(128).startswith(f"HANDOFF {challenge} ".encode("ascii"))
        assert process.wait(timeout=2) == 64
        absent = subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", session_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        assert absent.returncode != 0
    finally:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        os.close(descriptor)
        listener.close()


def test_scope_gate_cleanup_preserves_foreign_session_on_same_tmux_server() -> None:
    if not Path("/usr/bin/tmux").is_file():
        pytest.skip("requires_tmux")
    socket_name = f"g5-ack-foreign-{os.getpid()}"
    session_name = f"g5-ack-own-{os.getpid()}"
    foreign_session = f"g5-ack-foreign-{os.getpid()}"
    challenge = "e" * 64
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(f"\0codex-master-g5-{socket_name}")
    listener.listen(1)
    listener.settimeout(2)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    process: subprocess.Popen[bytes] | None = None
    try:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "new-session", "-d", "-s", foreign_session],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=2,
        )
        metadata = os.fstat(descriptor)
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                "--socket",
                socket_name,
                "--session",
                session_name,
                "--owner-pid",
                str(os.getpid()),
                "--runner-fd",
                str(descriptor),
                "--device",
                str(metadata.st_dev),
                "--inode",
                str(metadata.st_ino),
                "--challenge",
                challenge,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        connection, _address = listener.accept()
        with connection:
            connection.settimeout(2)
            assert connection.recv(128) == f"READY {challenge}\n".encode("ascii")
            connection.sendall(f"RELEASE {challenge}\n".encode("ascii"))
            assert connection.recv(160).startswith(f"HANDOFF {challenge} ".encode("ascii"))
        assert process.wait(timeout=2) == 64
        own = subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", session_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        foreign = subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", foreign_session],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        assert own.returncode != 0
        assert foreign.returncode == 0
    finally:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        os.close(descriptor)
        listener.close()


def test_scope_gate_cleans_renamed_own_session_without_commit() -> None:
    if not Path("/usr/bin/tmux").is_file():
        pytest.skip("requires_tmux")
    socket_name = f"g5-ack-rename-{os.getpid()}"
    session_name = f"g5-ack-own-{os.getpid()}"
    renamed_session = f"g5-ack-renamed-{os.getpid()}"
    foreign_session = f"g5-ack-foreign-{os.getpid()}"
    challenge = "d" * 64
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(f"\0codex-master-g5-{socket_name}")
    listener.listen(1)
    listener.settimeout(2)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    process: subprocess.Popen[bytes] | None = None
    try:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "new-session", "-d", "-s", foreign_session],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=2,
        )
        metadata = os.fstat(descriptor)
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                "--socket",
                socket_name,
                "--session",
                session_name,
                "--owner-pid",
                str(os.getpid()),
                "--runner-fd",
                str(descriptor),
                "--device",
                str(metadata.st_dev),
                "--inode",
                str(metadata.st_ino),
                "--challenge",
                challenge,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        connection, _address = listener.accept()
        with connection:
            connection.settimeout(2)
            assert connection.recv(128) == f"READY {challenge}\n".encode("ascii")
            connection.sendall(f"RELEASE {challenge}\n".encode("ascii"))
            assert connection.recv(160).startswith(f"HANDOFF {challenge} ".encode("ascii"))
            subprocess.run(
                [
                    "/usr/bin/tmux",
                    "-L",
                    socket_name,
                    "rename-session",
                    "-t",
                    session_name,
                    renamed_session,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=2,
            )
        assert process.wait(timeout=2) == 64
        own = subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", renamed_session],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        foreign = subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", foreign_session],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        assert own.returncode != 0
        assert foreign.returncode == 0
    finally:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        os.close(descriptor)
        listener.close()


def test_scope_gate_server_restart_never_cleans_reused_foreign_session_before_ack() -> None:
    if not Path("/usr/bin/tmux").is_file():
        pytest.skip("requires_tmux")
    socket_name = f"g5-ack-restart-{os.getpid()}"
    session_name = f"g5-ack-own-{os.getpid()}"
    foreign_session = f"g5-ack-foreign-{os.getpid()}"
    challenge = "b" * 64
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(f"\0codex-master-g5-{socket_name}")
    listener.listen(1)
    listener.settimeout(2)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    process: subprocess.Popen[bytes] | None = None
    try:
        metadata = os.fstat(descriptor)
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                "--socket",
                socket_name,
                "--session",
                session_name,
                "--owner-pid",
                str(os.getpid()),
                "--runner-fd",
                str(descriptor),
                "--device",
                str(metadata.st_dev),
                "--inode",
                str(metadata.st_ino),
                "--challenge",
                challenge,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        connection, _address = listener.accept()
        with connection:
            connection.settimeout(2)
            assert connection.recv(128) == f"READY {challenge}\n".encode("ascii")
            connection.sendall(f"RELEASE {challenge}\n".encode("ascii"))
            fields = connection.recv(160).decode("ascii").strip().split(" ")
            assert fields[:2] == ["HANDOFF", challenge]
            assert len(fields) == 6
            original_session_id = fields[3]
            subprocess.run(
                ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=2,
            )
            replacement = subprocess.run(
                [
                    "/usr/bin/tmux",
                    "-L",
                    socket_name,
                    "new-session",
                    "-d",
                    "-P",
                    "-F",
                    "#{session_id}",
                    "-s",
                    foreign_session,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                timeout=2,
            )
            assert replacement.stdout == f"{original_session_id}\n".encode("ascii")
            assert replacement.stderr == b""
        assert process.wait(timeout=2) == 64
        foreign = subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", original_session_id],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        assert foreign.returncode == 0
    finally:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        os.close(descriptor)
        listener.close()


@pytest.mark.parametrize("ack_kind", ("wrong_challenge", "replayed_commit"))
def test_scope_gate_rejects_nonfresh_commit_and_cleans_new_session(ack_kind: str) -> None:
    if not Path("/usr/bin/tmux").is_file():
        pytest.skip("requires_tmux")
    socket_name = f"g5-ack-{ack_kind}-{os.getpid()}"
    session_name = f"g5-ack-{ack_kind}-{os.getpid()}"
    challenge = "a" * 64
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(f"\0codex-master-g5-{socket_name}")
    listener.listen(1)
    listener.settimeout(2)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    process: subprocess.Popen[bytes] | None = None
    try:
        metadata = os.fstat(descriptor)
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                "--socket",
                socket_name,
                "--session",
                session_name,
                "--owner-pid",
                str(os.getpid()),
                "--runner-fd",
                str(descriptor),
                "--device",
                str(metadata.st_dev),
                "--inode",
                str(metadata.st_ino),
                "--challenge",
                challenge,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        connection, _address = listener.accept()
        with connection:
            connection.settimeout(2)
            assert connection.recv(128) == f"READY {challenge}\n".encode("ascii")
            connection.sendall(f"RELEASE {challenge}\n".encode("ascii"))
            fields = connection.recv(160).decode("ascii").strip().split(" ")
            assert fields[:2] == ["HANDOFF", challenge]
            assert len(fields) == 6
            commit = fields[2]
            assert len(commit) == 32
            if ack_kind == "wrong_challenge":
                acknowledgment = f"ACK {'b' * 64} {commit}\n"
            else:
                acknowledgment = f"ACK {challenge} {'0' * 32}\n"
            connection.sendall(acknowledgment.encode("ascii"))
        assert process.wait(timeout=2) == 64
        absent = subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", session_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        assert absent.returncode != 0
    finally:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        os.close(descriptor)
        listener.close()


def test_scope_gate_cleans_new_session_after_commit_timeout() -> None:
    if not Path("/usr/bin/tmux").is_file():
        pytest.skip("requires_tmux")
    socket_name = f"g5-ack-timeout-{os.getpid()}"
    session_name = f"g5-ack-timeout-{os.getpid()}"
    challenge = "c" * 64
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(f"\0codex-master-g5-{socket_name}")
    listener.listen(1)
    listener.settimeout(2)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    process: subprocess.Popen[bytes] | None = None
    try:
        metadata = os.fstat(descriptor)
        process = subprocess.Popen(
            [
                sys.executable,
                str(GATE),
                "--socket",
                socket_name,
                "--session",
                session_name,
                "--owner-pid",
                str(os.getpid()),
                "--runner-fd",
                str(descriptor),
                "--device",
                str(metadata.st_dev),
                "--inode",
                str(metadata.st_ino),
                "--challenge",
                challenge,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        connection, _address = listener.accept()
        with connection:
            connection.settimeout(2)
            assert connection.recv(128) == f"READY {challenge}\n".encode("ascii")
            connection.sendall(f"RELEASE {challenge}\n".encode("ascii"))
            assert connection.recv(160).startswith(f"HANDOFF {challenge} ".encode("ascii"))
            assert process.wait(timeout=7) == 64
        absent = subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", session_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        assert absent.returncode != 0
    finally:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        os.close(descriptor)
        listener.close()


def test_scope_gate_cleans_owned_session_when_bound_attestation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not Path("/usr/bin/tmux").is_file():
        pytest.skip("requires_tmux")
    socket_name = f"g5-control-generation-{os.getpid()}"
    session_name = f"g5-control-generation-{os.getpid()}"
    gate = runpy.run_path(str(GATE))
    gate_globals = gate["_start_tmux_and_read_handoff"].__globals__
    def failing_attestation(*_args: object) -> object:
        raise ValueError("generation changed")

    monkeypatch.setitem(gate_globals, "_read_bound_attestation", failing_attestation)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(ValueError, match="generation changed"):
            gate["_start_tmux_and_read_handoff"](descriptor, socket_name, session_name)
        own = subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", session_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        assert own.returncode != 0
    finally:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        os.close(descriptor)


def test_scope_gate_control_overflow_before_session_id_uses_bound_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not Path("/usr/bin/tmux").is_file():
        pytest.skip("requires_tmux")
    socket_name = f"g5-control-overflow-{os.getpid()}"
    session_name = f"g5-control-overflow-{os.getpid()}"
    gate = runpy.run_path(str(GATE))
    gate_globals = gate["_start_tmux_and_read_handoff"].__globals__
    monkeypatch.setitem(gate_globals, "_MAX_CONTROL_OUTPUT_BYTES", 1)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(ValueError, match="tmux control failed"):
            gate["_start_tmux_and_read_handoff"](descriptor, socket_name, session_name)
        own = subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", session_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        assert own.returncode != 0
    finally:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        os.close(descriptor)


def test_scope_gate_control_spawn_failure_cannot_create_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not Path("/usr/bin/tmux").is_file():
        pytest.skip("requires_tmux")
    socket_name = f"g5-control-spawn-{os.getpid()}"
    session_name = f"g5-control-spawn-{os.getpid()}"
    gate = runpy.run_path(str(GATE))
    gate_globals = gate["_start_tmux_and_read_handoff"].__globals__
    monkeypatch.setitem(gate_globals, "_TMUX_PATH", "/nonexistent/codex-master-tmux")
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(ValueError, match="tmux control failed"):
            gate["_start_tmux_and_read_handoff"](descriptor, socket_name, session_name)
        own = subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "has-session", "-t", session_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        assert own.returncode != 0
    finally:
        subprocess.run(
            ["/usr/bin/tmux", "-L", socket_name, "kill-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        os.close(descriptor)


@pytest.mark.parametrize("stream", (1, 2))
def test_parent_runner_aborts_each_output_overflow_before_timeout(stream: int) -> None:
    runner = resource_cgroup._SubprocessSystemdUserRunner()
    script = f"import os, time; os.write({stream}, b'x' * (1024 * 1024)); time.sleep(5)"
    started = time.monotonic()
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        runner.run(
            (sys.executable, "-c", script),
            timeout_seconds=2.0,
            max_stdout_bytes=128,
            max_stderr_bytes=128,
        )
    assert time.monotonic() - started < 1.0


def test_parent_runner_aborts_neverending_dual_stream_output_before_timeout() -> None:
    runner = resource_cgroup._SubprocessSystemdUserRunner()
    script = (
        "import os, time\n"
        "while True:\n"
        "    os.write(1, b'x' * 16)\n"
        "    os.write(2, b'y' * 16)\n"
        "    time.sleep(0.001)\n"
    )
    started = time.monotonic()
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        runner.run(
            (sys.executable, "-c", script),
            timeout_seconds=2.0,
            max_stdout_bytes=128,
            max_stderr_bytes=128,
        )
    assert time.monotonic() - started < 1.0


def test_gate_handoff_accepts_only_one_authenticated_peer_and_closes_replay_path() -> None:
    import threading

    socket_name = "g5-ready-1"
    listener = resource_cgroup._create_gate_listener(socket_name)
    challenge = "c" * 64
    commit = "d" * 32
    replies: list[bytes] = []
    acknowledgment_received = threading.Event()

    def first_gate() -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(resource_cgroup._gate_socket_address(socket_name))
            connection.sendall(f"READY {challenge}\n".encode("ascii"))
            replies.append(connection.recv(128))
            connection.sendall(
                f"HANDOFF {challenge} {commit} $0 {os.getpid()} {os.getpid()}\n".encode("ascii")
            )
            replies.append(connection.recv(128))
            acknowledgment_received.set()
        finally:
            connection.close()

    worker = threading.Thread(target=first_gate)
    worker.start()
    handoff = resource_cgroup._accept_gate_handoff(
        listener,
        gate_pid=os.getpid(),
        owner_pid=os.getpid(),
        challenge=challenge,
    )
    assert replies == [f"RELEASE {challenge}\n".encode("ascii")]
    assert handoff.session_id == "$0"
    assert (handoff.tmux_pid, handoff.pane_pid) == (os.getpid(), os.getpid())
    assert not acknowledgment_received.wait(timeout=0.2)
    resource_cgroup._commit_gate_handoff(handoff, challenge=challenge)
    worker.join(timeout=1)
    assert not worker.is_alive()
    assert acknowledgment_received.is_set()
    assert replies == [
        f"RELEASE {challenge}\n".encode("ascii"),
        f"ACK {challenge} {commit}\n".encode("ascii"),
    ]
    assert listener.fileno() == -1

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        resource_cgroup._accept_gate_handoff(
            listener,
            gate_pid=os.getpid(),
            owner_pid=os.getpid(),
            challenge=challenge,
        )


def test_gate_handoff_rejects_foreign_peer_pid() -> None:
    socket_name = "g5-peer-1"
    listener = resource_cgroup._create_gate_listener(socket_name)
    challenge = "d" * 64

    def foreign_gate() -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(resource_cgroup._gate_socket_address(socket_name))
            try:
                connection.sendall(f"READY {challenge}\n".encode("ascii"))
            except BrokenPipeError:
                pass
        finally:
            connection.close()

    import threading

    worker = threading.Thread(target=foreign_gate)
    worker.start()
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        resource_cgroup._accept_gate_handoff(
            listener,
            gate_pid=os.getpid() + 1,
            owner_pid=os.getpid(),
            challenge=challenge,
        )
    worker.join(timeout=1)
    assert not worker.is_alive()


def test_gate_attestation_rejects_replayed_commit_before_ack() -> None:
    challenge = "c" * 64
    handoff = resource_cgroup._GateHandoff(
        commit="d" * 32,
        session_id="$0",
        tmux_pid=os.getpid(),
        pane_pid=os.getpid(),
        connection=_FakeGateConnection(attestation_commit="e" * 32),
    )

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        resource_cgroup._attest_gate_handoff(handoff, challenge=challenge)
    assert handoff.connection is not None
    assert handoff.connection.sent == [f"ATTEST {challenge} {'d' * 32}\n".encode()]
    resource_cgroup._close_gate_handoff(handoff)


def test_confirm_scope_attests_pane_elf_and_is_exactly_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    runner.tmux_pid = os.getpid()
    (tmp_path / "cgroup" / "user.slice" / "codex-master.slice" / (
        "codex-master-resource-" + "d" * 32 + ".scope"
    ) / "cgroup.procs").write_bytes(f"4241\n{os.getpid()}\n".encode())
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        target = resource_cgroup.RunnerExecutionTargetV1(
            owner_pid=os.getpid(),
            fd=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        scope = start_released_scope(
            adapter,
            profile=_profile(),
            socket_name="g5-confirm-1",
            session_name="g5-confirm-1",
            runner_target=target,
        )
    finally:
        os.close(descriptor)
    (tmp_path / "cgroup" / scope.control_group / "cgroup.procs").write_bytes(
        f"4241\n{os.getpid()}\n".encode()
    )

    assert adapter.confirm_scope(scope) == os.getpid()
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        adapter.confirm_scope(scope)


def test_parent_commits_gate_handoff_only_after_pane_elf_attestation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    runner.tmux_pid = os.getpid()
    cgroup_procs = tmp_path / "cgroup" / "user.slice" / "codex-master.slice" / (
        "codex-master-resource-" + "d" * 32 + ".scope"
    ) / "cgroup.procs"
    cgroup_procs.write_bytes(f"4241\n{os.getpid()}\n".encode())
    connection = _FakeGateConnection()
    monkeypatch.setattr(
        resource_cgroup,
        "_accept_gate_handoff",
        lambda *_args, **_kwargs: resource_cgroup._GateHandoff(
            commit="e" * 32,
            session_id=runner.tmux_session_id,
            tmux_pid=os.getpid(),
            pane_pid=os.getpid(),
            connection=connection,
        ),
    )
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        target = resource_cgroup.RunnerExecutionTargetV1(
            owner_pid=os.getpid(),
            fd=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        scope = start_released_scope(
            adapter,
            profile=_profile(),
            socket_name="g5-commit-order-1",
            session_name="g5-commit-order-1",
            runner_target=target,
        )
    finally:
        os.close(descriptor)

    assert connection.sent == []
    assert not connection.closed
    assert adapter.confirm_scope(scope) == os.getpid()
    assert connection.sent == [
        f"ATTEST {scope.challenge} {'e' * 32}\n".encode(),
        f"ACK {scope.challenge} {'e' * 32}\n".encode(),
    ]
    assert connection.closed


def test_parent_closes_uncommitted_handoff_when_tmux_attestation_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    runner.tmux_pid = os.getpid()
    cgroup_procs = tmp_path / "cgroup" / "user.slice" / "codex-master.slice" / (
        "codex-master-resource-" + "d" * 32 + ".scope"
    ) / "cgroup.procs"
    cgroup_procs.write_bytes(f"4241\n{os.getpid()}\n".encode())
    connection = _FakeGateConnection(tmux_pid=os.getpid() + 1)
    monkeypatch.setattr(
        resource_cgroup,
        "_accept_gate_handoff",
        lambda *_args, **_kwargs: resource_cgroup._GateHandoff(
            commit="e" * 32,
            session_id=runner.tmux_session_id,
            tmux_pid=os.getpid(),
            pane_pid=os.getpid(),
            connection=connection,
        ),
    )
    scope = _start_released_for_test(
        adapter,
        profile=_profile(),
        socket_name="g5-commit-fail-1",
        session_name="g5-commit-fail-1",
    )
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        confirm_verified_scope(adapter, scope)
    assert connection.sent == [f"ATTEST {scope.challenge} {'e' * 32}\n".encode()]
    assert connection.closed
    assert runner.stopped == [scope.unit_name]


def test_parent_rejects_tmux_child_outside_scope_before_gate_commit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    runner.tmux_pid = os.getpid()
    cgroup_procs = tmp_path / "cgroup" / "user.slice" / "codex-master.slice" / (
        "codex-master-resource-" + "d" * 32 + ".scope"
    ) / "cgroup.procs"
    cgroup_procs.write_bytes(f"4241\n{os.getpid()}\n".encode())
    monkeypatch.setattr(
        resource_cgroup.SystemdUserCgroupAdapter,
        "_read_tmux_children",
        lambda _self, _tmux_pid: (os.getpid() + 1,),
    )
    connection = _FakeGateConnection()
    monkeypatch.setattr(
        resource_cgroup,
        "_accept_gate_handoff",
        lambda *_args, **_kwargs: resource_cgroup._GateHandoff(
            commit="e" * 32,
            session_id=runner.tmux_session_id,
            tmux_pid=os.getpid(),
            pane_pid=os.getpid(),
            connection=connection,
        ),
    )
    scope = _start_released_for_test(
        adapter,
        profile=_profile(),
        socket_name="g5-child-outside-1",
        session_name="g5-child-outside-1",
    )

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        confirm_verified_scope(adapter, scope)
    assert connection.sent == [f"ATTEST {scope.challenge} {'e' * 32}\n".encode()]
    assert connection.closed
    assert runner.stopped == [scope.unit_name]


def test_confirm_scope_accepts_attested_tmux_server_after_gate_pid_handoff(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    runner.tmux_pid = os.getpid()
    monkeypatch.setattr(
        resource_cgroup,
        "_accept_gate_handoff",
        lambda *_args, **_kwargs: resource_cgroup._GateHandoff(
            commit="e" * 32,
            session_id=runner.tmux_session_id,
            tmux_pid=os.getpid(),
            pane_pid=os.getpid(),
            connection=_FakeGateConnection(),
        ),
        raising=False,
    )
    cgroup_procs = tmp_path / "cgroup" / "user.slice" / "codex-master.slice" / (
        "codex-master-resource-" + "d" * 32 + ".scope"
    ) / "cgroup.procs"
    cgroup_procs.write_bytes(f"4241\n{os.getpid()}\n".encode())
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        target = resource_cgroup.RunnerExecutionTargetV1(
            owner_pid=os.getpid(),
            fd=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        scope = start_released_scope(
            adapter,
            profile=_profile(),
            socket_name="g5-handoff-1",
            session_name="g5-handoff-1",
            runner_target=target,
        )
    finally:
        os.close(descriptor)

    runner.scope_main_pid = os.getpid()
    assert adapter.confirm_scope(scope) == os.getpid()


def test_released_scope_rejects_gate_claimed_tmux_pid_that_tmux_does_not_confirm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    runner.tmux_pid = os.getpid()
    monkeypatch.setattr(
        resource_cgroup,
        "_accept_gate_handoff",
        lambda *_args, **_kwargs: resource_cgroup._GateHandoff(
            commit="e" * 32,
            session_id=runner.tmux_session_id,
            tmux_pid=os.getpid() + 1,
            pane_pid=os.getpid(),
            connection=_FakeGateConnection(),
        ),
    )
    cgroup_procs = tmp_path / "cgroup" / "user.slice" / "codex-master.slice" / (
        "codex-master-resource-" + "d" * 32 + ".scope"
    ) / "cgroup.procs"
    cgroup_procs.write_bytes(f"4241\n{os.getpid()}\n".encode())

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        _start_released_for_test(
            adapter,
            profile=_profile(),
            socket_name="g5-untrusted-handoff-1",
            session_name="g5-untrusted-handoff-1",
        )
    assert runner.stopped == ["codex-master-resource-" + "d" * 32 + ".scope"]


def test_confirm_scope_rejects_tmux_or_pane_switch_after_handoff(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    runner.tmux_pid = os.getpid()
    cgroup_procs = tmp_path / "cgroup" / "user.slice" / "codex-master.slice" / (
        "codex-master-resource-" + "d" * 32 + ".scope"
    ) / "cgroup.procs"
    cgroup_procs.write_bytes(f"4241\n{os.getpid()}\n".encode())
    scope = _start_released_for_test(
        adapter,
        profile=_profile(),
        socket_name="g5-switch-1",
        session_name="g5-switch-1",
    )
    owned = adapter._owned_scope(scope)
    assert owned.handoff is not None
    connection = owned.handoff.connection
    assert isinstance(connection, _FakeGateConnection)
    connection._tmux_pid = os.getpid() + 1

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        confirm_verified_scope(adapter, scope)
    assert runner.stopped == [scope.unit_name]


def test_confirm_scope_rejects_pid_reuse_after_handoff(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    runner.tmux_pid = os.getpid()
    cgroup_procs = tmp_path / "cgroup" / "user.slice" / "codex-master.slice" / (
        "codex-master-resource-" + "d" * 32 + ".scope"
    ) / "cgroup.procs"
    cgroup_procs.write_bytes(f"4241\n{os.getpid()}\n".encode())
    identities = iter((101, 102, 201, 202))
    monkeypatch.setattr(
        resource_cgroup,
        "_process_identity",
        lambda pid: resource_cgroup._ProcessIdentity(pid=pid, start_ticks=next(identities)),
    )
    scope = _start_released_for_test(
        adapter,
        profile=_profile(),
        socket_name="g5-reuse-1",
        session_name="g5-reuse-1",
    )

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        confirm_verified_scope(adapter, scope)
    assert runner.stopped == [scope.unit_name]


def test_confirm_scope_rejects_wrong_pane_elf_and_cleans_only_new_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    runner.tmux_pid = os.getpid()
    (tmp_path / "cgroup" / "user.slice" / "codex-master.slice" / (
        "codex-master-resource-" + "d" * 32 + ".scope"
    ) / "cgroup.procs").write_bytes(f"4241\n{os.getpid()}\n".encode())
    runner_path = tmp_path / "not-the-pane"
    runner_path.write_bytes(b"not-an-elf")
    descriptor = os.open(runner_path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        target = resource_cgroup.RunnerExecutionTargetV1(
            owner_pid=os.getpid(),
            fd=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        scope = start_released_scope(
            adapter,
            profile=_profile(),
            socket_name="g5-wrong-elf-1",
            session_name="g5-wrong-elf-1",
            runner_target=target,
        )
    finally:
        os.close(descriptor)
    (tmp_path / "cgroup" / scope.control_group / "cgroup.procs").write_bytes(
        f"4241\n{os.getpid()}\n".encode()
    )

    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        confirm_verified_scope(adapter, scope)
    assert runner.stopped == [scope.unit_name]


def test_released_scope_argv_is_fixed_and_never_uses_pipe_shell_or_unpinned_path() -> None:
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        target = resource_cgroup.RunnerExecutionTargetV1(
            owner_pid=os.getpid(),
            fd=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        argv = resource_cgroup._released_scope_argv(
            profile=_profile(),
            unit_name="codex-master-resource-" + "a" * 32 + ".scope",
            socket_name="g5-socket-1",
            session_name="g5-session-1",
            runner_target=target,
            challenge="b" * 64,
        )
    finally:
        os.close(descriptor)

    assert argv[:6] == (
        "/usr/bin/systemd-run",
        "--user",
        "--scope",
        "--no-block",
        "--quiet",
        "--collect",
    )
    assert "--pipe" not in argv
    assert not {"sh", "bash", "sudo", "taskset"} & set(argv)
    assert argv[-15:] == (
        "/usr/libexec/codex-master-resource-scope-gate",
        "--socket",
        "g5-socket-1",
        "--session",
        "g5-session-1",
        "--owner-pid",
        str(os.getpid()),
        "--runner-fd",
        str(target.fd),
        "--device",
        str(target.device),
        "--inode",
        str(target.inode),
        "--challenge",
        "b" * 64,
    )


def test_systemd_adapter_releases_only_after_readback_and_authenticated_gate_handoff(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    gate_handoff: list[tuple[int, int, str]] = []

    def accept_gate(
        _listener: socket.socket, *, gate_pid: int, owner_pid: int, challenge: str
    ) -> resource_cgroup._GateHandoff:
        gate_handoff.append((gate_pid, owner_pid, challenge))
        return resource_cgroup._GateHandoff(
            commit="e" * 32,
            session_id=runner.tmux_session_id,
            tmux_pid=runner.tmux_pid,
            pane_pid=runner.tmux_pid,
            connection=_FakeGateConnection(),
        )

    monkeypatch.setattr(resource_cgroup, "_accept_gate_handoff", accept_gate)
    descriptor = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        target = resource_cgroup.RunnerExecutionTargetV1(
            owner_pid=os.getpid(),
            fd=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        scope = resource_cgroup.start_released_scope(
            adapter,
            profile=_profile(),
            socket_name="g5-socket-1",
            session_name="g5-session-1",
            runner_target=target,
        )
    finally:
        os.close(descriptor)

    assert gate_handoff == [(4241, os.getpid(), scope.challenge)]
    assert runner.started[0][0] == "/usr/bin/systemd-run"
    assert "--pipe" not in runner.started[0]
    assert runner.started[0][-15:] == (
        "/usr/libexec/codex-master-resource-scope-gate",
        "--socket",
        "g5-socket-1",
        "--session",
        "g5-session-1",
        "--owner-pid",
        str(os.getpid()),
        "--runner-fd",
        str(target.fd),
        "--device",
        str(target.device),
        "--inode",
        str(target.inode),
        "--challenge",
        scope.challenge,
    )
