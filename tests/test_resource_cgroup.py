from __future__ import annotations

import io
import os
import runpy
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import codex_master.resource_cgroup as resource_cgroup
from codex_master.resource_cgroup import (
    CgroupPreflightError,
    CgroupPreflightV1,
    CgroupProfileV1,
    CpuTopologyV1,
    PreparedAgentScope,
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

    def verify_tmux_membership_and_inheritance(self, scope: PreparedAgentScope, tmux_pid: int) -> None:
        self.events.append("verify_tmux")
        if tmux_pid != 4242 or self.fail_at == "verify_tmux":
            raise CgroupPreflightError("cgroup_preflight_failed")

    def cleanup_new_scope(self, scope: PreparedAgentScope) -> None:
        self.events.append("cleanup")
        self.cleaned.append(scope)


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


def test_scope_runner_uses_held_scope_before_tmux_and_readbacks_every_required_property() -> None:
    adapter = FakeCgroupAdapter()
    scope = start_verified_scope(
        adapter,
        profile=_profile(),
        socket_name="scope_socket-1",
        session_name="scope-session.1",
    )

    assert scope.unit_name == "codex-master-test.scope"
    assert adapter.events == ["inspect", "start", "verify_scope", "release", "verify_tmux"]
    assert adapter.cleaned == []


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
    assert adapter.events == ["inspect", "start", "verify_scope", "release", "verify_tmux", "cleanup"]


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


class _GateExecveCalled(Exception):
    pass


class _GateExited(Exception):
    pass


class _GateStdout:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def flush(self) -> None:
        return None


def test_scope_gate_generates_internal_challenge_and_executes_only_fixed_tmux_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge = "c" * 64
    called: dict[str, object] = {}

    def _execve(path: str, argv: list[str], env: dict[str, str]) -> None:
        called.update(path=path, argv=argv, env=env)
        raise _GateExecveCalled

    def _exit(_status: int) -> None:
        raise _GateExited

    stdout = _GateStdout()
    monkeypatch.setattr(sys, "argv", [str(GATE), "scope_socket-1", "scope-session.1"])
    monkeypatch.setattr(sys, "stdin", type("GateStdin", (), {"buffer": io.BytesIO(f"{challenge}\n".encode())})())
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(os, "execve", _execve)
    monkeypatch.setattr(os, "_exit", _exit)
    import secrets

    monkeypatch.setattr(secrets, "token_hex", lambda size: challenge if size == 32 else "")

    with pytest.raises(_GateExecveCalled):
        runpy.run_path(str(GATE), run_name="__main__")

    assert stdout.buffer.getvalue() == f"{challenge}\n".encode()
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
        "env": {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    }


def test_scope_gate_rejects_wrong_or_replayed_challenge_without_exec() -> None:
    process = subprocess.Popen(
        [sys.executable, str(GATE), "scope_socket-1", "scope-session.1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    challenge = process.stdout.readline()
    assert len(challenge) == 65
    assert challenge.endswith(b"\n")
    process.stdin.write(b"0" * 64 + b"\n")
    process.stdin.close()
    assert process.wait(timeout=5) != 0
    assert process.stdout.read() == b""
    assert process.stderr.read() == b""


def test_systemd_user_adapter_is_concrete_and_uses_internal_unit_owner() -> None:
    adapter_type = getattr(resource_cgroup, "SystemdUserCgroupAdapter", None)

    assert adapter_type is not None, "missing concrete SystemdUserCgroupAdapter"


class _FakeHeldGate:
    def __init__(self, *, challenge: bytes = b"c" * 64 + b"\n") -> None:
        self.challenge = challenge
        self.releases: list[bytes] = []

    def read_stdout(self, *, max_bytes: int, timeout_seconds: float) -> bytes:
        assert max_bytes == 65
        assert timeout_seconds > 0
        return self.challenge

    def release_once(self, payload: bytes, *, timeout_seconds: float) -> None:
        assert timeout_seconds > 0
        self.releases.append(payload)

    def finish(
        self, *, timeout_seconds: float, max_stdout_bytes: int, max_stderr_bytes: int
    ) -> object:
        assert timeout_seconds > 0
        assert max_stdout_bytes > 0
        assert max_stderr_bytes > 0
        return resource_cgroup.CommandResultV1(returncode=0, stdout=b"", stderr=b"")

    def terminate(self) -> None:
        return None


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
    ) -> None:
        self.collision = collision
        self.control_group = control_group
        self.target_slice_control_group = target_slice_control_group
        self.target_slice_missing = target_slice_missing
        self.target_slice_stdout = target_slice_stdout
        self.timeout = timeout
        self.show_stdout = show_stdout
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
            return self._result(
                returncode=0,
                stdout=f"ControlGroup={control_group}\nMainPID=4241\n".encode(),
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
    return resource_cgroup.SystemdUserCgroupAdapter(runner=runner)


def test_systemd_adapter_uses_fixed_argv_internal_unit_and_one_internal_gate_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    monkeypatch.setattr(adapter, "_read_tmux_children", lambda _pid: (4243,))

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
            "--pipe",
            "--quiet",
            "--collect",
            f"--unit={scope.unit_name}",
            "--slice=codex-master.slice",
            "--property=Delegate=yes",
            "--property=AllowedCPUs=4-11",
            "--property=CPUQuota=750%",
            "--property=CPUWeight=50",
            f"--property=MemoryHigh={9 * GIB}",
            f"--property=MemoryMax={12 * GIB}",
            f"--property=MemorySwapMax={8 * GIB}",
            "--property=IOWeight=50",
            "/usr/libexec/codex-master-resource-scope-gate",
            "scope_socket-1",
            "scope-session.1",
        )
    ]
    assert runner.gate.releases == [b"c" * 64 + b"\n"]
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


def test_systemd_adapter_binds_preflight_and_new_scope_to_codex_master_slice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner()
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    monkeypatch.setattr(adapter, "_read_tmux_children", lambda _pid: (4243,))

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
        assert runner.gate.releases == []
        if number == 1:
            assert runner.stopped == ["codex-master-resource-" + "d" * 32 + ".scope"]
        else:
            assert runner.started == []


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
    assert runner.gate.releases == []


def test_integration_precondition_classifier_skips_only_clean_absence_and_fails_readback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing_runner = _FakeSystemdRunner(target_slice_missing=True)
    missing_adapter = _systemd_adapter(monkeypatch, tmp_path / "missing", missing_runner)
    monkeypatch.setattr(missing_adapter, "_user_bus_socket_present", lambda: True)
    assert missing_adapter.integration_precondition_reason() == "requires_target_slice"

    no_delegation = _FakeSystemdRunner()
    absent_adapter = _systemd_adapter(
        monkeypatch,
        tmp_path / "absence",
        no_delegation,
        slice_controllers=b"cpu cpuset memory pids\n",
    )
    monkeypatch.setattr(absent_adapter, "_user_bus_socket_present", lambda: True)
    assert absent_adapter.integration_precondition_reason() == "requires_delegated_controllers"

    malformed_runner = _FakeSystemdRunner()
    malformed_adapter = _systemd_adapter(
        monkeypatch,
        tmp_path / "malformed",
        malformed_runner,
        slice_subtree=b"cpu cpuset memory pids io io\n",
    )
    monkeypatch.setattr(malformed_adapter, "_user_bus_socket_present", lambda: True)
    with pytest.raises(CgroupPreflightError, match="^cgroup_preflight_failed$"):
        malformed_adapter.integration_precondition_reason()


def test_empty_target_slice_control_group_is_missing_only_for_integration_classifier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _FakeSystemdRunner(target_slice_stdout=b"ControlGroup=\n")
    adapter = _systemd_adapter(monkeypatch, tmp_path, runner)
    monkeypatch.setattr(adapter, "_user_bus_socket_present", lambda: True)

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
    monkeypatch.setattr(adapter, "_user_bus_socket_present", lambda: True)

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
        assert runner.gate.releases == []
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

    assert runner.gate.releases == []
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

    assert runner.gate.releases == []
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
