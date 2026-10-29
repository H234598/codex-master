from __future__ import annotations

import multiprocessing
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import subprocess
import sys
import secrets
from unittest.mock import patch

import pytest

from the_hive.hive.state import HiveStateStore
from the_hive.headless_write_scope import HeadlessWriteScopeStore
from the_hive.resource_cgroup import PreparedAgentScope
from the_hive import runtime_process
from the_hive import server as server_module
from the_hive.worktree_lifecycle import (
    G5ScopeBindingEvidence,
    RuntimeBindingEvidence,
    RuntimeEndEvidence,
    UseLease,
    WorktreeBinding,
    WorktreeLifecycleError,
    WorktreeLifecycleStore,
)


def _binding(root: Path) -> WorktreeBinding:
    source = root / "worktree"
    subprocess.run(["git", "init", "--quiet", str(source)], check=True)
    for args in (
        ("git", "config", "user.email", "test@example.invalid"),
        ("git", "config", "user.name", "Lifecycle Test"),
    ):
        subprocess.run(args, cwd=source, check=True, capture_output=True, text=True)
    (source / "baseline.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run(("git", "add", "baseline.txt"), cwd=source, check=True)
    subprocess.run(
        ("git", "commit", "--quiet", "-m", "baseline"), cwd=source, check=True
    )
    attestation = HeadlessWriteScopeStore(root / "binding-evidence-state").create(
        "agent.test",
        source.resolve(strict=True),
        source.resolve(strict=True),
        base_ref=None,
    )
    return WorktreeBinding.from_creation_attestation(attestation)


def _register_origin(
    store: WorktreeLifecycleStore, binding: WorktreeBinding, root: Path
) -> None:
    attestation = HeadlessWriteScopeStore(root / "origin-state").create(
        "agent.test",
        binding.canonical_source_path,
        binding.canonical_source_path,
        base_ref=None,
    )
    store._record_created_worktree(binding, attestation)


def _begin_use_and_exit(
    state_root: str, binding: WorktreeBinding, output: multiprocessing.Queue
) -> None:
    store = WorktreeLifecycleStore(HiveStateStore(Path(state_root)))
    output.put(
        store.begin_use(
            binding,
            principal_id="principal.test",
            session_id="session.test",
            assignment_id="assignment.test",
            now=1,
        )
    )


def _claim_in_process(
    state_root: str,
    binding: WorktreeBinding,
    barrier: multiprocessing.Barrier,
    output: multiprocessing.Queue,
) -> None:
    store = WorktreeLifecycleStore(HiveStateStore(Path(state_root)))
    barrier.wait()
    try:
        claim = store.claim_maintenance(binding, now=5)
    except WorktreeLifecycleError as exc:
        output.put(("blocked", str(exc)))
    else:
        output.put(("claimed", claim))


def _claim_and_exit(
    state_root: str, binding: WorktreeBinding, output: multiprocessing.Queue
) -> None:
    store = WorktreeLifecycleStore(HiveStateStore(Path(state_root)))
    output.put(store.claim_maintenance(binding, now=5))


def _begin_use_in_process(
    state_root: str, binding: WorktreeBinding, output: multiprocessing.Queue
) -> None:
    store = WorktreeLifecycleStore(HiveStateStore(Path(state_root)))
    try:
        lease = store.begin_use(
            binding,
            principal_id="principal.alias",
            session_id="session.alias",
            assignment_id="assignment.alias",
            now=2,
        )
    except WorktreeLifecycleError as exc:
        output.put(("blocked", str(exc)))
    else:
        output.put(("began", lease))


def _race_begin_use_in_process(
    state_root: str,
    binding: WorktreeBinding,
    barrier: multiprocessing.Barrier,
    output: multiprocessing.Queue,
) -> None:
    store = WorktreeLifecycleStore(HiveStateStore(Path(state_root)))
    barrier.wait()
    try:
        lease = store.begin_use(
            binding,
            principal_id="principal.racer",
            session_id="session.racer",
            assignment_id="assignment.racer",
            now=6,
        )
    except WorktreeLifecycleError as exc:
        output.put(("blocked", str(exc)))
    else:
        output.put(("began", lease))


def _native_reference_process(
    attempt: multiprocessing.Event,
    held: multiprocessing.Event,
    release: multiprocessing.Event,
    output: multiprocessing.Queue,
) -> None:
    attempt.set()
    with server_module.spawn_admission_lock():
        with server_module.native_agent_registry_lock():
            result = server_module._native_worktree_lifecycle_denial(
                reference_id="native.race"
            )
            output.put(("native", result))
            held.set()
            release.wait()


def _native_claim_process(
    binding: WorktreeBinding,
    attempt: multiprocessing.Event,
    held: multiprocessing.Event,
    release: multiprocessing.Event,
    output: multiprocessing.Queue,
) -> None:
    attempt.set()
    with server_module.spawn_admission_lock():
        with server_module.native_agent_registry_lock():
            try:
                server_module._claim_worktree_maintenance(binding, now=20)
            except WorktreeLifecycleError as exc:
                output.put(("claim_denied", str(exc)))
            else:
                output.put(("claim", "claimed"))
            held.set()
            release.wait()


def _runtime_process() -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )


def _complete_use(
    store: WorktreeLifecycleStore,
    binding: WorktreeBinding,
    *,
    session_id: str = "session.test",
    now: int = 1,
    slice_path: str = "/the-hive.slice",
) -> UseLease:
    lease = store.begin_use(
        binding,
        principal_id="principal.test",
        session_id=session_id,
        assignment_id="assignment.test",
        now=now,
    )
    unit = f"the-hive-resource-{secrets.token_hex(16)}.scope"
    group = f"{slice_path}/{unit}"
    cgroup_root = binding.canonical_source_path.parent / "test-cgroup"
    cgroup = cgroup_root.joinpath(*slice_path.strip("/").split("/"), unit)
    cgroup.mkdir(parents=True)
    (cgroup / "cgroup.events").write_text("populated 1\nfrozen 0\n", encoding="ascii")
    (cgroup / "cgroup.procs").write_text("777\n", encoding="ascii")
    invocation = secrets.token_hex(16)

    def fake_systemctl(_args, *, environment, deadline):
        del environment, deadline
        return (
            f"ControlGroup={group}\nInvocationID={invocation}\nLoadState=loaded\n"
        ).encode("ascii")

    scope = PreparedAgentScope(
        unit_name=unit,
        socket_name=f"g5-{secrets.token_hex(10)}",
        session_name=f"worktree-{secrets.token_hex(6)}",
        control_group=group,
        gate_pid=os.getpid(),
        challenge=secrets.token_hex(32),
    )
    with (
        patch.object(runtime_process, "_CGROUP_ROOT", cgroup_root),
        patch.object(runtime_process, "_systemctl", fake_systemctl),
    ):
        evidence = G5ScopeBindingEvidence.capture(lease, scope, now=now + 1)
        lease = store.bind_g5_runtime(lease, evidence, now=now + 1)
        reopened = WorktreeLifecycleStore(
            HiveStateStore(binding.canonical_source_path.parent / "state")
        )
        lease = next(
            item
            for item in reopened.snapshot().active_uses
            if item.lease_id == lease.lease_id
        )
        (cgroup / "cgroup.events").write_text(
            "populated 0\nfrozen 0\n", encoding="ascii"
        )
        (cgroup / "cgroup.procs").write_text("", encoding="ascii")
        end_evidence = RuntimeEndEvidence.observe(lease, now=now + 2)
        store.end_use(lease, end_evidence, now=now + 3)
    return lease


def test_full_user_manager_scope_persists_and_retires_after_cgroup_empty(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))

    lease = _complete_use(
        store,
        binding,
        session_id="session.user-manager-scope",
        now=10,
        slice_path="/user.slice/user-1000.slice/user@1000.service/the-hive.slice",
    )

    assert lease.runtime_scope is not None
    assert lease.runtime_scope.control_group == (
        "/user.slice/user-1000.slice/user@1000.service/the-hive.slice/"
        f"{lease.runtime_scope.unit_name}"
    )


def test_unknown_worktree_is_not_claimed_as_attested_unused(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))

    with pytest.raises(WorktreeLifecycleError, match="worktree_binding_unknown"):
        store.claim_maintenance(binding, now=1)


def test_pre_spawn_abort_removes_only_bound_temp_origin_and_active_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))
    _register_origin(store, binding, tmp_path)
    temp_base = tmp_path / "private-temp-base"
    temp_base.mkdir(mode=0o700)
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(temp_base))

    paths = []
    for index in range(2):
        lease = store.begin_use(
            binding,
            principal_id="principal.pre-spawn",
            session_id="session.pre-spawn",
            assignment_id=f"assignment.pre-spawn-{index}",
            now=10 + index,
        )
        producer_path = store.create_temporary_producer(lease, now=10 + index)
        paths.append(producer_path)
        store.abort_temporary_producer_before_spawn(
            lease, producer_path, now=20 + index
        )
        assert not producer_path.exists()
        assert store.active_use_for_assignment(lease.assignment_id) is None

    assert len(paths) == 2
    assert store.snapshot().active_uses == ()
    assert store.temporary_producers(binding) == ()
    assert store.last_use_ended_at(binding) is None


def test_pre_spawn_abort_keeps_changed_or_runtime_bound_temp_protected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))
    _register_origin(store, binding, tmp_path)
    temp_base = tmp_path / "private-temp-base"
    temp_base.mkdir(mode=0o700)
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(temp_base))
    lease = store.begin_use(
        binding,
        principal_id="principal.uncertain",
        session_id="session.uncertain",
        assignment_id="assignment.uncertain",
        now=10,
    )
    producer_path = store.create_temporary_producer(lease, now=10)
    wrong_path = producer_path.with_name("different-temp-root")
    with pytest.raises(
        WorktreeLifecycleError, match="temporary_producer_identity_invalid"
    ):
        store.abort_temporary_producer_before_spawn(lease, wrong_path, now=11)
    assert producer_path.is_dir()

    unit = f"the-hive-resource-{secrets.token_hex(16)}.scope"
    group = f"/the-hive.slice/{unit}"
    cgroup_root = tmp_path / "cgroups"
    cgroup = cgroup_root / "the-hive.slice" / unit
    cgroup.mkdir(parents=True)
    (cgroup / "cgroup.events").write_text("populated 1\nfrozen 0\n", encoding="ascii")
    (cgroup / "cgroup.procs").write_text("777\n", encoding="ascii")
    invocation = secrets.token_hex(16)
    scope = PreparedAgentScope(
        unit_name=unit,
        socket_name=f"g5-{secrets.token_hex(8)}",
        session_name="uncertain",
        control_group=group,
        gate_pid=os.getpid(),
        challenge=secrets.token_hex(32),
    )

    def fake_systemctl(_args, *, environment, deadline):
        del environment, deadline
        return f"ControlGroup={group}\nInvocationID={invocation}\nLoadState=loaded\n".encode()

    with (
        patch.object(runtime_process, "_CGROUP_ROOT", cgroup_root),
        patch.object(runtime_process, "_systemctl", fake_systemctl),
    ):
        evidence = G5ScopeBindingEvidence.capture(lease, scope, now=11)
        bound_lease = store.bind_g5_runtime(lease, evidence, now=11)
        with pytest.raises(
            WorktreeLifecycleError, match="pre_spawn_abort_runtime_bound"
        ):
            store.abort_temporary_producer_before_spawn(
                bound_lease, producer_path, now=12
            )

    assert producer_path.is_dir()
    assert store.active_use_for_assignment(lease.assignment_id) is not None
    assert store.temporary_producers(binding) == ()


def test_binding_for_subdirectory_resolves_registered_worktree_root(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))
    _register_origin(store, binding, tmp_path)
    nested = Path(binding.canonical_source_path) / "nested"
    nested.mkdir()

    assert store.binding_for_source(nested) == binding


def test_binding_does_not_map_nested_git_repository_to_parent_worktree(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))
    _register_origin(store, binding, tmp_path)
    nested = Path(binding.canonical_source_path) / "nested"
    nested.mkdir()
    subprocess.run(("git", "init", "--quiet"), cwd=nested, check=True)

    assert store.binding_for_source(nested) is None

    assert store.snapshot().maintenance_claims == ()


def test_old_worktree_stays_unclaimable_after_one_observed_use(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))

    _complete_use(store, binding)

    with pytest.raises(WorktreeLifecycleError, match="worktree_origin_unattested"):
        store.claim_maintenance(binding, now=10)


def test_lifecycle_exposes_only_recorded_runtime_end_time(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))
    _register_origin(store, binding, tmp_path)

    assert store.last_use_ended_at(binding) is None
    _complete_use(store, binding, now=10)
    assert store.last_use_ended_at(binding) == 12


def test_runtime_leader_exit_does_not_release_use_with_child_in_new_session(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))
    lease = store.begin_use(
        binding,
        principal_id="principal.test",
        session_id="session.test",
        assignment_id="assignment.test",
        now=1,
    )
    leader = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import subprocess,sys; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(600)'], "
            "start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
            "print(p.pid)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    child_pid = -1
    try:
        evidence = RuntimeBindingEvidence.capture(lease, leader, now=2)
        lease = store.bind_runtime(lease, evidence, now=2)
        assert leader.stdout is not None
        child_pid = int(leader.stdout.readline())
        leader.wait()

        with pytest.raises(WorktreeLifecycleError, match="runtime_process_active"):
            RuntimeEndEvidence.observe(lease, now=3)
        with pytest.raises(WorktreeLifecycleError, match="runtime_process_active"):
            store.end_use(
                lease,
                RuntimeEndEvidence.observe(lease, now=4),
                now=5,
            )
        assert store.snapshot().active_uses == (lease,)
    finally:
        if leader.poll() is None:
            leader.terminate()
            leader.wait()
        if child_pid > 0:
            try:
                os.kill(child_pid, 15)
            except ProcessLookupError:
                pass


def test_parent_exit_does_not_release_use_while_bound_runtime_is_active(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    state_root = tmp_path / "state"
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(state_root))
    _register_origin(store, binding, tmp_path)
    runtime = _runtime_process()
    output = context.Queue()
    process = context.Process(
        target=_begin_use_and_exit, args=(str(state_root), binding, output)
    )
    try:
        process.start()
        pending_lease = output.get()
        process.join()
        assert process.exitcode == 0
        assert isinstance(pending_lease, UseLease)
        bind_evidence = RuntimeBindingEvidence.capture(pending_lease, runtime, now=2)
        lease = store.bind_runtime(pending_lease, bind_evidence, now=3)
        reopened = WorktreeLifecycleStore(HiveStateStore(state_root))
        assert reopened.snapshot().active_uses == (lease,)
        with pytest.raises(WorktreeLifecycleError, match="worktree_in_use"):
            reopened.claim_maintenance(binding, now=4)
        with pytest.raises(WorktreeLifecycleError, match="runtime_process_active"):
            RuntimeEndEvidence.observe(lease, now=5)

        assert runtime.stdin is not None
        runtime.stdin.close()
        runtime.wait()
        with pytest.raises(WorktreeLifecycleError, match="runtime_process_active"):
            RuntimeEndEvidence.observe(lease, now=6)
        with pytest.raises(WorktreeLifecycleError, match="worktree_in_use"):
            store.claim_maintenance(binding, now=8)
    finally:
        if process.is_alive():
            process.join()
        output.close()
        output.join_thread()
        if runtime.poll() is None:
            runtime.terminate()
            runtime.wait()


def test_unverified_or_incomplete_end_evidence_keeps_worktree_protected(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))
    lease = store.begin_use(
        binding,
        principal_id="principal.test",
        session_id="session.test",
        assignment_id="assignment.test",
        now=1,
    )

    for evidence in (True, {"ended": True}, {"process_exited": True}):
        with pytest.raises(WorktreeLifecycleError, match="end_evidence_invalid"):
            store.end_use(lease, evidence, now=2)  # type: ignore[arg-type]

    with pytest.raises(WorktreeLifecycleError, match="runtime_binding_pending"):
        RuntimeEndEvidence.observe(lease, now=2)

    assert store.snapshot().active_uses == (lease,)
    with pytest.raises(WorktreeLifecycleError, match="worktree_in_use"):
        store.claim_maintenance(binding, now=3)


def test_one_runtime_process_cannot_be_bound_to_multiple_use_leases(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))
    first = store.begin_use(
        binding,
        principal_id="principal.first",
        session_id="session.first",
        assignment_id="assignment.first",
        now=1,
    )
    second = store.begin_use(
        binding,
        principal_id="principal.second",
        session_id="session.second",
        assignment_id="assignment.second",
        now=2,
    )
    runtime = _runtime_process()
    try:
        first = store.bind_runtime(
            first,
            RuntimeBindingEvidence.capture(first, runtime, now=3),
            now=3,
        )
        second_evidence = RuntimeBindingEvidence.capture(second, runtime, now=4)
        with pytest.raises(
            WorktreeLifecycleError, match="runtime_reference_already_bound"
        ):
            store.bind_runtime(second, second_evidence, now=4)

        active_uses = store.snapshot().active_uses
        by_lease = {item.lease_id: item for item in active_uses}
        assert set(by_lease) == {first.lease_id, second.lease_id}
        assert by_lease[first.lease_id].runtime_process is not None
        assert by_lease[second.lease_id].runtime_process is None
    finally:
        if runtime.poll() is None:
            runtime.terminate()
            runtime.wait()


def test_maintenance_claim_blocks_new_use_and_resume_after_store_reopen(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    state_root = tmp_path / "state"
    store = WorktreeLifecycleStore(HiveStateStore(state_root))
    _register_origin(store, binding, tmp_path)
    _complete_use(store, binding)
    claim = store.claim_maintenance(binding, now=5)
    reopened = WorktreeLifecycleStore(HiveStateStore(state_root))

    assert reopened.assert_claim(claim) is None
    for session_id in ("new-session", "session.test"):
        with pytest.raises(WorktreeLifecycleError, match="maintenance_claim_active"):
            reopened.begin_use(
                binding,
                principal_id="principal.test",
                session_id=session_id,
                assignment_id="assignment.test",
                now=6,
            )


def test_claim_exclusion_holds_in_both_deterministic_orders(tmp_path: Path) -> None:
    start_first_root = tmp_path / "start-first"
    start_first_root.mkdir()
    start_first_binding = _binding(start_first_root)
    start_first_store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state-a"))
    _register_origin(start_first_store, start_first_binding, start_first_root)
    start_first_store.begin_use(
        start_first_binding,
        principal_id="principal.start",
        session_id="session.start",
        assignment_id="assignment.start",
        now=1,
    )
    with pytest.raises(WorktreeLifecycleError, match="worktree_in_use"):
        start_first_store.claim_maintenance(start_first_binding, now=2)

    claim_first_root = tmp_path / "claim-first"
    claim_first_root.mkdir()
    claim_first_binding = _binding(claim_first_root)
    claim_first_store = WorktreeLifecycleStore(
        HiveStateStore(claim_first_root / "state")
    )
    _register_origin(claim_first_store, claim_first_binding, claim_first_root)
    _complete_use(claim_first_store, claim_first_binding)
    claim_first_store.claim_maintenance(claim_first_binding, now=5)
    with pytest.raises(WorktreeLifecycleError, match="maintenance_claim_active"):
        claim_first_store.begin_use(
            claim_first_binding,
            principal_id="principal.start",
            session_id="session.start",
            assignment_id="assignment.start",
            now=6,
        )


def test_claim_rejects_wrong_revision_fence_and_replay(tmp_path: Path) -> None:
    from dataclasses import replace

    binding = _binding(tmp_path)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))
    _register_origin(store, binding, tmp_path)
    _complete_use(store, binding)
    claim = store.claim_maintenance(binding, now=5)

    with pytest.raises(WorktreeLifecycleError, match="maintenance_claim_mismatch"):
        store.assert_claim(replace(claim, revision=claim.revision + 1))
    with pytest.raises(WorktreeLifecycleError, match="maintenance_claim_mismatch"):
        store.assert_claim(replace(claim, fence=claim.fence + 1))

    with pytest.raises(
        WorktreeLifecycleError, match="maintenance_operation_incomplete"
    ):
        store.finish_maintenance(claim, outcome="retained")
    store.assert_claim(claim)
    with pytest.raises(
        WorktreeLifecycleError, match="maintenance_operation_incomplete"
    ):
        store.finish_maintenance(claim, outcome="replayed")


def test_maintenance_phase_is_persisted_and_claim_recovers_under_new_fence(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    binding = _binding(tmp_path)
    state_root = tmp_path / "state"
    store = WorktreeLifecycleStore(HiveStateStore(state_root))
    _register_origin(store, binding, tmp_path)
    _complete_use(store, binding)
    output = context.Queue()
    process = context.Process(
        target=_claim_and_exit, args=(str(state_root), binding, output)
    )
    process.start()
    stale_claim = output.get()
    process.join()
    assert process.exitcode == 0

    with store._state.locked():
        document = store._state.read_json_locked(
            PurePosixPath("worktree-lifecycle-v1.json"), max_bytes=1024 * 1024
        )
    tree = next(iter(document["worktrees"].values()))
    assert tree["maintenance_operation"]["phase"] == "claimed"

    recovered = WorktreeLifecycleStore(
        HiveStateStore(state_root)
    ).recover_maintenance_claim(binding, now=6)

    assert recovered.claim_id == stale_claim.claim_id
    assert recovered.owner_process != stale_claim.owner_process
    assert recovered.fence == stale_claim.fence + 1
    with pytest.raises(
        WorktreeLifecycleError, match="maintenance_operation_incomplete"
    ):
        WorktreeLifecycleStore(HiveStateStore(state_root)).finish_maintenance(
            recovered, outcome="incorrectly-finished"
        )
    with pytest.raises(WorktreeLifecycleError, match="maintenance_recovery_hold"):
        WorktreeLifecycleStore(HiveStateStore(state_root)).assert_claim(recovered)
    with store._state.locked():
        document = store._state.read_json_locked(
            PurePosixPath("worktree-lifecycle-v1.json"), max_bytes=1024 * 1024
        )
    tree = next(iter(document["worktrees"].values()))
    assert tree["maintenance_claim"] is not None
    assert tree["maintenance_operation"]["phase"] == "recovery_hold"


def test_competing_processes_cannot_both_own_maintenance_claim(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    binding = _binding(tmp_path)
    state_root = tmp_path / "state"
    store = WorktreeLifecycleStore(HiveStateStore(state_root))
    _register_origin(store, binding, tmp_path)
    _complete_use(store, binding)
    barrier = context.Barrier(2)
    output = context.Queue()
    processes = [
        context.Process(
            target=_claim_in_process,
            args=(str(state_root), binding, barrier, output),
        )
        for _ in range(2)
    ]

    for process in processes:
        process.start()
    results = [output.get(), output.get()]
    for process in processes:
        process.join()
    output.close()
    output.join_thread()

    assert all(process.exitcode == 0 for process in processes)
    assert sorted(result[0] for result in results) == ["blocked", "claimed"]
    claim = next(result[1] for result in results if result[0] == "claimed")
    reopened = WorktreeLifecycleStore(HiveStateStore(state_root))
    assert reopened.snapshot().maintenance_claims == (claim,)
    with pytest.raises(WorktreeLifecycleError, match="maintenance_claim_active"):
        reopened.claim_maintenance(binding, now=2)


def test_start_and_maintenance_claim_race_has_one_atomic_winner(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    binding = _binding(tmp_path)
    state_root = tmp_path / "state"
    store = WorktreeLifecycleStore(HiveStateStore(state_root))
    _register_origin(store, binding, tmp_path)
    _complete_use(store, binding)
    barrier = context.Barrier(2)
    output = context.Queue()
    processes = (
        context.Process(
            target=_race_begin_use_in_process,
            args=(str(state_root), binding, barrier, output),
        ),
        context.Process(
            target=_claim_in_process,
            args=(str(state_root), binding, barrier, output),
        ),
    )
    for process in processes:
        process.start()
    results = (output.get(), output.get())
    for process in processes:
        process.join()
    output.close()
    output.join_thread()

    assert all(process.exitcode == 0 for process in processes)
    outcomes = {result[0]: result[1] for result in results}
    assert set(outcomes) in ({"blocked", "claimed"}, {"began", "blocked"})
    if "claimed" in outcomes:
        assert outcomes["blocked"] == "maintenance_claim_active"
    else:
        assert outcomes["blocked"] == "worktree_in_use"
    final = WorktreeLifecycleStore(HiveStateStore(state_root)).snapshot()
    assert len(final.active_uses) + len(final.maintenance_claims) == 1


def test_competing_alias_binding_cannot_create_second_physical_worktree_use(
    tmp_path: Path,
) -> None:
    from dataclasses import replace

    context = multiprocessing.get_context("spawn")
    binding = _binding(tmp_path)
    alias = replace(binding, repository_id="repo.alias")
    state_root = tmp_path / "state"
    store = WorktreeLifecycleStore(HiveStateStore(state_root))
    original_lease = store.begin_use(
        binding,
        principal_id="principal.original",
        session_id="session.original",
        assignment_id="assignment.original",
        now=1,
    )
    output = context.Queue()
    process = context.Process(
        target=_begin_use_in_process, args=(str(state_root), alias, output)
    )
    process.start()
    result = output.get()
    process.join()
    output.close()
    output.join_thread()

    assert process.exitcode == 0
    assert result == ("blocked", "worktree_binding_alias")
    assert WorktreeLifecycleStore(
        HiveStateStore(state_root)
    ).snapshot().active_uses == (original_lease,)


def test_binding_rejects_unrelated_git_common_directory(tmp_path: Path) -> None:
    from dataclasses import replace

    binding = _binding(tmp_path)
    unrelated_common = tmp_path / "unrelated-git-common"
    unrelated_common.mkdir()
    alias = replace(binding, git_common_directory=unrelated_common)
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))

    with pytest.raises(WorktreeLifecycleError, match="worktree_git_common_mismatch"):
        store.begin_use(
            alias,
            principal_id="principal.test",
            session_id="session.test",
            assignment_id="assignment.test",
            now=1,
        )


def test_native_reference_blocks_maintenance_for_any_project_source(
    tmp_path: Path,
) -> None:
    state = HiveStateStore(tmp_path / "state")
    store = WorktreeLifecycleStore(state)
    first = _binding(tmp_path)
    second = _binding(tmp_path / "second")
    _register_origin(store, first, tmp_path)
    _complete_use(store, first)
    store.reserve_native_reference(reference_id="native.spawn.1", now=1)

    with pytest.raises(WorktreeLifecycleError, match="native_reference_active"):
        store.claim_maintenance(first, now=2)
    with pytest.raises(WorktreeLifecycleError, match="native_reference_active"):
        store.claim_maintenance(second, now=2)


def test_maintenance_claim_blocks_new_native_reference(tmp_path: Path) -> None:
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))
    binding = _binding(tmp_path)
    _register_origin(store, binding, tmp_path)
    _complete_use(store, binding)
    claim = store.claim_maintenance(binding, now=2)

    with pytest.raises(WorktreeLifecycleError, match="maintenance_claim_active"):
        store.reserve_native_reference(reference_id="native.spawn.2", now=3)
    store.assert_claim(claim)


def test_unbound_native_reference_stays_protected_without_ttl_or_retire_api(
    tmp_path: Path,
) -> None:
    store = WorktreeLifecycleStore(HiveStateStore(tmp_path / "state"))
    binding = _binding(tmp_path)
    _register_origin(store, binding, tmp_path)
    _complete_use(store, binding)
    store.reserve_native_reference(reference_id="native.opaque", now=1)

    with pytest.raises(WorktreeLifecycleError, match="native_reference_active"):
        store.claim_maintenance(binding, now=10**12)


def test_repeated_native_admissions_share_one_bounded_pending_reference(
    tmp_path: Path,
) -> None:
    state = HiveStateStore(tmp_path / "state")
    store = WorktreeLifecycleStore(state)
    for index in range(3):
        store.reserve_native_reference(reference_id=f"native.resume.{index}", now=index)

    with state.locked():
        document = state.read_json_locked(
            PurePosixPath("worktree-lifecycle-v1.json"), max_bytes=1024 * 1024
        )
    assert document["native_references"] == [
        {"reference_id": "native-opaque-pending", "created_at": 0}
    ]


def test_native_writer_persists_reference_before_pruning_expired_reservation(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    state_root = tmp_path / "state"
    lifecycle = WorktreeLifecycleStore(HiveStateStore(state_root))
    _register_origin(lifecycle, binding, tmp_path)
    _complete_use(lifecycle, binding)
    native_file = state_root / "native-agents.json"
    with (
        patch.object(server_module, "STATE_ROOT", state_root),
        patch.object(server_module, "LOCK_DIR", state_root / "locks"),
        patch.object(server_module, "NATIVE_AGENT_REGISTRY_FILE", native_file),
        patch.object(
            server_module,
            "NATIVE_AGENT_REGISTRY_LOCK_FILE",
            state_root / "locks" / "native-agents.lock",
        ),
        patch.object(
            server_module, "_worktree_lifecycle_store", return_value=lifecycle
        ),
        patch(
            "the_hive.native_registry.retained_pin_session_ids",
            return_value=frozenset(),
        ),
    ):
        server_module._write_native_agent_registry(
            {
                "schema_version": 2,
                "agents": [],
                "sessions": [],
                "reservations": [
                    {
                        "reservation_id": "expired-native",
                        "kind": "native_spawn",
                        "created_at": 1,
                        "parent_session_id": "parent-session",
                    }
                ],
            },
            now=2_000,
        )
        assert json.loads(native_file.read_text(encoding="utf-8"))["reservations"] == []
        with pytest.raises(WorktreeLifecycleError, match="native_reference_active"):
            lifecycle.claim_maintenance(binding, now=2_001)


def test_native_writer_persists_reference_before_pruning_unpinned_history(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    state_root = tmp_path / "state"
    lifecycle = WorktreeLifecycleStore(HiveStateStore(state_root))
    _register_origin(lifecycle, binding, tmp_path)
    _complete_use(lifecycle, binding)
    native_file = state_root / "native-agents.json"
    agents = [
        {
            "session_id": f"parent-{index}",
            "agent_id": f"child-{index}",
            "agent_type": "worker",
            "activity_state": "completed",
            "updated_at": float(index),
        }
        for index in range(1025)
    ]
    with (
        patch.object(server_module, "STATE_ROOT", state_root),
        patch.object(server_module, "LOCK_DIR", state_root / "locks"),
        patch.object(server_module, "NATIVE_AGENT_REGISTRY_FILE", native_file),
        patch.object(
            server_module,
            "NATIVE_AGENT_REGISTRY_LOCK_FILE",
            state_root / "locks" / "native-agents.lock",
        ),
        patch.object(
            server_module, "_worktree_lifecycle_store", return_value=lifecycle
        ),
        patch(
            "the_hive.native_registry.retained_pin_session_ids",
            return_value=frozenset(),
        ),
    ):
        server_module._write_native_agent_registry(
            {"schema_version": 2, "agents": agents, "sessions": [], "reservations": []},
            now=2_000,
        )
        assert (
            len(json.loads(native_file.read_text(encoding="utf-8"))["agents"]) == 1024
        )
        with pytest.raises(WorktreeLifecycleError, match="native_reference_active"):
            lifecycle.claim_maintenance(binding, now=2_001)


def test_native_claim_fence_race_uses_real_hive_state_and_registry_locks(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("fork")
    for first in ("native", "claim"):
        case_root = tmp_path / first
        case_root.mkdir()
        binding = _binding(case_root)
        state_root = case_root / "state"
        lifecycle = WorktreeLifecycleStore(HiveStateStore(state_root))
        _register_origin(lifecycle, binding, case_root)
        _complete_use(lifecycle, binding)
        native_file = state_root / "native-agents.json"
        lock_file = state_root / "locks" / "native-agents.lock"
        with (
            patch.object(server_module, "STATE_ROOT", state_root),
            patch.object(server_module, "LOCK_DIR", state_root / "locks"),
            patch.object(server_module, "NATIVE_AGENT_REGISTRY_FILE", native_file),
            patch.object(server_module, "NATIVE_AGENT_REGISTRY_LOCK_FILE", lock_file),
            patch.object(
                server_module, "_worktree_lifecycle_store", return_value=lifecycle
            ),
            patch.object(
                server_module, "retained_pin_session_ids", return_value=frozenset()
            ),
        ):
            server_module._write_native_agent_registry(
                {"schema_version": 2, "agents": [], "sessions": [], "reservations": []},
                now=10,
            )
            output = context.Queue()
            if first == "native":
                native_attempt = context.Event()
                native_held = context.Event()
                release_native = context.Event()
                claim_attempt = context.Event()
                claim_held = context.Event()
                release_claim = context.Event()
                producer = context.Process(
                    target=_native_reference_process,
                    args=(native_attempt, native_held, release_native, output),
                )
                producer.start()
                native_held.wait()
                claimant = context.Process(
                    target=_native_claim_process,
                    args=(binding, claim_attempt, claim_held, release_claim, output),
                )
                claimant.start()
                claim_attempt.wait()
                release_native.set()
                claim_held.wait()
                assert output.get() == ("native", None)
                assert output.get() == ("claim_denied", "native_reference_active")
                release_claim.set()
                producer.join()
                claimant.join()
            else:
                claim_attempt = context.Event()
                claim_held = context.Event()
                release_claim = context.Event()
                native_attempt = context.Event()
                native_held = context.Event()
                release_native = context.Event()
                claimant = context.Process(
                    target=_native_claim_process,
                    args=(binding, claim_attempt, claim_held, release_claim, output),
                )
                claimant.start()
                claim_held.wait()
                producer = context.Process(
                    target=_native_reference_process,
                    args=(native_attempt, native_held, release_native, output),
                )
                producer.start()
                native_attempt.wait()
                release_claim.set()
                native_held.wait()
                assert output.get() == ("claim", "claimed")
                assert output.get() == (
                    "native",
                    {
                        "allowed": False,
                        "error_code": "spawn_capacity_unavailable",
                        "reason_codes": ["maintenance_claim_active"],
                    },
                )
                release_native.set()
                claimant.join()
                producer.join()
