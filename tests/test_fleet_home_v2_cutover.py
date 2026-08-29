import ast
import hashlib
import json
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from codex_master.fleet_home_v2_cutover import (
    MARKER_FILE,
    FleetHomeV2Artifact,
    FleetHomeV2Authority,
    FleetHomeV2CutoverError,
    FleetHomeV2CutoverService,
    FleetHomeV2EntropyPort,
    FleetHomeV2Inventory,
    FleetHomeV2Policy,
    FleetHomeV2QuiescencePort,
    FleetHomeV2SnapshotAuthorityPort,
    LocalFleetHomeV2Filesystem,
)


CORE_PATH = Path(__file__).resolve().parents[1] / "src/codex_master/fleet_home_v2_cutover.py"
_ENTROPY_SEED = 100


class FixedEntropy(FleetHomeV2EntropyPort):
    def __init__(self, value: int = 1) -> None:
        self.value = value

    def token_hex(self, bytes_count: int) -> str:
        value = f"{self.value:0{bytes_count * 2}x}"
        self.value += 1
        return value


class RepeatedEntropy(FleetHomeV2EntropyPort):
    def token_hex(self, bytes_count: int) -> str:
        return "f" * (bytes_count * 2)


class Crash(RuntimeError):
    pass


class CrashFilesystem(LocalFleetHomeV2Filesystem):
    def __init__(self, point: str) -> None:
        self.point = point

    def checkpoint(self, point: str) -> None:
        if point == self.point:
            raise Crash(point)


class NestedFsyncCrashFilesystem(CrashFilesystem):
    def __init__(self) -> None:
        super().__init__("after-stage-fsync")
        self.fsynced: list[int] = []

    def fsync_tree_at(self, directory_fd: int) -> None:
        self.fsynced.append(os.fstat(directory_fd).st_ino)
        super().fsync_tree_at(directory_fd)


class SwapInsideExchangeFilesystem(LocalFleetHomeV2Filesystem):
    def exchange_at(self, parent_fd: int, source: str, target: str) -> None:
        os.rename(source, f"{source}.bound-old", src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.mkdir(source, 0o700, dir_fd=parent_fd)
        foreign_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd)
        file_fd = -1
        try:
            file_fd = os.open("foreign", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=foreign_fd)
            os.write(file_fd, b"foreign")
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            os.close(foreign_fd)
        super().exchange_at(parent_fd, source, target)


class PostMutationFailureFilesystem(LocalFleetHomeV2Filesystem):
    def rename_noreplace_at(self, parent_fd: int, source: str, target: str) -> None:
        if source.endswith(".stage"):
            raise FleetHomeV2CutoverError("fleet_home_v2_stage_invalid")
        super().rename_noreplace_at(parent_fd, source, target)


class NoExchangeFilesystem(LocalFleetHomeV2Filesystem):
    def exchange_at(self, parent_fd: int, source: str, target: str) -> None:
        raise FleetHomeV2CutoverError("fleet_home_v2_exchange_unavailable")


def _authority(parent: Path, agent_id: str) -> FleetHomeV2Authority:
    prefix = agent_id.rstrip("0123456789")
    policy = FleetHomeV2Policy(schema_version=2, generation=435, digest="a" * 64)
    provider = b"# common policy\n"
    marker = {
        "schema_version": 2,
        "kind": "codex_master_fleet_agent",
        "agent_id": agent_id,
        "prefix": prefix,
        "runner": "gemini_cli",
        "provider": "gemini",
        "model": "gemini-test",
        "common_policy": {"schema_version": 2, "generation": 435, "digest": "a" * 64},
        "managed_files": [".gemini/GEMINI.md"],
        "files": {".gemini/GEMINI.md": hashlib.sha256(provider).hexdigest()},
    }
    return FleetHomeV2Authority(
        agent_id=agent_id,
        prefix=prefix,
        provider="gemini",
        runner="gemini_cli",
        model="gemini-test",
        home=parent / agent_id,
        registry_generation=435,
        policy=policy,
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
        authority_generation=435,
        lease_generation="lease-435",
        process_generation="process-435",
        artifacts=(
            FleetHomeV2Artifact(".gemini/GEMINI.md", provider, 0o600),
            FleetHomeV2Artifact(MARKER_FILE, (json.dumps(marker, sort_keys=True) + "\n").encode(), 0o600),
        ),
    )


def _service(
    authorities: tuple[FleetHomeV2Authority, ...],
    *,
    filesystem: LocalFleetHomeV2Filesystem | None = None,
    quiescence: FleetHomeV2QuiescencePort | None = None,
    entropy: FixedEntropy | None = None,
) -> tuple[FleetHomeV2CutoverService, FleetHomeV2SnapshotAuthorityPort]:
    global _ENTROPY_SEED
    port = FleetHomeV2SnapshotAuthorityPort(
        FleetHomeV2Inventory(435, {authority.agent_id: authority for authority in authorities})
    )
    selected_entropy = entropy
    if selected_entropy is None:
        selected_entropy = FixedEntropy(_ENTROPY_SEED)
        _ENTROPY_SEED += 100
    return (
        FleetHomeV2CutoverService(
            authority_port=port,
            quiescence_port=quiescence or FleetHomeV2QuiescencePort(),
            filesystem=filesystem,
            entropy=selected_entropy,
        ),
        port,
    )


def _v1_home(authority: FleetHomeV2Authority) -> None:
    authority.home.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    authority.home.mkdir(mode=0o700)
    (authority.home / MARKER_FILE).write_bytes(b"opaque V1 marker")
    (authority.home / "legacy").write_text("old\n")


def _single_plan(tmp_path: Path, **service_kwargs: object):
    authority = _authority(tmp_path, "g1")
    _v1_home(authority)
    service, port = _service((authority,), **service_kwargs)
    return authority, service, port, service.plan(("g1",))


def test_plan_internal_operation_id_g1_first_and_full_target_binding(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    h1 = _authority(tmp_path, "h1")
    for authority in (g1, h1):
        _v1_home(authority)
    service, _port = _service((g1, h1))

    plan = service.plan(("h1", "g1"))

    assert len(plan.operation_id) == 48
    assert [target.authority.agent_id for target in plan.targets] == ["g1", "h1"]
    assert plan.targets[0].manifest_digest


def test_apply_exchange_keeps_complete_bound_v1_backup_and_verify_requires_it(tmp_path: Path) -> None:
    authority, service, _port, plan = _single_plan(tmp_path)

    assert service.apply(plan)[0].state == "cutover-complete"
    backup = next(tmp_path.glob("*.backup"))
    assert (backup / "legacy").read_text() == "old\n"
    assert service.verify(plan)[0].state == "cutover-complete"

    backup.rename(tmp_path / "removed-backup")

    assert service.recover(plan)[0].state == "recovery-required"
    assert service.verify(plan)[0].state == "failed-terminal"


def test_rename_window_source_swap_never_completes_or_backs_up_foreign_home(tmp_path: Path) -> None:
    authority, service, _port, plan = _single_plan(
        tmp_path, filesystem=SwapInsideExchangeFilesystem()
    )

    result = service.apply(plan)

    assert result[0].state == "recovery-required"
    assert (authority.home.parent / f"{authority.agent_id}.bound-old" / "legacy").exists()
    assert not list(tmp_path.glob("*.backup/foreign"))


def test_service_has_bound_ports_and_collision_resistant_internal_operation_ids(tmp_path: Path) -> None:
    authority = _authority(tmp_path, "g1")
    _v1_home(authority)
    service, _port = _service((authority,))
    signature = ast.unparse(ast.parse(CORE_PATH.read_text()))

    assert "inventory: Callable" not in signature
    assert "quiescence: Callable" not in signature
    assert "attest_current: Callable" not in signature
    assert service.plan(("g1",)).operation_id != service.plan(("g1",)).operation_id

    repeated, _port = _service((authority,), entropy=RepeatedEntropy())
    repeated.plan(("g1",))
    with pytest.raises(FleetHomeV2CutoverError, match="fleet_home_v2_operation_collision"):
        repeated.plan(("g1",))


@pytest.mark.parametrize("forgery", ("reordered", "duplicate", "target-swap"))
def test_apply_revalidates_directly_constructed_or_tampered_plan(
    tmp_path: Path, forgery: str
) -> None:
    g1 = _authority(tmp_path, "g1")
    h1 = _authority(tmp_path, "h1")
    for authority in (g1, h1):
        _v1_home(authority)
    service, _port = _service((g1, h1))
    plan = service.plan(("g1", "h1"))
    if forgery == "reordered":
        forged = replace(plan, targets=tuple(reversed(plan.targets)))
    elif forgery == "duplicate":
        forged = replace(plan, targets=(plan.targets[0], plan.targets[0]))
    else:
        forged = replace(plan, targets=(replace(plan.targets[0], authority=h1), plan.targets[1]))

    with pytest.raises(FleetHomeV2CutoverError, match="fleet_home_v2_plan_invalid"):
        service.apply(forged)


def test_stage_root_owner_mode_nested_fsync_and_temp_collision_are_attested(tmp_path: Path) -> None:
    filesystem = NestedFsyncCrashFilesystem()
    authority, service, _port, plan = _single_plan(tmp_path, filesystem=filesystem)

    with pytest.raises(Crash, match="after-stage-fsync"):
        service.apply(plan)

    stage = next(tmp_path.glob("*.stage"))
    root_stat = stage.stat()
    nested_stat = (stage / ".gemini").stat()
    assert stat.S_IMODE(root_stat.st_mode) == stat.S_IMODE(nested_stat.st_mode) == 0o700
    assert (root_stat.st_uid, root_stat.st_gid) == (authority.owner_uid, authority.owner_gid)
    assert {root_stat.st_ino, nested_stat.st_ino} <= set(filesystem.fsynced)



def test_deterministic_stale_journal_temp_is_collision_safe_and_unmodified(tmp_path: Path) -> None:
    authority = _authority(tmp_path, "g1")
    _v1_home(authority)
    entropy = FixedEntropy(1_000_000)
    service, _port = _service((authority,), entropy=entropy)
    plan = service.plan(("g1",))
    journal = f".fleet-home-v2-cutover-{plan.operation_id}-g1.journal.json"
    temp = tmp_path / f".{journal}.{entropy.value:032x}.tmp"
    temp.write_bytes(b"stale bound operation temp")

    result = service.apply(plan)[0]

    assert (result.state, result.code) == (
        "failed-terminal", "fleet_home_v2_operation_collision"
    )
    assert temp.read_bytes() == b"stale bound operation temp"
    assert (authority.home / "legacy").read_text() == "old\n"


@pytest.mark.parametrize(
    ("field", "value"),
    (("kind", "foreign"), ("model", "other"), ("prefix", "h"), ("unknown", "x")),
)
def test_marker_requires_exact_canonical_schema_values_and_allowed_fields(
    tmp_path: Path, field: str, value: str
) -> None:
    authority = _authority(tmp_path, "g1")
    marker = json.loads(next(item.data for item in authority.artifacts if item.relative_path == MARKER_FILE))
    marker[field] = value
    authority = replace(
        authority,
        artifacts=tuple(
            replace(item, data=(json.dumps(marker, sort_keys=True) + "\n").encode())
            if item.relative_path == MARKER_FILE
            else item
            for item in authority.artifacts
        ),
    )
    _v1_home(authority)
    service, _port = _service((authority,))

    with pytest.raises(FleetHomeV2CutoverError, match="fleet_home_v2_marker_invalid"):
        service.plan(("g1",))


def test_journal_fsm_rejects_downgrade_replay_and_foreign_binding(tmp_path: Path) -> None:
    authority, service, _port, plan = _single_plan(tmp_path)
    assert service.apply(plan)[0].state == "cutover-complete"
    journal = next(tmp_path.glob("*.journal.json"))
    document = json.loads(journal.read_text())
    document["history"] = []
    document = service._append_journal_state(document, "planned")
    journal.write_text(json.dumps(document, sort_keys=True) + "\n")

    assert service.recover(plan)[0].state == "recovery-required"

    journal.write_text("{}\n")
    result = service.recover(plan)[0]
    assert (result.agent_id, result.state, result.code) == (
        "g1", "recovery-required", "fleet_home_v2_journal_invalid"
    )


def test_corrupt_pre_mutation_journal_is_terminal_and_quiescence_is_bound(tmp_path: Path) -> None:
    authority, service, _port, plan = _single_plan(tmp_path)
    journal = tmp_path / f".fleet-home-v2-cutover-{plan.operation_id}-g1.journal.json"
    journal.write_text("{}\n")

    result = service.apply(plan)[0]
    assert (result.agent_id, result.state, result.code) == (
        "g1", "failed-terminal", "fleet_home_v2_journal_invalid"
    )

    authority, service, _port, plan = _single_plan(
        tmp_path / "wrong-evidence",
        quiescence=FleetHomeV2QuiescencePort(agent_id="h1"),
    )
    result = service.apply(plan)[0]
    assert (result.agent_id, result.state, result.code) == (
        "g1", "failed-retryable", "fleet_home_v2_quiescence_invalid"
    )


def test_unsupported_exchange_fails_closed_without_two_rename_fallback(tmp_path: Path) -> None:
    authority, service, _port, plan = _single_plan(tmp_path, filesystem=NoExchangeFilesystem())

    result = service.apply(plan)[0]
    assert (result.agent_id, result.state, result.code) == (
        "g1", "failed-terminal", "fleet_home_v2_exchange_unavailable"
    )
    assert (authority.home / "legacy").read_text() == "old\n"
    assert not list(tmp_path.glob("*.backup"))


def test_post_mutation_error_has_recovery_required_precedence(tmp_path: Path) -> None:
    _authority_value, service, _port, plan = _single_plan(
        tmp_path, filesystem=PostMutationFailureFilesystem()
    )

    result = service.apply(plan)[0]
    assert (result.agent_id, result.state, result.code) == (
        "g1", "recovery-required", "fleet_home_v2_recovery_required"
    )


@pytest.mark.parametrize(
    ("point", "operation", "expected"),
    (
        ("after-journal-planned", "apply", "failed-retryable"),
        ("after-stage-fsync", "apply", "failed-retryable"),
        ("after-exchange", "apply", "cutover-complete"),
        ("after-stage-to-backup", "apply", "cutover-complete"),
        ("after-v2-verify", "apply", "cutover-complete"),
        ("after-rollback-exchange", "rollback", "rolled-back"),
        ("after-v2-archive", "rollback", "rolled-back"),
    ),
)
def test_crash_recovery_table(tmp_path: Path, point: str, operation: str, expected: str) -> None:
    authority = _authority(tmp_path, "g1")
    _v1_home(authority)
    filesystem = CrashFilesystem(point)
    service, _port = _service((authority,), filesystem=filesystem)
    plan = service.plan(("g1",))
    if operation == "rollback":
        assert service.apply(plan)[0].state == "cutover-complete"
    with pytest.raises(Crash, match=point):
        getattr(service, operation)(plan)

    recovery, _port = _service((authority,), entropy=FixedEntropy(99))
    assert recovery.recover(plan)[0].state == expected
