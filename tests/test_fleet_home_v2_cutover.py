import ast
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from codex_master.fleet_home_v2_cutover import (
    FleetHomeV2Artifact,
    FleetHomeV2Authority,
    FleetHomeV2CutoverError,
    FleetHomeV2CutoverService,
    FleetHomeV2Inventory,
    FleetHomeV2Policy,
    FleetHomeV2Quiescence,
    LocalFleetHomeV2Filesystem,
)


MARKER = ".codex-fleet-agent.json"
CORE_PATH = Path(__file__).resolve().parents[1] / "src/codex_master/fleet_home_v2_cutover.py"


class MutableInventory:
    def __init__(self, snapshot: FleetHomeV2Inventory) -> None:
        self.snapshot = snapshot

    def __call__(self) -> FleetHomeV2Inventory:
        return self.snapshot


class Quiescence:
    def __init__(self) -> None:
        self.evidence = FleetHomeV2Quiescence(
            stopped=True,
            lease_state="none",
            process_scan_available=True,
            managed_processes=0,
            external_processes=0,
        )

    def __call__(self, _authority: FleetHomeV2Authority) -> FleetHomeV2Quiescence:
        return self.evidence


class QuiescenceChangesAfterStage(Quiescence):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def __call__(self, authority: FleetHomeV2Authority) -> FleetHomeV2Quiescence:
        self.calls += 1
        if self.calls == 2:
            self.evidence = replace(self.evidence, lease_state="expired-unreconciled")
        return super().__call__(authority)


def _authority(parent: Path, agent_id: str) -> FleetHomeV2Authority:
    policy = FleetHomeV2Policy(schema_version=2, generation=435, digest="a" * 64)
    provider = b"# common policy\n"
    marker = {
        "schema_version": 2,
        "kind": "codex_master_fleet_agent",
        "agent_id": agent_id,
        "prefix": agent_id.rstrip("0123456789"),
        "runner": "gemini_cli",
        "provider": "gemini",
        "model": "gemini-test",
        "common_policy": {
            "schema_version": 2,
            "generation": 435,
            "digest": "a" * 64,
        },
        "managed_files": [".gemini/GEMINI.md"],
        "files": {".gemini/GEMINI.md": hashlib.sha256(provider).hexdigest()},
    }
    return FleetHomeV2Authority(
        agent_id=agent_id,
        provider="gemini",
        runner="gemini_cli",
        home=parent / agent_id,
        registry_generation=435,
        policy=policy,
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
        artifacts=(
            FleetHomeV2Artifact(".gemini/GEMINI.md", provider, 0o600),
            FleetHomeV2Artifact(
                MARKER,
                (json.dumps(marker, sort_keys=True) + "\n").encode(),
                0o600,
            ),
        ),
    )


def _service(
    inventory: MutableInventory,
    quiescence: Quiescence,
    filesystem: LocalFleetHomeV2Filesystem | None = None,
    attest_current=None,
) -> FleetHomeV2CutoverService:
    return FleetHomeV2CutoverService(
        inventory=inventory,
        filesystem=filesystem or LocalFleetHomeV2Filesystem(),
        quiescence=quiescence,
        attest_current=attest_current or (lambda _authority: False),
    )


class CrashAtCheckpoint(LocalFleetHomeV2Filesystem):
    def __init__(self, point: str) -> None:
        self.point = point

    def checkpoint(self, point: str) -> None:
        if point == self.point:
            raise RuntimeError(f"crash:{point}")


class TamperingFilesystem(LocalFleetHomeV2Filesystem):
    def __init__(self, kind: str) -> None:
        self.kind = kind

    def write_private(self, path: Path, data: bytes, mode: int, uid: int, gid: int) -> None:
        super().write_private(path, data, mode, uid, gid)
        if path.name != MARKER:
            return
        if self.kind == "extra":
            (path.parent / "unexpected").write_text("unexpected\n")
        elif self.kind == "symlink":
            (path.parent / "unexpected-link").symlink_to(path.name)
        elif self.kind == "hardlink":
            os.link(path, path.parent / "unexpected-link")
        elif self.kind == "mode":
            path.chmod(0o644)


class CrossDeviceFilesystem(LocalFleetHomeV2Filesystem):
    def identity(self, path: Path):
        identity = super().identity(path)
        return replace(identity, device=identity.device + 1) if path.name.endswith(".stage") else identity


class WrongOwnerFilesystem(LocalFleetHomeV2Filesystem):
    def identity(self, path: Path):
        identity = super().identity(path)
        if path.name == MARKER and path.parent.name.endswith(".stage"):
            return replace(identity, uid=identity.uid + 1)
        return identity


class TamperStageAfterFsync(LocalFleetHomeV2Filesystem):
    def __init__(self, parent: Path) -> None:
        self.parent = parent

    def checkpoint(self, point: str) -> None:
        if point == "after-stage-fsync":
            stage = next(self.parent.glob(".fleet-home-v2-cutover-*.stage"))
            (stage / MARKER).write_bytes(b"tampered after attestation")


class ForeignJournalAfterStageFsync(LocalFleetHomeV2Filesystem):
    def __init__(self, parent: Path) -> None:
        self.parent = parent

    def checkpoint(self, point: str) -> None:
        if point == "after-stage-fsync":
            journal = next(self.parent.glob(".fleet-home-v2-cutover-*.json"))
            journal.write_text("{}\n")


def test_plan_is_g1_first_bound_to_registry_policy_and_has_no_write(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    h1 = _authority(tmp_path, "h1")
    for authority in (g1, h1):
        authority.home.mkdir(mode=0o700)
        (authority.home / MARKER).write_text('{"schema_version": 1}\n')

    inventory = MutableInventory(
        FleetHomeV2Inventory(generation=435, homes={"g1": g1, "h1": h1})
    )
    service = _service(inventory, Quiescence())

    plan = service.plan(("h1", "g1"), operation_id="cutover-g1-h1-20260829")

    assert [target.authority.agent_id for target in plan.targets] == ["g1", "h1"]
    assert plan.registry_generation == 435
    assert plan.targets[0].authority.policy.generation == 435
    assert plan.targets[0].authority.policy.digest == "a" * 64
    assert (g1.home / MARKER).read_text() == '{"schema_version": 1}\n'


def test_plan_rejects_duplicate_unknown_and_more_than_27_targets(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence())

    with pytest.raises(FleetHomeV2CutoverError, match="fleet_home_v2_inventory_changed"):
        service.plan(("g1", "g1"), operation_id="duplicate-target-20260829")
    with pytest.raises(FleetHomeV2CutoverError, match="fleet_home_v2_inventory_changed"):
        service.plan(("missing",), operation_id="missing-target-20260829")
    with pytest.raises(FleetHomeV2CutoverError, match="fleet_home_v2_batch_limit"):
        service.plan(tuple(f"x{index}" for index in range(28)), operation_id="too-many-20260829")


def test_apply_replaces_whole_opaque_home_and_keeps_complete_backup(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    source_marker = b"\xffopaque marker: never parse me\n"
    (g1.home / MARKER).write_bytes(source_marker)
    (g1.home / "legacy-token").write_text("opaque old data\n")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence())

    result = service.apply(service.plan(("g1",), operation_id="apply-g1-20260829"))

    assert [(item.agent_id, item.state) for item in result] == [("g1", "cutover-complete")]
    assert sorted(
        path.relative_to(g1.home).as_posix()
        for path in g1.home.rglob("*")
        if path.is_file()
    ) == [".codex-fleet-agent.json", ".gemini/GEMINI.md"]
    backup = tmp_path / ".fleet-home-v2-cutover-apply-g1-20260829-g1.backup"
    assert (backup / "legacy-token").read_text() == "opaque old data\n"
    assert (backup / MARKER).read_bytes() == source_marker
    journal = json.loads(
        (
            tmp_path / ".fleet-home-v2-cutover-apply-g1-20260829-g1.json"
        ).read_text()
    )
    assert journal["artifact_manifest_digest"] == hashlib.sha256(
        json.dumps(
            {
                "agent_id": "g1",
                "provider": "gemini",
                "runner": "gemini_cli",
                "owner_uid": os.geteuid(),
                "owner_gid": os.getegid(),
                "policy": {"schema_version": 2, "generation": 435, "digest": "a" * 64},
                "artifacts": [
                    {
                        "path": ".codex-fleet-agent.json",
                        "digest": hashlib.sha256(
                            next(
                                artifact.data
                                for artifact in g1.artifacts
                                if artifact.relative_path == MARKER
                            )
                        ).hexdigest(),
                        "size": next(
                            len(artifact.data)
                            for artifact in g1.artifacts
                            if artifact.relative_path == MARKER
                        ),
                        "mode": 0o600,
                    },
                    {
                        "path": ".gemini/GEMINI.md",
                        "digest": hashlib.sha256(b"# common policy\n").hexdigest(),
                        "size": len(b"# common policy\n"),
                        "mode": 0o600,
                    },
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def test_apply_reports_non_quiescent_home_without_touching_source(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_text('{"schema_version": 1}\n')
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    quiescence = Quiescence()
    service = _service(inventory, quiescence)
    plan = service.plan(("g1",), operation_id="quiescence-g1-20260829")
    quiescence.evidence = replace(quiescence.evidence, lease_state="active")

    result = service.apply(plan)

    assert [(item.state, item.code) for item in result] == [
        ("failed-retryable", "fleet_home_v2_target_not_quiescent")
    ]
    assert (g1.home / MARKER).read_text() == '{"schema_version": 1}\n'


@pytest.mark.parametrize(
    ("evidence", "code"),
    (
        (
            FleetHomeV2Quiescence(False, "none", True, 0, 0),
            "fleet_home_v2_target_not_quiescent",
        ),
        (
            FleetHomeV2Quiescence(True, "expired-unreconciled", True, 0, 0),
            "fleet_home_v2_target_not_quiescent",
        ),
        (
            FleetHomeV2Quiescence(True, "none", False, 0, 0),
            "fleet_home_v2_process_scan_unavailable",
        ),
    ),
)
def test_apply_fails_closed_for_uncertain_quiescence(
    tmp_path: Path, evidence: FleetHomeV2Quiescence, code: str
) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"opaque source")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    quiescence = Quiescence()
    service = _service(inventory, quiescence)
    plan = service.plan(("g1",), operation_id=f"quiescence-{code[-8:]}-20260829")
    quiescence.evidence = evidence

    result = service.apply(plan)

    assert [(item.state, item.code) for item in result] == [("failed-retryable", code)]


def test_apply_rechecks_quiescence_immediately_before_rename(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"opaque source")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    quiescence = QuiescenceChangesAfterStage()
    service = _service(inventory, quiescence)

    result = service.apply(service.plan(("g1",), operation_id="second-check-20260829"))

    assert quiescence.calls == 2
    assert [(item.state, item.code) for item in result] == [
        ("failed-retryable", "fleet_home_v2_target_not_quiescent")
    ]
    assert (g1.home / MARKER).read_bytes() == b"opaque source"


def test_apply_rejects_stage_changed_after_fsync_before_old_home_moves(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    source_marker = b"opaque source"
    (g1.home / MARKER).write_bytes(source_marker)
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence(), TamperStageAfterFsync(tmp_path))

    result = service.apply(service.plan(("g1",), operation_id="stage-recheck-20260829"))

    assert [(item.state, item.code) for item in result] == [
        ("failed-retryable", "fleet_home_v2_artifact_attestation_failed")
    ]
    assert (g1.home / MARKER).read_bytes() == source_marker
    assert not list(tmp_path.glob(".fleet-home-v2-cutover-*.backup"))


def test_apply_refuses_foreign_journal_without_losing_old_home(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    source_marker = b"opaque source"
    (g1.home / MARKER).write_bytes(source_marker)
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence(), ForeignJournalAfterStageFsync(tmp_path))

    result = service.apply(service.plan(("g1",), operation_id="foreign-journal-20260829"))

    assert [(item.state, item.code) for item in result] == [
        ("failed-retryable", "fleet_home_v2_journal_invalid")
    ]
    assert (g1.home / MARKER).read_bytes() == source_marker
    assert not list(tmp_path.glob(".fleet-home-v2-cutover-*.backup"))


def test_crash_after_old_to_backup_leaves_complete_trees_for_recovery(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_text('{"schema_version": 1}\n')
    (g1.home / "legacy").write_text("old\n")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(
        inventory,
        Quiescence(),
        CrashAtCheckpoint("after-old-to-backup"),
    )
    plan = service.plan(("g1",), operation_id="crash-old-rename-20260829")

    with pytest.raises(RuntimeError, match="crash:after-old-to-backup"):
        service.apply(plan)

    backup = tmp_path / ".fleet-home-v2-cutover-crash-old-rename-20260829-g1.backup"
    stage = tmp_path / ".fleet-home-v2-cutover-crash-old-rename-20260829-g1.stage"
    assert not g1.home.exists()
    assert (backup / "legacy").read_text() == "old\n"
    assert (stage / MARKER).exists()

    recovered = _service(inventory, Quiescence()).recover(plan)

    assert [(item.state, item.code) for item in recovered] == [("cutover-complete", None)]
    assert (g1.home / ".gemini/GEMINI.md").read_bytes() == b"# common policy\n"
    assert (backup / "legacy").read_text() == "old\n"


def test_explicit_rollback_restores_complete_old_home(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_text('{"schema_version": 1}\n')
    (g1.home / "legacy").write_text("old\n")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence())
    plan = service.plan(("g1",), operation_id="rollback-g1-20260829")
    assert service.apply(plan)[0].state == "cutover-complete"

    result = service.rollback(plan)

    assert [(item.state, item.code) for item in result] == [("rolled-back", None)]
    assert (g1.home / "legacy").read_text() == "old\n"
    assert (g1.home / MARKER).read_text() == '{"schema_version": 1}\n'
    assert (
        tmp_path
        / ".fleet-home-v2-cutover-rollback-g1-20260829-g1.rollback-v2"
        / MARKER
    ).exists()


def test_verify_accepts_only_complete_bound_v2_home(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_text('{"schema_version": 1}\n')
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence())
    plan = service.plan(("g1",), operation_id="verify-g1-20260829")
    assert service.apply(plan)[0].state == "cutover-complete"

    result = service.verify(plan)

    assert [(item.state, item.code) for item in result] == [("cutover-complete", None)]


def test_verify_rejects_unexpected_empty_directory(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_text('{"schema_version": 1}\n')
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence())
    plan = service.plan(("g1",), operation_id="verify-extra-dir-20260829")
    assert service.apply(plan)[0].state == "cutover-complete"
    (g1.home / ".unexpected").mkdir(mode=0o700)

    result = service.verify(plan)

    assert [(item.state, item.code) for item in result] == [
        ("failed-terminal", "fleet_home_v2_artifact_attestation_failed")
    ]


@pytest.mark.parametrize("kind", ("extra", "symlink", "hardlink", "mode"))
def test_stage_attestation_rejects_unexpected_or_aliased_entries(
    tmp_path: Path, kind: str
) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"not a marker source")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence(), TamperingFilesystem(kind))

    result = service.apply(service.plan(("g1",), operation_id=f"stage-{kind}-20260829"))

    assert [(item.state, item.code) for item in result] == [
        ("failed-retryable", "fleet_home_v2_artifact_attestation_failed")
    ]
    assert (g1.home / MARKER).read_bytes() == b"not a marker source"


def test_stage_attestation_rejects_cross_device_sibling(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"opaque source")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence(), CrossDeviceFilesystem())

    result = service.apply(service.plan(("g1",), operation_id="cross-device-20260829"))

    assert [(item.state, item.code) for item in result] == [
        ("failed-retryable", "fleet_home_v2_stage_invalid")
    ]


def test_plan_rejects_marker_with_wrong_artifact_digest(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    marker_artifact = next(
        artifact for artifact in g1.artifacts if artifact.relative_path == MARKER
    )
    marker = json.loads(marker_artifact.data)
    marker["files"][".gemini/GEMINI.md"] = "0" * 64
    g1 = replace(
        g1,
        artifacts=tuple(
            replace(
                artifact,
                data=(json.dumps(marker, sort_keys=True) + "\n").encode(),
            )
            if artifact.relative_path == MARKER
            else artifact
            for artifact in g1.artifacts
        ),
    )
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"opaque source")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence())

    with pytest.raises(FleetHomeV2CutoverError, match="fleet_home_v2_stage_invalid"):
        service.plan(("g1",), operation_id="bad-marker-digest-20260829")


def test_stage_attestation_rejects_wrong_owner(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"opaque source")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence(), WrongOwnerFilesystem())

    result = service.apply(service.plan(("g1",), operation_id="wrong-owner-20260829"))

    assert [(item.state, item.code) for item in result] == [
        ("failed-retryable", "fleet_home_v2_artifact_attestation_failed")
    ]
    assert (g1.home / MARKER).read_bytes() == b"opaque source"


def test_plan_rejects_artifact_traversal_without_writing(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1 = replace(
        g1,
        artifacts=(*g1.artifacts, FleetHomeV2Artifact("../escape", b"no", 0o600)),
    )
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"opaque source")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence())

    with pytest.raises(FleetHomeV2CutoverError, match="fleet_home_v2_stage_invalid"):
        service.plan(("g1",), operation_id="traversal-20260829")

    assert not (tmp_path / "escape").exists()
    assert not list(tmp_path.glob(".fleet-home-v2-cutover-*"))


def test_apply_fails_closed_on_source_swap_and_generation_drift(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"opaque source")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence())
    plan = service.plan(("g1",), operation_id="source-swap-20260829")
    g1.home.rename(tmp_path / "g1.old")
    g1.home.mkdir(mode=0o700)

    assert [(item.state, item.code) for item in service.apply(plan)] == [
        ("failed-retryable", "fleet_home_v2_source_invalid")
    ]
    inventory.snapshot = replace(inventory.snapshot, generation=436)

    with pytest.raises(FleetHomeV2CutoverError, match="fleet_home_v2_generation_stale"):
        service.apply(plan)


def test_apply_fails_closed_on_parent_swap(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"opaque source")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence())
    plan = service.plan(("g1",), operation_id="parent-swap-20260829")
    replaced_parent = tmp_path.with_name(f"{tmp_path.name}-replaced")
    tmp_path.rename(replaced_parent)
    tmp_path.mkdir(mode=0o700)
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"replacement source")

    result = service.apply(plan)

    assert [(item.state, item.code) for item in result] == [
        ("failed-retryable", "fleet_home_v2_source_invalid")
    ]


def test_already_current_is_verified_no_op(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"current only according to strict injected attester")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence(), attest_current=lambda _authority: True)
    plan = service.plan(("g1",), operation_id="already-current-20260829")

    result = service.apply(plan)

    assert [(item.state, item.code) for item in result] == [
        ("already-current", "fleet_home_v2_already_current")
    ]
    assert not list(tmp_path.glob(".fleet-home-v2-cutover-*"))


def test_already_current_is_rechecked_before_apply(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"stale after planning")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    attestations = iter((True, False))
    service = _service(
        inventory,
        Quiescence(),
        attest_current=lambda _authority: next(attestations),
    )
    plan = service.plan(("g1",), operation_id="already-current-recheck-20260829")

    result = service.apply(plan)

    assert [(item.state, item.code) for item in result] == [
        ("failed-retryable", "fleet_home_v2_source_invalid")
    ]
    assert not list(tmp_path.glob(".fleet-home-v2-cutover-*"))


def test_existing_operation_journal_fails_closed_as_a_collision(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"opaque source")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence())
    operation_id = "concurrent-operation-20260829"
    plan = service.plan(("g1",), operation_id=operation_id)
    (tmp_path / f".fleet-home-v2-cutover-{operation_id}-g1.json").write_text("foreign\n")

    result = service.apply(plan)

    assert [(item.state, item.code) for item in result] == [
        ("failed-retryable", "fleet_home_v2_cutover_collision")
    ]


def test_core_neither_routes_series_nor_compares_marker_schema_to_one() -> None:
    tree = ast.parse(CORE_PATH.read_text())
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    schema_v1_comparisons = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Compare)
        and "schema_version" in ast.unparse(node.left)
        and any(isinstance(value, ast.Constant) and value.value == 1 for value in node.comparators)
    ]

    assert "fleet_series_apply" not in ast.unparse(tree)
    assert not any("fleet_inplace" in name or "fleet_series" in name for name in imports)
    assert schema_v1_comparisons == []


def test_recovery_finishes_v2_after_second_rename_crash(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"\xffopaque source marker")
    (g1.home / "legacy").write_text("old\n")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    plan = _service(
        inventory,
        Quiescence(),
        CrashAtCheckpoint("after-stage-to-home"),
    ).plan(("g1",), operation_id="crash-second-rename-20260829")
    crashing = _service(
        inventory,
        Quiescence(),
        CrashAtCheckpoint("after-stage-to-home"),
    )

    with pytest.raises(RuntimeError, match="crash:after-stage-to-home"):
        crashing.apply(plan)

    recovered = _service(inventory, Quiescence()).recover(plan)

    assert [(item.state, item.code) for item in recovered] == [("cutover-complete", None)]
    assert (g1.home / ".gemini/GEMINI.md").read_bytes() == b"# common policy\n"
    assert (tmp_path / ".fleet-home-v2-cutover-crash-second-rename-20260829-g1.backup" / "legacy").read_text() == "old\n"


def test_recovery_keeps_complete_source_retryable_before_first_rename(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    source_marker = b"\xffopaque source marker"
    (g1.home / MARKER).write_bytes(source_marker)
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    crashing = _service(
        inventory,
        Quiescence(),
        CrashAtCheckpoint("after-stage-fsync"),
    )
    plan = crashing.plan(("g1",), operation_id="crash-before-first-rename-20260829")

    with pytest.raises(RuntimeError, match="crash:after-stage-fsync"):
        crashing.apply(plan)

    result = _service(inventory, Quiescence()).recover(plan)

    assert [(item.state, item.code) for item in result] == [
        ("failed-retryable", "fleet_home_v2_cutover_failed")
    ]
    assert (g1.home / MARKER).read_bytes() == source_marker


def test_recovery_completes_interrupted_rollback(tmp_path: Path) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"opaque source marker")
    (g1.home / "legacy").write_text("old\n")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    crashing = _service(
        inventory,
        Quiescence(),
        CrashAtCheckpoint("after-rollback-v2-archive"),
    )
    plan = crashing.plan(("g1",), operation_id="rollback-crash-20260829")
    assert crashing.apply(plan)[0].state == "cutover-complete"

    with pytest.raises(RuntimeError, match="crash:after-rollback-v2-archive"):
        crashing.rollback(plan)

    recovered = _service(inventory, Quiescence()).recover(plan)

    assert [(item.state, item.code) for item in recovered] == [("rolled-back", None)]
    assert (g1.home / "legacy").read_text() == "old\n"


@pytest.mark.parametrize("foreign", (False, True))
def test_corrupt_or_foreign_journal_requires_visible_recovery(
    tmp_path: Path, foreign: bool
) -> None:
    g1 = _authority(tmp_path, "g1")
    g1.home.mkdir(mode=0o700)
    (g1.home / MARKER).write_bytes(b"opaque source marker")
    inventory = MutableInventory(FleetHomeV2Inventory(generation=435, homes={"g1": g1}))
    service = _service(inventory, Quiescence())
    plan = service.plan(("g1",), operation_id=f"journal-{'foreign' if foreign else 'corrupt'}-20260829")
    assert service.apply(plan)[0].state == "cutover-complete"
    journal = next(tmp_path.glob(".fleet-home-v2-cutover-*.json"))
    if foreign:
        document = json.loads(journal.read_text())
        document["agent_id"] = "h1"
        journal.write_text(json.dumps(document, sort_keys=True) + "\n")
    else:
        journal.write_text("{}\n")

    result = service.recover(plan)

    assert [(item.state, item.code) for item in result] == [
        ("recovery-required", "fleet_home_v2_journal_invalid")
    ]
