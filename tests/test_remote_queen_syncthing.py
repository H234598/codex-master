import ast
import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from codex_master.remote_queen_bootstrap import ManifestGenerationV1
from codex_master.remote_queen_syncthing import (
    ALLOWED_GUI_LISTEN_ADDRESSES,
    ANNOTATION_SIDECAR_PATTERN,
    VAULT_EXCLUDED_PATHS,
    VAULT_FOLDER_ID,
    VAULT_FOLDER_LABEL,
    VAULT_RELATIVE_PATH,
    VAULT_REQUIRED_PATHS,
    RemoteQueenSyncthingOperations,
    RemoteQueenSyncthingVaultManifestV1,
    RemoteQueenSyncthingVaultPlanV1,
    SingleWriterGrantV1,
    SyncthingFolderFactV1,
    SyncthingFolderModeV1,
    SyncthingFolderStateKindV1,
    SyncthingGuiFactV1,
    SyncthingVaultActionV1,
    SyncthingVaultApplyJournalV1,
    SyncthingVaultApplyRequestV1,
    SyncthingVaultApplyResultV1,
    SyncthingVaultRollbackRequestV1,
    SyncthingVaultRollbackResultV1,
    SyncthingVaultSnapshotV1,
    SyncthingVaultVerifyRequestV1,
    SyncthingVaultVerifyResultV1,
    VaultWriteScopeV1,
    VaultWriterIdV1,
    apply_remote_queen_syncthing_vault,
    build_remote_queen_syncthing_vault_manifest,
    plan_remote_queen_syncthing_vault,
    rollback_remote_queen_syncthing_vault,
    syncthing_vault_manifest_as_dict,
    syncthing_vault_plan_as_dict,
    verify_remote_queen_syncthing_vault,
)
from codex_master.remote_queen_bootstrap import RemoteQueenBootstrapError


DESIRED_GENERATION = ManifestGenerationV1(
    generation="rq-syncthing-vault-2026-08-29",
    sha256="a" * 64,
)
DEVICE_BINDING_GENERATION = ManifestGenerationV1(
    generation="syncthing-authority-2026-08-29",
    sha256="b" * 64,
)
EXPECTED_PLAN_DIGEST = "sha256:" + "c" * 64
REMOTE_HOME = "/home/queen"


def build_manifest(**overrides):
    values = {
        "desired_generation": DESIRED_GENERATION,
        "device_binding_generation": DEVICE_BINDING_GENERATION,
        "expected_plan_digest": EXPECTED_PLAN_DIGEST,
        "remote_home": REMOTE_HOME,
    }
    values.update(overrides)
    return build_remote_queen_syncthing_vault_manifest(**values)


def absent_snapshot(
    *, enabled=True, listen_address="127.0.0.1:8384"
) -> SyncthingVaultSnapshotV1:
    return SyncthingVaultSnapshotV1(
        gui=SyncthingGuiFactV1(
            enabled=enabled,
            listen_address=listen_address,
        ),
        folder=SyncthingFolderFactV1(
            state=SyncthingFolderStateKindV1.ABSENT,
            generation=None,
            config_manifest_digest=None,
            device_binding_sha256=None,
            sync_complete=False,
            unresolved_conflicts=0,
            annotation_sidecars_visible=False,
            observed_plan_digest=None,
        ),
    )


def owned_snapshot(
    manifest: RemoteQueenSyncthingVaultManifestV1,
    *,
    generation=None,
    config_manifest_digest=None,
    device_binding_sha256=None,
    sync_complete=True,
    unresolved_conflicts=0,
    annotation_sidecars_visible=True,
    observed_plan_digest=None,
    enabled=True,
    listen_address="127.0.0.1:8384",
) -> SyncthingVaultSnapshotV1:
    return SyncthingVaultSnapshotV1(
        gui=SyncthingGuiFactV1(
            enabled=enabled,
            listen_address=listen_address,
        ),
        folder=SyncthingFolderFactV1(
            state=SyncthingFolderStateKindV1.OWNED,
            generation=(
                manifest.desired_generation.generation
                if generation is None
                else generation
            ),
            config_manifest_digest=(
                manifest.manifest_digest
                if config_manifest_digest is None
                else config_manifest_digest
            ),
            device_binding_sha256=(
                manifest.device_binding_generation.sha256
                if device_binding_sha256 is None
                else device_binding_sha256
            ),
            sync_complete=sync_complete,
            unresolved_conflicts=unresolved_conflicts,
            annotation_sidecars_visible=annotation_sidecars_visible,
            observed_plan_digest=(
                manifest.expected_plan_digest
                if observed_plan_digest is None
                else observed_plan_digest
            ),
        ),
    )


def snapshot_as_dict(snapshot):
    return {
        "gui": {
            "enabled": snapshot.gui.enabled,
            "listen_address": snapshot.gui.listen_address,
        },
        "folder": {
            "state": snapshot.folder.state.value,
            "generation": snapshot.folder.generation,
            "config_manifest_digest": snapshot.folder.config_manifest_digest,
            "device_binding_sha256": snapshot.folder.device_binding_sha256,
            "sync_complete": snapshot.folder.sync_complete,
            "unresolved_conflicts": snapshot.folder.unresolved_conflicts,
            "annotation_sidecars_visible": snapshot.folder.annotation_sidecars_visible,
            "observed_plan_digest": snapshot.folder.observed_plan_digest,
        },
    }


def snapshot_digest(snapshot):
    canonical = json.dumps(
        snapshot_as_dict(snapshot), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def synthetic_plan(manifest, before, *, before_digest, action):
    payload = {
        "schema_version": "RemoteQueenSyncthingVaultPlanV1",
        "manifest": syncthing_vault_manifest_as_dict(manifest),
        "before": snapshot_as_dict(before),
        "before_digest": before_digest,
        "action": action.value if action is not None else None,
        "rollback": {
            "remove_own_configuration": True,
            "preserve_vault_data": True,
        },
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return RemoteQueenSyncthingVaultPlanV1(
        schema_version="RemoteQueenSyncthingVaultPlanV1",
        manifest=manifest,
        before=before,
        before_digest=before_digest,
        action=action,
        remove_own_configuration_on_rollback=True,
        preserve_vault_data_on_rollback=True,
        plan_digest="sha256:" + hashlib.sha256(canonical).hexdigest(),
    )


class MemoryOperations:
    def __init__(self, snapshot, *, post_snapshot=None):
        self.snapshot = snapshot
        self.post_snapshot = post_snapshot
        self.calls = []

    def inspect(self, manifest):
        self.calls.append("inspect")
        return self.snapshot

    def apply_configuration(self, plan):
        self.calls.append("apply_configuration")
        prior = self.snapshot
        resulting = self.post_snapshot or owned_snapshot(plan.manifest)
        self.snapshot = resulting
        return SyncthingVaultApplyJournalV1(
            schema_version="SyncthingVaultApplyJournalV1",
            generation=plan.manifest.desired_generation.generation,
            manifest_digest=plan.manifest.manifest_digest,
            plan_digest=plan.plan_digest,
            prior=prior,
            resulting_snapshot_digest=snapshot_digest(resulting),
            preserve_vault_data=True,
        )

    def rollback_configuration(
        self, plan, journal, *, preserve_vault_data
    ):
        self.calls.append(("rollback_configuration", preserve_vault_data))
        if not preserve_vault_data:
            raise AssertionError("rollback must preserve vault data")
        self.snapshot = journal.prior


class RaisingOperations:
    def __init__(self, error_text):
        self.error_text = error_text
        self.calls = []

    def inspect(self, manifest):
        self.calls.append("inspect")
        raise ValueError(self.error_text)

    def apply_configuration(self, plan):
        self.calls.append("apply_configuration")
        raise ValueError(self.error_text)

    def rollback_configuration(
        self, plan, journal, *, preserve_vault_data
    ):
        self.calls.append("rollback_configuration")
        raise ValueError(self.error_text)


def assert_code(callable_object, expected_code):
    with pytest.raises(RemoteQueenBootstrapError) as error:
        callable_object()
    assert error.value.code == expected_code
    assert str(error.value) == expected_code


def test_manifest_constants_are_closed_and_sidecar_is_explicit():
    assert VAULT_FOLDER_ID == "teladi-programming"
    assert VAULT_FOLDER_LABEL == "Teladi_Programming"
    assert VAULT_RELATIVE_PATH == "Dokumente/Obsidian_Vaults/Teladi_Programming"
    assert ANNOTATION_SIDECAR_PATTERN == (
        ".obsidian/plugins/annotation-marker/annotations/**"
    )
    assert VAULT_REQUIRED_PATHS == (ANNOTATION_SIDECAR_PATTERN,)
    assert VAULT_EXCLUDED_PATHS == (
        "**/.env",
        "**/.env.*",
        "**/.git/**",
        "**/*.key",
        "**/*.pem",
        "**/*credentials*.json",
        "**/auth.json",
        "**/.cache/**",
        "**/__pycache__/**",
        "**/.pytest_cache/**",
        "**/.mypy_cache/**",
        "**/.ruff_cache/**",
        "**/node_modules/**",
        ".obsidian/cache/**",
        ".obsidian/plugins/*/cache/**",
        ".obsidian/workspace*.json",
    )
    assert ALLOWED_GUI_LISTEN_ADDRESSES == (
        "127.0.0.1:8384",
        "[::1]:8384",
    )
    assert ".obsidian/**" not in VAULT_EXCLUDED_PATHS
    assert ".obsidian/plugins/**" not in VAULT_EXCLUDED_PATHS


def test_sidecar_pattern_is_not_shadowed_by_any_exclude():
    sidecar_prefix = ANNOTATION_SIDECAR_PATTERN.removesuffix("**")
    assert all(
        not excluded.startswith(sidecar_prefix)
        for excluded in VAULT_EXCLUDED_PATHS
    )


def test_manifest_has_exact_writer_grants_and_closed_policy():
    manifest = build_manifest()
    assert manifest.writer_grants == (
        SingleWriterGrantV1(
            writer_id=VaultWriterIdV1.G18_TOPIC_QUEEN,
            scopes=(VaultWriteScopeV1.G18_PLAN, VaultWriteScopeV1.G18_ARTIFACTS),
        ),
        SingleWriterGrantV1(
            writer_id=VaultWriterIdV1.INTEGRATION_QUEEN,
            scopes=(VaultWriteScopeV1.MASTER_PLAN, VaultWriteScopeV1.REMOTE_BOOTSTRAP_PLAN),
        ),
    )
    assert manifest.versioning_enabled is True
    assert manifest.conflict_retention_enabled is True
    assert manifest.delete_unknown_generation is False
    assert manifest.gui_policy == "disabled-or-loopback-only"
    assert manifest.allowed_gui_listen_addresses == ALLOWED_GUI_LISTEN_ADDRESSES


def test_writer_scopes_are_unique_and_disjoint():
    manifest = build_manifest()
    writers = [grant.writer_id for grant in manifest.writer_grants]
    scopes = [scope for grant in manifest.writer_grants for scope in grant.scopes]
    assert len(writers) == len(set(writers))
    assert len(scopes) == len(set(scopes))
    assert set(scopes) == set(VaultWriteScopeV1)


@pytest.mark.parametrize(
    "remote_home",
    [
        "",
        "queen",
        "/",
        "~/.config",
        "/home//queen",
        "/home/./queen",
        "/home/../queen",
        "/home/queen/",
        "/home/queen\n",
        "/home/queen\x00",
        "/home/queen\\vault",
    ],
)
def test_manifest_rejects_noncanonical_remote_home(remote_home):
    assert_code(
        lambda: build_manifest(remote_home=remote_home),
        "RQ_E_PLAN_INCONSISTENT",
    )


def test_manifest_derives_exact_remote_folder_path_and_authority_digests():
    manifest = build_manifest()
    assert manifest.folder_path == (
        "/home/queen/Dokumente/Obsidian_Vaults/Teladi_Programming"
    )
    assert manifest.expected_plan_digest == EXPECTED_PLAN_DIGEST
    assert manifest.device_binding_generation.sha256 == "b" * 64
    assert manifest.manifest_digest == (
        "sha256:8b40effdad85179b02688a99742eaf9ed7e24cba67afeca424e86f4fc1bee5e7"
    )


def test_manifest_dict_is_complete_literal_and_json_primitive_only():
    manifest = build_manifest()
    assert syncthing_vault_manifest_as_dict(manifest) == {
        "schema_version": "RemoteQueenSyncthingVaultManifestV1",
        "desired_generation": {
            "generation": "rq-syncthing-vault-2026-08-29",
            "sha256": "a" * 64,
        },
        "device_binding_generation": {
            "generation": "syncthing-authority-2026-08-29",
            "sha256": "b" * 64,
        },
        "expected_plan_digest": EXPECTED_PLAN_DIGEST,
        "folder_id": "teladi-programming",
        "folder_label": "Teladi_Programming",
        "folder_path": "/home/queen/Dokumente/Obsidian_Vaults/Teladi_Programming",
        "folder_mode": "sendreceive",
        "required_paths": [
            ".obsidian/plugins/annotation-marker/annotations/**",
        ],
        "excluded_paths": list(VAULT_EXCLUDED_PATHS),
        "writer_grants": [
            {
                "writer_id": "g18-topic-queen",
                "scopes": ["g18-plan", "g18-artifacts"],
            },
            {
                "writer_id": "codex-master-integration-queen",
                "scopes": ["master-plan", "remote-bootstrap-plan"],
            },
        ],
        "versioning_enabled": True,
        "conflict_retention_enabled": True,
        "delete_unknown_generation": False,
        "gui_policy": "disabled-or-loopback-only",
        "allowed_gui_listen_addresses": [
            "127.0.0.1:8384",
            "[::1]:8384",
        ],
        "manifest_digest": (
            "sha256:8b40effdad85179b02688a99742eaf9ed7e24cba67afeca424e86f4fc1bee5e7"
        ),
    }


def test_manifest_rejects_malformed_digest_generation_and_tuple_inputs():
    assert_code(
        lambda: build_manifest(expected_plan_digest="c" * 64),
        "RQ_E_PLAN_INCONSISTENT",
    )
    assert_code(
        lambda: SingleWriterGrantV1(
            writer_id=VaultWriterIdV1.G18_TOPIC_QUEEN,
            scopes=[VaultWriteScopeV1.G18_PLAN],
        ),
        "RQ_E_PLAN_INCONSISTENT",
    )
    assert_code(
        lambda: SyncthingGuiFactV1(enabled=1, listen_address=None),
        "RQ_E_PLAN_INCONSISTENT",
    )
    assert_code(
        lambda: SyncthingFolderFactV1(
            state=SyncthingFolderStateKindV1.ABSENT,
            generation=None,
            config_manifest_digest=None,
            device_binding_sha256=None,
            sync_complete=False,
            unresolved_conflicts=True,
            annotation_sidecars_visible=False,
            observed_plan_digest=None,
        ),
        "RQ_E_PLAN_INCONSISTENT",
    )


def test_plan_absent_creates_configuration_and_fixed_before_digest():
    manifest = build_manifest()
    operations = MemoryOperations(absent_snapshot())
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    assert plan.action is SyncthingVaultActionV1.CREATE_CONFIGURATION
    assert plan.before == absent_snapshot()
    assert plan.before_digest == (
        "sha256:286e4bf50abb990957c79f939d055b58937f60c92fd14e9e16fec8e2f99725d3"
    )
    assert plan.remove_own_configuration_on_rollback is True
    assert plan.preserve_vault_data_on_rollback is True
    assert plan.plan_digest == (
        "sha256:a6c6cdedffc86e31e6807a71bc9e457d8f6257eed36bc54696eaea3b1e3763c9"
    )
    assert operations.calls == ["inspect"]


def test_plan_dict_is_complete_literal():
    manifest = build_manifest()
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=MemoryOperations(absent_snapshot())
    )
    assert syncthing_vault_plan_as_dict(plan) == {
        "schema_version": "RemoteQueenSyncthingVaultPlanV1",
        "manifest": syncthing_vault_manifest_as_dict(manifest),
        "before": {
            "gui": {
                "enabled": True,
                "listen_address": "127.0.0.1:8384",
            },
            "folder": {
                "state": "absent",
                "generation": None,
                "config_manifest_digest": None,
                "device_binding_sha256": None,
                "sync_complete": False,
                "unresolved_conflicts": 0,
                "annotation_sidecars_visible": False,
                "observed_plan_digest": None,
            },
        },
        "before_digest": (
            "sha256:286e4bf50abb990957c79f939d055b58937f60c92fd14e9e16fec8e2f99725d3"
        ),
        "action": "create-folder-configuration",
        "rollback": {
            "remove_own_configuration": True,
            "preserve_vault_data": True,
        },
        "plan_digest": (
            "sha256:a6c6cdedffc86e31e6807a71bc9e457d8f6257eed36bc54696eaea3b1e3763c9"
        ),
    }


def test_plan_exact_owned_state_is_noop():
    manifest = build_manifest()
    operations = MemoryOperations(owned_snapshot(manifest))
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    assert plan.action is None
    assert operations.calls == ["inspect"]


def test_plan_owned_older_generation_replaces_without_delete_action():
    manifest = build_manifest()
    old_generation = "rq-syncthing-vault-2026-08-28"
    operations = MemoryOperations(
        owned_snapshot(
            manifest,
            generation=old_generation,
            config_manifest_digest="sha256:" + "d" * 64,
            device_binding_sha256="d" * 64,
        )
    )
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    assert plan.action is SyncthingVaultActionV1.REPLACE_OWNED_CONFIGURATION
    assert "delete" not in plan.action.value


def test_plan_rejects_wrong_before_digest_without_operations():
    manifest = build_manifest()
    before = absent_snapshot()
    operations = MemoryOperations(before)
    assert_code(
        lambda: synthetic_plan(
            manifest,
            before,
            before_digest="sha256:" + "d" * 64,
            action=SyncthingVaultActionV1.CREATE_CONFIGURATION,
        ),
        "RQ_E_PLAN_INCONSISTENT",
    )
    assert operations.calls == []


def test_plan_rejects_semantically_wrong_action_without_operations():
    manifest = build_manifest()
    before = absent_snapshot()
    operations = MemoryOperations(before)
    assert_code(
        lambda: synthetic_plan(
            manifest,
            before,
            before_digest=snapshot_digest(before),
            action=SyncthingVaultActionV1.REPLACE_OWNED_CONFIGURATION,
        ),
        "RQ_E_PLAN_INCONSISTENT",
    )
    assert operations.calls == []


def test_plan_foreign_folder_blocks_before_configuration_call():
    manifest = build_manifest()
    foreign = dataclasses.replace(
        owned_snapshot(manifest),
        folder=dataclasses.replace(
            owned_snapshot(manifest).folder,
            state=SyncthingFolderStateKindV1.FOREIGN,
        ),
    )
    operations = MemoryOperations(foreign)
    assert_code(
        lambda: plan_remote_queen_syncthing_vault(
            manifest=manifest, operations=operations
        ),
        "RQ_E_FOREIGN_STATE",
    )
    assert operations.calls == ["inspect"]


@pytest.mark.parametrize(
    "gui",
    [
        SyncthingGuiFactV1(enabled=True, listen_address="0.0.0.0:8384"),
        SyncthingGuiFactV1(enabled=True, listen_address="10.0.0.8:8384"),
        SyncthingGuiFactV1(enabled=True, listen_address="localhost:8384"),
        SyncthingGuiFactV1(enabled=True, listen_address=None),
        SyncthingGuiFactV1(enabled=False, listen_address="127.0.0.1:8384"),
    ],
)
def test_plan_unsafe_gui_blocks_before_configuration_call(gui):
    manifest = build_manifest()
    snapshot = dataclasses.replace(absent_snapshot(), gui=gui)
    operations = MemoryOperations(snapshot)
    assert_code(
        lambda: plan_remote_queen_syncthing_vault(
            manifest=manifest, operations=operations
        ),
        "RQ_E_FOREIGN_STATE",
    )
    assert operations.calls == ["inspect"]


def test_disabled_gui_and_ipv6_loopback_are_safe_policy_states():
    manifest = build_manifest()
    disabled = MemoryOperations(absent_snapshot(enabled=False, listen_address=None))
    assert (
        plan_remote_queen_syncthing_vault(
            manifest=manifest, operations=disabled
        ).action
        is SyncthingVaultActionV1.CREATE_CONFIGURATION
    )
    ipv6 = MemoryOperations(
        dataclasses.replace(
            absent_snapshot(),
            gui=SyncthingGuiFactV1(enabled=True, listen_address="[::1]:8384"),
        )
    )
    assert (
        plan_remote_queen_syncthing_vault(
            manifest=manifest, operations=ipv6
        ).action
        is SyncthingVaultActionV1.CREATE_CONFIGURATION
    )


def test_plan_conflicts_block():
    manifest = build_manifest()
    operations = MemoryOperations(
        owned_snapshot(manifest, unresolved_conflicts=1)
    )
    assert_code(
        lambda: plan_remote_queen_syncthing_vault(
            manifest=manifest, operations=operations
        ),
        "RQ_E_VAULT_CONFLICT",
    )


def test_plan_digest_drift_blocks():
    manifest = build_manifest()
    operations = MemoryOperations(
        owned_snapshot(manifest, observed_plan_digest="sha256:" + "d" * 64)
    )
    assert_code(
        lambda: plan_remote_queen_syncthing_vault(
            manifest=manifest, operations=operations
        ),
        "RQ_E_VAULT_CONFLICT",
    )


def test_plan_stale_annotation_sidecars_block():
    manifest = build_manifest()
    operations = MemoryOperations(
        owned_snapshot(manifest, annotation_sidecars_visible=False)
    )
    assert_code(
        lambda: plan_remote_queen_syncthing_vault(
            manifest=manifest, operations=operations
        ),
        "RQ_E_ANNOTATION_STALE",
    )


def test_absence_with_non_null_generation_is_inconsistent():
    assert_code(
        lambda: SyncthingFolderFactV1(
            state=SyncthingFolderStateKindV1.ABSENT,
            generation="unexpected",
            config_manifest_digest=None,
            device_binding_sha256=None,
            sync_complete=False,
            unresolved_conflicts=0,
            annotation_sidecars_visible=False,
            observed_plan_digest=None,
        ),
        "RQ_E_PLAN_INCONSISTENT",
    )


def test_plan_operations_exception_is_redacted():
    manifest = build_manifest()
    sentinel = "secret-rb5-do-not-retain"
    operations = RaisingOperations(sentinel)
    with pytest.raises(RemoteQueenBootstrapError) as error:
        plan_remote_queen_syncthing_vault(
            manifest=manifest, operations=operations
        )
    assert error.value.code == "RQ_E_VAULT_CONFLICT"
    assert str(error.value) == "RQ_E_VAULT_CONFLICT"
    assert sentinel not in str(error.value)


def test_apply_request_drift_happens_before_apply_call():
    manifest = build_manifest()
    operations = MemoryOperations(absent_snapshot())
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    operations.calls.clear()
    request = SyncthingVaultApplyRequestV1(
        generation=plan.manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest="sha256:" + "d" * 64,
    )
    assert_code(
        lambda: apply_remote_queen_syncthing_vault(
            plan=plan, request=request, operations=operations
        ),
        "RQ_E_VAULT_CONFLICT",
    )
    assert operations.calls == []


def test_apply_noop_inspects_once_without_configuration_call():
    manifest = build_manifest()
    operations = MemoryOperations(owned_snapshot(manifest))
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    operations.calls.clear()
    request = SyncthingVaultApplyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )
    result = apply_remote_queen_syncthing_vault(
        plan=plan, request=request, operations=operations
    )
    assert result == SyncthingVaultApplyResultV1(
        changed=False,
        journal=None,
        snapshot_digest=snapshot_digest(operations.snapshot),
    )
    assert operations.calls == ["inspect"]


def test_apply_success_has_exact_call_order_journal_and_attestation():
    manifest = build_manifest()
    operations = MemoryOperations(absent_snapshot())
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    operations.calls.clear()
    request = SyncthingVaultApplyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )
    result = apply_remote_queen_syncthing_vault(
        plan=plan, request=request, operations=operations
    )
    assert operations.calls == ["inspect", "apply_configuration", "inspect"]
    assert result.changed is True
    assert result.journal is not None
    assert result.journal.generation == manifest.desired_generation.generation
    assert result.journal.manifest_digest == manifest.manifest_digest
    assert result.journal.plan_digest == plan.plan_digest
    assert result.journal.prior == plan.before
    assert result.journal.resulting_snapshot_digest == result.snapshot_digest
    assert result.journal.preserve_vault_data is True
    assert result.snapshot_digest == snapshot_digest(operations.snapshot)


def test_plan_after_apply_is_idempotent_noop():
    manifest = build_manifest()
    operations = MemoryOperations(absent_snapshot())
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    request = SyncthingVaultApplyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )
    apply_remote_queen_syncthing_vault(
        plan=plan, request=request, operations=operations
    )
    operations.calls.clear()
    second_plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    assert second_plan.action is None
    assert operations.calls == ["inspect"]


def test_verify_is_exactly_one_read_only_inspect():
    manifest = build_manifest()
    operations = MemoryOperations(owned_snapshot(manifest))
    request = SyncthingVaultVerifyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        expected_plan_digest=manifest.expected_plan_digest,
    )
    result = verify_remote_queen_syncthing_vault(
        manifest=manifest, request=request, operations=operations
    )
    assert result == SyncthingVaultVerifyResultV1(
        snapshot_digest=snapshot_digest(operations.snapshot)
    )
    assert operations.calls == ["inspect"]


def test_verify_request_drift_has_no_operation_call():
    manifest = build_manifest()
    operations = MemoryOperations(owned_snapshot(manifest))
    request = SyncthingVaultVerifyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        expected_plan_digest="sha256:" + "d" * 64,
    )
    assert_code(
        lambda: verify_remote_queen_syncthing_vault(
            manifest=manifest, request=request, operations=operations
        ),
        "RQ_E_VAULT_CONFLICT",
    )
    assert operations.calls == []


@pytest.mark.parametrize(
    "mutator, expected_code",
    [
        (
            lambda snapshot: dataclasses.replace(
                snapshot,
                gui=SyncthingGuiFactV1(
                    enabled=True, listen_address="0.0.0.0:8384"
                ),
            ),
            "RQ_E_FOREIGN_STATE",
        ),
        (
            lambda snapshot: dataclasses.replace(
                snapshot,
                folder=dataclasses.replace(
                    snapshot.folder, sync_complete=False
                ),
            ),
            "RQ_E_VAULT_CONFLICT",
        ),
        (
            lambda snapshot: dataclasses.replace(
                snapshot,
                folder=dataclasses.replace(
                    snapshot.folder, unresolved_conflicts=1
                ),
            ),
            "RQ_E_VAULT_CONFLICT",
        ),
        (
            lambda snapshot: dataclasses.replace(
                snapshot,
                folder=dataclasses.replace(
                    snapshot.folder, annotation_sidecars_visible=False
                ),
            ),
            "RQ_E_ANNOTATION_STALE",
        ),
        (
            lambda snapshot: dataclasses.replace(
                snapshot,
                folder=dataclasses.replace(
                    snapshot.folder,
                    observed_plan_digest="sha256:" + "d" * 64,
                ),
            ),
            "RQ_E_VAULT_CONFLICT",
        ),
        (
            lambda snapshot: dataclasses.replace(
                snapshot,
                folder=dataclasses.replace(
                    snapshot.folder, device_binding_sha256="d" * 64
                ),
            ),
            "RQ_E_VAULT_CONFLICT",
        ),
        (
            lambda snapshot: dataclasses.replace(
                snapshot,
                folder=dataclasses.replace(
                    snapshot.folder,
                    config_manifest_digest="sha256:" + "d" * 64,
                ),
            ),
            "RQ_E_VAULT_CONFLICT",
        ),
    ],
)
def test_verify_every_attestation_deviation_blocks(mutator, expected_code):
    manifest = build_manifest()
    operations = MemoryOperations(mutator(owned_snapshot(manifest)))
    request = SyncthingVaultVerifyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        expected_plan_digest=manifest.expected_plan_digest,
    )
    assert_code(
        lambda: verify_remote_queen_syncthing_vault(
            manifest=manifest, request=request, operations=operations
        ),
        expected_code,
    )
    assert operations.calls == ["inspect"]


def test_rollback_restores_exact_prior_snapshot_and_preserves_vault_data():
    manifest = build_manifest()
    operations = MemoryOperations(absent_snapshot())
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    apply_request = SyncthingVaultApplyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )
    applied = apply_remote_queen_syncthing_vault(
        plan=plan, request=apply_request, operations=operations
    )
    operations.calls.clear()
    rollback_request = SyncthingVaultRollbackRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )
    result = rollback_remote_queen_syncthing_vault(
        plan=plan,
        journal=applied.journal,
        request=rollback_request,
        operations=operations,
    )
    assert result == SyncthingVaultRollbackResultV1(
        restored_snapshot_digest=plan.before_digest,
        vault_data_preserved=True,
    )
    assert operations.calls == [
        "inspect",
        ("rollback_configuration", True),
        "inspect",
    ]
    assert operations.snapshot == plan.before


def test_rollback_rejects_synthetic_noop_journal_without_operations():
    manifest = build_manifest()
    current = owned_snapshot(manifest)
    operations = MemoryOperations(current)
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    assert plan.action is None
    journal = SyncthingVaultApplyJournalV1(
        schema_version="SyncthingVaultApplyJournalV1",
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
        prior=plan.before,
        resulting_snapshot_digest=snapshot_digest(current),
        preserve_vault_data=True,
    )
    request = SyncthingVaultRollbackRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )
    operations.calls.clear()
    assert_code(
        lambda: rollback_remote_queen_syncthing_vault(
            plan=plan,
            journal=journal,
            request=request,
            operations=operations,
        ),
        "RQ_E_ROLLBACK_DRIFT",
    )
    assert operations.calls == []


def test_rollback_drift_does_not_call_configuration():
    manifest = build_manifest()
    operations = MemoryOperations(absent_snapshot())
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    request = SyncthingVaultApplyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )
    applied = apply_remote_queen_syncthing_vault(
        plan=plan, request=request, operations=operations
    )
    operations.snapshot = absent_snapshot()
    operations.calls.clear()
    rollback_request = SyncthingVaultRollbackRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )
    assert_code(
        lambda: rollback_remote_queen_syncthing_vault(
            plan=plan,
            journal=applied.journal,
            request=rollback_request,
            operations=operations,
        ),
        "RQ_E_ROLLBACK_DRIFT",
    )
    assert operations.calls == ["inspect"]


def test_rollback_foreign_or_unknown_generation_does_not_call_configuration():
    manifest = build_manifest()
    operations = MemoryOperations(absent_snapshot())
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    apply_request = SyncthingVaultApplyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )
    applied = apply_remote_queen_syncthing_vault(
        plan=plan, request=apply_request, operations=operations
    )
    desired = operations.snapshot
    operations.snapshot = dataclasses.replace(
        desired,
        folder=dataclasses.replace(
            desired.folder,
            state=SyncthingFolderStateKindV1.FOREIGN,
        ),
    )
    operations.calls.clear()
    request = SyncthingVaultRollbackRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )
    assert_code(
        lambda: rollback_remote_queen_syncthing_vault(
            plan=plan,
            journal=applied.journal,
            request=request,
            operations=operations,
        ),
        "RQ_E_ROLLBACK_DRIFT",
    )
    assert operations.calls == ["inspect"]


def test_malformed_journal_is_redacted_and_no_rollback_call():
    manifest = build_manifest()
    operations = MemoryOperations(absent_snapshot())
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=operations
    )
    sentinel = "device-id-rb5-do-not-retain"
    journal = SyncthingVaultApplyJournalV1(
        schema_version="SyncthingVaultApplyJournalV1",
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
        prior=plan.before,
        resulting_snapshot_digest=plan.before_digest,
        preserve_vault_data=True,
    )
    object.__setattr__(journal, "plan_digest", sentinel)
    request = SyncthingVaultRollbackRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )
    operations.calls.clear()
    with pytest.raises(RemoteQueenBootstrapError) as error:
        rollback_remote_queen_syncthing_vault(
            plan=plan,
            journal=journal,
            request=request,
            operations=operations,
        )
    assert error.value.code == "RQ_E_ROLLBACK_DRIFT"
    assert sentinel not in str(error.value)
    assert operations.calls == []


def test_operations_exceptions_are_redacted_during_apply_and_rollback():
    manifest = build_manifest()
    sentinel = "secret-rb5-do-not-retain"
    inspect_operations = RaisingOperations(sentinel)
    with pytest.raises(RemoteQueenBootstrapError) as error:
        plan_remote_queen_syncthing_vault(
            manifest=manifest, operations=inspect_operations
        )
    assert sentinel not in str(error.value)
    assert error.value.code == "RQ_E_VAULT_CONFLICT"


def test_runtime_operations_touch_no_files_or_processes(tmp_path):
    manifest = build_manifest(remote_home=str(tmp_path / "queen"))
    operations = MemoryOperations(absent_snapshot())
    before = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))
    plan_remote_queen_syncthing_vault(manifest=manifest, operations=operations)
    after = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))
    assert before == after == []
    assert operations.calls == ["inspect"]


def dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def test_import_gate_has_no_forbidden_imports_or_calls():
    source_path = (
        Path(__file__).parents[1]
        / "src"
        / "codex_master"
        / "remote_queen_syncthing.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    forbidden_namespaces = {
        "os",
        "subprocess",
        "socket",
        "asyncio",
        "requests",
        "urllib",
        "http",
        "httpx",
        "aiohttp",
        "paramiko",
        "asyncssh",
        "tempfile",
        "shutil",
        "pathlib.Path",
        "xml",
        "syncthing",
    }
    forbidden_calls = {
        "open",
        "system",
        "popen",
        "run",
        "call",
        "check_call",
        "check_output",
        "Popen",
        "connect",
        "urlopen",
        "request",
        "get",
        "post",
        "put",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "unlink",
        "rename",
        "replace",
        "mkdir",
        "rmdir",
        "chmod",
        "chown",
        "remove",
        "delete",
    }
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                local = item.asname or item.name.split(".")[0]
                aliases[local] = item.name
                assert item.name not in forbidden_namespaces
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert module not in forbidden_namespaces
            for item in node.names:
                full_name = f"{module}.{item.name}"
                assert full_name not in forbidden_namespaces
                aliases[item.asname or item.name] = full_name
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = dotted_name(node.func)
            resolved = called
            if called and "." not in called and called in aliases:
                resolved = aliases[called]
            assert (resolved or "").split(".")[-1] not in forbidden_calls


def test_secret_and_device_sentinels_never_enter_contract_or_errors():
    secret = "secret-rb5-do-not-retain"
    device = "device-id-rb5-do-not-retain"
    manifest = build_manifest()
    plan = plan_remote_queen_syncthing_vault(
        manifest=manifest, operations=MemoryOperations(absent_snapshot())
    )
    rendered = json.dumps(
        {
            "manifest": syncthing_vault_manifest_as_dict(manifest),
            "plan": syncthing_vault_plan_as_dict(plan),
        },
        sort_keys=True,
    )
    assert secret not in rendered
    assert device not in rendered
    assert secret not in repr(manifest)
    assert device not in repr(plan)


def test_public_dataclasses_have_no_secret_fields():
    public_types = [
        RemoteQueenSyncthingVaultManifestV1,
        RemoteQueenSyncthingVaultPlanV1,
        SingleWriterGrantV1,
        SyncthingFolderFactV1,
        SyncthingGuiFactV1,
        SyncthingVaultApplyJournalV1,
        SyncthingVaultApplyRequestV1,
        SyncthingVaultApplyResultV1,
        SyncthingVaultRollbackRequestV1,
        SyncthingVaultRollbackResultV1,
        SyncthingVaultSnapshotV1,
        SyncthingVaultVerifyRequestV1,
        SyncthingVaultVerifyResultV1,
    ]
    forbidden_fragments = (
        "secret",
        "token",
        "key",
        "credential",
        "api_key",
        "device_id",
        "auth",
    )
    for public_type in public_types:
        for field in dataclasses.fields(public_type):
            if field.name == "device_binding_sha256":
                continue
            assert not any(fragment in field.name.lower() for fragment in forbidden_fragments)


def test_vault_unchanged_and_no_live_command_strings():
    source_path = (
        Path(__file__).parents[1]
        / "src"
        / "codex_master"
        / "remote_queen_syncthing.py"
    )
    source = source_path.read_text(encoding="utf-8").lower()
    assert "systemctl" not in source
    assert "syncthing cli" not in source
    assert "syncthing serve" not in source
    assert "curl " not in source
    assert "wget " not in source


def test_protocol_is_structural_only_and_public_contract_names_exist():
    assert RemoteQueenSyncthingOperations.__name__ == "RemoteQueenSyncthingOperations"
    assert SyncthingFolderModeV1.SEND_RECEIVE.value == "sendreceive"
    assert SyncthingVaultActionV1.CREATE_CONFIGURATION.value == (
        "create-folder-configuration"
    )
