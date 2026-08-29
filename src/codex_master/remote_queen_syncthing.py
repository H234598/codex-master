from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from codex_master.remote_queen_bootstrap import (
    ManifestGenerationV1,
    RemoteQueenBootstrapError,
)


VAULT_FOLDER_ID = "teladi-programming"
VAULT_FOLDER_LABEL = "Teladi_Programming"
VAULT_RELATIVE_PATH = "Dokumente/Obsidian_Vaults/Teladi_Programming"
ANNOTATION_SIDECAR_PATTERN = (
    ".obsidian/plugins/annotation-marker/annotations/**"
)

VAULT_REQUIRED_PATHS = (ANNOTATION_SIDECAR_PATTERN,)

VAULT_EXCLUDED_PATHS = (
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

ALLOWED_GUI_LISTEN_ADDRESSES = (
    "127.0.0.1:8384",
    "[::1]:8384",
)


class SyncthingFolderStateKindV1(str, Enum):
    ABSENT = "absent"
    OWNED = "owned"
    FOREIGN = "foreign"


class SyncthingFolderModeV1(str, Enum):
    SEND_RECEIVE = "sendreceive"


class SyncthingVaultActionV1(str, Enum):
    CREATE_CONFIGURATION = "create-folder-configuration"
    REPLACE_OWNED_CONFIGURATION = "replace-owned-folder-configuration"


class VaultWriterIdV1(str, Enum):
    G18_TOPIC_QUEEN = "g18-topic-queen"
    INTEGRATION_QUEEN = "codex-master-integration-queen"


class VaultWriteScopeV1(str, Enum):
    G18_PLAN = "g18-plan"
    G18_ARTIFACTS = "g18-artifacts"
    MASTER_PLAN = "master-plan"
    REMOTE_BOOTSTRAP_PLAN = "remote-bootstrap-plan"


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RAW_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GENERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]*\Z")


def _error(code: str) -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError(code)


def _inconsistent() -> RemoteQueenBootstrapError:
    return _error("RQ_E_PLAN_INCONSISTENT")


def _conflict() -> RemoteQueenBootstrapError:
    return _error("RQ_E_VAULT_CONFLICT")


def _foreign() -> RemoteQueenBootstrapError:
    return _error("RQ_E_FOREIGN_STATE")


def _annotation_stale() -> RemoteQueenBootstrapError:
    return _error("RQ_E_ANNOTATION_STALE")


def _rollback_drift() -> RemoteQueenBootstrapError:
    return _error("RQ_E_ROLLBACK_DRIFT")


def _is_digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _is_raw_sha256(value: object) -> bool:
    return type(value) is str and _RAW_SHA256.fullmatch(value) is not None


def _is_generation(value: object) -> bool:
    return (
        type(value) is str
        and _GENERATION.fullmatch(value) is not None
    )


def _is_clean_string(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and not any(
            unicodedata.category(char).startswith("C") for char in value
        )
    )


def _validate_remote_home(value: object) -> None:
    if not _is_clean_string(value):
        raise _inconsistent()
    if (
        not value.startswith("/")
        or value == "/"
        or value.endswith("/")
        or "//" in value
        or "~" in value
        or "\\" in value
    ):
        raise _inconsistent()
    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components[1:]):
        raise _inconsistent()


def _validate_generation(value: object) -> None:
    if type(value) is not ManifestGenerationV1:
        raise _inconsistent()
    if not _is_generation(value.generation) or not _is_raw_sha256(value.sha256):
        raise _inconsistent()


def _validate_digest(value: object) -> None:
    if not _is_digest(value):
        raise _inconsistent()


def _validate_optional_string(value: object) -> None:
    if value is not None and type(value) is not str:
        raise _inconsistent()


def _expected_writer_grants() -> tuple["SingleWriterGrantV1", ...]:
    return (
        SingleWriterGrantV1(
            writer_id=VaultWriterIdV1.G18_TOPIC_QUEEN,
            scopes=(VaultWriteScopeV1.G18_PLAN, VaultWriteScopeV1.G18_ARTIFACTS),
        ),
        SingleWriterGrantV1(
            writer_id=VaultWriterIdV1.INTEGRATION_QUEEN,
            scopes=(
                VaultWriteScopeV1.MASTER_PLAN,
                VaultWriteScopeV1.REMOTE_BOOTSTRAP_PLAN,
            ),
        ),
    )


@dataclass(frozen=True, slots=True)
class SingleWriterGrantV1:
    writer_id: VaultWriterIdV1
    scopes: tuple[VaultWriteScopeV1, ...]

    def __post_init__(self) -> None:
        if (
            type(self.writer_id) is not VaultWriterIdV1
            or type(self.scopes) is not tuple
            or not self.scopes
            or any(type(scope) is not VaultWriteScopeV1 for scope in self.scopes)
            or len(self.scopes) != len(set(self.scopes))
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class SyncthingGuiFactV1:
    enabled: bool
    listen_address: str | None

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise _inconsistent()
        _validate_optional_string(self.listen_address)


@dataclass(frozen=True, slots=True)
class SyncthingFolderFactV1:
    state: SyncthingFolderStateKindV1
    generation: str | None
    config_manifest_digest: str | None
    device_binding_sha256: str | None
    sync_complete: bool
    unresolved_conflicts: int
    annotation_sidecars_visible: bool
    observed_plan_digest: str | None

    def __post_init__(self) -> None:
        _validate_folder_fields(self)


@dataclass(frozen=True, slots=True)
class SyncthingVaultSnapshotV1:
    gui: SyncthingGuiFactV1
    folder: SyncthingFolderFactV1

    def __post_init__(self) -> None:
        if (
            type(self.gui) is not SyncthingGuiFactV1
            or type(self.folder) is not SyncthingFolderFactV1
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class RemoteQueenSyncthingVaultManifestV1:
    schema_version: str
    desired_generation: ManifestGenerationV1
    device_binding_generation: ManifestGenerationV1
    expected_plan_digest: str
    folder_id: str
    folder_label: str
    folder_path: str
    folder_mode: SyncthingFolderModeV1
    required_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    writer_grants: tuple[SingleWriterGrantV1, ...]
    versioning_enabled: bool
    conflict_retention_enabled: bool
    delete_unknown_generation: bool
    gui_policy: str
    allowed_gui_listen_addresses: tuple[str, ...]
    manifest_digest: str

    def __post_init__(self) -> None:
        _validate_manifest(self)


@dataclass(frozen=True, slots=True)
class RemoteQueenSyncthingVaultPlanV1:
    schema_version: str
    manifest: RemoteQueenSyncthingVaultManifestV1
    before: SyncthingVaultSnapshotV1
    before_digest: str
    action: SyncthingVaultActionV1 | None
    remove_own_configuration_on_rollback: bool
    preserve_vault_data_on_rollback: bool
    plan_digest: str

    def __post_init__(self) -> None:
        _validate_plan(self)


@dataclass(frozen=True, slots=True)
class SyncthingVaultApplyRequestV1:
    generation: str
    manifest_digest: str
    plan_digest: str

    def __post_init__(self) -> None:
        _validate_request_fields(
            self.generation, self.manifest_digest, self.plan_digest
        )


@dataclass(frozen=True, slots=True)
class SyncthingVaultApplyJournalV1:
    schema_version: str
    generation: str
    manifest_digest: str
    plan_digest: str
    prior: SyncthingVaultSnapshotV1
    resulting_snapshot_digest: str
    preserve_vault_data: bool

    def __post_init__(self) -> None:
        _validate_journal_shape(self)


@dataclass(frozen=True, slots=True)
class SyncthingVaultApplyResultV1:
    changed: bool
    journal: SyncthingVaultApplyJournalV1 | None
    snapshot_digest: str

    def __post_init__(self) -> None:
        if type(self.changed) is not bool:
            raise _inconsistent()
        if self.journal is not None and type(self.journal) is not SyncthingVaultApplyJournalV1:
            raise _inconsistent()
        if not self.changed and self.journal is not None:
            raise _inconsistent()
        _validate_digest(self.snapshot_digest)


@dataclass(frozen=True, slots=True)
class SyncthingVaultVerifyRequestV1:
    generation: str
    manifest_digest: str
    expected_plan_digest: str

    def __post_init__(self) -> None:
        _validate_request_fields(
            self.generation,
            self.manifest_digest,
            self.expected_plan_digest,
        )


@dataclass(frozen=True, slots=True)
class SyncthingVaultVerifyResultV1:
    snapshot_digest: str

    def __post_init__(self) -> None:
        _validate_digest(self.snapshot_digest)


@dataclass(frozen=True, slots=True)
class SyncthingVaultRollbackRequestV1:
    generation: str
    manifest_digest: str
    plan_digest: str

    def __post_init__(self) -> None:
        _validate_request_fields(
            self.generation, self.manifest_digest, self.plan_digest
        )


@dataclass(frozen=True, slots=True)
class SyncthingVaultRollbackResultV1:
    restored_snapshot_digest: str
    vault_data_preserved: bool

    def __post_init__(self) -> None:
        _validate_digest(self.restored_snapshot_digest)
        if self.vault_data_preserved is not True:
            raise _inconsistent()


class RemoteQueenSyncthingOperations(Protocol):
    def inspect(
        self, manifest: RemoteQueenSyncthingVaultManifestV1
    ) -> SyncthingVaultSnapshotV1: ...

    def apply_configuration(
        self, plan: RemoteQueenSyncthingVaultPlanV1
    ) -> SyncthingVaultApplyJournalV1: ...

    def rollback_configuration(
        self,
        plan: RemoteQueenSyncthingVaultPlanV1,
        journal: SyncthingVaultApplyJournalV1,
        *,
        preserve_vault_data: bool,
    ) -> None: ...


def _validate_folder_fields(folder: SyncthingFolderFactV1) -> None:
    if type(folder.state) is not SyncthingFolderStateKindV1:
        raise _inconsistent()
    _validate_optional_string(folder.generation)
    _validate_optional_string(folder.config_manifest_digest)
    _validate_optional_string(folder.device_binding_sha256)
    _validate_optional_string(folder.observed_plan_digest)
    if (
        type(folder.sync_complete) is not bool
        or type(folder.unresolved_conflicts) is not int
        or folder.unresolved_conflicts < 0
        or type(folder.annotation_sidecars_visible) is not bool
    ):
        raise _inconsistent()
    if folder.state is SyncthingFolderStateKindV1.ABSENT and (
        folder.generation is not None
        or folder.config_manifest_digest is not None
        or folder.device_binding_sha256 is not None
        or folder.sync_complete is not False
        or folder.unresolved_conflicts != 0
        or folder.annotation_sidecars_visible is not False
        or folder.observed_plan_digest is not None
    ):
        raise _inconsistent()


def _validate_snapshot(snapshot: object) -> None:
    if type(snapshot) is not SyncthingVaultSnapshotV1:
        raise _inconsistent()
    if (
        type(snapshot.gui) is not SyncthingGuiFactV1
        or type(snapshot.folder) is not SyncthingFolderFactV1
    ):
        raise _inconsistent()
    if (
        type(snapshot.gui.enabled) is not bool
        or (
            snapshot.gui.listen_address is not None
            and type(snapshot.gui.listen_address) is not str
        )
    ):
        raise _inconsistent()
    _validate_folder_fields(snapshot.folder)
    if snapshot.folder.state is SyncthingFolderStateKindV1.OWNED:
        if (
            not _is_generation(snapshot.folder.generation)
            or not _is_digest(snapshot.folder.config_manifest_digest)
            or not _is_raw_sha256(snapshot.folder.device_binding_sha256)
            or not _is_digest(snapshot.folder.observed_plan_digest)
        ):
            raise _inconsistent()


def _validate_request_fields(
    generation: object, manifest_digest: object, plan_digest: object
) -> None:
    if not _is_generation(generation):
        raise _inconsistent()
    _validate_digest(manifest_digest)
    _validate_digest(plan_digest)


def _validate_journal_shape(journal: object) -> None:
    if type(journal) is not SyncthingVaultApplyJournalV1:
        raise _inconsistent()
    if journal.schema_version != "SyncthingVaultApplyJournalV1":
        raise _inconsistent()
    if not _is_generation(journal.generation):
        raise _inconsistent()
    _validate_digest(journal.manifest_digest)
    _validate_digest(journal.plan_digest)
    _validate_snapshot(journal.prior)
    _validate_digest(journal.resulting_snapshot_digest)
    if journal.preserve_vault_data is not True:
        raise _inconsistent()


def _generation_dict(generation: ManifestGenerationV1) -> dict[str, object]:
    return {
        "generation": generation.generation,
        "sha256": generation.sha256,
    }


def _grant_dict(grant: SingleWriterGrantV1) -> dict[str, object]:
    return {
        "writer_id": grant.writer_id.value,
        "scopes": [scope.value for scope in grant.scopes],
    }


def _manifest_payload_from_values(
    *,
    schema_version: str,
    desired_generation: ManifestGenerationV1,
    device_binding_generation: ManifestGenerationV1,
    expected_plan_digest: str,
    folder_id: str,
    folder_label: str,
    folder_path: str,
    folder_mode: SyncthingFolderModeV1,
    required_paths: tuple[str, ...],
    excluded_paths: tuple[str, ...],
    writer_grants: tuple[SingleWriterGrantV1, ...],
    versioning_enabled: bool,
    conflict_retention_enabled: bool,
    delete_unknown_generation: bool,
    gui_policy: str,
    allowed_gui_listen_addresses: tuple[str, ...],
    manifest_digest: str | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": schema_version,
        "desired_generation": _generation_dict(desired_generation),
        "device_binding_generation": _generation_dict(device_binding_generation),
        "expected_plan_digest": expected_plan_digest,
        "folder_id": folder_id,
        "folder_label": folder_label,
        "folder_path": folder_path,
        "folder_mode": folder_mode.value,
        "required_paths": list(required_paths),
        "excluded_paths": list(excluded_paths),
        "writer_grants": [_grant_dict(grant) for grant in writer_grants],
        "versioning_enabled": versioning_enabled,
        "conflict_retention_enabled": conflict_retention_enabled,
        "delete_unknown_generation": delete_unknown_generation,
        "gui_policy": gui_policy,
        "allowed_gui_listen_addresses": list(allowed_gui_listen_addresses),
    }
    if manifest_digest is not None:
        payload["manifest_digest"] = manifest_digest
    return payload


def _manifest_payload(
    manifest: RemoteQueenSyncthingVaultManifestV1,
    *,
    include_digest: bool,
) -> dict[str, object]:
    return _manifest_payload_from_values(
        schema_version=manifest.schema_version,
        desired_generation=manifest.desired_generation,
        device_binding_generation=manifest.device_binding_generation,
        expected_plan_digest=manifest.expected_plan_digest,
        folder_id=manifest.folder_id,
        folder_label=manifest.folder_label,
        folder_path=manifest.folder_path,
        folder_mode=manifest.folder_mode,
        required_paths=manifest.required_paths,
        excluded_paths=manifest.excluded_paths,
        writer_grants=manifest.writer_grants,
        versioning_enabled=manifest.versioning_enabled,
        conflict_retention_enabled=manifest.conflict_retention_enabled,
        delete_unknown_generation=manifest.delete_unknown_generation,
        gui_policy=manifest.gui_policy,
        allowed_gui_listen_addresses=manifest.allowed_gui_listen_addresses,
        manifest_digest=manifest.manifest_digest if include_digest else None,
    )


def _canonical_digest(payload: dict[str, object]) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _validate_manifest(manifest: object) -> None:
    if type(manifest) is not RemoteQueenSyncthingVaultManifestV1:
        raise _inconsistent()
    if manifest.schema_version != "RemoteQueenSyncthingVaultManifestV1":
        raise _inconsistent()
    _validate_generation(manifest.desired_generation)
    _validate_generation(manifest.device_binding_generation)
    _validate_digest(manifest.expected_plan_digest)
    if (
        manifest.folder_id != VAULT_FOLDER_ID
        or manifest.folder_label != VAULT_FOLDER_LABEL
        or type(manifest.folder_id) is not str
        or type(manifest.folder_label) is not str
        or type(manifest.folder_path) is not str
        or type(manifest.folder_mode) is not SyncthingFolderModeV1
    ):
        raise _inconsistent()
    suffix = "/" + VAULT_RELATIVE_PATH
    if not manifest.folder_path.endswith(suffix):
        raise _inconsistent()
    _validate_remote_home(manifest.folder_path[: -len(suffix)])
    if (
        type(manifest.required_paths) is not tuple
        or type(manifest.excluded_paths) is not tuple
        or type(manifest.writer_grants) is not tuple
        or type(manifest.allowed_gui_listen_addresses) is not tuple
        or manifest.required_paths != VAULT_REQUIRED_PATHS
        or manifest.excluded_paths != VAULT_EXCLUDED_PATHS
        or manifest.writer_grants != _expected_writer_grants()
        or manifest.allowed_gui_listen_addresses != ALLOWED_GUI_LISTEN_ADDRESSES
    ):
        raise _inconsistent()
    if (
        manifest.versioning_enabled is not True
        or manifest.conflict_retention_enabled is not True
        or manifest.delete_unknown_generation is not False
        or manifest.gui_policy != "disabled-or-loopback-only"
    ):
        raise _inconsistent()
    if type(manifest.gui_policy) is not str:
        raise _inconsistent()
    _validate_digest(manifest.manifest_digest)
    if _canonical_digest(_manifest_payload(manifest, include_digest=False)) != manifest.manifest_digest:
        raise _inconsistent()


def _snapshot_dict(snapshot: SyncthingVaultSnapshotV1) -> dict[str, object]:
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


def _snapshot_digest(snapshot: SyncthingVaultSnapshotV1) -> str:
    _validate_snapshot(snapshot)
    return _canonical_digest(_snapshot_dict(snapshot))


def _plan_payload_from_values(
    *,
    schema_version: str,
    manifest: RemoteQueenSyncthingVaultManifestV1,
    before: SyncthingVaultSnapshotV1,
    before_digest: str,
    action: SyncthingVaultActionV1 | None,
    remove_own_configuration_on_rollback: bool,
    preserve_vault_data_on_rollback: bool,
    plan_digest: str | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": schema_version,
        "manifest": _manifest_payload(manifest, include_digest=True),
        "before": _snapshot_dict(before),
        "before_digest": before_digest,
        "action": action.value if action is not None else None,
        "rollback": {
            "remove_own_configuration": remove_own_configuration_on_rollback,
            "preserve_vault_data": preserve_vault_data_on_rollback,
        },
    }
    if plan_digest is not None:
        payload["plan_digest"] = plan_digest
    return payload


def _plan_payload(
    plan: RemoteQueenSyncthingVaultPlanV1,
    *,
    include_digest: bool,
) -> dict[str, object]:
    return _plan_payload_from_values(
        schema_version=plan.schema_version,
        manifest=plan.manifest,
        before=plan.before,
        before_digest=plan.before_digest,
        action=plan.action,
        remove_own_configuration_on_rollback=plan.remove_own_configuration_on_rollback,
        preserve_vault_data_on_rollback=plan.preserve_vault_data_on_rollback,
        plan_digest=plan.plan_digest if include_digest else None,
    )


def _validate_plan(plan: object) -> None:
    if type(plan) is not RemoteQueenSyncthingVaultPlanV1:
        raise _inconsistent()
    if plan.schema_version != "RemoteQueenSyncthingVaultPlanV1":
        raise _inconsistent()
    _validate_manifest(plan.manifest)
    _validate_snapshot(plan.before)
    _validate_digest(plan.before_digest)
    if plan.before_digest != _snapshot_digest(plan.before):
        raise _inconsistent()
    if plan.action is not None and type(plan.action) is not SyncthingVaultActionV1:
        raise _inconsistent()
    try:
        expected_action = _classify_plan(plan.manifest, plan.before)
    except RemoteQueenBootstrapError:
        raise _inconsistent() from None
    if plan.action is not expected_action:
        raise _inconsistent()
    if (
        plan.remove_own_configuration_on_rollback is not True
        or plan.preserve_vault_data_on_rollback is not True
    ):
        raise _inconsistent()
    _validate_digest(plan.plan_digest)
    if _canonical_digest(_plan_payload(plan, include_digest=False)) != plan.plan_digest:
        raise _inconsistent()


def _validate_operations(operations: object, *, mutation: bool) -> None:
    names = ["inspect"]
    if mutation:
        names.extend(["apply_configuration", "rollback_configuration"])
    try:
        valid = all(callable(getattr(operations, name)) for name in names)
    except Exception:
        valid = False
    if not valid:
        raise _inconsistent()


def _inspect(
    operations: RemoteQueenSyncthingOperations,
    manifest: RemoteQueenSyncthingVaultManifestV1,
) -> SyncthingVaultSnapshotV1:
    try:
        snapshot = operations.inspect(manifest)
    except Exception:
        raise _conflict() from None
    _validate_snapshot(snapshot)
    return snapshot


def _safe_gui(gui: SyncthingGuiFactV1) -> None:
    if gui.enabled:
        if gui.listen_address not in ALLOWED_GUI_LISTEN_ADDRESSES:
            raise _foreign()
    elif gui.listen_address is not None:
        raise _foreign()


def _owned_complete(
    manifest: RemoteQueenSyncthingVaultManifestV1,
    snapshot: SyncthingVaultSnapshotV1,
) -> bool:
    folder = snapshot.folder
    return (
        folder.state is SyncthingFolderStateKindV1.OWNED
        and _is_generation(folder.generation)
        and _is_digest(folder.config_manifest_digest)
        and _is_raw_sha256(folder.device_binding_sha256)
        and _is_digest(folder.observed_plan_digest)
        and folder.sync_complete is True
        and folder.unresolved_conflicts == 0
        and folder.annotation_sidecars_visible is True
        and folder.observed_plan_digest == manifest.expected_plan_digest
    )


def _classify_plan(
    manifest: RemoteQueenSyncthingVaultManifestV1,
    snapshot: SyncthingVaultSnapshotV1,
) -> SyncthingVaultActionV1 | None:
    _safe_gui(snapshot.gui)
    folder = snapshot.folder
    if folder.state is SyncthingFolderStateKindV1.FOREIGN:
        raise _foreign()
    if folder.unresolved_conflicts != 0:
        raise _conflict()
    if folder.state is SyncthingFolderStateKindV1.ABSENT:
        return SyncthingVaultActionV1.CREATE_CONFIGURATION
    if folder.observed_plan_digest != manifest.expected_plan_digest:
        raise _conflict()
    if not folder.annotation_sidecars_visible:
        raise _annotation_stale()
    if not _owned_complete(manifest, snapshot):
        raise _conflict()
    if folder.generation == manifest.desired_generation.generation:
        if (
            folder.config_manifest_digest != manifest.manifest_digest
            or folder.device_binding_sha256
            != manifest.device_binding_generation.sha256
            or folder.sync_complete is not True
        ):
            raise _conflict()
        return None
    return SyncthingVaultActionV1.REPLACE_OWNED_CONFIGURATION


def _attest(
    manifest: RemoteQueenSyncthingVaultManifestV1,
    snapshot: SyncthingVaultSnapshotV1,
) -> None:
    _safe_gui(snapshot.gui)
    folder = snapshot.folder
    if folder.state is SyncthingFolderStateKindV1.FOREIGN:
        raise _foreign()
    if folder.state is not SyncthingFolderStateKindV1.OWNED:
        raise _conflict()
    if folder.unresolved_conflicts != 0:
        raise _conflict()
    if folder.observed_plan_digest != manifest.expected_plan_digest:
        raise _conflict()
    if not folder.annotation_sidecars_visible:
        raise _annotation_stale()
    if (
        folder.generation != manifest.desired_generation.generation
        or folder.config_manifest_digest != manifest.manifest_digest
        or folder.device_binding_sha256
        != manifest.device_binding_generation.sha256
        or folder.sync_complete is not True
    ):
        raise _conflict()


def _validate_request_match(
    generation: str,
    manifest_digest: str,
    plan_digest: str,
    manifest: RemoteQueenSyncthingVaultManifestV1,
    expected_plan_digest: str,
) -> None:
    if (
        generation != manifest.desired_generation.generation
        or manifest_digest != manifest.manifest_digest
        or plan_digest != expected_plan_digest
    ):
        raise _conflict()


def _validate_apply_journal(
    plan: RemoteQueenSyncthingVaultPlanV1,
    journal: SyncthingVaultApplyJournalV1,
) -> None:
    try:
        _validate_journal_shape(journal)
    except RemoteQueenBootstrapError:
        raise _conflict() from None
    if (
        journal.generation != plan.manifest.desired_generation.generation
        or journal.manifest_digest != plan.manifest.manifest_digest
        or journal.plan_digest != plan.plan_digest
        or journal.prior != plan.before
        or journal.preserve_vault_data is not True
    ):
        raise _conflict()


def build_remote_queen_syncthing_vault_manifest(
    *,
    desired_generation: ManifestGenerationV1,
    device_binding_generation: ManifestGenerationV1,
    expected_plan_digest: str,
    remote_home: str,
) -> RemoteQueenSyncthingVaultManifestV1:
    _validate_generation(desired_generation)
    _validate_generation(device_binding_generation)
    _validate_digest(expected_plan_digest)
    _validate_remote_home(remote_home)
    folder_path = remote_home + "/" + VAULT_RELATIVE_PATH
    writer_grants = _expected_writer_grants()
    payload = _manifest_payload_from_values(
        schema_version="RemoteQueenSyncthingVaultManifestV1",
        desired_generation=desired_generation,
        device_binding_generation=device_binding_generation,
        expected_plan_digest=expected_plan_digest,
        folder_id=VAULT_FOLDER_ID,
        folder_label=VAULT_FOLDER_LABEL,
        folder_path=folder_path,
        folder_mode=SyncthingFolderModeV1.SEND_RECEIVE,
        required_paths=VAULT_REQUIRED_PATHS,
        excluded_paths=VAULT_EXCLUDED_PATHS,
        writer_grants=writer_grants,
        versioning_enabled=True,
        conflict_retention_enabled=True,
        delete_unknown_generation=False,
        gui_policy="disabled-or-loopback-only",
        allowed_gui_listen_addresses=ALLOWED_GUI_LISTEN_ADDRESSES,
        manifest_digest=None,
    )
    return RemoteQueenSyncthingVaultManifestV1(
        schema_version="RemoteQueenSyncthingVaultManifestV1",
        desired_generation=desired_generation,
        device_binding_generation=device_binding_generation,
        expected_plan_digest=expected_plan_digest,
        folder_id=VAULT_FOLDER_ID,
        folder_label=VAULT_FOLDER_LABEL,
        folder_path=folder_path,
        folder_mode=SyncthingFolderModeV1.SEND_RECEIVE,
        required_paths=VAULT_REQUIRED_PATHS,
        excluded_paths=VAULT_EXCLUDED_PATHS,
        writer_grants=writer_grants,
        versioning_enabled=True,
        conflict_retention_enabled=True,
        delete_unknown_generation=False,
        gui_policy="disabled-or-loopback-only",
        allowed_gui_listen_addresses=ALLOWED_GUI_LISTEN_ADDRESSES,
        manifest_digest=_canonical_digest(payload),
    )


def plan_remote_queen_syncthing_vault(
    *,
    manifest: RemoteQueenSyncthingVaultManifestV1,
    operations: RemoteQueenSyncthingOperations,
) -> RemoteQueenSyncthingVaultPlanV1:
    _validate_manifest(manifest)
    _validate_operations(operations, mutation=False)
    before = _inspect(operations, manifest)
    action = _classify_plan(manifest, before)
    before_digest = _snapshot_digest(before)
    payload = _plan_payload_from_values(
        schema_version="RemoteQueenSyncthingVaultPlanV1",
        manifest=manifest,
        before=before,
        before_digest=before_digest,
        action=action,
        remove_own_configuration_on_rollback=True,
        preserve_vault_data_on_rollback=True,
        plan_digest=None,
    )
    return RemoteQueenSyncthingVaultPlanV1(
        schema_version="RemoteQueenSyncthingVaultPlanV1",
        manifest=manifest,
        before=before,
        before_digest=before_digest,
        action=action,
        remove_own_configuration_on_rollback=True,
        preserve_vault_data_on_rollback=True,
        plan_digest=_canonical_digest(payload),
    )


def apply_remote_queen_syncthing_vault(
    *,
    plan: RemoteQueenSyncthingVaultPlanV1,
    request: SyncthingVaultApplyRequestV1,
    operations: RemoteQueenSyncthingOperations,
) -> SyncthingVaultApplyResultV1:
    _validate_plan(plan)
    if type(request) is not SyncthingVaultApplyRequestV1:
        raise _inconsistent()
    _validate_operations(operations, mutation=True)
    _validate_request_match(
        request.generation,
        request.manifest_digest,
        request.plan_digest,
        plan.manifest,
        plan.plan_digest,
    )
    before = _inspect(operations, plan.manifest)
    if _snapshot_digest(before) != plan.before_digest or before != plan.before:
        raise _conflict()
    if plan.action is None:
        _attest(plan.manifest, before)
        return SyncthingVaultApplyResultV1(
            changed=False,
            journal=None,
            snapshot_digest=_snapshot_digest(before),
        )
    try:
        expected_action = _classify_plan(plan.manifest, before)
    except RemoteQueenBootstrapError:
        raise
    if expected_action is not plan.action:
        raise _conflict()
    try:
        journal = operations.apply_configuration(plan)
    except Exception:
        raise _conflict() from None
    _validate_apply_journal(plan, journal)
    after = _inspect(operations, plan.manifest)
    after_digest = _snapshot_digest(after)
    try:
        _attest(plan.manifest, after)
    except RemoteQueenBootstrapError:
        raise
    if journal.resulting_snapshot_digest != after_digest:
        raise _conflict()
    return SyncthingVaultApplyResultV1(
        changed=True,
        journal=journal,
        snapshot_digest=after_digest,
    )


def verify_remote_queen_syncthing_vault(
    *,
    manifest: RemoteQueenSyncthingVaultManifestV1,
    request: SyncthingVaultVerifyRequestV1,
    operations: RemoteQueenSyncthingOperations,
) -> SyncthingVaultVerifyResultV1:
    _validate_manifest(manifest)
    if type(request) is not SyncthingVaultVerifyRequestV1:
        raise _inconsistent()
    _validate_operations(operations, mutation=False)
    _validate_request_match(
        request.generation,
        request.manifest_digest,
        request.expected_plan_digest,
        manifest,
        manifest.expected_plan_digest,
    )
    snapshot = _inspect(operations, manifest)
    _attest(manifest, snapshot)
    return SyncthingVaultVerifyResultV1(
        snapshot_digest=_snapshot_digest(snapshot)
    )


def rollback_remote_queen_syncthing_vault(
    *,
    plan: RemoteQueenSyncthingVaultPlanV1,
    journal: SyncthingVaultApplyJournalV1,
    request: SyncthingVaultRollbackRequestV1,
    operations: RemoteQueenSyncthingOperations,
) -> SyncthingVaultRollbackResultV1:
    try:
        _validate_plan(plan)
        if plan.action is None:
            raise _rollback_drift()
        if type(request) is not SyncthingVaultRollbackRequestV1:
            raise _rollback_drift()
        _validate_request_match(
            request.generation,
            request.manifest_digest,
            request.plan_digest,
            plan.manifest,
            plan.plan_digest,
        )
        _validate_journal_shape(journal)
        if (
            journal.generation != plan.manifest.desired_generation.generation
            or journal.manifest_digest != plan.manifest.manifest_digest
            or journal.plan_digest != plan.plan_digest
            or journal.prior != plan.before
            or journal.preserve_vault_data is not True
        ):
            raise _rollback_drift()
        _validate_operations(operations, mutation=True)
    except RemoteQueenBootstrapError as error:
        if error.code == "RQ_E_ROLLBACK_DRIFT":
            raise
        raise _rollback_drift() from None
    current = _inspect(operations, plan.manifest)
    try:
        _attest(plan.manifest, current)
    except RemoteQueenBootstrapError:
        raise _rollback_drift() from None
    if _snapshot_digest(current) != journal.resulting_snapshot_digest:
        raise _rollback_drift()
    try:
        operations.rollback_configuration(
            plan,
            journal,
            preserve_vault_data=True,
        )
    except Exception:
        raise _conflict() from None
    restored = _inspect(operations, plan.manifest)
    try:
        _validate_snapshot(restored)
    except RemoteQueenBootstrapError:
        raise _rollback_drift() from None
    restored_digest = _snapshot_digest(restored)
    if restored != journal.prior or restored_digest != plan.before_digest:
        raise _rollback_drift()
    return SyncthingVaultRollbackResultV1(
        restored_snapshot_digest=restored_digest,
        vault_data_preserved=True,
    )


def syncthing_vault_manifest_as_dict(
    manifest: RemoteQueenSyncthingVaultManifestV1,
) -> dict[str, object]:
    _validate_manifest(manifest)
    return _manifest_payload(manifest, include_digest=True)


def syncthing_vault_plan_as_dict(
    plan: RemoteQueenSyncthingVaultPlanV1,
) -> dict[str, object]:
    _validate_plan(plan)
    return _plan_payload(plan, include_digest=True)
