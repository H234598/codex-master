import hashlib
import json
import re
from dataclasses import dataclass, fields
from enum import Enum
from typing import Protocol

from codex_master.remote_queen_bootstrap import (
    ManifestGenerationV1,
    RemoteQueenBootstrapError,
)


REMOTE_QUEEN_HOME_SCHEMA = "remote-queen-home-v1"
REMOTE_QUEEN_HOME_PLAN_SCHEMA = "remote-queen-home-plan-v1"
RESUME_CAPSULE_SCHEMA = "resume-capsule-v1"

QUEEN_REPO_ID = "codex-master"
QUEEN_TOPIC_ID = "g18-vertex-overflow"
QUEEN_ROLE = "queen"
QUEEN_BRANCH = "g18-vertex-overflow"
QUEEN_INTEGRATION_OWNER = "codex-master-integration-queen"
QUEEN_HOME_PARENT = ".codex-agents/Queens"
QUEEN_HOME_PREFIX = "G18-"
QUEEN_REPO_DIR = "codex-master"

GENERIC_RULES_PATH = "instructions/generic.md"
QUEEN_RULES_PATH = "instructions/queen.md"
TOPIC_ASSIGNMENT_PATH = "assignments/g18.md"


class QueenHomeStateKindV1(str, Enum):
    ABSENT = "absent"
    OWNED = "owned"
    FOREIGN = "foreign"


class QueenHomeActionV1(str, Enum):
    CREATE_HOME = "create-home"


class QueenMaterialKindV1(str, Enum):
    GENERIC_RULES = "generic-rules"
    QUEEN_RULES = "queen-rules"
    TOPIC_ASSIGNMENT = "topic-assignment"
    SKILL = "skill"


@dataclass(frozen=True, slots=True)
class QueenHomeMaterialV1:
    relative_path: str
    kind: QueenMaterialKindV1
    class_id: str
    content_sha256: str

    def __post_init__(self) -> None:
        _validate_material(self)


@dataclass(frozen=True, slots=True)
class QueenTopicBindingV1:
    repo_id: str
    topic_id: str
    role: str
    branch: str
    write_paths: tuple[str, ...]
    integration_owner: str
    binding_digest: str

    def __post_init__(self) -> None:
        _validate_topic_binding(self)


@dataclass(frozen=True, slots=True)
class QueenLeaseBindingV1:
    lease_id: str
    owner_principal_id: str
    repo_id: str
    topic_id: str
    fence_epoch: int
    lease_generation: ManifestGenerationV1
    binding_digest: str

    def __post_init__(self) -> None:
        _validate_lease_binding(self)


@dataclass(frozen=True, slots=True)
class ResumeCapsuleV1:
    schema_version: str
    capsule_generation: ManifestGenerationV1
    principal_id: str
    session_id: str
    repo_id: str
    topic_id: str
    plan_digest: str
    baseline_commit: str
    lease_binding_digest: str
    bus_cursor_sha256: str
    account_binding_sha256: str
    accepted_artifact_digests: tuple[str, ...]
    capsule_digest: str

    def __post_init__(self) -> None:
        _validate_resume_capsule(self)


@dataclass(frozen=True, slots=True)
class RemoteQueenHomeManifestV1:
    schema_version: str
    desired_generation: ManifestGenerationV1
    remote_home: str
    home_path: str
    repo_path: str
    topic_binding: QueenTopicBindingV1
    lease_binding: QueenLeaseBindingV1
    materials: tuple[QueenHomeMaterialV1, ...]
    resume_capsule: ResumeCapsuleV1
    manifest_digest: str

    def __post_init__(self) -> None:
        _validate_manifest(self)


@dataclass(frozen=True, slots=True)
class QueenHomeFactV1:
    state: QueenHomeStateKindV1
    generation: str | None
    owner_principal_id: str | None
    lease_id: str | None
    home_path: str | None
    manifest_digest: str | None
    baseline_commit: str | None
    branch: str | None
    material_tree_sha256: str | None
    resume_capsule_digest: str | None
    plan_digest: str | None
    lease_binding_digest: str | None
    bus_cursor_sha256: str | None

    def __post_init__(self) -> None:
        _validate_home_fact(self)


@dataclass(frozen=True, slots=True)
class QueenHomeSnapshotV1:
    home: QueenHomeFactV1
    active_topic_principal_id: str | None
    active_topic_home_path: str | None
    active_topic_lease_id: str | None
    conflicting_write_paths: tuple[str, ...]
    lease_active: bool
    observed_lease_binding_digest: str | None
    bus_available: bool
    observed_bus_cursor_sha256: str | None
    account_available: bool
    observed_account_binding_sha256: str | None

    def __post_init__(self) -> None:
        _validate_snapshot(self)


@dataclass(frozen=True, slots=True)
class RemoteQueenHomePlanV1:
    schema_version: str
    manifest: RemoteQueenHomeManifestV1
    before: QueenHomeSnapshotV1
    before_digest: str
    action: QueenHomeActionV1 | None
    remove_own_home_on_rollback: bool
    preserve_repo_on_rollback: bool
    preserve_vault_on_rollback: bool
    preserve_hive_state_on_rollback: bool
    plan_digest: str

    def __post_init__(self) -> None:
        _validate_plan(self)


@dataclass(frozen=True, slots=True)
class ApplyRemoteQueenHomeRequestV1:
    plan: RemoteQueenHomePlanV1
    expected_plan_digest: str

    def __post_init__(self) -> None:
        _validate_request_plan(self.plan, self.expected_plan_digest)


@dataclass(frozen=True, slots=True)
class RemoteQueenHomeApplyJournalV1:
    before_digest: str
    created_generation: str
    created_home_path: str
    resulting_snapshot_digest: str

    def __post_init__(self) -> None:
        _validate_journal(self)


@dataclass(frozen=True, slots=True)
class RemoteQueenHomeApplyResultV1:
    changed: bool
    snapshot: QueenHomeSnapshotV1
    journal: RemoteQueenHomeApplyJournalV1 | None

    def __post_init__(self) -> None:
        if type(self.changed) is not bool or type(self.snapshot) is not QueenHomeSnapshotV1:
            _raise("RQ_E_PLAN_INCONSISTENT")
        if self.journal is not None and type(self.journal) is not RemoteQueenHomeApplyJournalV1:
            _raise("RQ_E_PLAN_INCONSISTENT")
        if not self.changed and self.journal is not None:
            _raise("RQ_E_PLAN_INCONSISTENT")
        if self.changed and self.journal is None:
            _raise("RQ_E_PLAN_INCONSISTENT")


@dataclass(frozen=True, slots=True)
class VerifyRemoteQueenHomeRequestV1:
    plan: RemoteQueenHomePlanV1
    expected_plan_digest: str

    def __post_init__(self) -> None:
        _validate_request_plan(self.plan, self.expected_plan_digest)


@dataclass(frozen=True, slots=True)
class RemoteQueenHomeVerifyResultV1:
    verified: bool
    snapshot: QueenHomeSnapshotV1

    def __post_init__(self) -> None:
        if type(self.verified) is not bool or type(self.snapshot) is not QueenHomeSnapshotV1:
            _raise("RQ_E_PLAN_INCONSISTENT")


@dataclass(frozen=True, slots=True)
class RollbackRemoteQueenHomeRequestV1:
    plan: RemoteQueenHomePlanV1
    expected_plan_digest: str
    journal: RemoteQueenHomeApplyJournalV1 | None

    def __post_init__(self) -> None:
        _validate_request_plan(self.plan, self.expected_plan_digest)
        if self.journal is not None and type(self.journal) is not RemoteQueenHomeApplyJournalV1:
            _raise("RQ_E_PLAN_INCONSISTENT")


@dataclass(frozen=True, slots=True)
class RemoteQueenHomeRollbackResultV1:
    changed: bool
    snapshot: QueenHomeSnapshotV1

    def __post_init__(self) -> None:
        if type(self.changed) is not bool or type(self.snapshot) is not QueenHomeSnapshotV1:
            _raise("RQ_E_PLAN_INCONSISTENT")


class RemoteQueenHomeOperations(Protocol):
    def inspect(
        self, manifest: RemoteQueenHomeManifestV1
    ) -> QueenHomeSnapshotV1: ...

    def materialize_home(
        self, plan: RemoteQueenHomePlanV1
    ) -> RemoteQueenHomeApplyJournalV1: ...

    def rollback_home(
        self,
        plan: RemoteQueenHomePlanV1,
        journal: RemoteQueenHomeApplyJournalV1,
    ) -> None: ...


_SECRET_FIELD_NAMES = (
    "token",
    "secret",
    "password",
    "cookie",
    "credential",
    "stdout",
    "stderr",
    "command",
    "content",
)
_BANNED_SCOPE_SEGMENTS = ("worker", "teamleader", "teamlead", "tl", "admin", "godqueen")
_BANNED_PLAN_SEGMENTS = (
    "masterplan",
    "bootstrapplan",
    "master-plan",
    "master_plan",
    "bootstrap-plan",
    "bootstrap_plan",
    "bootstrap",
    "vault",
    "repo",
    "codex-master",
)


def _raise(code: str) -> None:
    raise RemoteQueenBootstrapError(code)


def _valid_digest(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _valid_generation(value: object) -> bool:
    if type(value) is not ManifestGenerationV1:
        return False
    if type(value.generation) is not str or type(value.sha256) is not str:
        return False
    if re.fullmatch(r"[0-9a-f]{64}", value.sha256) is None:
        return False
    return _valid_token(value.generation, None)


def _valid_token(value: object, maximum: int | None = 128) -> bool:
    if type(value) is not str or not 1 <= len(value) or (maximum is not None and len(value) > maximum):
        return False
    return all(0x21 <= ord(char) <= 0x7E and char not in "/\\" for char in value)


def _valid_identifier(value: object) -> bool:
    return _valid_token(value, 128)


def _valid_baseline(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _valid_safe_text(value: object) -> bool:
    if type(value) is not str or not value:
        return False
    return all(char != "\x00" and not char.isspace() and char.isprintable() for char in value)


def _valid_remote_home(value: object) -> bool:
    if type(value) is not str or value == "/" or not value.startswith("/") or value.endswith("/"):
        return False
    if "\\" in value or "~" in value or "\x00" in value:
        return False
    segments = value.split("/")[1:]
    if not segments or any(segment in ("", ".", "..") for segment in segments):
        return False
    return all(_valid_safe_text(segment) for segment in segments)


def _valid_relative_segment(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) is not None


def _valid_write_path(value: object) -> bool:
    if type(value) is not str or not value.startswith("G18/") or not value.endswith("/**"):
        return False
    base = value[:-3]
    segments = base.split("/")
    if len(segments) < 2 or segments[0] != "G18":
        return False
    if any(not _valid_relative_segment(segment) or segment in (".", "..") for segment in segments[1:]):
        return False
    folded = tuple(segment.casefold() for segment in segments[1:])
    if any(segment in _BANNED_SCOPE_SEGMENTS or segment in _BANNED_PLAN_SEGMENTS for segment in folded):
        return False
    return True


def _valid_write_paths(value: object, allow_empty: bool = False) -> bool:
    if type(value) is not tuple or (not allow_empty and not 1 <= len(value) <= 32) or (allow_empty and len(value) > 32):
        return False
    if any(type(path) is not str for path in value):
        return False
    if value != tuple(sorted(value)) or len(value) != len(set(value)):
        return False
    if any(not _valid_write_path(path) for path in value):
        return False
    bases = [path[:-3].split("/") for path in value]
    for index, current in enumerate(bases):
        for other in bases[index + 1 :]:
            if current == other or current[: len(other)] == other or other[: len(current)] == current:
                return False
    return True


def _valid_material_path(value: object) -> bool:
    if type(value) is not str or "\\" in value or "\x00" in value:
        return False
    if value in (GENERIC_RULES_PATH, QUEEN_RULES_PATH, TOPIC_ASSIGNMENT_PATH):
        return True
    if re.fullmatch(r"skills/[a-z0-9]+(?:-[a-z0-9]+)*/SKILL\.md", value) is None:
        return False
    return not any(segment in _BANNED_SCOPE_SEGMENTS for segment in value.split("/")[:-1])


def _valid_class_id(value: object) -> bool:
    return type(value) is str and value in ("generic", "queen", "g18-topic-queen")


def _digest_payload(value: object) -> str:
    try:
        encoded = _json_bytes(_canonicalize(value))
        return "sha256:" + hashlib.sha256(encoded).hexdigest()
    except RemoteQueenBootstrapError:
        raise
    except Exception:
        _raise("RQ_E_PLAN_INCONSISTENT")
    raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")


def _json_bytes(payload: object) -> bytes:
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except Exception:
        _raise("RQ_E_PLAN_INCONSISTENT")
    raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")


def _canonicalize(value: object, omit_field: str | None = None) -> object:
    if value is None or type(value) is bool or type(value) is int or type(value) is str:
        return value
    if type(value) is float:
        if value != value or value == float("inf") or value == float("-inf"):
            _raise("RQ_E_PLAN_INCONSISTENT")
        return value
    if type(value) in (
        QueenHomeStateKindV1,
        QueenHomeActionV1,
        QueenMaterialKindV1,
    ):
        return value.value
    if type(value) is tuple:
        return tuple(_canonicalize(item) for item in value)
    if type(value) is dict:
        result = {}
        for key, item in value.items():
            if type(key) is not str or key in _SECRET_FIELD_NAMES:
                _raise("RQ_E_PLAN_INCONSISTENT")
            result[key] = _canonicalize(item)
        return result
    domain_types = (
        ManifestGenerationV1,
        QueenHomeMaterialV1,
        QueenTopicBindingV1,
        QueenLeaseBindingV1,
        ResumeCapsuleV1,
        RemoteQueenHomeManifestV1,
        QueenHomeFactV1,
        QueenHomeSnapshotV1,
        RemoteQueenHomePlanV1,
        ApplyRemoteQueenHomeRequestV1,
        RemoteQueenHomeApplyJournalV1,
        RemoteQueenHomeApplyResultV1,
        VerifyRemoteQueenHomeRequestV1,
        RemoteQueenHomeVerifyResultV1,
        RollbackRemoteQueenHomeRequestV1,
        RemoteQueenHomeRollbackResultV1,
    )
    if type(value) not in domain_types:
        _raise("RQ_E_PLAN_INCONSISTENT")
    result = {}
    for field in fields(value):
        if field.name in _SECRET_FIELD_NAMES:
            _raise("RQ_E_PLAN_INCONSISTENT")
        if field.name == omit_field:
            continue
        result[field.name] = _canonicalize(getattr(value, field.name))
    return result


def canonical_json_bytes(value: object) -> bytes:
    try:
        _validate_top_level_domain(value)
        return _json_bytes(_canonicalize(value))
    except RemoteQueenBootstrapError:
        raise
    except Exception:
        _raise("RQ_E_PLAN_INCONSISTENT")
    raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")


def _own_digest_field(value: object) -> str | None:
    if type(value) is QueenTopicBindingV1 or type(value) is QueenLeaseBindingV1:
        return "binding_digest"
    if type(value) is ResumeCapsuleV1:
        return "capsule_digest"
    if type(value) is RemoteQueenHomeManifestV1:
        return "manifest_digest"
    if type(value) is RemoteQueenHomePlanV1:
        return "plan_digest"
    return None


def canonical_digest(value: object) -> str:
    try:
        _validate_top_level_domain(value)
        return _digest_payload(value) if _own_digest_field(value) is None else _digest_payload_without_field(value)
    except RemoteQueenBootstrapError:
        raise
    except Exception:
        _raise("RQ_E_PLAN_INCONSISTENT")
    raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")


def _digest_payload_without_field(value: object) -> str:
    return "sha256:" + hashlib.sha256(_json_bytes(_canonicalize(value, _own_digest_field(value)))).hexdigest()


def _field_payload(value: object, omit: str) -> dict[str, object]:
    payload = {}
    for field in fields(value):
        if field.name != omit:
            payload[field.name] = getattr(value, field.name)
    return payload


def _object_digest(value: object, omit: str) -> str:
    return _digest_payload(_field_payload(value, omit))


def _validate_material(value: object) -> None:
    if type(value) is not QueenHomeMaterialV1:
        _raise("RQ_E_PLAN_INCONSISTENT")
    expected = {
        TOPIC_ASSIGNMENT_PATH: (QueenMaterialKindV1.TOPIC_ASSIGNMENT, "g18-topic-queen"),
        GENERIC_RULES_PATH: (QueenMaterialKindV1.GENERIC_RULES, "generic"),
        QUEEN_RULES_PATH: (QueenMaterialKindV1.QUEEN_RULES, "queen"),
    }
    if not _valid_material_path(value.relative_path) or not _valid_class_id(value.class_id) or not _valid_digest(value.content_sha256):
        _raise("RQ_E_PLAN_INCONSISTENT")
    if value.relative_path in expected:
        kind, class_id = expected[value.relative_path]
        if type(value.kind) is not QueenMaterialKindV1 or value.kind is not kind or value.class_id != class_id:
            _raise("RQ_E_PLAN_INCONSISTENT")
    elif type(value.kind) is not QueenMaterialKindV1 or value.kind is not QueenMaterialKindV1.SKILL or value.class_id != "queen":
        _raise("RQ_E_PLAN_INCONSISTENT")
    if any(segment.casefold() in _BANNED_SCOPE_SEGMENTS for segment in value.relative_path.split("/")):
        _raise("RQ_E_PLAN_INCONSISTENT")


def _validate_materials(value: object) -> None:
    if type(value) is not tuple or not 4 <= len(value) <= 32:
        _raise("RQ_E_PLAN_INCONSISTENT")
    if any(type(item) is not QueenHomeMaterialV1 for item in value):
        _raise("RQ_E_PLAN_INCONSISTENT")
    if value != tuple(sorted(value, key=lambda item: item.relative_path)):
        _raise("RQ_E_PLAN_INCONSISTENT")
    paths = []
    skill_count = 0
    for item in value:
        _validate_material(item)
        if item.relative_path in paths:
            _raise("RQ_E_PLAN_INCONSISTENT")
        paths.append(item.relative_path)
        if item.kind is QueenMaterialKindV1.SKILL:
            skill_count += 1
    if paths.count(GENERIC_RULES_PATH) != 1 or paths.count(QUEEN_RULES_PATH) != 1 or paths.count(TOPIC_ASSIGNMENT_PATH) != 1 or skill_count < 1:
        _raise("RQ_E_PLAN_INCONSISTENT")


def _validate_topic_binding(value: object) -> None:
    if type(value) is not QueenTopicBindingV1:
        _raise("RQ_E_PLAN_INCONSISTENT")
    if (
        value.repo_id != QUEEN_REPO_ID
        or value.topic_id != QUEEN_TOPIC_ID
        or value.role != QUEEN_ROLE
        or value.branch != QUEEN_BRANCH
        or value.integration_owner != QUEEN_INTEGRATION_OWNER
        or type(value.repo_id) is not str
        or type(value.topic_id) is not str
        or type(value.role) is not str
        or type(value.branch) is not str
        or type(value.integration_owner) is not str
        or not _valid_write_paths(value.write_paths)
        or not _valid_digest(value.binding_digest)
    ):
        _raise("RQ_E_PLAN_INCONSISTENT")
    if _object_digest(value, "binding_digest") != value.binding_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")


def _validate_lease_binding(value: object) -> None:
    if type(value) is not QueenLeaseBindingV1:
        _raise("RQ_E_PLAN_INCONSISTENT")
    if (
        not _valid_identifier(value.lease_id)
        or not _valid_identifier(value.owner_principal_id)
        or value.repo_id != QUEEN_REPO_ID
        or value.topic_id != QUEEN_TOPIC_ID
        or type(value.repo_id) is not str
        or type(value.topic_id) is not str
        or type(value.fence_epoch) is not int
        or value.fence_epoch < 1
        or not _valid_generation(value.lease_generation)
        or not _valid_digest(value.binding_digest)
    ):
        _raise("RQ_E_PLAN_INCONSISTENT")
    if _object_digest(value, "binding_digest") != value.binding_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")


def _validate_accepted_digests(value: object) -> None:
    if type(value) is not tuple or any(type(item) is not str for item in value) or value != tuple(sorted(value)) or len(value) != len(set(value)):
        _raise("RQ_E_PLAN_INCONSISTENT")
    if any(not _valid_digest(item) for item in value):
        _raise("RQ_E_PLAN_INCONSISTENT")


def _validate_resume_capsule(value: object) -> None:
    if type(value) is not ResumeCapsuleV1:
        _raise("RQ_E_PLAN_INCONSISTENT")
    if (
        value.schema_version != RESUME_CAPSULE_SCHEMA
        or type(value.schema_version) is not str
        or not _valid_generation(value.capsule_generation)
        or not _valid_identifier(value.principal_id)
        or not _valid_identifier(value.session_id)
        or value.repo_id != QUEEN_REPO_ID
        or value.topic_id != QUEEN_TOPIC_ID
        or type(value.repo_id) is not str
        or type(value.topic_id) is not str
        or not _valid_digest(value.plan_digest)
        or not _valid_baseline(value.baseline_commit)
        or not _valid_digest(value.lease_binding_digest)
        or not _valid_digest(value.bus_cursor_sha256)
        or not _valid_digest(value.account_binding_sha256)
        or not _valid_digest(value.capsule_digest)
    ):
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_accepted_digests(value.accepted_artifact_digests)
    if _object_digest(value, "capsule_digest") != value.capsule_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")


def _derive_home_path(remote_home: str, lease_id: str) -> str:
    return remote_home + "/" + QUEEN_HOME_PARENT + "/" + QUEEN_HOME_PREFIX + lease_id


def _derive_repo_path(remote_home: str) -> str:
    return remote_home + "/" + QUEEN_REPO_DIR


def _validate_manifest(value: object) -> None:
    if type(value) is not RemoteQueenHomeManifestV1:
        _raise("RQ_E_PLAN_INCONSISTENT")
    if (
        value.schema_version != REMOTE_QUEEN_HOME_SCHEMA
        or type(value.schema_version) is not str
        or not _valid_generation(value.desired_generation)
        or not _valid_remote_home(value.remote_home)
        or type(value.home_path) is not str
        or type(value.repo_path) is not str
        or type(value.topic_binding) is not QueenTopicBindingV1
        or type(value.lease_binding) is not QueenLeaseBindingV1
        or type(value.resume_capsule) is not ResumeCapsuleV1
        or not _valid_digest(value.manifest_digest)
    ):
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_topic_binding(value.topic_binding)
    _validate_lease_binding(value.lease_binding)
    _validate_materials(value.materials)
    _validate_resume_capsule(value.resume_capsule)
    if value.home_path != _derive_home_path(value.remote_home, value.lease_binding.lease_id) or value.repo_path != _derive_repo_path(value.remote_home):
        _raise("RQ_E_PLAN_INCONSISTENT")
    if (
        value.lease_binding.repo_id != value.topic_binding.repo_id
        or value.lease_binding.topic_id != value.topic_binding.topic_id
        or value.resume_capsule.principal_id != value.lease_binding.owner_principal_id
        or value.resume_capsule.repo_id != value.lease_binding.repo_id
        or value.resume_capsule.topic_id != value.lease_binding.topic_id
        or value.resume_capsule.lease_binding_digest != value.lease_binding.binding_digest
        or tuple(sorted(set(item.content_sha256 for item in value.materials))) != value.resume_capsule.accepted_artifact_digests
    ):
        _raise("RQ_E_PLAN_INCONSISTENT")
    if _object_digest(value, "manifest_digest") != value.manifest_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")


def _optional_identifier(value: object) -> bool:
    return value is None or _valid_identifier(value)


def _optional_generation_token(value: object) -> bool:
    return value is None or _valid_token(value, None)


def _optional_digest(value: object) -> bool:
    return value is None or _valid_digest(value)


def _validate_home_fact(value: object) -> None:
    if type(value) is not QueenHomeFactV1 or type(value.state) is not QueenHomeStateKindV1:
        _raise("RQ_E_FOREIGN_STATE")
    if not _optional_generation_token(value.generation) or not _optional_identifier(value.owner_principal_id) or not _optional_identifier(value.lease_id):
        _raise("RQ_E_FOREIGN_STATE")
    if value.home_path is not None and not _valid_remote_home(value.home_path):
        _raise("RQ_E_FOREIGN_STATE")
    if value.baseline_commit is not None and not _valid_baseline(value.baseline_commit):
        _raise("RQ_E_FOREIGN_STATE")
    if value.branch is not None and not _valid_identifier(value.branch):
        _raise("RQ_E_FOREIGN_STATE")
    if not _optional_digest(value.manifest_digest) or not _optional_digest(value.material_tree_sha256) or not _optional_digest(value.resume_capsule_digest) or not _optional_digest(value.plan_digest) or not _optional_digest(value.lease_binding_digest) or not _optional_digest(value.bus_cursor_sha256):
        _raise("RQ_E_FOREIGN_STATE")
    optional_values = (
        value.generation,
        value.owner_principal_id,
        value.lease_id,
        value.home_path,
        value.manifest_digest,
        value.baseline_commit,
        value.branch,
        value.material_tree_sha256,
        value.resume_capsule_digest,
        value.plan_digest,
        value.lease_binding_digest,
        value.bus_cursor_sha256,
    )
    if value.state is QueenHomeStateKindV1.ABSENT and any(item is not None for item in optional_values):
        _raise("RQ_E_FOREIGN_STATE")
    if value.state is QueenHomeStateKindV1.OWNED and any(item is None for item in optional_values):
        _raise("RQ_E_FOREIGN_STATE")


def _validate_snapshot(value: object) -> None:
    if type(value) is not QueenHomeSnapshotV1 or type(value.home) is not QueenHomeFactV1:
        _raise("RQ_E_FOREIGN_STATE")
    _validate_home_fact(value.home)
    active = (value.active_topic_principal_id, value.active_topic_home_path, value.active_topic_lease_id)
    if all(item is None for item in active):
        pass
    elif all(item is not None for item in active):
        if not _valid_identifier(value.active_topic_principal_id) or not _valid_remote_home(value.active_topic_home_path) or not _valid_identifier(value.active_topic_lease_id):
            _raise("RQ_E_FOREIGN_STATE")
    else:
        _raise("RQ_E_FOREIGN_STATE")
    if not _valid_write_paths(value.conflicting_write_paths, allow_empty=True):
        _raise("RQ_E_FOREIGN_STATE")
    if type(value.lease_active) is not bool or type(value.bus_available) is not bool or type(value.account_available) is not bool:
        _raise("RQ_E_FOREIGN_STATE")
    if value.lease_active:
        if not _valid_digest(value.observed_lease_binding_digest):
            _raise("RQ_E_FOREIGN_STATE")
    elif not _optional_digest(value.observed_lease_binding_digest):
        _raise("RQ_E_FOREIGN_STATE")
    if value.bus_available:
        if not _valid_digest(value.observed_bus_cursor_sha256):
            _raise("RQ_E_FOREIGN_STATE")
    elif not _optional_digest(value.observed_bus_cursor_sha256):
        _raise("RQ_E_FOREIGN_STATE")
    if value.account_available:
        if not _valid_digest(value.observed_account_binding_sha256):
            _raise("RQ_E_FOREIGN_STATE")
    elif not _optional_digest(value.observed_account_binding_sha256):
        _raise("RQ_E_FOREIGN_STATE")


def _validate_plan(value: object) -> None:
    if type(value) is not RemoteQueenHomePlanV1:
        _raise("RQ_E_PLAN_INCONSISTENT")
    if (
        value.schema_version != REMOTE_QUEEN_HOME_PLAN_SCHEMA
        or type(value.schema_version) is not str
        or type(value.manifest) is not RemoteQueenHomeManifestV1
        or type(value.before) is not QueenHomeSnapshotV1
        or not _valid_digest(value.before_digest)
        or (value.action is not None and type(value.action) is not QueenHomeActionV1)
        or type(value.remove_own_home_on_rollback) is not bool
        or type(value.preserve_repo_on_rollback) is not bool
        or type(value.preserve_vault_on_rollback) is not bool
        or type(value.preserve_hive_state_on_rollback) is not bool
        or not _valid_digest(value.plan_digest)
    ):
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_manifest(value.manifest)
    _validate_snapshot(value.before)
    if queen_home_snapshot_digest(value.before) != value.before_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")
    if value.action is QueenHomeActionV1.CREATE_HOME:
        if not value.remove_own_home_on_rollback or not value.preserve_repo_on_rollback or not value.preserve_vault_on_rollback or not value.preserve_hive_state_on_rollback:
            _raise("RQ_E_PLAN_INCONSISTENT")
    elif value.action is None:
        if value.remove_own_home_on_rollback or not value.preserve_repo_on_rollback or not value.preserve_vault_on_rollback or not value.preserve_hive_state_on_rollback:
            _raise("RQ_E_PLAN_INCONSISTENT")
    else:
        _raise("RQ_E_PLAN_INCONSISTENT")
    try:
        _gate_snapshot(value.manifest, value.before)
    except RemoteQueenBootstrapError:
        _raise("RQ_E_PLAN_INCONSISTENT")
    if value.action is QueenHomeActionV1.CREATE_HOME and not _fully_absent(value.manifest, value.before):
        _raise("RQ_E_PLAN_INCONSISTENT")
    if value.action is None and not _fully_owned(value.manifest, value.before):
        _raise("RQ_E_PLAN_INCONSISTENT")
    if _object_digest(value, "plan_digest") != value.plan_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")


def _validate_request_plan(plan: object, expected_digest: object) -> None:
    if type(plan) is not RemoteQueenHomePlanV1 or not _valid_digest(expected_digest):
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_plan(plan)


def _validate_journal(value: object) -> None:
    if type(value) is not RemoteQueenHomeApplyJournalV1 or not _valid_digest(value.before_digest) or not _valid_token(value.created_generation, None) or not _valid_remote_home(value.created_home_path) or not _valid_digest(value.resulting_snapshot_digest):
        _raise("RQ_E_PLAN_INCONSISTENT")


def _validate_top_level_domain(value: object) -> None:
    if type(value) is ManifestGenerationV1:
        if not _valid_generation(value):
            _raise("RQ_E_PLAN_INCONSISTENT")
    elif type(value) is QueenHomeMaterialV1:
        _validate_material(value)
    elif type(value) is QueenTopicBindingV1:
        _validate_topic_binding(value)
    elif type(value) is QueenLeaseBindingV1:
        _validate_lease_binding(value)
    elif type(value) is ResumeCapsuleV1:
        _validate_resume_capsule(value)
    elif type(value) is RemoteQueenHomeManifestV1:
        _validate_manifest(value)
    elif type(value) is QueenHomeFactV1:
        _validate_home_fact(value)
    elif type(value) is QueenHomeSnapshotV1:
        _validate_snapshot(value)
    elif type(value) is RemoteQueenHomePlanV1:
        _validate_plan(value)
    elif type(value) is ApplyRemoteQueenHomeRequestV1 or type(value) is VerifyRemoteQueenHomeRequestV1:
        _validate_request_plan(value.plan, value.expected_plan_digest)
    elif type(value) is RollbackRemoteQueenHomeRequestV1:
        _validate_request_plan(value.plan, value.expected_plan_digest)
        if value.journal is not None:
            _validate_journal(value.journal)
    elif type(value) is RemoteQueenHomeApplyJournalV1:
        _validate_journal(value)


def _validate_manifest_input(manifest: object) -> None:
    try:
        _validate_manifest(manifest)
    except RemoteQueenBootstrapError:
        raise
    except Exception:
        _raise("RQ_E_PLAN_INCONSISTENT")


def build_queen_topic_binding(
    write_paths: tuple[str, ...],
) -> QueenTopicBindingV1:
    if not _valid_write_paths(write_paths):
        _raise("RQ_E_PLAN_INCONSISTENT")
    payload = {
        "repo_id": QUEEN_REPO_ID,
        "topic_id": QUEEN_TOPIC_ID,
        "role": QUEEN_ROLE,
        "branch": QUEEN_BRANCH,
        "write_paths": write_paths,
        "integration_owner": QUEEN_INTEGRATION_OWNER,
    }
    return QueenTopicBindingV1(**payload, binding_digest=_digest_payload(payload))


def build_queen_lease_binding(
    lease_id: str,
    owner_principal_id: str,
    fence_epoch: int,
    lease_generation: ManifestGenerationV1,
) -> QueenLeaseBindingV1:
    if not _valid_identifier(lease_id) or not _valid_identifier(owner_principal_id) or type(fence_epoch) is not int or fence_epoch < 1 or not _valid_generation(lease_generation):
        _raise("RQ_E_PLAN_INCONSISTENT")
    payload = {
        "lease_id": lease_id,
        "owner_principal_id": owner_principal_id,
        "repo_id": QUEEN_REPO_ID,
        "topic_id": QUEEN_TOPIC_ID,
        "fence_epoch": fence_epoch,
        "lease_generation": lease_generation,
    }
    return QueenLeaseBindingV1(**payload, binding_digest=_digest_payload(payload))


def build_resume_capsule(
    capsule_generation: ManifestGenerationV1,
    principal_id: str,
    session_id: str,
    plan_digest: str,
    baseline_commit: str,
    lease_binding: QueenLeaseBindingV1,
    bus_cursor_sha256: str,
    account_binding_sha256: str,
    accepted_artifact_digests: tuple[str, ...],
) -> ResumeCapsuleV1:
    if (
        not _valid_generation(capsule_generation)
        or not _valid_identifier(principal_id)
        or not _valid_identifier(session_id)
        or not _valid_digest(plan_digest)
        or not _valid_baseline(baseline_commit)
        or type(lease_binding) is not QueenLeaseBindingV1
        or not _valid_digest(bus_cursor_sha256)
        or not _valid_digest(account_binding_sha256)
    ):
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_lease_binding(lease_binding)
    if principal_id != lease_binding.owner_principal_id:
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_accepted_digests(accepted_artifact_digests)
    payload = {
        "schema_version": RESUME_CAPSULE_SCHEMA,
        "capsule_generation": capsule_generation,
        "principal_id": principal_id,
        "session_id": session_id,
        "repo_id": QUEEN_REPO_ID,
        "topic_id": QUEEN_TOPIC_ID,
        "plan_digest": plan_digest,
        "baseline_commit": baseline_commit,
        "lease_binding_digest": lease_binding.binding_digest,
        "bus_cursor_sha256": bus_cursor_sha256,
        "account_binding_sha256": account_binding_sha256,
        "accepted_artifact_digests": accepted_artifact_digests,
    }
    return ResumeCapsuleV1(**payload, capsule_digest=_digest_payload(payload))


def build_remote_queen_home_manifest(
    desired_generation: ManifestGenerationV1,
    remote_home: str,
    topic_binding: QueenTopicBindingV1,
    lease_binding: QueenLeaseBindingV1,
    materials: tuple[QueenHomeMaterialV1, ...],
    resume_capsule: ResumeCapsuleV1,
) -> RemoteQueenHomeManifestV1:
    if not _valid_generation(desired_generation) or not _valid_remote_home(remote_home) or type(topic_binding) is not QueenTopicBindingV1 or type(lease_binding) is not QueenLeaseBindingV1 or type(resume_capsule) is not ResumeCapsuleV1:
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_topic_binding(topic_binding)
    _validate_lease_binding(lease_binding)
    _validate_materials(materials)
    _validate_resume_capsule(resume_capsule)
    if (
        lease_binding.repo_id != topic_binding.repo_id
        or lease_binding.topic_id != topic_binding.topic_id
        or resume_capsule.principal_id != lease_binding.owner_principal_id
        or resume_capsule.lease_binding_digest != lease_binding.binding_digest
        or tuple(sorted(set(item.content_sha256 for item in materials))) != resume_capsule.accepted_artifact_digests
    ):
        _raise("RQ_E_PLAN_INCONSISTENT")
    payload = {
        "schema_version": REMOTE_QUEEN_HOME_SCHEMA,
        "desired_generation": desired_generation,
        "remote_home": remote_home,
        "home_path": _derive_home_path(remote_home, lease_binding.lease_id),
        "repo_path": _derive_repo_path(remote_home),
        "topic_binding": topic_binding,
        "lease_binding": lease_binding,
        "materials": materials,
        "resume_capsule": resume_capsule,
    }
    return RemoteQueenHomeManifestV1(**payload, manifest_digest=_digest_payload(payload))


def material_tree_digest(materials: tuple[QueenHomeMaterialV1, ...]) -> str:
    _validate_materials(materials)
    return canonical_digest(materials)


def queen_home_snapshot_digest(snapshot: QueenHomeSnapshotV1) -> str:
    _validate_snapshot(snapshot)
    return canonical_digest(snapshot)


def _fully_absent(manifest: RemoteQueenHomeManifestV1, snapshot: QueenHomeSnapshotV1) -> bool:
    return snapshot.home.state is QueenHomeStateKindV1.ABSENT and snapshot.active_topic_principal_id is None and snapshot.active_topic_home_path is None and snapshot.active_topic_lease_id is None and snapshot.conflicting_write_paths == ()


def _fully_owned(manifest: RemoteQueenHomeManifestV1, snapshot: QueenHomeSnapshotV1) -> bool:
    expected_tree = material_tree_digest(manifest.materials)
    home = snapshot.home
    return (
        home.state is QueenHomeStateKindV1.OWNED
        and home.generation == manifest.desired_generation.generation
        and home.owner_principal_id == manifest.lease_binding.owner_principal_id
        and home.lease_id == manifest.lease_binding.lease_id
        and home.home_path == manifest.home_path
        and home.manifest_digest == manifest.manifest_digest
        and home.baseline_commit == manifest.resume_capsule.baseline_commit
        and home.branch == manifest.topic_binding.branch
        and home.material_tree_sha256 == expected_tree
        and home.resume_capsule_digest == manifest.resume_capsule.capsule_digest
        and home.plan_digest == manifest.resume_capsule.plan_digest
        and home.lease_binding_digest == manifest.lease_binding.binding_digest
        and home.bus_cursor_sha256 == manifest.resume_capsule.bus_cursor_sha256
        and snapshot.active_topic_principal_id == manifest.lease_binding.owner_principal_id
        and snapshot.active_topic_home_path == manifest.home_path
        and snapshot.active_topic_lease_id == manifest.lease_binding.lease_id
        and snapshot.conflicting_write_paths == ()
        and snapshot.lease_active
        and snapshot.observed_lease_binding_digest == manifest.lease_binding.binding_digest
        and snapshot.bus_available
        and snapshot.observed_bus_cursor_sha256 == manifest.resume_capsule.bus_cursor_sha256
        and snapshot.account_available
        and snapshot.observed_account_binding_sha256 == manifest.resume_capsule.account_binding_sha256
    )


def _gate_snapshot(manifest: RemoteQueenHomeManifestV1, snapshot: QueenHomeSnapshotV1) -> None:
    try:
        _validate_snapshot(snapshot)
    except RemoteQueenBootstrapError:
        _raise("RQ_E_FOREIGN_STATE")
    home = snapshot.home
    if home.state is QueenHomeStateKindV1.FOREIGN:
        _raise("RQ_E_FOREIGN_STATE")
    if home.state is QueenHomeStateKindV1.OWNED and (home.owner_principal_id != manifest.lease_binding.owner_principal_id or home.home_path != manifest.home_path):
        _raise("RQ_E_FOREIGN_STATE")
    active = (snapshot.active_topic_principal_id, snapshot.active_topic_home_path, snapshot.active_topic_lease_id)
    expected_active = (manifest.lease_binding.owner_principal_id, manifest.home_path, manifest.lease_binding.lease_id)
    if snapshot.conflicting_write_paths or (any(item is not None for item in active) and active != expected_active):
        _raise("RQ_E_BUS_TOPIC_CONFLICT")
    if not snapshot.bus_available:
        _raise("RQ_E_BUS_UNAVAILABLE")
    if not snapshot.lease_active or snapshot.observed_lease_binding_digest != manifest.lease_binding.binding_digest or snapshot.observed_bus_cursor_sha256 != manifest.resume_capsule.bus_cursor_sha256:
        _raise("RQ_E_RESUME_STALE")
    if not snapshot.account_available or snapshot.observed_account_binding_sha256 != manifest.resume_capsule.account_binding_sha256:
        _raise("RQ_E_ACCOUNT_UNAVAILABLE")


def _inspect(operations: RemoteQueenHomeOperations, manifest: RemoteQueenHomeManifestV1, error_code: str) -> QueenHomeSnapshotV1:
    try:
        inspect = operations.inspect
        if not callable(inspect):
            _raise(error_code)
        return inspect(manifest)
    except RemoteQueenBootstrapError:
        _raise(error_code)
    except Exception:
        _raise(error_code)
    raise RemoteQueenBootstrapError(error_code)


def _make_plan(manifest: RemoteQueenHomeManifestV1, before: QueenHomeSnapshotV1, action: QueenHomeActionV1 | None) -> RemoteQueenHomePlanV1:
    before_digest = queen_home_snapshot_digest(before)
    payload = {
        "schema_version": REMOTE_QUEEN_HOME_PLAN_SCHEMA,
        "manifest": manifest,
        "before": before,
        "before_digest": before_digest,
        "action": action,
        "remove_own_home_on_rollback": action is QueenHomeActionV1.CREATE_HOME,
        "preserve_repo_on_rollback": True,
        "preserve_vault_on_rollback": True,
        "preserve_hive_state_on_rollback": True,
    }
    return RemoteQueenHomePlanV1(**payload, plan_digest=_digest_payload(payload))


def plan_remote_queen_home(
    manifest: RemoteQueenHomeManifestV1,
    operations: RemoteQueenHomeOperations,
) -> RemoteQueenHomePlanV1:
    _validate_manifest_input(manifest)
    snapshot = _inspect(operations, manifest, "RQ_E_RESUME_STALE")
    try:
        _validate_snapshot(snapshot)
    except RemoteQueenBootstrapError:
        _raise("RQ_E_FOREIGN_STATE")
    _gate_snapshot(manifest, snapshot)
    if _fully_absent(manifest, snapshot):
        return _make_plan(manifest, snapshot, QueenHomeActionV1.CREATE_HOME)
    if _fully_owned(manifest, snapshot):
        return _make_plan(manifest, snapshot, None)
    _raise("RQ_E_RESUME_STALE")
    raise RemoteQueenBootstrapError("RQ_E_RESUME_STALE")


def apply_remote_queen_home(
    request: ApplyRemoteQueenHomeRequestV1,
    operations: RemoteQueenHomeOperations,
) -> RemoteQueenHomeApplyResultV1:
    if type(request) is not ApplyRemoteQueenHomeRequestV1:
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_request_plan(request.plan, request.expected_plan_digest)
    if request.expected_plan_digest != request.plan.plan_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")
    plan = request.plan
    if plan.action is None:
        return RemoteQueenHomeApplyResultV1(False, plan.before, None)
    current = _inspect(operations, plan.manifest, "RQ_E_PLAN_INCONSISTENT")
    try:
        _validate_snapshot(current)
    except RemoteQueenBootstrapError:
        _raise("RQ_E_PLAN_INCONSISTENT")
    if queen_home_snapshot_digest(current) != plan.before_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_request_plan(request.plan, request.expected_plan_digest)
    if request.expected_plan_digest != request.plan.plan_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")
    try:
        materialize = operations.materialize_home
        if not callable(materialize):
            _raise("RQ_E_PLAN_INCONSISTENT")
        journal = materialize(plan)
    except RemoteQueenBootstrapError:
        _raise("RQ_E_PLAN_INCONSISTENT")
    except Exception:
        _raise("RQ_E_PLAN_INCONSISTENT")
    try:
        _validate_journal(journal)
    except RemoteQueenBootstrapError:
        _raise("RQ_E_PLAN_INCONSISTENT")
    if journal.before_digest != plan.before_digest or journal.created_generation != plan.manifest.desired_generation.generation or journal.created_home_path != plan.manifest.home_path:
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_request_plan(request.plan, request.expected_plan_digest)
    if request.expected_plan_digest != request.plan.plan_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")
    resulting = _inspect(operations, plan.manifest, "RQ_E_RESUME_STALE")
    try:
        _validate_snapshot(resulting)
    except RemoteQueenBootstrapError:
        _raise("RQ_E_RESUME_STALE")
    if not _fully_owned(plan.manifest, resulting) or queen_home_snapshot_digest(resulting) != journal.resulting_snapshot_digest:
        _raise("RQ_E_RESUME_STALE")
    return RemoteQueenHomeApplyResultV1(True, resulting, journal)


def verify_remote_queen_home(
    request: VerifyRemoteQueenHomeRequestV1,
    operations: RemoteQueenHomeOperations,
) -> RemoteQueenHomeVerifyResultV1:
    if type(request) is not VerifyRemoteQueenHomeRequestV1:
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_request_plan(request.plan, request.expected_plan_digest)
    if request.expected_plan_digest != request.plan.plan_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")
    snapshot = _inspect(operations, request.plan.manifest, "RQ_E_RESUME_STALE")
    _gate_snapshot(request.plan.manifest, snapshot)
    if not _fully_owned(request.plan.manifest, snapshot):
        _raise("RQ_E_RESUME_STALE")
    return RemoteQueenHomeVerifyResultV1(True, snapshot)


def rollback_remote_queen_home(
    request: RollbackRemoteQueenHomeRequestV1,
    operations: RemoteQueenHomeOperations,
) -> RemoteQueenHomeRollbackResultV1:
    if type(request) is not RollbackRemoteQueenHomeRequestV1:
        _raise("RQ_E_PLAN_INCONSISTENT")
    _validate_request_plan(request.plan, request.expected_plan_digest)
    if request.expected_plan_digest != request.plan.plan_digest:
        _raise("RQ_E_PLAN_INCONSISTENT")
    plan = request.plan
    if plan.action is None:
        if request.journal is not None:
            _raise("RQ_E_ROLLBACK_DRIFT")
        return RemoteQueenHomeRollbackResultV1(False, plan.before)
    journal = request.journal
    if journal is None:
        _raise("RQ_E_ROLLBACK_DRIFT")
    try:
        _validate_journal(journal)
    except RemoteQueenBootstrapError:
        _raise("RQ_E_ROLLBACK_DRIFT")
    if journal.before_digest != plan.before_digest or journal.created_generation != plan.manifest.desired_generation.generation or journal.created_home_path != plan.manifest.home_path:
        _raise("RQ_E_ROLLBACK_DRIFT")
    current = _inspect(operations, plan.manifest, "RQ_E_ROLLBACK_DRIFT")
    try:
        _validate_snapshot(current)
    except RemoteQueenBootstrapError:
        _raise("RQ_E_ROLLBACK_DRIFT")
    if not _fully_owned(plan.manifest, current) or queen_home_snapshot_digest(current) != journal.resulting_snapshot_digest:
        _raise("RQ_E_ROLLBACK_DRIFT")
    try:
        _validate_request_plan(request.plan, request.expected_plan_digest)
        if request.expected_plan_digest != request.plan.plan_digest:
            _raise("RQ_E_ROLLBACK_DRIFT")
    except RemoteQueenBootstrapError:
        _raise("RQ_E_ROLLBACK_DRIFT")
    try:
        rollback = operations.rollback_home
        if not callable(rollback):
            _raise("RQ_E_ROLLBACK_DRIFT")
        rollback(plan, journal)
    except RemoteQueenBootstrapError:
        _raise("RQ_E_ROLLBACK_DRIFT")
    except Exception:
        _raise("RQ_E_ROLLBACK_DRIFT")
    try:
        _validate_request_plan(request.plan, request.expected_plan_digest)
        if request.expected_plan_digest != request.plan.plan_digest:
            _raise("RQ_E_ROLLBACK_DRIFT")
    except RemoteQueenBootstrapError:
        _raise("RQ_E_ROLLBACK_DRIFT")
    after = _inspect(operations, plan.manifest, "RQ_E_ROLLBACK_DRIFT")
    try:
        _validate_snapshot(after)
    except RemoteQueenBootstrapError:
        _raise("RQ_E_ROLLBACK_DRIFT")
    if queen_home_snapshot_digest(after) != plan.before_digest or canonical_json_bytes(after) != canonical_json_bytes(plan.before):
        _raise("RQ_E_ROLLBACK_DRIFT")
    return RemoteQueenHomeRollbackResultV1(True, after)
