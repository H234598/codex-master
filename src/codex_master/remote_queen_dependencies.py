import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from codex_master.remote_queen_bootstrap import (
    HostFactsV1,
    ManifestGenerationV1,
    PackagePlanV1,
    RemoteQueenBootstrapError,
    package_plan_for,
)


class DependencyOwnershipV1(str, Enum):
    ABSENT = "absent"
    OWNED = "owned"
    FOREIGN = "foreign"


class DependencyActionV1(str, Enum):
    INSTALL_SYSTEM_PACKAGES = "install-system-packages"
    CREATE_PYTHON_ENVIRONMENT = "create-python-environment"
    REPLACE_PYTHON_ENVIRONMENT = "replace-python-environment"


class PythonImportIdV1(str, Enum):
    YAML = "yaml"
    DBUS = "dbus"
    GI = "gi"
    GOOGLE_AUTH = "google.auth"
    GOOGLE_AUTH_OAUTHLIB = "google_auth_oauthlib"


_BASE_DISTRIBUTIONS = ("PyYAML", "dbus-python", "PyGObject")
_GOOGLE_DISTRIBUTIONS = ("google-auth", "google-auth-oauthlib")
_DISTRIBUTION_IMPORTS = {
    "PyYAML": (PythonImportIdV1.YAML,),
    "dbus-python": (PythonImportIdV1.DBUS,),
    "PyGObject": (PythonImportIdV1.GI,),
    "google-auth": (PythonImportIdV1.GOOGLE_AUTH,),
    "google-auth-oauthlib": (PythonImportIdV1.GOOGLE_AUTH_OAUTHLIB,),
}
_PIN_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,2}\Z")
_PYTHON_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?\Z"
)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _inconsistent() -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")


def _attestation() -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError("RQ_E_DEPENDENCY_ATTESTATION")


def _foreign() -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError("RQ_E_FOREIGN_STATE")


def _operation_error() -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError("RQ_E_DEPENDENCY_OPERATION")


def _rollback_drift() -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError("RQ_E_ROLLBACK_DRIFT")


def _exact(value: object, expected: type[object]) -> bool:
    return type(value) is expected


def _valid_digest(value: object) -> bool:
    return _exact(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None


def _valid_pin_version(value: object) -> bool:
    return _exact(value, str) and _PIN_PATTERN.fullmatch(value) is not None


def _valid_text_version(value: object) -> bool:
    return (
        _exact(value, str)
        and bool(value)
        and len(value) <= 128
        and all(32 <= ord(character) < 127 for character in value)
    )


def _valid_python_version(value: object) -> bool:
    return _exact(value, str) and _PYTHON_PATTERN.fullmatch(value) is not None


def _python_is_supported(value: str) -> bool:
    try:
        parts = tuple(int(part) for part in value.split("."))
    except ValueError:
        return False
    return parts[0] > 3 or (parts[0] == 3 and parts[1] >= 11)


def _version_at_least(value: str, minimum: tuple[int, int]) -> bool:
    try:
        parts = tuple(int(part) for part in value.split("."))
    except ValueError:
        return False
    return parts + (0, 0) >= minimum + (0,)


def _unique(values: tuple[object, ...]) -> bool:
    return len(values) == len(set(values))


def _json_digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _distribution_fact_is_valid(pin: "PythonDistributionPinV1") -> bool:
    if pin.distribution not in _DISTRIBUTION_IMPORTS:
        return False
    expected_imports = _DISTRIBUTION_IMPORTS[pin.distribution]
    if pin.imports != expected_imports or not _valid_pin_version(pin.version):
        return False
    return True


def _distribution_pin_is_valid(pin: "PythonDistributionPinV1") -> bool:
    if not _distribution_fact_is_valid(pin):
        return False
    if pin.distribution == "dbus-python":
        return pin.version == "1.4.0"
    if pin.distribution == "PyGObject":
        return pin.version == "3.56.3"
    if pin.distribution == "PyYAML":
        return _version_at_least(pin.version, (6, 0))
    if pin.distribution == "google-auth":
        return _version_at_least(pin.version, (2, 35))
    if pin.distribution == "google-auth-oauthlib":
        return _version_at_least(pin.version, (1, 2))
    return False


@dataclass(frozen=True, slots=True)
class PythonDistributionPinV1:
    distribution: str
    version: str
    imports: tuple[PythonImportIdV1, ...]

    def __post_init__(self) -> None:
        if (
            not _exact(self.distribution, str)
            or not self.distribution
            or not _valid_pin_version(self.version)
            or not _exact(self.imports, tuple)
            or not all(
                _exact(item, PythonImportIdV1) for item in self.imports
            )
            or not _unique(tuple(self.imports))
            or self.distribution not in _DISTRIBUTION_IMPORTS
            or self.imports != _DISTRIBUTION_IMPORTS[self.distribution]
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class SystemPackageFactV1:
    name: str
    version: str | None

    def __post_init__(self) -> None:
        if (
            not _exact(self.name, str)
            or not self.name
            or (self.version is not None and not _valid_text_version(self.version))
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class PythonEnvironmentFactV1:
    ownership: DependencyOwnershipV1
    generation: str | None
    python_version: str | None
    distributions: tuple[PythonDistributionPinV1, ...]
    imports_available: tuple[PythonImportIdV1, ...]

    def __post_init__(self) -> None:
        if (
            not _exact(self.ownership, DependencyOwnershipV1)
            or (self.generation is not None and not _exact(self.generation, str))
            or (
                self.python_version is not None
                and not _exact(self.python_version, str)
            )
            or not _exact(self.distributions, tuple)
            or not _exact(self.imports_available, tuple)
            or not all(
                _exact(item, PythonDistributionPinV1)
                for item in self.distributions
            )
            or not all(
                _exact(item, PythonImportIdV1)
                for item in self.imports_available
            )
            or not _unique(tuple(item.distribution for item in self.distributions))
            or not _unique(tuple(self.imports_available))
        ):
            raise _inconsistent()
        if self.ownership is DependencyOwnershipV1.ABSENT and (
            self.generation is not None
            or self.distributions
            or self.imports_available
        ):
            raise _inconsistent()
        if self.ownership is DependencyOwnershipV1.OWNED and (
            self.generation is None or not self.generation
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class DependencySnapshotV1:
    package_manager: str
    packages: tuple[SystemPackageFactV1, ...]
    environment: PythonEnvironmentFactV1
    noninteractive_sudo_available: bool

    def __post_init__(self) -> None:
        if (
            not _exact(self.package_manager, str)
            or not self.package_manager
            or not _exact(self.packages, tuple)
            or not all(_exact(item, SystemPackageFactV1) for item in self.packages)
            or not _unique(tuple(item.name for item in self.packages))
            or not _exact(self.environment, PythonEnvironmentFactV1)
            or not _exact(self.noninteractive_sudo_available, bool)
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class RemoteQueenDependencyManifestV1:
    schema_version: str
    desired_generation: ManifestGenerationV1
    host_facts: HostFactsV1
    package_plan: PackagePlanV1
    minimum_python_version: str
    environment_kind: str
    python_distributions: tuple[PythonDistributionPinV1, ...]
    required_imports: tuple[PythonImportIdV1, ...]
    google_identity_required: bool
    manifest_digest: str

    def __post_init__(self) -> None:
        if (
            not _exact(self.schema_version, str)
            or not _exact(self.desired_generation, ManifestGenerationV1)
            or not _exact(self.host_facts, HostFactsV1)
            or not _exact(self.package_plan, PackagePlanV1)
            or not _exact(self.minimum_python_version, str)
            or not _exact(self.environment_kind, str)
            or not _exact(self.python_distributions, tuple)
            or not all(
                _exact(item, PythonDistributionPinV1)
                for item in self.python_distributions
            )
            or not _unique(
                tuple(item.distribution for item in self.python_distributions)
            )
            or not _exact(self.required_imports, tuple)
            or not all(
                _exact(item, PythonImportIdV1) for item in self.required_imports
            )
            or not _unique(tuple(self.required_imports))
            or not _exact(self.google_identity_required, bool)
            or not _exact(self.manifest_digest, str)
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class DependencyPlanStepV1:
    action: DependencyActionV1
    packages: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not _exact(self.action, DependencyActionV1)
            or not _exact(self.packages, tuple)
            or not all(_exact(item, str) and item for item in self.packages)
            or not _unique(tuple(self.packages))
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class RemoteQueenDependencyPlanV1:
    schema_version: str
    manifest: RemoteQueenDependencyManifestV1
    before: DependencySnapshotV1
    before_digest: str
    steps: tuple[DependencyPlanStepV1, ...]
    rollback_packages: tuple[str, ...]
    rollback_environment_generation: str | None
    privilege_required: bool
    plan_digest: str

    def __post_init__(self) -> None:
        if (
            not _exact(self.schema_version, str)
            or not _exact(self.manifest, RemoteQueenDependencyManifestV1)
            or not _exact(self.before, DependencySnapshotV1)
            or not _exact(self.before_digest, str)
            or not _exact(self.steps, tuple)
            or not all(_exact(item, DependencyPlanStepV1) for item in self.steps)
            or not _exact(self.rollback_packages, tuple)
            or not all(
                _exact(item, str) and item for item in self.rollback_packages
            )
            or not _unique(tuple(self.rollback_packages))
            or (
                self.rollback_environment_generation is not None
                and not _exact(self.rollback_environment_generation, str)
            )
            or not _exact(self.privilege_required, bool)
            or not _exact(self.plan_digest, str)
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class DependencyApplyRequestV1:
    generation: str
    manifest_digest: str
    plan_digest: str

    def __post_init__(self) -> None:
        if not all(
            _exact(item, str)
            for item in (self.generation, self.manifest_digest, self.plan_digest)
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class DependencyApplyJournalV1:
    schema_version: str
    generation: str
    manifest_digest: str
    plan_digest: str
    installed_packages: tuple[str, ...]
    prior_environment_generation: str | None
    resulting_snapshot_digest: str

    def __post_init__(self) -> None:
        if (
            not _exact(self.schema_version, str)
            or not _exact(self.generation, str)
            or not _exact(self.manifest_digest, str)
            or not _exact(self.plan_digest, str)
            or not _exact(self.installed_packages, tuple)
            or not all(_exact(item, str) and item for item in self.installed_packages)
            or not _unique(tuple(self.installed_packages))
            or (
                self.prior_environment_generation is not None
                and not _exact(self.prior_environment_generation, str)
            )
            or not _exact(self.resulting_snapshot_digest, str)
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class DependencyApplyResultV1:
    changed: bool
    journal: DependencyApplyJournalV1 | None
    snapshot_digest: str

    def __post_init__(self) -> None:
        if (
            not _exact(self.changed, bool)
            or (
                self.journal is not None
                and not _exact(self.journal, DependencyApplyJournalV1)
            )
            or not _exact(self.snapshot_digest, str)
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class DependencyVerifyRequestV1:
    generation: str
    manifest_digest: str

    def __post_init__(self) -> None:
        if not _exact(self.generation, str) or not _exact(self.manifest_digest, str):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class DependencyVerifyResultV1:
    snapshot_digest: str

    def __post_init__(self) -> None:
        if not _exact(self.snapshot_digest, str):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class DependencyRollbackRequestV1:
    generation: str
    manifest_digest: str
    plan_digest: str

    def __post_init__(self) -> None:
        if not all(
            _exact(item, str)
            for item in (self.generation, self.manifest_digest, self.plan_digest)
        ):
            raise _inconsistent()


@dataclass(frozen=True, slots=True)
class DependencyRollbackResultV1:
    restored_snapshot_digest: str

    def __post_init__(self) -> None:
        if not _exact(self.restored_snapshot_digest, str):
            raise _inconsistent()


class RemoteQueenDependencyOperations(Protocol):
    def inspect(
        self, manifest: RemoteQueenDependencyManifestV1
    ) -> DependencySnapshotV1: ...

    def apply(
        self, plan: RemoteQueenDependencyPlanV1
    ) -> DependencyApplyJournalV1: ...

    def rollback(
        self,
        plan: RemoteQueenDependencyPlanV1,
        journal: DependencyApplyJournalV1,
    ) -> None: ...


def _inspect_operation(
    operations: RemoteQueenDependencyOperations,
    manifest: RemoteQueenDependencyManifestV1,
) -> DependencySnapshotV1:
    failed = False
    snapshot = None
    try:
        snapshot = operations.inspect(manifest)
    except Exception:
        failed = True
    if failed:
        raise _operation_error()
    return snapshot


def _apply_operation(
    operations: RemoteQueenDependencyOperations,
    plan: RemoteQueenDependencyPlanV1,
) -> DependencyApplyJournalV1:
    failed = False
    journal = None
    try:
        journal = operations.apply(plan)
    except Exception:
        failed = True
    if failed:
        raise _operation_error()
    return journal


def _rollback_operation(
    operations: RemoteQueenDependencyOperations,
    plan: RemoteQueenDependencyPlanV1,
    journal: DependencyApplyJournalV1,
) -> None:
    failed = False
    try:
        operations.rollback(plan, journal)
    except Exception:
        failed = True
    if failed:
        raise _operation_error()


def _canonical_pins(
    pins: tuple[PythonDistributionPinV1, ...], google_identity_required: bool
) -> tuple[PythonDistributionPinV1, ...]:
    if not _exact(pins, tuple) or not _exact(google_identity_required, bool):
        raise _inconsistent()
    expected_names = _BASE_DISTRIBUTIONS + (
        _GOOGLE_DISTRIBUTIONS if google_identity_required else ()
    )
    by_name: dict[str, PythonDistributionPinV1] = {}
    for pin in pins:
        if not _exact(pin, PythonDistributionPinV1):
            raise _inconsistent()
        if pin.distribution not in expected_names or pin.distribution in by_name:
            raise _inconsistent()
        if not _distribution_pin_is_valid(pin):
            raise _inconsistent()
        by_name[pin.distribution] = pin
    if tuple(by_name) != tuple(expected_names) and set(by_name) != set(expected_names):
        raise _inconsistent()
    if set(by_name) != set(expected_names):
        raise _inconsistent()
    canonical = tuple(by_name[name] for name in expected_names)
    return canonical


def _manifest_payload(
    *,
    schema_version: str,
    desired_generation: ManifestGenerationV1,
    host_facts: HostFactsV1,
    package_plan: PackagePlanV1,
    minimum_python_version: str,
    environment_kind: str,
    python_distributions: tuple[PythonDistributionPinV1, ...],
    required_imports: tuple[PythonImportIdV1, ...],
    google_identity_required: bool,
    manifest_digest: str | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": schema_version,
        "desired_generation": {
            "generation": desired_generation.generation,
            "sha256": desired_generation.sha256,
        },
        "host_facts": {
            "distribution_id": host_facts.distribution_id,
            "distribution_version": host_facts.distribution_version,
            "architecture": host_facts.architecture,
            "package_manager": host_facts.package_manager,
        },
        "package_plan": {
            "manager": package_plan.manager,
            "packages": list(package_plan.packages),
        },
        "minimum_python_version": minimum_python_version,
        "environment_kind": environment_kind,
        "python_distributions": [
            {
                "distribution": item.distribution,
                "version": item.version,
                "imports": [import_id.value for import_id in item.imports],
            }
            for item in python_distributions
        ],
        "google_identity_required": google_identity_required,
    }
    if manifest_digest is not None:
        payload["manifest_digest"] = manifest_digest
    return payload


def _validate_manifest(manifest: RemoteQueenDependencyManifestV1) -> None:
    if not _exact(manifest, RemoteQueenDependencyManifestV1):
        raise _inconsistent()
    if manifest.schema_version != "RemoteQueenDependencyManifestV1":
        raise _inconsistent()
    if manifest.minimum_python_version != "3.11":
        raise _inconsistent()
    if manifest.environment_kind != "venv":
        raise _inconsistent()
    expected_package_plan = package_plan_for(manifest.host_facts)
    if manifest.package_plan != expected_package_plan:
        raise _inconsistent()
    canonical = _canonical_pins(
        manifest.python_distributions, manifest.google_identity_required
    )
    if canonical != manifest.python_distributions:
        raise _inconsistent()
    expected_imports = tuple(
        import_id
        for pin in canonical
        for import_id in pin.imports
    )
    if manifest.required_imports != expected_imports:
        raise _inconsistent()
    if not _valid_digest(manifest.manifest_digest):
        raise _inconsistent()
    payload = _manifest_payload(
        schema_version=manifest.schema_version,
        desired_generation=manifest.desired_generation,
        host_facts=manifest.host_facts,
        package_plan=manifest.package_plan,
        minimum_python_version=manifest.minimum_python_version,
        environment_kind=manifest.environment_kind,
        python_distributions=manifest.python_distributions,
        required_imports=manifest.required_imports,
        google_identity_required=manifest.google_identity_required,
        manifest_digest=None,
    )
    if _json_digest(payload) != manifest.manifest_digest:
        raise _inconsistent()


def build_remote_queen_dependency_manifest(
    *,
    host_facts: HostFactsV1,
    desired_generation: ManifestGenerationV1,
    python_distributions: tuple[PythonDistributionPinV1, ...],
    google_identity_required: bool,
) -> RemoteQueenDependencyManifestV1:
    if (
        not _exact(host_facts, HostFactsV1)
        or not _exact(desired_generation, ManifestGenerationV1)
        or not _exact(python_distributions, tuple)
        or not _exact(google_identity_required, bool)
    ):
        raise _inconsistent()
    package_plan = package_plan_for(host_facts)
    canonical = _canonical_pins(python_distributions, google_identity_required)
    required_imports = tuple(
        import_id for pin in canonical for import_id in pin.imports
    )
    payload = _manifest_payload(
        schema_version="RemoteQueenDependencyManifestV1",
        desired_generation=desired_generation,
        host_facts=host_facts,
        package_plan=package_plan,
        minimum_python_version="3.11",
        environment_kind="venv",
        python_distributions=canonical,
        required_imports=required_imports,
        google_identity_required=google_identity_required,
        manifest_digest=None,
    )
    manifest = RemoteQueenDependencyManifestV1(
        schema_version="RemoteQueenDependencyManifestV1",
        desired_generation=desired_generation,
        host_facts=host_facts,
        package_plan=package_plan,
        minimum_python_version="3.11",
        environment_kind="venv",
        python_distributions=canonical,
        required_imports=required_imports,
        google_identity_required=google_identity_required,
        manifest_digest=_json_digest(payload),
    )
    _validate_manifest(manifest)
    return manifest


def dependency_manifest_as_dict(
    manifest: RemoteQueenDependencyManifestV1,
) -> dict[str, object]:
    _validate_manifest(manifest)
    return _manifest_payload(
        schema_version=manifest.schema_version,
        desired_generation=manifest.desired_generation,
        host_facts=manifest.host_facts,
        package_plan=manifest.package_plan,
        minimum_python_version=manifest.minimum_python_version,
        environment_kind=manifest.environment_kind,
        python_distributions=manifest.python_distributions,
        required_imports=manifest.required_imports,
        google_identity_required=manifest.google_identity_required,
        manifest_digest=manifest.manifest_digest,
    )


def _snapshot_payload(snapshot: DependencySnapshotV1) -> dict[str, object]:
    return {
        "package_manager": snapshot.package_manager,
        "packages": [
            {"name": item.name, "version": item.version}
            for item in snapshot.packages
        ],
        "environment": {
            "ownership": snapshot.environment.ownership.value,
            "generation": snapshot.environment.generation,
            "python_version": snapshot.environment.python_version,
            "distributions": [
                {
                    "distribution": item.distribution,
                    "version": item.version,
                    "imports": [import_id.value for import_id in item.imports],
                }
                for item in snapshot.environment.distributions
            ],
            "imports_available": [
                import_id.value
                for import_id in snapshot.environment.imports_available
            ],
        },
        "noninteractive_sudo_available": snapshot.noninteractive_sudo_available,
    }


def _snapshot_digest(snapshot: DependencySnapshotV1) -> str:
    return _json_digest(_snapshot_payload(snapshot))


def _validate_snapshot(
    manifest: RemoteQueenDependencyManifestV1,
    snapshot: DependencySnapshotV1,
    *,
    desired: bool,
) -> None:
    if not _exact(snapshot, DependencySnapshotV1):
        raise _inconsistent()
    environment = snapshot.environment
    if environment.ownership is DependencyOwnershipV1.FOREIGN:
        raise _foreign()
    if snapshot.package_manager != manifest.package_plan.manager:
        raise _inconsistent()
    expected_names = manifest.package_plan.packages
    actual_names = tuple(item.name for item in snapshot.packages)
    if actual_names != expected_names:
        raise _inconsistent()
    for item in snapshot.packages:
        if item.version is not None and not _valid_text_version(item.version):
            raise _inconsistent()
    if environment.ownership is DependencyOwnershipV1.ABSENT:
        if (
            environment.generation is not None
            or environment.distributions
            or environment.imports_available
        ):
            raise _inconsistent()
        if (
            environment.python_version is None
            or not _valid_python_version(environment.python_version)
            or not _python_is_supported(environment.python_version)
        ):
            if desired:
                raise _attestation()
            raise RemoteQueenBootstrapError("RQ_E_HOST_UNSUPPORTED")
        if desired:
            raise _attestation()
        return
    if environment.ownership is not DependencyOwnershipV1.OWNED:
        raise _inconsistent()
    if environment.generation is None or not environment.generation:
        raise _inconsistent()
    if (
        environment.python_version is None
        or not _valid_python_version(environment.python_version)
        or not _python_is_supported(environment.python_version)
    ):
        if desired:
            raise _attestation()
        raise RemoteQueenBootstrapError("RQ_E_HOST_UNSUPPORTED")
    actual_distributions = tuple(
        item.distribution for item in environment.distributions
    )
    allowed_distributions = (
        _BASE_DISTRIBUTIONS,
        _BASE_DISTRIBUTIONS + _GOOGLE_DISTRIBUTIONS,
    )
    if actual_distributions not in allowed_distributions:
        raise _attestation()
    expected_fact_imports = tuple(
        import_id
        for distribution in actual_distributions
        for import_id in _DISTRIBUTION_IMPORTS[distribution]
    )
    if environment.imports_available != expected_fact_imports:
        raise _attestation()
    for item in environment.distributions:
        if not _distribution_fact_is_valid(item):
            raise _attestation()
    if desired:
        if any(item.version is None for item in snapshot.packages):
            raise _attestation()
        if environment.generation != manifest.desired_generation.generation:
            raise _attestation()
        expected_distributions = tuple(
            item.distribution for item in manifest.python_distributions
        )
        if actual_distributions != expected_distributions:
            raise _attestation()
        if environment.imports_available != manifest.required_imports:
            raise _attestation()
        if environment.distributions != manifest.python_distributions:
            raise _attestation()
    elif environment.generation == manifest.desired_generation.generation:
        expected_distributions = tuple(
            item.distribution for item in manifest.python_distributions
        )
        if (
            actual_distributions != expected_distributions
            or environment.imports_available != manifest.required_imports
            or not _desired_environment(manifest, snapshot)
        ):
            raise _attestation()


def _desired_environment(
    manifest: RemoteQueenDependencyManifestV1,
    snapshot: DependencySnapshotV1,
) -> bool:
    if snapshot.environment.ownership is not DependencyOwnershipV1.OWNED:
        return False
    return (
        all(item.version is not None for item in snapshot.packages)
        and snapshot.environment.generation
        == manifest.desired_generation.generation
        and snapshot.environment.distributions == manifest.python_distributions
        and snapshot.environment.imports_available == manifest.required_imports
    )


def _expected_plan_fields(
    manifest: RemoteQueenDependencyManifestV1,
    before: DependencySnapshotV1,
) -> tuple[
    tuple[DependencyPlanStepV1, ...],
    tuple[str, ...],
    str | None,
    bool,
]:
    _validate_snapshot(manifest, before, desired=False)
    missing = tuple(item.name for item in before.packages if item.version is None)
    steps: list[DependencyPlanStepV1] = []
    if missing:
        steps.append(
            DependencyPlanStepV1(
                action=DependencyActionV1.INSTALL_SYSTEM_PACKAGES,
                packages=missing,
            )
        )
    environment = before.environment
    rollback_generation = None
    if environment.ownership is DependencyOwnershipV1.ABSENT:
        steps.append(
            DependencyPlanStepV1(
                action=DependencyActionV1.CREATE_PYTHON_ENVIRONMENT,
                packages=(),
            )
        )
    elif environment.generation != manifest.desired_generation.generation:
        rollback_generation = environment.generation
        steps.append(
            DependencyPlanStepV1(
                action=DependencyActionV1.REPLACE_PYTHON_ENVIRONMENT,
                packages=(),
            )
        )
    elif not _desired_environment(manifest, before):
        raise _attestation()
    return tuple(steps), missing, rollback_generation, bool(missing)


def _plan_payload(
    plan: RemoteQueenDependencyPlanV1, plan_digest: str | None
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": plan.schema_version,
        "manifest": _manifest_payload(
            schema_version=plan.manifest.schema_version,
            desired_generation=plan.manifest.desired_generation,
            host_facts=plan.manifest.host_facts,
            package_plan=plan.manifest.package_plan,
            minimum_python_version=plan.manifest.minimum_python_version,
            environment_kind=plan.manifest.environment_kind,
            python_distributions=plan.manifest.python_distributions,
            required_imports=plan.manifest.required_imports,
            google_identity_required=plan.manifest.google_identity_required,
            manifest_digest=plan.manifest.manifest_digest,
        ),
        "before": _snapshot_payload(plan.before),
        "before_digest": plan.before_digest,
        "steps": [
            {"action": step.action.value, "packages": list(step.packages)}
            for step in plan.steps
        ],
        "rollback": {
            "remove_packages": list(plan.rollback_packages),
            "restore_environment_generation": plan.rollback_environment_generation,
        },
        "privilege_required": plan.privilege_required,
    }
    if plan_digest is not None:
        payload["plan_digest"] = plan_digest
    return payload


def _validate_plan(plan: RemoteQueenDependencyPlanV1) -> None:
    if not _exact(plan, RemoteQueenDependencyPlanV1):
        raise _inconsistent()
    if plan.schema_version != "RemoteQueenDependencyPlanV1":
        raise _inconsistent()
    _validate_manifest(plan.manifest)
    if not _valid_digest(plan.before_digest) or not _valid_digest(plan.plan_digest):
        raise _inconsistent()
    expected_steps, missing, rollback_generation, privilege = _expected_plan_fields(
        plan.manifest, plan.before
    )
    if (
        plan.steps != expected_steps
        or plan.rollback_packages != missing
        or plan.rollback_environment_generation != rollback_generation
        or plan.privilege_required is not privilege
        or _snapshot_digest(plan.before) != plan.before_digest
    ):
        raise _inconsistent()
    payload = _plan_payload(plan, None)
    if _json_digest(payload) != plan.plan_digest:
        raise _inconsistent()


def plan_remote_queen_dependencies(
    *,
    manifest: RemoteQueenDependencyManifestV1,
    operations: RemoteQueenDependencyOperations,
) -> RemoteQueenDependencyPlanV1:
    _validate_manifest(manifest)
    before = _inspect_operation(operations, manifest)
    _validate_snapshot(manifest, before, desired=False)
    steps, missing, rollback_generation, privilege = _expected_plan_fields(
        manifest, before
    )
    before_digest = _snapshot_digest(before)
    provisional = RemoteQueenDependencyPlanV1(
        schema_version="RemoteQueenDependencyPlanV1",
        manifest=manifest,
        before=before,
        before_digest=before_digest,
        steps=steps,
        rollback_packages=missing,
        rollback_environment_generation=rollback_generation,
        privilege_required=privilege,
        plan_digest="sha256:" + "0" * 64,
    )
    plan_digest = _json_digest(_plan_payload(provisional, None))
    return RemoteQueenDependencyPlanV1(
        schema_version=provisional.schema_version,
        manifest=provisional.manifest,
        before=provisional.before,
        before_digest=provisional.before_digest,
        steps=provisional.steps,
        rollback_packages=provisional.rollback_packages,
        rollback_environment_generation=provisional.rollback_environment_generation,
        privilege_required=provisional.privilege_required,
        plan_digest=plan_digest,
    )


def dependency_plan_as_dict(
    plan: RemoteQueenDependencyPlanV1,
) -> dict[str, object]:
    _validate_plan(plan)
    return _plan_payload(plan, plan.plan_digest)


def _validate_apply_request(
    plan: RemoteQueenDependencyPlanV1, request: DependencyApplyRequestV1
) -> None:
    if not _exact(request, DependencyApplyRequestV1):
        raise _inconsistent()
    if (
        request.generation != plan.manifest.desired_generation.generation
        or request.manifest_digest != plan.manifest.manifest_digest
        or request.plan_digest != plan.plan_digest
    ):
        raise _inconsistent()


def _validate_journal(
    plan: RemoteQueenDependencyPlanV1, journal: DependencyApplyJournalV1
) -> None:
    if not _exact(journal, DependencyApplyJournalV1):
        raise _inconsistent()
    if (
        journal.schema_version != "DependencyApplyJournalV1"
        or journal.generation != plan.manifest.desired_generation.generation
        or journal.manifest_digest != plan.manifest.manifest_digest
        or journal.plan_digest != plan.plan_digest
        or journal.installed_packages != plan.rollback_packages
        or journal.prior_environment_generation
        != plan.rollback_environment_generation
        or not _valid_digest(journal.resulting_snapshot_digest)
    ):
        raise _inconsistent()


def apply_remote_queen_dependencies(
    *,
    plan: RemoteQueenDependencyPlanV1,
    request: DependencyApplyRequestV1,
    operations: RemoteQueenDependencyOperations,
) -> DependencyApplyResultV1:
    _validate_plan(plan)
    _validate_apply_request(plan, request)
    current = _inspect_operation(operations, plan.manifest)
    _validate_snapshot(plan.manifest, current, desired=False)
    if _snapshot_digest(current) != plan.before_digest:
        raise _inconsistent()
    if not plan.steps:
        return DependencyApplyResultV1(
            changed=False,
            journal=None,
            snapshot_digest=_snapshot_digest(current),
        )
    if plan.privilege_required and not current.noninteractive_sudo_available:
        raise RemoteQueenBootstrapError("RQ_E_PRIVILEGE_REQUIRED")
    journal = _apply_operation(operations, plan)
    _validate_journal(plan, journal)
    after = _inspect_operation(operations, plan.manifest)
    _validate_snapshot(plan.manifest, after, desired=True)
    after_digest = _snapshot_digest(after)
    if journal.resulting_snapshot_digest != after_digest:
        raise _inconsistent()
    return DependencyApplyResultV1(
        changed=True,
        journal=journal,
        snapshot_digest=after_digest,
    )


def _validate_verify_request(
    manifest: RemoteQueenDependencyManifestV1, request: DependencyVerifyRequestV1
) -> None:
    if not _exact(request, DependencyVerifyRequestV1):
        raise _inconsistent()
    if (
        request.generation != manifest.desired_generation.generation
        or request.manifest_digest != manifest.manifest_digest
    ):
        raise _inconsistent()


def verify_remote_queen_dependencies(
    *,
    manifest: RemoteQueenDependencyManifestV1,
    request: DependencyVerifyRequestV1,
    operations: RemoteQueenDependencyOperations,
) -> DependencyVerifyResultV1:
    _validate_manifest(manifest)
    _validate_verify_request(manifest, request)
    snapshot = _inspect_operation(operations, manifest)
    _validate_snapshot(manifest, snapshot, desired=True)
    return DependencyVerifyResultV1(snapshot_digest=_snapshot_digest(snapshot))


def _validate_rollback_request(
    plan: RemoteQueenDependencyPlanV1, request: DependencyRollbackRequestV1
) -> None:
    if not _exact(request, DependencyRollbackRequestV1):
        raise _inconsistent()
    if (
        request.generation != plan.manifest.desired_generation.generation
        or request.manifest_digest != plan.manifest.manifest_digest
        or request.plan_digest != plan.plan_digest
    ):
        raise _inconsistent()


def rollback_remote_queen_dependencies(
    *,
    plan: RemoteQueenDependencyPlanV1,
    journal: DependencyApplyJournalV1,
    request: DependencyRollbackRequestV1,
    operations: RemoteQueenDependencyOperations,
) -> DependencyRollbackResultV1:
    _validate_plan(plan)
    _validate_rollback_request(plan, request)
    _validate_journal(plan, journal)
    current = _inspect_operation(operations, plan.manifest)
    try:
        _validate_snapshot(plan.manifest, current, desired=True)
    except RemoteQueenBootstrapError:
        raise _rollback_drift() from None
    if (
        _snapshot_digest(current) != journal.resulting_snapshot_digest
        or current.environment.generation
        != plan.manifest.desired_generation.generation
    ):
        raise _rollback_drift()
    _rollback_operation(operations, plan, journal)
    restored = _inspect_operation(operations, plan.manifest)
    try:
        _validate_snapshot(plan.manifest, restored, desired=False)
    except RemoteQueenBootstrapError:
        raise _rollback_drift() from None
    restored_digest = _snapshot_digest(restored)
    if restored_digest != plan.before_digest:
        raise _rollback_drift()
    return DependencyRollbackResultV1(restored_snapshot_digest=restored_digest)
