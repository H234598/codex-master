import ast
import dataclasses
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

import codex_master.remote_queen_dependencies as deps
from codex_master.remote_queen_bootstrap import (
    APT_PACKAGES,
    DNF_PACKAGES,
    HostFactsV1,
    ManifestGenerationV1,
    RemoteQueenBootstrapError,
    package_plan_for,
)


GENERATION = ManifestGenerationV1(
    generation="rq-dependencies-2026-08-29",
    sha256="b" * 64,
)
FEDORA = HostFactsV1(
    distribution_id="fedora",
    distribution_version="41",
    architecture="x86_64",
    package_manager="dnf",
)
UBUNTU = HostFactsV1(
    distribution_id="ubuntu",
    distribution_version="24.04",
    architecture="x86_64",
    package_manager="apt",
)
BASE_PINS = (
    ("PyYAML", "6.0.2", ("yaml",)),
    ("dbus-python", "1.4.0", ("dbus",)),
    ("PyGObject", "3.56.3", ("gi",)),
)
GOOGLE_PINS = (
    ("google-auth", "2.35.0", ("google.auth",)),
    ("google-auth-oauthlib", "1.2.0", ("google_auth_oauthlib",)),
)


def _pin(distribution, version, imports):
    return deps.PythonDistributionPinV1(
        distribution=distribution,
        version=version,
        imports=tuple(deps.PythonImportIdV1(item) for item in imports),
    )


def _pins(include_google=False):
    values = BASE_PINS + (GOOGLE_PINS if include_google else ())
    return tuple(_pin(*value) for value in values)


def _manifest(host_facts=FEDORA, include_google=False):
    return deps.build_remote_queen_dependency_manifest(
        host_facts=host_facts,
        desired_generation=GENERATION,
        python_distributions=_pins(include_google),
        google_identity_required=include_google,
    )


def _packages(manifest, *, missing=(), version="installed-1"):
    missing = set(missing)
    return tuple(
        deps.SystemPackageFactV1(
            name=name,
            version=None if name in missing else version,
        )
        for name in manifest.package_plan.packages
    )


def _environment(
    manifest,
    *,
    ownership=deps.DependencyOwnershipV1.ABSENT,
    generation=None,
    python_version="3.11.9",
    distributions=(),
    imports_available=(),
):
    return deps.PythonEnvironmentFactV1(
        ownership=ownership,
        generation=generation,
        python_version=python_version,
        distributions=tuple(distributions),
        imports_available=tuple(imports_available),
    )


def _absent_snapshot(manifest, *, missing=None, sudo=True):
    if missing is None:
        missing = manifest.package_plan.packages
    return deps.DependencySnapshotV1(
        package_manager=manifest.package_plan.manager,
        packages=_packages(manifest, missing=missing),
        environment=_environment(manifest),
        noninteractive_sudo_available=sudo,
    )


def _owned_snapshot(
    manifest,
    *,
    generation=None,
    python_version="3.11.9",
    distributions=None,
    imports_available=None,
    missing=(),
    sudo=True,
):
    if generation is None:
        generation = manifest.desired_generation.generation
    if distributions is None:
        distributions = manifest.python_distributions
    if imports_available is None:
        imports_available = manifest.required_imports
    return deps.DependencySnapshotV1(
        package_manager=manifest.package_plan.manager,
        packages=_packages(manifest, missing=missing),
        environment=_environment(
            manifest,
            ownership=deps.DependencyOwnershipV1.OWNED,
            generation=generation,
            python_version=python_version,
            distributions=distributions,
            imports_available=imports_available,
        ),
        noninteractive_sudo_available=sudo,
    )


def _snapshot_dict(snapshot):
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


def _digest(payload):
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _snapshot_digest(snapshot):
    return _digest(_snapshot_dict(snapshot))


def _request_for(plan):
    return deps.DependencyApplyRequestV1(
        generation=plan.manifest.desired_generation.generation,
        manifest_digest=plan.manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )


def _verify_request_for(manifest):
    return deps.DependencyVerifyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
    )


def _rollback_request_for(plan):
    return deps.DependencyRollbackRequestV1(
        generation=plan.manifest.desired_generation.generation,
        manifest_digest=plan.manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )


class FakeDependencyOperations:
    def __init__(self, snapshot, *, after=None, journal=None, apply_error=None):
        self.snapshot = snapshot
        self.after = after
        self.journal = journal
        self.apply_error = apply_error
        self.calls = []
        self.rollback_arguments = None

    def inspect(self, manifest):
        self.calls.append("inspect")
        return self.snapshot

    def apply(self, plan):
        self.calls.append("apply")
        if self.apply_error is not None:
            raise self.apply_error
        self.snapshot = self.after
        return self.journal

    def rollback(self, plan, journal):
        self.calls.append("rollback")
        self.rollback_arguments = (plan, journal)
        self.snapshot = self.after


def _journal(plan, snapshot):
    return deps.DependencyApplyJournalV1(
        schema_version="DependencyApplyJournalV1",
        generation=plan.manifest.desired_generation.generation,
        manifest_digest=plan.manifest.manifest_digest,
        plan_digest=plan.plan_digest,
        installed_packages=plan.rollback_packages,
        prior_environment_generation=plan.rollback_environment_generation,
        resulting_snapshot_digest=_snapshot_digest(snapshot),
    )


def _expected_manifest_dict(host_facts=FEDORA, include_google=False):
    package_plan = package_plan_for(host_facts)
    pins = BASE_PINS + (GOOGLE_PINS if include_google else ())
    imports = tuple(item[2][0] for item in pins)
    return {
        "schema_version": "RemoteQueenDependencyManifestV1",
        "desired_generation": {
            "generation": GENERATION.generation,
            "sha256": GENERATION.sha256,
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
        "minimum_python_version": "3.11",
        "environment_kind": "venv",
        "python_distributions": [
            {
                "distribution": distribution,
                "version": version,
                "imports": list(imports_for),
            }
            for distribution, version, imports_for in pins
        ],
        "required_imports": list(imports),
        "google_identity_required": include_google,
    }


def test_public_contract_uses_frozen_slots_dataclasses_and_string_enums():
    enum_types = (
        deps.DependencyOwnershipV1,
        deps.DependencyActionV1,
        deps.PythonImportIdV1,
    )
    data_types = (
        deps.PythonDistributionPinV1,
        deps.SystemPackageFactV1,
        deps.PythonEnvironmentFactV1,
        deps.DependencySnapshotV1,
        deps.RemoteQueenDependencyManifestV1,
        deps.DependencyPlanStepV1,
        deps.RemoteQueenDependencyPlanV1,
        deps.DependencyApplyRequestV1,
        deps.DependencyApplyJournalV1,
        deps.DependencyApplyResultV1,
        deps.DependencyVerifyRequestV1,
        deps.DependencyVerifyResultV1,
        deps.DependencyRollbackRequestV1,
        deps.DependencyRollbackResultV1,
    )

    assert all(issubclass(item, str) for item in enum_types)
    assert all(dataclasses.is_dataclass(item) for item in data_types)
    assert all("__slots__" in item.__dict__ for item in data_types)
    assert all(dataclasses.fields(item) for item in data_types)
    assert deps.DependencyOwnershipV1.ABSENT.value == "absent"
    assert deps.DependencyActionV1.REPLACE_PYTHON_ENVIRONMENT.value == (
        "replace-python-environment"
    )
    assert deps.PythonImportIdV1.GOOGLE_AUTH_OAUTHLIB.value == (
        "google_auth_oauthlib"
    )


@pytest.mark.parametrize(
    ("factory", "value"),
    [
        (
            lambda value: deps.PythonDistributionPinV1(
                distribution="PyYAML", version="6.0.2", imports=value
            ),
            [deps.PythonImportIdV1.YAML],
        ),
        (
            lambda value: deps.SystemPackageFactV1(name="curl", version=value),
            True,
        ),
        (
            lambda value: deps.PythonEnvironmentFactV1(
                ownership=deps.DependencyOwnershipV1.ABSENT,
                generation=None,
                python_version=None,
                distributions=value,
                imports_available=(),
            ),
            [],
        ),
        (
            lambda value: deps.DependencySnapshotV1(
                package_manager="dnf",
                packages=(),
                environment=_environment(_manifest()),
                noninteractive_sudo_available=value,
            ),
            1,
        ),
    ],
)
def test_public_contract_rejects_malformed_sequence_and_bool_types(factory, value):
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        factory(value)

    assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"
    assert str(exc_info.value) == exc_info.value.code


@pytest.mark.parametrize(
    ("host_facts", "expected_manager", "expected_packages"),
    [(FEDORA, "dnf", DNF_PACKAGES), (UBUNTU, "apt", APT_PACKAGES)],
)
def test_manifest_uses_rb0_package_plan_for_supported_distros(
    host_facts, expected_manager, expected_packages
):
    manifest = _manifest(host_facts)

    assert manifest.package_plan == package_plan_for(host_facts)
    assert manifest.package_plan.manager == expected_manager
    assert manifest.package_plan.packages == expected_packages


@pytest.mark.parametrize(
    ("distribution_id", "package_manager"),
    [("fedora", "apt"), ("ubuntu", "dnf"), ("arch", "pacman")],
)
def test_manifest_rejects_manager_distribution_mismatch(
    distribution_id, package_manager
):
    host_facts = HostFactsV1(
        distribution_id=distribution_id,
        distribution_version="41",
        architecture="x86_64",
        package_manager=package_manager,
    )

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        _manifest(host_facts)

    assert exc_info.value.code == "RQ_E_HOST_UNSUPPORTED"


def test_manifest_rejects_duplicate_or_noncanonical_distribution_pins():
    with pytest.raises(RemoteQueenBootstrapError) as duplicate:
        deps.build_remote_queen_dependency_manifest(
            host_facts=FEDORA,
            desired_generation=GENERATION,
            python_distributions=_pins() + (_pins()[0],),
            google_identity_required=False,
        )
    assert duplicate.value.code == "RQ_E_PLAN_INCONSISTENT"

    canonical = deps.build_remote_queen_dependency_manifest(
        host_facts=FEDORA,
        desired_generation=GENERATION,
        python_distributions=(_pins()[1], _pins()[0], _pins()[2]),
        google_identity_required=False,
    )
    assert canonical.python_distributions == _pins()


@pytest.mark.parametrize(
    ("distribution", "version", "imports"),
    [
        ("PyYAML", "5.4.1", ("yaml",)),
        ("PyYAML", ">=6.0", ("yaml",)),
        ("dbus-python", "1.4", ("dbus",)),
        ("PyGObject", "3.56.2", ("gi",)),
        ("google-auth", "2.34.0", ("google.auth",)),
        ("google-auth-oauthlib", "1.1.9", ("google_auth_oauthlib",)),
        ("unknown", "1.0.0", ("yaml",)),
    ],
)
def test_manifest_rejects_invalid_distribution_pinsets(
    distribution, version, imports
):
    values = list(_pins())
    if distribution in {"google-auth", "google-auth-oauthlib"}:
        values.append(_pin(distribution, version, imports))
    elif version.startswith(">") or distribution == "unknown":
        with pytest.raises(RemoteQueenBootstrapError) as exc_info:
            _pin(distribution, version, imports)
        assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"
        return
    else:
        values[0] = _pin(distribution, version, imports)

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.build_remote_queen_dependency_manifest(
            host_facts=FEDORA,
            desired_generation=GENERATION,
            python_distributions=tuple(values),
            google_identity_required=distribution.startswith("google-"),
        )

    assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"


def test_google_identity_requires_exact_additional_pins_and_imports():
    manifest = _manifest(include_google=True)

    assert tuple(item.distribution for item in manifest.python_distributions) == (
        "PyYAML",
        "dbus-python",
        "PyGObject",
        "google-auth",
        "google-auth-oauthlib",
    )
    assert manifest.required_imports == (
        deps.PythonImportIdV1.YAML,
        deps.PythonImportIdV1.DBUS,
        deps.PythonImportIdV1.GI,
        deps.PythonImportIdV1.GOOGLE_AUTH,
        deps.PythonImportIdV1.GOOGLE_AUTH_OAUTHLIB,
    )

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.build_remote_queen_dependency_manifest(
            host_facts=FEDORA,
            desired_generation=GENERATION,
            python_distributions=_pins(include_google=True)[:-1],
            google_identity_required=True,
        )
    assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"


@pytest.mark.parametrize(
    "python_distributions",
    [
        _pins() + (_pin("google-auth", "2.35.0", ("google.auth",)),),
        _pins() + (_pin("google-auth-oauthlib", "1.2.0", ("google_auth_oauthlib",)),),
    ],
)
def test_google_pins_are_forbidden_without_explicit_flag(python_distributions):
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.build_remote_queen_dependency_manifest(
            host_facts=FEDORA,
            desired_generation=GENERATION,
            python_distributions=python_distributions,
            google_identity_required=False,
        )
    assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"


def test_manifest_serialization_includes_required_imports():
    manifest = _manifest()

    assert deps.dependency_manifest_as_dict(manifest)["required_imports"] == [
        "yaml",
        "dbus",
        "gi",
    ]


def test_manifest_digest_binds_required_imports():
    manifest = _manifest()

    assert _digest(_expected_manifest_dict()) == manifest.manifest_digest


def test_manifest_serialization_and_fixed_digest_are_literal_contract():
    manifest = _manifest()
    expected_without_digest = _expected_manifest_dict()
    expected = {
        **expected_without_digest,
        "manifest_digest": (
            "sha256:b799d481fc48f5928dc54a316fc7c23500680185c2ab6769f41d47862a6b0b1f"
        ),
    }

    assert deps.dependency_manifest_as_dict(manifest) == expected
    assert manifest.manifest_digest == expected["manifest_digest"]
    assert _digest(expected_without_digest) == expected["manifest_digest"]
    assert json.loads(json.dumps(expected)) == expected


def test_manifest_digest_rejects_mutated_manifest():
    manifest = _manifest()
    mutated = replace(manifest, minimum_python_version="3.12")

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.dependency_manifest_as_dict(mutated)

    assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"


def test_plan_complete_is_noop_and_idempotent():
    manifest = _manifest()
    snapshot = _owned_snapshot(manifest)
    first = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(snapshot),
    )
    second = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(snapshot),
    )

    assert first.steps == ()
    assert first.rollback_packages == ()
    assert first.rollback_environment_generation is None
    assert first.privilege_required is False
    assert first.plan_digest == second.plan_digest
    assert deps.dependency_plan_as_dict(first) == deps.dependency_plan_as_dict(second)


def test_plan_empty_state_has_missing_allowlist_then_create_step():
    manifest = _manifest()
    snapshot = _absent_snapshot(manifest)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(snapshot),
    )

    assert plan.steps == (
        deps.DependencyPlanStepV1(
            action=deps.DependencyActionV1.INSTALL_SYSTEM_PACKAGES,
            packages=manifest.package_plan.packages,
        ),
        deps.DependencyPlanStepV1(
            action=deps.DependencyActionV1.CREATE_PYTHON_ENVIRONMENT,
            packages=(),
        ),
    )
    assert plan.rollback_packages == manifest.package_plan.packages
    assert plan.rollback_environment_generation is None
    assert plan.privilege_required is True


def test_plan_partial_state_lists_only_missing_packages_in_allowlist_order():
    manifest = _manifest()
    missing = manifest.package_plan.packages[1::3]
    snapshot = _absent_snapshot(manifest, missing=missing)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(snapshot),
    )

    assert plan.steps[0].packages == missing
    assert plan.rollback_packages == missing
    assert plan.steps[1].action == deps.DependencyActionV1.CREATE_PYTHON_ENVIRONMENT


def test_plan_owned_desired_environment_with_missing_package_is_install_only():
    manifest = _manifest()
    missing = manifest.package_plan.packages[0]
    snapshot = _owned_snapshot(manifest, missing=(missing,))

    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(snapshot),
    )

    assert plan.steps == (
        deps.DependencyPlanStepV1(
            action=deps.DependencyActionV1.INSTALL_SYSTEM_PACKAGES,
            packages=(missing,),
        ),
    )
    assert plan.rollback_packages == (missing,)
    assert plan.rollback_environment_generation is None
    assert plan.privilege_required is True


def test_plan_stale_owned_environment_replaces_and_binds_prior_generation():
    manifest = _manifest()
    snapshot = _owned_snapshot(manifest, generation="rq-dependencies-previous")
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(snapshot),
    )

    assert plan.steps == (
        deps.DependencyPlanStepV1(
            action=deps.DependencyActionV1.REPLACE_PYTHON_ENVIRONMENT,
            packages=(),
        ),
    )
    assert plan.rollback_environment_generation == "rq-dependencies-previous"
    assert plan.privilege_required is False


def test_plan_stale_owned_environment_allows_prior_valid_pin_versions():
    manifest = _manifest()
    old_pins = (
        _pin("PyYAML", "6.0.1", ("yaml",)),
        *_pins()[1:],
    )
    snapshot = _owned_snapshot(
        manifest,
        generation="rq-dependencies-previous",
        distributions=old_pins,
    )

    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(snapshot),
    )

    assert plan.steps == (
        deps.DependencyPlanStepV1(
            action=deps.DependencyActionV1.REPLACE_PYTHON_ENVIRONMENT,
            packages=(),
        ),
    )


def test_plan_stale_owned_environment_can_replace_prior_google_pinset():
    manifest = _manifest(include_google=True)
    snapshot = _owned_snapshot(
        manifest,
        generation="rq-dependencies-previous",
        distributions=_pins(),
        imports_available=(
            deps.PythonImportIdV1.YAML,
            deps.PythonImportIdV1.DBUS,
            deps.PythonImportIdV1.GI,
        ),
    )

    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(snapshot),
    )

    assert plan.steps == (
        deps.DependencyPlanStepV1(
            action=deps.DependencyActionV1.REPLACE_PYTHON_ENVIRONMENT,
            packages=(),
        ),
    )


@pytest.mark.parametrize("python_version", ["3.10", "3.10.9", None])
def test_plan_rejects_unsupported_or_missing_owned_python(python_version):
    manifest = _manifest()
    snapshot = _owned_snapshot(manifest, python_version=python_version)

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.plan_remote_queen_dependencies(
            manifest=manifest,
            operations=FakeDependencyOperations(snapshot),
        )

    assert exc_info.value.code == "RQ_E_HOST_UNSUPPORTED"


def test_plan_rejects_foreign_state_without_echoing_foreign_generation():
    manifest = _manifest()
    snapshot = deps.DependencySnapshotV1(
        package_manager=manifest.package_plan.manager,
        packages=_packages(manifest),
        environment=deps.PythonEnvironmentFactV1(
            ownership=deps.DependencyOwnershipV1.FOREIGN,
            generation="secret-rb2-do-not-retain",
            python_version="3.12.0",
            distributions=(),
            imports_available=(),
        ),
        noninteractive_sudo_available=True,
    )

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.plan_remote_queen_dependencies(
            manifest=manifest,
            operations=FakeDependencyOperations(snapshot),
        )

    assert exc_info.value.code == "RQ_E_FOREIGN_STATE"
    assert str(exc_info.value) == exc_info.value.code
    assert "secret-rb2-do-not-retain" not in repr(exc_info.value)


def test_plan_privilege_required_only_for_missing_system_packages():
    manifest = _manifest()
    complete_without_sudo = _owned_snapshot(manifest, sudo=False)
    missing_without_sudo = _absent_snapshot(
        manifest, missing=manifest.package_plan.packages[:1], sudo=False
    )

    complete_plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(complete_without_sudo),
    )
    missing_plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(missing_without_sudo),
    )

    assert complete_plan.privilege_required is False
    assert missing_plan.privilege_required is True


def test_fixed_before_and_plan_digest_vectors_use_literal_nested_contract():
    manifest = _manifest()
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(_absent_snapshot(manifest)),
    )
    expected = {
        "schema_version": "RemoteQueenDependencyPlanV1",
        "manifest": {
            **_expected_manifest_dict(),
            "manifest_digest": (
                "sha256:b799d481fc48f5928dc54a316fc7c23500680185c2ab6769f41d47862a6b0b1f"
            ),
        },
        "before": {
            "package_manager": "dnf",
            "packages": [
                {"name": name, "version": None} for name in DNF_PACKAGES
            ],
            "environment": {
                "ownership": "absent",
                "generation": None,
                "python_version": "3.11.9",
                "distributions": [],
                "imports_available": [],
            },
            "noninteractive_sudo_available": True,
        },
        "before_digest": (
            "sha256:a583c01491c7e378d702dc68719234c5fee3f2e4e3d2ef0d152a3fc1e8fe9642"
        ),
        "steps": [
            {
                "action": "install-system-packages",
                "packages": list(DNF_PACKAGES),
            },
            {"action": "create-python-environment", "packages": []},
        ],
        "rollback": {
            "remove_packages": list(DNF_PACKAGES),
            "restore_environment_generation": None,
        },
        "privilege_required": True,
        "plan_digest": (
            "sha256:818d0e8d556abfe9a8562a6a4da0a4ceb28e758009d50c728a1e81c30b162627"
        ),
    }

    assert deps.dependency_plan_as_dict(plan) == expected
    assert plan.before_digest == expected["before_digest"]
    assert plan.plan_digest == expected["plan_digest"]


def test_mutating_bound_plan_fields_changes_digest():
    manifest = _manifest()
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(_absent_snapshot(manifest)),
    )
    mutated = replace(plan, privilege_required=False)

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.dependency_plan_as_dict(mutated)

    assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"


def test_apply_request_binding_and_privilege_block_happen_before_apply():
    manifest = _manifest()
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(_absent_snapshot(manifest)),
    )
    wrong_request = replace(_request_for(plan), plan_digest="sha256:" + "0" * 64)
    fake = FakeDependencyOperations(_absent_snapshot(manifest))

    with pytest.raises(RemoteQueenBootstrapError) as binding_error:
        deps.apply_remote_queen_dependencies(
            plan=plan,
            request=wrong_request,
            operations=fake,
        )
    assert binding_error.value.code == "RQ_E_PLAN_INCONSISTENT"
    assert fake.calls == []

    no_sudo_snapshot = _absent_snapshot(manifest, sudo=False)
    privilege_plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(no_sudo_snapshot),
    )
    no_sudo = FakeDependencyOperations(no_sudo_snapshot)
    with pytest.raises(RemoteQueenBootstrapError) as privilege_error:
        deps.apply_remote_queen_dependencies(
            plan=privilege_plan,
            request=_request_for(privilege_plan),
            operations=no_sudo,
        )
    assert privilege_error.value.code == "RQ_E_PRIVILEGE_REQUIRED"
    assert no_sudo.calls == ["inspect"]


def test_apply_stale_before_state_blocks_before_apply():
    manifest = _manifest()
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(_absent_snapshot(manifest)),
    )
    drifted = _absent_snapshot(manifest, missing=manifest.package_plan.packages[:-1])
    fake = FakeDependencyOperations(drifted)

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.apply_remote_queen_dependencies(
            plan=plan,
            request=_request_for(plan),
            operations=fake,
        )

    assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"
    assert fake.calls == ["inspect"]


def test_apply_noop_inspects_without_apply_call():
    manifest = _manifest()
    snapshot = _owned_snapshot(manifest)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(snapshot),
    )
    fake = FakeDependencyOperations(snapshot)

    result = deps.apply_remote_queen_dependencies(
        plan=plan,
        request=_request_for(plan),
        operations=fake,
    )

    assert result == deps.DependencyApplyResultV1(
        changed=False,
        journal=None,
        snapshot_digest=_snapshot_digest(snapshot),
    )
    assert fake.calls == ["inspect"]


def test_apply_mutation_has_inspect_apply_inspect_and_complete_journal():
    manifest = _manifest()
    before = _absent_snapshot(manifest)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(before),
    )
    after = _owned_snapshot(manifest)
    journal = _journal(plan, after)
    fake = FakeDependencyOperations(before, after=after, journal=journal)

    result = deps.apply_remote_queen_dependencies(
        plan=plan,
        request=_request_for(plan),
        operations=fake,
    )

    assert result.changed is True
    assert result.journal == journal
    assert result.snapshot_digest == _snapshot_digest(after)
    assert fake.calls == ["inspect", "apply", "inspect"]
    assert journal.installed_packages == plan.rollback_packages
    assert journal.prior_environment_generation is None


def test_plan_after_successful_apply_is_noop():
    manifest = _manifest()
    before = _absent_snapshot(manifest)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(before),
    )
    after = _owned_snapshot(manifest)
    fake = FakeDependencyOperations(before, after=after, journal=_journal(plan, after))
    deps.apply_remote_queen_dependencies(
        plan=plan,
        request=_request_for(plan),
        operations=fake,
    )

    repeat = deps.plan_remote_queen_dependencies(manifest=manifest, operations=fake)

    assert repeat.steps == ()
    assert fake.calls[-1] == "inspect"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda snapshot, manifest: replace(
            snapshot,
            packages=_packages(manifest, missing=manifest.package_plan.packages[:1]),
        ),
        lambda snapshot, manifest: replace(
            snapshot,
            environment=replace(
                snapshot.environment,
                distributions=(
                    _pin("PyYAML", "6.0.1", ("yaml",)),
                    *_pins()[1:],
                ),
            ),
        ),
        lambda snapshot, manifest: replace(
            snapshot,
            environment=replace(
                snapshot.environment,
                imports_available=(deps.PythonImportIdV1.YAML,),
            ),
        ),
    ],
)
def test_apply_poststate_attestation_rejects_package_pin_or_import_drift(mutate):
    manifest = _manifest()
    before = _absent_snapshot(manifest)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(before),
    )
    valid_after = _owned_snapshot(manifest)
    drifted_after = mutate(valid_after, manifest)
    fake = FakeDependencyOperations(
        before,
        after=drifted_after,
        journal=_journal(plan, drifted_after),
    )

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.apply_remote_queen_dependencies(
            plan=plan,
            request=_request_for(plan),
            operations=fake,
        )

    assert exc_info.value.code == "RQ_E_DEPENDENCY_ATTESTATION"
    assert fake.calls == ["inspect", "apply", "inspect"]


def test_apply_rejects_malformed_journal_without_serializing_payload():
    manifest = _manifest()
    before = _absent_snapshot(manifest)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(before),
    )
    after = _owned_snapshot(manifest)
    journal = replace(
        _journal(plan, after),
        installed_packages=("secret-rb2-do-not-retain",),
    )
    fake = FakeDependencyOperations(before, after=after, journal=journal)

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.apply_remote_queen_dependencies(
            plan=plan,
            request=_request_for(plan),
            operations=fake,
        )

    assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"
    assert "secret-rb2-do-not-retain" not in str(exc_info.value)


def test_verify_is_read_only_and_attests_full_desired_state():
    manifest = _manifest()
    snapshot = _owned_snapshot(manifest)
    fake = FakeDependencyOperations(snapshot)

    result = deps.verify_remote_queen_dependencies(
        manifest=manifest,
        request=_verify_request_for(manifest),
        operations=fake,
    )

    assert result.snapshot_digest == _snapshot_digest(snapshot)
    assert fake.calls == ["inspect"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda snapshot: replace(
            snapshot,
            packages=tuple(
                replace(item, version=None) if index == 0 else item
                for index, item in enumerate(snapshot.packages)
            ),
        ),
        lambda snapshot: replace(
            snapshot,
            environment=replace(
                snapshot.environment,
                distributions=(
                    _pin("PyYAML", "6.0.1", ("yaml",)),
                    *_pins()[1:],
                ),
            ),
        ),
        lambda snapshot: replace(
            snapshot,
            environment=replace(
                snapshot.environment,
                imports_available=(deps.PythonImportIdV1.YAML,),
            ),
        ),
    ],
)
def test_verify_blocks_every_package_pin_and_import_deviation(mutate):
    manifest = _manifest()
    snapshot = mutate(_owned_snapshot(manifest))
    fake = FakeDependencyOperations(snapshot)

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.verify_remote_queen_dependencies(
            manifest=manifest,
            request=_verify_request_for(manifest),
            operations=fake,
        )

    assert exc_info.value.code == "RQ_E_DEPENDENCY_ATTESTATION"
    assert fake.calls == ["inspect"]


def test_rollback_validates_generation_and_restores_before_digest():
    manifest = _manifest()
    before = _absent_snapshot(manifest)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(before),
    )
    after = _owned_snapshot(manifest)
    journal = _journal(plan, after)
    fake = FakeDependencyOperations(after, after=before)

    result = deps.rollback_remote_queen_dependencies(
        plan=plan,
        journal=journal,
        request=_rollback_request_for(plan),
        operations=fake,
    )

    assert result.restored_snapshot_digest == _snapshot_digest(before)
    assert fake.calls == ["inspect", "rollback", "inspect"]
    assert fake.rollback_arguments == (plan, journal)


def test_rollback_rejects_noop_plan_before_any_operations_call():
    manifest = _manifest()
    snapshot = _owned_snapshot(manifest)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(snapshot),
    )
    journal = _journal(plan, snapshot)
    fake = FakeDependencyOperations(snapshot, after=snapshot)
    error = None

    try:
        deps.rollback_remote_queen_dependencies(
            plan=plan,
            journal=journal,
            request=_rollback_request_for(plan),
            operations=fake,
        )
    except RemoteQueenBootstrapError as exc:
        error = exc

    assert fake.calls == []
    assert error is not None
    assert error.code == "RQ_E_PLAN_INCONSISTENT"


def test_rollback_passes_only_journalized_new_packages():
    manifest = _manifest()
    existing = manifest.package_plan.packages[::2]
    before = _absent_snapshot(manifest, missing=set(manifest.package_plan.packages) - set(existing))
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(before),
    )
    after = _owned_snapshot(manifest)
    journal = _journal(plan, after)
    fake = FakeDependencyOperations(after, after=before)

    deps.rollback_remote_queen_dependencies(
        plan=plan,
        journal=journal,
        request=_rollback_request_for(plan),
        operations=fake,
    )

    assert journal.installed_packages == tuple(
        name for name in manifest.package_plan.packages if name not in existing
    )
    assert fake.rollback_arguments[1].installed_packages == plan.rollback_packages


def test_rollback_drift_and_foreign_state_block_without_rollback_call():
    manifest = _manifest()
    before = _absent_snapshot(manifest)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(before),
    )
    after = _owned_snapshot(manifest)
    journal = _journal(plan, after)
    drifted = replace(after, noninteractive_sudo_available=False)
    fake = FakeDependencyOperations(drifted)

    with pytest.raises(RemoteQueenBootstrapError) as drift_error:
        deps.rollback_remote_queen_dependencies(
            plan=plan,
            journal=journal,
            request=_rollback_request_for(plan),
            operations=fake,
        )
    assert drift_error.value.code == "RQ_E_ROLLBACK_DRIFT"
    assert fake.calls == ["inspect"]

    foreign = replace(
        after,
        environment=replace(
            after.environment,
            ownership=deps.DependencyOwnershipV1.FOREIGN,
            generation="secret-rb2-do-not-retain",
        ),
    )
    foreign_fake = FakeDependencyOperations(foreign)
    with pytest.raises(RemoteQueenBootstrapError) as foreign_error:
        deps.rollback_remote_queen_dependencies(
            plan=plan,
            journal=journal,
            request=_rollback_request_for(plan),
            operations=foreign_fake,
        )
    assert foreign_error.value.code == "RQ_E_ROLLBACK_DRIFT"
    assert foreign_fake.calls == ["inspect"]


def test_unknown_operation_exception_is_redacted():
    manifest = _manifest()
    before = _absent_snapshot(manifest)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(before),
    )
    fake = FakeDependencyOperations(
        before,
        apply_error=RuntimeError("secret-rb2-do-not-retain"),
    )

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.apply_remote_queen_dependencies(
            plan=plan,
            request=_request_for(plan),
            operations=fake,
        )

    assert exc_info.value.code == "RQ_E_DEPENDENCY_OPERATION"
    assert str(exc_info.value) == exc_info.value.code
    assert "secret-rb2-do-not-retain" not in repr(exc_info.value)


def test_verify_and_rollback_request_bindings_fail_closed():
    manifest = _manifest()
    wrong_verify = replace(
        _verify_request_for(manifest), generation="other-generation"
    )
    with pytest.raises(RemoteQueenBootstrapError) as verify_error:
        deps.verify_remote_queen_dependencies(
            manifest=manifest,
            request=wrong_verify,
            operations=FakeDependencyOperations(_owned_snapshot(manifest)),
        )
    assert verify_error.value.code == "RQ_E_PLAN_INCONSISTENT"

    before = _absent_snapshot(manifest)
    plan = deps.plan_remote_queen_dependencies(
        manifest=manifest,
        operations=FakeDependencyOperations(before),
    )
    wrong_rollback = replace(
        _rollback_request_for(plan), manifest_digest="sha256:" + "0" * 64
    )
    with pytest.raises(RemoteQueenBootstrapError) as rollback_error:
        deps.rollback_remote_queen_dependencies(
            plan=plan,
            journal=_journal(plan, _owned_snapshot(manifest)),
            request=wrong_rollback,
            operations=FakeDependencyOperations(_owned_snapshot(manifest)),
        )
    assert rollback_error.value.code == "RQ_E_PLAN_INCONSISTENT"


def test_runtime_effect_gate_rejects_forbidden_imports_and_calls():
    source_path = Path(__file__).parents[1] / "src/codex_master/remote_queen_dependencies.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    forbidden_imports = {
        "os",
        "subprocess",
        "socket",
        "asyncio",
        "requests",
        "urllib",
        "http",
        "paramiko",
        "asyncssh",
        "pathlib",
        "shutil",
        "tempfile",
        "dbus",
        "gi",
        "yaml",
        "google",
        "pip",
        "venv",
        "ensurepip",
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
        "mkdir",
        "chmod",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [item.name for item in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            names = []
        assert not any(
            name == forbidden or name.startswith(forbidden + ".")
            for name in names
            for forbidden in forbidden_imports
        ), ast.dump(node)

        if isinstance(node, ast.Call):
            function_name = node.func.attr if isinstance(node.func, ast.Attribute) else (
                node.func.id if isinstance(node.func, ast.Name) else None
            )
            assert function_name not in forbidden_calls, ast.dump(node)


def test_foreign_and_operation_payloads_never_enter_errors():
    manifest = _manifest()
    foreign = deps.DependencySnapshotV1(
        package_manager=manifest.package_plan.manager,
        packages=_packages(manifest),
        environment=deps.PythonEnvironmentFactV1(
            ownership=deps.DependencyOwnershipV1.FOREIGN,
            generation="secret-rb2-do-not-retain",
            python_version="3.12.0",
            distributions=(),
            imports_available=(),
        ),
        noninteractive_sudo_available=True,
    )
    fake = FakeDependencyOperations(foreign)

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        deps.plan_remote_queen_dependencies(manifest=manifest, operations=fake)

    assert exc_info.value.code == "RQ_E_FOREIGN_STATE"
    assert "secret-rb2-do-not-retain" not in str(exc_info.value)


def test_exact_accepts_only_the_requested_concrete_type() -> None:
    class TextSubclass(str):
        pass

    assert deps._exact("value", str) is True
    assert deps._exact(TextSubclass("value"), str) is False
    assert deps._exact(True, int) is False


def test_unique_requires_hashable_distinct_tuple_values() -> None:
    assert deps._unique(("one", "two")) is True
    assert deps._unique(("one", "one")) is False


def test_valid_pin_version_accepts_only_canonical_two_or_three_part_versions() -> None:
    assert deps._valid_pin_version("1.2") is True
    assert deps._valid_pin_version("1.2.3") is True
    assert deps._valid_pin_version("01.2") is False
    assert deps._valid_pin_version("1") is False
    assert deps._valid_pin_version(1.2) is False
