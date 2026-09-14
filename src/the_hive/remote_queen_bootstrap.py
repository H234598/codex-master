import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum


class RemoteQueenBootstrapError(ValueError):
    code: str

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class SshTargetV1:
    user: str | None
    host: str


class DistributionFamilyV1(str, Enum):
    FEDORA_RHEL = "fedora-rhel"
    DEBIAN_UBUNTU = "debian-ubuntu"


@dataclass(frozen=True, slots=True)
class HostFactsV1:
    distribution_id: str
    distribution_version: str
    architecture: str
    package_manager: str

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str)
            for value in (
                self.distribution_id,
                self.distribution_version,
                self.architecture,
                self.package_manager,
            )
        ):
            raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")


@dataclass(frozen=True, slots=True)
class PackagePlanV1:
    manager: str
    packages: tuple[str, ...]


DNF_PACKAGES = (
    "ca-certificates",
    "curl",
    "gcc",
    "git",
    "glib2-devel",
    "pkgconf-pkg-config",
    "python3",
    "python3-dbus",
    "python3-devel",
    "python3-gobject",
    "syncthing",
    "systemd",
)
APT_PACKAGES = (
    "build-essential",
    "ca-certificates",
    "curl",
    "git",
    "libgirepository1.0-dev",
    "pkg-config",
    "python3",
    "python3-dbus",
    "python3-dev",
    "python3-gi",
    "python3-venv",
    "syncthing",
    "systemd",
)


def package_plan_for(host_facts: HostFactsV1) -> PackagePlanV1:
    if not isinstance(host_facts, HostFactsV1):
        raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")
    if host_facts.package_manager == "dnf" and host_facts.distribution_id in {
        "fedora",
        "rhel",
        "rocky",
        "almalinux",
    }:
        return PackagePlanV1(manager="dnf", packages=DNF_PACKAGES)
    if host_facts.package_manager == "apt" and host_facts.distribution_id in {
        "debian",
        "ubuntu",
    }:
        return PackagePlanV1(manager="apt", packages=APT_PACKAGES)
    raise RemoteQueenBootstrapError("RQ_E_HOST_UNSUPPORTED")


@dataclass(frozen=True, slots=True)
class ManifestGenerationV1:
    generation: str
    sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.generation, str)
            or not self.generation
            or not isinstance(self.sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None
        ):
            raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")


@dataclass(frozen=True, slots=True)
class ManagedObjectStateV1:
    object_id: str
    owner: str | None
    generation: str | None


@dataclass(frozen=True, slots=True)
class QueenBindingV1:
    repo_id: str
    topic_id: str
    role: str
    scope: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.scope, (tuple, list)):
            raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")
        scope = tuple(self.scope)
        object.__setattr__(self, "scope", scope)
        if (
            not isinstance(self.repo_id, str)
            or not self.repo_id.strip()
            or not isinstance(self.topic_id, str)
            or not self.topic_id.strip()
            or self.role != "queen"
            or not scope
            or any(not isinstance(item, str) or not item.strip() for item in scope)
            or len(scope) != len(set(scope))
        ):
            raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")


@dataclass(frozen=True, slots=True)
class RollbackObjectV1:
    object_id: str
    expected_generation: str
    prior_generation: str | None


@dataclass(frozen=True, slots=True)
class BootstrapPlanStepV1:
    object_id: str
    action: str


@dataclass(frozen=True, slots=True)
class RemoteQueenBootstrapPlanV1:
    schema_version: str
    ssh_target: SshTargetV1
    host_facts: HostFactsV1
    desired_generation: ManifestGenerationV1
    package_plan: PackagePlanV1
    artifacts: tuple[str, ...]
    services: tuple[str, ...]
    syncthing_folders: tuple[str, ...]
    queen_binding: QueenBindingV1
    rollback_objects: tuple[RollbackObjectV1, ...]
    steps: tuple[BootstrapPlanStepV1, ...]
    plan_digest: str


@dataclass(frozen=True, slots=True)
class ApplyRequestV1:
    ssh_target: SshTargetV1
    plan_digest: str


@dataclass(frozen=True, slots=True)
class VerifyRequestV1:
    ssh_target: SshTargetV1
    generation: str


@dataclass(frozen=True, slots=True)
class RollbackRequestV1:
    ssh_target: SshTargetV1
    generation: str


_OBJECT_IDS = (
    "packages",
    "release-artifacts",
    "user-services",
    "syncthing-folder:Teladi_Programming",
    "queen-binding",
)
_OBJECT_ID_SET = frozenset(_OBJECT_IDS)
_OWNER = "remote-queen-bootstrap"
_ARTIFACTS = ("codex-cli", "codex-master-client")
_SERVICES = ("syncthing-user",)
_SYNCTHING_FOLDERS = ("Teladi_Programming",)


def _inconsistent_plan() -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")


def _plan_dict(
    *,
    ssh_target: SshTargetV1,
    host_facts: HostFactsV1,
    desired_generation: ManifestGenerationV1,
    package_plan: PackagePlanV1,
    artifacts: tuple[str, ...],
    services: tuple[str, ...],
    syncthing_folders: tuple[str, ...],
    queen_binding: QueenBindingV1,
    rollback_objects: tuple[RollbackObjectV1, ...],
    steps: tuple[BootstrapPlanStepV1, ...],
    plan_digest: str | None,
) -> dict[str, object]:
    plan = {
        "schema_version": "RemoteQueenBootstrapPlanV1",
        "ssh_target": {
            "user": ssh_target.user,
            "host": ssh_target.host,
        },
        "host_facts": {
            "distribution_id": host_facts.distribution_id,
            "distribution_version": host_facts.distribution_version,
            "architecture": host_facts.architecture,
            "package_manager": host_facts.package_manager,
        },
        "desired_generation": {
            "generation": desired_generation.generation,
            "sha256": desired_generation.sha256,
        },
        "package_plan": {
            "manager": package_plan.manager,
            "packages": list(package_plan.packages),
        },
        "artifacts": list(artifacts),
        "services": list(services),
        "syncthing_folders": list(syncthing_folders),
        "queen_binding": {
            "repo_id": queen_binding.repo_id,
            "topic_id": queen_binding.topic_id,
            "role": queen_binding.role,
            "scope": list(queen_binding.scope),
        },
        "rollback_objects": [
            {
                "object_id": item.object_id,
                "expected_generation": item.expected_generation,
                "prior_generation": item.prior_generation,
            }
            for item in rollback_objects
        ],
        "steps": [
            {"object_id": item.object_id, "action": item.action}
            for item in steps
        ],
    }
    if plan_digest is not None:
        plan["plan_digest"] = plan_digest
    return plan


def _validate_object_states(
    object_states: tuple[ManagedObjectStateV1, ...],
    desired_generation: str,
) -> dict[str, ManagedObjectStateV1]:
    try:
        states = tuple(object_states)
    except TypeError as error:
        raise _inconsistent_plan() from error
    if len(states) != len(_OBJECT_IDS):
        raise _inconsistent_plan()

    by_id: dict[str, ManagedObjectStateV1] = {}
    for state in states:
        if not isinstance(state, ManagedObjectStateV1):
            raise _inconsistent_plan()
        if not isinstance(state.object_id, str) or not state.object_id:
            raise _inconsistent_plan()
        if state.object_id not in _OBJECT_ID_SET or state.object_id in by_id:
            raise _inconsistent_plan()
        by_id[state.object_id] = state

        if state.owner is None:
            if state.generation is not None:
                raise _inconsistent_plan()
        elif state.owner == _OWNER:
            if not isinstance(state.generation, str) or not state.generation:
                raise _inconsistent_plan()
        elif not isinstance(state.owner, str) or not state.owner:
            raise _inconsistent_plan()
        else:
            raise RemoteQueenBootstrapError("RQ_E_FOREIGN_STATE")

    if set(by_id) != _OBJECT_ID_SET:
        raise _inconsistent_plan()
    return by_id


def build_remote_queen_bootstrap_plan(
    *,
    ssh_target: SshTargetV1,
    host_facts: HostFactsV1,
    desired_generation: ManifestGenerationV1,
    object_states: tuple[ManagedObjectStateV1, ...],
    queen_binding: QueenBindingV1,
) -> RemoteQueenBootstrapPlanV1:
    if not isinstance(ssh_target, SshTargetV1) or not isinstance(
        host_facts, HostFactsV1
    ) or not isinstance(desired_generation, ManifestGenerationV1):
        raise _inconsistent_plan()
    if not isinstance(queen_binding, QueenBindingV1):
        raise _inconsistent_plan()

    package_plan = package_plan_for(host_facts)
    states = _validate_object_states(object_states, desired_generation.generation)
    rollback_objects = []
    steps = []
    for object_id in _OBJECT_IDS:
        state = states[object_id]
        if state.owner is None:
            prior_generation = None
            action = "ensure"
        elif state.generation == desired_generation.generation:
            prior_generation = desired_generation.generation
            action = None
        else:
            prior_generation = state.generation
            action = "replace"
        rollback_objects.append(
            RollbackObjectV1(
                object_id=object_id,
                expected_generation=desired_generation.generation,
                prior_generation=prior_generation,
            )
        )
        if action is not None:
            steps.append(BootstrapPlanStepV1(object_id=object_id, action=action))

    rollback_objects_tuple = tuple(rollback_objects)
    steps_tuple = tuple(steps)
    digest_payload = _plan_dict(
        ssh_target=ssh_target,
        host_facts=host_facts,
        desired_generation=desired_generation,
        package_plan=package_plan,
        artifacts=_ARTIFACTS,
        services=_SERVICES,
        syncthing_folders=_SYNCTHING_FOLDERS,
        queen_binding=queen_binding,
        rollback_objects=rollback_objects_tuple,
        steps=steps_tuple,
        plan_digest=None,
    )
    canonical = json.dumps(
        digest_payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    plan_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return RemoteQueenBootstrapPlanV1(
        schema_version="RemoteQueenBootstrapPlanV1",
        ssh_target=ssh_target,
        host_facts=host_facts,
        desired_generation=desired_generation,
        package_plan=package_plan,
        artifacts=_ARTIFACTS,
        services=_SERVICES,
        syncthing_folders=_SYNCTHING_FOLDERS,
        queen_binding=queen_binding,
        rollback_objects=rollback_objects_tuple,
        steps=steps_tuple,
        plan_digest=plan_digest,
    )


def plan_as_dict(plan: RemoteQueenBootstrapPlanV1) -> dict[str, object]:
    if not isinstance(plan, RemoteQueenBootstrapPlanV1):
        raise TypeError("plan must be RemoteQueenBootstrapPlanV1")
    return _plan_dict(
        ssh_target=plan.ssh_target,
        host_facts=plan.host_facts,
        desired_generation=plan.desired_generation,
        package_plan=plan.package_plan,
        artifacts=plan.artifacts,
        services=plan.services,
        syncthing_folders=plan.syncthing_folders,
        queen_binding=plan.queen_binding,
        rollback_objects=plan.rollback_objects,
        steps=plan.steps,
        plan_digest=plan.plan_digest,
    )


_SSH_USER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


def _invalid_ssh_target() -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError("RQ_E_SSH_TARGET_INVALID")


def _is_dns_host(host: str) -> bool:
    if not 1 <= len(host) <= 253:
        return False
    labels = host.split(".")
    if any(not _DNS_LABEL.fullmatch(label) for label in labels):
        return False
    if len(labels) == 4 and all(label.isdigit() for label in labels):
        try:
            ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError:
            return False
    return True


def _is_host(host: str) -> bool:
    if host.startswith("[") or host.endswith("]"):
        if not (host.startswith("[") and host.endswith("]")):
            return False
        if host.count("[") != 1 or host.count("]") != 1:
            return False
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ipaddress.AddressValueError:
            return False
        return True
    if ":" in host or "[" in host or "]" in host:
        return False
    try:
        ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        return _is_dns_host(host)
    return True


def parse_ssh_target(value: str) -> SshTargetV1:
    if not isinstance(value, str) or not value or value.startswith("-"):
        raise _invalid_ssh_target()
    if any(char.isspace() or unicodedata.category(char).startswith("C") for char in value):
        raise _invalid_ssh_target()
    if any(token in value for token in ("://", "?", "#", ",")):
        raise _invalid_ssh_target()
    if value.count("@") > 1:
        raise _invalid_ssh_target()

    user: str | None = None
    host = value
    if "@" in value:
        user, host = value.split("@", 1)
        if not _SSH_USER.fullmatch(user):
            raise _invalid_ssh_target()
    if not _is_host(host):
        raise _invalid_ssh_target()
    return SshTargetV1(user=user, host=host)
