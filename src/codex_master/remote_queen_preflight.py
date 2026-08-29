import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import NoReturn

from .remote_queen_bootstrap import (
    HostFactsV1,
    ManifestGenerationV1,
    PackagePlanV1,
    RemoteQueenBootstrapError,
    SshTargetV1,
    package_plan_for,
)
from .remote_queen_ssh import (
    ApprovedHostKeyV1,
    RemoteQueenSshOperations,
    SshOperationLimitsV1,
    SshReadOnlyOperationV1,
    approve_known_host_key,
    validate_ssh_operation_result,
)


class NetworkPathIdV1(str, Enum):
    DNS = "dns"
    PACKAGE_REPOSITORIES = "package-repositories"
    CODEX_DOWNLOAD = "codex-download"
    CANONICAL_MASTERJET = "canonical-masterjet"
    CANONICAL_HIVE_BUS = "canonical-hive-bus"
    SYNCTHING_DISCOVERY = "syncthing-discovery"


class ManagedStateIdV1(str, Enum):
    CODEX = "codex"
    MCP = "mcp"
    QUEEN = "queen"
    SYNCTHING = "syncthing"


class ManagedStateKindV1(str, Enum):
    ABSENT = "absent"
    OWNED = "owned"
    FOREIGN = "foreign"


def _fail(code: str) -> NoReturn:
    raise RemoteQueenBootstrapError(code)


def _is_ascii_line(value: object, *, allow_empty: bool = False) -> bool:
    if type(value) is not str or (not allow_empty and not value):
        return False
    if not value.isascii():
        return False
    return not any(ord(character) < 32 or ord(character) == 127 for character in value)


def _is_absolute_posix_path(value: object, *, user_home: bool) -> bool:
    if type(value) is not str or not value or len(value) > 1024:
        return False
    if not value.startswith("/"):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    if user_home and value == "/":
        return False
    if value != "/" and value.endswith("/"):
        return False
    if "//" in value:
        return False
    path = PurePosixPath(value)
    if path.as_posix() != value:
        return False
    return not any(part in {".", ".."} for part in path.parts)


@dataclass(frozen=True, slots=True)
class NetworkPathFactV1:
    path_id: NetworkPathIdV1
    reachable: bool

    def __post_init__(self) -> None:
        if not isinstance(self.path_id, NetworkPathIdV1) or type(
            self.reachable
        ) is not bool:
            _fail("RQ_E_PLAN_INCONSISTENT")


@dataclass(frozen=True, slots=True)
class ManagedStateFactV1:
    object_id: ManagedStateIdV1
    state: ManagedStateKindV1
    generation: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.object_id, ManagedStateIdV1) or not isinstance(
            self.state, ManagedStateKindV1
        ):
            _fail("RQ_E_PLAN_INCONSISTENT")
        if self.state is ManagedStateKindV1.ABSENT and self.generation is not None:
            _fail("RQ_E_PLAN_INCONSISTENT")
        if self.state is ManagedStateKindV1.OWNED and (
            not _is_ascii_line(self.generation)
            or len(self.generation) > 128
        ):
            _fail("RQ_E_PLAN_INCONSISTENT")
        if self.state is ManagedStateKindV1.FOREIGN and self.generation is not None:
            if not _is_ascii_line(self.generation):
                _fail("RQ_E_PLAN_INCONSISTENT")


@dataclass(frozen=True, slots=True)
class RemoteQueenHostFactsV1:
    schema_version: str
    host_facts: HostFactsV1
    remote_user: str
    remote_home: str
    uid: int
    gid: int
    shell: str
    python_version: str | None
    git_version: str | None
    curl_version: str | None
    systemd_user_available: bool
    dbus_session_available: bool
    selinux_mode: str
    apparmor_mode: str
    syncthing_version: str | None
    codex_version: str | None
    free_bytes: int
    clock_synchronized: bool
    noninteractive_sudo_available: bool
    network_paths: tuple[NetworkPathFactV1, ...]
    managed_states: tuple[ManagedStateFactV1, ...]


@dataclass(frozen=True, slots=True)
class RemoteQueenSshPreflightV1:
    schema_version: str
    ssh_target: SshTargetV1
    host_key: ApprovedHostKeyV1
    desired_generation: ManifestGenerationV1
    host_facts: RemoteQueenHostFactsV1
    package_plan: PackagePlanV1
    preflight_digest: str


_HOST_FACT_KEYS = frozenset(
    {
        "schema_version",
        "distribution_id",
        "distribution_version",
        "architecture",
        "package_manager",
        "remote_user",
        "remote_home",
        "uid",
        "gid",
        "shell",
        "python_version",
        "git_version",
        "curl_version",
        "systemd_user_available",
        "dbus_session_available",
        "selinux_mode",
        "apparmor_mode",
        "syncthing_version",
        "codex_version",
        "free_bytes",
        "clock_synchronized",
        "noninteractive_sudo_available",
        "network_paths",
        "managed_states",
    }
)
_NETWORK_PATH_KEYS = frozenset({"path_id", "reachable"})
_MANAGED_STATE_KEYS = frozenset({"object_id", "state", "generation"})
_SELINUX_MODES = frozenset(
    {"enforcing", "permissive", "disabled", "unavailable"}
)
_APPARMOR_MODES = frozenset(
    {"enforcing", "complain", "disabled", "unavailable"}
)


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("RQ_E_PLAN_INCONSISTENT")
        result[key] = value
    return result


def _reject_json_constant(value):
    del value
    _fail("RQ_E_PLAN_INCONSISTENT")


def _parse_network_paths(value: object) -> tuple[NetworkPathFactV1, ...]:
    if type(value) is not list:
        _fail("RQ_E_PLAN_INCONSISTENT")
    by_id = {}
    for item in value:
        if type(item) is not dict or set(item) != _NETWORK_PATH_KEYS:
            _fail("RQ_E_PLAN_INCONSISTENT")
        raw_id = item["path_id"]
        if type(raw_id) is not str:
            _fail("RQ_E_PLAN_INCONSISTENT")
        try:
            path_id = NetworkPathIdV1(raw_id)
        except ValueError:
            _fail("RQ_E_PLAN_INCONSISTENT")
        if path_id in by_id or type(item["reachable"]) is not bool:
            _fail("RQ_E_PLAN_INCONSISTENT")
        by_id[path_id] = NetworkPathFactV1(
            path_id=path_id,
            reachable=item["reachable"],
        )
    if set(by_id) != set(NetworkPathIdV1):
        _fail("RQ_E_PLAN_INCONSISTENT")
    return tuple(by_id[path_id] for path_id in NetworkPathIdV1)


def _parse_managed_states(value: object) -> tuple[ManagedStateFactV1, ...]:
    if type(value) is not list:
        _fail("RQ_E_PLAN_INCONSISTENT")
    by_id = {}
    for item in value:
        if type(item) is not dict or set(item) != _MANAGED_STATE_KEYS:
            _fail("RQ_E_PLAN_INCONSISTENT")
        raw_id = item["object_id"]
        raw_state = item["state"]
        if type(raw_id) is not str or type(raw_state) is not str:
            _fail("RQ_E_PLAN_INCONSISTENT")
        try:
            object_id = ManagedStateIdV1(raw_id)
            state = ManagedStateKindV1(raw_state)
        except ValueError:
            _fail("RQ_E_PLAN_INCONSISTENT")
        if object_id in by_id:
            _fail("RQ_E_PLAN_INCONSISTENT")
        if state is ManagedStateKindV1.FOREIGN:
            _fail("RQ_E_FOREIGN_STATE")
        generation = item["generation"]
        if state is ManagedStateKindV1.ABSENT:
            if generation is not None:
                _fail("RQ_E_PLAN_INCONSISTENT")
        elif not _is_ascii_line(generation) or len(generation) > 128:
            _fail("RQ_E_PLAN_INCONSISTENT")
        by_id[object_id] = ManagedStateFactV1(
            object_id=object_id,
            state=state,
            generation=generation,
        )
    if set(by_id) != set(ManagedStateIdV1):
        _fail("RQ_E_PLAN_INCONSISTENT")
    return tuple(by_id[object_id] for object_id in ManagedStateIdV1)


def _parse_host_facts(payload: object, target: SshTargetV1) -> RemoteQueenHostFactsV1:
    if type(payload) is not dict or set(payload) != _HOST_FACT_KEYS:
        _fail("RQ_E_PLAN_INCONSISTENT")
    if payload["schema_version"] != "RemoteQueenHostFactsV1":
        _fail("RQ_E_PLAN_INCONSISTENT")

    remote_user = payload["remote_user"]
    if not _is_ascii_line(remote_user) or len(remote_user) > 32:
        _fail("RQ_E_PLAN_INCONSISTENT")
    if target.user is not None and remote_user != target.user:
        _fail("RQ_E_PLAN_INCONSISTENT")
    remote_home = payload["remote_home"]
    shell = payload["shell"]
    if not _is_absolute_posix_path(
        remote_home, user_home=True
    ) or not _is_absolute_posix_path(shell, user_home=False):
        _fail("RQ_E_PLAN_INCONSISTENT")

    uid = payload["uid"]
    gid = payload["gid"]
    if (
        type(uid) is not int
        or type(gid) is not int
        or not 0 <= uid <= 2**31 - 1
        or not 0 <= gid <= 2**31 - 1
    ):
        _fail("RQ_E_PLAN_INCONSISTENT")

    versions = (
        payload["python_version"],
        payload["git_version"],
        payload["curl_version"],
        payload["syncthing_version"],
        payload["codex_version"],
    )
    if any(
        version is not None
        and (not _is_ascii_line(version) or len(version) > 128)
        for version in versions
    ):
        _fail("RQ_E_PLAN_INCONSISTENT")

    boolean_values = (
        payload["systemd_user_available"],
        payload["dbus_session_available"],
        payload["clock_synchronized"],
        payload["noninteractive_sudo_available"],
    )
    if any(type(value) is not bool for value in boolean_values):
        _fail("RQ_E_PLAN_INCONSISTENT")

    free_bytes = payload["free_bytes"]
    if type(free_bytes) is not int or not 0 <= free_bytes <= 2**63 - 1:
        _fail("RQ_E_PLAN_INCONSISTENT")
    if payload["selinux_mode"] not in _SELINUX_MODES or payload[
        "apparmor_mode"
    ] not in _APPARMOR_MODES:
        _fail("RQ_E_PLAN_INCONSISTENT")

    distribution_values = (
        payload["distribution_id"],
        payload["distribution_version"],
        payload["architecture"],
        payload["package_manager"],
    )
    if any(type(value) is not str for value in distribution_values):
        _fail("RQ_E_PLAN_INCONSISTENT")
    host_facts = HostFactsV1(
        distribution_id=payload["distribution_id"],
        distribution_version=payload["distribution_version"],
        architecture=payload["architecture"],
        package_manager=payload["package_manager"],
    )
    return RemoteQueenHostFactsV1(
        schema_version=payload["schema_version"],
        host_facts=host_facts,
        remote_user=remote_user,
        remote_home=remote_home,
        uid=uid,
        gid=gid,
        shell=shell,
        python_version=payload["python_version"],
        git_version=payload["git_version"],
        curl_version=payload["curl_version"],
        systemd_user_available=payload["systemd_user_available"],
        dbus_session_available=payload["dbus_session_available"],
        selinux_mode=payload["selinux_mode"],
        apparmor_mode=payload["apparmor_mode"],
        syncthing_version=payload["syncthing_version"],
        codex_version=payload["codex_version"],
        free_bytes=free_bytes,
        clock_synchronized=payload["clock_synchronized"],
        noninteractive_sudo_available=payload["noninteractive_sudo_available"],
        network_paths=_parse_network_paths(payload["network_paths"]),
        managed_states=_parse_managed_states(payload["managed_states"]),
    )


def _host_facts_as_dict(host_facts: RemoteQueenHostFactsV1) -> dict[str, object]:
    return {
        "schema_version": host_facts.schema_version,
        "distribution_id": host_facts.host_facts.distribution_id,
        "distribution_version": host_facts.host_facts.distribution_version,
        "architecture": host_facts.host_facts.architecture,
        "package_manager": host_facts.host_facts.package_manager,
        "remote_user": host_facts.remote_user,
        "remote_home": host_facts.remote_home,
        "uid": host_facts.uid,
        "gid": host_facts.gid,
        "shell": host_facts.shell,
        "python_version": host_facts.python_version,
        "git_version": host_facts.git_version,
        "curl_version": host_facts.curl_version,
        "systemd_user_available": host_facts.systemd_user_available,
        "dbus_session_available": host_facts.dbus_session_available,
        "selinux_mode": host_facts.selinux_mode,
        "apparmor_mode": host_facts.apparmor_mode,
        "syncthing_version": host_facts.syncthing_version,
        "codex_version": host_facts.codex_version,
        "free_bytes": host_facts.free_bytes,
        "clock_synchronized": host_facts.clock_synchronized,
        "noninteractive_sudo_available": host_facts.noninteractive_sudo_available,
        "network_paths": [
            {"path_id": item.path_id.value, "reachable": item.reachable}
            for item in host_facts.network_paths
        ],
        "managed_states": [
            {
                "object_id": item.object_id.value,
                "state": item.state.value,
                "generation": item.generation,
            }
            for item in host_facts.managed_states
        ],
    }


def _preflight_payload(
    preflight: RemoteQueenSshPreflightV1,
) -> dict[str, object]:
    return {
        "schema_version": preflight.schema_version,
        "ssh_target": {
            "user": preflight.ssh_target.user,
            "host": preflight.ssh_target.host,
        },
        "host_key": {
            "key_type": preflight.host_key.key_type,
            "sha256_fingerprint": preflight.host_key.sha256_fingerprint,
        },
        "desired_generation": {
            "generation": preflight.desired_generation.generation,
            "sha256": preflight.desired_generation.sha256,
        },
        "host_facts": _host_facts_as_dict(preflight.host_facts),
        "package_plan": {
            "manager": preflight.package_plan.manager,
            "packages": list(preflight.package_plan.packages),
        },
    }


def collect_remote_queen_ssh_preflight(
    *,
    ssh_target: SshTargetV1,
    desired_generation: ManifestGenerationV1,
    operations: RemoteQueenSshOperations,
    limits: SshOperationLimitsV1 = SshOperationLimitsV1(),
) -> RemoteQueenSshPreflightV1:
    if not isinstance(ssh_target, SshTargetV1) or not isinstance(
        desired_generation, ManifestGenerationV1
    ) or not isinstance(limits, SshOperationLimitsV1):
        _fail("RQ_E_PLAN_INCONSISTENT")

    try:
        known_host_keys = operations.known_host_keys(ssh_target)
    except Exception:
        _fail("RQ_E_SSH_PREFLIGHT")
    try:
        presented_host_key = operations.presented_host_key(ssh_target, limits)
    except Exception:
        _fail("RQ_E_SSH_PREFLIGHT")
    approved_host_key = approve_known_host_key(
        target=ssh_target,
        known_host_keys=known_host_keys,
        presented_host_key=presented_host_key,
    )
    try:
        result = operations.run_read_only(
            ssh_target,
            SshReadOnlyOperationV1.HOST_FACTS,
            expected_host_key_sha256=approved_host_key.sha256_fingerprint,
            limits=limits,
        )
    except Exception:
        _fail("RQ_E_SSH_PREFLIGHT")
    stdout = validate_ssh_operation_result(
        result,
        expected_operation=SshReadOnlyOperationV1.HOST_FACTS,
        approved_host_key=approved_host_key,
        limits=limits,
    )

    try:
        payload = json.loads(
            stdout.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        host_facts = _parse_host_facts(payload, ssh_target)
    except RemoteQueenBootstrapError:
        raise
    except Exception:
        _fail("RQ_E_PLAN_INCONSISTENT")

    package_plan = package_plan_for(host_facts.host_facts)
    preflight = RemoteQueenSshPreflightV1(
        schema_version="RemoteQueenSshPreflightV1",
        ssh_target=ssh_target,
        host_key=approved_host_key,
        desired_generation=desired_generation,
        host_facts=host_facts,
        package_plan=package_plan,
        preflight_digest="",
    )
    digest_payload = _preflight_payload(preflight)
    canonical = json.dumps(
        digest_payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return RemoteQueenSshPreflightV1(
        schema_version=preflight.schema_version,
        ssh_target=preflight.ssh_target,
        host_key=preflight.host_key,
        desired_generation=preflight.desired_generation,
        host_facts=preflight.host_facts,
        package_plan=preflight.package_plan,
        preflight_digest=digest,
    )


def preflight_as_dict(
    preflight: RemoteQueenSshPreflightV1,
) -> dict[str, object]:
    if not isinstance(preflight, RemoteQueenSshPreflightV1):
        _fail("RQ_E_PLAN_INCONSISTENT")
    payload = _preflight_payload(preflight)
    payload["preflight_digest"] = preflight.preflight_digest
    return payload
