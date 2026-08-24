"""Injected, FD-pinned agent launch preparation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Protocol

from codex_master.fleet_home_broker_client import AttestedHome
from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_home_broker_linux import FdStat
from codex_master.fleet_home_broker_protocol import (
    BindingExpectation,
    BrokerReply,
    BrokerResultCode,
    CANONICAL_AGENT_HOME,
    ChpbMessageKind,
    DirectoryIdentity,
    HomeAttestation,
    PrincipalBinding,
    TransactionBinding,
    TransactionStatus,
    validate_chpb_message,
    validate_principal_binding,
    validate_transaction_binding,
)


class LauncherError(ValueError):
    """Raised when an agent launch plan cannot be attested."""


@dataclass(frozen=True, slots=True)
class ExecutablePin:
    path: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class AgentLaunchPlan:
    executable: ExecutablePin
    environment: tuple[tuple[str, str], ...]
    home_fd: int


class LauncherOperations(Protocol):
    def open_agent_parent(self) -> int: ...

    def openat2(
        self, parent_fd: int, child_name: str, flags: int, resolve: int
    ) -> int: ...

    def fstat(self, fd: int) -> FdStat: ...

    def close(self, fd: int) -> None: ...

    def executable_fingerprint(self, path: str) -> str: ...


_OPENAT2_FLAGS = 0o10000000 | 0o200000 | 0o400000 | 0o2000000
_OPENAT2_RESOLVE = 0x08 | 0x04 | 0x02
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


def _fail(message: str) -> None:
    raise LauncherError(message)


def _validate_expected(
    expected_principal: PrincipalBinding,
    expected: BindingExpectation,
    identity: BrokerIdentity,
) -> None:
    if type(expected_principal) is not PrincipalBinding:
        _fail("expected principal has wrong type")
    try:
        validate_principal_binding(expected_principal)
    except Exception as exc:
        raise LauncherError("expected principal is invalid") from exc

    if type(expected) is not BindingExpectation:
        _fail("binding expectation has wrong type")
    if type(identity) is not BrokerIdentity:
        _fail("broker identity has wrong type")
    if (
        type(expected.agent_id) is not str
        or type(expected.manifest_generation) is not int
        or type(expected.unit_generation) is not int
        or type(expected.policy_generation) is not int
        or type(expected.projection_digest) is not str
        or type(expected.fencing_epoch) is not int
        or expected.projection_digest != expected.projection_digest.lower()
        or _SHA256.fullmatch(expected.projection_digest) is None
        or expected.agent_id != expected_principal.agent_id
        or expected.manifest_generation != expected_principal.manifest_generation
        or expected.unit_generation != expected_principal.unit_generation
        or expected.policy_generation <= 0
        or expected.fencing_epoch != expected_principal.fencing_epoch
    ):
        _fail("binding expectation drifted")
    if (
        identity.agent_id != expected.agent_id
        or identity.manifest_generation != expected.manifest_generation
        or identity.mcs_pair != expected_principal.mcs_pair
        or identity.policy_generation != expected.policy_generation
        or identity.projection_digest != expected.projection_digest
        or identity.fencing_epoch != expected.fencing_epoch
    ):
        _fail("broker identity drifted")


def _validate_home(
    home: AttestedHome,
    expected_principal: PrincipalBinding,
    expected: BindingExpectation,
) -> None:
    if type(home) is not AttestedHome:
        _fail("attested home has wrong type")
    if type(home.fd) is not int or home.fd < 0:
        _fail("attested home fd is invalid")
    if type(home.reply) is not BrokerReply:
        _fail("attested home reply has wrong type")
    try:
        validate_chpb_message(home.reply)
    except Exception as exc:
        raise LauncherError("broker reply is invalid") from exc
    if (
        home.reply.kind is not ChpbMessageKind.REPLY
        or home.reply.result is not BrokerResultCode.OK
    ):
        _fail("attested home reply is not successful")
    if type(home.attestation) is not HomeAttestation:
        _fail("attestation has wrong type")
    if home.reply.attestation != home.attestation:
        _fail("reply and attestation differ")
    if type(home.reply.transaction) is not TransactionStatus:
        _fail("attested home transaction has wrong type")

    attestation = home.attestation
    binding = attestation.binding
    if type(binding) is not TransactionBinding:
        _fail("attestation binding has wrong type")
    if type(attestation.directory) is not DirectoryIdentity:
        _fail("attestation directory has wrong type")
    try:
        validate_transaction_binding(binding)
    except Exception as exc:
        raise LauncherError("attestation binding is invalid") from exc
    if home.reply.transaction.binding != binding:
        _fail("reply transaction and attestation differ")
    if attestation.canonical_path != CANONICAL_AGENT_HOME:
        _fail("home path is not canonical")
    if binding.principal != expected_principal:
        _fail("home principal drifted")
    if (
        binding.policy.policy_generation != expected.policy_generation
        or binding.policy.projection_digest != expected.projection_digest
    ):
        _fail("home policy drifted")
    if attestation.mcs_pair != expected_principal.mcs_pair:
        _fail("home MCS binding drifted")


def _validate_executable(executable: ExecutablePin, identity: BrokerIdentity) -> None:
    if type(executable) is not ExecutablePin:
        _fail("executable pin has wrong type")
    if (
        type(executable.path) is not str
        or not executable.path.startswith("/")
        or executable.path != executable.path.strip()
        or "//" in executable.path
        or executable.path.endswith("/")
        or "\x00" in executable.path
        or "\\" in executable.path
    ):
        _fail("executable path is not canonical")
    path_parts = executable.path.split("/")
    if (
        not path_parts
        or any(part in {"", ".", ".."} for part in path_parts[1:])
        or tuple(path_parts[-3:-1]) == ("self", "fd")
    ):
        _fail("executable path is not canonical")
    if (
        type(executable.fingerprint) is not str
        or _SHA256.fullmatch(executable.fingerprint) is None
        or executable.fingerprint != executable.fingerprint.lower()
        or executable.fingerprint != identity.executable_fingerprint
    ):
        _fail("executable fingerprint drifted")


def _copy_environment(environment: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    if not isinstance(environment, Mapping):
        _fail("environment has wrong type")
    try:
        copied = dict(environment)
    except Exception as exc:
        raise LauncherError("environment cannot be copied") from exc
    if any(
        type(key) is not str or type(value) is not str for key, value in copied.items()
    ):
        _fail("environment contains non-text values")
    copied["CODEX_HOME"] = CANONICAL_AGENT_HOME
    copied["HOME"] = CANONICAL_AGENT_HOME
    copied["GEMINI_CLI_HOME"] = CANONICAL_AGENT_HOME
    return tuple(sorted(copied.items()))


def _validate_operations(operations: LauncherOperations) -> None:
    required = (
        "open_agent_parent",
        "openat2",
        "fstat",
        "close",
        "executable_fingerprint",
    )
    if any(not callable(getattr(operations, name, None)) for name in required):
        _fail("launcher operations are incomplete")


def _same_stat(observed: FdStat, expected: object) -> bool:
    return (
        type(observed) is FdStat
        and observed.dev == expected.dev
        and observed.ino == expected.ino
        and observed.mode == expected.mode
    )


def _close_fds(
    operations: LauncherOperations, fds: tuple[int, ...]
) -> BaseException | None:
    first_error = None
    for fd in fds:
        try:
            operations.close(fd)
        except Exception as exc:
            if first_error is None:
                first_error = exc
    return first_error


def prepare_agent_launch(
    home: AttestedHome,
    expected_principal: PrincipalBinding,
    expected: BindingExpectation,
    identity: BrokerIdentity,
    executable: ExecutablePin,
    environment: Mapping[str, str],
    operations: LauncherOperations,
) -> AgentLaunchPlan:
    """Validate injected state and return a launch plan without starting anything."""

    scm_fd = (
        home.fd
        if type(home) is AttestedHome and type(home.fd) is int and home.fd >= 0
        else None
    )
    parent_fd = None
    path_fd = None
    failure = None
    plan = None
    try:
        _validate_operations(operations)
        _validate_expected(expected_principal, expected, identity)
        _validate_home(home, expected_principal, expected)
        _validate_executable(executable, identity)
        copied_environment = _copy_environment(environment)

        parent_fd = operations.open_agent_parent()
        if type(parent_fd) is not int or parent_fd < 0:
            _fail("agent parent fd is invalid")
        path_fd = operations.openat2(
            parent_fd,
            "home",
            _OPENAT2_FLAGS,
            _OPENAT2_RESOLVE,
        )
        if type(path_fd) is not int or path_fd < 0:
            _fail("home path fd is invalid")

        scm_stat = operations.fstat(home.fd)
        path_stat = operations.fstat(path_fd)
        expected_directory = home.attestation.directory
        if not _same_stat(scm_stat, expected_directory):
            _fail("SCM home fd identity drifted")
        if not _same_stat(path_stat, expected_directory):
            _fail("path home fd identity drifted")

        observed_fingerprint = operations.executable_fingerprint(executable.path)
        if observed_fingerprint != executable.fingerprint:
            _fail("observed executable fingerprint drifted")

        plan = AgentLaunchPlan(executable, copied_environment, path_fd)
    except LauncherError as exc:
        failure = exc
    except Exception as exc:
        failure = LauncherError("launch attestation failed")
        failure.__cause__ = exc

    cleanup = []
    if scm_fd is not None:
        cleanup.append(scm_fd)
    if failure is not None and path_fd is not None:
        cleanup.append(path_fd)
    if parent_fd is not None:
        cleanup.append(parent_fd)
    close_error = _close_fds(operations, tuple(cleanup))
    if close_error is not None:
        if path_fd is not None and failure is None:
            _close_fds(operations, (path_fd,))
        raise LauncherError("fd close failed") from close_error
    if failure is not None:
        raise failure
    return plan


__all__ = [
    "AgentLaunchPlan",
    "ExecutablePin",
    "LauncherError",
    "LauncherOperations",
    "prepare_agent_launch",
]
