import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .remote_queen_bootstrap import (
    RemoteQueenBootstrapError,
    SshTargetV1,
)


MAX_SSH_CONNECT_TIMEOUT_SECONDS = 10
MAX_SSH_OPERATION_TIMEOUT_SECONDS = 30
MAX_SSH_STDOUT_BYTES = 64 * 1024
MAX_SSH_STDERR_BYTES = 8 * 1024

SSH_HOST_KEY_TYPES = frozenset(
    {"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"}
)

_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")


def _error(code: str) -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError(code)


def _valid_fingerprint(value: object) -> bool:
    return isinstance(value, str) and _FINGERPRINT.fullmatch(value) is not None


def _validate_host_key_fields(
    host: object,
    key_type: object,
    sha256_fingerprint: object,
) -> None:
    if (
        not isinstance(host, str)
        or not host
        or not isinstance(key_type, str)
        or key_type not in SSH_HOST_KEY_TYPES
        or not _valid_fingerprint(sha256_fingerprint)
    ):
        raise _error("RQ_E_PLAN_INCONSISTENT")


def _validate_limits(limits: "SshOperationLimitsV1") -> None:
    fields = (
        (limits.connect_timeout_seconds, 1, MAX_SSH_CONNECT_TIMEOUT_SECONDS),
        (
            limits.operation_timeout_seconds,
            1,
            MAX_SSH_OPERATION_TIMEOUT_SECONDS,
        ),
        (limits.max_stdout_bytes, 1, MAX_SSH_STDOUT_BYTES),
        (limits.max_stderr_bytes, 1, MAX_SSH_STDERR_BYTES),
    )
    if any(
        type(value) is not int or not lower <= value <= upper
        for value, lower, upper in fields
    ):
        raise _error("RQ_E_PLAN_INCONSISTENT")


class SshReadOnlyOperationV1(str, Enum):
    HOST_FACTS = "host-facts-v1"


@dataclass(frozen=True, slots=True)
class SshOperationLimitsV1:
    connect_timeout_seconds: int = 5
    operation_timeout_seconds: int = 15
    max_stdout_bytes: int = MAX_SSH_STDOUT_BYTES
    max_stderr_bytes: int = MAX_SSH_STDERR_BYTES

    def __post_init__(self) -> None:
        _validate_limits(self)


@dataclass(frozen=True, slots=True)
class KnownHostKeyV1:
    host: str
    key_type: str
    sha256_fingerprint: str
    revoked: bool = False

    def __post_init__(self) -> None:
        _validate_host_key_fields(
            self.host,
            self.key_type,
            self.sha256_fingerprint,
        )
        if type(self.revoked) is not bool:
            raise _error("RQ_E_PLAN_INCONSISTENT")


@dataclass(frozen=True, slots=True)
class PresentedHostKeyV1:
    host: str
    key_type: str
    sha256_fingerprint: str

    def __post_init__(self) -> None:
        _validate_host_key_fields(
            self.host,
            self.key_type,
            self.sha256_fingerprint,
        )


@dataclass(frozen=True, slots=True)
class ApprovedHostKeyV1:
    host: str
    key_type: str
    sha256_fingerprint: str

    def __post_init__(self) -> None:
        _validate_host_key_fields(
            self.host,
            self.key_type,
            self.sha256_fingerprint,
        )


@dataclass(frozen=True, slots=True, repr=False)
class SshOperationResultV1:
    operation: SshReadOnlyOperationV1
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    host_key_fingerprint: str

    def __repr__(self) -> str:
        return "SshOperationResultV1(<redacted>)"


class RemoteQueenSshOperations(Protocol):
    def known_host_keys(
        self, target: SshTargetV1
    ) -> tuple[KnownHostKeyV1, ...]: ...

    def presented_host_key(
        self,
        target: SshTargetV1,
        limits: SshOperationLimitsV1,
    ) -> PresentedHostKeyV1: ...

    def run_read_only(
        self,
        target: SshTargetV1,
        operation: SshReadOnlyOperationV1,
        *,
        expected_host_key_sha256: str,
        limits: SshOperationLimitsV1,
    ) -> SshOperationResultV1: ...


def _validate_known_host_key(value: object) -> None:
    if not isinstance(value, KnownHostKeyV1):
        raise _error("RQ_E_PLAN_INCONSISTENT")
    _validate_host_key_fields(
        value.host,
        value.key_type,
        value.sha256_fingerprint,
    )
    if type(value.revoked) is not bool:
        raise _error("RQ_E_PLAN_INCONSISTENT")


def _validate_presented_host_key(value: object) -> None:
    if not isinstance(value, PresentedHostKeyV1):
        raise _error("RQ_E_PLAN_INCONSISTENT")
    _validate_host_key_fields(
        value.host,
        value.key_type,
        value.sha256_fingerprint,
    )


def _validate_approved_host_key(value: object) -> None:
    if not isinstance(value, ApprovedHostKeyV1):
        raise _error("RQ_E_PLAN_INCONSISTENT")
    _validate_host_key_fields(
        value.host,
        value.key_type,
        value.sha256_fingerprint,
    )


def approve_known_host_key(
    *,
    target: SshTargetV1,
    known_host_keys: tuple[KnownHostKeyV1, ...],
    presented_host_key: PresentedHostKeyV1,
) -> ApprovedHostKeyV1:
    if not isinstance(target, SshTargetV1):
        raise _error("RQ_E_PLAN_INCONSISTENT")
    if type(known_host_keys) is not tuple:
        raise _error("RQ_E_PLAN_INCONSISTENT")
    _validate_presented_host_key(presented_host_key)
    for known_host_key in known_host_keys:
        _validate_known_host_key(known_host_key)

    if presented_host_key.host != target.host:
        raise _error("RQ_E_SSH_HOSTKEY")

    exact_matches = tuple(
        known_host_key
        for known_host_key in known_host_keys
        if (
            known_host_key.host == presented_host_key.host
            and known_host_key.key_type == presented_host_key.key_type
            and known_host_key.sha256_fingerprint
            == presented_host_key.sha256_fingerprint
        )
    )
    if any(known_host_key.revoked for known_host_key in exact_matches):
        raise _error("RQ_E_SSH_HOSTKEY")
    if not exact_matches:
        raise _error("RQ_E_SSH_HOSTKEY")
    return ApprovedHostKeyV1(
        host=presented_host_key.host,
        key_type=presented_host_key.key_type,
        sha256_fingerprint=presented_host_key.sha256_fingerprint,
    )


def validate_ssh_operation_result(
    result: SshOperationResultV1,
    *,
    expected_operation: SshReadOnlyOperationV1,
    approved_host_key: ApprovedHostKeyV1,
    limits: SshOperationLimitsV1,
) -> bytes:
    if (
        not isinstance(result, SshOperationResultV1)
        or not isinstance(expected_operation, SshReadOnlyOperationV1)
        or not isinstance(approved_host_key, ApprovedHostKeyV1)
        or not isinstance(limits, SshOperationLimitsV1)
    ):
        raise _error("RQ_E_PLAN_INCONSISTENT")
    _validate_approved_host_key(approved_host_key)
    _validate_limits(limits)

    if not isinstance(result.operation, SshReadOnlyOperationV1):
        raise _error("RQ_E_PLAN_INCONSISTENT")
    if result.operation != expected_operation:
        raise _error("RQ_E_PLAN_INCONSISTENT")
    if not isinstance(result.host_key_fingerprint, str) or not _valid_fingerprint(
        result.host_key_fingerprint
    ):
        raise _error("RQ_E_PLAN_INCONSISTENT")
    if result.host_key_fingerprint != approved_host_key.sha256_fingerprint:
        raise _error("RQ_E_SSH_HOSTKEY")
    if type(result.returncode) is not int:
        raise _error("RQ_E_PLAN_INCONSISTENT")
    if type(result.stdout) is not bytes or type(result.stderr) is not bytes:
        raise _error("RQ_E_PLAN_INCONSISTENT")
    if (
        type(result.timed_out) is not bool
        or type(result.stdout_truncated) is not bool
        or type(result.stderr_truncated) is not bool
    ):
        raise _error("RQ_E_PLAN_INCONSISTENT")
    if result.timed_out or result.stdout_truncated or result.stderr_truncated:
        raise _error("RQ_E_SSH_PREFLIGHT")
    if len(result.stdout) > limits.max_stdout_bytes:
        raise _error("RQ_E_SSH_PREFLIGHT")
    if len(result.stderr) > limits.max_stderr_bytes:
        raise _error("RQ_E_SSH_PREFLIGHT")
    if result.returncode != 0:
        raise _error("RQ_E_SSH_PREFLIGHT")
    return result.stdout
