"""Private, fail-closed GA-I2d P1a read-only deployment composition.

P1a deliberately owns neither an effect port nor a quiescence issuer.  It
only retains explicitly supplied P0 read ports, resolves existing quiescence
evidence, projects the two-field public candidate view, and safely reads an
already materialized request descriptor.
"""

from __future__ import annotations

from collections.abc import Mapping
import fcntl
import os
import stat
from typing import Final, Literal, Protocol

from .google_inventory_deployment_quiescence_authority import (
    QuiescenceReceipt,
    _PlanBindingPort,
    _PrincipalLeaseScopePort,
    _TargetsetPort,
)


_MAX_REQUEST_BYTES: Final[int] = 16 * 1024
_MEMFD_REQUIRED_SEALS: Final[int] = (
    fcntl.F_SEAL_WRITE
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_SEAL
)


class DeploymentOwnerUnavailable(RuntimeError):
    """The source-only owner lacks safe, complete read-only evidence."""

    code: Final[str] = "inventory.deployment_owner_unavailable"

    def __init__(self) -> None:
        super().__init__(self.code)


class _QuiescenceResolver(Protocol):
    def resolve(self, receipt_reference: str) -> QuiescenceReceipt | None:
        """Resolve existing P0 quiescence evidence without mutation."""


def public_candidate_metadata(record: object) -> dict[str, str]:
    """Project only the two D337-authorized public candidate fields."""

    try:
        if isinstance(record, Mapping):
            account_ref = record["account_ref"]
            candidate_fingerprint = record["candidate_fingerprint"]
        else:
            account_ref = getattr(record, "account_ref")
            candidate_fingerprint = getattr(record, "candidate_fingerprint")
    except Exception as exc:
        raise DeploymentOwnerUnavailable() from exc
    if type(account_ref) is not str or type(candidate_fingerprint) is not str:
        raise DeploymentOwnerUnavailable()
    return {
        "account_ref": account_ref,
        "candidate_fingerprint": candidate_fingerprint,
    }


def read_request_bytes_from_fd(fd: int) -> bytes:
    """Read bounded request bytes from a stable regular file or sealed memfd."""

    if type(fd) is not int or fd < 0:
        raise DeploymentOwnerUnavailable()
    duplicate = -1
    result: bytes | None = None
    failure: Exception | None = None
    try:
        duplicate = os.dup(fd)
        before = os.fstat(duplicate)
        if not stat.S_ISREG(before.st_mode):
            raise DeploymentOwnerUnavailable()
        if before.st_size < 0 or before.st_size > _MAX_REQUEST_BYTES:
            raise DeploymentOwnerUnavailable()
        try:
            descriptor_target = os.readlink(f"/proc/self/fd/{duplicate}")
        except OSError as exc:
            raise DeploymentOwnerUnavailable() from exc
        if descriptor_target.startswith("/memfd:"):
            try:
                seals = fcntl.fcntl(duplicate, fcntl.F_GET_SEALS)
            except OSError as exc:
                raise DeploymentOwnerUnavailable() from exc
            if (
                type(seals) is not int
                or seals & _MEMFD_REQUIRED_SEALS != _MEMFD_REQUIRED_SEALS
            ):
                raise DeploymentOwnerUnavailable()
        result = os.pread(duplicate, before.st_size, 0)
        if type(result) is not bytes or len(result) != before.st_size:
            raise DeploymentOwnerUnavailable()
        after = os.fstat(duplicate)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_rdev,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_rdev,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise DeploymentOwnerUnavailable()
    except Exception as exc:
        failure = exc
    finally:
        if duplicate >= 0:
            try:
                os.close(duplicate)
            except OSError as exc:
                if failure is None:
                    failure = exc
    if failure is not None:
        if isinstance(failure, DeploymentOwnerUnavailable):
            raise failure
        raise DeploymentOwnerUnavailable() from failure
    if result is None:
        raise DeploymentOwnerUnavailable()
    return result


class GoogleInventoryDeploymentOwnerV1:
    """P1a's explicit, read-only P0 composition boundary."""

    __slots__ = (
        "_plan_binding",
        "_principal_lease_scope",
        "_targetset",
        "_quiescence_resolver",
    )

    def __init__(
        self,
        *,
        plan_binding: _PlanBindingPort,
        principal_lease_scope: _PrincipalLeaseScopePort,
        targetset: _TargetsetPort,
        quiescence_resolver: _QuiescenceResolver,
    ) -> None:
        if not callable(getattr(plan_binding, "read", None)):
            raise DeploymentOwnerUnavailable()
        if not callable(getattr(principal_lease_scope, "read", None)):
            raise DeploymentOwnerUnavailable()
        if not callable(getattr(targetset, "read", None)):
            raise DeploymentOwnerUnavailable()
        if not callable(getattr(quiescence_resolver, "resolve", None)):
            raise DeploymentOwnerUnavailable()
        self._plan_binding = plan_binding
        self._principal_lease_scope = principal_lease_scope
        self._targetset = targetset
        self._quiescence_resolver = quiescence_resolver

    def resolve_quiescence(self, receipt_reference: str) -> QuiescenceReceipt:
        """Resolve extant P0 evidence; absence and uncertainty stay closed."""

        if type(receipt_reference) is not str or not receipt_reference:
            raise DeploymentOwnerUnavailable()
        try:
            receipt = self._quiescence_resolver.resolve(receipt_reference)
        except Exception as exc:
            raise DeploymentOwnerUnavailable() from exc
        if receipt is None:
            raise DeploymentOwnerUnavailable()
        return receipt

    def effect(self) -> Literal["unavailable"]:
        """P1a has no D212 effect binding or action value."""

        return "unavailable"


__all__: tuple[str, ...] = ()
