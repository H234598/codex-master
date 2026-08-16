"""Transport-evidence attestation for fixed Hive resource reads."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Callable, Protocol

from codex_master.hive.authority import AuthorityEngine, AuthorityError, AuthorityRequest
from codex_master.hive.principals import PrincipalError, PrincipalRegistry
from codex_master.hive.types import HiveValidationError, validate_identifier


_ALLOWED_CAPABILITIES = frozenset({"hive.resource.trend.read", "hive.resource.absolute.read"})
_ALLOWED_CLASSES = frozenset({"teamleiterin", "koenigin", "queen"})
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RESOURCE_SCOPE = (".codex-master/resource-status",)
_MAX_TTL = timedelta(seconds=60)


class TransportPrincipalError(ValueError):
    """Public failure projection for transport-principal attestation."""

    def __init__(self, _detail: object = None) -> None:
        super().__init__("resource_access_denied")


def _deny() -> None:
    raise TransportPrincipalError() from None


def _identifier(value: object, field: str) -> str:
    try:
        return validate_identifier(value, field=field)  # type: ignore[arg-type]
    except HiveValidationError:
        _deny()
    raise AssertionError("unreachable")


def _digest(value: object) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        _deny()
    return value


def _utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta():
        _deny()
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class VerifiedTransportClaims:
    """Immutable verifier output containing only live-comparison claims."""

    principal_id: str
    class_id: str
    repo_id: str
    principal_version: int
    config_digest: str
    execution_binding_id: str
    transport_digest: str
    issued_at_utc: datetime
    expires_at_utc: datetime

    def __post_init__(self) -> None:
        _identifier(self.principal_id, "principal")
        _identifier(self.class_id, "class")
        _identifier(self.repo_id, "repo")
        _identifier(self.execution_binding_id, "binding")
        _digest(self.config_digest)
        _digest(self.transport_digest)
        if isinstance(self.principal_version, bool) or not isinstance(self.principal_version, int) or self.principal_version < 1:
            _deny()
        issued_at = _utc(self.issued_at_utc)
        expires_at = _utc(self.expires_at_utc)
        if expires_at <= issued_at or expires_at - issued_at > _MAX_TTL:
            _deny()


@dataclass(frozen=True, slots=True)
class AttestedPrincipalV1:
    """Immutable, non-cacheable principal state for one resource access."""

    attestation_schema_version: int
    principal_id: str
    class_id: str
    repo_id: str
    scope: tuple[str, ...]
    principal_version: int
    config_digest: str
    execution_binding_id: str
    attested_transport_digest: str
    expires_at_utc: datetime

    def __post_init__(self) -> None:
        if self.attestation_schema_version != 1:
            _deny()
        _identifier(self.principal_id, "principal")
        if self.class_id not in _ALLOWED_CLASSES:
            _deny()
        _identifier(self.repo_id, "repo")
        if self.scope != _RESOURCE_SCOPE:
            _deny()
        if isinstance(self.principal_version, bool) or not isinstance(self.principal_version, int) or self.principal_version < 1:
            _deny()
        _digest(self.config_digest)
        _identifier(self.execution_binding_id, "binding")
        _digest(self.attested_transport_digest)
        _utc(self.expires_at_utc)


class TransportEvidenceVerifier(Protocol):
    """Verify opaque transport evidence against one injected UTC instant."""

    def verify(self, evidence: object, *, now: datetime) -> VerifiedTransportClaims:
        """Return bounded, immutable claims or raise TransportPrincipalError."""


class TransportPrincipalAdapter:
    """Revalidate verified transport claims through existing Hive owners."""

    def __init__(
        self,
        principals: PrincipalRegistry,
        authority: AuthorityEngine,
        verifier: TransportEvidenceVerifier,
        *,
        now: Callable[[], datetime],
    ) -> None:
        if (
            not isinstance(principals, PrincipalRegistry)
            or not isinstance(authority, AuthorityEngine)
            or not callable(getattr(verifier, "verify", None))
            or not callable(now)
        ):
            _deny()
        if authority.context.principals is not principals:
            _deny()
        self._principals = principals
        self._authority = authority
        self._verifier = verifier
        self._now = now

    def attest(self, evidence: object, *, capability: str) -> AttestedPrincipalV1:
        """Return current attestation or the uniform public denial."""

        if capability not in _ALLOWED_CAPABILITIES:
            _deny()
        now = _utc(self._now())
        try:
            claims = self._verifier.verify(evidence, now=now)
        except TransportPrincipalError:
            _deny()
        if not isinstance(claims, VerifiedTransportClaims):
            _deny()
        if (
            claims.class_id not in _ALLOWED_CLASSES
            or claims.issued_at_utc > now
            or claims.expires_at_utc <= now
        ):
            _deny()
        try:
            binding = self._principals.get_active_execution_binding(
                claims.execution_binding_id,
                claims.principal_id,
                claims.repo_id,
                now=now,
            )
            principal = self._principals.get(claims.principal_id)
        except PrincipalError:
            _deny()
        if (
            principal.state != "active"
            or principal.class_id != claims.class_id
            or principal.version != claims.principal_version
            or principal.config_digest != claims.config_digest
            or principal.repo_id != claims.repo_id
            or binding.binding_id != claims.execution_binding_id
            or binding.principal_id != claims.principal_id
            or binding.repo_id != claims.repo_id
            or claims.expires_at_utc > _binding_expiry(binding.expires_at_utc)
        ):
            _deny()
        try:
            decision = self._authority.authorize(
                AuthorityRequest(
                    claims.principal_id,
                    capability,
                    claims.repo_id,
                    None,
                    None,
                    _RESOURCE_SCOPE,
                    (),
                )
            )
        except AuthorityError:
            _deny()
        if not decision.allowed:
            _deny()
        return AttestedPrincipalV1(
            attestation_schema_version=1,
            principal_id=claims.principal_id,
            class_id=claims.class_id,
            repo_id=claims.repo_id,
            scope=_RESOURCE_SCOPE,
            principal_version=claims.principal_version,
            config_digest=claims.config_digest,
            execution_binding_id=claims.execution_binding_id,
            attested_transport_digest=claims.transport_digest,
            expires_at_utc=claims.expires_at_utc,
        )


def _binding_expiry(value: object) -> datetime:
    if not isinstance(value, str):
        _deny()
    try:
        return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        _deny()
    raise AssertionError("unreachable")


__all__ = [
    "AttestedPrincipalV1",
    "TransportEvidenceVerifier",
    "TransportPrincipalAdapter",
    "TransportPrincipalError",
    "VerifiedTransportClaims",
]
