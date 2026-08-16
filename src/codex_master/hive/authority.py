"""Deny-by-default capability grants and replay-safe authority checks."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import contextlib
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import PurePosixPath
import re
from threading import RLock
from typing import Callable

from codex_master.hive.principals import Principal, PrincipalError, PrincipalRegistry
from codex_master.hive.repositories import RepositoryError, RepositoryRegistry
from codex_master.hive.state import HiveStateError, HiveStateStore
from codex_master.hive.types import HiveValidationError, validate_identifier, validate_utc_datetime


_CAPABILITY_RE = re.compile(r"[a-z][a-z0-9_-]{1,127}\.[a-z][a-z0-9_.-]{1,127}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GRANT_STATES = {"active", "consumed", "revoked", "expired"}
MAX_GRANT_TTL_SECONDS = 24 * 60 * 60
MAX_GRANT_PATHS = 256


class AuthorityError(ValueError):
    """Raised when authority state cannot be loaded or safely changed."""


@dataclass(frozen=True, slots=True)
class AuthorityRequest:
    actor_principal_id: str
    capability: str
    repo_id: str | None
    dispatch_id: str | None
    workpackage_id: str | None
    scope: tuple[str, ...]
    write_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.actor_principal_id, "actor_principal")
        _capability(self.capability)
        if self.repo_id is not None:
            _identifier(self.repo_id, "repo")
        if self.dispatch_id is not None:
            _identifier(self.dispatch_id, "dispatch")
        if self.workpackage_id is not None:
            _identifier(self.workpackage_id, "workpackage")
        _paths(self.scope, "invalid_scope")
        _paths(self.write_paths, "invalid_write_paths", allow_empty=True)


@dataclass(frozen=True, slots=True)
class AuthorityDecision:
    allowed: bool
    reason_code: str
    grant_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool) or not isinstance(self.reason_code, str) or not re.fullmatch(
            r"[a-z][a-z0-9_]{1,95}", self.reason_code
        ):
            raise AuthorityError("invalid_authority_decision")
        if self.grant_id is not None:
            _identifier(self.grant_id, "grant")

    def public(self) -> dict[str, object]:
        return {"allowed": self.allowed, "reason_code": self.reason_code, "grant_id": self.grant_id}


@dataclass(frozen=True, slots=True)
class DelegationGrant:
    schema_version: int
    grant_id: str
    issuer_principal_id: str
    subject_principal_id: str
    repo_id: str
    dispatch_id: str | None
    capabilities: tuple[str, ...]
    scope: tuple[str, ...]
    write_paths: tuple[str, ...]
    max_delegation_depth: int
    issued_at_utc: datetime
    expires_at_utc: datetime
    nonce_digest: str
    request_digest: str
    status: str
    version: int

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise AuthorityError("unsupported_grant_schema")
        for value, field in (
            (self.grant_id, "grant"),
            (self.issuer_principal_id, "issuer_principal"),
            (self.subject_principal_id, "subject_principal"),
            (self.repo_id, "repo"),
        ):
            _identifier(value, field)
        if self.dispatch_id is not None:
            _identifier(self.dispatch_id, "dispatch")
        if not isinstance(self.capabilities, tuple) or not self.capabilities:
            raise AuthorityError("invalid_grant_capabilities")
        for capability in self.capabilities:
            _capability(capability)
        _paths(self.scope, "invalid_grant_scope")
        _paths(self.write_paths, "invalid_grant_write_paths", allow_empty=True)
        if isinstance(self.max_delegation_depth, bool) or not 0 <= self.max_delegation_depth <= 32:
            raise AuthorityError("invalid_delegation_depth")
        issued = validate_utc_datetime(self.issued_at_utc, field="issued")
        expires = validate_utc_datetime(self.expires_at_utc, field="expires")
        ttl = (expires - issued).total_seconds()
        if ttl <= 0 or ttl > MAX_GRANT_TTL_SECONDS:
            raise AuthorityError("invalid_grant_ttl")
        if not _DIGEST_RE.fullmatch(self.nonce_digest) or not _DIGEST_RE.fullmatch(self.request_digest):
            raise AuthorityError("invalid_grant_digest")
        if self.status not in _GRANT_STATES:
            raise AuthorityError("invalid_grant_state")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or not 1 <= self.version <= 10**12:
            raise AuthorityError("invalid_grant_version")

    def public(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "grant_id": self.grant_id,
            "issuer_principal_id": self.issuer_principal_id,
            "subject_principal_id": self.subject_principal_id,
            "repo_id": self.repo_id,
            "dispatch_id": self.dispatch_id,
            "capabilities": list(self.capabilities),
            "scope_count": len(self.scope),
            "write_path_count": len(self.write_paths),
            "max_delegation_depth": self.max_delegation_depth,
            "issued_at_utc": self.issued_at_utc.isoformat(),
            "expires_at_utc": self.expires_at_utc.isoformat(),
            "status": self.status,
            "version": self.version,
        }

    def binding_digest(self) -> str:
        """Return the immutable digest used to bind an admission to this grant."""

        payload = {
            "schema_version": self.schema_version,
            "grant_id": self.grant_id,
            "issuer_principal_id": self.issuer_principal_id,
            "subject_principal_id": self.subject_principal_id,
            "repo_id": self.repo_id,
            "dispatch_id": self.dispatch_id,
            "capabilities": list(self.capabilities),
            "scope": list(self.scope),
            "write_paths": list(self.write_paths),
            "max_delegation_depth": self.max_delegation_depth,
            "issued_at_utc": self.issued_at_utc.isoformat(),
            "expires_at_utc": self.expires_at_utc.isoformat(),
            "nonce_digest": self.nonce_digest,
            "request_digest": self.request_digest,
            "status": self.status,
            "version": self.version,
        }
        canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


@dataclass(frozen=True, slots=True)
class AuthorityContext:
    principals: PrincipalRegistry
    repositories: RepositoryRegistry
    capabilities: Mapping[str, frozenset[str]]

    def __post_init__(self) -> None:
        if not isinstance(self.principals, PrincipalRegistry) or not isinstance(self.repositories, RepositoryRegistry):
            raise AuthorityError("invalid_authority_context")
        if not isinstance(self.capabilities, Mapping):
            raise AuthorityError("invalid_authority_capabilities")
        for profile, values in self.capabilities.items():
            if not isinstance(profile, str) or not isinstance(values, frozenset):
                raise AuthorityError("invalid_authority_capabilities")
            for capability in values:
                _capability(capability)


class AuthorityEngine:
    """Authority evaluator and grant store with one replay-consuming lock."""

    def __init__(
        self,
        context: AuthorityContext,
        *,
        state: HiveStateStore | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(context, AuthorityContext):
            raise AuthorityError("invalid_authority_context")
        if state is not None and not isinstance(state, HiveStateStore):
            raise AuthorityError("invalid_authority_state_store")
        self._context = context
        self._state = state
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._grants: dict[str, DelegationGrant] = {}
        if state is not None:
            self._load()

    def authorize(self, request: AuthorityRequest) -> AuthorityDecision:
        """Check a live principal against one capability request."""

        if not isinstance(request, AuthorityRequest):
            raise AuthorityError("invalid_authority_request")
        try:
            actor = self._context.principals.get(request.actor_principal_id)
        except PrincipalError:
            return AuthorityDecision(False, "principal_not_found")
        if actor.state != "active":
            return AuthorityDecision(False, "principal_inactive")
        if request.capability not in self._capabilities(actor):
            return AuthorityDecision(False, "capability_denied")
        if request.repo_id != actor.repo_id:
            return AuthorityDecision(False, "repository_mismatch")
        if not self._scope_allowed(request.repo_id, request.scope, request.write_paths):
            return AuthorityDecision(False, "scope_denied")
        return AuthorityDecision(True, "authorized")

    @property
    def context(self) -> AuthorityContext:
        """Return the immutable context used for authority evaluation."""

        return self._context

    def issue_grant(
        self,
        *,
        grant_id: str,
        issuer_principal_id: str,
        subject_principal_id: str,
        repo_id: str,
        dispatch_id: str | None,
        capabilities: Iterable[str],
        scope: Iterable[str],
        write_paths: Iterable[str],
        max_delegation_depth: int,
        issued_at_utc: datetime,
        expires_at_utc: datetime,
        nonce: str,
        request_digest: str,
    ) -> DelegationGrant:
        grant = self._build_grant(
            grant_id=grant_id,
            issuer_principal_id=issuer_principal_id,
            subject_principal_id=subject_principal_id,
            repo_id=repo_id,
            dispatch_id=dispatch_id,
            capabilities=capabilities,
            scope=scope,
            write_paths=write_paths,
            max_delegation_depth=max_delegation_depth,
            issued_at_utc=issued_at_utc,
            expires_at_utc=expires_at_utc,
            nonce=nonce,
            request_digest=request_digest,
        )
        with self._transaction():
            if grant.grant_id in self._grants:
                raise AuthorityError("duplicate_grant")
            self._grants[grant.grant_id] = grant
            self._persist()
            return grant

    def consume_grant(self, grant_id: str, nonce: str, request_digest: str) -> AuthorityDecision:
        with self._transaction():
            try:
                grant = self._grants[grant_id]
            except KeyError:
                return AuthorityDecision(False, "grant_not_found")
            now = self._safe_now()
            if grant.status != "active":
                return AuthorityDecision(False, "grant_replayed" if grant.status == "consumed" else "grant_inactive", grant_id)
            if now >= grant.expires_at_utc:
                self._grants[grant_id] = replace(grant, status="expired", version=grant.version + 1)
                self._persist()
                return AuthorityDecision(False, "grant_expired", grant_id)
            if not hmac.compare_digest(_digest_secret(nonce), grant.nonce_digest):
                return AuthorityDecision(False, "grant_nonce_mismatch", grant_id)
            if (
                not isinstance(request_digest, str)
                or not _DIGEST_RE.fullmatch(request_digest)
                or not hmac.compare_digest(request_digest, grant.request_digest)
            ):
                return AuthorityDecision(False, "grant_request_mismatch", grant_id)
            self._grants[grant_id] = replace(grant, status="consumed", version=grant.version + 1)
            self._persist()
            return AuthorityDecision(True, "grant_consumed", grant_id)

    def revoke_grant(self, grant_id: str, *, expected_version: int) -> DelegationGrant:
        with self._transaction():
            try:
                current = self._grants[grant_id]
            except KeyError as exc:
                raise AuthorityError("grant_not_found") from exc
            if current.version != expected_version:
                raise AuthorityError("stale_grant_version")
            if current.status == "revoked":
                return current
            revoked = replace(current, status="revoked", version=current.version + 1)
            self._grants[grant_id] = revoked
            self._persist()
            return revoked

    def get_grant(self, grant_id: str) -> DelegationGrant:
        with self._transaction():
            try:
                return self._grants[grant_id]
            except KeyError as exc:
                raise AuthorityError("grant_not_found") from exc

    def validate_grant(
        self,
        grant_id: str,
        *,
        subject_principal_id: str,
        repo_id: str,
        dispatch_id: str | None,
        scope: Iterable[str],
        write_paths: Iterable[str],
        capability: str,
    ) -> AuthorityDecision:
        """Check a grant without consuming its single-use nonce."""

        _identifier(subject_principal_id, "subject_principal")
        _identifier(repo_id, "repo")
        _capability(capability)
        with self._transaction():
            grant = self._grants.get(grant_id)
            if grant is None:
                return AuthorityDecision(False, "grant_not_found", grant_id)
            if grant.status != "active":
                return AuthorityDecision(False, "grant_inactive", grant_id)
            if self._safe_now() >= grant.expires_at_utc:
                return AuthorityDecision(False, "grant_expired", grant_id)
            try:
                subject = self._context.principals.get(subject_principal_id)
            except PrincipalError:
                return AuthorityDecision(False, "principal_not_found", grant_id)
            if subject.state != "active":
                return AuthorityDecision(False, "principal_inactive", grant_id)
            if (
                grant.subject_principal_id != subject_principal_id
                or grant.repo_id != repo_id
                or grant.dispatch_id != dispatch_id
                or capability not in grant.capabilities
            ):
                return AuthorityDecision(False, "grant_binding_mismatch", grant_id)
            if not self._scope_allowed(repo_id, tuple(scope), tuple(write_paths)):
                return AuthorityDecision(False, "scope_denied", grant_id)
            if not all(
                any(_within(self._context.repositories.resolve_path(repo_id, value), self._context.repositories.resolve_path(repo_id, allowed)) for allowed in grant.scope)
                for value in scope
            ):
                return AuthorityDecision(False, "grant_scope_mismatch", grant_id)
            if not all(
                any(_within(self._context.repositories.resolve_path(repo_id, value), self._context.repositories.resolve_path(repo_id, allowed)) for allowed in grant.write_paths)
                for value in write_paths
            ):
                return AuthorityDecision(False, "grant_write_scope_mismatch", grant_id)
            return AuthorityDecision(True, "grant_verified", grant_id)

    def public_grants(self) -> tuple[dict[str, object], ...]:
        with self._transaction():
            return tuple(grant.public() for grant in self._grants.values())

    def _build_grant(self, **values: object) -> DelegationGrant:
        try:
            issuer = self._context.principals.get(values["issuer_principal_id"])
            subject = self._context.principals.get(values["subject_principal_id"])
        except (PrincipalError, KeyError) as exc:
            raise AuthorityError("principal_not_found") from exc
        if issuer.state != "active" or subject.state != "active":
            raise AuthorityError("principal_inactive")
        if subject.parent_principal_id != issuer.principal_id:
            raise AuthorityError("parent_mismatch")
        repo_id = values["repo_id"]
        if issuer.repo_id not in {None, repo_id} or subject.repo_id != repo_id:
            raise AuthorityError("repository_mismatch")
        try:
            self._context.repositories.get(repo_id)
        except (RepositoryError, KeyError) as exc:
            raise AuthorityError("unknown_repository") from exc
        capabilities = tuple(sorted(set(values["capabilities"])))
        scope = tuple(dict.fromkeys(values["scope"]))
        write_paths = tuple(dict.fromkeys(values["write_paths"]))
        if not capabilities or any(capability not in self._capabilities(issuer) for capability in capabilities):
            raise AuthorityError("capability_subset_denied")
        if any(capability not in self._capabilities(subject) for capability in capabilities):
            raise AuthorityError("subject_capability_denied")
        if not self._scope_allowed(repo_id, scope, write_paths):
            raise AuthorityError("scope_denied")
        max_depth = values["max_delegation_depth"]
        if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 0:
            raise AuthorityError("invalid_delegation_depth")
        if max_depth > 8:
            raise AuthorityError("invalid_delegation_depth")
        try:
            nonce = values["nonce"]
            if not isinstance(nonce, str) or not nonce:
                raise AuthorityError("invalid_grant_nonce")
            issued = values["issued_at_utc"]
            expires = values["expires_at_utc"]
            request_digest = values["request_digest"]
            if not isinstance(request_digest, str) or not _DIGEST_RE.fullmatch(request_digest):
                raise AuthorityError("invalid_grant_request_digest")
            return DelegationGrant(
                1,
                values["grant_id"], issuer.principal_id, subject.principal_id, repo_id, values["dispatch_id"],
                capabilities, scope, write_paths, max_depth, issued, expires, _digest_secret(nonce), request_digest,
                "active", 1,
            )
        except (KeyError, TypeError, HiveValidationError, AuthorityError) as exc:
            if isinstance(exc, AuthorityError):
                raise
            raise AuthorityError("invalid_grant") from exc

    def _capabilities(self, principal: Principal) -> frozenset[str]:
        return self._context.capabilities.get(principal.authority_profile, frozenset())

    def _scope_allowed(self, repo_id: str | None, scope: Iterable[str], write_paths: Iterable[str]) -> bool:
        if repo_id is None:
            return False
        try:
            scope_paths = tuple(self._context.repositories.resolve_path(repo_id, item) for item in scope)
            write_values = tuple(write_paths)
            write_resolved = tuple(self._context.repositories.resolve_path(repo_id, item) for item in write_values)
        except (RepositoryError, TypeError):
            return False
        if not scope_paths:
            return False
        return all(any(_within(candidate, allowed) for allowed in scope_paths) for candidate in write_resolved)

    def _safe_now(self) -> datetime:
        try:
            return validate_utc_datetime(self._now())
        except (HiveValidationError, TypeError, ValueError):
            raise AuthorityError("authority_clock_unavailable") from None

    def _load(self) -> None:
        assert self._state is not None
        with self._state.locked():
            self._load_locked()

    def _load_locked(self) -> None:
        assert self._state is not None
        self._grants.clear()
        try:
            payload = self._state.read_json_locked(PurePosixPath("grants.json"), max_bytes=4 * 1024 * 1024)
        except HiveStateError as exc:
            if str(exc) == "state_not_found":
                return
            raise AuthorityError("grant_state_invalid") from exc
        raw_grants = payload.get("grants")
        if payload.get("schema_version") != 1 or not isinstance(raw_grants, list):
            raise AuthorityError("grant_state_invalid")
        for raw in raw_grants:
            grant = self._grant_from_payload(raw)
            if grant.grant_id in self._grants:
                raise AuthorityError("duplicate_grant")
            self._grants[grant.grant_id] = grant

    def _persist(self) -> None:
        if self._state is None:
            return
        self._state.replace_json_locked(
            PurePosixPath("grants.json"),
            {"schema_version": 1, "grants": [self._grant_payload(item) for item in self._grants.values()]},
        )

    @contextlib.contextmanager
    def _transaction(self):
        with self._lock:
            state_lock = self._state.locked() if self._state is not None else contextlib.nullcontext()
            with state_lock:
                if self._state is not None:
                    self._load_locked()
                yield

    @staticmethod
    def _grant_payload(item: DelegationGrant) -> dict[str, object]:
        return {
            "schema_version": item.schema_version,
            "grant_id": item.grant_id,
            "issuer_principal_id": item.issuer_principal_id,
            "subject_principal_id": item.subject_principal_id,
            "repo_id": item.repo_id,
            "dispatch_id": item.dispatch_id,
            "capabilities": list(item.capabilities),
            "scope": list(item.scope),
            "write_paths": list(item.write_paths),
            "max_delegation_depth": item.max_delegation_depth,
            "issued_at_utc": item.issued_at_utc.isoformat(),
            "expires_at_utc": item.expires_at_utc.isoformat(),
            "nonce_digest": item.nonce_digest,
            "request_digest": item.request_digest,
            "status": item.status,
            "version": item.version,
        }

    @staticmethod
    def _grant_from_payload(raw: object) -> DelegationGrant:
        if not isinstance(raw, Mapping):
            raise AuthorityError("grant_state_invalid")
        try:
            return DelegationGrant(
                raw["schema_version"], raw["grant_id"], raw["issuer_principal_id"], raw["subject_principal_id"],
                raw["repo_id"], raw.get("dispatch_id"), tuple(raw["capabilities"]), tuple(raw["scope"]),
                tuple(raw["write_paths"]), raw["max_delegation_depth"],
                datetime.fromisoformat(raw["issued_at_utc"].replace("Z", "+00:00")),
                datetime.fromisoformat(raw["expires_at_utc"].replace("Z", "+00:00")),
                raw["nonce_digest"], raw["request_digest"], raw["status"], raw["version"],
            )
        except (KeyError, TypeError, ValueError, AttributeError, AuthorityError) as exc:
            raise AuthorityError("grant_state_invalid") from exc


def _identifier(value: object, field: str) -> str:
    try:
        return validate_identifier(value, field=field)
    except HiveValidationError as exc:
        raise AuthorityError(str(exc)) from exc


def _capability(value: object) -> str:
    if not isinstance(value, str) or not _CAPABILITY_RE.fullmatch(value):
        raise AuthorityError("invalid_capability")
    return value


def _paths(values: object, code: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(values, tuple) or (not allow_empty and not values) or len(values) > MAX_GRANT_PATHS:
        raise AuthorityError(code)
    for value in values:
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 512
            or value.startswith(("/", "~"))
            or "\\" in value
            or "://" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
        ):
            raise AuthorityError(code)
    return values


def _digest_secret(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorityError("invalid_grant_nonce")
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _within(path, scope) -> bool:
    try:
        path.relative_to(scope)
        return True
    except ValueError:
        return False


__all__ = [
    "AuthorityContext",
    "AuthorityDecision",
    "AuthorityEngine",
    "AuthorityError",
    "AuthorityRequest",
    "DelegationGrant",
]
