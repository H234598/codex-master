"""Persistent Hive principals and renewable execution bindings."""

from __future__ import annotations

from collections.abc import Mapping
import contextlib
from dataclasses import dataclass, replace
from datetime import datetime
import re
from threading import RLock
from pathlib import PurePosixPath

from codex_master.hive.state import HiveStateError, HiveStateStore
from codex_master.hive.types import HiveValidationError, validate_identifier, validate_utc_datetime


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_STATES = {"active", "retired"}
_BINDING_STATES = {"active", "released"}
_MAX_LIST_LIMIT = 256
_ROLE_RULES = {
    "gottbiene": (None, "global", False),
    "godbee": (None, "global", False),
    "koenigin": ({"gottbiene", "godbee"}, "repository", True),
    "queen": ({"gottbiene", "godbee"}, "repository", True),
    "teamleiterin": ({"koenigin", "queen"}, "repository", True),
    "teamlead": ({"koenigin", "queen"}, "repository", True),
    "spezialistin": ({"teamleiterin", "teamlead"}, "repository", True),
    "specialist": ({"teamleiterin", "teamlead"}, "repository", True),
    "arbeitsbiene": ({"spezialistin", "specialist"}, "repository", True),
    "worker": ({"spezialistin", "specialist"}, "repository", True),
}


class PrincipalError(ValueError):
    """Raised when principal or execution-binding state is invalid."""


def _text(value: object, code: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(char) < 32 for char in value):
        raise PrincipalError(code)
    return value


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    class_id: str
    parent_principal_id: str | None
    authority_profile: str
    scope_kind: str
    repo_id: str | None
    state: str
    config_digest: str
    version: int
    created_at_utc: str | None = None

    def __post_init__(self) -> None:
        try:
            validate_identifier(self.principal_id, field="principal")
            validate_identifier(self.class_id, field="class")
            if self.parent_principal_id is not None:
                validate_identifier(self.parent_principal_id, field="parent_principal")
            if self.repo_id is not None:
                validate_identifier(self.repo_id, field="repo")
        except HiveValidationError as exc:
            raise PrincipalError(str(exc)) from exc
        _text(self.authority_profile, "invalid_authority_profile")
        if self.scope_kind not in {"global", "repository", "read", "write"}:
            raise PrincipalError("invalid_scope_kind")
        if self.state not in _STATES:
            raise PrincipalError("invalid_principal_state")
        if not isinstance(self.config_digest, str) or not _DIGEST_RE.fullmatch(self.config_digest):
            raise PrincipalError("invalid_principal_config_digest")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or not 1 <= self.version <= 10**12:
            raise PrincipalError("invalid_principal_version")
        if self.created_at_utc is not None:
            try:
                validate_utc_datetime(datetime.fromisoformat(self.created_at_utc.replace("Z", "+00:00")))
            except (HiveValidationError, TypeError, ValueError):
                raise PrincipalError("invalid_principal_timestamp") from None

    def public(self) -> dict[str, object]:
        return {
            "principal_id": self.principal_id,
            "class_id": self.class_id,
            "parent_principal_id": self.parent_principal_id,
            "authority_profile": self.authority_profile,
            "scope_kind": self.scope_kind,
            "repo_id": self.repo_id,
            "state": self.state,
            "version": self.version,
            "created_at_utc": self.created_at_utc,
        }


@dataclass(frozen=True, slots=True)
class ExecutionBinding:
    binding_id: str
    principal_id: str
    repo_id: str | None
    dispatch_id: str | None
    agent_id: str
    account_key: str
    model_id: str
    lease_id: str
    admission_id: str
    state: str
    expires_at_utc: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.binding_id, "binding"),
            (self.principal_id, "principal"),
            (self.agent_id, "agent"),
            (self.model_id, "model"),
            (self.lease_id, "lease"),
            (self.admission_id, "admission"),
        ):
            try:
                validate_identifier(value, field=field)
            except HiveValidationError as exc:
                raise PrincipalError(str(exc)) from exc
        for value, code in ((self.account_key, "invalid_account_key"),):
            _text(value, code)
        if self.repo_id is not None:
            try:
                validate_identifier(self.repo_id, field="repo")
            except HiveValidationError as exc:
                raise PrincipalError(str(exc)) from exc
        if self.dispatch_id is not None:
            try:
                validate_identifier(self.dispatch_id, field="dispatch")
            except HiveValidationError as exc:
                raise PrincipalError(str(exc)) from exc
        if self.state not in _BINDING_STATES:
            raise PrincipalError("invalid_binding_state")
        try:
            validate_utc_datetime(datetime.fromisoformat(self.expires_at_utc.replace("Z", "+00:00")))
        except (HiveValidationError, TypeError, ValueError):
            raise PrincipalError("invalid_binding_timestamp") from None

    def public(self) -> dict[str, object]:
        return {
            "binding_id": self.binding_id,
            "principal_id": self.principal_id,
            "repo_id": self.repo_id,
            "dispatch_id": self.dispatch_id,
            "agent_id": self.agent_id,
            "model_id": self.model_id,
            "admission_id": self.admission_id,
            "state": self.state,
            "expires_at_utc": self.expires_at_utc,
        }


class PrincipalRegistry:
    """CAS-like principal registry with optional private JSON persistence."""

    def __init__(self, state: HiveStateStore | None = None) -> None:
        if state is not None and not isinstance(state, HiveStateStore):
            raise PrincipalError("invalid_principal_state_store")
        self._state = state
        self._lock = RLock()
        self._principals: dict[str, Principal] = {}
        self._bindings: dict[str, ExecutionBinding] = {}
        if state is not None:
            self._load()

    def get(self, principal_id: str) -> Principal:
        with self._transaction():
            try:
                validate_identifier(principal_id, field="principal")
                return self._principals[principal_id]
            except (HiveValidationError, KeyError) as exc:
                raise PrincipalError("principal_not_found") from exc

    def list(self, *, offset: int = 0, limit: int = _MAX_LIST_LIMIT) -> tuple[Principal, ...]:
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise PrincipalError("invalid_principal_offset")
        if isinstance(limit, bool) or not 1 <= limit <= _MAX_LIST_LIMIT:
            raise PrincipalError("invalid_principal_limit")
        with self._transaction():
            return tuple(sorted(self._principals.values(), key=lambda item: item.principal_id)[offset : offset + limit])

    def create(self, principal: Principal) -> Principal:
        if not isinstance(principal, Principal):
            raise PrincipalError("invalid_principal")
        with self._transaction():
            if principal.principal_id in self._principals:
                raise PrincipalError("duplicate_principal")
            self._validate_parent(principal)
            self._principals[principal.principal_id] = principal
            self._persist()
            return principal

    def retire(self, principal_id: str, *, expected_version: int) -> Principal:
        with self._transaction():
            try:
                validate_identifier(principal_id, field="principal")
                current = self._principals[principal_id]
            except (HiveValidationError, KeyError) as exc:
                raise PrincipalError("principal_not_found") from exc
            if current.version != expected_version:
                raise PrincipalError("stale_principal_version")
            if current.state == "retired":
                return current
            retired = replace(current, state="retired", version=current.version + 1)
            self._principals[principal_id] = retired
            self._persist()
            return retired

    def bind_execution(self, binding: ExecutionBinding) -> ExecutionBinding:
        if not isinstance(binding, ExecutionBinding):
            raise PrincipalError("invalid_execution_binding")
        with self._transaction():
            try:
                principal = self._principals[binding.principal_id]
            except KeyError as exc:
                raise PrincipalError("principal_not_found") from exc
            if principal.state != "active":
                raise PrincipalError("principal_inactive")
            for current in self._bindings.values():
                if (
                    current.state == "active"
                    and current.principal_id == binding.principal_id
                    and current.dispatch_id == binding.dispatch_id
                ):
                    raise PrincipalError("duplicate_active_execution_binding")
            if principal.repo_id != binding.repo_id:
                raise PrincipalError("binding_repository_mismatch")
            self._bindings[binding.binding_id] = binding
            self._persist()
            return binding

    def release_execution(self, binding_id: str) -> ExecutionBinding:
        with self._transaction():
            try:
                current = self._bindings[binding_id]
            except KeyError as exc:
                raise PrincipalError("execution_binding_not_found") from exc
            if current.state == "released":
                return current
            released = replace(current, state="released")
            self._bindings[binding_id] = released
            self._persist()
            return released

    def public_bindings(self) -> tuple[dict[str, object], ...]:
        with self._transaction():
            return tuple(binding.public() for binding in self._bindings.values())

    def _validate_parent(self, principal: Principal) -> None:
        rule = _ROLE_RULES.get(principal.class_id)
        if rule is None:
            raise PrincipalError("unknown_principal_class")
        parent_classes, expected_scope, repo_required = rule
        if expected_scope != principal.scope_kind:
            raise PrincipalError("principal_scope_mismatch")
        if repo_required != (principal.repo_id is not None):
            raise PrincipalError("principal_repository_scope_mismatch")
        if parent_classes is None:
            if principal.parent_principal_id is not None:
                raise PrincipalError("root_principal_has_parent")
            return
        if principal.parent_principal_id is None:
            raise PrincipalError("principal_parent_required")
        try:
            parent = self._principals[principal.parent_principal_id]
        except KeyError as exc:
            raise PrincipalError("principal_parent_not_found") from exc
        if parent.state != "active" or parent.class_id not in parent_classes:
            raise PrincipalError("invalid_principal_parent")
        if principal.repo_id != parent.repo_id and parent.repo_id is not None:
            raise PrincipalError("principal_repository_mismatch")

    def _load(self) -> None:
        assert self._state is not None
        with self._state.locked():
            self._load_locked()

    def _load_locked(self) -> None:
        assert self._state is not None
        self._principals.clear()
        self._bindings.clear()
        try:
            payload = self._state.read_json_locked(PurePosixPath("principals.json"), max_bytes=4 * 1024 * 1024)
        except HiveStateError as exc:
            if str(exc) == "state_not_found":
                return
            raise PrincipalError("principal_state_invalid") from exc
        raw_principals = payload.get("principals")
        raw_bindings = payload.get("bindings")
        if payload.get("schema_version") != 1 or not isinstance(raw_principals, list) or not isinstance(raw_bindings, list):
            raise PrincipalError("principal_state_invalid")
        for raw in raw_principals:
            principal = self._principal_from_payload(raw)
            if principal.principal_id in self._principals:
                raise PrincipalError("duplicate_principal")
            self._principals[principal.principal_id] = principal
        for principal in tuple(self._principals.values()):
            self._validate_parent(principal)
        for raw in raw_bindings:
            binding = self._binding_from_payload(raw)
            if binding.binding_id in self._bindings:
                raise PrincipalError("duplicate_execution_binding")
            self._bindings[binding.binding_id] = binding

    def _persist(self) -> None:
        if self._state is None:
            return
        self._state.replace_json_locked(
            PurePosixPath("principals.json"),
            {
                "schema_version": 1,
                "principals": [self._principal_payload(item) for item in self._principals.values()],
                "bindings": [self._binding_payload(item) for item in self._bindings.values()],
            },
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
    def _principal_payload(item: Principal) -> dict[str, object]:
        return {
            "principal_id": item.principal_id,
            "class_id": item.class_id,
            "parent_principal_id": item.parent_principal_id,
            "authority_profile": item.authority_profile,
            "scope_kind": item.scope_kind,
            "repo_id": item.repo_id,
            "state": item.state,
            "config_digest": item.config_digest,
            "version": item.version,
            "created_at_utc": item.created_at_utc,
        }

    @staticmethod
    def _binding_payload(item: ExecutionBinding) -> dict[str, object]:
        return {
            "binding_id": item.binding_id,
            "principal_id": item.principal_id,
            "repo_id": item.repo_id,
            "dispatch_id": item.dispatch_id,
            "agent_id": item.agent_id,
            "account_key": item.account_key,
            "model_id": item.model_id,
            "lease_id": item.lease_id,
            "admission_id": item.admission_id,
            "state": item.state,
            "expires_at_utc": item.expires_at_utc,
        }

    @classmethod
    def _principal_from_payload(cls, raw: object) -> Principal:
        if not isinstance(raw, Mapping):
            raise PrincipalError("principal_state_invalid")
        try:
            return Principal(
                raw["principal_id"], raw["class_id"], raw.get("parent_principal_id"),
                raw["authority_profile"], raw["scope_kind"], raw.get("repo_id"), raw["state"],
                raw["config_digest"], raw["version"], raw.get("created_at_utc"),
            )
        except (KeyError, PrincipalError, TypeError) as exc:
            raise PrincipalError("principal_state_invalid") from exc

    @classmethod
    def _binding_from_payload(cls, raw: object) -> ExecutionBinding:
        if not isinstance(raw, Mapping):
            raise PrincipalError("principal_state_invalid")
        try:
            return ExecutionBinding(
                raw["binding_id"], raw["principal_id"], raw.get("repo_id"), raw.get("dispatch_id"),
                raw["agent_id"], raw["account_key"], raw["model_id"], raw["lease_id"],
                raw["admission_id"], raw["state"], raw["expires_at_utc"],
            )
        except (KeyError, PrincipalError, TypeError) as exc:
            raise PrincipalError("principal_state_invalid") from exc


__all__ = ["ExecutionBinding", "Principal", "PrincipalError", "PrincipalRegistry"]
