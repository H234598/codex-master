"""Provenance-aware, bounded Hive memory promotion."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import hashlib
import re

from codex_master.hive.principals import Principal
from codex_master.hive.types import HiveValidationError, validate_identifier, validate_utc_datetime


_SECRET_RE = re.compile(r"(?i)(?:sk|api[_-]?key|token|secret)[=:][^\s,;]+")
_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9])/(?:[^\s/]+/)+[^\s]+")
_ROLES_TEAMLEAD = frozenset({"teamleiterin", "teamlead"})
_ROLES_QUEEN = frozenset({"koenigin", "queen"})
MAX_MEMORY_TEXT = 8192


class MemoryError(ValueError):
    """Raised when memory provenance or promotion authority is invalid."""


def _id(value: object, field: str) -> str:
    try:
        return validate_identifier(value, field=field)
    except HiveValidationError as exc:
        raise MemoryError(str(exc)) from exc


def _safe_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_MEMORY_TEXT or any(ord(char) < 32 for char in value):
        raise MemoryError(f"invalid_{field}")
    return _ABSOLUTE_PATH_RE.sub("<path-redacted>", _SECRET_RE.sub("<redacted>", value))


def _refs(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not 1 <= len(value) <= 128:
        raise MemoryError(f"invalid_{field}")
    return tuple(_safe_text(item, field) for item in value)


@dataclass(frozen=True, slots=True)
class MemoryEntry:
    memory_id: str
    scope_kind: str
    repo_id: str | None
    summary: str
    provenance_refs: tuple[str, ...]
    trust_level: str
    source_principal_id: str
    created_by: str
    created_at_utc: datetime
    content_digest: str

    def __post_init__(self) -> None:
        _id(self.memory_id, "memory")
        if self.scope_kind not in {"repository", "global"}:
            raise MemoryError("invalid_memory_scope")
        if self.scope_kind == "repository" and self.repo_id is None:
            raise MemoryError("memory_repository_required")
        if self.scope_kind == "global" and self.repo_id is not None:
            raise MemoryError("global_memory_has_repository")
        if self.repo_id is not None:
            _id(self.repo_id, "repo")
        _safe_text(self.summary, "summary")
        _refs(self.provenance_refs, "provenance_refs")
        if self.trust_level not in {"observed", "verified", "accepted"}:
            raise MemoryError("invalid_memory_trust")
        _id(self.source_principal_id, "source_principal")
        _id(self.created_by, "creator")
        try:
            validate_utc_datetime(self.created_at_utc, field="memory_timestamp")
        except HiveValidationError as exc:
            raise MemoryError(str(exc)) from exc
        if not isinstance(self.content_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.content_digest):
            raise MemoryError("invalid_memory_digest")

    def public(self) -> dict[str, object]:
        return {
            "memory_id": self.memory_id,
            "scope_kind": self.scope_kind,
            "repo_id": self.repo_id,
            "summary": self.summary,
            "provenance_refs": list(self.provenance_refs),
            "trust_level": self.trust_level,
            "source_principal_id": self.source_principal_id,
            "created_by": self.created_by,
            "created_at_utc": self.created_at_utc.isoformat(),
            "content_digest": self.content_digest,
            "raw_output": "not_returned",
        }


def _entry(
    *, memory_id: str, scope_kind: str, repo_id: str | None, summary: str, provenance_refs: tuple[str, ...],
    trust_level: str, source_principal_id: str, actor: Principal, now: datetime,
) -> MemoryEntry:
    redacted = _safe_text(summary, "summary")
    digest = "sha256:" + hashlib.sha256(redacted.encode("utf-8")).hexdigest()
    return MemoryEntry(memory_id, scope_kind, repo_id, redacted, provenance_refs, trust_level, source_principal_id, actor.principal_id, now, digest)


def promote_teamlead_report(
    report: Mapping[str, object], *, actor: Principal, memory_id: str, repo_id: str, now: datetime
) -> MemoryEntry:
    if not isinstance(report, Mapping):
        raise MemoryError("invalid_teamlead_report")
    if not isinstance(actor, Principal) or actor.state != "active" or actor.class_id not in _ROLES_TEAMLEAD or actor.repo_id != repo_id:
        raise MemoryError("teamlead_promotion_unauthorized")
    source = report.get("source_principal_id")
    if not isinstance(source, str):
        raise MemoryError("missing_report_provenance")
    return _entry(
        memory_id=memory_id,
        scope_kind="repository",
        repo_id=repo_id,
        summary=report.get("summary"),
        provenance_refs=report.get("provenance_refs"),
        trust_level=report.get("trust_level", "observed"),
        source_principal_id=source,
        actor=actor,
        now=now,
    )


def promote_queen_memory_to_global(
    memory: MemoryEntry, *, actor: Principal, memory_id: str, now: datetime
) -> MemoryEntry:
    if not isinstance(memory, MemoryEntry) or memory.scope_kind != "repository":
        raise MemoryError("invalid_queen_memory")
    if not isinstance(actor, Principal) or actor.state != "active" or actor.class_id not in _ROLES_QUEEN or actor.repo_id != memory.repo_id:
        raise MemoryError("queen_promotion_unauthorized")
    return _entry(
        memory_id=memory_id,
        scope_kind="global",
        repo_id=None,
        summary=memory.summary,
        provenance_refs=(*memory.provenance_refs, f"memory:{memory.memory_id}"),
        trust_level="accepted",
        source_principal_id=memory.source_principal_id,
        actor=actor,
        now=now,
    )


__all__ = ["MemoryEntry", "MemoryError", "promote_queen_memory_to_global", "promote_teamlead_report"]
