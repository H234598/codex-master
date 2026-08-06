"""Append-only, provenance-bound Hive decision records."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re

from codex_master.hive.principals import Principal
from codex_master.hive.types import HiveValidationError, validate_identifier, validate_utc_datetime


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DECISION_STATES = frozenset({"proposed", "accepted", "rejected", "superseded"})
_ROLES_GLOBAL = frozenset({"gottbiene", "godbee"})
_ROLES_REPOSITORY = frozenset({"koenigin", "queen", "teamleiterin", "teamlead"})
MAX_DECISION_BYTES = 256 * 1024


class DecisionError(ValueError):
    """Raised when a decision is unauthorized or chain-invalid."""


def _id(value: object, field: str) -> str:
    try:
        return validate_identifier(value, field=field)
    except HiveValidationError as exc:
        raise DecisionError(str(exc)) from exc


def _text(value: object, field: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(char) < 32 for char in value):
        raise DecisionError(f"invalid_{field}")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise DecisionError(f"invalid_{field}")
    return value


def _refs(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, tuple) or len(value) > 128:
        raise DecisionError(f"invalid_{field}")
    return tuple(_text(item, field, 512) for item in value)


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    decision_id: str
    scope_kind: str
    repo_id: str | None
    topic: str
    status: str
    options: tuple[Mapping[str, object], ...]
    selected_option_id: str | None
    rationale: str
    evidence_refs: tuple[str, ...]
    created_by: str
    approved_by: tuple[str, ...]
    created_at_utc: datetime
    supersedes: str | None = None
    previous_record_hash: str | None = None
    record_hash: str | None = None

    def __post_init__(self) -> None:
        _id(self.decision_id, "decision")
        if self.scope_kind not in {"global", "repository"}:
            raise DecisionError("invalid_decision_scope")
        if self.scope_kind == "global" and self.repo_id is not None:
            raise DecisionError("global_decision_has_repository")
        if self.scope_kind == "repository" and self.repo_id is None:
            raise DecisionError("repository_decision_missing_repository")
        if self.repo_id is not None:
            _id(self.repo_id, "repo")
        _text(self.topic, "decision_topic", 512)
        if self.status not in _DECISION_STATES:
            raise DecisionError("invalid_decision_status")
        if not isinstance(self.options, tuple) or len(self.options) > 64:
            raise DecisionError("invalid_decision_options")
        for option in self.options:
            if not isinstance(option, Mapping) or set(option) - {"option_id", "summary"}:
                raise DecisionError("invalid_decision_option")
            _id(option.get("option_id"), "option")
            _text(option.get("summary"), "option_summary", 1024)
        if self.selected_option_id is not None:
            _id(self.selected_option_id, "selected_option")
            if self.selected_option_id not in {option["option_id"] for option in self.options}:
                raise DecisionError("selected_option_not_found")
        _text(self.rationale, "decision_rationale", MAX_DECISION_BYTES)
        _refs(self.evidence_refs, "evidence_refs")
        _id(self.created_by, "creator")
        if not isinstance(self.approved_by, tuple) or len(self.approved_by) > 32:
            raise DecisionError("invalid_approvers")
        for approver in self.approved_by:
            _id(approver, "approver")
        try:
            validate_utc_datetime(self.created_at_utc, field="decision_timestamp")
        except HiveValidationError as exc:
            raise DecisionError(str(exc)) from exc
        if self.supersedes is not None:
            _id(self.supersedes, "superseded_decision")
        if self.previous_record_hash is not None:
            _digest(self.previous_record_hash, "previous_record_hash")
        if self.record_hash is not None:
            _digest(self.record_hash, "record_hash")
        if len(json.dumps(self.public(), ensure_ascii=True, sort_keys=True).encode("utf-8")) > MAX_DECISION_BYTES:
            raise DecisionError("decision_oversize")

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "decision_id": self.decision_id,
            "scope": {"kind": self.scope_kind, "repo_id": self.repo_id},
            "topic": self.topic,
            "status": self.status,
            "options": [dict(option) for option in self.options],
            "selected_option_id": self.selected_option_id,
            "rationale": self.rationale,
            "evidence_refs": list(self.evidence_refs),
            "created_by": self.created_by,
            "approved_by": list(self.approved_by),
            "created_at_utc": self.created_at_utc.isoformat(),
            "supersedes": self.supersedes,
            "previous_record_hash": self.previous_record_hash,
            "record_hash": self.record_hash,
        }


def _authorized(record: DecisionRecord, actor: Principal) -> None:
    if not isinstance(actor, Principal) or actor.state != "active" or record.created_by != actor.principal_id:
        raise DecisionError("decision_actor_unauthorized")
    allowed = _ROLES_GLOBAL if record.scope_kind == "global" else _ROLES_REPOSITORY
    if actor.class_id not in allowed:
        raise DecisionError("decision_scope_unauthorized")
    if record.scope_kind == "repository" and actor.repo_id != record.repo_id:
        raise DecisionError("decision_repository_mismatch")
    if record.status == "accepted" and not record.approved_by:
        raise DecisionError("accepted_decision_needs_approval")
    if any(approver == actor.principal_id for approver in record.approved_by) is False and record.status == "accepted":
        raise DecisionError("decision_approval_mismatch")


def _canonical_for_hash(record: DecisionRecord) -> bytes:
    payload = record.public()
    payload["record_hash"] = None
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def record_decision(record: DecisionRecord, *, actor: Principal) -> DecisionRecord:
    """Authorize and stamp one immutable record; never mutate an old record."""

    if not isinstance(record, DecisionRecord):
        raise DecisionError("invalid_decision")
    _authorized(record, actor)
    computed = "sha256:" + hashlib.sha256(
        (record.previous_record_hash or "genesis").encode("utf-8") + b"\0" + _canonical_for_hash(record)
    ).hexdigest()
    if record.record_hash is not None and record.record_hash != computed:
        raise DecisionError("decision_hash_mismatch")
    return DecisionRecord(
        record.decision_id, record.scope_kind, record.repo_id, record.topic, record.status, record.options,
        record.selected_option_id, record.rationale, record.evidence_refs, record.created_by, record.approved_by,
        record.created_at_utc, record.supersedes, record.previous_record_hash, computed,
    )


def supersede_decision(decision_id: str, replacement: DecisionRecord, *, actor: Principal) -> DecisionRecord:
    _id(decision_id, "decision")
    if not isinstance(replacement, DecisionRecord) or replacement.supersedes != decision_id:
        raise DecisionError("supersede_reference_mismatch")
    return record_decision(replacement, actor=actor)


def verify_decision_chain(records: Iterable[DecisionRecord] = ()) -> Mapping[str, object]:
    """Verify record hashes, links, and supersede references without exposing content."""

    values = tuple(records)
    seen: set[str] = set()
    previous: str | None = None
    for record in values:
        if not isinstance(record, DecisionRecord) or record.decision_id in seen:
            return {"valid": False, "record_count": len(values), "reason_code": "duplicate_or_invalid_record"}
        seen.add(record.decision_id)
        expected = "sha256:" + hashlib.sha256(
            (record.previous_record_hash or "genesis").encode("utf-8") + b"\0" + _canonical_for_hash(record)
        ).hexdigest()
        if record.previous_record_hash != previous or record.record_hash != expected:
            return {"valid": False, "record_count": len(values), "reason_code": "decision_chain_mismatch"}
        previous = record.record_hash
    return {"valid": True, "record_count": len(values), "reason_code": "decision_chain_verified"}


__all__ = ["DecisionError", "DecisionRecord", "record_decision", "supersede_decision", "verify_decision_chain"]
