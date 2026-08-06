"""Passive reset-anchor state machine; it never creates work or executes."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import re

from codex_master.hive.types import validate_utc_datetime


class AnchorError(ValueError):
    """Raised for invalid passive anchor state."""


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_STATES = frozenset({"grace", "due", "reserved", "attempted", "pending_confirmation", "anchored", "cooldown"})


@dataclass(frozen=True, slots=True)
class ProactiveAnchorSafetyStatus:
    """Explicit safety evidence for a future proactive path."""

    allowlisted: bool
    cooldown_clear: bool
    attempts_available: bool
    kill_switch_active: bool
    execute_enabled: bool
    hard_sandbox_verified: bool
    token_budget_verified: bool
    runtime_limit_verified: bool
    no_tools_verified: bool
    empty_workspace_verified: bool
    no_repository_data_verified: bool
    fixed_internal_task_verified: bool

    def __post_init__(self) -> None:
        if any(not isinstance(value, bool) for value in (
            self.allowlisted, self.cooldown_clear, self.attempts_available,
            self.kill_switch_active, self.execute_enabled, self.hard_sandbox_verified,
            self.token_budget_verified, self.runtime_limit_verified, self.no_tools_verified,
            self.empty_workspace_verified, self.no_repository_data_verified,
            self.fixed_internal_task_verified,
        )):
            raise AnchorError("invalid_proactive_safety_status")

    @property
    def gate_ready(self) -> bool:
        return all((
            self.allowlisted, self.cooldown_clear, self.attempts_available,
            not self.kill_switch_active, self.execute_enabled,
            self.hard_sandbox_verified, self.token_budget_verified,
            self.runtime_limit_verified, self.no_tools_verified,
            self.empty_workspace_verified, self.no_repository_data_verified,
            self.fixed_internal_task_verified,
        ))

    def public(self) -> dict[str, object]:
        return {
            "allowlisted": self.allowlisted,
            "cooldown_clear": self.cooldown_clear,
            "attempts_available": self.attempts_available,
            "kill_switch_active": self.kill_switch_active,
            "execute_enabled": self.execute_enabled,
            "hard_sandbox_verified": self.hard_sandbox_verified,
            "token_budget_verified": self.token_budget_verified,
            "runtime_limit_verified": self.runtime_limit_verified,
            "no_tools_verified": self.no_tools_verified,
            "empty_workspace_verified": self.empty_workspace_verified,
            "no_repository_data_verified": self.no_repository_data_verified,
            "fixed_internal_task_verified": self.fixed_internal_task_verified,
            "gate_ready": self.gate_ready,
            "raw_output": "not_returned",
        }


@dataclass(frozen=True, slots=True)
class ProactiveAnchorPlan:
    anchor_key: str
    attempt_number: int
    state: str
    reason_code: str = "anchor_due"

    def __post_init__(self) -> None:
        if not _DIGEST_RE.fullmatch(self.anchor_key) or self.state != "due":
            raise AnchorError("invalid_proactive_anchor_plan")
        if isinstance(self.attempt_number, bool) or not isinstance(self.attempt_number, int) or not 1 <= self.attempt_number <= 3:
            raise AnchorError("invalid_proactive_anchor_plan")

    def public(self) -> dict[str, object]:
        return {
            "anchor_key": self.anchor_key,
            "attempt_number": self.attempt_number,
            "state": self.state,
            "reason_code": self.reason_code,
            "raw_output": "not_returned",
        }


@dataclass(frozen=True, slots=True)
class LimitObservation:
    semantics: str
    quantity_value: int
    reset_kind: str
    confidence: str
    observed_at_utc: datetime

    def __post_init__(self) -> None:
        if self.semantics not in {"remaining", "consumed"} or isinstance(self.quantity_value, bool) or not isinstance(self.quantity_value, int) or not 0 <= self.quantity_value <= 100:
            raise AnchorError("invalid_anchor_observation")
        if self.reset_kind not in {"rolling_unanchored", "rolling_anchored", "fixed"} or self.confidence not in {"verified", "observed", "unknown"}:
            raise AnchorError("invalid_anchor_observation")
        try:
            validate_utc_datetime(self.observed_at_utc)
        except ValueError as exc:
            raise AnchorError("invalid_anchor_observation") from exc


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    anchor_key: str
    state: str
    attempt_count: int
    admission_id: str | None
    cooldown_until_utc: datetime | None
    last_observed_at_utc: datetime | None

    def __post_init__(self) -> None:
        if not _DIGEST_RE.fullmatch(self.anchor_key) or self.state not in _STATES:
            raise AnchorError("invalid_anchor_record")
        if isinstance(self.attempt_count, bool) or not isinstance(self.attempt_count, int) or not 0 <= self.attempt_count <= 3:
            raise AnchorError("invalid_anchor_attempts")
        if self.admission_id is not None and (not isinstance(self.admission_id, str) or not self.admission_id):
            raise AnchorError("invalid_anchor_admission")
        for value in (self.cooldown_until_utc, self.last_observed_at_utc):
            if value is not None:
                try:
                    validate_utc_datetime(value)
                except ValueError as exc:
                    raise AnchorError("invalid_anchor_timestamp") from exc


class AnchorStateMachine:
    def transition(self, record: AnchorRecord, observation: LimitObservation, *, now: datetime) -> AnchorRecord:
        if not isinstance(record, AnchorRecord) or not isinstance(observation, LimitObservation):
            raise AnchorError("invalid_anchor_transition")
        try:
            now = validate_utc_datetime(now, field="anchor_time")
        except ValueError as exc:
            raise AnchorError("invalid_anchor_time") from exc
        if observation.observed_at_utc > now:
            raise AnchorError("future_anchor_observation")
        if observation.semantics == "remaining" and observation.quantity_value == 100 and observation.reset_kind == "rolling_unanchored" and observation.confidence == "verified":
            if record.attempt_count >= 3:
                return replace(record, state="cooldown", last_observed_at_utc=observation.observed_at_utc)
            return replace(record, state="due", last_observed_at_utc=observation.observed_at_utc)
        return replace(record, state="grace", last_observed_at_utc=observation.observed_at_utc)


def anchor_due(record: AnchorRecord, *, now: datetime) -> bool:
    try:
        now = validate_utc_datetime(now, field="anchor_time")
    except ValueError:
        return False
    return record.state == "due" and (record.cooldown_until_utc is None or now >= record.cooldown_until_utc)


class ResetAnchorPlanner:
    """Plan passive anchors while keeping proactive execution permanently gated."""

    def __init__(
        self,
        record: AnchorRecord,
        *,
        allowed_anchor_keys: Iterable[str] = (),
        execute_enabled: bool = False,
        kill_switch_active: bool = True,
        hard_sandbox_verified: bool = False,
        token_budget_verified: bool = False,
        runtime_limit_verified: bool = False,
        no_tools_verified: bool = False,
        empty_workspace_verified: bool = False,
        no_repository_data_verified: bool = False,
        fixed_internal_task_verified: bool = False,
    ) -> None:
        if not isinstance(record, AnchorRecord):
            raise AnchorError("invalid_anchor_record")
        try:
            allowed = frozenset(allowed_anchor_keys)
        except TypeError as exc:
            raise AnchorError("invalid_anchor_allowlist") from exc
        if len(allowed) > 256 or any(not _DIGEST_RE.fullmatch(value) for value in allowed):
            raise AnchorError("invalid_anchor_allowlist")
        if not isinstance(execute_enabled, bool) or not isinstance(kill_switch_active, bool):
            raise AnchorError("invalid_proactive_safety_status")
        self._record = record
        self._allowed = allowed
        self._execute_enabled = execute_enabled
        self._kill_switch_active = kill_switch_active
        self._safety_flags = (
            hard_sandbox_verified, token_budget_verified, runtime_limit_verified,
            no_tools_verified, empty_workspace_verified, no_repository_data_verified,
            fixed_internal_task_verified,
        )
        if any(not isinstance(value, bool) for value in self._safety_flags):
            raise AnchorError("invalid_proactive_safety_status")

    def safety_status(self, *, now: datetime) -> ProactiveAnchorSafetyStatus:
        try:
            now = validate_utc_datetime(now, field="anchor_time")
        except ValueError as exc:
            raise AnchorError("invalid_anchor_time") from exc
        cooldown_clear = self._record.cooldown_until_utc is None or now >= self._record.cooldown_until_utc
        return ProactiveAnchorSafetyStatus(
            self._record.anchor_key in self._allowed,
            cooldown_clear,
            self._record.attempt_count < 3,
            self._kill_switch_active,
            self._execute_enabled,
            *self._safety_flags,
        )

    def plan_due(self, *, now: datetime) -> ProactiveAnchorPlan | None:
        status = self.safety_status(now=now)
        if not anchor_due(self._record, now=now) or not status.allowlisted or not status.cooldown_clear or not status.attempts_available:
            return None
        return ProactiveAnchorPlan(self._record.anchor_key, self._record.attempt_count + 1, self._record.state)

    def dry_run(self, *, now: datetime) -> dict[str, object]:
        status = self.safety_status(now=now)
        plan = self.plan_due(now=now)
        if plan is not None:
            reason_code = "anchor_due"
        elif self._record.state != "due":
            reason_code = "anchor_not_due"
        elif not status.cooldown_clear:
            reason_code = "anchor_cooldown"
        elif not status.allowlisted:
            reason_code = "anchor_allowlist_blocked"
        else:
            reason_code = "anchor_attempt_limit"
        return {
            "mode": "dry_run",
            "allowed": plan is not None,
            "reason_code": reason_code,
            "plan": None if plan is None else plan.public(),
            "safety": status.public(),
            "mutation_performed": False,
            "raw_output": "not_returned",
        }

    def execute(self, plan: ProactiveAnchorPlan) -> dict[str, object]:
        if not isinstance(plan, ProactiveAnchorPlan) or plan.anchor_key != self._record.anchor_key:
            raise AnchorError("invalid_proactive_anchor_plan")
        return {
            "allowed": False,
            "reason_code": "selection_proactive_anchor_safety_gate",
            "plan": plan.public(),
            "safety": self.safety_status(now=self._record.last_observed_at_utc or datetime.now(timezone.utc)).public(),
            "mutation_performed": False,
            "raw_output": "not_returned",
        }


__all__ = [
    "AnchorError",
    "AnchorRecord",
    "AnchorStateMachine",
    "LimitObservation",
    "ProactiveAnchorPlan",
    "ProactiveAnchorSafetyStatus",
    "ResetAnchorPlanner",
    "anchor_due",
]
