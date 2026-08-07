"""Data-sparse Hive status aggregation helpers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from codex_master.hive.messages import HiveMessage, HiveMessageError, record_child_report
from codex_master.hive.principals import PrincipalRegistry

if TYPE_CHECKING:
    from codex_master.selection.reset_anchor import ProactiveAnchorSafetyStatus


_STATUS_RANK = {
    "unknown": 0,
    "planned": 1,
    "queued": 2,
    "completed": 10,
    "integrating": 20,
    "executing": 20,
    "paused": 30,
    "decision_required": 40,
    "blocked": 50,
    "failed": 60,
}
MAX_AGGREGATE_REPORTS = 256


def hive_status(*, mode: str = "disabled", counts: Mapping[str, int] | None = None) -> Mapping[str, object]:
    if mode not in {"disabled", "shadow", "enforced"}:
        raise ValueError("invalid_hive_mode")
    values = dict(counts or {})
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values.values()):
        raise ValueError("invalid_hive_counts")
    return {
        "mode": mode,
        "counts": {key: values[key] for key in sorted(values) if isinstance(key, str) and len(key) <= 64},
        "authority": "fail_closed",
        "raw_output": "not_returned",
    }


def godbee_status() -> Mapping[str, object]:
    return {"principal_class": "gottbiene", "direct_repository_writes": False, "open_requests": 0, "raw_output": "not_returned"}


def queen_list(*, offset: int, limit: int, registry: PrincipalRegistry | None = None) -> Mapping[str, object]:
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or isinstance(limit, bool) or not 1 <= limit <= 256:
        raise ValueError("invalid_status_pagination")
    values = registry.list(offset=offset, limit=limit) if registry is not None else ()
    return {"items": [item.public() for item in values if item.class_id in {"koenigin", "queen"}], "offset": offset, "limit": limit, "raw_output": "not_returned"}


def queen_status(queen_id: str, *, registry: PrincipalRegistry | None = None) -> Mapping[str, object]:
    if registry is None:
        return {"queen_id": queen_id, "state": "unknown", "raw_output": "not_returned"}
    principal = registry.get(queen_id)
    if principal.class_id not in {"koenigin", "queen"}:
        raise ValueError("not_a_queen")
    return {"principal_id": principal.principal_id, "class_id": principal.class_id, "repo_id": principal.repo_id, "state": principal.state, "raw_output": "not_returned"}


def queue_status(*, offset: int, limit: int, items: Sequence[Mapping[str, object]] = ()) -> Mapping[str, object]:
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or isinstance(limit, bool) or not 1 <= limit <= 256:
        raise ValueError("invalid_status_pagination")
    safe = tuple(item for item in items if isinstance(item, Mapping))
    return {"items": [dict(item) for item in safe[offset : offset + limit]], "offset": offset, "limit": limit, "raw_output": "not_returned"}


def admission_status(admission_id: str, *, state: str = "unknown") -> Mapping[str, object]:
    if not isinstance(admission_id, str) or not admission_id:
        raise ValueError("invalid_admission_id")
    return {"admission_id": admission_id, "state": state, "account_key": "not_returned", "scope": "not_returned", "raw_output": "not_returned"}


def hive_doctor() -> Mapping[str, object]:
    return {"healthy": True, "checks": {"authority": "fail_closed", "repository": "not_configured", "state": "not_configured"}, "raw_output": "not_returned"}


def selection_status() -> Mapping[str, object]:
    return {"mode": "preview_only", "eligible_candidates": 0, "raw_output": "not_returned"}


def proactive_anchor_status(
    *, safety: ProactiveAnchorSafetyStatus | None = None
) -> Mapping[str, object]:
    from codex_master.selection.reset_anchor import ProactiveAnchorSafetyStatus

    if safety is None:
        safety = ProactiveAnchorSafetyStatus(
            False, False, False, True, False, False, False, False, False, False, False, False
        )
    if not isinstance(safety, ProactiveAnchorSafetyStatus):
        raise ValueError("invalid_proactive_safety_status")
    return {
        "mode": "dry_run_only",
        "execute_reason_code": "selection_proactive_anchor_safety_gate",
        "safety": safety.public(),
        "raw_output": "not_returned",
    }


def _aggregate_reports(
    scope: str,
    scope_id: str,
    reports: Sequence[HiveMessage],
    *,
    field: str,
) -> Mapping[str, object]:
    if not isinstance(scope_id, str) or not 1 <= len(scope_id) <= 128 or any(ord(char) < 32 for char in scope_id):
        raise ValueError("invalid_aggregate_scope")
    if not isinstance(reports, (tuple, list)) or len(reports) > MAX_AGGREGATE_REPORTS:
        raise ValueError("invalid_aggregate_reports")
    reduced: list[Mapping[str, object]] = []
    for message in reports:
        if not isinstance(message, HiveMessage):
            raise HiveMessageError("invalid_child_report")
        if getattr(message, field) != scope_id:
            continue
        reduced.append(record_child_report(message))
    statuses = Counter(
        item["status"] for item in reduced if isinstance(item.get("status"), str)
    )
    status = max(statuses, key=lambda value: (_STATUS_RANK.get(value, 0), value), default="unknown")
    correlations = sorted({
        value for value in (item.get("correlation_id") for item in reduced) if isinstance(value, str)
    })
    digests = sorted({
        value for value in (item.get("payload_digest") for item in reduced) if isinstance(value, str)
    })
    return {
        "scope": scope,
        f"{scope}_id": scope_id,
        "status": status,
        "report_count": len(reduced),
        "status_counts": {key: statuses[key] for key in sorted(statuses)},
        "blocked_count": sum(1 for item in reduced if item.get("blocked") is True),
        "escalation_count": sum(1 for item in reduced if item.get("message_type") == "escalation"),
        "correlation_ids": correlations[:MAX_AGGREGATE_REPORTS],
        "payload_digest_count": len(digests),
        "raw_output": "not_returned",
    }


def aggregate_teamlead_status(
    workpackage_id: str, reports: Sequence[HiveMessage] = ()
) -> Mapping[str, object]:
    return _aggregate_reports("workpackage", workpackage_id, reports, field="workpackage_id")


def aggregate_queen_status(
    dispatch_id: str, reports: Sequence[HiveMessage] = ()
) -> Mapping[str, object]:
    return _aggregate_reports("dispatch", dispatch_id, reports, field="dispatch_id")


def aggregate_godbee_status(
    request_id: str, reports: Sequence[HiveMessage] = ()
) -> Mapping[str, object]:
    return _aggregate_reports("request", request_id, reports, field="correlation_id")


__all__ = [
    "admission_status",
    "aggregate_godbee_status",
    "aggregate_queen_status",
    "aggregate_teamlead_status",
    "godbee_status",
    "hive_doctor",
    "hive_status",
    "queen_list",
    "queen_status",
    "queue_status",
    "proactive_anchor_status",
    "selection_status",
]
