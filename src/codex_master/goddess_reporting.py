from __future__ import annotations

import math
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from collections.abc import Iterable, Mapping
from pathlib import Path


MAX_STATE_BYTES = 512 * 1024
MAX_BUCKET_RECORDS = 744
_TASK_STATUSES = frozenset({
    "assigned", "queued", "executing", "integrating", "completed", "failed", "cancelled", "timeout",
    "rate_limited", "planned", "ready", "admission_planned", "admitted", "blocked", "decision_required",
    "compensating", "failed_final", "paused",
})
_TASK_TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled", "timeout"})
_SECRET_RE = re.compile(
    r"(?:Bearer\s+|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.|"
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*[:=])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class HourlyReport:
    bucket_start: datetime
    bucket_end: datetime
    bucket_id: str
    completed: tuple[dict[str, str], ...]
    pending: tuple[dict[str, str], ...]
    agents: tuple[dict[str, str], ...]
    usage_accounts: tuple[dict[str, object], ...]
    risks: tuple[str, ...] = ()
    data_quality: tuple[str, ...] = ()


def build_hourly_report(
    bucket_start: datetime,
    *,
    end: datetime | None = None,
    completed: Iterable[Mapping[str, object]] = (),
    pending: Iterable[Mapping[str, object]] = (),
    agents: Iterable[Mapping[str, object]] = (),
    usage_accounts: Iterable[Mapping[str, object]] = (),
    risks: Iterable[object] = (),
    data_quality: Iterable[object] = (),
) -> HourlyReport:
    start = _utc(bucket_start)
    bucket_end = start + timedelta(hours=1) if end is None else _utc(end)
    if bucket_end - start != timedelta(hours=1):
        raise ValueError("report bucket must cover one complete hour")
    completed_rows = tuple(_task_row(row) for row in completed)
    pending_rows = tuple(_task_row(row) for row in pending)
    agent_rows = tuple(_agent_row(row) for row in agents)
    usage_rows = tuple(_usage_row(row) for row in usage_accounts)
    risk_rows = tuple(_text(value, "unbekannt") for value in risks)
    quality_rows = tuple(_text(value, "unbekannt") for value in data_quality)
    return HourlyReport(
        bucket_start=start,
        bucket_end=bucket_end,
        bucket_id=start.isoformat().replace("+00:00", "Z") + "/PT1H",
        completed=completed_rows,
        pending=pending_rows,
        agents=agent_rows,
        usage_accounts=usage_rows,
        risks=risk_rows,
        data_quality=quality_rows,
    )


def aggregate_task_rows(
    bucket: datetime,
    *,
    end: datetime | None = None,
    assignments: Iterable[Mapping[str, object]] = (),
    events: Iterable[Mapping[str, object]] = (),
) -> tuple[tuple[dict[str, str], ...], tuple[dict[str, str], ...]]:
    """Reduce bounded assignment and result events into report task rows.

    Assignment prompts and responses are intentionally ignored. An assignment
    without a terminal event remains pending; missing completion evidence is
    never inferred from agent liveness.
    """

    start = _utc(bucket)
    bucket_end = start + timedelta(hours=1) if end is None else _utc(end)
    if bucket_end - start != timedelta(hours=1):
        raise ValueError("task bucket must cover one complete hour")
    task_records: dict[str, dict[str, object]] = {}
    task_order: list[str] = []
    for raw in assignments:
        if not isinstance(raw, Mapping):
            continue
        assignment_id = _task_identifier(raw.get("assignment_id"))
        created = _task_timestamp(raw.get("created_at_utc"))
        if assignment_id is None or created is None or created >= bucket_end:
            continue
        agent_id = _task_identifier(raw.get("agent")) or "—"
        if assignment_id not in task_records:
            task_order.append(assignment_id)
        task_records[assignment_id] = {
            "created": created,
            "agent_id": agent_id,
            "events": [],
        }

    for raw in events:
        if not isinstance(raw, Mapping):
            continue
        assignment_id = _task_identifier(raw.get("assignment_id"))
        at = _task_timestamp(raw.get("at_utc"))
        status = raw.get("status")
        if (
            assignment_id is None
            or at is None
            or not isinstance(status, str)
            or status not in _TASK_STATUSES
        ):
            continue
        record = task_records.get(assignment_id)
        if record is None or at < record["created"] or at >= bucket_end:
            continue
        record["events"].append((at, status))

    completed: list[dict[str, str]] = []
    pending: list[dict[str, str]] = []
    for assignment_id in task_order:
        record = task_records[assignment_id]
        events_for_task = sorted(record["events"], key=lambda item: item[0])
        latest = events_for_task[-1][1] if events_for_task else "assigned"
        latest_at = events_for_task[-1][0] if events_for_task else None
        if latest in _TASK_TERMINAL_STATUSES and latest_at is not None and latest_at >= start:
            completed.append({"title": assignment_id, "status": latest, "agent_id": record["agent_id"]})
        elif latest not in _TASK_TERMINAL_STATUSES:
            pending.append({"title": assignment_id, "status": latest, "agent_id": record["agent_id"]})
    return tuple(completed), tuple(pending)


def render_markdown(
    report: HourlyReport,
    *,
    created_at: datetime | None = None,
    final: bool = True,
) -> str:
    if not isinstance(report, HourlyReport):
        raise ValueError("report is invalid")
    if not isinstance(final, bool):
        raise ValueError("final must be boolean")
    created = _utc(created_at or datetime.now(UTC)).isoformat()
    lines = [
        "---",
        f'title: "Göttinnenbericht – {report.bucket_start.isoformat()}"',
        f"created: {created}",
        "type: goddess-executive-summary",
        f"status: {'final' if final else 'partial'}",
        f'bucket_id: "{report.bucket_id}"',
        "data_freshness: sanitized",
        "---",
        "",
        "# Executive Summary",
        "",
        "## Erledigt",
        "",
    ]
    if report.completed:
        lines.extend(_task_line(row) for row in report.completed)
    else:
        lines.append("- Keine.")
    lines.extend(["", "## Läuft / steht an", ""])
    if report.pending:
        lines.extend(_task_line(row) for row in report.pending)
    else:
        lines.append("- Keine.")
    lines.extend(["", "## Aktive Flotte", "", "| Biene | Serie | Provider | Account | Zustand |", "|---|---|---|---|---|"])
    lines.extend(
        f"| {row['agent_id']} | {row['series']} | {row['provider']} | "
        f"{row['account_label']} | {row['state']} |"
        for row in report.agents
    )
    if not report.agents:
        lines.append("| — | — | — | — | — |")
    lines.extend(["", "## Limitkosten pro Account", ""])
    for account in report.usage_accounts:
        lines.append(f"- `{account['account_id']}`: {account['cost_text']}")
    if not report.usage_accounts:
        lines.append("- Keine Usage-Daten.")
    lines.extend(["", "## Risiken / Blocker", ""])
    if report.risks:
        lines.extend(f"- {value}" for value in report.risks)
    else:
        lines.append("- Keine.")
    lines.extend(["", "## Datenqualität", ""])
    if report.data_quality:
        lines.extend(f"- {value}" for value in report.data_quality)
    else:
        lines.append("- Keine Zusatzhinweise.")
    lines.extend(
        [
            "",
            "## Technische Metadaten",
            "",
            "<details>",
            "<summary>Bucket und Datenherkunft</summary>",
            "",
            f"- Bucket: `{report.bucket_id}`",
            "- Daten: sanitisiert; Rohprompts und Rohantworten nicht enthalten.",
            "",
            "</details>",
        ]
    )
    return "\n".join(lines) + "\n"


def _task_row(value: Mapping[str, object]) -> dict[str, str]:
    return {
        "title": _text(value.get("title"), "Unbenannte Aufgabe"),
        "status": _text(value.get("status"), "unknown"),
        "agent_id": _text(value.get("agent_id"), "—"),
    }


def _agent_row(value: Mapping[str, object]) -> dict[str, str]:
    return {
        "agent_id": _text(value.get("agent_id"), "—"),
        "series": _text(value.get("series"), "—"),
        "provider": _text(value.get("provider"), "—"),
        "account_id": _text(value.get("account_id"), "—"),
        "account_label": _text(value.get("account_label"), "—"),
        "state": _text(value.get("state"), "unknown"),
    }


def _usage_row(value: Mapping[str, object]) -> dict[str, object]:
    account_id = _text(value.get("account_id"), "—")
    costs = value.get("cost_windows", ())
    rendered: list[str] = []
    if isinstance(costs, Iterable) and not isinstance(costs, (str, bytes, Mapping)):
        for cost in costs:
            if not isinstance(cost, Mapping):
                continue
            number = cost.get("consumed_percentage_points")
            if isinstance(number, (int, float)) and not isinstance(number, bool) and math.isfinite(float(number)):
                rendered.append(f"{float(number):g} %-Pkt.")
    return {"account_id": account_id, "cost_text": ", ".join(rendered) or "—"}


def _task_line(row: Mapping[str, str]) -> str:
    return f"- {row['title']} ({row['status']}; {row['agent_id']})"


def _text(value: object, fallback: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        return fallback
    if _SECRET_RE.search(value):
        return fallback
    return value.replace("\n", " ").replace("\r", " ").replace("|", "¦")


def _task_identifier(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any(ord(char) < 32 for char in value)
        or _SECRET_RE.search(value)
    ):
        return None
    return value.replace("\n", " ").replace("\r", " ").replace("|", "¦")


def _task_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return _utc(parsed)
    except (TypeError, ValueError, OverflowError):
        return None


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def bucket_start(value: datetime) -> datetime:
    """Return canonical UTC hour start for an aware timestamp."""

    current = _utc(value)
    return current.replace(minute=0, second=0, microsecond=0)


def eligible_buckets(
    now: datetime,
    *,
    last_final: datetime | None = None,
    grace_minutes: int = 5,
    max_backfill_hours: int = 24,
) -> tuple[datetime, ...]:
    """Return complete, grace-eligible UTC buckets in oldest-first order."""

    if (
        isinstance(grace_minutes, bool)
        or not isinstance(grace_minutes, int)
        or not 0 <= grace_minutes <= 60
        or isinstance(max_backfill_hours, bool)
        or not isinstance(max_backfill_hours, int)
        or not 1 <= max_backfill_hours <= 24
    ):
        raise ValueError("report scheduler bounds are invalid")
    current = _utc(now)
    hour = bucket_start(current)
    candidate = hour - timedelta(hours=1)
    if current < candidate + timedelta(hours=1, minutes=grace_minutes):
        candidate -= timedelta(hours=1)
    if last_final is None:
        first = candidate - timedelta(hours=max_backfill_hours - 1)
    else:
        previous = bucket_start(last_final)
        first = previous + timedelta(hours=1)
        first = max(first, candidate - timedelta(hours=max_backfill_hours - 1))
    if first > candidate:
        return ()
    return tuple(
        first + timedelta(hours=offset)
        for offset in range(int((candidate - first).total_seconds() // 3600) + 1)
    )


class ReporterStateStore:
    """Private bounded state for final bucket hashes and retry metadata."""

    def __init__(self, path: Path):
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("reporter state path must be absolute")
        self.path = path

    def load(self) -> dict[str, object]:
        _assert_no_symlink_ancestors(self.path)
        if not self.path.exists():
            return {"schema_version": 1, "buckets": {}}
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("reporter state must be a regular file")
        if stat.S_IMODE(self.path.stat().st_mode) != 0o600 or self.path.stat().st_size > MAX_STATE_BYTES:
            raise ValueError("reporter state permissions or size are invalid")
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("reporter state is invalid") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != 1
            or not isinstance(payload.get("buckets"), dict)
            or len(payload["buckets"]) > MAX_BUCKET_RECORDS
        ):
            raise ValueError("reporter state is invalid")
        return payload

    def save(self, payload: Mapping[str, object]) -> None:
        if not isinstance(payload, Mapping) or payload.get("schema_version") != 1:
            raise ValueError("reporter state is invalid")
        encoded = (json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(encoded) > MAX_STATE_BYTES:
            raise ValueError("reporter state is too large")
        parent = self.path.parent
        _assert_no_symlink_ancestors(self.path)
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("reporter state parent must be a real directory")
        if self.path.is_symlink() or (self.path.exists() and not self.path.is_file()):
            raise ValueError("reporter state must be a regular file")
        os.chmod(parent, 0o700)
        temporary = parent / f".{self.path.name}.tmp-{os.getpid()}"
        if temporary.exists() or temporary.is_symlink():
            raise ValueError("reporter state temporary path already exists")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        finally:
            if fd >= 0:
                os.close(fd)
            if temporary.exists():
                temporary.unlink()

    def record(
        self,
        bucket: datetime,
        content: str,
        *,
        vault_path: Path | None,
        final: bool = True,
        replace: bool = False,
    ) -> tuple[dict[str, object], bool]:
        if not isinstance(content, str):
            raise ValueError("report content is invalid")
        canonical = bucket_start(bucket).isoformat().replace("+00:00", "Z") + "/PT1H"
        payload = self.load()
        buckets = dict(payload["buckets"])
        key = canonical
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        previous = buckets.get(key)
        if isinstance(previous, Mapping) and previous.get("status") == "final" and not replace:
            if previous.get("content_sha256") == digest:
                return dict(previous), False
            raise ValueError("final report already exists; replace is required")
        record = {
            "status": "final" if final else "partial",
            "content_sha256": digest,
            "vault_path": str(vault_path) if vault_path is not None else None,
            "emitted_at": datetime.now(UTC).isoformat(),
            "retry_count": int(previous.get("retry_count", 0)) + 1 if isinstance(previous, Mapping) else 0,
        }
        buckets[key] = record
        if len(buckets) > MAX_BUCKET_RECORDS:
            for old_key in sorted(buckets)[: len(buckets) - MAX_BUCKET_RECORDS]:
                buckets.pop(old_key, None)
        self.save({"schema_version": 1, "buckets": buckets})
        return record, True


def _assert_no_symlink_ancestors(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError("reporter state path must not contain symlink ancestors")
        if not current.exists():
            break
