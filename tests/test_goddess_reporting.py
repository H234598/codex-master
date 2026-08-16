from datetime import UTC, datetime, timedelta

import json

import pytest

from codex_master.goddess_reporting import (
    ReporterStateStore,
    aggregate_task_rows,
    build_hourly_report,
    bucket_start,
    eligible_buckets,
    render_markdown,
)


def test_task_aggregation_uses_assignment_and_terminal_events():
    start = datetime(2026, 8, 16, 10, tzinfo=UTC)
    completed, pending = aggregate_task_rows(
        start,
        assignments=(
            {"assignment_id": "done-1", "created_at_utc": "2026-08-16T10:05:00Z", "agent": "g1"},
            {"assignment_id": "open-1", "created_at_utc": "2026-08-16T09:30:00Z", "agent": "g2"},
        ),
        events=(
            {"assignment_id": "done-1", "at_utc": "2026-08-16T10:20:00Z", "status": "completed"},
            {"assignment_id": "open-1", "at_utc": "2026-08-16T10:10:00Z", "status": "rate_limited"},
        ),
    )

    assert completed == (
        {"title": "done-1", "status": "completed", "agent_id": "g1"},
    )
    assert pending == (
        {"title": "open-1", "status": "rate_limited", "agent_id": "g2"},
    )


def test_task_aggregation_keeps_hive_blocked_state_pending():
    start = datetime(2026, 8, 16, 10, tzinfo=UTC)
    completed, pending = aggregate_task_rows(
        start,
        assignments=(
            {"assignment_id": "blocked-1", "created_at_utc": "2026-08-16T10:05:00Z", "agent": "g1"},
        ),
        events=(
            {"assignment_id": "blocked-1", "at_utc": "2026-08-16T10:20:00Z", "status": "blocked"},
        ),
    )

    assert completed == ()
    assert pending == (
        {"title": "blocked-1", "status": "blocked", "agent_id": "g1"},
    )


def test_hourly_report_uses_utc_bucket_and_allowlisted_data():
    start = datetime(2026, 8, 16, 10, tzinfo=UTC)
    report = build_hourly_report(
        start,
        completed=(
            {
                "title": "Task abgeschlossen",
                "status": "success",
                "agent_id": "g1",
                "prompt": "SECRET_PROMPT",
            },
        ),
        pending=( {"title": "Noch offen", "status": "queued", "agent_id": "g2"}, ),
        agents=(
            {
                "agent_id": "g1",
                "series": "G",
                "provider": "gemini_api",
                "account_id": "gem-a",
                "account_label": "Gemini A",
                "state": "active",
            },
        ),
        usage_accounts=(
            {
                "account_id": "gem-a",
                "cost_windows": (
                    {
                        "lookback_seconds": 3600,
                        "pool": "main",
                        "limit_window_seconds": 18000,
                        "consumed_percentage_points": 4.5,
                        "coverage": "complete",
                        "sample_count": 5,
                    },
                ),
            },
        ),
    )

    assert report.bucket_id == "2026-08-16T10:00:00Z/PT1H"
    text = render_markdown(report)
    assert "SECRET_PROMPT" not in text
    assert "Task abgeschlossen" in text
    assert "Gemini A" in text
    assert "4.5" in text
    assert "status: final" in text
    assert "## Risiken / Blocker" in text
    assert "## Datenqualität" in text
    assert "SECRET_PROMPT" not in text


def test_hourly_report_requires_one_complete_utc_hour():
    start = datetime(2026, 8, 16, 10, tzinfo=UTC)
    try:
        build_hourly_report(start, end=start + timedelta(minutes=30))
    except ValueError as exc:
        assert "hour" in str(exc)
    else:
        raise AssertionError("incomplete bucket accepted")


def test_scheduler_applies_grace_and_returns_oldest_first_backfill():
    now = datetime(2026, 8, 16, 10, 4, tzinfo=UTC)
    assert eligible_buckets(now, last_final=datetime(2026, 8, 16, 7, tzinfo=UTC)) == (
        datetime(2026, 8, 16, 8, tzinfo=UTC),
    )
    now = datetime(2026, 8, 16, 10, 5, tzinfo=UTC)
    assert eligible_buckets(now, last_final=datetime(2026, 8, 16, 7, tzinfo=UTC)) == (
        datetime(2026, 8, 16, 8, tzinfo=UTC),
        datetime(2026, 8, 16, 9, tzinfo=UTC),
    )


def test_reporter_state_is_bounded_and_idempotent(tmp_path):
    store = ReporterStateStore(tmp_path / "state" / "reporter.json")
    bucket = bucket_start(datetime(2026, 8, 16, 10, 20, tzinfo=UTC))
    first, changed = store.record(bucket, "report-a", vault_path=tmp_path / "a.md")
    assert changed is True
    second, changed = store.record(bucket, "report-a", vault_path=tmp_path / "a.md")
    assert changed is False
    assert second["content_sha256"] == first["content_sha256"]
    with pytest.raises(ValueError, match="replace"):
        store.record(bucket, "report-b", vault_path=tmp_path / "a.md")
    replaced, changed = store.record(
        bucket,
        "report-b",
        vault_path=tmp_path / "a.md",
        replace=True,
    )
    assert changed is True
    assert replaced["status"] == "final"
    assert json.loads(store.path.read_text(encoding="utf-8"))["schema_version"] == 1


def test_reporter_state_rejects_symlinked_parent_on_read(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    state_file = outside / "reporter.json"
    state_file.write_text(
        '{"schema_version":1,"buckets":{}}\n',
        encoding="utf-8",
    )
    state_file.chmod(0o600)
    linked_parent = tmp_path / "state"
    linked_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink ancestors"):
        ReporterStateStore(linked_parent / "reporter.json").load()
