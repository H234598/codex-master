from datetime import UTC, datetime, timedelta

from codex_master.goddess_supervisor import (
    ReporterLeaderBusy,
    ReporterLeaderLease,
    active_reporter_required,
    reporter_leader_active,
)


def test_reporter_requires_capability_and_live_binding():
    now = datetime(2026, 8, 16, 10, tzinfo=UTC)
    principals = ({"id": "goddess", "role": "goddess", "active": True},)
    bindings = ({"principal_id": "goddess", "expires_at": now + timedelta(hours=1)},)
    assert active_reporter_required(principals, bindings, now=now) is True
    assert active_reporter_required(principals, (), now=now) is False
    assert active_reporter_required(
        principals,
        ({"principal_id": "goddess", "expires_at": now - timedelta(seconds=1)},),
        now=now,
    ) is False


def test_reporter_accepts_persisted_hive_public_rows():
    now = datetime(2026, 8, 16, 10, tzinfo=UTC)
    assert active_reporter_required(
        ({"principal_id": "goddess", "class_id": "goddess", "state": "active"},),
        ({
            "principal_id": "goddess",
            "state": "active",
            "expires_at_utc": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        },),
        now=now,
    ) is True


def test_reporter_leader_is_single_process_scoped_and_probeable(tmp_path):
    path = tmp_path / "leader.lock"
    first = ReporterLeaderLease(path)
    second = ReporterLeaderLease(path)
    with first as held:
        assert held is first
        assert reporter_leader_active(path) is True
        try:
            second.acquire()
        except ReporterLeaderBusy:
            pass
        else:
            raise AssertionError("second reporter unexpectedly acquired leader lock")
    assert reporter_leader_active(path) is False
