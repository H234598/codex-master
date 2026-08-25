from __future__ import annotations

import contextlib
import importlib
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, Mock, patch

import pytest

from codex_master.usage_snapshot import UsageEvidenceV2, UsageSnapshot


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)


def server_module():
    return importlib.import_module("codex_master.server")


def complete_evidence(status: str = "complete") -> UsageEvidenceV2:
    return UsageEvidenceV2((), status, NOW, NOW)


def patch_overview_dependencies(module: object, evidence: UsageEvidenceV2):
    events: list[str] = []
    service = Mock()
    service.registry_snapshot.return_value = SimpleNamespace(
        accounts=(SimpleNamespace(account_id="overview-account"),)
    )

    @contextlib.contextmanager
    def lock(_path: Path):
        events.append("lock-enter")
        yield
        events.append("lock-exit")

    def inventory(_snapshot: object, _pool_root: Path) -> object:
        events.append("inventory")
        return object()

    def overview(*_args: object, **_kwargs: object) -> object:
        events.append("overview")
        return object()

    def display(
        value: UsageEvidenceV2, *, known_account_ids: frozenset[str]
    ) -> UsageSnapshot:
        assert value is evidence
        assert known_account_ids == frozenset({"overview-account"})
        events.append("display")
        return UsageSnapshot((), "unavailable", True, ("usage_unavailable",))

    def tracker(value: UsageEvidenceV2, *, now: datetime) -> tuple[object, ...]:
        assert value is evidence
        assert now == NOW
        events.append("tracker")
        return ()

    def enrich(base: object, snapshot: UsageSnapshot) -> object:
        assert base is not None
        assert snapshot.source == "unavailable"
        events.append("enrich")
        return object()

    def render(_overview: object, *, format: str) -> str:
        assert format == "json"
        events.append("render")
        return "rendered"

    reader = patch.object(module, "read_usage_evidence_v2", return_value=evidence)
    derive = patch.object(module, "derive_limit_decisions", side_effect=tracker)
    patches = (
        patch.object(
            module,
            "FleetPaths",
            SimpleNamespace(
                from_state_root=lambda _root: SimpleNamespace(lock=Path("/lock"))
            ),
        ),
        patch.object(module, "_fleet_registry_read_lock", lock),
        patch.object(module, "_readonly_fleet_service", return_value=service),
        patch.object(module, "build_inventory", side_effect=inventory),
        patch.object(module, "build_fleet_overview", side_effect=overview),
        patch.object(module, "display_snapshot_from_evidence", side_effect=display),
        patch.object(module, "enrich_fleet_overview_usage", side_effect=enrich),
        patch.object(module, "render_fleet_overview", side_effect=render),
    )
    return events, reader, derive, patches


def test_server_imports_with_only_v2_usage_consumer() -> None:
    module = server_module()

    assert callable(module.read_usage_evidence_v2)
    assert callable(module.derive_limit_decisions)


def test_reconciliation_reads_one_complete_v2_dto_then_projects_and_evaluates() -> None:
    module = server_module()
    evidence = complete_evidence()
    events, reader, derive, patches = patch_overview_dependencies(module, evidence)

    with contextlib.ExitStack() as stack:
        reader_mock = stack.enter_context(reader)
        derive_mock = stack.enter_context(derive)
        for item in patches:
            stack.enter_context(item)
        result = module._fleet_overview_local_admin(
            active_only=True,
            format="json",
            clock=lambda: NOW,
            usage_clock=lambda: NOW,
        )

    assert result == "rendered"
    reader_mock.assert_called_once_with(clock=ANY)
    derive_mock.assert_called_once_with(evidence, now=NOW)
    assert events == [
        "lock-enter",
        "inventory",
        "overview",
        "lock-exit",
        "tracker",
        "display",
        "enrich",
        "render",
    ]


@pytest.mark.parametrize(
    "status", ["busy", "unavailable", "invalid", "stale", "partial"]
)
def test_noncomplete_v2_status_is_display_only_and_never_reaches_tracker(
    status: str,
) -> None:
    module = server_module()
    evidence = complete_evidence(status)
    events, reader, derive, patches = patch_overview_dependencies(module, evidence)

    with contextlib.ExitStack() as stack:
        reader_mock = stack.enter_context(reader)
        derive_mock = stack.enter_context(derive)
        for item in patches:
            stack.enter_context(item)
        result = module._fleet_overview_local_admin(
            active_only=True,
            format="json",
            clock=lambda: NOW,
            usage_clock=lambda: NOW,
        )

    assert result == "rendered"
    reader_mock.assert_called_once_with(clock=ANY)
    derive_mock.assert_not_called()
    assert events == [
        "lock-enter",
        "inventory",
        "overview",
        "lock-exit",
        "display",
        "enrich",
        "render",
    ]
