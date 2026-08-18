from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetSeries,
    FleetSnapshot,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
)
from codex_master.fleet_runners import ProbeResult, ProviderErrorQuotaObservation


NOW = datetime(2026, 8, 3, 12, tzinfo=timezone.utc)


def _account(account_id: str) -> FleetAccount:
    return FleetAccount(
        account_id,
        account_id,
        Provider.GEMINI_API,
        AuthKind.API_KEY,
        SecretState.CONFIGURED,
        LimitState.READY,
        True,
        None,
        NOW.isoformat().replace("+00:00", "Z"),
        None,
    )


def _series(prefix: str, account_id: str, model: str) -> FleetSeries:
    return FleetSeries(
        prefix,
        prefix,
        1,
        RunnerKind.GEMINI_CLI,
        Provider.GEMINI_API,
        model,
        account_id,
        True,
    )


def _service(tmp_path: Path, accounts: tuple[FleetAccount, ...], series: tuple[FleetSeries, ...]):
    from codex_master.fleet_service import FleetPaths, FleetService
    from codex_master.server import build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path)
    service = FleetService(
        paths,
        replace(build_fleet_private_io(paths), utc_now=lambda: NOW),
        pool_root=tmp_path / "pool",
    )
    service.commit_snapshot(FleetSnapshot(1, 2, accounts, series), expected_generation=1)
    return service, paths


def test_known_model_rpm_gate_rotates_to_ready_gemini_account_before_openai(tmp_path: Path) -> None:
    service, _ = _service(
        tmp_path,
        (_account("the-hive-4"), _account("the-hive-6")),
        (
            _series("d", "the-hive-4", "gemini-3-flash"),
            _series("e", "the-hive-6", "gemini-3-flash"),
        ),
    )
    for _ in range(5):
        service.record_gemini_usage("the-hive-4", model="gemini-3-flash")

    decision = service.gemini_headless_gate("d1")

    assert decision.action == "rotate_account"
    assert decision.diagnostic_code == "gemini_rpm_exhausted"
    assert decision.target_agent_id == "e1"
    assert decision.openai_fallback_reason is None


def test_known_local_reset_defers_headless_start_until_reset(tmp_path: Path) -> None:
    service, _ = _service(
        tmp_path,
        (_account("the-hive-4"),),
        (_series("d", "the-hive-4", "gemini-3-flash"),),
    )
    reservation = service.reserve_gemini_request("the-hive-4")
    service.release_gemini_request(
        reservation,
        outcome="rate_limited",
        reset_at_utc="2026-08-03T12:10:00Z",
    )

    decision = service.gemini_headless_gate("d1")

    assert decision.action == "defer_until"
    assert decision.defer_until == "2026-08-03T12:10:00Z"
    assert decision.diagnostic_code == "gemini_local_rate_limited"


def test_probe_reservation_blocks_following_work_request_in_same_local_minute(tmp_path: Path) -> None:
    service, _ = _service(
        tmp_path,
        (_account("the-hive-4"),),
        (_series("d", "the-hive-4", "gemini-3-flash"),),
    )

    service.probe_account(
        "the-hive-4",
        lambda _account: ProbeResult(Provider.GEMINI_API, True, "gemini-3-flash", True, None),
        expected_generation=2,
    )

    assert service.gemini_headless_gate("d1").action == "defer_until"


def test_known_model_rpm_gate_rotates_to_equal_gemini_model_on_same_key(tmp_path: Path) -> None:
    service, _ = _service(
        tmp_path,
        (_account("the-hive-4"), _account("the-hive-6")),
        (
            _series("d", "the-hive-4", "gemini-3-flash"),
            _series("e", "the-hive-4", "gemini-3.1-flash-lite"),
            _series("f", "the-hive-6", "gemini-3-flash"),
        ),
    )
    for _ in range(5):
        service.record_gemini_usage("the-hive-4", model="gemini-3-flash")

    decision = service.gemini_headless_gate("d1")

    assert (decision.action, decision.target_agent_id) == ("rotate_model", "e1")


def test_model_scope_limited_rotation_keeps_account_ready_and_rotates_model(tmp_path: Path) -> None:
    service, _ = _service(
        tmp_path,
        (_account("shared"), _account("the-hive-6")),
        (
            _series("d", "shared", "gemini-3-flash"),
            _series("e", "shared", "gemini-3.1-flash-lite"),
            _series("f", "the-hive-6", "gemini-3-flash"),
        ),
    )
    service.record_gemini_usage(
        "shared",
        model="gemini-3-flash",
        status="failed",
        gate_action="defer_until",
        gate_code="gemini_model_limited",
        next_reset_at_utc="2026-08-03T12:02:00Z",
        quota_observation=ProviderErrorQuotaObservation(scope="model", retry_after_seconds=120),
    )

    decision = service.gemini_headless_gate("d1")

    assert decision.action == "rotate_model"
    assert decision.target_agent_id == "e1"
    assert decision.diagnostic_code == "gemini_model_limited"
    assert service.account_gate("d1").reason == "ready"


def test_unknown_dashboard_limits_remain_explicitly_observed_only(tmp_path: Path) -> None:
    service, _ = _service(
        tmp_path,
        (_account("untracked"),),
        (_series("d", "untracked", "gemini-3-flash"),),
    )

    decision = service.gemini_headless_gate("d1")

    assert (decision.action, decision.diagnostic_code) == ("allow", "gemini_limits_unknown")
    assert decision.defer_until is None
    assert decision.public()["next_reset_at_utc"] is None


@pytest.mark.parametrize(("event_time", "count", "input_tokens", "code", "reset_at"), [
    (
        NOW - timedelta(seconds=30),
        5,
        0,
        "gemini_rpm_exhausted",
        "2026-08-03T12:00:30Z",
    ),
    (
        NOW - timedelta(seconds=20),
        1,
        250_000,
        "gemini_tpm_exhausted",
        "2026-08-03T12:00:40Z",
    ),
    (
        NOW - timedelta(hours=1),
        20,
        0,
        "gemini_rpd_exhausted",
        "2026-08-04T11:00:00Z",
    ),
])
def test_known_quota_windows_provide_metric_reset_to_gate(
    tmp_path: Path,
    event_time: datetime,
    count: int,
    input_tokens: int,
    code: str,
    reset_at: str,
) -> None:
    service, _ = _service(
        tmp_path,
        (_account("the-hive-4"),),
        (_series("d", "the-hive-4", "gemini-3-flash"),),
    )
    service._io = replace(service._io, utc_now=lambda: event_time)
    for _ in range(count):
        service.record_gemini_usage(
            "the-hive-4", model="gemini-3-flash", input_tokens=input_tokens,
        )
    service._io = replace(service._io, utc_now=lambda: NOW)

    decision = service.gemini_headless_gate("d1")

    assert decision.action == "defer_until"
    assert decision.diagnostic_code == code
    assert decision.defer_until == reset_at
    assert decision.public()["next_reset_at_utc"] == reset_at


def test_quota_reset_waits_until_observed_count_falls_below_limit(tmp_path: Path) -> None:
    service, _ = _service(
        tmp_path,
        (_account("the-hive-4"),),
        (_series("d", "the-hive-4", "gemini-3-flash"),),
    )
    for seconds_ago in (50, 40, 30, 20, 10, 0):
        event_time = NOW - timedelta(seconds=seconds_ago)
        service._io = replace(service._io, utc_now=lambda event_time=event_time: event_time)
        service.record_gemini_usage("the-hive-4", model="gemini-3-flash")
    service._io = replace(service._io, utc_now=lambda: NOW)

    decision = service.gemini_headless_gate("d1")

    assert decision.diagnostic_code == "gemini_rpm_exhausted"
    assert decision.defer_until == "2026-08-03T12:00:20Z"


def test_known_reset_releases_gate_when_time_has_passed(tmp_path: Path) -> None:
    service, _ = _service(
        tmp_path,
        (_account("the-hive-4"),),
        (_series("d", "the-hive-4", "gemini-3-flash"),),
    )
    reservation = service.reserve_gemini_request("the-hive-4")
    service.release_gemini_request(
        reservation,
        outcome="rate_limited",
        reset_at_utc="2026-08-03T12:10:00Z",
    )
    service._io = replace(service._io, utc_now=lambda: datetime(2026, 8, 3, 12, 10, tzinfo=timezone.utc))

    assert service.gemini_headless_gate("d1").action == "allow"


def test_openai_fallback_reason_is_exposed_only_after_gemini_rotation_is_exhausted(tmp_path: Path) -> None:
    openai = FleetAccount(
        "openai", "openai", Provider.OPENAI_API, AuthKind.API_KEY,
        SecretState.CONFIGURED, LimitState.READY, True, None,
        NOW.isoformat().replace("+00:00", "Z"), None,
    )
    service, _ = _service(
        tmp_path,
        (_account("the-hive-4"), openai),
        (
            _series("d", "the-hive-4", "gemini-3-flash"),
            FleetSeries("o", "o", 1, RunnerKind.CODEX_CLI, Provider.OPENAI_API, "gpt", "openai", True),
        ),
    )
    for _ in range(5):
        service.record_gemini_usage("the-hive-4", model="gemini-3-flash")

    decision = service.gemini_headless_gate("d1")

    assert decision.action == "defer_until"
    assert decision.defer_until == "2026-08-03T12:01:00Z"
    assert decision.openai_fallback_reason == "Gemini rotation exhausted; eligible OpenAI fallback may be selected."


def test_usage_ledger_keeps_gate_usage_and_reset_but_never_prompt_or_secret(tmp_path: Path) -> None:
    service, paths = _service(
        tmp_path,
        (_account("the-hive-4"),),
        (_series("d", "the-hive-4", "gemini-3-flash"),),
    )

    service.record_gemini_usage(
        "the-hive-4",
        model="gemini-3-flash",
        input_tokens=105_547,
        output_tokens=17,
        tool_call_count=13,
        status="failed",
        gate_action="allow",
        gate_code="gemini_ready",
        next_reset_at_utc="2026-08-03T12:10:00Z",
    )

    status = service.gemini_usage_status("the-hive-4")
    ledger = paths.usage.read_text(encoding="utf-8")
    assert status["tool_call_count_24h"] == 13
    assert status["last_gate"] == {"action": "allow", "code": "gemini_ready"}
    assert "prompt" not in ledger.lower()
    assert "secret" not in ledger.lower()
    assert "105547" in ledger


def test_event_ledger_replaces_unstructured_failure_reason_with_redacted_code(tmp_path: Path) -> None:
    service, paths = _service(
        tmp_path,
        (_account("the-hive-4"),),
        (_series("d", "the-hive-4", "gemini-3-flash"),),
    )

    service.record_gemini_event(
        event_type="headless_exception",
        agent_id="d1",
        account_id="the-hive-4",
        assignment_id="assignment-1",
        status="failed",
        reason="private provider detail must not be persisted",
        model="gemini-3-flash",
    )

    ledger = paths.events.read_text(encoding="utf-8")
    assert "private provider detail" not in ledger
    assert '"reason": "runner_failed"' in ledger


@pytest.mark.parametrize(("legacy_code", "expected_code"), [
    ("ready", "gemini_ready"),
    ("limit_active", "gemini_account_limited"),
    ("probe_stale", "gemini_probe_stale"),
    ("gemini_local_rate_limit", "gemini_local_rate_limited"),
    ("account_disabled", "gemini_account_disabled"),
    ("secret_missing", "gemini_secret_missing"),
    ("auth_invalid", "gemini_auth_invalid"),
    ("provider_unavailable", "gemini_provider_unavailable"),
    ("model_unavailable", "gemini_model_unavailable"),
    ("limit_unknown", "gemini_account_limit_unknown"),
])
def test_every_gate_diagnostic_is_redacted_and_legacy_codes_map_exactly(
    legacy_code: str, expected_code: str,
) -> None:
    from codex_master.fleet_service import GEMINI_GATE_DIAGNOSTICS, map_gemini_gate_code

    mapped = map_gemini_gate_code(legacy_code)
    assert mapped == expected_code
    diagnostic = GEMINI_GATE_DIAGNOSTICS[mapped]

    assert diagnostic["severity"] in {"info", "warning", "error"}
    assert isinstance(diagnostic["retryable"], bool)
    assert diagnostic["action"] in {"allow", "defer_until", "rotate_account", "rotate_model", "reject"}
    assert "secret" not in diagnostic["reason"].lower()
    assert "prompt" not in diagnostic["reason"].lower()


def test_all_gate_diagnostics_have_safe_complete_metadata() -> None:
    from codex_master.fleet_service import GEMINI_GATE_DIAGNOSTICS

    for code, diagnostic in GEMINI_GATE_DIAGNOSTICS.items():
        assert code.startswith("gemini_")
        assert diagnostic["severity"] in {"info", "warning", "error"}
        assert isinstance(diagnostic["retryable"], bool)
        assert diagnostic["action"] in {"allow", "defer_until", "rotate_account", "rotate_model", "reject"}
        assert "secret" not in diagnostic["reason"].lower()
        assert "prompt" not in diagnostic["reason"].lower()
