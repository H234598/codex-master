from datetime import datetime, timedelta, timezone

from codex_master.selection import (
    AdmissionMode,
    AdmissionPolicy,
    FairnessLedger,
    FairnessRecord,
    ModelRole,
    SelectionBand,
    SelectionCandidate,
    SelectionError,
    SelectionPolicy,
    TaskKind,
    UsageObservation,
    normalize_usage_observation,
    normalize_usage_v2,
    preview_selection,
    preview_selection_admission,
    usage_windows_usable_for_sp1,
)


NOW = datetime(2026, 8, 5, 12, tzinfo=timezone.utc)


def candidate(agent_id: str, *, account_key: str = "account-a", **changes: object) -> SelectionCandidate:
    values: dict[str, object] = {
        "agent_id": agent_id,
        "account_key": account_key,
        "model_id": "primary-model",
        "task_kind": TaskKind.SIMPLE,
        "model_role": ModelRole.PRIMARY,
    }
    values.update(changes)
    return SelectionCandidate(**values)  # type: ignore[arg-type]


def test_ineligible_candidates_never_receive_a_selection_band() -> None:
    preview = preview_selection(
        [candidate("a1", authenticated=False), candidate("a2", account_ready=False)],
        policy=SelectionPolicy(sp3=True),
        now=NOW,
    )

    assert preview.selected is None
    assert preview.eligible_count == 0
    assert preview.exclusions == (("a1", "unauthenticated"), ("a2", "account_unready"))


def test_complex_or_unknown_work_never_uses_secondary_simple_model() -> None:
    secondary = candidate(
        "a1",
        model_id="spark",
        model_role=ModelRole.SECONDARY_SIMPLE,
        task_kind=TaskKind.COMPLEX,
        sp2_eligible=True,
    )
    preview = preview_selection(
        [secondary],
        policy=SelectionPolicy(sp2=True, sp3=True),
        now=NOW,
    )

    assert preview.selected is None
    assert preview.eligible_count == 0
    assert preview.exclusions == (("a1", "secondary_requires_simple_task"),)


def test_passive_sp0_requires_verified_remaining_percent_and_freshness() -> None:
    valid = UsageObservation("remaining", "percent", 100, "rolling_unanchored", "verified", NOW - timedelta(minutes=2))
    stale = UsageObservation("remaining", "percent", 100, "rolling_unanchored", "verified", NOW - timedelta(minutes=16))
    candidates = [
        candidate("a1", usage=stale),
        candidate("a2", usage=valid, account_key="account-b"),
    ]

    preview = preview_selection(candidates, policy=SelectionPolicy(sp0=True, sp3=True), now=NOW)

    assert preview.selected is not None
    assert preview.selected.agent_id == "a2"
    assert preview.selected.band is SelectionBand.SP0


def test_untyped_legacy_usage_is_unknown_and_cannot_activate_sp0() -> None:
    assert normalize_usage_observation({"remaining_percent": 100, "status": "ok"}) is None
    preview = preview_selection(
        [candidate("a1")],
        policy=SelectionPolicy(sp0=True),
        now=NOW,
    )

    assert preview.selected is None
    assert preview.exclusions == (("a1", "feature_disabled"),)


def test_typed_usage_v2_is_data_sparse_and_private_fields_fail_closed() -> None:
    observation = normalize_usage_observation({
        "semantics": "remaining",
        "unit": "percent",
        "value": 100,
        "reset_kind": "rolling_unanchored",
        "confidence": "verified",
        "observed_at": "2026-08-05T11:58:00Z",
    })
    assert observation is not None
    assert observation.is_passive_sp0_due(NOW)

    try:
        normalize_usage_observation({
            "semantics": "remaining",
            "unit": "percent",
            "value": 100,
            "reset_kind": "rolling_unanchored",
            "confidence": "verified",
            "observed_at": "2026-08-05T11:58:00Z",
            "account_id": "private-account",
        })
    except ValueError as exc:
        assert str(exc) == "invalid_usage_payload"
    else:
        raise AssertionError("private usage fields must be rejected")


def usage_window(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "window_id": "standard-5h",
        "budget_key": "standard",
        "applies_to_model_ids": ["primary-model"],
        "applies_to_model_roles": ["primary"],
        "quantity_semantics": "remaining",
        "quantity_unit": "percent",
        "quantity_value": 80,
        "capacity": 100,
        "absolute_remaining": 80,
        "window_kind": "rolling_5h",
        "constraint_relation": "conjunctive",
        "reset_at_utc": "2026-08-05T16:00:00Z",
        "reset_kind": "rolling",
        "observed_at_utc": "2026-08-05T11:58:00Z",
        "source": "codex_usage_v2",
        "confidence": "verified",
        "includes_inflight_usage": True,
        "blocked": False,
        "exhausted": False,
    }
    value.update(changes)
    return value


def test_usage_v2_windows_require_all_conjunctive_fresh_verified_budgets() -> None:
    windows = normalize_usage_v2({"schema_version": 2, "limit_windows": [usage_window()]})

    assert windows is not None
    assert len(windows) == 1
    assert usage_windows_usable_for_sp1(windows, NOW)
    assert normalize_usage_v2({"schema_version": 1, "status": "ok"}) is None


def test_usage_v2_sp1_accepts_a_conjunctive_fixed_window_with_a_five_hour_window() -> None:
    windows = normalize_usage_v2({
        "schema_version": 2,
        "limit_windows": [
            usage_window(),
            usage_window(
                window_id="standard-weekly",
                window_kind="fixed",
                reset_kind="fixed",
                quantity_value=53,
                absolute_remaining=53,
                reset_at_utc="2026-08-12T00:00:00Z",
            ),
        ],
    })

    assert windows is not None
    assert usage_windows_usable_for_sp1(windows, NOW)


def test_usage_v2_sp1_requires_a_five_hour_window_and_all_windows_usable() -> None:
    weekly_only = normalize_usage_v2({
        "schema_version": 2,
        "limit_windows": [usage_window(window_kind="fixed", reset_kind="fixed")],
    })
    exhausted_weekly = normalize_usage_v2({
        "schema_version": 2,
        "limit_windows": [
            usage_window(),
            usage_window(
                window_id="standard-weekly",
                window_kind="fixed",
                reset_kind="fixed",
                quantity_value=0,
                absolute_remaining=0,
                exhausted=True,
                blocked=True,
                reset_at_utc="2026-08-12T00:00:00Z",
            ),
        ],
    })

    assert weekly_only is not None and not usage_windows_usable_for_sp1(weekly_only, NOW)
    assert exhausted_weekly is not None and not usage_windows_usable_for_sp1(exhausted_weekly, NOW)


def test_usage_v2_alternative_stale_and_past_reset_windows_fail_closed() -> None:
    alternative = normalize_usage_v2({
        "schema_version": 2,
        "limit_windows": [usage_window(constraint_relation="alternative")],
    })
    stale = normalize_usage_v2({
        "schema_version": 2,
        "limit_windows": [usage_window(observed_at_utc="2026-08-05T11:00:00Z")],
    })
    past_reset = normalize_usage_v2({
        "schema_version": 2,
        "limit_windows": [usage_window(reset_at_utc="2026-08-05T11:00:00Z")],
    })

    assert alternative is not None and not usage_windows_usable_for_sp1(alternative, NOW)
    assert stale is not None and not usage_windows_usable_for_sp1(stale, NOW)
    assert past_reset is not None and not usage_windows_usable_for_sp1(past_reset, NOW)


def test_usage_v2_window_rejects_private_fields() -> None:
    try:
        normalize_usage_v2({
            "schema_version": 2,
            "limit_windows": [usage_window(token="secret")],
        })
    except ValueError as exc:
        assert str(exc) == "invalid_usage_window"
    else:
        raise AssertionError("private usage window fields must be rejected")


def test_band_order_is_deterministic_and_sp3_fairness_is_non_mutating() -> None:
    ledger = FairnessLedger({
        "account-a": FairnessRecord(9_000_000, 1_000_000, NOW - timedelta(days=1)),
        "account-b": FairnessRecord(1_000_000, 1_000_000, NOW - timedelta(days=1)),
    })
    before = dict(ledger.records)
    preview = preview_selection(
        [
            candidate("a1", account_key="account-a", sp1a_bucket=0),
            candidate("b1", account_key="account-b", sp1a_bucket=1),
        ],
        policy=SelectionPolicy(sp1a=True, sp3=True),
        now=NOW,
        ledger=ledger,
    )

    assert preview.selected is not None
    assert preview.selected.agent_id == "a1"
    assert preview.selected.band is SelectionBand.SP1A
    assert dict(ledger.records) == before


def test_sp3_uses_fixed_point_decay_and_median_bootstrap_without_private_output() -> None:
    ledger = FairnessLedger({
        "known-a": FairnessRecord(4_000_000, 1_000_000, NOW),
        "known-b": FairnessRecord(8_000_000, 1_000_000, NOW),
    })
    preview = preview_selection(
        [candidate("new", account_key="new-account"), candidate("known", account_key="known-b")],
        policy=SelectionPolicy(sp3=True),
        now=NOW,
        ledger=ledger,
    )

    assert preview.selected is not None
    assert preview.selected.band is SelectionBand.SP3
    assert preview.selected.agent_id == "new"
    assert preview.selected.fairness_micro == 4_000_000
    assert "known-b" not in repr(preview)


def test_all_feature_gates_off_keep_preview_closed() -> None:
    preview = preview_selection([candidate("a1")], policy=SelectionPolicy(), now=NOW)

    assert preview.selected is None
    assert preview.exclusions == (("a1", "feature_disabled"),)


def test_admission_defaults_closed_without_hiding_selection_preview() -> None:
    preview = preview_selection_admission(
        [candidate("a1")],
        selection_policy=SelectionPolicy(sp3=True),
        admission_policy=AdmissionPolicy(),
        now=NOW,
    )

    assert preview.selection.selected is not None
    assert preview.mode is AdmissionMode.OFF
    assert not preview.planned
    assert not preview.executable
    assert preview.reason == "admission_disabled"
    assert preview.missing_gates == (
        "pilot_repository", "principal", "scope", "account", "model", "reservation", "execute",
    )


def test_shadow_admission_plans_but_never_executes_and_does_not_mutate_ledger() -> None:
    ledger = FairnessLedger({
        "account-a": FairnessRecord(9_000_000, 1_000_000, NOW),
    })
    before = dict(ledger.records)
    preview = preview_selection_admission(
        [candidate("a1")],
        selection_policy=SelectionPolicy(sp3=True),
        admission_policy=AdmissionPolicy(mode=AdmissionMode.SHADOW),
        now=NOW,
        ledger=ledger,
    )

    assert preview.planned
    assert not preview.executable
    assert preview.reason == "shadow_only"
    assert preview.selection.selected is not None
    assert dict(ledger.records) == before
    assert "account-a" not in repr(preview)


def test_enforced_admission_requires_every_gate_and_reuses_shadow_selection() -> None:
    shadow = preview_selection_admission(
        [candidate("a1")],
        selection_policy=SelectionPolicy(sp3=True),
        admission_policy=AdmissionPolicy(mode=AdmissionMode.SHADOW),
        now=NOW,
    )
    enforced = preview_selection_admission(
        [candidate("a1")],
        selection_policy=SelectionPolicy(sp3=True),
        admission_policy=AdmissionPolicy(
            mode=AdmissionMode.ENFORCED,
            pilot_repository_allowed=True,
            principal_verified=True,
            scope_allowed=True,
            account_verified=True,
            model_verified=True,
            reservation_available=True,
            execute_enabled=True,
        ),
        now=NOW,
    )

    assert shadow.selection.selected == enforced.selection.selected
    assert enforced.planned
    assert enforced.executable
    assert enforced.reason == "admitted"
    assert enforced.missing_gates == ()


def test_enforced_admission_reports_ordered_missing_gates_fail_closed() -> None:
    preview = preview_selection_admission(
        [candidate("a1")],
        selection_policy=SelectionPolicy(sp3=True),
        admission_policy=AdmissionPolicy(
            mode=AdmissionMode.ENFORCED,
            pilot_repository_allowed=True,
            principal_verified=True,
            scope_allowed=True,
            account_verified=False,
            model_verified=True,
            reservation_available=False,
            execute_enabled=True,
        ),
        now=NOW,
    )

    assert not preview.planned
    assert not preview.executable
    assert preview.reason == "admission_gate_blocked"
    assert preview.missing_gates == ("account", "reservation")


def test_selection_and_admission_policies_reject_non_boolean_flags() -> None:
    try:
        SelectionPolicy(sp3=1)  # type: ignore[arg-type]
    except SelectionError as exc:
        assert str(exc) == "invalid_selection_policy"
    else:
        raise AssertionError("selection policy must reject non-boolean flags")

    try:
        AdmissionPolicy(mode=AdmissionMode.SHADOW, execute_enabled=1)  # type: ignore[arg-type]
    except SelectionError as exc:
        assert str(exc) == "invalid_admission_policy"
    else:
        raise AssertionError("admission policy must reject non-boolean flags")
