from __future__ import annotations

import json
import math

import pytest

from codex_master.resource_ema import (
    MAX_SNAPSHOT_BYTES,
    ResourceEMAAdmissionV1,
    ResourceEMAError,
    canonical_policy,
    thermal_policy,
)


NS = 1_000_000_000


def _core(*roles: str) -> ResourceEMAAdmissionV1:
    return ResourceEMAAdmissionV1.cold(tuple(canonical_policy(role) for role in roles))


@pytest.mark.parametrize(
    ("policy", "delta_seconds", "tau_seconds"),
    [
        (canonical_policy("cpu_busy"), 7.0, 30.0),
        (canonical_policy("io_psi_full_avg10"), 3.0, 15.0),
        (thermal_policy("thermal_cpu_package", high=80.0, crit=100.0), 5.0, 15.0),
        (canonical_policy("gpu_utilization"), 11.0, 20.0),
    ],
)
def test_irregular_intervals_use_time_correct_ema_for_every_tau_class(
    policy: object, delta_seconds: float, tau_seconds: float
) -> None:
    core = ResourceEMAAdmissionV1.cold((policy,)).observe(policy.role, 0.0, 0)
    updated = core.observe(policy.role, 100.0, int(delta_seconds * NS))

    metric = updated.metric(policy.role)
    expected = 100.0 * (1.0 - math.exp(-delta_seconds / tau_seconds))
    assert metric.ema == pytest.approx(expected)
    assert metric.tau_seconds == tau_seconds
    assert metric.coverage_seconds == delta_seconds


def test_poll_interval_changes_do_not_change_tau() -> None:
    core = _core("cpu_busy").observe("cpu_busy", 10.0, 0)
    expected = 10.0
    previous_seconds = 0.0

    for seconds, raw in ((1.0, 30.0), (5.0, 70.0), (17.0, 20.0)):
        delta = seconds - previous_seconds
        expected += (1.0 - math.exp(-delta / 30.0)) * (raw - expected)
        core = core.observe("cpu_busy", raw, int(seconds * NS))
        assert core.metric("cpu_busy").ema == pytest.approx(expected)
        assert core.metric("cpu_busy").tau_seconds == 30.0
        previous_seconds = seconds


def test_ema_hysteresis_enters_holds_and_releases_without_flapping() -> None:
    core = _core("cpu_busy").observe("cpu_busy", 89.0, 0)
    assert core.decision(0).normal_blocked_roles == ()

    core = core.observe("cpu_busy", 100.0, 60 * NS)
    assert core.decision(60 * NS).normal_blocked_roles == ("cpu_busy",)

    core = core.observe("cpu_busy", 84.0, 61 * NS)
    assert core.metric("cpu_busy").ema > 85.0
    assert core.decision(61 * NS).normal_blocked_roles == ("cpu_busy",)

    core = core.observe("cpu_busy", 0.0, 121 * NS)
    assert core.metric("cpu_busy").ema <= 85.0
    assert core.decision(121 * NS).normal_blocked_roles == ()


def test_thermal_raw_spike_is_not_a_normal_block_but_sustained_ema_is() -> None:
    policy = thermal_policy("thermal_cpu_package", high=80.0, crit=100.0)
    core = ResourceEMAAdmissionV1.cold((policy,)).observe(policy.role, 70.0, 0)

    core = core.observe(policy.role, 90.0, NS)
    assert core.metric(policy.role).raw == 90.0
    assert core.metric(policy.role).ema < 80.0
    assert core.decision(NS).normal_blocked_roles == ()

    core = core.observe(policy.role, 90.0, 31 * NS)
    assert core.metric(policy.role).ema >= 80.0
    assert core.decision(31 * NS).normal_blocked_roles == (policy.role,)

    core = core.observe(policy.role, 70.0, 32 * NS)
    assert core.metric(policy.role).ema > 75.0
    assert core.decision(32 * NS).normal_blocked_roles == (policy.role,)

    core = core.observe(policy.role, 70.0, 62 * NS)
    assert core.metric(policy.role).ema <= 75.0
    assert core.decision(62 * NS).normal_blocked_roles == ()


def test_first_valid_value_initializes_ema_and_can_block_immediately() -> None:
    high = _core("cpu_busy").observe("cpu_busy", 90.0, 10 * NS)
    low = _core("cpu_busy").observe("cpu_busy", 20.0, 10 * NS)

    assert high.metric("cpu_busy").ema == 90.0
    assert high.metric("cpu_busy").coverage_seconds == 0.0
    assert high.decision(10 * NS).normal_blocked_roles == ("cpu_busy",)
    assert low.metric("cpu_busy").ema == 20.0
    assert low.decision(10 * NS).blocked is False


def test_bad_evidence_is_fail_closed_and_only_invalidates_its_metric() -> None:
    core = _core("cpu_busy", "io_psi_full_avg10")
    core = core.observe("cpu_busy", 20.0, NS)
    core = core.observe("io_psi_full_avg10", 10.0, NS)
    io_before = core.metric("io_psi_full_avg10")

    malformed = core.observe("cpu_busy", {"provider": "raw-secret"}, 2 * NS)

    assert malformed.metric("io_psi_full_avg10") == io_before
    assert malformed.metric("cpu_busy").ema is None
    assert malformed.decision(2 * NS).interlocks == (("cpu_busy", "invalid_evidence"),)
    assert b"raw-secret" not in malformed.to_json()

    recovered = malformed.observe("cpu_busy", 30.0, 3 * NS)
    assert recovered.metric("cpu_busy").ema == 30.0
    assert recovered.decision(3 * NS).interlocks == ()


def test_gap_time_rollback_and_stale_evidence_fail_closed() -> None:
    initial = _core("cpu_busy").observe("cpu_busy", 20.0, 10 * NS)

    rollback = initial.observe("cpu_busy", 30.0, 9 * NS)
    assert rollback.metric("cpu_busy").ema is None
    assert rollback.decision(9 * NS).interlocks == (("cpu_busy", "time_regression"),)

    gap = initial.observe("cpu_busy", 30.0, 71 * NS)
    assert gap.metric("cpu_busy").ema is None
    assert gap.decision(71 * NS).interlocks == (("cpu_busy", "gap_exceeded"),)

    assert initial.decision(70 * NS).interlocks == ()
    assert initial.decision(70 * NS + 1).interlocks == (("cpu_busy", "stale_evidence"),)


def test_coverage_is_capped_at_one_tau_and_is_visible() -> None:
    core = _core("io_psi_some_avg10").observe("io_psi_some_avg10", 10.0, 0)
    core = core.observe("io_psi_some_avg10", 20.0, 10 * NS)
    core = core.observe("io_psi_some_avg10", 30.0, 20 * NS)

    metric = core.metric("io_psi_some_avg10")
    telemetry = core.telemetry(20 * NS)[0]
    assert metric.coverage_seconds == 15.0
    assert telemetry["coverage"] == {"seconds": 15.0, "target_seconds": 15.0}


def test_memory_and_vram_use_only_current_raw_evidence_and_hysteresis() -> None:
    core = _core("memory_available_mib", "vram_used_percent")
    core = core.observe("memory_available_mib", 7168.0, 0)
    core = core.observe("vram_used_percent", 90.0, 0)

    for role in ("memory_available_mib", "vram_used_percent"):
        metric = core.metric(role)
        assert metric.ema is None
        assert metric.tau_seconds is None

    assert core.decision(0).normal_blocked_roles == (
        "memory_available_mib",
        "vram_used_percent",
    )

    core = core.observe("memory_available_mib", 7500.0, NS)
    core = core.observe("vram_used_percent", 87.0, NS)
    assert len(core.decision(NS).normal_blocked_roles) == 2

    core = core.observe("memory_available_mib", 8192.0, 2 * NS)
    core = core.observe("vram_used_percent", 85.0, 2 * NS)
    assert core.decision(2 * NS).normal_blocked_roles == ()


def test_raw_memory_and_vram_become_stale_after_thirty_seconds() -> None:
    core = _core("memory_available_mib", "vram_used_percent")
    core = core.observe("memory_available_mib", 9000.0, 0)
    core = core.observe("vram_used_percent", 10.0, 0)

    assert core.decision(30 * NS).interlocks == ()
    assert core.decision(30 * NS + 1).interlocks == (
        ("memory_available_mib", "stale_evidence"),
        ("vram_used_percent", "stale_evidence"),
    )


def test_thermal_crit_oom_and_device_loss_are_separate_immediate_interlocks() -> None:
    thermal = thermal_policy("thermal_cpu_package", high=80.0, crit=100.0)
    core = ResourceEMAAdmissionV1.cold(
        (
            thermal,
            canonical_policy("memory_available_mib"),
            canonical_policy("gpu_utilization"),
        )
    )
    core = core.observe(thermal.role, 70.0, 0)
    core = core.observe("memory_available_mib", 10000.0, 0)
    core = core.observe("gpu_utilization", 10.0, 0)

    core = core.observe(thermal.role, 100.0, NS)
    core = core.observe("memory_available_mib", 10000.0, NS, interlock="oom_event")
    core = core.signal_interlock("gpu_utilization", "gpu_device_lost")
    decision = core.decision(NS)

    assert decision.normal_blocked_roles == ()
    assert decision.interlocks == (
        ("gpu_utilization", "gpu_device_lost"),
        ("memory_available_mib", "oom_event"),
        ("thermal_cpu_package", "thermal_critical"),
    )

    telemetry = {item["role"]: item for item in core.telemetry(NS)}
    assert telemetry[thermal.role]["hysteresis"] == {"state": "clear"}
    assert telemetry[thermal.role]["interlock"] == {
        "active": True,
        "reason": "thermal_critical",
    }


def test_no_gpu_lane_is_allowed_but_configured_gpu_evidence_is_required() -> None:
    no_gpu = _core("cpu_busy").observe("cpu_busy", 10.0, 0)
    assert no_gpu.decision(0).blocked is False
    assert all(not item["role"].startswith("gpu_") for item in no_gpu.telemetry(0))

    configured_gpu = _core("gpu_utilization", "vram_used_percent")
    assert configured_gpu.decision(0).interlocks == (
        ("gpu_utilization", "missing_evidence"),
        ("vram_used_percent", "missing_evidence"),
    )


def test_iops_without_capacity_is_ema_telemetry_only() -> None:
    core = _core("io_iops_rate", "io_iops_capacity_percent", "io_queue_percent")
    core = core.observe("io_iops_rate", 1_000_000.0, 0)
    core = core.observe("io_iops_capacity_percent", 90.0, 0)
    core = core.observe("io_queue_percent", 90.0, 0)

    rate = core.metric("io_iops_rate")
    assert rate.tau_seconds == 15.0
    assert rate.ema == 1_000_000.0
    assert rate.enter_threshold is None
    assert rate.latched is False
    assert core.decision(0).normal_blocked_roles == (
        "io_iops_capacity_percent",
        "io_queue_percent",
    )


def test_iops_rate_cold_stale_and_gap_states_are_visible_but_never_block() -> None:
    cold = _core("io_iops_rate")
    assert cold.telemetry(0)[0]["interlock"] == {
        "active": True,
        "reason": "missing_evidence",
    }
    assert cold.decision(0).blocked is False
    assert cold.decision(0).interlocks == ()

    observed = cold.observe("io_iops_rate", 1000.0, 0)
    stale_at = 30 * NS + 1
    assert observed.telemetry(stale_at)[0]["interlock"] == {
        "active": True,
        "reason": "stale_evidence",
    }
    assert observed.decision(stale_at).blocked is False
    assert observed.decision(stale_at).interlocks == ()

    gapped = observed.observe("io_iops_rate", 2000.0, 31 * NS)
    assert gapped.telemetry(31 * NS)[0]["interlock"] == {
        "active": True,
        "reason": "gap_exceeded",
    }
    assert gapped.decision(31 * NS).blocked is False
    assert gapped.decision(31 * NS).interlocks == ()


def test_iops_rate_required_device_loss_remains_an_immediate_block() -> None:
    core = _core("io_iops_rate").signal_interlock(
        "io_iops_rate", "required_device_lost"
    )

    assert core.telemetry(0)[0]["interlock"] == {
        "active": True,
        "reason": "required_device_lost",
    }
    assert core.decision(0).blocked is True
    assert core.decision(0).interlocks == (
        ("io_iops_rate", "required_device_lost"),
    )


def test_thermal_thresholds_follow_advertised_high_and_crit_contract() -> None:
    advertised = thermal_policy("thermal_cpu_package", high=80.0, crit=100.0)
    capped = thermal_policy("thermal_cpu_package", high=105.0, crit=100.0)
    crit_only = thermal_policy("thermal_cpu_package", crit=100.0)

    assert (advertised.enter_threshold, advertised.release_threshold) == (80.0, 75.0)
    assert (capped.enter_threshold, capped.release_threshold) == (95.0, 90.0)
    assert (crit_only.enter_threshold, crit_only.release_threshold) == (90.0, 80.0)

    with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
        thermal_policy("thermal_cpu_package")


def test_io_group_blocks_when_any_member_is_latched() -> None:
    roles = ("io_psi_some_avg10", "io_psi_full_avg10", "io_psi_full_avg60")
    core = _core(*roles)
    for role in roles:
        core = core.observe(role, 0.0, 0)

    core = core.observe("io_psi_full_avg10", 100.0, 30 * NS)
    assert core.decision(30 * NS).normal_blocked_roles == ("io_psi_full_avg10",)

    core = core.observe("io_psi_full_avg10", 0.0, 60 * NS)
    assert core.decision(60 * NS).normal_blocked_roles == ()
    assert {core.metric(role).tau_seconds for role in roles} == {15.0}


def test_snapshot_roundtrip_is_strict_bounded_and_deterministic() -> None:
    thermal = thermal_policy("thermal_cpu_package", high=80.0, crit=100.0)
    core = ResourceEMAAdmissionV1.cold(
        (canonical_policy("vram_used_percent"), thermal, canonical_policy("cpu_busy"))
    )
    core = core.observe("cpu_busy", 20.0, NS)
    core = core.observe(thermal.role, 70.0, NS)
    core = core.observe("vram_used_percent", 10.0, NS)

    encoded = core.to_json()
    decoded = ResourceEMAAdmissionV1.from_json(encoded)

    assert decoded == core
    assert decoded.to_json() == encoded
    assert [item["role"] for item in decoded.telemetry(NS)] == [
        "cpu_busy",
        "thermal_cpu_package",
        "vram_used_percent",
    ]
    assert set(decoded.telemetry(NS)[0]) == {
        "age_seconds",
        "coverage",
        "ema",
        "hysteresis",
        "interlock",
        "raw",
        "role",
        "tau_seconds",
        "threshold",
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document.update({"unknown": True}),
        lambda document: document.update({"schema": "ResourceSnapshotV1"}),
        lambda document: document.update({"schema_version": 0}),
        lambda document: document["metrics"][0].update({"provider_path": "/secret"}),
        lambda document: document["metrics"][0]["interlock"].update({"reason": "unknown"}),
    ],
)
def test_snapshot_rejects_unknown_fields_states_and_v1(mutate: object) -> None:
    document = json.loads(_core("cpu_busy").to_json())
    mutate(document)

    with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
        ResourceEMAAdmissionV1.from_json(json.dumps(document).encode())


def test_snapshot_rejects_duplicate_keys_nonfinite_values_and_oversize() -> None:
    duplicate = b'{"schema":"ResourceEMAAdmissionV1","schema":"ResourceEMAAdmissionV1"}'
    nonfinite = _core("cpu_busy").to_json().replace(b'"raw":null', b'"raw":NaN')

    for payload in (duplicate, nonfinite, b" " * (MAX_SNAPSHOT_BYTES + 1)):
        with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
            ResourceEMAAdmissionV1.from_json(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("family", []),
        ("direction", {}),
        ("role", ["cpu_busy"]),
        ("admission_enabled", 1),
        ("latched", 0),
    ],
)
def test_snapshot_rejects_wrong_scalar_types_with_contract_error(
    field: str, value: object
) -> None:
    document = json.loads(_core("cpu_busy").to_json())
    document["metrics"][0][field] = value

    with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
        ResourceEMAAdmissionV1.from_json(json.dumps(document).encode())


def test_snapshot_rejects_impossible_metric_state_combinations() -> None:
    ema_without_raw = json.loads(_core("cpu_busy").to_json())
    ema_without_raw["metrics"][0].update(
        {
            "coverage_seconds": 0.0,
            "ema": 20.0,
            "last_observed_monotonic_ns": 0,
        }
    )
    latch_without_evidence = json.loads(_core("cpu_busy").to_json())
    latch_without_evidence["metrics"][0]["latched"] = True

    for document in (ema_without_raw, latch_without_evidence):
        with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
            ResourceEMAAdmissionV1.from_json(json.dumps(document).encode())


def test_snapshot_rejects_zero_coverage_when_raw_and_ema_differ() -> None:
    document = json.loads(_core("cpu_busy").observe("cpu_busy", 20.0, 0).to_json())
    document["metrics"][0]["ema"] = 21.0

    with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
        ResourceEMAAdmissionV1.from_json(json.dumps(document).encode())


def test_snapshot_rejects_zero_coverage_latch_not_derivable_from_cold() -> None:
    document = json.loads(_core("cpu_busy").observe("cpu_busy", 87.0, 0).to_json())
    document["metrics"][0]["latched"] = True

    with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
        ResourceEMAAdmissionV1.from_json(json.dumps(document).encode())


def test_snapshot_rejects_latch_states_incompatible_with_thresholds() -> None:
    cpu_enter_clear = json.loads(
        _core("cpu_busy").observe("cpu_busy", 90.0, 0).to_json()
    )
    cpu_enter_clear["metrics"][0]["latched"] = False

    cpu_release_blocked = json.loads(
        _core("cpu_busy").observe("cpu_busy", 85.0, 0).to_json()
    )
    cpu_release_blocked["metrics"][0]["latched"] = True

    memory_enter_clear = json.loads(
        _core("memory_available_mib").observe("memory_available_mib", 7168.0, 0).to_json()
    )
    memory_enter_clear["metrics"][0]["latched"] = False

    memory_release_blocked = json.loads(
        _core("memory_available_mib").observe("memory_available_mib", 8192.0, 0).to_json()
    )
    memory_release_blocked["metrics"][0]["latched"] = True

    for document in (
        cpu_enter_clear,
        cpu_release_blocked,
        memory_enter_clear,
        memory_release_blocked,
    ):
        with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
            ResourceEMAAdmissionV1.from_json(json.dumps(document).encode())


def test_huge_numbers_and_timestamps_are_normalized_to_contract_failures() -> None:
    huge = 1 << 4096

    malformed = _core("cpu_busy").observe("cpu_busy", huge, 0)
    assert malformed.decision(0).interlocks == (("cpu_busy", "invalid_evidence"),)

    with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
        thermal_policy("thermal_cpu_package", high=huge)

    observed = _core("cpu_busy").observe("cpu_busy", 20.0, 0)
    with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
        observed.decision(huge)

    raw_document = json.loads(observed.to_json())
    raw_document["metrics"][0]["raw"] = huge
    with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
        ResourceEMAAdmissionV1.from_json(json.dumps(raw_document).encode())

    timestamp_document = json.loads(observed.to_json())
    timestamp_document["metrics"][0]["last_observed_monotonic_ns"] = huge
    with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
        ResourceEMAAdmissionV1.from_json(json.dumps(timestamp_document).encode())

    digit_overflow = _core("cpu_busy").to_json().replace(
        b'"raw":null', b'"raw":' + (b"9" * 5000)
    )
    with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
        ResourceEMAAdmissionV1.from_json(digit_overflow)


def test_large_finite_ema_inputs_do_not_overflow_intermediate_math() -> None:
    core = _core("cpu_busy").observe("cpu_busy", 1e308, 0)
    core = core.observe("cpu_busy", -1e308, NS)

    assert math.isfinite(core.metric("cpu_busy").ema)


def test_public_metric_time_methods_reject_invalid_now_before_early_returns() -> None:
    cold = _core("cpu_busy").metric("cpu_busy")
    observed = _core("cpu_busy").observe("cpu_busy", 20.0, 0).metric("cpu_busy")

    for metric in (cold, observed):
        for now_ns in (1 << 4096, -1, 1.0, True):
            with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
                metric.effective_interlock(now_ns)
            with pytest.raises(ResourceEMAError, match="^resource_ema_invalid$"):
                metric.age_seconds(now_ns)
