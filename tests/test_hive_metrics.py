from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from itertools import count

import pytest

from codex_master.fleet_overview import (
    FleetOverviewAgentRow,
    FleetOverviewSeriesRow,
    FleetOverviewSnapshot,
)
from codex_master.hive_metrics import (
    FleetMetricBlockDevice,
    FleetMetricIoPsi,
    FleetMetricObservation,
    FleetMetricSnapshot,
    HiveMetricsError,
    fleet_metric_values,
    pcp_htop_meter_config,
    project_hive_metrics,
    render_openmetrics,
)


CAPTURED = datetime(2026, 8, 22, 16, 0, tzinfo=timezone.utc)
MAX_OBSERVATIONS = 4096
_OBSERVATION_SEQUENCE = count()


def opaque_key(index: int | None = None) -> str:
    value = next(_OBSERVATION_SEQUENCE) if index is None else index
    return f"sha256:{value:064x}"


def observation(
    provider: str,
    role: str,
    *,
    active: bool = True,
    valid: bool = True,
    detail: bool = True,
    special_class: str = "analyst",
    model_tier: str = "M2",
    reasoning_tier: str = "R3",
    lifecycle: str = "persistent",
    observation_key: str | None = None,
) -> FleetMetricObservation:
    values: dict[str, object] = {
        "active": active,
        "valid": valid,
        "provider": provider,
        "role": role,
        "special_class": special_class if detail else None,
        "model_tier": model_tier if detail else None,
        "reasoning_tier": reasoning_tier if detail else None,
        "lifecycle": lifecycle if detail else None,
    }
    if observation_key is not None:
        values["observation_key"] = observation_key
    try:
        return FleetMetricObservation(**values)  # type: ignore[arg-type]
    except TypeError as error:
        if observation_key is None:
            raise
        pytest.fail(f"opaque observation key is not accepted: {error}")


def overview(*, generation: int = 4, homes: int = 0) -> FleetOverviewSnapshot:
    return FleetOverviewSnapshot(
        generation=generation,
        created_at=CAPTURED,
        integration_freshness="fresh",
        series=(
            FleetOverviewSeriesRow(
                "x", "Example", "openai_api", "codex", "model", 0, homes, (),
            ),
        ) if homes else (),
        agents=(),
        account_limits=(),
        warnings=(),
    )


def test_detail_tiers_validate_each_axis_including_zero_and_future_levels() -> None:
    def state_for(model_tier: str, reasoning_tier: str) -> str:
        return project_hive_metrics(
            observations=(
                observation("gemini", "worker", model_tier=model_tier, reasoning_tier=reasoning_tier),
            ),
            registered_homes=1,
            captured_at=CAPTURED,
            observed_at=CAPTURED,
        ).state

    assert state_for("M0", "R0") == "fresh"
    assert state_for("R3", "M3") == "invalid"
    assert state_for("M10", "R3") == "invalid"
    assert state_for("M9", "R9") == "fresh"


@pytest.mark.parametrize("unsafe_class", ("sk-live-secret", "account-123"))
def test_detail_projects_unrecognized_special_class_to_unknown(unsafe_class: str) -> None:
    projection = project_hive_metrics(
        observations=(observation("gemini", "worker", special_class=unsafe_class),),
        registered_homes=1,
        captured_at=CAPTURED,
        observed_at=CAPTURED,
    )

    assert projection.state == "fresh"
    assert projection.details[0].special_class == "unknown"
    assert unsafe_class not in repr(projection)


def test_projection_deduplicates_opaque_observation_keys_without_exposing_them() -> None:
    first_key = opaque_key(1)
    second_key = opaque_key(2)
    original = observation("gemini", "worker", observation_key=first_key)
    repeated_event = observation("gemini", "worker", observation_key=first_key)
    projection = project_hive_metrics(
        observations=(
            original,
            repeated_event,
            observation("gemini", "worker", model_tier="M3", observation_key=second_key),
        ),
        registered_homes=2,
        captured_at=CAPTURED,
        observed_at=CAPTURED,
    )

    assert projection.active_bees == 2
    assert len(projection.details) == 2
    assert first_key not in repr(original)
    assert first_key not in repr(projection)


def test_projection_rejects_nonopaque_observation_keys() -> None:
    projection = project_hive_metrics(
        observations=(
            observation("gemini", "worker", observation_key="account-123"),
        ),
        registered_homes=1,
        captured_at=CAPTURED,
        observed_at=CAPTURED,
    )

    assert projection.state == "invalid"
    assert "account-123" not in repr(projection)


def test_overview_adapter_requires_common_native_generation_binding() -> None:
    snapshot = overview(generation=7)

    with pytest.raises(HiveMetricsError, match="invalid_metric_input"):
        fleet_metric_values(snapshot, native_active=1, observed_at=CAPTURED)

    values = fleet_metric_values(
        snapshot,
        native_active=1,
        native_generation=7,
        observed_at=CAPTURED,
    )

    assert values["codex_master_bees_total"] == 1
    with pytest.raises(HiveMetricsError, match="invalid_metric_input"):
        fleet_metric_values(
            snapshot,
            native_active=1,
            native_generation=8,
            observed_at=CAPTURED,
        )


def test_projection_consumes_no_more_than_bounded_input_prefix() -> None:
    class EndlessObservations:
        def __init__(self) -> None:
            self.consumed = 0

        def __iter__(self):
            while True:
                self.consumed += 1
                if self.consumed > MAX_OBSERVATIONS + 1:
                    pytest.fail("projection consumed beyond its bounded input prefix")
                yield observation("gemini", "worker", detail=False)

    source = EndlessObservations()
    with pytest.raises(HiveMetricsError, match="invalid_metric_input"):
        project_hive_metrics(
            observations=source,
            registered_homes=0,
            captured_at=CAPTURED,
            observed_at=CAPTURED,
        )
    assert source.consumed == MAX_OBSERVATIONS + 1


@pytest.mark.parametrize("count", (MAX_OBSERVATIONS - 1, MAX_OBSERVATIONS))
def test_projection_accepts_observation_input_at_telemetry_bound(count: int) -> None:
    projection = project_hive_metrics(
        observations=tuple(observation("gemini", "worker", detail=False) for _ in range(count)),
        registered_homes=0,
        captured_at=CAPTURED,
        observed_at=CAPTURED,
    )

    assert projection.active_bees == count


def test_projection_rejects_observation_input_above_telemetry_bound() -> None:
    with pytest.raises(HiveMetricsError, match="invalid_metric_input"):
        project_hive_metrics(
            observations=tuple(
                observation("gemini", "worker", detail=False)
                for _ in range(MAX_OBSERVATIONS + 1)
            ),
            registered_homes=0,
            captured_at=CAPTURED,
            observed_at=CAPTURED,
        )


@pytest.mark.parametrize("registered_homes", (MAX_OBSERVATIONS - 1, MAX_OBSERVATIONS))
def test_projection_accepts_inventory_at_telemetry_input_bound(registered_homes: int) -> None:
    projection = project_hive_metrics(
        observations=(),
        registered_homes=registered_homes,
        captured_at=CAPTURED,
        observed_at=CAPTURED,
    )

    assert projection.registered_homes == registered_homes


def test_projection_rejects_inventory_above_telemetry_input_bound() -> None:
    with pytest.raises(HiveMetricsError, match="invalid_metric_input"):
        project_hive_metrics(
            observations=(),
            registered_homes=MAX_OBSERVATIONS + 1,
            captured_at=CAPTURED,
            observed_at=CAPTURED,
        )


@pytest.mark.parametrize("native_active", (MAX_OBSERVATIONS - 1, MAX_OBSERVATIONS))
def test_overview_adapter_accepts_native_input_at_telemetry_bound(native_active: int) -> None:
    snapshot = overview(generation=9)

    values = fleet_metric_values(
        snapshot,
        native_active=native_active,
        native_generation=9,
        observed_at=CAPTURED,
    )

    assert values["codex_master_bees_total"] == native_active


def test_overview_adapter_rejects_native_input_above_telemetry_bound() -> None:
    with pytest.raises(HiveMetricsError, match="invalid_metric_input"):
        fleet_metric_values(
            overview(generation=9),
            native_active=MAX_OBSERVATIONS + 1,
            native_generation=9,
            observed_at=CAPTURED,
        )


def test_openmetrics_uses_label_free_openmetrics_eof_contract() -> None:
    rendered = render_openmetrics({"codex_master_bees_total": 4})

    assert rendered == "codex_master_bees_total 4\n# EOF\n"
    assert re.fullmatch(r"codex_master_bees_total 4\n# EOF\n", rendered)
    with pytest.raises(HiveMetricsError, match="invalid_metric_values"):
        render_openmetrics({'codex_master_bees{provider="gemini"}': 1})


def test_projection_separates_active_inventory_and_visible_unknowns() -> None:
    projection = project_hive_metrics(
        observations=(
            observation("native", "goddess"),
            observation("openai_api", "queen"),
            observation("gemini_api", "teamleiterin"),
            observation("anthropic", "arbeitsbiene"),
            observation("huggingface_inference", "rogue"),
            observation("ollama_local", "worker"),
            observation("deepseek", "queen"),
            observation("unlisted-provider", "unlisted-role"),
        ),
        registered_homes=13,
        captured_at=CAPTURED,
        observed_at=CAPTURED,
    )

    assert projection.state == "fresh"
    assert projection.registered_homes == 13
    assert projection.active_bees == 8
    assert dict(projection.provider_counts) == {
        "native": 1,
        "codex": 1,
        "gemini": 1,
        "claude": 1,
        "hf": 1,
        "ollama": 1,
        "deepseek": 1,
        "unknown": 1,
    }
    assert dict(projection.role_counts) == {
        "godbee": 1,
        "queen": 2,
        "team_lead": 1,
        "worker": 2,
        "rogue": 1,
        "unknown": 1,
    }
    assert projection.details[0].special_class == "unknown"
    assert projection.details[0].model_tier == "M2"
    assert projection.details[0].reasoning_tier == "R3"
    assert projection.details[0].lifecycle == "persistent"
    assert "agent_id" not in projection.details[0].__dataclass_fields__
    assert "account_id" not in projection.details[0].__dataclass_fields__


def test_invalid_observation_returns_invalid_state_without_zero_counts() -> None:
    projection = project_hive_metrics(
        observations=(
            observation("gemini", "worker"),
            observation("codex", "worker", valid=False),
        ),
        registered_homes=2,
        captured_at=CAPTURED,
        observed_at=CAPTURED,
    )

    assert projection.state == "invalid"
    assert projection.active_bees is None
    assert projection.provider_counts is None
    assert projection.role_counts is None
    assert projection.details == ()


def test_stale_boundary_preserves_last_valid_counts() -> None:
    kwargs = {
        "observations": (observation("gemini", "worker", detail=False),),
        "registered_homes": 4,
        "captured_at": CAPTURED,
        "stale_after_seconds": 60,
    }

    fresh = project_hive_metrics(observed_at=CAPTURED + timedelta(seconds=60), **kwargs)
    stale = project_hive_metrics(observed_at=CAPTURED + timedelta(seconds=61), **kwargs)

    assert fresh.state == "fresh"
    assert stale.state == "stale"
    assert stale.active_bees == 1
    assert dict(stale.provider_counts or ())["gemini"] == 1
    assert stale.age_seconds == 61.0


def test_projection_bounds_detail_output_without_changing_counts() -> None:
    projection = project_hive_metrics(
        observations=tuple(observation("gemini", "worker") for _ in range(129)),
        registered_homes=129,
        captured_at=CAPTURED,
        observed_at=CAPTURED,
    )

    assert projection.active_bees == 129
    assert len(projection.details) == 128
    assert projection.details_truncated is True


def test_legacy_overview_adapter_uses_one_active_counting_semantics() -> None:
    overview = FleetOverviewSnapshot(
        generation=4,
        created_at=CAPTURED,
        integration_freshness="fresh",
        series=(
            FleetOverviewSeriesRow(
                "x", "Example", "openai_api", "codex", "model", 2, 5, ("x1", "x2"),
            ),
        ),
        agents=(
            FleetOverviewAgentRow(
                "x1", "Example", "openai_api", "codex", "model", None, None,
                "running", "teamleiterin", None, None, None, None, None, None, "fresh",
            ),
            FleetOverviewAgentRow(
                "x2", "Example", "unlisted-provider", "codex", "model", None, None,
                "running", "unlisted-role", None, None, None, None, None, None, "fresh",
            ),
            FleetOverviewAgentRow(
                "x3", "Example", "gemini_api", "gemini", "model", None, None,
                "stopped", "worker", None, None, None, None, None, None, "fresh",
            ),
        ),
        account_limits=(),
        warnings=(),
    )

    values = fleet_metric_values(
        overview,
        native_active=2,
        native_generation=4,
        observed_at=CAPTURED,
    )

    assert values["codex_master_bees_total"] == 4
    assert values["codex_master_homes_registered"] == 5
    assert values["codex_master_bees_codex"] == 1
    assert values["codex_master_bees_native"] == 2
    assert values["codex_master_bees_unknown"] == 1
    assert values["codex_master_roles_team_lead"] == 1
    assert values["codex_master_roles_unknown"] == 3


def test_openmetrics_renderer_is_deterministic_and_rejects_nonfinite_values() -> None:
    rendered = render_openmetrics(
        {
            "codex_master_bees_total": 4,
            "codex_master_hive_metrics_age_seconds": 0.5,
        }
    )

    assert rendered == (
        "codex_master_bees_total 4\n"
        "codex_master_hive_metrics_age_seconds 0.5\n"
        "# EOF\n"
    )
    with pytest.raises(HiveMetricsError, match="invalid_metric_values"):
        render_openmetrics({"codex_master_bees_total": float("nan")})


def test_projection_consumes_one_typed_snapshot_without_runtime_or_callback_inputs() -> None:
    snapshot = FleetMetricSnapshot(
        observations=(
            observation("native", "gottbiene", detail=False),
            observation("ollama_local", "arbeitsbiene", detail=False),
        ),
        registered_homes=7,
        captured_at=CAPTURED,
        block_devices=(
            FleetMetricBlockDevice(
                "nvme0n1", 12.5, 3.25, 2, 14.0, 0.125, "nvme", True,
            ),
        ),
        hive_io_psi=FleetMetricIoPsi(4.0, 2.0, 1.0),
        health_state="WARN",
    )

    projection = project_hive_metrics(snapshot=snapshot, observed_at=CAPTURED)

    assert projection.registered_homes == 7
    assert projection.active_bees == 2
    assert projection.health_state == "WARN"
    assert projection.block_devices == snapshot.block_devices
    assert projection.hive_io_psi == snapshot.hive_io_psi


def test_metric_values_accepts_typed_snapshot_without_separate_native_count() -> None:
    snapshot = FleetMetricSnapshot(
        observations=(observation("native", "unknown", detail=False),),
        registered_homes=3,
        captured_at=CAPTURED,
    )

    values = fleet_metric_values(snapshot, observed_at=CAPTURED)

    assert values["codex_master_bees_total"] == 1
    assert values["codex_master_homes_registered"] == 3
    assert values["codex_master_bees_native"] == 1


def test_snapshot_projection_preserves_all_provider_and_role_buckets() -> None:
    projection = project_hive_metrics(
        snapshot=FleetMetricSnapshot(
            observations=tuple(
                observation(provider, role, detail=False)
                for provider, role in (
                    ("native", "gottbiene"),
                    ("codex_cli", "koenigin"),
                    ("gemini_api", "tl"),
                    ("anthropic", "arbeitsbiene"),
                    ("huggingface_inference", "rogue"),
                    ("ollama_local", "worker"),
                    ("deepseek", "queen"),
                    ("provider-from-next-runtime", "role-from-next-runtime"),
                )
            ),
            registered_homes=8,
            captured_at=CAPTURED,
        ),
        observed_at=CAPTURED,
    )

    assert dict(projection.provider_counts or ()) == {
        "native": 1,
        "codex": 1,
        "gemini": 1,
        "claude": 1,
        "hf": 1,
        "ollama": 1,
        "deepseek": 1,
        "unknown": 1,
    }
    assert dict(projection.role_counts or ()) == {
        "godbee": 1,
        "queen": 2,
        "team_lead": 1,
        "worker": 2,
        "rogue": 1,
        "unknown": 1,
    }


@pytest.mark.parametrize("state", ("OK", "WARN", "BLOCK", "CONTAMINATED", "STALE", "RUCKEL-HOLD"))
def test_snapshot_projection_exposes_each_plan_state(state: str) -> None:
    projection = project_hive_metrics(
        snapshot=FleetMetricSnapshot(
            observations=(observation("gemini", "worker", detail=False),),
            registered_homes=1,
            captured_at=CAPTURED,
            health_state=state,
        ),
        observed_at=CAPTURED,
    )

    assert projection.health_state == state


def test_snapshot_projection_explicitly_marks_age_expiry_stale() -> None:
    projection = project_hive_metrics(
        snapshot=FleetMetricSnapshot(
            observations=(observation("gemini", "worker", detail=False),),
            registered_homes=1,
            captured_at=CAPTURED,
            health_state="OK",
        ),
        observed_at=CAPTURED + timedelta(seconds=61),
    )

    assert projection.health_state == "STALE"
    assert projection.active_bees == 1


def test_snapshot_projection_keeps_all_lifecycle_values_exactly() -> None:
    for lifecycle in ("ephemeral", "invocation", "binding", "persistent"):
        projection = project_hive_metrics(
            snapshot=FleetMetricSnapshot(
                observations=(observation("gemini", "worker", lifecycle=lifecycle),),
                registered_homes=1,
                captured_at=CAPTURED,
            ),
            observed_at=CAPTURED,
        )

        assert projection.details[0].lifecycle == lifecycle


def test_pcp_htop_meter_config_has_exactly_two_complete_canonical_blocks() -> None:
    blocks = pcp_htop_meter_config()

    assert blocks == (
        "[textmeter provider_runtime]\n"
        "metrics = codex_master_bees_native,codex_master_bees_codex,"
        "codex_master_bees_gemini,codex_master_bees_claude,"
        "codex_master_bees_hf,codex_master_bees_ollama,"
        "codex_master_bees_deepseek,codex_master_bees_unknown\n"
        "labels = Native,Codex/OpenAI,Gemini,Claude,HF,Ollama,DeepSeek,unknown\n",
        "[textmeter hierarchy]\n"
        "metrics = codex_master_roles_godbee,codex_master_roles_queen,"
        "codex_master_roles_team_lead,codex_master_roles_worker,"
        "codex_master_roles_rogue,codex_master_roles_unknown\n"
        "labels = Gottbiene,Königin,TL,Arbeiterin,Rogue,unknown\n",
    )
    assert "OpenAI/Codex" not in "\n".join(blocks)


@pytest.mark.parametrize(
    ("device", "transport"),
    (("dm-0", "nvme"), ("vda", "scsi"), ("xvda", "scsi"), ("nvme0n1", "virtio")),
)
def test_snapshot_projection_rejects_virtual_or_nonphysical_devices(
    device: str, transport: str,
) -> None:
    projection = project_hive_metrics(
        snapshot=FleetMetricSnapshot(
            observations=(),
            registered_homes=0,
            captured_at=CAPTURED,
            block_devices=(FleetMetricBlockDevice(device, 1.0, 1.0, 1, 1.0, 1.0, transport, True),),
        ),
        observed_at=CAPTURED,
    )

    assert projection.state == "invalid"
    assert projection.health_state == "CONTAMINATED"
    assert projection.block_devices == ()


@pytest.mark.parametrize(
    ("device", "transport"),
    (("/dev/nvme0n1", "nvme"), ("nvme0n1", "unknown"), ("unknown", "nvme")),
)
def test_snapshot_projection_fails_closed_without_physicality_evidence(
    device: str, transport: str,
) -> None:
    projection = project_hive_metrics(
        snapshot=FleetMetricSnapshot(
            observations=(),
            registered_homes=0,
            captured_at=CAPTURED,
            block_devices=(FleetMetricBlockDevice(device, 1.0, 1.0, 1, 1.0, 1.0, transport, True),),
        ),
        observed_at=CAPTURED,
    )

    assert projection.state == "invalid"
    assert projection.health_state == "CONTAMINATED"
    assert projection.block_devices == ()
    assert device not in repr(projection)


def test_snapshot_projection_keeps_validated_physical_devices_bounded_scalar_and_path_free() -> None:
    projection = project_hive_metrics(
        snapshot=FleetMetricSnapshot(
            observations=(),
            registered_homes=0,
            captured_at=CAPTURED,
            block_devices=(FleetMetricBlockDevice("nvme0n1", 1.0, 2.0, 3, 4.0, 5.0, "nvme", True),),
        ),
        observed_at=CAPTURED,
    )

    assert projection.state == "fresh"
    assert len(projection.block_devices) == 1
    assert projection.block_devices[0] == FleetMetricBlockDevice(
        "nvme0n1", 1.0, 2.0, 3, 4.0, 5.0, "nvme", True,
    )
    assert "/" not in projection.block_devices[0].device


def test_explicit_stale_snapshot_sets_freshness_and_stale_metric_consistently() -> None:
    snapshot = FleetMetricSnapshot(
        observations=(observation("gemini", "worker", detail=False),),
        registered_homes=1,
        captured_at=CAPTURED,
        health_state="STALE",
    )

    projection = project_hive_metrics(snapshot=snapshot, observed_at=CAPTURED)
    values = fleet_metric_values(snapshot, observed_at=CAPTURED)

    assert projection.state == "stale"
    assert projection.health_state == "STALE"
    assert values["codex_master_hive_metrics_stale"] == 1


def test_age_stale_snapshot_sets_freshness_health_and_stale_metric_consistently() -> None:
    snapshot = FleetMetricSnapshot(
        observations=(observation("gemini", "worker", detail=False),),
        registered_homes=1,
        captured_at=CAPTURED,
        health_state="OK",
    )

    projection = project_hive_metrics(
        snapshot=snapshot,
        observed_at=CAPTURED + timedelta(seconds=61),
    )
    values = fleet_metric_values(snapshot, observed_at=CAPTURED + timedelta(seconds=61))

    assert projection.state == "stale"
    assert projection.health_state == "STALE"
    assert values["codex_master_hive_metrics_stale"] == 1


def test_snapshot_projection_bounds_and_redacts_untrusted_detail_values() -> None:
    projection = project_hive_metrics(
        snapshot=FleetMetricSnapshot(
            observations=(
                observation("gemini", "worker", special_class="credential=secret"),
            ),
            registered_homes=1,
            captured_at=CAPTURED,
            block_devices=(
                FleetMetricBlockDevice(
                    "nvme0n1", 1.0, 1.0, 1, 1.0, 1.0, "nvme", True,
                ),
            ),
        ),
        observed_at=CAPTURED,
    )

    assert projection.details[0].special_class == "unknown"
    assert projection.block_devices[0].device == "nvme0n1"
    assert projection.block_devices[0].transport == "nvme"
    assert "credential=secret" not in repr(projection)
    assert "private-secret" not in repr(projection)


class _NeverEnterIterable:
    def __init__(self) -> None:
        self.iterated = False
        self.len_called = False

    def __iter__(self):
        self.iterated = True
        raise AssertionError("foreign iterable was entered")

    def __len__(self):
        self.len_called = True
        raise AssertionError("foreign iterable length was read")


def test_snapshot_rejects_foreign_observations_without_entering_iterable() -> None:
    observations = _NeverEnterIterable()

    with pytest.raises(HiveMetricsError, match="invalid_metric_input"):
        FleetMetricSnapshot(observations, 0, CAPTURED)

    assert observations.iterated is False
    assert observations.len_called is False


def test_snapshot_rejects_foreign_devices_without_entering_iterable() -> None:
    block_devices = _NeverEnterIterable()

    with pytest.raises(HiveMetricsError, match="invalid_metric_input"):
        FleetMetricSnapshot((), 0, CAPTURED, block_devices)

    assert block_devices.iterated is False
    assert block_devices.len_called is False


def test_snapshot_accepts_exact_tuple_inputs_without_coercion() -> None:
    observations = (observation("gemini", "worker", detail=False),)
    block_devices = (FleetMetricBlockDevice("nvme0n1", 1.0, 1.0, 1, 1.0, 1.0, "nvme", True),)

    snapshot = FleetMetricSnapshot(observations, 1, CAPTURED, block_devices)

    assert snapshot.observations is observations
    assert snapshot.block_devices is block_devices


def test_snapshot_tuple_observations_above_bound_remain_fail_closed() -> None:
    snapshot = FleetMetricSnapshot(
        tuple(observation("gemini", "worker", detail=False) for _ in range(MAX_OBSERVATIONS + 1)),
        MAX_OBSERVATIONS,
        CAPTURED,
    )

    with pytest.raises(HiveMetricsError, match="invalid_metric_input"):
        project_hive_metrics(snapshot=snapshot, observed_at=CAPTURED)


def test_snapshot_tuple_devices_above_bound_remain_fail_closed() -> None:
    device = FleetMetricBlockDevice("nvme0n1", 1.0, 1.0, 1, 1.0, 1.0, "nvme", True)
    snapshot = FleetMetricSnapshot((), 0, CAPTURED, (device,) * 65)

    projection = project_hive_metrics(snapshot=snapshot, observed_at=CAPTURED)

    assert projection.state == "invalid"
    assert projection.health_state == "CONTAMINATED"
