from __future__ import annotations

import json
import math
import os
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

import pytest

from codex_master.hive import state as hive_state_module
from codex_master.hive.state import HiveStateStore
from codex_master.resource_monitor import (
    ResourceSnapshotError,
    ResourceSnapshotV1,
    ResourceGateFacts,
    ResourceOperatorStatus,
    ResourceSchedulerSnapshot,
    ThermalPolicyV1,
    TrendAssessmentV1,
    build_resource_gate_facts,
    build_resource_operator_status,
    build_resource_scheduler_snapshot,
    classify_trend,
    parse_snapshot_document,
    read_resource_snapshot,
    read_thermal_policy,
    write_resource_snapshot,
    write_thermal_policy,
)


NOW = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)
BOOT_ID = "123e4567-e89b-12d3-a456-426614174000"
SNAPSHOT_PATH = PurePosixPath("resources/resource-snapshot-v1.json")
THERMAL_POLICY_PATH = PurePosixPath("resources/thermal-policy-v1.json")


def snapshot_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "boot_id": BOOT_ID,
        "generation": 7,
        "observed_at_utc": "2026-08-16T12:00:00Z",
        "observed_monotonic_ns": 123_456_789,
        "freshness": "fresh",
        "gate_state": "ready",
        "reason_codes": ["resource_ready"],
        "current": {"cpu": 12.0, "io": 8.0, "memory": 20.0},
        "mean_1m": {"cpu": 11.0, "io": 7.0, "memory": 19.0},
        "mean_10m": {"cpu": 10.0, "io": 6.0, "memory": 18.0},
        "peak_10m": {"cpu": 13.0, "io": 9.0, "memory": 21.0},
        "normalized_pressure": {"cpu": 12, "io": 8, "memory": 20},
        "normalized_headroom": {"cpu": 88, "io": 92, "memory": 80},
        "trend": {"cpu": "stable", "io": "stable", "memory": "stable"},
        "bottleneck": "unknown",
        "preferred_profiles": ["balanced"],
        "avoid_profiles": [],
        "confidence": "high",
        "cgroup_state": "ready",
        "thermal_state": "ready",
    }


class ResourceMonitorTests(unittest.TestCase):
    def parse(self, payload: dict[str, object] | None = None):
        return parse_snapshot_document(
            snapshot_document() if payload is None else payload,
            now_utc=NOW,
            expected_boot_id=BOOT_ID,
        )

    def test_snapshot_rejects_unknown_schema_generation_zero_nonfinite_bool_and_unknown_fields(self) -> None:
        invalid_payloads: list[dict[str, object]] = []

        unknown_schema = snapshot_document()
        unknown_schema["schema_version"] = 2
        invalid_payloads.append(unknown_schema)

        zero_generation = snapshot_document()
        zero_generation["generation"] = 0
        invalid_payloads.append(zero_generation)

        bool_generation = snapshot_document()
        bool_generation["generation"] = True
        invalid_payloads.append(bool_generation)

        nonfinite = snapshot_document()
        nonfinite["current"] = {"cpu": math.nan, "io": 8.0, "memory": 20.0}
        invalid_payloads.append(nonfinite)

        unknown_field = snapshot_document()
        unknown_field["unexpected"] = "value"
        invalid_payloads.append(unknown_field)

        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ResourceSnapshotError, "^resource_snapshot_invalid$"):
                    self.parse(payload)

    def test_snapshot_rejects_stale_future_or_wrong_boot_without_error_details(self) -> None:
        invalid_payloads: list[dict[str, object]] = []

        stale = snapshot_document()
        stale["observed_at_utc"] = (NOW - timedelta(seconds=4)).isoformat()
        invalid_payloads.append(stale)

        future = snapshot_document()
        future["observed_at_utc"] = (NOW + timedelta(seconds=3)).isoformat()
        invalid_payloads.append(future)

        future_microsecond = snapshot_document()
        future_microsecond["observed_at_utc"] = (NOW + timedelta(microseconds=1)).isoformat()
        invalid_payloads.append(future_microsecond)

        future_second = snapshot_document()
        future_second["observed_at_utc"] = (NOW + timedelta(seconds=1)).isoformat()
        invalid_payloads.append(future_second)

        wrong_boot = snapshot_document()
        wrong_boot["boot_id"] = "123e4567-e89b-12d3-a456-426614174001"
        invalid_payloads.append(wrong_boot)

        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(ResourceSnapshotError) as raised:
                    self.parse(payload)
                self.assertEqual(str(raised.exception), "resource_snapshot_invalid")

        exact_now = snapshot_document()
        exact_now["observed_at_utc"] = NOW.isoformat()
        self.parse(exact_now)

        exact_max_age = snapshot_document()
        exact_max_age["observed_at_utc"] = (NOW - timedelta(seconds=3)).isoformat()
        self.parse(exact_max_age)

    def test_snapshot_is_deeply_immutable(self) -> None:
        payload = snapshot_document()
        snapshot = self.parse(payload)

        payload["current"]["cpu"] = 99.0  # type: ignore[index]

        self.assertEqual(snapshot.current["cpu"], 12.0)
        with self.assertRaises(TypeError):
            snapshot.current["cpu"] = 99.0
        with self.assertRaises(FrozenInstanceError):
            snapshot.generation = 8

    def test_public_models_normalize_or_reject_nested_mutables_on_constructor_and_replace(self) -> None:
        class CustomMutable:
            pass

        current = {"cpu": 12.0, "io": 8.0, "memory": 20.0}
        snapshot = ResourceSnapshotV1(
            schema_version=1,
            boot_id=BOOT_ID,
            generation=7,
            observed_at_utc=NOW,
            observed_monotonic_ns=123_456_789,
            freshness="fresh",
            gate_state="ready",
            reason_codes=["resource_ready"],
            current=current,
            mean_1m=current,
            mean_10m=current,
            peak_10m=current,
            normalized_pressure={"cpu": 12, "io": 8, "memory": 20},
            normalized_headroom={"cpu": 88, "io": 92, "memory": 80},
            trend={"cpu": "stable", "io": "stable", "memory": "stable"},
            bottleneck="unknown",
            preferred_profiles=["balanced"],
            avoid_profiles=[],
            confidence="high",
            cgroup_state="ready",
            thermal_state="ready",
        )
        current["cpu"] = 99.0
        self.assertEqual(snapshot.current["cpu"], 12.0)

        with self.assertRaisesRegex(ResourceSnapshotError, "^resource_snapshot_invalid$"):
            replace(snapshot, current={"cpu": CustomMutable(), "io": 8.0, "memory": 20.0})

        with self.assertRaisesRegex(ResourceSnapshotError, "^resource_snapshot_invalid$"):
            replace(snapshot, schema_version=True)

        with self.assertRaisesRegex(ResourceSnapshotError, "^resource_snapshot_invalid$"):
            TrendAssessmentV1(trend=[], confidence="high")

        with self.assertRaisesRegex(ResourceSnapshotError, "^resource_snapshot_invalid$"):
            ResourceGateFacts(
                generation=7,
                observed_at_utc=NOW,
                observed_monotonic_ns=123_456_789,
                gate_state="ready",
                reason_codes=["resource_ready"],
                current={"cpu": [], "io": 8.0, "memory": 20.0},
                normalized_pressure={"cpu": 12, "io": 8, "memory": 20},
                normalized_headroom={"cpu": 88, "io": 92, "memory": 80},
                bottleneck="unknown",
                cgroup_state="ready",
                thermal_state="ready",
            )

        with self.assertRaisesRegex(ResourceSnapshotError, "^resource_snapshot_invalid$"):
            ResourceOperatorStatus(
                schema_version=1,
                generation=7,
                state="ready",
                bottleneck="unknown",
                current={"cpu": 12.0, "io": 8.0, "memory": 20.0},
                mean_1m={"cpu": 11.0, "io": 7.0, "memory": 19.0},
                mean_10m={"cpu": 10.0, "io": 6.0, "memory": 18.0},
                peak_10m={"cpu": 13.0, "io": 9.0, "memory": 21.0},
                trend={"cpu": {"mutable": []}, "io": "stable", "memory": "stable"},
                confidence="high",
                preferred_profiles=["balanced"],
                avoid_profiles=[],
                reason_codes=["resource_ready"],
            )

        with self.assertRaisesRegex(ResourceSnapshotError, "^resource_snapshot_invalid$"):
            ResourceSchedulerSnapshot(
                schema_version=1,
                generation=7,
                confidence="high",
                normalized_pressure={"cpu": {"mutable": []}, "io": 8, "memory": 20},
                preferred_profiles=["balanced"],
                avoid_profiles=[],
            )

    def test_projection_builders_share_exactly_one_generation(self) -> None:
        snapshot = self.parse()

        facts = build_resource_gate_facts(snapshot)
        operator = build_resource_operator_status(snapshot)
        scheduler = build_resource_scheduler_snapshot(snapshot)

        self.assertEqual((facts.generation, operator.generation, scheduler.generation), (7, 7, 7))
        self.assertEqual(facts.reason_codes, ("resource_ready",))
        self.assertEqual(operator.trend["cpu"], "stable")
        self.assertEqual(scheduler.normalized_pressure["memory"], 20)

    def test_operator_and_scheduler_projection_omit_paths_labels_history_pid_scope_and_raw_output(self) -> None:
        snapshot = self.parse()
        operator = build_resource_operator_status(snapshot)
        scheduler = build_resource_scheduler_snapshot(snapshot)

        forbidden = {"path", "label", "history", "pid", "scope", "raw_output"}
        for projection in (operator, scheduler):
            self.assertTrue(forbidden.isdisjoint(projection.__dataclass_fields__))

    def test_trend_uses_last_two_buckets_against_previous_eight_with_plus_minus_five(self) -> None:
        self.assertEqual(classify_trend([10] * 8 + [15, 15]).trend, "rising")
        self.assertEqual(classify_trend([10] * 8 + [5, 5]).trend, "falling")
        self.assertEqual(classify_trend([10] * 8 + [14, 14]).trend, "stable")

    def test_under_six_buckets_is_low_confidence_and_never_guesses_trend(self) -> None:
        assessment = classify_trend([90] * 5)
        payload = snapshot_document()
        payload["confidence"] = assessment.confidence
        payload["trend"] = {"cpu": assessment.trend, "io": assessment.trend, "memory": assessment.trend}

        operator = build_resource_operator_status(self.parse(payload))

        self.assertEqual(operator.confidence, "low")
        self.assertIsNone(assessment.trend)
        self.assertEqual(dict(operator.trend), {})


if __name__ == "__main__":
    unittest.main()


def _snapshot(payload: dict[str, object] | None = None) -> ResourceSnapshotV1:
    return parse_snapshot_document(
        snapshot_document() if payload is None else payload,
        now_utc=NOW,
        expected_boot_id=BOOT_ID,
    )


def _snapshot_bytes(payload: dict[str, object] | None = None) -> bytes:
    return json.dumps(snapshot_document() if payload is None else payload).encode("utf-8")


def test_resource_document_reader_rejects_nonregular_mode_owner_link_partial_duplicate_key_nan_and_overlimit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = HiveStateStore(tmp_path / "state")
    invalid_documents = (
        b"{",
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":NaN}',
        b" " * (64 * 1024 + 1),
    )
    for document in invalid_documents:
        store.replace_private_bytes(SNAPSHOT_PATH, document)
        with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
            read_resource_snapshot(store, now_utc=NOW, expected_boot_id=BOOT_ID)

    path = tmp_path / "state" / "resources" / "resource-snapshot-v1.json"
    path.write_bytes(_snapshot_bytes())
    path.chmod(0o644)
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        read_resource_snapshot(store, now_utc=NOW, expected_boot_id=BOOT_ID)

    path.chmod(0o600)
    expected_uid = os.geteuid()
    monkeypatch.setattr(hive_state_module.os, "geteuid", lambda: expected_uid + 1)
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        read_resource_snapshot(store, now_utc=NOW, expected_boot_id=BOOT_ID)
    monkeypatch.undo()

    path.unlink()
    hardlink_source = tmp_path / "snapshot-source.json"
    hardlink_source.write_bytes(_snapshot_bytes())
    hardlink_source.chmod(0o600)
    os.link(hardlink_source, path)
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        read_resource_snapshot(store, now_utc=NOW, expected_boot_id=BOOT_ID)


def test_resource_document_reader_rejects_generation_regression_wrong_boot_stale_future_and_time_rollback(
    tmp_path: Path,
) -> None:
    store = HiveStateStore(tmp_path / "state")
    snapshot = _snapshot()
    write_resource_snapshot(store, snapshot)

    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        write_resource_snapshot(store, replace(snapshot, generation=6))
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        write_resource_snapshot(store, replace(snapshot, generation=8, observed_monotonic_ns=1))
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        read_resource_snapshot(store, now_utc=NOW, expected_boot_id="123e4567-e89b-12d3-a456-426614174001")

    stale = snapshot_document()
    stale["observed_at_utc"] = (NOW - timedelta(seconds=4)).isoformat()
    store.replace_private_bytes(SNAPSHOT_PATH, _snapshot_bytes(stale))
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        read_resource_snapshot(store, now_utc=NOW, expected_boot_id=BOOT_ID)

    future = snapshot_document()
    future["observed_at_utc"] = (NOW + timedelta(seconds=3)).isoformat()
    store.replace_private_bytes(SNAPSHOT_PATH, _snapshot_bytes(future))
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        read_resource_snapshot(store, now_utc=NOW, expected_boot_id=BOOT_ID)


def test_resource_document_reader_reads_one_document_once_and_never_mixes_generation(tmp_path: Path) -> None:
    class CountingStore(HiveStateStore):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.reads: list[PurePosixPath] = []

        def read_private_bytes(self, relative: PurePosixPath, *, max_bytes: int) -> bytes:
            self.reads.append(relative)
            return super().read_private_bytes(relative, max_bytes=max_bytes)

    store = CountingStore(tmp_path / "state")
    write_resource_snapshot(store, _snapshot())
    write_thermal_policy(
        store,
        ThermalPolicyV1(schema_version=1, sensor_thresholds={"cpu_package": 95.0}),
    )
    store.reads.clear()

    snapshot = read_resource_snapshot(store, now_utc=NOW, expected_boot_id=BOOT_ID)

    assert snapshot.generation == 7
    assert store.reads == [SNAPSHOT_PATH]


def test_resource_documents_use_only_authorized_injected_hive_state_store_and_fixed_resources_relative_paths(
    tmp_path: Path,
) -> None:
    class RecordingStore(HiveStateStore):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.paths: list[PurePosixPath] = []

        def read_private_bytes(self, relative: PurePosixPath, *, max_bytes: int) -> bytes:
            self.paths.append(relative)
            return super().read_private_bytes(relative, max_bytes=max_bytes)

        def replace_private_bytes(self, relative: PurePosixPath, payload: bytes) -> None:
            self.paths.append(relative)
            super().replace_private_bytes(relative, payload)

    store = RecordingStore(tmp_path / "state")
    write_resource_snapshot(store, _snapshot())
    assert read_resource_snapshot(store, now_utc=NOW, expected_boot_id=BOOT_ID).generation == 7
    write_thermal_policy(
        store,
        ThermalPolicyV1(schema_version=1, sensor_thresholds={"cpu_package": 95.0}),
    )
    assert read_thermal_policy(store) == ThermalPolicyV1(
        schema_version=1, sensor_thresholds={"cpu_package": 95.0}
    )
    assert set(store.paths) == {SNAPSHOT_PATH, THERMAL_POLICY_PATH}


def test_resource_monitor_rejects_path_root_factory_home_environment_and_second_store_or_lock_api(
    tmp_path: Path,
) -> None:
    store = HiveStateStore(tmp_path / "state")

    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        read_resource_snapshot(object(), now_utc=NOW, expected_boot_id=BOOT_ID)  # type: ignore[arg-type]
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        write_resource_snapshot(store, object())  # type: ignore[arg-type]
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        write_thermal_policy(store, object())  # type: ignore[arg-type]


def test_snapshot_stale_persistence_is_unavailable_without_cross_document_atomicity_claim(tmp_path: Path) -> None:
    store = HiveStateStore(tmp_path / "state")
    stale = snapshot_document()
    stale["observed_at_utc"] = (NOW - timedelta(seconds=4)).isoformat()
    store.replace_private_bytes(SNAPSHOT_PATH, _snapshot_bytes(stale))
    write_thermal_policy(
        store,
        ThermalPolicyV1(schema_version=1, sensor_thresholds={"cpu_package": 95.0}),
    )

    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        read_resource_snapshot(store, now_utc=NOW, expected_boot_id=BOOT_ID)
    assert read_thermal_policy(store) == ThermalPolicyV1(
        schema_version=1, sensor_thresholds={"cpu_package": 95.0}
    )


def test_thermal_policy_only_contains_normalized_derived_values_not_applet_configuration(tmp_path: Path) -> None:
    store = HiveStateStore(tmp_path / "state")
    policy = ThermalPolicyV1(schema_version=1, sensor_thresholds={"cpu_package": 95.0})
    write_thermal_policy(store, policy)

    document = json.loads(store.read_private_bytes(THERMAL_POLICY_PATH, max_bytes=64 * 1024))
    assert document == {"schema_version": 1, "sensor_thresholds": {"cpu_package": 95.0}}

    store.replace_private_bytes(
        THERMAL_POLICY_PATH,
        b'{"schema_version":1,"sensor_thresholds":{"cpu_package":95.0},"show_in_panel":true}',
    )
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        read_thermal_policy(store)
