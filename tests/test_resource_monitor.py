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
    ResourceClocks,
    ResourceInputPaths,
    ResourceSampleV1,
    ResourceSnapshotError,
    ResourceSnapshotV1,
    ResourceGateFacts,
    ResourceOperatorStatus,
    ResourceSchedulerSnapshot,
    ThermalCandidate,
    ThermalPolicyV1,
    TrendAssessmentV1,
    build_monitor_snapshot,
    build_resource_gate_facts,
    build_resource_operator_status,
    build_resource_scheduler_snapshot,
    classify_trend,
    collect_resource_sample,
    parse_snapshot_document,
    read_resource_snapshot,
    read_thermal_policy,
    resolve_thermal_policy,
    write_resource_snapshot,
    write_thermal_policy,
)


NOW = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)
BOOT_ID = "123e4567-e89b-12d3-a456-426614174000"
SNAPSHOT_PATH = PurePosixPath("resources/resource-snapshot-v1.json")
THERMAL_POLICY_PATH = PurePosixPath("resources/thermal-policy-v1.json")


class FakeResourceBackend:
    def __init__(self, kernel: dict[Path, bytes], sensors: bytes | BaseException) -> None:
        self.kernel = kernel
        self.sensors = sensors
        self.reads: list[tuple[Path, int]] = []
        self.sensor_calls: list[dict[str, object]] = []

    def read_private_kernel_bytes(self, path: Path, *, max_bytes: int) -> bytes:
        self.reads.append((path, max_bytes))
        try:
            return self.kernel[path]
        except KeyError as error:
            raise RuntimeError("missing fake input") from error

    def run_sensors_json(self, **kwargs: object) -> bytes:
        self.sensor_calls.append(kwargs)
        if isinstance(self.sensors, BaseException):
            raise self.sensors
        return self.sensors


def resource_paths() -> ResourceInputPaths:
    return ResourceInputPaths()


def resource_clocks(*, monotonic_ns: int = 10_000_000_000, now_utc: datetime = NOW) -> ResourceClocks:
    return ResourceClocks(now_utc=lambda: now_utc, monotonic_ns=lambda: monotonic_ns)


def resource_kernel_document(paths: ResourceInputPaths) -> dict[Path, bytes]:
    return {
        paths.loadavg: b"1.00 0.50 0.25 1/100 42\n",
        paths.meminfo: (
            b"MemTotal:       1048576 kB\nMemFree:        131072 kB\nMemAvailable:  524288 kB\n"
            b"Buffers:          1024 kB\nCached:          2048 kB\nSwapCached:         0 kB\n"
        ),
        paths.stat: (
            b"cpu  10 0 10 70 0 0 0 0 0 0\ncpu0 5 0 5 35 0 0 0 0 0 0\n"
            b"intr 1 0 0\nctxt 1\nbtime 1\nprocesses 1\nprocs_running 1\nprocs_blocked 0\n"
        ),
        paths.psi_cpu: b"some avg10=1.00 avg60=1.00 avg300=1.00 total=1\n",
        paths.psi_io: b"some avg10=2.00 avg60=2.00 avg300=2.00 total=1\nfull avg10=1.00 avg60=1.00 avg300=1.00 total=1\n",
        paths.psi_memory: b"some avg10=3.00 avg60=3.00 avg300=3.00 total=1\nfull avg10=1.00 avg60=1.00 avg300=1.00 total=1\n",
        paths.boot_id: (BOOT_ID + "\n").encode("ascii"),
    }


def sensor_document(*, include_formula: bool = False, show_in_panel: object | None = None) -> bytes:
    payload: dict[str, object] = {
        "coretemp-isa-0000": {
            "Adapter": "ISA adapter",
            "Package id 0": {
                "temp1_input": 70.0,
                "temp1_max": 80.0,
                "temp1_crit": 100.0,
            },
        }
    }
    sensor = payload["coretemp-isa-0000"]["Package id 0"]  # type: ignore[index]
    if include_formula:
        sensor["user_formula"] = "x+1"  # type: ignore[index]
    if show_in_panel is not None:
        sensor["show_in_panel"] = show_in_panel  # type: ignore[index]
    return json.dumps(payload).encode("utf-8")


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


def test_proc_and_psi_parsers_reject_malformed_duplicate_negative_nonfinite_overflow_and_unknown_inputs() -> None:
    paths = resource_paths()
    kernel = resource_kernel_document(paths)
    candidates = [ThermalCandidate("coretemp-isa-0000", "ISA adapter", "Package id 0", high=90.0)]

    invalid_inputs = (
        (paths.loadavg, b"-1.00 0.50 0.25 1/100 42\n"),
        (paths.meminfo, b"MemTotal: 1048576 kB\nMemTotal: 1 kB\nMemAvailable: 524288 kB\n"),
        (paths.stat, b"cpu  1 2 x 4\n"),
        (paths.psi_cpu, b"some avg10=NaN avg60=1.00 avg300=1.00 total=1\n"),
        (paths.psi_io, b"some avg10=2.00 avg60=2.00 avg300=2.00 total=1\n"),
        (paths.psi_memory, b"some avg10=2e999 avg60=2.00 avg300=2.00 total=1\nfull avg10=1.00 avg60=1.00 avg300=1.00 total=1\n"),
        (paths.boot_id, b"not-a-uuid\n"),
    )
    for path, payload in invalid_inputs:
        candidate_kernel = dict(kernel)
        candidate_kernel[path] = payload
        backend = FakeResourceBackend(candidate_kernel, sensor_document())
        with pytest.raises(ResourceSnapshotError, match="^resource_monitor_unavailable$"):
            collect_resource_sample(
                backend, paths, clocks=resource_clocks(), candidates=candidates, completed_sample_count=10
            )

    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        ResourceInputPaths(loadavg=Path("relative"))


def test_sensor_runner_parser_and_thermal_policy_are_bounded_fixed_and_fail_closed() -> None:
    paths = resource_paths()
    kernel = resource_kernel_document(paths)
    candidates = [ThermalCandidate("coretemp-isa-0000", "ISA adapter", "Package id 0", high=90.0)]
    backend = FakeResourceBackend(kernel, sensor_document())

    sample = collect_resource_sample(
        backend, paths, clocks=resource_clocks(), candidates=candidates, completed_sample_count=10
    )

    assert sample.thermal_state == "ready"
    assert sample.thermal_policy == ThermalPolicyV1(schema_version=1, sensor_thresholds={"coretemp-isa-0000:isa_adapter:package_id_0": 90.0})
    assert backend.sensor_calls == [
        {
            "argv": ("/usr/bin/sensors", "-j"),
            "environment": {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"},
            "stdin_closed": True,
            "timeout_seconds": 1.0,
            "max_stdout_bytes": 512 * 1024,
            "max_stderr_bytes": 16 * 1024,
        }
    ]

    invalid_sensors = (
        b'{"coretemp-isa-0000":{"Adapter":"ISA adapter","Package id 0":{"temp1_input":NaN}}}',
        b'{"coretemp-isa-0000":{},"coretemp-isa-0000":{}}',
        sensor_document(include_formula=True),
        sensor_document(show_in_panel=False),
    )
    for document in invalid_sensors:
        with pytest.raises(ResourceSnapshotError, match="^temperature_monitor_unavailable$"):
            collect_resource_sample(
                FakeResourceBackend(kernel, document),
                paths,
                clocks=resource_clocks(),
                candidates=candidates,
                completed_sample_count=10,
            )

def test_thermal_policy_prefers_configured_high_then_max_then_ninety_percent_crit_and_rejects_unknown_sensor() -> None:
    document = json.loads(sensor_document())
    configured = ThermalCandidate("coretemp-isa-0000", "ISA adapter", "Package id 0", high=90.0)
    automatic = ThermalCandidate("coretemp-isa-0000", "ISA adapter", "Package id 0")
    assert resolve_thermal_policy(document, configured_candidates=[configured]) == ThermalPolicyV1(
        schema_version=1,
        sensor_thresholds={"coretemp-isa-0000:isa_adapter:package_id_0": 90.0},
    )
    assert resolve_thermal_policy(document, configured_candidates=[automatic]) == ThermalPolicyV1(
        schema_version=1,
        sensor_thresholds={"coretemp-isa-0000:isa_adapter:package_id_0": 80.0},
    )
    reading = document["coretemp-isa-0000"]["Package id 0"]
    del reading["temp1_max"]
    assert resolve_thermal_policy(document, configured_candidates=[automatic]) == ThermalPolicyV1(
        schema_version=1,
        sensor_thresholds={"coretemp-isa-0000:isa_adapter:package_id_0": 90.0},
    )
    document["unknown-chip"] = {"Adapter": "Unknown", "temp": {"temp1_input": 10.0, "temp1_crit": 80.0}}
    with pytest.raises(ResourceSnapshotError, match="^temperature_monitor_unavailable$"):
        resolve_thermal_policy(document, configured_candidates=[automatic])


def test_kernel_parsers_accept_standard_extra_lines_but_reject_duplicate_or_malformed_target_lines() -> None:
    paths = resource_paths()
    kernel = resource_kernel_document(paths)
    candidates = [ThermalCandidate("coretemp-isa-0000", "ISA adapter", "Package id 0")]
    sample = collect_resource_sample(
        FakeResourceBackend(kernel, sensor_document()),
        paths,
        clocks=resource_clocks(),
        candidates=candidates,
        completed_sample_count=10,
    )
    assert sample.current["cpu"] == pytest.approx(22.22222222222222)

    duplicate_meminfo = dict(kernel)
    duplicate_meminfo[paths.meminfo] += b"MemAvailable: 1 kB\n"
    duplicate_cpu = dict(kernel)
    duplicate_cpu[paths.stat] = kernel[paths.stat] + b"cpu 1 0 0 9 0 0 0 0 0 0\n"
    malformed_cpu = dict(kernel)
    malformed_cpu[paths.stat] = b"cpu 1 0 malformed 9\ncpu0 1 0 0 9\n"
    for invalid in (duplicate_meminfo, duplicate_cpu, malformed_cpu):
        with pytest.raises(ResourceSnapshotError, match="^resource_monitor_unavailable$"):
            collect_resource_sample(
                FakeResourceBackend(invalid, sensor_document()),
                paths,
                clocks=resource_clocks(),
                candidates=candidates,
                completed_sample_count=10,
            )


def test_collect_resource_sample_redacts_short_numeric_aggregate_cpu_line() -> None:
    paths = resource_paths()
    kernel = resource_kernel_document(paths)
    kernel[paths.stat] = b"cpu 1 2 3 4\n"

    with pytest.raises(ResourceSnapshotError, match="^resource_monitor_unavailable$"):
        collect_resource_sample(
            FakeResourceBackend(kernel, sensor_document()),
            paths,
            clocks=resource_clocks(),
            candidates=[ThermalCandidate("coretemp-isa-0000", "ISA adapter", "Package id 0")],
            completed_sample_count=10,
        )


def test_completed_sample_count_is_mandatory_and_only_tenth_valid_sample_leaves_warmup() -> None:
    paths = resource_paths()
    kernel = resource_kernel_document(paths)
    candidates = [ThermalCandidate("coretemp-isa-0000", "ISA adapter", "Package id 0")]
    backend = FakeResourceBackend(kernel, sensor_document())

    with pytest.raises(TypeError):
        collect_resource_sample(backend, paths, clocks=resource_clocks(), candidates=candidates)
    for count in range(10):
        sample = collect_resource_sample(
            backend,
            paths,
            clocks=resource_clocks(),
            candidates=candidates,
            completed_sample_count=count,
        )
        assert sample.thermal_state == "warming_up"
    ready = collect_resource_sample(
        backend,
        paths,
        clocks=resource_clocks(),
        candidates=candidates,
        completed_sample_count=10,
    )
    assert ready.thermal_state == "ready"


def test_g3_cannot_accept_or_construct_claimed_cgroup_readiness() -> None:
    paths = resource_paths()
    kernel = resource_kernel_document(paths)
    candidates = [ThermalCandidate("coretemp-isa-0000", "ISA adapter", "Package id 0")]
    with pytest.raises(TypeError):
        collect_resource_sample(
            FakeResourceBackend(kernel, sensor_document()),
            paths,
            clocks=resource_clocks(),
            candidates=candidates,
            cgroup_state="ready",
            completed_sample_count=10,
        )
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        ResourceSampleV1(
            boot_id=BOOT_ID,
            observed_at_utc=NOW,
            observed_monotonic_ns=1,
            current={"cpu": 1.0, "io": 1.0, "memory": 1.0},
            cgroup_state="ready",
            thermal_state="warming_up",
            thermal_policy=None,
        )


def test_thermal_states_and_ten_one_hz_samples_build_one_complete_generation() -> None:
    paths = resource_paths()
    kernel = resource_kernel_document(paths)
    candidates = [ThermalCandidate("coretemp-isa-0000", "ISA adapter", "Package id 0")]

    ready = collect_resource_sample(
        FakeResourceBackend(kernel, sensor_document()),
        paths,
        clocks=resource_clocks(),
        candidates=candidates,
        completed_sample_count=10,
    )
    warming = collect_resource_sample(
        FakeResourceBackend(kernel, sensor_document()),
        paths,
        clocks=resource_clocks(),
        candidates=candidates,
        completed_sample_count=9,
    )
    empty = collect_resource_sample(
        FakeResourceBackend(kernel, b"{}"), paths, clocks=resource_clocks(), candidates=candidates, completed_sample_count=10
    )
    unavailable = collect_resource_sample(
        FakeResourceBackend(kernel, RuntimeError("runner failed")),
        paths,
        clocks=resource_clocks(),
        candidates=candidates,
        completed_sample_count=10,
    )
    assert ready.thermal_state == "ready"
    assert warming.thermal_state == "warming_up"
    assert empty.thermal_state == "no_valid_sensors"
    assert unavailable.thermal_state == "monitor_unavailable"

    samples = [
        collect_resource_sample(
            FakeResourceBackend(kernel, sensor_document()),
            paths,
            clocks=resource_clocks(
                monotonic_ns=10_000_000_000 + index * 1_000_000_000,
                now_utc=NOW + timedelta(seconds=index),
            ),
            candidates=candidates,
            completed_sample_count=index + 1,
        )
        for index in range(10)
    ]
    snapshot = build_monitor_snapshot(
        samples,
        prior_generation=7,
        clocks=resource_clocks(monotonic_ns=19_000_000_000, now_utc=NOW + timedelta(seconds=9)),
    )
    assert snapshot.generation == 8
    assert snapshot.confidence == "high"
    assert snapshot.thermal_state == "ready"
    assert snapshot.mean_10m["cpu"] == pytest.approx(sum(sample.current["cpu"] for sample in samples) / 10)

    with pytest.raises(ResourceSnapshotError, match="^temperature_monitor_unavailable$"):
        build_monitor_snapshot(
            samples[:9],
            prior_generation=7,
            clocks=resource_clocks(monotonic_ns=18_000_000_000, now_utc=NOW + timedelta(seconds=8)),
        )
    with pytest.raises(ResourceSnapshotError, match="^resource_snapshot_invalid$"):
        build_monitor_snapshot(
            samples + [samples[-1]],
            prior_generation=7,
            clocks=resource_clocks(monotonic_ns=20_000_000_000, now_utc=NOW + timedelta(seconds=10)),
        )
