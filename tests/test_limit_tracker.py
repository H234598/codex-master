from __future__ import annotations

from collections import Counter
import fcntl
import hashlib
import importlib
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_master import limit_tracker
from codex_master.usage_snapshot import (
    AccountUsageEvidenceV2,
    TrackerEvidenceV2,
    UsageEvidenceV2,
    UsageLimitV2,
    UsageTrendV2,
)


NOW = datetime(2026, 8, 26, 18, 0, tzinfo=UTC)
GENERATION = "1" * 32
SOURCE_DIGEST = "2" * 64
RESET = "2026-08-27T00:00:00Z"


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def test_non_finite_json_and_emergency_block_state_are_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="non-finite JSON constant: NaN"):
        limit_tracker._reject_non_finite("NaN")

    state = {
        "state": "running",
        "generation": 3,
        "children": [],
        "plans": [],
        "emergency_active": True,
    }
    monkeypatch.setattr(limit_tracker, "_queen_state", state)

    assert limit_tracker.set_emergency_queen_blocked(2, "stale")["updated"] is False
    blocked = limit_tracker.set_emergency_queen_blocked(3, "waiting")
    assert blocked["updated"] is True
    assert blocked["state"]["blocked_reason"] == "waiting"


def private_file(path: Path, payload: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(payload)
    path.chmod(mode)
    return path


def release_tree_digest(release: Path) -> str:
    rows: list[bytes] = []
    stack = [(release, ".")]
    while stack:
        path, relative = stack.pop()
        item = path.lstat()
        mode = stat.S_IMODE(item.st_mode)
        if path.is_dir():
            rows.append(f"D {relative}\0{mode:04o}\n".encode())
            children = sorted(
                path.iterdir(), key=lambda child: child.name, reverse=True
            )
            stack.extend((child, f"{relative}/{child.name}") for child in children)
        else:
            payload = path.read_bytes()
            rows.append(
                f"F {relative}\0{mode:04o}\0{len(payload)}\0".encode()
                + hashlib.sha256(payload).hexdigest().encode()
                + b"\n"
            )
    return hashlib.sha256(b"".join(rows)).hexdigest()


def tracker(
    *,
    pool: str = "main",
    window: int = 18_000,
    coverage: str = "complete",
    reset_generation: str = RESET,
) -> dict[str, object]:
    return {
        "coverage": coverage,
        "ema_time_constant_seconds": 3_600,
        "first_sample_at": "2026-08-26T16:00:00Z",
        "last_sample_at": "2026-08-26T17:59:00Z",
        "limit_window_seconds": window,
        "pool": pool,
        "projected_used_percent_at_reset": 75.0,
        "rate_percentage_points_per_second": 0.002,
        "reset_generation": reset_generation,
        "sample_count": 3,
    }


def limit(*, pool: str = "main", window: int = 18_000) -> dict[str, object]:
    return {
        "pool": pool,
        "remaining_percent": 40.0,
        "reset_at": RESET,
        "used_percent": 60.0,
        "window_seconds": window,
    }


def document(*, status: str = "ok", stale: bool = False) -> dict[str, object]:
    return {
        "accounts": [
            {
                "account_id": "BW_Nufker",
                "freshness": {
                    "captured_at": "2026-08-26T17:59:00Z",
                    "fresh_until": "2026-08-26T18:14:00Z",
                    "stale": stale,
                },
                "limits": [limit(pool="gpt-5.3-codex-spark"), limit()],
                "status": status,
                "tracker_evidence": [
                    tracker(),
                    tracker(pool="gpt-5.3-codex-spark", reset_generation=RESET),
                ],
            }
        ],
        "generated_at": "2026-08-26T17:59:00Z",
        "schema_version": 2,
    }


class EvidenceTree:
    def __init__(self, root: Path, payload: dict[str, object]) -> None:
        self.root = private_dir(root)
        self.state_home = private_dir(root / "state")
        self.data_home = private_dir(root / "data")
        self.app = private_dir(self.state_home / "codex-usage")
        self.integration = private_dir(self.app / "integration")
        self.producer_install = private_dir(self.integration / "producer-install")
        self.releases = private_dir(self.integration / "releases")
        self.generations = private_dir(self.integration / "generations")
        self.lock_home = private_dir(root / "lock-home")
        self.local = private_dir(self.lock_home / ".local")
        self.lock_state = private_dir(self.local / "state")
        self.lock_app = private_dir(self.lock_state / "codex-usage")
        self.lock_root = private_dir(self.lock_app / "locks")
        self.release_id = f"0.6.536-{SOURCE_DIGEST[:16]}"
        self.release = private_dir(self.releases / self.release_id)
        private_file(self.release / "producer.whl", b"wheel")
        venv = private_dir(self.release / "venv")
        bin_dir = private_dir(venv / "bin")
        lib = private_dir(venv / "lib")
        python = private_dir(lib / "python3.13")
        site = private_dir(python / "site-packages")
        package = private_dir(site / "codex_usage")
        dist = private_dir(site / "codex_usage_integration_producer-0.6.536.dist-info")
        self.launcher = private_file(
            bin_dir / "codex-usage",
            b"#!/bin/sh\nexec python -B -I -m codex_usage.integration_entrypoint\n",
            0o700,
        )
        self.entrypoint = private_file(package / "integration_entrypoint.py", b"pass\n")
        self.record = private_file(dist / "RECORD", b"record\n")
        self.publish(payload)
        self.make_locks()

    def make_locks(self) -> None:
        for target in (self.producer_install, self.integration / "current.json"):
            name = (
                hashlib.sha256(os.fsencode(os.path.abspath(target))).hexdigest()
                + ".lock"
            )
            private_file(self.lock_root / name, b"")

    def active(self) -> dict[str, object]:
        return {
            "data_home": str(self.data_home),
            "entrypoint_path": str(self.entrypoint),
            "entrypoint_sha256": hashlib.sha256(
                self.entrypoint.read_bytes()
            ).hexdigest(),
            "launcher_path": str(self.launcher),
            "launcher_sha256": hashlib.sha256(self.launcher.read_bytes()).hexdigest(),
            "record_path": str(self.record),
            "record_sha256": hashlib.sha256(self.record.read_bytes()).hexdigest(),
            "release_dir": str(self.release),
            "release_id": self.release_id,
            "release_tree_sha256": release_tree_digest(self.release),
            "schema_version": 2,
            "source_manifest_sha256": SOURCE_DIGEST,
            "state_home": str(self.state_home),
            "version": "0.6.536",
            "wheel_path": str(self.release / "producer.whl"),
            "wheel_sha256": hashlib.sha256(
                (self.release / "producer.whl").read_bytes()
            ).hexdigest(),
        }

    def publish(
        self, payload_value: dict[str, object], *, generation: str = GENERATION
    ) -> None:
        for child in tuple(self.generations.iterdir()):
            for item in sorted(child.rglob("*"), reverse=True):
                item.rmdir() if item.is_dir() else item.unlink()
            child.rmdir()
        payload = canonical(payload_value)
        generation_dir = private_dir(self.generations / generation)
        private_file(generation_dir / "account-usage-v2.json", payload)
        active_payload = canonical(self.active())
        private_file(self.integration / "active.json", active_payload)
        binding = {
            "active_manifest_sha256": hashlib.sha256(active_payload).hexdigest(),
            "binding_schema_version": 1,
            "generation_id": generation,
            "payload_filename": "account-usage-v2.json",
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "payload_size_bytes": len(payload),
            "producer_version": "0.6.536",
            "published_at": payload_value["generated_at"],
            "release_id": self.release_id,
            "source_manifest_sha256": SOURCE_DIGEST,
        }
        binding_payload = canonical(binding)
        private_file(generation_dir / "account-usage-v2.binding.json", binding_payload)
        pointer = {
            "current_binding_sha256": hashlib.sha256(binding_payload).hexdigest(),
            "current_generation_id": generation,
            "pointer_schema_version": 1,
            "previous_binding_sha256": None,
            "previous_generation_id": None,
        }
        private_file(self.integration / "current.json", canonical(pointer))

    def paths(self) -> limit_tracker._EvidencePaths:
        return limit_tracker._EvidencePaths(
            state_home=self.state_home,
            data_home=self.data_home,
            lock_home=self.lock_home,
        )


@pytest.fixture
def evidence(tmp_path: Path) -> EvidenceTree:
    return EvidenceTree(tmp_path / "fixture", document())


def read(
    tree: EvidenceTree, *, now: datetime = NOW
) -> limit_tracker.EvidenceReadResult:
    return limit_tracker._read_current_evidence(tree.paths(), now=now)


def m3_evidence(
    *,
    status: str = "complete",
    pool: str = "main",
    evidence_pool: str | None = None,
    coverage: str = "complete",
    with_trend: bool = True,
    reset_generation: str = "reset-1",
    evidence_reset_generation: str | None = None,
    window_seconds: int = 18000,
    evidence_window_seconds: int | None = None,
) -> UsageEvidenceV2:
    usage_limit = UsageLimitV2(
        pool=pool,
        window_seconds=window_seconds,
        reset_generation=reset_generation,
        used_percent=25.0,
        remaining_percent=75.0,
        reset_at=NOW + timedelta(minutes=30),
    )
    tracker_evidence = TrackerEvidenceV2(
        pool=evidence_pool or pool,
        window_seconds=evidence_window_seconds or window_seconds,
        reset_generation=evidence_reset_generation or reset_generation,
        coverage=coverage,
        last_sample_at=NOW,
    )
    trends = ()
    if with_trend:
        trends = (
            UsageTrendV2(
                pool=pool,
                window_seconds=window_seconds,
                reset_generation=reset_generation,
                coverage=coverage,
                last_sample_at=NOW,
                projected_exhaustion_at=NOW + timedelta(minutes=20),
            ),
        )
    return UsageEvidenceV2(
        accounts=(
            AccountUsageEvidenceV2(
                "alpha", (usage_limit,), trends, (tracker_evidence,)
            ),
        ),
        status=status,
        captured_at=NOW - timedelta(seconds=60),
        generated_at=NOW,
    )


def derive_m3(value: UsageEvidenceV2):
    tracker_module = importlib.import_module("codex_master.limit_tracker")
    return tracker_module.derive_limit_decisions(value, now=NOW)


def test_m3_fresh_complete_matching_v2_evidence_is_descriptive_eligible() -> None:
    decisions = derive_m3(m3_evidence())

    assert len(decisions) == 1
    assert decisions[0].account_id == "alpha"
    assert decisions[0].pool == "main"
    assert decisions[0].window_seconds == 18000
    assert decisions[0].automatic is True
    assert decisions[0].reason == "eligible"


@pytest.mark.parametrize(
    "value",
    [
        m3_evidence(status="stale"),
        m3_evidence(status="partial"),
        m3_evidence(status="busy"),
        m3_evidence(status="unavailable"),
        m3_evidence(status="invalid"),
        m3_evidence(coverage="insufficient"),
        m3_evidence(with_trend=False),
        m3_evidence(evidence_reset_generation="other-reset"),
        m3_evidence(evidence_window_seconds=604800),
        m3_evidence(pool="main", evidence_pool="spark"),
    ],
)
def test_m3_noncomplete_or_mismatched_evidence_never_activates(
    value: UsageEvidenceV2,
) -> None:
    decisions = derive_m3(value)

    assert decisions
    assert all(decision.automatic is False for decision in decisions)


def test_m3_tracker_is_deterministic_and_explicit_now_gates_reset() -> None:
    value = m3_evidence()

    tracker_module = importlib.import_module("codex_master.limit_tracker")
    before_reset = tracker_module.derive_limit_decisions(value, now=NOW)
    after_reset = tracker_module.derive_limit_decisions(
        value, now=NOW + timedelta(hours=1)
    )

    assert before_reset == derive_m3(value)
    assert before_reset[0].automatic is True
    assert after_reset[0].automatic is False
    assert after_reset[0].reason == "reset_elapsed"


def add_previous_generation(tree: EvidenceTree) -> Path:
    generation = "3" * 32
    previous = private_dir(tree.generations / generation)
    current = tree.generations / GENERATION
    private_file(
        previous / "account-usage-v2.json",
        (current / "account-usage-v2.json").read_bytes(),
    )
    binding = json.loads(
        (current / "account-usage-v2.binding.json").read_text(encoding="utf-8")
    )
    binding["generation_id"] = generation
    binding_path = private_file(
        previous / "account-usage-v2.binding.json", canonical(binding)
    )
    pointer_path = tree.integration / "current.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    pointer["previous_generation_id"] = generation
    pointer["previous_binding_sha256"] = hashlib.sha256(
        binding_path.read_bytes()
    ).hexdigest()
    private_file(pointer_path, canonical(pointer))
    return binding_path


def test_golden_schema2_chain_reads_complete(evidence: EvidenceTree) -> None:
    result = read(evidence)
    assert result.status == "complete"
    assert result.generation_id == GENERATION
    assert result.document["schema_version"] == 2


def test_active_and_current_are_reread_fd_bound_after_generation(
    evidence: EvidenceTree,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: Counter[str] = Counter()
    original = limit_tracker._read_private_file_at

    def counted(
        parent_fd: int,
        name: str,
        *,
        path: Path,
        maximum: int,
        minimum: int = 1,
    ) -> tuple[bytes, limit_tracker._Proof]:
        if name in {"active.json", "current.json"}:
            reads[name] += 1
        return original(
            parent_fd,
            name,
            path=path,
            maximum=maximum,
            minimum=minimum,
        )

    monkeypatch.setattr(limit_tracker, "_read_private_file_at", counted)

    result = read(evidence)
    assert result.status == "complete"
    assert reads == Counter({"active.json": 2, "current.json": 2})


def test_official_main_5h_golden_without_spark_reads_complete(
    evidence: EvidenceTree,
) -> None:
    payload = document()
    account = payload["accounts"][0]
    account["limits"] = [limit()]
    account["tracker_evidence"] = [tracker(reset_generation="main-5h-r7")]
    evidence.publish(payload)

    result = read(evidence)
    assert result.status == "complete"
    assert result.automatic_decisions_allowed


def test_main_only_golden_consumer_omits_unavailable_spark(
    evidence: EvidenceTree, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = document()
    account = payload["accounts"][0]
    account["limits"] = [limit()]
    account["tracker_evidence"] = [tracker(reset_generation="main-5h-r7")]
    evidence.publish(payload)
    monkeypatch.setattr(limit_tracker, "_production_paths", evidence.paths)
    monkeypatch.setattr(limit_tracker, "_utc_now", lambda: NOW)

    result = limit_tracker.evaluate_account("BW_Nufker")
    assert result["status"] == "complete"
    assert result["main"]["pool"] == "main"
    assert "spark" not in result


def test_opaque_reset_generation_is_valid_and_independent_from_reset_at(
    evidence: EvidenceTree,
) -> None:
    payload = document()
    for item in payload["accounts"][0]["tracker_evidence"]:
        item["reset_generation"] = "main-5h-r7"
    evidence.publish(payload)

    assert read(evidence).status == "complete"


@pytest.mark.parametrize(
    ("reset_generation", "expected"),
    [("x" * 128, "complete"), ("x" * 129, "invalid"), ("bad token", "invalid")],
)
def test_reset_generation_is_bounded_printable_token(
    evidence: EvidenceTree, reset_generation: str, expected: str
) -> None:
    payload = document()
    for item in payload["accounts"][0]["tracker_evidence"]:
        item["reset_generation"] = reset_generation
    evidence.publish(payload)

    assert read(evidence).status == expected


@pytest.mark.parametrize(
    ("mutation", "expected_status", "automatic"),
    [
        (
            lambda payload: payload.update(generated_at="2026-08-26T18:14:01Z"),
            "stale",
            False,
        ),
        (
            lambda payload: payload["accounts"][0]["freshness"].update(
                fresh_until="2026-08-26T18:14:01Z"
            ),
            "invalid",
            False,
        ),
        (
            lambda payload: payload["accounts"][0]["tracker_evidence"][0].update(
                last_sample_at="2026-08-26T17:45:00Z"
            ),
            "complete",
            True,
        ),
        (
            lambda payload: payload["accounts"][0]["tracker_evidence"][0].update(
                last_sample_at="2026-08-26T17:44:59Z"
            ),
            "invalid",
            False,
        ),
        (
            lambda payload: payload["accounts"][0]["tracker_evidence"][0].update(
                coverage="stale", last_sample_at="2026-08-26T17:44:59Z"
            ),
            "stale",
            False,
        ),
        (
            lambda payload: payload["accounts"][0]["limits"][1].pop("reset_at"),
            "partial",
            False,
        ),
        (
            lambda payload: payload["accounts"][0]["limits"][1].update(
                reset_at="2026-08-26T17:59:59Z"
            ),
            "partial",
            False,
        ),
        (
            lambda payload: payload["accounts"][0]["tracker_evidence"][0].update(
                rate_percentage_points_per_second=100.0
            ),
            "complete",
            True,
        ),
        (
            lambda payload: payload["accounts"][0]["tracker_evidence"][0].update(
                rate_percentage_points_per_second=100.000_001
            ),
            "invalid",
            False,
        ),
        (
            lambda payload: payload["accounts"][0]["tracker_evidence"][0].update(
                projected_used_percent_at_reset=100.000_001
            ),
            "invalid",
            False,
        ),
        (
            lambda payload: payload["accounts"][0]["tracker_evidence"][0].update(
                projected_used_percent_at_reset=-0.000_001
            ),
            "invalid",
            False,
        ),
        (
            lambda payload: payload["accounts"][0]["limits"][1].update(
                remaining_percent=40.000000001
            ),
            "complete",
            True,
        ),
        (
            lambda payload: payload["accounts"][0]["limits"][1].update(
                remaining_percent=40.00000001
            ),
            "invalid",
            False,
        ),
        (
            lambda payload: payload["accounts"][0]["tracker_evidence"][0].update(
                sample_count=500_000
            ),
            "complete",
            True,
        ),
        (
            lambda payload: payload["accounts"][0]["tracker_evidence"][0].update(
                sample_count=500_001
            ),
            "invalid",
            False,
        ),
    ],
)
def test_freshness_reset_and_tracker_quality_boundaries(
    evidence: EvidenceTree,
    mutation: Any,
    expected_status: str,
    automatic: bool,
) -> None:
    payload = document()
    mutation(payload)
    evidence.publish(payload)

    result = read(evidence)
    assert result.status == expected_status
    assert result.automatic_decisions_allowed is automatic


def test_valid_credits_limit_is_not_a_tracker_pool(evidence: EvidenceTree) -> None:
    payload = document()
    payload["accounts"][0]["limits"].append(limit(pool="credits", window=2_592_000))
    evidence.publish(payload)

    result = read(evidence)
    assert result.status == "complete"
    assert result.automatic_decisions_allowed


@pytest.mark.parametrize("status", ["error", "login_required", "unknown"])
def test_status_only_accounts_are_valid_but_not_automatic(
    evidence: EvidenceTree, status: str
) -> None:
    payload = document(status=status)
    payload["accounts"][0]["limits"] = []
    payload["accounts"][0]["tracker_evidence"] = []
    evidence.publish(payload)

    result = read(evidence)
    assert result.status == "partial"
    assert not result.automatic_decisions_allowed


@pytest.mark.parametrize("account_id", ["contains space", "path/account"])
def test_account_id_must_match_schema_token(
    evidence: EvidenceTree, account_id: str
) -> None:
    payload = document()
    payload["accounts"][0]["account_id"] = account_id
    evidence.publish(payload)

    assert read(evidence).status == "invalid"


def test_limit_pool_cannot_be_local_path_form(evidence: EvidenceTree) -> None:
    payload = document()
    payload["accounts"][0]["limits"][0]["pool"] = "/tmp/credits"
    evidence.publish(payload)

    assert read(evidence).status == "invalid"


@pytest.mark.parametrize(
    ("extra_limits", "expected"), [(30, "complete"), (31, "invalid")]
)
def test_per_account_limit_and_tracker_count_boundary(
    evidence: EvidenceTree, extra_limits: int, expected: str
) -> None:
    payload = document()
    payload["accounts"][0]["limits"].extend(
        limit(pool=f"source-{index}", window=604_800) for index in range(extra_limits)
    )
    evidence.publish(payload)

    assert read(evidence).status == expected


def test_all_allowlisted_windows_are_valid_for_matched_main_trends(
    evidence: EvidenceTree,
) -> None:
    payload = document()
    for window in (604_800, 2_592_000):
        payload["accounts"][0]["limits"].append(limit(pool="main", window=window))
        payload["accounts"][0]["tracker_evidence"].append(
            tracker(pool="main", window=window)
        )
    evidence.publish(payload)

    assert read(evidence).status == "complete"


def test_tracker_pool_cannot_be_credits(evidence: EvidenceTree) -> None:
    payload = document()
    payload["accounts"][0]["limits"].append(limit(pool="credits", window=2_592_000))
    payload["accounts"][0]["tracker_evidence"].append(
        tracker(pool="credits", window=2_592_000)
    )
    evidence.publish(payload)

    assert read(evidence).status == "invalid"


def test_account_id_accepts_schema_maximum(evidence: EvidenceTree) -> None:
    payload = document()
    payload["accounts"][0]["account_id"] = "a" * 64
    evidence.publish(payload)

    assert read(evidence).status == "complete"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(schema_version=1),
        lambda payload: payload.update(extra=True),
        lambda payload: payload["accounts"][0]["limits"][0].update(
            window_seconds=3_600
        ),
        lambda payload: payload["accounts"][0]["tracker_evidence"][0].update(
            extra=True
        ),
        lambda payload: payload["accounts"][0]["tracker_evidence"][0].update(
            ema_time_constant_seconds=600
        ),
    ],
)
def test_schema_field_window_and_ema_fail_closed(
    evidence: EvidenceTree, mutation: Any
) -> None:
    payload = document()
    mutation(payload)
    evidence.publish(payload)
    assert read(evidence).status == "invalid"


@pytest.mark.parametrize(
    ("target", "value"),
    [
        ("payload", True),
        ("payload", 2.0),
        ("payload", "2"),
        ("pointer", True),
        ("pointer", 1.0),
        ("pointer", "1"),
        ("binding", True),
        ("binding", 1.0),
        ("binding", "1"),
        ("active", True),
        ("active", 2.0),
        ("active", "2"),
    ],
)
def test_all_schema_versions_require_exact_integer_type(
    evidence: EvidenceTree, target: str, value: object
) -> None:
    binding_path = evidence.generations / GENERATION / "account-usage-v2.binding.json"
    pointer_path = evidence.integration / "current.json"
    if target == "payload":
        payload = document()
        payload["schema_version"] = value
        evidence.publish(payload)
    elif target == "pointer":
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        pointer["pointer_schema_version"] = value
        private_file(pointer_path, canonical(pointer))
    elif target == "binding":
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        binding["binding_schema_version"] = value
        private_file(binding_path, canonical(binding))
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        pointer["current_binding_sha256"] = hashlib.sha256(
            binding_path.read_bytes()
        ).hexdigest()
        private_file(pointer_path, canonical(pointer))
    else:
        active_path = evidence.integration / "active.json"
        active = json.loads(active_path.read_text(encoding="utf-8"))
        active["schema_version"] = value
        private_file(active_path, canonical(active))
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        binding["active_manifest_sha256"] = hashlib.sha256(
            active_path.read_bytes()
        ).hexdigest()
        private_file(binding_path, canonical(binding))
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        pointer["current_binding_sha256"] = hashlib.sha256(
            binding_path.read_bytes()
        ).hexdigest()
        private_file(pointer_path, canonical(pointer))

    result = read(evidence)
    assert result.status == "invalid"
    assert not result.automatic_decisions_allowed


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (document(stale=True), "stale"),
        (document(status="partial"), "partial"),
    ],
)
def test_stale_and_partial_are_not_automatic(
    evidence: EvidenceTree, payload: dict[str, object], expected: str
) -> None:
    evidence.publish(payload)
    result = read(evidence)
    assert result.status == expected
    assert not result.automatic_decisions_allowed


def test_insufficient_tracker_is_partial(evidence: EvidenceTree) -> None:
    payload = document()
    item = payload["accounts"][0]["tracker_evidence"][0]
    item.update(
        coverage="insufficient", sample_count=1, rate_percentage_points_per_second=0.0
    )
    evidence.publish(payload)
    result = read(evidence)
    assert result.status == "partial"
    assert not result.automatic_decisions_allowed


def test_main_and_spark_are_never_interchanged(evidence: EvidenceTree) -> None:
    payload = document()
    payload["accounts"][0]["tracker_evidence"][0]["pool"] = "gpt-5.3-codex-spark"
    evidence.publish(payload)
    assert read(evidence).status == "invalid"


@pytest.mark.parametrize("part", ["generation", "binding", "payload", "release"])
def test_generation_digest_and_release_drift_fail_closed(
    evidence: EvidenceTree, part: str
) -> None:
    if part == "generation":
        pointer = json.loads((evidence.integration / "current.json").read_text())
        pointer["current_generation_id"] = "f" * 32
        private_file(evidence.integration / "current.json", canonical(pointer))
    elif part == "binding":
        pointer = json.loads((evidence.integration / "current.json").read_text())
        pointer["current_binding_sha256"] = "f" * 64
        private_file(evidence.integration / "current.json", canonical(pointer))
    elif part == "payload":
        binding_path = (
            evidence.generations / GENERATION / "account-usage-v2.binding.json"
        )
        binding = json.loads(binding_path.read_text())
        binding["payload_sha256"] = "f" * 64
        private_file(binding_path, canonical(binding))
        pointer = json.loads((evidence.integration / "current.json").read_text())
        pointer["current_binding_sha256"] = hashlib.sha256(
            binding_path.read_bytes()
        ).hexdigest()
        private_file(evidence.integration / "current.json", canonical(pointer))
    else:
        binding_path = (
            evidence.generations / GENERATION / "account-usage-v2.binding.json"
        )
        binding = json.loads(binding_path.read_text())
        binding["release_id"] = "0.6.536-" + "f" * 16
        private_file(binding_path, canonical(binding))
        pointer = json.loads((evidence.integration / "current.json").read_text())
        pointer["current_binding_sha256"] = hashlib.sha256(
            binding_path.read_bytes()
        ).hexdigest()
        private_file(evidence.integration / "current.json", canonical(pointer))
    assert read(evidence).status == "invalid"


def test_reader_pre_post_race_fails_closed(
    evidence: EvidenceTree, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutate(_fd: int, _name: str, _held: int) -> None:
        payload_path = evidence.generations / GENERATION / "account-usage-v2.json"
        private_file(payload_path, payload_path.read_bytes() + b" ")

    monkeypatch.setattr(limit_tracker, "_before_payload_recheck", mutate)
    assert read(evidence).status == "invalid"


def test_release_artifact_identity_race_fails_closed(
    evidence: EvidenceTree, monkeypatch: pytest.MonkeyPatch
) -> None:
    def replace_artifact() -> None:
        replacement = evidence.entrypoint.with_name("replacement.py")
        private_file(replacement, evidence.entrypoint.read_bytes())
        os.replace(replacement, evidence.entrypoint)

    monkeypatch.setattr(
        limit_tracker, "_before_release_recheck", replace_artifact, raising=False
    )

    assert read(evidence).status == "invalid"


@pytest.mark.parametrize("target", ["active", "current", "release", "release_parent"])
def test_active_current_and_release_races_fail_closed(
    evidence: EvidenceTree, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    def replace(_fd: int, _name: str, _held: int) -> None:
        if target == "active":
            path = evidence.integration / "active.json"
            replacement = evidence.root / "replacement-active.json"
            private_file(replacement, path.read_bytes())
            os.replace(replacement, path)
        elif target == "current":
            path = evidence.integration / "current.json"
            replacement = evidence.root / "replacement-current.json"
            private_file(replacement, path.read_bytes())
            os.replace(replacement, path)
        elif target == "release":
            moved = evidence.root / "replaced-release"
            evidence.release.rename(moved)
            private_dir(evidence.release)
        else:
            evidence.releases.chmod(0o750)

    monkeypatch.setattr(limit_tracker, "_before_payload_recheck", replace)

    assert read(evidence).status == "invalid"


def test_current_generation_namespace_must_contain_exactly_two_files(
    evidence: EvidenceTree,
) -> None:
    private_file(evidence.generations / GENERATION / "unexpected.json", b"{}")

    assert read(evidence).status == "invalid"


@pytest.mark.parametrize(
    "kind",
    ["symlink", "hardlink", "directory", "mode", "oversize", "malformed", "extra"],
)
def test_previous_generation_is_fully_validated(
    evidence: EvidenceTree, kind: str
) -> None:
    binding_path = add_previous_generation(evidence)
    generation = binding_path.parent
    payload_path = generation / "account-usage-v2.json"
    if kind == "symlink":
        external = evidence.root / "previous-payload-target"
        private_file(external, payload_path.read_bytes())
        payload_path.unlink()
        payload_path.symlink_to(external)
    elif kind == "hardlink":
        external = evidence.root / "previous-payload-target"
        private_file(external, payload_path.read_bytes())
        payload_path.unlink()
        os.link(external, payload_path)
    elif kind == "directory":
        payload_path.unlink()
        private_dir(payload_path)
    elif kind == "mode":
        payload_path.chmod(0o640)
    elif kind == "oversize":
        private_file(payload_path, b"x" * (2 * 1024 * 1024 + 1))
    elif kind == "malformed":
        private_file(payload_path, b"{")
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        binding["payload_sha256"] = hashlib.sha256(
            payload_path.read_bytes()
        ).hexdigest()
        binding["payload_size_bytes"] = payload_path.stat().st_size
        private_file(binding_path, canonical(binding))
        pointer_path = evidence.integration / "current.json"
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        pointer["previous_binding_sha256"] = hashlib.sha256(
            binding_path.read_bytes()
        ).hexdigest()
        private_file(pointer_path, canonical(pointer))
    else:
        private_file(generation / "unexpected.json", b"{}")

    assert read(evidence).status == "invalid"


def test_previous_historical_payload_is_checked_at_its_own_generation_time(
    evidence: EvidenceTree,
) -> None:
    binding_path = add_previous_generation(evidence)
    payload_path = binding_path.with_name("account-usage-v2.json")
    payload = document()
    payload["generated_at"] = "2026-08-25T17:59:00Z"
    account = payload["accounts"][0]
    account["freshness"].update(
        captured_at="2026-08-25T17:59:00Z",
        fresh_until="2026-08-25T18:14:00Z",
    )
    for item in account["tracker_evidence"]:
        item.update(
            first_sample_at="2026-08-25T16:00:00Z",
            last_sample_at="2026-08-25T17:59:00Z",
        )
    private_file(payload_path, canonical(payload))
    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    binding["payload_sha256"] = hashlib.sha256(payload_path.read_bytes()).hexdigest()
    binding["payload_size_bytes"] = payload_path.stat().st_size
    binding["published_at"] = payload["generated_at"]
    private_file(binding_path, canonical(binding))
    pointer_path = evidence.integration / "current.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    pointer["previous_binding_sha256"] = hashlib.sha256(
        binding_path.read_bytes()
    ).hexdigest()
    private_file(pointer_path, canonical(pointer))

    assert read(evidence).status == "complete"


def test_previous_binding_keeps_its_historical_active_release_identity(
    evidence: EvidenceTree,
) -> None:
    binding_path = add_previous_generation(evidence)
    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    binding.update(
        active_manifest_sha256="a" * 64,
        release_id="0.6.536-" + "b" * 16,
        source_manifest_sha256="c" * 64,
    )
    private_file(binding_path, canonical(binding))
    pointer_path = evidence.integration / "current.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    pointer["previous_binding_sha256"] = hashlib.sha256(
        binding_path.read_bytes()
    ).hexdigest()
    private_file(pointer_path, canonical(pointer))

    assert read(evidence).status == "complete"


def test_previous_binding_must_keep_valid_historical_identity_form(
    evidence: EvidenceTree,
) -> None:
    binding_path = add_previous_generation(evidence)
    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    binding["active_manifest_sha256"] = "a" * 63
    private_file(binding_path, canonical(binding))
    pointer_path = evidence.integration / "current.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    pointer["previous_binding_sha256"] = hashlib.sha256(
        binding_path.read_bytes()
    ).hexdigest()
    private_file(pointer_path, canonical(pointer))

    assert read(evidence).status == "invalid"


@pytest.mark.parametrize(
    "target",
    ["previous_binding", "previous_payload", "previous_generation", "lock_parent"],
)
def test_transaction_rechecks_previous_and_lock_proofs(
    evidence: EvidenceTree, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    previous_binding = add_previous_generation(evidence)

    def mutate(_fd: int, _name: str, _held: int) -> None:
        if target == "previous_binding":
            private_file(previous_binding, previous_binding.read_bytes())
        elif target == "previous_payload":
            payload_path = previous_binding.with_name("account-usage-v2.json")
            private_file(payload_path, payload_path.read_bytes())
        elif target == "previous_generation":
            previous_binding.parent.chmod(0o750)
        else:
            evidence.lock_root.chmod(0o750)

    monkeypatch.setattr(limit_tracker, "_before_payload_recheck", mutate)

    assert read(evidence).status == "invalid"


@pytest.mark.parametrize(
    ("target", "kind"),
    [
        ("active", "symlink"),
        ("active", "hardlink"),
        ("current", "symlink"),
        ("current", "hardlink"),
        ("release", "symlink"),
        ("release", "hardlink"),
    ],
)
def test_active_current_and_release_no_follow_link_boundaries(
    evidence: EvidenceTree, target: str, kind: str
) -> None:
    if target == "release":
        if kind == "symlink":
            moved = evidence.root / "saved-release"
            evidence.release.rename(moved)
            evidence.release.symlink_to(moved, target_is_directory=True)
        else:
            external = evidence.root / "entrypoint-target"
            private_file(external, evidence.entrypoint.read_bytes())
            evidence.entrypoint.unlink()
            os.link(external, evidence.entrypoint)
    else:
        path = evidence.integration / f"{target}.json"
        external = evidence.root / f"{target}-target"
        private_file(external, path.read_bytes())
        path.unlink()
        if kind == "symlink":
            path.symlink_to(external)
        else:
            os.link(external, path)

    assert read(evidence).status == "invalid"


@pytest.mark.parametrize("parent", ["integration", "releases"])
def test_active_current_and_release_parent_mode_boundaries(
    evidence: EvidenceTree, parent: str
) -> None:
    getattr(evidence, parent).chmod(0o750)

    assert read(evidence).status == "invalid"


@pytest.mark.parametrize(
    "kind", ["symlink", "hardlink", "mode", "oversize", "parent_mode"]
)
def test_file_and_parent_security_fail_closed(
    evidence: EvidenceTree, kind: str
) -> None:
    payload_path = evidence.generations / GENERATION / "account-usage-v2.json"
    if kind == "symlink":
        original = payload_path.with_name("saved")
        payload_path.rename(original)
        payload_path.symlink_to(original)
    elif kind == "hardlink":
        os.link(payload_path, payload_path.with_name("extra-link"))
    elif kind == "mode":
        payload_path.chmod(0o640)
    elif kind == "oversize":
        private_file(payload_path, b"x" * (2 * 1024 * 1024 + 1))
    else:
        evidence.generations.chmod(0o750)
    assert read(evidence).status == "invalid"


def test_owner_validation_is_exact() -> None:
    item = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_uid=os.geteuid() + 1,
        st_nlink=1,
        st_size=1,
    )
    with pytest.raises(limit_tracker._InvalidEvidence):
        limit_tracker._validate_private_file(item, maximum=2)


def test_lock_unavailable_busy_and_invalid_are_distinct(evidence: EvidenceTree) -> None:
    release_name = limit_tracker._lock_name(evidence.producer_install)
    release_lock = evidence.lock_root / release_name
    release_lock.unlink()
    assert read(evidence).status == "unavailable"
    private_file(release_lock, b"")
    release_lock.chmod(0o640)
    assert read(evidence).status == "invalid"
    release_lock.chmod(0o600)
    with release_lock.open("r+b", buffering=0) as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert read(evidence).status == "busy"


def test_imported_consumer_reads_real_evidence_boundary(
    evidence: EvidenceTree, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(limit_tracker, "_production_paths", evidence.paths)
    monkeypatch.setattr(limit_tracker, "_utc_now", lambda: NOW)
    result = limit_tracker.evaluate_account("BW_Nufker", active_fast=False)
    assert result["status"] == "complete"
    assert result["recommended_action"] == "activate"
    assert result["main"]["pool"] == "main"
    assert result["spark"]["pool"] == "gpt-5.3-codex-spark"
    assert result["spark"]["recommended_action"] == "activate"
    evidence.publish(document(stale=True))
    blocked = limit_tracker.evaluate_account("BW_Nufker", active_fast=False)
    assert blocked["recommended_action"] == "flex"
    assert blocked["error_code"] == "usage_evidence_producer_unavailable"


def test_preferred_window_accepts_only_schema2() -> None:
    assert limit_tracker.preferred_delta_window(document(), pool="main") == "5h"
    assert limit_tracker.preferred_delta_window({"weekly": {}}, pool="main") is None
    assert limit_tracker.preferred_delta_window(document(), pool="spark") == "5h"


def test_refresh_is_consumer_reread_not_legacy_or_provider_call() -> None:
    result = limit_tracker.refresh_usage_snapshots()
    assert result == {
        "attempted": False,
        "ok": False,
        "status": "unavailable",
        "error_code": "usage_evidence_producer_unavailable",
    }


def test_spark_priority_and_display_state_are_bounded() -> None:
    assert limit_tracker.set_spark_priority("acct", enabled=True, reason="need") == {
        "account": "acct",
        "active": True,
        "reason": "need",
    }
    assert limit_tracker.spark_priority_active("acct")
    assert not limit_tracker.set_spark_priority("acct", enabled=False)["active"]
    display = limit_tracker.set_emergency_display_override(
        "acct", enabled=True, limit_window="5h", reason="need"
    )
    assert display["enabled"] is True
    with pytest.raises(ValueError, match="limit_tracker_input_invalid"):
        limit_tracker.set_spark_priority("x" * 65, enabled=True)


def test_emergency_queen_state_machine_is_generation_bound() -> None:
    limit_tracker._reset_runtime_state_for_tests()
    requested = limit_tracker.request_emergency_queen_work(reason="approved-plan")
    generation = requested["state"]["generation"]
    assert requested["queued"] is True
    running = limit_tracker.set_emergency_queen_running(generation, "q1")
    assert running["updated"] is True
    assert (
        limit_tracker.register_emergency_queen_child(generation, "w1")["updated"]
        is True
    )
    assert (
        limit_tracker.unregister_emergency_queen_child(generation, "w1")["updated"]
        is True
    )
    next_state = limit_tracker.advance_emergency_queen(
        generation, emergency_active=True, completed_plan="approved-plan"
    )
    assert next_state["state"]["state"] == "next"
    draining = limit_tracker.advance_emergency_queen(
        generation, emergency_active=False, completed_plan="approved-plan"
    )
    assert draining["state"]["state"] == "draining"
    assert limit_tracker.finish_emergency_queen(generation)["updated"] is True
    assert limit_tracker.emergency_queen_status()["state"] == "idle"


def test_emergency_recommendation_and_refresh_gate_fail_closed() -> None:
    incomplete = {"status": "partial", "recommended_action": "activate"}
    assert (
        limit_tracker.emergency_recommendation(incomplete, active_fast=False) == "flex"
    )
    assert not limit_tracker.emergency_refresh_needed(incomplete, active_fast=False)
    complete = {
        "status": "complete",
        "recommended_action": "activate",
        "hot_window": True,
    }
    assert (
        limit_tracker.emergency_recommendation(complete, active_fast=False)
        == "activate"
    )
    assert limit_tracker.emergency_refresh_needed(complete, active_fast=False)
