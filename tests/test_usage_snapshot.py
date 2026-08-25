from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import codex_master.usage_snapshot as usage_snapshot


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def private_file(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def active_manifest() -> dict[str, object]:
    return {
        "active_manifest_schema_version": 2,
        "entry_point": "codex_usage.cli:main",
        "launcher_sha256": "b" * 64,
        "producer_version": "0.6.536",
        "record_sha256": "c" * 64,
        "release_id": "0.6.536-test-release",
        "release_tree_sha256": "d" * 64,
        "source_manifest_sha256": "e" * 64,
        "wheel_sha256": "f" * 64,
    }


def payload_document(
    *, status: str = "complete", last_sample_at: datetime | None = None
) -> dict[str, object]:
    captured_at = NOW - timedelta(minutes=1)
    generated_at = NOW
    return {
        "accounts": [
            {
                "account_id": "alpha",
                "limits": [
                    {
                        "pool": "main",
                        "remaining_percent": 75.0,
                        "reset_at": iso(NOW + timedelta(hours=1)),
                        "reset_generation": "reset-main-1",
                        "used_percent": 25.0,
                        "window_seconds": 18000,
                    }
                ],
                "tracker_evidence": [
                    {
                        "coverage": "complete",
                        "last_sample_at": iso(last_sample_at or NOW),
                        "pool": "main",
                        "reset_generation": "reset-main-1",
                        "window_seconds": 18000,
                    }
                ],
                "trends": [
                    {
                        "coverage": "complete",
                        "last_sample_at": iso(last_sample_at or NOW),
                        "pool": "main",
                        "projected_exhaustion_at": iso(NOW + timedelta(minutes=30)),
                        "reset_generation": "reset-main-1",
                        "window_seconds": 18000,
                    }
                ],
            }
        ],
        "captured_at": iso(captured_at),
        "fresh_until": iso(captured_at + timedelta(seconds=900)),
        "generated_at": iso(generated_at),
        "schema_version": 2,
        "status": status,
    }


def write_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, Path]]:
    state_home = tmp_path / "state"
    integration = state_home / "codex-usage" / "integration"
    generation_id = "a" * 32
    generation = integration / "generations" / generation_id
    staging = integration / "staging"
    lock_home = tmp_path / "lock-home"
    for directory in (
        state_home,
        state_home / "codex-usage",
        integration,
        integration / "generations",
        generation,
        staging,
        lock_home,
        lock_home / ".local",
        lock_home / ".local" / "state",
        lock_home / ".local" / "state" / "codex-usage",
        lock_home / ".local" / "state" / "codex-usage" / "locks",
    ):
        private_dir(directory)
    locks = lock_home / ".local" / "state" / "codex-usage" / "locks"
    private_file(locks / "release.lock", b"")
    private_file(locks / "current.lock", b"")
    active = active_manifest()
    active_bytes = canonical(active)
    active_path = integration / "active.json"
    private_file(active_path, active_bytes)
    document = payload_document()
    payload = canonical(document)
    payload_path = generation / "account-usage-v2.json"
    private_file(payload_path, payload)
    binding = {
        "active_manifest_sha256": digest(active_bytes),
        "binding_schema_version": 2,
        "generation_id": generation_id,
        "payload_filename": "account-usage-v2.json",
        "payload_sha256": digest(payload),
        "payload_size_bytes": len(payload),
        "producer_version": active["producer_version"],
        "published_at": iso(NOW),
        "release_id": active["release_id"],
        "source_manifest_sha256": active["source_manifest_sha256"],
    }
    binding_path = generation / "account-usage-v2.binding.json"
    private_file(binding_path, canonical(binding))
    pointer = {
        "current_binding_sha256": digest(canonical(binding)),
        "current_generation_id": generation_id,
        "pointer_schema_version": 2,
        "previous_binding_sha256": None,
        "previous_generation_id": None,
    }
    pointer_path = integration / "current.json"
    private_file(pointer_path, canonical(pointer))
    monkeypatch.setattr(
        usage_snapshot,
        "pwd",
        SimpleNamespace(getpwuid=lambda _uid: SimpleNamespace(pw_dir=str(lock_home))),
        raising=False,
    )
    return state_home, {
        "active": active_path,
        "binding": binding_path,
        "payload": payload_path,
        "pointer": pointer_path,
    }


def rebind(paths: dict[str, Path]) -> None:
    binding = json.loads(paths["binding"].read_text(encoding="utf-8"))
    payload = paths["payload"].read_bytes()
    binding["payload_sha256"] = digest(payload)
    binding["payload_size_bytes"] = len(payload)
    binding_bytes = canonical(binding)
    private_file(paths["binding"], binding_bytes)
    pointer = json.loads(paths["pointer"].read_text(encoding="utf-8"))
    pointer["current_binding_sha256"] = digest(binding_bytes)
    private_file(paths["pointer"], canonical(pointer))


def read(state_home: Path):
    return usage_snapshot.read_usage_evidence_v2(
        state_home=state_home, clock=lambda: NOW
    )


def test_v2_chain_returns_fresh_reset_consistent_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, _paths = write_chain(tmp_path, monkeypatch)

    result = read(state_home)

    assert result.status == "complete"
    assert result.accounts[0].account_id == "alpha"
    assert result.accounts[0].limits[0].reset_generation == "reset-main-1"
    assert result.accounts[0].tracker_evidence[0].window_seconds == 18000


@pytest.mark.parametrize(
    ("target", "expected_status"),
    [
        ("pointer", "unavailable"),
        ("active", "invalid"),
        ("binding", "invalid"),
        ("payload", "invalid"),
    ],
)
def test_missing_chain_file_has_fail_closed_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    expected_status: str,
) -> None:
    state_home, paths = write_chain(tmp_path, monkeypatch)
    paths[target].unlink()

    assert read(state_home).status == expected_status


def test_contended_lock_is_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, _paths = write_chain(tmp_path, monkeypatch)

    def blocked_lock(*_args: object) -> None:
        raise BlockingIOError()

    monkeypatch.setattr(
        usage_snapshot,
        "fcntl",
        SimpleNamespace(LOCK_NB=4, LOCK_SH=1, flock=blocked_lock),
        raising=False,
    )

    assert read(state_home).status == "busy"


@pytest.mark.parametrize(
    "target, mutate",
    [
        ("active", lambda value: value.update({"active_manifest_schema_version": 1})),
        ("pointer", lambda value: value.update({"unknown": True})),
        ("binding", lambda value: value.update({"generation_id": "b" * 32})),
        ("payload", lambda value: value.update({"schema_version": 1})),
        (
            "payload",
            lambda value: value["accounts"][0]["limits"][0].update(
                {"window_seconds": 60}
            ),
        ),
        (
            "payload",
            lambda value: value["accounts"][0]["limits"][0].update(
                {"remaining_percent": float("nan")}
            ),
        ),
        (
            "payload",
            lambda value: value["accounts"][0]["trends"].append(
                value["accounts"][0]["trends"][0].copy()
            ),
        ),
        ("payload", lambda value: value.update({"fresh_until": iso(NOW)})),
        (
            "payload",
            lambda value: value["accounts"][0]["tracker_evidence"][0].update(
                {"reset_generation": "other"}
            ),
        ),
    ],
)
def test_schema_binding_bounds_time_and_pool_violations_are_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    mutate: object,
) -> None:
    state_home, paths = write_chain(tmp_path, monkeypatch)
    value = json.loads(paths[target].read_text(encoding="utf-8"))
    assert callable(mutate)
    mutate(value)
    private_file(paths[target], canonical(value))
    if target == "payload":
        rebind(paths)

    assert read(state_home).status == "invalid"


@pytest.mark.parametrize("target", ["pointer", "binding", "payload"])
def test_noncanonical_json_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    state_home, paths = write_chain(tmp_path, monkeypatch)
    raw = paths[target].read_bytes()
    private_file(paths[target], b" " + raw)
    if target == "payload":
        rebind(paths)

    assert read(state_home).status == "invalid"


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "mode"])
def test_filesystem_substitution_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    state_home, paths = write_chain(tmp_path, monkeypatch)
    payload = paths["payload"]
    if unsafe == "symlink":
        outside = tmp_path / "outside.json"
        private_file(outside, payload.read_bytes())
        payload.unlink()
        payload.symlink_to(outside)
    elif unsafe == "hardlink":
        replacement = payload.with_name("linked.json")
        os.link(payload, replacement)
    else:
        payload.chmod(0o644)

    assert read(state_home).status == "invalid"


def test_payload_name_swap_after_open_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_chain(tmp_path, monkeypatch)
    original_read = os.read
    payload_inode = payload_inode_before = paths["payload"].stat().st_ino
    swapped = False

    def swap_after_open(descriptor: int, count: int) -> bytes:
        nonlocal swapped
        if not swapped and os.fstat(descriptor).st_ino == payload_inode:
            swapped = True
            replacement = paths["payload"].with_name("replacement.json")
            private_file(replacement, canonical(payload_document()))
            os.replace(replacement, paths["payload"])
        return original_read(descriptor, count)

    monkeypatch.setattr(usage_snapshot.os, "read", swap_after_open)

    assert read(state_home).status == "invalid"
    assert swapped is True
    assert payload_inode_before != paths["payload"].stat().st_ino


def test_stale_and_partial_are_data_statuses_without_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_chain(tmp_path, monkeypatch)
    document = payload_document(last_sample_at=NOW - timedelta(seconds=901))
    private_file(paths["payload"], canonical(document))
    rebind(paths)

    assert read(state_home).status == "stale"

    document = payload_document(status="partial")
    private_file(paths["payload"], canonical(document))
    rebind(paths)

    assert read(state_home).status == "partial"
