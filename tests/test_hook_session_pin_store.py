from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from the_hive.hook_session_pin_store import (
    HookSessionPinStoreError,
    HookSessionPinStoreV1,
    ReclamationEvidenceV1,
)


ABI_V1 = "/usr/local/libexec/the-hive/hook-abi/v1/launcher"
DAY_NS = 24 * 60 * 60 * 1_000_000_000
HOOKS = {
    "native_bee_event": "sha256:" + "a" * 64,
    "native_spawn_admission": "sha256:" + "b" * 64,
}


def _store(tmp_path: Path) -> HookSessionPinStoreV1:
    return HookSessionPinStoreV1.create_at(
        tmp_path / "home" / ".local" / "state" / "the-hive" / "hook-session-pins-v1"
    )


def _bind(store: HookSessionPinStoreV1, *, now: int = 10) -> dict[str, object]:
    return store.bind_session(
        session_id="session-a",
        generation="generation-a",
        runtime_manifest_digest="sha256:" + "c" * 64,
        hooks=HOOKS,
        now_unix_ns=now,
    )


def test_pin_store_creates_private_nofollow_lock_and_digest_bound_binding(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    binding = _bind(store)

    assert binding["schema"] == "HookSessionBindingV1"
    assert binding["launcher_abi"] == ABI_V1
    assert (
        binding["content_digest"]
        == "sha256:"
        + hashlib.sha256(
            b'{"created_at_unix_ns":10,"ended_at_unix_ns":null,"generation":"generation-a","hooks":{"native_bee_event":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","native_spawn_admission":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"last_seen_at_unix_ns":10,"launcher_abi":"/usr/local/libexec/the-hive/hook-abi/v1/launcher","orphan_candidate_at_unix_ns":null,"revalidations":[],"runtime_manifest_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","schema":"HookSessionBindingV1","session_id":"session-a","state":"active","state_transitions":[{"at_unix_ns":10,"state":"active"}],"store_generation":1}\n'
        ).hexdigest()
    )
    assert store.bindings() == {"session-a": binding}


def test_session_end_retains_exactly_24_hours_and_stop_style_touches_do_not_release(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _bind(store, now=10)
    store.bind_session(
        session_id="session-a",
        generation="generation-a",
        runtime_manifest_digest="sha256:" + "c" * 64,
        hooks=HOOKS,
        now_unix_ns=20,
    )
    ended = store.end_session(session_id="session-a", now_unix_ns=30)

    assert ended["ended_at_unix_ns"] == 30
    assert store.retained_generations(now_unix_ns=30 + DAY_NS - 1) == {"generation-a"}
    assert store.retained_generations(now_unix_ns=30 + DAY_NS) == set()


def test_unended_orphan_requires_30_days_seven_day_quarantine_two_day_spaced_reads(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _bind(store, now=0)
    absent = {
        "session-a": ReclamationEvidenceV1(
            session_file_present=False,
            process_present=False,
            writer_lock_present=False,
            certain=True,
        )
    }

    assert store.reclaim_orphans(now_unix_ns=30 * DAY_NS - 1, evidence=absent) == set()
    assert store.reclaim_orphans(now_unix_ns=30 * DAY_NS, evidence=absent) == set()
    assert store.bindings()["session-a"]["state"] == "orphan_candidate"
    assert store.reclaim_orphans(now_unix_ns=37 * DAY_NS - 1, evidence=absent) == set()
    assert store.reclaim_orphans(now_unix_ns=37 * DAY_NS, evidence=absent) == set()
    assert store.reclaim_orphans(now_unix_ns=38 * DAY_NS - 1, evidence=absent) == set()
    assert store.reclaim_orphans(now_unix_ns=38 * DAY_NS, evidence=absent) == {
        "session-a"
    }
    assert store.bindings() == {}


def test_uncertainty_or_time_rollback_clears_orphan_reclamation_and_retains_pin(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _bind(store, now=10)
    absent = {"session-a": ReclamationEvidenceV1(False, False, False, certain=True)}
    store.reclaim_orphans(now_unix_ns=30 * DAY_NS + 10, evidence=absent)
    assert store.bindings()["session-a"]["state"] == "orphan_candidate"

    assert store.reclaim_orphans(now_unix_ns=1, evidence=None) == set()
    binding = store.bindings()["session-a"]
    assert binding["state"] == "active"
    assert binding["orphan_candidate_at_unix_ns"] is None
    assert store.retained_generations(now_unix_ns=1) == {"generation-a"}


def test_store_rejects_a_symlink_or_unknown_member_instead_of_repairing_it(
    tmp_path: Path,
) -> None:
    state_root = (
        tmp_path / "home" / ".local" / "state" / "the-hive" / "hook-session-pins-v1"
    )
    store = _store(tmp_path)
    _bind(store)
    (state_root / "unexpected").write_text("no", encoding="utf-8")

    with pytest.raises(HookSessionPinStoreError):
        store.bindings()
