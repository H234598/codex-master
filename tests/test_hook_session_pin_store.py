from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
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


def _unpublished_touch(store: HookSessionPinStoreV1) -> Path:
    from the_hive import hook_session_pin_store as pins

    pending = dict(_bind(store))
    pending.update(last_seen_at_unix_ns=20, store_generation=2)
    path = store.state_root / f".{pins._binding_name('session-a')}.abcdefgh.tmp"
    path.write_bytes(pins._canonical_json(store._with_digest(pending)))
    path.chmod(0o600)
    return path


def test_interrupted_write_temp_preserves_canonical_pin_lifecycle(
    tmp_path: Path,
) -> None:
    from the_hive import hook_session_pin_store as pins

    store = _store(tmp_path)
    original = _bind(store)
    canonical = store.state_root / pins._binding_name("session-a")

    def interrupted_writer() -> None:
        def crash_before_replace(*_args, **_kwargs):
            os._exit(73)

        pins.os.replace = crash_before_replace
        _bind(store, now=20)

    writer = multiprocessing.get_context("fork").Process(target=interrupted_writer)
    writer.start()
    writer.join(timeout=10)
    if writer.is_alive():
        writer.kill()
        writer.join()
    assert writer.exitcode == 73
    temporaries = list(store.state_root.glob(".*.json.*.tmp"))
    assert len(temporaries) == 1
    temporary = temporaries[0]
    before = temporary.stat()
    raw = temporary.read_bytes()

    assert store.bindings() == {"session-a": original}
    assert store.retained_generations(now_unix_ns=20) == {"generation-a"}
    assert _bind(store, now=30)["store_generation"] == 2
    store.end_session(session_id="session-a", now_unix_ns=40)
    assert store.retained_generations(now_unix_ns=40 + DAY_NS - 1) == {"generation-a"}
    assert store.retained_generations(now_unix_ns=40 + DAY_NS) == set()
    store.resume_session(
        session_id="session-a",
        generation="generation-a",
        runtime_manifest_digest="sha256:" + "c" * 64,
        hooks=HOOKS,
        now_unix_ns=50,
    )
    assert store.retained_generations(now_unix_ns=50) == {"generation-a"}
    retired = store._with_digest(
        {
            "schema": "HookSessionRetirementV1",
            "session_id": "session-a",
            "original_sha256": "sha256:"
            + hashlib.sha256(canonical.read_bytes()).hexdigest(),
            "transaction_id": "a" * 64,
            "retired_at_unix_ns": 60,
            "lifecycle_sha256": "sha256:" + "b" * 64,
        }
    )
    canonical.write_bytes(pins._canonical_json(retired))
    assert store.bindings() == {}
    assert store.retained_generations(now_unix_ns=60) == set()
    canonical.unlink()
    assert store.bindings() == {}
    assert store.retained_generations(now_unix_ns=70) == set()
    after = temporary.stat()
    assert (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_mtime_ns,
    )
    assert temporary.read_bytes() == raw


def test_unpublished_other_release_never_adds_pin_authority(tmp_path: Path) -> None:
    from the_hive import hook_session_pin_store as pins

    store = _store(tmp_path)
    temporary = _unpublished_touch(store)
    pending = json.loads(temporary.read_bytes())
    pending["generation"] = "unpublished-other-generation"
    temporary.write_bytes(pins._canonical_json(store._with_digest(pending)))
    assert store.retained_generations(now_unix_ns=30) == {"generation-a"}
    assert store.bindings()["session-a"]["generation"] == "generation-a"
    (store.state_root / pins._binding_name("session-a")).unlink()
    assert store.bindings() == {}
    assert store.retained_generations(now_unix_ns=30) == set()
    assert temporary.exists()


@pytest.mark.parametrize(
    "invalid",
    [
        "foreign_name",
        "long_suffix",
        "name_mismatch",
        "json",
        "duplicate",
        "digest",
        "schema",
        "nonobject",
        "mode",
        "owner",
        "hardlink",
        "symlink",
        "directory",
        "oversize",
        "canonical_corrupt",
    ],
)
def test_invalid_write_temp_stays_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    from the_hive import hook_session_pin_store as pins

    store = _store(tmp_path)
    path = _unpublished_touch(store)
    canonical = store.state_root / pins._binding_name("session-a")
    if invalid == "foreign_name":
        path = path.rename(path.with_name("unexpected.tmp"))
    elif invalid == "long_suffix":
        path = path.rename(path.with_name(path.name.replace("abcdefgh", "abcdefghi")))
    elif invalid == "name_mismatch":
        path = path.rename(path.with_name("." + "0" * 64 + ".json.abcdefgh.tmp"))
    elif invalid == "json":
        path.write_bytes(b"{")
    elif invalid == "duplicate":
        path.write_bytes(b'{"schema":"first","schema":"second"}')
    elif invalid == "nonobject":
        path.write_bytes(b"[]")
    elif invalid in {"digest", "schema"}:
        value = json.loads(path.read_bytes())
        value["content_digest" if invalid == "digest" else "schema"] = "invalid"
        path.write_bytes(pins._canonical_json(value))
    elif invalid == "mode":
        path.chmod(0o644)
    elif invalid == "owner":
        fstat = pins.os.fstat

        def foreign_owner(descriptor: int):
            info = fstat(descriptor)
            if os.readlink(f"/proc/self/fd/{descriptor}") == str(path):
                fields = list(info)
                fields[4] = os.geteuid() + 1
                return os.stat_result(fields)
            return info

        monkeypatch.setattr(pins.os, "fstat", foreign_owner)
    elif invalid == "hardlink":
        os.link(path, store.state_root.parent / "other-link")
    elif invalid == "symlink":
        path.unlink()
        path.symlink_to(canonical)
    elif invalid == "directory":
        path.unlink()
        path.mkdir(mode=0o700)
    elif invalid == "oversize":
        path.write_bytes(b"x" * (64 * 1024 + 1))
    elif invalid == "canonical_corrupt":
        canonical.write_bytes(b"{")
    with pytest.raises(HookSessionPinStoreError):
        store.bindings()
    assert path.exists()


def test_fifo_write_temp_is_rejected_without_blocking(tmp_path: Path) -> None:
    store = _store(tmp_path)
    path = _unpublished_touch(store)
    path.unlink()
    os.mkfifo(path, mode=0o600)

    def reader() -> None:
        try:
            store.bindings()
        except HookSessionPinStoreError:
            os._exit(0)
        os._exit(1)

    process = multiprocessing.get_context("fork").Process(target=reader)
    process.start()
    process.join(timeout=5)
    blocked = process.is_alive()
    if blocked:
        process.kill()
        process.join()
    assert not blocked
    assert process.exitcode == 0


def test_cutover_retirement_preserves_reference_and_denies_id_reuse(tmp_path):
    from the_hive import hook_session_pin_store as pins

    store = _store(tmp_path)
    original = _bind(store)
    path = store.state_root / pins._binding_name("session-a")
    raw = path.read_bytes()
    retired = {
        "schema": "HookSessionRetirementV1",
        "session_id": "session-a",
        "original_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "transaction_id": "a" * 64,
        "retired_at_unix_ns": 20,
        "lifecycle_sha256": "sha256:" + "b" * 64,
    }
    retired = store._with_digest(retired)
    path.write_bytes(pins._canonical_json(retired))
    assert store.bindings() == {}
    assert store.retained_generations(now_unix_ns=30) == set()
    with pytest.raises(HookSessionPinStoreError):
        _bind(store, now=30)
    with pytest.raises(HookSessionPinStoreError):
        store.resume_session(
            session_id="session-a",
            generation=original["generation"],
            runtime_manifest_digest=original["runtime_manifest_digest"],
            hooks=HOOKS,
            now_unix_ns=30,
        )
    assert path.read_bytes() == pins._canonical_json(retired)
    retired["original_sha256"] = "sha256:" + "d" * 64
    path.write_bytes(pins._canonical_json(retired))
    with pytest.raises(HookSessionPinStoreError):
        store.bindings()


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


@pytest.mark.parametrize("mismatch", ("generation", "digest", "hooks", "time"))
def test_resume_reopens_only_matching_ended_pin_and_can_end_again(
    tmp_path: Path, mismatch: str
) -> None:
    store = _store(tmp_path)
    original = _bind(store, now=10)
    ended = store.end_session(session_id="session-a", now_unix_ns=20)

    invalid = {
        "session_id": "session-a",
        "generation": "generation-a",
        "runtime_manifest_digest": "sha256:" + "c" * 64,
        "hooks": HOOKS,
        "now_unix_ns": 30,
    }
    if mismatch == "generation":
        invalid["generation"] = "generation-other"
    elif mismatch == "digest":
        invalid["runtime_manifest_digest"] = "sha256:" + "d" * 64
    elif mismatch == "hooks":
        invalid["hooks"] = {**HOOKS, "native_bee_event": "sha256:" + "d" * 64}
    else:
        invalid["now_unix_ns"] = 19
    with pytest.raises(HookSessionPinStoreError):
        store.resume_session(**invalid)
    assert store.bindings()["session-a"] == ended

    resumed = store.resume_session(
        session_id="session-a",
        generation="generation-a",
        runtime_manifest_digest="sha256:" + "c" * 64,
        hooks=HOOKS,
        now_unix_ns=30,
    )
    assert resumed["state"] == "active"
    assert resumed["ended_at_unix_ns"] is None
    assert resumed["state_transitions"] == [
        {"state": "active", "at_unix_ns": 10},
        {"state": "ended", "at_unix_ns": 20},
        {"state": "active", "at_unix_ns": 30},
    ]
    for key in (
        "session_id",
        "generation",
        "runtime_manifest_digest",
        "launcher_abi",
        "hooks",
        "created_at_unix_ns",
    ):
        assert resumed[key] == original[key]
    assert resumed["store_generation"] == ended["store_generation"] + 1

    with pytest.raises(HookSessionPinStoreError):
        store.resume_session(
            session_id="session-a",
            generation="generation-a",
            runtime_manifest_digest="sha256:" + "c" * 64,
            hooks=HOOKS,
            now_unix_ns=31,
        )
    assert store.bindings()["session-a"] == resumed
    assert store.end_session(session_id="session-a", now_unix_ns=40)["state"] == "ended"


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
