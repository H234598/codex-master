from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import codex_master.fleet_inplace as inplace
from codex_master.fleet_inplace import (
    InplaceError,
    QHomeUpdate,
    apply_series_update,
    recover_series_update,
)


TX_ID = "a" * 32
OLD_GENERATION = 8
NEW_GENERATION = 9
MANAGED = ("codex", "config.toml", "AGENTS.md", "AGENTS.class-teamleiterin.md", ".codex-fleet-agent.json")


class Crash(BaseException):
    pass


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def write_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_bytes(data)
    path.chmod(mode)


def make_home(tmp_path: Path, home_id: str, *, absent: str | None = None) -> QHomeUpdate:
    home = private_dir(tmp_path / home_id)
    old = {
        "codex": f"old wrapper {home_id}\n".encode(),
        "config.toml": f"old config {home_id}\n".encode(),
        "AGENTS.md": f"old instructions {home_id}\n".encode(),
        ".codex-fleet-agent.json": f'{{"generation":8,"id":"{home_id}"}}\n'.encode(),
    }
    for name, data in old.items():
        if name != absent:
            write_file(home / name, data, 0o700 if name == "codex" else 0o600)
    unknown = {
        "auth.json": f"auth-secret-{home_id}\n".encode(),
        "sessions/live.jsonl": b"session\n",
        "logs/runtime.log": b"log\n",
        "skills/user/SKILL.md": b"skill\n",
        "plugins/local/plugin.json": b"plugin\n",
        "cache/blob": b"cache\n",
        "tmp/in-flight": b"tmp\n",
        "state.sqlite": b"SQLite format 3\x00runtime",
        "unknown/value": b"unknown\n",
    }
    for name, data in unknown.items():
        write_file(home / name, data)
    return QHomeUpdate(
        home_id=home_id,
        home=home,
        wrapper=f"new wrapper {home_id}\n".encode(),
        config=f"new config {home_id}\n".encode(),
        instructions=f"new instructions {home_id}\n".encode(),
        marker=f'{{"generation":9,"id":"{home_id}"}}\n'.encode(),
        class_instructions=f"new class instructions {home_id}\n".encode(),
    )


def series(tmp_path: Path, *, absent: str | None = None) -> tuple[tuple[QHomeUpdate, ...], Path]:
    transaction_root = private_dir(tmp_path / "transactions")
    homes = tuple(make_home(tmp_path, f"q{number}", absent=absent) for number in range(1, 4))
    return homes, transaction_root


def unknown_snapshot(home: Path) -> dict[str, tuple[bytes, int, int]]:
    return {
        path.relative_to(home).as_posix(): (
            path.read_bytes(),
            path.stat().st_mode & 0o777,
            path.stat().st_ino,
        )
        for path in home.rglob("*")
        if path.is_file() and path.name not in MANAGED
    }


def managed_snapshot(home: Path) -> dict[str, tuple[bytes, int] | None]:
    return {
        name: None
        if not (home / name).exists()
        else ((home / name).read_bytes(), (home / name).stat().st_mode & 0o777)
        for name in MANAGED
    }


def assert_snapshot(home: Path, snapshot: dict[str, tuple[bytes, int] | None]) -> None:
    for name, state in snapshot.items():
        target = home / name
        if state is None:
            assert not target.exists()
        else:
            assert (target.read_bytes(), target.stat().st_mode & 0o777) == state


def assert_unknown(home: Path, snapshot: dict[str, tuple[bytes, int, int]]) -> None:
    assert unknown_snapshot(home) == snapshot


def apply(
    homes: tuple[QHomeUpdate, ...],
    transaction_root: Path,
    cas,
    *,
    fault=None,
) -> int:
    return apply_series_update(
        homes,
        transaction_root=transaction_root,
        transaction_id=TX_ID,
        old_generation=OLD_GENERATION,
        new_generation=NEW_GENERATION,
        registry_cas=cas,
        _fault=fault,
    )


def recover(
    homes: tuple[QHomeUpdate, ...], transaction_root: Path, generation: int
) -> int:
    return recover_series_update(
        {item.home_id: item.home for item in homes},
        transaction_root=transaction_root,
        transaction_id=TX_ID,
        authoritative_generation=generation,
    )


def crashed_series(tmp_path: Path, point: str, *, absent: str | None = None):
    homes, transactions = series(tmp_path, absent=absent)
    before = {item.home_id: managed_snapshot(item.home) for item in homes}
    with pytest.raises(Crash):
        apply(
            homes,
            transactions,
            lambda _a, _b: True,
            fault=lambda event: (_ for _ in ()).throw(Crash) if event == point else None,
        )
    return homes, transactions, before


def test_public_api_is_q_specific_and_minimal() -> None:
    assert inplace.__all__ == [
        "InplaceError",
        "QHomeUpdate",
        "apply_series_update",
        "recover_series_update",
    ]


def test_partial_transaction_cleanup_removes_only_declared_owned_files(
    tmp_path: Path,
) -> None:
    parent = private_dir(tmp_path / "transactions")
    transaction = private_dir(parent / TX_ID)
    write_file(transaction / "stage-a", b"stage")
    write_file(transaction / "backup-a", b"backup")

    inplace._cleanup_partial(
        transaction, [{"stage": "stage-a", "backup": "backup-a"}]
    )

    assert not transaction.exists()
    assert parent.exists()


def test_q1_q3_update_uses_one_cas_and_preserves_home_and_runtime_identity(tmp_path: Path) -> None:
    homes, transactions = series(tmp_path)
    home_inodes = {item.home_id: item.home.stat().st_ino for item in homes}
    unknown = {item.home_id: unknown_snapshot(item.home) for item in homes}
    calls: list[tuple[int, int]] = []

    assert apply(homes, transactions, lambda old, new: calls.append((old, new)) or True) == 9
    assert calls == [(8, 9)]
    for item in homes:
        assert item.home.stat().st_ino == home_inodes[item.home_id]
        assert (item.home / "codex").read_bytes() == item.wrapper
        assert (item.home / "config.toml").read_bytes() == item.config
        assert (item.home / ".codex-fleet-agent.json").read_bytes() == item.marker
        assert_unknown(item.home, unknown[item.home_id])
    assert list(transactions.iterdir()) == []


@pytest.mark.parametrize("failure", ["partial", "conflict"])
def test_precommit_failure_rolls_back_all_homes(tmp_path: Path, failure: str) -> None:
    homes, transactions = series(tmp_path, absent="config.toml")
    old = {item.home_id: managed_snapshot(item.home) for item in homes}
    unknown = {item.home_id: unknown_snapshot(item.home) for item in homes}
    calls: list[tuple[int, int]] = []

    def fault(point: str) -> None:
        if failure == "partial" and point == "after:q2:config.toml":
            raise OSError("private")

    with pytest.raises(InplaceError) as caught:
        apply(
            homes,
            transactions,
            lambda a, b: calls.append((a, b)) or failure != "conflict",
            fault=fault,
        )
    assert caught.value.code == ("materialization_failed" if failure == "partial" else "registry_conflict")
    assert calls == ([] if failure == "partial" else [(8, 9)])
    for item in homes:
        assert_snapshot(item.home, old[item.home_id])
        assert_unknown(item.home, unknown[item.home_id])


@pytest.mark.parametrize(
    ("crash_point", "generation", "expected"),
    [("before_cas", 8, "old"), ("after_cas", 9, "new")],
)
def test_crash_recovery_follows_authoritative_generation(
    tmp_path: Path, crash_point: str, generation: int, expected: str
) -> None:
    homes, transactions, old = crashed_series(tmp_path, crash_point, absent="config.toml")
    assert recover(homes, transactions, generation) == generation
    for item in homes:
        if expected == "old":
            assert_snapshot(item.home, old[item.home_id])
        else:
            assert (item.home / "config.toml").read_bytes() == item.config
            assert (item.home / ".codex-fleet-agent.json").read_bytes() == item.marker
    assert list(transactions.iterdir()) == []


def test_third_generation_blocks_and_uncertain_cas_remains_recoverable(tmp_path: Path) -> None:
    homes, transactions = series(tmp_path)

    def uncertain(_old: int, _new: int) -> bool:
        raise TimeoutError("unknown")

    with pytest.raises(InplaceError) as caught:
        apply(homes, transactions, uncertain)
    assert caught.value.code == "registry_cas_uncertain"
    journal = transactions / TX_ID / "journal.json"
    with pytest.raises(InplaceError) as caught:
        recover(homes, transactions, 77)
    assert caught.value.code == "generation_ambiguous"
    assert journal.is_file()
    assert recover(homes, transactions, 9) == 9


def test_rollback_divergence_keeps_journal_and_concurrent_leaf(tmp_path: Path) -> None:
    homes, transactions = series(tmp_path)
    target = homes[0].home / "codex"

    def diverge(point: str) -> None:
        if point == "after:q1:codex":
            target.write_bytes(b"concurrent managed value\n")
            target.chmod(0o700)
            raise OSError("private")

    with pytest.raises(InplaceError) as caught:
        apply(homes, transactions, lambda _a, _b: True, fault=diverge)
    assert caught.value.code == "rollback_diverged"
    assert target.read_bytes() == b"concurrent managed value\n"
    assert (transactions / TX_ID / "journal.json").is_file()


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "home_mode"])
def test_unsafe_home_and_leaf_are_rejected(tmp_path: Path, unsafe: str) -> None:
    homes, transactions = series(tmp_path)
    target = homes[0].home / "config.toml"
    outside = private_dir(tmp_path / "outside") / "file"
    write_file(outside, b"outside\n")
    if unsafe == "symlink":
        target.unlink()
        target.symlink_to(outside)
    elif unsafe == "hardlink":
        os.link(target, outside.parent / "linked")
    else:
        homes[0].home.chmod(0o755)
    with pytest.raises(InplaceError) as caught:
        apply(homes, transactions, lambda _a, _b: True)
    assert caught.value.code in {"unsafe_home", "unsafe_managed_leaf"}
    assert outside.read_bytes() == b"outside\n"


def test_home_inode_race_fails_before_materialization(tmp_path: Path) -> None:
    homes, transactions = series(tmp_path)
    original = homes[0].home.with_name("q1-original")

    def race(point: str) -> None:
        if point == "prepared":
            homes[0].home.rename(original)
            private_dir(homes[0].home)

    with pytest.raises(InplaceError) as caught:
        apply(homes, transactions, lambda _a, _b: True, fault=race)
    assert caught.value.code == "home_drift"
    assert (original / "codex").read_bytes() == b"old wrapper q1\n"


@pytest.mark.parametrize("operation", ["replace_inode", "replace_digest", "rollback_unlink"])
def test_leaf_race_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    absent = "config.toml" if operation == "rollback_unlink" else None
    homes, transactions = series(tmp_path, absent=absent)
    target = homes[0].home / ("config.toml" if absent else "codex")
    concurrent = b"bad wrapper q1\n"
    original_replace = inplace._replace_leaf
    original_unlink = inplace._unlink_leaf
    calls = 0

    def replace_leaf(*args, **kwargs) -> None:
        nonlocal calls
        calls += args[1] == target.name
        should_race = operation != "rollback_unlink" and calls == 1
        if should_race and operation == "replace_inode":
            swap = target.with_name(".swap")
            write_file(swap, concurrent, 0o700)
            os.replace(swap, target)
        elif should_race:
            inode = target.stat().st_ino
            target.write_bytes(concurrent)
            assert target.stat().st_ino == inode
        original_replace(*args, **kwargs)

    def unlink_leaf(*args, **kwargs) -> None:
        if operation == "rollback_unlink" and args[1] == "config.toml":
            inode = target.stat().st_ino
            target.write_bytes(b"bad config q1\n")
            assert target.stat().st_ino == inode
        original_unlink(*args, **kwargs)

    monkeypatch.setattr(inplace, "_replace_leaf", replace_leaf)
    monkeypatch.setattr(inplace, "_unlink_leaf", unlink_leaf)
    with pytest.raises(InplaceError) as caught:
        apply(
            homes,
            transactions,
            lambda _a, _b: False if operation == "rollback_unlink" else True,
        )
    assert caught.value.code in {"managed_drift", "rollback_diverged"}
    assert target.read_bytes() == (b"bad config q1\n" if absent else concurrent)


def test_markers_are_last_and_journal_contains_no_user_data(tmp_path: Path) -> None:
    homes, transactions = series(tmp_path)
    events: list[str] = []

    def crash(point: str) -> None:
        if point.startswith("after:"):
            events.append(point)
            if point == "after:q3:config.toml":
                assert all(
                    (item.home / ".codex-fleet-agent.json").read_bytes()
                    != item.marker
                    for item in homes
                )
        if point == "before_cas":
            raise Crash

    with pytest.raises(Crash):
        apply(homes, transactions, lambda _a, _b: True, fault=crash)
    assert [event.rsplit(":", 1)[-1] for event in events[-3:]] == [
        ".codex-fleet-agent.json"
    ] * 3
    transaction = transactions / TX_ID
    payload = b"".join(path.read_bytes() for path in transaction.iterdir())
    for item in homes:
        assert f"auth-secret-{item.home_id}".encode() not in payload
        assert str(item.home).encode() not in payload


@pytest.mark.parametrize("entry", ["module_temp", "foreign"])
def test_recovery_cleanup_handles_only_module_owned_temps(tmp_path: Path, entry: str) -> None:
    homes, transactions, _old = crashed_series(tmp_path, "before_cas")
    transaction = transactions / TX_ID
    extra = transaction / (
        ".codex-inplace-0123456789abcdef0123456789abcdef"
        if entry == "module_temp"
        else "foreign-user-entry"
    )
    write_file(extra, b"leftover\n")
    if entry == "module_temp":
        assert recover(homes, transactions, 8) == 8
        assert not transaction.exists()
    else:
        managed_before = {item.home_id: managed_snapshot(item.home) for item in homes}
        with pytest.raises(InplaceError) as caught:
            recover(homes, transactions, 8)
        assert caught.value.code == "transaction_contains_foreign_entry"
        assert extra.read_bytes() == b"leftover\n"
        assert (transaction / "journal.json").is_file()
        for item in homes:
            assert_snapshot(item.home, managed_before[item.home_id])


def test_corrupt_global_marker_order_and_tight_bounds_are_rejected(tmp_path: Path) -> None:
    homes, transactions, _old = crashed_series(tmp_path, "before_cas")
    journal_path = transactions / TX_ID / "journal.json"
    raw = json.loads(journal_path.read_bytes())
    raw["entries"][1], raw["entries"][6] = raw["entries"][6], raw["entries"][1]
    journal_path.write_text(json.dumps(raw, separators=(",", ":")) + "\n")
    journal_path.chmod(0o600)
    with pytest.raises(InplaceError) as caught:
        recover(homes, transactions, 8)
    assert caught.value.code == "invalid_journal"

    fresh = private_dir(tmp_path / "fresh-transactions")
    oversized = QHomeUpdate(
        "q4",
        private_dir(tmp_path / "q4"),
        b"x",
        b"x" * 262145,
        b"x",
        b"x",
    )
    with pytest.raises(InplaceError) as caught:
        apply((oversized,), fresh, lambda _a, _b: True)
    assert caught.value.code == "invalid_request"


def test_committed_journal_with_old_authoritative_generation_blocks_unchanged(tmp_path: Path) -> None:
    homes, transactions, _old = crashed_series(tmp_path, "after_cas")
    before = {item.home_id: managed_snapshot(item.home) for item in homes}
    journal = transactions / TX_ID / "journal.json"
    with pytest.raises(InplaceError) as caught:
        recover(homes, transactions, OLD_GENERATION)
    assert caught.value.code in {"generation_ambiguous", "recovery_diverged"}
    assert journal.is_file()
    for item in homes:
        assert_snapshot(item.home, before[item.home_id])


@pytest.mark.parametrize("corruption", ["installed", "restored", "restored_absent"])
def test_semantically_foreign_journal_state_is_rejected_without_mutation(
    tmp_path: Path, corruption: str
) -> None:
    homes, transactions, _old = crashed_series(
        tmp_path, "before_cas", absent="config.toml" if corruption == "restored_absent" else None
    )
    journal = transactions / TX_ID / "journal.json"
    raw = json.loads(journal.read_bytes())
    entry = next(
        item
        for item in raw["entries"]
        if item["home_id"] == "q1"
        and item["name"] == ("config.toml" if corruption == "restored_absent" else "codex")
    )
    if corruption == "installed":
        entry["installed"]["digest"] = "f" * 64
    else:
        entry["restored"] = dict(entry["installed"] if entry["old"] is None else entry["old"])
        if corruption == "restored":
            entry["restored"]["digest"] = "f" * 64
    journal.write_text(json.dumps(raw, separators=(",", ":")) + "\n")
    journal.chmod(0o600)
    before = {item.home_id: managed_snapshot(item.home) for item in homes}
    with pytest.raises(InplaceError) as caught:
        recover(homes, transactions, NEW_GENERATION)
    assert caught.value.code == "invalid_journal"
    assert journal.is_file()
    for item in homes:
        assert_snapshot(item.home, before[item.home_id])
