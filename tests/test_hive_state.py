import json
import os
from pathlib import Path, PurePosixPath
import stat

import pytest

from codex_master.hive.state import HiveStateError, HiveStateStore


def test_state_store_round_trips_private_json_and_jsonl(tmp_path: Path) -> None:
    store = HiveStateStore(tmp_path / "state")
    store.replace_json(PurePosixPath("principals.json"), {"schema_version": 1, "value": "ok"})
    assert store.read_json(PurePosixPath("principals.json"), max_bytes=4096)["value"] == "ok"
    store.append_bounded_jsonl(
        PurePosixPath("audit/events.jsonl"), {"event": "one"}, max_records=2, max_bytes=4096
    )
    store.append_bounded_jsonl(
        PurePosixPath("audit/events.jsonl"), {"event": "two"}, max_records=2, max_bytes=4096
    )
    store.append_bounded_jsonl(
        PurePosixPath("audit/events.jsonl"), {"event": "three"}, max_records=2, max_bytes=4096
    )
    lines = (tmp_path / "state" / "audit" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["event"] for line in lines] == ["two", "three"]


def test_read_only_state_store_rejects_all_mutations(tmp_path: Path) -> None:
    writable = HiveStateStore(tmp_path / "state")
    writable.replace_json(PurePosixPath("principals.json"), {"schema_version": 1})
    before = (tmp_path / "state" / "principals.json").read_bytes()

    read_only = HiveStateStore(tmp_path / "state", read_only=True)
    with pytest.raises(HiveStateError, match="^state_read_only$"):
        read_only.replace_json(PurePosixPath("principals.json"), {"schema_version": 2})
    with pytest.raises(HiveStateError, match="^state_read_only$"):
        read_only.replace_private_bytes(PurePosixPath("private.bin"), b"blocked")
    with pytest.raises(HiveStateError, match="^state_read_only$"):
        read_only.remove_private_bytes(PurePosixPath("principals.json"))
    with pytest.raises(HiveStateError, match="^state_read_only$"):
        read_only.append_bounded_jsonl(
            PurePosixPath("events.jsonl"), {"event": "blocked"}, max_records=4, max_bytes=4096
        )
    assert (tmp_path / "state" / "principals.json").read_bytes() == before
    assert not (tmp_path / "state" / "private.bin").exists()
    assert not (tmp_path / "state" / "events.jsonl").exists()


def test_state_store_uses_private_modes(tmp_path: Path) -> None:
    store = HiveStateStore(tmp_path / "state")
    store.replace_json(PurePosixPath("record.json"), {"ok": True})
    assert stat.S_IMODE((tmp_path / "state").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "state" / "record.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "state" / ".hive-state.lock").stat().st_mode) == 0o600


def test_state_store_reuses_exact_0700_root_without_chmod_and_existing_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    lock = root / ".hive-state.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    original_chmod = os.chmod

    def deny_root_chmod(path: os.PathLike[str] | str, mode: int, *args: object, **kwargs: object) -> None:
        if Path(path) == root:
            raise PermissionError("root is read-only")
        original_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr("codex_master.hive.state.os.chmod", deny_root_chmod)

    store = HiveStateStore(root)
    store.replace_private_bytes(PurePosixPath("resources/snapshot.bin"), b"complete")

    assert store.read_private_bytes(PurePosixPath("resources/snapshot.bin"), max_bytes=64) == b"complete"
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600


def test_state_store_still_rejects_untrusted_root_mode_and_root_symlink(tmp_path: Path) -> None:
    untrusted = tmp_path / "untrusted"
    untrusted.mkdir(mode=0o750)
    with pytest.raises(HiveStateError, match="state_directory_untrusted"):
        HiveStateStore(untrusted)

    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(HiveStateError, match="state_directory_untrusted"):
        HiveStateStore(linked)


@pytest.mark.parametrize("relative", [PurePosixPath("../escape.json"), PurePosixPath("/absolute.json")])
def test_state_store_rejects_path_escape(tmp_path: Path, relative: PurePosixPath) -> None:
    store = HiveStateStore(tmp_path / "state")
    with pytest.raises(HiveStateError, match="invalid_state_path"):
        store.replace_json(relative, {"x": 1})


def test_state_store_rejects_symlink_and_hardlink_targets(tmp_path: Path) -> None:
    store = HiveStateStore(tmp_path / "state")
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    link = tmp_path / "state" / "linked.json"
    link.symlink_to(outside)
    with pytest.raises(HiveStateError, match="state_file_untrusted"):
        store.replace_json(PurePosixPath("linked.json"), {"x": 1})
    hardlink = tmp_path / "state" / "hardlinked.json"
    hardlink_path = tmp_path / "hardlink-source.json"
    hardlink_path.write_text("{}", encoding="utf-8")
    os.link(hardlink_path, hardlink)
    with pytest.raises(HiveStateError, match="state_file_untrusted"):
        store.read_json(PurePosixPath("hardlinked.json"), max_bytes=4096)


def test_state_store_rejects_malformed_and_oversized_documents(tmp_path: Path) -> None:
    store = HiveStateStore(tmp_path / "state")
    path = tmp_path / "state" / "broken.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(HiveStateError, match="invalid_state_json"):
        store.read_json(PurePosixPath("broken.json"), max_bytes=4096)
    with pytest.raises(HiveStateError, match="state_oversize"):
        store.replace_json(PurePosixPath("large.json"), {"x": "a" * (4 * 1024 * 1024)})


def test_hive_state_raw_private_bytes_keep_nofollow_hardlink_parent_swap_and_atomic_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = HiveStateStore(tmp_path / "state")
    relative = PurePosixPath("resources/snapshot.bin")

    store.replace_private_bytes(relative, b"first")
    store.replace_private_bytes(relative, b"second")

    path = tmp_path / "state" / "resources" / "snapshot.bin"
    assert store.read_private_bytes(relative, max_bytes=64) == b"second"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(path.parent.glob(".snapshot.bin.*"))

    path.chmod(0o644)
    with pytest.raises(HiveStateError, match="state_file_untrusted"):
        store.read_private_bytes(relative, max_bytes=64)
    path.chmod(0o600)

    expected_uid = os.geteuid()
    monkeypatch.setattr(HiveStateStore, "_validate_private_directory", staticmethod(lambda _info: None))
    monkeypatch.setattr("codex_master.hive.state.os.geteuid", lambda: expected_uid + 1)
    with pytest.raises(HiveStateError, match="state_file_untrusted"):
        store.read_private_bytes(relative, max_bytes=64)
    monkeypatch.undo()

    path.unlink()
    hardlink_source = tmp_path / "hardlink-source.bin"
    hardlink_source.write_bytes(b"hardlinked")
    hardlink_source.chmod(0o600)
    os.link(hardlink_source, path)
    with pytest.raises(HiveStateError, match="state_file_untrusted"):
        store.read_private_bytes(relative, max_bytes=64)

    path.unlink()
    parent = path.parent
    displaced_parent = tmp_path / "displaced-resources"
    parent.rename(displaced_parent)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(HiveStateError, match="state_directory_untrusted"):
        store.read_private_bytes(relative, max_bytes=64)


def test_private_bytes_reject_root_swap_inside_and_after_held_store_lock(tmp_path: Path) -> None:
    store = HiveStateStore(tmp_path / "state")
    relative = PurePosixPath("resources/snapshot.bin")
    store.replace_private_bytes(relative, b"old")

    root = tmp_path / "state"
    displaced_root = tmp_path / "displaced-state"
    replacement_path = root / "resources" / "snapshot.bin"

    with store.locked():
        root.rename(displaced_root)
        root.mkdir(mode=0o700)
        replacement_path.parent.mkdir(mode=0o700)
        replacement_path.write_bytes(b"new")
        replacement_path.chmod(0o600)

        locked_read_error: HiveStateError | None = None
        locked_write_error: HiveStateError | None = None
        try:
            store.read_private_bytes(relative, max_bytes=64)
        except HiveStateError as exc:
            locked_read_error = exc
        try:
            store.replace_private_bytes(relative, b"replacement")
        except HiveStateError as exc:
            locked_write_error = exc

    assert str(locked_read_error) == "state_root_untrusted"
    assert str(locked_write_error) == "state_root_untrusted"
    assert (displaced_root / "resources" / "snapshot.bin").read_bytes() == b"old"
    assert replacement_path.read_bytes() == b"new"

    reacquired_read_error: HiveStateError | None = None
    reacquired_write_error: HiveStateError | None = None
    try:
        store.read_private_bytes(relative, max_bytes=64)
    except HiveStateError as exc:
        reacquired_read_error = exc
    try:
        store.replace_private_bytes(relative, b"replacement")
    except HiveStateError as exc:
        reacquired_write_error = exc

    assert str(reacquired_read_error) == "state_root_untrusted"
    assert str(reacquired_write_error) == "state_root_untrusted"
    assert (displaced_root / "resources" / "snapshot.bin").read_bytes() == b"old"
    assert replacement_path.read_bytes() == b"new"


def test_state_store_removes_one_private_file_locked_without_following_links(tmp_path: Path) -> None:
    store = HiveStateStore(tmp_path / "state")
    relative = PurePosixPath("resources/v1.json")
    store.replace_private_bytes(relative, b"old")

    store.remove_private_bytes(relative)

    with pytest.raises(HiveStateError, match="state_not_found"):
        store.read_private_bytes(relative, max_bytes=64)

    outside = tmp_path / "outside.json"
    outside.write_bytes(b"keep")
    linked = tmp_path / "state" / "resources" / "v1.json"
    linked.symlink_to(outside)
    with pytest.raises(HiveStateError, match="state_file_untrusted"):
        store.remove_private_bytes(relative)
    assert outside.read_bytes() == b"keep"
