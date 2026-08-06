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


def test_state_store_uses_private_modes(tmp_path: Path) -> None:
    store = HiveStateStore(tmp_path / "state")
    store.replace_json(PurePosixPath("record.json"), {"ok": True})
    assert stat.S_IMODE((tmp_path / "state").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "state" / "record.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "state" / ".hive-state.lock").stat().st_mode) == 0o600


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
