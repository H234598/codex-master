from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path, PurePosixPath
from typing import Iterator, Mapping

import pytest

from codex_master.hive import control_plane_store as control_plane_store_module
from codex_master.hive.control_plane_store import HiveControlPlaneStore
from codex_master.hive.state import HiveStateError, HiveStateStore


NOW = datetime(2026, 8, 16, 20, 45, tzinfo=timezone.utc)
TASK9_PATH = PurePosixPath("control-plane/task9.json")


def _empty_document(*, created: datetime = NOW, updated: datetime = NOW) -> dict[str, object]:
    return {
        "schema_version": 1,
        "revision": 0,
        "created_at_utc": created.isoformat(),
        "updated_at_utc": updated.isoformat(),
        "grants": [],
        "messages": [],
        "workpackages": [],
        "by_message_id": {},
        "by_correlation_id": {},
        "by_causation_id": {},
    }


class RecordingStore(HiveStateStore):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.locked_calls = 0
        self.lock_depth = 0
        self.reads: list[PurePosixPath] = []
        self.replacements: list[PurePosixPath] = []

    @contextmanager
    def locked(self) -> Iterator[HiveStateStore]:
        self.locked_calls += 1
        with super().locked() as held:
            self.lock_depth += 1
            try:
                yield held
            finally:
                self.lock_depth -= 1

    def read_json_locked(self, relative: PurePosixPath, *, max_bytes: int) -> dict[str, object]:
        assert self.lock_depth > 0
        self.reads.append(relative)
        return dict(super().read_json_locked(relative, max_bytes=max_bytes))

    def replace_json(self, relative: PurePosixPath, payload: dict[str, object]) -> None:
        raise AssertionError("control-plane store must use replace_json_locked")

    def replace_json_locked(
        self,
        relative: PurePosixPath,
        payload: dict[str, object],
        *,
        encoded: bytes | None = None,
    ) -> None:
        assert self.lock_depth > 0
        self.replacements.append(relative)
        super().replace_json_locked(relative, payload, encoded=encoded)


class LockAwareMapping(Mapping[str, object]):
    def __init__(self, state: RecordingStore) -> None:
        self._state = state

    def __iter__(self) -> Iterator[str]:
        assert self._state.lock_depth == 0
        return iter(_empty_document())

    def __len__(self) -> int:
        return len(_empty_document())

    def __getitem__(self, key: str) -> object:
        assert self._state.lock_depth == 0
        return _empty_document()[key]


def test_module_exports_only_hive_control_plane_store() -> None:
    assert control_plane_store_module.__all__ == ["HiveControlPlaneStore"]


def test_constructor_accepts_only_hive_state_store(tmp_path: Path) -> None:
    store = HiveStateStore(tmp_path / "state")
    assert isinstance(HiveControlPlaneStore(store), HiveControlPlaneStore)
    with pytest.raises(HiveStateError):
        HiveControlPlaneStore(tmp_path)  # type: ignore[arg-type]


def test_load_rejects_missing_invalid_unknown_and_incomplete_documents_without_mutation(tmp_path: Path) -> None:
    state = HiveStateStore(tmp_path / "state")
    control = HiveControlPlaneStore(state)
    path = tmp_path / "state" / TASK9_PATH

    with pytest.raises(HiveStateError, match="^control_plane_state_unavailable$"):
        control.load_task9()
    assert not path.exists()

    invalid_documents = (
        b"{",
        json.dumps({**_empty_document(), "unexpected": "field"}).encode("utf-8"),
        json.dumps({key: value for key, value in _empty_document().items() if key != "messages"}).encode("utf-8"),
    )
    for raw in invalid_documents:
        state.replace_private_bytes(TASK9_PATH, raw)
        before = path.read_bytes()
        with pytest.raises(HiveStateError, match="^control_plane_state_unavailable$"):
            control.load_task9()
        assert path.read_bytes() == before


def test_initialize_is_only_missing_file_bootstrap_and_returns_defensive_v1_document(tmp_path: Path) -> None:
    state = HiveStateStore(tmp_path / "state")
    control = HiveControlPlaneStore(state)
    path = tmp_path / "state" / TASK9_PATH

    document = control.initialize_task9(now=NOW)

    assert document == _empty_document()
    assert state.read_json(TASK9_PATH, max_bytes=4096) == _empty_document()
    document["grants"].append({"grant_id": "mutated"})  # type: ignore[union-attr]
    assert control.load_task9()["grants"] == []

    before = path.read_bytes()
    with pytest.raises(HiveStateError, match="^control_plane_state_unavailable$"):
        control.initialize_task9(now=NOW + timedelta(minutes=1))
    assert path.read_bytes() == before


def test_initialize_and_replace_require_aware_utc_time(tmp_path: Path) -> None:
    state = HiveStateStore(tmp_path / "state")
    control = HiveControlPlaneStore(state)
    with pytest.raises(HiveStateError):
        control.initialize_task9(now=NOW.replace(tzinfo=None))
    with pytest.raises(HiveStateError):
        control.initialize_task9(now=NOW.astimezone(timezone(timedelta(hours=1))))

    control.initialize_task9(now=NOW)
    with pytest.raises(HiveStateError):
        control.replace_task9(control.load_task9(), expected_revision=0, now=NOW.replace(tzinfo=None))
    with pytest.raises(HiveStateError):
        control.replace_task9(
            control.load_task9(),
            expected_revision=0,
            now=NOW.astimezone(timezone(timedelta(hours=1))),
        )


def test_replace_rejects_stale_revision_and_backward_time_without_mutation(tmp_path: Path) -> None:
    state = HiveStateStore(tmp_path / "state")
    control = HiveControlPlaneStore(state)
    path = tmp_path / "state" / TASK9_PATH
    control.initialize_task9(now=NOW)
    document = control.load_task9()
    before = path.read_bytes()

    with pytest.raises(HiveStateError, match="^stale_control_plane_revision$"):
        control.replace_task9(document, expected_revision=1, now=NOW + timedelta(minutes=1))
    assert path.read_bytes() == before

    with pytest.raises(HiveStateError, match="^control_plane_state_unavailable$"):
        control.replace_task9(document, expected_revision=0, now=NOW - timedelta(seconds=1))
    assert path.read_bytes() == before


def test_replace_increments_revision_preserves_created_updates_time_and_returns_defensive_copy(tmp_path: Path) -> None:
    state = HiveStateStore(tmp_path / "state")
    control = HiveControlPlaneStore(state)
    control.initialize_task9(now=NOW)
    document = control.load_task9()
    document["grants"].append({"grant_id": "grant-one"})  # type: ignore[union-attr]

    replaced = control.replace_task9(document, expected_revision=0, now=NOW + timedelta(minutes=1))

    assert replaced["revision"] == 1
    assert replaced["created_at_utc"] == NOW.isoformat()
    assert replaced["updated_at_utc"] == (NOW + timedelta(minutes=1)).isoformat()
    assert replaced["grants"] == [{"grant_id": "grant-one"}]
    replaced["grants"].clear()  # type: ignore[union-attr]
    assert control.load_task9()["grants"] == [{"grant_id": "grant-one"}]


def test_replace_valid_standard_json_candidate_returns_exact_following_load(tmp_path: Path) -> None:
    state = HiveStateStore(tmp_path / "state")
    control = HiveControlPlaneStore(state)
    control.initialize_task9(now=NOW)
    candidate = control.load_task9()
    candidate["messages"].append({"message_id": "message-one", "nested": [None, True, 1, 1.5, {"key": "value"}]})  # type: ignore[union-attr]
    candidate["by_message_id"] = {"message-one": {"sequence": 1}}

    replaced = control.replace_task9(candidate, expected_revision=0, now=NOW + timedelta(minutes=1))

    assert replaced == control.load_task9()


def test_replace_checks_expected_revision_and_custom_mapping_before_root_lock(tmp_path: Path) -> None:
    state = RecordingStore(tmp_path / "state")
    control = HiveControlPlaneStore(state)
    control.initialize_task9(now=NOW)
    candidate = control.load_task9()
    before = state.locked_calls

    with pytest.raises(HiveStateError, match="^stale_control_plane_revision$"):
        control.replace_task9(candidate, expected_revision=True, now=NOW + timedelta(minutes=1))  # type: ignore[arg-type]
    assert state.locked_calls == before

    with pytest.raises(HiveStateError, match="^control_plane_state_unavailable$"):
        control.replace_task9(LockAwareMapping(state), expected_revision=0, now=NOW + timedelta(minutes=1))
    assert state.locked_calls == before


@pytest.mark.parametrize(
    "invalid_index",
    (
        {1: "integer-key"},
        {True: "boolean-key"},
        {"message-one": float("nan")},
        {"message-one": float("inf")},
        {"message-one": float("-inf")},
        {"message-one": ("tuple",)},
    ),
)
def test_replace_rejects_nonstandard_json_candidate_before_root_lock_without_mutation(
    tmp_path: Path, invalid_index: dict[object, object]
) -> None:
    state = RecordingStore(tmp_path / "state")
    control = HiveControlPlaneStore(state)
    path = tmp_path / "state" / TASK9_PATH
    control.initialize_task9(now=NOW)
    candidate = control.load_task9()
    candidate["by_message_id"] = invalid_index
    before = path.read_bytes()
    locked_before = state.locked_calls

    with pytest.raises(HiveStateError, match="^control_plane_state_unavailable$"):
        control.replace_task9(candidate, expected_revision=0, now=NOW + timedelta(minutes=1))

    assert state.locked_calls == locked_before
    assert path.read_bytes() == before


def _cyclic_messages() -> list[object]:
    messages: list[object] = []
    messages.append(messages)
    return messages


def _deep_messages() -> list[object]:
    messages: list[object] = []
    for _ in range(2_000):
        messages = [messages]
    return messages


@pytest.mark.parametrize("build_messages", (_cyclic_messages, _deep_messages))
def test_replace_normalizes_recursive_candidate_validation_before_root_lock_without_mutation(
    tmp_path: Path, build_messages: callable[[], list[object]]
) -> None:
    state = RecordingStore(tmp_path / "state")
    control = HiveControlPlaneStore(state)
    path = tmp_path / "state" / TASK9_PATH
    control.initialize_task9(now=NOW)
    candidate = control.load_task9()
    candidate["messages"] = build_messages()
    before = path.read_bytes()
    locked_before = state.locked_calls

    with pytest.raises(HiveStateError, match="^control_plane_state_unavailable$"):
        control.replace_task9(candidate, expected_revision=0, now=NOW + timedelta(minutes=1))

    assert state.locked_calls == locked_before
    assert path.read_bytes() == before


def test_mutations_use_one_reentrant_root_lock_and_one_atomic_replace(tmp_path: Path) -> None:
    state = RecordingStore(tmp_path / "state")
    control = HiveControlPlaneStore(state)
    path = tmp_path / "state" / TASK9_PATH

    initialized = control.initialize_task9(now=NOW)

    assert state.locked_calls == 1
    assert state.reads == [TASK9_PATH]
    assert state.replacements == [TASK9_PATH]
    assert not list(path.parent.glob(".task9.json.*"))

    with state.locked():
        replaced = control.replace_task9(initialized, expected_revision=0, now=NOW + timedelta(minutes=1))

    assert replaced["revision"] == 1
    assert state.locked_calls == 3
    assert state.reads == [TASK9_PATH, TASK9_PATH]
    assert state.replacements == [TASK9_PATH, TASK9_PATH]
    assert not list(path.parent.glob(".task9.json.*"))
