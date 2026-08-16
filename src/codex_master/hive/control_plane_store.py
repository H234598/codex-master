"""Private Task-9 control-plane state owner."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import cast

from codex_master.hive.state import MAX_HIVE_STATE_BYTES, HiveStateError, HiveStateStore
from codex_master.hive.types import HiveValidationError, validate_utc_datetime


_TASK9_PATH = PurePosixPath("control-plane/task9.json")
_TASK9_KEYS = frozenset(
    {
        "schema_version",
        "revision",
        "created_at_utc",
        "updated_at_utc",
        "grants",
        "messages",
        "workpackages",
        "by_message_id",
        "by_correlation_id",
        "by_causation_id",
    }
)
_LEDGER_KEYS = ("grants", "messages", "workpackages")
_INDEX_KEYS = ("by_message_id", "by_correlation_id", "by_causation_id")


class HiveControlPlaneStore:
    """Own the closed Task-9 aggregate through one existing Hive state store."""

    def __init__(self, state: HiveStateStore) -> None:
        if not isinstance(state, HiveStateStore):
            raise HiveStateError("invalid_control_plane_state_store")
        self._state = state

    def load_task9(self) -> dict[str, object]:
        """Return a defensive, validated Task-9 document."""

        with self._state.locked():
            return _copy_document(self._load_task9_locked())

    def initialize_task9(self, *, now: datetime) -> dict[str, object]:
        """Create the sole permitted empty Task-9 document when it is absent."""

        moment = _utc_time(now)
        with self._state.locked():
            try:
                self._state.read_json_locked(_TASK9_PATH, max_bytes=MAX_HIVE_STATE_BYTES)
            except HiveStateError as exc:
                if str(exc) != "state_not_found":
                    raise HiveStateError("control_plane_state_unavailable") from exc
            else:
                raise HiveStateError("control_plane_state_unavailable")
            document = _empty_document(moment)
            self._state.replace_json_locked(_TASK9_PATH, document)
            return _copy_document(document)

    def replace_task9(
        self,
        document: Mapping[str, object],
        *,
        expected_revision: int,
        now: datetime,
    ) -> dict[str, object]:
        """CAS-replace the Task-9 aggregate through the existing root lock."""

        moment = _utc_time(now)
        with self._state.locked():
            persisted = self._load_task9_locked()
            candidate = _validate_document(document)
            revision = persisted["revision"]
            updated = _parse_utc_timestamp(persisted["updated_at_utc"])
            if (
                type(expected_revision) is not int
                or expected_revision < 0
                or candidate["revision"] != expected_revision
                or revision != expected_revision
            ):
                raise HiveStateError("stale_control_plane_revision")
            if moment < updated:
                raise HiveStateError("control_plane_state_unavailable")
            candidate["revision"] = revision + 1
            candidate["created_at_utc"] = persisted["created_at_utc"]
            candidate["updated_at_utc"] = moment.isoformat()
            self._state.replace_json_locked(_TASK9_PATH, candidate)
            return _copy_document(candidate)

    def _load_task9_locked(self) -> dict[str, object]:
        try:
            document = self._state.read_json_locked(_TASK9_PATH, max_bytes=MAX_HIVE_STATE_BYTES)
            return _validate_document(document)
        except HiveStateError as exc:
            raise HiveStateError("control_plane_state_unavailable") from exc


def _empty_document(now: datetime) -> dict[str, object]:
    timestamp = now.isoformat()
    return {
        "schema_version": 1,
        "revision": 0,
        "created_at_utc": timestamp,
        "updated_at_utc": timestamp,
        "grants": [],
        "messages": [],
        "workpackages": [],
        "by_message_id": {},
        "by_correlation_id": {},
        "by_causation_id": {},
    }


def _validate_document(value: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise HiveStateError("control_plane_state_unavailable")
    try:
        document = cast(dict[str, object], deepcopy(dict(value)))
    except (TypeError, ValueError, RecursionError) as exc:
        raise HiveStateError("control_plane_state_unavailable") from exc
    if set(document) != _TASK9_KEYS:
        raise HiveStateError("control_plane_state_unavailable")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise HiveStateError("control_plane_state_unavailable")
    if type(document["revision"]) is not int or document["revision"] < 0:
        raise HiveStateError("control_plane_state_unavailable")
    if any(type(document[key]) is not list for key in _LEDGER_KEYS):
        raise HiveStateError("control_plane_state_unavailable")
    if any(type(document[key]) is not dict for key in _INDEX_KEYS):
        raise HiveStateError("control_plane_state_unavailable")
    created = _parse_utc_timestamp(document["created_at_utc"])
    updated = _parse_utc_timestamp(document["updated_at_utc"])
    if updated < created:
        raise HiveStateError("control_plane_state_unavailable")
    return document


def _parse_utc_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise HiveStateError("control_plane_state_unavailable")
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValueError
        normalized = validate_utc_datetime(parsed, field="control_plane_timestamp")
    except (HiveValidationError, TypeError, ValueError):
        raise HiveStateError("control_plane_state_unavailable") from None
    return normalized.astimezone(timezone.utc)


def _utc_time(value: datetime) -> datetime:
    try:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError
        return validate_utc_datetime(value, field="control_plane_time")
    except (HiveValidationError, TypeError, ValueError):
        raise HiveStateError("control_plane_state_unavailable") from None


def _copy_document(document: Mapping[str, object]) -> dict[str, object]:
    try:
        return cast(dict[str, object], deepcopy(dict(document)))
    except (TypeError, ValueError, RecursionError) as exc:
        raise HiveStateError("control_plane_state_unavailable") from exc


__all__ = ["HiveControlPlaneStore"]
