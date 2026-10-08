"""Shared, conservative native-registry validation and write-time retention.

Thread IDs are not process identities. Only individual terminal hook/tool
observations make a child history row eligible; parent shutdown, age, and a
missing PID never do. Readers validate without discarding valid history.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import pwd
import re

from the_hive.hook_session_pin_store import (
    HookSessionPinStoreV1,
    HookSessionPinStoreError,
)

ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
TYPE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
HISTORY_LIMIT = 1024
BYTE_LIMIT = 1024 * 1024
RESERVATION_TTL_SECONDS = 30


class RegistryByteBudgetError(ValueError):
    """Protected registry data exceeds the atomic document byte budget."""


def empty_registry():
    return {"schema_version": 2, "agents": [], "sessions": [], "reservations": []}


def _identifier(value, pattern=ID_RE):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _timestamp(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        result = float(value)
    except (ValueError, OverflowError):
        return None
    return result if math.isfinite(result) else None


def normalize_registry(value):
    """Validate all rows, with no population cap or clock-dependent cleanup."""
    if (
        not isinstance(value, dict)
        or value.get("schema_version") not in (1, 2)
        or not isinstance(value.get("agents"), list)
    ):
        return None
    agents = []
    for row in value["agents"]:
        if not isinstance(row, dict):
            continue
        timestamp = _timestamp(row.get("updated_at"))
        if (
            not (
                _identifier(row.get("session_id"))
                and _identifier(row.get("agent_id"))
                and _identifier(row.get("agent_type"), TYPE_RE)
            )
            or row.get("activity_state") not in {"active", "unconfirmed", "completed"}
            or timestamp is None
        ):
            continue
        agents.append(
            {
                key: row[key]
                for key in ("session_id", "agent_id", "agent_type", "activity_state")
            }
            | {"updated_at": timestamp}
        )
    raw_sessions = (
        value.get("sessions")
        if value["schema_version"] == 2
        else [
            {
                "session_id": row["session_id"],
                "activity_state": "active",
                "updated_at": row["updated_at"],
            }
            for row in agents
        ]
    )
    if not isinstance(raw_sessions, list):
        return None
    sessions = {}
    for row in raw_sessions:
        if not isinstance(row, dict):
            continue
        timestamp = _timestamp(row.get("updated_at"))
        session_id = row.get("session_id")
        if (
            not _identifier(session_id)
            or row.get("activity_state") not in {"active", "ended"}
            or timestamp is None
        ):
            continue
        normalized = {
            "session_id": session_id,
            "activity_state": row["activity_state"],
            "updated_at": timestamp,
        }
        if _identifier(row.get("managed_session")):
            normalized["managed_session"] = row["managed_session"]
        if (
            session_id not in sessions
            or timestamp >= sessions[session_id]["updated_at"]
        ):
            sessions[session_id] = normalized
    reservations = []
    raw_reservations = (
        value.get("reservations", []) if value["schema_version"] == 2 else []
    )
    if isinstance(raw_reservations, list):
        for row in raw_reservations:
            if not isinstance(row, dict):
                continue
            fields = {
                "native_spawn": ("parent_session_id",),
                "managed_replacement": ("managed_session",),
                "headless_inflight": ("agent", "assignment_id"),
            }.get(row.get("kind"))
            timestamp = _timestamp(row.get("created_at"))
            if (
                fields is None
                or not _identifier(row.get("reservation_id"))
                or timestamp is None
                or not all(_identifier(row.get(key)) for key in fields)
            ):
                continue
            reservations.append(
                {
                    "reservation_id": row["reservation_id"],
                    "kind": row["kind"],
                    "created_at": timestamp,
                    **{key: row[key] for key in fields},
                }
            )
    return {
        "schema_version": 2,
        "agents": agents,
        "sessions": list(sessions.values()),
        "reservations": reservations,
    }


def retained_pin_session_ids(now):
    """Read every persisted ABI session reference, never repair the store.

    Missing or invalid pin evidence is unknown, protecting all history. Ended
    bindings remain resumable after the generation-retention grace expires.
    Use the account database, like the launcher, rather than HOME/PLUGIN_ROOT.
    """
    try:
        account_home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        if not account_home.is_absolute():
            return None
        store = HookSessionPinStoreV1.open_at(
            account_home / ".local" / "state" / "the-hive" / "hook-session-pins-v1"
        )
        return frozenset(store.bindings())
    except (HookSessionPinStoreError, OSError, ValueError, OverflowError, KeyError):
        return None


def reservation_is_live(row, now):
    return (
        row["kind"] == "headless_inflight"
        or now - row["created_at"] <= RESERVATION_TTL_SECONDS
    )


def _eligible_history(document, retained_session_ids, stopped_managed_sessions):
    """The one eligibility policy used for count and byte retention."""
    result = document
    if retained_session_ids is None:
        return {"agents": [], "sessions": []}
    roots = set(retained_session_ids)
    managed_reservations = {
        row["managed_session"]
        for row in result["reservations"]
        if row["kind"] == "managed_replacement"
    }
    for row in result["reservations"]:
        roots.update(
            row[key]
            for key in ("parent_session_id", "agent", "assignment_id")
            if key in row
        )
    for row in result["sessions"]:
        if row["activity_state"] == "active" or (
            "managed_session" in row
            and (
                row["managed_session"] not in stopped_managed_sessions
                or row["managed_session"] in managed_reservations
            )
        ):
            roots.add(row["session_id"])
    # Every child association is a reference to its parent thread. In particular,
    # a completed subagent that itself owns descendants must remain resumable.
    referenced_parents = {row["session_id"] for row in result["agents"]}

    remaining_references = roots | {
        value
        for row in result["agents"]
        for value in (row["session_id"], row["agent_id"])
    }
    return {
        "agents": [
            index
            for index, row in enumerate(result["agents"])
            if row["activity_state"] == "completed"
            and row["session_id"] not in roots
            and row["agent_id"] not in roots
            and row["agent_id"] not in referenced_parents
        ],
        "sessions": [
            index
            for index, row in enumerate(result["sessions"])
            if row["activity_state"] == "ended"
            and row["session_id"] not in remaining_references
        ],
    }


def cleanup_registry(
    document,
    *,
    now,
    retained_session_ids,
    stopped_managed_sessions=frozenset(),
    history_limit=HISTORY_LIMIT,
):
    """Retain protected rows and the newest eligible terminal history.

    Call under the registry writer lock. ``stopped_managed_sessions`` is only
    supplied by an existing lifecycle-locked stop after full home-process and
    lease confirmation; it releases ended parent history, never child proof.
    The pin snapshot is acquired after the registry lock. ABI dispatch releases
    its pin-store lock before executing a hook, so this introduces no lock cycle.
    """
    result = normalize_registry(document)
    if result is None:
        raise ValueError("invalid native registry")
    result["reservations"] = [
        row for row in result["reservations"] if reservation_is_live(row, now)
    ]
    for collection in ("agents", "sessions"):
        candidates = _eligible_history(
            result, retained_session_ids, stopped_managed_sessions
        )[collection]
        candidates.sort(
            key=lambda index: (result[collection][index]["updated_at"], index)
        )
        removed = set(candidates[: max(0, len(candidates) - history_limit)])
        result[collection] = [
            row for index, row in enumerate(result[collection]) if index not in removed
        ]
    return result


def encode_registry_for_write(
    document, *, now, stopped_managed_sessions=frozenset(), max_bytes=BYTE_LIMIT
):
    retained_ids = retained_pin_session_ids(now)
    cleaned = cleanup_registry(
        document,
        now=now,
        retained_session_ids=retained_ids,
        stopped_managed_sessions=stopped_managed_sessions,
    )

    def json_bytes(value):
        return json.dumps(value, sort_keys=True, allow_nan=False).encode("utf-8")

    encoded = json_bytes(cleaned) + b"\n"
    size = len(encoded)
    while size > max_bytes:
        eligibility = _eligible_history(cleaned, retained_ids, stopped_managed_sessions)
        candidates = [
            (cleaned[collection][index]["updated_at"], collection, index)
            for collection, indices in eligibility.items()
            for index in indices
        ]
        if not candidates:
            raise RegistryByteBudgetError("native agent registry byte budget exceeded")
        candidates.sort()
        removed = {"agents": set(), "sessions": set()}
        counts = {collection: len(cleaned[collection]) for collection in removed}
        for _timestamp, collection, index in candidates:
            row_size = len(json_bytes(cleaned[collection][index]))
            # Default JSON list separators contribute two bytes except when
            # removing the sole remaining element. No document reserialization
            # is needed for each removal.
            size -= row_size + (2 if counts[collection] > 1 else 0)
            counts[collection] -= 1
            removed[collection].add(index)
            if size <= max_bytes:
                break
        for collection, indices in removed.items():
            cleaned[collection] = [
                row
                for index, row in enumerate(cleaned[collection])
                if index not in indices
            ]
        # Removing history can release previously referenced parent history.
        # Re-evaluate exactly the same policy before any further removal.
    if size != len(encoded):
        encoded = json_bytes(cleaned) + b"\n"
    if len(encoded) > max_bytes:
        raise RegistryByteBudgetError("native agent registry byte budget exceeded")
    return encoded
