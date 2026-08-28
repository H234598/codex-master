"""Durable, idempotent plans and progress for Masterjet administration."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any
import uuid

from codex_master.admin_contracts import AdminContractError, OperationV1
from codex_master.hive.state import HiveStateError, HiveStateStore


MAX_OPERATION_RECORDS = 256
MAX_OPERATION_STEPS = 1_000
MAX_OPERATION_STATE_BYTES = 2 * 1024 * 1024
OPERATION_LIFETIME = timedelta(minutes=15)

_DOCUMENT = PurePosixPath("operations.json")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_STEP_STATES = frozenset({"not_attempted", "succeeded", "failed"})
_TERMINAL_STATES = frozenset({"partial", "succeeded", "failed", "blocked"})
_RECORD_FIELDS = frozenset(
    {
        "id",
        "kind",
        "state",
        "expected_generation",
        "resulting_generation",
        "plan_digest",
        "created_at",
        "expires_at",
        "idempotency_key",
        "steps",
        "reason_codes",
    }
)
_STEP_FIELDS = frozenset({"name", "state", "reason_code"})


class AdminOperationError(ValueError):
    """Stable, path-free operation-store error."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class AdminOperationPlan:
    operation_id: str
    plan_digest: str
    expected_generation: int
    created_at: datetime
    expires_at: datetime
    operation: OperationV1


class AdminOperationStore:
    """One bounded private document guarded by Hive's durable CAS lock."""

    def __init__(
        self,
        state_root: Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(state_root, Path) or not state_root.is_absolute():
            raise AdminOperationError("control.operation_store_unavailable")
        self._root = state_root / "admin-operations"
        self._clock = clock or (lambda: datetime.now(UTC))
        try:
            self._state = HiveStateStore(self._root)
            self._reconcile_running()
        except (HiveStateError, OSError, ValueError):
            raise AdminOperationError("control.operation_store_unavailable") from None

    @classmethod
    def for_test(
        cls,
        state_root: Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> AdminOperationStore:
        return cls(state_root, clock=clock)

    def plan(
        self,
        *,
        kind: str,
        generation: int,
        key: str,
        steps: tuple[str, ...],
    ) -> AdminOperationPlan:
        kind = self._token(kind)
        generation = self._generation(generation)
        key = self._token(key)
        steps = self._steps(steps)
        digest = self._plan_digest(kind, generation, steps)
        now = self._now()

        with self._locked_records() as records:
            self._prune(records, now)
            for record in records:
                if record["idempotency_key"] != key:
                    continue
                if (
                    record["kind"] != kind
                    or record["expected_generation"] != generation
                    or tuple(step["name"] for step in record["steps"]) != steps
                    or record["plan_digest"] != digest
                ):
                    raise AdminOperationError("control.idempotency_conflict")
                return self._plan(record)

            if len(records) >= MAX_OPERATION_RECORDS:
                raise AdminOperationError("control.operation_limit")
            operation_id = self._new_id(records)
            record: dict[str, Any] = {
                "id": operation_id,
                "kind": kind,
                "state": "planned",
                "expected_generation": generation,
                "resulting_generation": None,
                "plan_digest": digest,
                "created_at": self._wire_time(now),
                "expires_at": self._wire_time(now + OPERATION_LIFETIME),
                "idempotency_key": key,
                "steps": [
                    {"name": step, "state": "not_attempted", "reason_code": None}
                    for step in steps
                ],
                "reason_codes": ["control.plan_ready"],
            }
            records.append(record)
            self._write_locked(records)
            return self._plan(record)

    def begin(self, operation_id: str, *, current_generation: int) -> OperationV1:
        operation_id = self._token(operation_id)
        current_generation = self._generation(current_generation)
        with self._locked_records() as records:
            record = self._find(records, operation_id)
            if record["expected_generation"] != current_generation:
                raise AdminOperationError("control.plan_stale")
            if record["state"] != "planned":
                raise AdminOperationError("control.operation_state_conflict")
            if self._parse_time(record["expires_at"]) <= self._now():
                raise AdminOperationError("control.plan_expired")
            record["state"] = "running"
            record["reason_codes"] = ["control.operation_running"]
            self._write_locked(records)
            return self._operation(record)

    def record_step(
        self,
        operation_id: str,
        step: str,
        *,
        succeeded: bool,
        reason_code: str | None = None,
    ) -> OperationV1:
        operation_id = self._token(operation_id)
        step = self._token(step)
        if type(succeeded) is not bool:
            raise AdminOperationError("control.operation_invalid")
        if reason_code is not None:
            reason_code = self._token(reason_code)
        with self._locked_records() as records:
            record = self._find(records, operation_id)
            if record["state"] != "running":
                raise AdminOperationError("control.operation_state_conflict")
            matched = next(
                (candidate for candidate in record["steps"] if candidate["name"] == step),
                None,
            )
            if matched is None:
                raise AdminOperationError("control.step_unknown")
            if matched["state"] != "not_attempted":
                raise AdminOperationError("control.step_already_recorded")
            matched["state"] = "succeeded" if succeeded else "failed"
            matched["reason_code"] = (
                reason_code
                if succeeded or reason_code is not None
                else "control.step_failed"
            )
            codes = [
                candidate["reason_code"]
                for candidate in record["steps"]
                if candidate["reason_code"] is not None
            ]
            record["reason_codes"] = list(dict.fromkeys(codes))
            self._write_locked(records)
            return self._operation(record)

    def finish(
        self,
        operation_id: str,
        *,
        state: str,
        resulting_generation: int | None = None,
        reason_codes: tuple[str, ...] = (),
    ) -> OperationV1:
        operation_id = self._token(operation_id)
        state = self._token(state)
        if state not in _TERMINAL_STATES:
            raise AdminOperationError("control.operation_invalid")
        if resulting_generation is not None:
            resulting_generation = self._generation(resulting_generation)
        reason_codes = self._reason_codes(reason_codes)
        with self._locked_records() as records:
            record = self._find(records, operation_id)
            if record["state"] != "running":
                raise AdminOperationError("control.operation_state_conflict")
            step_states = tuple(step["state"] for step in record["steps"])
            if state == "succeeded" and (
                any(step_state != "succeeded" for step_state in step_states)
                or resulting_generation is None
                or resulting_generation < record["expected_generation"]
            ):
                raise AdminOperationError("control.operation_invalid")
            record["state"] = state
            record["resulting_generation"] = resulting_generation
            record["reason_codes"] = list(reason_codes)
            self._write_locked(records)
            return self._operation(record)

    def get(self, operation_id: str) -> OperationV1:
        operation_id = self._token(operation_id)
        with self._locked_records() as records:
            return self._operation(self._find(records, operation_id))

    def _reconcile_running(self) -> None:
        with self._locked_records() as records:
            changed = False
            for record in records:
                if record["state"] == "running":
                    record["state"] = "partial"
                    record["reason_codes"] = ["control.restart_reconciled"]
                    changed = True
            if changed:
                self._write_locked(records)

    @contextlib.contextmanager
    def _locked_records(self) -> Any:
        try:
            with self._state.locked():
                yield self._read_locked()
        except AdminOperationError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError):
            raise AdminOperationError("control.operation_store_unavailable") from None

    def _read_locked(self) -> list[dict[str, Any]]:
        try:
            raw = self._state.read_private_bytes(
                _DOCUMENT, max_bytes=MAX_OPERATION_STATE_BYTES
            )
        except HiveStateError as exc:
            if exc.args == ("state_not_found",):
                return []
            raise AdminOperationError("control.operation_store_unavailable") from None
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise AdminOperationError("control.operation_store_unavailable") from None
        if (
            not isinstance(document, Mapping)
            or set(document) != {"schema_version", "operations"}
            or document.get("schema_version") != 1
            or type(document.get("operations")) is not list
            or len(document["operations"]) > MAX_OPERATION_RECORDS
        ):
            raise AdminOperationError("control.operation_store_unavailable")
        records: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        seen_keys: set[str] = set()
        for item in document["operations"]:
            record = self._validate_record(item)
            if record["id"] in seen_ids or record["idempotency_key"] in seen_keys:
                raise AdminOperationError("control.operation_store_unavailable")
            seen_ids.add(record["id"])
            seen_keys.add(record["idempotency_key"])
            records.append(record)
        return records

    def _write_locked(self, records: list[dict[str, Any]]) -> None:
        if len(records) > MAX_OPERATION_RECORDS:
            raise AdminOperationError("control.operation_limit")
        try:
            raw = (
                json.dumps(
                    {"schema_version": 1, "operations": records},
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            if len(raw) > MAX_OPERATION_STATE_BYTES:
                raise AdminOperationError("control.operation_limit")
            self._state.replace_private_bytes(_DOCUMENT, raw)
        except AdminOperationError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError, RecursionError):
            raise AdminOperationError("control.operation_store_unavailable") from None

    def _validate_record(self, value: object) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != _RECORD_FIELDS:
            raise AdminOperationError("control.operation_store_unavailable")
        record = dict(value)
        record["id"] = self._stored_token(record["id"])
        record["kind"] = self._stored_token(record["kind"])
        record["idempotency_key"] = self._stored_token(record["idempotency_key"])
        record["expected_generation"] = self._stored_generation(
            record["expected_generation"]
        )
        if record["resulting_generation"] is not None:
            record["resulting_generation"] = self._stored_generation(
                record["resulting_generation"]
            )
        if type(record["plan_digest"]) is not str or _DIGEST.fullmatch(
            record["plan_digest"]
        ) is None:
            raise AdminOperationError("control.operation_store_unavailable")
        created = self._parse_time(record["created_at"])
        expires = self._parse_time(record["expires_at"])
        if expires != created + OPERATION_LIFETIME:
            raise AdminOperationError("control.operation_store_unavailable")
        if type(record["steps"]) is not list or not 1 <= len(
            record["steps"]
        ) <= MAX_OPERATION_STEPS:
            raise AdminOperationError("control.operation_store_unavailable")
        names: set[str] = set()
        steps: list[dict[str, str | None]] = []
        for value_step in record["steps"]:
            if not isinstance(value_step, Mapping) or set(value_step) != _STEP_FIELDS:
                raise AdminOperationError("control.operation_store_unavailable")
            name = self._stored_token(value_step["name"])
            state = value_step["state"]
            reason_code = value_step["reason_code"]
            if name in names or state not in _STEP_STATES:
                raise AdminOperationError("control.operation_store_unavailable")
            if reason_code is not None:
                reason_code = self._stored_token(reason_code)
            names.add(name)
            steps.append({"name": name, "state": state, "reason_code": reason_code})
        record["steps"] = steps
        if record["plan_digest"] != self._plan_digest(
            record["kind"],
            record["expected_generation"],
            tuple(step["name"] for step in steps),
        ):
            raise AdminOperationError("control.operation_store_unavailable")
        if type(record["reason_codes"]) is not list or len(record["reason_codes"]) > 32:
            raise AdminOperationError("control.operation_store_unavailable")
        record["reason_codes"] = [
            self._stored_token(code) for code in record["reason_codes"]
        ]
        self._operation(record)
        return record

    def _operation(self, record: Mapping[str, Any]) -> OperationV1:
        steps = record["steps"]
        try:
            return OperationV1(
                id=record["id"],
                kind=record["kind"],
                state=record["state"],
                expected_generation=record["expected_generation"],
                resulting_generation=record["resulting_generation"],
                plan_digest=record["plan_digest"],
                created_at=self._parse_time(record["created_at"]),
                expires_at=self._parse_time(record["expires_at"]),
                completed_count=sum(step["state"] == "succeeded" for step in steps),
                failed_count=sum(step["state"] == "failed" for step in steps),
                not_attempted_count=sum(
                    step["state"] == "not_attempted" for step in steps
                ),
                reason_codes=tuple(record["reason_codes"]),
            )
        except (AdminContractError, KeyError, TypeError, ValueError):
            raise AdminOperationError("control.operation_store_unavailable") from None

    def _plan(self, record: Mapping[str, Any]) -> AdminOperationPlan:
        operation = self._operation(record)
        return AdminOperationPlan(
            operation_id=operation.id,
            plan_digest=operation.plan_digest,
            expected_generation=operation.expected_generation,
            created_at=operation.created_at,
            expires_at=operation.expires_at,
            operation=operation,
        )

    @staticmethod
    def _find(records: list[dict[str, Any]], operation_id: str) -> dict[str, Any]:
        for record in records:
            if record["id"] == operation_id:
                return record
        raise AdminOperationError("control.operation_not_found")

    @staticmethod
    def _prune(records: list[dict[str, Any]], now: datetime) -> None:
        if len(records) < MAX_OPERATION_RECORDS:
            return
        retained = [
            record
            for record in records
            if record["state"] not in _TERMINAL_STATES
            or AdminOperationStore._parse_time(record["expires_at"]) > now
        ]
        records[:] = retained
        if len(records) < MAX_OPERATION_RECORDS:
            return
        for record in tuple(records):
            if len(records) < MAX_OPERATION_RECORDS:
                break
            if record["state"] in _TERMINAL_STATES:
                records.remove(record)

    @staticmethod
    def _new_id(records: list[dict[str, Any]]) -> str:
        existing = {record["id"] for record in records}
        for _attempt in range(8):
            candidate = f"op-{uuid.uuid4().hex}"
            if candidate not in existing:
                return candidate
        raise AdminOperationError("control.operation_store_unavailable")

    @staticmethod
    def _plan_digest(kind: str, generation: int, steps: tuple[str, ...]) -> str:
        payload = json.dumps(
            {"generation": generation, "kind": kind, "steps": list(steps)},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _token(value: object) -> str:
        if type(value) is not str or _TOKEN.fullmatch(value) is None:
            raise AdminOperationError("control.operation_invalid")
        return value

    @staticmethod
    def _stored_token(value: object) -> str:
        try:
            return AdminOperationStore._token(value)
        except AdminOperationError:
            raise AdminOperationError("control.operation_store_unavailable") from None

    @staticmethod
    def _generation(value: object) -> int:
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise AdminOperationError("control.operation_invalid")
        return value

    @staticmethod
    def _stored_generation(value: object) -> int:
        try:
            return AdminOperationStore._generation(value)
        except AdminOperationError:
            raise AdminOperationError("control.operation_store_unavailable") from None

    @staticmethod
    def _steps(value: object) -> tuple[str, ...]:
        if type(value) is not tuple or not 1 <= len(value) <= MAX_OPERATION_STEPS:
            raise AdminOperationError("control.operation_invalid")
        steps = tuple(AdminOperationStore._token(step) for step in value)
        if len(set(steps)) != len(steps):
            raise AdminOperationError("control.operation_invalid")
        return steps

    @staticmethod
    def _reason_codes(value: object) -> tuple[str, ...]:
        if type(value) is not tuple or len(value) > 32:
            raise AdminOperationError("control.operation_invalid")
        return tuple(AdminOperationStore._token(code) for code in value)

    def _now(self) -> datetime:
        value = self._clock()
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise AdminOperationError("control.operation_store_unavailable")
        return value.astimezone(UTC)

    @staticmethod
    def _wire_time(value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")

    @staticmethod
    def _parse_time(value: object) -> datetime:
        if type(value) is not str or not value.endswith("Z") or len(value) > 40:
            raise AdminOperationError("control.operation_store_unavailable")
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError:
            raise AdminOperationError("control.operation_store_unavailable") from None
        if parsed.utcoffset() != timedelta(0):
            raise AdminOperationError("control.operation_store_unavailable")
        return parsed.astimezone(UTC)


__all__ = [
    "AdminOperationError",
    "AdminOperationPlan",
    "AdminOperationStore",
]
