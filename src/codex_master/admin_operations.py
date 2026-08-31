"""Durable, idempotent plans and progress for Masterjet administration."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Protocol
import uuid

from codex_master.admin_contracts import AdminContractError, OperationV1
from codex_master.hive.state import HiveStateError, HiveStateStore


MAX_OPERATION_RECORDS = 256
MAX_OPERATION_STEPS = 1_000
MAX_OPERATION_V1_STATE_BYTES = 2 * 1024 * 1024
# Largest canonical `,"owner":...` admitted by owner validation below.
_MAX_OWNER_METADATA_BYTES = len(
    b',"owner":{"boot_id":"ffffffff-ffff-ffff-ffff-ffffffffffff",'
    b'"pid":2147483647,"start_ticks":9223372036854775807}'
)
MAX_OPERATION_V2_STATE_BYTES = (
    MAX_OPERATION_V1_STATE_BYTES
    + MAX_OPERATION_RECORDS * _MAX_OWNER_METADATA_BYTES
)
OPERATION_LIFETIME = timedelta(minutes=15)

_DOCUMENT = PurePosixPath("operations.json")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_BOOT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z",
    re.ASCII,
)
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
        "owner",
        "steps",
        "reason_codes",
    }
)
_LEGACY_RECORD_FIELDS = _RECORD_FIELDS - {"owner"}
_STEP_FIELDS = frozenset({"name", "state", "reason_code"})
_OWNER_FIELDS = frozenset({"boot_id", "pid", "start_ticks"})
_UNKNOWN_OWNER_FIELDS = frozenset({"status"})

OwnerIdentity = tuple[str, int, int]


class _OwnerProbe(Protocol):
    def current(self) -> OwnerIdentity: ...

    def is_alive(self, owner: OwnerIdentity) -> bool | None: ...


class _LinuxOwnerProbe:
    @staticmethod
    def _boot_id() -> str:
        try:
            value = Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()
        except (OSError, UnicodeError):
            raise AdminOperationError("control.operation_owner_unavailable") from None
        if _BOOT_ID.fullmatch(value) is None:
            raise AdminOperationError("control.operation_owner_unavailable")
        return value

    @staticmethod
    def _start_ticks(pid: int) -> int | None:
        try:
            stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError):
            raise AdminOperationError("control.operation_owner_unavailable") from None
        fields = stat_text.rsplit(")", 1)[-1].split()
        if len(fields) <= 19 or not fields[19].isdigit():
            raise AdminOperationError("control.operation_owner_unavailable")
        value = int(fields[19])
        if value <= 0:
            raise AdminOperationError("control.operation_owner_unavailable")
        return value

    def current(self) -> OwnerIdentity:
        pid = os.getpid()
        start_ticks = self._start_ticks(pid)
        if start_ticks is None:
            raise AdminOperationError("control.operation_owner_unavailable")
        return self._boot_id(), pid, start_ticks

    def is_alive(self, owner: OwnerIdentity) -> bool | None:
        boot_id, pid, start_ticks = owner
        try:
            if self._boot_id() != boot_id:
                return False
            observed = self._start_ticks(pid)
        except AdminOperationError:
            return None
        return observed == start_ticks if observed is not None else False


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
        owner_probe: _OwnerProbe | None = None,
    ) -> None:
        if not isinstance(state_root, Path) or not state_root.is_absolute():
            raise AdminOperationError("control.operation_store_unavailable")
        self._root = state_root / "admin-operations"
        self._clock = clock or (lambda: datetime.now(UTC))
        self._owner_probe = owner_probe or _LinuxOwnerProbe()
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
        owner_probe: _OwnerProbe | None = None,
    ) -> AdminOperationStore:
        return cls(state_root, clock=clock, owner_probe=owner_probe)

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
            if self._prune_expired(records, now):
                self._write_locked(records)
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
                "owner": None,
                "steps": [
                    {"name": step, "state": "not_attempted", "reason_code": None}
                    for step in steps
                ],
                "reason_codes": ["control.plan_ready"],
            }
            records.append(record)
            self._write_locked(records)
            return self._plan(record)

    def lookup_plan(
        self,
        *,
        kind: str,
        generation: int,
        key: str,
        steps: tuple[str, ...],
    ) -> AdminOperationPlan | None:
        """Return a live idempotent plan without creating or pruning records."""

        kind = self._token(kind)
        generation = self._generation(generation)
        key = self._token(key)
        steps = self._steps(steps)
        digest = self._plan_digest(kind, generation, steps)
        now = self._now()
        with self._locked_records() as records:
            for record in records:
                if record["idempotency_key"] != key or (
                    record["state"] != "running"
                    and self._parse_time(record["expires_at"]) <= now
                ):
                    continue
                if (
                    record["kind"] != kind
                    or record["expected_generation"] != generation
                    or tuple(step["name"] for step in record["steps"]) != steps
                    or record["plan_digest"] != digest
                ):
                    raise AdminOperationError("control.idempotency_conflict")
                return self._plan(record)
        return None

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
            record["owner"] = self._owner_document(self._current_owner())
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
            if not reason_codes and state in {"partial", "failed", "blocked"}:
                reason_codes = tuple(
                    dict.fromkeys(
                        step["reason_code"]
                        for step in record["steps"]
                        if step["state"] == "failed"
                        and step["reason_code"] is not None
                    )
                )
            record["state"] = state
            record["resulting_generation"] = resulting_generation
            record["reason_codes"] = list(reason_codes)
            record["owner"] = None
            self._validate_state(record, "control.operation_invalid")
            self._write_locked(records)
            return self._operation(record)

    def get(self, operation_id: str) -> OperationV1:
        operation_id = self._token(operation_id)
        with self._locked_records() as records:
            return self._operation(self._find(records, operation_id))

    def resume_host_probe(
        self, operation_id: str, *, expected_generation: int
    ) -> OperationV1:
        """Reclaim only a dead-owner host probe reconciled by this store."""

        operation_id = self._token(operation_id)
        expected_generation = self._generation(expected_generation)
        with self._locked_records() as records:
            record = self._find(records, operation_id)
            if (
                record["kind"] != "hosts.probe"
                or record["expected_generation"] != expected_generation
                or tuple(step["name"] for step in record["steps"])
                != ("host.probe.collect",)
                or record["state"] != "partial"
                or record["reason_codes"] != ["control.restart_reconciled"]
                or record["owner"] is not None
            ):
                raise AdminOperationError("control.operation_state_conflict")
            if self._parse_time(record["expires_at"]) <= self._now():
                raise AdminOperationError("control.plan_expired")
            record["owner"] = self._owner_document(self._current_owner())
            record["state"] = "running"
            record["reason_codes"] = ["control.operation_running"]
            self._write_locked(records)
            return self._operation(record)

    def expire_host_probe(
        self,
        operation_id: str,
        *,
        expected_generation: int,
        plan_digest: str,
    ) -> OperationV1:
        """Fail only an exact expired or failure-reconciled host probe."""

        operation_id = self._token(operation_id)
        expected_generation = self._generation(expected_generation)
        if type(plan_digest) is not str or _DIGEST.fullmatch(plan_digest) is None:
            raise AdminOperationError("control.operation_invalid")
        with self._locked_records() as records:
            record = self._find(records, operation_id)
            exact_pair = (
                record["kind"] == "hosts.probe"
                and record["expected_generation"] == expected_generation
                and record["plan_digest"] == plan_digest
                and tuple(step["name"] for step in record["steps"])
                == ("host.probe.collect",)
            )
            not_attempted_step = [
                {
                    "name": "host.probe.collect",
                    "state": "not_attempted",
                    "reason_code": None,
                }
            ]
            failed_step = [
                {
                    "name": "host.probe.collect",
                    "state": "failed",
                    "reason_code": "host.probe_unknown",
                }
            ]
            terminal = (
                record["state"] == "failed"
                and record["owner"] is None
                and record["resulting_generation"] is None
                and record["reason_codes"] == ["host.probe_unknown"]
                and record["steps"] == failed_step
            )
            if exact_pair and terminal:
                return self._operation(record)
            planned = (
                record["state"] == "planned"
                and record["owner"] is None
                and record["resulting_generation"] is None
                and record["reason_codes"] == ["control.plan_ready"]
                and record["steps"] == not_attempted_step
            )
            restart_reconciled_failure = (
                record["state"] == "partial"
                and record["owner"] is None
                and record["resulting_generation"] is None
                and record["reason_codes"] == ["control.restart_reconciled"]
                and record["steps"] in (not_attempted_step, failed_step)
            )
            if (
                not exact_pair
                or not (planned or restart_reconciled_failure)
                or self._parse_time(record["expires_at"]) > self._now()
            ):
                raise AdminOperationError("control.operation_state_conflict")
            record["state"] = "failed"
            record["steps"][0]["state"] = "failed"
            record["steps"][0]["reason_code"] = "host.probe_unknown"
            record["reason_codes"] = ["host.probe_unknown"]
            self._validate_state(record, "control.operation_invalid")
            self._write_locked(records)
            return self._operation(record)

    def _reconcile_running(self) -> None:
        with self._locked_records() as records:
            changed = False
            for record in records:
                if record["state"] == "running" and self._owner_is_dead(
                    record["owner"]
                ):
                    record["state"] = "partial"
                    record["reason_codes"] = ["control.restart_reconciled"]
                    record["owner"] = None
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
                _DOCUMENT, max_bytes=MAX_OPERATION_V2_STATE_BYTES
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
            or type(document.get("schema_version")) is not int
            or document.get("schema_version") not in {1, 2}
            or type(document.get("operations")) is not list
            or len(document["operations"]) > MAX_OPERATION_RECORDS
        ):
            raise AdminOperationError("control.operation_store_unavailable")
        legacy = document.get("schema_version") == 1
        if len(raw) > (
            MAX_OPERATION_V1_STATE_BYTES
            if legacy
            else MAX_OPERATION_V2_STATE_BYTES
        ):
            raise AdminOperationError("control.operation_store_unavailable")
        records: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        seen_keys: set[str] = set()
        for item in document["operations"]:
            if legacy:
                if not isinstance(item, Mapping) or frozenset(item) not in {
                    _LEGACY_RECORD_FIELDS,
                    _RECORD_FIELDS,
                }:
                    raise AdminOperationError("control.operation_store_unavailable")
                item = dict(item)
                if "owner" not in item:
                    item["owner"] = (
                        {"status": "unknown"}
                        if item.get("state") == "running"
                        else None
                    )
            record = self._validate_record(item)
            if record["id"] in seen_ids or record["idempotency_key"] in seen_keys:
                raise AdminOperationError("control.operation_store_unavailable")
            seen_ids.add(record["id"])
            seen_keys.add(record["idempotency_key"])
            records.append(record)
        if not legacy and len(self._owner_free_document(records)) > (
            MAX_OPERATION_V1_STATE_BYTES
        ):
            raise AdminOperationError("control.operation_store_unavailable")
        if legacy:
            self._prune_expired(records, self._now())
            self._write_locked(records)
        return records

    def _write_locked(self, records: list[dict[str, Any]]) -> None:
        if len(records) > MAX_OPERATION_RECORDS:
            raise AdminOperationError("control.operation_limit")
        try:
            payload = self._owner_free_document(records)
            raw = self._encoded_document(2, records)
            if (
                len(payload) > MAX_OPERATION_V1_STATE_BYTES
                or len(raw) > MAX_OPERATION_V2_STATE_BYTES
            ):
                raise AdminOperationError("control.operation_limit")
            self._state.replace_private_bytes(_DOCUMENT, raw)
        except AdminOperationError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError, RecursionError):
            raise AdminOperationError("control.operation_store_unavailable") from None

    @classmethod
    def _owner_free_document(cls, records: list[dict[str, Any]]) -> bytes:
        return cls._encoded_document(
            1,
            [
                {key: value for key, value in record.items() if key != "owner"}
                for record in records
            ],
        )

    @staticmethod
    def _encoded_document(
        schema_version: int, records: list[dict[str, Any]]
    ) -> bytes:
        return (
            json.dumps(
                {"schema_version": schema_version, "operations": records},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    def _validate_record(self, value: object) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != _RECORD_FIELDS:
            raise AdminOperationError("control.operation_store_unavailable")
        record = dict(value)
        record["id"] = self._stored_token(record["id"])
        record["kind"] = self._stored_token(record["kind"])
        record["idempotency_key"] = self._stored_token(record["idempotency_key"])
        record["owner"] = self._stored_owner_document(record["owner"])
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
        self._validate_state(record, "control.operation_store_unavailable")
        self._operation(record)
        return record

    @staticmethod
    def _validate_state(record: Mapping[str, Any], error_code: str) -> None:
        state = record["state"]
        expected_generation = record["expected_generation"]
        resulting_generation = record["resulting_generation"]
        step_states = tuple(step["state"] for step in record["steps"])
        step_shape_valid = all(
            (step["state"] != "not_attempted" or step["reason_code"] is None)
            and (step["state"] != "failed" or step["reason_code"] is not None)
            for step in record["steps"]
        )
        generation_valid = (
            resulting_generation is None
            or resulting_generation >= expected_generation
        )
        if state in {"planned", "queued"}:
            valid = (
                record["owner"] is None
                and resulting_generation is None
                and all(value == "not_attempted" for value in step_states)
            )
        elif state == "running":
            valid = record["owner"] is not None and resulting_generation is None
        elif state == "succeeded":
            valid = (
                record["owner"] is None
                and resulting_generation is not None
                and all(value == "succeeded" for value in step_states)
            )
        elif state in {"partial", "failed", "blocked"}:
            valid = record["owner"] is None and bool(record["reason_codes"])
        else:
            valid = False
        if not valid or not generation_valid or not step_shape_valid:
            raise AdminOperationError(error_code)

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

    def _current_owner(self) -> OwnerIdentity:
        try:
            return self._owner(self._owner_probe.current())
        except AdminOperationError:
            raise
        except Exception:
            raise AdminOperationError("control.operation_owner_unavailable") from None

    def _owner_is_dead(self, value: object) -> bool:
        if value == {"status": "unknown"}:
            return False
        owner = self._stored_owner(value)
        try:
            alive = self._owner_probe.is_alive(owner)
        except Exception:
            return False
        return alive is False

    @staticmethod
    def _owner(value: object) -> OwnerIdentity:
        if (
            type(value) is not tuple
            or len(value) != 3
            or type(value[0]) is not str
            or _BOOT_ID.fullmatch(value[0]) is None
            or type(value[1]) is not int
            or not 0 < value[1] <= 2**31 - 1
            or type(value[2]) is not int
            or not 0 < value[2] <= 2**63 - 1
        ):
            raise AdminOperationError("control.operation_owner_unavailable")
        return value

    @staticmethod
    def _stored_owner(value: object) -> OwnerIdentity:
        if not isinstance(value, Mapping) or set(value) != _OWNER_FIELDS:
            raise AdminOperationError("control.operation_store_unavailable")
        candidate = (value["boot_id"], value["pid"], value["start_ticks"])
        try:
            return AdminOperationStore._owner(candidate)
        except AdminOperationError:
            raise AdminOperationError("control.operation_store_unavailable") from None

    @staticmethod
    def _stored_owner_document(value: object) -> dict[str, object] | None:
        if value is None:
            return None
        if (
            isinstance(value, Mapping)
            and set(value) == _UNKNOWN_OWNER_FIELDS
            and value.get("status") == "unknown"
        ):
            return {"status": "unknown"}
        return AdminOperationStore._owner_document(
            AdminOperationStore._stored_owner(value)
        )

    @staticmethod
    def _owner_document(owner: OwnerIdentity) -> dict[str, object]:
        return {"boot_id": owner[0], "pid": owner[1], "start_ticks": owner[2]}

    @staticmethod
    def _find(records: list[dict[str, Any]], operation_id: str) -> dict[str, Any]:
        for record in records:
            if record["id"] == operation_id:
                return record
        raise AdminOperationError("control.operation_not_found")

    @staticmethod
    def _prune_expired(records: list[dict[str, Any]], now: datetime) -> bool:
        retained = [
            record
            for record in records
            if record["state"] == "running"
            or AdminOperationStore._parse_time(record["expires_at"]) > now
        ]
        changed = len(retained) != len(records)
        records[:] = retained
        return changed

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
