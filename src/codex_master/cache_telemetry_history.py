"""Bounded, atomic local storage and redacted aggregation for cache telemetry."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Iterator

from .cache_telemetry import (
    CacheTelemetryV1,
    CacheTelemetryValidationError,
    ContextResetTelemetryV1,
)


MAX_HISTORY_RECORDS = 4096
MAX_HISTORY_BYTES = 4 * 1024 * 1024
_HISTORY_SCHEMA_VERSION = 1
_UNKNOWN = "unknown"
TelemetryRecordV1 = CacheTelemetryV1 | ContextResetTelemetryV1


class CacheTelemetryHistoryError(ValueError):
    """The local telemetry journal was malformed, unsafe, or could not be replaced."""


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise CacheTelemetryHistoryError(f"invalid_{field}")
    return value.astimezone(UTC)


def _record_time(record: TelemetryRecordV1) -> datetime:
    return record.observed_at if isinstance(record, CacheTelemetryV1) else record.occurred_at


def _record_from_dict(value: object) -> TelemetryRecordV1:
    if not isinstance(value, dict):
        raise CacheTelemetryHistoryError("invalid_history_record")
    try:
        if value.get("record_kind") == "cache_telemetry_v1":
            return CacheTelemetryV1.from_dict(value)
        if value.get("record_kind") == "context_reset_telemetry_v1":
            return ContextResetTelemetryV1.from_dict(value)
    except CacheTelemetryValidationError as exc:
        raise CacheTelemetryHistoryError("invalid_history_record") from exc
    raise CacheTelemetryHistoryError("invalid_history_record")


def _strict_json(payload: str) -> object:
    def reject_constant(_value: str) -> object:
        raise ValueError("non-finite JSON number")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(payload, parse_constant=reject_constant, object_pairs_hook=reject_duplicates)


def _sorted(records: list[TelemetryRecordV1]) -> list[TelemetryRecordV1]:
    return sorted(records, key=lambda record: (_record_time(record), record.event_key))


def _sum(values: list[int | None]) -> int | None:
    known = [value for value in values if value is not None]
    return None if not known else sum(known)


def _decimal_sum(values: list[Decimal | None]) -> Decimal | None:
    known = [value for value in values if value is not None]
    return None if not known else sum(known, Decimal(0))


def _complete(values: list[object | None]) -> bool:
    return bool(values) and all(value is not None for value in values)


def _ratio(numerator: int | None, denominator: int | None, *, complete: bool) -> Decimal | None:
    if not complete or numerator is None or denominator is None or denominator == 0:
        return None
    return Decimal(numerator) / Decimal(denominator)


def _combined_coverage(values: list[str]) -> str:
    if not values or all(value == "unknown" for value in values):
        return "unknown"
    return "complete" if all(value == "complete" for value in values) else "partial"


def _decimal_text(value: Decimal | None) -> str | None:
    return None if value is None else format(value, "f")


@dataclass(frozen=True, slots=True)
class CacheTelemetryAppendReceiptV1:
    event_key: str
    generation: int
    appended: bool
    retained_record_count: int


@dataclass(frozen=True, slots=True)
class CacheTelemetryAggregateV1:
    """A deterministic, redacted time-bucket aggregate.

    A total is ``None`` when no source event supplied that metric. A ratio is
    ``None`` unless every cache event in the bucket supplied both its numerator
    and native input-token denominator. This prevents an aggregate from turning
    a missing measurement into a zero or a complete-looking rate.
    """

    provider: str
    model: str
    account_ref: str
    context_class: str
    lifecycle: str
    tier: str
    session_id: str
    window_start: datetime
    window_end: datetime
    request_count: int
    reset_count: int
    input_tokens: int | None
    output_tokens: int | None
    reasoning_tokens: int | None
    cache_read_tokens: int | None
    cache_write_tokens: int | None
    cache_miss_tokens: int | None
    cache_read_ratio: Decimal | None
    cache_write_ratio: Decimal | None
    cache_miss_ratio: Decimal | None
    normal_input_cost: Decimal | None
    cache_read_cost: Decimal | None
    cache_write_cost: Decimal | None
    output_cost: Decimal | None
    reasoning_cost: Decimal | None
    reset_coverage: str
    recovery_coverage: str
    recovery_reread_tokens: int | None
    recovery_replayed_tokens: int | None
    recovery_duration_seconds: Decimal | None
    recovery_cost: Decimal | None
    reset_kind_counts: tuple[tuple[str, int], ...]
    coverage: str

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider, "model": self.model,
            "account_ref": self.account_ref, "context_class": self.context_class,
            "lifecycle": self.lifecycle, "tier": self.tier,
            "session_id": self.session_id,
            "window_start": self.window_start.isoformat().replace("+00:00", "Z"),
            "window_end": self.window_end.isoformat().replace("+00:00", "Z"),
            "request_count": self.request_count, "reset_count": self.reset_count,
            "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "cache_miss_tokens": self.cache_miss_tokens,
            "cache_read_ratio": _decimal_text(self.cache_read_ratio),
            "cache_write_ratio": _decimal_text(self.cache_write_ratio),
            "cache_miss_ratio": _decimal_text(self.cache_miss_ratio),
            "normal_input_cost": _decimal_text(self.normal_input_cost),
            "cache_read_cost": _decimal_text(self.cache_read_cost),
            "cache_write_cost": _decimal_text(self.cache_write_cost),
            "output_cost": _decimal_text(self.output_cost),
            "reasoning_cost": _decimal_text(self.reasoning_cost),
            "reset_coverage": self.reset_coverage,
            "recovery_coverage": self.recovery_coverage,
            "recovery_reread_tokens": self.recovery_reread_tokens,
            "recovery_replayed_tokens": self.recovery_replayed_tokens,
            "recovery_duration_seconds": _decimal_text(self.recovery_duration_seconds),
            "recovery_cost": _decimal_text(self.recovery_cost),
            "reset_kind_counts": dict(self.reset_kind_counts), "coverage": self.coverage,
        }


def _bucket(value: datetime, seconds: int) -> tuple[datetime, datetime]:
    timestamp = int(value.timestamp())
    start = datetime.fromtimestamp(timestamp - timestamp % seconds, tz=UTC)
    return start, start + timedelta(seconds=seconds)


def _dimensions(record: TelemetryRecordV1, window_seconds: int) -> tuple[str, str, str, str, str, str, str, datetime, datetime]:
    if isinstance(record, CacheTelemetryV1):
        context_class = record.context_class or _UNKNOWN
        lifecycle = _UNKNOWN
        tier = record.effective_service_tier or record.requested_service_tier or _UNKNOWN
        timestamp = record.observed_at
    else:
        context_class = record.context_class or _UNKNOWN
        lifecycle = record.lifecycle or _UNKNOWN
        tier = _UNKNOWN
        timestamp = record.occurred_at
    start, end = _bucket(timestamp, window_seconds)
    return (
        record.provider, record.model, record.account_ref, context_class,
        lifecycle, tier, record.session_id, start, end,
    )


def aggregate_cache_telemetry(records: tuple[TelemetryRecordV1, ...], *, window_seconds: int = 3600) -> tuple[CacheTelemetryAggregateV1, ...]:
    """Aggregate only safe contract instances by the plan's required dimensions."""

    if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or not 60 <= window_seconds <= 31 * 24 * 60 * 60:
        raise CacheTelemetryHistoryError("invalid_aggregate_window")
    groups: dict[tuple[str, str, str, str, str, str, str, datetime, datetime], list[TelemetryRecordV1]] = {}
    for record in records:
        if not isinstance(record, (CacheTelemetryV1, ContextResetTelemetryV1)):
            raise CacheTelemetryHistoryError("invalid_aggregate_record")
        groups.setdefault(_dimensions(record, window_seconds), []).append(record)
    aggregates: list[CacheTelemetryAggregateV1] = []
    for dimensions, grouped in sorted(groups.items()):
        caches = [record for record in grouped if isinstance(record, CacheTelemetryV1)]
        resets = [record for record in grouped if isinstance(record, ContextResetTelemetryV1)]
        input_values = [record.input_tokens for record in caches]
        read_values = [record.cache_read_tokens for record in caches]
        write_values = [record.cache_write_tokens for record in caches]
        miss_values = [record.cache_miss_tokens for record in caches]
        input_total = _sum(input_values)
        read_total = _sum(read_values)
        write_total = _sum(write_values)
        miss_total = _sum(miss_values)
        complete_input = _complete(input_values)
        reset_counts: dict[str, int] = {}
        for reset in resets:
            reset_counts[reset.reset_kind] = reset_counts.get(reset.reset_kind, 0) + 1
        reset_coverage = _combined_coverage([record.reset_coverage for record in resets])
        recovery_coverage = _combined_coverage([record.recovery_coverage for record in resets])
        coverage = _combined_coverage(
            [record.coverage for record in caches]
            + [record.reset_coverage for record in resets]
            + [record.recovery_coverage for record in resets]
        )
        aggregates.append(CacheTelemetryAggregateV1(
            *dimensions, request_count=len(caches), reset_count=len(resets),
            input_tokens=input_total, output_tokens=_sum([record.output_tokens for record in caches]),
            reasoning_tokens=_sum([record.reasoning_tokens for record in caches]),
            cache_read_tokens=read_total, cache_write_tokens=write_total, cache_miss_tokens=miss_total,
            cache_read_ratio=_ratio(read_total, input_total, complete=complete_input and _complete(read_values)),
            cache_write_ratio=_ratio(write_total, input_total, complete=complete_input and _complete(write_values)),
            cache_miss_ratio=_ratio(miss_total, input_total, complete=complete_input and _complete(miss_values)),
            normal_input_cost=_decimal_sum([record.costs.normal_input_cost for record in caches]),
            cache_read_cost=_decimal_sum([record.costs.cache_read_cost for record in caches]),
            cache_write_cost=_decimal_sum([record.costs.cache_write_cost for record in caches]),
            output_cost=_decimal_sum([record.costs.output_cost for record in caches]),
            reasoning_cost=_decimal_sum([record.costs.reasoning_cost for record in caches]),
            reset_coverage=reset_coverage, recovery_coverage=recovery_coverage,
            recovery_reread_tokens=_sum([record.recovery_reread_tokens for record in resets]),
            recovery_replayed_tokens=_sum([record.recovery_replayed_tokens for record in resets]),
            recovery_duration_seconds=_decimal_sum([record.recovery_duration_seconds for record in resets]),
            recovery_cost=_decimal_sum([record.recovery_cost for record in resets]),
            reset_kind_counts=tuple(sorted(reset_counts.items())), coverage=coverage,
        ))
    return tuple(aggregates)


class CacheTelemetryHistoryV1:
    """A single-file, lock-protected JSON journal with atomic replacement.

    The journal has a fixed schema, byte ceiling, record ceiling, and retention
    window. Its lock serialises read-modify-replace operations; the existing
    document remains valid if a process fails before ``os.replace``.
    """

    def __init__(self, path: Path, *, max_records: int = 1024, retention: timedelta = timedelta(days=7)) -> None:
        if not isinstance(path, Path):
            raise CacheTelemetryHistoryError("invalid_history_path")
        if isinstance(max_records, bool) or not isinstance(max_records, int) or not 1 <= max_records <= MAX_HISTORY_RECORDS:
            raise CacheTelemetryHistoryError("invalid_history_max_records")
        if not isinstance(retention, timedelta) or not timedelta(minutes=1) <= retention <= timedelta(days=365):
            raise CacheTelemetryHistoryError("invalid_history_retention")
        self._path = path
        self._lock_path = path.with_name(f".{path.name}.lock")
        self._max_records = max_records
        self._retention = retention

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            descriptor = os.open(self._lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            raise CacheTelemetryHistoryError("history_lock_failed") from exc
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        except OSError as exc:
            raise CacheTelemetryHistoryError("history_lock_failed") from exc
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _read_unlocked(self) -> tuple[int, list[TelemetryRecordV1]]:
        if not self._path.exists():
            return 0, []
        try:
            descriptor = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                os.close(descriptor)
                raise CacheTelemetryHistoryError("invalid_history_document")
            if metadata.st_size > MAX_HISTORY_BYTES:
                os.close(descriptor)
                raise CacheTelemetryHistoryError("history_too_large")
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                data = _strict_json(handle.read())
        except CacheTelemetryHistoryError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise CacheTelemetryHistoryError("invalid_history_document") from exc
        if not isinstance(data, dict) or set(data) != {"generation", "records", "schema_version"} or data["schema_version"] != _HISTORY_SCHEMA_VERSION:
            raise CacheTelemetryHistoryError("invalid_history_document")
        generation = data["generation"]
        source_records = data["records"]
        if isinstance(generation, bool) or not isinstance(generation, int) or not 0 <= generation <= 2**63 - 1 or not isinstance(source_records, list) or len(source_records) > MAX_HISTORY_RECORDS:
            raise CacheTelemetryHistoryError("invalid_history_document")
        records = [_record_from_dict(record) for record in source_records]
        if len({record.event_key for record in records}) != len(records) or records != _sorted(records):
            raise CacheTelemetryHistoryError("invalid_history_document")
        return generation, records

    def _write_unlocked(self, generation: int, records: list[TelemetryRecordV1]) -> None:
        document = {
            "schema_version": _HISTORY_SCHEMA_VERSION,
            "generation": generation,
            "records": [record.to_dict() for record in records],
        }
        encoded = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_HISTORY_BYTES:
            raise CacheTelemetryHistoryError("history_too_large")
        temporary: Path | None = None
        try:
            descriptor, name = tempfile.mkstemp(prefix=f".{self._path.name}.", dir=self._path.parent)
            temporary = Path(name)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._path)
            temporary = None
            directory_descriptor = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError as exc:
            raise CacheTelemetryHistoryError("history_replace_failed") from exc
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    def append(self, record: TelemetryRecordV1, *, now: datetime) -> CacheTelemetryAppendReceiptV1:
        if not isinstance(record, (CacheTelemetryV1, ContextResetTelemetryV1)):
            raise CacheTelemetryHistoryError("invalid_history_record")
        now = _utc(now, "history_now")
        if _record_time(record) > now:
            raise CacheTelemetryHistoryError("future_history_record")
        with self._exclusive_lock():
            generation, original = self._read_unlocked()
            cutoff = now - self._retention
            records = [item for item in original if _record_time(item) >= cutoff]
            duplicate_record = next((item for item in records if item.event_key == record.event_key), None)
            duplicate = duplicate_record is not None
            if duplicate_record is not None and duplicate_record.to_dict() != record.to_dict():
                raise CacheTelemetryHistoryError("idempotency_conflict")
            if not duplicate:
                records.append(record)
            records = _sorted(records)[-self._max_records:]
            retained = not duplicate and any(item.event_key == record.event_key for item in records)
            changed = records != original
            if changed:
                generation += 1
                self._write_unlocked(generation, records)
            return CacheTelemetryAppendReceiptV1(record.event_key, generation, retained, len(records))

    def read(self, *, now: datetime) -> tuple[TelemetryRecordV1, ...]:
        now = _utc(now, "history_now")
        with self._exclusive_lock():
            _generation, records = self._read_unlocked()
            cutoff = now - self._retention
            retained = [record for record in records if _record_time(record) >= cutoff]
            if retained != records:
                self._write_unlocked(_generation + 1, retained)
            return tuple(retained)

    def aggregate(self, *, now: datetime, window_seconds: int = 3600) -> tuple[CacheTelemetryAggregateV1, ...]:
        return aggregate_cache_telemetry(self.read(now=now), window_seconds=window_seconds)


__all__ = [
    "CacheTelemetryAggregateV1", "CacheTelemetryAppendReceiptV1", "CacheTelemetryHistoryError",
    "CacheTelemetryHistoryV1", "MAX_HISTORY_BYTES", "MAX_HISTORY_RECORDS",
    "aggregate_cache_telemetry",
]
