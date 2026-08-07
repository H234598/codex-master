from __future__ import annotations

import contextlib
import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace as dataclass_replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ContextManager

from .fleet_registry import (
    FleetAccount,
    FleetSeries,
    FleetSnapshot,
    InventorySnapshot,
    LimitState,
    SecretState,
    build_inventory,
    fleet_document,
    mark_account_limit,
    normalize_fleet_document,
    plan_account_delete,
    plan_account_upsert,
    public_fleet_snapshot,
)
from .fleet_runners import ProbeResult


MAX_REGISTRY_BYTES = 1024 * 1024
MAX_LIMIT_BYTES = 256 * 1024
MAX_RATE_LIMIT_BYTES = 256 * 1024
MAX_USAGE_BYTES = 1024 * 1024
MAX_EVENT_BYTES = 512 * 1024
MAX_SECRET_BYTES = 16 * 1024
GEMINI_MIN_REQUEST_INTERVAL_SECONDS = 60
GEMINI_REQUEST_LEASE_SECONDS = 120 * 60 + 60
GEMINI_INITIAL_429_COOLDOWN_SECONDS = 15 * 60
GEMINI_MAX_429_COOLDOWN_SECONDS = 24 * 60 * 60
_ACCOUNT_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_LIMIT_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class FleetConflictError(ValueError):
    pass


class FleetSecretError(ValueError):
    pass


class FleetRateLimitError(ValueError):
    def __init__(self, reason: str, retry_after_seconds: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_after_seconds = max(0, int(retry_after_seconds))


@dataclass(frozen=True, slots=True)
class GeminiRequestReservation:
    account_id: str
    reservation_id: str
    expires_at_utc: str


@dataclass(frozen=True, slots=True)
class AccountGateDecision:
    allowed: bool
    reason: str
    account_id: str | None
    generation: int


@dataclass(frozen=True, slots=True)
class FleetPaths:
    root: Path = field(repr=False)
    registry: Path = field(repr=False)
    secrets: Path = field(repr=False)
    limits: Path = field(repr=False)
    rate_limits: Path = field(repr=False)
    lock: Path = field(repr=False)
    recovery: Path = field(repr=False)
    mutation_lock: Path = field(repr=False)
    usage: Path = field(repr=False)
    events: Path = field(repr=False)

    @classmethod
    def from_state_root(cls, root: Path) -> FleetPaths:
        fleet_root = root / "fleet"
        return cls(
            root=fleet_root,
            registry=fleet_root / "registry.json",
            secrets=fleet_root / "secrets",
            limits=fleet_root / "limits.json",
            rate_limits=fleet_root / "rate-limits.json",
            lock=fleet_root / "registry.lock",
            recovery=fleet_root / "recovery.json",
            mutation_lock=fleet_root / "mutation.lock",
            usage=fleet_root / "usage.json",
            events=fleet_root / "events.jsonl",
        )


@dataclass(frozen=True, slots=True)
class FleetPrivateIO:
    ensure_dir: Callable[[Path], None]
    read_text: Callable[[Path, int, str], str | None]
    replace_text: Callable[[Path, str], None]
    read_bytes: Callable[[Path, int, str], bytes | None]
    replace_bytes: Callable[[Path, bytes, int], None]
    lock: Callable[[], ContextManager[None]]
    utc_now: Callable[[], datetime]
    remove_file: Callable[[Path], bool] | None = None


class FleetService:
    def __init__(
        self,
        paths: FleetPaths,
        private_io: FleetPrivateIO,
        *,
        pool_root: Path,
        probe_max_age_seconds: int = 900,
        read_only: bool = False,
    ) -> None:
        self._paths = paths
        self._io = private_io
        self._pool_root = pool_root
        if not isinstance(read_only, bool):
            raise ValueError("invalid_fleet_read_only")
        self._read_only = read_only
        if (
            isinstance(probe_max_age_seconds, bool)
            or not isinstance(probe_max_age_seconds, int)
            or not 1 <= probe_max_age_seconds <= 900
        ):
            raise ValueError("invalid_probe_max_age")
        self._probe_max_age_seconds = probe_max_age_seconds

    def _ensure_layout(self) -> None:
        self._io.ensure_dir(self._paths.root)
        self._io.ensure_dir(self._paths.secrets)

    def _load_registry(self) -> FleetSnapshot:
        self._ensure_layout()
        text = self._io.read_text(
            self._paths.registry,
            MAX_REGISTRY_BYTES,
            "could_not_read_fleet_registry",
        )
        if text is None:
            return FleetSnapshot(1, 1, (), ())
        try:
            raw = json.loads(text)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise ValueError("invalid_fleet_registry") from exc
        return normalize_fleet_document(raw)

    def _write_registry(self, snapshot: FleetSnapshot) -> FleetSnapshot:
        document = fleet_document(snapshot)
        text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        self._io.replace_text(self._paths.registry, text)
        stored = self._load_registry()
        if stored != snapshot:
            raise ValueError("fleet_registry_write_verification_failed")
        return stored

    @staticmethod
    def _parse_time(value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not 1 <= len(value) <= 40:
            raise ValueError("invalid_fleet_limits")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("invalid_fleet_limits") from None
        if parsed.tzinfo is None:
            raise ValueError("invalid_fleet_limits")
        return value

    def _quarantine_limits(self, reason: str = "invalid_fleet_limits") -> None:
        """Record a redacted limits failure without overwriting the WAL journal."""

        marker = self._paths.recovery.with_name("limits.recovery.json")
        try:
            self._io.replace_text(
                marker,
                json.dumps({"schema_version": 1, "kind": "fleet_limits_quarantine", "reason": reason}) + "\n",
            )
        except Exception:
            pass

    def _load_limits(self) -> dict[str, dict[str, str | None]]:
        self._ensure_layout()
        try:
            text = self._io.read_text(
                self._paths.limits,
                MAX_LIMIT_BYTES,
                "could_not_read_fleet_limits",
            )
            if text is None:
                return {}
            raw = json.loads(text)
            if (
                not isinstance(raw, dict)
                or set(raw) != {"schema_version", "accounts"}
                or raw.get("schema_version") != 1
                or not isinstance(raw.get("accounts"), dict)
            ):
                raise ValueError("invalid_fleet_limits")
            entries: dict[str, dict[str, str | None]] = {}
            for account_id, value in raw["accounts"].items():
                if (
                    not isinstance(account_id, str)
                    or not _ACCOUNT_ID_RE.fullmatch(account_id)
                    or not isinstance(value, dict)
                    or set(value) != {"reset_at_utc", "reason"}
                ):
                    raise ValueError("invalid_fleet_limits")
                reason = value.get("reason")
                if not isinstance(reason, str) or not _LIMIT_REASON_RE.fullmatch(reason):
                    raise ValueError("invalid_fleet_limits")
                entries[account_id] = {
                    "reset_at_utc": self._parse_time(value.get("reset_at_utc")),
                    "reason": reason,
                }
            return entries
        except Exception:
            self._quarantine_limits()
            if self._read_only:
                raise ValueError("invalid_fleet_limits") from None
            return {}

    def _write_limits(self, entries: dict[str, dict[str, str | None]]) -> None:
        document = {"schema_version": 1, "accounts": entries}
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self._io.replace_text(self._paths.limits, text)
        if self._load_limits() != entries:
            raise ValueError("fleet_limits_write_verification_failed")

    def _quarantine_rate_limits(self, reason: str = "invalid_gemini_rate_limits") -> None:
        marker = self._paths.recovery.with_name("rate-limits.recovery.json")
        try:
            self._io.replace_text(
                marker,
                json.dumps({"schema_version": 1, "kind": "gemini_rate_limits_quarantine", "reason": reason}) + "\n",
            )
        except Exception:
            pass

    def _load_rate_limits(self) -> dict[str, dict[str, object]]:
        self._ensure_layout()
        try:
            text = self._io.read_text(
                self._paths.rate_limits,
                MAX_RATE_LIMIT_BYTES,
                "could_not_read_gemini_rate_limits",
            )
            if text is None:
                return {}
            raw = json.loads(text)
            if (
                not isinstance(raw, dict)
                or set(raw) != {"schema_version", "accounts"}
                or raw.get("schema_version") != 1
                or not isinstance(raw.get("accounts"), dict)
            ):
                raise ValueError("invalid_gemini_rate_limits")
            entries: dict[str, dict[str, object]] = {}
            for account_id, value in raw["accounts"].items():
                if (
                    not isinstance(account_id, str)
                    or not _ACCOUNT_ID_RE.fullmatch(account_id)
                    or not isinstance(value, dict)
                    or set(value) != {
                        "next_allowed_at_utc", "cooldown_until_utc", "in_flight", "consecutive_429",
                    }
                ):
                    raise ValueError("invalid_gemini_rate_limits")
                next_allowed = self._parse_time(value.get("next_allowed_at_utc"))
                cooldown = self._parse_time(value.get("cooldown_until_utc"))
                if next_allowed is None:
                    raise ValueError("invalid_gemini_rate_limits")
                in_flight = value.get("in_flight")
                if in_flight is not None:
                    if (
                        not isinstance(in_flight, dict)
                        or set(in_flight) != {"reservation_id", "expires_at_utc"}
                        or not isinstance(in_flight.get("reservation_id"), str)
                        or not re.fullmatch(r"[0-9a-f]{32}", in_flight["reservation_id"])
                        or self._parse_time(in_flight.get("expires_at_utc")) is None
                    ):
                        raise ValueError("invalid_gemini_rate_limits")
                    in_flight = {
                        "reservation_id": in_flight["reservation_id"],
                        "expires_at_utc": in_flight["expires_at_utc"],
                    }
                consecutive = value.get("consecutive_429")
                if isinstance(consecutive, bool) or not isinstance(consecutive, int) or not 0 <= consecutive <= 32:
                    raise ValueError("invalid_gemini_rate_limits")
                entries[account_id] = {
                    "next_allowed_at_utc": next_allowed,
                    "cooldown_until_utc": cooldown,
                    "in_flight": in_flight,
                    "consecutive_429": consecutive,
                }
            return entries
        except Exception:
            self._quarantine_rate_limits()
            raise ValueError("invalid_gemini_rate_limits") from None

    def _write_rate_limits(self, entries: dict[str, dict[str, object]]) -> None:
        document = {"schema_version": 1, "accounts": entries}
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self._io.replace_text(self._paths.rate_limits, text)
        if self._load_rate_limits() != entries:
            raise ValueError("gemini_rate_limits_write_verification_failed")

    def _load_usage(self) -> dict[str, list[dict[str, object]]]:
        self._ensure_layout()
        try:
            text = self._io.read_text(self._paths.usage, MAX_USAGE_BYTES, "could_not_read_gemini_usage")
            if text is None:
                return {}
            raw = json.loads(text)
            if not isinstance(raw, dict) or raw.get("schema_version") != 1 or not isinstance(raw.get("accounts"), dict):
                raise ValueError("invalid_gemini_usage")
            result: dict[str, list[dict[str, object]]] = {}
            for account_id, events in raw["accounts"].items():
                if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id) or not isinstance(events, list):
                    raise ValueError("invalid_gemini_usage")
                clean: list[dict[str, object]] = []
                for event in events:
                    if not isinstance(event, dict):
                        raise ValueError("invalid_gemini_usage")
                    timestamp = event.get("at_utc")
                    if self._parse_time(timestamp) is None:
                        raise ValueError("invalid_gemini_usage")
                    model = event.get("model")
                    if not isinstance(model, str) or not 1 <= len(model) <= 200:
                        raise ValueError("invalid_gemini_usage")
                    for key in ("input_tokens", "output_tokens"):
                        value = event.get(key, 0)
                        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
                            raise ValueError("invalid_gemini_usage")
                    status = event.get("status")
                    if not isinstance(status, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", status):
                        raise ValueError("invalid_gemini_usage")
                    clean.append({
                        "at_utc": timestamp,
                        "model": model,
                        "input_tokens": event.get("input_tokens", 0),
                        "output_tokens": event.get("output_tokens", 0),
                        "status": status,
                    })
                result[account_id] = clean[-2000:]
            return result
        except Exception:
            marker = self._paths.recovery.with_name("usage.recovery.json")
            try:
                self._io.replace_text(
                    marker,
                    json.dumps({"schema_version": 1, "kind": "gemini_usage_quarantine"}) + "\n",
                )
            except Exception:
                pass
            raise ValueError("invalid_gemini_usage") from None

    def _write_usage(self, entries: dict[str, list[dict[str, object]]]) -> None:
        document = {"schema_version": 1, "accounts": entries}
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self._io.replace_text(self._paths.usage, text)
        if self._load_usage() != entries:
            raise ValueError("gemini_usage_write_verification_failed")

    @staticmethod
    def gemini_billing_group(account_id: str) -> str:
        match = re.fullmatch(r"the-hive-(\d+)", account_id)
        if match:
            number = int(match.group(1))
            return f"the-hive-account-{((number - 1) // 10) + 1}"
        return account_id

    def record_gemini_usage(
        self,
        account_id: str,
        *,
        model: str,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        status: str = "completed",
    ) -> dict[str, object]:
        if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id):
            raise ValueError("invalid_account")
        if not isinstance(model, str) or not 1 <= len(model) <= 200:
            raise ValueError("invalid_gemini_usage")
        if status not in {"completed", "failed", "cancelled", "timeout", "probe", "rate_limited"}:
            raise ValueError("invalid_gemini_usage")
        input_value = 0 if input_tokens is None else input_tokens
        output_value = 0 if output_tokens is None else output_tokens
        if (
            isinstance(input_value, bool) or not isinstance(input_value, int) or input_value < 0
            or isinstance(output_value, bool) or not isinstance(output_value, int) or output_value < 0
        ):
            raise ValueError("invalid_gemini_usage")
        with self._io.lock():
            now = self._rate_now()
            cutoff = now - timedelta(hours=24)
            entries = self._load_usage()
            events = []
            for event in entries.get(account_id, []):
                try:
                    at = datetime.fromisoformat(str(event["at_utc"]).replace("Z", "+00:00"))
                except (KeyError, TypeError, ValueError):
                    continue
                if at.tzinfo is not None and at.astimezone(timezone.utc) >= cutoff:
                    events.append(event)
            event = {
                "at_utc": self._rate_text(now),
                "model": model,
                "input_tokens": input_value,
                "output_tokens": output_value,
                "status": status,
            }
            events.append(event)
            entries[account_id] = events[-2000:]
            self._write_usage(entries)
        return self.gemini_usage_status(account_id)

    def gemini_usage_status(self, account_id: str) -> dict[str, object]:
        snapshot = self.load()
        now = self._rate_now()
        events = self._load_usage().get(account_id, [])
        recent_minute: list[dict[str, object]] = []
        recent_day: list[dict[str, object]] = []
        for event in events:
            try:
                at = datetime.fromisoformat(str(event["at_utc"]).replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError):
                continue
            if at.tzinfo is None:
                continue
            age = (now - at.astimezone(timezone.utc)).total_seconds()
            if 0 <= age <= 60:
                recent_minute.append(event)
            if 0 <= age <= 86400:
                recent_day.append(event)
        account = next((item for item in snapshot.accounts if item.account_id == account_id), None)
        probe_age = None
        probe_state = "unknown"
        if account is not None and account.last_probe_at_utc is not None:
            try:
                probed = datetime.fromisoformat(account.last_probe_at_utc.replace("Z", "+00:00"))
                probe_age = max(0, int((now - probed.astimezone(timezone.utc)).total_seconds()))
                probe_state = "fresh" if self._probe_is_fresh(account.last_probe_at_utc) else "stale"
            except (TypeError, ValueError, AttributeError):
                probe_state = "invalid"
        return {
            "account_id": account_id,
            "billing_group": self.gemini_billing_group(account_id),
            "probe_state": probe_state,
            "probe_age_seconds": probe_age,
            "rpm_observed": len(recent_minute),
            "tpm_observed": sum(int(event.get("input_tokens", 0)) + int(event.get("output_tokens", 0)) for event in recent_minute),
            "rpd_observed": len(recent_day),
            "input_tokens_24h": sum(int(event.get("input_tokens", 0)) for event in recent_day),
            "output_tokens_24h": sum(int(event.get("output_tokens", 0)) for event in recent_day),
            "last_request_at_utc": events[-1].get("at_utc") if events else None,
            "event_count_24h": len(recent_day),
            "raw_output": "not_returned",
        }

    def gemini_usage_watchdog(self) -> dict[str, object]:
        snapshot = self.load()
        accounts = [
            self.gemini_usage_status(account.account_id)
            for account in snapshot.accounts
            if account.provider.value == "gemini_api"
        ]
        stale = [item["account_id"] for item in accounts if item["probe_state"] in {"stale", "unknown", "invalid"}]
        return {
            "provider": "gemini_api",
            "account_count": len(accounts),
            "accounts": accounts,
            "stale_or_unknown_accounts": stale,
            "state": "degraded" if stale else "ready",
            "limits_source": "observed_request_and_token_counters; provider_quota_caps_not_available_locally",
            "recent_events": self.gemini_event_status(),
            "raw_output": "not_returned",
        }

    def gemini_event_status(self, limit: int = 20) -> list[dict[str, object]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("invalid_gemini_event_limit")
        try:
            text = self._io.read_text(self._paths.events, MAX_EVENT_BYTES, "could_not_read_gemini_events") or ""
        except Exception:
            return []
        result: list[dict[str, object]] = []
        for line in text.splitlines()[-limit:]:
            try:
                value = json.loads(line)
            except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                value.pop("raw_output", None)
                result.append(value)
        return result

    def record_gemini_event(
        self,
        *,
        event_type: str,
        agent_id: str | None,
        account_id: str | None,
        assignment_id: str | None,
        status: str,
        reason: str | None = None,
        model: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
    ) -> dict[str, object]:
        """Append a bounded, redacted Gemini event for master/dispatcher status."""

        if self._read_only:
            return {"recorded": False, "reason": "read_only"}
        values = {
            "event_type": event_type,
            "agent_id": agent_id,
            "account_id": account_id,
            "assignment_id": assignment_id,
            "status": status,
            "reason": reason,
            "model": model,
            "input_tokens": input_tokens or 0,
            "output_tokens": output_tokens or 0,
        }
        for key in ("event_type", "status"):
            value = values[key]
            if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value):
                raise ValueError("invalid_gemini_event")
        for key in ("agent_id", "account_id", "assignment_id", "reason", "model"):
            value = values[key]
            if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 300):
                raise ValueError("invalid_gemini_event")
        for key in ("input_tokens", "output_tokens"):
            value = values[key]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
                raise ValueError("invalid_gemini_event")
        with self._io.lock():
            try:
                existing = self._io.read_text(self._paths.events, MAX_EVENT_BYTES, "could_not_read_gemini_events") or ""
            except Exception:
                existing = ""
            lines = [line for line in existing.splitlines() if line.strip()][-511:]
            entry = {
                "at_utc": self._rate_text(self._rate_now()),
                **values,
                "raw_output": "not_returned",
            }
            lines.append(json.dumps(entry, sort_keys=True, ensure_ascii=False))
            text = "\n".join(lines) + "\n"
            if len(text.encode("utf-8")) > MAX_EVENT_BYTES:
                lines = lines[-256:]
                text = "\n".join(lines) + "\n"
            self._io.replace_text(self._paths.events, text)
        return {"recorded": True, "event_type": event_type, "status": status}

    def _rate_now(self) -> datetime:
        now = self._io.utc_now()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("invalid_utc_clock")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _rate_text(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _retry_after(now: datetime, *values: str | None) -> int:
        deadlines: list[datetime] = []
        for value in values:
            if value is None:
                continue
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed.tzinfo is not None and parsed > now:
                deadlines.append(parsed.astimezone(timezone.utc))
        if not deadlines:
            return 0
        return max(1, int(max((item - now).total_seconds() for item in deadlines) + 0.999))

    def reserve_gemini_request(self, account_id: str) -> GeminiRequestReservation:
        if self._read_only:
            raise FleetRateLimitError("rate_limiter_read_only", 60)
        if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id):
            raise FleetRateLimitError("rate_limiter_invalid_account", 60)
        with self._io.lock():
            now = self._rate_now()
            entries = self._load_rate_limits()
            entry = entries.get(account_id)
            if entry is not None:
                in_flight = entry.get("in_flight")
                in_flight_until = in_flight.get("expires_at_utc") if isinstance(in_flight, dict) else None
                retry_after = self._retry_after(
                    now,
                    entry.get("next_allowed_at_utc") if isinstance(entry.get("next_allowed_at_utc"), str) else None,
                    entry.get("cooldown_until_utc") if isinstance(entry.get("cooldown_until_utc"), str) else None,
                    in_flight_until if isinstance(in_flight_until, str) else None,
                )
                if retry_after:
                    raise FleetRateLimitError("gemini_local_rate_limit", retry_after)
            reservation_id = uuid.uuid4().hex
            expires = now + timedelta(seconds=GEMINI_REQUEST_LEASE_SECONDS)
            previous_cooldown = entry.get("cooldown_until_utc") if entry else None
            previous_429 = entry.get("consecutive_429", 0) if entry else 0
            entries[account_id] = {
                "next_allowed_at_utc": self._rate_text(
                    now + timedelta(seconds=GEMINI_MIN_REQUEST_INTERVAL_SECONDS)
                ),
                "cooldown_until_utc": previous_cooldown if isinstance(previous_cooldown, str) else None,
                "in_flight": {"reservation_id": reservation_id, "expires_at_utc": self._rate_text(expires)},
                "consecutive_429": previous_429 if isinstance(previous_429, int) else 0,
            }
            self._write_rate_limits(entries)
        return GeminiRequestReservation(account_id, reservation_id, self._rate_text(expires))

    def gemini_rate_status(self, account_id: str) -> dict[str, object]:
        """Return the local admission state without reserving a request."""

        now = self._rate_now()
        entry = self._load_rate_limits().get(account_id)
        if entry is None:
            return {"allowed": True, "reason": "ready", "retry_after_seconds": 0}
        in_flight = entry.get("in_flight")
        in_flight_until = in_flight.get("expires_at_utc") if isinstance(in_flight, dict) else None
        retry_after = self._retry_after(
            now,
            entry.get("next_allowed_at_utc") if isinstance(entry.get("next_allowed_at_utc"), str) else None,
            entry.get("cooldown_until_utc") if isinstance(entry.get("cooldown_until_utc"), str) else None,
            in_flight_until if isinstance(in_flight_until, str) else None,
        )
        return {
            "allowed": retry_after == 0,
            "reason": "ready" if retry_after == 0 else "gemini_local_rate_limit",
            "retry_after_seconds": retry_after,
        }

    def release_gemini_request(
        self,
        reservation: GeminiRequestReservation,
        *,
        outcome: str,
        reset_at_utc: str | None = None,
    ) -> None:
        if self._read_only:
            return
        if outcome not in {"completed", "provider_error", "rate_limited"}:
            raise ValueError("invalid_gemini_rate_outcome")
        with self._io.lock():
            now = self._rate_now()
            entries = self._load_rate_limits()
            entry = entries.get(reservation.account_id)
            in_flight = entry.get("in_flight") if entry else None
            if (
                entry is None
                or not isinstance(in_flight, dict)
                or in_flight.get("reservation_id") != reservation.reservation_id
            ):
                return
            next_allowed = entry.get("next_allowed_at_utc")
            cooldown = entry.get("cooldown_until_utc")
            consecutive = entry.get("consecutive_429", 0)
            if not isinstance(consecutive, int):
                consecutive = 0
            if outcome == "rate_limited":
                consecutive = min(32, consecutive + 1)
                cooldown_at: datetime | None = None
                if reset_at_utc is not None:
                    try:
                        cooldown_at = datetime.fromisoformat(reset_at_utc.replace("Z", "+00:00"))
                    except ValueError:
                        cooldown_at = None
                    if cooldown_at is not None and cooldown_at.tzinfo is not None:
                        cooldown_at = cooldown_at.astimezone(timezone.utc)
                if cooldown_at is None or cooldown_at <= now:
                    seconds = min(
                        GEMINI_MAX_429_COOLDOWN_SECONDS,
                        GEMINI_INITIAL_429_COOLDOWN_SECONDS * (2 ** min(consecutive - 1, 6)),
                    )
                    cooldown_at = now + timedelta(seconds=seconds)
                cooldown = self._rate_text(cooldown_at)
                next_allowed = cooldown
            elif isinstance(cooldown, str) and self._retry_after(now, cooldown) == 0:
                cooldown = None
                consecutive = 0
            entry = {
                "next_allowed_at_utc": next_allowed,
                "cooldown_until_utc": cooldown,
                "in_flight": None,
                "consecutive_429": consecutive,
            }
            entries[reservation.account_id] = entry
            self._write_rate_limits(entries)

    def _overlay_limits(
        self,
        snapshot: FleetSnapshot,
        entries: dict[str, dict[str, str | None]],
    ) -> FleetSnapshot:
        now = self._io.utc_now()
        active_entries: dict[str, dict[str, str | None]] = {}
        expired_ids: set[str] = set()
        for account_id, entry in entries.items():
            reset_at = entry["reset_at_utc"]
            if reset_at is not None and isinstance(now, datetime) and now.tzinfo is not None:
                try:
                    parsed = datetime.fromisoformat(reset_at.replace("Z", "+00:00"))
                    if parsed.tzinfo is not None and parsed <= now:
                        expired_ids.add(account_id)
                        continue
                except ValueError:
                    continue
            active_entries[account_id] = entry
        accounts = tuple(
            dataclass_replace(
                account,
                limit_state=LimitState.LIMITED,
                reset_at_utc=active_entries[account.account_id]["reset_at_utc"],
                limit_reason=active_entries[account.account_id]["reason"],
            ) if account.account_id in active_entries else dataclass_replace(
                account,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                limit_reason=None,
            ) if account.account_id in expired_ids else account
            for account in snapshot.accounts
        )
        return normalize_fleet_document(
            fleet_document(dataclass_replace(snapshot, accounts=accounts))
        )

    @staticmethod
    def _check_generation(snapshot: FleetSnapshot, expected_generation: int) -> None:
        if (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or snapshot.generation != expected_generation
        ):
            raise FleetConflictError("generation_conflict")

    def load(self) -> FleetSnapshot:
        return self._overlay_limits(self._load_registry(), self._load_limits())

    def public_snapshot(self) -> dict[str, object]:
        return public_fleet_snapshot(self.load())

    def commit_snapshot(
        self,
        snapshot: FleetSnapshot,
        *,
        expected_generation: int,
    ) -> FleetSnapshot:
        candidate = normalize_fleet_document(fleet_document(snapshot))
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            if candidate.generation != current.generation + 1:
                raise FleetConflictError("generation_conflict")
            return self._write_registry(candidate)

    def set_secret(
        self,
        account_id: str,
        secret: str,
        *,
        expected_generation: int,
    ) -> dict[str, object]:
        if not isinstance(secret, str):
            raise FleetSecretError("invalid_secret")
        try:
            encoded = secret.encode("utf-8")
        except UnicodeError:
            raise FleetSecretError("invalid_secret") from None
        if not 1 <= len(encoded) <= MAX_SECRET_BYTES:
            raise FleetSecretError("invalid_secret")

        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise FleetSecretError("invalid_account")
            secret_path = self._paths.secrets / f"{account.account_id}.secret"
            try:
                previous_secret = self._io.read_bytes(
                    secret_path,
                    MAX_SECRET_BYTES,
                    "secret_read_failed",
                )
            except Exception:
                raise FleetSecretError("secret_write_failed") from None
            try:
                self._io.replace_bytes(
                    secret_path,
                    encoded,
                    0o600,
                )
            except Exception:
                raise FleetSecretError("secret_write_failed") from None
            try:
                updated_account = dataclass_replace(
                    account,
                    secret_state=SecretState.CONFIGURED,
                    limit_state=LimitState.UNKNOWN,
                    reset_at_utc=None,
                    last_probe_at_utc=None,
                    limit_reason=None,
                )
                updated = plan_account_upsert(
                    current,
                    updated_account,
                    expected_generation=current.generation,
                )
                stored = self._write_registry(updated)
            except Exception:
                with contextlib.suppress(Exception):
                    if previous_secret is None:
                        if self._io.remove_file is not None:
                            self._io.remove_file(secret_path)
                    else:
                        self._io.replace_bytes(secret_path, previous_secret, 0o600)
                raise
        return {"configured": True, "generation": stored.generation}

    def read_secret(
        self,
        account_id: str,
        *,
        expected_generation: int,
    ) -> str:
        """Read one configured secret for a bounded provider probe only."""

        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise FleetSecretError("invalid_account")
            if account.secret_state is SecretState.MISSING:
                raise FleetSecretError("secret_missing")
            if account.secret_state is not SecretState.CONFIGURED:
                raise FleetSecretError("secret_unavailable")
            raw = self._io.read_bytes(
                self._paths.secrets / f"{account.account_id}.secret",
                MAX_SECRET_BYTES,
                "secret_read_failed",
            )
            if raw is None:
                raise FleetSecretError("secret_missing")
            try:
                secret = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise FleetSecretError("secret_read_failed") from None
            if not 1 <= len(raw) <= MAX_SECRET_BYTES:
                raise FleetSecretError("secret_read_failed")
            return secret

    def delete_account(
        self,
        account_id: str,
        *,
        expected_generation: int,
    ) -> dict[str, object]:
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise FleetSecretError("invalid_account")
            if account.enabled:
                raise FleetSecretError("account_must_be_disabled")
            updated = plan_account_delete(current, account_id, expected_generation=current.generation)
            if account.secret_state is not SecretState.NOT_REQUIRED:
                if self._io.remove_file is None:
                    raise FleetSecretError("secret_cleanup_unavailable")
                try:
                    if not self._io.remove_file(self._paths.secrets / f"{account.account_id}.secret"):
                        raise FleetSecretError("secret_cleanup_failed")
                except FleetSecretError:
                    raise
                except Exception:
                    raise FleetSecretError("secret_cleanup_failed") from None
            stored = self._write_registry(updated)
            entries = self._load_limits()
            if account_id in entries:
                remaining = dict(entries)
                del remaining[account_id]
                self._write_limits(remaining)
        return {
            "deleted": True,
            "generation": stored.generation,
            "cleanup_pending": False,
        }

    def remove_secret_sidecar(
        self,
        account_id: str,
        *,
        expected_generation: int,
    ) -> bool:
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            if not any(item.account_id == account_id for item in current.accounts):
                raise FleetSecretError("invalid_account")
            if self._io.remove_file is None:
                raise FleetSecretError("secret_cleanup_unavailable")
            try:
                return self._io.remove_file(self._paths.secrets / f"{account_id}.secret")
            except Exception:
                raise FleetSecretError("secret_cleanup_failed") from None

    def _mark_limited_locked(
        self,
        account_id: str,
        *,
        reset_at_utc: str | None,
        reason: str,
    ) -> FleetSnapshot:
        self._parse_time(reset_at_utc)
        if not isinstance(reason, str) or not _LIMIT_REASON_RE.fullmatch(reason):
            raise ValueError("invalid_fleet_limits")
        current = self._load_registry()
        if not any(item.account_id == account_id for item in current.accounts):
            raise ValueError("invalid_account")
        updated = mark_account_limit(
            current,
            account_id,
            reset_at_utc=reset_at_utc,
            reason=reason,
            expected_generation=current.generation,
        )
        entries = self._load_limits()
        updated_entries = dict(entries)
        updated_entries[account_id] = {
            "reset_at_utc": reset_at_utc,
            "reason": reason,
        }
        self._write_limits(updated_entries)
        return self._write_registry(updated)

    def mark_limited(
        self,
        account_id: str,
        *,
        reset_at_utc: str | None,
        reason: str,
    ) -> FleetSnapshot:
        with self._io.lock():
            return self._mark_limited_locked(
                account_id,
                reset_at_utc=reset_at_utc,
                reason=reason,
            )

    @staticmethod
    def _probe_status(
        snapshot: FleetSnapshot,
        *,
        ready: bool,
        reason: str,
        model: str | None = None,
    ) -> dict[str, object]:
        status: dict[str, object] = {
            "probed": True,
            "generation": snapshot.generation,
            "ready": ready,
            "reason": reason,
        }
        if isinstance(model, str) and model:
            status["model"] = model
        return status

    @staticmethod
    def _updated_probe_account(
        account: FleetAccount,
        *,
        now: str,
        reason: str,
    ) -> FleetAccount:
        if reason == "ready":
            return dataclass_replace(
                account,
                limit_state=LimitState.READY,
                reset_at_utc=None,
                last_probe_at_utc=now,
                limit_reason=None,
            )
        if reason == "auth_invalid":
            return dataclass_replace(
                account,
                secret_state=SecretState.INVALID,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                last_probe_at_utc=None,
                limit_reason=None,
            )
        if reason == "secret_missing":
            return dataclass_replace(
                account,
                secret_state=SecretState.MISSING,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                last_probe_at_utc=None,
                limit_reason=None,
            )
        if reason in {"provider_unavailable", "model_unavailable"}:
            return dataclass_replace(
                account,
                secret_state=SecretState.CONFIGURED,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                last_probe_at_utc=None,
                limit_reason=reason,
            )
        return dataclass_replace(
            account,
            limit_state=LimitState.READY,
            reset_at_utc=None,
            last_probe_at_utc=now,
            limit_reason=reason,
        )

    def _utc_text(self) -> str:
        now = self._io.utc_now()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("invalid_utc_clock")
        return now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def probe_account(
        self,
        account_id: str,
        probe: Callable[[FleetAccount], ProbeResult],
        *,
        expected_generation: int,
    ) -> dict[str, object]:
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise ValueError("invalid_account")
            probed_generation = current.generation

        reservation = None
        if account.provider.value == "gemini_api":
            reservation = self.reserve_gemini_request(account.account_id)
        result: ProbeResult | None = None
        try:
            result = probe(account)
        except Exception:
            result = None
        finally:
            if reservation is not None:
                rate_limited = (
                    isinstance(result, ProbeResult)
                    and result.error is not None
                    and result.error.kind == "account_limited"
                )
                self.release_gemini_request(
                    reservation,
                    outcome=(
                        "rate_limited" if rate_limited
                        else "completed" if isinstance(result, ProbeResult) and result.ok
                        else "provider_error"
                    ),
                    reset_at_utc=(
                        result.error.reset_at_utc
                        if rate_limited and result is not None and result.error is not None
                        else None
                    ),
                )

        with self._io.lock():
            latest = self._load_registry()
            self._check_generation(latest, probed_generation)
            latest_account = next(
                (item for item in latest.accounts if item.account_id == account_id),
                None,
            )
            if latest_account is None:
                raise FleetConflictError("generation_conflict")
            if (
                isinstance(result, ProbeResult)
                and result.provider is latest_account.provider
                and result.ok
                and result.error is None
            ):
                reason = "ready"
            elif (
                isinstance(result, ProbeResult)
                and result.provider is latest_account.provider
                and not result.ok
                and result.error is not None
            ):
                reason = {
                    "account_limited": "limit_active",
                    "auth_invalid": "auth_invalid",
                    "secret_missing": "secret_missing",
                    "provider_unavailable": "provider_unavailable",
                    "model_unavailable": "model_unavailable",
                    "runner_failed": "provider_unavailable",
                }.get(result.error.kind, "provider_unavailable")
            else:
                reason = "provider_unavailable"

            if reason == "limit_active":
                reset_at_utc = result.error.reset_at_utc if isinstance(result, ProbeResult) and result.error else None
                stored = self._mark_limited_locked(
                    account_id,
                    reset_at_utc=reset_at_utc,
                    reason="provider_429",
                )
                return self._probe_status(
                    stored,
                    ready=False,
                    reason=reason,
                    model=result.model if isinstance(result, ProbeResult) else None,
                )

            updated_account = self._updated_probe_account(
                latest_account,
                now=self._utc_text(),
                reason=reason,
            )
            updated = plan_account_upsert(
                latest,
                updated_account,
                expected_generation=latest.generation,
            )
            stored = self._write_registry(updated)
            if reason == "ready":
                entries = self._load_limits()
                if account_id in entries:
                    remaining = dict(entries)
                    del remaining[account_id]
                    self._write_limits(remaining)
            return self._probe_status(
                stored,
                ready=reason == "ready",
                reason=reason,
                model=result.model if isinstance(result, ProbeResult) else None,
            )

    def account_gate(
        self,
        agent_id: str,
        *,
        snapshot: FleetSnapshot | None = None,
        inventory: InventorySnapshot | None = None,
    ) -> AccountGateDecision:
        snapshot = snapshot or self.load()
        inventory = inventory or build_inventory(snapshot, self._pool_root)
        agent = inventory.agents.get(agent_id)
        if agent is None:
            return AccountGateDecision(False, "account_disabled", None, snapshot.generation)
        series = next(
            (item for item in snapshot.series if item.prefix == agent.series_prefix),
            None,
        )
        if series is None or not series.enabled:
            return AccountGateDecision(False, "account_disabled", None, snapshot.generation)
        return self._account_decision(
            snapshot,
            account_id=agent.account_id,
            provider=agent.provider,
        )

    def series_gate(
        self,
        series: FleetSeries,
        *,
        snapshot: FleetSnapshot | None = None,
    ) -> AccountGateDecision:
        snapshot = snapshot or self.load()
        if not series.enabled:
            return AccountGateDecision(
                False,
                "series_disabled",
                series.account_id,
                snapshot.generation,
            )
        return self._account_decision(
            snapshot,
            account_id=series.account_id,
            provider=series.provider,
        )

    def _account_decision(
        self,
        snapshot: FleetSnapshot,
        *,
        account_id: str | None,
        provider: object,
    ) -> AccountGateDecision:
        if account_id is None:
            return AccountGateDecision(True, "ready", None, snapshot.generation)
        account = next(
            (item for item in snapshot.accounts if item.account_id == account_id),
            None,
        )
        if account is not None and account.provider is not provider:
            reason = "account_provider_mismatch"
        elif account is None or not account.enabled or account.limit_state is LimitState.DISABLED:
            reason = "account_disabled"
        elif account.secret_state is SecretState.MISSING:
            reason = "secret_missing"
        elif account.secret_state is SecretState.INVALID:
            reason = "auth_invalid"
        elif account.limit_reason == "provider_unavailable":
            reason = "provider_unavailable"
        elif account.limit_reason == "model_unavailable":
            reason = "model_unavailable"
        elif account.limit_state is LimitState.LIMITED:
            reason = "limit_active"
        elif account.limit_state in {LimitState.UNKNOWN, LimitState.PROBING}:
            reason = "limit_unknown"
        elif account.limit_reason == "provider_unavailable":
            reason = "provider_unavailable"
        elif account.limit_reason == "model_unavailable":
            reason = "model_unavailable"
        elif not self._probe_is_fresh(account.last_probe_at_utc):
            reason = "probe_stale"
        else:
            reason = "ready"
        return AccountGateDecision(reason == "ready", reason, account_id, snapshot.generation)

    def _probe_is_fresh(self, value: str | None) -> bool:
        if value is None:
            return False
        try:
            probed_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
        now = self._io.utc_now()
        if not isinstance(now, datetime) or now.tzinfo is None or probed_at.tzinfo is None:
            return False
        age = (now.astimezone(timezone.utc) - probed_at.astimezone(timezone.utc)).total_seconds()
        return 0 <= age <= self._probe_max_age_seconds
