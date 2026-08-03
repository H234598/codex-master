from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, replace as dataclass_replace
from datetime import datetime, timezone
from pathlib import Path
from typing import ContextManager

from .fleet_registry import (
    FleetAccount,
    FleetSnapshot,
    LimitState,
    SecretState,
    build_inventory,
    fleet_document,
    mark_account_limit,
    normalize_fleet_document,
    plan_account_upsert,
    public_fleet_snapshot,
)
from .fleet_runners import ProbeResult


MAX_REGISTRY_BYTES = 1024 * 1024
MAX_LIMIT_BYTES = 256 * 1024
MAX_SECRET_BYTES = 16 * 1024
_ACCOUNT_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_LIMIT_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class FleetConflictError(ValueError):
    pass


class FleetSecretError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AccountGateDecision:
    allowed: bool
    reason: str
    account_id: str | None
    generation: int


@dataclass(frozen=True, slots=True)
class FleetPaths:
    root: Path
    registry: Path
    secrets: Path
    limits: Path
    lock: Path

    @classmethod
    def from_state_root(cls, root: Path) -> FleetPaths:
        fleet_root = root / "fleet"
        return cls(
            root=fleet_root,
            registry=fleet_root / "registry.json",
            secrets=fleet_root / "secrets",
            limits=fleet_root / "limits.json",
            lock=fleet_root / "registry.lock",
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


class FleetService:
    def __init__(
        self,
        paths: FleetPaths,
        private_io: FleetPrivateIO,
        *,
        pool_root: Path,
        probe_max_age_seconds: int = 900,
    ) -> None:
        self._paths = paths
        self._io = private_io
        self._pool_root = pool_root
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

    def _load_limits(self) -> dict[str, dict[str, str | None]]:
        self._ensure_layout()
        text = self._io.read_text(
            self._paths.limits,
            MAX_LIMIT_BYTES,
            "could_not_read_fleet_limits",
        )
        if text is None:
            return {}
        try:
            raw = json.loads(text)
        except (json.JSONDecodeError, UnicodeError):
            raise ValueError("invalid_fleet_limits") from None
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

    def _write_limits(self, entries: dict[str, dict[str, str | None]]) -> None:
        document = {"schema_version": 1, "accounts": entries}
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self._io.replace_text(self._paths.limits, text)
        if self._load_limits() != entries:
            raise ValueError("fleet_limits_write_verification_failed")

    @staticmethod
    def _overlay_limits(
        snapshot: FleetSnapshot,
        entries: dict[str, dict[str, str | None]],
    ) -> FleetSnapshot:
        accounts = tuple(
            dataclass_replace(
                account,
                limit_state=LimitState.LIMITED,
                reset_at_utc=entries[account.account_id]["reset_at_utc"],
                limit_reason=entries[account.account_id]["reason"],
            )
            if account.account_id in entries
            else account
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
            try:
                self._io.replace_bytes(
                    self._paths.secrets / f"{account.account_id}.secret",
                    encoded,
                    0o600,
                )
            except Exception:
                raise FleetSecretError("secret_write_failed") from None
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
        return {"configured": True, "generation": stored.generation}

    def _mark_limited_locked(
        self,
        account_id: str,
        *,
        reset_at_utc: str | None,
        reason: str,
    ) -> FleetSnapshot:
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
    def _probe_status(snapshot: FleetSnapshot, *, ready: bool, reason: str) -> dict[str, object]:
        return {
            "probed": True,
            "generation": snapshot.generation,
            "ready": ready,
            "reason": reason,
        }

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

        try:
            result = probe(account)
        except Exception:
            result = None

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
                return self._probe_status(stored, ready=False, reason=reason)

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
            return self._probe_status(stored, ready=reason == "ready", reason=reason)

    def account_gate(self, agent_id: str) -> AccountGateDecision:
        snapshot = self.load()
        inventory = build_inventory(snapshot, self._pool_root)
        agent = inventory.agents.get(agent_id)
        if agent is None:
            return AccountGateDecision(False, "account_disabled", None, snapshot.generation)
        series = next(
            (item for item in snapshot.series if item.prefix == agent.series_prefix),
            None,
        )
        if series is None or not series.enabled:
            return AccountGateDecision(False, "account_disabled", None, snapshot.generation)
        if agent.account_id is None:
            return AccountGateDecision(True, "ready", None, snapshot.generation)
        account = next(
            (item for item in snapshot.accounts if item.account_id == agent.account_id),
            None,
        )
        if account is None or not account.enabled or account.limit_state is LimitState.DISABLED:
            reason = "account_disabled"
        elif account.secret_state is SecretState.MISSING:
            reason = "secret_missing"
        elif account.secret_state is SecretState.INVALID:
            reason = "auth_invalid"
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
        return AccountGateDecision(reason == "ready", reason, account.account_id, snapshot.generation)

    def _probe_is_fresh(self, value: str | None) -> bool:
        if value is None:
            return False
        try:
            probed_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
        now = self._io.utc_now()
        if now.tzinfo is None or probed_at.tzinfo is None:
            return False
        age = (now.astimezone(timezone.utc) - probed_at.astimezone(timezone.utc)).total_seconds()
        return 0 <= age <= self._probe_max_age_seconds
