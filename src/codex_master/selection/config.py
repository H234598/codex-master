"""Strict loader for the private account-aware Selection policy."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import stat
from types import MappingProxyType

from codex_master.selection import AdmissionMode, SelectionPolicy


MAX_SELECTION_POLICY_BYTES = 1024 * 1024
MAX_POLICY_LIST = 256
MAX_ACCOUNT_POLICIES = 256
MAX_IDENTIFIER_LENGTH = 128
MAX_RETRY_LIMIT = 16
MAX_TTL_SECONDS = 24 * 60 * 60


class SelectionConfigError(ValueError):
    """Raised when a private Selection policy is unavailable or invalid."""


@dataclass(frozen=True, slots=True)
class AccountPolicy:
    max_parallel_bees: int
    capacity_weight_micro: int

    def __post_init__(self) -> None:
        _bounded_int(self.max_parallel_bees, 1, 256, "invalid_account_parallelism")
        _bounded_int(self.capacity_weight_micro, 0, 10**12, "invalid_account_capacity_weight")


@dataclass(frozen=True, slots=True)
class SelectionPolicyConfig:
    """Validated policy, with private allowlists kept out of public output."""

    schema_version: int
    mode: AdmissionMode
    kill_switch: bool
    features: Mapping[str, bool]
    reservation: Mapping[str, int]
    time: Mapping[str, int]
    freshness: Mapping[str, int]
    account_policies: Mapping[str, AccountPolicy]
    teamleader_allowlist: tuple[str, ...]
    account_allowlist: tuple[str, ...]
    operation_allowlist: tuple[str, ...]
    sp0_proactive: Mapping[str, int | bool]
    digest: str

    def __post_init__(self) -> None:
        if self.schema_version != 1 or not isinstance(self.mode, AdmissionMode):
            raise SelectionConfigError("invalid_selection_policy_version")
        if not isinstance(self.kill_switch, bool):
            raise SelectionConfigError("invalid_selection_kill_switch")
        for field, value, expected in (
            ("features", self.features, set(_FEATURES)),
            ("reservation", self.reservation, {"ttl_seconds", "retry_limit"}),
            ("time", self.time, {"reset_tolerance_seconds", "max_clock_skew_seconds"}),
            ("freshness", self.freshness, {"routing_seconds", "short_window_seconds", "long_window_seconds"}),
            ("sp0_proactive", self.sp0_proactive, {"execute_enabled", "max_attempts_per_window", "retry_cooldown_seconds"}),
        ):
            if not isinstance(value, Mapping) or set(value) != expected:
                raise SelectionConfigError(f"invalid_selection_{field}")
        if any(not isinstance(value, bool) for value in self.features.values()):
            raise SelectionConfigError("invalid_selection_features")
        _bounded_int(self.reservation["ttl_seconds"], 1, MAX_TTL_SECONDS, "invalid_selection_ttl")
        _bounded_int(self.reservation["retry_limit"], 0, MAX_RETRY_LIMIT, "invalid_selection_retry_limit")
        for value in self.time.values():
            _bounded_int(value, 0, MAX_TTL_SECONDS, "invalid_selection_time")
        for value in self.freshness.values():
            _bounded_int(value, 1, 7 * 24 * 60 * 60, "invalid_selection_freshness")
        if not isinstance(self.account_policies, Mapping) or len(self.account_policies) > MAX_ACCOUNT_POLICIES:
            raise SelectionConfigError("invalid_account_policies")
        if any(not isinstance(key, str) or not key or len(key) > MAX_IDENTIFIER_LENGTH or not isinstance(value, AccountPolicy) for key, value in self.account_policies.items()):
            raise SelectionConfigError("invalid_account_policies")
        for values in (self.teamleader_allowlist, self.account_allowlist, self.operation_allowlist):
            _bounded_list(values, "invalid_selection_allowlist")
        if not isinstance(self.sp0_proactive["execute_enabled"], bool):
            raise SelectionConfigError("invalid_sp0_proactive")
        _bounded_int(self.sp0_proactive["max_attempts_per_window"], 1, MAX_RETRY_LIMIT, "invalid_sp0_attempts")
        _bounded_int(self.sp0_proactive["retry_cooldown_seconds"], 0, MAX_TTL_SECONDS, "invalid_sp0_cooldown")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise SelectionConfigError("invalid_selection_policy_digest")

    def selection_policy(self) -> SelectionPolicy:
        """Return the core policy with all gates still bounded by config."""

        return SelectionPolicy(
            sp0=self.features["sp0_passive"],
            sp1a=self.features["sp1_deadline"],
            sp1b=False,
            sp2=self.features["sp2_secondary_model"],
            sp3=self.features["sp3_fairness"],
        )

    def allows_pilot(self, *, teamleader: str, account: str, operation: str) -> bool:
        """Check only policy allowlists; this is not authority or credential evidence."""

        if self.kill_switch or self.mode is not AdmissionMode.ENFORCED:
            return False
        return (
            teamleader in self.teamleader_allowlist
            and account in self.account_allowlist
            and operation in self.operation_allowlist
        )

    def public(self) -> dict[str, object]:
        """Return counts and feature state without private allowlist values."""

        return {
            "schema_version": self.schema_version,
            "mode": self.mode.value,
            "kill_switch": self.kill_switch,
            "features": dict(self.features),
            "account_policy_count": len(self.account_policies),
            "teamleader_allowlist_count": len(self.teamleader_allowlist),
            "account_allowlist_count": len(self.account_allowlist),
            "operation_allowlist_count": len(self.operation_allowlist),
            "sp0_proactive_execute_enabled": self.sp0_proactive["execute_enabled"],
            "digest": self.digest,
            "raw_output": "not_returned",
        }


def load_selection_policy(path: Path) -> SelectionPolicyConfig:
    """Load one absolute, regular, bounded JSON policy without mutating state."""

    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise SelectionConfigError("invalid_selection_policy_path")
    try:
        current = path.lstat()
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or current.st_size > MAX_SELECTION_POLICY_BYTES:
            raise SelectionConfigError("invalid_selection_policy_file")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except SelectionConfigError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SelectionConfigError("selection_policy_unavailable") from exc
    if not isinstance(payload, Mapping):
        raise SelectionConfigError("invalid_selection_policy")
    allowed = {
        "$schema", "schema_version", "selection", "features", "reservation", "time", "freshness",
        "account_policies", "teamleader_allowlist", "account_allowlist", "operation_allowlist", "sp0_proactive",
    }
    required = allowed - {"$schema"}
    if set(payload) not in (required, allowed):
        raise SelectionConfigError("invalid_selection_policy_fields")
    selection = _strict_mapping(payload["selection"], {"mode", "kill_switch"}, "selection")
    try:
        mode = {"disabled": AdmissionMode.OFF, "shadow": AdmissionMode.SHADOW, "enforced": AdmissionMode.ENFORCED}.get(selection["mode"])
    except TypeError:
        mode = None
    if mode is None or not isinstance(selection["kill_switch"], bool):
        raise SelectionConfigError("invalid_selection_selection")
    features = _strict_mapping(payload["features"], set(_FEATURES), "features")
    reservation = _strict_mapping(payload["reservation"], {"ttl_seconds", "retry_limit"}, "reservation")
    time_policy = _strict_mapping(payload["time"], {"reset_tolerance_seconds", "max_clock_skew_seconds"}, "time")
    freshness = _strict_mapping(payload["freshness"], {"routing_seconds", "short_window_seconds", "long_window_seconds"}, "freshness")
    account_policies = _account_policies(payload["account_policies"])
    allowlists = tuple(
        _bounded_list(payload[field], f"invalid_{field}")
        for field in ("teamleader_allowlist", "account_allowlist", "operation_allowlist")
    )
    sp0 = _strict_mapping(payload["sp0_proactive"], {"execute_enabled", "max_attempts_per_window", "retry_cooldown_seconds"}, "sp0_proactive")
    canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return SelectionPolicyConfig(
        1,
        mode,
        selection["kill_switch"],
        MappingProxyType(dict(features)),
        MappingProxyType(dict(reservation)),
        MappingProxyType(dict(time_policy)),
        MappingProxyType(dict(freshness)),
        MappingProxyType(account_policies),
        allowlists[0],
        allowlists[1],
        allowlists[2],
        MappingProxyType(dict(sp0)),
        digest,
    )


_FEATURES = (
    "account_grouping", "model_roles", "shadow_ranking", "auto_selection", "sp3_fairness",
    "sp2_secondary_model", "sp1_deadline", "sp0_passive", "sp0_proactive",
)


def _strict_mapping(value: object, fields: set[str], name: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SelectionConfigError(f"invalid_selection_{name}")
    return dict(value)


def _account_policies(value: object) -> dict[str, AccountPolicy]:
    if not isinstance(value, Mapping) or len(value) > MAX_ACCOUNT_POLICIES:
        raise SelectionConfigError("invalid_account_policies")
    result: dict[str, AccountPolicy] = {}
    for key, raw in value.items():
        if not isinstance(key, str) or not key or len(key) > MAX_IDENTIFIER_LENGTH:
            raise SelectionConfigError("invalid_account_policy_key")
        item = _strict_mapping(raw, {"max_parallel_bees", "capacity_weight_micro"}, "account_policy")
        try:
            result[key] = AccountPolicy(item["max_parallel_bees"], item["capacity_weight_micro"])
        except (TypeError, ValueError) as exc:
            raise SelectionConfigError("invalid_account_policy") from exc
    return result


def _bounded_list(value: object, code: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_POLICY_LIST:
        raise SelectionConfigError(code)
    result = tuple(value)
    if any(not isinstance(item, str) or not 1 <= len(item) <= MAX_IDENTIFIER_LENGTH or any(ord(char) < 32 for char in item) for item in result):
        raise SelectionConfigError(code)
    if len(set(result)) != len(result):
        raise SelectionConfigError(code)
    return result


def _bounded_int(value: object, minimum: int, maximum: int, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SelectionConfigError(code)
    return value


__all__ = ["AccountPolicy", "SelectionConfigError", "SelectionPolicyConfig", "load_selection_policy"]
