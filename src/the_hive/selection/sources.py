"""Secret-free account and fleet source contracts."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import hmac
import re


class SelectionSourceError(ValueError):
    """Raised when a private Selection source cannot be trusted."""


_ACCOUNT_RE = re.compile(r"[A-Za-z0-9._:@/-]{1,256}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class AccountIdentity:
    account_key: str
    source: str
    confidence: str

    def __post_init__(self) -> None:
        if not _DIGEST_RE.fullmatch(self.account_key) or not isinstance(self.source, str) or not isinstance(self.confidence, str):
            raise SelectionSourceError("invalid_account_identity")


class AccountIdentityResolver:
    def __init__(self, salt: bytes) -> None:
        if not isinstance(salt, bytes) or len(salt) < 16:
            raise SelectionSourceError("invalid_account_identity_salt")
        self._salt = salt

    def resolve(self, *, agent_id: str, routing: Mapping[str, object]) -> AccountIdentity:
        if not isinstance(agent_id, str) or not 1 <= len(agent_id) <= 128 or not isinstance(routing, Mapping):
            raise SelectionSourceError("invalid_account_identity_input")
        external = routing.get("account")
        if not isinstance(external, str) or not _ACCOUNT_RE.fullmatch(external):
            raise SelectionSourceError("account_identity_unavailable")
        digest = hmac.new(self._salt, b"codex-usage-account\0" + external.encode("utf-8"), hashlib.sha256).hexdigest()
        return AccountIdentity(f"sha256:{digest}", "usage_routing", "verified")


@dataclass(frozen=True, slots=True)
class AccountSnapshot:
    account_key: str
    enabled: bool
    ready: bool
    limited: bool
    model_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BeeSnapshot:
    agent_id: str
    account_key: str
    model_id: str
    enabled: bool


class SelectionSourceProvider:
    def __init__(
        self,
        fleet_reader: Callable[[Sequence[str]], tuple[BeeSnapshot, ...]],
        usage_reader: Callable[[str], Mapping[str, object]],
    ) -> None:
        if not callable(fleet_reader) or not callable(usage_reader):
            raise SelectionSourceError("invalid_selection_source")
        self._fleet_reader = fleet_reader
        self._usage_reader = usage_reader

    def fleet_snapshot(self, agent_ids: Sequence[str]) -> tuple[BeeSnapshot, ...]:
        values = tuple(agent_ids)
        if len(values) > 4096 or any(not isinstance(value, str) or not value for value in values):
            raise SelectionSourceError("invalid_agent_snapshot")
        result = self._fleet_reader(values)
        if not isinstance(result, tuple) or any(not isinstance(item, BeeSnapshot) for item in result):
            raise SelectionSourceError("invalid_fleet_snapshot")
        return result

    def usage_snapshot(self, agent_id: str) -> Mapping[str, object]:
        if not isinstance(agent_id, str) or not agent_id:
            raise SelectionSourceError("invalid_agent_id")
        result = self._usage_reader(agent_id)
        if not isinstance(result, Mapping):
            raise SelectionSourceError("invalid_usage_snapshot")
        return {"schema_version": result.get("schema_version", 1), "fresh": result.get("fresh", False), "raw_output": "not_returned"}


__all__ = ["AccountIdentity", "AccountIdentityResolver", "BeeSnapshot", "SelectionSourceError", "SelectionSourceProvider"]
