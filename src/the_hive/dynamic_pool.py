"""Immutable dynamic PoolAuthorityV2 bindings and their exact reader check."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
import re
from types import MappingProxyType

from the_hive.usage_snapshot import UsageEvidenceV2


_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_POOL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_PROVIDER_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_RUNTIME_PROVIDER_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_AGENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class DynamicPoolBindingError(ValueError):
    """Raised when an explicit dynamic pool binding is absent or malformed."""


@dataclass(frozen=True, slots=True)
class AccountPoolBindingV1:
    """One explicit immutable PoolAuthorityV2 identity for a selected agent."""

    account_id: str
    pool_id: str
    authority_provider: str
    runtime_provider: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.account_id, str)
            or self.account_id in {".", ".."}
            or _ACCOUNT_RE.fullmatch(self.account_id) is None
        ):
            raise DynamicPoolBindingError("invalid_dynamic_pool_account")
        if (
            not isinstance(self.pool_id, str)
            or _POOL_RE.fullmatch(self.pool_id) is None
        ):
            raise DynamicPoolBindingError("invalid_dynamic_pool_id")
        if (
            not isinstance(self.authority_provider, str)
            or _PROVIDER_RE.fullmatch(self.authority_provider) is None
        ):
            raise DynamicPoolBindingError("invalid_dynamic_pool_authority_provider")
        if self.runtime_provider is not None and (
            not isinstance(self.runtime_provider, str)
            or _RUNTIME_PROVIDER_RE.fullmatch(self.runtime_provider) is None
        ):
            raise DynamicPoolBindingError("invalid_dynamic_pool_runtime_provider")

    @property
    def provider(self) -> str:
        """The canonical provider used only for PoolAuthorityV2 matching."""

        return self.authority_provider


def _make_account_pool_binding_v1(
    *,
    account_id: str,
    pool_id: str,
    authority_provider: str,
    runtime_provider: str | None = None,
) -> AccountPoolBindingV1:
    """Construct the only binding type at the central dynamic resolver boundary."""

    return AccountPoolBindingV1(
        account_id, pool_id, authority_provider, runtime_provider
    )


def account_pool_binding_payload(
    binding: AccountPoolBindingV1,
) -> dict[str, str | None]:
    """Encode the typed binding for private local persistence only."""

    if not isinstance(binding, AccountPoolBindingV1):
        raise DynamicPoolBindingError("invalid_dynamic_pool_binding")
    return {
        "account_id": binding.account_id,
        "pool_id": binding.pool_id,
        "authority_provider": binding.authority_provider,
        "runtime_provider": binding.runtime_provider,
    }


def account_pool_binding_from_payload(raw: object) -> AccountPoolBindingV1:
    """Decode an exact private persistence payload through the central factory."""

    if not isinstance(raw, Mapping) or set(raw) != {
        "account_id",
        "pool_id",
        "authority_provider",
        "runtime_provider",
    }:
        raise DynamicPoolBindingError("invalid_dynamic_pool_binding")
    return _make_account_pool_binding_v1(
        account_id=raw["account_id"],
        pool_id=raw["pool_id"],
        authority_provider=raw["authority_provider"],
        runtime_provider=raw["runtime_provider"],
    )


@dataclass(frozen=True, slots=True)
class DynamicPoolInventoryEntryV1:
    """One explicit inventory value, before the resolver creates a binding."""

    account_id: str
    pool_id: str
    authority_provider: str
    runtime_provider: str | None = None

    def __post_init__(self) -> None:
        _make_account_pool_binding_v1(
            account_id=self.account_id,
            pool_id=self.pool_id,
            authority_provider=self.authority_provider,
            runtime_provider=self.runtime_provider,
        )


@dataclass(frozen=True, slots=True)
class DynamicPoolInventoryV1:
    """Explicit dynamic inventory injected by the sole resolver owner."""

    entries_by_agent: Mapping[str, DynamicPoolInventoryEntryV1]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.entries_by_agent, Mapping)
            or len(self.entries_by_agent) > 256
        ):
            raise DynamicPoolBindingError("invalid_dynamic_pool_inventory")
        normalized: dict[str, DynamicPoolInventoryEntryV1] = {}
        for agent_id, entry in self.entries_by_agent.items():
            if not isinstance(agent_id, str) or _AGENT_RE.fullmatch(agent_id) is None:
                raise DynamicPoolBindingError("invalid_dynamic_pool_inventory")
            if not isinstance(entry, DynamicPoolInventoryEntryV1):
                raise DynamicPoolBindingError("invalid_dynamic_pool_inventory")
            normalized[agent_id] = entry
        object.__setattr__(self, "entries_by_agent", MappingProxyType(normalized))

    def entry_for(self, agent_id: str) -> DynamicPoolInventoryEntryV1:
        if not isinstance(agent_id, str) or _AGENT_RE.fullmatch(agent_id) is None:
            raise DynamicPoolBindingError("dynamic_pool_binding_missing")
        try:
            return self.entries_by_agent[agent_id]
        except KeyError as exc:
            raise DynamicPoolBindingError("dynamic_pool_binding_missing") from exc


def resolve_dynamic_pool_selection(
    selection: object, inventory: DynamicPoolInventoryV1
) -> object:
    """Attach the one explicit inventory binding to an already selected agent.

    This resolver does not inspect PoolAuthorityV2, grants, accounts, labels,
    profiles, or fleet series.  Inventory lookup by the selected agent id is
    the sole selection input for the dynamic pool identity.
    """

    from the_hive.selection import SelectionResult

    if not isinstance(selection, SelectionResult) or not isinstance(
        inventory, DynamicPoolInventoryV1
    ):
        raise DynamicPoolBindingError("invalid_dynamic_pool_selection")
    entry = inventory.entry_for(selection.agent_id)
    return replace(
        selection,
        account_pool_binding=_make_account_pool_binding_v1(
            account_id=entry.account_id,
            pool_id=entry.pool_id,
            authority_provider=entry.authority_provider,
            runtime_provider=entry.runtime_provider,
        ),
    )


def exact_pool_authority_revalidation(
    binding: AccountPoolBindingV1,
    *,
    reader: Callable[[], UsageEvidenceV2],
) -> bool:
    """Freshly accept one explicit complete V2 reader entry with the exact triple."""

    if not isinstance(binding, AccountPoolBindingV1):
        return False
    if not callable(reader):
        return False
    try:
        evidence = reader()
    except Exception:
        return False
    if not isinstance(evidence, UsageEvidenceV2) or evidence.status != "complete":
        return False
    matches = tuple(
        authority
        for authority in evidence.pool_authorities
        if (
            authority.account_id == binding.account_id
            and authority.pool_id == binding.pool_id
            and authority.provider == binding.authority_provider
        )
    )
    return len(matches) == 1 and matches[0].hive_available is True


__all__ = [
    "AccountPoolBindingV1",
    "DynamicPoolBindingError",
    "DynamicPoolInventoryEntryV1",
    "DynamicPoolInventoryV1",
    "account_pool_binding_from_payload",
    "account_pool_binding_payload",
    "exact_pool_authority_revalidation",
    "resolve_dynamic_pool_selection",
]
