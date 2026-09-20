"""Private, fail-closed GA-I2d deployment-quiescence authority.

This module deliberately has no product composer or public factory.  The three
ports below are read-only seams which must be supplied by a later, separately
composed owner.  Tests may construct the authority with explicit fakes; the
production graph has no implicit fallback.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import time
import uuid
import weakref
from typing import Protocol

from .runtime_layout import RuntimeStateLayoutV1


_SCHEMA_VERSION = 1
_PRINCIPAL_ID = "google.inventory.deployment.quiescence.v1"
_SCOPES = frozenset(
    {
        "ga_i2d.quiescence.issue",
        "ga_i2d.quiescence.resolve",
        "ga_i2d.quiescence.consume",
    }
)
_SCOPE_ORDER = tuple(sorted(_SCOPES))
_REPOSITORY_SCOPE = "the-hive"
_ACTIONS = {
    "binding_manifest": "desktop-client-binding-manifest-v1",
    "inventory.desktop_client_registry.provision": "inventory-desktop-clients-v1",
    "inventory.schema2_to_schema3": "google-account-inventory",
}
_STATES = frozenset({"ISSUED", "CLAIMED", "CONSUMED", "INDETERMINATE"})
_LOCK_NAME = ".receipt-store.lock"
_MAX_REFERENCE = 256
_MAX_IDENTIFIER = 256
_MAX_RECORD_BYTES = 128 * 1024
_MAX_RECORDS = 128
_MAX_STORE_ENTRIES = _MAX_RECORDS
_MAX_STORE_BYTES = 4 * 1024 * 1024
_MAX_PLAN_SECONDS = 300
_MAX_RECEIPT_SECONDS = 60
_NOREPLACE = 1
_RECEIPT_NAME = re.compile(
    r"^(?P<reference>receipt-v1-[0-9a-f]{64})-(?P<state>issued|claimed|consumed|indeterminate)\.json$"
)
_TEMP_RECEIPT_NAME = re.compile(
    r"^\.receipt-v1-[0-9a-f]{64}\.[0-9a-f]{32}\.tmp$"
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_BOOT_ID_RE = re.compile(r"^[0-9a-fA-F-]{8,128}$")
_OPAQUE_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*$")
_OPAQUE_GENERATION_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SECRET_MARKERS = frozenset(
    {"secret", "token", "password", "credential", "client_secret", "refresh_token"}
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_reference",
        "plan_reference",
        "plan_digest",
        "action",
        "target_class",
        "inventory_authority_generation",
        "inventory_authority_fingerprint",
        "manifest_generation",
        "manifest_fingerprint",
        "inventory_generation",
        "inventory_content_fingerprint",
        "registry_generation",
        "registry_fingerprint",
        "candidate_inventory_fingerprint",
        "issuer_principal_id",
        "issuer_principal_generation",
        "principal_lease_digest",
        "principal_scope_digest",
        "target_set_digest",
        "boot_id",
        "issued_at_utc",
        "expires_at_utc",
        "issued_boottime_ns",
        "expires_boottime_ns",
        "state",
        "binding_digest",
        "receipt_digest",
    }
)


class QuiescenceAuthorityError(RuntimeError):
    """Base class for typed fail-closed authority failures."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.reason = code
        suffix = (
            "indeterminate"
            if self.__class__.__name__ == "AuthorityIndeterminate"
            else "unavailable"
        )
        self.code = (
            code
            if code.startswith("google_inventory_deployment_quiescence_")
            else f"google_inventory_deployment_quiescence_{suffix}"
        )
        super().__init__(message or code)


class AuthorityUnavailable(QuiescenceAuthorityError):
    """Evidence or a required safe primitive is unavailable or invalid."""


class AuthorityIndeterminate(QuiescenceAuthorityError):
    """A persisted or observed sequence cannot be safely classified."""

    def __init__(
        self,
        code: str = "indeterminate",
        message: str | None = None,
        *,
        receipt: QuiescenceReceipt | None = None,
    ) -> None:
        self.receipt = receipt
        super().__init__(code, message)


class _TransitionExpired(RuntimeError):
    """The lifecycle receipt expired while its durable state was changing."""


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_member")
        result[key] = value
    return result


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _receipt_reference_for_plan(plan_reference: object) -> str:
    """Derive the only bounded opaque receipt reference for a plan."""

    reference = _opaque_reference(plan_reference)
    return "receipt-v1-" + hashlib.sha256(reference.encode("utf-8")).hexdigest()


def _text(value: object, *, name: str, max_length: int = _MAX_IDENTIFIER) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise AuthorityUnavailable(f"invalid_{name}")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise AuthorityUnavailable(f"invalid_{name}")
    return value


def _opaque_reference(value: object) -> str:
    result = _text(value, name="reference", max_length=_MAX_REFERENCE)
    if _OPAQUE_REFERENCE_RE.fullmatch(result) is None:
        raise AuthorityUnavailable("invalid_reference")
    if any(marker in result.casefold() for marker in _SECRET_MARKERS):
        raise AuthorityUnavailable("secret_in_reference")
    return result


def _identifier(value: object, *, name: str) -> str:
    result = _text(value, name=name)
    if "/" in result or "\\" in result or "@" in result:
        raise AuthorityUnavailable(f"invalid_{name}")
    lowered = result.casefold()
    if any(marker in lowered for marker in _SECRET_MARKERS):
        raise AuthorityUnavailable(f"secret_in_{name}")
    return result


def _digest_value(value: object, *, name: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise AuthorityUnavailable(f"invalid_{name}")
    return value


def _generation_value(value: object, *, name: str) -> int | str:
    if type(value) is int:
        if value <= 0:
            raise AuthorityUnavailable(f"invalid_{name}")
        return value
    result = _text(value, name=name)
    if _OPAQUE_GENERATION_RE.fullmatch(result) is None:
        raise AuthorityUnavailable(f"invalid_{name}")
    if any(marker in result.casefold() for marker in _SECRET_MARKERS):
        raise AuthorityUnavailable(f"secret_in_{name}")
    return result


def _utc_ns(value: object, *, name: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        result = value
    elif isinstance(value, str):
        candidate = value
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise AuthorityUnavailable(f"invalid_{name}") from exc
        if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(None):
            raise AuthorityUnavailable(f"invalid_{name}")
        result = int(parsed.timestamp() * 1_000_000_000)
    else:
        raise AuthorityUnavailable(f"invalid_{name}")
    if result <= 0:
        raise AuthorityUnavailable(f"invalid_{name}")
    return result


def _utc_text(value_ns: int) -> str:
    return (
        datetime.fromtimestamp(value_ns / 1_000_000_000, tz=timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _now_utc_ns() -> int:
    return time.time_ns()


def _now_boottime_ns() -> int:
    clock = getattr(time, "CLOCK_BOOTTIME", None)
    if clock is None:
        raise AuthorityUnavailable("clock_boottime_unavailable")
    try:
        return time.clock_gettime_ns(clock)
    except (OSError, ValueError) as exc:
        raise AuthorityUnavailable("clock_boottime_unavailable") from exc


def _read_boot_id() -> str:
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as stream:
            value = stream.read(129).strip()
    except (OSError, UnicodeError) as exc:
        raise AuthorityUnavailable("boot_id_unavailable") from exc
    if _BOOT_ID_RE.fullmatch(value) is None:
        raise AuthorityUnavailable("invalid_boot_id")
    return value.casefold()


_current_boottime = _now_boottime_ns
_current_utc = _now_utc_ns
_current_boot_id = _read_boot_id


def _store_checkpoint(state: str, boundary: str) -> None:
    """Test-observable boundary; production has no alternate persistence path."""

    del state, boundary


def _sequence(value: object, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not value:
        raise AuthorityUnavailable(f"invalid_{name}")
    result = tuple(_identifier(item, name=name) for item in value)
    if len(set(result)) != len(result):
        raise AuthorityUnavailable(f"duplicate_{name}")
    return result


@dataclass(frozen=True, slots=True)
class PlanBindingRecord:
    plan_reference: str
    plan_digest: str
    action: str
    target_class: str
    inventory_authority_generation: int | str
    inventory_authority_fingerprint: str
    manifest_generation: int | str
    manifest_fingerprint: str
    inventory_generation: int | str
    inventory_content_fingerprint: str
    registry_generation: int | str
    registry_fingerprint: str
    candidate_inventory_fingerprint: str
    expires_at_utc: str | int

    def to_document(self) -> dict[str, object]:
        return {
            "plan_reference": self.plan_reference,
            "plan_digest": self.plan_digest,
            "action": self.action,
            "target_class": self.target_class,
            "inventory_authority_generation": self.inventory_authority_generation,
            "inventory_authority_fingerprint": self.inventory_authority_fingerprint,
            "manifest_generation": self.manifest_generation,
            "manifest_fingerprint": self.manifest_fingerprint,
            "inventory_generation": self.inventory_generation,
            "inventory_content_fingerprint": self.inventory_content_fingerprint,
            "registry_generation": self.registry_generation,
            "registry_fingerprint": self.registry_fingerprint,
            "candidate_inventory_fingerprint": self.candidate_inventory_fingerprint,
            "expires_at_utc": self.expires_at_utc,
        }

    @property
    def digest(self) -> str:
        return _digest(self.to_document())


@dataclass(frozen=True, slots=True)
class PrincipalLeaseScopeRecord:
    principal_id: str
    authority_generation: int | str
    lease_id: str
    lease_expires_boottime_ns: int
    scopes: tuple[str, ...]
    scope_digest: str
    queen_authorization_digest: str
    repository_scope: str
    boot_id: str | None = None

    @property
    def lease_digest(self) -> str:
        return _digest(
            {
                "principal_id": self.principal_id,
                "authority_generation": self.authority_generation,
                "lease_id": self.lease_id,
                "repository_scope": self.repository_scope,
                "lease_expires_boottime_ns": self.lease_expires_boottime_ns,
            }
        )

    @property
    def attested_scope_digest(self) -> str:
        return self.scope_digest


@dataclass(frozen=True, slots=True)
class TargetSetRecord:
    action: str
    target_class: str
    principal_id: str
    principal_generation: int | str
    lease_id: str
    owner: str
    consumers: tuple[str, ...]
    target_set_digest: str
    boot_id: str | None = None

    @property
    def digest(self) -> str:
        return _digest(_target_projection(self))


class _PlanBindingPort(Protocol):
    def read(self, plan_reference: str) -> PlanBindingRecord | None:
        """Read one complete, closed plan binding without side effects."""


class _PrincipalLeaseScopePort(Protocol):
    def read(self) -> PrincipalLeaseScopeRecord | None:
        """Read one complete, closed principal/lease/scope record."""


class _TargetsetPort(Protocol):
    def read(
        self, action: str, target_class: str
    ) -> TargetSetRecord | None:
        """Read one complete, closed targetset record."""


@dataclass(frozen=True, slots=True)
class QuiescenceReceipt:
    schema_version: int
    receipt_reference: str
    plan_reference: str
    plan_digest: str
    action: str
    target_class: str
    inventory_authority_generation: int | str
    inventory_authority_fingerprint: str
    manifest_generation: int | str
    manifest_fingerprint: str
    inventory_generation: int | str
    inventory_content_fingerprint: str
    registry_generation: int | str
    registry_fingerprint: str
    candidate_inventory_fingerprint: str
    issuer_principal_id: str
    issuer_principal_generation: int | str
    principal_lease_digest: str
    principal_scope_digest: str
    target_set_digest: str
    boot_id: str
    issued_at_utc: str
    expires_at_utc: str
    issued_boottime_ns: int
    expires_boottime_ns: int
    state: str
    binding_digest: str
    receipt_digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "receipt_reference": self.receipt_reference,
            "plan_reference": self.plan_reference,
            "plan_digest": self.plan_digest,
            "action": self.action,
            "target_class": self.target_class,
            "inventory_authority_generation": self.inventory_authority_generation,
            "inventory_authority_fingerprint": self.inventory_authority_fingerprint,
            "manifest_generation": self.manifest_generation,
            "manifest_fingerprint": self.manifest_fingerprint,
            "inventory_generation": self.inventory_generation,
            "inventory_content_fingerprint": self.inventory_content_fingerprint,
            "registry_generation": self.registry_generation,
            "registry_fingerprint": self.registry_fingerprint,
            "candidate_inventory_fingerprint": self.candidate_inventory_fingerprint,
            "issuer_principal_id": self.issuer_principal_id,
            "issuer_principal_generation": self.issuer_principal_generation,
            "principal_lease_digest": self.principal_lease_digest,
            "principal_scope_digest": self.principal_scope_digest,
            "target_set_digest": self.target_set_digest,
            "boot_id": self.boot_id,
            "issued_at_utc": self.issued_at_utc,
            "expires_at_utc": self.expires_at_utc,
            "issued_boottime_ns": self.issued_boottime_ns,
            "expires_boottime_ns": self.expires_boottime_ns,
            "state": self.state,
            "binding_digest": self.binding_digest,
            "receipt_digest": self.receipt_digest,
        }

    def to_json(self) -> bytes:
        return _canonical_json(self.to_dict())

    def canonical_bytes(self) -> bytes:
        return self.to_json()

    @classmethod
    def from_canonical_bytes(cls, raw: bytes) -> QuiescenceReceipt:
        if not isinstance(raw, bytes) or len(raw) > _MAX_RECORD_BYTES:
            raise AuthorityUnavailable("record_size_bound")
        try:
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise AuthorityUnavailable("record_json_invalid") from exc
        if not isinstance(payload, dict) or raw != _canonical_json(payload):
            raise AuthorityUnavailable("record_not_canonical")
        return _receipt_from_payload(payload)

def _coerce_plan(value: object) -> PlanBindingRecord:
    if not isinstance(value, PlanBindingRecord):
        raise AuthorityUnavailable("plan_binding_unavailable")
    return value


def _coerce_principal(value: object) -> PrincipalLeaseScopeRecord:
    if not isinstance(value, PrincipalLeaseScopeRecord):
        raise AuthorityUnavailable("principal_unavailable")
    return value


def _coerce_targetset(value: object) -> TargetSetRecord:
    if not isinstance(value, TargetSetRecord):
        raise AuthorityUnavailable("targetset_unavailable")
    return value


def _validate_plan(
    record: PlanBindingRecord, *, now_utc_ns: int | None
) -> int:
    _opaque_reference(record.plan_reference)
    for field_name in (
        "plan_digest",
        "inventory_authority_fingerprint",
        "manifest_fingerprint",
        "inventory_content_fingerprint",
        "registry_fingerprint",
        "candidate_inventory_fingerprint",
    ):
        _digest_value(getattr(record, field_name), name=field_name)
    _text(record.action, name="action")
    if record.action not in _ACTIONS or record.target_class != _ACTIONS[record.action]:
        raise AuthorityUnavailable("invalid_action_target")
    for field_name in (
        "inventory_authority_generation",
        "manifest_generation",
        "inventory_generation",
        "registry_generation",
    ):
        _generation_value(getattr(record, field_name), name=field_name)
    expires_ns = _utc_ns(record.expires_at_utc, name="plan_expiry")
    if now_utc_ns is not None:
        remaining = expires_ns - now_utc_ns
        if remaining <= 0 or remaining > _MAX_PLAN_SECONDS * 1_000_000_000:
            raise AuthorityUnavailable("plan_expired_or_unbounded")
    return expires_ns


def _principal_projection(record: PrincipalLeaseScopeRecord) -> dict[str, object]:
    return {
        "principal_id": record.principal_id,
        "authority_generation": record.authority_generation,
        "lease_id": record.lease_id,
        "repository_scope": record.repository_scope,
        "scopes": sorted(record.scopes),
        "queen_authorization_digest": record.queen_authorization_digest,
    }


def _validate_principal(
    record: PrincipalLeaseScopeRecord, *, now_boottime_ns: int, boot_id: str
) -> None:
    if record.principal_id != _PRINCIPAL_ID:
        raise AuthorityUnavailable("principal_mismatch")
    if record.boot_id is not None and record.boot_id != boot_id:
        raise AuthorityIndeterminate("principal_rebooted")
    _generation_value(record.authority_generation, name="authority_generation")
    _identifier(record.lease_id, name="lease_id")
    if (
        _identifier(record.repository_scope, name="repository_scope")
        != _REPOSITORY_SCOPE
    ):
        raise AuthorityUnavailable("repository_scope_mismatch")
    if (
        type(record.lease_expires_boottime_ns) is not int
        or record.lease_expires_boottime_ns <= now_boottime_ns
    ):
        raise AuthorityUnavailable("lease_expired")
    scopes = _sequence(record.scopes, name="scope")
    if frozenset(scopes) != _SCOPES:
        raise AuthorityUnavailable("scope_mismatch")
    _digest_value(record.queen_authorization_digest, name="queen_authorization")
    if record.scope_digest != _digest(_principal_projection(record)):
        raise AuthorityUnavailable("scope_digest_mismatch")


def _target_projection(record: TargetSetRecord) -> dict[str, object]:
    return {
        "action": record.action,
        "target_class": record.target_class,
        "principal_id": record.principal_id,
        "principal_generation": record.principal_generation,
        "lease_id": record.lease_id,
        "owner": record.owner,
        "consumers": sorted(record.consumers),
    }


def _validate_targetset(
    record: TargetSetRecord,
    *,
    action: str,
    target_class: str,
    principal: PrincipalLeaseScopeRecord,
    boot_id: str | None = None,
) -> None:
    if record.action != action or record.target_class != target_class:
        raise AuthorityUnavailable("targetset_mismatch")
    if record.principal_id != principal.principal_id:
        raise AuthorityUnavailable("targetset_principal_mismatch")
    if record.principal_generation != principal.authority_generation:
        raise AuthorityUnavailable("targetset_generation_mismatch")
    if record.lease_id != principal.lease_id:
        raise AuthorityUnavailable("targetset_lease_mismatch")
    if record.boot_id is not None and boot_id is not None and record.boot_id != boot_id:
        raise AuthorityIndeterminate("targetset_rebooted")
    _identifier(record.owner, name="target_owner")
    consumers = _sequence(record.consumers, name="target_consumer")
    if record.target_set_digest != record.digest:
        raise AuthorityUnavailable("targetset_digest_mismatch")
    if record.owner in consumers:
        raise AuthorityUnavailable("targetset_owner_consumer_overlap")


def _binding_projection(receipt: QuiescenceReceipt) -> dict[str, object]:
    return {
        "schema_version": receipt.schema_version,
        "plan_reference": receipt.plan_reference,
        "plan_digest": receipt.plan_digest,
        "action": receipt.action,
        "target_class": receipt.target_class,
        "inventory_authority_generation": receipt.inventory_authority_generation,
        "inventory_authority_fingerprint": receipt.inventory_authority_fingerprint,
        "manifest_generation": receipt.manifest_generation,
        "manifest_fingerprint": receipt.manifest_fingerprint,
        "inventory_generation": receipt.inventory_generation,
        "inventory_content_fingerprint": receipt.inventory_content_fingerprint,
        "registry_generation": receipt.registry_generation,
        "registry_fingerprint": receipt.registry_fingerprint,
        "candidate_inventory_fingerprint": receipt.candidate_inventory_fingerprint,
        "issuer_principal_id": receipt.issuer_principal_id,
        "issuer_principal_generation": receipt.issuer_principal_generation,
        "principal_lease_digest": receipt.principal_lease_digest,
        "principal_scope_digest": receipt.principal_scope_digest,
        "target_set_digest": receipt.target_set_digest,
        "boot_id": receipt.boot_id,
    }


def _receipt_digest_payload(receipt: QuiescenceReceipt) -> dict[str, object]:
    payload = receipt.to_dict()
    payload.pop("receipt_digest")
    return payload


def _validate_receipt(receipt: QuiescenceReceipt) -> None:
    if type(receipt.schema_version) is not int or receipt.schema_version != _SCHEMA_VERSION:
        raise AuthorityUnavailable("schema_mismatch")
    if _RECEIPT_NAME.fullmatch(receipt.receipt_reference + "-issued.json") is None:
        raise AuthorityUnavailable("invalid_receipt_reference")
    _opaque_reference(receipt.plan_reference)
    if receipt.receipt_reference != _receipt_reference_for_plan(receipt.plan_reference):
        raise AuthorityUnavailable("receipt_reference_not_plan_bound")
    for field_name in (
        "plan_digest",
        "inventory_authority_fingerprint",
        "manifest_fingerprint",
        "inventory_content_fingerprint",
        "registry_fingerprint",
        "candidate_inventory_fingerprint",
        "principal_lease_digest",
        "principal_scope_digest",
        "target_set_digest",
    ):
        _digest_value(getattr(receipt, field_name), name=field_name)
    if receipt.action not in _ACTIONS or _ACTIONS[receipt.action] != receipt.target_class:
        raise AuthorityUnavailable("invalid_receipt_action")
    for field_name in (
        "inventory_authority_generation",
        "manifest_generation",
        "inventory_generation",
        "registry_generation",
        "issuer_principal_generation",
    ):
        _generation_value(getattr(receipt, field_name), name=field_name)
    if receipt.issuer_principal_id != _PRINCIPAL_ID:
        raise AuthorityUnavailable("receipt_principal_mismatch")
    if _BOOT_ID_RE.fullmatch(receipt.boot_id) is None:
        raise AuthorityUnavailable("invalid_receipt_boot_id")
    issued_utc = _utc_ns(receipt.issued_at_utc, name="issued_at")
    expires_utc = _utc_ns(receipt.expires_at_utc, name="expires_at")
    if (
        type(receipt.issued_boottime_ns) is not int
        or type(receipt.expires_boottime_ns) is not int
        or receipt.issued_boottime_ns <= 0
        or receipt.expires_boottime_ns <= receipt.issued_boottime_ns
        or expires_utc <= issued_utc
        or receipt.expires_boottime_ns - receipt.issued_boottime_ns
        > _MAX_RECEIPT_SECONDS * 1_000_000_000
    ):
        raise AuthorityUnavailable("invalid_receipt_time")
    if receipt.state not in _STATES:
        raise AuthorityUnavailable("invalid_receipt_state")
    _digest_value(receipt.binding_digest, name="binding_digest")
    if receipt.receipt_digest != _digest(_receipt_digest_payload(receipt)):
        raise AuthorityUnavailable("receipt_digest_mismatch")


def _receipt_from_payload(payload: Mapping[str, object]) -> QuiescenceReceipt:
    if set(payload) != _RECEIPT_FIELDS:
        raise AuthorityUnavailable("receipt_field_set_mismatch")
    try:
        receipt = QuiescenceReceipt(**dict(payload))
    except (TypeError, ValueError) as exc:
        raise AuthorityUnavailable("invalid_receipt") from exc
    _validate_receipt(receipt)
    return receipt


def _with_state(receipt: QuiescenceReceipt, state: str) -> QuiescenceReceipt:
    payload = receipt.to_dict()
    payload["state"] = state
    payload["receipt_digest"] = ""
    candidate = QuiescenceReceipt(**payload)
    payload["receipt_digest"] = _digest(_receipt_digest_payload(candidate))
    return QuiescenceReceipt(**payload)


class _ClaimContinuity:
    __slots__ = ("authority", "receipt_reference", "binding_digest", "nonce", "__weakref__")

    def __init__(self, authority: object, receipt_reference: str, binding_digest: str) -> None:
        self.authority = authority
        self.receipt_reference = receipt_reference
        self.binding_digest = binding_digest
        self.nonce = object()

    def __copy__(self) -> _ClaimContinuity:
        raise TypeError("continuity_not_copyable")

    def __deepcopy__(self, memo: dict[int, object]) -> _ClaimContinuity:
        raise TypeError("continuity_not_copyable")

    def __reduce__(self) -> object:
        raise TypeError("continuity_not_serializable")


class _AuthorityState:
    __slots__ = (
        "layout",
        "plan_binding",
        "principal_lease_scope",
        "targetset",
        "claimed_continuities",
    )

    def __init__(
        self,
        layout: RuntimeStateLayoutV1,
        plan_binding: _PlanBindingPort,
        principal_lease_scope: _PrincipalLeaseScopePort,
        targetset: _TargetsetPort,
    ) -> None:
        self.layout = layout
        self.plan_binding = plan_binding
        self.principal_lease_scope = principal_lease_scope
        self.targetset = targetset
        self.claimed_continuities: weakref.WeakKeyDictionary[_ClaimContinuity, str] = (
            weakref.WeakKeyDictionary()
        )


_AUTHORITY_STATES = weakref.WeakKeyDictionary()


def _require_safe_fd_flags() -> tuple[int, int]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if not nofollow or not cloexec:
        raise AuthorityUnavailable("o_nofollow_unavailable")
    return nofollow, cloexec


def _stat_regular(fd: int, *, expected_size: int | None = None) -> os.stat_result:
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise AuthorityUnavailable("store_stat_failed") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
        or info.st_size < 0
        or info.st_size > _MAX_RECORD_BYTES
        or (expected_size is not None and info.st_size != expected_size)
    ):
        raise AuthorityUnavailable("store_file_invariant")
    return info


def _read_fd(fd: int, *, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size + 1
    while remaining:
        try:
            chunk = os.read(fd, min(65536, remaining))
        except OSError as exc:
            raise AuthorityUnavailable("store_read_failed") from exc
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) != size or len(raw) > _MAX_RECORD_BYTES:
        raise AuthorityUnavailable("store_read_bound")
    return raw


def _read_record_file(dirfd: int, name: str) -> QuiescenceReceipt:
    nofollow, cloexec = _require_safe_fd_flags()
    try:
        fd = os.open(name, os.O_RDONLY | nofollow | cloexec, dir_fd=dirfd)
    except OSError as exc:
        raise AuthorityUnavailable("record_open_failed") from exc
    try:
        info = _stat_regular(fd)
        raw = _read_fd(fd, size=info.st_size)
    finally:
        os.close(fd)
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise AuthorityUnavailable("record_json_invalid") from exc
    if not isinstance(payload, dict) or raw != _canonical_json(payload):
        raise AuthorityUnavailable("record_not_canonical")
    return _receipt_from_payload(payload)


def _entry_names(dirfd: int) -> list[str]:
    try:
        names = os.listdir(dirfd)
    except OSError as exc:
        raise AuthorityUnavailable("store_list_failed") from exc
    if not isinstance(names, list) or len(names) > _MAX_RECORDS + 1:
        raise AuthorityUnavailable("store_entry_bound")
    return names


def _validate_lock_file(dirfd: int) -> None:
    nofollow, cloexec = _require_safe_fd_flags()
    try:
        fd = os.open(_LOCK_NAME, os.O_RDONLY | nofollow | cloexec, dir_fd=dirfd)
    except OSError as exc:
        raise AuthorityUnavailable("lock_open_failed") from exc
    try:
        info = _stat_regular(fd, expected_size=0)
    finally:
        os.close(fd)
    if info.st_size != 0:
        raise AuthorityUnavailable("lock_not_empty")


def _scan_store(dirfd: int) -> dict[str, QuiescenceReceipt]:
    records: dict[str, QuiescenceReceipt] = {}
    states: dict[str, str] = {}
    total_size = 0
    record_count = 0
    for name in _entry_names(dirfd):
        if name == _LOCK_NAME:
            _validate_lock_file(dirfd)
            continue
        match = _RECEIPT_NAME.fullmatch(name)
        if match is None:
            if _TEMP_RECEIPT_NAME.fullmatch(name) is not None:
                raise AuthorityIndeterminate("ambiguous_record_transition")
            raise AuthorityUnavailable("unknown_store_artifact")
        record_count += 1
        reference = match.group("reference")
        state = match.group("state").upper()
        try:
            receipt = _read_record_file(dirfd, name)
        except AuthorityUnavailable as exc:
            if state != "ISSUED":
                raise AuthorityIndeterminate("known_record_unreadable") from exc
            raise
        total_size += len(receipt.to_json())
        if total_size > _MAX_STORE_BYTES:
            raise AuthorityUnavailable("store_size_bound")
        if receipt.receipt_reference != reference or receipt.state != state:
            raise AuthorityUnavailable("record_name_state_mismatch")
        if reference in records:
            raise AuthorityIndeterminate(
                "ambiguous_record_transition", receipt=receipt
            )
        records[reference] = receipt
        states[reference] = state
    if record_count > _MAX_RECORDS:
        raise AuthorityUnavailable("record_count_bound")
    return records


def _open_lock(dirfd: int) -> int:
    nofollow, cloexec = _require_safe_fd_flags()
    flags = os.O_RDWR | os.O_CREAT | nofollow | cloexec
    created = False
    try:
        fd = os.open(_LOCK_NAME, flags | os.O_EXCL, 0o600, dir_fd=dirfd)
        created = True
    except FileExistsError:
        try:
            fd = os.open(_LOCK_NAME, os.O_RDWR | nofollow | cloexec, dir_fd=dirfd)
        except OSError as exc:
            raise AuthorityUnavailable("lock_open_failed") from exc
    except OSError as exc:
        raise AuthorityUnavailable("lock_create_failed") from exc
    try:
        _stat_regular(fd, expected_size=0)
        if created:
            try:
                os.fsync(dirfd)
            except OSError as exc:
                raise AuthorityUnavailable("lock_parent_fsync_failed") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError as exc:
            raise AuthorityUnavailable("lock_failed") from exc
        return fd
    except Exception:
        os.close(fd)
        raise


def _close_lock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(fd, raw[offset:])
        except OSError as exc:
            raise AuthorityUnavailable("record_write_failed") from exc
        if written <= 0:
            raise AuthorityUnavailable("record_write_failed")
        offset += written


def _renameat2_noreplace(dirfd: int, source: str, target: str) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        function = getattr(libc, "renameat2", None)
    except OSError as exc:
        raise AuthorityUnavailable("renameat2_unavailable") from exc
    if function is None:
        raise AuthorityUnavailable("renameat2_unavailable")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    result = function(
        dirfd,
        source.encode("utf-8"),
        dirfd,
        target.encode("utf-8"),
        _NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise AuthorityIndeterminate("rename_noreplace_collision")
        raise AuthorityUnavailable("rename_noreplace_failed")


def _persist_new_record(
    dirfd: int,
    receipt: QuiescenceReceipt,
    *,
    checkpoint_guard: Callable[[], None] | None = None,
) -> str:
    raw = receipt.to_json()
    if len(raw) > _MAX_RECORD_BYTES:
        raise AuthorityUnavailable("record_size_bound")
    final_name = f"{receipt.receipt_reference}-{receipt.state.casefold()}.json"
    temp_name = f".{receipt.receipt_reference}.{uuid.uuid4().hex}.tmp"
    nofollow, cloexec = _require_safe_fd_flags()
    fd = -1
    try:
        try:
            fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
                0o600,
                dir_fd=dirfd,
            )
        except OSError as exc:
            raise AuthorityUnavailable("record_temp_create_failed") from exc
        _write_all(fd, raw)
        _store_checkpoint(receipt.state, "after_temp_write")
        if checkpoint_guard is not None:
            checkpoint_guard()
        os.fsync(fd)
        _store_checkpoint(receipt.state, "after_temp_fsync")
        if checkpoint_guard is not None:
            checkpoint_guard()
        info = _stat_regular(fd, expected_size=len(raw))
        if info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise AuthorityUnavailable("record_temp_invariant")
        os.close(fd)
        fd = -1
        rename = _renameat2_noreplace
        if not callable(rename):
            raise AuthorityUnavailable("renameat2_unavailable")
        rename(dirfd, temp_name, final_name)
        _store_checkpoint(receipt.state, "after_rename")
        if checkpoint_guard is not None:
            checkpoint_guard()
        os.fsync(dirfd)
        _store_checkpoint(receipt.state, "after_parent_fsync")
        if checkpoint_guard is not None:
            checkpoint_guard()
        readback = _read_record_file(dirfd, final_name)
        if readback != receipt:
            raise AuthorityIndeterminate("record_readback_mismatch", receipt=readback)
        _store_checkpoint(receipt.state, "after_readback")
        if checkpoint_guard is not None:
            checkpoint_guard()
        return final_name
    except AuthorityIndeterminate:
        raise
    except OSError as exc:
        raise AuthorityUnavailable("record_persist_failed") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temp_name, dir_fd=dirfd)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _remove_record(
    dirfd: int,
    name: str,
    *,
    state: str,
    checkpoint_guard: Callable[[], None] | None = None,
) -> None:
    try:
        os.unlink(name, dir_fd=dirfd)
        os.fsync(dirfd)
        _store_checkpoint(state, "after_cleanup")
        if checkpoint_guard is not None:
            checkpoint_guard()
    except OSError as exc:
        raise AuthorityIndeterminate("record_cleanup_uncertain") from exc


class GoogleInventoryDeploymentQuiescenceAuthorityV1:
    """The sole package-private owner of the P0 receipt lifecycle."""

    __slots__ = ("__weakref__",)

    def __init__(
        self,
        layout: RuntimeStateLayoutV1,
        plan_binding: _PlanBindingPort,
        principal_lease_scope: _PrincipalLeaseScopePort,
        targetset: _TargetsetPort,
    ) -> None:
        if type(layout) is not RuntimeStateLayoutV1:
            raise AuthorityUnavailable("state_layout_unavailable")
        try:
            RuntimeStateLayoutV1.validate(layout)
        except Exception as exc:
            raise AuthorityUnavailable("state_layout_unavailable") from exc
        if not callable(getattr(plan_binding, "read", None)):
            raise AuthorityUnavailable("private_port_unavailable")
        if not callable(getattr(principal_lease_scope, "read", None)):
            raise AuthorityUnavailable("private_port_unavailable")
        if not callable(getattr(targetset, "read", None)):
            raise AuthorityUnavailable("private_port_unavailable")
        for port in (plan_binding, principal_lease_scope, targetset):
            if port is None:
                raise AuthorityUnavailable("private_port_unavailable")
        _AUTHORITY_STATES[self] = _AuthorityState(
            layout, plan_binding, principal_lease_scope, targetset
        )

    def _state(self) -> _AuthorityState:
        try:
            return _AUTHORITY_STATES[self]
        except KeyError as exc:
            raise AuthorityUnavailable("authority_reconstruction_unavailable") from exc

    @property
    def _layout(self) -> RuntimeStateLayoutV1:
        return self._state().layout

    @property
    def _plan_binding(self) -> _PlanBindingPort:
        return self._state().plan_binding

    @property
    def _principal_lease_scope(self) -> _PrincipalLeaseScopePort:
        return self._state().principal_lease_scope

    @property
    def _targetset(self) -> _TargetsetPort:
        return self._state().targetset

    @property
    def _claimed_continuities(self) -> weakref.WeakKeyDictionary[_ClaimContinuity, str]:
        return self._state().claimed_continuities

    def __copy__(self) -> GoogleInventoryDeploymentQuiescenceAuthorityV1:
        raise TypeError("authority_not_copyable")

    def __deepcopy__(
        self, memo: dict[int, object]
    ) -> GoogleInventoryDeploymentQuiescenceAuthorityV1:
        raise TypeError("authority_not_copyable")

    def __reduce__(self) -> object:
        raise TypeError("authority_not_serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("authority_not_serializable")

    def _clock_values(self) -> tuple[int, int, str]:
        self._state()
        try:
            boot = _current_boottime()
            utc = _current_utc()
            boot_id = _current_boot_id()
        except QuiescenceAuthorityError:
            raise
        except Exception as exc:
            raise AuthorityUnavailable("clock_unavailable") from exc
        if type(boot) is not int or type(utc) is not int or boot <= 0 or utc <= 0:
            raise AuthorityUnavailable("clock_unavailable")
        if _BOOT_ID_RE.fullmatch(boot_id) is None:
            raise AuthorityUnavailable("invalid_boot_id")
        return boot, utc, boot_id.casefold()

    def _read_binding(self, plan_reference: str) -> PlanBindingRecord:
        _opaque_reference(plan_reference)
        try:
            value = self._plan_binding.read(plan_reference)
        except Exception as exc:
            raise AuthorityUnavailable("plan_binding_unavailable") from exc
        if value is None:
            raise AuthorityUnavailable("plan_binding_unavailable")
        record = _coerce_plan(value)
        if record.plan_reference != plan_reference:
            raise AuthorityUnavailable("plan_reference_mismatch")
        return record

    def _read_principal(
        self, *, now_boottime_ns: int, boot_id: str
    ) -> PrincipalLeaseScopeRecord:
        try:
            value = self._principal_lease_scope.read()
        except Exception as exc:
            raise AuthorityUnavailable("principal_unavailable") from exc
        if value is None:
            raise AuthorityUnavailable("principal_unavailable")
        record = _coerce_principal(value)
        _validate_principal(
            record, now_boottime_ns=now_boottime_ns, boot_id=boot_id
        )
        return record

    def _read_targetset(
        self,
        *,
        binding: PlanBindingRecord,
        principal: PrincipalLeaseScopeRecord,
        boot_id: str,
    ) -> TargetSetRecord:
        try:
            value = self._targetset.read(binding.action, binding.target_class)
        except Exception as exc:
            raise AuthorityUnavailable("targetset_unavailable") from exc
        if value is None:
            raise AuthorityUnavailable("targetset_unavailable")
        record = _coerce_targetset(value)
        _validate_targetset(
            record,
            action=binding.action,
            target_class=binding.target_class,
            principal=principal,
            boot_id=boot_id,
        )
        return record

    def _attest_receipt(
        self,
        receipt: QuiescenceReceipt,
        *,
        now_boottime_ns: int,
        now_utc_ns: int,
        boot_id: str,
        require_open: bool,
    ) -> None:
        _validate_receipt(receipt)
        if receipt.state == "INDETERMINATE":
            raise AuthorityIndeterminate("receipt_indeterminate", receipt=receipt)
        if receipt.state in {"ISSUED", "CLAIMED"} and require_open:
            if boot_id != receipt.boot_id:
                raise AuthorityIndeterminate("reboot_invalidated", receipt=receipt)
            if now_boottime_ns < receipt.issued_boottime_ns:
                raise AuthorityIndeterminate("boottime_regressed", receipt=receipt)
            if now_boottime_ns >= receipt.expires_boottime_ns:
                raise AuthorityUnavailable("receipt_expired")
        binding = self._read_binding(receipt.plan_reference)
        plan_expires_utc = _validate_plan(binding, now_utc_ns=None)
        if _utc_ns(receipt.expires_at_utc, name="expires_at") > plan_expires_utc:
            raise AuthorityUnavailable("receipt_plan_expiry_stale")
        principal = self._read_principal(
            now_boottime_ns=now_boottime_ns, boot_id=boot_id
        )
        targetset = self._read_targetset(
            binding=binding, principal=principal, boot_id=boot_id
        )
        expected = {
            "plan_digest": binding.plan_digest,
            "binding_digest": binding.digest,
            "action": binding.action,
            "target_class": binding.target_class,
            "inventory_authority_generation": binding.inventory_authority_generation,
            "inventory_authority_fingerprint": binding.inventory_authority_fingerprint,
            "manifest_generation": binding.manifest_generation,
            "manifest_fingerprint": binding.manifest_fingerprint,
            "inventory_generation": binding.inventory_generation,
            "inventory_content_fingerprint": binding.inventory_content_fingerprint,
            "registry_generation": binding.registry_generation,
            "registry_fingerprint": binding.registry_fingerprint,
            "candidate_inventory_fingerprint": binding.candidate_inventory_fingerprint,
            "issuer_principal_id": principal.principal_id,
            "issuer_principal_generation": principal.authority_generation,
            "principal_lease_digest": principal.lease_digest,
            "principal_scope_digest": principal.attested_scope_digest,
            "target_set_digest": targetset.target_set_digest,
        }
        for field_name, expected_value in expected.items():
            if getattr(receipt, field_name) != expected_value:
                raise AuthorityUnavailable(f"receipt_{field_name}_stale")

    @contextmanager
    def _mutation_store(self) -> Iterator[int]:
        try:
            dirfd = self._layout.open_dirfd()
        except Exception as exc:
            if isinstance(exc, AuthorityUnavailable):
                raise
            raise AuthorityUnavailable("state_directory_unavailable") from exc
        lockfd = -1
        try:
            _scan_store(dirfd)
            lockfd = _open_lock(dirfd)
            _scan_store(dirfd)
            yield dirfd
        finally:
            if lockfd >= 0:
                _close_lock(lockfd)
            os.close(dirfd)

    def _read_store(self) -> dict[str, QuiescenceReceipt]:
        try:
            dirfd = self._layout.open_dirfd()
        except Exception as exc:
            if isinstance(exc, AuthorityUnavailable):
                raise
            raise AuthorityUnavailable("state_directory_unavailable") from exc
        try:
            return _scan_store(dirfd)
        finally:
            os.close(dirfd)

    def _transition(
        self,
        dirfd: int,
        current: QuiescenceReceipt,
        next_state: str,
        *,
        checkpoint_guard: Callable[[], None] | None = None,
    ) -> QuiescenceReceipt:
        next_receipt = _with_state(current, next_state)
        _validate_receipt(next_receipt)
        _persist_new_record(
            dirfd, next_receipt, checkpoint_guard=checkpoint_guard
        )
        old_name = f"{current.receipt_reference}-{current.state.casefold()}.json"
        _remove_record(
            dirfd,
            old_name,
            state=next_receipt.state,
            checkpoint_guard=checkpoint_guard,
        )
        if checkpoint_guard is not None:
            checkpoint_guard()
        return next_receipt

    def _assert_transition_live(self, receipt: QuiescenceReceipt) -> None:
        try:
            boot, _utc, boot_id = self._clock_values()
        except QuiescenceAuthorityError as exc:
            raise _TransitionExpired("transition_clock_unavailable") from exc
        if boot_id != receipt.boot_id:
            raise _TransitionExpired("transition_rebooted")
        if boot < receipt.issued_boottime_ns or boot >= receipt.expires_boottime_ns:
            raise _TransitionExpired("transition_receipt_expired")

    def _transition_record_names(self, dirfd: int, reference: str) -> list[str]:
        names: list[str] = []
        for name in _entry_names(dirfd):
            if name == _LOCK_NAME:
                continue
            match = _RECEIPT_NAME.fullmatch(name)
            if match is None:
                if _TEMP_RECEIPT_NAME.fullmatch(name) is not None:
                    raise AuthorityIndeterminate("ambiguous_record_transition")
                raise AuthorityUnavailable("unknown_store_artifact")
            if match.group("reference") != reference:
                continue
            record = _read_record_file(dirfd, name)
            if record.receipt_reference != reference:
                raise AuthorityIndeterminate("record_name_state_mismatch")
            names.append(name)
        return names

    def _persist_terminal_indeterminate(
        self, dirfd: int, receipt: QuiescenceReceipt
    ) -> QuiescenceReceipt:
        terminal = _with_state(receipt, "INDETERMINATE")
        _validate_receipt(terminal)
        _persist_new_record(dirfd, terminal)
        terminal_name = (
            f"{receipt.receipt_reference}-indeterminate.json"
        )
        for name in self._transition_record_names(
            dirfd, receipt.receipt_reference
        ):
            if name == terminal_name:
                continue
            try:
                os.unlink(name, dir_fd=dirfd)
                os.fsync(dirfd)
            except OSError as exc:
                raise AuthorityIndeterminate("record_cleanup_uncertain") from exc
        return terminal

    def issue(self, plan_reference: str) -> QuiescenceReceipt:
        def build_receipt(
            *,
            boot: int,
            utc: int,
            boot_id: str,
            binding: PlanBindingRecord,
            principal: PrincipalLeaseScopeRecord,
            targetset: TargetSetRecord,
            plan_expires_utc: int,
        ) -> QuiescenceReceipt:
            lease_remaining = principal.lease_expires_boottime_ns - boot
            plan_remaining = plan_expires_utc - utc
            lifetime = min(
                lease_remaining,
                plan_remaining,
                _MAX_RECEIPT_SECONDS * 1_000_000_000,
            )
            if lifetime <= 0:
                raise AuthorityUnavailable("receipt_lifetime_unavailable")
            reference = _receipt_reference_for_plan(binding.plan_reference)
            issued_utc = _utc_text(utc)
            expires_utc = _utc_text(utc + lifetime)
            receipt = QuiescenceReceipt(
                schema_version=_SCHEMA_VERSION,
                receipt_reference=reference,
                plan_reference=binding.plan_reference,
                plan_digest=binding.plan_digest,
                action=binding.action,
                target_class=binding.target_class,
                inventory_authority_generation=binding.inventory_authority_generation,
                inventory_authority_fingerprint=binding.inventory_authority_fingerprint,
                manifest_generation=binding.manifest_generation,
                manifest_fingerprint=binding.manifest_fingerprint,
                inventory_generation=binding.inventory_generation,
                inventory_content_fingerprint=binding.inventory_content_fingerprint,
                registry_generation=binding.registry_generation,
                registry_fingerprint=binding.registry_fingerprint,
                candidate_inventory_fingerprint=binding.candidate_inventory_fingerprint,
                issuer_principal_id=principal.principal_id,
                issuer_principal_generation=principal.authority_generation,
                principal_lease_digest=principal.lease_digest,
                principal_scope_digest=principal.attested_scope_digest,
                target_set_digest=targetset.target_set_digest,
                boot_id=boot_id,
                issued_at_utc=issued_utc,
                expires_at_utc=expires_utc,
                issued_boottime_ns=boot,
                expires_boottime_ns=boot + lifetime,
                state="ISSUED",
                binding_digest="",
                receipt_digest="",
            )
            payload = receipt.to_dict()
            payload["binding_digest"] = binding.digest
            receipt = QuiescenceReceipt(**payload)
            payload["receipt_digest"] = _digest(_receipt_digest_payload(receipt))
            receipt = QuiescenceReceipt(**payload)
            _validate_receipt(receipt)
            return receipt

        boot, utc, boot_id = self._clock_values()
        binding = self._read_binding(plan_reference)
        plan_expires_utc = _validate_plan(binding, now_utc_ns=utc)
        principal = self._read_principal(now_boottime_ns=boot, boot_id=boot_id)
        targetset = self._read_targetset(
            binding=binding, principal=principal, boot_id=boot_id
        )
        receipt = build_receipt(
            boot=boot,
            utc=utc,
            boot_id=boot_id,
            binding=binding,
            principal=principal,
            targetset=targetset,
            plan_expires_utc=plan_expires_utc,
        )
        with self._mutation_store() as dirfd:
            boot, utc, boot_id = self._clock_values()
            binding = self._read_binding(plan_reference)
            plan_expires_utc = _validate_plan(binding, now_utc_ns=utc)
            principal = self._read_principal(
                now_boottime_ns=boot, boot_id=boot_id
            )
            targetset = self._read_targetset(
                binding=binding, principal=principal, boot_id=boot_id
            )
            receipt = build_receipt(
                boot=boot,
                utc=utc,
                boot_id=boot_id,
                binding=binding,
                principal=principal,
                targetset=targetset,
                plan_expires_utc=plan_expires_utc,
            )
            records = _scan_store(dirfd)
            for existing in records.values():
                if existing.plan_reference == binding.plan_reference:
                    if existing.state == "CLAIMED":
                        raise AuthorityIndeterminate(
                            "plan_already_claimed", receipt=existing
                        )
                    if existing.state == "INDETERMINATE":
                        raise AuthorityIndeterminate(
                            "plan_already_indeterminate", receipt=existing
                        )
                    raise AuthorityUnavailable("plan_already_issued")
            _persist_new_record(dirfd, receipt)
        return receipt

    def resolve(self, receipt_reference: str) -> QuiescenceReceipt | None:
        reference = _opaque_reference(receipt_reference)
        records = self._read_store()
        receipt = records.get(reference)
        if receipt is None:
            return None
        if receipt.state == "INDETERMINATE":
            return receipt
        if receipt.state == "CLAIMED" and not any(
            known.authority is self
            and known.receipt_reference == receipt.receipt_reference
            and known.binding_digest == receipt.binding_digest
            and digest == receipt.binding_digest
            for known, digest in list(self._claimed_continuities.items())
        ):
            raise AuthorityIndeterminate(
                "claim_continuity_missing", receipt=_with_state(receipt, "INDETERMINATE")
            )
        boot, utc, boot_id = self._clock_values()
        self._attest_receipt(
            receipt,
            now_boottime_ns=boot,
            now_utc_ns=utc,
            boot_id=boot_id,
            require_open=receipt.state in {"ISSUED", "CLAIMED"},
        )
        return receipt

    def claim(self, receipt_reference: str) -> _ClaimContinuity:
        reference = _opaque_reference(receipt_reference)
        with self._mutation_store() as dirfd:
            boot, utc, boot_id = self._clock_values()
            records = _scan_store(dirfd)
            receipt = records.get(reference)
            if receipt is None:
                raise AuthorityUnavailable("receipt_not_found")
            if receipt.state != "ISSUED":
                if receipt.state == "CLAIMED":
                    raise AuthorityIndeterminate("receipt_already_claimed", receipt=receipt)
                if receipt.state == "CONSUMED":
                    raise AuthorityUnavailable("receipt_consumed")
                raise AuthorityIndeterminate("receipt_indeterminate", receipt=receipt)
            self._attest_receipt(
                receipt,
                now_boottime_ns=boot,
                now_utc_ns=utc,
                boot_id=boot_id,
                require_open=True,
            )
            try:
                claimed = self._transition(
                    dirfd,
                    receipt,
                    "CLAIMED",
                    checkpoint_guard=lambda: self._assert_transition_live(receipt),
                )
            except _TransitionExpired as exc:
                try:
                    indeterminate = self._persist_terminal_indeterminate(dirfd, receipt)
                except QuiescenceAuthorityError as terminal_exc:
                    raise AuthorityIndeterminate(
                        "claim_transition_indeterminate"
                    ) from terminal_exc
                raise AuthorityIndeterminate(
                    "claim_transition_expired", receipt=indeterminate
                ) from exc
        continuity = _ClaimContinuity(self, claimed.receipt_reference, claimed.binding_digest)
        self._claimed_continuities[continuity] = claimed.binding_digest
        return continuity

    def _continuity_matches(
        self, continuity: object, receipt: QuiescenceReceipt
    ) -> bool:
        if not isinstance(continuity, _ClaimContinuity):
            return False
        if continuity.authority is not self:
            return False
        if continuity.receipt_reference != receipt.receipt_reference:
            return False
        if continuity.binding_digest != receipt.binding_digest:
            return False
        for known, digest in list(self._claimed_continuities.items()):
            if known is continuity and digest == receipt.binding_digest:
                return True
        return False

    def consume(
        self,
        receipt_reference: str,
        continuity: _ClaimContinuity,
    ) -> QuiescenceReceipt:
        receipt_reference = _opaque_reference(receipt_reference)
        evidence = continuity
        with self._mutation_store() as dirfd:
            boot, utc, boot_id = self._clock_values()
            records = _scan_store(dirfd)
            receipt = records.get(receipt_reference)
            if receipt is None:
                raise AuthorityUnavailable("receipt_not_found")
            if receipt.state != "CLAIMED":
                if receipt.state in {"CONSUMED", "INDETERMINATE"}:
                    raise AuthorityIndeterminate("receipt_not_consumable", receipt=receipt)
                raise AuthorityIndeterminate("claim_required", receipt=receipt)
            if not self._continuity_matches(evidence, receipt):
                indeterminate = self._transition(dirfd, receipt, "INDETERMINATE")
                raise AuthorityIndeterminate(
                    "claim_continuity_missing", receipt=indeterminate
                )
            try:
                self._attest_receipt(
                    receipt,
                    now_boottime_ns=boot,
                    now_utc_ns=utc,
                    boot_id=boot_id,
                    require_open=True,
                )
                boot, utc, boot_id = self._clock_values()
                self._attest_receipt(
                    receipt,
                    now_boottime_ns=boot,
                    now_utc_ns=utc,
                    boot_id=boot_id,
                    require_open=True,
                )
            except (AuthorityUnavailable, AuthorityIndeterminate) as exc:
                indeterminate = self._transition(dirfd, receipt, "INDETERMINATE")
                raise AuthorityIndeterminate(
                    "consume_reattest_failed", receipt=indeterminate
                ) from exc
            try:
                consumed = self._transition(
                    dirfd,
                    receipt,
                    "CONSUMED",
                    checkpoint_guard=lambda: self._assert_transition_live(receipt),
                )
            except _TransitionExpired as exc:
                try:
                    indeterminate = self._persist_terminal_indeterminate(dirfd, receipt)
                except QuiescenceAuthorityError as terminal_exc:
                    self._claimed_continuities.pop(evidence, None)
                    raise AuthorityIndeterminate(
                        "consume_transition_indeterminate"
                    ) from terminal_exc
                self._claimed_continuities.pop(evidence, None)
                raise AuthorityIndeterminate(
                    "consume_transition_expired", receipt=indeterminate
                ) from exc
        self._claimed_continuities.pop(evidence, None)
        return consumed


__all__: tuple[str, ...] = ()
