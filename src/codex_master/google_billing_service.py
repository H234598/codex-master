"""Account-bound, allowlisted Google project billing operations."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import math
import re
import threading
from types import MappingProxyType
from typing import Any, NoReturn, Protocol, cast
import uuid

from .google_account_inventory_manager import GoogleAccountInventoryManager


DEFAULT_BILLING_PLAN_TTL_SECONDS = 300
MAX_BILLING_PLAN_TTL_SECONDS = 900

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_PROVIDER_CODES = {
    "google.api_auth_failed": "billing.provider_auth_failed",
    "google.api_conflict": "billing.provider_conflict",
    "google.api_operation_failed": "billing.provider_failed",
    "google.api_operation_timeout": "billing.provider_unavailable",
    "google.api_quota_exhausted": "billing.provider_unavailable",
    "google.api_request_failed": "billing.provider_failed",
    "google.api_response_invalid": "billing.provider_response_invalid",
    "google.api_unavailable": "billing.provider_unavailable",
}


class GoogleBillingApi(Protocol):
    """Only provider operations this service can represent."""

    def get_project_billing_binding(self, project_id: str) -> str | None: ...

    def create_project_billing_binding(
        self, project_id: str, billing_account_id: str
    ) -> None: ...


@dataclass(frozen=True, slots=True, repr=False)
class GoogleBillingPlanV1:
    id: str
    account_ref: str
    subject_id: str
    inventory_generation: int
    snapshot_fingerprint: str
    project_ref: str
    project_id: str
    billing_ref: str
    billing_account_id: str
    digest: str
    created_at: datetime
    expires_at: datetime
    idempotency_key: str

    def __repr__(self) -> str:
        return (
            "GoogleBillingPlanV1("
            f"id={self.id!r}, account_ref={self.account_ref!r}, "
            f"project_ref={self.project_ref!r}, billing_ref={self.billing_ref!r}, "
            f"inventory_generation={self.inventory_generation!r}, "
            f"digest={self.digest!r}, expires_at={self.expires_at!r})"
        )

    def public_projection(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "id": self.id,
                "account_ref": self.account_ref,
                "inventory_generation": self.inventory_generation,
                "snapshot_fingerprint": self.snapshot_fingerprint,
                "project_ref": self.project_ref,
                "billing_ref": self.billing_ref,
                "digest": self.digest,
                "created_at": _wire_time(self.created_at),
                "expires_at": _wire_time(self.expires_at),
                "idempotency_key": self.idempotency_key,
            }
        )


@dataclass(frozen=True, slots=True)
class GoogleBillingReceiptV1:
    plan_id: str
    state: str
    attempted: int
    completed: int
    failed: int
    not_attempted: int
    reason_code: str

    def public_projection(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "plan_id": self.plan_id,
                "state": self.state,
                "attempted": self.attempted,
                "completed": self.completed,
                "failed": self.failed,
                "not_attempted": self.not_attempted,
                "reason_code": self.reason_code,
            }
        )


class GoogleBillingError(Exception):
    """Stable, redacted billing failure."""

    __slots__ = ("code", "partial")

    def __init__(
        self, code: str, *, partial: GoogleBillingReceiptV1 | None = None
    ) -> None:
        self.code = code
        self.partial = partial
        super().__init__(code)

    def __repr__(self) -> str:
        return f"GoogleBillingError({self.code!r})"


class GoogleBillingService:
    """Plans and applies one project-to-billing association at a time."""

    __slots__ = (
        "_clock",
        "_lock",
        "_manager",
        "_plans",
        "_plans_by_idempotency",
        "_receipts",
        "api",
    )

    def __init__(
        self,
        manager: GoogleAccountInventoryManager,
        api: GoogleBillingApi,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(manager, GoogleAccountInventoryManager):
            raise GoogleBillingError("billing.service_invalid")
        self._manager = manager
        self.api = api
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._plans: dict[str, GoogleBillingPlanV1] = {}
        self._plans_by_idempotency: dict[str, GoogleBillingPlanV1] = {}
        self._receipts: dict[str, GoogleBillingReceiptV1] = {}

    def plan_billing_binding(
        self,
        *,
        project_ref: str,
        billing_ref: str,
        expected_generation: int,
        idempotency_key: str | None = None,
        ttl_seconds: int | float = DEFAULT_BILLING_PLAN_TTL_SECONDS,
    ) -> GoogleBillingPlanV1:
        project_ref = _token(project_ref, "billing.project_not_found")
        billing_ref = _token(billing_ref, "billing.account_not_found")
        expected_generation = _generation(expected_generation)
        ttl = _ttl(ttl_seconds)

        with self._lock:
            snapshot = self._manager._snapshot_for_internal_use()
            if snapshot.generation != expected_generation:
                raise GoogleBillingError("billing.generation_conflict")
            binding = _resolve_binding(snapshot, project_ref, billing_ref)
            if idempotency_key is None:
                idempotency_key = _automatic_idempotency_key(
                    expected_generation, project_ref, billing_ref
                )
            else:
                idempotency_key = _token(idempotency_key, "billing.idempotency_invalid")

            prior = self._plans_by_idempotency.get(idempotency_key)
            if prior is not None:
                if _plan_binding(prior) != binding:
                    raise GoogleBillingError("billing.idempotency_conflict")
                return prior

            created_at = self._now()
            expires_at = created_at + timedelta(seconds=ttl)
            digest = _plan_digest(
                binding,
                created_at=created_at,
                expires_at=expires_at,
                idempotency_key=idempotency_key,
            )
            plan = GoogleBillingPlanV1(
                id="billing-plan-" + uuid.uuid4().hex,
                account_ref=binding[0],
                subject_id=binding[1],
                inventory_generation=binding[2],
                snapshot_fingerprint=binding[3],
                project_ref=binding[4],
                project_id=binding[5],
                billing_ref=binding[6],
                billing_account_id=binding[7],
                digest=digest,
                created_at=created_at,
                expires_at=expires_at,
                idempotency_key=idempotency_key,
            )
            self._plans[plan.id] = plan
            self._plans_by_idempotency[idempotency_key] = plan
            return plan

    def apply_billing_binding(
        self,
        plan_id: str,
        *,
        expected_generation: int,
        confirmed_digest: str | None = None,
        idempotency_key: str | None = None,
    ) -> GoogleBillingReceiptV1:
        plan_id = _token(plan_id, "billing.plan_not_found")
        expected_generation = _generation(expected_generation)
        if confirmed_digest is not None:
            if (
                type(confirmed_digest) is not str
                or _DIGEST.fullmatch(confirmed_digest) is None
            ):
                raise GoogleBillingError("billing.plan_digest_mismatch")
        if idempotency_key is not None:
            idempotency_key = _token(idempotency_key, "billing.idempotency_invalid")

        with self._lock:
            try:
                plan = self._plans[plan_id]
            except KeyError:
                raise GoogleBillingError("billing.plan_not_found") from None
            if expected_generation != plan.inventory_generation:
                raise GoogleBillingError("billing.plan_stale")
            if confirmed_digest is not None and confirmed_digest != plan.digest:
                raise GoogleBillingError("billing.plan_digest_mismatch")
            if idempotency_key is not None and idempotency_key != plan.idempotency_key:
                raise GoogleBillingError("billing.idempotency_conflict")
            prior = self._receipts.get(plan.id)
            if prior is not None:
                return prior
            if self._now() >= plan.expires_at:
                raise GoogleBillingError("billing.plan_expired")

            with self._manager._lock:
                self._revalidate(plan)
                current = self._get_binding(plan.project_id, plan_id=plan.id)
                if current is not None:
                    if current != plan.billing_account_id:
                        raise GoogleBillingError("billing.foreign_binding")
                    return self._finish(plan, "billing.binding_already_present")

                # Query may itself trigger a same-thread manager reload. Recheck
                # after it and immediately before the only allowed mutation.
                self._revalidate(plan)
                try:
                    self.api.create_project_billing_binding(
                        plan.project_id, plan.billing_account_id
                    )
                except Exception as error:
                    self._raise_provider_failure(error, plan.id, partial=True)
                try:
                    observed = self._provider_binding(plan.project_id)
                except Exception as error:
                    self._raise_provider_failure(error, plan.id, partial=True)
                if observed != plan.billing_account_id:
                    self._raise_provider_failure(
                        None,
                        plan.id,
                        partial=True,
                        code="billing.provider_response_invalid",
                    )
                return self._finish(plan, "billing.binding_created")

    def _revalidate(self, plan: GoogleBillingPlanV1) -> None:
        snapshot = self._manager._snapshot_for_internal_use()
        if (
            snapshot.generation != plan.inventory_generation
            or snapshot.content_fingerprint != plan.snapshot_fingerprint
        ):
            raise GoogleBillingError("billing.plan_stale")
        try:
            current = _resolve_binding(snapshot, plan.project_ref, plan.billing_ref)
        except GoogleBillingError as error:
            if error.code in {
                "billing.account_mismatch",
                "billing.account_not_found",
                "billing.project_not_found",
                "billing.project_unbound",
                "billing.subject_unbound",
            }:
                raise GoogleBillingError("billing.binding_changed") from None
            raise
        if current != _plan_binding(plan):
            raise GoogleBillingError("billing.binding_changed")

    def _get_binding(self, project_id: str, *, plan_id: str) -> str | None:
        try:
            return self._provider_binding(project_id)
        except Exception as error:
            self._raise_provider_failure(error, plan_id, partial=False)

    def _provider_binding(self, project_id: str) -> str | None:
        value = self.api.get_project_billing_binding(project_id)
        if value is not None and (
            type(value) is not str or not value or len(value.encode("utf-8")) > 512
        ):
            raise GoogleBillingError("billing.provider_response_invalid")
        return value

    def _raise_provider_failure(
        self,
        error: object,
        plan_id: str,
        *,
        partial: bool,
        code: str | None = None,
    ) -> NoReturn:
        if code is None:
            raw_provider_code = getattr(error, "code", None)
            provider_code = raw_provider_code if type(raw_provider_code) is str else ""
            code = (
                "billing.provider_response_invalid"
                if provider_code == "billing.provider_response_invalid"
                else _PROVIDER_CODES.get(provider_code, "billing.provider_failed")
            )
        receipt = None
        if partial:
            receipt = GoogleBillingReceiptV1(
                plan_id=plan_id,
                state="partial",
                attempted=1,
                completed=0,
                failed=1,
                not_attempted=0,
                reason_code=code,
            )
        raise GoogleBillingError(code, partial=receipt) from None

    def _finish(
        self, plan: GoogleBillingPlanV1, reason_code: str
    ) -> GoogleBillingReceiptV1:
        receipt = GoogleBillingReceiptV1(
            plan_id=plan.id,
            state="succeeded",
            attempted=1,
            completed=1,
            failed=0,
            not_attempted=0,
            reason_code=reason_code,
        )
        self._receipts[plan.id] = receipt
        return receipt

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception:
            raise GoogleBillingError("billing.clock_invalid") from None
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise GoogleBillingError("billing.clock_invalid")
        try:
            return value.astimezone(UTC)
        except (OverflowError, ValueError):
            raise GoogleBillingError("billing.clock_invalid") from None

    def __repr__(self) -> str:
        return "GoogleBillingService()"


_Binding = tuple[str, str, int, str, str, str, str, str]


def _resolve_binding(snapshot: Any, project_ref: str, billing_ref: str) -> _Binding:
    try:
        project = snapshot.by_project_ref[project_ref]
    except KeyError:
        raise GoogleBillingError("billing.project_not_found") from None
    try:
        billing = snapshot.by_billing_ref[billing_ref]
    except KeyError:
        raise GoogleBillingError("billing.account_not_found") from None

    project_owner = next(
        (
            account
            for account in snapshot.accounts
            if any(item is project for item in account.projects)
        ),
        None,
    )
    billing_owner = next(
        (
            account
            for account in snapshot.accounts
            if any(item is billing for item in account.billing_accounts)
        ),
        None,
    )
    if project_owner is None or billing_owner is None:
        raise GoogleBillingError("billing.binding_changed")
    if project_owner is not billing_owner:
        raise GoogleBillingError("billing.account_mismatch")
    if type(project_owner.subject_id) is not str or not project_owner.subject_id:
        raise GoogleBillingError("billing.subject_unbound")
    if type(project.project_id) is not str or not project.project_id:
        raise GoogleBillingError("billing.project_unbound")
    if type(billing.billing_account_id) is not str or not billing.billing_account_id:
        raise GoogleBillingError("billing.account_unbound")
    if project.status != "active":
        raise GoogleBillingError("billing.project_blocked")
    return (
        project_owner.ref,
        project_owner.subject_id,
        snapshot.generation,
        snapshot.content_fingerprint,
        project.ref,
        project.project_id,
        billing.ref,
        billing.billing_account_id,
    )


def _plan_binding(plan: GoogleBillingPlanV1) -> _Binding:
    return (
        plan.account_ref,
        plan.subject_id,
        plan.inventory_generation,
        plan.snapshot_fingerprint,
        plan.project_ref,
        plan.project_id,
        plan.billing_ref,
        plan.billing_account_id,
    )


def _plan_digest(
    binding: _Binding,
    *,
    created_at: datetime,
    expires_at: datetime,
    idempotency_key: str,
) -> str:
    payload = {
        "account_ref": binding[0],
        "subject_id": binding[1],
        "inventory_generation": binding[2],
        "snapshot_fingerprint": binding[3],
        "project_ref": binding[4],
        "project_id": binding[5],
        "billing_ref": binding[6],
        "billing_account_id": binding[7],
        "created_at": _wire_time(created_at),
        "expires_at": _wire_time(expires_at),
        "idempotency_key": idempotency_key,
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "sha256:" + sha256(canonical).hexdigest()


def _automatic_idempotency_key(
    generation: int, project_ref: str, billing_ref: str
) -> str:
    canonical = f"{generation}\0{project_ref}\0{billing_ref}".encode("utf-8")
    return "auto-" + sha256(canonical).hexdigest()


def _token(value: object, code: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise GoogleBillingError(code)
    return value


def _generation(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise GoogleBillingError("billing.generation_conflict")
    return value


def _ttl(value: object) -> float:
    if type(value) not in (int, float):
        raise GoogleBillingError("billing.plan_invalid")
    try:
        ttl = float(cast(int | float, value))
    except (OverflowError, ValueError):
        raise GoogleBillingError("billing.plan_invalid") from None
    if not math.isfinite(ttl) or not 0 < ttl <= MAX_BILLING_PLAN_TTL_SECONDS:
        raise GoogleBillingError("billing.plan_invalid")
    return ttl


def _wire_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
