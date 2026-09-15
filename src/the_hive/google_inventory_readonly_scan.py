"""Private scan capability and plan construction for read-only inventory.

This module has no public HTTP or caller-configurable request surface. Its private
discovery leaf constructs only four fixed bodyless read templates for a broker
lease; refresh and access bytes remain inside that broker. The resulting plan can
only be consumed by the closed control authority.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from hashlib import sha256
import json
import math
import re as _re
import secrets
import time
from types import MappingProxyType
from threading import Lock as _Lock
from typing import Final, Mapping
from urllib.parse import urlencode as _urlencode

from . import google_account_inventory as _inventory
from . import google_oauth_authorization as _authorization


_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "inventory.readonly_scan_request_invalid",
        "inventory.readonly_scan_capability_invalid",
        "inventory.readonly_scan_discovery_invalid",
        "inventory.readonly_scan_plan_invalid",
        "inventory.readonly_scan_unavailable",
    }
)
_FINGERPRINT_PREFIX: Final[str] = "sha256:"
_MAX_REFERENCE_BYTES: Final[int] = 192
_MAX_SUBJECT_BYTES: Final[int] = 1024
_MAX_PLAN_ID_BYTES: Final[int] = 192
_MAX_GENERATION: Final[int] = 2**63 - 1
_PLAN_LIFETIME_SECONDS: Final[float] = 300.0
_MAX_DISCOVERY_RECORDS: Final[int] = 4096
_MAX_DISCOVERY_PAGES: Final[int] = 128
_MAX_PAGE_TOKEN_BYTES: Final[int] = 4096
_MAX_SEALED_PLAN_BYTES: Final[int] = _inventory.MAX_INVENTORY_BYTES
_ACCOUNT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "ref",
        "login_email",
        "recovery_email",
        "label",
        "subject_id",
        "billing_accounts",
        "projects",
    }
)
_BILLING_FIELDS: Final[frozenset[str]] = frozenset(
    {"ref", "billing_account_id", "label"}
)
_PROJECT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "ref",
        "billing_account_ref",
        "status",
        "project_id",
        "project_number",
        "key_id",
        "key_uid",
        "project_name",
        "purpose",
        "key_name",
    }
)
_BINDING_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "account_ref",
        "subject_id",
        "inventory_generation",
        "content_fingerprint",
        "oauth_client_fingerprint",
        "scope_fingerprint",
        "plan_id",
        "plan_digest",
        "resulting_content_fingerprint",
        "created_at",
        "expires_at",
    }
)


class GoogleInventoryReadonlyScanError(Exception):
    """Code-only failure at the private read-only scan boundary."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            raise TypeError("invalid inventory readonly scan error code")
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"GoogleInventoryReadonlyScanError({self.code!r})"

    def __str__(self) -> str:
        return self.code


def _fail(code: str) -> None:
    raise GoogleInventoryReadonlyScanError(code) from None


def _is_nonempty_text(value: object, maximum_bytes: int) -> bool:
    if type(value) is not str or not value or "\x00" in value:
        return False
    try:
        return len(value.encode("utf-8")) <= maximum_bytes
    except UnicodeError:
        return False


def _is_fingerprint(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 71
        and value.startswith(_FINGERPRINT_PREFIX)
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _is_timestamp(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        parsed = float(value)
    except (OverflowError, ValueError):
        return False
    return math.isfinite(parsed) and 0.0 <= parsed <= float(_MAX_GENERATION)


def _digest(value: object) -> str:
    try:
        encoded = _canonical_json(value)
    except (TypeError, ValueError):
        _fail("inventory.readonly_scan_plan_invalid")
    return _FINGERPRINT_PREFIX + sha256(encoded).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _copy(value: object, code: str) -> object:
    try:
        return copy.deepcopy(value)
    except Exception:
        _fail(code)


def _is_optional_text(value: object, maximum_bytes: int) -> bool:
    return value is None or _is_nonempty_text(value, maximum_bytes)


def _validate_sealed_target_account(
    value: object, *, account_ref: str, subject_id: str
) -> dict[str, object]:
    """Accept only the secret-free target-account shape produced by discovery."""

    if type(value) is not dict or set(value) != _ACCOUNT_FIELDS:
        _fail("inventory.readonly_scan_plan_invalid")
    if (
        value.get("ref") != account_ref
        or value.get("subject_id") != subject_id
        or not _is_nonempty_text(
            value.get("login_email"), _inventory.MAX_YAML_SCALAR_BYTES
        )
        or not _is_optional_text(
            value.get("recovery_email"), _inventory.MAX_YAML_SCALAR_BYTES
        )
        or not _is_optional_text(value.get("label"), _inventory.MAX_YAML_SCALAR_BYTES)
    ):
        _fail("inventory.readonly_scan_plan_invalid")
    billings = value.get("billing_accounts")
    projects = value.get("projects")
    if (
        type(billings) is not list
        or len(billings) > _inventory.MAX_BILLING_ACCOUNTS_PER_ACCOUNT
        or type(projects) is not list
        or len(projects) > _inventory.MAX_PROJECT_SLOTS_PER_ACCOUNT
    ):
        _fail("inventory.readonly_scan_plan_invalid")
    billing_refs: set[str] = set()
    for billing in billings:
        if type(billing) is not dict or set(billing) != _BILLING_FIELDS:
            _fail("inventory.readonly_scan_plan_invalid")
        ref = billing.get("ref")
        if (
            not _is_nonempty_text(ref, _MAX_REFERENCE_BYTES)
            or ref in billing_refs
            or not _is_optional_text(
                billing.get("billing_account_id"), _inventory.MAX_YAML_SCALAR_BYTES
            )
            or not _is_optional_text(
                billing.get("label"), _inventory.MAX_YAML_SCALAR_BYTES
            )
        ):
            _fail("inventory.readonly_scan_plan_invalid")
        assert type(ref) is str
        billing_refs.add(ref)
    project_refs: set[str] = set()
    for project in projects:
        if type(project) is not dict or set(project) != _PROJECT_FIELDS:
            _fail("inventory.readonly_scan_plan_invalid")
        ref = project.get("ref")
        billing_ref = project.get("billing_account_ref")
        purpose = project.get("purpose")
        status = project.get("status")
        if (
            not _is_nonempty_text(ref, _MAX_REFERENCE_BYTES)
            or ref in project_refs
            or not _is_optional_text(billing_ref, _MAX_REFERENCE_BYTES)
            or (billing_ref is not None and billing_ref not in billing_refs)
            or not _is_nonempty_text(status, _inventory.MAX_YAML_SCALAR_BYTES)
            or status not in _inventory._PROJECT_STATUSES
            or not _is_nonempty_text(purpose, _inventory.MAX_YAML_SCALAR_BYTES)
            or purpose not in _inventory._PROJECT_PURPOSES
            or any(
                not _is_optional_text(
                    project.get(field), _inventory.MAX_YAML_SCALAR_BYTES
                )
                for field in (
                    "project_id",
                    "project_number",
                    "key_id",
                    "key_uid",
                    "project_name",
                    "key_name",
                )
            )
        ):
            _fail("inventory.readonly_scan_plan_invalid")
        assert type(ref) is str
        project_refs.add(ref)
    return value


def _validated_sealed_plan_payload(payload: object) -> dict[str, object]:
    """Parse the bounded canonical private plan bytes without accepting aliases."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > _MAX_SEALED_PLAN_BYTES
    ):
        _fail("inventory.readonly_scan_plan_invalid")
    assert type(payload) is bytes
    try:
        value = json.loads(payload.decode("utf-8"))
        if _canonical_json(value) != payload:
            _fail("inventory.readonly_scan_plan_invalid")
    except GoogleInventoryReadonlyScanError:
        raise
    except (UnicodeError, TypeError, ValueError, json.JSONDecodeError, RecursionError):
        _fail("inventory.readonly_scan_plan_invalid")
    if type(value) is not dict or set(value) != {
        "binding",
        "discovery_fingerprint",
        "target_account",
    }:
        _fail("inventory.readonly_scan_plan_invalid")
    binding = value["binding"]
    if type(binding) is not dict or set(binding) != _BINDING_FIELDS - {"plan_digest"}:
        _fail("inventory.readonly_scan_plan_invalid")
    account_ref = binding.get("account_ref")
    subject_id = binding.get("subject_id")
    generation = binding.get("inventory_generation")
    plan_id = binding.get("plan_id")
    created_at = binding.get("created_at")
    expires_at = binding.get("expires_at")
    if not (
        _is_nonempty_text(account_ref, _MAX_REFERENCE_BYTES)
        and _is_nonempty_text(subject_id, _MAX_SUBJECT_BYTES)
        and type(generation) is int
        and 1 <= generation <= _MAX_GENERATION
        and _is_nonempty_text(plan_id, _MAX_PLAN_ID_BYTES)
        and type(created_at) is float
        and type(expires_at) is float
        and _is_timestamp(created_at)
        and _is_timestamp(expires_at)
        and expires_at == created_at + _PLAN_LIFETIME_SECONDS
        and all(
            _is_fingerprint(binding.get(field))
            for field in (
                "content_fingerprint",
                "oauth_client_fingerprint",
                "scope_fingerprint",
                "resulting_content_fingerprint",
            )
        )
        and _is_fingerprint(value["discovery_fingerprint"])
    ):
        _fail("inventory.readonly_scan_plan_invalid")
    assert type(account_ref) is str
    assert type(subject_id) is str
    _validate_sealed_target_account(
        value["target_account"], account_ref=account_ref, subject_id=subject_id
    )
    return value


class _GoogleInventoryReadonlyScanCapabilityV1:
    """A broker-owned one-use capability with no token-bearing field."""

    __slots__ = (
        "_account_ref",
        "_broker",
        "_consumed",
        "_content_fingerprint",
        "_discovery_claimed",
        "_discovery_lock",
        "_inventory_generation",
        "_oauth_client_fingerprint",
        "_scope_fingerprint",
        "_subject_id",
    )

    def __init__(
        self,
        broker: object,
        *,
        account_ref: str,
        subject_id: str,
        inventory_generation: int,
        content_fingerprint: str,
        oauth_client_fingerprint: str,
        scope_fingerprint: str,
    ) -> None:
        self._broker = broker
        self._account_ref = account_ref
        self._subject_id = subject_id
        self._inventory_generation = inventory_generation
        self._content_fingerprint = content_fingerprint
        self._oauth_client_fingerprint = oauth_client_fingerprint
        self._scope_fingerprint = scope_fingerprint
        self._consumed = False
        self._discovery_claimed = False
        self._discovery_lock = _Lock()

    def __repr__(self) -> str:
        return "_GoogleInventoryReadonlyScanCapabilityV1(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> object:
        raise TypeError("scan capability is not serializable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("scan capability is not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("scan capability is not serializable")

    def _consume_for_discovery(
        self,
        broker: object,
        *,
        account_ref: str,
        subject_id: str,
        inventory_generation: int,
        content_fingerprint: str,
        oauth_client_fingerprint: str,
        scope_fingerprint: str,
    ) -> None:
        if (
            self._consumed
            or self._broker is not broker
            or self._account_ref != account_ref
            or self._subject_id != subject_id
            or self._inventory_generation != inventory_generation
            or self._content_fingerprint != content_fingerprint
            or self._oauth_client_fingerprint != oauth_client_fingerprint
            or self._scope_fingerprint != scope_fingerprint
        ):
            _fail("inventory.readonly_scan_capability_invalid")
        self._consumed = True

    def _claim_for_fixed_discovery(self, broker: object) -> None:
        """Permit one fixed leaf invocation after the control binding was consumed."""

        with self._discovery_lock:
            if (
                self._broker is not broker
                or self._consumed is not True
                or self._discovery_claimed
            ):
                _fail("inventory.readonly_scan_capability_invalid")
            self._discovery_claimed = True


def _issue_scan_capability_for_broker(
    broker: object,
    *,
    account_ref: object,
    subject_id: object,
    inventory_generation: object,
    content_fingerprint: object,
    oauth_client_fingerprint: object,
    scope_fingerprint: object,
) -> _GoogleInventoryReadonlyScanCapabilityV1:
    """Private broker factory; its capability never carries refresh bytes."""

    if not (
        _is_nonempty_text(account_ref, _MAX_REFERENCE_BYTES)
        and _is_nonempty_text(subject_id, _MAX_SUBJECT_BYTES)
        and type(inventory_generation) is int
        and 1 <= inventory_generation <= _MAX_GENERATION
        and _is_fingerprint(content_fingerprint)
        and _is_fingerprint(oauth_client_fingerprint)
        and _is_fingerprint(scope_fingerprint)
    ):
        _fail("inventory.readonly_scan_capability_invalid")
    assert type(account_ref) is str
    assert type(subject_id) is str
    assert type(inventory_generation) is int
    assert type(content_fingerprint) is str
    assert type(oauth_client_fingerprint) is str
    assert type(scope_fingerprint) is str
    return _GoogleInventoryReadonlyScanCapabilityV1(
        broker,
        account_ref=account_ref,
        subject_id=subject_id,
        inventory_generation=inventory_generation,
        content_fingerprint=content_fingerprint,
        oauth_client_fingerprint=oauth_client_fingerprint,
        scope_fingerprint=scope_fingerprint,
    )


class _GoogleInventoryReadonlyDiscoveryPortV1:
    """Private fixed-semantic discovery port: its only call takes a capability."""

    __slots__ = ()

    def discover_readonly_inventory(self, capability: object) -> object:
        raise NotImplementedError


def _fixed_discovery_page_request(
    operation: object, *, project_number: object = None, page_token: object = None
) -> Mapping[str, object]:
    """Broker-internal templates; callers cannot supply URL, headers or a body."""

    operations = _authorization.GoogleOAuthOperationV1
    templates = {
        operations.PROJECTS_SEARCH: (
            "https://cloudresourcemanager.googleapis.com/v3/projects:search",
            False,
        ),
        operations.BILLING_ACCOUNTS_LIST: (
            "https://cloudbilling.googleapis.com/v1/billingAccounts",
            False,
        ),
        operations.SERVICES_LIST: (
            "https://serviceusage.googleapis.com/v1/projects/{project}/services",
            True,
        ),
        operations.KEYS_LIST: (
            "https://apikeys.googleapis.com/v2/projects/{project}/locations/global/keys",
            True,
        ),
    }
    if type(operation) is not operations or operation not in templates:
        _fail("inventory.readonly_scan_discovery_invalid")
    template, needs_project = templates[operation]
    if needs_project:
        if (
            type(project_number) is not str
            or not 1 <= len(project_number) <= 20
            or project_number[0] == "0"
            or any(character not in "0123456789" for character in project_number)
        ):
            _fail("inventory.readonly_scan_discovery_invalid")
    elif project_number is not None:
        _fail("inventory.readonly_scan_discovery_invalid")
    if page_token is not None and not _is_nonempty_text(
        page_token, _MAX_PAGE_TOKEN_BYTES
    ):
        _fail("inventory.readonly_scan_discovery_invalid")
    query: dict[str, str] = {}
    if operation is operations.SERVICES_LIST:
        query["filter"] = "state:ENABLED"
    if page_token is not None:
        assert type(page_token) is str
        query["pageToken"] = page_token
    url = template.format(project=project_number)
    if query:
        url += "?" + _urlencode(query)
    return MappingProxyType({"method": "GET", "url": url, "body": None})


def _normalise_fixed_discovery_page(
    operation: object, page: object, *, project_number: object = None
) -> tuple[tuple[dict[str, object], ...], str | None]:
    """Discard provider payload fields after selecting the fixed metadata schema."""

    _fixed_discovery_page_request(operation, project_number=project_number)
    operations = _authorization.GoogleOAuthOperationV1
    collection = {
        operations.PROJECTS_SEARCH: "projects",
        operations.BILLING_ACCOUNTS_LIST: "billingAccounts",
        operations.SERVICES_LIST: "services",
        operations.KEYS_LIST: "keys",
    }[operation]
    if type(page) is not dict or set(page) - {collection, "nextPageToken"}:
        _fail("inventory.readonly_scan_discovery_invalid")
    raw_rows = page.get(collection, [])
    cursor = page.get("nextPageToken")
    if cursor == "":
        cursor = None
    if (
        type(raw_rows) is not list
        or len(raw_rows) > _MAX_DISCOVERY_RECORDS
        or (cursor is not None and not _is_nonempty_text(cursor, _MAX_PAGE_TOKEN_BYTES))
    ):
        _fail("inventory.readonly_scan_discovery_invalid")
    rows: list[dict[str, object]] = []
    for raw in raw_rows:
        if type(raw) is not dict or set(raw) & {
            "keyString",
            "access_token",
            "refresh_token",
            "Authorization",
            "secret",
        }:
            _fail("inventory.readonly_scan_discovery_invalid")
        name = raw.get("name")
        if not _is_nonempty_text(name, _MAX_SUBJECT_BYTES):
            _fail("inventory.readonly_scan_discovery_invalid")
        assert type(name) is str
        label = raw.get("displayName")
        if label == "":
            label = None
        if not _is_optional_text(label, _inventory.MAX_YAML_SCALAR_BYTES):
            _fail("inventory.readonly_scan_discovery_invalid")
        if operation is operations.PROJECTS_SEARCH:
            project_id = raw.get("projectId")
            state = raw.get("state")
            if (
                not name.startswith("projects/")
                or not _is_nonempty_text(project_id, _MAX_SUBJECT_BYTES)
                or type(state) is not str
                or state not in {"ACTIVE", "DELETE_REQUESTED"}
            ):
                _fail("inventory.readonly_scan_discovery_invalid")
            number = name[len("projects/") :]
            _fixed_discovery_page_request(
                operations.SERVICES_LIST, project_number=number
            )
            rows.append(
                {
                    "project_id": project_id,
                    "project_number": number,
                    "state": state,
                    "project_name": label,
                }
            )
        elif operation is operations.BILLING_ACCOUNTS_LIST:
            prefix = "billingAccounts/"
            if (
                not name.startswith(prefix)
                or _re.fullmatch(r"[A-Za-z0-9-]+", name[len(prefix) :]) is None
            ):
                _fail("inventory.readonly_scan_discovery_invalid")
            rows.append({"billing_account_id": name[len(prefix) :], "label": label})
        elif operation is operations.SERVICES_LIST:
            prefix = f"projects/{project_number}/services/"
            if (
                not name.startswith(prefix)
                or _re.fullmatch(r"[A-Za-z0-9.-]+", name[len(prefix) :]) is None
                or raw.get("state") != "ENABLED"
            ):
                _fail("inventory.readonly_scan_discovery_invalid")
            rows.append({"service_name": name})
        else:
            prefix = f"projects/{project_number}/locations/global/keys/"
            uid = raw.get("uid")
            if (
                not name.startswith(prefix)
                or _re.fullmatch(r"[A-Za-z0-9_-]+", name[len(prefix) :]) is None
                or not _is_optional_text(uid, _MAX_SUBJECT_BYTES)
            ):
                _fail("inventory.readonly_scan_discovery_invalid")
            rows.append({"key_id": name, "key_uid": uid, "key_name": label})
    assert cursor is None or type(cursor) is str
    return tuple(rows), cursor


def _collect_fixed_discovery_pages(
    lease: object, operation: object, *, project_number: object = None
) -> tuple[dict[str, object], ...]:
    """One attempt per server page; the lease retains all bearer material."""

    _fixed_discovery_page_request(operation, project_number=project_number)
    operations = _authorization.GoogleOAuthOperationV1
    identifiers = {
        operations.PROJECTS_SEARCH: ("project_id", "project_number"),
        operations.BILLING_ACCOUNTS_LIST: ("billing_account_id",),
        operations.SERVICES_LIST: ("service_name",),
        operations.KEYS_LIST: ("key_id",),
    }[operation]
    seen_identifiers: set[tuple[str, object]] = set()
    seen_cursors: set[str] = set()
    cursor: str | None = None
    records: list[dict[str, object]] = []
    page: object = None
    try:
        for _ in range(_MAX_DISCOVERY_PAGES):
            page = lease._read_fixed_page(
                operation, project_number=project_number, page_token=cursor
            )
            rows, next_cursor = _normalise_fixed_discovery_page(
                operation, page, project_number=project_number
            )
            page = None
            if len(records) + len(rows) > _MAX_DISCOVERY_RECORDS:
                _fail("inventory.readonly_scan_discovery_invalid")
            for row in rows:
                for field_name in identifiers:
                    identity = (field_name, row[field_name])
                    if identity in seen_identifiers:
                        _fail("inventory.readonly_scan_discovery_invalid")
                    seen_identifiers.add(identity)
                records.append(row)
            if next_cursor is None:
                return tuple(records)
            if next_cursor in seen_cursors:
                _fail("inventory.readonly_scan_discovery_invalid")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        _fail("inventory.readonly_scan_discovery_invalid")
    except GoogleInventoryReadonlyScanError:
        raise
    except Exception:
        _fail("inventory.readonly_scan_unavailable")
    finally:
        page = None
        cursor = None


def _project_fixed_discovery_target(
    source: object,
    *,
    account_ref: str,
    subject_id: str,
    projects: tuple[dict[str, object], ...],
    billings: tuple[dict[str, object], ...],
    keys: tuple[dict[str, object], ...],
) -> dict[str, object]:
    """Refresh metadata only for existing identities; never allocate or infer links."""

    target = _validate_sealed_target_account(
        _copy(source, "inventory.readonly_scan_discovery_invalid"),
        account_ref=account_ref,
        subject_id=subject_id,
    )
    billing_by_id = {row["billing_account_id"]: row for row in billings}
    project_by_id = {row["project_id"]: row for row in projects}
    project_by_number = {row["project_number"]: row for row in projects}
    key_by_name = {row["key_id"]: row for row in keys}
    for billing in target["billing_accounts"]:
        discovered = billing_by_id.get(billing["billing_account_id"])
        if discovered is not None and discovered["label"] is not None:
            billing["label"] = discovered["label"]
    for project in target["projects"]:
        discovered = project_by_id.get(project["project_id"])
        if discovered is None:
            discovered = project_by_number.get(project["project_number"])
        if discovered is None:
            continue
        for field_name in ("project_id", "project_number"):
            if (
                project[field_name] is not None
                and project[field_name] != discovered[field_name]
            ):
                _fail("inventory.readonly_scan_discovery_invalid")
            project[field_name] = discovered[field_name]
        if discovered["project_name"] is not None:
            project["project_name"] = discovered["project_name"]
        existing_key = project["key_id"]
        if existing_key is None:
            continue
        prefix = f"projects/{discovered['project_number']}/locations/global/keys/"
        if "/" in existing_key and not existing_key.startswith(prefix):
            _fail("inventory.readonly_scan_discovery_invalid")
        full_key_name = (
            existing_key if existing_key.startswith(prefix) else prefix + existing_key
        )
        key = key_by_name.get(full_key_name)
        if key is None:
            continue
        if (
            project["key_uid"] is not None
            and key["key_uid"] is not None
            and project["key_uid"] != key["key_uid"]
        ):
            _fail("inventory.readonly_scan_discovery_invalid")
        for field_name in ("key_uid", "key_name"):
            if key[field_name] is not None:
                project[field_name] = key[field_name]
    return _validate_sealed_target_account(
        target, account_ref=account_ref, subject_id=subject_id
    )


class _FixedGoogleInventoryReadonlyDiscoveryV1(_GoogleInventoryReadonlyDiscoveryPortV1):
    """Private four-operation leaf; a production broker lease is still required.

    The broker's `_open_readonly_discovery_lease(capability)` must fresh-check the
    authorization receipt, account, subject, durable generation/content and
    client/scope fingerprints before its single fixed refresh exchange. Its lease
    retains refresh/access bytes and provides only `_target_account_for_discovery`,
    `_read_fixed_page(operation, *, project_number, page_token)` and `_close`.
    `_read_fixed_page` must revalidate this module's fixed request template and
    must not retry, redirect, refresh again or expose credentials. The broker must
    zero credential buffers on failed opens; the lease's `_close` must zero its
    retained buffers in a finally block. No production transport is constructed
    here.
    """

    __slots__ = ("_broker",)

    def __init__(self, broker: object) -> None:
        if not callable(getattr(broker, "_open_readonly_discovery_lease", None)):
            _fail("inventory.readonly_scan_unavailable")
        self._broker = broker

    def __repr__(self) -> str:
        return "_FixedGoogleInventoryReadonlyDiscoveryV1(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> object:
        raise TypeError("fixed inventory discovery is not serializable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("fixed inventory discovery is not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("fixed inventory discovery is not serializable")

    def discover_readonly_inventory(self, capability: object) -> object:
        if type(capability) is not _GoogleInventoryReadonlyScanCapabilityV1:
            _fail("inventory.readonly_scan_capability_invalid")
        lease: object = None
        try:
            capability._claim_for_fixed_discovery(self._broker)
            lease = self._broker._open_readonly_discovery_lease(capability)
            if not all(
                callable(getattr(lease, method, None))
                for method in (
                    "_read_fixed_page",
                    "_target_account_for_discovery",
                    "_close",
                )
            ):
                _fail("inventory.readonly_scan_unavailable")
            source_target = _validate_sealed_target_account(
                lease._target_account_for_discovery(),
                account_ref=capability._account_ref,
                subject_id=capability._subject_id,
            )
            operations = _authorization.GoogleOAuthOperationV1
            projects = _collect_fixed_discovery_pages(lease, operations.PROJECTS_SEARCH)
            billings = _collect_fixed_discovery_pages(
                lease, operations.BILLING_ACCOUNTS_LIST
            )
            services: list[dict[str, object]] = []
            keys: list[dict[str, object]] = []
            for project in projects:
                services.extend(
                    _collect_fixed_discovery_pages(
                        lease,
                        operations.SERVICES_LIST,
                        project_number=project["project_number"],
                    )
                )
                if len(services) > _MAX_DISCOVERY_RECORDS:
                    _fail("inventory.readonly_scan_discovery_invalid")
                keys.extend(
                    _collect_fixed_discovery_pages(
                        lease,
                        operations.KEYS_LIST,
                        project_number=project["project_number"],
                    )
                )
                if len(keys) > _MAX_DISCOVERY_RECORDS:
                    _fail("inventory.readonly_scan_discovery_invalid")
            target = _project_fixed_discovery_target(
                source_target,
                account_ref=capability._account_ref,
                subject_id=capability._subject_id,
                projects=projects,
                billings=billings,
                keys=tuple(keys),
            )
            return _GoogleInventoryReadonlyDiscoveryResultV1._issue_for_port(
                self,
                projects=tuple(
                    {"project_id": row["project_id"], "state": row["state"]}
                    for row in projects
                ),
                billings=tuple(
                    {"billing_account_id": row["billing_account_id"]}
                    for row in billings
                ),
                services=tuple(services),
                keys=tuple({"key_id": row["key_id"]} for row in keys),
                canonical_target_account=target,
            )
        except GoogleInventoryReadonlyScanError:
            raise
        except Exception:
            _fail("inventory.readonly_scan_unavailable")
        finally:
            if lease is not None:
                try:
                    lease._close()
                except Exception:
                    _fail("inventory.readonly_scan_unavailable")


def _normalise_records(
    value: object,
    *,
    fields: tuple[str, ...],
) -> tuple[tuple[str, ...], ...]:
    if type(value) is not tuple or len(value) > _MAX_DISCOVERY_RECORDS:
        _fail("inventory.readonly_scan_discovery_invalid")
    records: list[tuple[str, ...]] = []
    expected = frozenset(fields)
    for item in value:
        if type(item) is not dict or set(item) != expected:
            _fail("inventory.readonly_scan_discovery_invalid")
        row: list[str] = []
        for field_name in fields:
            cell = item[field_name]
            if not _is_nonempty_text(cell, _MAX_SUBJECT_BYTES):
                _fail("inventory.readonly_scan_discovery_invalid")
            assert type(cell) is str
            row.append(cell)
        records.append(tuple(row))
    ordered = tuple(sorted(records))
    if len(set(ordered)) != len(ordered):
        _fail("inventory.readonly_scan_discovery_invalid")
    return ordered


class _GoogleInventoryReadonlyDiscoveryResultV1:
    """A discovery-port-issued result that is consumable once by its issuer."""

    __slots__ = (
        "_billings",
        "_canonical_target_account",
        "_consumed",
        "_issuer",
        "_keys",
        "_projects",
        "_services",
    )

    def __init__(
        self,
        issuer: object,
        *,
        projects: tuple[tuple[str, ...], ...],
        billings: tuple[tuple[str, ...], ...],
        services: tuple[tuple[str, ...], ...],
        keys: tuple[tuple[str, ...], ...],
        canonical_target_account: object,
    ) -> None:
        self._issuer = issuer
        self._projects = projects
        self._billings = billings
        self._services = services
        self._keys = keys
        self._canonical_target_account = _copy(
            canonical_target_account, "inventory.readonly_scan_discovery_invalid"
        )
        self._consumed = False

    @classmethod
    def _issue_for_port(
        cls,
        issuer: object,
        *,
        projects: object,
        billings: object,
        services: object,
        keys: object,
        canonical_target_account: object,
    ) -> _GoogleInventoryReadonlyDiscoveryResultV1:
        return cls(
            issuer,
            projects=_normalise_records(projects, fields=("project_id", "state")),
            billings=_normalise_records(billings, fields=("billing_account_id",)),
            services=_normalise_records(services, fields=("service_name",)),
            keys=_normalise_records(keys, fields=("key_id",)),
            canonical_target_account=canonical_target_account,
        )

    def __repr__(self) -> str:
        return "_GoogleInventoryReadonlyDiscoveryResultV1(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> object:
        raise TypeError("discovery result is not serializable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("discovery result is not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("discovery result is not serializable")

    def _consume_for_issuer(
        self, issuer: object
    ) -> tuple[object, str, tuple[int, int, int, int]]:
        if self._consumed or self._issuer is not issuer:
            _fail("inventory.readonly_scan_discovery_invalid")
        self._consumed = True
        fingerprint = _digest(
            {
                "projects": self._projects,
                "billings": self._billings,
                "services": self._services,
                "keys": self._keys,
            }
        )
        return (
            _copy(
                self._canonical_target_account,
                "inventory.readonly_scan_discovery_invalid",
            ),
            fingerprint,
            (
                len(self._projects),
                len(self._billings),
                len(self._services),
                len(self._keys),
            ),
        )


def _document_for_validation(document: object) -> dict[str, object]:
    """Copy a canonical in-memory document without relaxing its schema.

    Production documents originate in the strict YAML loader.  The exact integer
    normalization is retained solely for closed in-memory component tests and is
    written back only when such a test document is transformed.
    """

    copied = _copy(document, "inventory.readonly_scan_plan_invalid")
    if type(copied) is not dict:
        _fail("inventory.readonly_scan_plan_invalid")
    version = copied.get("schema_version")
    if type(version) is int and version == 3:
        copied["schema_version"] = _inventory._YamlIntegerLiteral(str(version))
    generation = copied.get("authority_generation")
    if type(generation) is int:
        copied["authority_generation"] = _inventory._YamlIntegerLiteral(str(generation))
    return copied


def _account_index(document: dict[str, object], account_ref: str) -> int:
    accounts = document.get("google_accounts")
    if type(accounts) is not list:
        _fail("inventory.readonly_scan_plan_invalid")
    indices = [
        index
        for index, account in enumerate(accounts)
        if type(account) is dict and account.get("ref") == account_ref
    ]
    if len(indices) != 1:
        _fail("inventory.readonly_scan_plan_invalid")
    return indices[0]


def _complete_target_account(
    source_account: object,
    target_account: object,
    *,
    account_ref: str,
    subject_id: str,
) -> dict[str, object]:
    if type(source_account) is not dict or type(target_account) is not dict:
        _fail("inventory.readonly_scan_plan_invalid")
    if set(target_account) != _ACCOUNT_FIELDS:
        _fail("inventory.readonly_scan_plan_invalid")
    if (
        target_account.get("ref") != account_ref
        or target_account.get("subject_id") != subject_id
        or source_account.get("login_email") != target_account.get("login_email")
    ):
        _fail("inventory.readonly_scan_plan_invalid")
    auth = source_account.get("auth")
    source_projects = source_account.get("projects")
    target_projects = target_account.get("projects")
    if (
        (auth is not None and type(auth) is not dict)
        or type(source_projects) is not list
        or type(target_projects) is not list
    ):
        _fail("inventory.readonly_scan_plan_invalid")
    secrets: dict[str, object] = {}
    for project in source_projects:
        if type(project) is not dict or type(project.get("ref")) is not str:
            _fail("inventory.readonly_scan_plan_invalid")
        project_ref = project["ref"]
        if project_ref in secrets:
            _fail("inventory.readonly_scan_plan_invalid")
        secrets[project_ref] = project.get("secret")
    completed_projects: list[dict[str, object]] = []
    seen_projects: set[str] = set()
    for project in target_projects:
        if type(project) is not dict or set(project) != _PROJECT_FIELDS:
            _fail("inventory.readonly_scan_plan_invalid")
        project_ref = project.get("ref")
        if (
            type(project_ref) is not str
            or project_ref not in secrets
            or project_ref in seen_projects
        ):
            _fail("inventory.readonly_scan_plan_invalid")
        seen_projects.add(project_ref)
        completed = _copy(project, "inventory.readonly_scan_plan_invalid")
        assert type(completed) is dict
        completed["secret"] = _copy(
            secrets[project_ref], "inventory.readonly_scan_plan_invalid"
        )
        completed_projects.append(completed)
    if seen_projects != set(secrets):
        _fail("inventory.readonly_scan_plan_invalid")
    billings = target_account.get("billing_accounts")
    if type(billings) is not list or any(
        type(billing) is not dict or set(billing) != _BILLING_FIELDS
        for billing in billings
    ):
        _fail("inventory.readonly_scan_plan_invalid")
    completed_account = _copy(target_account, "inventory.readonly_scan_plan_invalid")
    assert type(completed_account) is dict
    completed_account["auth"] = _copy(auth, "inventory.readonly_scan_plan_invalid")
    completed_account["projects"] = completed_projects
    return completed_account


def _candidate_document(
    document: object,
    target_account: object,
    *,
    account_ref: str,
    subject_id: str,
) -> tuple[dict[str, object], str]:
    candidate = _document_for_validation(document)
    try:
        parsed_source = _inventory._build_document(candidate)
    except Exception:
        _fail("inventory.readonly_scan_plan_invalid")
    source_index = _account_index(candidate, account_ref)
    accounts = candidate["google_accounts"]
    assert type(accounts) is list
    source_account = accounts[source_index]
    if (
        type(source_account) is not dict
        or source_account.get("subject_id") != subject_id
    ):
        _fail("inventory.readonly_scan_plan_invalid")
    completed = _complete_target_account(
        source_account,
        target_account,
        account_ref=account_ref,
        subject_id=subject_id,
    )
    accounts[source_index] = completed
    try:
        parsed_candidate = _inventory._build_document(candidate)
    except Exception:
        _fail("inventory.readonly_scan_plan_invalid")
    if parsed_source.by_ref[account_ref].ref != account_ref:
        _fail("inventory.readonly_scan_plan_invalid")
    return candidate, parsed_candidate.content_fingerprint


def _verify_current_document_binding(
    document: object,
    *,
    account_ref: str,
    subject_id: str,
    inventory_generation: int,
    content_fingerprint: str,
) -> None:
    """Fail before capability issuance when the receipt-attested document drifted."""

    current = _document_for_validation(document)
    try:
        parsed = _inventory._build_document(current)
    except Exception:
        _fail("inventory.readonly_scan_request_invalid")
    if (
        type(inventory_generation) is not int
        or parsed.authority_generation != inventory_generation
        or parsed.content_fingerprint != content_fingerprint
    ):
        _fail("inventory.readonly_scan_request_invalid")
    account_index = _account_index(current, account_ref)
    accounts = current["google_accounts"]
    assert type(accounts) is list
    account = accounts[account_index]
    if type(account) is not dict or account.get("subject_id") != subject_id:
        _fail("inventory.readonly_scan_request_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class _GoogleInventoryReadonlyPlanV1:
    _account_ref: str = field(repr=False)
    _subject_id: str = field(repr=False)
    _inventory_generation: int
    _content_fingerprint: str
    _oauth_client_fingerprint: str
    _scope_fingerprint: str
    _plan_id: str = field(repr=False)
    _plan_digest: str
    _resulting_content_fingerprint: str
    _created_at: float
    _expires_at: float
    _sealed_payload: bytes = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "_GoogleInventoryReadonlyPlanV1(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> object:
        raise TypeError("inventory plan is not serializable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("inventory plan is not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("inventory plan is not serializable")

    def _binding_for_authority(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "account_ref": self._account_ref,
                "subject_id": self._subject_id,
                "inventory_generation": self._inventory_generation,
                "content_fingerprint": self._content_fingerprint,
                "oauth_client_fingerprint": self._oauth_client_fingerprint,
                "scope_fingerprint": self._scope_fingerprint,
                "plan_id": self._plan_id,
                "plan_digest": self._plan_digest,
                "resulting_content_fingerprint": self._resulting_content_fingerprint,
                "created_at": self._created_at,
                "expires_at": self._expires_at,
            }
        )

    def _sealed_for_authority(self) -> dict[str, object]:
        value = _validated_sealed_plan_payload(self._sealed_payload)
        sealed_binding = value["binding"]
        assert type(sealed_binding) is dict
        expected = {
            "account_ref": self._account_ref,
            "subject_id": self._subject_id,
            "inventory_generation": self._inventory_generation,
            "content_fingerprint": self._content_fingerprint,
            "oauth_client_fingerprint": self._oauth_client_fingerprint,
            "scope_fingerprint": self._scope_fingerprint,
            "plan_id": self._plan_id,
            "resulting_content_fingerprint": self._resulting_content_fingerprint,
            "created_at": self._created_at,
            "expires_at": self._expires_at,
        }
        if sealed_binding != expected or _digest(value) != self._plan_digest:
            _fail("inventory.readonly_scan_plan_invalid")
        return value

    def _verify_for_authority(self) -> Mapping[str, object]:
        """Recheck sealed plan bytes before the authority's CAS/apply path."""

        self._sealed_for_authority()
        return self._binding_for_authority()

    def _export_sealed_for_authority(self) -> bytes:
        """Return only verified, secret-free plan bytes to the closed authority."""

        self._sealed_for_authority()
        return self._sealed_payload

    def _transform_for_authority(self, document: dict[str, object]) -> None:
        sealed = self._sealed_for_authority()
        candidate, resulting_fingerprint = _candidate_document(
            document,
            sealed["target_account"],
            account_ref=self._account_ref,
            subject_id=self._subject_id,
        )
        if resulting_fingerprint != self._resulting_content_fingerprint:
            _fail("inventory.readonly_scan_plan_invalid")
        # The strict parser has validated these literals; Store owns ordinary
        # canonical integers and advances authority_generation on commit.
        for field_name in ("schema_version", "authority_generation"):
            literal = candidate[field_name]
            assert type(literal) is _inventory._YamlIntegerLiteral
            candidate[field_name] = int(literal.value)
        document.clear()
        document.update(candidate)


def _rehydrate_sealed_plan_for_authority(
    payload: bytes,
) -> _GoogleInventoryReadonlyPlanV1:
    """Restore a closed-authority plan after validating its canonical bytes."""

    value = _validated_sealed_plan_payload(payload)
    binding = value["binding"]
    assert type(binding) is dict
    account_ref = binding["account_ref"]
    subject_id = binding["subject_id"]
    generation = binding["inventory_generation"]
    content_fingerprint = binding["content_fingerprint"]
    oauth_client_fingerprint = binding["oauth_client_fingerprint"]
    scope_fingerprint = binding["scope_fingerprint"]
    plan_id = binding["plan_id"]
    resulting_content_fingerprint = binding["resulting_content_fingerprint"]
    created_at = binding["created_at"]
    expires_at = binding["expires_at"]
    assert type(account_ref) is str
    assert type(subject_id) is str
    assert type(generation) is int
    assert type(content_fingerprint) is str
    assert type(oauth_client_fingerprint) is str
    assert type(scope_fingerprint) is str
    assert type(plan_id) is str
    assert type(resulting_content_fingerprint) is str
    assert type(created_at) is float
    assert type(expires_at) is float
    plan = _GoogleInventoryReadonlyPlanV1(
        _account_ref=account_ref,
        _subject_id=subject_id,
        _inventory_generation=generation,
        _content_fingerprint=content_fingerprint,
        _oauth_client_fingerprint=oauth_client_fingerprint,
        _scope_fingerprint=scope_fingerprint,
        _plan_id=plan_id,
        _plan_digest=_digest(value),
        _resulting_content_fingerprint=resulting_content_fingerprint,
        _created_at=created_at,
        _expires_at=expires_at,
        _sealed_payload=payload,
    )
    plan._verify_for_authority()
    return plan


class _GoogleInventoryReadonlyScanResultV1:
    """Private plan handoff with a separately safe, immutable projection."""

    __slots__ = ("_plan", "_public_projection")

    def __init__(
        self,
        plan: _GoogleInventoryReadonlyPlanV1,
        public_projection: Mapping[str, object],
    ) -> None:
        self._plan = plan
        self._public_projection = MappingProxyType(dict(public_projection))

    def __repr__(self) -> str:
        return "_GoogleInventoryReadonlyScanResultV1(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> object:
        raise TypeError("inventory scan result is not serializable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("inventory scan result is not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("inventory scan result is not serializable")


class _VerifiedScanAuthorizationBindingV1:
    """One-use authority attestation for exactly one private inventory scan."""

    __slots__ = (
        "_account_ref",
        "_component",
        "_content_fingerprint",
        "_consumed",
        "_inventory_generation",
        "_oauth_client_fingerprint",
        "_receipt_operation_digest",
        "_receipt_binding_fingerprint",
        "_scope_fingerprint",
        "_subject_id",
    )

    def __init__(
        self,
        component: object,
        *,
        account_ref: str,
        subject_id: str,
        inventory_generation: int,
        content_fingerprint: str,
        oauth_client_fingerprint: str,
        scope_fingerprint: str,
        receipt_operation_digest: str,
        receipt_binding_fingerprint: str,
    ) -> None:
        self._component = component
        self._account_ref = account_ref
        self._subject_id = subject_id
        self._inventory_generation = inventory_generation
        self._content_fingerprint = content_fingerprint
        self._oauth_client_fingerprint = oauth_client_fingerprint
        self._scope_fingerprint = scope_fingerprint
        self._receipt_operation_digest = receipt_operation_digest
        self._receipt_binding_fingerprint = receipt_binding_fingerprint
        self._consumed = False

    def __repr__(self) -> str:
        return "_VerifiedScanAuthorizationBindingV1(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> object:
        raise TypeError("verified scan binding is not serializable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("verified scan binding is not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("verified scan binding is not serializable")

    def _consume_for_component(
        self, component: object
    ) -> tuple[str, str, int, str, str, str, str, str]:
        if self._consumed or self._component is not component:
            _fail("inventory.readonly_scan_request_invalid")
        self._consumed = True
        values = (
            self._account_ref,
            self._subject_id,
            self._inventory_generation,
            self._content_fingerprint,
            self._oauth_client_fingerprint,
            self._scope_fingerprint,
            self._receipt_operation_digest,
            self._receipt_binding_fingerprint,
        )
        self._receipt_operation_digest = ""
        self._receipt_binding_fingerprint = ""
        return values


class _GoogleInventoryReadonlyScanComponentV1:
    """Closed adapter from a receipt-attested binding to fixed discovery."""

    __slots__ = ("_broker", "_clock", "_discovery", "_owner", "_plan_id_factory")

    def __init__(
        self,
        broker: object,
        discovery: _GoogleInventoryReadonlyDiscoveryPortV1,
        *,
        owner: object,
        clock: object,
        plan_id_factory: object,
    ) -> None:
        if not callable(clock) or not callable(plan_id_factory):
            _fail("inventory.readonly_scan_unavailable")
        self._broker = broker
        self._discovery = discovery
        self._owner = owner
        self._clock = clock
        self._plan_id_factory = plan_id_factory

    def __repr__(self) -> str:
        return "_GoogleInventoryReadonlyScanComponentV1(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> object:
        raise TypeError("private inventory scan component is not serializable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("private inventory scan component is not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private inventory scan component is not serializable")

    def _new_verified_binding_for_control(
        self,
        owner: object,
        *,
        account_ref: object,
        subject_id: object,
        inventory_generation: object,
        content_fingerprint: object,
        oauth_client_fingerprint: object,
        scope_fingerprint: object,
        receipt_operation_digest: object,
        receipt_binding_fingerprint: object,
    ) -> _VerifiedScanAuthorizationBindingV1:
        if not hasattr(self, "_owner") or self._owner is not owner:
            _fail("inventory.readonly_scan_request_invalid")
        if not (
            _is_nonempty_text(account_ref, _MAX_REFERENCE_BYTES)
            and _is_nonempty_text(subject_id, _MAX_SUBJECT_BYTES)
            and type(inventory_generation) is int
            and 1 <= inventory_generation <= _MAX_GENERATION
            and _is_fingerprint(content_fingerprint)
            and _is_fingerprint(oauth_client_fingerprint)
            and _is_fingerprint(scope_fingerprint)
            and _is_fingerprint(receipt_operation_digest)
            and _is_fingerprint(receipt_binding_fingerprint)
        ):
            _fail("inventory.readonly_scan_request_invalid")
        assert type(account_ref) is str
        assert type(subject_id) is str
        assert type(inventory_generation) is int
        assert type(content_fingerprint) is str
        assert type(oauth_client_fingerprint) is str
        assert type(scope_fingerprint) is str
        return _VerifiedScanAuthorizationBindingV1(
            self,
            account_ref=account_ref,
            subject_id=subject_id,
            inventory_generation=inventory_generation,
            content_fingerprint=content_fingerprint,
            oauth_client_fingerprint=oauth_client_fingerprint,
            scope_fingerprint=scope_fingerprint,
            receipt_operation_digest=receipt_operation_digest,
            receipt_binding_fingerprint=receipt_binding_fingerprint,
        )

    def _scan_for_control(
        self,
        owner: object,
        binding: object,
        canonical_document: object,
    ) -> _GoogleInventoryReadonlyScanResultV1:
        if not hasattr(self, "_owner") or self._owner is not owner:
            _fail("inventory.readonly_scan_request_invalid")
        if type(binding) is not _VerifiedScanAuthorizationBindingV1:
            _fail("inventory.readonly_scan_request_invalid")
        (
            account_ref,
            subject_id,
            inventory_generation,
            content_fingerprint,
            oauth_client_fingerprint,
            scope_fingerprint,
            receipt_operation_digest,
            receipt_binding_fingerprint,
        ) = binding._consume_for_component(self)
        _verify_current_document_binding(
            canonical_document,
            account_ref=account_ref,
            subject_id=subject_id,
            inventory_generation=inventory_generation,
            content_fingerprint=content_fingerprint,
        )
        capability: _GoogleInventoryReadonlyScanCapabilityV1 | None = None
        try:
            issue = getattr(self._broker, "issue_scan_capability")
            close = getattr(self._broker, "close_scan_capability")
            discover = getattr(self._discovery, "discover_readonly_inventory")
            if not all(callable(item) for item in (issue, close, discover)):
                _fail("inventory.readonly_scan_unavailable")
            capability = issue(
                account_ref=account_ref,
                subject_id=subject_id,
                inventory_generation=inventory_generation,
                content_fingerprint=content_fingerprint,
                oauth_client_fingerprint=oauth_client_fingerprint,
                scope_fingerprint=scope_fingerprint,
                receipt_operation_digest=receipt_operation_digest,
                receipt_binding_fingerprint=receipt_binding_fingerprint,
            )
            if type(capability) is not _GoogleInventoryReadonlyScanCapabilityV1:
                _fail("inventory.readonly_scan_capability_invalid")
            capability._consume_for_discovery(
                self._broker,
                account_ref=account_ref,
                subject_id=subject_id,
                inventory_generation=inventory_generation,
                content_fingerprint=content_fingerprint,
                oauth_client_fingerprint=oauth_client_fingerprint,
                scope_fingerprint=scope_fingerprint,
            )
            discovery_result = discover(capability)
            if type(discovery_result) is not _GoogleInventoryReadonlyDiscoveryResultV1:
                _fail("inventory.readonly_scan_discovery_invalid")
            target_account, discovery_fingerprint, counts = (
                discovery_result._consume_for_issuer(self._discovery)
            )
            _, resulting_fingerprint = _candidate_document(
                canonical_document,
                target_account,
                account_ref=account_ref,
                subject_id=subject_id,
            )
            created_at = self._clock()
            plan_id = self._plan_id_factory()
            if not _is_timestamp(created_at) or not _is_nonempty_text(
                plan_id, _MAX_PLAN_ID_BYTES
            ):
                _fail("inventory.readonly_scan_plan_invalid")
            assert type(created_at) in (int, float)
            assert type(plan_id) is str
            created = float(created_at)
            expires = created + _PLAN_LIFETIME_SECONDS
            sealed_payload = _canonical_json(
                {
                    "binding": {
                        "account_ref": account_ref,
                        "subject_id": subject_id,
                        "inventory_generation": inventory_generation,
                        "content_fingerprint": content_fingerprint,
                        "oauth_client_fingerprint": oauth_client_fingerprint,
                        "scope_fingerprint": scope_fingerprint,
                        "plan_id": plan_id,
                        "resulting_content_fingerprint": resulting_fingerprint,
                        "created_at": created,
                        "expires_at": expires,
                    },
                    "discovery_fingerprint": discovery_fingerprint,
                    "target_account": target_account,
                }
            )
            digest = _FINGERPRINT_PREFIX + sha256(sealed_payload).hexdigest()
            plan = _GoogleInventoryReadonlyPlanV1(
                _account_ref=account_ref,
                _subject_id=subject_id,
                _inventory_generation=inventory_generation,
                _content_fingerprint=content_fingerprint,
                _oauth_client_fingerprint=oauth_client_fingerprint,
                _scope_fingerprint=scope_fingerprint,
                _plan_id=plan_id,
                _plan_digest=digest,
                _resulting_content_fingerprint=resulting_fingerprint,
                _created_at=created,
                _expires_at=expires,
                _sealed_payload=sealed_payload,
            )
            projects, billings, services, keys = counts
            return _GoogleInventoryReadonlyScanResultV1(
                plan,
                {
                    "status": "planned",
                    "account_count": 1,
                    "project_count": projects,
                    "billing_account_count": billings,
                    "service_count": services,
                    "key_count": keys,
                    "changes": MappingProxyType({"canonical_account": 1}),
                },
            )
        except GoogleInventoryReadonlyScanError:
            raise
        except Exception:
            _fail("inventory.readonly_scan_unavailable")
        finally:
            receipt_operation_digest = None
            receipt_binding_fingerprint = None
            if capability is not None:
                try:
                    closer = getattr(self._broker, "close_scan_capability")
                    if callable(closer):
                        closer(capability)
                except Exception:
                    # The capability is already consumed and never contains token bytes.
                    pass


def _create_scan_component_for_control(
    *,
    broker: object,
    discovery: _GoogleInventoryReadonlyDiscoveryPortV1,
) -> tuple[_GoogleInventoryReadonlyScanComponentV1, object]:
    """Build the fixed-control scan component and its opaque owner capability."""

    owner = object()
    return (
        _GoogleInventoryReadonlyScanComponentV1(
            broker,
            discovery,
            owner=owner,
            clock=time.time,
            plan_id_factory=lambda: secrets.token_urlsafe(32),
        ),
        owner,
    )


def _for_test_scan_component(
    *,
    broker: object,
    discovery: _GoogleInventoryReadonlyDiscoveryPortV1,
    clock: object,
    plan_id_factory: object,
) -> tuple[_GoogleInventoryReadonlyScanComponentV1, object]:
    """Test-only construction seam; production must use the fixed factory."""

    owner = object()
    return (
        _GoogleInventoryReadonlyScanComponentV1(
            broker,
            discovery,
            owner=owner,
            clock=clock,
            plan_id_factory=plan_id_factory,
        ),
        owner,
    )
