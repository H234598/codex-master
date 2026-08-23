"""Deterministic, read-only Google OAuth authorization policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
from typing import Final, NoReturn


class GoogleOAuthProfileIdV1(str, Enum):
    INVENTORY_READONLY = "inventory_readonly"


class GoogleOAuthOperationV1(str, Enum):
    PROJECTS_SEARCH = "projects.search"
    KEYS_LOOKUP_KEY = "keys.lookupKey"
    PROJECTS_GET = "projects.get"
    KEYS_GET = "keys.get"
    KEYS_LIST = "keys.list"
    PROJECTS_GET_BILLING_INFO = "projects.getBillingInfo"


_OAUTH_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "credential.oauth_request_invalid",
        "credential.oauth_profile_unknown",
        "credential.oauth_operation_forbidden",
        "credential.oauth_scope_mismatch",
        "credential.oauth_policy_invalid",
    }
)


class GoogleOAuthAuthorizationError(Exception):
    """Code-only failure from the closed OAuth policy boundary."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        if type(code) is not str:
            del code
            raise TypeError("invalid OAuth policy error code")
        if code not in _OAUTH_ERROR_CODES:
            del code
            raise TypeError("invalid OAuth policy error code")
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"GoogleOAuthAuthorizationError({self.code!r})"

    def __str__(self) -> str:
        return self.code


_INVENTORY_READONLY_SCOPES: Final[tuple[str, ...]] = (
    "cloud-billing.readonly",
    "cloud-platform.read-only",
    "email",
    "openid",
)
_INVENTORY_READONLY_OPERATIONS: Final[tuple[GoogleOAuthOperationV1, ...]] = (
    GoogleOAuthOperationV1.KEYS_GET,
    GoogleOAuthOperationV1.KEYS_LIST,
    GoogleOAuthOperationV1.KEYS_LOOKUP_KEY,
    GoogleOAuthOperationV1.PROJECTS_GET,
    GoogleOAuthOperationV1.PROJECTS_GET_BILLING_INFO,
    GoogleOAuthOperationV1.PROJECTS_SEARCH,
)
_INVENTORY_READONLY_PROFILE_ID: Final[str] = (
    GoogleOAuthProfileIdV1.INVENTORY_READONLY.value
)
_INVENTORY_READONLY_OPERATION_VALUES: Final[frozenset[str]] = frozenset(
    operation.value for operation in _INVENTORY_READONLY_OPERATIONS
)
_INVENTORY_READONLY_SCOPE_FINGERPRINT: Final[str] = (
    "sha256:"
    + hashlib.sha256("\n".join(_INVENTORY_READONLY_SCOPES).encode("utf-8")).hexdigest()
)


def _raise(code: str) -> NoReturn:
    raise GoogleOAuthAuthorizationError(code) from None


@dataclass(frozen=True, slots=True, init=False)
class GoogleOAuthAuthorizationProfileV1:
    profile_id: GoogleOAuthProfileIdV1
    allowed_operations: tuple[GoogleOAuthOperationV1, ...]
    minimal_scopes: tuple[str, ...]
    scope_fingerprint: str

    def __init__(self) -> None:
        raise TypeError("canonical OAuth policy profiles are resolved")

    def __repr__(self) -> str:
        return (
            "GoogleOAuthAuthorizationProfileV1("
            f"profile_id={self.profile_id.value!r}, "
            "allowed_operations="
            f"{tuple(operation.value for operation in self.allowed_operations)!r}, "
            f"minimal_scopes={self.minimal_scopes!r}, "
            f"scope_fingerprint={self.scope_fingerprint!r})"
        )

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        return (_restore_inventory_readonly_profile, ())


def _build_inventory_readonly_profile() -> GoogleOAuthAuthorizationProfileV1:
    if tuple(sorted(_INVENTORY_READONLY_SCOPES)) != _INVENTORY_READONLY_SCOPES:
        _raise("credential.oauth_scope_mismatch")
    if len(set(_INVENTORY_READONLY_SCOPES)) != len(_INVENTORY_READONLY_SCOPES):
        _raise("credential.oauth_scope_mismatch")
    if (
        tuple(
            sorted(
                _INVENTORY_READONLY_OPERATIONS, key=lambda operation: operation.value
            )
        )
        != _INVENTORY_READONLY_OPERATIONS
    ):
        _raise("credential.oauth_policy_invalid")
    if len(set(_INVENTORY_READONLY_OPERATIONS)) != len(_INVENTORY_READONLY_OPERATIONS):
        _raise("credential.oauth_policy_invalid")

    expected_fingerprint = (
        "sha256:"
        + hashlib.sha256(
            "\n".join(_INVENTORY_READONLY_SCOPES).encode("utf-8")
        ).hexdigest()
    )
    if expected_fingerprint != _INVENTORY_READONLY_SCOPE_FINGERPRINT:
        _raise("credential.oauth_scope_mismatch")

    profile = object.__new__(GoogleOAuthAuthorizationProfileV1)
    object.__setattr__(profile, "profile_id", GoogleOAuthProfileIdV1.INVENTORY_READONLY)
    object.__setattr__(profile, "allowed_operations", _INVENTORY_READONLY_OPERATIONS)
    object.__setattr__(profile, "minimal_scopes", _INVENTORY_READONLY_SCOPES)
    object.__setattr__(
        profile, "scope_fingerprint", _INVENTORY_READONLY_SCOPE_FINGERPRINT
    )
    return profile


_INVENTORY_READONLY_PROFILE: Final[GoogleOAuthAuthorizationProfileV1] = (
    _build_inventory_readonly_profile()
)


def _restore_inventory_readonly_profile() -> GoogleOAuthAuthorizationProfileV1:
    return _INVENTORY_READONLY_PROFILE


def _decode_profile(value: object) -> GoogleOAuthProfileIdV1 | str:
    if type(value) is GoogleOAuthProfileIdV1:
        return value
    if type(value) is str:
        if value == _INVENTORY_READONLY_PROFILE_ID:
            return GoogleOAuthProfileIdV1.INVENTORY_READONLY
        return "credential.oauth_profile_unknown"
    return "credential.oauth_request_invalid"


def _decode_operation(value: object) -> GoogleOAuthOperationV1 | str:
    if type(value) is GoogleOAuthOperationV1:
        return value
    if type(value) is str:
        if value in _INVENTORY_READONLY_OPERATION_VALUES:
            return GoogleOAuthOperationV1(value)
        return "credential.oauth_operation_forbidden"
    return "credential.oauth_request_invalid"


def resolve_google_oauth_profile_v1(
    profile_id: object, operation: object
) -> GoogleOAuthAuthorizationProfileV1:
    """Resolve one closed-world profile and one allowed inventory operation."""

    profile_result = _decode_profile(profile_id)
    operation_result = _decode_operation(operation)
    del profile_id, operation
    if (
        type(profile_result) is str
        and profile_result == "credential.oauth_request_invalid"
    ) or (
        type(operation_result) is str
        and operation_result == "credential.oauth_request_invalid"
    ):
        del profile_result, operation_result
        _raise("credential.oauth_request_invalid")
    if type(profile_result) is str:
        del operation_result
        _raise(profile_result)
    if type(operation_result) is str:
        del profile_result
        _raise(operation_result)
    del profile_result, operation_result
    return _INVENTORY_READONLY_PROFILE
