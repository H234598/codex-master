"""Account-isolated installed-app OAuth sessions."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import socket
import stat
import subprocess
import threading
import time
from typing import Final, Protocol, cast
import urllib.parse
import urllib.request
import webbrowser

from .credential_vault import CredentialVault, CredentialVaultError
from .google_account_inventory import GoogleAccountInventoryError
from .google_account_inventory_manager import GoogleAccountInventoryManager
from .google_cloud_api import GoogleCloudApi, GoogleCloudApiError
from .google_oauth_authorization import (
    GoogleOAuthAuthorizationError,
    GoogleOAuthOperationV1,
    GoogleOAuthProfileIdV1,
    google_oauth_scope_values_v1,
    resolve_google_oauth_profile_v1,
)
from .google_project_naming import generate_pretty_project_identity
from .hive.state import HiveStateError, HiveStateStore


_SCOPES = (
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
)


class GoogleOAuthSessionError(Exception):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"GoogleOAuthSessionError({self.code!r})"


@dataclass(frozen=True, slots=True)
class GoogleOAuthSessionReceipt:
    account_ref: str
    subject_bound: bool
    refresh_token_stored: bool


def _account(document: dict[str, object], account_ref: str) -> dict[str, object]:
    accounts = document.get("google_accounts")
    if type(accounts) is not list:
        raise GoogleOAuthSessionError("oauth.session_inventory_invalid")
    found = [
        item
        for item in accounts
        if type(item) is dict and item.get("ref") == account_ref
    ]
    if len(found) != 1:
        raise GoogleOAuthSessionError("oauth.session_account_invalid")
    return found[0]


def _client(path: Path) -> tuple[dict[str, object], str]:
    try:
        metadata = os.lstat(path)
        raw = path.read_bytes()
    except OSError:
        raise GoogleOAuthSessionError("oauth.session_client_invalid") from None
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
    ):
        raise GoogleOAuthSessionError("oauth.session_client_invalid")
    return _client_document(raw)


def _client_document(raw: bytes | bytearray) -> tuple[dict[str, object], str]:
    try:
        if type(raw) not in (bytes, bytearray) or not 1 <= len(raw) <= 64 * 1024:
            raise ValueError
        document = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise GoogleOAuthSessionError("oauth.session_client_invalid") from None
    installed = document.get("installed") if type(document) is dict else None
    if (
        type(installed) is not dict
        or re.fullmatch(
            r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com",
            str(installed.get("client_id", "")),
        )
        is None
        or type(installed.get("client_secret")) is not str
        or not installed["client_secret"]
        or installed.get("auth_uri") != "https://accounts.google.com/o/oauth2/auth"
        or installed.get("token_uri") != "https://oauth2.googleapis.com/token"
        or installed.get("redirect_uris") != ["http://localhost"]
    ):
        raise GoogleOAuthSessionError("oauth.session_client_invalid")
    return dict(installed), "sha256:" + sha256(raw).hexdigest()


def _client_project_number(client: dict[str, object]) -> str:
    client_id = client.get("client_id")
    if type(client_id) is not str:
        raise GoogleOAuthSessionError("oauth.session_client_invalid")
    match = re.fullmatch(r"([0-9]+)-[a-z0-9]+\.apps\.googleusercontent\.com", client_id)
    if match is None:
        raise GoogleOAuthSessionError("oauth.session_client_invalid")
    return match.group(1)


def _persist_authorization(
    store,
    *,
    account_ref: str,
    observed_subject_id: str,
    access_token: str,
    refresh_token: str | None,
    client_fingerprint: str,
) -> None:
    _, current = store._read()
    account = _account(current, account_ref)
    bound = account.get("subject_id")
    if bound is not None and bound != observed_subject_id:
        raise GoogleOAuthSessionError("oauth.session_subject_mismatch")
    if any(
        type(value) is not str or not value
        for value in (
            account_ref,
            observed_subject_id,
            access_token,
            client_fingerprint,
        )
    ) or (
        refresh_token is not None
        and (type(refresh_token) is not str or not refresh_token)
    ):
        raise GoogleOAuthSessionError("oauth.session_credentials_invalid")

    def update(document: dict[str, object]) -> None:
        target = _account(document, account_ref)
        target["subject_id"] = observed_subject_id
        old_auth = target.get("auth")
        old_refresh = old_auth.get("refresh_token") if type(old_auth) is dict else None
        target["auth"] = {
            "access_token": access_token,
            "refresh_token": refresh_token or old_refresh,
            "client_fingerprint": client_fingerprint,
            "cookies": old_auth.get("cookies", []) if type(old_auth) is dict else [],
        }

    store.atomic_update(update)


class _ProfileBrowser:
    def __init__(
        self, executable: str, profile: Path, debug_port: int | None = None
    ) -> None:
        self._executable = executable
        self._profile = profile
        self._debug_port = debug_port

    def open(self, url: str, new: int = 0, autoraise: bool = True) -> bool:
        if self._debug_port is not None:
            target_url = (
                f"http://127.0.0.1:{self._debug_port}/json/new?"
                + urllib.parse.quote(url, safe="")
            )
            request = urllib.request.Request(target_url, method="PUT")
            with urllib.request.urlopen(request, timeout=5) as response:
                raw = response.read(4097)
            if len(raw) > 4096 or type(json.loads(raw).get("id")) is not str:
                raise GoogleOAuthSessionError("oauth.session_browser_invalid")
            return True
        subprocess.Popen(
            [
                self._executable,
                f"--user-data-dir={self._profile}",
                "--new-window",
                url,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return True

    open_new = open
    open_new_tab = open


def authorize_google_account(
    store,
    *,
    account_ref: str,
    client_file: Path,
    browser_profile: Path,
    browser_debug_port: int | None = None,
) -> GoogleOAuthSessionReceipt:
    client, fingerprint = _client(client_file)
    client_project_number = _client_project_number(client)
    try:
        profile_metadata = os.lstat(browser_profile)
    except OSError:
        raise GoogleOAuthSessionError("oauth.session_browser_invalid") from None
    if (
        not stat.S_ISDIR(profile_metadata.st_mode)
        or profile_metadata.st_uid != os.geteuid()
        or bool(stat.S_IMODE(profile_metadata.st_mode) & 0o077)
        or (
            browser_debug_port is not None
            and (
                type(browser_debug_port) is not int
                or not 1 <= browser_debug_port <= 65535
            )
        )
    ):
        raise GoogleOAuthSessionError("oauth.session_browser_invalid")
    executable = shutil.which("vivaldi-stable") or shutil.which("vivaldi")
    if executable is None:
        raise GoogleOAuthSessionError("oauth.session_browser_invalid")
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow

        flow = InstalledAppFlow.from_client_secrets_file(
            str(client_file), scopes=_SCOPES
        )
        browser_name = "codex-google-" + account_ref
        webbrowser.register(
            browser_name,
            None,
            _ProfileBrowser(executable, browser_profile, browser_debug_port),
            preferred=False,
        )
        credentials = flow.run_local_server(
            host="127.0.0.1",
            port=0,
            open_browser=True,
            browser=browser_name,
            authorization_prompt_message="",
            success_message="OAuth abgeschlossen. Dieses Fenster kann geschlossen werden.",
            access_type="offline",
            prompt="consent",
            timeout_seconds=600,
        )
    except GoogleOAuthSessionError:
        raise
    except Exception:
        raise GoogleOAuthSessionError("oauth.session_authorization_failed") from None
    api = GoogleCloudApi(credentials.token)
    try:
        observed_subject = api.subject_id()
    except GoogleCloudApiError:
        raise GoogleOAuthSessionError("oauth.session_subject_unavailable") from None
    try:
        api.enable_control_services(client_project_number)
    except GoogleCloudApiError:
        raise GoogleOAuthSessionError(
            "oauth.session_control_services_unavailable"
        ) from None
    _persist_authorization(
        store,
        account_ref=account_ref,
        observed_subject_id=observed_subject,
        access_token=credentials.token,
        refresh_token=credentials.refresh_token,
        client_fingerprint=fingerprint,
    )
    return GoogleOAuthSessionReceipt(
        account_ref=account_ref,
        subject_bound=True,
        refresh_token_stored=bool(credentials.refresh_token),
    )


def load_access_token(store, *, account_ref: str, client_file: Path) -> str:
    client, fingerprint = _client(client_file)
    _, document = store._read()
    account = _account(document, account_ref)
    auth = account.get("auth")
    if type(auth) is not dict or auth.get("client_fingerprint") != fingerprint:
        raise GoogleOAuthSessionError("oauth.session_client_mismatch")
    access_token = auth.get("access_token")
    refresh_token = auth.get("refresh_token")
    if type(access_token) is not str or not access_token:
        raise GoogleOAuthSessionError("oauth.session_credentials_invalid")
    if type(refresh_token) is not str or not refresh_token:
        return access_token
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials

        credentials = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            token_uri=str(
                client.get("token_uri", "https://oauth2.googleapis.com/token")
            ),
            client_id=str(client.get("client_id", "")),
            client_secret=str(client.get("client_secret", "")),
            scopes=_SCOPES,
        )
        credentials.refresh(Request())
    except Exception:
        raise GoogleOAuthSessionError("oauth.session_refresh_failed") from None
    _persist_authorization(
        store,
        account_ref=account_ref,
        observed_subject_id=str(account.get("subject_id")),
        access_token=credentials.token,
        refresh_token=credentials.refresh_token,
        client_fingerprint=fingerprint,
    )
    return credentials.token


MAX_OAUTH_TRANSACTION_SECONDS: Final[int] = 10 * 60
MAX_OAUTH_CLIENT_IMPORT_SECONDS: Final[int] = 5 * 60
_CONTROL_DOCUMENT: Final[PurePosixPath] = PurePosixPath("google-oauth-control.json")
_INVENTORY_AUTHORIZATION_DOCUMENT: Final[PurePosixPath] = PurePosixPath(
    "google-oauth-inventory-readonly.json"
)
_MAX_CONTROL_BYTES: Final[int] = 2 * 1024 * 1024
_MAX_CONTROL_RECORDS: Final[int] = 4096
_CONTROL_SCHEMA_VERSION: Final[int] = 3
_INVENTORY_AUTHORIZATION_SCHEMA_VERSION: Final[int] = 1
_REF: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII
)
_REDIRECT: Final[re.Pattern[str]] = re.compile(
    r"http://127\.0\.0\.1:([1-9][0-9]{0,4})/callback\Z", re.ASCII
)
_DIGEST: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_URLSAFE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_-]{16,512}\Z", re.ASCII)
_DISPLAY_NAME: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z]{2,20} [A-Za-z]{2,20}\Z", re.ASCII
)


GoogleOAuthError = GoogleOAuthSessionError


class SecretIngressPort(Protocol):
    """Task-8/9 durable claim port.

    Read stays replayable until acknowledged. Ack atomically removes the claim
    and durably records its binding. ``ack_operation_id`` is the persisted,
    unique plan digest. Repeating that exact operation ID with the same binding
    succeeds even after claim removal.
    """

    def read_oauth_client(
        self,
        session: object,
        *,
        account_ref: str,
        expected_generation: int,
        plan_digest: str,
    ) -> bytearray: ...

    def acknowledge_oauth_client(
        self,
        session: object,
        *,
        account_ref: str,
        expected_generation: int,
        plan_digest: str,
        ack_operation_id: str,
    ) -> None: ...


class GoogleOAuthCodeExchangePort(Protocol):
    """Provider boundary; adapter receives code and client only in process memory."""

    def exchange(
        self,
        client: dict[str, object],
        *,
        code: str,
        redirect_uri: str,
        pkce_verifier: str,
    ) -> GoogleOAuthCodeExchangeV1: ...


class GoogleOAuthTokenWriterPort(Protocol):
    """Account/scope-bound authority over the existing Google token owner.

    Implementations atomically bind token effect and durable operation receipt.
    Repeating one operation ID returns that receipt without another token write.
    """

    def lookup_refresh_token_receipt(
        self,
        operation_id: str,
        *,
        account_ref: str,
        scope_profile: GoogleOAuthProfileIdV1,
        scope_fingerprint: str,
    ) -> GoogleOAuthTokenWriteReceiptV1 | None: ...

    def store_refresh_token(
        self,
        operation_id: str,
        *,
        account_ref: str,
        subject_id: str,
        oauth_client_fingerprint: str,
        scope_profile: GoogleOAuthProfileIdV1,
        scope_fingerprint: str,
        refresh_token: bytearray,
    ) -> GoogleOAuthTokenWriteReceiptV1: ...


@dataclass(frozen=True, slots=True, repr=False)
class GoogleOAuthCodeExchangeV1:
    subject_id: str
    refresh_token: bytearray

    def __post_init__(self) -> None:
        if (
            type(self.subject_id) is not str
            or not self.subject_id
            or type(self.refresh_token) is not bytearray
            or not self.refresh_token
        ):
            raise GoogleOAuthSessionError("oauth.exchange_failed")

    def __repr__(self) -> str:
        return "GoogleOAuthCodeExchangeV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class GoogleOAuthTokenWriteReceiptV1:
    operation_id: str
    account_ref: str
    subject_id: str
    oauth_client_fingerprint: str
    scope_profile: GoogleOAuthProfileIdV1
    scope_fingerprint: str

    def __repr__(self) -> str:
        return "GoogleOAuthTokenWriteReceiptV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class GoogleOAuthClientImportPlanV1:
    id: str
    account_ref: str
    expected_generation: int
    expires_at: float
    idempotency_key: str
    plan_digest: str

    def __repr__(self) -> str:
        return "GoogleOAuthClientImportPlanV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class GoogleOAuthClientImportReceiptV1:
    account_ref: str
    client_ref: str
    display_name: str
    inventory_generation: int
    client_digest: str

    def __repr__(self) -> str:
        return "GoogleOAuthClientImportReceiptV1(<redacted>)"


class GoogleOAuthClientAvailabilityV1(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    REVOKED = "revoked"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class GoogleOAuthClientBindingV1:
    account_ref: str
    inventory_generation: int
    default_oauth_client_ref: str | None
    availability: GoogleOAuthClientAvailabilityV1


@dataclass(frozen=True, slots=True, repr=False)
class GoogleOAuthClientMaterialV1:
    client_id: str
    client_secret: str
    token_uri: str
    client_fingerprint: str


@dataclass(frozen=True, slots=True, repr=False)
class GoogleOAuthTransactionV1:
    id: str
    account_ref: str
    authorization_url: str
    expires_at: float
    inventory_generation: int

    def __repr__(self) -> str:
        return "GoogleOAuthTransactionV1(<redacted>)"


class _InventoryReadonlyCodeExchangeV1:
    """Private, mutable provider result; no token value may escape its owner."""

    __slots__ = ("refresh_token", "access_token", "id_token")

    def __init__(
        self,
        *,
        refresh_token: bytearray,
        access_token: bytearray,
        id_token: bytearray,
    ) -> None:
        if not all(
            type(value) is bytearray and value
            for value in (refresh_token, access_token, id_token)
        ):
            raise GoogleOAuthSessionError("oauth.exchange_failed")
        self.refresh_token = refresh_token
        self.access_token = access_token
        self.id_token = id_token

    def __repr__(self) -> str:
        return "_InventoryReadonlyCodeExchangeV1(<redacted>)"

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private OAuth exchange result is not serializable")

    def clear(self) -> None:
        _zero_bytes(self.refresh_token)
        _zero_bytes(self.access_token)
        _zero_bytes(self.id_token)
        self.refresh_token = bytearray()
        self.access_token = bytearray()
        self.id_token = bytearray()


class _InventoryReadonlyVerifiedIdTokenV1:
    """Private verifier output, carrying only the signed subject and nonce claim."""

    __slots__ = ("subject_id", "nonce")

    def __init__(self, *, subject_id: str, nonce: bytearray) -> None:
        if (
            type(subject_id) is not str
            or not subject_id
            or type(nonce) is not bytearray
            or not nonce
        ):
            raise GoogleOAuthSessionError("oauth.id_token_invalid")
        self.subject_id = subject_id
        self.nonce = nonce

    def __repr__(self) -> str:
        return "_InventoryReadonlyVerifiedIdTokenV1(<redacted>)"

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private verified ID token is not serializable")

    def clear(self) -> None:
        _zero_bytes(self.nonce)
        self.nonce = bytearray()
        self.subject_id = ""


class _InventoryReadonlyAuthorizationTransactionV1:
    """Private transaction projection with no nonce, token, or identity material."""

    __slots__ = ("id", "authorization_url", "expires_at", "inventory_generation")

    def __init__(
        self,
        transaction_id: str,
        authorization_url: str,
        expires_at: float,
        inventory_generation: int,
    ) -> None:
        self.id = transaction_id
        self.authorization_url = authorization_url
        self.expires_at = expires_at
        self.inventory_generation = inventory_generation

    def __repr__(self) -> str:
        return "_InventoryReadonlyAuthorizationTransactionV1(<redacted>)"

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError(
            "private inventory authorization transaction is not serializable"
        )


class _InventoryReadonlyAuthorizationEffectV1:
    """One-shot, redacted in-memory authorization effect for the Authority only."""

    __slots__ = (
        "_account_ref",
        "_subject_id",
        "_inventory_generation",
        "_oauth_client_fingerprint",
        "_scope_fingerprint",
        "_refresh_token",
    )

    def __init__(
        self,
        *,
        account_ref: str,
        subject_id: str,
        inventory_generation: int,
        oauth_client_fingerprint: str,
        scope_fingerprint: str,
        refresh_token: bytearray,
    ) -> None:
        self._account_ref = account_ref
        self._subject_id = subject_id
        self._inventory_generation = inventory_generation
        self._oauth_client_fingerprint = oauth_client_fingerprint
        self._scope_fingerprint = scope_fingerprint
        self._refresh_token = refresh_token

    def __repr__(self) -> str:
        return "_InventoryReadonlyAuthorizationEffectV1(<redacted>)"

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private inventory authorization effect is not serializable")

    def clear(self) -> None:
        _zero_bytes(self._refresh_token)
        self._refresh_token = bytearray()
        self._account_ref = ""
        self._subject_id = ""
        self._inventory_generation = 0
        self._oauth_client_fingerprint = ""
        self._scope_fingerprint = ""

    def _consume_for_authority(
        self,
    ) -> tuple[str, str, int, str, str, bytearray]:
        if not self._refresh_token:
            raise GoogleOAuthSessionError("oauth.inventory_effect_consumed")
        result = (
            self._account_ref,
            self._subject_id,
            self._inventory_generation,
            self._oauth_client_fingerprint,
            self._scope_fingerprint,
            self._refresh_token,
        )
        self._refresh_token = bytearray()
        self._account_ref = ""
        self._subject_id = ""
        self._inventory_generation = 0
        self._oauth_client_fingerprint = ""
        self._scope_fingerprint = ""
        return result


class _InventoryReadonlyIdTokenVerifierPort(Protocol):
    """Private fixed-policy verifier for signed Google ID tokens.

    The concrete port verifies the fixed Google issuer and algorithm, the bound
    client audience/authorized-party, expiration and time bounds, verified
    login email, and subject. It returns only signed subject and nonce claims;
    this owner compares the nonce against its pending transaction digest.
    """

    def verify_inventory_readonly_id_token(
        self,
        id_token: bytearray,
        *,
        expected_nonce: bytearray,
        client_id: str,
        login_email: str,
        now: float,
    ) -> _InventoryReadonlyVerifiedIdTokenV1: ...


class _GoogleInventoryReadonlyIdTokenVerifierV1:
    """Fixed Google RS256 verifier; its only result is a redacted identity claim."""

    _ISSUERS: Final[frozenset[str]] = frozenset(
        {"accounts.google.com", "https://accounts.google.com"}
    )
    _ALGORITHM: Final[str] = "RS256"
    _CLOCK_SKEW_SECONDS: Final[int] = 60
    _MAX_ID_TOKEN_SECONDS: Final[int] = 3_660

    def __repr__(self) -> str:
        return "_GoogleInventoryReadonlyIdTokenVerifierV1(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private Google ID token verifier is not serializable")

    @classmethod
    def _fixed_rs256_header(cls, token: str) -> None:
        try:
            parts = token.split(".")
            if len(parts) != 3 or not all(parts):
                raise ValueError
            encoded_header = parts[0]
            padded_header = encoded_header + "=" * (-len(encoded_header) % 4)
            header = json.loads(
                base64.urlsafe_b64decode(padded_header.encode("ascii")).decode("utf-8")
            )
            if (
                type(header) is not dict
                or header.get("alg") != cls._ALGORITHM
                or type(header.get("kid")) is not str
                or not header["kid"]
            ):
                raise ValueError
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise GoogleOAuthSessionError("oauth.id_token_invalid") from None

    def verify_inventory_readonly_id_token(
        self,
        id_token: bytearray,
        *,
        expected_nonce: bytearray,
        client_id: str,
        login_email: str,
        now: float,
    ) -> _InventoryReadonlyVerifiedIdTokenV1:
        """Verify signature and every fixed Inventory Readonly identity binding."""

        token = ""
        nonce = ""
        claims: Mapping[str, object] | object = {}
        try:
            if (
                type(id_token) is not bytearray
                or not id_token
                or type(expected_nonce) is not bytearray
                or not expected_nonce
                or type(client_id) is not str
                or not client_id
                or type(login_email) is not str
                or not login_email
                or type(now) not in (int, float)
                or isinstance(now, bool)
                or not math.isfinite(float(now))
            ):
                raise ValueError
            token = id_token.decode("ascii")
            nonce = expected_nonce.decode("ascii")
            if (
                _URLSAFE.fullmatch(nonce) is None
                or len(token) > 64 * 1024
                or len(nonce) > 512
            ):
                raise ValueError
            self._fixed_rs256_header(token)
            from google.auth.transport.requests import Request
            from google.oauth2 import id_token as google_id_token

            claims = google_id_token.verify_oauth2_token(
                token,
                Request(),
                client_id,
                clock_skew_in_seconds=self._CLOCK_SKEW_SECONDS,
            )
            if type(claims) is not dict:
                raise ValueError
            issuer = claims.get("iss")
            audience = claims.get("aud")
            authorized_party = claims.get("azp")
            issued_at = claims.get("iat")
            expires_at = claims.get("exp")
            claimed_nonce = claims.get("nonce")
            email_verified = claims.get("email_verified")
            email = claims.get("email")
            subject_id = claims.get("sub")
            if (
                issuer not in self._ISSUERS
                or audience != client_id
                or authorized_party != client_id
                or type(issued_at) is not int
                or isinstance(issued_at, bool)
                or type(expires_at) is not int
                or isinstance(expires_at, bool)
                or issued_at > now + self._CLOCK_SKEW_SECONDS
                or expires_at <= now - self._CLOCK_SKEW_SECONDS
                or expires_at < issued_at
                or expires_at - issued_at > self._MAX_ID_TOKEN_SECONDS
                or type(claimed_nonce) is not str
                or _URLSAFE.fullmatch(claimed_nonce) is None
                or not secrets.compare_digest(claimed_nonce, nonce)
                or email_verified is not True
                or type(email) is not str
                or not secrets.compare_digest(email, login_email)
                or type(subject_id) is not str
                or not 1 <= len(subject_id.encode("utf-8")) <= 1024
                or "\x00" in subject_id
            ):
                raise ValueError
            return _InventoryReadonlyVerifiedIdTokenV1(
                subject_id=subject_id,
                nonce=bytearray(claimed_nonce.encode("ascii")),
            )
        except (GoogleOAuthSessionError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise GoogleOAuthSessionError("oauth.id_token_invalid") from None
        finally:
            token = ""
            nonce = ""
            if type(claims) is dict:
                claims.clear()
            claims = {}


class _InventoryReadonlyNoRedirectHandlerV1(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        raise GoogleOAuthSessionError("oauth.exchange_failed")


class _GoogleInventoryReadonlyCodeExchangeV1:
    """Fixed Google token endpoint for the Inventory Readonly callback only."""

    _TOKEN_URI: Final[str] = "https://oauth2.googleapis.com/token"

    def __repr__(self) -> str:
        return "_GoogleInventoryReadonlyCodeExchangeV1(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private inventory code exchange is not serializable")

    def exchange_inventory_readonly(
        self,
        client: dict[str, object],
        *,
        code: str,
        redirect_uri: str,
        pkce_verifier: str,
    ) -> _InventoryReadonlyCodeExchangeV1:
        payload: bytearray | None = None
        raw = b""
        value: object = {}
        access_token = ""
        id_token = ""
        refresh_token = ""
        try:
            if (
                type(client) is not dict
                or client.get("token_uri") != self._TOKEN_URI
                or "client_secret" in client
                or any(
                    type(value) is not str or not value
                    for value in (
                        client.get("client_id"),
                        code,
                        redirect_uri,
                        pkce_verifier,
                    )
                )
            ):
                raise ValueError
            payload = bytearray(
                urllib.parse.urlencode(
                    {
                        "code": code,
                        "client_id": client["client_id"],
                        "redirect_uri": redirect_uri,
                        "grant_type": "authorization_code",
                        "code_verifier": pkce_verifier,
                    }
                ).encode("ascii")
            )
            request = urllib.request.Request(
                self._TOKEN_URI,
                data=payload,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                method="POST",
            )
            opener = urllib.request.build_opener(
                _InventoryReadonlyNoRedirectHandlerV1()
            )
            with opener.open(request, timeout=10) as response:
                if response.status != 200 or response.geturl() != self._TOKEN_URI:
                    raise ValueError
                raw = response.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise ValueError
            value = json.loads(raw)
            if type(value) is not dict:
                raise ValueError
            access_token = value.get("access_token", "")
            id_token = value.get("id_token", "")
            refresh_token = value.get("refresh_token", "")
            if any(
                type(token) is not str
                or not token
                or len(token.encode("utf-8")) > 16 * 1024
                for token in (access_token, id_token, refresh_token)
            ):
                raise ValueError
            return _InventoryReadonlyCodeExchangeV1(
                refresh_token=bytearray(refresh_token.encode("utf-8")),
                access_token=bytearray(access_token.encode("utf-8")),
                id_token=bytearray(id_token.encode("utf-8")),
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise GoogleOAuthSessionError("oauth.exchange_failed") from None
        finally:
            _zero_bytes(payload) if payload is not None else None
            payload = None
            raw = b""
            if type(value) is dict:
                value.clear()
            value = {}
            access_token = ""
            id_token = ""
            refresh_token = ""


def _zero_bytes(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _required_callable(owner: object, name: str) -> bool:
    failed = False
    value: object = None
    try:
        value = getattr(owner, name)
    except BaseException:
        failed = True
    return not failed and callable(value)


class _InventoryReadonlyAuthorizationCallbackDriverV1:
    """Fixed, private callback inputs for one Inventory Readonly interaction.

    This type is deliberately reachable only through the module-private test
    factory below.  Production has no callback material until its source-owned
    private client and loopback callback owners exist.
    """

    __slots__ = (
        "_account_ref",
        "_code",
        "_expected_generation",
        "_idempotency_key",
        "_oauth_client_ref",
        "_principal",
        "_redirect_uri",
        "_state",
    )

    def __init__(
        self,
        *,
        account_ref: str,
        oauth_client_ref: str,
        redirect_uri: str,
        expected_generation: int,
        idempotency_key: str,
        principal: str,
        code: str,
        state: str,
    ) -> None:
        try:
            self._account_ref = GoogleOAuthControlService._ref(account_ref)
            self._oauth_client_ref = GoogleOAuthControlService._ref(oauth_client_ref)
            self._redirect_uri = GoogleOAuthControlService._redirect_uri(redirect_uri)
            self._expected_generation = GoogleOAuthControlService._generation(
                expected_generation
            )
            self._idempotency_key = GoogleOAuthControlService._ref(idempotency_key)
            self._principal = GoogleOAuthControlService._ref(principal)
            if (
                type(code) is not str
                or not 1 <= len(code) <= 8192
                or type(state) is not str
                or not 1 <= len(state) <= 512
            ):
                raise ValueError
            self._code = code
            self._state = state
        except (GoogleOAuthSessionError, ValueError, TypeError):
            raise GoogleOAuthSessionError("oauth.inventory_unavailable") from None

    def __repr__(self) -> str:
        return "_InventoryReadonlyAuthorizationCallbackDriverV1(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private inventory callback driver is not serializable")

    def _begin_arguments(self) -> tuple[str, dict[str, object]]:
        return self._account_ref, {
            "oauth_client_ref": self._oauth_client_ref,
            "redirect_uri": self._redirect_uri,
            "expected_generation": self._expected_generation,
            "idempotency_key": self._idempotency_key,
            "principal": self._principal,
        }

    def _complete_arguments(self, transaction_id: str) -> tuple[str, dict[str, object]]:
        return transaction_id, {
            "code": self._code,
            "account_ref": self._account_ref,
            "redirect_uri": self._redirect_uri,
            "expected_generation": self._expected_generation,
            "state": self._state,
        }


class _InventoryReadonlyAuthorizationPreflightForTestV1:
    """Statically bounded no-I/O preflight seam for direct OAuth leaf tests."""

    __slots__ = ("calls",)

    def __init__(self) -> None:
        self.calls = 0

    def __repr__(self) -> str:
        return "_InventoryReadonlyAuthorizationPreflightForTestV1(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private inventory preflight is not serializable")

    def _preflight_for_inventory_authorize(self) -> None:
        self.calls += 1


class _InventoryReadonlyAuthorizationHandleV1:
    """One nonserializable RAM transaction owned only by the OAuth service."""

    __slots__ = (
        "registry_generation",
        "registry_fingerprint",
        "record",
        "account",
        "inventory_generation",
        "redirect_uri",
        "expires_at",
        "state",
        "verifier",
        "nonce",
        "code",
        "callback_state",
        "authorization_url",
    )

    def __init__(
        self,
        *,
        registry_generation,
        registry_fingerprint,
        record,
        account,
        inventory_generation,
        redirect_uri,
        expires_at,
    ):
        self.registry_generation = registry_generation
        self.registry_fingerprint = registry_fingerprint
        self.record = record
        self.account = account
        self.inventory_generation = inventory_generation
        self.redirect_uri = redirect_uri
        self.expires_at = expires_at
        self.state = bytearray()
        self.verifier = bytearray()
        self.nonce = bytearray()
        self.code = bytearray()
        self.callback_state = bytearray()
        self.authorization_url = bytearray()

    def __repr__(self) -> str:
        return "_InventoryReadonlyAuthorizationHandleV1(<redacted>)"

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private inventory transaction is not serializable")

    def clear(self) -> None:
        for value in (
            self.state,
            self.verifier,
            self.nonce,
            self.code,
            self.callback_state,
            self.authorization_url,
        ):
            _zero_bytes(value)
        self.record = None
        self.account = None
        self.registry_generation = 0
        self.registry_fingerprint = ""
        self.inventory_generation = 0
        self.redirect_uri = ""
        self.expires_at = 0.0


class _InventoryReadonlyLoopbackDriverV1:
    """Fixed IPv4 loopback and desktop browser driver for one callback GET."""

    __slots__ = ("_listener", "_redirect_uri")

    def __init__(self) -> None:
        self._listener = None
        self._redirect_uri = ""

    def __repr__(self) -> str:
        return "_InventoryReadonlyLoopbackDriverV1(<redacted>)"

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private loopback driver is not serializable")

    def clear(self) -> None:
        listener, self._listener = self._listener, None
        self._redirect_uri = ""
        if listener is not None:
            listener.close()

    def _open(self) -> str:
        display = os.environ.get("DISPLAY", "")
        wayland = os.environ.get("WAYLAND_DISPLAY", "")
        if (
            any(
                os.environ.get(name)
                for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")
            )
            or not (display or wayland)
            or (display and re.fullmatch(r":[0-9]+(?:\.[0-9]+)?", display) is None)
            or (wayland and re.fullmatch(r"wayland-[0-9]+", wayland) is None)
            or self._listener is not None
        ):
            raise GoogleOAuthSessionError("oauth.interactive_authorization_required")
        try:
            self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._listener.bind(("127.0.0.1", 0))
            self._listener.listen(1)
            host, port = self._listener.getsockname()
            if host != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65535:
                raise ValueError
            self._redirect_uri = f"http://127.0.0.1:{port}/callback"
            return self._redirect_uri
        except (KeyboardInterrupt, SystemExit):
            self.clear()
            raise
        except Exception:
            self.clear()
            raise GoogleOAuthSessionError(
                "oauth.interactive_authorization_required"
            ) from None

    def _receive(self, handle: _InventoryReadonlyAuthorizationHandleV1) -> None:
        connection = None
        raw = bytearray()
        try:
            if (
                type(handle) is not _InventoryReadonlyAuthorizationHandleV1
                or self._listener is None
                or handle.redirect_uri != self._redirect_uri
                or not handle.authorization_url.startswith(
                    b"https://accounts.google.com/o/oauth2/auth?"
                )
            ):
                raise ValueError
            self._listener.settimeout(MAX_OAUTH_TRANSACTION_SECONDS)
            subprocess.run(
                ["/usr/bin/xdg-open", handle.authorization_url.decode("ascii")],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=10,
            )
            connection, peer = self._listener.accept()
            self.clear()
            if peer[0] != "127.0.0.1":
                raise ValueError
            connection.settimeout(10)
            while b"\r\n\r\n" not in raw:
                chunk = connection.recv(min(4096, 16 * 1024 + 1 - len(raw)))
                if not chunk:
                    raise ValueError
                raw.extend(chunk)
                if len(raw) > 16 * 1024:
                    raise ValueError
            head, body = raw.split(b"\r\n\r\n", 1)
            lines = head.decode("ascii").split("\r\n")
            method, target, version = lines[0].split(" ")
            if method != "GET" or version not in ("HTTP/1.0", "HTTP/1.1") or body:
                raise ValueError
            headers = {}
            for line in lines[1:]:
                key, value = line.split(":", 1)
                key = key.lower()
                if key in headers or key.strip() != key:
                    raise ValueError
                headers[key] = value.strip()
            if (
                headers.get("host") != urllib.parse.urlsplit(handle.redirect_uri).netloc
                or "transfer-encoding" in headers
                or headers.get("content-length", "0") != "0"
            ):
                raise ValueError
            parsed = urllib.parse.urlsplit(target)
            if (
                parsed.scheme
                or parsed.netloc
                or parsed.fragment
                or parsed.path != "/callback"
            ):
                raise ValueError
            values = urllib.parse.parse_qs(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=8,
            )
            if (
                set(values) - {"code", "state", "scope", "authuser", "prompt", "hd"}
                or "code" not in values
                or "state" not in values
                or any(len(value) != 1 for value in values.values())
                or not 1 <= len(values["code"][0]) <= 8192
                or not 1 <= len(values["state"][0]) <= 512
            ):
                raise ValueError
            handle.code.extend(values["code"][0].encode("ascii"))
            handle.callback_state.extend(values["state"][0].encode("ascii"))
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Cache-Control: no-store\r\nConnection: close\r\nContent-Length: 32\r\n\r\n"
                b"Authorization callback received."
            )
        except (KeyboardInterrupt, SystemExit):
            if type(handle) is _InventoryReadonlyAuthorizationHandleV1:
                handle.clear()
            raise
        except Exception:
            if type(handle) is _InventoryReadonlyAuthorizationHandleV1:
                handle.clear()
            raise GoogleOAuthSessionError(
                "oauth.interactive_authorization_required"
            ) from None
        finally:
            _zero_bytes(raw)
            if connection is not None:
                connection.close()
            self.clear()


class _TheHiveInventoryReadonlyAuthorizationPort:
    """Authority-only adapter over the existing narrow Inventory OAuth owner."""

    __slots__ = ("_callback_driver", "_control_service", "_manager", "_preflight")

    def __init__(
        self,
        *,
        preflight: object,
        manager: GoogleAccountInventoryManager | None,
        control_service: GoogleOAuthControlService | None = None,
        callback_driver: _InventoryReadonlyAuthorizationCallbackDriverV1
        | _InventoryReadonlyLoopbackDriverV1
        | None = None,
    ) -> None:
        self._preflight = preflight
        self._manager = manager
        self._control_service = control_service
        self._callback_driver = callback_driver

    def __repr__(self) -> str:
        return "_TheHiveInventoryReadonlyAuthorizationPort(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private inventory authorization port is not serializable")

    def authorize(self) -> object:
        """Run the fixed registry-bound OAuth transaction with no caller choices."""

        try:
            preflight = getattr(self._preflight, "_preflight_for_inventory_authorize")
            if not callable(preflight):
                raise TypeError
            preflight()
            if self._manager is None:
                raise TypeError
            if self._control_service is None or self._callback_driver is None:
                raise GoogleOAuthSessionError("oauth.inventory_unavailable")
            if type(self._callback_driver) is _InventoryReadonlyLoopbackDriverV1:
                handle = None
                try:
                    # Resolve before opening any socket or launching the desktop.
                    self._control_service._inventory_bound_selection()
                    redirect_uri = self._callback_driver._open()
                    handle = (
                        self._control_service._begin_inventory_readonly_authorization(
                            redirect_uri=redirect_uri,
                        )
                    )
                    self._callback_driver._receive(handle)
                    return self._control_service._complete_inventory_readonly_authorization(
                        handle
                    )
                finally:
                    if handle is not None:
                        with self._control_service._inventory_transaction_lock:
                            if (
                                self._control_service._inventory_pending_handle
                                is handle
                            ):
                                self._control_service._inventory_pending_handle = None
                        handle.clear()
                    self._callback_driver.clear()
            if (
                type(self._preflight)
                is not _InventoryReadonlyAuthorizationPreflightForTestV1
            ):
                raise GoogleOAuthSessionError("oauth.inventory_unavailable")
            account_ref, begin_arguments = self._callback_driver._begin_arguments()
            transaction = self._control_service._for_test_legacy_begin_inventory_readonly_authorization(
                account_ref, **begin_arguments
            )
            if type(transaction) is not _InventoryReadonlyAuthorizationTransactionV1:
                raise TypeError
            transaction_id, complete_arguments = (
                self._callback_driver._complete_arguments(transaction.id)
            )
            return self._control_service._for_test_legacy_complete_inventory_readonly_authorization(
                transaction_id, **complete_arguments
            )
        except GoogleOAuthSessionError:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise GoogleOAuthSessionError("oauth.inventory_unavailable") from None


def _new_the_hive_inventory_readonly_authorization_port(
    *, vault_components: object, manager: object
) -> _TheHiveInventoryReadonlyAuthorizationPort:
    """Build the production OAuth leaf from only fixed private owner resources."""

    try:
        from .google_inventory_token_vault import (
            _TheHiveInventoryVaultProductionComponents,
        )
        from .google_inventory_desktop_client_registry import (
            _InventoryDesktopClientRegistryStoreV1,
        )

        if (
            type(vault_components) is not _TheHiveInventoryVaultProductionComponents
            or type(manager) is not GoogleAccountInventoryManager
        ):
            raise TypeError
        return _TheHiveInventoryReadonlyAuthorizationPort(
            preflight=vault_components,
            manager=manager,
            control_service=GoogleOAuthControlService._from_inventory_registry(
                registry=_InventoryDesktopClientRegistryStoreV1(
                    vault_components._layout
                ),
                manager=manager,
            ),
            callback_driver=_InventoryReadonlyLoopbackDriverV1(),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise GoogleOAuthSessionError("oauth.inventory_unavailable") from None


def _for_test_the_hive_inventory_readonly_authorization_port(
    *,
    control_service: GoogleOAuthControlService | None,
    callback_driver: _InventoryReadonlyAuthorizationCallbackDriverV1 | None,
    preflight: _InventoryReadonlyAuthorizationPreflightForTestV1,
) -> _TheHiveInventoryReadonlyAuthorizationPort:
    """Construct the only statically bounded direct-test OAuth leaf seam."""

    if type(preflight) is not _InventoryReadonlyAuthorizationPreflightForTestV1:
        raise GoogleOAuthSessionError("oauth.inventory_unavailable")
    populated = (
        type(control_service) is GoogleOAuthControlService
        and type(callback_driver) is _InventoryReadonlyAuthorizationCallbackDriverV1
    )
    absent = control_service is None and callback_driver is None
    if not (populated or absent):
        raise GoogleOAuthSessionError("oauth.inventory_unavailable")
    return _TheHiveInventoryReadonlyAuthorizationPort(
        preflight=preflight,
        manager=GoogleAccountInventoryManager.__new__(GoogleAccountInventoryManager),
        control_service=control_service,
        callback_driver=callback_driver,
    )


class GoogleOAuthControlService:
    """Durable account-bound OAuth transactions over existing secret owners."""

    def __init__(
        self,
        state_root: Path,
        *,
        manager: GoogleAccountInventoryManager,
        client_vault: CredentialVault,
        token_writer: GoogleOAuthTokenWriterPort,
        secret_ingress: SecretIngressPort,
        code_exchange: GoogleOAuthCodeExchangePort,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if (
            not isinstance(state_root, Path)
            or not state_root.is_absolute()
            or not isinstance(manager, GoogleAccountInventoryManager)
            or not isinstance(client_vault, CredentialVault)
            or not _required_callable(token_writer, "lookup_refresh_token_receipt")
            or not _required_callable(token_writer, "store_refresh_token")
            or not _required_callable(secret_ingress, "read_oauth_client")
            or not _required_callable(secret_ingress, "acknowledge_oauth_client")
            or not _required_callable(code_exchange, "exchange")
            or (clock is not None and not callable(clock))
        ):
            raise GoogleOAuthSessionError("oauth.control_unavailable")
        self._root = state_root
        self._manager = manager
        self._client_vault = client_vault
        self._token_writer = token_writer
        self._secret_ingress = secret_ingress
        self._code_exchange = code_exchange
        self._inventory_code_exchange = (
            code_exchange
            if _required_callable(code_exchange, "exchange_inventory_readonly")
            else _GoogleInventoryReadonlyCodeExchangeV1()
        )
        self._inventory_id_token_verifier: _InventoryReadonlyIdTokenVerifierPort = (
            _GoogleInventoryReadonlyIdTokenVerifierV1()
        )
        self._inventory_pending_nonces: dict[str, bytearray] = {}
        self._clock = clock or time.time
        try:
            self._state = HiveStateStore(state_root)
            with self._state.locked():
                try:
                    os.lstat(state_root / _CONTROL_DOCUMENT.name)
                except FileNotFoundError:
                    self._write_locked(self._empty_document())
                else:
                    self._read_locked()
                try:
                    os.lstat(state_root / _INVENTORY_AUTHORIZATION_DOCUMENT.name)
                except FileNotFoundError:
                    self._write_inventory_authorization_locked(
                        self._empty_inventory_authorization_document()
                    )
                else:
                    self._read_inventory_authorization_locked()
        except (GoogleOAuthSessionError, HiveStateError, OSError):
            raise GoogleOAuthSessionError("oauth.control_unavailable") from None

    def __repr__(self) -> str:
        return "GoogleOAuthControlService(<redacted>)"

    def account_generation(self, account_ref: str) -> int:
        """Read current Inventory generation for one OAuth account."""

        account_ref = self._ref(account_ref)
        try:
            snapshot = self._manager._snapshot_for_internal_use()
            snapshot.by_account_ref[account_ref]
        except (GoogleAccountInventoryError, KeyError, AttributeError):
            raise GoogleOAuthSessionError("oauth.account_mismatch") from None
        return cast(int, snapshot.generation)

    def account_oauth_state(self, account_ref: str, *, expected_generation: int) -> str:
        """Project current non-secret OAuth authority state for one account."""

        account_ref = self._ref(account_ref)
        expected_generation = self._generation(expected_generation)
        if self.account_generation(account_ref) != expected_generation:
            raise GoogleOAuthSessionError("oauth.generation_mismatch")
        try:
            with self._state.locked():
                document = self._read_locked()
                transactions = [
                    cast(dict[str, object], item)
                    for item in cast(list[object], document["transactions"])
                    if cast(dict[str, object], item)["account_ref"] == account_ref
                    and cast(dict[str, object], item)["inventory_generation"]
                    == expected_generation
                ]
                for record in reversed(transactions):
                    if (
                        record["state"] != "succeeded"
                        or record["token_operation_id"] is None
                    ):
                        continue
                    receipt = self._lookup_token_receipt(record)
                    if receipt is None:
                        return "stale"
                    self._validate_token_receipt(record, receipt)
                    return "ready"
                if any(
                    record["state"] in {"reconcile_required", "repair_required"}
                    for record in transactions
                ):
                    return "repair_required"
                if any(
                    record["state"] in {"pending", "completing", "persisting"}
                    for record in transactions
                ):
                    return "pending"
        except (HiveStateError, OSError):
            return "unavailable"
        return "needs_auth"

    @staticmethod
    def _empty_document() -> dict[str, object]:
        return {
            "schema_version": _CONTROL_SCHEMA_VERSION,
            "imports": [],
            "clients": [],
            "transactions": [],
        }

    @staticmethod
    def _empty_inventory_authorization_document() -> dict[str, object]:
        return {
            "schema_version": _INVENTORY_AUTHORIZATION_SCHEMA_VERSION,
            "transactions": [],
        }

    @classmethod
    def _validate_inventory_authorization_document(
        cls, value: Mapping[str, object]
    ) -> None:
        if (
            set(value) != {"schema_version", "transactions"}
            or value.get("schema_version") != _INVENTORY_AUTHORIZATION_SCHEMA_VERSION
            or type(value.get("transactions")) is not list
            or len(cast(list[object], value["transactions"])) > _MAX_CONTROL_RECORDS
        ):
            raise HiveStateError("invalid_google_oauth_inventory_authorization_state")
        transaction_ids: set[str] = set()
        for item in cast(list[object], value["transactions"]):
            record = cls._record(
                item,
                {
                    "id",
                    "account_ref",
                    "oauth_client_ref",
                    "client_digest",
                    "client_vault_generation",
                    "pkce_verifier",
                    "redirect_uri",
                    "scope_fingerprint",
                    "state_token",
                    "state_digest",
                    "nonce_digest",
                    "inventory_generation",
                    "expires_at",
                    "state",
                    "authorization_code_digest",
                    "effect_subject_digest",
                    "terminal_at",
                },
            )
            base = (
                cls._stored_ref(record["id"])
                and cls._stored_ref(record["account_ref"])
                and cls._stored_ref(record["oauth_client_ref"])
                and cls._stored_digest(record["client_digest"])
                and cls._stored_generation(record["client_vault_generation"])
                and type(record["redirect_uri"]) is str
                and _REDIRECT.fullmatch(cast(str, record["redirect_uri"])) is not None
                and cls._stored_digest(record["scope_fingerprint"])
                and record["scope_fingerprint"]
                == resolve_google_oauth_profile_v1(
                    GoogleOAuthProfileIdV1.INVENTORY_READONLY,
                    GoogleOAuthOperationV1.PROJECTS_SEARCH,
                ).scope_fingerprint
                and cls._stored_digest(record["state_digest"])
                and cls._stored_digest(record["nonce_digest"])
                and cls._stored_generation(record["inventory_generation"])
                and cls._stored_time(record["expires_at"])
            )
            pending = record["state"] == "pending" and (
                cls._stored_urlsafe(record["pkce_verifier"])
                and cls._stored_urlsafe(record["state_token"])
                and record["state_digest"]
                == cls._digest("google.oauth-state", record["state_token"])
                and record["authorization_code_digest"] is None
                and record["effect_subject_digest"] is None
                and record["terminal_at"] is None
            )
            exchanging = record["state"] == "exchanging" and (
                record["pkce_verifier"] is None
                and record["state_token"] is None
                and cls._stored_digest(record["authorization_code_digest"])
                and record["effect_subject_digest"] is None
                and record["terminal_at"] is None
            )
            verified = record["state"] == "verified" and (
                record["pkce_verifier"] is None
                and record["state_token"] is None
                and cls._stored_digest(record["authorization_code_digest"])
                and cls._stored_digest(record["effect_subject_digest"])
                and record["terminal_at"] is None
            )
            terminal = record["state"] in {"failed", "expired"} and (
                record["pkce_verifier"] is None
                and record["state_token"] is None
                and record["authorization_code_digest"] is None
                and record["effect_subject_digest"] is None
                and cls._stored_time(record["terminal_at"])
            )
            if not base or not (pending or exchanging or verified or terminal):
                raise HiveStateError(
                    "invalid_google_oauth_inventory_authorization_state"
                )
            transaction_id = cast(str, record["id"])
            if transaction_id in transaction_ids:
                raise HiveStateError(
                    "invalid_google_oauth_inventory_authorization_state"
                )
            transaction_ids.add(transaction_id)

    def _read_inventory_authorization_locked(self) -> dict[str, object]:
        try:
            value = dict(
                self._state.read_json_locked(
                    _INVENTORY_AUTHORIZATION_DOCUMENT,
                    max_bytes=_MAX_CONTROL_BYTES,
                )
            )
            self._validate_inventory_authorization_document(value)
        except (HiveStateError, OSError, GoogleOAuthAuthorizationError):
            raise GoogleOAuthSessionError("oauth.inventory_unavailable") from None
        return value

    def _write_inventory_authorization_locked(
        self, document: Mapping[str, object]
    ) -> None:
        try:
            self._validate_inventory_authorization_document(document)
            self._state.replace_json_locked(_INVENTORY_AUTHORIZATION_DOCUMENT, document)
        except (HiveStateError, OSError, GoogleOAuthAuthorizationError):
            raise GoogleOAuthSessionError("oauth.inventory_unavailable") from None

    def _read_locked(self) -> dict[str, object]:
        try:
            value = dict(
                self._state.read_json_locked(
                    _CONTROL_DOCUMENT, max_bytes=_MAX_CONTROL_BYTES
                )
            )
            if value.get("schema_version") == 1:
                value = self._migrate_v1(value)
                self._write_locked(value)
            elif value.get("schema_version") == 2:
                value = self._migrate_v2(value)
                self._write_locked(value)
            self._validate_document(value)
        except (HiveStateError, OSError):
            raise GoogleOAuthSessionError("oauth.control_unavailable") from None
        return value

    @staticmethod
    def _record(value: object, fields: set[str]) -> dict[str, object]:
        if type(value) is not dict or set(value) != fields:
            raise HiveStateError("invalid_google_oauth_control_state")
        return cast(dict[str, object], value)

    @staticmethod
    def _stored_ref(value: object) -> bool:
        return type(value) is str and _REF.fullmatch(value) is not None

    @staticmethod
    def _stored_digest(value: object) -> bool:
        return type(value) is str and _DIGEST.fullmatch(value) is not None

    @staticmethod
    def _stored_urlsafe(value: object) -> bool:
        return type(value) is str and _URLSAFE.fullmatch(value) is not None

    @staticmethod
    def _stored_generation(value: object) -> bool:
        return type(value) is int and 1 <= value <= 2**63 - 1

    @staticmethod
    def _stored_time(value: object) -> bool:
        if type(value) is int:
            return 0 <= value <= 2**63 - 1
        if type(value) is float:
            return 0 <= value <= float(2**63 - 1)
        return False

    @staticmethod
    def _stored_display_name(value: object) -> bool:
        return type(value) is str and _DISPLAY_NAME.fullmatch(value) is not None

    @classmethod
    def _validate_document(cls, value: Mapping[str, object]) -> None:
        if set(value) != {"schema_version", "imports", "clients", "transactions"}:
            raise HiveStateError("invalid_google_oauth_control_state")
        if value.get("schema_version") != _CONTROL_SCHEMA_VERSION:
            raise HiveStateError("invalid_google_oauth_control_state")
        collections: list[list[object]] = []
        for field in ("imports", "clients", "transactions"):
            records = value.get(field)
            if type(records) is not list or len(records) > _MAX_CONTROL_RECORDS:
                raise HiveStateError("invalid_google_oauth_control_state")
            collections.append(records)
        imports, clients, transactions = collections
        import_ids: set[str] = set()
        idempotency_keys: set[str] = set()
        for item in imports:
            record = cls._record(
                item,
                {
                    "id",
                    "account_ref",
                    "expected_generation",
                    "expires_at",
                    "idempotency_key",
                    "plan_digest",
                    "state",
                    "nonce",
                    "client_ref",
                    "client_digest",
                    "display_name",
                    "vault_generation",
                    "terminal_at",
                },
            )
            common = (
                cls._stored_ref(record["id"])
                and cls._stored_ref(record["account_ref"])
                and cls._stored_generation(record["expected_generation"])
                and cls._stored_time(record["expires_at"])
                and cls._stored_ref(record["idempotency_key"])
                and cls._stored_digest(record["plan_digest"])
            )
            state = record["state"]
            pending = state == "planned" and (
                cls._stored_urlsafe(record["nonce"])
                and record["plan_digest"]
                == cls._digest(
                    "google.oauth-client-import",
                    record["id"],
                    record["account_ref"],
                    record["expected_generation"],
                    record["expires_at"],
                    record["idempotency_key"],
                    record["nonce"],
                )
                and all(
                    record[field] is None
                    for field in (
                        "client_ref",
                        "client_digest",
                        "display_name",
                        "vault_generation",
                        "terminal_at",
                    )
                )
            )
            has_client = (
                cls._stored_ref(record["client_ref"])
                and cls._stored_digest(record["client_digest"])
                and cls._stored_display_name(record["display_name"])
                and cls._stored_generation(record["vault_generation"])
            )
            effect_pending = (
                state in {"persisting", "ack_pending"}
                and record["nonce"] is None
                and has_client
                and record["terminal_at"] is None
            )
            cleanup = (
                state == "cleanup"
                and record["nonce"] is None
                and all(
                    record[field] is None
                    for field in (
                        "client_ref",
                        "client_digest",
                        "display_name",
                        "vault_generation",
                        "terminal_at",
                    )
                )
            )
            repair_required = (
                state == "repair_required"
                and record["nonce"] is None
                and (
                    has_client
                    or all(
                        record[field] is None
                        for field in (
                            "client_ref",
                            "client_digest",
                            "display_name",
                            "vault_generation",
                        )
                    )
                )
                and record["terminal_at"] is None
            )
            succeeded = (
                state == "succeeded"
                and record["nonce"] is None
                and has_client
                and cls._stored_time(record["terminal_at"])
            )
            failed = (
                state in {"failed", "expired"}
                and record["nonce"] is None
                and all(
                    record[field] is None
                    for field in (
                        "client_ref",
                        "client_digest",
                        "display_name",
                        "vault_generation",
                    )
                )
                and cls._stored_time(record["terminal_at"])
            )
            if not common or not (
                pending
                or effect_pending
                or cleanup
                or repair_required
                or succeeded
                or failed
            ):
                raise HiveStateError("invalid_google_oauth_control_state")
            import_id = cast(str, record["id"])
            idempotency_key = cast(str, record["idempotency_key"])
            if import_id in import_ids or idempotency_key in idempotency_keys:
                raise HiveStateError("invalid_google_oauth_control_state")
            import_ids.add(import_id)
            idempotency_keys.add(idempotency_key)
        client_ids: set[str] = set()
        client_authorities: set[tuple[str, int]] = set()
        active_accounts: set[str] = set()
        for item in clients:
            record = cls._record(
                item,
                {
                    "id",
                    "account_ref",
                    "inventory_generation",
                    "client_digest",
                    "display_name",
                    "vault_generation",
                    "state",
                    "terminal_at",
                },
            )
            state = record["state"]
            valid_state = (state == "active" and record["terminal_at"] is None) or (
                state == "retired" and cls._stored_time(record["terminal_at"])
            )
            if not (
                cls._stored_ref(record["id"])
                and cls._stored_ref(record["account_ref"])
                and cls._stored_generation(record["inventory_generation"])
                and cls._stored_digest(record["client_digest"])
                and cls._stored_display_name(record["display_name"])
                and cls._stored_generation(record["vault_generation"])
                and valid_state
            ):
                raise HiveStateError("invalid_google_oauth_control_state")
            client_id = cast(str, record["id"])
            account_ref = cast(str, record["account_ref"])
            if client_id in client_ids or (
                state == "active" and account_ref in active_accounts
            ):
                raise HiveStateError("invalid_google_oauth_control_state")
            authority = (account_ref, cast(int, record["vault_generation"]))
            if authority in client_authorities:
                raise HiveStateError("invalid_google_oauth_control_state")
            client_ids.add(client_id)
            client_authorities.add(authority)
            if state == "active":
                active_accounts.add(account_ref)
        transaction_ids: set[str] = set()
        operation_ids: set[str] = set()
        for item in transactions:
            record = cls._record(
                item,
                {
                    "id",
                    "account_ref",
                    "oauth_client_ref",
                    "client_digest",
                    "client_vault_generation",
                    "pkce_verifier",
                    "redirect_uri",
                    "scope_profile",
                    "scope_fingerprint",
                    "state_token",
                    "state_digest",
                    "inventory_generation",
                    "expires_at",
                    "state",
                    "token_operation_id",
                    "authorization_code_digest",
                    "effect_subject_id",
                    "completion_owner",
                    "completion_lease_expires_at",
                    "terminal_at",
                },
            )
            try:
                profile_id = GoogleOAuthProfileIdV1(cast(str, record["scope_profile"]))
                profile_operation = (
                    GoogleOAuthOperationV1.PROJECTS_SEARCH
                    if profile_id is GoogleOAuthProfileIdV1.INVENTORY_READONLY
                    else GoogleOAuthOperationV1.PROJECTS_CREATE
                )
                expected_scope_fingerprint = resolve_google_oauth_profile_v1(
                    profile_id, profile_operation
                ).scope_fingerprint
            except (TypeError, ValueError, GoogleOAuthAuthorizationError):
                raise HiveStateError("invalid_google_oauth_control_state") from None
            base = (
                cls._stored_ref(record["id"])
                and cls._stored_ref(record["account_ref"])
                and cls._stored_ref(record["oauth_client_ref"])
                and cls._stored_digest(record["client_digest"])
                and cls._stored_generation(record["client_vault_generation"])
                and type(record["redirect_uri"]) is str
                and _REDIRECT.fullmatch(cast(str, record["redirect_uri"])) is not None
                and record["scope_profile"] == profile_id.value
                and cls._stored_digest(record["scope_fingerprint"])
                and record["scope_fingerprint"] == expected_scope_fingerprint
                and cls._stored_digest(record["state_digest"])
                and cls._stored_generation(record["inventory_generation"])
                and cls._stored_time(record["expires_at"])
            )
            state = record["state"]
            pending = state == "pending" and (
                cls._stored_urlsafe(record["pkce_verifier"])
                and cls._stored_urlsafe(record["state_token"])
                and record["state_digest"]
                == cls._digest("google.oauth-state", record["state_token"])
                and record["token_operation_id"] is None
                and record["authorization_code_digest"] is None
                and record["effect_subject_id"] is None
                and record["completion_owner"] is None
                and record["completion_lease_expires_at"] is None
                and record["terminal_at"] is None
            )
            completing = state == "completing" and (
                cls._stored_urlsafe(record["pkce_verifier"])
                and cls._stored_urlsafe(record["state_token"])
                and record["state_digest"]
                == cls._digest("google.oauth-state", record["state_token"])
                and record["token_operation_id"] is None
                and cls._stored_digest(record["authorization_code_digest"])
                and record["effect_subject_id"] is None
                and cls._stored_ref(record["completion_owner"])
                and cls._stored_time(record["completion_lease_expires_at"])
                and cast(float, record["completion_lease_expires_at"])
                <= cast(float, record["expires_at"])
                and record["terminal_at"] is None
            )
            persisting = state == "persisting" and (
                record["pkce_verifier"] is None
                and record["state_token"] is None
                and cls._stored_ref(record["effect_subject_id"])
                and cls._stored_digest(record["authorization_code_digest"])
                and record["completion_owner"] is None
                and record["completion_lease_expires_at"] is None
                and cls._stored_digest(record["token_operation_id"])
                and record["token_operation_id"]
                == cls._digest(
                    "google.oauth-token-write",
                    record["id"],
                    record["account_ref"],
                    record["client_digest"],
                    record["scope_fingerprint"],
                    record["effect_subject_id"],
                )
                and record["terminal_at"] is None
            )
            reconcile_required = state == "reconcile_required" and (
                record["pkce_verifier"] is None
                and record["state_token"] is None
                and record["effect_subject_id"] is None
                and record["authorization_code_digest"] is None
                and record["completion_owner"] is None
                and record["completion_lease_expires_at"] is None
                and cls._stored_digest(record["token_operation_id"])
                and record["token_operation_id"]
                == cls._digest(
                    "google.oauth-token-write",
                    record["id"],
                    record["account_ref"],
                    record["client_digest"],
                    record["scope_fingerprint"],
                )
                and record["terminal_at"] is None
            )
            repair_required = state == "repair_required" and (
                record["pkce_verifier"] is None
                and record["state_token"] is None
                and record["effect_subject_id"] is None
                and record["authorization_code_digest"] is None
                and record["completion_owner"] is None
                and record["completion_lease_expires_at"] is None
                and record["token_operation_id"] is None
                and record["terminal_at"] is None
            )
            terminal = state in {"succeeded", "failed", "expired"} and (
                record["pkce_verifier"] is None
                and record["state_token"] is None
                and record["completion_owner"] is None
                and record["completion_lease_expires_at"] is None
                and cls._stored_time(record["terminal_at"])
                and (
                    (
                        record["token_operation_id"] is None
                        and record["effect_subject_id"] is None
                        and record["authorization_code_digest"] is None
                    )
                    or (
                        cls._stored_ref(record["effect_subject_id"])
                        and cls._stored_digest(record["authorization_code_digest"])
                        and cls._stored_digest(record["token_operation_id"])
                        and record["token_operation_id"]
                        in {
                            cls._digest(
                                "google.oauth-token-write",
                                record["id"],
                                record["account_ref"],
                                record["client_digest"],
                                record["scope_fingerprint"],
                            ),
                            cls._digest(
                                "google.oauth-token-write",
                                record["id"],
                                record["account_ref"],
                                record["client_digest"],
                                record["scope_fingerprint"],
                                record["effect_subject_id"],
                            ),
                        }
                    )
                )
            )
            if not base or not (
                pending
                or completing
                or persisting
                or reconcile_required
                or repair_required
                or terminal
            ):
                raise HiveStateError("invalid_google_oauth_control_state")
            transaction_id = cast(str, record["id"])
            operation_id = record["token_operation_id"]
            if transaction_id in transaction_ids or (
                type(operation_id) is str and operation_id in operation_ids
            ):
                raise HiveStateError("invalid_google_oauth_control_state")
            transaction_ids.add(transaction_id)
            if type(operation_id) is str:
                operation_ids.add(operation_id)
            if state in {
                "pending",
                "completing",
                "persisting",
                "reconcile_required",
                "repair_required",
            }:
                authorities = [
                    cast(dict[str, object], item)
                    for item in clients
                    if cast(dict[str, object], item)["id"] == record["oauth_client_ref"]
                    and cast(dict[str, object], item)["account_ref"]
                    == record["account_ref"]
                    and cast(dict[str, object], item)["client_digest"]
                    == record["client_digest"]
                    and cast(dict[str, object], item)["vault_generation"]
                    == record["client_vault_generation"]
                ]
                if len(authorities) != 1:
                    raise HiveStateError("invalid_google_oauth_control_state")

    @classmethod
    def _migrate_v1(cls, value: Mapping[str, object]) -> dict[str, object]:
        if set(value) != {
            "schema_version",
            "imports",
            "clients",
            "transactions",
            "token_generations",
        }:
            raise HiveStateError("invalid_google_oauth_control_state")
        imports = value.get("imports")
        clients = value.get("clients")
        transactions = value.get("transactions")
        generations = value.get("token_generations")
        if (
            type(imports) is not list
            or type(clients) is not list
            or type(transactions) is not list
            or type(generations) is not dict
            or any(
                len(items) > _MAX_CONTROL_RECORDS
                for items in (imports, clients, transactions)
            )
            or any(
                not cls._stored_ref(key) or not cls._stored_generation(generation)
                for key, generation in generations.items()
            )
        ):
            raise HiveStateError("invalid_google_oauth_control_state")
        migrated_imports: list[object] = []
        for item in imports:
            record = cls._record(
                item,
                {
                    "id",
                    "account_ref",
                    "expected_generation",
                    "expires_at",
                    "idempotency_key",
                    "nonce",
                    "plan_digest",
                    "state",
                    "client_ref",
                    "client_digest",
                    "display_name",
                    "vault_generation",
                },
            )
            if not (
                cls._stored_ref(record["id"])
                and cls._stored_ref(record["account_ref"])
                and cls._stored_generation(record["expected_generation"])
                and cls._stored_time(record["expires_at"])
                and cls._stored_ref(record["idempotency_key"])
                and cls._stored_digest(record["plan_digest"])
                and cls._stored_urlsafe(record["nonce"])
                and record["plan_digest"]
                == cls._digest(
                    "google.oauth-client-import",
                    record["id"],
                    record["account_ref"],
                    record["expected_generation"],
                    record["expires_at"],
                    record["idempotency_key"],
                    record["nonce"],
                )
                and record["state"]
                in {"planned", "applying", "succeeded", "failed", "expired"}
            ):
                raise HiveStateError("invalid_google_oauth_control_state")
            client_fields_none = all(
                record[field] is None
                for field in (
                    "client_ref",
                    "client_digest",
                    "display_name",
                    "vault_generation",
                )
            )
            client_fields_valid = (
                cls._stored_ref(record["client_ref"])
                and cls._stored_digest(record["client_digest"])
                and cls._stored_display_name(record["display_name"])
                and cls._stored_generation(record["vault_generation"])
            )
            succeeded = record["state"] == "succeeded"
            valid_fields = (
                client_fields_valid
                if succeeded
                else (
                    client_fields_none or client_fields_valid
                    if record["state"] == "failed"
                    else client_fields_none
                )
            )
            if not valid_fields:
                raise HiveStateError("invalid_google_oauth_control_state")
            ambiguous = record["state"] in {"applying", "failed"}
            state = (
                "planned"
                if record["state"] == "planned"
                else (
                    "succeeded"
                    if succeeded
                    else ("repair_required" if ambiguous else "expired")
                )
            )
            migrated_imports.append(
                {
                    **record,
                    "state": state,
                    "nonce": record["nonce"] if state == "planned" else None,
                    "client_ref": record["client_ref"]
                    if succeeded or (ambiguous and client_fields_valid)
                    else None,
                    "client_digest": record["client_digest"]
                    if succeeded or (ambiguous and client_fields_valid)
                    else None,
                    "display_name": record["display_name"]
                    if succeeded or (ambiguous and client_fields_valid)
                    else None,
                    "vault_generation": record["vault_generation"]
                    if succeeded or (ambiguous and client_fields_valid)
                    else None,
                    "terminal_at": record["expires_at"]
                    if state in {"succeeded", "expired"}
                    else None,
                }
            )
        migrated_clients: list[object] = []
        for item in clients:
            record = cls._record(
                item,
                {
                    "id",
                    "account_ref",
                    "inventory_generation",
                    "client_digest",
                    "display_name",
                    "vault_generation",
                },
            )
            if not (
                cls._stored_ref(record["id"])
                and cls._stored_ref(record["account_ref"])
                and cls._stored_generation(record["inventory_generation"])
                and cls._stored_digest(record["client_digest"])
                and cls._stored_display_name(record["display_name"])
                and cls._stored_generation(record["vault_generation"])
            ):
                raise HiveStateError("invalid_google_oauth_control_state")
            migrated_clients.append({**record, "state": "active", "terminal_at": None})
        migrated_transactions: list[object] = []
        for item in transactions:
            record = cls._record(
                item,
                {
                    "id",
                    "account_ref",
                    "oauth_client_ref",
                    "client_digest",
                    "pkce_verifier",
                    "redirect_uri",
                    "scope_profile",
                    "scope_fingerprint",
                    "state_token",
                    "inventory_generation",
                    "expires_at",
                    "state",
                },
            )
            if not (
                cls._stored_ref(record["id"])
                and cls._stored_ref(record["account_ref"])
                and cls._stored_ref(record["oauth_client_ref"])
                and cls._stored_digest(record["client_digest"])
                and cls._stored_urlsafe(record["pkce_verifier"])
                and type(record["redirect_uri"]) is str
                and _REDIRECT.fullmatch(cast(str, record["redirect_uri"])) is not None
                and record["scope_profile"]
                == GoogleOAuthProfileIdV1.INVENTORY_READONLY.value
                and cls._stored_digest(record["scope_fingerprint"])
                and cls._stored_urlsafe(record["state_token"])
                and cls._stored_generation(record["inventory_generation"])
                and cls._stored_time(record["expires_at"])
                and record["state"]
                in {"pending", "completing", "succeeded", "failed", "expired"}
            ):
                raise HiveStateError("invalid_google_oauth_control_state")
            matching_clients = [
                candidate
                for candidate in migrated_clients
                if cast(dict[str, object], candidate)["id"]
                == record["oauth_client_ref"]
            ]
            if len(matching_clients) != 1:
                raise HiveStateError("invalid_google_oauth_control_state")
            active = record["state"] == "pending"
            repair_required = record["state"] in {"completing", "succeeded"}
            migrated_transactions.append(
                {
                    **record,
                    "client_vault_generation": cast(
                        dict[str, object], matching_clients[0]
                    )["vault_generation"],
                    "state": (
                        "pending"
                        if active
                        else ("repair_required" if repair_required else record["state"])
                    ),
                    "pkce_verifier": record["pkce_verifier"] if active else None,
                    "state_token": record["state_token"] if active else None,
                    "state_digest": cls._digest(
                        "google.oauth-state", record["state_token"]
                    ),
                    "token_operation_id": None,
                    "authorization_code_digest": None,
                    "effect_subject_id": None,
                    "completion_owner": None,
                    "completion_lease_expires_at": None,
                    "terminal_at": None
                    if active or repair_required
                    else record["expires_at"],
                }
            )
        migrated = {
            "schema_version": _CONTROL_SCHEMA_VERSION,
            "imports": migrated_imports,
            "clients": migrated_clients,
            "transactions": migrated_transactions,
        }
        cls._validate_document(migrated)
        return migrated

    @classmethod
    def _migrate_v2(cls, value: Mapping[str, object]) -> dict[str, object]:
        if set(value) != {"schema_version", "imports", "clients", "transactions"}:
            raise HiveStateError("invalid_google_oauth_control_state")
        imports = value.get("imports")
        clients = value.get("clients")
        transactions = value.get("transactions")
        if not all(type(items) is list for items in (imports, clients, transactions)):
            raise HiveStateError("invalid_google_oauth_control_state")
        migrated_imports: list[object] = []
        for item in cast(list[object], imports):
            record = cls._record(
                item,
                {
                    "id",
                    "account_ref",
                    "expected_generation",
                    "expires_at",
                    "idempotency_key",
                    "plan_digest",
                    "state",
                    "nonce",
                    "client_ref",
                    "client_digest",
                    "display_name",
                    "vault_generation",
                    "terminal_at",
                },
            )
            state = record["state"]
            if state == "succeeded":
                record["state"] = "ack_pending"
                record["terminal_at"] = None
            elif state not in {"planned", "persisting", "failed", "expired"}:
                raise HiveStateError("invalid_google_oauth_control_state")
            migrated_imports.append(record)
        migrated_transactions: list[object] = []
        for item in cast(list[object], transactions):
            record = cls._record(
                item,
                {
                    "id",
                    "account_ref",
                    "oauth_client_ref",
                    "client_digest",
                    "client_vault_generation",
                    "pkce_verifier",
                    "redirect_uri",
                    "scope_profile",
                    "scope_fingerprint",
                    "state_token",
                    "state_digest",
                    "inventory_generation",
                    "expires_at",
                    "state",
                    "token_operation_id",
                    "terminal_at",
                },
            )
            state = record["state"]
            operation_id = record["token_operation_id"]
            if state in {"persisting", "succeeded"} or (
                state in {"failed", "expired"} and operation_id is not None
            ):
                record.update(
                    {
                        "state": "reconcile_required",
                        "pkce_verifier": None,
                        "state_token": None,
                        "terminal_at": None,
                    }
                )
            elif state == "completing":
                record.update(
                    {
                        "state": "repair_required",
                        "pkce_verifier": None,
                        "state_token": None,
                        "terminal_at": None,
                    }
                )
            elif state not in {"pending", "failed", "expired"}:
                raise HiveStateError("invalid_google_oauth_control_state")
            record.update(
                {
                    "authorization_code_digest": None,
                    "effect_subject_id": None,
                    "completion_owner": None,
                    "completion_lease_expires_at": None,
                }
            )
            migrated_transactions.append(record)
        migrated = {
            "schema_version": _CONTROL_SCHEMA_VERSION,
            "imports": migrated_imports,
            "clients": cast(list[object], clients),
            "transactions": migrated_transactions,
        }
        cls._validate_document(migrated)
        return migrated

    def _write_locked(self, document: Mapping[str, object]) -> None:
        try:
            self._validate_document(document)
            self._state.replace_json_locked(_CONTROL_DOCUMENT, document)
        except (HiveStateError, OSError):
            raise GoogleOAuthSessionError("oauth.control_unavailable") from None

    def _now(self) -> float:
        try:
            value = float(self._clock())
        except (TypeError, ValueError, OverflowError):
            raise GoogleOAuthSessionError("oauth.control_unavailable") from None
        if not 0 <= value <= 2**63 - 1 - MAX_OAUTH_TRANSACTION_SECONDS:
            raise GoogleOAuthSessionError("oauth.control_unavailable")
        return value

    @staticmethod
    def _ref(value: object) -> str:
        if type(value) is not str or _REF.fullmatch(value) is None:
            raise GoogleOAuthSessionError("oauth.request_invalid")
        return value

    @staticmethod
    def _generation(value: object) -> int:
        if type(value) is not int or not 1 <= value <= 2**63 - 1:
            raise GoogleOAuthSessionError("oauth.request_invalid")
        return value

    @staticmethod
    def _ttl(value: object, maximum: int) -> int:
        if type(value) is not int or not 1 <= value <= maximum:
            raise GoogleOAuthSessionError("oauth.request_invalid")
        return value

    @staticmethod
    def _redirect_uri(value: object) -> str:
        if type(value) is not str:
            raise GoogleOAuthSessionError("oauth.redirect_mismatch")
        match = _REDIRECT.fullmatch(value)
        if match is None or int(match.group(1)) > 65535:
            raise GoogleOAuthSessionError("oauth.redirect_mismatch")
        return value

    def _account_subject(self, account_ref: str, generation: int) -> str | None:
        try:
            snapshot = self._manager._snapshot_for_internal_use()
            if snapshot.generation != generation:
                raise GoogleOAuthSessionError("oauth.generation_mismatch")
            account = snapshot.by_account_ref[account_ref]
            subject_id = account.subject_id
        except GoogleOAuthSessionError:
            raise
        except (GoogleAccountInventoryError, KeyError, AttributeError):
            raise GoogleOAuthSessionError("oauth.account_mismatch") from None
        if subject_id is None:
            return None
        if type(subject_id) is not str or not subject_id:
            raise GoogleOAuthSessionError("oauth.subject_mismatch")
        return subject_id

    def default_oauth_client_binding(
        self, account_ref: str, *, expected_generation: int
    ) -> GoogleOAuthClientBindingV1:
        """Project only one current account-bound opaque client reference."""

        account_ref = self._ref(account_ref)
        expected_generation = self._generation(expected_generation)
        try:
            snapshot = self._manager._snapshot_for_internal_use()
            if snapshot.generation != expected_generation:
                raise GoogleOAuthSessionError("oauth.generation_mismatch")
            snapshot.by_account_ref[account_ref]
        except GoogleOAuthSessionError:
            raise
        except (GoogleAccountInventoryError, KeyError, AttributeError):
            raise GoogleOAuthSessionError("oauth.account_mismatch") from None
        try:
            with self._state.locked():
                document = self._read_locked()
                clients = cast(list[object], document["clients"])
                active = [
                    cast(dict[str, object], item)
                    for item in clients
                    if cast(dict[str, object], item)["account_ref"] == account_ref
                    and cast(dict[str, object], item)["state"] == "active"
                ]
                if len(active) > 1:
                    availability = GoogleOAuthClientAvailabilityV1.AMBIGUOUS
                elif not active:
                    availability = GoogleOAuthClientAvailabilityV1.MISSING
                else:
                    record = active[0]
                    if record["inventory_generation"] != expected_generation:
                        availability = GoogleOAuthClientAvailabilityV1.STALE
                    else:
                        try:
                            metadata = self._client_vault.projection_metadata(
                                self._client_vault_ref(account_ref)
                            )
                        except CredentialVaultError:
                            metadata = None
                            availability = GoogleOAuthClientAvailabilityV1.UNAVAILABLE
                        else:
                            if metadata is None:
                                availability = GoogleOAuthClientAvailabilityV1.MISSING
                            elif metadata[0] == "revoked":
                                availability = GoogleOAuthClientAvailabilityV1.REVOKED
                            elif metadata[1] != record["vault_generation"]:
                                availability = GoogleOAuthClientAvailabilityV1.STALE
                            else:
                                return GoogleOAuthClientBindingV1(
                                    account_ref,
                                    expected_generation,
                                    cast(str, record["id"]),
                                    GoogleOAuthClientAvailabilityV1.AVAILABLE,
                                )
        except GoogleOAuthSessionError as error:
            if error.code != "oauth.control_unavailable":
                raise
            availability = GoogleOAuthClientAvailabilityV1.UNAVAILABLE
        except HiveStateError:
            availability = GoogleOAuthClientAvailabilityV1.UNAVAILABLE
        return GoogleOAuthClientBindingV1(
            account_ref, expected_generation, None, availability
        )

    def active_oauth_client_material(
        self, account_ref: str, *, expected_generation: int
    ) -> GoogleOAuthClientMaterialV1:
        """Lease one exact active client into the installed authority graph."""

        account_ref = self._ref(account_ref)
        expected_generation = self._generation(expected_generation)
        if self._account_subject(account_ref, expected_generation) is None:
            raise GoogleOAuthSessionError("oauth.subject_mismatch")
        with self._state.locked():
            document = self._read_locked()
            matches = [
                cast(dict[str, object], item)
                for item in cast(list[object], document["clients"])
                if cast(dict[str, object], item)["account_ref"] == account_ref
                and cast(dict[str, object], item)["state"] == "active"
                and cast(dict[str, object], item)["inventory_generation"]
                == expected_generation
            ]
            if len(matches) != 1:
                raise GoogleOAuthSessionError("oauth.client_expired")
            client, fingerprint = self._load_client(account_ref, matches[0])
            if fingerprint != matches[0]["client_digest"]:
                raise GoogleOAuthSessionError("oauth.client_expired")
        material = GoogleOAuthClientMaterialV1(
            cast(str, client["client_id"]),
            cast(str, client["client_secret"]),
            cast(str, client["token_uri"]),
            fingerprint,
        )
        client.clear()
        return material

    @staticmethod
    def _digest(*values: object) -> str:
        encoded = json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode(
            "ascii"
        )
        return "sha256:" + sha256(encoded).hexdigest()

    @staticmethod
    def _find(
        records: list[object], field: str, value: object
    ) -> dict[str, object] | None:
        for item in records:
            record = cast(dict[str, object], item)
            if record.get(field) == value:
                return record
        return None

    @staticmethod
    def _client_vault_ref(account_ref: str) -> str:
        account_digest = sha256(account_ref.encode("ascii")).hexdigest()
        return f"google-oauth-{account_digest}"

    @staticmethod
    def _make_room(records: list[object], active_states: set[str]) -> None:
        while len(records) >= _MAX_CONTROL_RECORDS:
            terminal = [
                (index, cast(dict[str, object], item))
                for index, item in enumerate(records)
                if cast(dict[str, object], item)["state"] not in active_states
            ]
            if not terminal:
                raise GoogleOAuthSessionError("oauth.control_unavailable")
            index, _record = min(
                terminal,
                key=lambda pair: (
                    cast(float, pair[1]["terminal_at"]),
                    cast(str, pair[1]["id"]),
                ),
            )
            records.pop(index)

    @staticmethod
    def _make_client_room(document: Mapping[str, object]) -> None:
        clients = cast(list[object], document["clients"])
        protected = {
            cast(str, cast(dict[str, object], item)["oauth_client_ref"])
            for item in cast(list[object], document["transactions"])
            if cast(dict[str, object], item)["state"]
            in {
                "pending",
                "completing",
                "persisting",
                "reconcile_required",
                "repair_required",
            }
        }
        while len(clients) >= _MAX_CONTROL_RECORDS:
            terminal = [
                (index, cast(dict[str, object], item))
                for index, item in enumerate(clients)
                if cast(dict[str, object], item)["state"] == "retired"
                and cast(dict[str, object], item)["id"] not in protected
            ]
            if not terminal:
                raise GoogleOAuthSessionError("oauth.control_unavailable")
            index, _record = min(
                terminal,
                key=lambda pair: (
                    cast(float, pair[1]["terminal_at"]),
                    cast(str, pair[1]["id"]),
                ),
            )
            clients.pop(index)

    def _retire_client_records(
        self,
        document: Mapping[str, object],
        *,
        account_ref: str,
        replacement_id: str,
    ) -> None:
        clients = cast(list[object], document["clients"])
        now = self._now()
        for item in clients:
            record = cast(dict[str, object], item)
            if record["account_ref"] == account_ref and record["state"] == "active":
                record["state"] = "retired"
                record["terminal_at"] = now
        if len(clients) >= _MAX_CONTROL_RECORDS or any(
            cast(dict[str, object], item)["id"] == replacement_id for item in clients
        ):
            raise GoogleOAuthSessionError("oauth.control_unavailable")

    def _client_projection_matches(
        self, account_ref: str, vault_generation: int, client_digest: str
    ) -> bool:
        raw = bytearray()
        client: dict[str, object] = {}
        try:
            lease = self._client_vault.lease(
                self._client_vault_ref(account_ref),
                expected_generation=vault_generation,
                ttl_seconds=30,
            )
            raw = bytearray(self._client_vault.consume_lease(lease))
            client, observed_digest = _client_document(raw)
            return observed_digest == client_digest
        except (CredentialVaultError, GoogleOAuthSessionError):
            return False
        finally:
            client.clear()
            _zero_bytes(raw)

    def plan_oauth_client_import(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
        ttl_seconds: int = MAX_OAUTH_CLIENT_IMPORT_SECONDS,
    ) -> GoogleOAuthClientImportPlanV1:
        account_ref = self._ref(account_ref)
        expected_generation = self._generation(expected_generation)
        idempotency_key = self._ref(idempotency_key)
        ttl_seconds = self._ttl(ttl_seconds, MAX_OAUTH_CLIENT_IMPORT_SECONDS)
        self._account_subject(account_ref, expected_generation)
        with self._state.locked():
            document = self._read_locked()
            imports = cast(list[object], document["imports"])
            if any(
                cast(dict[str, object], item)["account_ref"] == account_ref
                and cast(dict[str, object], item)["state"] == "repair_required"
                for item in imports
            ):
                raise GoogleOAuthSessionError("oauth.client_repair_required")
            existing = self._find(imports, "idempotency_key", idempotency_key)
            if existing is not None:
                if (
                    existing.get("account_ref") != account_ref
                    or existing.get("expected_generation") != expected_generation
                ):
                    raise GoogleOAuthSessionError("control.idempotency_conflict")
                return self._import_plan(existing)
            self._make_room(
                imports,
                {"planned", "persisting", "ack_pending", "cleanup", "repair_required"},
            )
            now = self._now()
            plan_id = "oauth-import-" + secrets.token_hex(16)
            expires_at = now + ttl_seconds
            nonce = secrets.token_urlsafe(32)
            plan_digest = self._digest(
                "google.oauth-client-import",
                plan_id,
                account_ref,
                expected_generation,
                expires_at,
                idempotency_key,
                nonce,
            )
            record: dict[str, object] = {
                "id": plan_id,
                "account_ref": account_ref,
                "expected_generation": expected_generation,
                "expires_at": expires_at,
                "idempotency_key": idempotency_key,
                "nonce": nonce,
                "plan_digest": plan_digest,
                "state": "planned",
                "client_ref": None,
                "client_digest": None,
                "display_name": None,
                "vault_generation": None,
                "terminal_at": None,
            }
            imports.append(record)
            self._write_locked(document)
            return self._import_plan(record)

    def resolve_oauth_client_import_plan(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        plan_digest: str,
    ) -> GoogleOAuthClientImportPlanV1:
        account_ref = self._ref(account_ref)
        expected_generation = self._generation(expected_generation)
        if type(plan_digest) is not str or _DIGEST.fullmatch(plan_digest) is None:
            raise GoogleOAuthSessionError("oauth.import_plan_invalid")
        with self._state.locked():
            document = self._read_locked()
            for value in cast(list[object], document["imports"]):
                record = cast(dict[str, object], value)
                if (
                    record["account_ref"] == account_ref
                    and record["expected_generation"] == expected_generation
                    and secrets.compare_digest(
                        cast(str, record["plan_digest"]), plan_digest
                    )
                ):
                    return self._import_plan(record)
        raise GoogleOAuthSessionError("oauth.import_plan_invalid")

    @staticmethod
    def _import_plan(record: Mapping[str, object]) -> GoogleOAuthClientImportPlanV1:
        return GoogleOAuthClientImportPlanV1(
            cast(str, record["id"]),
            cast(str, record["account_ref"]),
            cast(int, record["expected_generation"]),
            cast(float, record["expires_at"]),
            cast(str, record["idempotency_key"]),
            cast(str, record["plan_digest"]),
        )

    @staticmethod
    def _import_receipt(
        record: Mapping[str, object],
    ) -> GoogleOAuthClientImportReceiptV1:
        return GoogleOAuthClientImportReceiptV1(
            cast(str, record["account_ref"]),
            cast(str, record["client_ref"]),
            cast(str, record["display_name"]),
            cast(int, record["expected_generation"]),
            cast(str, record["client_digest"]),
        )

    def apply_oauth_client_import(
        self,
        plan: GoogleOAuthClientImportPlanV1,
        ingress_session: object,
    ) -> GoogleOAuthClientImportReceiptV1:
        raw = bytearray()
        client_data: dict[str, object] = {}
        try:
            if not isinstance(plan, GoogleOAuthClientImportPlanV1):
                raise GoogleOAuthSessionError("oauth.import_plan_invalid")
            with self._state.locked():
                document = self._read_locked()
                imports = cast(list[object], document["imports"])
                record = self._find(imports, "id", plan.id)
                if record is None or any(
                    record.get(field) != getattr(plan, field)
                    for field in (
                        "account_ref",
                        "expected_generation",
                        "expires_at",
                        "idempotency_key",
                        "plan_digest",
                    )
                ):
                    raise GoogleOAuthSessionError("oauth.import_plan_invalid")
                if record.get("state") == "succeeded":
                    return self._import_receipt(record)
                if record.get("state") == "repair_required":
                    raise GoogleOAuthSessionError("oauth.client_repair_required")
                if record.get("state") in {"ack_pending", "cleanup"}:
                    pass
                elif record.get("state") not in {"planned", "persisting"}:
                    raise GoogleOAuthSessionError("oauth.import_plan_expired")
                state = cast(str, record["state"])
                if state in {"ack_pending", "cleanup"}:
                    return self._finish_import_ack(
                        document, record, plan, ingress_session
                    )
                persisted = state == "persisting" and self._client_projection_matches(
                    plan.account_ref,
                    cast(int, record["vault_generation"]),
                    cast(str, record["client_digest"]),
                )
                if persisted:
                    self._finalize_client_projection(document, record)
                    self._write_import_locked(document)
                    return self._finish_import_ack(
                        document, record, plan, ingress_session
                    )
                if self._now() >= plan.expires_at:
                    self._mark_import_cleanup(record)
                    self._write_locked(document)
                    return self._finish_import_ack(
                        document, record, plan, ingress_session
                    )
                try:
                    self._account_subject(plan.account_ref, plan.expected_generation)
                except GoogleOAuthSessionError:
                    self._mark_import_cleanup(record)
                    self._write_locked(document)
                    return self._finish_import_ack(
                        document, record, plan, ingress_session
                    )
                if any(
                    cast(dict[str, object], item)["account_ref"] == plan.account_ref
                    and cast(dict[str, object], item)["state"]
                    in {"persisting", "reconcile_required"}
                    for item in cast(list[object], document["transactions"])
                ) or any(
                    cast(dict[str, object], item)["id"] != plan.id
                    and cast(dict[str, object], item)["account_ref"] == plan.account_ref
                    and cast(dict[str, object], item)["state"]
                    in {"persisting", "ack_pending", "cleanup", "repair_required"}
                    for item in imports
                ):
                    raise GoogleOAuthSessionError("oauth.client_busy")
                ingress_failed = False
                try:
                    raw = self._read_ingress(plan, ingress_session)
                except GoogleOAuthSessionError:
                    ingress_failed = True
                if ingress_failed:
                    self._mark_import_cleanup(record)
                    self._write_locked(document)
                    ack_failed = False
                    try:
                        self._ack_ingress(
                            plan,
                            ingress_session,
                            plan.plan_digest,
                        )
                    except BaseException:
                        ack_failed = True
                    if not ack_failed:
                        self._terminalize_import(record, "expired")
                        self._write_locked(document)
                    raise GoogleOAuthSessionError("credential.upload_expired") from None
                client_data, client_digest = _client_document(raw)
                if state == "planned":
                    active = next(
                        (
                            cast(dict[str, object], item)
                            for item in cast(list[object], document["clients"])
                            if cast(dict[str, object], item)["account_ref"]
                            == plan.account_ref
                            and cast(dict[str, object], item)["state"] == "active"
                        ),
                        None,
                    )
                    vault_generation = (
                        cast(int, active["vault_generation"]) + 1
                        if active is not None
                        else 1
                    )
                    identity = generate_pretty_project_identity(
                        visible_names=(), reserved_project_ids=()
                    )
                    self._make_client_room(document)
                    record.update(
                        {
                            "state": "persisting",
                            "nonce": None,
                            "client_ref": "oauth-client-" + secrets.token_hex(16),
                            "client_digest": client_digest,
                            "display_name": identity.project_name,
                            "vault_generation": vault_generation,
                        }
                    )
                    self._write_locked(document)
                elif record["client_digest"] != client_digest:
                    raise GoogleOAuthSessionError("credential.upload_expired")
                vault_generation = cast(int, record["vault_generation"])
                try:
                    self._client_vault.store_projection(
                        self._client_vault_ref(plan.account_ref),
                        vault_generation,
                        raw,
                    )
                except CredentialVaultError:
                    if not self._client_projection_matches(
                        plan.account_ref,
                        vault_generation,
                        cast(str, record["client_digest"]),
                    ):
                        raise GoogleOAuthSessionError(
                            "oauth.client_write_failed"
                        ) from None
                if not self._client_projection_matches(
                    plan.account_ref,
                    vault_generation,
                    cast(str, record["client_digest"]),
                ):
                    raise GoogleOAuthSessionError("oauth.client_write_failed")
                self._finalize_client_projection(document, record)
                self._write_import_locked(document)
                return self._finish_import_ack(document, record, plan, ingress_session)
        finally:
            client_data.clear()
            _zero_bytes(raw)

    def reconcile_oauth_client_import(
        self,
        plan: GoogleOAuthClientImportPlanV1,
        ingress_session: object,
    ) -> GoogleOAuthClientImportReceiptV1:
        """Finish only an already durable client-import effect and ingress ack."""

        if not isinstance(plan, GoogleOAuthClientImportPlanV1):
            raise GoogleOAuthSessionError("oauth.import_plan_invalid")
        with self._state.locked():
            document = self._read_locked()
            record = self._find(cast(list[object], document["imports"]), "id", plan.id)
            if record is None or any(
                record.get(field) != getattr(plan, field)
                for field in (
                    "account_ref",
                    "expected_generation",
                    "expires_at",
                    "idempotency_key",
                    "plan_digest",
                )
            ):
                raise GoogleOAuthSessionError("oauth.import_plan_invalid")
            state = record.get("state")
            if state == "succeeded":
                self._ack_ingress(plan, ingress_session, plan.plan_digest)
                return self._import_receipt(record)
            if state in {"ack_pending", "cleanup"}:
                return self._finish_import_ack(document, record, plan, ingress_session)
            if state != "persisting" or not self._client_projection_matches(
                plan.account_ref,
                cast(int, record["vault_generation"]),
                cast(str, record["client_digest"]),
            ):
                raise GoogleOAuthSessionError("oauth.client_repair_required")
            self._finalize_client_projection(document, record)
            self._write_import_locked(document)
            return self._finish_import_ack(document, record, plan, ingress_session)

    def _read_ingress(
        self, plan: GoogleOAuthClientImportPlanV1, ingress_session: object
    ) -> bytearray:
        raw: object = None
        failed = False
        try:
            raw = self._secret_ingress.read_oauth_client(
                ingress_session,
                account_ref=plan.account_ref,
                expected_generation=plan.expected_generation,
                plan_digest=plan.plan_digest,
            )
        except BaseException:
            failed = True
        if failed or type(raw) is not bytearray:
            raise GoogleOAuthSessionError("credential.upload_expired") from None
        return raw

    def _finalize_client_projection(
        self, document: Mapping[str, object], record: dict[str, object]
    ) -> None:
        clients = cast(list[object], document["clients"])
        client_ref = cast(str, record["client_ref"])
        existing = self._find(clients, "id", client_ref)
        if existing is None:
            self._retire_client_records(
                document,
                account_ref=cast(str, record["account_ref"]),
                replacement_id=client_ref,
            )
            clients.append(
                {
                    "id": client_ref,
                    "account_ref": record["account_ref"],
                    "inventory_generation": record["expected_generation"],
                    "client_digest": record["client_digest"],
                    "display_name": record["display_name"],
                    "vault_generation": record["vault_generation"],
                    "state": "active",
                    "terminal_at": None,
                }
            )
        record["state"] = "ack_pending"
        record["terminal_at"] = None

    def _finish_import_ack(
        self,
        document: Mapping[str, object],
        record: dict[str, object],
        plan: GoogleOAuthClientImportPlanV1,
        ingress_session: object,
    ) -> GoogleOAuthClientImportReceiptV1:
        cleanup = record["state"] == "cleanup"
        self._ack_ingress(plan, ingress_session, plan.plan_digest)
        if cleanup:
            self._terminalize_import(record, "expired")
            self._write_import_locked(document)
            raise GoogleOAuthSessionError("oauth.import_plan_expired")
        record["state"] = "succeeded"
        record["terminal_at"] = self._now()
        self._write_import_locked(document)
        return self._import_receipt(record)

    def _write_import_locked(self, document: Mapping[str, object]) -> None:
        try:
            self._write_locked(document)
        except GoogleOAuthSessionError:
            raise
        except (HiveStateError, OSError):
            raise GoogleOAuthSessionError("oauth.client_write_failed") from None

    def _ack_ingress(
        self,
        plan: GoogleOAuthClientImportPlanV1,
        ingress_session: object,
        ack_operation_id: str,
    ) -> None:
        failed = False
        try:
            self._secret_ingress.acknowledge_oauth_client(
                ingress_session,
                account_ref=plan.account_ref,
                expected_generation=plan.expected_generation,
                plan_digest=plan.plan_digest,
                ack_operation_id=ack_operation_id,
            )
        except BaseException:
            failed = True
        if failed:
            raise GoogleOAuthSessionError("credential.upload_expired") from None

    def _terminalize_import(self, record: dict[str, object], state: str) -> None:
        record.update(
            {
                "state": state,
                "nonce": None,
                "client_ref": None,
                "client_digest": None,
                "display_name": None,
                "vault_generation": None,
                "terminal_at": self._now(),
            }
        )

    @staticmethod
    def _mark_import_cleanup(record: dict[str, object]) -> None:
        record.update(
            {
                "state": "cleanup",
                "nonce": None,
                "client_ref": None,
                "client_digest": None,
                "display_name": None,
                "vault_generation": None,
                "terminal_at": None,
            }
        )

    def _load_client(
        self, account_ref: str, record: Mapping[str, object]
    ) -> tuple[dict[str, object], str]:
        raw = bytearray()
        try:
            lease = self._client_vault.lease(
                self._client_vault_ref(account_ref),
                expected_generation=cast(int, record["vault_generation"]),
                ttl_seconds=30,
            )
            raw = bytearray(self._client_vault.consume_lease(lease))
            return _client_document(raw)
        except GoogleOAuthSessionError:
            raise
        except CredentialVaultError:
            raise GoogleOAuthSessionError("oauth.client_expired") from None
        finally:
            _zero_bytes(raw)

    @staticmethod
    def _profile(profile_id: object):
        if type(profile_id) is not GoogleOAuthProfileIdV1:
            raise GoogleOAuthSessionError("oauth.scope_mismatch")
        try:
            return resolve_google_oauth_profile_v1(
                profile_id,
                (
                    GoogleOAuthOperationV1.PROJECTS_SEARCH
                    if profile_id is GoogleOAuthProfileIdV1.INVENTORY_READONLY
                    else GoogleOAuthOperationV1.PROJECTS_CREATE
                ),
            )
        except Exception:
            raise GoogleOAuthSessionError("oauth.scope_mismatch") from None

    def begin_oauth_transaction(
        self,
        account_ref: str,
        *,
        oauth_client_ref: str,
        redirect_uri: str,
        scope_profile: GoogleOAuthProfileIdV1,
        expected_generation: int,
        idempotency_key: str,
        principal: str,
        ttl_seconds: int = MAX_OAUTH_TRANSACTION_SECONDS,
    ) -> GoogleOAuthTransactionV1:
        account_ref = self._ref(account_ref)
        oauth_client_ref = self._ref(oauth_client_ref)
        redirect_uri = self._redirect_uri(redirect_uri)
        expected_generation = self._generation(expected_generation)
        idempotency_key = self._ref(idempotency_key)
        principal = self._ref(principal)
        ttl_seconds = self._ttl(ttl_seconds, MAX_OAUTH_TRANSACTION_SECONDS)
        self._account_subject(account_ref, expected_generation)
        profile = self._profile(scope_profile)
        with self._state.locked():
            document = self._read_locked()
            clients = cast(list[object], document["clients"])
            client_record = self._find(clients, "id", oauth_client_ref)
            if (
                client_record is None
                or client_record.get("account_ref") != account_ref
                or client_record.get("state") != "active"
            ):
                raise GoogleOAuthSessionError("oauth.client_account_mismatch")
            if client_record.get("inventory_generation") != expected_generation:
                raise GoogleOAuthSessionError("oauth.generation_mismatch")
            client, client_digest = self._load_client(account_ref, client_record)
            if client_digest != client_record.get("client_digest"):
                raise GoogleOAuthSessionError("oauth.client_expired")
            now = self._now()
            expires_at = now + ttl_seconds
            transaction_prefix = (
                "oauth-txn-"
                + sha256(
                    ("google.oauth-begin\0" + idempotency_key).encode("utf-8")
                ).hexdigest()[:32]
                + "-"
            )
            transaction_id = (
                transaction_prefix
                + sha256(
                    ("google.oauth-principal\0" + principal).encode("utf-8")
                ).hexdigest()[:32]
            )
            transactions = cast(list[object], document["transactions"])
            prior_matches = [
                cast(dict[str, object], item)
                for item in transactions
                if cast(str, cast(dict[str, object], item)["id"]).startswith(
                    transaction_prefix
                )
            ]
            if prior_matches:
                if len(prior_matches) != 1:
                    raise GoogleOAuthSessionError("oauth.control_unavailable")
                prior = prior_matches[0]
                if (
                    any(
                        prior[field] != expected
                        for field, expected in (
                            ("id", transaction_id),
                            ("account_ref", account_ref),
                            ("oauth_client_ref", oauth_client_ref),
                            ("client_digest", client_digest),
                            (
                                "client_vault_generation",
                                client_record["vault_generation"],
                            ),
                            ("redirect_uri", redirect_uri),
                            ("scope_profile", profile.profile_id.value),
                            ("scope_fingerprint", profile.scope_fingerprint),
                            ("inventory_generation", expected_generation),
                        )
                    )
                    or prior["state"] != "pending"
                ):
                    raise GoogleOAuthSessionError("control.idempotency_conflict")
                return GoogleOAuthTransactionV1(
                    transaction_id,
                    account_ref,
                    self._authorization_url(
                        client,
                        redirect_uri=redirect_uri,
                        profile_id=profile.profile_id,
                        state=cast(str, prior["state_token"]),
                        verifier=cast(str, prior["pkce_verifier"]),
                    ),
                    cast(float, prior["expires_at"]),
                    expected_generation,
                )
            state = secrets.token_urlsafe(32)
            verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
            authorization_url = self._authorization_url(
                client,
                redirect_uri=redirect_uri,
                profile_id=profile.profile_id,
                state=state,
                verifier=verifier,
            )
            if any(
                cast(dict[str, object], item)["account_ref"] == account_ref
                and cast(dict[str, object], item)["state"] == "repair_required"
                for item in transactions
            ):
                raise GoogleOAuthSessionError("oauth.client_repair_required")
            self._make_room(
                transactions,
                {
                    "pending",
                    "completing",
                    "persisting",
                    "reconcile_required",
                    "repair_required",
                },
            )
            transactions.append(
                {
                    "id": transaction_id,
                    "account_ref": account_ref,
                    "oauth_client_ref": oauth_client_ref,
                    "client_digest": client_digest,
                    "client_vault_generation": client_record["vault_generation"],
                    "pkce_verifier": verifier,
                    "redirect_uri": redirect_uri,
                    "scope_profile": profile.profile_id.value,
                    "scope_fingerprint": profile.scope_fingerprint,
                    "state_token": state,
                    "state_digest": self._digest("google.oauth-state", state),
                    "inventory_generation": expected_generation,
                    "expires_at": expires_at,
                    "state": "pending",
                    "token_operation_id": None,
                    "authorization_code_digest": None,
                    "effect_subject_id": None,
                    "completion_owner": None,
                    "completion_lease_expires_at": None,
                    "terminal_at": None,
                }
            )
            self._write_locked(document)
        return GoogleOAuthTransactionV1(
            transaction_id,
            account_ref,
            authorization_url,
            expires_at,
            expected_generation,
        )

    @staticmethod
    def _authorization_url(
        client: Mapping[str, object],
        *,
        redirect_uri: str,
        profile_id: GoogleOAuthProfileIdV1,
        state: str,
        verifier: str,
    ) -> str:
        challenge = (
            base64.urlsafe_b64encode(sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode()
        )
        return (
            str(client["auth_uri"])
            + "?"
            + urllib.parse.urlencode(
                {
                    "access_type": "offline",
                    "client_id": str(client["client_id"]),
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "prompt": "consent",
                    "redirect_uri": redirect_uri,
                    "response_type": "code",
                    "scope": " ".join(google_oauth_scope_values_v1(profile_id)),
                    "state": state,
                }
            )
        )

    @staticmethod
    def _inventory_authorization_url(
        client: Mapping[str, object],
        *,
        redirect_uri: str,
        state: str,
        verifier: str,
        nonce: str,
    ) -> str:
        challenge = (
            base64.urlsafe_b64encode(sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        return (
            str(client["auth_uri"])
            + "?"
            + urllib.parse.urlencode(
                {
                    "access_type": "offline",
                    "client_id": str(client["client_id"]),
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "nonce": nonce,
                    "prompt": "consent",
                    "redirect_uri": redirect_uri,
                    "response_type": "code",
                    "scope": " ".join(
                        google_oauth_scope_values_v1(
                            GoogleOAuthProfileIdV1.INVENTORY_READONLY
                        )
                    ),
                    "state": state,
                }
            )
        )

    def _inventory_account_login(
        self, account_ref: str, expected_generation: int
    ) -> str:
        try:
            snapshot = self._manager._snapshot_for_internal_use()
            if snapshot.generation != expected_generation:
                raise GoogleOAuthSessionError("oauth.generation_mismatch")
            account = snapshot.by_account_ref[account_ref]
            login_email = account.login_email
            subject_id = account.subject_id
        except GoogleOAuthSessionError:
            raise
        except (GoogleAccountInventoryError, KeyError, AttributeError):
            raise GoogleOAuthSessionError("oauth.account_mismatch") from None
        if (
            type(login_email) is not str
            or not login_email
            or (
                subject_id is not None
                and (type(subject_id) is not str or not subject_id)
            )
        ):
            raise GoogleOAuthSessionError("oauth.account_mismatch")
        return login_email

    def _inventory_active_client(
        self,
        document: Mapping[str, object],
        *,
        account_ref: str,
        oauth_client_ref: str,
        expected_generation: int,
    ) -> tuple[dict[str, object], dict[str, object], str]:
        matches = [
            cast(dict[str, object], item)
            for item in cast(list[object], document["clients"])
            if cast(dict[str, object], item)["id"] == oauth_client_ref
            and cast(dict[str, object], item)["account_ref"] == account_ref
            and cast(dict[str, object], item)["state"] == "active"
            and cast(dict[str, object], item)["inventory_generation"]
            == expected_generation
        ]
        if len(matches) != 1:
            raise GoogleOAuthSessionError("oauth.client_expired")
        client_record = matches[0]
        client, fingerprint = self._load_client(account_ref, client_record)
        if fingerprint != client_record["client_digest"]:
            client.clear()
            raise GoogleOAuthSessionError("oauth.client_expired")
        return client_record, client, fingerprint

    def _inventory_authorization_capable(self) -> _InventoryReadonlyIdTokenVerifierPort:
        verifier = self._inventory_id_token_verifier
        if (
            verifier is None
            or not _required_callable(verifier, "verify_inventory_readonly_id_token")
            or not _required_callable(
                self._inventory_code_exchange, "exchange_inventory_readonly"
            )
        ):
            raise GoogleOAuthSessionError("oauth.inventory_unavailable")
        return verifier

    @classmethod
    def _from_inventory_registry(
        cls, *, registry, manager
    ) -> GoogleOAuthControlService:
        """Private construction of the OAuth owner without generic/admin storage."""

        from .google_inventory_desktop_client_registry import (
            _InventoryDesktopClientRegistryStoreV1,
        )

        if (
            type(registry) is not _InventoryDesktopClientRegistryStoreV1
            or type(manager) is not GoogleAccountInventoryManager
        ):
            raise GoogleOAuthSessionError("oauth.inventory_unavailable")
        service = cls.__new__(cls)
        service._manager = manager
        service._inventory_registry = registry
        service._inventory_pending_handle = None
        service._inventory_transaction_lock = threading.RLock()
        service._inventory_code_exchange = _GoogleInventoryReadonlyCodeExchangeV1()
        service._inventory_id_token_verifier = (
            _GoogleInventoryReadonlyIdTokenVerifierV1()
        )
        service._clock = time.time
        return service

    def _inventory_bound_selection(self):
        """Resolve exactly one registry-bound canonical account, never a caller choice."""

        try:
            registry = self._inventory_registry.load()
            snapshot = self._manager._snapshot_for_internal_use()
            if registry is None:
                raise ValueError
            eligible = [
                (record, snapshot.by_account_ref[record.account_ref])
                for record in registry.records
                if record.account_ref in snapshot.by_account_ref
            ]
            if len(eligible) != 1:
                raise ValueError
            record, account = eligible[0]
            return (
                registry.registry_generation,
                registry.fingerprint,
                record,
                account,
                snapshot.generation,
            )
        except Exception:
            raise GoogleOAuthSessionError("oauth.inventory_unavailable") from None

    def _begin_inventory_readonly_authorization(
        self, *, redirect_uri: str
    ) -> _InventoryReadonlyAuthorizationHandleV1:
        """Create State, PKCE-S256 and OIDC nonce only in a private RAM handle."""

        handle = None
        try:
            with self._inventory_transaction_lock:
                if self._inventory_pending_handle is not None:
                    raise GoogleOAuthSessionError(
                        "oauth.inventory_reauthorization_required"
                    )
                self._inventory_authorization_capable()
                redirect_uri = self._redirect_uri(redirect_uri)
                generation, fingerprint, record, account, inventory_generation = (
                    self._inventory_bound_selection()
                )
                handle = _InventoryReadonlyAuthorizationHandleV1(
                    registry_generation=generation,
                    registry_fingerprint=fingerprint,
                    record=record,
                    account=account,
                    inventory_generation=inventory_generation,
                    redirect_uri=redirect_uri,
                    expires_at=self._now() + MAX_OAUTH_TRANSACTION_SECONDS,
                )
                handle.state.extend(secrets.token_urlsafe(32).encode("ascii"))
                handle.verifier.extend(secrets.token_urlsafe(32).encode("ascii"))
                handle.nonce.extend(secrets.token_urlsafe(32).encode("ascii"))
                handle.authorization_url.extend(
                    self._inventory_authorization_url(
                        {"client_id": record.client_id, "auth_uri": record.auth_uri},
                        redirect_uri=redirect_uri,
                        state=handle.state.decode("ascii"),
                        verifier=handle.verifier.decode("ascii"),
                        nonce=handle.nonce.decode("ascii"),
                    ).encode("ascii")
                )
                self._inventory_pending_handle = handle
                return handle
        except BaseException:
            if handle is not None:
                handle.clear()
            raise

    def _complete_inventory_readonly_authorization(
        self, handle
    ) -> _InventoryReadonlyAuthorizationEffectV1:
        """Consume the private callback once and reattest both registry bindings."""

        result = None
        verified = None
        refresh = None
        try:
            with self._inventory_transaction_lock:
                if (
                    type(handle) is not _InventoryReadonlyAuthorizationHandleV1
                    or self._inventory_pending_handle is not handle
                ):
                    raise GoogleOAuthSessionError(
                        "oauth.inventory_reauthorization_required"
                    )
                self._inventory_pending_handle = None
            if (
                self._now() >= handle.expires_at
                or not 1 <= len(handle.code) <= 8192
                or not secrets.compare_digest(handle.state, handle.callback_state)
            ):
                raise GoogleOAuthSessionError(
                    "oauth.inventory_reauthorization_required"
                )
            generation, fingerprint, record, account, inventory_generation = (
                self._inventory_bound_selection()
            )
            if (
                generation != handle.registry_generation
                or record != handle.record
                or fingerprint != handle.registry_fingerprint
                or inventory_generation != handle.inventory_generation
                or account != handle.account
            ):
                raise GoogleOAuthSessionError("oauth.client_expired")
            verifier = self._inventory_authorization_capable()
            result = self._inventory_code_exchange.exchange_inventory_readonly(
                {"client_id": record.client_id, "token_uri": record.token_uri},
                code=handle.code.decode("ascii"),
                redirect_uri=handle.redirect_uri,
                pkce_verifier=handle.verifier.decode("ascii"),
            )
            if type(result) is not _InventoryReadonlyCodeExchangeV1:
                raise GoogleOAuthSessionError("oauth.exchange_failed")
            verified = verifier.verify_inventory_readonly_id_token(
                result.id_token,
                expected_nonce=handle.nonce,
                client_id=record.client_id,
                login_email=account.login_email,
                now=self._now(),
            )
            if type(
                verified
            ) is not _InventoryReadonlyVerifiedIdTokenV1 or not secrets.compare_digest(
                verified.nonce, handle.nonce
            ):
                raise GoogleOAuthSessionError("oauth.id_token_invalid")
            if account.subject_id is not None and not secrets.compare_digest(
                account.subject_id, verified.subject_id
            ):
                raise GoogleOAuthSessionError("oauth.subject_mismatch")
            if self._inventory_bound_selection() != (
                generation,
                fingerprint,
                record,
                account,
                inventory_generation,
            ):
                raise GoogleOAuthSessionError("oauth.client_expired")
            refresh = result.refresh_token
            result.refresh_token = bytearray()
            effect = _InventoryReadonlyAuthorizationEffectV1(
                account_ref=record.account_ref,
                subject_id=verified.subject_id,
                inventory_generation=inventory_generation,
                oauth_client_fingerprint=record.fingerprint,
                scope_fingerprint=resolve_google_oauth_profile_v1(
                    GoogleOAuthProfileIdV1.INVENTORY_READONLY,
                    GoogleOAuthOperationV1.PROJECTS_SEARCH,
                ).scope_fingerprint,
                refresh_token=refresh,
            )
            refresh = None
            return effect
        except (GoogleOAuthSessionError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise GoogleOAuthSessionError("oauth.inventory_unavailable") from None
        finally:
            if refresh is not None:
                _zero_bytes(refresh)
            if type(verified) is _InventoryReadonlyVerifiedIdTokenV1:
                verified.clear()
            if type(result) is _InventoryReadonlyCodeExchangeV1:
                result.clear()
            if type(handle) is _InventoryReadonlyAuthorizationHandleV1:
                handle.clear()

    def _for_test_legacy_begin_inventory_readonly_authorization(
        self,
        account_ref: str,
        *,
        oauth_client_ref: str,
        redirect_uri: str,
        expected_generation: int,
        idempotency_key: str,
        principal: str,
        ttl_seconds: int = MAX_OAUTH_TRANSACTION_SECONDS,
    ) -> _InventoryReadonlyAuthorizationTransactionV1:
        """Begin the only fixed-profile Inventory Readonly OAuth flow.

        The raw OIDC nonce stays only in this process as a scrubbable capability.
        A process crash therefore loses a pending browser interaction safely and
        requires re-authorization; durable state contains only its digest.
        """

        account_ref = self._ref(account_ref)
        oauth_client_ref = self._ref(oauth_client_ref)
        redirect_uri = self._redirect_uri(redirect_uri)
        expected_generation = self._generation(expected_generation)
        idempotency_key = self._ref(idempotency_key)
        principal = self._ref(principal)
        ttl_seconds = self._ttl(ttl_seconds, MAX_OAUTH_TRANSACTION_SECONDS)
        self._inventory_authorization_capable()
        self._inventory_account_login(account_ref, expected_generation)
        nonce_bytes = bytearray(secrets.token_bytes(32))
        nonce = ""
        client: dict[str, object] = {}
        try:
            nonce = base64.urlsafe_b64encode(nonce_bytes).rstrip(b"=").decode("ascii")
            _zero_bytes(nonce_bytes)
            nonce_bytes = bytearray(nonce.encode("ascii"))
            transaction_prefix = (
                "inventory-oauth-"
                + sha256(
                    ("google.inventory-oauth\0" + idempotency_key).encode("utf-8")
                ).hexdigest()[:32]
                + "-"
            )
            transaction_id = (
                transaction_prefix
                + sha256(
                    ("google.inventory-oauth-principal\0" + principal).encode("utf-8")
                ).hexdigest()[:32]
            )
            state = secrets.token_urlsafe(32)
            verifier = (
                base64.urlsafe_b64encode(secrets.token_bytes(32))
                .rstrip(b"=")
                .decode("ascii")
            )
            now = self._now()
            expires_at = now + ttl_seconds
            with self._state.locked():
                control = self._read_locked()
                inventory = self._read_inventory_authorization_locked()
                prior = [
                    cast(dict[str, object], item)
                    for item in cast(list[object], inventory["transactions"])
                    if cast(str, cast(dict[str, object], item)["id"]).startswith(
                        transaction_prefix
                    )
                ]
                if prior:
                    raise GoogleOAuthSessionError(
                        "oauth.inventory_reauthorization_required"
                    )
                client_record, client, client_digest = self._inventory_active_client(
                    control,
                    account_ref=account_ref,
                    oauth_client_ref=oauth_client_ref,
                    expected_generation=expected_generation,
                )
                if len(self._inventory_pending_nonces) >= _MAX_CONTROL_RECORDS:
                    raise GoogleOAuthSessionError("oauth.inventory_unavailable")
                authorization_url = self._inventory_authorization_url(
                    client,
                    redirect_uri=redirect_uri,
                    state=state,
                    verifier=verifier,
                    nonce=nonce,
                )
                transactions = cast(list[object], inventory["transactions"])
                self._make_room(transactions, {"pending", "exchanging", "verified"})
                transactions.append(
                    {
                        "id": transaction_id,
                        "account_ref": account_ref,
                        "oauth_client_ref": oauth_client_ref,
                        "client_digest": client_digest,
                        "client_vault_generation": client_record["vault_generation"],
                        "pkce_verifier": verifier,
                        "redirect_uri": redirect_uri,
                        "scope_fingerprint": resolve_google_oauth_profile_v1(
                            GoogleOAuthProfileIdV1.INVENTORY_READONLY,
                            GoogleOAuthOperationV1.PROJECTS_SEARCH,
                        ).scope_fingerprint,
                        "state_token": state,
                        "state_digest": self._digest("google.oauth-state", state),
                        "nonce_digest": self._digest("google.oidc-nonce", nonce),
                        "inventory_generation": expected_generation,
                        "expires_at": expires_at,
                        "state": "pending",
                        "authorization_code_digest": None,
                        "effect_subject_digest": None,
                        "terminal_at": None,
                    }
                )
                self._write_inventory_authorization_locked(inventory)
                self._inventory_pending_nonces[transaction_id] = nonce_bytes
                nonce_bytes = bytearray()
            return _InventoryReadonlyAuthorizationTransactionV1(
                transaction_id,
                authorization_url,
                expires_at,
                expected_generation,
            )
        finally:
            _zero_bytes(nonce_bytes)
            client.clear()
            nonce = ""

    def _for_test_legacy_complete_inventory_readonly_authorization(
        self,
        transaction_id: str,
        *,
        code: str,
        account_ref: str,
        redirect_uri: str,
        expected_generation: int,
        state: str,
    ) -> _InventoryReadonlyAuthorizationEffectV1:
        """Verify one fixed-profile callback and return a one-shot RAM-only effect."""

        transaction_id = self._ref(transaction_id)
        account_ref = self._ref(account_ref)
        redirect_uri = self._redirect_uri(redirect_uri)
        expected_generation = self._generation(expected_generation)
        if (
            type(code) is not str
            or not 1 <= len(code) <= 8192
            or type(state) is not str
            or not 1 <= len(state) <= 512
        ):
            raise GoogleOAuthSessionError("oauth.request_invalid")
        verifier_port = self._inventory_authorization_capable()
        client: dict[str, object] = {}
        result: _InventoryReadonlyCodeExchangeV1 | None = None
        verified: _InventoryReadonlyVerifiedIdTokenV1 | None = None
        nonce_bytes: bytearray | None = None
        refresh_token: bytearray | None = None
        try:
            with self._state.locked():
                control = self._read_locked()
                inventory = self._read_inventory_authorization_locked()
                record = self._find(
                    cast(list[object], inventory["transactions"]), "id", transaction_id
                )
                if record is None or record["state"] != "pending":
                    raise GoogleOAuthSessionError(
                        "oauth.inventory_reauthorization_required"
                    )
                mismatch = (
                    record["account_ref"] != account_ref
                    or record["redirect_uri"] != redirect_uri
                    or record["inventory_generation"] != expected_generation
                    or self._now() >= cast(float, record["expires_at"])
                    or not secrets.compare_digest(
                        cast(str, record["state_digest"]),
                        self._digest("google.oauth-state", state),
                    )
                )
                nonce_bytes = self._inventory_pending_nonces.pop(transaction_id, None)
                if mismatch or nonce_bytes is None:
                    record.update(
                        {
                            "pkce_verifier": None,
                            "state_token": None,
                            "state": "expired" if mismatch else "failed",
                            "terminal_at": self._now(),
                        }
                    )
                    self._write_inventory_authorization_locked(inventory)
                    raise GoogleOAuthSessionError(
                        "oauth.inventory_reauthorization_required"
                    )
                client_record, client, client_digest = self._inventory_active_client(
                    control,
                    account_ref=account_ref,
                    oauth_client_ref=cast(str, record["oauth_client_ref"]),
                    expected_generation=expected_generation,
                )
                if (
                    client_digest != record["client_digest"]
                    or client_record["vault_generation"]
                    != record["client_vault_generation"]
                ):
                    raise GoogleOAuthSessionError("oauth.client_expired")
                pkce_verifier = cast(str, record["pkce_verifier"])
                record.update(
                    {
                        "pkce_verifier": None,
                        "state_token": None,
                        "state": "exchanging",
                        "authorization_code_digest": self._digest(
                            "google.oauth-code", code
                        ),
                    }
                )
                self._write_inventory_authorization_locked(inventory)
            try:
                result = self._inventory_code_exchange.exchange_inventory_readonly(
                    client,
                    code=code,
                    redirect_uri=redirect_uri,
                    pkce_verifier=pkce_verifier,
                )
            except GoogleOAuthSessionError:
                raise
            except Exception:
                raise GoogleOAuthSessionError("oauth.exchange_failed") from None
            if type(result) is not _InventoryReadonlyCodeExchangeV1:
                raise GoogleOAuthSessionError("oauth.exchange_failed")
            login_email = self._inventory_account_login(
                account_ref, expected_generation
            )
            try:
                verified = verifier_port.verify_inventory_readonly_id_token(
                    result.id_token,
                    expected_nonce=nonce_bytes,
                    client_id=cast(str, client["client_id"]),
                    login_email=login_email,
                    now=self._now(),
                )
            except GoogleOAuthSessionError:
                raise
            except Exception:
                raise GoogleOAuthSessionError("oauth.id_token_invalid") from None
            if type(verified) is not _InventoryReadonlyVerifiedIdTokenV1:
                raise GoogleOAuthSessionError("oauth.id_token_invalid")
            nonce_text = ""
            try:
                nonce_text = verified.nonce.decode("ascii")
            except UnicodeError:
                raise GoogleOAuthSessionError("oauth.id_token_invalid") from None
            if _URLSAFE.fullmatch(nonce_text) is None or not secrets.compare_digest(
                cast(str, record["nonce_digest"]),
                self._digest("google.oidc-nonce", nonce_text),
            ):
                raise GoogleOAuthSessionError("oauth.id_token_invalid")
            expected_subject = self._account_subject(account_ref, expected_generation)
            if expected_subject is not None and not secrets.compare_digest(
                expected_subject, verified.subject_id
            ):
                raise GoogleOAuthSessionError("oauth.subject_mismatch")
            with self._state.locked():
                inventory = self._read_inventory_authorization_locked()
                record = self._find(
                    cast(list[object], inventory["transactions"]), "id", transaction_id
                )
                if record is None or record["state"] != "exchanging":
                    raise GoogleOAuthSessionError(
                        "oauth.inventory_reauthorization_required"
                    )
                record.update(
                    {
                        "state": "verified",
                        "effect_subject_digest": self._digest(
                            "google.oauth-subject", verified.subject_id
                        ),
                    }
                )
                self._write_inventory_authorization_locked(inventory)
            refresh_token = result.refresh_token
            result.refresh_token = bytearray()
            return _InventoryReadonlyAuthorizationEffectV1(
                account_ref=account_ref,
                subject_id=verified.subject_id,
                inventory_generation=expected_generation,
                oauth_client_fingerprint=cast(str, record["client_digest"]),
                scope_fingerprint=cast(str, record["scope_fingerprint"]),
                refresh_token=refresh_token,
            )
        except BaseException:
            if refresh_token is not None:
                _zero_bytes(refresh_token)
            refresh_token = None
            raise
        finally:
            _zero_bytes(nonce_bytes)
            nonce_bytes = None
            if verified is not None:
                verified.clear()
            if result is not None:
                result.clear()
            client.clear()
            code = ""
            state = ""

    def complete_oauth_transaction(
        self,
        transaction_id: str,
        *,
        code: str,
        account_ref: str,
        redirect_uri: str,
        expected_generation: int,
        state: str,
    ) -> GoogleOAuthSessionReceipt:
        transaction_id = self._ref(transaction_id)
        account_ref = self._ref(account_ref)
        redirect_uri = self._redirect_uri(redirect_uri)
        expected_generation = self._generation(expected_generation)
        if (
            type(code) is not str
            or not 1 <= len(code) <= 8192
            or type(state) is not str
            or not 1 <= len(state) <= 512
        ):
            raise GoogleOAuthSessionError("oauth.request_invalid")
        client: dict[str, object] = {}
        result: GoogleOAuthCodeExchangeV1 | None = None
        verifier = ""
        owns_completion = False
        completion_owner = "oauth-owner-" + secrets.token_hex(16)
        code_digest = self._digest("google.oauth-code", code)
        try:
            with self._state.locked():
                document = self._read_locked()
                record = self._find(
                    cast(list[object], document["transactions"]),
                    "id",
                    transaction_id,
                )
                if record is None:
                    raise GoogleOAuthSessionError("oauth.transaction_expired")
                mismatch = self._callback_mismatch(
                    record,
                    account_ref=account_ref,
                    redirect_uri=redirect_uri,
                    expected_generation=expected_generation,
                    state=state,
                    check_expiry=record["state"]
                    not in {"persisting", "reconcile_required", "succeeded"},
                )
                stored_code_digest = record["authorization_code_digest"]
                if stored_code_digest is not None and not secrets.compare_digest(
                    cast(str, stored_code_digest), code_digest
                ):
                    mismatch = "oauth.transaction_expired"
                if record["state"] in {
                    "persisting",
                    "reconcile_required",
                    "succeeded",
                }:
                    if mismatch is not None:
                        raise GoogleOAuthSessionError(mismatch)
                    if record["state"] == "succeeded":
                        return GoogleOAuthSessionReceipt(account_ref, True, True)
                    receipt = self._lookup_token_receipt(record)
                    if receipt is None:
                        self._mark_transaction_terminal(record, "failed")
                        self._write_locked(document)
                        raise GoogleOAuthSessionError("oauth.token_write_failed")
                    self._validate_token_receipt(record, receipt)
                    if record["effect_subject_id"] is None:
                        record["effect_subject_id"] = receipt.subject_id
                    if record["authorization_code_digest"] is None:
                        record["authorization_code_digest"] = code_digest
                    self._mark_transaction_terminal(record, "succeeded")
                    self._write_locked(document)
                    return GoogleOAuthSessionReceipt(account_ref, True, True)
                if record["state"] == "completing":
                    if self._now() >= cast(
                        float, record["completion_lease_expires_at"]
                    ):
                        self._mark_transaction_terminal(record, "failed")
                        self._write_locked(document)
                        raise GoogleOAuthSessionError("oauth.token_write_failed")
                    if mismatch is not None:
                        raise GoogleOAuthSessionError(mismatch)
                    raise GoogleOAuthSessionError("oauth.transaction_expired")
                if record["state"] != "pending":
                    raise GoogleOAuthSessionError("oauth.transaction_expired")
                if mismatch is not None:
                    self._mark_transaction_terminal(record, "expired")
                    self._write_locked(document)
                    raise GoogleOAuthSessionError(mismatch)
                self._account_subject(account_ref, expected_generation)
                client_record = self._bound_active_client(document, record)
                record.update(
                    {
                        "state": "completing",
                        "authorization_code_digest": code_digest,
                        "completion_owner": completion_owner,
                        "completion_lease_expires_at": record["expires_at"],
                    }
                )
                self._write_locked(document)
                owns_completion = True
                verifier = cast(str, record["pkce_verifier"])
            client, client_digest = self._load_client(account_ref, client_record)
            if client_digest != record["client_digest"]:
                raise GoogleOAuthSessionError("oauth.client_expired")
            try:
                result = self._code_exchange.exchange(
                    client,
                    code=code,
                    redirect_uri=redirect_uri,
                    pkce_verifier=verifier,
                )
            except GoogleOAuthSessionError:
                raise
            except Exception:
                raise GoogleOAuthSessionError("oauth.exchange_failed") from None
            if not isinstance(result, GoogleOAuthCodeExchangeV1):
                raise GoogleOAuthSessionError("oauth.exchange_failed")
            expected_subject = self._account_subject(account_ref, expected_generation)
            if expected_subject is not None and result.subject_id != expected_subject:
                raise GoogleOAuthSessionError("oauth.subject_mismatch")
            with self._state.locked():
                document = self._read_locked()
                record = self._find(
                    cast(list[object], document["transactions"]),
                    "id",
                    transaction_id,
                )
                if (
                    record is None
                    or record["state"] != "completing"
                    or record["completion_owner"] != completion_owner
                ):
                    raise GoogleOAuthSessionError("oauth.transaction_expired")
                if self._now() >= cast(float, record["expires_at"]):
                    self._mark_transaction_terminal(record, "expired")
                    self._write_locked(document)
                    raise GoogleOAuthSessionError("oauth.transaction_expired")
                self._account_subject(account_ref, expected_generation)
                self._bound_active_client(document, record)
                operation_id = self._digest(
                    "google.oauth-token-write",
                    transaction_id,
                    account_ref,
                    client_digest,
                    record["scope_fingerprint"],
                    result.subject_id,
                )
                record.update(
                    {
                        "state": "persisting",
                        "pkce_verifier": None,
                        "state_token": None,
                        "token_operation_id": operation_id,
                        "effect_subject_id": result.subject_id,
                        "completion_owner": None,
                        "completion_lease_expires_at": None,
                    }
                )
                self._write_locked(document)
                owns_completion = False
            try:
                token_receipt = self._token_writer.store_refresh_token(
                    operation_id,
                    account_ref=account_ref,
                    subject_id=result.subject_id,
                    oauth_client_fingerprint=client_digest,
                    scope_profile=GoogleOAuthProfileIdV1(
                        cast(str, record["scope_profile"])
                    ),
                    scope_fingerprint=cast(str, record["scope_fingerprint"]),
                    refresh_token=result.refresh_token,
                )
            except GoogleOAuthSessionError:
                raise
            except Exception:
                raise GoogleOAuthSessionError("oauth.token_write_failed") from None
            with self._state.locked():
                document = self._read_locked()
                record = self._find(
                    cast(list[object], document["transactions"]),
                    "id",
                    transaction_id,
                )
                if record is None or record["state"] != "persisting":
                    raise GoogleOAuthSessionError("oauth.transaction_expired")
                self._validate_token_receipt(record, token_receipt)
                self._rebase_bound_client(document, record, token_receipt.subject_id)
                self._mark_transaction_terminal(record, "succeeded")
                try:
                    self._write_locked(document)
                except (HiveStateError, OSError):
                    raise GoogleOAuthSessionError("oauth.token_write_failed") from None
        except BaseException:
            if owns_completion:
                try:
                    self._terminalize(
                        transaction_id, "failed", completion_owner=completion_owner
                    )
                except BaseException:
                    pass
            raise
        finally:
            if result is not None:
                _zero_bytes(result.refresh_token)
            client.clear()
            code = ""
            verifier = ""
        return GoogleOAuthSessionReceipt(account_ref, True, True)

    def reconcile_oauth_transaction(
        self,
        transaction_id: str,
        *,
        account_ref: str,
        redirect_uri: str,
        expected_generation: int,
        state: str,
    ) -> GoogleOAuthSessionReceipt:
        """Return only a receipt proven by an existing durable token effect."""

        transaction_id = self._ref(transaction_id)
        account_ref = self._ref(account_ref)
        redirect_uri = self._redirect_uri(redirect_uri)
        expected_generation = self._generation(expected_generation)
        if type(state) is not str or not 1 <= len(state) <= 512:
            raise GoogleOAuthSessionError("oauth.request_invalid")
        with self._state.locked():
            document = self._read_locked()
            record = self._find(
                cast(list[object], document["transactions"]),
                "id",
                transaction_id,
            )
            if record is None:
                raise GoogleOAuthSessionError("oauth.transaction_expired")
            mismatch = self._callback_mismatch(
                record,
                account_ref=account_ref,
                redirect_uri=redirect_uri,
                expected_generation=expected_generation,
                state=state,
                check_expiry=False,
            )
            if mismatch is not None:
                raise GoogleOAuthSessionError(mismatch)
            if record["state"] == "succeeded":
                return GoogleOAuthSessionReceipt(account_ref, True, True)
            if record["state"] not in {"persisting", "reconcile_required"}:
                raise GoogleOAuthSessionError("oauth.transaction_expired")
            receipt = self._lookup_token_receipt(record)
            if receipt is None:
                raise GoogleOAuthSessionError("oauth.token_write_failed")
            self._validate_token_receipt(record, receipt)
            if record["effect_subject_id"] is None:
                record["effect_subject_id"] = receipt.subject_id
            self._rebase_bound_client(document, record, receipt.subject_id)
            self._mark_transaction_terminal(record, "succeeded")
            self._write_locked(document)
            return GoogleOAuthSessionReceipt(account_ref, True, True)

    def _callback_mismatch(
        self,
        record: Mapping[str, object],
        *,
        account_ref: str,
        redirect_uri: str,
        expected_generation: int,
        state: str,
        check_expiry: bool = True,
    ) -> str | None:
        if check_expiry and self._now() >= cast(float, record["expires_at"]):
            return "oauth.transaction_expired"
        if record["account_ref"] != account_ref:
            return "oauth.account_mismatch"
        if record["inventory_generation"] != expected_generation:
            return "oauth.generation_mismatch"
        if record["redirect_uri"] != redirect_uri:
            return "oauth.redirect_mismatch"
        observed_digest = self._digest("google.oauth-state", state)
        if not secrets.compare_digest(
            cast(str, record["state_digest"]), observed_digest
        ):
            return "oauth.state_mismatch"
        return None

    @staticmethod
    def _bound_active_client(
        document: Mapping[str, object], record: Mapping[str, object]
    ) -> dict[str, object]:
        clients = cast(list[object], document["clients"])
        matches = [
            cast(dict[str, object], item)
            for item in clients
            if cast(dict[str, object], item)["id"] == record["oauth_client_ref"]
            and cast(dict[str, object], item)["state"] == "active"
            and cast(dict[str, object], item)["account_ref"] == record["account_ref"]
            and cast(dict[str, object], item)["client_digest"]
            == record["client_digest"]
            and cast(dict[str, object], item)["vault_generation"]
            == record["client_vault_generation"]
        ]
        if len(matches) != 1:
            raise GoogleOAuthSessionError("oauth.client_expired")
        return matches[0]

    def _rebase_bound_client(
        self,
        document: Mapping[str, object],
        record: Mapping[str, object],
        subject_id: str,
    ) -> None:
        client_record = self._bound_active_client(document, record)
        try:
            snapshot = self._manager._snapshot_for_internal_use()
            account = snapshot.by_account_ref[cast(str, record["account_ref"])]
        except (GoogleAccountInventoryError, KeyError, AttributeError):
            raise GoogleOAuthSessionError("oauth.account_mismatch") from None
        if account.subject_id != subject_id:
            raise GoogleOAuthSessionError("oauth.subject_mismatch")
        client_record["inventory_generation"] = snapshot.generation

    def _lookup_token_receipt(
        self, record: Mapping[str, object]
    ) -> GoogleOAuthTokenWriteReceiptV1 | None:
        try:
            scope_profile = GoogleOAuthProfileIdV1(cast(str, record["scope_profile"]))
            return self._token_writer.lookup_refresh_token_receipt(
                cast(str, record["token_operation_id"]),
                account_ref=cast(str, record["account_ref"]),
                scope_profile=scope_profile,
                scope_fingerprint=cast(str, record["scope_fingerprint"]),
            )
        except GoogleOAuthSessionError:
            raise
        except Exception:
            raise GoogleOAuthSessionError("oauth.token_write_failed") from None

    def _validate_token_receipt(
        self, record: Mapping[str, object], receipt: object
    ) -> None:
        effect_subject_id = record["effect_subject_id"]
        try:
            scope_profile = GoogleOAuthProfileIdV1(cast(str, record["scope_profile"]))
        except (TypeError, ValueError):
            raise GoogleOAuthSessionError("oauth.token_write_failed") from None
        if not isinstance(receipt, GoogleOAuthTokenWriteReceiptV1) or any(
            (
                receipt.operation_id != record["token_operation_id"],
                receipt.account_ref != record["account_ref"],
                receipt.oauth_client_fingerprint != record["client_digest"],
                receipt.scope_profile is not scope_profile,
                receipt.scope_fingerprint != record["scope_fingerprint"],
                not self._stored_ref(receipt.subject_id),
                effect_subject_id is not None
                and receipt.subject_id != effect_subject_id,
            )
        ):
            raise GoogleOAuthSessionError("oauth.token_write_failed")

    def _mark_transaction_terminal(self, record: dict[str, object], state: str) -> None:
        if record.get("token_operation_id") is None:
            record["authorization_code_digest"] = None
        if record.get("effect_subject_id") is None:
            record["token_operation_id"] = None
        record.update(
            {
                "state": state,
                "pkce_verifier": None,
                "state_token": None,
                "completion_owner": None,
                "completion_lease_expires_at": None,
                "terminal_at": self._now(),
            }
        )

    def _terminalize(
        self, transaction_id: str, state: str, *, completion_owner: str
    ) -> None:
        try:
            with self._state.locked():
                document = self._read_locked()
                record = self._find(
                    cast(list[object], document["transactions"]),
                    "id",
                    transaction_id,
                )
                if (
                    record is not None
                    and record.get("state") == "completing"
                    and record.get("completion_owner") == completion_owner
                ):
                    self._mark_transaction_terminal(record, state)
                    self._write_locked(document)
        except (HiveStateError, OSError):
            raise GoogleOAuthSessionError("oauth.control_unavailable") from None


def plan_oauth_client_import(
    service: GoogleOAuthControlService, *args: object, **kwargs: object
) -> GoogleOAuthClientImportPlanV1:
    return service.plan_oauth_client_import(*args, **kwargs)  # type: ignore[arg-type]


def apply_oauth_client_import(
    service: GoogleOAuthControlService, *args: object, **kwargs: object
) -> GoogleOAuthClientImportReceiptV1:
    return service.apply_oauth_client_import(*args, **kwargs)  # type: ignore[arg-type]


def begin_oauth_transaction(
    service: GoogleOAuthControlService, *args: object, **kwargs: object
) -> GoogleOAuthTransactionV1:
    return service.begin_oauth_transaction(*args, **kwargs)  # type: ignore[arg-type]


def complete_oauth_transaction(
    service: GoogleOAuthControlService, *args: object, **kwargs: object
) -> GoogleOAuthSessionReceipt:
    return service.complete_oauth_transaction(*args, **kwargs)  # type: ignore[arg-type]
