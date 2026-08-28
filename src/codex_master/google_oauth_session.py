"""Account-isolated installed-app OAuth sessions."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import time
from typing import Final, Protocol, cast
import urllib.parse
import urllib.request
import webbrowser

from .credential_vault import CredentialVault, CredentialVaultError
from .google_account_inventory import GoogleAccountInventoryError
from .google_account_inventory_manager import GoogleAccountInventoryManager
from .google_cloud_api import GoogleCloudApi, GoogleCloudApiError
from .google_inventory_token_vault import (
    GoogleInventoryReadonlyTokenVault,
    GoogleInventoryReadonlyTokenVaultError,
)
from .google_oauth_authorization import (
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
_MAX_CONTROL_BYTES: Final[int] = 2 * 1024 * 1024
_MAX_CONTROL_RECORDS: Final[int] = 4096
_REF: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII
)
_REDIRECT: Final[re.Pattern[str]] = re.compile(
    r"http://127\.0\.0\.1:([1-9][0-9]{0,4})/callback\Z", re.ASCII
)


GoogleOAuthError = GoogleOAuthSessionError


class SecretIngressPort(Protocol):
    """Task-8/9 adapter port for one authorized, session-bound secret put."""

    def consume_oauth_client(
        self,
        session: object,
        *,
        account_ref: str,
        expected_generation: int,
        plan_digest: str,
    ) -> bytearray: ...


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


@dataclass(frozen=True, slots=True, repr=False)
class GoogleOAuthTransactionV1:
    id: str
    account_ref: str
    authorization_url: str
    expires_at: float
    inventory_generation: int

    def __repr__(self) -> str:
        return "GoogleOAuthTransactionV1(<redacted>)"


def _zero_bytes(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


class GoogleOAuthControlService:
    """Durable account-bound OAuth transactions over existing secret owners."""

    def __init__(
        self,
        state_root: Path,
        *,
        manager: GoogleAccountInventoryManager,
        client_vault: CredentialVault,
        token_vault: GoogleInventoryReadonlyTokenVault,
        secret_ingress: SecretIngressPort,
        code_exchange: GoogleOAuthCodeExchangePort,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if (
            not isinstance(state_root, Path)
            or not state_root.is_absolute()
            or not isinstance(manager, GoogleAccountInventoryManager)
            or not isinstance(client_vault, CredentialVault)
            or not isinstance(token_vault, GoogleInventoryReadonlyTokenVault)
            or not callable(getattr(secret_ingress, "consume_oauth_client", None))
            or not callable(getattr(code_exchange, "exchange", None))
            or (clock is not None and not callable(clock))
        ):
            raise GoogleOAuthSessionError("oauth.control_unavailable")
        self._root = state_root
        self._manager = manager
        self._client_vault = client_vault
        self._token_vault = token_vault
        self._secret_ingress = secret_ingress
        self._code_exchange = code_exchange
        self._clock = clock or time.time
        try:
            self._state = HiveStateStore(state_root)
            with self._state.locked():
                try:
                    self._read_locked()
                except HiveStateError:
                    try:
                        os.lstat(state_root / _CONTROL_DOCUMENT.name)
                    except FileNotFoundError:
                        self._write_locked(self._empty_document())
                    else:
                        raise
        except (HiveStateError, OSError):
            raise GoogleOAuthSessionError("oauth.control_unavailable") from None

    def __repr__(self) -> str:
        return "GoogleOAuthControlService(<redacted>)"

    @staticmethod
    def _empty_document() -> dict[str, object]:
        return {
            "schema_version": 1,
            "imports": [],
            "clients": [],
            "transactions": [],
            "token_generations": {},
        }

    def _read_locked(self) -> dict[str, object]:
        value = dict(
            self._state.read_json_locked(
                _CONTROL_DOCUMENT, max_bytes=_MAX_CONTROL_BYTES
            )
        )
        if (
            value.get("schema_version") != 1
            or type(value.get("imports")) is not list
            or type(value.get("clients")) is not list
            or type(value.get("transactions")) is not list
            or type(value.get("token_generations")) is not dict
            or any(
                len(cast(list[object], value[field])) > _MAX_CONTROL_RECORDS
                for field in ("imports", "clients", "transactions")
            )
            or any(
                type(record) is not dict
                for field in ("imports", "clients", "transactions")
                for record in cast(list[object], value[field])
            )
        ):
            raise HiveStateError("invalid_google_oauth_control_state")
        return value

    def _write_locked(self, document: Mapping[str, object]) -> None:
        self._state.replace_json_locked(_CONTROL_DOCUMENT, document)

    def _now(self) -> float:
        try:
            value = float(self._clock())
        except (TypeError, ValueError, OverflowError):
            raise GoogleOAuthSessionError("oauth.control_unavailable") from None
        if not 0 <= value < float("inf"):
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

    def _account_subject(self, account_ref: str, generation: int) -> str:
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
        if type(subject_id) is not str or not subject_id:
            raise GoogleOAuthSessionError("oauth.subject_mismatch")
        return subject_id

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
            existing = self._find(imports, "idempotency_key", idempotency_key)
            if existing is not None:
                if (
                    existing.get("account_ref") != account_ref
                    or existing.get("expected_generation") != expected_generation
                ):
                    raise GoogleOAuthSessionError("control.idempotency_conflict")
                return self._import_plan(existing)
            if len(imports) >= _MAX_CONTROL_RECORDS:
                raise GoogleOAuthSessionError("oauth.control_unavailable")
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
            }
            imports.append(record)
            self._write_locked(document)
            return self._import_plan(record)

    @staticmethod
    def _import_plan(record: Mapping[str, object]) -> GoogleOAuthClientImportPlanV1:
        return GoogleOAuthClientImportPlanV1(
            str(record["id"]),
            str(record["account_ref"]),
            cast(int, record["expected_generation"]),
            cast(float, record["expires_at"]),
            str(record["idempotency_key"]),
            str(record["plan_digest"]),
        )

    @staticmethod
    def _import_receipt(
        record: Mapping[str, object],
    ) -> GoogleOAuthClientImportReceiptV1:
        return GoogleOAuthClientImportReceiptV1(
            str(record["account_ref"]),
            str(record["client_ref"]),
            str(record["display_name"]),
            cast(int, record["expected_generation"]),
            str(record["client_digest"]),
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
                if record.get("state") != "planned":
                    raise GoogleOAuthSessionError("oauth.import_plan_expired")
                if self._now() >= plan.expires_at:
                    record["state"] = "expired"
                    self._write_locked(document)
                    raise GoogleOAuthSessionError("oauth.import_plan_expired")
                try:
                    self._account_subject(plan.account_ref, plan.expected_generation)
                except GoogleOAuthSessionError:
                    record["state"] = "expired"
                    self._write_locked(document)
                    raise
                record["state"] = "applying"
                self._write_locked(document)
                try:
                    raw = self._secret_ingress.consume_oauth_client(
                        ingress_session,
                        account_ref=plan.account_ref,
                        expected_generation=plan.expected_generation,
                        plan_digest=plan.plan_digest,
                    )
                    if type(raw) is not bytearray:
                        raise GoogleOAuthSessionError("credential.upload_expired")
                    client_data, client_digest = _client_document(raw)
                    identity = generate_pretty_project_identity(
                        visible_names=(), reserved_project_ids=()
                    )
                    display_name = identity.project_name
                    clients = cast(list[object], document["clients"])
                    previous = next(
                        (
                            cast(dict[str, object], item)
                            for item in clients
                            if cast(dict[str, object], item).get("account_ref")
                            == plan.account_ref
                        ),
                        None,
                    )
                    vault_generation = (
                        cast(int, previous["vault_generation"]) + 1
                        if previous is not None
                        else 1
                    )
                    client_ref = "oauth-client-" + secrets.token_hex(16)
                    self._client_vault.store_projection(
                        self._client_vault_ref(plan.account_ref),
                        vault_generation,
                        bytes(raw),
                    )
                    if previous is not None:
                        clients.remove(previous)
                    clients.append(
                        {
                            "id": client_ref,
                            "account_ref": plan.account_ref,
                            "inventory_generation": plan.expected_generation,
                            "client_digest": client_digest,
                            "display_name": display_name,
                            "vault_generation": vault_generation,
                        }
                    )
                    record.update(
                        {
                            "state": "succeeded",
                            "client_ref": client_ref,
                            "client_digest": client_digest,
                            "display_name": display_name,
                            "vault_generation": vault_generation,
                        }
                    )
                    self._write_locked(document)
                    return self._import_receipt(record)
                except GoogleOAuthSessionError:
                    record["state"] = "failed"
                    self._write_locked(document)
                    raise
                except (CredentialVaultError, HiveStateError, OSError):
                    record["state"] = "failed"
                    self._write_locked(document)
                    raise GoogleOAuthSessionError("oauth.client_write_failed") from None
        finally:
            client_data.clear()
            _zero_bytes(raw)

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
        operation = (
            GoogleOAuthOperationV1.PROJECTS_SEARCH
            if profile_id is GoogleOAuthProfileIdV1.INVENTORY_READONLY
            else GoogleOAuthOperationV1.USERINFO_GET
        )
        try:
            return resolve_google_oauth_profile_v1(profile_id, operation)
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
        ttl_seconds: int = MAX_OAUTH_TRANSACTION_SECONDS,
    ) -> GoogleOAuthTransactionV1:
        account_ref = self._ref(account_ref)
        oauth_client_ref = self._ref(oauth_client_ref)
        redirect_uri = self._redirect_uri(redirect_uri)
        expected_generation = self._generation(expected_generation)
        ttl_seconds = self._ttl(ttl_seconds, MAX_OAUTH_TRANSACTION_SECONDS)
        self._account_subject(account_ref, expected_generation)
        profile = self._profile(scope_profile)
        with self._state.locked():
            document = self._read_locked()
            clients = cast(list[object], document["clients"])
            client_record = self._find(clients, "id", oauth_client_ref)
            if client_record is None or client_record.get("account_ref") != account_ref:
                raise GoogleOAuthSessionError("oauth.client_account_mismatch")
            if client_record.get("inventory_generation") != expected_generation:
                raise GoogleOAuthSessionError("oauth.generation_mismatch")
            client, client_digest = self._load_client(account_ref, client_record)
            if client_digest != client_record.get("client_digest"):
                raise GoogleOAuthSessionError("oauth.client_expired")
            now = self._now()
            expires_at = now + ttl_seconds
            transaction_id = "oauth-txn-" + secrets.token_hex(16)
            state = secrets.token_urlsafe(32)
            verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
            challenge = (
                base64.urlsafe_b64encode(sha256(verifier.encode("ascii")).digest())
                .rstrip(b"=")
                .decode()
            )
            authorization_url = (
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
                        "scope": " ".join(
                            google_oauth_scope_values_v1(profile.profile_id)
                        ),
                        "state": state,
                    }
                )
            )
            transactions = cast(list[object], document["transactions"])
            if len(transactions) >= _MAX_CONTROL_RECORDS:
                raise GoogleOAuthSessionError("oauth.control_unavailable")
            transactions.append(
                {
                    "id": transaction_id,
                    "account_ref": account_ref,
                    "oauth_client_ref": oauth_client_ref,
                    "client_digest": client_digest,
                    "pkce_verifier": verifier,
                    "redirect_uri": redirect_uri,
                    "scope_profile": profile.profile_id.value,
                    "scope_fingerprint": profile.scope_fingerprint,
                    "state_token": state,
                    "inventory_generation": expected_generation,
                    "expires_at": expires_at,
                    "state": "pending",
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
        if type(code) is not str or not code or type(state) is not str or not state:
            raise GoogleOAuthSessionError("oauth.request_invalid")
        client: dict[str, object] = {}
        result: GoogleOAuthCodeExchangeV1 | None = None
        with self._state.locked():
            document = self._read_locked()
            record = self._find(
                cast(list[object], document["transactions"]), "id", transaction_id
            )
            if record is None or record.get("state") != "pending":
                raise GoogleOAuthSessionError("oauth.transaction_expired")
            mismatch: str | None = None
            if self._now() >= cast(float, record["expires_at"]):
                mismatch = "oauth.transaction_expired"
            elif record.get("account_ref") != account_ref:
                mismatch = "oauth.account_mismatch"
            elif record.get("inventory_generation") != expected_generation:
                mismatch = "oauth.generation_mismatch"
            elif record.get("redirect_uri") != redirect_uri:
                mismatch = "oauth.redirect_mismatch"
            elif not secrets.compare_digest(str(record.get("state_token")), state):
                mismatch = "oauth.state_mismatch"
            else:
                try:
                    self._account_subject(account_ref, expected_generation)
                except GoogleOAuthSessionError as error:
                    mismatch = error.code
            if mismatch is not None:
                record["state"] = "expired"
                self._write_locked(document)
                raise GoogleOAuthSessionError(mismatch)
            client_record = self._find(
                cast(list[object], document["clients"]),
                "id",
                record["oauth_client_ref"],
            )
            if (
                client_record is None
                or client_record.get("account_ref") != account_ref
                or client_record.get("client_digest") != record.get("client_digest")
            ):
                record["state"] = "expired"
                self._write_locked(document)
                raise GoogleOAuthSessionError("oauth.client_expired")
            record["state"] = "completing"
            self._write_locked(document)
            verifier = str(record["pkce_verifier"])
            client, client_digest = self._load_client(account_ref, client_record)
        try:
            result = self._code_exchange.exchange(
                client,
                code=code,
                redirect_uri=redirect_uri,
                pkce_verifier=verifier,
            )
            if not isinstance(result, GoogleOAuthCodeExchangeV1):
                raise GoogleOAuthSessionError("oauth.exchange_failed")
        except GoogleOAuthSessionError:
            self._terminalize(transaction_id, "failed")
            raise
        except Exception:
            self._terminalize(transaction_id, "failed")
            raise GoogleOAuthSessionError("oauth.exchange_failed") from None
        finally:
            client.clear()
            code = ""
            verifier = ""
        try:
            expected_subject = self._account_subject(account_ref, expected_generation)
        except GoogleOAuthSessionError:
            _zero_bytes(result.refresh_token)
            self._terminalize(transaction_id, "failed")
            raise
        if result.subject_id != expected_subject:
            _zero_bytes(result.refresh_token)
            self._terminalize(transaction_id, "failed")
            raise GoogleOAuthSessionError("oauth.subject_mismatch")
        try:
            with self._state.locked():
                document = self._read_locked()
                record = self._find(
                    cast(list[object], document["transactions"]),
                    "id",
                    transaction_id,
                )
                if record is None or record.get("state") != "completing":
                    raise GoogleOAuthSessionError("oauth.transaction_expired")
                if self._now() >= cast(float, record["expires_at"]):
                    record["state"] = "expired"
                    self._write_locked(document)
                    raise GoogleOAuthSessionError("oauth.transaction_expired")
                if (
                    self._account_subject(account_ref, expected_generation)
                    != result.subject_id
                ):
                    record["state"] = "failed"
                    self._write_locked(document)
                    raise GoogleOAuthSessionError("oauth.subject_mismatch")
                generations = cast(dict[str, object], document["token_generations"])
                token_receipt = self._token_vault.store_inventory_refresh_token(
                    self._manager,
                    account_ref=account_ref,
                    subject_id=result.subject_id,
                    oauth_client_fingerprint=client_digest,
                    refresh_token=result.refresh_token,
                    expected_vault_generation=generations.get(account_ref),
                )
                generations[account_ref] = token_receipt.vault_generation
                record["state"] = "succeeded"
                self._write_locked(document)
        except GoogleOAuthSessionError:
            raise
        except (GoogleInventoryReadonlyTokenVaultError, HiveStateError, OSError):
            self._terminalize(transaction_id, "failed")
            raise GoogleOAuthSessionError("oauth.token_write_failed") from None
        finally:
            _zero_bytes(result.refresh_token)
        return GoogleOAuthSessionReceipt(account_ref, True, True)

    def _terminalize(self, transaction_id: str, state: str) -> None:
        try:
            with self._state.locked():
                document = self._read_locked()
                record = self._find(
                    cast(list[object], document["transactions"]),
                    "id",
                    transaction_id,
                )
                if record is not None and record.get("state") == "completing":
                    record["state"] = state
                    self._write_locked(document)
        except (HiveStateError, OSError):
            pass


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
