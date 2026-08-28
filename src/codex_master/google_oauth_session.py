"""Account-isolated installed-app OAuth sessions."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import urllib.parse
import urllib.request
import webbrowser

from .google_cloud_api import GoogleCloudApi, GoogleCloudApiError


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
        document = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise GoogleOAuthSessionError("oauth.session_client_invalid") from None
    installed = document.get("installed") if type(document) is dict else None
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or type(installed) is not dict
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
    return installed, "sha256:" + sha256(raw).hexdigest()


def _client_project_number(client: dict[str, object]) -> str:
    client_id = client.get("client_id")
    if type(client_id) is not str:
        raise GoogleOAuthSessionError("oauth.session_client_invalid")
    match = re.fullmatch(
        r"([0-9]+)-[a-z0-9]+\.apps\.googleusercontent\.com", client_id
    )
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
        for value in (account_ref, observed_subject_id, access_token, client_fingerprint)
    ) or (refresh_token is not None and (type(refresh_token) is not str or not refresh_token)):
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
            token_uri=str(client.get("token_uri", "https://oauth2.googleapis.com/token")),
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
