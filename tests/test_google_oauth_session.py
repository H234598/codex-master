from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from types import ModuleType

import pytest

from codex_master.google_oauth_session import (
    GoogleOAuthSessionError,
    _ProfileBrowser,
    _client,
    _client_project_number,
    _persist_authorization,
)
import codex_master.google_oauth_session as session


class MemoryStore:
    def __init__(self, document):
        self.document = copy.deepcopy(document)
        self.writes = 0

    def atomic_update(self, transform):
        candidate = copy.deepcopy(self.document)
        transform(candidate)
        self.document = candidate
        self.writes += 1

    def _read(self):
        return b"", copy.deepcopy(self.document)


def _document(subject="subject-one"):
    return {
        "schema_version": 2,
        "google_accounts": [
            {
                "ref": "google-account-01",
                "login_email": "one@example.test",
                "recovery_email": None,
                "subject_id": subject,
                "billing_accounts": [],
                "projects": [],
            },
            {
                "ref": "google-account-02",
                "login_email": "two@example.test",
                "recovery_email": None,
                "subject_id": "subject-two",
                "billing_accounts": [],
                "projects": [],
            },
        ],
    }


def test_authorization_is_bound_to_one_account_and_never_cross_written() -> None:
    store = MemoryStore(_document())

    _persist_authorization(
        store,
        account_ref="google-account-01",
        observed_subject_id="subject-one",
        access_token="private-access",
        refresh_token="private-refresh",
        client_fingerprint="sha256:" + "a" * 64,
    )

    first, second = store.document["google_accounts"]
    assert first["auth"]["access_token"] == "private-access"
    assert "auth" not in second
    assert store.writes == 1
    assert "private-access" not in repr(_persist_authorization)


def test_subject_mismatch_stops_without_auth_write() -> None:
    store = MemoryStore(_document())

    with pytest.raises(GoogleOAuthSessionError, match="oauth.session_subject_mismatch"):
        _persist_authorization(
            store,
            account_ref="google-account-01",
            observed_subject_id="wrong",
            access_token="private-access",
            refresh_token="private-refresh",
            client_fingerprint="sha256:" + "a" * 64,
        )

    assert store.writes == 0
    assert all("auth" not in account for account in store.document["google_accounts"])


def test_client_project_number_is_strictly_derived_from_client_id() -> None:
    assert (
        _client_project_number(
            {"client_id": "577074103233-clientpart.apps.googleusercontent.com"}
        )
        == "577074103233"
    )

    for invalid in ({}, {"client_id": "clientpart.apps.googleusercontent.com"}):
        with pytest.raises(
            GoogleOAuthSessionError, match="oauth.session_client_invalid"
        ):
            _client_project_number(invalid)


def test_client_rejects_non_google_oauth_endpoints(tmp_path: Path) -> None:
    client_file = tmp_path / "client.json"
    installed = {
        "client_id": "577074103233-clientpart.apps.googleusercontent.com",
        "project_id": "private-project",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_secret": "private-secret",
        "redirect_uris": ["http://localhost"],
    }
    client_file.write_text(json.dumps({"installed": installed}))
    client_file.chmod(0o600)

    assert _client(client_file)[0]["token_uri"] == installed["token_uri"]

    installed["token_uri"] = "https://attacker.example.test/token"
    client_file.write_text(json.dumps({"installed": installed}))
    with pytest.raises(GoogleOAuthSessionError, match="oauth.session_client_invalid"):
        _client(client_file)


def test_profile_browser_can_open_in_existing_remote_debug_session(
    monkeypatch,
) -> None:
    calls = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            assert limit == 4097
            return b'{"id":"target"}'

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, request.method, timeout))
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    browser = _ProfileBrowser("vivaldi", Path("/private/profile"), 9241)

    assert browser.open("https://accounts.example.test/oauth?a=b") is True
    assert calls == [
        (
            "http://127.0.0.1:9241/json/new?https%3A%2F%2Faccounts.example.test%2Foauth%3Fa%3Db",
            "PUT",
            5,
        )
    ]


def test_session_error_repr_contains_only_its_stable_code() -> None:
    assert repr(GoogleOAuthSessionError("oauth.session_client_invalid")) == (
        "GoogleOAuthSessionError('oauth.session_client_invalid')"
    )


def test_authorize_google_account_runs_the_local_flow_and_persists_subject_bound_result(
    monkeypatch, tmp_path: Path
) -> None:
    browser_profile = tmp_path / "browser"
    browser_profile.mkdir(mode=0o700)
    stored: dict[str, object] = {}

    class Credentials:
        token = "access-test"
        refresh_token = "refresh-test"

    class Flow:
        @classmethod
        def from_client_secrets_file(cls, path, scopes):
            assert str(path) == "/private/client.json"
            assert tuple(scopes) == session._SCOPES
            return cls()

        def run_local_server(self, **kwargs):
            assert kwargs["host"] == "127.0.0.1"
            return Credentials()

    class Api:
        def __init__(self, token):
            assert token == "access-test"

        def subject_id(self):
            return "subject-one"

        def enable_control_services(self, project_number):
            assert project_number == "123"

    package = ModuleType("google_auth_oauthlib")
    flow_module = ModuleType("google_auth_oauthlib.flow")
    flow_module.InstalledAppFlow = Flow
    monkeypatch.setitem(sys.modules, "google_auth_oauthlib", package)
    monkeypatch.setitem(sys.modules, "google_auth_oauthlib.flow", flow_module)
    monkeypatch.setattr(session, "_client", lambda path: ({"client_id": "123-test.apps.googleusercontent.com"}, "sha256:test"))
    monkeypatch.setattr(session.shutil, "which", lambda name: "/mock/vivaldi" if name == "vivaldi-stable" else None)
    monkeypatch.setattr(session, "GoogleCloudApi", Api)
    monkeypatch.setattr(session, "_persist_authorization", lambda *args, **kwargs: stored.update(kwargs))

    receipt = session.authorize_google_account(
        object(), account_ref="one", client_file=Path("/private/client.json"), browser_profile=browser_profile
    )

    assert receipt.account_ref == "one"
    assert receipt.subject_bound is True and receipt.refresh_token_stored is True
    assert stored["observed_subject_id"] == "subject-one"


def test_load_access_token_returns_unrefreshable_bound_access_token(monkeypatch) -> None:
    store = MemoryStore(_document())
    store.document["google_accounts"][0]["auth"] = {
        "client_fingerprint": "sha256:test",
        "access_token": "access-test",
        "refresh_token": None,
    }
    monkeypatch.setattr(session, "_client", lambda path: ({}, "sha256:test"))

    assert session.load_access_token(store, account_ref="google-account-01", client_file=Path("/private/client.json")) == "access-test"
