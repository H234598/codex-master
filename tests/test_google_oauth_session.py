from __future__ import annotations

import copy
from dataclasses import asdict
import json
import os
from pathlib import Path
import threading
import urllib.parse

import pytest
import yaml

import codex_master.google_oauth_session as oauth_session
from codex_master.credential_vault import CredentialVault
from codex_master.google_account_inventory import GoogleAccountInventoryLoader
from codex_master.google_account_inventory_manager import GoogleAccountInventoryManager
from codex_master.google_inventory_token_vault import GoogleInventoryReadonlyTokenVault
from codex_master.google_oauth_authorization import GoogleOAuthProfileIdV1

from codex_master.google_oauth_session import (
    GoogleOAuthSessionReceipt,
    GoogleOAuthSessionError,
    _ProfileBrowser,
    _client,
    _client_project_number,
    _persist_authorization,
)


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


class _Clock:
    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value


class _SecretIngress:
    class Session:
        def __init__(self, plan, payload: bytes) -> None:
            self.account_ref = plan.account_ref
            self.generation = plan.expected_generation
            self.plan_digest = plan.plan_digest
            self.payload = bytearray(payload)
            self.consumed = False

        def __repr__(self) -> str:
            return "SecretIngressSession(<redacted>)"

    def put(self, plan, payload: bytes):
        return self.Session(plan, payload)

    def consume_oauth_client(
        self,
        session,
        *,
        account_ref: str,
        expected_generation: int,
        plan_digest: str,
    ) -> bytearray:
        if (
            not isinstance(session, self.Session)
            or session.consumed
            or session.account_ref != account_ref
            or session.generation != expected_generation
            or session.plan_digest != plan_digest
        ):
            raise oauth_session.GoogleOAuthSessionError("credential.upload_expired")
        session.consumed = True
        payload = session.payload
        session.payload = bytearray(len(payload))
        return payload


class _Exchange:
    def __init__(self, subject_id: str = "subject-one") -> None:
        self.subject_id = subject_id
        self.calls: list[tuple[str, str, str]] = []

    def exchange(
        self,
        client: dict[str, object],
        *,
        code: str,
        redirect_uri: str,
        pkce_verifier: str,
    ):
        assert client["client_id"] == (
            "577074103233-clientpart.apps.googleusercontent.com"
        )
        self.calls.append((code, redirect_uri, pkce_verifier))
        return oauth_session.GoogleOAuthCodeExchangeV1(
            subject_id=self.subject_id,
            refresh_token=bytearray(b"private-refresh-token"),
        )


def _manager(tmp_path: Path) -> GoogleAccountInventoryManager:
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "google_accounts": [
                    {
                        "ref": "google-account-01",
                        "login_email": "one@example.test",
                        "recovery_email": None,
                        "label": None,
                        "subject_id": "subject-one",
                        "billing_accounts": [],
                        "projects": [],
                    },
                    {
                        "ref": "google-account-02",
                        "login_email": "two@example.test",
                        "recovery_email": None,
                        "label": None,
                        "subject_id": "subject-two",
                        "billing_accounts": [],
                        "projects": [],
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    inventory.chmod(0o600)
    loader = GoogleAccountInventoryLoader._for_test_path(inventory)
    manager = GoogleAccountInventoryManager._for_test_loader(
        loader.load,
        monotonic_clock=lambda: 1.0,
        operator_timestamp_utc=lambda: "2026-08-28T12:00:00Z",
    )
    manager.reload()
    return manager


def _token_vault(root: Path) -> GoogleInventoryReadonlyTokenVault:
    root.mkdir(mode=0o700, exist_ok=True)
    (root / "tokens").mkdir(mode=0o700, exist_ok=True)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return GoogleInventoryReadonlyTokenVault._for_test_tokens_parent_directory_fd(
            descriptor
        )
    finally:
        os.close(descriptor)


def _client_json(marker: str = "private-client-secret") -> bytes:
    return json.dumps(
        {
            "installed": {
                "client_id": ("577074103233-clientpart.apps.googleusercontent.com"),
                "project_id": "private-project",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "client_secret": marker,
                "redirect_uris": ["http://localhost"],
            }
        }
    ).encode()


def _service(
    tmp_path: Path,
    *,
    clock: _Clock | None = None,
    exchange: _Exchange | None = None,
    ingress: _SecretIngress | None = None,
    manager: GoogleAccountInventoryManager | None = None,
):
    manager = manager or _manager(tmp_path)
    clock = clock or _Clock()
    ingress = ingress or _SecretIngress()
    exchange = exchange or _Exchange()
    service = oauth_session.GoogleOAuthControlService(
        tmp_path / "oauth-state",
        manager=manager,
        client_vault=CredentialVault.for_test(
            tmp_path / "client-vault", key=b"k" * 32, clock=clock
        ),
        token_vault=_token_vault(tmp_path / "token-vault"),
        secret_ingress=ingress,
        code_exchange=exchange,
        clock=clock,
    )
    return service, ingress, exchange, manager


def _import_client(service, ingress: _SecretIngress, *, key: str = "import-one"):
    plan = service.plan_oauth_client_import(
        "google-account-01",
        expected_generation=1,
        idempotency_key=key,
    )
    session = ingress.put(plan, _client_json())
    return plan, session, service.apply_oauth_client_import(plan, session)


def _begin(service, client_ref: str, *, ttl_seconds: int = 600):
    return service.begin_oauth_transaction(
        "google-account-01",
        oauth_client_ref=client_ref,
        redirect_uri="http://127.0.0.1:8765/callback",
        scope_profile=GoogleOAuthProfileIdV1.INVENTORY_READONLY,
        expected_generation=1,
        ttl_seconds=ttl_seconds,
    )


def _state(transaction) -> str:
    return urllib.parse.parse_qs(
        urllib.parse.urlsplit(transaction.authorization_url).query
    )["state"][0]


def _complete(service, transaction, **overrides):
    arguments = {
        "code": "first-code",
        "account_ref": "google-account-01",
        "redirect_uri": "http://127.0.0.1:8765/callback",
        "expected_generation": 1,
        "state": _state(transaction),
    }
    arguments.update(overrides)
    return service.complete_oauth_transaction(transaction.id, **arguments)


def test_oauth_transaction_is_account_bound_and_code_is_consumed_once(
    tmp_path: Path,
) -> None:
    service, ingress, exchange, _manager_instance = _service(tmp_path)
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)

    receipt = _complete(service, transaction)
    assert receipt == GoogleOAuthSessionReceipt(
        account_ref="google-account-01",
        subject_bound=True,
        refresh_token_stored=True,
    )
    with pytest.raises(GoogleOAuthSessionError, match="oauth.transaction_expired"):
        _complete(service, transaction, code="second-code")
    assert len(exchange.calls) == 1


@pytest.mark.parametrize(
    ("override", "code"),
    (
        ({"account_ref": "google-account-02"}, "oauth.account_mismatch"),
        ({"expected_generation": 2}, "oauth.generation_mismatch"),
        (
            {"redirect_uri": "http://127.0.0.1:8766/callback"},
            "oauth.redirect_mismatch",
        ),
    ),
)
def test_oauth_callback_binding_mismatch_is_terminal_without_token_write(
    tmp_path: Path, override: dict[str, object], code: str
) -> None:
    service, ingress, exchange, _manager_instance = _service(tmp_path)
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)

    with pytest.raises(GoogleOAuthSessionError, match=code):
        _complete(service, transaction, **override)
    assert not list((tmp_path / "token-vault" / "tokens").iterdir())
    assert exchange.calls == []
    with pytest.raises(GoogleOAuthSessionError, match="oauth.transaction_expired"):
        _complete(service, transaction)


def test_subject_mismatch_is_terminal_and_writes_no_token(tmp_path: Path) -> None:
    service, ingress, _exchange, _manager_instance = _service(
        tmp_path, exchange=_Exchange("subject-two")
    )
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)

    with pytest.raises(GoogleOAuthSessionError, match="oauth.subject_mismatch"):
        _complete(service, transaction)
    assert not list((tmp_path / "token-vault" / "tokens").iterdir())


def test_expired_transaction_stays_terminal_across_restart(tmp_path: Path) -> None:
    clock = _Clock()
    ingress = _SecretIngress()
    exchange = _Exchange()
    manager = _manager(tmp_path)
    service, _ingress, _exchange, _manager_instance = _service(
        tmp_path,
        clock=clock,
        ingress=ingress,
        exchange=exchange,
        manager=manager,
    )
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref, ttl_seconds=1)
    clock.value += 2

    with pytest.raises(GoogleOAuthSessionError, match="oauth.transaction_expired"):
        _complete(service, transaction)
    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path,
        clock=clock,
        ingress=ingress,
        exchange=exchange,
        manager=manager,
    )
    with pytest.raises(GoogleOAuthSessionError, match="oauth.transaction_expired"):
        _complete(restarted, transaction)


def test_inventory_generation_change_prevents_token_write(tmp_path: Path) -> None:
    service, ingress, exchange, manager = _service(tmp_path)
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    assert manager.reload().generation == 2

    with pytest.raises(GoogleOAuthSessionError, match="oauth.generation_mismatch"):
        _complete(service, transaction)
    assert not list((tmp_path / "token-vault" / "tokens").iterdir())
    assert exchange.calls == []


def test_concurrent_completion_exchanges_and_writes_token_once(tmp_path: Path) -> None:
    service, ingress, exchange, _manager_instance = _service(tmp_path)
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    barrier = threading.Barrier(3)
    outcomes: list[str] = []

    def complete() -> None:
        barrier.wait()
        try:
            _complete(service, transaction)
        except GoogleOAuthSessionError as error:
            outcomes.append(error.code)
        else:
            outcomes.append("succeeded")

    threads = [threading.Thread(target=complete) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["oauth.transaction_expired", "succeeded"]
    assert len(exchange.calls) == 1
    token_records = list((tmp_path / "token-vault" / "tokens").glob("*.json"))
    assert len(token_records) == 1


def test_client_import_apply_is_idempotent_but_ingress_cannot_be_replayed(
    tmp_path: Path,
) -> None:
    service, ingress, _exchange, _manager_instance = _service(tmp_path)
    first_plan, first_session, first = _import_client(service, ingress)

    assert service.apply_oauth_client_import(first_plan, first_session) == first
    second_plan = service.plan_oauth_client_import(
        "google-account-01",
        expected_generation=1,
        idempotency_key="import-two",
    )
    with pytest.raises(GoogleOAuthSessionError, match="credential.upload_expired"):
        service.apply_oauth_client_import(second_plan, first_session)


def test_client_import_and_transaction_projections_are_redacted_and_digit_free(
    tmp_path: Path,
) -> None:
    marker = "private-client-secret-marker"
    service, ingress, _exchange, _manager_instance = _service(tmp_path)
    plan = service.plan_oauth_client_import(
        "google-account-01", expected_generation=1, idempotency_key="import-one"
    )
    imported = service.apply_oauth_client_import(
        plan, ingress.put(plan, _client_json(marker))
    )
    transaction = _begin(service, imported.client_ref)

    assert imported.account_ref == "google-account-01"
    assert not any(character.isdigit() for character in imported.display_name)
    assert "mji-client" not in imported.display_name.casefold()
    assert "hive-ref" not in imported.display_name.casefold()
    assert set(asdict(transaction)) == {
        "id",
        "account_ref",
        "authorization_url",
        "expires_at",
        "inventory_generation",
    }
    rendered = repr((plan, imported, transaction))
    assert marker not in rendered
    assert all(
        private not in asdict(transaction)
        for private in ("state", "pkce_verifier", "code", "token", "client_secret")
    )
    stored = b"".join(
        path.read_bytes()
        for path in (tmp_path / "client-vault").iterdir()
        if path.is_file()
    )
    state = b"".join(
        path.read_bytes()
        for path in (tmp_path / "oauth-state").iterdir()
        if path.is_file()
    )
    assert marker.encode() not in stored
    assert marker.encode() not in state


def test_oauth_client_ref_cannot_cross_accounts(tmp_path: Path) -> None:
    service, ingress, _exchange, _manager_instance = _service(tmp_path)
    _plan, _session, imported = _import_client(service, ingress)

    with pytest.raises(GoogleOAuthSessionError, match="oauth.client_account_mismatch"):
        service.begin_oauth_transaction(
            "google-account-02",
            oauth_client_ref=imported.client_ref,
            redirect_uri="http://127.0.0.1:8765/callback",
            scope_profile=GoogleOAuthProfileIdV1.INVENTORY_READONLY,
            expected_generation=1,
        )
