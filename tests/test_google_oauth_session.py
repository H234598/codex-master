from __future__ import annotations

import copy
from contextlib import contextmanager
from dataclasses import asdict
import json
from pathlib import Path
import sys
import threading
from types import ModuleType
import urllib.parse

import pytest
import yaml

import codex_master.google_oauth_session as oauth_session
from codex_master.credential_vault import CredentialVault
from codex_master.google_account_inventory import GoogleAccountInventoryLoader
from codex_master.google_account_inventory_manager import GoogleAccountInventoryManager
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


def test_module_level_oauth_helpers_delegate_exact_arguments() -> None:
    class Service:
        def __init__(self) -> None:
            self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

        def _call(self, name: str, args: tuple[object, ...], kwargs: dict[str, object]):
            self.calls.append((name, args, kwargs))
            return name

        def plan_oauth_client_import(self, *args: object, **kwargs: object):
            return self._call("plan", args, kwargs)

        def apply_oauth_client_import(self, *args: object, **kwargs: object):
            return self._call("apply", args, kwargs)

        def begin_oauth_transaction(self, *args: object, **kwargs: object):
            return self._call("begin", args, kwargs)

        def complete_oauth_transaction(self, *args: object, **kwargs: object):
            return self._call("complete", args, kwargs)

    service = Service()

    assert oauth_session.plan_oauth_client_import(service, "account", generation=1) == "plan"
    assert oauth_session.apply_oauth_client_import(service, "plan", ingress="cap") == "apply"
    assert oauth_session.begin_oauth_transaction(service, "account", profile="inventory") == "begin"
    assert oauth_session.complete_oauth_transaction(service, "txn", code="code") == "complete"
    assert service.calls == [
        ("plan", ("account",), {"generation": 1}),
        ("apply", ("plan",), {"ingress": "cap"}),
        ("begin", ("account",), {"profile": "inventory"}),
        ("complete", ("txn",), {"code": "code"}),
    ]


def test_v2_migration_rejects_noncanonical_shape() -> None:
    with pytest.raises(oauth_session.HiveStateError, match="invalid_google_oauth_control_state"):
        oauth_session.GoogleOAuthControlService._migrate_v2(
            {"schema_version": 2, "imports": [], "clients": []}
        )


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
            assert tuple(scopes) == oauth_session._SCOPES
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
    monkeypatch.setattr(
        oauth_session,
        "_client",
        lambda path: (
            {"client_id": "123-test.apps.googleusercontent.com"},
            "sha256:test",
        ),
    )
    monkeypatch.setattr(
        oauth_session.shutil,
        "which",
        lambda name: "/mock/vivaldi" if name == "vivaldi-stable" else None,
    )
    monkeypatch.setattr(oauth_session, "GoogleCloudApi", Api)
    monkeypatch.setattr(
        oauth_session,
        "_persist_authorization",
        lambda *args, **kwargs: stored.update(kwargs),
    )

    receipt = oauth_session.authorize_google_account(
        object(),
        account_ref="one",
        client_file=Path("/private/client.json"),
        browser_profile=browser_profile,
    )

    assert receipt.account_ref == "one"
    assert receipt.subject_bound is True
    assert receipt.refresh_token_stored is True
    assert stored["observed_subject_id"] == "subject-one"


def test_load_access_token_returns_unrefreshable_bound_access_token(monkeypatch) -> None:
    store = MemoryStore(_document())
    store.document["google_accounts"][0]["auth"] = {
        "client_fingerprint": "sha256:test",
        "access_token": "access-test",
        "refresh_token": None,
    }
    monkeypatch.setattr(
        oauth_session, "_client", lambda path: ({}, "sha256:test")
    )

    assert (
        oauth_session.load_access_token(
            store,
            account_ref="google-account-01",
            client_file=Path("/private/client.json"),
        )
        == "access-test"
    )


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
            self.acknowledged = False

        def __repr__(self) -> str:
            return "SecretIngressSession(<redacted>)"

    def __init__(self) -> None:
        self.receipts: dict[str, tuple[str, int, str]] = {}
        self.ack_calls: list[str] = []

    def put(self, plan, payload: bytes):
        return self.Session(plan, payload)

    def read_oauth_client(
        self,
        session,
        *,
        account_ref: str,
        expected_generation: int,
        plan_digest: str,
    ) -> bytearray:
        if (
            not isinstance(session, self.Session)
            or session.acknowledged
            or session.account_ref != account_ref
            or session.generation != expected_generation
            or session.plan_digest != plan_digest
        ):
            raise oauth_session.GoogleOAuthSessionError("credential.upload_expired")
        return bytearray(session.payload)

    def acknowledge_oauth_client(
        self,
        session,
        *,
        account_ref: str,
        expected_generation: int,
        plan_digest: str,
        ack_operation_id: str,
    ) -> None:
        binding = (account_ref, expected_generation, plan_digest)
        self.ack_calls.append(ack_operation_id)
        receipt = self.receipts.get(ack_operation_id)
        if receipt is not None:
            if receipt != binding:
                raise oauth_session.GoogleOAuthSessionError("credential.upload_expired")
            return
        if (
            not isinstance(session, self.Session)
            or session.acknowledged
            or session.account_ref != account_ref
            or session.generation != expected_generation
            or session.plan_digest != plan_digest
        ):
            raise oauth_session.GoogleOAuthSessionError("credential.upload_expired")
        session.acknowledged = True
        session.payload[:] = b"\0" * len(session.payload)
        self.receipts[ack_operation_id] = binding


class _TokenWriter:
    def __init__(self) -> None:
        self.receipts: dict[str, oauth_session.GoogleOAuthTokenWriteReceiptV1] = {}
        self.writes: list[tuple[str, str, str]] = []

    def lookup_refresh_token_receipt(
        self,
        operation_id: str,
        *,
        account_ref: str,
        scope_profile: GoogleOAuthProfileIdV1,
        scope_fingerprint: str,
    ):
        receipt = self.receipts.get(operation_id)
        if receipt is not None and (
            receipt.account_ref != account_ref
            or receipt.scope_profile is not scope_profile
            or receipt.scope_fingerprint != scope_fingerprint
        ):
            raise oauth_session.GoogleOAuthSessionError("oauth.scope_mismatch")
        return receipt

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
    ):
        existing = self.lookup_refresh_token_receipt(
            operation_id,
            account_ref=account_ref,
            scope_profile=scope_profile,
            scope_fingerprint=scope_fingerprint,
        )
        if existing is not None:
            return existing
        assert refresh_token == bytearray(b"private-refresh-token")
        self.writes.append((account_ref, scope_profile.value, scope_fingerprint))
        receipt = oauth_session.GoogleOAuthTokenWriteReceiptV1(
            operation_id=operation_id,
            account_ref=account_ref,
            subject_id=subject_id,
            oauth_client_fingerprint=oauth_client_fingerprint,
            scope_profile=scope_profile,
            scope_fingerprint=scope_fingerprint,
        )
        self.receipts[operation_id] = receipt
        return receipt


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


def _manager(
    tmp_path: Path, *, subject_one: str | None = "subject-one"
) -> GoogleAccountInventoryManager:
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
                        "subject_id": subject_one,
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
    token_writer: _TokenWriter | None = None,
    manager: GoogleAccountInventoryManager | None = None,
):
    manager = manager or _manager(tmp_path)
    clock = clock or _Clock()
    ingress = ingress or _SecretIngress()
    token_writer = token_writer or _TokenWriter()
    exchange = exchange or _Exchange()
    service = oauth_session.GoogleOAuthControlService(
        tmp_path / "oauth-state",
        manager=manager,
        client_vault=CredentialVault.for_test(
            tmp_path / "client-vault", key=b"k" * 32, clock=clock
        ),
        token_writer=token_writer,
        secret_ingress=ingress,
        code_exchange=exchange,
        clock=clock,
    )
    return service, ingress, exchange, manager


def test_exchange_token_receipt_and_control_service_repr_are_redacted(
    tmp_path: Path,
) -> None:
    service, _ingress, _exchange, _manager = _service(tmp_path)
    exchange = oauth_session.GoogleOAuthCodeExchangeV1(
        "private-subject",
        bytearray(b"private-refresh-token"),
    )
    receipt = oauth_session.GoogleOAuthTokenWriteReceiptV1(
        operation_id="operation-one",
        account_ref="google-account-01",
        subject_id="private-subject",
        oauth_client_fingerprint="sha256:" + "a" * 64,
        scope_profile=GoogleOAuthProfileIdV1.INVENTORY_READONLY,
        scope_fingerprint="sha256:" + "b" * 64,
    )

    assert repr(exchange) == "GoogleOAuthCodeExchangeV1(<redacted>)"
    assert repr(receipt) == "GoogleOAuthTokenWriteReceiptV1(<redacted>)"
    assert repr(service) == "GoogleOAuthControlService(<redacted>)"


def _import_client(service, ingress: _SecretIngress, *, key: str = "import-one"):
    plan = service.plan_oauth_client_import(
        "google-account-01",
        expected_generation=1,
        idempotency_key=key,
    )
    session = ingress.put(plan, _client_json())
    return plan, session, service.apply_oauth_client_import(plan, session)


def test_resolve_oauth_client_import_plan_from_durable_digest_after_restart(
    tmp_path: Path,
) -> None:
    service, _ingress, _exchange, _manager = _service(tmp_path)
    plan = service.plan_oauth_client_import(
        "google-account-01", expected_generation=1, idempotency_key="resolve-one"
    )
    restarted, _ingress, _exchange, _manager = _service(tmp_path)

    assert (
        restarted.resolve_oauth_client_import_plan(
            "google-account-01",
            expected_generation=1,
            plan_digest=plan.plan_digest,
        )
        == plan
    )


def test_client_import_keeps_vault_input_mutable_until_crypto_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break caught: project code must not create an immutable secret copy."""

    observed: list[type[object]] = []
    real_store = CredentialVault.store_projection

    def require_mutable(vault, account_ref, generation, payload):
        observed.append(type(payload))
        if type(payload) is bytes:
            raise AssertionError("immutable project copy")
        return real_store(vault, account_ref, generation, payload)

    monkeypatch.setattr(CredentialVault, "store_projection", require_mutable)
    service, ingress, _exchange, _manager = _service(tmp_path)
    _import_client(service, ingress)

    assert observed == [bytearray]


def _begin(
    service,
    client_ref: str,
    *,
    ttl_seconds: int = 600,
    idempotency_key: str = "oauth-begin-default",
):
    return service.begin_oauth_transaction(
        "google-account-01",
        oauth_client_ref=client_ref,
        redirect_uri="http://127.0.0.1:8765/callback",
        scope_profile=GoogleOAuthProfileIdV1.INVENTORY_READONLY,
        expected_generation=1,
        idempotency_key=idempotency_key,
        principal="operator-one",
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


def test_provisioner_oauth_profile_is_stored_for_write_authority(
    tmp_path: Path,
) -> None:
    token_writer = _TokenWriter()
    service, ingress, _exchange, _manager_instance = _service(
        tmp_path, token_writer=token_writer
    )
    _plan, _session, imported = _import_client(service, ingress)
    transaction = service.begin_oauth_transaction(
        "google-account-01",
        oauth_client_ref=imported.client_ref,
        redirect_uri="http://127.0.0.1:8765/callback",
        scope_profile=GoogleOAuthProfileIdV1.PROVISIONER,
        expected_generation=1,
        idempotency_key="oauth-provisioner",
        principal="operator-one",
    )

    assert "cloud-platform.read-only" not in transaction.authorization_url
    assert "cloud-platform" in urllib.parse.unquote(transaction.authorization_url)
    assert _complete(service, transaction).refresh_token_stored is True
    assert token_writer.writes == [
        (
            "google-account-01",
            GoogleOAuthProfileIdV1.PROVISIONER.value,
            oauth_session.resolve_google_oauth_profile_v1(
                GoogleOAuthProfileIdV1.PROVISIONER,
                oauth_session.GoogleOAuthOperationV1.PROJECTS_CREATE,
            ).scope_fingerprint,
        )
    ]


def test_first_subject_binding_rebases_active_client_generation(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path, subject_one=None)
    inventory = tmp_path / "inventory.yaml"

    class BindingWriter(_TokenWriter):
        def store_refresh_token(self, *args, **kwargs):
            receipt = super().store_refresh_token(*args, **kwargs)
            document = yaml.safe_load(inventory.read_text(encoding="utf-8"))
            document["google_accounts"][0]["subject_id"] = receipt.subject_id
            inventory.write_text(yaml.safe_dump(document), encoding="utf-8")
            inventory.chmod(0o600)
            manager.reload(expected_generation=1)
            return receipt

    service, ingress, _exchange, _manager_instance = _service(
        tmp_path, manager=manager, token_writer=BindingWriter()
    )
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)

    assert _complete(service, transaction).subject_bound is True
    binding = service.default_oauth_client_binding(
        "google-account-01", expected_generation=2
    )
    assert (
        binding.availability is oauth_session.GoogleOAuthClientAvailabilityV1.AVAILABLE
    )
    assert binding.default_oauth_client_ref == imported.client_ref


def test_oauth_begin_replays_same_receipt_after_restart_and_conflicts_on_rebind(
    tmp_path: Path,
) -> None:
    service, ingress, exchange, manager = _service(tmp_path)
    _plan, _session, imported = _import_client(service, ingress)
    values = {
        "oauth_client_ref": imported.client_ref,
        "redirect_uri": "http://127.0.0.1:8765/callback",
        "scope_profile": GoogleOAuthProfileIdV1.INVENTORY_READONLY,
        "expected_generation": 1,
        "idempotency_key": "oauth-begin-one",
        "principal": "operator-one",
    }
    first = service.begin_oauth_transaction("google-account-01", **values)
    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path,
        ingress=ingress,
        exchange=exchange,
        manager=manager,
    )

    assert restarted.begin_oauth_transaction("google-account-01", **values) == first
    with pytest.raises(GoogleOAuthSessionError, match="control.idempotency_conflict"):
        restarted.begin_oauth_transaction(
            "google-account-01",
            **{**values, "redirect_uri": "http://127.0.0.1:8766/callback"},
        )
    document = json.loads(
        (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
    )
    assert len(document["transactions"]) == 1


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
    assert service._token_writer.writes == []
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
    assert service._token_writer.writes == []


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
    assert service._token_writer.writes == []
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
    assert len(service._token_writer.writes) == 1


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
            idempotency_key="oauth-cross-account",
            principal="operator-one",
        )


def test_default_oauth_client_binding_is_exact_account_scoped_and_redacted(
    tmp_path: Path,
) -> None:
    service, ingress, _exchange, _manager_instance = _service(tmp_path)
    _plan, _session, imported = _import_client(service, ingress)

    bound = service.default_oauth_client_binding(
        "google-account-01", expected_generation=1
    )
    missing = service.default_oauth_client_binding(
        "google-account-02", expected_generation=1
    )

    assert bound == oauth_session.GoogleOAuthClientBindingV1(
        account_ref="google-account-01",
        inventory_generation=1,
        default_oauth_client_ref=imported.client_ref,
        availability=oauth_session.GoogleOAuthClientAvailabilityV1.AVAILABLE,
    )
    assert missing == oauth_session.GoogleOAuthClientBindingV1(
        account_ref="google-account-02",
        inventory_generation=1,
        default_oauth_client_ref=None,
        availability=oauth_session.GoogleOAuthClientAvailabilityV1.MISSING,
    )
    rendered = repr((bound, missing))
    assert "private-client-secret" not in rendered
    assert "577074103233-clientpart" not in rendered


def test_active_oauth_client_material_is_account_bound_and_redacted(
    tmp_path: Path,
) -> None:
    service, ingress, _exchange, _manager_instance = _service(tmp_path)
    _import_client(service, ingress)

    material = service.active_oauth_client_material(
        "google-account-01", expected_generation=1
    )

    assert material.client_id == "577074103233-clientpart.apps.googleusercontent.com"
    assert material.client_secret == "private-client-secret"
    assert material.token_uri == "https://oauth2.googleapis.com/token"
    assert material.client_fingerprint.startswith("sha256:")
    assert "private-client-secret" not in repr(material)


def test_default_oauth_client_binding_disables_stale_or_revoked_projection(
    tmp_path: Path,
) -> None:
    service, ingress, _exchange, manager = _service(tmp_path)
    _plan, _session, _imported = _import_client(service, ingress)

    service._client_vault.revoke_account(
        service._client_vault_ref("google-account-01"), expected_generation=1
    )
    revoked = service.default_oauth_client_binding(
        "google-account-01", expected_generation=1
    )
    manager.reload(expected_generation=1)
    stale = service.default_oauth_client_binding(
        "google-account-01", expected_generation=2
    )

    assert stale.default_oauth_client_ref is None
    assert stale.availability is oauth_session.GoogleOAuthClientAvailabilityV1.STALE
    assert revoked.default_oauth_client_ref is None
    assert revoked.availability is oauth_session.GoogleOAuthClientAvailabilityV1.REVOKED


@pytest.mark.parametrize("fault_phase", ["enter", "exit"])
def test_default_oauth_client_binding_degrades_journal_lock_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault_phase: str
) -> None:
    service, ingress, _exchange, _manager_instance = _service(tmp_path)
    _import_client(service, ingress)

    @contextmanager
    def unavailable_lock():
        if fault_phase == "enter":
            raise oauth_session.HiveStateError("state_lock_unavailable")
        yield
        raise oauth_session.HiveStateError("state_lock_unavailable")

    monkeypatch.setattr(service._state, "locked", unavailable_lock)
    binding = service.default_oauth_client_binding(
        "google-account-01", expected_generation=1
    )

    assert binding.default_oauth_client_ref is None
    assert (
        binding.availability
        is oauth_session.GoogleOAuthClientAvailabilityV1.UNAVAILABLE
    )


def test_default_oauth_client_binding_degrades_corrupt_journal_read(
    tmp_path: Path,
) -> None:
    service, ingress, _exchange, _manager_instance = _service(tmp_path)
    _import_client(service, ingress)
    service._state.replace_json(oauth_session._CONTROL_DOCUMENT, {"schema_version": 3})
    binding = service.default_oauth_client_binding(
        "google-account-01", expected_generation=1
    )

    assert binding.default_oauth_client_ref is None
    assert (
        binding.availability
        is oauth_session.GoogleOAuthClientAvailabilityV1.UNAVAILABLE
    )


def test_default_oauth_client_binding_does_not_hide_programming_or_control_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, ingress, _exchange, _manager_instance = _service(tmp_path)
    _import_client(service, ingress)
    programming_error = RuntimeError("programming-error-marker")

    def broken_read() -> dict[str, object]:
        raise programming_error

    monkeypatch.setattr(service, "_read_locked", broken_read)
    with pytest.raises(RuntimeError) as captured:
        service.default_oauth_client_binding("google-account-01", expected_generation=1)
    assert captured.value is programming_error

    domain_error = GoogleOAuthSessionError("oauth.request_invalid")

    def invalid_domain_read() -> dict[str, object]:
        raise domain_error

    monkeypatch.setattr(service, "_read_locked", invalid_domain_read)
    with pytest.raises(GoogleOAuthSessionError) as invalid_domain:
        service.default_oauth_client_binding("google-account-01", expected_generation=1)
    assert invalid_domain.value is domain_error

    control_signal = KeyboardInterrupt()

    @contextmanager
    def interrupted_lock():
        raise control_signal
        yield

    monkeypatch.setattr(service._state, "locked", interrupted_lock)
    with pytest.raises(KeyboardInterrupt) as interrupted:
        service.default_oauth_client_binding("google-account-01", expected_generation=1)
    assert interrupted.value is control_signal


def test_non_profile_grant_is_rejected_before_any_transaction_or_token_write(
    tmp_path: Path,
) -> None:
    service, ingress, _exchange, _manager_instance = _service(tmp_path)
    _plan, _session, imported = _import_client(service, ingress)

    with pytest.raises(GoogleOAuthSessionError, match="oauth.scope_mismatch"):
        service.begin_oauth_transaction(
            "google-account-01",
            oauth_client_ref=imported.client_ref,
            redirect_uri="http://127.0.0.1:8765/callback",
            scope_profile="provisioner",  # type: ignore[arg-type]
            expected_generation=1,
            idempotency_key="oauth-wrong-profile",
            principal="operator-one",
        )

    document = json.loads(
        (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
    )
    assert document["transactions"] == []
    assert service._token_writer.writes == []


def test_client_import_recovers_receipt_after_control_write_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, ingress, exchange, manager = _service(tmp_path)
    plan = service.plan_oauth_client_import(
        "google-account-01", expected_generation=1, idempotency_key="import-one"
    )
    session = ingress.put(plan, _client_json())
    original_write = service._write_locked
    writes = 0

    def crash_after_vault_write(document):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise oauth_session.HiveStateError("simulated_crash")
        original_write(document)

    monkeypatch.setattr(service, "_write_locked", crash_after_vault_write)
    with pytest.raises(GoogleOAuthSessionError, match="oauth.client_write_failed"):
        service.apply_oauth_client_import(plan, session)
    monkeypatch.setattr(service, "_write_locked", original_write)

    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path, ingress=ingress, exchange=exchange, manager=manager
    )
    receipt = restarted.reconcile_oauth_client_import(plan, session)
    assert receipt.account_ref == "google-account-01"
    assert receipt.inventory_generation == 1
    assert session.acknowledged is True


def test_token_write_receipt_recovers_after_control_write_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_writer = _TokenWriter()
    clock = _Clock()
    service, ingress, exchange, manager = _service(
        tmp_path, token_writer=token_writer, clock=clock
    )
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    original_write = service._write_locked
    writes = 0

    def crash_after_token_write(document):
        nonlocal writes
        writes += 1
        if writes == 3:
            raise oauth_session.HiveStateError("simulated_crash")
        original_write(document)

    monkeypatch.setattr(service, "_write_locked", crash_after_token_write)
    with pytest.raises(GoogleOAuthSessionError, match="oauth.token_write_failed"):
        _complete(service, transaction)
    monkeypatch.setattr(service, "_write_locked", original_write)
    assert len(token_writer.writes) == 1
    clock.value += 1_000

    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path,
        ingress=ingress,
        exchange=exchange,
        manager=manager,
        token_writer=token_writer,
        clock=clock,
    )
    assert (
        restarted.reconcile_oauth_transaction(
            transaction.id,
            account_ref="google-account-01",
            redirect_uri="http://127.0.0.1:8765/callback",
            expected_generation=1,
            state=_state(transaction),
        ).refresh_token_stored
        is True
    )
    assert len(token_writer.writes) == 1
    assert len(exchange.calls) == 1


def test_concurrent_client_reimport_invalidates_inflight_completion(
    tmp_path: Path,
) -> None:
    started = threading.Event()
    release = threading.Event()

    class BlockingExchange(_Exchange):
        def exchange(self, client, *, code, redirect_uri, pkce_verifier):
            started.set()
            assert release.wait(5)
            return super().exchange(
                client,
                code=code,
                redirect_uri=redirect_uri,
                pkce_verifier=pkce_verifier,
            )

    exchange = BlockingExchange()
    service, ingress, _exchange, _manager_instance = _service(
        tmp_path, exchange=exchange
    )
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    outcome: list[str] = []

    def complete() -> None:
        try:
            _complete(service, transaction)
        except GoogleOAuthSessionError as error:
            outcome.append(error.code)
        else:
            outcome.append("succeeded")

    thread = threading.Thread(target=complete)
    thread.start()
    assert started.wait(5)
    _import_client(service, ingress, key="import-two")
    release.set()
    thread.join(5)

    assert outcome == ["oauth.client_expired"]
    assert service._token_writer.writes == []


def test_client_load_failure_terminalizes_and_removes_callback_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, ingress, _exchange, _manager_instance = _service(tmp_path)
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)

    def fail_load(*_args, **_kwargs):
        raise GoogleOAuthSessionError("oauth.client_expired")

    monkeypatch.setattr(service, "_load_client", fail_load)
    with pytest.raises(GoogleOAuthSessionError, match="oauth.client_expired"):
        _complete(service, transaction)

    document = json.loads(
        (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
    )
    record = next(
        item for item in document["transactions"] if item["id"] == transaction.id
    )
    assert record["state"] == "failed"
    assert record["pkce_verifier"] is None
    assert record["state_token"] is None


def test_unexpected_base_exception_zeroes_token_and_terminalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    held: list[bytearray] = []

    class HoldingExchange(_Exchange):
        def exchange(self, client, *, code, redirect_uri, pkce_verifier):
            result = super().exchange(
                client,
                code=code,
                redirect_uri=redirect_uri,
                pkce_verifier=pkce_verifier,
            )
            held.append(result.refresh_token)
            return result

    class FatalProviderBoundary(BaseException):
        pass

    service, ingress, _exchange, _manager_instance = _service(
        tmp_path, exchange=HoldingExchange()
    )
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    original_subject = service._account_subject
    calls = 0

    def fail_after_exchange(account_ref, generation):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise FatalProviderBoundary()
        return original_subject(account_ref, generation)

    monkeypatch.setattr(service, "_account_subject", fail_after_exchange)
    with pytest.raises(FatalProviderBoundary):
        _complete(service, transaction)

    assert held and held[0] == bytearray(len(held[0]))
    document = json.loads(
        (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
    )
    record = next(
        item for item in document["transactions"] if item["id"] == transaction.id
    )
    assert record["state"] == "failed"
    assert record["pkce_verifier"] is None
    assert record["state_token"] is None


def test_terminal_history_is_pruned_without_dropping_active_transactions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(oauth_session, "_MAX_CONTROL_RECORDS", 2)
    service, ingress, _exchange, _manager_instance = _service(tmp_path)
    _plan, _session, imported = _import_client(service, ingress)
    active = _begin(service, imported.client_ref, idempotency_key="active-begin")
    terminal = _begin(service, imported.client_ref, idempotency_key="terminal-begin")
    with pytest.raises(GoogleOAuthSessionError, match="oauth.state_mismatch"):
        _complete(service, terminal, state="wrong-state")

    replacement = _begin(
        service, imported.client_ref, idempotency_key="replacement-begin"
    )
    document = json.loads(
        (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
    )
    ids = {item["id"] for item in document["transactions"]}
    assert ids == {active.id, replacement.id}
    assert all(item["state"] == "pending" for item in document["transactions"])


def test_corrupt_durable_record_fails_closed_during_service_start(
    tmp_path: Path,
) -> None:
    service, ingress, exchange, manager = _service(tmp_path)
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    path = tmp_path / "oauth-state" / "google-oauth-control.json"
    document = json.loads(path.read_text())
    document["transactions"][0]["inventory_generation"] = "one"
    path.write_text(json.dumps(document))

    with pytest.raises(GoogleOAuthSessionError, match="oauth.control_unavailable"):
        _service(tmp_path, ingress=ingress, exchange=exchange, manager=manager)

    assert transaction.id


def test_valid_v1_records_migrate_before_callback_effect(
    tmp_path: Path,
) -> None:
    token_writer = _TokenWriter()
    service, ingress, exchange, manager = _service(tmp_path, token_writer=token_writer)
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    path = tmp_path / "oauth-state" / "google-oauth-control.json"
    document = json.loads(path.read_text())
    document["schema_version"] = 1
    document["token_generations"] = {}
    document["imports"] = []
    for record in document["clients"]:
        record.pop("state")
        record.pop("terminal_at")
    for record in document["transactions"]:
        for field in (
            "client_vault_generation",
            "state_digest",
            "token_operation_id",
            "authorization_code_digest",
            "effect_subject_id",
            "completion_owner",
            "completion_lease_expires_at",
            "terminal_at",
        ):
            record.pop(field)
    path.write_text(json.dumps(document))

    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path,
        ingress=ingress,
        exchange=exchange,
        manager=manager,
        token_writer=token_writer,
    )
    assert json.loads(path.read_text())["schema_version"] == 3
    assert _complete(restarted, transaction).refresh_token_stored is True


def test_stale_completing_record_is_terminalized_after_restart(
    tmp_path: Path,
) -> None:
    token_writer = _TokenWriter()
    service, ingress, exchange, manager = _service(tmp_path, token_writer=token_writer)
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    path = tmp_path / "oauth-state" / "google-oauth-control.json"
    document = json.loads(path.read_text())
    document["transactions"][0].update(
        {
            "state": "completing",
            "authorization_code_digest": service._digest(
                "google.oauth-code", "first-code"
            ),
            "completion_owner": "oauth-owner-" + "b" * 32,
            "completion_lease_expires_at": 999.0,
        }
    )
    path.write_text(json.dumps(document))

    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path,
        ingress=ingress,
        exchange=exchange,
        manager=manager,
        token_writer=token_writer,
    )
    with pytest.raises(GoogleOAuthSessionError, match="oauth.token_write_failed"):
        _complete(restarted, transaction)
    record = json.loads(path.read_text())["transactions"][0]
    assert record["state"] == "failed"
    assert record["pkce_verifier"] is None
    assert record["state_token"] is None
    assert token_writer.writes == []


def test_client_import_reconciles_vault_effect_after_plan_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = _Clock()
    service, ingress, exchange, manager = _service(tmp_path, clock=clock)
    plan = service.plan_oauth_client_import(
        "google-account-01",
        expected_generation=1,
        idempotency_key="import-expiry-recovery",
        ttl_seconds=1,
    )
    session = ingress.put(plan, _client_json())
    original_write = service._write_locked
    writes = 0

    def crash_after_vault_write(document):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise oauth_session.HiveStateError("simulated_crash")
        original_write(document)

    monkeypatch.setattr(service, "_write_locked", crash_after_vault_write)
    with pytest.raises(GoogleOAuthSessionError, match="oauth.client_write_failed"):
        service.apply_oauth_client_import(plan, session)
    monkeypatch.setattr(service, "_write_locked", original_write)
    clock.value += 2

    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path,
        clock=clock,
        ingress=ingress,
        exchange=exchange,
        manager=manager,
    )
    receipt = restarted.apply_oauth_client_import(plan, session)
    assert receipt.inventory_generation == 1
    assert session.acknowledged is True


def test_token_receipt_reconciles_after_inventory_generation_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_writer = _TokenWriter()
    service, ingress, exchange, manager = _service(tmp_path, token_writer=token_writer)
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    original_write = service._write_locked
    writes = 0

    def crash_after_token_write(document):
        nonlocal writes
        writes += 1
        if writes == 3:
            raise oauth_session.HiveStateError("simulated_crash")
        original_write(document)

    monkeypatch.setattr(service, "_write_locked", crash_after_token_write)
    with pytest.raises(GoogleOAuthSessionError, match="oauth.token_write_failed"):
        _complete(service, transaction)
    monkeypatch.setattr(service, "_write_locked", original_write)
    assert manager.reload().generation == 2

    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path,
        ingress=ingress,
        exchange=exchange,
        manager=manager,
        token_writer=token_writer,
    )
    assert _complete(restarted, transaction).refresh_token_stored is True
    assert len(token_writer.writes) == 1


def test_wrong_retry_does_not_destroy_committed_token_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_writer = _TokenWriter()
    service, ingress, exchange, manager = _service(tmp_path, token_writer=token_writer)
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    original_write = service._write_locked
    writes = 0

    def crash_after_token_write(document):
        nonlocal writes
        writes += 1
        if writes == 3:
            raise oauth_session.HiveStateError("simulated_crash")
        original_write(document)

    monkeypatch.setattr(service, "_write_locked", crash_after_token_write)
    with pytest.raises(GoogleOAuthSessionError, match="oauth.token_write_failed"):
        _complete(service, transaction)
    monkeypatch.setattr(service, "_write_locked", original_write)
    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path,
        ingress=ingress,
        exchange=exchange,
        manager=manager,
        token_writer=token_writer,
    )

    with pytest.raises(GoogleOAuthSessionError, match="oauth.state_mismatch"):
        _complete(restarted, transaction, state="wrong-state")
    document = json.loads(
        (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
    )
    assert document["transactions"][0]["state"] == "persisting"
    assert _complete(restarted, transaction).refresh_token_stored is True


def test_second_service_cannot_terminalize_live_completion_owner(
    tmp_path: Path,
) -> None:
    started = threading.Event()
    release = threading.Event()

    class BlockingExchange(_Exchange):
        def exchange(self, client, *, code, redirect_uri, pkce_verifier):
            started.set()
            assert release.wait(5)
            return super().exchange(
                client,
                code=code,
                redirect_uri=redirect_uri,
                pkce_verifier=pkce_verifier,
            )

    clock = _Clock()
    ingress = _SecretIngress()
    token_writer = _TokenWriter()
    exchange = BlockingExchange()
    manager = _manager(tmp_path)
    owner, _ingress, _exchange, _manager_instance = _service(
        tmp_path,
        clock=clock,
        ingress=ingress,
        token_writer=token_writer,
        exchange=exchange,
        manager=manager,
    )
    _plan, _session, imported = _import_client(owner, ingress)
    transaction = _begin(owner, imported.client_ref)
    outcome: list[str] = []

    thread = threading.Thread(
        target=lambda: outcome.append(
            "succeeded" if _complete(owner, transaction) else "unreachable"
        )
    )
    thread.start()
    assert started.wait(5)
    contender, _ingress, _exchange, _manager_instance = _service(
        tmp_path,
        clock=clock,
        ingress=ingress,
        token_writer=token_writer,
        exchange=exchange,
        manager=manager,
    )
    with pytest.raises(GoogleOAuthSessionError, match="oauth.transaction_expired"):
        _complete(contender, transaction)
    document = json.loads(
        (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
    )
    assert document["transactions"][0]["state"] == "completing"
    release.set()
    thread.join(5)
    assert outcome == ["succeeded"]
    assert len(exchange.calls) == 1


def test_three_callers_cannot_release_another_completion_owner(
    tmp_path: Path,
) -> None:
    started = threading.Event()
    release = threading.Event()

    class BlockingExchange(_Exchange):
        def exchange(self, client, *, code, redirect_uri, pkce_verifier):
            started.set()
            assert release.wait(5)
            return super().exchange(
                client,
                code=code,
                redirect_uri=redirect_uri,
                pkce_verifier=pkce_verifier,
            )

    service, ingress, exchange, _manager_instance = _service(
        tmp_path, exchange=BlockingExchange()
    )
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    outcome: list[str] = []
    owner = threading.Thread(
        target=lambda: outcome.append(
            "succeeded" if _complete(service, transaction) else "unreachable"
        )
    )
    owner.start()
    assert started.wait(5)

    for _attempt in range(2):
        with pytest.raises(GoogleOAuthSessionError, match="oauth.transaction_expired"):
            _complete(service, transaction)
    document = json.loads(
        (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
    )
    assert document["transactions"][0]["state"] == "completing"
    release.set()
    owner.join(5)
    assert outcome == ["succeeded"]
    assert len(exchange.calls) == 1


def test_primary_base_exception_survives_cleanup_base_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class PrimaryFatal(BaseException):
        pass

    class CleanupFatal(BaseException):
        pass

    class FatalExchange(_Exchange):
        def exchange(self, client, *, code, redirect_uri, pkce_verifier):
            raise PrimaryFatal()

    service, ingress, _exchange, _manager_instance = _service(
        tmp_path, exchange=FatalExchange()
    )
    _plan, _session, imported = _import_client(service, ingress)
    transaction = _begin(service, imported.client_ref)
    monkeypatch.setattr(
        service,
        "_terminalize",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CleanupFatal()),
    )

    with pytest.raises(PrimaryFatal):
        _complete(service, transaction)


@pytest.mark.parametrize("boundary", ("read", "ack"))
@pytest.mark.parametrize("fatal", (False, True))
def test_secret_ingress_errors_are_typed_and_redacted(
    tmp_path: Path, boundary: str, fatal: bool
) -> None:
    marker = "private-ingress-exception-marker"

    class SecretIngressFailure(BaseException if fatal else Exception):
        def __str__(self) -> str:
            return marker

        def __repr__(self) -> str:
            return marker

    class FailingIngress(_SecretIngress):
        def read_oauth_client(self, *args, **kwargs):
            if boundary == "read":
                raise SecretIngressFailure()
            return super().read_oauth_client(*args, **kwargs)

        def acknowledge_oauth_client(self, *args, **kwargs):
            if boundary == "ack":
                raise SecretIngressFailure()
            return super().acknowledge_oauth_client(*args, **kwargs)

    ingress = FailingIngress()
    service, _ingress, _exchange, _manager_instance = _service(
        tmp_path, ingress=ingress
    )
    plan = service.plan_oauth_client_import(
        "google-account-01",
        expected_generation=1,
        idempotency_key=f"ingress-{boundary}-{fatal}",
    )
    session = ingress.put(plan, _client_json())

    with pytest.raises(GoogleOAuthSessionError) as caught:
        service.apply_oauth_client_import(plan, session)
    assert caught.value.code == "credential.upload_expired"
    rendered = repr(caught.value) + str(caught.value)
    assert marker not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    if boundary == "read":
        document = json.loads(
            (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
        )
        assert document["imports"][0]["state"] == "expired"
        assert session.acknowledged is True


def test_secret_ingress_callable_property_failure_is_typed_and_redacted(
    tmp_path: Path,
) -> None:
    marker = "private-ingress-property-marker"

    class PropertyFailure(BaseException):
        def __str__(self) -> str:
            return marker

    class PropertyIngress:
        @property
        def read_oauth_client(self):
            raise PropertyFailure()

        def acknowledge_oauth_client(self, *args, **kwargs):
            raise AssertionError("not reached")

    manager = _manager(tmp_path)
    clock = _Clock()
    with pytest.raises(GoogleOAuthSessionError) as caught:
        oauth_session.GoogleOAuthControlService(
            tmp_path / "oauth-state",
            manager=manager,
            client_vault=CredentialVault.for_test(
                tmp_path / "client-vault", key=b"k" * 32, clock=clock
            ),
            token_writer=_TokenWriter(),
            secret_ingress=PropertyIngress(),
            code_exchange=_Exchange(),
            clock=clock,
        )
    assert caught.value.code == "oauth.control_unavailable"
    assert marker not in repr(caught.value) + str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_ingress_ack_failure_remains_retryable_until_claim_cleanup(
    tmp_path: Path,
) -> None:
    marker = "private-ack-retry-marker"

    class RetryableAckIngress(_SecretIngress):
        fail = True

        def acknowledge_oauth_client(self, *args, **kwargs):
            if self.fail:
                raise RuntimeError(marker)
            return super().acknowledge_oauth_client(*args, **kwargs)

    ingress = RetryableAckIngress()
    service, _ingress, _exchange, _manager_instance = _service(
        tmp_path, ingress=ingress
    )
    plan = service.plan_oauth_client_import(
        "google-account-01", expected_generation=1, idempotency_key="ack-retry"
    )
    session = ingress.put(plan, _client_json())

    with pytest.raises(GoogleOAuthSessionError, match="credential.upload_expired"):
        service.apply_oauth_client_import(plan, session)
    document = json.loads(
        (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
    )
    assert document["imports"][0]["state"] == "ack_pending"
    assert session.acknowledged is False
    ingress.fail = False
    receipt = service.apply_oauth_client_import(plan, session)
    assert receipt.inventory_generation == 1
    assert session.acknowledged is True


def test_acknowledged_import_recovers_after_final_journal_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, ingress, exchange, manager = _service(tmp_path)
    plan = service.plan_oauth_client_import(
        "google-account-01", expected_generation=1, idempotency_key="ack-crash"
    )
    session = ingress.put(plan, _client_json())
    original_write = service._write_locked
    writes = 0

    def crash_after_ack(document):
        nonlocal writes
        writes += 1
        if writes == 3:
            raise oauth_session.HiveStateError("simulated_crash")
        original_write(document)

    monkeypatch.setattr(service, "_write_locked", crash_after_ack)
    with pytest.raises(GoogleOAuthSessionError, match="oauth.client_write_failed"):
        service.apply_oauth_client_import(plan, session)
    assert session.acknowledged is True
    monkeypatch.setattr(service, "_write_locked", original_write)

    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path, ingress=ingress, exchange=exchange, manager=manager
    )
    receipt = restarted.apply_oauth_client_import(plan, session)
    assert receipt.inventory_generation == 1
    assert session.acknowledged is True
    assert ingress.ack_calls == [plan.plan_digest, plan.plan_digest]
    assert ingress.receipts == {
        plan.plan_digest: (
            plan.account_ref,
            plan.expected_generation,
            plan.plan_digest,
        )
    }


def test_expired_import_retries_claim_cleanup_before_terminalizing(
    tmp_path: Path,
) -> None:
    class RetryableAckIngress(_SecretIngress):
        fail = True

        def acknowledge_oauth_client(self, *args, **kwargs):
            if self.fail:
                raise RuntimeError("private-expiry-cleanup-marker")
            return super().acknowledge_oauth_client(*args, **kwargs)

    clock = _Clock()
    ingress = RetryableAckIngress()
    service, _ingress, _exchange, _manager_instance = _service(
        tmp_path, clock=clock, ingress=ingress
    )
    plan = service.plan_oauth_client_import(
        "google-account-01",
        expected_generation=1,
        idempotency_key="expiry-cleanup",
        ttl_seconds=1,
    )
    session = ingress.put(plan, _client_json())
    clock.value += 2

    with pytest.raises(GoogleOAuthSessionError, match="credential.upload_expired"):
        service.apply_oauth_client_import(plan, session)
    document = json.loads(
        (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
    )
    assert document["imports"][0]["state"] == "cleanup"
    ingress.fail = False
    with pytest.raises(GoogleOAuthSessionError, match="oauth.import_plan_expired"):
        service.apply_oauth_client_import(plan, session)
    assert session.acknowledged is True
    document = json.loads(
        (tmp_path / "oauth-state" / "google-oauth-control.json").read_text()
    )
    assert document["imports"][0]["state"] == "expired"


def test_v1_ambiguous_import_migrates_to_manual_repair_block(
    tmp_path: Path,
) -> None:
    service, ingress, exchange, manager = _service(tmp_path)
    plan = service.plan_oauth_client_import(
        "google-account-01", expected_generation=1, idempotency_key="legacy-claim"
    )
    path = tmp_path / "oauth-state" / "google-oauth-control.json"
    document = json.loads(path.read_text())
    document["schema_version"] = 1
    document["token_generations"] = {}
    document["imports"][0].pop("terminal_at")
    document["imports"][0]["state"] = "applying"
    path.write_text(json.dumps(document))

    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path, ingress=ingress, exchange=exchange, manager=manager
    )
    migrated = json.loads(path.read_text())
    assert migrated["imports"][0]["state"] == "repair_required"
    with pytest.raises(GoogleOAuthSessionError, match="oauth.client_repair_required"):
        restarted.plan_oauth_client_import(
            "google-account-01",
            expected_generation=1,
            idempotency_key="new-import",
        )
    assert plan.account_ref == "google-account-01"


def test_v1_succeeded_import_migrates_terminal_without_obsolete_ack(
    tmp_path: Path,
) -> None:
    service, ingress, exchange, manager = _service(tmp_path)
    _plan, _session, receipt = _import_client(service, ingress)
    path = tmp_path / "oauth-state" / "google-oauth-control.json"
    document = json.loads(path.read_text())
    record = document["imports"][0]
    nonce = "v1-terminal-import-nonce"
    plan_digest = service._digest(
        "google.oauth-client-import",
        record["id"],
        record["account_ref"],
        record["expected_generation"],
        record["expires_at"],
        record["idempotency_key"],
        nonce,
    )
    record.update({"nonce": nonce, "plan_digest": plan_digest, "state": "succeeded"})
    record.pop("terminal_at")
    for client in document["clients"]:
        client.pop("state")
        client.pop("terminal_at")
    document.update(
        {
            "schema_version": 1,
            "token_generations": {},
            "transactions": [],
        }
    )
    path.write_text(json.dumps(document))
    legacy_plan = oauth_session.GoogleOAuthClientImportPlanV1(
        record["id"],
        record["account_ref"],
        record["expected_generation"],
        record["expires_at"],
        record["idempotency_key"],
        plan_digest,
    )

    restarted, _ingress, _exchange, _manager_instance = _service(
        tmp_path, ingress=ingress, exchange=exchange, manager=manager
    )
    migrated = json.loads(path.read_text())
    assert migrated["imports"][0]["state"] == "succeeded"
    assert restarted.apply_oauth_client_import(legacy_plan, object()) == receipt
