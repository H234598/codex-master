from __future__ import annotations

import json
import pickle
import urllib.parse

import pytest

import the_hive.google_oauth_session as oauth
import the_hive.google_inventory_desktop_client_registry as registry
from test_google_inventory_desktop_client_registry import (
    _document,
    _record,
    registry_store as registry_store,
)
from test_google_oauth_session import (
    _InventoryReadonlyExchange,
    _InventoryReadonlyVerifier,
)
from the_hive.google_account_inventory import GoogleAccountInventoryLoader
from the_hive.google_account_inventory_manager import GoogleAccountInventoryManager


@pytest.fixture
def bound_service(tmp_path, registry_store):
    store, path = registry_store
    store._replace(
        registry.InventoryDesktopClientRegistryV1.parse(
            _document([_record("google-synthetic-account-01")])
        ),
        expected_generation=0,
    )
    inventory = tmp_path / "synthetic-inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "authority_generation": 1,
                "google_accounts": [
                    {
                        "ref": "google-synthetic-account-01",
                        "login_email": "synthetic-one@example.test",
                        "subject_id": "synthetic-subject-one",
                        "billing_accounts": [],
                        "projects": [],
                    }
                ],
            }
        )
    )
    inventory.chmod(0o600)
    manager = GoogleAccountInventoryManager._for_test_loader(
        GoogleAccountInventoryLoader._for_test_path(inventory).load,
        monotonic_clock=lambda: 1.0,
        operator_timestamp_utc=lambda: "2026-09-15T12:00:00Z",
    )
    manager.reload()
    service = oauth.GoogleOAuthControlService._from_inventory_registry(
        registry=store,
        manager=manager,
    )
    service._inventory_code_exchange = _InventoryReadonlyExchange()
    service._inventory_id_token_verifier = _InventoryReadonlyVerifier()
    return service, store, path


def test_bound_inventory_owner_has_only_ram_transaction_and_clears_success(
    bound_service,
) -> None:
    service, _store, path = bound_service
    before = {
        item.name: item.read_bytes() for item in path.parent.iterdir() if item.is_file()
    }
    handle = service._begin_inventory_readonly_authorization(
        redirect_uri="http://127.0.0.1:8765/callback"
    )
    assert not hasattr(service, "_state")
    assert not hasattr(service, "_client_vault")
    assert "synthetic" not in repr(handle)
    with pytest.raises(TypeError):
        pickle.dumps(handle)
    query = urllib.parse.parse_qs(
        urllib.parse.urlsplit(handle.authorization_url.decode("ascii")).query
    )
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"][0].encode("ascii") == handle.state
    assert query["nonce"][0].encode("ascii") == handle.nonce
    assert "cloud-platform.read-only" in query["scope"][0]
    handle.callback_state.extend(handle.state)
    handle.code.extend(b"synthetic-code")
    buffers = [
        handle.state,
        handle.verifier,
        handle.nonce,
        handle.code,
        handle.callback_state,
        handle.authorization_url,
    ]
    effect = service._complete_inventory_readonly_authorization(handle)
    assert service._inventory_pending_handle is None
    assert all(buffer == bytearray(len(buffer)) for buffer in buffers)
    assert service._inventory_code_exchange.access_token == bytearray(
        len(service._inventory_code_exchange.access_token)
    )
    assert service._inventory_code_exchange.id_token == bytearray(
        len(service._inventory_code_exchange.id_token)
    )
    assert before == {
        item.name: item.read_bytes() for item in path.parent.iterdir() if item.is_file()
    }
    assert effect._consume_for_authority()[0] == "google-synthetic-account-01"
    with pytest.raises(oauth.GoogleOAuthSessionError):
        service._complete_inventory_readonly_authorization(handle)


@pytest.mark.parametrize(
    "failure",
    [
        "state",
        "expired",
        "registry",
        "fingerprint",
        "registry_fingerprint",
        "nonce",
        "cancel",
        "malformed",
    ],
)
def test_bound_inventory_owner_clears_every_callback_failure(
    bound_service, failure
) -> None:
    service, store, path = bound_service
    handle = service._begin_inventory_readonly_authorization(
        redirect_uri="http://127.0.0.1:8765/callback"
    )
    handle.callback_state.extend(handle.state)
    handle.code.extend(b"synthetic-code")
    buffers = [
        handle.state,
        handle.verifier,
        handle.nonce,
        handle.code,
        handle.callback_state,
        handle.authorization_url,
    ]
    if failure == "state":
        handle.callback_state[:] = b"wrong-synthetic-state"
    elif failure == "expired":
        service._clock = lambda: handle.expires_at + 1
    elif failure == "registry":
        value = json.loads(store.load().canonical_bytes())
        value["registry_generation"] = 2
        store._replace(
            registry.InventoryDesktopClientRegistryV1.parse(json.dumps(value).encode()),
            expected_generation=1,
        )
    elif failure == "fingerprint":
        path.write_bytes(
            _document(
                [
                    _record(
                        "google-synthetic-account-01",
                        "000000000000-otherclient.apps.googleusercontent.com",
                    )
                ]
            )
        )
    elif failure == "registry_fingerprint":
        path.write_bytes(
            _document(
                [
                    _record("google-synthetic-account-01"),
                    _record(
                        "unmapped-synthetic-account",
                        "000000000000-otherclient.apps.googleusercontent.com",
                    ),
                ]
            )
        )
    elif failure == "nonce":
        from test_google_oauth_session import _WrongInventoryReadonlyNonceVerifier

        service._inventory_id_token_verifier = _WrongInventoryReadonlyNonceVerifier()
    elif failure == "cancel":

        def cancelled(*args, **kwargs):
            raise KeyboardInterrupt

        service._inventory_code_exchange.exchange_inventory_readonly = cancelled
    else:
        handle.code.clear()
    with pytest.raises((oauth.GoogleOAuthSessionError, KeyboardInterrupt)):
        service._complete_inventory_readonly_authorization(handle)
    assert service._inventory_pending_handle is None
    assert all(buffer == bytearray(len(buffer)) for buffer in buffers)


def test_bound_inventory_resolver_requires_exactly_one_account(
    bound_service, monkeypatch
) -> None:
    service, store, _path = bound_service
    monkeypatch.setattr(
        type(store),
        "load",
        lambda self: registry.InventoryDesktopClientRegistryV1(1, ()),
    )
    with pytest.raises(
        oauth.GoogleOAuthSessionError, match="oauth.inventory_unavailable"
    ):
        service._begin_inventory_readonly_authorization(
            redirect_uri="http://127.0.0.1:8765/callback"
        )


def test_bound_inventory_resolver_rejects_multiple_accounts(
    bound_service, tmp_path
) -> None:
    service, store, _path = bound_service
    path = tmp_path / "synthetic-inventory.json"
    value = json.loads(path.read_bytes())
    value["authority_generation"] = 2
    value["google_accounts"].append(
        {
            "ref": "google-synthetic-account-02",
            "login_email": "synthetic-two@example.test",
            "subject_id": "synthetic-subject-two",
            "billing_accounts": [],
            "projects": [],
        }
    )
    path.write_text(json.dumps(value))
    service._manager.reload(expected_generation=1)
    document = json.loads(
        _document(
            [
                _record("google-synthetic-account-01"),
                _record(
                    "google-synthetic-account-02",
                    "000000000000-secondclient.apps.googleusercontent.com",
                ),
            ]
        )
    )
    document["registry_generation"] = 2
    store._replace(
        registry.InventoryDesktopClientRegistryV1.parse(json.dumps(document).encode()),
        expected_generation=1,
    )
    with pytest.raises(
        oauth.GoogleOAuthSessionError, match="oauth.inventory_unavailable"
    ):
        service._begin_inventory_readonly_authorization(
            redirect_uri="http://127.0.0.1:8765/callback"
        )


class _SyntheticConnection:
    def __init__(self, request):
        self.request = request
        self.closed = False
        self.responses = []

    def settimeout(self, seconds):
        assert 0 < seconds <= 600

    def recv(self, maximum):
        result, self.request = self.request[:maximum], self.request[maximum:]
        return result

    def sendall(self, value):
        self.responses.append(value)

    def close(self):
        self.closed = True


class _SyntheticListener:
    def __init__(self):
        self.bound = None
        self.closed = False
        self.accepts = 0
        self.connection = None

    def bind(self, address):
        self.bound = address

    def settimeout(self, seconds):
        assert 0 < seconds <= 600

    def listen(self, backlog):
        assert backlog == 1

    def getsockname(self):
        return "127.0.0.1", 49152

    def accept(self):
        self.accepts += 1
        assert self.accepts == 1
        return self.connection, ("127.0.0.1", 49200)

    def close(self):
        self.closed = True


@pytest.fixture
def synthetic_driver(monkeypatch):
    for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "WAYLAND_DISPLAY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DISPLAY", ":999")
    listener = _SyntheticListener()
    calls = []

    def socket_factory(family, kind):
        assert family == oauth.socket.AF_INET
        assert kind == oauth.socket.SOCK_STREAM
        return listener

    monkeypatch.setattr(oauth.socket, "socket", socket_factory)
    monkeypatch.setattr(
        oauth.subprocess, "run", lambda args, **kwargs: calls.append((args, kwargs))
    )
    driver = oauth._InventoryReadonlyLoopbackDriverV1()
    return driver, listener, calls


def test_private_loopback_driver_binds_os_port_and_accepts_exactly_one_get(
    bound_service, synthetic_driver
) -> None:
    service, _store, _path = bound_service
    driver, listener, calls = synthetic_driver
    redirect = driver._open()
    assert listener.bound == ("127.0.0.1", 0)
    assert redirect == "http://127.0.0.1:49152/callback"
    handle = service._begin_inventory_readonly_authorization(redirect_uri=redirect)
    listener.connection = _SyntheticConnection(
        b"GET /callback?code=synthetic-code&state="
        + handle.state
        + b" HTTP/1.1\r\nHost: 127.0.0.1:49152\r\n\r\n"
    )
    driver._receive(handle)
    assert handle.code == b"synthetic-code"
    assert handle.callback_state == handle.state
    assert listener.accepts == 1 and listener.closed and listener.connection.closed
    assert calls[0][0][0] == "/usr/bin/xdg-open"
    assert len(calls[0][0]) == 2
    assert "synthetic-code" not in str(listener.connection.responses)
    assert "synthetic" not in repr(driver)
    with pytest.raises(TypeError):
        pickle.dumps(driver)
    driver.clear()
    handle.clear()


@pytest.mark.parametrize(
    "callback_request",
    [
        b"POST /callback?code=x&state=y HTTP/1.1\r\nHost: 127.0.0.1:49152\r\n\r\n",
        b"GET /other?code=x&state=y HTTP/1.1\r\nHost: 127.0.0.1:49152\r\n\r\n",
        b"GET /callback?code=x&code=z&state=y HTTP/1.1\r\nHost: 127.0.0.1:49152\r\n\r\n",
        b"GET /callback?code=x&state=y HTTP/1.1\r\nHost: untrusted.example.test\r\n\r\n",
        b"GET /callback?error=access_denied&state=y HTTP/1.1\r\nHost: 127.0.0.1:49152\r\n\r\n",
        b"x" * (16 * 1024 + 1),
    ],
)
def test_private_loopback_driver_closes_and_clears_malformed_callback(
    bound_service, synthetic_driver, callback_request
) -> None:
    service, _store, _path = bound_service
    driver, listener, _calls = synthetic_driver
    handle = service._begin_inventory_readonly_authorization(
        redirect_uri=driver._open()
    )
    buffers = [handle.state, handle.verifier, handle.nonce, handle.authorization_url]
    listener.connection = _SyntheticConnection(callback_request)
    with pytest.raises(oauth.GoogleOAuthSessionError):
        driver._receive(handle)
    assert listener.closed and listener.connection.closed
    assert all(value == bytearray(len(value)) for value in buffers)


@pytest.mark.parametrize("remote", [False, True, "display"])
def test_private_loopback_driver_headless_or_remote_never_opens_socket(
    synthetic_driver, monkeypatch, remote
) -> None:
    driver, listener, calls = synthetic_driver
    if remote == "display":
        monkeypatch.setenv("DISPLAY", "synthetic-remote.example.test:0")
    elif remote:
        monkeypatch.setenv("SSH_CONNECTION", "synthetic-remote")
    else:
        monkeypatch.delenv("DISPLAY")
    with pytest.raises(
        oauth.GoogleOAuthSessionError, match="interactive_authorization_required"
    ):
        driver._open()
    assert listener.bound is None
    assert calls == []


def test_production_leaf_selects_registry_bound_account_without_caller_inputs(
    bound_service, synthetic_driver, monkeypatch
) -> None:
    service, store, _path = bound_service
    _driver, listener, _calls = synthetic_driver
    from the_hive.google_inventory_token_vault import (
        _TheHiveInventoryVaultProductionComponents,
    )

    components = _TheHiveInventoryVaultProductionComponents(store._layout)
    leaf = oauth._new_the_hive_inventory_readonly_authorization_port(
        vault_components=components,
        manager=service._manager,
    )
    assert type(leaf._control_service) is oauth.GoogleOAuthControlService
    assert not hasattr(leaf._control_service, "_state")
    leaf._control_service._inventory_code_exchange = service._inventory_code_exchange
    leaf._control_service._inventory_id_token_verifier = (
        service._inventory_id_token_verifier
    )

    def open_browser(args, **kwargs):
        state = urllib.parse.parse_qs(urllib.parse.urlsplit(args[1]).query)["state"][0]
        listener.connection = _SyntheticConnection(
            f"GET /callback?code=synthetic-code&state={state} HTTP/1.1\r\nHost: 127.0.0.1:49152\r\n\r\n".encode(
                "ascii"
            )
        )

    monkeypatch.setattr(oauth.subprocess, "run", open_browser)
    effect = leaf.authorize()
    assert effect._consume_for_authority()[0] == "google-synthetic-account-01"
    assert leaf._control_service._inventory_pending_handle is None
    with pytest.raises(TypeError):
        leaf.authorize(account_ref="caller-selected")


def test_production_leaf_cancellation_clears_handle_and_closes_listener(
    bound_service, synthetic_driver, monkeypatch
) -> None:
    service, store, _path = bound_service
    _driver, listener, _calls = synthetic_driver
    from the_hive.google_inventory_token_vault import (
        _TheHiveInventoryVaultProductionComponents,
    )

    leaf = oauth._new_the_hive_inventory_readonly_authorization_port(
        vault_components=_TheHiveInventoryVaultProductionComponents(store._layout),
        manager=service._manager,
    )
    assert leaf._control_service is not None
    captured = []

    def cancelled(*args, **kwargs):
        handle = leaf._control_service._inventory_pending_handle
        captured.extend(
            (handle.state, handle.nonce, handle.verifier, handle.authorization_url)
        )
        raise KeyboardInterrupt

    monkeypatch.setattr(oauth.subprocess, "run", cancelled)
    with pytest.raises(KeyboardInterrupt):
        leaf.authorize()
    assert listener.closed
    assert leaf._control_service._inventory_pending_handle is None
    assert all(value == bytearray(len(value)) for value in captured)
