"""Synthetic direct tests of the private Vault-owned scan lease; no provider IO."""

from copy import copy, deepcopy
import hashlib
import http.client
import inspect
import json
import os
import pickle
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
import yaml

from the_hive import google_account_inventory as inventory
from the_hive import google_inventory_desktop_client_registry as registry
from the_hive import google_inventory_readonly_scan as scan
from the_hive import google_inventory_token_vault as vault
from the_hive.google_account_inventory_manager import GoogleAccountInventoryManager
from the_hive.google_oauth_authorization import GoogleOAuthOperationV1 as Operation


def _fingerprint(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


class _LeaseState(SimpleNamespace):
    @property
    def broker(self):
        if not hasattr(self, "_broker"):
            factory = getattr(vault, "_new_inventory_readonly_scan_broker", None)
            assert callable(factory), "private scan broker factory is missing"
            self._broker = factory(self.components._vault, self.manager)
        return self._broker


class _OfflineConnection:
    def __init__(self, owner, host, *, timeout):
        self.owner, self.host, self.closed = owner, host, False
        assert timeout == 10
        owner.connections.append(self)

    def request(self, method, url, body=None, headers=None):
        self.owner.calls.append(
            (self.host, method, url, bytes(body or b""), dict(headers or {}))
        )
        if body is not None:
            self.owner.buffers.append(body)
        if self.owner.request_error:
            raise RuntimeError("synthetic-private-http-error")

    def getresponse(self):
        status, raw = self.owner.responses.pop(0)
        self.status = status
        self.raw = raw
        return self

    def read(self, maximum):
        return self.raw[:maximum]

    def close(self):
        self.closed = True


@pytest.fixture
def state(tmp_path, monkeypatch):
    """Real Vault, Registry, loader and receipt, backed only by temporary fixtures."""
    offline = SimpleNamespace(
        calls=[], connections=[], buffers=[], responses=[], request_error=False
    )
    monkeypatch.setattr(
        http.client,
        "HTTPSConnection",
        lambda host, *, timeout: _OfflineConnection(offline, host, timeout=timeout),
    )
    tmp_path.chmod(0o700)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    code, identity = vault._validated_directory_identity(
        fd,
        expected_owner=os.geteuid(),
        exact_mode=0o700,
        reject_group_world_write=False,
    )
    assert code is None
    root = vault._DirectoryCapability(
        [
            vault._DirectoryNode(
                fd,
                None,
                identity,
                expected_owner=os.geteuid(),
                exact_mode=0o700,
                reject_group_world_write=False,
            )
        ]
    )
    components = vault._for_test_the_hive_inventory_vault_production_components(root)
    vault._close_directory_capability(root)
    components._preflight_for_inventory_authorize()
    client = dict(
        account_ref="synthetic-account",
        client_id="000000000000-synthetic.apps.googleusercontent.com",
        client_type="installed",
        auth_uri="https://accounts.google.com/o/oauth2/auth",
        token_uri="https://oauth2.googleapis.com/token",
        redirect_kind="ipv4_loopback_ephemeral_callback",
    )
    client["fingerprint"] = _fingerprint(
        json.dumps(client, sort_keys=True, separators=(",", ":"))
    )
    registry_value = registry.InventoryDesktopClientRegistryV1.parse(
        json.dumps(
            dict(
                format_version=1,
                record_kind="inventory_desktop_client_registry_v1",
                registry_generation=1,
                records=[client],
            )
        ).encode()
    )
    registry_store = registry._InventoryDesktopClientRegistryStoreV1(components._layout)
    registry_store._replace(registry_value, expected_generation=0)
    source = dict(
        schema_version=3,
        authority_generation=7,
        google_accounts=[
            dict(
                ref="synthetic-account",
                login_email="synthetic@example.invalid",
                recovery_email=None,
                label="Synthetic",
                subject_id="synthetic-subject",
                billing_accounts=[],
                projects=[],
            )
        ],
    )
    source_path = tmp_path / "synthetic-inventory.yaml"
    source_path.write_text(yaml.safe_dump(source))
    source_path.chmod(0o600)
    loader = inventory.GoogleAccountInventoryLoader._for_test_path(source_path)
    manager = GoogleAccountInventoryManager._for_test_loader(
        loader.load,
        monotonic_clock=lambda: 1.0,
        operator_timestamp_utc=lambda: "2026-09-15T12:00:00Z",
    )
    manager.reload()
    operation = _fingerprint("synthetic-operation")
    port = vault._new_inventory_readonly_authorization_token_port(
        components._vault, manager
    )
    receipt = port.store_authorization_refresh_token(
        operation_digest=operation,
        account_ref="synthetic-account",
        subject_id="synthetic-subject",
        oauth_client_fingerprint=client["fingerprint"],
        inventory_generation=7,
        expected_vault_generation=None,
        refresh_token=bytearray(b"synthetic-refresh"),
    )
    binding = dict(
        account_ref="synthetic-account",
        subject_id="synthetic-subject",
        inventory_generation=7,
        content_fingerprint=manager._snapshot_for_internal_use().content_fingerprint,
        oauth_client_fingerprint=client["fingerprint"],
        scope_fingerprint=port._scope_fingerprint(),
        receipt_operation_digest=operation,
        receipt_binding_fingerprint=receipt._binding_fingerprint,
    )
    try:
        yield _LeaseState(
            binding=binding,
            manager=manager,
            components=components,
            source=source,
            source_path=source_path,
            registry_store=registry_store,
            client=client,
            offline=offline,
            root=tmp_path,
        )
    finally:
        manager.close()
        components.clear()


def _issue(state):
    return state.broker.issue_scan_capability(**state.binding)


def _claim(state, capability):
    binding = {
        key: value
        for key, value in state.binding.items()
        if not key.startswith("receipt_")
    }
    capability._consume_for_discovery(state.broker, **binding)
    capability._claim_for_fixed_discovery(state.broker)


def _refresh_response(**changes):
    value = dict(access_token="synthetic-access", token_type="Bearer", expires_in=3600)
    value.update(changes)
    return 200, json.dumps(value).encode()


def _open(state):
    capability = _issue(state)
    _claim(state, capability)
    state.offline.responses.append(_refresh_response())
    return capability, state.broker._open_readonly_discovery_lease(capability)


def test_private_broker_fixed_factory_and_nonserializable_capabilities(state):
    assert state.broker is not None
    assert tuple(
        inspect.signature(vault._new_inventory_readonly_scan_broker).parameters
    ) == ("vault", "manager")
    for value in (state.broker, _issue(state)):
        assert "synthetic" not in repr(value)
        for operation in (copy, deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(value)
    for owners in ((object(), state.manager), (state.components._vault, object())):
        with pytest.raises(vault.GoogleInventoryReadonlyTokenVaultError):
            vault._new_inventory_readonly_scan_broker(*owners)
    assert state.offline.calls == []


def test_lease_refreshes_once_with_fixed_request_and_closes_all_buffers(
    state, monkeypatch
):
    zeroed = []
    original_zero = vault._zero

    def observe_zero(buffer):
        if type(buffer) is bytearray:
            zeroed.append(buffer)
        original_zero(buffer)

    monkeypatch.setattr(vault, "_zero", observe_zero)
    capability, lease = _open(state)
    host, method, path, body, headers = state.offline.calls[0]
    assert (host, method, path) == ("oauth2.googleapis.com", "POST", "/token")
    assert parse_qs(body.decode()) == {
        "grant_type": ["refresh_token"],
        "client_id": [state.client["client_id"]],
        "refresh_token": ["synthetic-refresh"],
    }
    assert headers == {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    target = lease._target_account_for_discovery()
    assert target == state.source["google_accounts"][0]
    target["label"] = "mutated caller copy"
    assert lease._target_account_for_discovery()["label"] == "Synthetic"
    for operation in (copy, deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(lease)
    assert "synthetic" not in repr(lease)
    lease._close()
    lease._close()
    state.broker.close_scan_capability(capability)
    assert all(connection.closed for connection in state.offline.connections)
    assert all(
        buffer == bytearray(len(buffer)) for buffer in state.offline.buffers + zeroed
    )
    for call in (
        lambda: lease._target_account_for_discovery(),
        lambda: state.broker._open_readonly_discovery_lease(capability),
        lambda: lease._read_fixed_page(
            Operation.PROJECTS_SEARCH, project_number=None, page_token=None
        ),
    ):
        with pytest.raises(vault.GoogleInventoryReadonlyTokenVaultError):
            call()
    assert len(state.offline.calls) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("receipt_operation_digest", "sha256:" + "0" * 64),
        ("receipt_binding_fingerprint", "sha256:" + "0" * 64),
        ("inventory_generation", True),
        ("account_ref", "other-account"),
        ("subject_id", "other-subject"),
        ("content_fingerprint", "sha256:" + "0" * 64),
        ("oauth_client_fingerprint", "sha256:" + "0" * 64),
        ("scope_fingerprint", "sha256:" + "0" * 64),
        ("receipt_operation_digest", object()),
    ],
)
def test_broker_rejects_unbound_receipt_or_identity_before_transport(
    state, field, value
):
    binding = dict(state.binding, **{field: value})
    with pytest.raises(vault.GoogleInventoryReadonlyTokenVaultError):
        state.broker.issue_scan_capability(**binding)
    assert state.offline.calls == []


@pytest.mark.parametrize(
    "drift",
    [
        "generation",
        "content",
        "subject",
        "schema",
        "receipt",
        "client",
        "record_mode",
        "record_symlink",
    ],
)
def test_lease_rechecks_durable_source_registry_and_receipt_before_refresh(
    state, drift
):
    capability = _issue(state)
    _claim(state, capability)
    if drift == "generation":
        state.source["authority_generation"] = 8
    elif drift == "content":
        state.source["google_accounts"][0]["label"] = "Changed"
    elif drift == "subject":
        state.source["google_accounts"][0]["subject_id"] = "changed-subject"
    elif drift == "schema":
        state.source["schema_version"] = 2
        state.source.pop("authority_generation")
    elif drift == "client":
        state.registry_store._replace(
            registry.InventoryDesktopClientRegistryV1(2, ()), expected_generation=1
        )
    else:
        path = state.root / "the-hive-mcp/google-oauth/tokens/synthetic-account.json"
        if drift == "record_mode":
            path.chmod(0o644)
        elif drift == "record_symlink":
            moved = path.with_suffix(".synthetic")
            path.rename(moved)
            path.symlink_to(moved)
        else:
            record = json.loads(path.read_bytes())
            record["operation_digest"] = _fingerprint("changed-receipt")
            path.write_text(json.dumps(record))
    state.source_path.write_text(yaml.safe_dump(state.source))
    if drift in {"generation", "content", "subject", "schema"}:
        try:
            state.manager.reload()
        except inventory.GoogleAccountInventoryError:
            pass
    with pytest.raises(vault.GoogleInventoryReadonlyTokenVaultError):
        state.broker._open_readonly_discovery_lease(capability)
    assert state.offline.calls == []


def test_broker_accepts_exact_transaction_rehydration_without_invoking_loader(state):
    manager = GoogleAccountInventoryManager._from_authority_bytes(
        state.source_path.read_bytes()
    )

    def forbidden_reload():
        raise AssertionError("transaction bytes must not be reread")

    manager._document_loader = forbidden_reload
    state._broker = vault._new_inventory_readonly_scan_broker(
        state.components._vault, manager
    )
    try:
        capability, lease = _open(state)
        assert (
            lease._target_account_for_discovery() == state.source["google_accounts"][0]
        )
        lease._close()
        state.broker.close_scan_capability(capability)
    finally:
        manager.close()


def test_broker_rejects_unconsumed_forged_and_replayed_capabilities(state):
    issued = _issue(state)
    with pytest.raises(vault.GoogleInventoryReadonlyTokenVaultError):
        state.broker._open_readonly_discovery_lease(issued)
    forged = scan._issue_scan_capability_for_broker(
        state.broker,
        **{k: v for k, v in state.binding.items() if not k.startswith("receipt_")},
    )
    _claim(state, forged)
    with pytest.raises(vault.GoogleInventoryReadonlyTokenVaultError):
        state.broker._open_readonly_discovery_lease(forged)
    state.broker.close_scan_capability(issued)
    assert state.offline.calls == []


@pytest.mark.parametrize("invalid", [{}, [], object()])
def test_open_rejects_foreign_objects_without_running_their_hash_or_equality(
    state, invalid
):
    capability, lease = _open(state)
    with pytest.raises(vault.GoogleInventoryReadonlyTokenVaultError):
        state.broker._open_readonly_discovery_lease(invalid)
    assert len(state.offline.calls) == 1
    lease._close()
    state.broker.close_scan_capability(capability)


def test_refresh_cancellation_zeroes_allocated_access_buffer(state, monkeypatch):
    buffers = []
    original_zero = vault._zero

    def observe_zero(buffer):
        if type(buffer) is bytearray:
            buffers.append(buffer)
        original_zero(buffer)

    monkeypatch.setattr(vault, "_zero", observe_zero)

    def interrupt_clock():
        raise KeyboardInterrupt

    capability = _issue(state)
    _claim(state, capability)
    state.offline.responses.append(_refresh_response())
    monkeypatch.setattr(vault.time, "monotonic", interrupt_clock)
    with pytest.raises(KeyboardInterrupt):
        state.broker._open_readonly_discovery_lease(capability)
    # The access buffer is allocated before expiry is computed; cancellation
    # must erase it as well as the refresh request, not merely close the socket.
    assert any(len(buffer) == len(b"synthetic-access") for buffer in buffers)
    assert all(buffer == bytearray(len(buffer)) for buffer in buffers)
    assert all(connection.closed for connection in state.offline.connections)


def test_page_cancellation_zeroes_the_lease_bearer(state, monkeypatch):
    capability, lease = _open(state)
    access = lease._access

    def interrupt_request(self, *args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(_OfflineConnection, "request", interrupt_request)
    with pytest.raises(KeyboardInterrupt):
        lease._read_fixed_page(
            Operation.PROJECTS_SEARCH, project_number=None, page_token=None
        )
    assert access == bytearray(len(access))
    assert all(connection.closed for connection in state.offline.connections)
    state.broker.close_scan_capability(capability)


@pytest.mark.parametrize(
    "response",
    [
        (302, b"{}"),
        (429, b"{}"),
        (503, b"{}"),
        (200, b"not-json"),
        (200, b"x" * (64 * 1024 + 1)),
        (
            200,
            b'{"access_token":"first","access_token":"second","token_type":"Bearer","expires_in":30}',
        ),
        _refresh_response(token_type="Other"),
        _refresh_response(access_token="bad\r\nheader"),
        _refresh_response(expires_in=True),
        _refresh_response(scope="https://www.googleapis.com/auth/cloud-platform"),
    ],
)
def test_refresh_failure_is_code_only_no_retry_and_clears_request(state, response):
    capability = _issue(state)
    _claim(state, capability)
    state.offline.responses.append(response)
    with pytest.raises(vault.GoogleInventoryReadonlyTokenVaultError) as caught:
        state.broker._open_readonly_discovery_lease(capability)
    assert str(caught.value) == "credential.inventory_token_vault_unavailable"
    assert caught.value.__context__ is None
    assert len(state.offline.calls) == 1
    assert all(connection.closed for connection in state.offline.connections)
    assert all(buffer == bytearray(len(buffer)) for buffer in state.offline.buffers)
    with pytest.raises(vault.GoogleInventoryReadonlyTokenVaultError):
        state.broker._open_readonly_discovery_lease(capability)
    assert len(state.offline.calls) == 1


def test_lease_permits_only_four_fixed_bodyless_get_templates(state):
    capability, lease = _open(state)
    cases = [
        (
            Operation.PROJECTS_SEARCH,
            None,
            "cloudresourcemanager.googleapis.com",
            "/v3/projects:search",
        ),
        (
            Operation.BILLING_ACCOUNTS_LIST,
            None,
            "cloudbilling.googleapis.com",
            "/v1/billingAccounts",
        ),
        (
            Operation.SERVICES_LIST,
            "123",
            "serviceusage.googleapis.com",
            "/v1/projects/123/services?filter=state%3AENABLED",
        ),
        (
            Operation.KEYS_LIST,
            "123",
            "apikeys.googleapis.com",
            "/v2/projects/123/locations/global/keys",
        ),
    ]
    for operation, project, host, path in cases:
        state.offline.responses.append((200, b"{}"))
        assert (
            lease._read_fixed_page(operation, project_number=project, page_token=None)
            == {}
        )
        actual = state.offline.calls[-1]
        assert actual == (
            host,
            "GET",
            path,
            b"",
            {"Accept": "application/json", "Authorization": "Bearer synthetic-access"},
        )
    lease._close()
    state.broker.close_scan_capability(capability)
    assert len(state.offline.calls) == 5


@pytest.mark.parametrize(
    "operation,project,cursor",
    [
        (Operation.KEYS_LOOKUP_KEY, None, None),
        (Operation.KEYS_GET, "123", None),
        (Operation.PROJECTS_CREATE, None, None),
        (Operation.SERVICES_ENABLE, "123", None),
        ("projects.search", None, None),
        (Operation.KEYS_LIST, "123/operations", None),
        (Operation.PROJECTS_SEARCH, "123", None),
        (Operation.PROJECTS_SEARCH, None, "x" * 4097),
    ],
)
def test_lease_rejects_other_operations_and_invalid_template_arguments(
    state, operation, project, cursor
):
    capability, lease = _open(state)
    with pytest.raises(vault.GoogleInventoryReadonlyTokenVaultError):
        lease._read_fixed_page(operation, project_number=project, page_token=cursor)
    assert len(state.offline.calls) == 1
    lease._close()
    state.broker.close_scan_capability(capability)


@pytest.mark.parametrize(
    "response",
    [
        (302, b"{}"),
        (429, b"{}"),
        (
            200,
            b'{"projects":[{"name":"projects/123","projectId":"synthetic-access","state":"ACTIVE"}]}',
        ),
        (
            200,
            b'{"projects":[{"name":"projects/123","projectId":"synthetic-project","state":"ACTIVE","keyString":"synthetic-rejected"}]}',
        ),
    ],
)
def test_page_rejects_redirects_secret_echo_and_credentials_without_retry(
    state, response
):
    capability, lease = _open(state)
    state.offline.responses.append(response)
    with pytest.raises(vault.GoogleInventoryReadonlyTokenVaultError) as caught:
        lease._read_fixed_page(
            Operation.PROJECTS_SEARCH, project_number=None, page_token=None
        )
    assert caught.value.__context__ is None
    assert len(state.offline.calls) == 2
    assert all(connection.closed for connection in state.offline.connections)
    lease._close()
    state.broker.close_scan_capability(capability)


def test_current_scan_leaf_consumes_real_private_lease_and_closes_it(state):
    capability = _issue(state)
    capability._consume_for_discovery(
        state.broker,
        **{
            key: value
            for key, value in state.binding.items()
            if not key.startswith("receipt_")
        },
    )
    state.offline.responses.extend([_refresh_response(), (200, b"{}"), (200, b"{}")])
    leaf = scan._FixedGoogleInventoryReadonlyDiscoveryV1(state.broker)
    result = leaf.discover_readonly_inventory(capability)
    target, _fingerprint_value, counts = result._consume_for_issuer(leaf)
    assert target == state.source["google_accounts"][0]
    assert counts == (0, 0, 0, 0)
    state.broker.close_scan_capability(capability)
    assert [call[1] for call in state.offline.calls] == ["POST", "GET", "GET"]
