"""Synthetic local integration of ControlService with Schema3 Store authority."""

from types import MappingProxyType, SimpleNamespace

import pytest
import yaml

from the_hive import google_inventory_readonly_control_service as control
from the_hive import google_inventory_store as stores
from the_hive import google_account_inventory as inventory
from the_hive import google_account_inventory_manager as inventory_manager
from the_hive import google_account_manager_cli as cli


_REF = "synthetic-account-01"
_SUBJECT = "synthetic-subject"
_LOGIN = "synthetic@example.test"
_CLIENT = "sha256:" + "4" * 64
_SCOPE = "sha256:" + "5" * 64


def _fingerprint(document):
    return inventory._document_from_bytes(
        yaml.safe_dump(document).encode()
    ).content_fingerprint


class _CachedManagerMustNotAuthorize:
    def _snapshot_for_internal_use(self):
        pytest.fail("cached Manager must not authorize an operation")

    def reload(self, **kwargs):
        pytest.fail("Store transaction owns exact result rehydration")


class _Effect:
    def __init__(self, generation):
        self.generation = generation

    def _consume_for_authority(self):
        return (
            _REF,
            _SUBJECT,
            self.generation,
            _CLIENT,
            _SCOPE,
            bytearray(b"synthetic-refresh"),
        )


class _Authorize:
    def __init__(self, generation):
        self.generation = generation
        self.calls = 0

    def authorize(self):
        self.calls += 1
        return _Effect(self.generation)


class _TokenPort:
    def __init__(self):
        self.receipt = None
        self.hook = lambda: None

    def store_authorization_refresh_token(self, **values):
        from types import SimpleNamespace

        self.receipt = SimpleNamespace(
            _binding_fingerprint=control._authorization_binding_fingerprint(
                account_ref=values["account_ref"],
                subject_id=values["subject_id"],
                login_email=_LOGIN,
                oauth_client_fingerprint=_CLIENT,
                scope_fingerprint=_SCOPE,
                inventory_generation=values["inventory_generation"],
            ),
            _vault_generation=1,
        )
        token = values["refresh_token"]
        token[:] = b"\x00" * len(token)
        self.hook()
        return self.receipt

    def lookup_authorization_refresh_receipt(self, **values):
        return self.receipt


class _Plan:
    def __init__(self, document):
        self.document = document
        candidate = yaml.safe_load(yaml.safe_dump(document))
        self._transform_for_authority(candidate)
        self.binding = {
            "account_ref": _REF,
            "subject_id": _SUBJECT,
            "inventory_generation": document["authority_generation"],
            "content_fingerprint": _fingerprint(document),
            "oauth_client_fingerprint": _CLIENT,
            "scope_fingerprint": _SCOPE,
            "plan_id": "synthetic-plan",
            "plan_digest": "sha256:" + "3" * 64,
            "resulting_content_fingerprint": _fingerprint(candidate),
            "created_at": 0,
            "expires_at": 100,
        }

    def _binding_for_authority(self):
        return MappingProxyType(self.binding)

    _verify_for_authority = _binding_for_authority

    def _transform_for_authority(self, document):
        document["google_accounts"][0]["label"] = "Synthetic account"

    def _export_sealed_for_authority(self):
        return b"synthetic-sealed-plan"


def _setup(tmp_path, *, subject=_SUBJECT):
    document = {
        "schema_version": 3,
        "authority_generation": 7,
        "google_accounts": [
            {"ref": _REF, "login_email": _LOGIN, "billing_accounts": [], "projects": []}
        ],
    }
    if subject is not None:
        document["google_accounts"][0]["subject_id"] = subject
    path = tmp_path / "synthetic-inventory.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)
    store = stores.GoogleInventoryStore._for_test_path(path)
    journal = tmp_path / "synthetic-journal"
    journal.mkdir(mode=0o700)
    authorize = _Authorize(7)
    tokens = _TokenPort()
    plan = _Plan(document) if subject is not None else None

    def service():
        return control.GoogleInventoryReadonlyControlService._for_test_components(
            store=store,
            manager=_CachedManagerMustNotAuthorize(),
            authorization_port=authorize,
            authorization_token_port=tokens,
            document_state_reader=control._production_document_state,
            journal_directory=journal,
            plan_rehydrator=lambda payload: plan,
            clock=lambda: 1,
        )

    return service, path, authorize, tokens, plan


@pytest.mark.parametrize("subject", [None, _SUBJECT])
def test_authorize_uses_fresh_store_transaction_for_cas_and_equal_subject(
    tmp_path, subject
):
    factory, path, authorize, tokens, _ = _setup(tmp_path, subject=subject)
    service = factory()
    original = path.read_bytes()
    assert service.authorize() == {"status": "authorized"}
    result = yaml.safe_load(path.read_bytes())
    assert result["authority_generation"] == (8 if subject is None else 7)
    assert result["google_accounts"][0]["subject_id"] == _SUBJECT
    if subject is not None:
        assert path.read_bytes() == original
    assert len(list(tmp_path.glob("*.backup-*"))) == (1 if subject is None else 0)
    assert factory().authorize() == {"status": "authorized"}
    assert authorize.calls == 1
    assert service.subject_status() == {"status": "bound"}


def test_authorize_final_byte_attestation_clears_held_binding(tmp_path):
    factory, path, _, tokens, _ = _setup(tmp_path)
    service = factory()
    tokens.hook = lambda: path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(control.GoogleInventoryReadonlyControlError):
        service.authorize()
    assert service._subject_binding_verified is False


def test_apply_commit_and_receipt_recovery_require_fresh_exact_generation(tmp_path):
    factory, path, _, _, plan = _setup(tmp_path)
    service = factory()
    reference = service._register_scan_plan_for_internal_use(plan)
    assert service.apply(reference) == {"status": "applied"}
    result = yaml.safe_load(path.read_bytes())
    assert result["authority_generation"] == 8
    assert factory().apply(reference) == {"status": "applied"}
    assert len(list(tmp_path.glob("*.backup-*"))) == 1
    result["authority_generation"] = 9
    path.write_text(yaml.safe_dump(result, sort_keys=False), encoding="utf-8")
    with pytest.raises(control.GoogleInventoryReadonlyControlError) as captured:
        service.apply(reference)
    assert captured.value.code == "inventory.readonly_control_recovery_failed"
    assert service._subject_binding_verified is False


def test_apply_recovers_interrupted_journal_only_after_exact_store_result(
    tmp_path, monkeypatch
):
    factory, path, _, _, plan = _setup(tmp_path)
    service = factory()
    reference = service._register_scan_plan_for_internal_use(plan)
    original = control._OperationJournal.mark_reloaded

    def fail_once(self, operation):
        monkeypatch.setattr(control._OperationJournal, "mark_reloaded", original)
        raise control._JournalFailure()

    monkeypatch.setattr(control._OperationJournal, "mark_reloaded", fail_once)
    with pytest.raises(control.GoogleInventoryReadonlyControlError):
        service.apply(reference)
    assert yaml.safe_load(path.read_bytes())["authority_generation"] == 8
    assert factory().apply(reference) == {"status": "applied"}
    assert len(list(tmp_path.glob("*.backup-*"))) == 1


def test_status_rechecks_store_before_reporting_a_previously_held_binding(tmp_path):
    factory, path, _, _, _ = _setup(tmp_path)
    service = factory()
    service.authorize()
    document = yaml.safe_load(path.read_bytes())
    document["authority_generation"] += 1
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    with pytest.raises(control.GoogleInventoryReadonlyControlError):
        service.subject_status()
    assert service._subject_binding_verified is False


def test_private_authority_helpers_fail_without_an_open_store_transaction(tmp_path):
    factory, _, _, _, _ = _setup(tmp_path)
    service = factory()
    with pytest.raises(control.GoogleInventoryReadonlyControlError):
        service._current_document_for_authority()


def test_document_state_projects_a_plain_schema3_store_document(tmp_path):
    _, path, _, _, _ = _setup(tmp_path)
    document = yaml.safe_load(path.read_bytes())
    assert control._production_document_state(
        document
    ).content_fingerprint == _fingerprint(document)


def test_production_constructor_defers_private_ports_to_fresh_transaction(
    tmp_path, monkeypatch
):
    factory, path, authorize, tokens, _ = _setup(tmp_path)
    store = stores.GoogleInventoryStore._for_test_path(path)
    events = []

    class Components:
        _vault = object()

        def _journal_directory_for_authority(self):
            return tmp_path / "synthetic-journal"

    components = Components()
    monkeypatch.setattr(
        inventory_manager.GoogleAccountInventoryManager,
        "from_systemd_state_directory",
        lambda: pytest.fail("constructor must not cache a Manager"),
    )
    monkeypatch.setattr(
        stores.GoogleInventoryStore, "from_systemd_state_directory", lambda: store
    )
    monkeypatch.setattr(
        control._token_vault,
        "_new_the_hive_inventory_vault_production_components",
        lambda: components,
    )

    def token_port(vault, manager):
        events.append(("token", manager))
        return tokens

    def oauth_port(*, vault_components, manager):
        events.append(("oauth", manager))
        return authorize

    monkeypatch.setattr(
        control._token_vault,
        "_new_inventory_readonly_authorization_token_port",
        token_port,
    )
    monkeypatch.setattr(
        control._oauth_session,
        "_new_the_hive_inventory_readonly_authorization_port",
        oauth_port,
    )
    service = control.GoogleInventoryReadonlyControlService()
    assert events == []
    assert service._manager is None
    assert service.authorize() == {"status": "authorized"}
    assert [event[0] for event in events] == ["token", "oauth", "token", "oauth"]
    assert events[0][1] is not events[2][1]
    assert service._manager is None
    assert service._transaction is None


@pytest.mark.parametrize("action", ["authorize", "subject_status"])
def test_authorization_recovery_rejects_content_drift_even_at_same_generation(
    tmp_path, action
):
    factory, path, _, _, _ = _setup(tmp_path)
    service = factory()
    service.authorize()
    document = yaml.safe_load(path.read_bytes())
    document["google_accounts"][0]["label"] = "Synthetic unexpected change"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    recovered = factory()
    with pytest.raises(control.GoogleInventoryReadonlyControlError):
        getattr(recovered, action)()
    assert recovered._subject_binding_verified is False


@pytest.mark.parametrize(
    "drift", ["source_generation", "source_content", "transform_generation"]
)
def test_apply_refuses_stale_source_or_transform_owned_generation(tmp_path, drift):
    factory, path, _, _, plan = _setup(tmp_path)
    service = factory()
    reference = service._register_scan_plan_for_internal_use(plan)
    if drift == "transform_generation":
        transform = plan._transform_for_authority

        def changed(document):
            transform(document)
            document["authority_generation"] += 1

        plan._transform_for_authority = changed
    else:
        document = yaml.safe_load(path.read_bytes())
        if drift == "source_generation":
            document["authority_generation"] += 1
        else:
            document["google_accounts"][0]["label"] = "Synthetic other change"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    original = path.read_bytes()
    with pytest.raises(control.GoogleInventoryReadonlyControlError):
        service.apply(reference)
    assert path.read_bytes() == original
    assert list(tmp_path.glob("*.backup-*")) == []


def test_production_scan_builds_only_fixed_private_owners_with_receipt_binding(
    tmp_path, monkeypatch
):
    factory, _, authorize, tokens, plan = _setup(tmp_path)
    service = factory()
    service.authorize()
    components = SimpleNamespace(_vault=object())
    service._vault_components = components
    broker = object()
    discovery = object()
    owner = object()
    events = []

    class Component:
        def _new_verified_binding_for_control(self, supplied_owner, **binding):
            events.append(("binding", supplied_owner, binding))
            return binding

        def _scan_for_control(self, supplied_owner, binding, document):
            assert supplied_owner is owner
            return SimpleNamespace(
                _plan=plan,
                _public_projection={
                    "status": "planned",
                    "account_count": 1,
                    "project_count": 0,
                    "billing_account_count": 0,
                    "service_count": 0,
                    "key_count": 0,
                    "changes": {"canonical_account": 1},
                },
            )

    def new_broker(vault, manager):
        events.append(("broker", vault, manager.inventory_generation()))
        return broker

    def new_discovery(supplied_broker):
        assert supplied_broker is broker
        return discovery

    def new_component(*, broker: object, discovery: object):
        events.append(("component", broker, discovery))
        return Component(), owner

    monkeypatch.setattr(
        control._token_vault,
        "_new_inventory_readonly_authorization_token_port",
        lambda vault, manager: tokens,
    )
    monkeypatch.setattr(
        control._oauth_session,
        "_new_the_hive_inventory_readonly_authorization_port",
        lambda **values: authorize,
    )
    monkeypatch.setattr(
        control._token_vault, "_new_inventory_readonly_scan_broker", new_broker
    )
    monkeypatch.setattr(
        control._scan, "_FixedGoogleInventoryReadonlyDiscoveryV1", new_discovery
    )
    monkeypatch.setattr(
        control._scan, "_create_scan_component_for_control", new_component
    )

    result = service.scan_plan()
    record = service._authorization_journal._receipt
    assert result["status"] == "planned"
    assert events[0] == ("broker", components._vault, 7)
    assert events[1] == ("component", broker, discovery)
    binding = events[2][2]
    assert events[2][1] is owner
    assert binding["receipt_operation_digest"] == record.operation_digest
    assert binding["receipt_binding_fingerprint"] == record.binding_fingerprint
    assert "receipt" not in repr(result)
    assert record.operation_digest not in repr(result)


def test_real_scan_component_plan_applies_through_schema3_transaction(tmp_path):
    factory, path, _, _, _ = _setup(tmp_path)
    service = factory()
    service.authorize()
    events = []

    class Lease:
        def _target_account_for_discovery(self):
            return {
                "ref": _REF,
                "subject_id": _SUBJECT,
                "login_email": _LOGIN,
                "recovery_email": None,
                "label": "Synthetic account",
                "billing_accounts": [],
                "projects": [],
            }

        def _read_fixed_page(self, operation, **values):
            events.append("page")
            return {}

        def _close(self):
            events.append("closed")

    class Broker:
        def issue_scan_capability(self, **binding):
            record = service._authorization_journal._receipt
            assert binding.pop("receipt_operation_digest") == record.operation_digest
            assert (
                binding.pop("receipt_binding_fingerprint") == record.binding_fingerprint
            )
            return control._scan._issue_scan_capability_for_broker(self, **binding)

        def _open_readonly_discovery_lease(self, capability):
            return Lease()

        def close_scan_capability(self, capability):
            events.append("capability_closed")

    broker = Broker()
    component, owner = control._scan._for_test_scan_component(
        broker=broker,
        discovery=control._scan._FixedGoogleInventoryReadonlyDiscoveryV1(broker),
        clock=lambda: 1,
        plan_id_factory=lambda: "synthetic-plan",
    )
    service._scan_component = component
    service._scan_owner = owner
    planned = service.scan_plan()
    assert events == ["page", "page", "closed", "capability_closed"]
    assert service.apply(planned["plan_reference"]) == {"status": "applied"}
    document = yaml.safe_load(path.read_bytes())
    assert document["authority_generation"] == 8
    assert document["google_accounts"][0]["label"] == "Synthetic account"


@pytest.mark.parametrize("boundary", ["authority", "cli"])
@pytest.mark.parametrize("environment", ["headless", "remote"])
def test_interactive_leaf_diagnostic_reaches_authority_and_closed_cli(
    tmp_path, monkeypatch, capsys, boundary, environment
):
    oauth = control._oauth_session
    for name in (
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "SSH_CONNECTION",
        "SSH_CLIENT",
        "SSH_TTY",
    ):
        monkeypatch.delenv(name, raising=False)
    if environment == "remote":
        monkeypatch.setenv("DISPLAY", ":0")
        monkeypatch.setenv("SSH_CONNECTION", "synthetic-remote")

    def forbidden(*args, **kwargs):
        pytest.fail("offline diagnostic must not open a socket or browser")

    monkeypatch.setattr(oauth.socket, "socket", forbidden)
    monkeypatch.setattr(oauth.subprocess, "run", forbidden)
    factory, path, _, tokens, _ = _setup(tmp_path)
    service = factory()
    original = path.read_bytes()
    service._authorization_port = oauth._TheHiveInventoryReadonlyAuthorizationPort(
        preflight=SimpleNamespace(_preflight_for_inventory_authorize=lambda: None),
        manager=object(),
        control_service=SimpleNamespace(_inventory_bound_selection=lambda: None),
        callback_driver=oauth._InventoryReadonlyLoopbackDriverV1(),
    )

    if boundary == "authority":
        with pytest.raises(control.GoogleInventoryReadonlyControlError) as captured:
            service.authorize()
        assert captured.value.code == "oauth.interactive_authorization_required"
        assert str(captured.value) == "oauth.interactive_authorization_required"
        assert captured.value.__suppress_context__ is True
    else:
        monkeypatch.setattr(
            cli, "GoogleInventoryReadonlyControlService", lambda: service
        )
        assert cli.main(["inventory", "authorize"]) == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "oauth.interactive_authorization_required\n"
    assert path.read_bytes() == original
    assert tokens.receipt is None
    assert service._subject_binding_verified is False


@pytest.mark.parametrize("case", ["allowed", "unknown", "forged"])
def test_cli_authorize_diagnostic_mapping_never_reflects_raw_leaf_exception(
    tmp_path, monkeypatch, capsys, case
):
    diagnostic = "oauth.interactive_authorization_required"
    if case == "forged":
        error = RuntimeError("synthetic-private-exception")
        error.code = diagnostic
    else:
        error = control._oauth_session.GoogleOAuthSessionError(
            diagnostic if case == "allowed" else "oauth.synthetic_unknown"
        )
        error.args = ("synthetic-private-exception",)

    def authorize():
        raise error

    factory, _, _, _, _ = _setup(tmp_path)
    service = factory()
    service._authorization_port = SimpleNamespace(authorize=authorize)
    monkeypatch.setattr(cli, "GoogleInventoryReadonlyControlService", lambda: service)
    assert cli.main(["inventory", "authorize"]) == 1
    captured = capsys.readouterr()
    expected = (
        diagnostic if case == "allowed" else "inventory.readonly_control_unavailable"
    )
    assert captured.out == ""
    assert captured.err == expected + "\n"
