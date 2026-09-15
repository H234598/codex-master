from __future__ import annotations

import copy
from contextlib import contextmanager
import inspect
import json
from pathlib import Path
import pickle
from types import MappingProxyType, SimpleNamespace

import pytest

from the_hive import google_inventory_readonly_control_service as _control_module
from the_hive import google_account_inventory_manager as _inventory_manager
from the_hive.google_inventory_readonly_control_service import (
    GoogleInventoryReadonlyControlError,
    GoogleInventoryReadonlyControlService,
    _InventoryDocumentState,
    _authorization_binding_fingerprint,
)


_ACCOUNT_REF = "test-account"
_SUBJECT = "test-subject"
_BEFORE_FINGERPRINT = "sha256:" + "1" * 64
_AFTER_FINGERPRINT = "sha256:" + "2" * 64
_PLAN_DIGEST = "sha256:" + "3" * 64
_LOGIN = "test-login"


class _Store:
    def __init__(self, document: dict[str, object]) -> None:
        self.document = document
        self.update_calls = 0

    def atomic_update(self, transform):
        self.update_calls += 1
        candidate = copy.deepcopy(self.document)
        transform(candidate)
        self.document = candidate
        return object()

    def _read(self) -> tuple[bytes, dict[str, object]]:
        return b"", copy.deepcopy(self.document)


class _FailOnceStore(_Store):
    def __init__(self, document: dict[str, object]) -> None:
        super().__init__(document)
        self.fail_once = True

    def atomic_update(self, transform):
        self.update_calls += 1
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("synthetic pre-commit interruption")
        candidate = copy.deepcopy(self.document)
        transform(candidate)
        self.document = candidate
        return object()


class _StoreChangedBeforeLockedTransform(_Store):
    """Model another process committing after preflight but before CAS."""

    def __init__(
        self,
        document: dict[str, object],
        replacement: dict[str, object],
    ) -> None:
        super().__init__(document)
        self._replacement = replacement

    def atomic_update(self, transform):
        self.update_calls += 1
        self.document = copy.deepcopy(self._replacement)
        candidate = copy.deepcopy(self.document)
        transform(candidate)
        self.document = candidate
        return object()


class _StoreRunsBeforeLockedTransform(_Store):
    """Run a synthetic competing manager update under the Store lock."""

    def __init__(self, document: dict[str, object], before_transform) -> None:
        super().__init__(document)
        self._before_transform = before_transform

    def atomic_update(self, transform):
        self.update_calls += 1
        self._before_transform()
        candidate = copy.deepcopy(self.document)
        transform(candidate)
        self.document = candidate
        return object()


class _Manager:
    def __init__(self, before: object, after: object) -> None:
        self.snapshot = before
        self._after = after
        self.reload_calls: list[int] = []
        self.fail_reload_once = False

    def _snapshot_for_internal_use(self) -> object:
        return self.snapshot

    def reload(self, *, expected_generation: int) -> object:
        self.reload_calls.append(expected_generation)
        if self.fail_reload_once:
            self.fail_reload_once = False
            raise RuntimeError("synthetic interrupted reload")
        self.snapshot = self._after
        return SimpleNamespace(generation=self._after.generation)


@pytest.fixture(autouse=True)
def _synthetic_store_transactions(monkeypatch):
    """Keep legacy interruption cases on a synthetic fresh-transaction boundary."""

    original_initialize = GoogleInventoryReadonlyControlService._initialize
    original_transaction = _control_module._inventory_store._authority_transaction

    def initialize(service, **components):
        store = components["store"]
        if isinstance(store, _Store):
            store.manager = components["manager"]
            store.reader = components["document_state_reader"]
            if not hasattr(store, "generation"):
                store.generation = store.manager.snapshot.generation
        original_initialize(service, **components)

    class Transaction:
        def __init__(self, store):
            self.store = store
            self.source = copy.deepcopy(store.document)
            self.expected = copy.deepcopy(store.document)
            self.binding = object()
            self._refresh_manager()

        def _refresh_manager(self):
            state = self.store.reader(self.store.document)
            prior = self.store.manager.snapshot.accounts[0]
            accounts = tuple(
                SimpleNamespace(
                    ref=ref,
                    subject_id=subject,
                    login_email=getattr(prior, "login_email", _LOGIN),
                )
                for ref, subject in state.subjects_by_account_ref.items()
            )
            snapshot = SimpleNamespace(
                generation=self.store.generation,
                content_fingerprint=state.content_fingerprint,
                accounts=accounts,
            )
            self.manager = SimpleNamespace(_snapshot_for_internal_use=lambda: snapshot)

        @property
        def document(self):
            return copy.deepcopy(self.source)

        def attest(self):
            if self.store.document != self.expected:
                raise RuntimeError("synthetic source conflict")
            self._refresh_manager()

        def commit(self, candidate, *, expected, expected_content_fingerprint):
            assert expected is self.binding

            def update(document):
                if (
                    document != self.source
                    or self.store.manager.snapshot.generation != self.store.generation
                ):
                    raise RuntimeError("synthetic source conflict")
                assert (
                    self.store.reader(candidate).content_fingerprint
                    == expected_content_fingerprint
                )
                document.clear()
                document.update(copy.deepcopy(candidate))

            source_generation = self.store.generation
            self.store.atomic_update(update)
            self.store.generation += 1
            self.expected = copy.deepcopy(self.store.document)
            self.store.manager.reload(expected_generation=source_generation)
            self.attest()

    @contextmanager
    def transaction(store):
        if not isinstance(store, _Store):
            with original_transaction(store) as current:
                yield current
            return
        current = Transaction(store)
        yield current
        current.attest()

    monkeypatch.setattr(
        GoogleInventoryReadonlyControlService, "_initialize", initialize
    )
    monkeypatch.setattr(
        _control_module._inventory_store, "_authority_transaction", transaction
    )


class _Plan:
    def _binding_for_authority(self) -> MappingProxyType:
        return MappingProxyType(
            {
                "account_ref": _ACCOUNT_REF,
                "subject_id": _SUBJECT,
                "inventory_generation": 7,
                "content_fingerprint": _BEFORE_FINGERPRINT,
                "oauth_client_fingerprint": "sha256:" + "4" * 64,
                "scope_fingerprint": "sha256:" + "5" * 64,
                "plan_id": "test-plan",
                "plan_digest": _PLAN_DIGEST,
                "resulting_content_fingerprint": _AFTER_FINGERPRINT,
                "created_at": 0,
                "expires_at": 100,
            }
        )

    def _transform_for_authority(self, document: dict[str, object]) -> None:
        if document.get("phase") != "before":
            raise AssertionError("transform must receive the attested source")
        document["phase"] = "after"

    def _verify_for_authority(self) -> MappingProxyType:
        return self._binding_for_authority()

    def _export_sealed_for_authority(self) -> bytes:
        return b"sealed-test-plan"


class _BindingChangingPlan(_Plan):
    def __init__(self) -> None:
        self._binding = dict(super()._binding_for_authority())

    def _binding_for_authority(self) -> MappingProxyType:
        return MappingProxyType(self._binding)

    def change_scope_binding(self) -> None:
        self._binding["scope_fingerprint"] = "sha256:" + "7" * 64


class _DigestInvalidPlan(_Plan):
    def _verify_for_authority(self) -> MappingProxyType:
        raise RuntimeError("private digest does not match immutable plan")


class _PostCommitDigestInvalidPlan(_Plan):
    def __init__(self) -> None:
        self.invalid = False

    def _verify_for_authority(self) -> MappingProxyType:
        if self.invalid:
            raise RuntimeError("private digest does not match immutable plan")
        return super()._verify_for_authority()


class _AuthorizationPort:
    def __init__(self) -> None:
        self.calls = 0

    def authorize(self) -> object:
        self.calls += 1
        return object()


class _AuthorizationEffect:
    def __init__(self, *, generation: int = 7) -> None:
        self.consumed = False
        self._generation = generation

    def _consume_for_authority(self) -> tuple[str, str, int, str, str, bytearray]:
        if self.consumed:
            raise RuntimeError("effect already consumed")
        self.consumed = True
        return (
            _ACCOUNT_REF,
            _SUBJECT,
            self._generation,
            "sha256:" + "4" * 64,
            "sha256:" + "5" * 64,
            bytearray(b"synthetic-private-synthetic-refresh-marker"),
        )


class _AuthorizePortWithEffect:
    def __init__(self, *, generation: int = 7) -> None:
        self.calls = 0
        self.effect = _AuthorizationEffect(generation=generation)

    def authorize(self) -> _AuthorizationEffect:
        self.calls += 1
        return self.effect


class _AuthorizationTokenReceipt:
    def __init__(self, binding_fingerprint: str, vault_generation: int = 1) -> None:
        self._binding_fingerprint = binding_fingerprint
        self._vault_generation = vault_generation

    def __repr__(self) -> str:
        return "_AuthorizationTokenReceipt(<redacted>)"


class _AuthorizationTokenPort:
    def __init__(self) -> None:
        self.store_calls: list[dict[str, object]] = []
        self.lookup_calls: list[dict[str, object]] = []
        self.recovery_receipt: _AuthorizationTokenReceipt | None = None

    def store_authorization_refresh_token(
        self, **kwargs: object
    ) -> _AuthorizationTokenReceipt:
        self.store_calls.append(kwargs)
        token = kwargs["refresh_token"]
        assert type(token) is bytearray
        token[:] = b"\x00" * len(token)
        receipt = _AuthorizationTokenReceipt(
            _authorization_binding_fingerprint(
                account_ref=kwargs["account_ref"],
                subject_id=kwargs["subject_id"],
                login_email=_LOGIN,
                oauth_client_fingerprint=kwargs["oauth_client_fingerprint"],
                scope_fingerprint="sha256:" + "5" * 64,
                inventory_generation=kwargs["inventory_generation"],
            )
        )
        self.recovery_receipt = receipt
        return receipt

    def lookup_authorization_refresh_receipt(
        self, **kwargs: object
    ) -> _AuthorizationTokenReceipt | None:
        self.lookup_calls.append(kwargs)
        return self.recovery_receipt


class _FailingAuthorizationTokenPort(_AuthorizationTokenPort):
    def store_authorization_refresh_token(
        self, **kwargs: object
    ) -> _AuthorizationTokenReceipt:
        self.store_calls.append(kwargs)
        raise RuntimeError("synthetic vault interruption")


class _ScanResult:
    def __init__(self) -> None:
        self._plan = _Plan()
        self._public_projection = MappingProxyType(
            {
                "status": "planned",
                "account_count": 1,
                "project_count": 0,
                "billing_account_count": 0,
                "service_count": 0,
                "key_count": 0,
                "changes": MappingProxyType({"canonical_account": 1}),
            }
        )


class _ScanPort:
    def __init__(self) -> None:
        self.calls = 0

    def scan_plan(self) -> _ScanResult:
        self.calls += 1
        return _ScanResult()


class _LeakingScanPort:
    def scan_plan(self) -> _ScanResult:
        result = _ScanResult()
        result._public_projection = MappingProxyType(
            {
                "status": "planned",
                "account_count": 1,
                "project_count": 0,
                "billing_account_count": 0,
                "service_count": 0,
                "key_count": 0,
                "changes": MappingProxyType(
                    {"synthetic-private-synthetic-subject-marker": 1}
                ),
            }
        )
        return result


class _BoundScanComponent:
    """Private scan-component double that records the Authority attestation."""

    def __init__(self) -> None:
        self.binding_calls: list[tuple[object, dict[str, object]]] = []
        self.scan_calls: list[tuple[object, object, dict[str, object]]] = []

    def _new_verified_binding_for_control(
        self, owner: object, **kwargs: object
    ) -> object:
        self.binding_calls.append((owner, kwargs))
        return object()

    def _scan_for_control(
        self, owner: object, binding: object, document: dict[str, object]
    ) -> _ScanResult:
        self.scan_calls.append((owner, binding, document))
        return _ScanResult()


def _snapshot(generation: int, fingerprint: str) -> object:
    account = SimpleNamespace(ref=_ACCOUNT_REF, subject_id=_SUBJECT)
    return SimpleNamespace(
        generation=generation,
        content_fingerprint=fingerprint,
        accounts=(account,),
    )


def _document_state(document: dict[str, object]) -> _InventoryDocumentState:
    phase = document.get("phase")
    if phase == "before":
        fingerprint = _BEFORE_FINGERPRINT
    elif phase == "after":
        fingerprint = _AFTER_FINGERPRINT
    else:
        fingerprint = "sha256:" + "6" * 64
    return _InventoryDocumentState(
        content_fingerprint=fingerprint,
        subjects_by_account_ref=MappingProxyType({_ACCOUNT_REF: _SUBJECT}),
    )


def _authorization_document_state(
    document: dict[str, object],
) -> _InventoryDocumentState:
    accounts = document.get("google_accounts")
    assert type(accounts) is list and len(accounts) == 1
    account = accounts[0]
    assert type(account) is dict
    subject = account.get("subject_id")
    fingerprint = (
        "sha256:" + "9" * 64
        if document.get("revision") == "concurrent-synthetic-change"
        else _BEFORE_FINGERPRINT
        if subject is None
        else _AFTER_FINGERPRINT
    )
    return _InventoryDocumentState(
        content_fingerprint=fingerprint,
        subjects_by_account_ref=MappingProxyType({_ACCOUNT_REF: subject}),
    )


def _rehydrate_test_plan(payload: object) -> _Plan:
    if payload != b"sealed-test-plan":
        raise RuntimeError("sealed plan is invalid")
    return _Plan()


def _authorization_document() -> dict[str, object]:
    return {"google_accounts": [{"ref": _ACCOUNT_REF, "subject_id": None}]}


def _service(
    document: dict[str, object], journal_directory: Path
) -> tuple[GoogleInventoryReadonlyControlService, _Store, _Manager]:
    manager = _Manager(
        _snapshot(7, _BEFORE_FINGERPRINT), _snapshot(8, _AFTER_FINGERPRINT)
    )
    store = _Store(document)
    service = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_document_state,
        journal_directory=journal_directory,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )
    return service, store, manager


def _authorized_service_with_scan(
    tmp_path: Path,
    *,
    scan_port: object | None = None,
    scan_component: object | None = None,
    scan_owner: object | None = None,
) -> GoogleInventoryReadonlyControlService:
    document = _authorization_document()
    store = _Store(document)
    before_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=None, login_email=_LOGIN
    )
    after_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=_SUBJECT, login_email=_LOGIN
    )
    manager = _Manager(
        SimpleNamespace(
            generation=7,
            content_fingerprint=_BEFORE_FINGERPRINT,
            accounts=(before_account,),
        ),
        SimpleNamespace(
            generation=8,
            content_fingerprint=_AFTER_FINGERPRINT,
            accounts=(after_account,),
        ),
    )
    service = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=_AuthorizePortWithEffect(),
        authorization_token_port=_AuthorizationTokenPort(),
        scan_port=scan_port,
        scan_component=scan_component,
        scan_owner=scan_owner,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )
    assert service.authorize() == {"status": "authorized"}
    return service


def test_scan_is_a_facade_method_over_its_constructor_owned_private_port(
    tmp_path: Path,
) -> None:
    scan_port = _ScanPort()
    service = _authorized_service_with_scan(tmp_path, scan_port=scan_port)

    planned = service.scan_plan()

    assert planned == {
        "status": "planned",
        "account_count": 1,
        "project_count": 0,
        "billing_account_count": 0,
        "service_count": 0,
        "key_count": 0,
        "changes": {"canonical_account": 1},
        "plan_reference": planned["plan_reference"],
    }
    assert scan_port.calls == 1


def test_subject_status_exposes_only_the_authority_verified_bound_state(
    tmp_path: Path,
) -> None:
    service, _, _ = _service({"phase": "before"}, tmp_path)

    assert service.subject_status() == {"status": "unavailable"}

    assert _ACCOUNT_REF not in repr(service.subject_status())
    assert _SUBJECT not in repr(service.subject_status())


def test_authorize_consumes_one_private_effect_after_subject_cas_and_reattest(
    tmp_path: Path,
) -> None:
    document = _authorization_document()
    store = _Store(document)
    before_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=None, login_email=_LOGIN
    )
    after_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=_SUBJECT, login_email=_LOGIN
    )
    manager = _Manager(
        SimpleNamespace(
            generation=7,
            content_fingerprint=_BEFORE_FINGERPRINT,
            accounts=(before_account,),
        ),
        SimpleNamespace(
            generation=8,
            content_fingerprint=_AFTER_FINGERPRINT,
            accounts=(after_account,),
        ),
    )
    authorize_port = _AuthorizePortWithEffect()
    token_port = _AuthorizationTokenPort()
    service = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=authorize_port,
        authorization_token_port=token_port,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    assert service.authorize() == {"status": "authorized"}
    assert authorize_port.calls == 1
    assert authorize_port.effect.consumed is True
    assert store.document["google_accounts"] == [
        {"ref": _ACCOUNT_REF, "subject_id": _SUBJECT}
    ]
    assert store.update_calls == 1
    assert manager.reload_calls == [7]
    assert len(token_port.store_calls) == 1
    assert token_port.lookup_calls == []
    assert service.subject_status() == {"status": "bound"}


def test_authorize_reconstructs_only_a_matching_secret_free_vault_receipt(
    tmp_path: Path,
) -> None:
    document = _authorization_document()
    store = _Store(document)
    before_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=None, login_email=_LOGIN
    )
    after_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=_SUBJECT, login_email=_LOGIN
    )
    manager = _Manager(
        SimpleNamespace(
            generation=7,
            content_fingerprint=_BEFORE_FINGERPRINT,
            accounts=(before_account,),
        ),
        SimpleNamespace(
            generation=8,
            content_fingerprint=_AFTER_FINGERPRINT,
            accounts=(after_account,),
        ),
    )
    first_authorize_port = _AuthorizePortWithEffect()
    first_token_port = _AuthorizationTokenPort()
    first = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=first_authorize_port,
        authorization_token_port=first_token_port,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    assert first.authorize() == {"status": "authorized"}
    assert first_token_port.recovery_receipt is not None
    journal_bytes = b"".join(item.read_bytes() for item in tmp_path.iterdir())
    assert _ACCOUNT_REF.encode() not in journal_bytes
    assert _SUBJECT.encode() not in journal_bytes
    assert _LOGIN.encode() not in journal_bytes

    recovery_authorize_port = _AuthorizePortWithEffect()
    recovery_token_port = _AuthorizationTokenPort()
    recovery_token_port.recovery_receipt = first_token_port.recovery_receipt
    recovered = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=recovery_authorize_port,
        authorization_token_port=recovery_token_port,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    assert recovered.authorize() == {"status": "authorized"}
    assert recovery_authorize_port.calls == 0
    assert len(recovery_token_port.lookup_calls) == 1
    assert store.update_calls == 1
    assert manager.reload_calls == [7]
    assert recovered.subject_status() == {"status": "bound"}


def test_authorize_recovery_fails_closed_for_a_different_vault_binding_receipt(
    tmp_path: Path,
) -> None:
    document = _authorization_document()
    store = _Store(document)
    before_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=None, login_email=_LOGIN
    )
    after_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=_SUBJECT, login_email=_LOGIN
    )
    manager = _Manager(
        SimpleNamespace(
            generation=7,
            content_fingerprint=_BEFORE_FINGERPRINT,
            accounts=(before_account,),
        ),
        SimpleNamespace(
            generation=8,
            content_fingerprint=_AFTER_FINGERPRINT,
            accounts=(after_account,),
        ),
    )
    first_token_port = _AuthorizationTokenPort()
    first = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=_AuthorizePortWithEffect(),
        authorization_token_port=first_token_port,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )
    assert first.authorize() == {"status": "authorized"}

    recovery_authorize_port = _AuthorizePortWithEffect(generation=8)
    recovery_token_port = _AuthorizationTokenPort()
    recovery_token_port.recovery_receipt = _AuthorizationTokenReceipt(
        "sha256:" + "f" * 64
    )
    recovered = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=recovery_authorize_port,
        authorization_token_port=recovery_token_port,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        recovered.authorize()

    assert raised.value.code == "inventory.readonly_control_recovery_failed"
    assert recovery_authorize_port.calls == 0
    assert len(recovery_token_port.lookup_calls) == 1
    assert store.update_calls == 1
    assert manager.reload_calls == [7]


def test_authorize_crash_before_vault_receipt_discards_only_pending_state_and_reauths(
    tmp_path: Path,
) -> None:
    document = _authorization_document()
    store = _Store(document)
    before_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=None, login_email=_LOGIN
    )
    after_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=_SUBJECT, login_email=_LOGIN
    )
    manager = _Manager(
        SimpleNamespace(
            generation=7,
            content_fingerprint=_BEFORE_FINGERPRINT,
            accounts=(before_account,),
        ),
        SimpleNamespace(
            generation=8,
            content_fingerprint=_AFTER_FINGERPRINT,
            accounts=(after_account,),
        ),
    )
    first_token_port = _FailingAuthorizationTokenPort()
    first = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=_AuthorizePortWithEffect(),
        authorization_token_port=first_token_port,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        first.authorize()

    assert raised.value.code == "inventory.readonly_control_unavailable"
    assert store.update_calls == 1
    assert manager.reload_calls == [7]
    first_refresh = first_token_port.store_calls[0]["refresh_token"]
    assert type(first_refresh) is bytearray and not any(first_refresh)

    recovered_authorize_port = _AuthorizePortWithEffect(generation=8)
    recovered_token_port = _AuthorizationTokenPort()
    recovered = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=recovered_authorize_port,
        authorization_token_port=recovered_token_port,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    assert recovered.authorize() == {"status": "authorized"}
    assert len(recovered_token_port.lookup_calls) == 1
    assert recovered_authorize_port.calls == 1
    assert store.update_calls == 1
    assert manager.reload_calls == [7]
    assert len(recovered_token_port.store_calls) == 1


def test_authorize_recovers_manager_attestation_after_subject_cas_before_vault(
    tmp_path: Path,
) -> None:
    document = _authorization_document()
    store = _Store(document)
    before_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=None, login_email=_LOGIN
    )
    after_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=_SUBJECT, login_email=_LOGIN
    )
    manager = _Manager(
        SimpleNamespace(
            generation=7,
            content_fingerprint=_BEFORE_FINGERPRINT,
            accounts=(before_account,),
        ),
        SimpleNamespace(
            generation=8,
            content_fingerprint=_AFTER_FINGERPRINT,
            accounts=(after_account,),
        ),
    )
    manager.fail_reload_once = True
    first = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=_AuthorizePortWithEffect(),
        authorization_token_port=_AuthorizationTokenPort(),
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        first.authorize()

    assert raised.value.code == "inventory.readonly_control_unavailable"
    assert store.update_calls == 1
    assert manager.reload_calls == [7]

    recovered_authorize_port = _AuthorizePortWithEffect(generation=8)
    recovered_token_port = _AuthorizationTokenPort()
    recovered = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=recovered_authorize_port,
        authorization_token_port=recovered_token_port,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    assert recovered.authorize() == {"status": "authorized"}
    assert store.update_calls == 1
    assert manager.reload_calls == [7]
    assert len(recovered_token_port.lookup_calls) == 1
    assert recovered_authorize_port.calls == 1


def test_authorize_discards_an_uncommitted_pending_record_before_new_oauth(
    tmp_path: Path,
) -> None:
    document = _authorization_document()
    store = _FailOnceStore(document)
    before_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=None, login_email=_LOGIN
    )
    after_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=_SUBJECT, login_email=_LOGIN
    )
    manager = _Manager(
        SimpleNamespace(
            generation=7,
            content_fingerprint=_BEFORE_FINGERPRINT,
            accounts=(before_account,),
        ),
        SimpleNamespace(
            generation=8,
            content_fingerprint=_AFTER_FINGERPRINT,
            accounts=(after_account,),
        ),
    )
    first = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=_AuthorizePortWithEffect(),
        authorization_token_port=_AuthorizationTokenPort(),
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        first.authorize()

    assert raised.value.code == "inventory.readonly_control_unavailable"
    assert document == _authorization_document()
    assert manager.reload_calls == []

    recovered_authorize_port = _AuthorizePortWithEffect()
    recovered_token_port = _AuthorizationTokenPort()
    recovered = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=recovered_authorize_port,
        authorization_token_port=recovered_token_port,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    assert recovered.authorize() == {"status": "authorized"}
    assert recovered_authorize_port.calls == 1
    assert recovered_token_port.lookup_calls == []
    assert store.update_calls == 2
    assert manager.reload_calls == [7]


def test_authorize_rejects_a_different_current_document_subject_before_store_cas(
    tmp_path: Path,
) -> None:
    document = {"google_accounts": [{"ref": _ACCOUNT_REF, "subject_id": "other"}]}
    store = _Store(document)
    account = SimpleNamespace(ref=_ACCOUNT_REF, subject_id=None, login_email=_LOGIN)
    manager = _Manager(
        SimpleNamespace(
            generation=7,
            content_fingerprint=_AFTER_FINGERPRINT,
            accounts=(account,),
        ),
        SimpleNamespace(
            generation=8,
            content_fingerprint=_AFTER_FINGERPRINT,
            accounts=(account,),
        ),
    )
    service = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=_AuthorizePortWithEffect(),
        authorization_token_port=_AuthorizationTokenPort(),
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        service.authorize()

    assert raised.value.code == "inventory.readonly_control_unavailable"
    assert store.update_calls == 0
    assert manager.reload_calls == []


def test_authorize_subject_cas_rechecks_the_fresh_locked_document_before_write(
    tmp_path: Path,
) -> None:
    raced_document = _authorization_document()
    raced_document["revision"] = "concurrent-synthetic-change"
    store = _StoreChangedBeforeLockedTransform(
        _authorization_document(), raced_document
    )
    before_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=None, login_email=_LOGIN
    )
    after_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=_SUBJECT, login_email=_LOGIN
    )
    manager = _Manager(
        SimpleNamespace(
            generation=7,
            content_fingerprint=_BEFORE_FINGERPRINT,
            accounts=(before_account,),
        ),
        SimpleNamespace(
            generation=8,
            content_fingerprint=_AFTER_FINGERPRINT,
            accounts=(after_account,),
        ),
    )
    service = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=_AuthorizePortWithEffect(),
        authorization_token_port=_AuthorizationTokenPort(),
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        service.authorize()

    assert raised.value.code == "inventory.readonly_control_unavailable"
    accounts = store.document["google_accounts"]
    assert type(accounts) is list and type(accounts[0]) is dict
    assert accounts[0]["subject_id"] is None
    assert manager.reload_calls == []


def test_authorize_subject_cas_rechecks_fresh_generation_under_the_store_lock(
    tmp_path: Path,
) -> None:
    before_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=None, login_email=_LOGIN
    )
    after_account = SimpleNamespace(
        ref=_ACCOUNT_REF, subject_id=_SUBJECT, login_email=_LOGIN
    )
    manager = _Manager(
        SimpleNamespace(
            generation=7,
            content_fingerprint=_BEFORE_FINGERPRINT,
            accounts=(before_account,),
        ),
        SimpleNamespace(
            generation=8,
            content_fingerprint=_AFTER_FINGERPRINT,
            accounts=(after_account,),
        ),
    )

    def advance_manager_only() -> None:
        manager.snapshot = SimpleNamespace(
            generation=8,
            content_fingerprint=_BEFORE_FINGERPRINT,
            accounts=(before_account,),
        )

    store = _StoreRunsBeforeLockedTransform(
        _authorization_document(), advance_manager_only
    )
    service = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=_AuthorizePortWithEffect(),
        authorization_token_port=_AuthorizationTokenPort(),
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        service.authorize()

    assert raised.value.code == "inventory.readonly_control_unavailable"
    accounts = store.document["google_accounts"]
    assert type(accounts) is list and type(accounts[0]) is dict
    assert accounts[0]["subject_id"] is None
    assert manager.reload_calls == []


def test_authorize_reattests_an_equal_subject_without_a_second_store_write(
    tmp_path: Path,
) -> None:
    document = {"google_accounts": [{"ref": _ACCOUNT_REF, "subject_id": _SUBJECT}]}
    store = _Store(document)
    account = SimpleNamespace(ref=_ACCOUNT_REF, subject_id=_SUBJECT, login_email=_LOGIN)
    snapshot = SimpleNamespace(
        generation=7,
        content_fingerprint=_AFTER_FINGERPRINT,
        accounts=(account,),
    )
    manager = _Manager(snapshot, snapshot)
    token_port = _AuthorizationTokenPort()
    service = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_authorization_document_state,
        authorization_port=_AuthorizePortWithEffect(),
        authorization_token_port=token_port,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    assert service.authorize() == {"status": "authorized"}
    assert store.update_calls == 0
    assert manager.reload_calls == []
    assert len(token_port.store_calls) == 1
    assert token_port.store_calls[0]["inventory_generation"] == 7


def test_scan_plan_rejects_private_values_disguised_as_public_change_kinds(
    tmp_path: Path,
) -> None:
    service = _authorized_service_with_scan(tmp_path, scan_port=_LeakingScanPort())

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        service.scan_plan()

    assert raised.value.code == "inventory.readonly_control_unavailable"


def test_apply_performs_one_attested_local_store_update_then_one_reload(
    tmp_path: Path,
) -> None:
    service, store, manager = _service({"phase": "before"}, tmp_path)
    plan_reference = service._register_scan_plan_for_internal_use(_Plan())

    result = service.apply(plan_reference)

    assert result == {"status": "applied"}
    assert store.document == {"phase": "after"}
    assert store.update_calls == 1
    assert manager.reload_calls == [7]
    assert _ACCOUNT_REF not in repr(result)
    assert _SUBJECT not in repr(result)


def test_apply_fails_closed_when_store_content_no_longer_matches_plan(
    tmp_path: Path,
) -> None:
    service, store, manager = _service({"phase": "unexpected"}, tmp_path)
    plan_reference = service._register_scan_plan_for_internal_use(_Plan())

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        service.apply(plan_reference)

    assert raised.value.code == "inventory.readonly_control_plan_stale"
    assert store.document == {"phase": "unexpected"}
    assert store.update_calls == 0
    assert manager.reload_calls == []


def test_apply_recovers_only_a_committed_matching_plan_without_a_second_store_write(
    tmp_path: Path,
) -> None:
    service, store, manager = _service({"phase": "before"}, tmp_path)
    manager.fail_reload_once = True
    plan_reference = service._register_scan_plan_for_internal_use(_Plan())

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        service.apply(plan_reference)

    assert raised.value.code == "inventory.readonly_control_apply_failed"
    assert store.document == {"phase": "after"}
    assert store.update_calls == 1
    assert manager.reload_calls == [7]

    result = service.apply(plan_reference)

    assert result == {"status": "applied"}
    assert store.update_calls == 1
    assert manager.reload_calls == [7]

    assert service.apply(plan_reference) == {"status": "applied"}
    assert store.update_calls == 1
    assert manager.reload_calls == [7]


def test_apply_revalidates_the_private_plan_binding_before_the_store_cas(
    tmp_path: Path,
) -> None:
    service, store, manager = _service({"phase": "before"}, tmp_path)
    plan = _BindingChangingPlan()
    plan_reference = service._register_scan_plan_for_internal_use(plan)
    plan.change_scope_binding()

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        service.apply(plan_reference)

    assert raised.value.code == "inventory.readonly_control_plan_invalid"
    assert store.document == {"phase": "before"}
    assert store.update_calls == 0
    assert manager.reload_calls == []


def test_apply_rejects_a_private_plan_whose_recomputed_digest_is_invalid(
    tmp_path: Path,
) -> None:
    service, store, manager = _service({"phase": "before"}, tmp_path)

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        service._register_scan_plan_for_internal_use(_DigestInvalidPlan())

    assert raised.value.code == "inventory.readonly_control_plan_invalid"
    assert store.document == {"phase": "before"}
    assert store.update_calls == 0
    assert manager.reload_calls == []


def test_recovery_rejects_a_plan_whose_private_binding_changed_after_commit(
    tmp_path: Path,
) -> None:
    service, store, manager = _service({"phase": "before"}, tmp_path)
    manager.fail_reload_once = True
    plan = _BindingChangingPlan()
    plan_reference = service._register_scan_plan_for_internal_use(plan)

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        service.apply(plan_reference)
    assert raised.value.code == "inventory.readonly_control_apply_failed"
    assert store.update_calls == 1
    assert manager.reload_calls == [7]

    plan.change_scope_binding()
    with pytest.raises(GoogleInventoryReadonlyControlError) as recovered:
        service.apply(plan_reference)

    assert recovered.value.code == "inventory.readonly_control_recovery_failed"
    assert store.update_calls == 1
    assert manager.reload_calls == [7]


def test_recovery_rechecks_the_private_plan_digest_before_reloading(
    tmp_path: Path,
) -> None:
    service, store, manager = _service({"phase": "before"}, tmp_path)
    manager.fail_reload_once = True
    plan = _PostCommitDigestInvalidPlan()
    plan_reference = service._register_scan_plan_for_internal_use(plan)

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        service.apply(plan_reference)
    assert raised.value.code == "inventory.readonly_control_apply_failed"
    assert store.update_calls == 1
    assert manager.reload_calls == [7]

    plan.invalid = True
    with pytest.raises(GoogleInventoryReadonlyControlError) as recovered:
        service.apply(plan_reference)

    assert recovered.value.code == "inventory.readonly_control_recovery_failed"
    assert store.update_calls == 1
    assert manager.reload_calls == [7]


def test_reconstructed_authority_recovers_a_durable_post_commit_operation_once(
    tmp_path: Path,
) -> None:
    service, store, manager = _service({"phase": "before"}, tmp_path)
    manager.fail_reload_once = True
    plan_reference = service._register_scan_plan_for_internal_use(_Plan())

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        service.apply(plan_reference)
    assert raised.value.code == "inventory.readonly_control_apply_failed"
    assert store.document == {"phase": "after"}
    assert store.update_calls == 1
    assert manager.reload_calls == [7]

    journal_files = tuple(tmp_path.iterdir())
    assert len(journal_files) == 1
    journal_bytes = journal_files[0].read_bytes()
    assert _ACCOUNT_REF.encode() not in journal_bytes
    assert _SUBJECT.encode() not in journal_bytes
    assert str(tmp_path) not in repr(service)
    with pytest.raises(TypeError):
        pickle.dumps(service)

    recovered = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_document_state,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    assert recovered.apply(plan_reference) == {"status": "applied"}
    assert recovered.apply(plan_reference) == {"status": "applied"}
    assert store.update_calls == 1
    assert manager.reload_calls == [7]


def test_reconstructed_authority_applies_a_durable_sealed_plan_once(
    tmp_path: Path,
) -> None:
    service, store, manager = _service({"phase": "before"}, tmp_path)
    plan_reference = service._register_scan_plan_for_internal_use(_Plan())

    reconstructed = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_document_state,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 1,
    )

    assert reconstructed.apply(plan_reference) == {"status": "applied"}
    assert store.document == {"phase": "after"}
    assert store.update_calls == 1
    assert manager.reload_calls == [7]


def test_reconstructed_authority_rejects_an_expired_durable_plan_before_store_cas(
    tmp_path: Path,
) -> None:
    service, store, manager = _service({"phase": "before"}, tmp_path)
    plan_reference = service._register_scan_plan_for_internal_use(_Plan())

    reconstructed = GoogleInventoryReadonlyControlService._for_test_components(
        store=store,
        manager=manager,
        document_state_reader=_document_state,
        journal_directory=tmp_path,
        plan_rehydrator=_rehydrate_test_plan,
        clock=lambda: 101,
    )

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        reconstructed.apply(plan_reference)

    assert raised.value.code == "inventory.readonly_control_plan_expired"
    assert store.document == {"phase": "before"}
    assert store.update_calls == 0
    assert manager.reload_calls == []


def test_tampered_durable_plan_digest_is_rejected_before_store_cas(
    tmp_path: Path,
) -> None:
    service, store, manager = _service({"phase": "before"}, tmp_path)
    service._register_scan_plan_for_internal_use(_Plan())
    journal_file = next(tmp_path.iterdir())
    journal = json.loads(journal_file.read_text(encoding="ascii"))
    sealed_plan = journal["sealed_plan"]
    assert type(sealed_plan) is dict
    sealed_plan["plan_digest"] = "sha256:" + "f" * 64
    journal_file.write_text(
        json.dumps(journal, separators=(",", ":"), sort_keys=True), encoding="ascii"
    )

    with pytest.raises(GoogleInventoryReadonlyControlError) as raised:
        GoogleInventoryReadonlyControlService._for_test_components(
            store=store,
            manager=manager,
            document_state_reader=_document_state,
            journal_directory=tmp_path,
            plan_rehydrator=_rehydrate_test_plan,
            clock=lambda: 1,
        )

    assert raised.value.code == "inventory.readonly_control_unavailable"
    assert store.document == {"phase": "before"}
    assert store.update_calls == 0
    assert manager.reload_calls == []


def test_private_registry_entry_never_serializes_the_plan_or_its_binding(
    tmp_path: Path,
) -> None:
    service, _, _ = _service({"phase": "before"}, tmp_path)
    plan_reference = service._register_scan_plan_for_internal_use(_Plan())
    _, entry = service._plan_registry.resolve(plan_reference)

    assert repr(entry) == "_PlanRegistryEntry(<redacted>)"
    with pytest.raises(TypeError, match="_PlanRegistryEntry is not serializable"):
        pickle.dumps(entry)


def test_public_constructor_has_no_caller_replaceable_ports() -> None:
    assert (
        tuple(inspect.signature(GoogleInventoryReadonlyControlService).parameters) == ()
    )


def test_public_constructor_composes_only_fixed_source_owned_production_owners(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The public constructor accepts no port, path, OAuth or broker selection."""

    events: list[tuple[str, object]] = []

    class _Components:
        _vault = object()

        def _journal_directory_for_authority(self) -> Path:
            events.append(("journal", None))
            return tmp_path

    class _ManagerFactory:
        @classmethod
        def from_systemd_state_directory(cls) -> object:
            del cls
            events.append(("manager", None))
            return manager

    class _StoreFactory:
        @classmethod
        def from_systemd_state_directory(cls) -> object:
            del cls
            events.append(("store", None))
            return store

    components = _Components()
    manager = object()
    store = object()
    authorization_port = object()
    token_port = object()
    scan_component = object()
    scan_owner = object()

    monkeypatch.setattr(
        _control_module._token_vault,
        "_new_the_hive_inventory_vault_production_components",
        lambda: components,
    )
    monkeypatch.setattr(
        _inventory_manager,
        "GoogleAccountInventoryManager",
        _ManagerFactory,
    )
    monkeypatch.setattr(
        _control_module._inventory_store,
        "GoogleInventoryStore",
        _StoreFactory,
    )
    monkeypatch.setattr(
        _control_module._token_vault,
        "_new_inventory_readonly_authorization_token_port",
        lambda vault, supplied_manager: (
            events.append(("token", (vault, supplied_manager))) or token_port
        ),
    )
    monkeypatch.setattr(
        _control_module._oauth_session,
        "_new_the_hive_inventory_readonly_authorization_port",
        lambda *, vault_components, manager: (
            events.append(("oauth", (vault_components, manager))) or authorization_port
        ),
    )
    monkeypatch.setattr(
        _control_module._scan,
        "_create_scan_component_for_control",
        lambda *, broker, discovery: (
            events.append(("scan", (broker, discovery))) or (scan_component, scan_owner)
        ),
    )

    service = GoogleInventoryReadonlyControlService()

    assert service._store is store
    assert service._manager is None
    assert service._vault_components is components
    assert isinstance(
        service._authorization_port, _control_module._UnavailableAuthorizationPort
    )
    assert isinstance(
        service._authorization_token_port,
        _control_module._UnavailableAuthorizationTokenPort,
    )
    assert service._scan_component is None
    assert service._scan_owner is None
    assert events == [("store", None), ("journal", None)]


def test_scan_reverifies_a_durable_authorization_receipt_and_current_binding(
    tmp_path: Path,
) -> None:
    component = _BoundScanComponent()
    owner = object()
    service = _authorized_service_with_scan(
        tmp_path,
        scan_component=component,
        scan_owner=owner,
    )

    planned = service.scan_plan()

    assert planned["status"] == "planned"
    assert component.binding_calls == [
        (
            owner,
            {
                "account_ref": _ACCOUNT_REF,
                "subject_id": _SUBJECT,
                "inventory_generation": 8,
                "content_fingerprint": _AFTER_FINGERPRINT,
                "oauth_client_fingerprint": "sha256:" + "4" * 64,
                "scope_fingerprint": "sha256:" + "5" * 64,
                "receipt_operation_digest": service._authorization_journal._receipt.operation_digest,
                "receipt_binding_fingerprint": service._authorization_journal._receipt.binding_fingerprint,
            },
        )
    ]
    assert len(component.scan_calls) == 1
    assert component.scan_calls[0][0] is owner
    assert component.scan_calls[0][2] == {
        "google_accounts": [{"ref": _ACCOUNT_REF, "subject_id": _SUBJECT}]
    }
