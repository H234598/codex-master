from __future__ import annotations

import ast
from dataclasses import asdict, is_dataclass
import gc
import inspect
import math
from pathlib import Path
import pickle
import threading
import weakref

import pytest
import yaml

import codex_master.google_account_inventory_manager as manager_module
from codex_master.admin_contracts import AdminContractError
from codex_master.google_account_inventory import GoogleAccountInventoryError
from codex_master.google_account_inventory import GoogleAccountInventoryLoader
from codex_master.google_account_inventory_manager import (
    GoogleAccountInventoryManager,
    GoogleAccountInventoryStatusV1,
    _SecretLeasePurposeV1,
    InventoryManagerStateV1,
    InventorySourceTypeV1,
)


SYNTHETIC_SECRET = "synthetic-secret-not-for-output"


class ExplodingComparison:
    def __eq__(self, other: object) -> bool:
        raise AssertionError("custom equality must not run")

    def __hash__(self) -> int:
        raise AssertionError("custom hashing must not run")


class StringSubclass(str):
    pass


def fresh_document(
    root: Path,
    *,
    secret: str | None = SYNTHETIC_SECRET,
    key_id: object = "000654",
) -> object:
    if root.exists():
        root = root / "inventory"
    document = {
        "schema_version": 1,
        "google_accounts": [
            {
                "ref": "google-account-01",
                "login_email": "account@example.test",
                "recovery_email": None,
                "label": "Test account",
                "subject_id": "000123",
                "billing_accounts": [
                    {
                        "ref": "billing-01",
                        "billing_account_id": "000456",
                        "label": "Trial",
                    }
                ],
                "projects": [
                    {
                        "ref": "the-hive-1",
                        "billing_account_ref": "billing-01",
                        "status": "active",
                        "project_id": "000789",
                        "project_number": "000987",
                        "key_id": key_id,
                        "key_uid": "000321",
                        "secret": secret,
                    }
                ],
            }
        ],
    }
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    path = root / "api-token.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)
    return GoogleAccountInventoryLoader._for_test_path(path).load()


def projection_document(
    root: Path,
    *,
    private_marker: str,
    public_overrides: dict[str, str] | None = None,
) -> object:
    if root.exists():
        root = root / "inventory"
    accounts = []
    for number, account_ref, project_ref, label, subject_id in (
        (
            1,
            "google-account-01",
            "the-hive-1",
            "Quiet account",
            f"{private_marker}-subject-one",
        ),
        (2, "google-account-02", "the-hive-2", "Calm account", None),
    ):
        accounts.append(
            {
                "ref": account_ref,
                "login_email": f"{private_marker}-{number}@example.test",
                "recovery_email": f"{private_marker}-recovery-{number}@example.test",
                "label": label,
                "subject_id": subject_id,
                "auth": {
                    "access_token": f"{private_marker}-access-{number}",
                    "refresh_token": f"{private_marker}-refresh-{number}",
                    "cookies": [{"value": f"{private_marker}-cookie-{number}"}],
                    "client_fingerprint": f"{private_marker}-fingerprint-{number}",
                },
                "billing_accounts": [
                    {
                        "ref": f"billing-{number:02d}",
                        "billing_account_id": f"{private_marker}-billing-{number}",
                        "label": f"Billing {number}",
                    }
                ],
                "projects": [
                    {
                        "ref": project_ref,
                        "billing_account_ref": f"billing-{number:02d}",
                        "status": "active" if number == 1 else "blocked",
                        "project_id": f"{private_marker}-project-{number}",
                        "project_number": f"{private_marker}-number-{number}",
                        "key_id": f"{private_marker}-key-{number}",
                        "key_uid": f"{private_marker}-uid-{number}",
                        "secret": f"{private_marker}-secret-{number}"
                        if number == 1
                        else None,
                        "project_name": (
                            "Quietglow Aurorabay"
                            if number == 1
                            else "Calmshore Fernhaven"
                        ),
                        "purpose": "hive" if number == 1 else "external",
                        "key_name": (
                            "Quietglow Aurorabay Key"
                            if number == 1
                            else "Calmshore Fernhaven Key"
                        ),
                    }
                ],
            }
        )
    for field, value in (public_overrides or {}).items():
        if field in {"ref", "label"}:
            accounts[0][field] = value
        elif field == "billing_ref":
            accounts[0]["billing_accounts"][0]["ref"] = value
            accounts[0]["projects"][0]["billing_account_ref"] = value
        else:
            accounts[0]["projects"][0][field] = value
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    path = root / "api-token.yaml"
    path.write_text(
        yaml.safe_dump(
            {"schema_version": 2, "google_accounts": accounts}, sort_keys=False
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return GoogleAccountInventoryLoader._for_test_path(path).load()


class FakeMonotonic:
    def __init__(self) -> None:
        self.seconds = 0.0

    def __call__(self) -> float:
        return self.seconds

    def advance(self, seconds: float) -> None:
        self.seconds += seconds


def sequence_loader(*outcomes: object):
    remaining = iter(outcomes)

    def load() -> object:
        outcome = next(remaining)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    return load


def test_manager(*outcomes: object, **kwargs: object) -> GoogleAccountInventoryManager:
    kwargs.setdefault("monotonic_clock", FakeMonotonic())
    kwargs.setdefault("operator_timestamp_utc", lambda: "2026-08-23T12:00:00Z")
    return GoogleAccountInventoryManager._for_test_loader(
        sequence_loader(*outcomes), **kwargs
    )


test_manager.__test__ = False


def test_default_manager_initializes_empty_and_reload_failure_is_redacted() -> None:
    manager = GoogleAccountInventoryManager()
    failure = manager_module._ReloadFailureV1("private-code")

    assert manager.status().state is InventoryManagerStateV1.EMPTY
    assert manager.status().generation is None
    assert repr(failure) == "_ReloadFailureV1()"
    assert "private-code" not in repr(failure)
    with pytest.raises(TypeError, match="not serializable"):
        pickle.dumps(failure)


def test_reload_rejects_stale_expected_generation_before_publish(
    tmp_path: Path,
) -> None:
    first = fresh_document(tmp_path / "first")
    second = fresh_document(tmp_path / "second", key_id="000655")
    manager = test_manager(first, second)
    assert manager.reload().generation == 1

    with pytest.raises(
        GoogleAccountInventoryError, match="credential.generation_conflict"
    ):
        manager.reload(expected_generation=0)

    assert manager.inventory_generation() == 1


def issue_valid_lease(
    manager: GoogleAccountInventoryManager,
    snapshot: object,
    ttl_seconds: float = 30.0,
    key_id: object = "000654",
) -> object:
    return manager._issue_secret_lease(
        expected_generation=snapshot.generation,
        account_ref="google-account-01",
        project_ref="the-hive-1",
        key_id=key_id,  # type: ignore[arg-type]
        purpose=_SecretLeasePurposeV1.PROVIDER_REQUEST,
        ttl_seconds=ttl_seconds,
    )


def consume_valid_lease(
    manager: GoogleAccountInventoryManager,
    lease: object,
    snapshot: object,
    **overrides: object,
) -> str:
    binding = {
        "expected_generation": snapshot.generation,
        "account_ref": "google-account-01",
        "project_ref": "the-hive-1",
        "key_id": "000654",
        "purpose": _SecretLeasePurposeV1.PROVIDER_REQUEST,
    }
    binding.update(overrides)
    return manager._consume_secret_lease(lease, **binding)


def test_manager_returning(*documents: object) -> GoogleAccountInventoryManager:
    return test_manager(*documents)


test_manager_returning.__test__ = False


def private_claim_for_test(document: object) -> object:
    manager_module._claim_document_ownership(document, object())
    return manager_module._DOCUMENT_OWNERS[id(document)]


def private_ownership_record_for_test(document: object) -> object:
    return manager_module._DOCUMENT_OWNERS[id(document)]


def blocking_document(
    entered: threading.Event,
    release: threading.Event,
    document: object,
):
    def load() -> object:
        entered.set()
        try:
            assert release.wait(timeout=1)
            return document
        finally:
            entered.clear()

    return load


def blocking_sequence_loader(
    first: object,
    entered: threading.Event,
    release: threading.Event,
    second: object,
):
    first_pending = True

    def load() -> object:
        nonlocal first_pending
        if first_pending:
            first_pending = False
            return first
        return blocking_document(entered, release, second)()

    return load


def _exception_graph_values(error: BaseException) -> list[object]:
    pending: list[object] = [error]
    seen: set[int] = set()
    values: list[object] = []
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        values.append(value)
        if isinstance(value, BaseException):
            pending.extend(
                linked
                for linked in (value.__context__, value.__cause__)
                if linked is not None
            )
            traceback = value.__traceback__
            while traceback is not None:
                values.extend(traceback.tb_frame.f_locals.values())
                traceback = traceback.tb_next
    return values


def _assert_reload_failure_graph_is_redacted(error: BaseException) -> None:
    forbidden_markers = (
        SYNTHETIC_SECRET,
        "google-account-01",
        "account@example.test",
        "000123",
        "billing-01",
        "000456",
        "the-hive-1",
        "000789",
        "000654",
    )
    for value in _exception_graph_values(error):
        assert type(value).__name__ != "GoogleAccountInventoryDocumentV1"
        assert type(value).__name__ != "_GoogleAccountInventorySecretSource"
        if isinstance(value, str):
            assert all(marker not in value for marker in forbidden_markers)
        if isinstance(value, (tuple, list, dict)):
            nested = value.values() if isinstance(value, dict) else value
            for item in nested:
                assert type(item).__name__ != "GoogleAccountInventoryDocumentV1"
                assert type(item).__name__ != "_GoogleAccountInventorySecretSource"
                if isinstance(item, str):
                    assert all(marker not in item for marker in forbidden_markers)


def _capture_candidate_failure(operation: object, candidate: object) -> BaseException:
    try:
        operation(candidate)  # type: ignore[operator]
    except BaseException as error:
        candidate = None
        return error
    raise AssertionError("candidate operation unexpectedly succeeded")


def test_review_candidate_repr_asdict_pickle_paths_and_type_are_gone(
    tmp_path: Path,
) -> None:
    candidate_type = getattr(manager_module, "_ReloadCandidateV1", None)
    if candidate_type is not None:
        manager = test_manager(fresh_document(tmp_path))
        candidate = manager._prepare_reload_candidate()
        assert isinstance(candidate, candidate_type)
        for operation in (repr, asdict, pickle.dumps):
            failure = _capture_candidate_failure(operation, candidate)
            assert all(
                type(value).__name__ != "_ReloadCandidateV1"
                for value in _exception_graph_values(failure)
            )
            _assert_reload_failure_graph_is_redacted(failure)
        del candidate
    assert candidate_type is None
    assert not hasattr(GoogleAccountInventoryManager, "_prepare_reload_candidate")


def test_review_reload_has_no_candidate_or_source_document_transfer_ast() -> None:
    source = inspect.getsource(manager_module)
    tree = ast.parse(source)
    assert "_ReloadCandidateV1" not in source
    assert all(
        not isinstance(node, ast.ClassDef) or node.name != "_ReloadCandidateV1"
        for node in ast.walk(tree)
    )

    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    helper = functions["_prepare_and_publish_reload_locked"]
    reload_function = functions["reload"]
    for return_node in ast.walk(tree):
        if not isinstance(return_node, ast.Return) or return_node.value is None:
            continue
        assert not (
            isinstance(return_node.value, ast.Name)
            and return_node.value.id in {"document", "source"}
        )
        assert not (
            isinstance(return_node.value, ast.Attribute)
            and return_node.value.attr in {"document", "source"}
        )
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_ReloadCandidateV1"
            for node in ast.walk(return_node.value)
        )
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Yield))
        for node in ast.walk(helper)
        if node is not helper
    )
    assert not any(
        isinstance(node, ast.Name)
        and node.id in {"document", "source"}
        or isinstance(node, ast.Attribute)
        and node.attr in {"document", "source"}
        for node in ast.walk(reload_function)
    )


def test_review_reload_success_returns_only_redacted_status(tmp_path: Path) -> None:
    manager = test_manager(fresh_document(tmp_path))
    result = manager.reload()

    assert type(result) is GoogleAccountInventoryStatusV1
    visible = (
        repr(result),
        str(result),
        repr(asdict(result)),
        repr(result.public_projection()),
        repr(vars(result)),
        repr(dir(result)),
    )
    markers = (
        SYNTHETIC_SECRET,
        "google-account-01",
        "account@example.test",
        "000123",
        "billing-01",
        "000456",
        "the-hive-1",
        "000789",
        "000654",
    )
    assert all(marker not in value for value in visible for marker in markers)
    pickled = pickle.dumps(result)
    assert all(marker.encode() not in pickled for marker in markers)


def test_first_reload_publishes_immutable_generation_one_snapshot(
    tmp_path: Path,
) -> None:
    manager = GoogleAccountInventoryManager._for_test_loader(
        lambda: fresh_document(tmp_path),
        monotonic_clock=FakeMonotonic(),
        operator_timestamp_utc=lambda: "2026-08-23T12:00:00Z",
    )
    status = manager.reload()
    snapshot = manager._snapshot_for_internal_use()
    assert status.generation == 1
    assert status.source_type is InventorySourceTypeV1.TEST
    assert status.loaded_at_utc == "2026-08-23T12:00:00Z"
    assert snapshot.by_account_ref["google-account-01"].ref == "google-account-01"
    assert snapshot.by_project_ref["the-hive-1"].hive_slot == 1
    assert snapshot.by_hive_slot[1].ref == "the-hive-1"


def test_status_and_snapshot_public_projection_are_redacted_aggregates(
    tmp_path: Path,
) -> None:
    manager = test_manager(fresh_document(tmp_path))
    status = manager.reload()
    assert status.project_count == 1
    assert status.new_work_allowed is True
    assert set(status.public_projection()) == {
        "state",
        "new_work_allowed",
        "generation",
        "loaded_at_utc",
        "source_type",
        "content_fingerprint",
        "account_count",
        "billing_account_count",
        "project_count",
        "active_project_count",
    }


def test_admin_views_are_immutable_redacted_and_account_isolated(
    tmp_path: Path,
) -> None:
    private_marker = "private-provider-marker"
    manager = test_manager(projection_document(tmp_path, private_marker=private_marker))
    manager.reload()

    accounts = manager.list_accounts()
    assert accounts == (
        {
            "ref": "google-account-01",
            "label": "Quiet account",
            "subject_bound": True,
            "inventory_generation": 1,
            "project_count": 1,
            "billing_count": 1,
        },
        {
            "ref": "google-account-02",
            "label": "Calm account",
            "subject_bound": False,
            "inventory_generation": 1,
            "project_count": 1,
            "billing_count": 1,
        },
    )
    assert manager.get_account("google-account-01") == accounts[0]
    assert manager.list_projects("google-account-01") == (
        {
            "ref": "the-hive-1",
            "project_name": "Quietglow Aurorabay",
            "key_name": "Quietglow Aurorabay Key",
            "purpose": "hive",
            "billing_ref": "billing-01",
            "status": "active",
            "inventory_generation": 1,
        },
    )
    assert manager.inventory_generation() == 1
    assert private_marker not in repr(
        (
            accounts,
            manager.get_account("google-account-01"),
            manager.list_projects("google-account-01"),
        )
    )
    with pytest.raises(TypeError):
        accounts[0]["label"] = "changed"  # type: ignore[index]


@pytest.mark.parametrize(
    ("field", "value", "operation"),
    [
        ("ref", "/private/credential.json", "accounts"),
        ("label", "private-login@example.test", "accounts"),
        ("label", "RuntimeError: provider exploded", "accounts"),
        ("label", "ＣＬＩＥＮＴＳＥＣＲＥＴ topvalue", "accounts"),
        ("label", "client%5Fsecret=topvalue", "accounts"),
        ("label", "client%255Fsecret=topvalue", "accounts"),
        ("label", "failed%20at%20%2Fprivate%2Fauth.json", "accounts"),
        ("project_name", "Secret Meadow", "projects"),
        ("key_name", "cLiEnTsEcReT Meadow", "projects"),
        ("billing_ref", "client%5Fsecret", "projects"),
    ],
)
def test_admin_views_reject_private_smuggling_in_public_source_fields(
    tmp_path: Path,
    field: str,
    value: str,
    operation: str,
) -> None:
    manager = test_manager(
        projection_document(
            tmp_path,
            private_marker="private-source-marker",
            public_overrides={field: value},
        )
    )
    manager.reload()

    with pytest.raises(AdminContractError) as caught:
        if operation == "accounts":
            manager.list_accounts()
        else:
            manager.list_projects("google-account-01")

    assert caught.value.code == "control.response_private"
    assert value not in repr(caught.value)


def test_admin_views_keep_safe_unicode_label(tmp_path: Path) -> None:
    manager = test_manager(
        projection_document(
            tmp_path,
            private_marker="private-source-marker",
            public_overrides={"label": "Café München"},
        )
    )
    manager.reload()

    assert manager.get_account("google-account-01")["label"] == "Café München"


def test_admin_views_use_one_existing_snapshot_per_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first_manager = test_manager(
        projection_document(tmp_path / "first", private_marker="first-private")
    )
    second_manager = test_manager(
        projection_document(tmp_path / "second-one", private_marker="second-private"),
        projection_document(tmp_path / "second-two", private_marker="second-private"),
    )
    first_manager.reload()
    second_manager.reload()
    second_manager.reload()
    first_snapshot = first_manager._snapshot_for_internal_use()
    second_snapshot = second_manager._snapshot_for_internal_use()
    assert second_snapshot.generation == 2

    def reject_second_yaml_read() -> object:
        raise AssertionError("admin view must not call inventory loader")

    monkeypatch.setattr(first_manager, "_document_loader", reject_second_yaml_read)
    generation_reads = (
        lambda: first_manager.list_accounts()[0]["inventory_generation"],
        lambda: first_manager.get_account("google-account-01")["inventory_generation"],
        lambda: first_manager.list_projects("google-account-01")[0][
            "inventory_generation"
        ],
        first_manager.inventory_generation,
    )
    for read_generation in generation_reads:
        snapshots = iter((first_snapshot, second_snapshot))
        monkeypatch.setattr(
            first_manager, "_snapshot_for_internal_use", lambda: next(snapshots)
        )
        assert read_generation() == 1
        assert next(snapshots) is second_snapshot


def test_admin_views_fail_closed_for_unknown_and_duplicate_account_refs(
    tmp_path: Path,
) -> None:
    private_marker = "private-error-marker"
    manager = test_manager(
        projection_document(tmp_path / "valid", private_marker=private_marker)
    )
    manager.reload()
    for operation in (manager.get_account, manager.list_projects):
        with pytest.raises(GoogleAccountInventoryError) as caught:
            operation(private_marker)
        assert caught.value.code == "credential.account_not_found"
        assert private_marker not in repr(caught.value)

    duplicate = tmp_path / "duplicate"
    document = {
        "schema_version": 1,
        "google_accounts": [
            {
                "ref": "duplicate-account",
                "login_email": "one@example.test",
                "billing_accounts": [],
                "projects": [],
            },
            {
                "ref": "duplicate-account",
                "login_email": "two@example.test",
                "billing_accounts": [],
                "projects": [],
            },
        ],
    }
    duplicate.mkdir(mode=0o700)
    path = duplicate / "api-token.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)
    loader = GoogleAccountInventoryLoader._for_test_path(path)
    invalid_manager = test_manager(loader.load)
    with pytest.raises(
        GoogleAccountInventoryError, match="credential.inventory_reload_failed"
    ):
        invalid_manager.reload()
    with pytest.raises(
        GoogleAccountInventoryError, match="credential.inventory_snapshot_unavailable"
    ):
        invalid_manager.list_accounts()


def test_startup_without_snapshot_is_fail_closed(tmp_path: Path) -> None:
    manager = test_manager(
        GoogleAccountInventoryError("credential.inventory_schema_invalid")
    )
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_reload_failed",
    ):
        manager.reload()
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_snapshot_unavailable",
    ):
        manager._snapshot_for_internal_use()


def test_failed_later_reload_keeps_snapshot_but_blocks_new_leases(
    tmp_path: Path,
) -> None:
    manager = test_manager(
        fresh_document(tmp_path / "first"),
        GoogleAccountInventoryError("credential.inventory_schema_invalid"),
    )
    first = manager.reload()
    first_internal = manager._snapshot_for_internal_use()
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_reload_failed",
    ):
        manager.reload()
    assert manager._snapshot_for_internal_use() is first_internal
    assert manager.status().state is InventoryManagerStateV1.RELOAD_BLOCKED
    assert manager.status().new_work_allowed is False
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_reload_failed",
    ):
        issue_valid_lease(manager, first)


def test_later_successful_reload_publishes_next_generation_and_reopens_gate(
    tmp_path: Path,
) -> None:
    manager = test_manager(
        fresh_document(tmp_path / "first"),
        GoogleAccountInventoryError("credential.inventory_schema_invalid"),
        fresh_document(tmp_path / "second"),
    )
    manager.reload()
    with pytest.raises(GoogleAccountInventoryError):
        manager.reload()
    assert manager.reload().generation == 2
    assert manager.status().state is InventoryManagerStateV1.READY


def test_same_manager_rejects_second_consume_of_same_document(
    tmp_path: Path,
) -> None:
    document = fresh_document(tmp_path)
    manager = test_manager_returning(document, document)
    status = manager.reload()
    lease = issue_valid_lease(manager, status, ttl_seconds=10.0)
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_document_consumed",
    ):
        manager.reload()
    assert manager.status().state is InventoryManagerStateV1.RELOAD_BLOCKED
    assert manager._active.source is None
    assert manager._active.document is None
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_reload_failed",
    ):
        issue_valid_lease(manager, status)
    assert consume_valid_lease(manager, lease, status) == SYNTHETIC_SECRET


def test_other_manager_rejects_document_owned_by_first_manager(
    tmp_path: Path,
) -> None:
    document = fresh_document(tmp_path)
    first = test_manager_returning(document)
    second = test_manager_returning(document)
    first.reload()
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_document_foreign",
    ):
        second.reload()


def test_distinct_value_equal_documents_do_not_collide_in_ownership_table(
    tmp_path: Path,
) -> None:
    first_document = fresh_document(tmp_path / "first")
    second_document = fresh_document(tmp_path / "second")
    assert first_document == second_document
    assert first_document is not second_document
    assert test_manager(first_document).reload().generation == 1
    assert test_manager(second_document).reload().generation == 1


def test_stale_ownership_cleanup_cannot_remove_new_identity_record(
    tmp_path: Path,
) -> None:
    old_document = fresh_document(tmp_path / "old")
    old_ref = weakref.ref(old_document)
    old_identity_token = object()
    current_document = fresh_document(tmp_path / "current")
    current_record = private_claim_for_test(current_document)
    manager_module._remove_ownership_if_current(
        id(current_document), old_ref, old_identity_token
    )
    assert private_ownership_record_for_test(current_document) is current_record


def test_issued_lease_returns_secret_once_only_for_exact_binding(
    tmp_path: Path,
) -> None:
    manager = test_manager(fresh_document(tmp_path))
    snapshot = manager.reload()
    lease = issue_valid_lease(manager, snapshot, ttl_seconds=10.0)
    assert consume_valid_lease(manager, lease, snapshot) == SYNTHETIC_SECRET
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.secret_lease_invalid",
    ):
        consume_valid_lease(manager, lease, snapshot)


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"expected_generation": 2}, "credential.secret_lease_generation_mismatch"),
        ({"account_ref": "other-account"}, "credential.secret_lease_binding_mismatch"),
        ({"project_ref": "other-project"}, "credential.secret_lease_binding_mismatch"),
        ({"key_id": "other-key"}, "credential.secret_lease_binding_mismatch"),
        (
            {"purpose": _SecretLeasePurposeV1.PROVIDER_PROBE},
            "credential.secret_lease_binding_mismatch",
        ),
    ],
)
def test_lease_rejects_cross_generation_or_cross_binding(
    tmp_path: Path, override: dict[str, object], code: str
) -> None:
    manager = test_manager(fresh_document(tmp_path))
    snapshot = manager.reload()
    lease = issue_valid_lease(manager, snapshot)
    with pytest.raises(GoogleAccountInventoryError, match=code):
        consume_valid_lease(manager, lease, snapshot, **override)


def test_existing_lease_survives_failed_reload_until_monotonic_expiry(
    tmp_path: Path,
) -> None:
    clock = FakeMonotonic()
    manager = test_manager(
        fresh_document(tmp_path / "first"),
        GoogleAccountInventoryError("credential.inventory_schema_invalid"),
        monotonic_clock=clock,
    )
    original_snapshot = manager.reload()
    issued = issue_valid_lease(manager, original_snapshot, ttl_seconds=10.0)
    later_issued = issue_valid_lease(manager, original_snapshot, ttl_seconds=10.0)
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_reload_failed",
    ):
        manager.reload()
    assert consume_valid_lease(manager, issued, original_snapshot) == SYNTHETIC_SECRET
    clock.advance(10.0)
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.secret_lease_expired",
    ):
        consume_valid_lease(manager, later_issued, original_snapshot)


def test_close_revokes_unconsumed_leases(tmp_path: Path) -> None:
    manager = test_manager(fresh_document(tmp_path))
    snapshot = manager.reload()
    lease = issue_valid_lease(manager, snapshot)
    manager.close()
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.secret_lease_revoked",
    ):
        consume_valid_lease(manager, lease, snapshot)


def test_expired_leases_are_swept_before_capacity_check(tmp_path: Path) -> None:
    clock = FakeMonotonic()
    manager = test_manager(fresh_document(tmp_path), monotonic_clock=clock)
    snapshot = manager.reload()
    leases = [issue_valid_lease(manager, snapshot) for _ in range(128)]
    clock.advance(30.0)
    replacement = issue_valid_lease(manager, snapshot)
    assert replacement not in leases
    assert len(manager._lease_records) == 1
    assert all(
        lease._terminal_state.value == "expired" and lease not in manager._lease_records
        for lease in leases
    )


def test_live_lease_capacity_is_fail_closed(tmp_path: Path) -> None:
    manager = test_manager(fresh_document(tmp_path))
    snapshot = manager.reload()
    leases = [issue_valid_lease(manager, snapshot) for _ in range(128)]
    assert len(leases) == 128
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.secret_lease_capacity_exhausted",
    ):
        issue_valid_lease(manager, snapshot)


def test_terminal_records_scrub_secret_and_repr(tmp_path: Path) -> None:
    clock = FakeMonotonic()
    manager = test_manager(fresh_document(tmp_path), monotonic_clock=clock)
    snapshot = manager.reload()
    consumed = issue_valid_lease(manager, snapshot)
    assert consume_valid_lease(manager, consumed, snapshot) == SYNTHETIC_SECRET
    assert consumed._terminal_state.value == "consumed"
    assert consumed not in manager._lease_records

    expired = issue_valid_lease(manager, snapshot)
    clock.advance(30.0)
    with pytest.raises(
        GoogleAccountInventoryError, match="credential.secret_lease_expired"
    ):
        consume_valid_lease(manager, expired, snapshot)
    assert expired._terminal_state.value == "expired"
    assert expired not in manager._lease_records

    swept = issue_valid_lease(manager, snapshot)
    clock.advance(30.0)
    issue_valid_lease(manager, snapshot)
    assert swept._terminal_state.value == "expired"
    assert swept not in manager._lease_records

    revoked = issue_valid_lease(manager, snapshot)
    manager.close()
    assert revoked._terminal_state.value == "revoked"
    assert revoked not in manager._lease_records


def test_swept_expired_lease_wins_before_binding_check(tmp_path: Path) -> None:
    clock = FakeMonotonic()
    manager = test_manager(fresh_document(tmp_path), monotonic_clock=clock)
    snapshot = manager.reload()
    lease = issue_valid_lease(manager, snapshot)
    clock.advance(30.0)
    issue_valid_lease(manager, snapshot)
    assert lease._terminal_state.value == "expired"
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.secret_lease_expired",
    ):
        consume_valid_lease(
            manager,
            lease,
            snapshot,
            account_ref="other-account",
            expected_generation=999,
        )


@pytest.mark.parametrize("ttl_seconds", [True, math.nan, math.inf, 0, -1, 60.1])
def test_invalid_ttl_is_rejected_without_secret_access(
    tmp_path: Path, ttl_seconds: object
) -> None:
    manager = test_manager(fresh_document(tmp_path))
    snapshot = manager.reload()
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.secret_lease_invalid",
    ):
        issue_valid_lease(manager, snapshot, ttl_seconds=ttl_seconds)  # type: ignore[arg-type]


def test_snapshot_status_lease_manager_and_errors_never_render_secret(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    manager = test_manager(fresh_document(tmp_path, secret=SYNTHETIC_SECRET))
    status = manager.reload()
    lease = issue_valid_lease(manager, status)
    internal_snapshot = manager._snapshot_for_internal_use()
    visible = (
        repr(status),
        str(status),
        repr(manager),
        str(manager),
        repr(lease),
        str(lease),
        repr(asdict(status)),
        repr(status.public_projection()),
        caplog.text,
    )
    assert all(SYNTHETIC_SECRET not in value for value in visible)
    private_record = manager._lease_records[lease]
    assert SYNTHETIC_SECRET not in repr(private_record)
    with pytest.raises(TypeError):
        pickle.dumps(internal_snapshot)
    with pytest.raises(TypeError):
        pickle.dumps(lease)
    with pytest.raises(TypeError):
        pickle.dumps(manager)
    with pytest.raises(TypeError):
        asdict(lease)


@pytest.mark.parametrize("operator_timestamp", [None, "", "x" * 65])
def test_operator_timestamp_must_be_bounded_serializable_string(
    tmp_path: Path, operator_timestamp: object
) -> None:
    manager = test_manager(
        fresh_document(tmp_path),
        operator_timestamp_utc=lambda: operator_timestamp,  # type: ignore[return-value]
    )
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_timestamp_invalid",
    ):
        manager.reload()
    assert manager.status().state is InventoryManagerStateV1.EMPTY


def test_wall_clock_changes_do_not_change_lease_expiry(tmp_path: Path) -> None:
    clock = FakeMonotonic()
    operator_times = iter(("2026-08-23T12:00:00Z", "2099-01-01T00:00:00Z"))
    manager = test_manager(
        fresh_document(tmp_path),
        fresh_document(tmp_path / "second"),
        monotonic_clock=clock,
        operator_timestamp_utc=lambda: next(operator_times),
    )
    first = manager.reload()
    lease = issue_valid_lease(manager, first, ttl_seconds=10.0)
    assert manager.reload().loaded_at_utc == "2099-01-01T00:00:00Z"
    assert consume_valid_lease(manager, lease, first) == SYNTHETIC_SECRET


def test_reload_and_snapshot_reader_never_observe_partial_generation(
    tmp_path: Path,
) -> None:
    second_load_entered = threading.Event()
    release_second_load = threading.Event()
    reader_started = threading.Event()
    reader_finished = threading.Event()
    first = fresh_document(tmp_path / "first")
    second = fresh_document(tmp_path / "second")
    manager = GoogleAccountInventoryManager._for_test_loader(
        blocking_sequence_loader(
            first, second_load_entered, release_second_load, second
        ),
        monotonic_clock=FakeMonotonic(),
        operator_timestamp_utc=lambda: "2026-08-23T12:00:00Z",
    )
    assert manager.reload().generation == 1
    reload_thread = threading.Thread(target=manager.reload)
    reload_thread.start()
    assert second_load_entered.wait(timeout=1)

    observed: list[object] = []
    reader = threading.Thread(
        target=lambda: (
            reader_started.set(),
            observed.append(manager.status()),
            reader_finished.set(),
        )
    )
    reader.start()
    assert reader_started.wait(timeout=1)
    assert not reader_finished.wait(timeout=0.05)
    release_second_load.set()
    reload_thread.join(timeout=1)
    reader.join(timeout=1)
    assert not reload_thread.is_alive()
    assert not reader.is_alive()
    assert [status.generation for status in observed] == [2]


def test_parallel_reloads_publish_strictly_increasing_generations(
    tmp_path: Path,
) -> None:
    manager = test_manager(
        fresh_document(tmp_path / "first"),
        fresh_document(tmp_path / "second"),
        fresh_document(tmp_path / "third"),
    )
    assert manager.reload().generation == 1
    results: list[int] = []
    errors: list[BaseException] = []

    def reload_once() -> None:
        try:
            results.append(manager.reload().generation)
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=reload_once) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=1)
    assert not errors
    assert sorted(results) == [2, 3]
    assert manager.status().generation == 3


@pytest.mark.parametrize("failure_kind", ["timestamp", "snapshot"])
def test_review_reload_failure_graph_after_source_consume_is_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
) -> None:
    first_document = fresh_document(tmp_path / "first")
    second_document = fresh_document(tmp_path / "second")
    clock = FakeMonotonic()
    operator_timestamps = iter(
        (
            "2026-08-23T12:00:00Z",
            "bad" if failure_kind == "timestamp" else "2026-08-23T12:00:00Z",
        )
    )
    manager = test_manager(
        first_document,
        second_document,
        monotonic_clock=clock,
        operator_timestamp_utc=lambda: next(operator_timestamps),
    )
    first_status = manager.reload()
    old_lease = issue_valid_lease(manager, first_status, ttl_seconds=10.0)
    expiring_old_lease = issue_valid_lease(manager, first_status, ttl_seconds=10.0)
    del first_document, second_document
    if failure_kind == "snapshot":

        def fail_snapshot(*args: object, **kwargs: object) -> object:
            raise RuntimeError("synthetic snapshot fault")

        monkeypatch.setattr(manager_module, "_build_snapshot", fail_snapshot)

    with pytest.raises(GoogleAccountInventoryError) as caught:
        manager.reload()

    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    _assert_reload_failure_graph_is_redacted(caught.value)
    assert manager._active.source is None
    assert manager._active.document is None
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_reload_failed|credential.inventory_timestamp_invalid",
    ):
        issue_valid_lease(manager, first_status)
    assert consume_valid_lease(manager, old_lease, first_status) == SYNTHETIC_SECRET
    clock.advance(10.0)
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.secret_lease_expired",
    ):
        consume_valid_lease(manager, expiring_old_lease, first_status)


ISSUE_BINDING_TYPE_CASES = [
    ("expected_generation", True, "credential.generation_conflict"),
    ("expected_generation", 1.0, "credential.generation_conflict"),
    ("expected_generation", None, "credential.generation_conflict"),
    ("expected_generation", [], "credential.generation_conflict"),
    ("expected_generation", {}, "credential.generation_conflict"),
    (
        "expected_generation",
        StringSubclass("1"),
        "credential.generation_conflict",
    ),
    ("expected_generation", ExplodingComparison(), "credential.generation_conflict"),
    ("expected_generation", 0, "credential.generation_conflict"),
    ("expected_generation", 2**63, "credential.generation_conflict"),
    ("account_ref", True, "credential.account_not_found"),
    ("account_ref", 1.0, "credential.account_not_found"),
    ("account_ref", None, "credential.account_not_found"),
    ("account_ref", [], "credential.account_not_found"),
    ("account_ref", {}, "credential.account_not_found"),
    (
        "account_ref",
        StringSubclass("google-account-01"),
        "credential.account_not_found",
    ),
    ("account_ref", ExplodingComparison(), "credential.account_not_found"),
    ("account_ref", "", "credential.account_not_found"),
    ("account_ref", 1, "credential.account_not_found"),
    ("project_ref", True, "credential.project_not_found"),
    ("project_ref", 1.0, "credential.project_not_found"),
    ("project_ref", None, "credential.project_not_found"),
    ("project_ref", [], "credential.project_not_found"),
    ("project_ref", {}, "credential.project_not_found"),
    (
        "project_ref",
        StringSubclass("the-hive-1"),
        "credential.project_not_found",
    ),
    ("project_ref", ExplodingComparison(), "credential.project_not_found"),
    ("project_ref", "", "credential.project_not_found"),
    ("project_ref", 1, "credential.project_not_found"),
    ("key_id", True, "credential.key_not_found"),
    ("key_id", 1.0, "credential.key_not_found"),
    ("key_id", None, "credential.key_not_found"),
    ("key_id", [], "credential.key_not_found"),
    ("key_id", {}, "credential.key_not_found"),
    ("key_id", StringSubclass("000654"), "credential.key_not_found"),
    ("key_id", ExplodingComparison(), "credential.key_not_found"),
    ("key_id", "", "credential.key_not_found"),
    ("key_id", 1, "credential.key_not_found"),
    ("purpose", True, "credential.secret_lease_invalid"),
    ("purpose", 1.0, "credential.secret_lease_invalid"),
    ("purpose", None, "credential.secret_lease_invalid"),
    ("purpose", [], "credential.secret_lease_invalid"),
    ("purpose", {}, "credential.secret_lease_invalid"),
    (
        "purpose",
        StringSubclass("provider_request"),
        "credential.secret_lease_invalid",
    ),
    ("purpose", ExplodingComparison(), "credential.secret_lease_invalid"),
    ("purpose", "", "credential.secret_lease_invalid"),
    ("purpose", 1, "credential.secret_lease_invalid"),
]


@pytest.mark.parametrize(("field", "value", "code"), ISSUE_BINDING_TYPE_CASES)
def test_review_issue_binding_types_fail_before_index_or_equality(
    tmp_path: Path, field: str, value: object, code: str
) -> None:
    manager = test_manager(fresh_document(tmp_path))
    status = manager.reload()
    arguments: dict[str, object] = {
        "expected_generation": status.generation,
        "account_ref": "google-account-01",
        "project_ref": "the-hive-1",
        "key_id": "000654",
        "purpose": _SecretLeasePurposeV1.PROVIDER_REQUEST,
    }
    arguments[field] = value
    with pytest.raises(GoogleAccountInventoryError, match=code):
        manager._issue_secret_lease(**arguments)  # type: ignore[arg-type]


CONSUME_BINDING_TYPE_CASES = [
    ("expected_generation", True, "credential.secret_lease_generation_mismatch"),
    ("expected_generation", 1.0, "credential.secret_lease_generation_mismatch"),
    ("expected_generation", None, "credential.secret_lease_generation_mismatch"),
    ("expected_generation", [], "credential.secret_lease_generation_mismatch"),
    ("expected_generation", {}, "credential.secret_lease_generation_mismatch"),
    (
        "expected_generation",
        StringSubclass("1"),
        "credential.secret_lease_generation_mismatch",
    ),
    (
        "expected_generation",
        ExplodingComparison(),
        "credential.secret_lease_generation_mismatch",
    ),
    ("expected_generation", 0, "credential.secret_lease_generation_mismatch"),
    ("expected_generation", 2**63, "credential.secret_lease_generation_mismatch"),
    ("account_ref", True, "credential.secret_lease_binding_mismatch"),
    ("account_ref", 1.0, "credential.secret_lease_binding_mismatch"),
    ("account_ref", None, "credential.secret_lease_binding_mismatch"),
    ("account_ref", [], "credential.secret_lease_binding_mismatch"),
    ("account_ref", {}, "credential.secret_lease_binding_mismatch"),
    (
        "account_ref",
        StringSubclass("google-account-01"),
        "credential.secret_lease_binding_mismatch",
    ),
    (
        "account_ref",
        ExplodingComparison(),
        "credential.secret_lease_binding_mismatch",
    ),
    ("account_ref", "", "credential.secret_lease_binding_mismatch"),
    ("account_ref", 1, "credential.secret_lease_binding_mismatch"),
    ("project_ref", True, "credential.secret_lease_binding_mismatch"),
    ("project_ref", 1.0, "credential.secret_lease_binding_mismatch"),
    ("project_ref", None, "credential.secret_lease_binding_mismatch"),
    ("project_ref", [], "credential.secret_lease_binding_mismatch"),
    ("project_ref", {}, "credential.secret_lease_binding_mismatch"),
    (
        "project_ref",
        StringSubclass("the-hive-1"),
        "credential.secret_lease_binding_mismatch",
    ),
    (
        "project_ref",
        ExplodingComparison(),
        "credential.secret_lease_binding_mismatch",
    ),
    ("project_ref", "", "credential.secret_lease_binding_mismatch"),
    ("project_ref", 1, "credential.secret_lease_binding_mismatch"),
    ("key_id", True, "credential.secret_lease_binding_mismatch"),
    ("key_id", 1.0, "credential.secret_lease_binding_mismatch"),
    ("key_id", None, "credential.secret_lease_binding_mismatch"),
    ("key_id", [], "credential.secret_lease_binding_mismatch"),
    ("key_id", {}, "credential.secret_lease_binding_mismatch"),
    ("key_id", StringSubclass("000654"), "credential.secret_lease_binding_mismatch"),
    ("key_id", ExplodingComparison(), "credential.secret_lease_binding_mismatch"),
    ("key_id", "", "credential.secret_lease_binding_mismatch"),
    ("key_id", 1, "credential.secret_lease_binding_mismatch"),
    ("purpose", True, "credential.secret_lease_binding_mismatch"),
    ("purpose", 1.0, "credential.secret_lease_binding_mismatch"),
    ("purpose", None, "credential.secret_lease_binding_mismatch"),
    ("purpose", [], "credential.secret_lease_binding_mismatch"),
    ("purpose", {}, "credential.secret_lease_binding_mismatch"),
    (
        "purpose",
        StringSubclass("provider_request"),
        "credential.secret_lease_binding_mismatch",
    ),
    ("purpose", ExplodingComparison(), "credential.secret_lease_binding_mismatch"),
    ("purpose", "", "credential.secret_lease_binding_mismatch"),
    ("purpose", 1, "credential.secret_lease_binding_mismatch"),
]


@pytest.mark.parametrize(("field", "value", "code"), CONSUME_BINDING_TYPE_CASES)
def test_review_consume_binding_types_fail_before_equality_or_clock(
    tmp_path: Path, field: str, value: object, code: str
) -> None:
    manager = test_manager(fresh_document(tmp_path))
    status = manager.reload()
    lease = issue_valid_lease(manager, status, ttl_seconds=10.0)
    arguments: dict[str, object] = {
        "expected_generation": status.generation,
        "account_ref": "google-account-01",
        "project_ref": "the-hive-1",
        "key_id": "000654",
        "purpose": _SecretLeasePurposeV1.PROVIDER_REQUEST,
    }
    arguments[field] = value
    with pytest.raises(GoogleAccountInventoryError, match=code):
        manager._consume_secret_lease(lease, **arguments)  # type: ignore[arg-type]


def test_review_public_contract_hides_snapshot_and_identifiers(
    tmp_path: Path,
) -> None:
    manager = test_manager(fresh_document(tmp_path))
    status = manager.reload()
    internal_snapshot = manager._snapshot_for_internal_use()

    assert status.generation == 1
    assert internal_snapshot.by_hive_slot[1].ref == "the-hive-1"
    assert not hasattr(manager, "snapshot")
    assert set(status.public_projection()) == {
        "state",
        "new_work_allowed",
        "generation",
        "loaded_at_utc",
        "source_type",
        "content_fingerprint",
        "account_count",
        "billing_account_count",
        "project_count",
        "active_project_count",
    }
    visible = (
        repr(status),
        str(status),
        repr(status.public_projection()),
        repr(asdict(status)),
        repr(vars(status)),
        repr(status.public_projection()),
    )
    assert all(
        marker not in value
        for marker in (
            "google-account-01",
            "account@example.test",
            "000123",
            "billing-01",
            "000456",
            "the-hive-1",
            "000789",
            "000654",
        )
        for value in visible
    )
    assert pickle.dumps(status)
    assert pickle.dumps(status.public_projection())
    assert status == status
    assert hash(status) == hash(status)


def test_review_reload_failure_is_source_free_but_old_lease_survives(
    tmp_path: Path,
) -> None:
    clock = FakeMonotonic()
    manager = test_manager(
        fresh_document(tmp_path / "first"),
        GoogleAccountInventoryError("credential.inventory_schema_invalid"),
        monotonic_clock=clock,
    )
    first_status = manager.reload()
    old_snapshot = manager._snapshot_for_internal_use()
    lease = issue_valid_lease(manager, first_status, ttl_seconds=10.0)

    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_reload_failed",
    ):
        manager.reload()

    assert manager.status().state is InventoryManagerStateV1.RELOAD_BLOCKED
    assert manager._active.source is None
    assert manager._active.document is None
    assert manager._snapshot_for_internal_use() is old_snapshot
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_reload_failed",
    ):
        issue_valid_lease(manager, first_status)
    assert consume_valid_lease(manager, lease, first_status) == SYNTHETIC_SECRET


def test_review_close_is_source_free_and_revokes_old_lease(
    tmp_path: Path,
) -> None:
    manager = test_manager(fresh_document(tmp_path))
    status = manager.reload()
    old_snapshot = manager._snapshot_for_internal_use()
    lease = issue_valid_lease(manager, status)

    manager.close()

    assert manager._active.source is None
    assert manager._active.document is None
    assert manager._active.snapshot is old_snapshot
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_manager_closed",
    ):
        manager._snapshot_for_internal_use()
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.secret_lease_revoked",
    ):
        consume_valid_lease(manager, lease, status)


def test_review_ownership_failure_blocks_existing_manager_source_free(
    tmp_path: Path,
) -> None:
    document = fresh_document(tmp_path / "owned")
    first = test_manager_returning(document)
    first_status = first.reload()
    lease = issue_valid_lease(first, first_status, ttl_seconds=10.0)

    second = test_manager(fresh_document(tmp_path / "second"), document)
    second.reload()
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_document_foreign",
    ):
        second.reload()

    assert second.status().state is InventoryManagerStateV1.RELOAD_BLOCKED
    assert second._active.source is None
    assert second._active.document is None
    assert consume_valid_lease(first, lease, first_status) == SYNTHETIC_SECRET


def test_review_many_expired_strong_handles_keep_only_active_records(
    tmp_path: Path,
) -> None:
    clock = FakeMonotonic()
    manager = test_manager(fresh_document(tmp_path), monotonic_clock=clock)
    status = manager.reload()
    old_leases: list[object] = []

    for _ in range(4):
        old_leases.extend(issue_valid_lease(manager, status) for _ in range(128))
        clock.advance(30.0)
        issue_valid_lease(manager, status)

    assert len(manager._lease_records) <= 128
    assert all(lease._terminal_state.value == "expired" for lease in old_leases)
    assert all(lease not in manager._lease_records for lease in old_leases)
    for lease in old_leases[::64]:
        with pytest.raises(
            GoogleAccountInventoryError,
            match="credential.secret_lease_expired",
        ):
            consume_valid_lease(manager, lease, status)


def test_review_issued_record_is_non_dataclass_nonserializable_and_redacted(
    tmp_path: Path,
) -> None:
    manager = test_manager(fresh_document(tmp_path))
    status = manager.reload()
    lease = issue_valid_lease(manager, status)
    record = manager._lease_records[lease]

    assert not is_dataclass(record)
    with pytest.raises(TypeError):
        asdict(record)
    with pytest.raises(TypeError):
        pickle.dumps(record)
    assert all(
        marker not in repr(record)
        for marker in (
            SYNTHETIC_SECRET,
            "google-account-01",
            "the-hive-1",
            "000654",
        )
    )


@pytest.mark.parametrize(
    "clock_value", [True, "bad", None, math.nan, math.inf, -math.inf]
)
def test_review_invalid_issue_clock_uses_fixed_code(
    tmp_path: Path, clock_value: object
) -> None:
    manager = test_manager(
        fresh_document(tmp_path),
        monotonic_clock=lambda: clock_value,  # type: ignore[return-value]
    )
    status = manager.reload()
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_clock_invalid",
    ):
        issue_valid_lease(manager, status)


def test_review_backward_consume_clock_uses_fixed_code(tmp_path: Path) -> None:
    clock = FakeMonotonic()
    manager = test_manager(fresh_document(tmp_path), monotonic_clock=clock)
    status = manager.reload()
    lease = issue_valid_lease(manager, status)
    clock.seconds = -1.0

    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_clock_invalid",
    ):
        consume_valid_lease(manager, lease, status)


@pytest.mark.parametrize("clock_value", [True, "bad", None, math.nan, math.inf])
def test_review_invalid_consume_clock_uses_fixed_code(
    tmp_path: Path, clock_value: object
) -> None:
    clock = FakeMonotonic()
    manager = test_manager(fresh_document(tmp_path), monotonic_clock=clock)
    status = manager.reload()
    lease = issue_valid_lease(manager, status)
    clock_value_holder = [clock_value]
    manager._monotonic_clock = lambda: clock_value_holder[0]

    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_clock_invalid",
    ):
        consume_valid_lease(manager, lease, status)


@pytest.mark.parametrize(
    "operator_timestamp",
    [
        None,
        "2026-08-23T12:00:00+00:00",
        "2026-08-23T12:00:00.000Z",
        "2026-08-23 12:00:00Z",
        "2026-02-30T12:00:00Z",
        "2026-8-23T12:00:00Z",
        "2026-08-23T12:00:00",
        "2026-08-23T12:00:00\x00Z",
    ],
)
def test_review_operator_timestamp_is_strict_utc_z(
    tmp_path: Path, operator_timestamp: object
) -> None:
    manager = test_manager(
        fresh_document(tmp_path),
        operator_timestamp_utc=lambda: operator_timestamp,  # type: ignore[return-value]
    )
    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_timestamp_invalid",
    ):
        manager.reload()


def test_review_key_binding_requires_two_nonempty_equal_strings(tmp_path: Path) -> None:
    manager = test_manager(fresh_document(tmp_path, key_id=None))
    status = manager.reload()
    for request_key in (None, "", 123, "000654"):
        with pytest.raises(
            GoogleAccountInventoryError,
            match="credential.key_not_found",
        ):
            issue_valid_lease(manager, status, key_id=request_key)  # type: ignore[arg-type]


def test_review_generation_limit_is_checked_before_loader_and_source_consume(
    tmp_path: Path,
) -> None:
    load_count = 0

    def load() -> object:
        nonlocal load_count
        load_count += 1
        return fresh_document(tmp_path / f"load-{load_count}")

    manager = GoogleAccountInventoryManager._for_test_loader(
        load,
        monotonic_clock=FakeMonotonic(),
        operator_timestamp_utc=lambda: "2026-08-23T12:00:00Z",
    )
    manager._generation = 2**63 - 1

    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_generation_exhausted",
    ):
        manager.reload()

    assert load_count == 0
    assert manager.status().state is InventoryManagerStateV1.EMPTY


def test_review_generation_limit_blocks_active_manager_source_free(
    tmp_path: Path,
) -> None:
    load_count = 0
    first = fresh_document(tmp_path / "first")
    second = fresh_document(tmp_path / "second")

    def load() -> object:
        nonlocal load_count
        load_count += 1
        return first if load_count == 1 else second

    manager = GoogleAccountInventoryManager._for_test_loader(
        load,
        monotonic_clock=FakeMonotonic(),
        operator_timestamp_utc=lambda: "2026-08-23T12:00:00Z",
    )
    status = manager.reload()
    old_snapshot = manager._snapshot_for_internal_use()
    manager._generation = 2**63 - 1

    with pytest.raises(
        GoogleAccountInventoryError,
        match="credential.inventory_generation_exhausted",
    ):
        manager.reload()

    assert load_count == 1
    assert manager.status().state is InventoryManagerStateV1.RELOAD_BLOCKED
    assert manager._active.source is None
    assert manager._active.document is None
    assert manager._active.snapshot is old_snapshot
    assert manager.status().generation == status.generation


def test_review_parallel_issue_consume_close_and_gc_stay_bounded(
    tmp_path: Path,
) -> None:
    manager = test_manager(fresh_document(tmp_path))
    status = manager.reload()
    barrier = threading.Barrier(3)
    errors: list[BaseException] = []
    leases: list[object] = []
    leases_lock = threading.Lock()

    def issue_and_consume() -> None:
        try:
            barrier.wait(timeout=1)
            for _ in range(32):
                try:
                    lease = issue_valid_lease(manager, status, ttl_seconds=60.0)
                except GoogleAccountInventoryError:
                    continue
                with leases_lock:
                    leases.append(lease)
                try:
                    consume_valid_lease(manager, lease, status)
                except GoogleAccountInventoryError:
                    pass
                gc.collect()
        except BaseException as error:
            errors.append(error)

    def close_manager() -> None:
        try:
            barrier.wait(timeout=1)
            manager.close()
            gc.collect()
        except BaseException as error:
            errors.append(error)

    threads = [
        threading.Thread(target=issue_and_consume),
        threading.Thread(target=issue_and_consume),
        threading.Thread(target=close_manager),
    ]
    try:
        for thread in threads:
            thread.start()
    finally:
        for thread in threads:
            thread.join(timeout=1)

    assert not errors
    assert all(not isinstance(error, Exception) for error in errors)
    assert len(manager._lease_records) <= 128
    assert SYNTHETIC_SECRET not in repr(manager)
    assert all(SYNTHETIC_SECRET not in repr(lease) for lease in leases)
