from __future__ import annotations

import copy
from dataclasses import asdict
import os
from pathlib import Path
import pickle
import socket
import subprocess
import sys

import pytest
import yaml

import codex_master.google_account_inventory as inventory
from codex_master.google_account_inventory import (
    GoogleAccountInventoryDocumentV1,
    GoogleAccountInventoryError,
    GoogleAccountInventoryLoader,
)


_SYNTHETIC_SECRET = "synthetic-secret-not-for-output"


def test_public_loader_uses_only_canonical_inventory_path() -> None:
    loader = GoogleAccountInventoryLoader()
    assert loader._path == inventory.DEFAULT_GOOGLE_ACCOUNT_INVENTORY_PATH


def test_frozen_index_iteration_returns_stable_keys() -> None:
    index = inventory._FrozenIndex({"account-one": 1, "account-two": 2})
    assert tuple(iter(index)) == ("account-one", "account-two")


def test_frozen_index_length_matches_copied_mapping() -> None:
    source = {"account-one": 1}
    index = inventory._FrozenIndex(source)
    source["account-two"] = 2
    assert len(index) == 1


def test_private_secret_source_rejects_serializing() -> None:
    source = inventory._GoogleAccountInventorySecretSource({"project-one": "synthetic-secret"})
    with pytest.raises(TypeError, match="private inventory secret source is not serializable"):
        pickle.dumps(source)


def _write_private_inventory(root: Path, content: str) -> Path:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    path = root / "api-token.yaml"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def _inventory_document(*, secret: object = _SYNTHETIC_SECRET) -> dict[str, object]:
    return {
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
                        "key_id": "000654",
                        "key_uid": "000321",
                        "secret": secret,
                    }
                ],
            }
        ],
    }


def _write_document(root: Path, document: object) -> Path:
    return _write_private_inventory(root, yaml.safe_dump(document, sort_keys=False))


def _load_test_document(path: Path) -> GoogleAccountInventoryDocumentV1:
    return GoogleAccountInventoryLoader._for_test_path(path).load()


def _assert_inventory_error(path: Path) -> GoogleAccountInventoryError:
    with pytest.raises(GoogleAccountInventoryError) as raised:
        _load_test_document(path)
    return raised.value


def _run_with_large_integer_constructor_guard(
    path: Path,
    *,
    disable_decimal_digit_limit: bool,
    reject_integer_constructor_result: bool = False,
) -> subprocess.CompletedProcess[str]:
    source_root = str(Path(inventory.__file__).resolve().parents[1])
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        filter(None, (source_root, environment.get("PYTHONPATH")))
    )
    script = """\
import builtins
from pathlib import Path
import sys

from codex_master.google_account_inventory import GoogleAccountInventoryError
from codex_master.google_account_inventory import GoogleAccountInventoryLoader
from codex_master.google_account_inventory import _StrictInventoryYamlLoader

if sys.argv[2] == "disabled":
    sys.set_int_max_str_digits(0)
original_int = int

if sys.argv[3] == "reject-integer-result":
    yaml_int_tag = "tag:yaml.org,2002:int"
    constructors = dict(_StrictInventoryYamlLoader.yaml_constructors)
    original_yaml_int_constructor = constructors[yaml_int_tag]

    def guarded_yaml_int_constructor(loader, node):
        value = original_yaml_int_constructor(loader, node)
        if type(value) is original_int:
            raise AssertionError("YAML integer constructor returned int")
        return value

    constructors[yaml_int_tag] = guarded_yaml_int_constructor
    _StrictInventoryYamlLoader.yaml_constructors = constructors

def guarded_int(value, *args, **kwargs):
    if type(value) is str and len(value) > 1024:
        raise AssertionError("large YAML integer constructor ran")
    return original_int(value, *args, **kwargs)

builtins.int = guarded_int
try:
    GoogleAccountInventoryLoader._for_test_path(Path(sys.argv[1])).load()
except GoogleAccountInventoryError as error:
    outcome = 0 if error.code == "credential.inventory_schema_invalid" else 2
else:
    outcome = 3
finally:
    builtins.int = original_int

if outcome == 0:
    print("credential.inventory_schema_invalid")
raise SystemExit(outcome)
"""
    return subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(path),
            "disabled" if disable_decimal_digit_limit else "default",
            (
                "reject-integer-result"
                if reject_integer_constructor_result
                else "allow-integer-result"
            ),
        ],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
        timeout=10,
    )


def test_load_builds_private_immutable_document_and_indices(tmp_path: Path) -> None:
    path = _write_private_inventory(
        tmp_path / "inventory",
        f"""\
schema_version: 1
google_accounts:
  - ref: google-account-01
    login_email: account@example.test
    recovery_email: null
    label: Test account
    subject_id: "000123"
    billing_accounts:
      - ref: billing-01
        billing_account_id: "000456"
        label: Trial
    projects:
      - ref: the-hive-1
        billing_account_ref: billing-01
        status: active
        project_id: "000789"
        project_number: "000987"
        key_id: "000654"
        key_uid: "000321"
        secret: {_SYNTHETIC_SECRET}
""",
    )

    document = _load_test_document(path)

    assert document.schema_version == 1
    assert [account.ref for account in document.accounts] == ["google-account-01"]
    assert document.by_subject_id["000123"].ref == "google-account-01"
    assert document.by_billing_account_id["000456"].ref == "billing-01"
    assert document.by_project_id["000789"].project_number == "000987"
    assert document.by_key_id["000654"].key_uid == "000321"
    assert document.by_hive_slot[1].ref == "the-hive-1"
    assert document.content_fingerprint.startswith("sha256:")

    for value in (
        repr(document),
        repr(asdict(document)),
        repr(document.public_projection()),
    ):
        assert _SYNTHETIC_SECRET not in value

    try:
        document.by_ref["different"] = document.accounts[0]  # type: ignore[index]
    except TypeError:
        pass
    else:
        raise AssertionError("snapshot index accepted mutation")


@pytest.mark.parametrize(
    ("change", "expected_code"),
    [
        (
            lambda document: document.__setitem__("unexpected", None),
            "credential.inventory_schema_invalid",
        ),
        (
            lambda document: document["google_accounts"][0].__setitem__(
                "unexpected", None
            ),
            "credential.inventory_schema_invalid",
        ),
        (
            lambda document: document["google_accounts"][0]["projects"][0].__setitem__(
                "unexpected", None
            ),
            "credential.inventory_schema_invalid",
        ),
        (
            lambda document: document["google_accounts"][0]["billing_accounts"][
                0
            ].__setitem__("unexpected", None),
            "credential.inventory_schema_invalid",
        ),
        (
            lambda document: document["google_accounts"][0]["projects"][0].__setitem__(
                "status", "unknown"
            ),
            "credential.inventory_schema_invalid",
        ),
        (
            lambda document: document["google_accounts"][0]["projects"][0].__setitem__(
                "secret", None
            ),
            "credential.inventory_schema_invalid",
        ),
        (
            lambda document: document["google_accounts"][0]["projects"][0].__setitem__(
                "secret", ""
            ),
            "credential.inventory_schema_invalid",
        ),
    ],
)
def test_schema_rejects_unknown_fields_invalid_status_and_active_without_secret(
    tmp_path: Path, change: object, expected_code: str
) -> None:
    document = _inventory_document()
    change(document)  # type: ignore[operator]

    error = _assert_inventory_error(_write_document(tmp_path / "inventory", document))

    assert error.code == expected_code
    assert _SYNTHETIC_SECRET not in repr(error)


@pytest.mark.parametrize(
    "status",
    ["blocked", "delete_planned", "delete_requested", "restore_pending", "deleted"],
)
def test_nonactive_project_statuses_require_null_secret(
    tmp_path: Path, status: str
) -> None:
    document = _inventory_document(secret=None)
    document["google_accounts"][0]["projects"][0]["status"] = status  # type: ignore[index]

    document = _load_test_document(_write_document(tmp_path / "inventory", document))

    assert document.accounts[0].projects[0].status == status


def test_nonactive_project_with_secret_is_rejected_without_secret_leak(
    tmp_path: Path,
) -> None:
    document = _inventory_document()
    document["google_accounts"][0]["projects"][0]["status"] = "blocked"  # type: ignore[index]

    error = _assert_inventory_error(_write_document(tmp_path / "inventory", document))

    assert error.code == "credential.inventory_schema_invalid"
    assert _SYNTHETIC_SECRET not in repr(error)


def test_schema_preserves_numeric_looking_external_ids_as_strings(
    tmp_path: Path,
) -> None:
    document = _load_test_document(
        _write_document(tmp_path / "inventory", _inventory_document())
    )

    project = document.accounts[0].projects[0]
    assert document.accounts[0].subject_id == "000123"
    assert project.project_id == "000789"
    assert project.project_number == "000987"
    assert project.key_id == "000654"
    assert project.key_uid == "000321"


@pytest.mark.parametrize(
    "field",
    [
        "subject_id",
        "billing_account_id",
        "project_id",
        "project_number",
        "key_id",
        "key_uid",
    ],
)
def test_schema_rejects_nonstring_external_ids(tmp_path: Path, field: str) -> None:
    document = _inventory_document()
    if field == "subject_id":
        document["google_accounts"][0][field] = 123  # type: ignore[index]
    elif field == "billing_account_id":
        document["google_accounts"][0]["billing_accounts"][0][field] = 456  # type: ignore[index]
    else:
        document["google_accounts"][0]["projects"][0][field] = 789  # type: ignore[index]

    assert (
        _assert_inventory_error(_write_document(tmp_path / "inventory", document)).code
        == "credential.inventory_schema_invalid"
    )


def test_schema_enforces_four_billing_accounts_without_ten_project_ceiling(
    tmp_path: Path,
) -> None:
    within_limit = _inventory_document()
    billing_accounts = within_limit["google_accounts"][0]["billing_accounts"]  # type: ignore[index]
    projects = within_limit["google_accounts"][0]["projects"]  # type: ignore[index]
    for number in range(2, 5):
        billing_accounts.append(  # type: ignore[union-attr]
            {
                "ref": f"billing-{number:02d}",
                "billing_account_id": f"billing-id-{number}",
                "label": None,
            }
        )
    for number in range(2, 11):
        projects.append(  # type: ignore[union-attr]
            {
                "ref": f"the-hive-{number}",
                "billing_account_ref": None,
                "status": "blocked",
                "project_id": f"project-{number}",
                "project_number": f"number-{number}",
                "key_id": f"key-{number}",
                "key_uid": f"key-uid-{number}",
                "secret": None,
            }
        )

    document = _load_test_document(
        _write_document(tmp_path / "within-limit", within_limit)
    )
    assert len(document.accounts[0].billing_accounts) == 4
    assert len(document.accounts[0].projects) == 10

    over_billing = copy.deepcopy(within_limit)
    over_billing["google_accounts"][0]["billing_accounts"].append(  # type: ignore[index]
        {"ref": "billing-05", "billing_account_id": "billing-id-5", "label": None}
    )
    assert (
        _assert_inventory_error(
            _write_document(tmp_path / "over-billing", over_billing)
        ).code
        == "credential.inventory_schema_invalid"
    )

    eleven_projects = copy.deepcopy(within_limit)
    eleven_projects["google_accounts"][0]["projects"].append(  # type: ignore[index]
        {
            "ref": "the-hive-11",
            "billing_account_ref": None,
            "status": "blocked",
            "project_id": "project-11",
            "project_number": "number-11",
            "key_id": "key-11",
            "key_uid": "key-uid-11",
            "secret": None,
        }
    )
    document = _load_test_document(
        _write_document(tmp_path / "eleven-projects", eleven_projects)
    )
    assert len(document.accounts[0].projects) == 11


@pytest.mark.parametrize(
    ("field", "expected_code"),
    [
        ("ref", "credential.account_duplicate"),
        ("login_email", "credential.login_duplicate"),
        ("subject_id", "credential.subject_duplicate"),
        ("billing_account_id", "credential.billing_duplicate"),
        ("project_id", "credential.project_duplicate"),
        ("project_number", "credential.project_duplicate"),
        ("key_id", "credential.key_duplicate"),
        ("key_uid", "credential.key_duplicate"),
    ],
)
def test_duplicate_global_identity_has_specific_code(
    tmp_path: Path, field: str, expected_code: str
) -> None:
    document = _inventory_document()
    duplicated = _inventory_document()
    duplicated["google_accounts"][0]["ref"] = "google-account-02"  # type: ignore[index]
    duplicated["google_accounts"][0]["login_email"] = "second@example.test"  # type: ignore[index]
    duplicated["google_accounts"][0]["subject_id"] = "000124"  # type: ignore[index]
    duplicated["google_accounts"][0]["billing_accounts"][0]["ref"] = "billing-02"  # type: ignore[index]
    duplicated["google_accounts"][0]["billing_accounts"][0]["billing_account_id"] = (
        "000457"  # type: ignore[index]
    )
    duplicated["google_accounts"][0]["projects"][0]["ref"] = "the-hive-2"  # type: ignore[index]
    duplicated["google_accounts"][0]["projects"][0]["billing_account_ref"] = (
        "billing-02"  # type: ignore[index]
    )
    duplicated["google_accounts"][0]["projects"][0]["project_id"] = "000790"  # type: ignore[index]
    duplicated["google_accounts"][0]["projects"][0]["project_number"] = "000988"  # type: ignore[index]
    duplicated["google_accounts"][0]["projects"][0]["key_id"] = "000655"  # type: ignore[index]
    duplicated["google_accounts"][0]["projects"][0]["key_uid"] = "000322"  # type: ignore[index]
    if field == "ref":
        duplicated["google_accounts"][0]["ref"] = "google-account-01"  # type: ignore[index]
    elif field == "login_email":
        duplicated["google_accounts"][0]["login_email"] = "account@example.test"  # type: ignore[index]
    elif field == "subject_id":
        duplicated["google_accounts"][0]["subject_id"] = "000123"  # type: ignore[index]
    elif field == "billing_account_id":
        duplicated["google_accounts"][0]["billing_accounts"][0][
            "billing_account_id"
        ] = "000456"  # type: ignore[index]
    elif field == "project_id":
        duplicated["google_accounts"][0]["projects"][0]["project_id"] = "000789"  # type: ignore[index]
    elif field == "project_number":
        duplicated["google_accounts"][0]["projects"][0]["project_number"] = "000987"  # type: ignore[index]
    elif field == "key_id":
        duplicated["google_accounts"][0]["projects"][0]["key_id"] = "000654"  # type: ignore[index]
    elif field == "key_uid":
        duplicated["google_accounts"][0]["projects"][0]["key_uid"] = "000321"  # type: ignore[index]
    document["google_accounts"].append(duplicated["google_accounts"][0])  # type: ignore[index]

    error = _assert_inventory_error(_write_document(tmp_path / "inventory", document))

    assert error.code == expected_code


def test_duplicate_hive_slot_is_rejected_even_when_ref_spelling_differs(
    tmp_path: Path,
) -> None:
    document = _inventory_document()
    other = dict(document["google_accounts"][0]["projects"][0])  # type: ignore[index]
    other["ref"] = "the-hive-01"
    other["project_id"] = "other-project"
    other["project_number"] = "other-number"
    other["key_id"] = "other-key"
    other["key_uid"] = "other-key-uid"
    document["google_accounts"][0]["projects"].append(other)  # type: ignore[index]

    error = _assert_inventory_error(_write_document(tmp_path / "inventory", document))

    assert error.code == "credential.project_duplicate"


def test_project_billing_reference_must_belong_to_same_account(tmp_path: Path) -> None:
    document = _inventory_document()
    document["google_accounts"][0]["projects"][0]["billing_account_ref"] = (
        "foreign-billing"  # type: ignore[index]
    )

    error = _assert_inventory_error(_write_document(tmp_path / "inventory", document))

    assert error.code == "credential.billing_reference_foreign"


@pytest.mark.parametrize("kind", ["file", "parent"])
def test_symlinked_inventory_path_or_parent_is_rejected(
    tmp_path: Path, kind: str
) -> None:
    target = _write_document(tmp_path / "target", _inventory_document())
    if kind == "file":
        path = tmp_path / "api-token.yaml"
        path.symlink_to(target)
    else:
        parent = tmp_path / "linked-parent"
        parent.symlink_to(target.parent, target_is_directory=True)
        path = parent / "api-token.yaml"

    error = _assert_inventory_error(path)

    assert error.code == "credential.inventory_permissions"


def test_nonprivate_mode_owner_or_hardlinked_file_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_document(tmp_path / "inventory", _inventory_document())
    path.chmod(0o644)
    assert _assert_inventory_error(path).code == "credential.inventory_permissions"

    path.chmod(0o600)
    real_geteuid = os.geteuid
    monkeypatch.setattr(inventory.os, "geteuid", lambda: real_geteuid() + 1)
    assert _assert_inventory_error(path).code == "credential.inventory_permissions"


def test_hardlinked_inventory_file_is_rejected(tmp_path: Path) -> None:
    path = _write_document(tmp_path / "inventory", _inventory_document())
    os.link(path, path.with_name("extra-link"))

    assert _assert_inventory_error(path).code == "credential.inventory_permissions"


def test_owner_readonly_direct_parent_matches_production_0755(tmp_path: Path) -> None:
    path = _write_document(tmp_path / "inventory", _inventory_document())
    path.parent.chmod(0o755)

    assert _load_test_document(path).schema_version == 1

    path.parent.chmod(0o775)
    assert _assert_inventory_error(path).code == "credential.inventory_permissions"


def test_rejects_oversize_invalid_utf8_and_nul_before_yaml_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oversize = _write_document(tmp_path / "oversize", _inventory_document())
    monkeypatch.setattr(inventory, "MAX_INVENTORY_BYTES", 8)
    assert _assert_inventory_error(oversize).code == "credential.inventory_unavailable"

    invalid_utf8 = _write_private_inventory(tmp_path / "invalid-utf8", "placeholder")
    invalid_utf8.write_bytes(b"\xff")
    assert (
        _assert_inventory_error(invalid_utf8).code == "credential.inventory_unavailable"
    )

    nul = _write_private_inventory(tmp_path / "nul", "placeholder")
    nul.write_bytes(b"schema_version: 1\x00")
    assert _assert_inventory_error(nul).code == "credential.inventory_unavailable"


def test_post_read_file_identity_change_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_document(tmp_path / "inventory", _inventory_document())
    real_read = inventory.os.read
    changed = False

    def mutate_after_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        value = real_read(descriptor, size)
        if not changed:
            changed = True
            replacement = path.with_name("replacement.yaml")
            replacement.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            replacement.chmod(0o600)
            replacement.replace(path)
        return value

    monkeypatch.setattr(inventory.os, "read", mutate_after_read)

    assert _assert_inventory_error(path).code == "credential.inventory_unavailable"


def test_redacted_fingerprint_and_order_ignore_yaml_order_and_secret_value(
    tmp_path: Path,
) -> None:
    first = _inventory_document(secret="synthetic-first-secret")
    first["google_accounts"].append(  # type: ignore[index]
        {
            **first["google_accounts"][0],  # type: ignore[index]
            "ref": "google-account-02",
            "login_email": "second@example.test",
            "subject_id": "000124",
            "billing_accounts": [],
            "projects": [],
        }
    )
    second = copy.deepcopy(first)
    second["google_accounts"] = list(reversed(second["google_accounts"]))  # type: ignore[index]
    second["google_accounts"][1]["projects"][0]["secret"] = "synthetic-second-secret"  # type: ignore[index]

    first_document = _load_test_document(_write_document(tmp_path / "first", first))
    second_document = _load_test_document(_write_document(tmp_path / "second", second))

    assert [account.ref for account in second_document.accounts] == [
        "google-account-01",
        "google-account-02",
    ]
    assert second_document.content_fingerprint == first_document.content_fingerprint
    assert "synthetic-first-secret" not in repr(second_document)
    assert "synthetic-second-secret" not in repr(second_document.public_projection())


def test_private_test_factory_never_uses_environment_network_or_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_document(tmp_path / "inventory", _inventory_document())
    calls = 0

    def forbidden_network(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("network access")

    monkeypatch.setenv("CODEX_MASTER_API_TOKEN_PATH", "/does/not/exist")
    monkeypatch.setattr(socket, "create_connection", forbidden_network)

    document = _load_test_document(path)

    assert document.accounts[0].ref == "google-account-01"
    assert calls == 0


def test_public_loader_rejects_arbitrary_credential_paths(tmp_path: Path) -> None:
    path = _write_document(tmp_path / "inventory", _inventory_document())

    with pytest.raises(TypeError):
        GoogleAccountInventoryLoader(path)  # type: ignore[call-arg]


def test_document_is_not_runtime_snapshot_and_omits_secret_from_value_protocols(
    tmp_path: Path,
) -> None:
    first = _inventory_document(secret="first-synthetic-secret")
    second = _inventory_document(secret="second-synthetic-secret")
    first_document = _load_test_document(_write_document(tmp_path / "first", first))
    second_document = _load_test_document(_write_document(tmp_path / "second", second))

    assert type(first_document).__name__ == "GoogleAccountInventoryDocumentV1"
    assert first_document == second_document
    assert hash(first_document) == hash(second_document)
    for value in (
        repr(first_document),
        str(first_document),
        repr(asdict(first_document)),
        repr(first_document.public_projection()),
    ):
        assert "first-synthetic-secret" not in value
        assert "second-synthetic-secret" not in value
    with pytest.raises(TypeError) as raised:
        pickle.dumps(first_document)
    assert "first-synthetic-secret" not in repr(raised.value)
    assert not hasattr(inventory, "GoogleAccountInventorySnapshotV1")


def test_private_document_secret_source_is_bound_and_one_shot(tmp_path: Path) -> None:
    first_document = _load_test_document(
        _write_document(tmp_path / "first", _inventory_document(secret="secret-one"))
    )
    second_document = _load_test_document(
        _write_document(tmp_path / "second", _inventory_document(secret="secret-two"))
    )

    first_source = inventory._consume_document_secret_source(first_document)
    second_source = inventory._consume_document_secret_source(second_document)

    assert first_source._secret_for_project("the-hive-1") == "secret-one"
    assert second_source._secret_for_project("the-hive-1") == "secret-two"
    with pytest.raises(GoogleAccountInventoryError) as raised:
        inventory._consume_document_secret_source(first_document)
    assert raised.value.code == "credential.inventory_secret_source_unavailable"
    assert "secret-one" not in repr(first_source)
    assert "secret-two" not in repr(second_source)
    assert not hasattr(first_document, "secret_source")


def test_public_projection_is_small_redacted_aggregate(tmp_path: Path) -> None:
    document = _inventory_document(secret="projection-synthetic-secret")
    account = document["google_accounts"][0]  # type: ignore[index]
    account["login_email"] = "login-marker@example.test"  # type: ignore[index]
    account["recovery_email"] = "recovery-marker@example.test"  # type: ignore[index]
    account["subject_id"] = "subject-marker"  # type: ignore[index]
    account["billing_accounts"][0]["billing_account_id"] = "billing-marker"  # type: ignore[index]
    project = account["projects"][0]  # type: ignore[index]
    project["project_id"] = "project-marker"
    project["key_id"] = "key-marker"

    projection = _load_test_document(
        _write_document(tmp_path / "inventory", document)
    ).public_projection()

    assert projection == {
        "schema_version": 1,
        "account_count": 1,
        "billing_account_count": 1,
        "project_count": 1,
        "active_project_count": 1,
    }
    rendered = repr(projection)
    for marker in (
        "login-marker",
        "recovery-marker",
        "subject-marker",
        "billing-marker",
        "project-marker",
        "key-marker",
        "projection-synthetic-secret",
        str(tmp_path),
    ):
        assert marker not in rendered


@pytest.mark.parametrize(
    "content",
    [
        "schema_version: 1\\nschema_version: 1\\ngoogle_accounts: []\\n",
        "schema_version: 1\\ngoogle_accounts: &accounts []\\n",
        "schema_version: 1\\ngoogle_accounts: &accounts []\\ngoogle_accounts: *accounts\\n",
    ],
)
def test_yaml_boundary_rejects_duplicate_anchor_and_alias(
    tmp_path: Path, content: str
) -> None:
    error = _assert_inventory_error(
        _write_private_inventory(tmp_path / "inventory", content)
    )

    assert error.code == "credential.inventory_schema_invalid"


def test_yaml_boundary_rejects_merge_keys(tmp_path: Path) -> None:
    content = """\\
schema_version: 1
google_accounts:
  - ref: google-account-01
    login_email: account@example.test
    billing_accounts: []
    projects:
      - &project
        ref: the-hive-1
        billing_account_ref: null
        status: blocked
        project_id: project-1
        project_number: number-1
        key_id: key-1
        key_uid: key-uid-1
        secret: null
      - <<: *project
        ref: the-hive-2
        project_id: project-2
        project_number: number-2
        key_id: key-2
        key_uid: key-uid-2
"""

    error = _assert_inventory_error(
        _write_private_inventory(tmp_path / "inventory", content)
    )

    assert error.code == "credential.inventory_schema_invalid"


def test_yaml_boundary_rejects_merge_key_without_anchor_or_alias(
    tmp_path: Path,
) -> None:
    error = _assert_inventory_error(
        _write_private_inventory(
            tmp_path / "inventory",
            "schema_version: 1\\ngoogle_accounts: []\\n<<: {}\\n",
        )
    )

    assert error.code == "credential.inventory_schema_invalid"


def test_yaml_boundary_rejects_excessive_depth_nodes_and_scalar_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixtures = (
        ("MAX_YAML_DEPTH", 4, "schema_version: 1\\ngoogle_accounts: [[[[[]]]]]\\n"),
        (
            "MAX_YAML_NODES",
            12,
            "schema_version: 1\\ngoogle_accounts: [[], [], [], [], [], [], []]\\n",
        ),
        (
            "MAX_YAML_SCALAR_BYTES",
            16,
            "schema_version: 1\\ngoogle_accounts: []\\nlabel: 12345678901234567\\n",
        ),
    )

    for position, (bound, value, content) in enumerate(fixtures):
        with monkeypatch.context() as patch:
            patch.setattr(inventory, bound, value)
            error = _assert_inventory_error(
                _write_private_inventory(tmp_path / f"inventory-{position}", content)
            )
        assert error.code == "credential.inventory_schema_invalid"


def test_loader_never_logs_synthetic_secret(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _load_test_document(
        _write_document(
            tmp_path / "inventory", _inventory_document(secret="log-secret")
        )
    )

    assert "log-secret" not in caplog.text


def test_hive_slot_length_is_bounded_before_integer_conversion(tmp_path: Path) -> None:
    document = _inventory_document(secret=None)
    project = document["google_accounts"][0]["projects"][0]  # type: ignore[index]
    project["status"] = "blocked"
    project["ref"] = "the-hive-" + ("9" * 10_000)

    error = _assert_inventory_error(_write_document(tmp_path / "inventory", document))

    assert error.code == "credential.inventory_schema_invalid"
    assert "9" * 32 not in repr(error)


@pytest.mark.parametrize("failure", [RecursionError, ValueError, OverflowError])
def test_yaml_parser_exception_is_normalized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: type[Exception]
) -> None:
    path = _write_document(tmp_path / "inventory", _inventory_document())

    def fail_parser(*args: object, **kwargs: object) -> object:
        raise failure("synthetic-parser-detail")

    monkeypatch.setattr(inventory.yaml, "load", fail_parser)

    error = _assert_inventory_error(path)

    assert error.code == "credential.inventory_schema_invalid"
    assert "synthetic-parser-detail" not in repr(error)


@pytest.mark.parametrize("tag_prefix", ["", "!!int "])
def test_overlong_hex_integer_is_rejected_before_integer_construction(
    tmp_path: Path, tag_prefix: str
) -> None:
    path = _write_private_inventory(
        tmp_path / "inventory",
        "schema_version: " + tag_prefix + "0x" + ("f" * 30_000) + "\n"
        "google_accounts: []\n",
    )

    completed = _run_with_large_integer_constructor_guard(
        path, disable_decimal_digit_limit=False
    )

    assert completed.returncode == 0
    assert completed.stdout == "credential.inventory_schema_invalid\n"


def test_overlong_decimal_integer_is_rejected_before_construction_in_subprocess(
    tmp_path: Path,
) -> None:
    path = _write_private_inventory(
        tmp_path / "inventory",
        "schema_version: " + ("9" * 10_000) + "\ngoogle_accounts: []\n",
    )
    completed = _run_with_large_integer_constructor_guard(
        path, disable_decimal_digit_limit=True
    )

    assert completed.returncode == 0
    assert completed.stdout == "credential.inventory_schema_invalid\n"


def test_account_integer_label_is_rejected_without_integer_construction(
    tmp_path: Path,
) -> None:
    path = _write_private_inventory(
        tmp_path / "inventory",
        """\
schema_version: 1
google_accounts:
  - ref: google-account-01
    login_email: account@example.test
    label: !!int 1
    billing_accounts: []
    projects: []
""",
    )

    completed = _run_with_large_integer_constructor_guard(
        path,
        disable_decimal_digit_limit=False,
        reject_integer_constructor_result=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == "credential.inventory_schema_invalid\n"


def test_integer_mapping_key_is_rejected_without_integer_construction(
    tmp_path: Path,
) -> None:
    path = _write_private_inventory(
        tmp_path / "inventory",
        "schema_version: 1\ngoogle_accounts: []\n1: value\n",
    )

    completed = _run_with_large_integer_constructor_guard(
        path,
        disable_decimal_digit_limit=False,
        reject_integer_constructor_result=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == "credential.inventory_schema_invalid\n"


def test_nested_canonical_integer_tag_is_rejected_without_integer_construction(
    tmp_path: Path,
) -> None:
    path = _write_private_inventory(
        tmp_path / "inventory",
        """\
schema_version: 1
google_accounts:
  - ref: google-account-01
    login_email: account@example.test
    billing_accounts: []
    projects:
      - ref: the-hive-1
        billing_account_ref: null
        status: blocked
        project_id: project-1
        project_number: project-number-1
        key_id: !<tag:yaml.org,2002:int> 1
        key_uid: key-uid-1
        secret: null
""",
    )

    completed = _run_with_large_integer_constructor_guard(
        path,
        disable_decimal_digit_limit=False,
        reject_integer_constructor_result=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == "credential.inventory_schema_invalid\n"


@pytest.mark.parametrize(
    "schema_version",
    ["schema_version: 1", "schema_version: !!int 1"],
)
def test_only_top_level_canonical_schema_version_integer_is_valid(
    tmp_path: Path, schema_version: str
) -> None:
    document = _load_test_document(
        _write_private_inventory(
            tmp_path / "inventory", schema_version + "\ngoogle_accounts: []\n"
        )
    )

    assert document.schema_version == 1


def test_login_identity_uses_casefold_but_keeps_raw_spelling(tmp_path: Path) -> None:
    document = _inventory_document()
    duplicate = _inventory_document()
    account = duplicate["google_accounts"][0]  # type: ignore[index]
    account["ref"] = "google-account-02"
    account["login_email"] = "ACCOUNT@example.test"
    account["subject_id"] = "subject-two"
    account["billing_accounts"] = []
    account["projects"] = []
    document["google_accounts"].append(account)  # type: ignore[index]

    error = _assert_inventory_error(_write_document(tmp_path / "inventory", document))

    assert error.code == "credential.login_duplicate"


def test_unique_login_keeps_private_raw_spelling(tmp_path: Path) -> None:
    document = _inventory_document()
    account = document["google_accounts"][0]  # type: ignore[index]
    account["login_email"] = "Account@Example.test"

    loaded = _load_test_document(_write_document(tmp_path / "inventory", document))

    assert loaded.accounts[0].login_email == "Account@Example.test"


def test_parent_component_rename_after_read_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outer = tmp_path / "outer"
    outer.mkdir(mode=0o700)
    outer.chmod(0o700)
    path = _write_document(outer / "inventory", _inventory_document())
    real_read = inventory.os.read
    moved = False

    def rename_parent_after_read(descriptor: int, size: int) -> bytes:
        nonlocal moved
        value = real_read(descriptor, size)
        if not moved:
            moved = True
            replacement = path.parent.with_name("replacement")
            path.parent.rename(replacement)
            _write_document(path.parent, _inventory_document())
        return value

    monkeypatch.setattr(inventory.os, "read", rename_parent_after_read)

    assert _assert_inventory_error(path).code == "credential.inventory_unavailable"
