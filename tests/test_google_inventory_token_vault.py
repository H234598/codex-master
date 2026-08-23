from __future__ import annotations

from dataclasses import asdict
import base64
import hashlib
import inspect
import json
import multiprocessing
import os
from pathlib import Path
import pickle
import stat
import threading
from traceback import TracebackException

import pytest
import yaml

import codex_master.google_inventory_token_vault as vault_module
from codex_master.google_account_inventory import GoogleAccountInventoryLoader
from codex_master.google_account_inventory_manager import GoogleAccountInventoryManager
from codex_master.google_inventory_token_vault import (
    GoogleInventoryReadonlyTokenVault,
    GoogleInventoryReadonlyTokenVaultError,
)


class StringSubclass(str):
    pass


class BytearraySubclass(bytearray):
    pass


class ExplodingComparison:
    def __eq__(self, other: object) -> bool:
        raise AssertionError("foreign equality must not run")

    def __hash__(self) -> int:
        raise AssertionError("foreign hashing must not run")


def _manager(
    tmp_path: Path,
    *,
    account_ref: str = "test-account",
    subject_id: str = "subject-001",
    login_email: str = "login@example.test",
) -> GoogleAccountInventoryManager:
    inventory_path = tmp_path / "inventory.yaml"
    inventory_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "google_accounts": [
                    {
                        "ref": account_ref,
                        "login_email": login_email,
                        "recovery_email": "recovery@example.test",
                        "label": None,
                        "subject_id": subject_id,
                        "billing_accounts": [],
                        "projects": [],
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    inventory_path.chmod(0o600)
    document = GoogleAccountInventoryLoader._for_test_path(inventory_path).load()
    manager = GoogleAccountInventoryManager._for_test_loader(
        lambda: document,
        monotonic_clock=lambda: 1.0,
        operator_timestamp_utc=lambda: "2026-08-23T12:00:00Z",
    )
    manager.reload()
    return manager


def _manager_for_accounts(
    tmp_path: Path, accounts: tuple[tuple[str, str, str], ...]
) -> GoogleAccountInventoryManager:
    inventory_path = tmp_path / "inventory.yaml"
    inventory_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "google_accounts": [
                    {
                        "ref": account_ref,
                        "login_email": login_email,
                        "recovery_email": None,
                        "label": None,
                        "subject_id": subject_id,
                        "billing_accounts": [],
                        "projects": [],
                    }
                    for account_ref, subject_id, login_email in accounts
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    inventory_path.chmod(0o600)
    document = GoogleAccountInventoryLoader._for_test_path(inventory_path).load()
    manager = GoogleAccountInventoryManager._for_test_loader(
        lambda: document,
        monotonic_clock=lambda: 1.0,
        operator_timestamp_utc=lambda: "2026-08-23T12:00:00Z",
    )
    manager.reload()
    return manager


def _vault(tmp_path: Path) -> GoogleInventoryReadonlyTokenVault:
    tmp_path.chmod(0o700)
    tokens = tmp_path / "tokens"
    tokens.mkdir(mode=0o700)
    tokens.chmod(0o700)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return GoogleInventoryReadonlyTokenVault._for_test_tokens_parent_directory_fd(
            fd
        )
    finally:
        os.close(fd)


def _client_fingerprint(value: str = "client") -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _store(
    vault: GoogleInventoryReadonlyTokenVault,
    manager: GoogleAccountInventoryManager,
    *,
    token: bytearray | None = None,
    generation: int | None = None,
    subject_id: str = "subject-001",
    account_ref: str = "test-account",
    client_fingerprint: str | None = None,
):
    return vault.store_inventory_refresh_token(
        manager,
        account_ref=account_ref,
        subject_id=subject_id,
        oauth_client_fingerprint=client_fingerprint or _client_fingerprint(),
        refresh_token=token if token is not None else bytearray(b"synthetic-token"),
        expected_vault_generation=generation,
    )


def _delete(
    vault: GoogleInventoryReadonlyTokenVault,
    manager: GoogleAccountInventoryManager,
    *,
    generation: int | None = None,
    subject_id: str = "subject-001",
    account_ref: str = "test-account",
    client_fingerprint: str | None = None,
):
    return vault.delete_inventory_refresh_token(
        manager,
        account_ref=account_ref,
        subject_id=subject_id,
        oauth_client_fingerprint=client_fingerprint or _client_fingerprint(),
        expected_vault_generation=generation,
    )


def _record(tmp_path: Path) -> dict[str, object]:
    return json.loads((tmp_path / "tokens" / "test-account.json").read_text("utf-8"))


def _error_code(call: object) -> str:
    with pytest.raises(GoogleInventoryReadonlyTokenVaultError) as caught:
        call()  # type: ignore[operator]
    return caught.value.code


def _directory_state(path: Path) -> tuple[int, int, int, int, int, int, int]:
    metadata = os.lstat(path)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _private_file_state(path: Path) -> tuple[int, int, int, int, int, bytes]:
    metadata = os.lstat(path)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        path.read_bytes(),
    )


def _fixed_user_vault_tree(tmp_path: Path) -> dict[str, Path]:
    home = tmp_path / "home"
    config = home / ".config"
    application = config / "codex-master-mcp"
    oauth = application / "google-oauth"
    tokens = oauth / "tokens"
    home.mkdir(mode=0o700)
    config.mkdir(mode=0o755)
    application.mkdir(mode=0o755)
    oauth.mkdir(mode=0o700)
    tokens.mkdir(mode=0o700)
    record = tokens / "test-account.json"
    lock = tokens / "test-account.lock"
    record.write_bytes(b"existing-record")
    lock.write_bytes(b"existing-lock")
    record.chmod(0o600)
    lock.chmod(0o600)
    return {
        "home": home,
        "config": config,
        "application": application,
        "oauth": oauth,
        "tokens": tokens,
        "record": record,
        "lock": lock,
    }


def _open_fixed_user_vault_tree(
    home: Path, *, expected_owner: int | None = None
) -> tuple[str | None, object]:
    fd = os.open(
        home,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    code, identity = vault_module._validated_directory_identity(
        fd,
        expected_owner=os.geteuid(),
        exact_mode=None,
        reject_group_world_write=True,
    )
    assert code is None and identity is not None
    capability = vault_module._DirectoryCapability(
        [
            vault_module._DirectoryNode(
                fd,
                None,
                identity,
                expected_owner=os.geteuid(),
                exact_mode=None,
                reject_group_world_write=True,
            )
        ]
    )
    try:
        code = vault_module._append_user_tokens_directory_components(
            capability,
            effective_uid=(os.geteuid() if expected_owner is None else expected_owner),
        )
    except BaseException:
        vault_module._close_directory_capability(capability)
        raise
    return code, capability


def _assert_error_graph_redacted(
    error: BaseException, *, markers: tuple[str, ...]
) -> None:
    production_path = Path(vault_module.__file__).resolve()
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        rendered = (
            repr(current),
            str(current),
            repr(current.args),
            repr(pickle.dumps(current)),
        )
        assert all(marker not in value for marker in markers for value in rendered)
        pending.extend(
            linked
            for linked in (current.__cause__, current.__context__)
            if linked is not None
        )
        traceback = current.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if Path(frame.f_code.co_filename).resolve() == production_path:
                assert all(
                    marker not in repr(value)
                    for marker in markers
                    for value in frame.f_locals.values()
                )
            traceback = traceback.tb_next
        captured = TracebackException.from_exception(current, capture_locals=True)
        for summary in captured.stack:
            if Path(summary.filename).resolve() == production_path:
                assert all(
                    marker not in value
                    for marker in markers
                    for value in (summary.locals or {}).values()
                )


def _process_store(
    vault: GoogleInventoryReadonlyTokenVault,
    manager: GoogleAccountInventoryManager,
    start: object,
    output: object,
) -> None:
    assert start.wait(timeout=2)  # type: ignore[union-attr]
    try:
        receipt = _store(vault, manager)
    except GoogleInventoryReadonlyTokenVaultError as error:
        output.put(("error", error.code))  # type: ignore[union-attr]
    else:
        output.put(("ok", receipt.vault_generation))  # type: ignore[union-attr]


def _process_raced_mutation(
    vault: GoogleInventoryReadonlyTokenVault,
    manager: GoogleAccountInventoryManager,
    barrier: str,
    operation: str,
    ready: object,
    proceed: object,
    output: object,
) -> None:
    original_read = vault_module._read_existing_record
    original_parse = vault_module._parse_record
    original_write_all = vault_module._write_all
    original_flock = vault_module.fcntl.flock

    def wait_at_barrier() -> None:
        ready.set()  # type: ignore[union-attr]
        if not proceed.wait(timeout=5):  # type: ignore[union-attr]
            raise RuntimeError("race barrier timed out")

    if barrier == "parent":

        def blocked_read(*args: object, **kwargs: object):
            wait_at_barrier()
            return original_read(*args, **kwargs)  # type: ignore[arg-type]

        vault_module._read_existing_record = blocked_read  # type: ignore[assignment]
    elif barrier == "lock":

        def blocked_flock(fd: int, operation_flag: int) -> None:
            original_flock(fd, operation_flag)
            if operation_flag & vault_module.fcntl.LOCK_EX:
                wait_at_barrier()

        vault_module.fcntl.flock = blocked_flock
    elif barrier == "record":

        def blocked_parse(raw: bytes):
            result = original_parse(raw)
            wait_at_barrier()
            return result

        vault_module._parse_record = blocked_parse
    elif barrier == "temp":

        def blocked_write_all(fd: int, payload: bytearray) -> bool:
            result = original_write_all(fd, payload)
            wait_at_barrier()
            return result

        vault_module._write_all = blocked_write_all
    else:
        raise AssertionError("unknown race barrier")

    token = bytearray(b"subprocess-race-secret-marker")
    try:
        if operation == "store":
            result = (
                "ok",
                _store(vault, manager, token=token, generation=1).vault_generation,
            )
        else:
            result = ("ok", _delete(vault, manager, generation=1).removed)
    except GoogleInventoryReadonlyTokenVaultError as error:
        result = ("error", error.code)
    except BaseException as error:
        result = ("raw", type(error).__name__)
    output.put((result, token == bytearray(len(token))))  # type: ignore[union-attr]


def _run_raced_mutation(
    vault: GoogleInventoryReadonlyTokenVault,
    manager: GoogleAccountInventoryManager,
    *,
    barrier: str,
    operation: str,
    mutate: object,
) -> tuple[tuple[str, object], bool]:
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    proceed = context.Event()
    output = context.Queue()
    process = context.Process(
        target=_process_raced_mutation,
        args=(vault, manager, barrier, operation, ready, proceed, output),
    )
    process.start()
    try:
        assert ready.wait(timeout=5)
        mutate()  # type: ignore[operator]
        proceed.set()
        result = output.get(timeout=5)
    finally:
        proceed.set()
        process.join(timeout=5)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
    assert process.exitcode == 0
    return result


def _assert_no_race_secret(
    directory: Path, marker: bytes = b"subprocess-race-secret-marker"
) -> None:
    encoded = base64.b64encode(marker)
    for path in directory.iterdir():
        if path.is_file():
            content = path.read_bytes()
            assert marker not in content
            assert encoded not in content


def test_current_host_production_open_allows_0755_nonsecret_parents_and_is_read_only() -> (
    None
):
    home = Path.home()
    config = home / ".config"
    application = config / "codex-master-mcp"
    oauth = application / "google-oauth"
    if (
        home != Path("/home/teladi")
        or not config.is_dir()
        or not application.is_dir()
        or os.path.lexists(oauth)
    ):
        pytest.skip("current-host read-only evidence preconditions are absent")
    assert os.lstat(config).st_uid == os.geteuid()
    assert os.lstat(application).st_uid == os.geteuid()
    assert stat.S_IMODE(os.lstat(config).st_mode) == 0o755
    assert stat.S_IMODE(os.lstat(application).st_mode) == 0o755
    before = tuple(_directory_state(path) for path in (home, config, application))

    code, capability = vault_module._open_production_tokens_directory()
    try:
        assert code == "credential.inventory_token_vault_unavailable"
        assert capability is None
    finally:
        vault_module._close_directory_capability(capability)

    assert tuple(_directory_state(path) for path in (home, config, application)) == (
        before
    )
    assert not os.path.lexists(oauth)


def test_temp_user_chain_accepts_owner_0755_nonwritable_parents_read_only(
    tmp_path: Path,
) -> None:
    tree = _fixed_user_vault_tree(tmp_path)
    before = tuple(_private_file_state(tree[name]) for name in ("record", "lock"))

    code, capability = _open_fixed_user_vault_tree(tree["home"])
    try:
        assert code is None
        assert vault_module._revalidate_directory_capability(capability) is None
        assert os.fstat(capability.fd).st_ino == os.lstat(tree["tokens"]).st_ino
    finally:
        vault_module._close_directory_capability(capability)

    assert (
        tuple(_private_file_state(tree[name]) for name in ("record", "lock")) == before
    )


@pytest.mark.parametrize(
    ("component", "mode"),
    (("config", 0o775), ("application", 0o757)),
)
def test_temp_user_chain_rejects_writable_nonsecret_parent_without_file_mutation(
    tmp_path: Path, component: str, mode: int
) -> None:
    tree = _fixed_user_vault_tree(tmp_path)
    tree[component].chmod(mode)
    before = tuple(_private_file_state(tree[name]) for name in ("record", "lock"))

    code, capability = _open_fixed_user_vault_tree(tree["home"])
    try:
        assert code == "credential.inventory_token_vault_permissions"
    finally:
        vault_module._close_directory_capability(capability)

    assert (
        tuple(_private_file_state(tree[name]) for name in ("record", "lock")) == before
    )


def test_temp_user_chain_rejects_wrong_owner_without_file_mutation(
    tmp_path: Path,
) -> None:
    tree = _fixed_user_vault_tree(tmp_path)
    before = tuple(_private_file_state(tree[name]) for name in ("record", "lock"))

    code, capability = _open_fixed_user_vault_tree(
        tree["home"], expected_owner=os.geteuid() + 1
    )
    try:
        assert code == "credential.inventory_token_vault_permissions"
    finally:
        vault_module._close_directory_capability(capability)

    assert (
        tuple(_private_file_state(tree[name]) for name in ("record", "lock")) == before
    )


def test_temp_user_chain_rejects_symlinked_nonsecret_parent_without_file_mutation(
    tmp_path: Path,
) -> None:
    tree = _fixed_user_vault_tree(tmp_path)
    real_config = tree["home"] / ".config-real"
    tree["config"].rename(real_config)
    tree["config"].symlink_to(real_config, target_is_directory=True)
    record = real_config / "codex-master-mcp/google-oauth/tokens/test-account.json"
    lock = real_config / "codex-master-mcp/google-oauth/tokens/test-account.lock"
    before = (_private_file_state(record), _private_file_state(lock))

    code, capability = _open_fixed_user_vault_tree(tree["home"])
    try:
        assert code == "credential.inventory_token_vault_path_invalid"
    finally:
        vault_module._close_directory_capability(capability)

    assert (_private_file_state(record), _private_file_state(lock)) == before


@pytest.mark.parametrize("component", ("oauth", "tokens"))
def test_temp_user_chain_rejects_nonprivate_secret_directory_without_file_mutation(
    tmp_path: Path, component: str
) -> None:
    tree = _fixed_user_vault_tree(tmp_path)
    tree[component].chmod(0o755)
    before = tuple(_private_file_state(tree[name]) for name in ("record", "lock"))

    code, capability = _open_fixed_user_vault_tree(tree["home"])
    try:
        assert code == "credential.inventory_token_vault_permissions"
    finally:
        vault_module._close_directory_capability(capability)

    assert (
        tuple(_private_file_state(tree[name]) for name in ("record", "lock")) == before
    )


def test_temp_user_chain_missing_secret_subtree_is_unavailable_and_not_created(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    config = home / ".config"
    application = config / "codex-master-mcp"
    home.mkdir(mode=0o700)
    config.mkdir(mode=0o755)
    application.mkdir(mode=0o755)
    oauth = application / "google-oauth"
    before = tuple(_directory_state(path) for path in (home, config, application))

    code, capability = _open_fixed_user_vault_tree(home)
    try:
        assert code == "credential.inventory_token_vault_unavailable"
    finally:
        vault_module._close_directory_capability(capability)

    assert tuple(_directory_state(path) for path in (home, config, application)) == (
        before
    )
    assert not os.path.lexists(oauth)


def test_private_mutation_contract_excludes_unsandboxed_same_uid_last_syscall_swap() -> (
    None
):
    boundary = vault_module._MUTATION_THREAT_BOUNDARY

    assert boundary.detects_observable_swaps_through_last_attestation
    assert not boundary.unsandboxed_same_uid_after_last_attestation_in_scope
    assert boundary.future_isolation == "separate_uid_or_root_broker"


def test_store_writes_bound_readonly_record_and_returns_generation(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    refresh_token = bytearray(b"synthetic-refresh-token")

    receipt = vault.store_inventory_refresh_token(
        _manager(tmp_path),
        account_ref="test-account",
        subject_id="subject-001",
        oauth_client_fingerprint=_client_fingerprint(),
        refresh_token=refresh_token,
        expected_vault_generation=None,
    )

    assert receipt.vault_generation == 1
    assert refresh_token == bytearray(len(refresh_token))


def test_record_is_bound_to_snapshot_login_not_recovery_email(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    _store(vault, _manager(tmp_path))

    record = _record(tmp_path)

    assert record["subject_fingerprint"] == _client_fingerprint("subject-001")
    assert record["login_fingerprint"] == _client_fingerprint("login@example.test")
    assert _client_fingerprint("recovery@example.test") not in record.values()
    assert record["profile_id"] == "inventory_readonly"
    assert record["scope_fingerprint"] == (
        "sha256:9b2a7ff6966db417c590bbaae896036309e4391f414c7c93cf727873ed7d7e7f"
    )


def test_store_uses_compare_and_swap_generation(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)

    assert _store(vault, manager).vault_generation == 1
    assert _error_code(lambda: _store(vault, manager, generation=None)) == (
        "credential.inventory_token_vault_generation_conflict"
    )
    assert _error_code(lambda: _store(vault, manager, generation=2)) == (
        "credential.inventory_token_vault_generation_conflict"
    )
    assert _store(vault, manager, generation=1).vault_generation == 2


def test_delete_is_bound_cas_and_idempotent_when_missing(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)

    assert _delete(vault, manager).removed is False
    _store(vault, manager)
    assert _error_code(lambda: _delete(vault, manager, generation=2)) == (
        "credential.inventory_token_vault_generation_conflict"
    )
    assert _delete(vault, manager, generation=1).removed is True
    assert _error_code(lambda: _delete(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_generation_conflict"
    )
    assert (tmp_path / "tokens" / "test-account.lock").is_file()


def test_binding_failure_precedes_generation_conflict(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)

    assert (
        _error_code(
            lambda: _store(
                vault,
                manager,
                generation=99,
                client_fingerprint=_client_fingerprint("other-client"),
            )
        )
        == "credential.inventory_token_vault_binding_invalid"
    )
    assert (
        _error_code(
            lambda: _delete(
                vault,
                manager,
                generation=99,
                subject_id="other-subject",
            )
        )
        == "credential.inventory_token_vault_binding_invalid"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("account_ref", b"test-account"),
        ("subject_id", b"subject-001"),
        ("oauth_client_fingerprint", "sha256:" + "A" * 64),
        ("refresh_token", b"synthetic-token"),
        ("expected_vault_generation", True),
    ),
)
def test_request_boundary_rejects_nonexact_inputs_and_zeroizes_token(
    tmp_path: Path, field: str, value: object
) -> None:
    vault = _vault(tmp_path)
    token = bytearray(b"synthetic-token")
    kwargs: dict[str, object] = {
        "account_ref": "test-account",
        "subject_id": "subject-001",
        "oauth_client_fingerprint": _client_fingerprint(),
        "refresh_token": token,
        "expected_vault_generation": None,
    }
    kwargs[field] = value

    assert _error_code(
        lambda: vault.store_inventory_refresh_token(_manager(tmp_path), **kwargs)
    ) == ("credential.inventory_token_vault_request_invalid")
    if field != "refresh_token":
        assert token == bytearray(len(token))


def test_schema_rejects_unknown_fields_and_invalid_token_payload(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    tokens = tmp_path / "tokens"
    record = {
        "format_version": 1,
        "record_kind": "google_inventory_readonly_refresh_token_v1",
        "vault_generation": 1,
        "account_ref": "test-account",
        "subject_fingerprint": _client_fingerprint("subject-001"),
        "login_fingerprint": _client_fingerprint("login@example.test"),
        "oauth_client_fingerprint": _client_fingerprint(),
        "profile_id": "inventory_readonly",
        "scope_fingerprint": "sha256:9b2a7ff6966db417c590bbaae896036309e4391f414c7c93cf727873ed7d7e7f",
        "refresh_token_b64": "%%%",
    }
    (tokens / "test-account.json").write_text(json.dumps(record), encoding="utf-8")
    (tokens / "test-account.json").chmod(0o600)

    assert _error_code(lambda: _store(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_token_invalid"
    )
    record["refresh_token_b64"] = "c3ludGhldGljLXRva2Vu"
    record["unknown"] = "x"
    (tokens / "test-account.json").write_text(json.dumps(record), encoding="utf-8")
    (tokens / "test-account.json").chmod(0o600)
    assert _error_code(lambda: _store(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_schema_invalid"
    )


def test_file_and_lock_hardening_fail_closed(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    tokens = tmp_path / "tokens"
    tokens.chmod(0o755)
    assert _error_code(lambda: _store(vault, manager)) == (
        "credential.inventory_token_vault_permissions"
    )
    tokens.chmod(0o700)
    (tokens / "test-account.lock").symlink_to("elsewhere")
    assert _error_code(lambda: _store(vault, manager)) == (
        "credential.inventory_token_vault_path_invalid"
    )


def test_store_reports_parent_fsync_failure_after_atomic_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    original_fsync = vault_module.os.fsync
    calls = 0

    def fail_parent_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic")
        original_fsync(fd)

    monkeypatch.setattr(vault_module.os, "fsync", fail_parent_fsync)

    assert _error_code(lambda: _store(vault, manager)) == (
        "credential.inventory_token_vault_durability_failed"
    )
    assert (tmp_path / "tokens" / "test-account.json").is_file()


def test_public_receipts_and_errors_do_not_expose_secret_or_identifier(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    marker = "synthetic-private-refresh-marker"
    token = bytearray(marker.encode("ascii"))
    receipt = _store(vault, manager, token=token)
    error: GoogleInventoryReadonlyTokenVaultError
    try:
        vault.store_inventory_refresh_token(
            manager,
            account_ref="test-account",
            subject_id="synthetic-subject-marker",
            oauth_client_fingerprint=_client_fingerprint(),
            refresh_token=bytearray(marker.encode("ascii")),
            expected_vault_generation=1,
        )
    except GoogleInventoryReadonlyTokenVaultError as caught:
        error = caught
    else:
        raise AssertionError("expected binding error")

    rendered = (
        repr(receipt),
        str(receipt),
        repr(asdict(receipt)),
        pickle.dumps(receipt),
    )
    assert all(marker not in value for value in rendered if type(value) is str)
    assert marker.encode("ascii") not in rendered[-1]
    assert marker not in repr(error)
    assert "synthetic-subject-marker" not in repr(error)

    traceback = TracebackException.from_exception(error, capture_locals=True)
    production = Path(vault_module.__file__).resolve()
    for summary in traceback.stack:
        if Path(summary.filename).resolve() == production:
            assert all(
                marker not in value and "synthetic-subject-marker" not in value
                for value in (summary.locals or {}).values()
            )


def test_thread_contention_has_single_mutation_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    original_write = vault_module._write_record

    def delayed_write(*args: object, **kwargs: object) -> str | None:
        entered.set()
        assert release.wait(timeout=2)
        return original_write(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(vault_module, "_write_record", delayed_write)
    results: list[object] = []

    def mutate() -> None:
        try:
            results.append(_store(vault, manager))
        except GoogleInventoryReadonlyTokenVaultError as error:
            results.append(error.code)

    first = threading.Thread(target=mutate)
    second = threading.Thread(target=mutate)
    first.start()
    assert entered.wait(timeout=2)
    second.start()
    second.join(timeout=2)
    release.set()
    first.join(timeout=2)

    assert not first.is_alive() and not second.is_alive()
    assert sum(hasattr(result, "vault_generation") for result in results) == 1
    assert "credential.inventory_token_vault_busy" in results


def test_process_contention_has_single_mutation_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = multiprocessing.get_context("fork")
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    start = context.Event()
    output = context.Queue()
    process = context.Process(
        target=_process_store, args=(vault, manager, start, output)
    )
    process.start()
    entered = threading.Event()
    release = threading.Event()
    original_write = vault_module._write_record

    def delayed_write(*args: object, **kwargs: object) -> str | None:
        entered.set()
        assert release.wait(timeout=2)
        return original_write(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(vault_module, "_write_record", delayed_write)
    parent_result: list[object] = []

    def parent_store() -> None:
        try:
            parent_result.append(_store(vault, manager))
        except GoogleInventoryReadonlyTokenVaultError as error:
            parent_result.append(error.code)

    parent = threading.Thread(target=parent_store)
    try:
        parent.start()
        assert entered.wait(timeout=2)
        start.set()
        child_result = output.get(timeout=2)
    finally:
        release.set()
        parent.join(timeout=2)
        process.join(timeout=2)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)

    assert not parent.is_alive() and process.exitcode == 0
    assert hasattr(parent_result[0], "vault_generation")
    assert child_result == ("error", "credential.inventory_token_vault_busy")


def test_existing_record_hardlink_and_mode_fail_closed(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    record = tmp_path / "tokens" / "test-account.json"
    os.link(record, tmp_path / "tokens" / "linked-record")

    assert _error_code(lambda: _delete(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_permissions"
    )
    (tmp_path / "tokens" / "linked-record").unlink()
    record.chmod(0o640)
    assert _error_code(lambda: _delete(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_permissions"
    )


def test_failed_replace_leaves_previous_complete_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    before = (tmp_path / "tokens" / "test-account.json").read_bytes()

    def fail_replace(*args: object, **kwargs: object) -> None:
        raise OSError("synthetic")

    monkeypatch.setattr(vault_module.os, "replace", fail_replace)
    assert _error_code(lambda: _store(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_write_failed"
    )
    assert (tmp_path / "tokens" / "test-account.json").read_bytes() == before


def test_duplicate_json_keys_and_profile_mismatch_precede_generation(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    path = tmp_path / "tokens" / "test-account.json"
    duplicate = path.read_text("utf-8").replace(
        '"format_version":1,', '"format_version":1,"format_version":1,'
    )
    path.write_text(duplicate, encoding="utf-8")
    path.chmod(0o600)
    assert _error_code(lambda: _store(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_schema_invalid"
    )

    record = _record(tmp_path)
    record["profile_id"] = "foreign-profile"
    path.write_text(json.dumps(record), encoding="utf-8")
    path.chmod(0o600)
    assert _error_code(lambda: _store(vault, manager, generation=99)) == (
        "credential.inventory_token_vault_profile_mismatch"
    )


@pytest.mark.parametrize(
    "value",
    (StringSubclass("test-account"), ExplodingComparison(), True),
)
def test_foreign_identifier_values_fail_before_hash_or_equality(
    tmp_path: Path, value: object
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    token = bytearray(b"synthetic-token")

    assert (
        _error_code(
            lambda: vault.store_inventory_refresh_token(
                manager,
                account_ref=value,
                subject_id="subject-001",
                oauth_client_fingerprint=_client_fingerprint(),
                refresh_token=token,
                expected_vault_generation=None,
            )
        )
        == "credential.inventory_token_vault_request_invalid"
    )
    assert token == bytearray(len(token))


def test_error_graph_and_traceback_locals_redact_untrusted_markers(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    token_marker = "synthetic-token-traceback-marker"
    subject_marker = "synthetic-subject-traceback-marker"
    try:
        vault.store_inventory_refresh_token(
            manager,
            account_ref="test-account",
            subject_id=subject_marker,
            oauth_client_fingerprint=_client_fingerprint(),
            refresh_token=bytearray(token_marker.encode("ascii")),
            expected_vault_generation=None,
        )
    except GoogleInventoryReadonlyTokenVaultError as caught:
        error = caught
    else:
        raise AssertionError("expected binding failure")

    pending: list[BaseException] = [error]
    seen: set[int] = set()
    production_path = Path(vault_module.__file__).resolve()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        assert token_marker not in repr(current)
        assert subject_marker not in repr(current)
        pending.extend(
            linked
            for linked in (current.__cause__, current.__context__)
            if linked is not None
        )
        traceback = current.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if Path(frame.f_code.co_filename).resolve() == production_path:
                assert all(
                    token_marker not in repr(value)
                    and subject_marker not in repr(value)
                    for value in frame.f_locals.values()
                )
            traceback = traceback.tb_next
        captured = TracebackException.from_exception(current, capture_locals=True)
        for summary in captured.stack:
            if Path(summary.filename).resolve() == production_path:
                assert all(
                    token_marker not in value and subject_marker not in value
                    for value in (summary.locals or {}).values()
                )


@pytest.mark.parametrize(
    "refresh_token",
    (
        b"synthetic-token",
        "synthetic-token",
        memoryview(b"synthetic-token"),
        BytearraySubclass(b"synthetic-token"),
    ),
)
def test_only_exact_bytearray_is_accepted_for_refresh_token(
    tmp_path: Path, refresh_token: object
) -> None:
    vault = _vault(tmp_path)

    assert (
        _error_code(
            lambda: vault.store_inventory_refresh_token(
                _manager(tmp_path),
                account_ref="test-account",
                subject_id="subject-001",
                oauth_client_fingerprint=_client_fingerprint(),
                refresh_token=refresh_token,
                expected_vault_generation=None,
            )
        )
        == "credential.inventory_token_vault_request_invalid"
    )


def test_token_size_limits_zeroize_actual_bytearray(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    too_small = bytearray()
    too_large = bytearray(b"x" * (16 * 1024 + 1))

    assert _error_code(lambda: _store(vault, manager, token=too_small)) == (
        "credential.inventory_token_vault_request_invalid"
    )
    assert _error_code(lambda: _store(vault, manager, token=too_large)) == (
        "credential.inventory_token_vault_request_invalid"
    )
    assert too_small == bytearray()
    assert too_large == bytearray(len(too_large))


def test_lock_wrong_mode_and_oversized_record_fail_closed(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    lock = tmp_path / "tokens" / "test-account.lock"
    lock.write_bytes(b"")
    lock.chmod(0o644)
    assert _error_code(lambda: _store(vault, manager)) == (
        "credential.inventory_token_vault_permissions"
    )
    lock.unlink()
    record = tmp_path / "tokens" / "test-account.json"
    record.write_bytes(b"{" + b" " * (32 * 1024))
    record.chmod(0o600)
    assert _error_code(lambda: _store(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_schema_invalid"
    )


def test_delete_reports_durability_failure_after_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)

    def fail_fsync(fd: int) -> None:
        raise OSError("synthetic")

    monkeypatch.setattr(vault_module.os, "fsync", fail_fsync)
    assert _error_code(lambda: _delete(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_durability_failed"
    )
    assert not (tmp_path / "tokens" / "test-account.json").exists()


def test_pre_rename_failure_removes_only_own_temp_and_retry_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    record_path = tmp_path / "tokens" / "test-account.json"
    before = record_path.read_bytes()

    def fail_replace(*args: object, **kwargs: object) -> None:
        raise OSError("synthetic")

    monkeypatch.setattr(vault_module.os, "replace", fail_replace)
    token = bytearray(b"synthetic-temp-cleanup-marker")
    assert _error_code(lambda: _store(vault, manager, token=token, generation=1)) == (
        "credential.inventory_token_vault_write_failed"
    )
    assert token == bytearray(len(token))
    assert record_path.read_bytes() == before
    assert not list((tmp_path / "tokens").glob(".test-account.*.tmp"))
    monkeypatch.undo()
    assert _store(vault, manager, generation=1).vault_generation == 2


def test_generation_maximum_never_writes_invalid_success_record(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    record_path = tmp_path / "tokens" / "test-account.json"
    record = _record(tmp_path)
    record["vault_generation"] = vault_module._MAX_GENERATION
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    before = record_path.read_bytes()

    assert (
        _error_code(
            lambda: _store(vault, manager, generation=vault_module._MAX_GENERATION)
        )
        == "credential.inventory_token_vault_generation_conflict"
    )
    assert record_path.read_bytes() == before


def test_generation_maximum_minus_one_reaches_maximum(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    record_path = tmp_path / "tokens" / "test-account.json"
    record = _record(tmp_path)
    record["vault_generation"] = vault_module._MAX_GENERATION - 1
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)

    assert (
        _store(
            vault, manager, generation=vault_module._MAX_GENERATION - 1
        ).vault_generation
        == vault_module._MAX_GENERATION
    )


def test_existing_token_base64_must_be_exact_canonical_encoding(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager, token=bytearray(b"a"))
    path = tmp_path / "tokens" / "test-account.json"
    record = _record(tmp_path)
    assert record["refresh_token_b64"] == "YQ=="
    record["refresh_token_b64"] = "YR=="
    path.write_text(json.dumps(record), encoding="utf-8")
    path.chmod(0o600)

    assert _error_code(lambda: _store(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_token_invalid"
    )


def test_process_lock_registry_releases_last_reference(tmp_path: Path) -> None:
    vault_module._IN_PROCESS_LOCKS.clear()
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)

    _store(vault, manager)
    _delete(vault, manager, generation=1)

    assert not vault_module._IN_PROCESS_LOCKS


def test_cleanup_close_failure_is_code_only_and_zeroizes_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    original_close = vault_module.os.close
    closes = 0

    def fail_tokens_close(fd: int) -> None:
        nonlocal closes
        closes += 1
        original_close(fd)
        if closes == 3:
            raise OSError("synthetic close failure")

    monkeypatch.setattr(vault_module.os, "close", fail_tokens_close)
    marker = "synthetic-cleanup-close-marker"
    token = bytearray(marker.encode("ascii"))
    try:
        _store(vault, manager, token=token)
    except GoogleInventoryReadonlyTokenVaultError as caught:
        error = caught
    else:
        raise AssertionError("expected cleanup failure")

    assert error.code == "credential.inventory_token_vault_write_failed"
    assert token == bytearray(len(token))
    captured = TracebackException.from_exception(error, capture_locals=True)
    production = Path(vault_module.__file__).resolve()
    for summary in captured.stack:
        if Path(summary.filename).resolve() == production:
            assert all(marker not in value for value in (summary.locals or {}).values())


def test_temp_cleanup_drops_secret_and_identifier_locals_before_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    account_marker = "cleanup-account-marker"
    subject_id = "subject-cleanup"
    vault = _vault(tmp_path)
    manager = _manager(
        tmp_path,
        account_ref=account_marker,
        subject_id=subject_id,
        login_email="cleanup@example.test",
    )
    _store(
        vault,
        manager,
        account_ref=account_marker,
        subject_id=subject_id,
    )
    record_path = tmp_path / "tokens" / f"{account_marker}.json"
    before = record_path.read_bytes()
    token_marker = b"cleanup-secret-marker"
    encoded_marker = base64.b64encode(token_marker).decode("ascii")
    production_locals: list[str] = []
    original_unlink = vault_module.os.unlink

    def fail_replace(*args: object, **kwargs: object) -> None:
        raise OSError("synthetic replace failure")

    def inspect_temp_unlink(path: object, *args: object, **kwargs: object) -> None:
        path_text = os.fspath(path)  # type: ignore[arg-type]
        if type(path_text) is str and path_text.startswith(f".{account_marker}."):
            frame = inspect.currentframe()
            assert frame is not None
            frame = frame.f_back
            while frame is not None:
                if (
                    Path(frame.f_code.co_filename).resolve()
                    == Path(vault_module.__file__).resolve()
                ):
                    production_locals.append(repr(frame.f_locals))
                frame = frame.f_back
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(vault_module.os, "replace", fail_replace)
    monkeypatch.setattr(vault_module.os, "unlink", inspect_temp_unlink)
    token = bytearray(token_marker)

    assert (
        _error_code(
            lambda: _store(
                vault,
                manager,
                token=token,
                generation=1,
                account_ref=account_marker,
                subject_id=subject_id,
            )
        )
        == "credential.inventory_token_vault_write_failed"
    )
    assert token == bytearray(len(token))
    assert production_locals
    assert all(
        account_marker not in value and encoded_marker not in value
        for value in production_locals
    )
    assert record_path.read_bytes() == before
    assert not list((tmp_path / "tokens").glob(f".{account_marker}.*.tmp"))


def test_temp_fd_close_failure_is_not_retried_and_temp_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    record_path = tmp_path / "tokens" / "test-account.json"
    before = record_path.read_bytes()
    original_open = vault_module.os.open
    original_close = vault_module.os.close
    temp_fd: int | None = None
    temp_close_calls = 0

    def track_open(path: object, *args: object, **kwargs: object) -> int:
        nonlocal temp_fd
        fd = original_open(path, *args, **kwargs)
        path_text = os.fspath(path)  # type: ignore[arg-type]
        if type(path_text) is str and path_text.endswith(".tmp"):
            temp_fd = fd
        return fd

    def fail_temp_close(fd: int) -> None:
        nonlocal temp_close_calls
        if fd == temp_fd:
            temp_close_calls += 1
            original_close(fd)
            if temp_close_calls == 1:
                raise OSError("synthetic temp close failure")
            return
        original_close(fd)

    monkeypatch.setattr(vault_module.os, "open", track_open)
    monkeypatch.setattr(vault_module.os, "close", fail_temp_close)

    assert _error_code(lambda: _store(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_write_failed"
    )
    assert temp_close_calls == 1
    assert record_path.read_bytes() == before
    assert not list((tmp_path / "tokens").glob(".test-account.*.tmp"))


@pytest.mark.parametrize("operation", ("store", "delete"))
def test_busy_primary_wins_over_lock_close_failure_and_keeps_registry_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    vault_module._IN_PROCESS_LOCKS.clear()
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    if operation == "delete":
        _store(vault, manager)
    held_entry = vault_module._acquire_process_lock_reference("test-account")
    held_entry.lock.acquire()
    original_open = vault_module.os.open
    original_close = vault_module.os.close
    lock_fd: int | None = None
    close_failed = False

    def track_open(path: object, *args: object, **kwargs: object) -> int:
        nonlocal lock_fd
        fd = original_open(path, *args, **kwargs)
        if os.fspath(path) == "test-account.lock":  # type: ignore[arg-type]
            lock_fd = fd
        return fd

    def fail_lock_close(fd: int) -> None:
        nonlocal close_failed
        if fd == lock_fd and not close_failed:
            close_failed = True
            original_close(fd)
            raise OSError("synthetic lock close failure")
        original_close(fd)

    monkeypatch.setattr(vault_module.os, "open", track_open)
    monkeypatch.setattr(vault_module.os, "close", fail_lock_close)
    token = bytearray(b"busy-cleanup-secret")
    try:
        if operation == "store":
            code = _error_code(lambda: _store(vault, manager, token=token))
        else:
            code = _error_code(lambda: _delete(vault, manager, generation=1))
        registry_kept = (
            vault_module._IN_PROCESS_LOCKS.get("test-account") is held_entry
            and held_entry.references == 1
        )
        lock_still_held = held_entry.lock.locked()
    finally:
        if held_entry.lock.locked():
            held_entry.lock.release()
        if vault_module._IN_PROCESS_LOCKS.get("test-account") is held_entry:
            vault_module._release_process_lock_reference("test-account", held_entry)
        vault_module._IN_PROCESS_LOCKS.clear()

    assert close_failed
    assert code == "credential.inventory_token_vault_busy"
    assert registry_kept
    assert lock_still_held
    if operation == "store":
        assert token == bytearray(len(token))


@pytest.mark.parametrize("operation", ("store", "delete"))
@pytest.mark.parametrize(
    "failure_kind", ("record_close", "lock_un", "lock_close", "parent_close")
)
def test_store_and_delete_cleanup_failures_are_code_only_and_continue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    failure_kind: str,
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    original_open = vault_module.os.open
    original_dup = vault_module.os.dup
    original_close = vault_module.os.close
    original_flock = vault_module.fcntl.flock
    tracked: dict[str, int] = {}
    attempts: list[str] = []

    def track_open(path: object, *args: object, **kwargs: object) -> int:
        fd = original_open(path, *args, **kwargs)
        path_text = os.fspath(path)  # type: ignore[arg-type]
        if path_text == "test-account.lock":
            tracked["lock_close"] = fd
        elif path_text == "test-account.json":
            tracked["record_close"] = fd
        return fd

    def track_dup(fd: int) -> int:
        duplicate = original_dup(fd)
        tracked["parent_close"] = duplicate
        return duplicate

    def fail_selected_close(fd: int) -> None:
        kind = next((name for name, value in tracked.items() if value == fd), None)
        if kind is not None:
            attempts.append(kind)
        original_close(fd)
        if kind == failure_kind:
            raise OSError(f"synthetic {kind} failure")

    def fail_selected_unlock(fd: int, operation_flag: int) -> None:
        original_flock(fd, operation_flag)
        if operation_flag == vault_module.fcntl.LOCK_UN:
            attempts.append("lock_un")
            if failure_kind == "lock_un":
                raise OSError("synthetic unlock failure")

    monkeypatch.setattr(vault_module.os, "open", track_open)
    monkeypatch.setattr(vault_module.os, "dup", track_dup)
    monkeypatch.setattr(vault_module.os, "close", fail_selected_close)
    monkeypatch.setattr(vault_module.fcntl, "flock", fail_selected_unlock)

    if operation == "store":
        token = bytearray(b"cleanup-store-marker")
        code = _error_code(lambda: _store(vault, manager, token=token, generation=1))
        expected = "credential.inventory_token_vault_write_failed"
        assert token == bytearray(len(token))
    else:
        code = _error_code(lambda: _delete(vault, manager, generation=1))
        expected = "credential.inventory_token_vault_delete_failed"

    assert code == expected
    assert failure_kind in attempts
    assert "lock_un" in attempts
    assert "lock_close" in attempts
    assert "parent_close" in attempts
    assert attempts.count(failure_kind) == 1
    assert not vault_module._IN_PROCESS_LOCKS


def test_multiple_cleanup_failures_continue_and_primary_error_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    before = (tmp_path / "tokens" / "test-account.json").read_bytes()
    original_open = vault_module.os.open
    original_dup = vault_module.os.dup
    original_close = vault_module.os.close
    original_flock = vault_module.fcntl.flock
    original_unlink = vault_module.os.unlink
    tracked: dict[str, int] = {}
    failures: list[str] = []

    def track_open(path: object, *args: object, **kwargs: object) -> int:
        fd = original_open(path, *args, **kwargs)
        if os.fspath(path) == "test-account.lock":  # type: ignore[arg-type]
            tracked["lock_close"] = fd
        return fd

    def track_dup(fd: int) -> int:
        duplicate = original_dup(fd)
        tracked["parent_close"] = duplicate
        return duplicate

    def fail_close(fd: int) -> None:
        kind = next((name for name, value in tracked.items() if value == fd), None)
        original_close(fd)
        if kind is not None:
            failures.append(kind)
            raise OSError(f"synthetic {kind} failure")

    def fail_unlock(fd: int, operation_flag: int) -> None:
        original_flock(fd, operation_flag)
        if operation_flag == vault_module.fcntl.LOCK_UN:
            failures.append("lock_un")
            raise OSError("synthetic unlock failure")

    def fail_replace(*args: object, **kwargs: object) -> None:
        raise OSError("synthetic primary replace failure")

    def fail_temp_unlink(path: object, *args: object, **kwargs: object) -> None:
        original_unlink(path, *args, **kwargs)
        path_text = os.fspath(path)  # type: ignore[arg-type]
        if type(path_text) is str and path_text.endswith(".tmp"):
            failures.append("temp_unlink")
            raise OSError("synthetic temp unlink failure")

    monkeypatch.setattr(vault_module.os, "open", track_open)
    monkeypatch.setattr(vault_module.os, "dup", track_dup)
    monkeypatch.setattr(vault_module.os, "close", fail_close)
    monkeypatch.setattr(vault_module.os, "replace", fail_replace)
    monkeypatch.setattr(vault_module.os, "unlink", fail_temp_unlink)
    monkeypatch.setattr(vault_module.fcntl, "flock", fail_unlock)

    token = bytearray(b"multi-cleanup-secret")
    assert (
        _error_code(lambda: _store(vault, manager, token=token, generation=1))
        == "credential.inventory_token_vault_write_failed"
    )
    assert token == bytearray(len(token))
    assert failures == ["temp_unlink", "lock_un", "lock_close", "parent_close"]
    assert (tmp_path / "tokens" / "test-account.json").read_bytes() == before
    assert not list((tmp_path / "tokens").glob(".test-account.*.tmp"))
    assert not vault_module._IN_PROCESS_LOCKS


@pytest.mark.parametrize("operation", ("store", "delete"))
def test_cleanup_errors_have_fully_redacted_error_graphs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    account_marker = f"{operation}-cleanup-account-marker"
    subject_marker = f"{operation}-cleanup-subject-marker"
    token_marker = f"{operation}-cleanup-token-marker"
    vault = _vault(tmp_path)
    manager = _manager(
        tmp_path,
        account_ref=account_marker,
        subject_id=subject_marker,
        login_email=f"{operation}-cleanup-login-marker@example.test",
    )
    if operation == "delete":
        _store(
            vault,
            manager,
            account_ref=account_marker,
            subject_id=subject_marker,
        )
    original_dup = vault_module.os.dup
    original_close = vault_module.os.close
    parent_fd: int | None = None

    def track_dup(fd: int) -> int:
        nonlocal parent_fd
        parent_fd = original_dup(fd)
        return parent_fd

    def fail_parent_close(fd: int) -> None:
        original_close(fd)
        if fd == parent_fd:
            raise OSError("synthetic parent close failure")

    monkeypatch.setattr(vault_module.os, "dup", track_dup)
    monkeypatch.setattr(vault_module.os, "close", fail_parent_close)
    try:
        if operation == "store":
            vault.store_inventory_refresh_token(
                manager,
                account_ref=account_marker,
                subject_id=subject_marker,
                oauth_client_fingerprint=_client_fingerprint(),
                refresh_token=bytearray(token_marker.encode("ascii")),
                expected_vault_generation=None,
            )
        else:
            vault.delete_inventory_refresh_token(
                manager,
                account_ref=account_marker,
                subject_id=subject_marker,
                oauth_client_fingerprint=_client_fingerprint(),
                expected_vault_generation=1,
            )
    except GoogleInventoryReadonlyTokenVaultError as caught:
        error = caught
    else:
        raise AssertionError("expected cleanup failure")

    _assert_error_graph_redacted(
        error,
        markers=(account_marker, subject_marker, token_marker),
    )


def test_error_constructor_rejects_marker_without_retaining_it_in_product_frame() -> (
    None
):
    marker = "invalid-error-code-marker"
    try:
        GoogleInventoryReadonlyTokenVaultError(marker)
    except TypeError as caught:
        error = caught
    else:
        raise AssertionError("expected constructor rejection")

    _assert_error_graph_redacted(error, markers=(marker,))


def test_subprocess_parent_directory_rename_swap_fails_before_child_access(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    tokens = tmp_path / "tokens"
    old_tokens = tmp_path / "tokens-before-race"
    before = (tokens / "test-account.json").read_bytes()
    foreign = b"foreign-parent-swap-record"

    def swap_parent() -> None:
        tokens.rename(old_tokens)
        tokens.mkdir(mode=0o700)
        tokens.chmod(0o700)
        (tokens / "test-account.json").write_bytes(foreign)
        (tokens / "test-account.json").chmod(0o600)

    result, zeroized = _run_raced_mutation(
        vault,
        manager,
        barrier="parent",
        operation="store",
        mutate=swap_parent,
    )

    assert result == ("error", "credential.inventory_token_vault_path_invalid")
    assert zeroized
    assert (old_tokens / "test-account.json").read_bytes() == before
    assert (tokens / "test-account.json").read_bytes() == foreign
    _assert_no_race_secret(old_tokens)
    _assert_no_race_secret(tokens)


def test_subprocess_lockfile_unlink_replace_fails_after_flock(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    tokens = tmp_path / "tokens"
    record = tokens / "test-account.json"
    before = record.read_bytes()
    lock = tokens / "test-account.lock"
    foreign = b"foreign-lock-inode"

    def swap_lock() -> None:
        lock.unlink()
        lock.write_bytes(foreign)
        lock.chmod(0o600)

    result, zeroized = _run_raced_mutation(
        vault,
        manager,
        barrier="lock",
        operation="store",
        mutate=swap_lock,
    )

    assert result == ("error", "credential.inventory_token_vault_path_invalid")
    assert zeroized
    assert record.read_bytes() == before
    assert lock.read_bytes() == foreign
    _assert_no_race_secret(tokens)


@pytest.mark.parametrize("operation", ("store", "delete"))
def test_subprocess_record_rename_replace_is_detected_at_pre_mutation_attestation(
    tmp_path: Path, operation: str
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    tokens = tmp_path / "tokens"
    record = tokens / "test-account.json"
    moved = tokens / "record-before-race"
    before = record.read_bytes()
    foreign = b"foreign-record-inode"

    def swap_record() -> None:
        record.rename(moved)
        record.write_bytes(foreign)
        record.chmod(0o600)

    result, zeroized = _run_raced_mutation(
        vault,
        manager,
        barrier="record",
        operation=operation,
        mutate=swap_record,
    )

    assert result == ("error", "credential.inventory_token_vault_path_invalid")
    if operation == "store":
        assert zeroized
    assert moved.read_bytes() == before
    assert record.read_bytes() == foreign
    _assert_no_race_secret(tokens)


@pytest.mark.parametrize("operation", ("store", "delete"))
def test_subprocess_record_hardlink_race_fails_after_parse(
    tmp_path: Path, operation: str
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    tokens = tmp_path / "tokens"
    record = tokens / "test-account.json"
    linked = tokens / "record-race-hardlink"
    before = record.read_bytes()

    def add_hardlink() -> None:
        os.link(record, linked)

    result, zeroized = _run_raced_mutation(
        vault,
        manager,
        barrier="record",
        operation=operation,
        mutate=add_hardlink,
    )

    assert result == ("error", "credential.inventory_token_vault_permissions")
    if operation == "store":
        assert zeroized
    assert record.read_bytes() == before
    assert linked.read_bytes() == before
    _assert_no_race_secret(tokens)


def test_subprocess_temp_name_swap_is_detected_at_pre_rename_attestation(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    tokens = tmp_path / "tokens"
    record = tokens / "test-account.json"
    before = record.read_bytes()
    foreign = b"foreign-temp-inode"
    swapped_temp: list[Path] = []

    def swap_temp() -> None:
        matches = list(tokens.glob(".test-account.*.tmp"))
        assert len(matches) == 1
        temporary = matches[0]
        temporary.unlink()
        temporary.write_bytes(foreign)
        temporary.chmod(0o600)
        swapped_temp.append(temporary)

    result, zeroized = _run_raced_mutation(
        vault,
        manager,
        barrier="temp",
        operation="store",
        mutate=swap_temp,
    )

    assert result == ("error", "credential.inventory_token_vault_path_invalid")
    assert zeroized
    assert record.read_bytes() == before
    assert swapped_temp[0].read_bytes() == foreign
    _assert_no_race_secret(tokens)


@pytest.mark.parametrize(
    "fault",
    ("write", "fsync", "temp_close", "replace", "temp_cleanup"),
)
def test_every_pre_rename_failure_preserves_old_record_cleans_temp_and_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager)
    tokens = tmp_path / "tokens"
    record = tokens / "test-account.json"
    before = record.read_bytes()
    original_open = vault_module.os.open
    original_write = vault_module.os.write
    original_fsync = vault_module.os.fsync
    original_close = vault_module.os.close
    original_replace = vault_module.os.replace
    original_unlink = vault_module.os.unlink
    temp_fd: int | None = None
    injected = False
    cleanup_attempted = False

    def track_open(path: object, *args: object, **kwargs: object) -> int:
        nonlocal temp_fd
        fd = original_open(path, *args, **kwargs)
        path_text = os.fspath(path)  # type: ignore[arg-type]
        if type(path_text) is str and path_text.endswith(".tmp"):
            temp_fd = fd
        return fd

    def fail_write(fd: int, payload: object) -> int:
        nonlocal injected
        if fault == "write" and fd == temp_fd and not injected:
            injected = True
            raise OSError("synthetic write failure")
        return original_write(fd, payload)  # type: ignore[arg-type]

    def fail_fsync(fd: int) -> None:
        nonlocal injected
        if fault == "fsync" and fd == temp_fd and not injected:
            injected = True
            raise OSError("synthetic fsync failure")
        original_fsync(fd)

    def fail_close(fd: int) -> None:
        nonlocal injected
        original_close(fd)
        if fault == "temp_close" and fd == temp_fd and not injected:
            injected = True
            raise OSError("synthetic temp close failure")

    def fail_replace(*args: object, **kwargs: object) -> None:
        nonlocal injected
        if fault in ("replace", "temp_cleanup") and not injected:
            injected = True
            raise OSError("synthetic replace failure")
        original_replace(*args, **kwargs)

    def fail_cleanup(path: object, *args: object, **kwargs: object) -> None:
        nonlocal cleanup_attempted
        original_unlink(path, *args, **kwargs)
        path_text = os.fspath(path)  # type: ignore[arg-type]
        if (
            fault == "temp_cleanup"
            and type(path_text) is str
            and path_text.endswith(".tmp")
        ):
            cleanup_attempted = True
            raise OSError("synthetic temp cleanup failure")

    monkeypatch.setattr(vault_module.os, "open", track_open)
    monkeypatch.setattr(vault_module.os, "write", fail_write)
    monkeypatch.setattr(vault_module.os, "fsync", fail_fsync)
    monkeypatch.setattr(vault_module.os, "close", fail_close)
    monkeypatch.setattr(vault_module.os, "replace", fail_replace)
    monkeypatch.setattr(vault_module.os, "unlink", fail_cleanup)
    token_marker = b"all-pre-rename-secret-marker"
    token = bytearray(token_marker)

    assert (
        _error_code(lambda: _store(vault, manager, token=token, generation=1))
        == "credential.inventory_token_vault_write_failed"
    )
    assert injected
    if fault == "temp_cleanup":
        assert cleanup_attempted
    assert token == bytearray(len(token))
    assert record.read_bytes() == before
    assert not list(tokens.glob(".test-account.*.tmp"))
    _assert_no_race_secret(tokens, token_marker)
    assert not vault_module._IN_PROCESS_LOCKS

    monkeypatch.undo()
    assert _store(vault, manager, generation=1).vault_generation == 2


@pytest.mark.parametrize(
    "invalid_b64",
    (
        "YR==",
        "YQ",
        "YQ===",
        "YQ==\n",
        " YQ==",
    ),
)
def test_noncanonical_base64_forms_fail_through_record_product_path(
    tmp_path: Path, invalid_b64: str
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    _store(vault, manager, token=bytearray(b"a"))
    path = tmp_path / "tokens" / "test-account.json"
    record = _record(tmp_path)
    record["refresh_token_b64"] = invalid_b64
    path.write_text(json.dumps(record), encoding="utf-8")
    path.chmod(0o600)

    assert _error_code(lambda: _store(vault, manager, generation=1)) == (
        "credential.inventory_token_vault_token_invalid"
    )


def test_token_size_boundaries_round_trip_through_record_product_path(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    maximum = bytearray(b"x" * vault_module._MAX_TOKEN_BYTES)

    assert _store(vault, manager, token=maximum).vault_generation == 1
    assert maximum == bytearray(vault_module._MAX_TOKEN_BYTES)
    assert _store(vault, manager, generation=1).vault_generation == 2

    path = tmp_path / "tokens" / "test-account.json"
    record = _record(tmp_path)
    record["refresh_token_b64"] = base64.b64encode(
        b"x" * (vault_module._MAX_TOKEN_BYTES + 1)
    ).decode("ascii")
    path.write_text(json.dumps(record), encoding="utf-8")
    path.chmod(0o600)
    assert _error_code(lambda: _store(vault, manager, generation=2)) == (
        "credential.inventory_token_vault_token_invalid"
    )


def test_different_account_refs_do_not_share_a_global_process_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault_module._IN_PROCESS_LOCKS.clear()
    vault = _vault(tmp_path)
    manager = _manager_for_accounts(
        tmp_path,
        (
            ("account-a", "subject-a", "a@example.test"),
            ("account-b", "subject-b", "b@example.test"),
        ),
    )
    entered = threading.Event()
    release = threading.Event()
    original_write_record = vault_module._write_record

    def block_account_a(*args: object, **kwargs: object) -> str | None:
        record_name = args[1]
        if os.fspath(record_name) == "account-a.json":  # type: ignore[arg-type]
            entered.set()
            assert release.wait(timeout=5)
        return original_write_record(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(vault_module, "_write_record", block_account_a)
    first_result: list[object] = []

    def store_account_a() -> None:
        try:
            first_result.append(
                _store(
                    vault,
                    manager,
                    account_ref="account-a",
                    subject_id="subject-a",
                )
            )
        except GoogleInventoryReadonlyTokenVaultError as error:
            first_result.append(error.code)

    first = threading.Thread(target=store_account_a)
    first.start()
    try:
        assert entered.wait(timeout=5)
        second = _store(
            vault,
            manager,
            account_ref="account-b",
            subject_id="subject-b",
        )
        assert second.vault_generation == 1
    finally:
        release.set()
        first.join(timeout=5)

    assert not first.is_alive()
    assert len(first_result) == 1 and hasattr(first_result[0], "vault_generation")
    assert not vault_module._IN_PROCESS_LOCKS


def test_registry_stays_empty_across_many_validation_error_and_reload_like_cycles(
    tmp_path: Path,
) -> None:
    vault_module._IN_PROCESS_LOCKS.clear()
    for index in range(24):
        cycle = tmp_path / f"cycle-{index}"
        cycle.mkdir(mode=0o700)
        account_ref = f"cycle-account-{index}"
        subject_id = f"cycle-subject-{index}"
        vault = _vault(cycle)
        manager = _manager(
            cycle,
            account_ref=account_ref,
            subject_id=subject_id,
            login_email=f"cycle-{index}@example.test",
        )
        assert (
            _store(
                vault,
                manager,
                account_ref=account_ref,
                subject_id=subject_id,
            ).vault_generation
            == 1
        )
        assert (
            _error_code(
                lambda: _delete(
                    vault,
                    manager,
                    generation=2,
                    account_ref=account_ref,
                    subject_id=subject_id,
                )
            )
            == "credential.inventory_token_vault_generation_conflict"
        )
        assert _delete(
            vault,
            manager,
            generation=1,
            account_ref=account_ref,
            subject_id=subject_id,
        ).removed
        assert (
            _error_code(
                lambda: _store(
                    vault,
                    manager,
                    account_ref=account_ref,
                    subject_id=subject_id,
                    token=bytearray(),
                )
            )
            == "credential.inventory_token_vault_request_invalid"
        )
        manager.close()
        assert not vault_module._IN_PROCESS_LOCKS


def test_parent_fd_capability_mode_change_fails_before_child_access(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    token = bytearray(b"parent-mode-secret-marker")
    tmp_path.chmod(0o770)
    try:
        assert _error_code(lambda: _store(vault, manager, token=token)) == (
            "credential.inventory_token_vault_permissions"
        )
        assert token == bytearray(len(token))
        assert not (tmp_path / "tokens" / "test-account.lock").exists()
        assert not (tmp_path / "tokens" / "test-account.json").exists()
    finally:
        tmp_path.chmod(0o700)


def test_tokens_parent_close_failure_does_not_skip_root_parent_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path)
    manager = _manager(tmp_path)
    original_dup = vault_module.os.dup
    original_open = vault_module.os.open
    original_close = vault_module.os.close
    root_fd: int | None = None
    tokens_fd: int | None = None
    closes: list[str] = []

    def track_dup(fd: int) -> int:
        nonlocal root_fd
        root_fd = original_dup(fd)
        return root_fd

    def track_open(path: object, *args: object, **kwargs: object) -> int:
        nonlocal tokens_fd
        fd = original_open(path, *args, **kwargs)
        if os.fspath(path) == "tokens":  # type: ignore[arg-type]
            tokens_fd = fd
        return fd

    def fail_tokens_close(fd: int) -> None:
        if fd == tokens_fd:
            closes.append("tokens")
            original_close(fd)
            raise OSError("synthetic tokens parent close failure")
        if fd == root_fd:
            closes.append("root")
        original_close(fd)

    monkeypatch.setattr(vault_module.os, "dup", track_dup)
    monkeypatch.setattr(vault_module.os, "open", track_open)
    monkeypatch.setattr(vault_module.os, "close", fail_tokens_close)
    token = bytearray(b"parent-close-secret-marker")

    assert _error_code(lambda: _store(vault, manager, token=token)) == (
        "credential.inventory_token_vault_write_failed"
    )
    assert token == bytearray(len(token))
    assert closes == ["tokens", "root"]


def test_vault_public_surface_remains_store_delete_only(tmp_path: Path) -> None:
    vault = _vault(tmp_path)

    assert {name for name in dir(vault) if not name.startswith("_")} == {
        "delete_inventory_refresh_token",
        "store_inventory_refresh_token",
    }
    with pytest.raises(TypeError):
        GoogleInventoryReadonlyTokenVault._for_test_tokens_parent_directory_fd(tmp_path)


@pytest.mark.parametrize("operation", ("store", "delete"))
def test_unexpected_record_binding_error_is_fresh_and_fully_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    account_marker = f"{operation}-unexpected-account-marker"
    subject_marker = f"{operation}-unexpected-subject-marker"
    token_marker = f"{operation}-unexpected-token-marker"
    vault = _vault(tmp_path)
    manager = _manager(
        tmp_path,
        account_ref=account_marker,
        subject_id=subject_marker,
        login_email=f"{operation}-unexpected-login-marker@example.test",
    )
    _store(
        vault,
        manager,
        account_ref=account_marker,
        subject_id=subject_marker,
    )

    def fail_binding(*args: object, **kwargs: object) -> str | None:
        raise RuntimeError("synthetic fixed binding failure")

    monkeypatch.setattr(vault_module, "_record_binding_code", fail_binding)
    token = bytearray(token_marker.encode("ascii"))
    try:
        if operation == "store":
            _store(
                vault,
                manager,
                token=token,
                generation=1,
                account_ref=account_marker,
                subject_id=subject_marker,
            )
        else:
            _delete(
                vault,
                manager,
                generation=1,
                account_ref=account_marker,
                subject_id=subject_marker,
            )
    except GoogleInventoryReadonlyTokenVaultError as caught:
        error = caught
    else:
        raise AssertionError("expected fixed vault error")

    assert error.code == (
        "credential.inventory_token_vault_write_failed"
        if operation == "store"
        else "credential.inventory_token_vault_delete_failed"
    )
    if operation == "store":
        assert token == bytearray(len(token))
    _assert_error_graph_redacted(
        error,
        markers=(account_marker, subject_marker, token_marker),
    )
    assert not vault_module._IN_PROCESS_LOCKS
