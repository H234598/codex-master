from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import json
import itertools
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import threading
import time
from dataclasses import replace

import pytest

import codex_master.openai_credential_service as service_module
from codex_master.credential_vault import CredentialVault, CredentialVaultError
from codex_master.openai_credential_service import (
    AuthorizedAuthIngress,
    OpenAIAccountIdentity,
    OpenAICredentialError,
    OpenAICredentialService,
    OpenAIAuthReceiptStore,
    OpenAIIdentitySource,
)


KEY = b"k" * 32
INGRESS_AUTHORITY = object()
SECRET_MARKER = "super-secret-auth-marker"


class Clock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def auth_json(account_id: str, *, marker: str = SECRET_MARKER) -> bytes:
    return json.dumps(
        {
            "last_refresh": "2026-08-28T12:00:00Z",
            "tokens": {
                "refresh_token": f"refresh-{marker}",
                "account_id": account_id,
                "access_token": f"access-{marker}",
                "id_token": f"id-{marker}",
            },
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": None,
        },
        indent=2,
    ).encode("utf-8")


def make_service(
    tmp_path: Path,
    *,
    clock: Clock | None = None,
    registered_backend: str = "acct-one",
    identity_generation: int = 2,
) -> OpenAICredentialService:
    vault = CredentialVault.for_test(tmp_path / "vault", key=KEY, clock=clock)
    nonce_counter = itertools.count(1)
    return OpenAICredentialService(
        vault,
        OpenAIIdentitySource(
            tmp_path / "identities",
            initial_identities={
                "openai-one": OpenAIAccountIdentity(
                    enabled=True,
                    backend_account_id=registered_backend,
                    generation=identity_generation,
                )
            },
        ),
        OpenAIAuthReceiptStore(tmp_path / "receipts"),
        ingress_authority=INGRESS_AUTHORITY,
        clock=clock,
        nonce_factory=lambda: next(nonce_counter).to_bytes(32, "big"),
    )


def ingress(plan: object, raw: bytes) -> AuthorizedAuthIngress:
    return AuthorizedAuthIngress.issue(INGRESS_AUTHORITY, plan, raw)


def synced_service(
    tmp_path: Path, *, clock: Clock | None = None
) -> OpenAICredentialService:
    service = make_service(tmp_path, clock=clock)
    plan = service.plan_auth_sync(
        "openai-one",
        expected_generation=2,
        idempotency_key="sync-one",
        ttl_seconds=60,
    )
    service.apply_auth_sync(plan, ingress(plan, auth_json("acct-one")))
    return service


def open_private_runtime(path: Path) -> int:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )


def write_materialization_claim(
    service: OpenAICredentialService,
    runtime: Path,
    *,
    legacy_v1: bool,
    token: str,
    expires_at: float,
) -> Path:
    runtime_stat = runtime.stat()
    target = runtime / "auth.json"
    target.write_bytes(auth_json("acct-one"))
    target.chmod(0o600)
    target_stat = target.stat()
    claim = {
        "account_ref": "openai-one",
        "directory_metadata": [
            runtime_stat.st_dev,
            runtime_stat.st_ino,
            runtime_stat.st_mode,
            runtime_stat.st_uid,
            runtime_stat.st_gid,
            runtime_stat.st_nlink,
        ],
        "directory_path": str(runtime),
        "expires_at": expires_at,
        "file_metadata": [
            target_stat.st_dev,
            target_stat.st_ino,
            target_stat.st_mode,
            target_stat.st_uid,
            target_stat.st_gid,
            target_stat.st_nlink,
            target_stat.st_size,
            target_stat.st_mtime_ns,
            target_stat.st_ctime_ns,
        ],
        "generation": 2,
        "owner_boot_id": service._vault._owner_boot_id,  # noqa: SLF001
        "owner_pid": service._vault._process_id,  # noqa: SLF001
        "owner_start_ticks": service._vault._owner_start_ticks,  # noqa: SLF001
        "state": "published",
        "token": token,
    }
    if not legacy_v1:
        temporary_name = f".auth.json.{token}.tmp"
        claim["temporary_name"] = temporary_name
        os.setxattr(target, "user.codex_master_claim", token.encode("ascii"))
    raw = (
        json.dumps(
            {"claims": [claim], "schema_version": 1},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    with service._vault._state.locked():  # noqa: SLF001
        service._vault._state.replace_private_bytes(  # noqa: SLF001
            PurePosixPath("materialization-claims.json"), raw
        )
    return target


def assert_private_values_absent(rendered: str, *values: str) -> None:
    if any(value in rendered for value in values):
        pytest.fail("private value exposed", pytrace=False)


def test_forged_plan_is_rejected_and_upload_is_closed(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    plan = service.plan_auth_sync(
        "openai-one",
        expected_generation=2,
        idempotency_key="object-bound",
        ttl_seconds=60,
    )
    forged = replace(plan)
    upload = ingress(forged, auth_json("acct-one"))

    with pytest.raises(OpenAICredentialError, match="control.plan_stale"):
        service.apply_auth_sync(forged, upload)

    assert upload.closed
    assert not any(upload._payload)  # noqa: SLF001


def test_identity_and_expiry_are_rechecked_under_guard_through_vault_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    source = OpenAIIdentitySource(
        tmp_path / "identities",
        initial_identities={
            "openai-one": OpenAIAccountIdentity(
                enabled=True, backend_account_id="acct-one", generation=2
            )
        },
    )
    vault = CredentialVault.for_test(tmp_path / "vault", key=KEY, clock=clock)
    service = OpenAICredentialService(
        vault,
        source,
        OpenAIAuthReceiptStore(tmp_path / "receipts"),
        ingress_authority=INGRESS_AUTHORITY,
        clock=clock,
        nonce_factory=lambda: b"n" * 32,
    )
    plan = service.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="guarded", ttl_seconds=5
    )
    real_validate = service_module.validate_openai_auth_json

    def rebind_during_parse(
        raw: bytes | bytearray, *, expected_account_id: str
    ) -> bytes:
        result = real_validate(raw, expected_account_id=expected_account_id)
        source.set_identity(
            "openai-one",
            OpenAIAccountIdentity(
                enabled=True, backend_account_id="acct-two", generation=3
            ),
        )
        clock.value = 106.0
        return result

    monkeypatch.setattr(
        service_module, "validate_openai_auth_json", rebind_during_parse
    )
    with pytest.raises(OpenAICredentialError, match="control.plan_stale"):
        service.apply_auth_sync(plan, ingress(plan, auth_json("acct-one")))
    with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
        vault.lease("openai-one", expected_generation=2, ttl_seconds=30)


def test_plan_expiry_crossing_durable_intent_boundary_never_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    service = make_service(tmp_path, clock=clock)
    plan = service.plan_auth_sync(
        "openai-one",
        expected_generation=2,
        idempotency_key="late-expiry",
        ttl_seconds=5,
    )
    real_begin = OpenAIAuthReceiptStore.begin

    def expire_after_begin(store: OpenAIAuthReceiptStore, candidate: object) -> str:
        result = real_begin(store, candidate)  # type: ignore[arg-type]
        clock.value = 106.0
        return result

    monkeypatch.setattr(OpenAIAuthReceiptStore, "begin", expire_after_begin)
    with pytest.raises(OpenAICredentialError, match="control.plan_stale"):
        service.apply_auth_sync(plan, ingress(plan, auth_json("acct-one")))
    with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
        service._vault.lease(  # noqa: SLF001
            "openai-one", expected_generation=2, ttl_seconds=30
        )


def test_durable_idempotent_replay_after_restart_does_not_write_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = make_service(tmp_path)
    plan = first.plan_auth_sync(
        "openai-one",
        expected_generation=2,
        idempotency_key="restart-retry",
        ttl_seconds=60,
    )
    receipt = first.apply_auth_sync(plan, ingress(plan, auth_json("acct-one")))

    restarted = make_service(tmp_path)
    replay = restarted.plan_auth_sync(
        "openai-one",
        expected_generation=2,
        idempotency_key="restart-retry",
        ttl_seconds=60,
    )

    def forbidden_store(*_args: object, **_kwargs: object) -> None:
        pytest.fail("durable replay performed second vault write")

    monkeypatch.setattr(CredentialVault, "store_projection", forbidden_store)
    upload = ingress(replay, auth_json("acct-one"))
    assert restarted.apply_auth_sync(replay, upload) == receipt
    assert upload.closed


def test_idempotency_collision_and_durable_running_ambiguity_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = make_service(tmp_path)
    plan = service.plan_auth_sync(
        "openai-one",
        expected_generation=2,
        idempotency_key="durable-intent",
        ttl_seconds=60,
    )
    with pytest.raises(OpenAICredentialError, match="control.idempotency_conflict"):
        service._receipts.plan(  # noqa: SLF001 - exercises durable collision CAS
            {
                "account_ref": "openai-one",
                "expected_generation": 3,
                "expires_at": plan.expires_at,
                "idempotency_key": "durable-intent",
                "nonce": plan.nonce,
                "plan_digest": plan.plan_digest,
            }
        )

    with monkeypatch.context() as context:
        context.setattr(
            CredentialVault,
            "store_projection",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
        with pytest.raises(KeyboardInterrupt):
            service.apply_auth_sync(plan, ingress(plan, auth_json("acct-one")))

    restarted = make_service(tmp_path)
    replay = restarted.plan_auth_sync(
        "openai-one",
        expected_generation=2,
        idempotency_key="durable-intent",
        ttl_seconds=60,
    )
    upload = ingress(replay, auth_json("acct-one"))
    with pytest.raises(OpenAICredentialError, match="control.operation_ambiguous"):
        restarted.apply_auth_sync(replay, upload)
    assert upload.closed


def test_concurrent_shared_idempotency_key_performs_one_vault_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = make_service(tmp_path)
    second = make_service(tmp_path)
    first_plan = first.plan_auth_sync(
        "openai-one",
        expected_generation=2,
        idempotency_key="concurrent-retry",
        ttl_seconds=60,
    )
    second_plan = second.plan_auth_sync(
        "openai-one",
        expected_generation=2,
        idempotency_key="concurrent-retry",
        ttl_seconds=60,
    )
    real_store = CredentialVault.store_projection
    writes = 0
    write_lock = threading.Lock()
    barrier = threading.Barrier(3)
    results: list[str] = []

    def counted_store(
        vault: CredentialVault, account_ref: str, generation: int, payload: bytes
    ) -> None:
        nonlocal writes
        with write_lock:
            writes += 1
        real_store(vault, account_ref, generation, payload)

    monkeypatch.setattr(CredentialVault, "store_projection", counted_store)

    def apply(service: OpenAICredentialService, plan: object) -> None:
        barrier.wait()
        try:
            service.apply_auth_sync(plan, ingress(plan, auth_json("acct-one")))  # type: ignore[arg-type]
            results.append("succeeded")
        except OpenAICredentialError as exc:
            results.append(exc.code)

    threads = [
        threading.Thread(target=apply, args=(first, first_plan)),
        threading.Thread(target=apply, args=(second, second_plan)),
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=2)

    assert writes == 1
    assert results.count("succeeded") >= 1
    assert set(results) <= {"succeeded", "control.operation_ambiguous"}


def test_ingress_close_context_and_rejected_replay_zero_payload(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    plan = service.plan_auth_sync(
        "openai-one",
        expected_generation=2,
        idempotency_key="close-boundary",
        ttl_seconds=60,
    )
    with ingress(plan, auth_json("acct-one")) as upload:
        assert not upload.closed
    assert upload.closed
    assert not any(upload._payload)  # noqa: SLF001

    applied = ingress(plan, auth_json("acct-one"))
    service.apply_auth_sync(plan, applied)
    retry = ingress(plan, auth_json("acct-one"))
    service.apply_auth_sync(plan, retry)
    assert retry.closed
    assert not any(retry._payload)  # noqa: SLF001


def test_auth_sync_rejects_different_openai_account_without_vault_mutation(
    tmp_path: Path,
) -> None:
    service = make_service(tmp_path, registered_backend="acct-one")
    plan = service.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="mismatch", ttl_seconds=60
    )
    upload = ingress(plan, auth_json("acct-two"))

    with pytest.raises(OpenAICredentialError, match="oauth.identity_mismatch"):
        service.apply_auth_sync(plan, upload)
    with pytest.raises(OpenAICredentialError, match="credential.upload_expired"):
        service.apply_auth_sync(plan, upload)
    with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
        service._vault.lease(  # noqa: SLF001 - verifies no mutation at trust boundary
            "openai-one", expected_generation=2, ttl_seconds=30
        )


def test_plan_is_bound_to_account_generation_expiry_nonce_digest_and_provenance(
    tmp_path: Path,
) -> None:
    first = make_service(tmp_path / "first", clock=Clock(), identity_generation=7)
    second = make_service(tmp_path / "second", clock=Clock(), identity_generation=7)
    plan = first.plan_auth_sync(
        "openai-one",
        expected_generation=7,
        idempotency_key="provenance",
        ttl_seconds=60,
    )

    assert plan.account_ref == "openai-one"
    assert plan.expected_generation == 7
    assert plan.expires_at == 160.0
    assert plan.nonce == "00" * 31 + "01"
    assert len(plan.plan_digest) == 64
    assert SECRET_MARKER not in repr(plan)
    with pytest.raises(OpenAICredentialError, match="control.plan_stale"):
        second.apply_auth_sync(plan, ingress(plan, auth_json("acct-one")))


def test_apply_is_idempotent_and_generation_cas_blocks_competing_plan(
    tmp_path: Path,
) -> None:
    service = make_service(tmp_path)
    first = service.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="first", ttl_seconds=60
    )
    first_ingress = ingress(first, auth_json("acct-one"))
    receipt = service.apply_auth_sync(first, first_ingress)

    assert service.apply_auth_sync(first, first_ingress) is receipt
    competing = service.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="competing", ttl_seconds=60
    )
    with pytest.raises(OpenAICredentialError, match="credential.generation_conflict"):
        service.apply_auth_sync(
            competing, ingress(competing, auth_json("acct-one", marker="other"))
        )


def test_expired_plan_and_wrong_ingress_provenance_fail_before_vault_write(
    tmp_path: Path,
) -> None:
    clock = Clock()
    service = make_service(tmp_path, clock=clock)
    plan = service.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="expired", ttl_seconds=5
    )
    clock.value = 106.0

    with pytest.raises(OpenAICredentialError, match="control.plan_stale"):
        service.apply_auth_sync(plan, ingress(plan, auth_json("acct-one")))

    fresh = service.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="foreign", ttl_seconds=5
    )
    foreign = AuthorizedAuthIngress.issue(object(), fresh, auth_json("acct-one"))
    with pytest.raises(OpenAICredentialError, match="credential.upload_expired"):
        service.apply_auth_sync(fresh, foreign)


@pytest.mark.parametrize(
    "field,value",
    [
        ("account_ref", "../openai-one"),
        ("expected_generation", True),
        ("expected_generation", 0),
        ("expected_generation", 2**63),
        ("ttl_seconds", True),
        ("ttl_seconds", 0),
        ("ttl_seconds", 301),
    ],
)
def test_plan_rejects_bool_limits_and_pathlike_account_refs(
    tmp_path: Path, field: str, value: object
) -> None:
    service = make_service(tmp_path)
    arguments: dict[str, object] = {
        "account_ref": "openai-one",
        "expected_generation": 2,
        "idempotency_key": "invalid-input",
        "ttl_seconds": 60,
    }
    arguments[field] = value

    with pytest.raises(OpenAICredentialError, match="control.request_invalid"):
        service.plan_auth_sync(**arguments)  # type: ignore[arg-type]


def test_materialized_auth_is_private_fixed_and_removed_on_close(
    tmp_path: Path,
) -> None:
    service = synced_service(tmp_path)
    runtime = tmp_path / "runtime"
    runtime_fd = open_private_runtime(runtime)
    try:
        with service.materialize_auth_lease(
            "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
        ) as relative:
            assert relative == PurePosixPath("auth.json")
            info = os.stat(relative, dir_fd=runtime_fd, follow_symlinks=False)
            assert stat.S_ISREG(info.st_mode)
            assert stat.S_IMODE(info.st_mode) == 0o600
            assert info.st_nlink == 1
            fd = os.open(relative, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=runtime_fd)
            try:
                raw = os.read(fd, 1024 * 1024 + 1)
            finally:
                os.close(fd)
            expected = (
                json.dumps(
                    json.loads(auth_json("acct-one")),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii")
            assert hmac.compare_digest(
                hashlib.sha256(raw).digest(), hashlib.sha256(expected).digest()
            )
        with pytest.raises(FileNotFoundError):
            os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        os.close(runtime_fd)


def test_materialized_auth_cleanup_runs_for_baseexception(tmp_path: Path) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    try:
        with pytest.raises(KeyboardInterrupt):
            with service.materialize_auth_lease(
                "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
            ):
                raise KeyboardInterrupt
        with pytest.raises(FileNotFoundError):
            os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        os.close(runtime_fd)


def test_live_materialization_is_removed_before_revoke_returns(tmp_path: Path) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    try:
        with service.materialize_auth_lease(
            "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
        ):
            service._vault.revoke_account(  # noqa: SLF001 - adversarial race boundary
                "openai-one", expected_generation=2
            )
            with pytest.raises(FileNotFoundError):
                os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        os.close(runtime_fd)


def test_live_materialization_is_removed_at_lease_ttl(tmp_path: Path) -> None:
    clock = Clock()
    service = synced_service(tmp_path, clock=clock)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    try:
        with service.materialize_auth_lease(
            "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
        ):
            clock.value += 301
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline:
                try:
                    os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
                except FileNotFoundError:
                    break
                threading.Event().wait(0.02)
            with pytest.raises(FileNotFoundError):
                os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        os.close(runtime_fd)


def test_cross_process_generation_reconciliation_removes_live_file(
    tmp_path: Path,
) -> None:
    service = synced_service(tmp_path)
    competing_vault = CredentialVault.for_test(tmp_path / "vault", key=KEY)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    try:
        with service.materialize_auth_lease(
            "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
        ):
            competing_vault.store_projection("openai-one", 3, b"replacement")
            service.reap_materializations()
            with pytest.raises(FileNotFoundError):
                os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        os.close(runtime_fd)


def test_materialization_rereads_projection_at_publish_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    real_read = CredentialVault._read_or_migrate_locked  # noqa: SLF001
    reads = 0

    def counted_read(
        vault: CredentialVault, account_ref: str
    ) -> tuple[int, int, bytes] | None:
        nonlocal reads
        reads += 1
        return real_read(vault, account_ref)

    monkeypatch.setattr(CredentialVault, "_read_or_migrate_locked", counted_read)
    try:
        with service.materialize_auth_lease(
            "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
        ):
            assert reads == 2
    finally:
        os.close(runtime_fd)


def test_revoke_winning_before_publish_never_exposes_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    revoker = CredentialVault.for_test(tmp_path / "vault", key=KEY)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    ready = threading.Event()
    release = threading.Event()
    real_publish = CredentialVault.publish_active
    result: list[str] = []

    def delayed_publish(
        vault: CredentialVault, active: object, effect: object
    ) -> tuple[int, tuple[int, ...]]:
        ready.set()
        release.wait(timeout=2)
        return real_publish(vault, active, effect)  # type: ignore[arg-type]

    monkeypatch.setattr(CredentialVault, "publish_active", delayed_publish)

    def materialize() -> None:
        try:
            with service.materialize_auth_lease(
                "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
            ):
                result.append("published")
        except OpenAICredentialError as exc:
            result.append(exc.code)

    thread = threading.Thread(target=materialize)
    thread.start()
    assert ready.wait(timeout=2)
    revoker.revoke_account("openai-one", expected_generation=2)
    release.set()
    thread.join(timeout=2)
    try:
        assert result == ["credential.source_unavailable"]
        with pytest.raises(FileNotFoundError):
            os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        os.close(runtime_fd)


def test_baseexception_cleanup_retries_after_first_unlink_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    real_remove = service_module._remove_auth
    calls = 0

    def fail_once(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OpenAICredentialError("credential.source_unavailable")
        real_remove(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(service_module, "_remove_auth", fail_once)
    primary = KeyboardInterrupt()
    try:
        with pytest.raises(KeyboardInterrupt) as raised:
            with service.materialize_auth_lease(
                "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
            ):
                raise primary
        assert raised.value is primary
        assert calls >= 2
        with pytest.raises(FileNotFoundError):
            os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        os.close(runtime_fd)


@pytest.mark.parametrize("drift", ["file", "directory"])
def test_baseexception_cleanup_unlinks_owned_file_after_metadata_drift(
    tmp_path: Path, drift: str
) -> None:
    service = synced_service(tmp_path)
    runtime = tmp_path / "runtime"
    runtime_fd = open_private_runtime(runtime)
    primary = RuntimeError("primary-code-only")
    try:
        with pytest.raises(RuntimeError) as raised:
            with service.materialize_auth_lease(
                "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
            ):
                if drift == "file":
                    os.chmod("auth.json", 0o640, dir_fd=runtime_fd)
                else:
                    runtime.chmod(0o750)
                raise primary
        assert raised.value is primary
        with pytest.raises(FileNotFoundError):
            os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        os.close(runtime_fd)


def test_unlinked_runtime_dirfd_is_rejected_before_lease(tmp_path: Path) -> None:
    service = synced_service(tmp_path)
    runtime = tmp_path / "runtime"
    runtime_fd = open_private_runtime(runtime)
    runtime.rmdir()
    try:
        with pytest.raises(
            OpenAICredentialError, match="credential.source_unavailable"
        ):
            with service.materialize_auth_lease(
                "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
            ):
                pass
    finally:
        os.close(runtime_fd)


def test_consumed_ingress_buffer_is_zeroed(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    plan = service.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="zeroed", ttl_seconds=60
    )
    upload = ingress(plan, auth_json("acct-one"))

    service.apply_auth_sync(plan, upload)

    assert len(upload._payload) == len(auth_json("acct-one"))  # noqa: SLF001
    assert not any(upload._payload)  # noqa: SLF001 - zeroization boundary


@pytest.mark.parametrize("kind", ["file", "mode", "preexisting"])
def test_runtime_dirfd_and_target_fail_closed(kind: str, tmp_path: Path) -> None:
    service = synced_service(tmp_path)
    runtime = tmp_path / "runtime"
    if kind == "file":
        runtime.write_bytes(b"not-a-directory")
        runtime.chmod(0o600)
        runtime_fd = os.open(runtime, os.O_RDONLY | os.O_CLOEXEC)
    else:
        runtime_fd = open_private_runtime(runtime)
        if kind == "mode":
            runtime.chmod(0o750)
        else:
            target_fd = os.open(
                "auth.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=runtime_fd,
            )
            os.close(target_fd)
    try:
        with pytest.raises(
            OpenAICredentialError, match="credential.source_unavailable"
        ):
            with service.materialize_auth_lease(
                "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
            ):
                pass
    finally:
        os.close(runtime_fd)


def test_parallel_materialization_never_overwrites_or_leaves_auth(
    tmp_path: Path,
) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    barrier = threading.Barrier(3)
    entered = threading.Event()
    rejected = threading.Event()
    release = threading.Event()
    results: list[str] = []

    def materialize() -> None:
        barrier.wait()
        try:
            with service.materialize_auth_lease(
                "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
            ):
                results.append("materialized")
                entered.set()
                release.wait(timeout=2)
        except OpenAICredentialError as exc:
            results.append(exc.code)
            rejected.set()

    threads = [threading.Thread(target=materialize) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    assert entered.wait(timeout=2)
    assert rejected.wait(timeout=2)
    release.set()
    for thread in threads:
        thread.join()
    try:
        assert results.count("materialized") == 1
        assert results.count("credential.source_unavailable") == 1
        with pytest.raises(FileNotFoundError):
            os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        os.close(runtime_fd)


def test_publish_failure_removes_temp_and_error_has_no_secret_or_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    runtime = tmp_path / "runtime"
    runtime_fd = open_private_runtime(runtime)

    def fail_link(*_args: object, **_kwargs: object) -> None:
        raise OSError(f"{runtime}/{SECRET_MARKER}")

    monkeypatch.setattr(service_module.os, "link", fail_link)
    try:
        with pytest.raises(OpenAICredentialError) as raised:
            with service.materialize_auth_lease(
                "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
            ):
                pass
        rendered = repr(raised.value) + str(raised.value)
        assert_private_values_absent(rendered, SECRET_MARKER, str(runtime))
        assert os.listdir(runtime_fd) == []
    finally:
        os.close(runtime_fd)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
def test_forked_service_cannot_consume_parent_ingress(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    plan = service.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="fork", ttl_seconds=60
    )
    upload = ingress(plan, auth_json("acct-one"))
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            service.apply_auth_sync(plan, upload)
        except OpenAICredentialError as exc:
            os.write(write_fd, exc.code.encode("ascii"))
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    child_code = os.read(read_fd, 128).decode("ascii")
    os.close(read_fd)
    _pid, status = os.waitpid(child, 0)

    assert status == 0
    assert child_code == "credential.source_unavailable"
    service.apply_auth_sync(plan, upload)


def test_public_rendering_never_contains_secret_or_backend_identity(
    tmp_path: Path,
) -> None:
    service = make_service(tmp_path)
    plan = service.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="render", ttl_seconds=60
    )
    upload = ingress(plan, auth_json("acct-one"))
    receipt = service.apply_auth_sync(plan, upload)

    rendered = repr(service) + repr(plan) + repr(upload) + repr(receipt)
    assert_private_values_absent(rendered, SECRET_MARKER, "acct-one", str(tmp_path))


@pytest.mark.parametrize("tamper", ["duplicate", "noncanonical"])
def test_receipt_state_rejects_duplicate_keys_and_noncanonical_json(
    tmp_path: Path, tamper: str
) -> None:
    service = make_service(tmp_path)
    plan = service.plan_auth_sync(
        "openai-one",
        expected_generation=2,
        idempotency_key="strict-receipt",
        ttl_seconds=60,
    )
    state_path = tmp_path / "receipts" / "openai-auth-sync.json"
    document = json.loads(state_path.read_text(encoding="ascii"))
    if tamper == "duplicate":
        raw = (
            '{"schema_version":1,"schema_version":1,"records":'
            + json.dumps(document["records"], sort_keys=True, separators=(",", ":"))
            + "}\n"
        )
    else:
        raw = json.dumps(document, indent=2, sort_keys=True) + "\n"
    state_path.write_text(raw, encoding="ascii")

    upload = ingress(plan, auth_json("acct-one"))
    with pytest.raises(OpenAICredentialError, match="credential.source_unavailable"):
        service.apply_auth_sync(plan, upload)
    assert upload.closed


def test_productive_identity_source_is_durable_and_rebind_requires_generation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "identity-state"
    initial = {
        "openai-one": OpenAIAccountIdentity(
            enabled=True, backend_account_id="acct-one", generation=2
        )
    }
    source = OpenAIIdentitySource(root, initial_identities=initial)

    with pytest.raises(OpenAICredentialError, match="credential.generation_conflict"):
        source.set_identity(
            "openai-one",
            OpenAIAccountIdentity(
                enabled=True, backend_account_id="acct-two", generation=2
            ),
        )

    restarted = OpenAIIdentitySource(root)
    with restarted.guard("openai-one") as identity:
        assert identity == initial["openai-one"]


def test_cross_vault_materialization_claim_blocks_second_decrypt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = synced_service(tmp_path)
    second = make_service(tmp_path)
    first_runtime_fd = open_private_runtime(tmp_path / "runtime-first")
    second_runtime_fd = open_private_runtime(tmp_path / "runtime-second")
    real_decrypt = CredentialVault._decrypt_record  # noqa: SLF001
    second_decrypts = 0

    def counted_decrypt(
        vault: CredentialVault, raw: bytes, account_ref: str
    ) -> tuple[int, int, bytes]:
        nonlocal second_decrypts
        if vault is second._vault:  # noqa: SLF001 - prove claim check precedes decrypt
            second_decrypts += 1
        return real_decrypt(vault, raw, account_ref)

    monkeypatch.setattr(CredentialVault, "_decrypt_record", counted_decrypt)
    try:
        with first.materialize_auth_lease(
            "openai-one", expected_generation=2, runtime_dir_fd=first_runtime_fd
        ):
            with pytest.raises(
                OpenAICredentialError, match="credential.source_unavailable"
            ):
                with second.materialize_auth_lease(
                    "openai-one",
                    expected_generation=2,
                    runtime_dir_fd=second_runtime_fd,
                ):
                    pass
            assert second_decrypts == 0
    finally:
        os.close(first_runtime_fd)
        os.close(second_runtime_fd)


def test_cross_process_revoke_removes_published_file_before_return(
    tmp_path: Path,
) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    try:
        with service.materialize_auth_lease(
            "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
        ):
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; "
                        "from codex_master.credential_vault import CredentialVault; "
                        "CredentialVault.for_test(Path(__import__('sys').argv[1]), "
                        "key=b'k'*32).revoke_account('openai-one', "
                        "expected_generation=2)"
                    ),
                    str(tmp_path / "vault"),
                ],
                check=True,
                env={**os.environ, "PYTHONPATH": str(Path.cwd() / "src")},
            )
            with pytest.raises(FileNotFoundError):
                os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        os.close(runtime_fd)


def test_normal_lease_prune_runs_materialization_invalidator(tmp_path: Path) -> None:
    clock = Clock()
    service = synced_service(tmp_path, clock=clock)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    try:
        with service.materialize_auth_lease(
            "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
        ):
            clock.value += 301
            service._vault.lease(  # noqa: SLF001 - exercises legacy prune path
                "openai-one", expected_generation=2, ttl_seconds=30
            )
            with pytest.raises(FileNotFoundError):
                os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        os.close(runtime_fd)


def test_service_close_removes_file_while_context_is_held(tmp_path: Path) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    context = service.materialize_auth_lease(
        "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
    )
    context.__enter__()
    try:
        service.close()
        with pytest.raises(FileNotFoundError):
            os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        context.__exit__(None, None, None)
        os.close(runtime_fd)


def test_cleanup_claim_survives_service_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    runtime = tmp_path / "runtime"
    runtime_fd = open_private_runtime(runtime)
    context = service.materialize_auth_lease(
        "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
    )
    context.__enter__()

    def fail_remove(*_args: object, **_kwargs: object) -> None:
        raise OpenAICredentialError("credential.source_unavailable")

    with monkeypatch.context() as patching:
        patching.setattr(service_module, "_remove_auth", fail_remove)
        with pytest.raises(
            OpenAICredentialError, match="credential.source_unavailable"
        ):
            context.__exit__(None, None, None)
        with pytest.raises(
            OpenAICredentialError, match="credential.source_unavailable"
        ):
            service.close()
    os.close(runtime_fd)

    restarted = make_service(tmp_path)
    try:
        with pytest.raises(FileNotFoundError):
            os.stat(runtime / "auth.json", follow_symlinks=False)
    finally:
        restarted.close()


def test_restart_migrates_f0f1262_v1_claim_and_removes_published_secret(
    tmp_path: Path,
) -> None:
    clock = Clock()
    service = synced_service(tmp_path, clock=clock)
    service.close()
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    target = write_materialization_claim(
        service,
        runtime,
        legacy_v1=True,
        token="a" * 64,
        expires_at=clock.value - 1,
    )

    restarted = make_service(tmp_path, clock=clock)
    try:
        assert not target.exists()
        migrated = json.loads(
            (tmp_path / "vault" / "materialization-claims.json").read_text(
                encoding="ascii"
            )
        )
        assert migrated == {"claims": [], "schema_version": 2}
    finally:
        restarted.close()


def test_revoke_migrates_active_f0f1262_v1_claim_and_removes_published_secret(
    tmp_path: Path,
) -> None:
    clock = Clock()
    service = synced_service(tmp_path, clock=clock)
    service.close()
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    target = write_materialization_claim(
        service,
        runtime,
        legacy_v1=True,
        token="c" * 64,
        expires_at=clock.value + 60,
    )

    assert service._vault.revoke_account(  # noqa: SLF001
        "openai-one", expected_generation=2
    )
    assert not target.exists()
    migrated = json.loads(
        (tmp_path / "vault" / "materialization-claims.json").read_text(encoding="ascii")
    )
    assert migrated == {"claims": [], "schema_version": 2}


def test_restart_removes_claim_bound_file_after_in_place_update(
    tmp_path: Path,
) -> None:
    clock = Clock()
    service = synced_service(tmp_path, clock=clock)
    service.close()
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    target = write_materialization_claim(
        service,
        runtime,
        legacy_v1=False,
        token="b" * 64,
        expires_at=clock.value - 1,
    )
    original_identity = (target.stat().st_dev, target.stat().st_ino)
    with target.open("wb") as handle:
        handle.write(auth_json("acct-one", marker="runtime-refresh"))
        handle.flush()
        os.fsync(handle.fileno())
    assert (target.stat().st_dev, target.stat().st_ino) == original_identity
    assert os.getxattr(target, "user.codex_master_claim") == b"b" * 64

    restarted = make_service(tmp_path, clock=clock)
    try:
        assert not target.exists()
    finally:
        restarted.close()


def test_restart_retains_published_claim_with_unknown_hardlink(
    tmp_path: Path,
) -> None:
    clock = Clock()
    service = synced_service(tmp_path, clock=clock)
    service.close()
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    target = write_materialization_claim(
        service,
        runtime,
        legacy_v1=False,
        token="d" * 64,
        expires_at=clock.value - 1,
    )
    unknown_hardlink = runtime / "unknown-auth-copy"
    os.link(target, unknown_hardlink)

    restarted = make_service(tmp_path, clock=clock)
    try:
        assert target.exists()
        assert unknown_hardlink.exists()
        claims = json.loads(
            (tmp_path / "vault" / "materialization-claims.json").read_text(
                encoding="ascii"
            )
        )["claims"]
        assert len(claims) == 1
        assert claims[0]["token"] == "d" * 64
    finally:
        restarted.close()


def test_materialization_claim_schema_newer_than_supported_fails_closed(
    tmp_path: Path,
) -> None:
    service = synced_service(tmp_path)
    service.close()
    raw = b'{"claims":[],"schema_version":3}\n'
    with service._vault._state.locked():  # noqa: SLF001
        service._vault._state.replace_private_bytes(  # noqa: SLF001
            PurePosixPath("materialization-claims.json"), raw
        )

    with pytest.raises(OpenAICredentialError, match="credential.source_unavailable"):
        make_service(tmp_path)


def test_materialization_claim_is_durable_before_projection_decrypt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    observed: list[bool] = []

    def crash_at_decrypt(
        _vault: CredentialVault, _raw: bytes, _account_ref: str
    ) -> tuple[int, int, bytes]:
        try:
            document = json.loads(
                (tmp_path / "vault" / "materialization-claims.json").read_text(
                    encoding="ascii"
                )
            )
        except FileNotFoundError:
            observed.append(False)
        else:
            observed.append(len(document["claims"]) == 1)
        raise KeyboardInterrupt

    monkeypatch.setattr(CredentialVault, "_decrypt_record", crash_at_decrypt)
    try:
        with pytest.raises(KeyboardInterrupt):
            with service.materialize_auth_lease(
                "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
            ):
                pass
        assert observed == [True]
    finally:
        os.close(runtime_fd)


def test_secret_write_starts_only_after_durable_temp_inode_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    real_write = os.write
    observed: list[bool] = []

    def crash_after_first_secret_write(descriptor: int, payload: bytes) -> int:
        name = Path(os.readlink(f"/proc/self/fd/{descriptor}")).name
        written = real_write(descriptor, payload)
        if name.startswith(".auth.json.") and name.endswith(".tmp"):
            document = json.loads(
                (tmp_path / "vault" / "materialization-claims.json").read_text(
                    encoding="ascii"
                )
            )
            observed.append(document["claims"][0]["file_metadata"] is not None)
            raise KeyboardInterrupt
        return written

    monkeypatch.setattr(service_module.os, "write", crash_after_first_secret_write)
    try:
        with pytest.raises(KeyboardInterrupt):
            with service.materialize_auth_lease(
                "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
            ):
                pass
        assert observed == [True]
        assert not tuple((tmp_path / "runtime").iterdir())
    finally:
        os.close(runtime_fd)


def test_prepare_crash_leaves_only_recoverable_empty_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    runtime = tmp_path / "runtime"
    runtime_fd = open_private_runtime(runtime)
    real_fsync = os.fsync
    real_unlink = os.unlink

    def crash_before_prepared_metadata(descriptor: int) -> None:
        name = Path(os.readlink(f"/proc/self/fd/{descriptor}")).name
        if name.startswith(".auth.json.") and name.endswith(".tmp"):
            raise KeyboardInterrupt
        real_fsync(descriptor)

    def retain_temporary(name: object, *args: object, **kwargs: object) -> None:
        if str(name).startswith(".auth.json.") and str(name).endswith(".tmp"):
            raise OSError
        real_unlink(name, *args, **kwargs)  # type: ignore[arg-type]

    try:
        with monkeypatch.context() as patching:
            patching.setattr(service_module.os, "fsync", crash_before_prepared_metadata)
            patching.setattr(service_module.os, "unlink", retain_temporary)
            with pytest.raises(KeyboardInterrupt):
                with service.materialize_auth_lease(
                    "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
                ):
                    pass
        claim_document = json.loads(
            (tmp_path / "vault" / "materialization-claims.json").read_text(
                encoding="ascii"
            )
        )
        assert claim_document["claims"][0]["file_metadata"] is None
        assert len(tuple(runtime.iterdir())) == 1

        restarted = make_service(tmp_path)
        restarted.close()
        assert not tuple(runtime.iterdir())
        service.close()
    finally:
        os.close(runtime_fd)


def test_janitor_does_not_finalize_valid_unpublished_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = make_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    owned_fd, metadata, _path = service_module._duplicate_runtime_dir(runtime_fd)
    entry = service_module._MaterializedAuth(
        "openai-one",
        owned_fd,
        metadata,
        service_module._materialization_temporary_name(),
    )
    finalized: list[object] = []
    with service._lock:  # noqa: SLF001 - exercise setup registry race
        service._materializing_accounts.add("openai-one")  # noqa: SLF001
        service._materializations.add(entry)  # noqa: SLF001
    try:
        with monkeypatch.context() as patching:
            patching.setattr(
                OpenAICredentialService,
                "_finalize_entry",
                lambda *_args, **_kwargs: finalized.append(entry),
            )
            service.reap_materializations()
        assert finalized == []
        service.close()
    finally:
        os.close(runtime_fd)


def test_failed_service_close_can_retry_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    context = service.materialize_auth_lease(
        "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
    )
    context.__enter__()

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OpenAICredentialError("credential.source_unavailable")

    def fail_vault(*_args: object, **_kwargs: object) -> None:
        raise CredentialVaultError("credential.source_unavailable")

    try:
        with monkeypatch.context() as patching:
            patching.setattr(service_module, "_remove_auth", fail)
            patching.setattr(CredentialVault, "abandon_materialization", fail_vault)
            with pytest.raises(
                OpenAICredentialError, match="credential.source_unavailable"
            ):
                service.close()
        service.close()
        with pytest.raises(FileNotFoundError):
            os.stat("auth.json", dir_fd=runtime_fd, follow_symlinks=False)
    finally:
        context.__exit__(None, None, None)
        os.close(runtime_fd)


def test_parallel_context_and_service_finalization_never_double_closes_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")
    context = service.materialize_auth_lease(
        "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
    )
    context.__enter__()
    entry = next(iter(service._materializations))  # noqa: SLF001
    owned_runtime_fd = entry._runtime_fd  # noqa: SLF001
    close_barrier = threading.Barrier(2)
    real_entry_close = service_module._MaterializedAuth.close  # noqa: SLF001
    real_close = service_module._close  # noqa: SLF001
    replacement: list[int] = []
    target_closes = 0
    close_lock = threading.Lock()
    errors: list[BaseException] = []

    def synchronized_entry_close(value: object) -> None:
        real_entry_close(value)  # type: ignore[arg-type]
        close_barrier.wait(timeout=2)

    def reuse_after_first_close(value: int | None) -> None:
        nonlocal target_closes
        if value != owned_runtime_fd:
            real_close(value)
            return
        with close_lock:
            target_closes += 1
            real_close(value)
            if target_closes == 1:
                replacement.append(os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC))

    def run(action: Callable[[], object]) -> None:
        try:
            action()
        except BaseException as exc:  # pragma: no branch - assertion reports it
            errors.append(exc)

    monkeypatch.setattr(
        service_module._MaterializedAuth, "close", synchronized_entry_close
    )
    monkeypatch.setattr(service_module, "_close", reuse_after_first_close)
    context_thread = threading.Thread(
        target=run, args=(lambda: context.__exit__(None, None, None),)
    )
    close_thread = threading.Thread(target=run, args=(service.close,))
    context_thread.start()
    close_thread.start()
    context_thread.join(timeout=3)
    close_thread.join(timeout=3)
    try:
        assert not context_thread.is_alive()
        assert not close_thread.is_alive()
        assert errors == []
        assert len(replacement) == 1
        os.fstat(replacement[0])
    finally:
        if replacement:
            try:
                os.close(replacement[0])
            except OSError:
                pass
        os.close(runtime_fd)


def test_service_context_preserves_primary_baseexception_on_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    runtime_fd = open_private_runtime(tmp_path / "runtime")

    def fail_remove(*_args: object, **_kwargs: object) -> None:
        raise OpenAICredentialError("credential.source_unavailable")

    try:
        with monkeypatch.context() as patching:
            patching.setattr(service_module, "_remove_auth", fail_remove)
            with pytest.raises(KeyboardInterrupt):
                with service:
                    with service.materialize_auth_lease(
                        "openai-one",
                        expected_generation=2,
                        runtime_dir_fd=runtime_fd,
                    ):
                        raise KeyboardInterrupt
        restarted = make_service(tmp_path)
        restarted.close()
        service.close()
    finally:
        os.close(runtime_fd)


def test_restart_cleanup_never_unlinks_replacement_without_claim_temp_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
    runtime = tmp_path / "runtime"
    runtime_fd = open_private_runtime(runtime)
    context = service.materialize_auth_lease(
        "openai-one", expected_generation=2, runtime_dir_fd=runtime_fd
    )
    context.__enter__()
    claim = json.loads(
        (tmp_path / "vault" / "materialization-claims.json").read_text(encoding="ascii")
    )["claims"][0]
    claim_token = claim["temporary_name"].split(".")[-2].encode("ascii")
    assert os.getxattr(runtime / "auth.json", "user.codex_master_claim") == claim_token
    os.unlink("auth.json", dir_fd=runtime_fd)
    replacement = b"foreign-runtime-file"
    replacement_fd = os.open(
        "auth.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=runtime_fd,
    )
    try:
        os.write(replacement_fd, replacement)
        os.fsync(replacement_fd)
    finally:
        os.close(replacement_fd)
    os.fsync(runtime_fd)

    def fail_remove(*_args: object, **_kwargs: object) -> None:
        raise OpenAICredentialError("credential.source_unavailable")

    try:
        with monkeypatch.context() as patching:
            patching.setattr(service_module, "_remove_auth", fail_remove)
            with pytest.raises(
                OpenAICredentialError, match="credential.source_unavailable"
            ):
                context.__exit__(None, None, None)
            with pytest.raises(
                OpenAICredentialError, match="credential.source_unavailable"
            ):
                service.close()
        restarted = make_service(tmp_path)
        try:
            assert (runtime / "auth.json").read_bytes() == replacement
            os.unlink("auth.json", dir_fd=runtime_fd)
            os.fsync(runtime_fd)
            restarted._vault.recover_materializations()  # noqa: SLF001
        finally:
            restarted.close()
        service.close()
    finally:
        os.close(runtime_fd)
