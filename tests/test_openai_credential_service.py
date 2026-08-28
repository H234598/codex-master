from __future__ import annotations

import hashlib
import hmac
import json
import itertools
import os
from pathlib import Path, PurePosixPath
import stat
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
        OpenAIIdentitySource.for_test(
            {
                "openai-one": OpenAIAccountIdentity(
                    enabled=True,
                    backend_account_id=registered_backend,
                    generation=identity_generation,
                )
            }
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
    source = OpenAIIdentitySource.for_test(
        {
            "openai-one": OpenAIAccountIdentity(
                enabled=True, backend_account_id="acct-one", generation=2
            )
        }
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
        make_service(tmp_path, identity_generation=3).plan_auth_sync(
            "openai-one",
            expected_generation=3,
            idempotency_key="durable-intent",
            ttl_seconds=60,
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


def test_materialization_reads_projection_once_before_publish(
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
            assert reads == 1
    finally:
        os.close(runtime_fd)


def test_revoke_winning_before_publish_never_exposes_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = synced_service(tmp_path)
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
    service._vault.revoke_account("openai-one", expected_generation=2)  # noqa: SLF001
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
