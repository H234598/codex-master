from __future__ import annotations

import hashlib
import hmac
import json
import itertools
import os
from pathlib import Path, PurePosixPath
import stat
import threading

import pytest

import codex_master.openai_credential_service as service_module
from codex_master.credential_vault import CredentialVault, CredentialVaultError
from codex_master.openai_credential_service import (
    AuthorizedAuthIngress,
    OpenAICredentialError,
    OpenAICredentialService,
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
) -> OpenAICredentialService:
    vault = CredentialVault.for_test(tmp_path / "vault", key=KEY, clock=clock)
    nonce_counter = itertools.count(1)
    return OpenAICredentialService(
        vault,
        {"openai-one": registered_backend},
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
    plan = service.plan_auth_sync("openai-one", expected_generation=2, ttl_seconds=60)
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


def test_auth_sync_rejects_different_openai_account_without_vault_mutation(
    tmp_path: Path,
) -> None:
    service = make_service(tmp_path, registered_backend="acct-one")
    plan = service.plan_auth_sync("openai-one", expected_generation=2, ttl_seconds=60)
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
    first = make_service(tmp_path / "first", clock=Clock())
    second = make_service(tmp_path / "second", clock=Clock())
    plan = first.plan_auth_sync("openai-one", expected_generation=7, ttl_seconds=60)

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
    first = service.plan_auth_sync("openai-one", expected_generation=2, ttl_seconds=60)
    first_ingress = ingress(first, auth_json("acct-one"))
    receipt = service.apply_auth_sync(first, first_ingress)

    assert service.apply_auth_sync(first, first_ingress) is receipt
    competing = service.plan_auth_sync(
        "openai-one", expected_generation=2, ttl_seconds=60
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
    plan = service.plan_auth_sync("openai-one", expected_generation=2, ttl_seconds=5)
    clock.value = 106.0

    with pytest.raises(OpenAICredentialError, match="control.plan_stale"):
        service.apply_auth_sync(plan, ingress(plan, auth_json("acct-one")))

    fresh = service.plan_auth_sync("openai-one", expected_generation=2, ttl_seconds=5)
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
    plan = service.plan_auth_sync("openai-one", expected_generation=2, ttl_seconds=60)
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
    plan = service.plan_auth_sync("openai-one", expected_generation=2, ttl_seconds=60)
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
    plan = service.plan_auth_sync("openai-one", expected_generation=2, ttl_seconds=60)
    upload = ingress(plan, auth_json("acct-one"))
    receipt = service.apply_auth_sync(plan, upload)

    rendered = repr(service) + repr(plan) + repr(upload) + repr(receipt)
    assert_private_values_absent(rendered, SECRET_MARKER, "acct-one", str(tmp_path))
