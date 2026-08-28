from __future__ import annotations

import os
from pathlib import Path
import stat
import threading

import pytest

from codex_master.credential_vault import (
    MAX_LEASE_SECONDS,
    MAX_PROJECTION_BYTES,
    CredentialVault,
    CredentialVaultError,
)


KEY = b"k" * 32


class Clock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def vault_at(tmp_path: Path, *, clock: Clock | None = None) -> CredentialVault:
    return CredentialVault.for_test(tmp_path, key=KEY, clock=clock)


def vault_path(tmp_path: Path, account_ref: str = "openai-one") -> Path:
    return tmp_path / f"{account_ref}.vault"


def test_vault_file_does_not_contain_auth_json(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 3, b'{"tokens":{"access_token":"marker"}}')

    raw = vault_path(tmp_path).read_bytes()

    assert b"marker" not in raw
    assert b"access_token" not in raw
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    assert stat.S_IMODE(vault_path(tmp_path).stat().st_mode) == 0o600
    assert vault_path(tmp_path).stat().st_uid == os.geteuid()


def test_old_generation_cannot_be_leased_after_replace(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"first")
    vault.store_projection("openai-one", 2, b"second")

    with pytest.raises(CredentialVaultError, match="credential.generation_conflict"):
        vault.lease("openai-one", expected_generation=1, ttl_seconds=30)


def test_generation_must_increase_and_failed_replace_preserves_current(
    tmp_path: Path,
) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 2, b"second")

    for generation in (1, 2):
        with pytest.raises(
            CredentialVaultError, match="credential.generation_conflict"
        ):
            vault.store_projection("openai-one", generation, b"stale-marker")

    lease = vault.lease("openai-one", expected_generation=2, ttl_seconds=30)
    assert vault.consume_lease(lease) == b"second"
    assert b"stale-marker" not in vault_path(tmp_path).read_bytes()


def test_lease_is_one_shot_under_concurrent_consumers(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"only-once")
    lease = vault.lease("openai-one", expected_generation=1, ttl_seconds=30)
    barrier = threading.Barrier(3)
    results: list[bytes | str] = []

    def consume() -> None:
        barrier.wait()
        try:
            results.append(vault.consume_lease(lease))
        except CredentialVaultError as exc:
            results.append(exc.code)

    threads = [threading.Thread(target=consume) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)

    assert not any(thread.is_alive() for thread in threads)
    assert results.count(b"only-once") == 1
    assert results.count("credential.lease_consumed") == 1


def test_lease_expiry_uses_injected_monotonic_clock(tmp_path: Path) -> None:
    clock = Clock()
    vault = vault_at(tmp_path, clock=clock)
    vault.store_projection("openai-one", 1, b"secret")
    lease = vault.lease("openai-one", expected_generation=1, ttl_seconds=5)

    clock.value = 105.0

    with pytest.raises(CredentialVaultError, match="credential.lease_expired"):
        vault.consume_lease(lease)


def test_lease_is_generation_bound_at_consumption(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"old-secret")
    lease = vault.lease("openai-one", expected_generation=1, ttl_seconds=30)

    vault.store_projection("openai-one", 2, b"new-secret")

    with pytest.raises(CredentialVaultError, match="credential.generation_conflict"):
        vault.consume_lease(lease)


def test_lease_repr_contains_no_account_or_secret(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-sensitive", 1, b"secret-marker")
    lease = vault.lease("openai-sensitive", expected_generation=1, ttl_seconds=30)

    rendered = repr(lease)

    assert rendered == "<CredentialLease>"
    assert "openai-sensitive" not in rendered
    assert "secret-marker" not in rendered


@pytest.mark.parametrize("size", [0, MAX_PROJECTION_BYTES + 1])
def test_projection_size_is_bounded_without_secret_in_error(
    tmp_path: Path, size: int
) -> None:
    secret = b"secret-marker" + b"x" * max(0, size - len(b"secret-marker"))
    vault = vault_at(tmp_path)

    with pytest.raises(CredentialVaultError) as captured:
        vault.store_projection("openai-one", 1, secret[:size])

    assert captured.value.code == "credential.vault_request_invalid"
    assert "secret-marker" not in repr(captured.value)
    assert "secret-marker" not in str(captured.value)


@pytest.mark.parametrize("ttl", [0, MAX_LEASE_SECONDS + 1, True])
def test_lease_ttl_is_bounded(tmp_path: Path, ttl: object) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"secret")

    with pytest.raises(CredentialVaultError, match="credential.vault_request_invalid"):
        vault.lease("openai-one", expected_generation=1, ttl_seconds=ttl)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "key",
    [b"", b"k" * 31, b"k" * 33, "k" * 32],
    ids=("empty", "short", "long", "not-bytes"),
)
def test_test_key_must_be_exactly_256_bits(tmp_path: Path, key: object) -> None:
    with pytest.raises(
        CredentialVaultError, match="credential.vault_key_invalid"
    ) as captured:
        CredentialVault.for_test(tmp_path, key=key)  # type: ignore[arg-type]

    assert "kkkk" not in repr(captured.value)


def test_exact_maximum_projection_round_trips(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    plaintext = b"x" * MAX_PROJECTION_BYTES
    vault.store_projection("openai-one", 1, plaintext)

    lease = vault.lease("openai-one", expected_generation=1, ttl_seconds=30)

    assert vault.consume_lease(lease) == plaintext


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_monotonic_time_fails_closed(tmp_path: Path, value: float) -> None:
    vault = vault_at(tmp_path, clock=Clock(value))
    vault.store_projection("openai-one", 1, b"secret")

    with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
        vault.lease("openai-one", expected_generation=1, ttl_seconds=30)


def test_error_constructor_cannot_echo_arbitrary_text() -> None:
    with pytest.raises(
        TypeError, match="invalid credential vault error code"
    ) as captured:
        CredentialVaultError("secret-marker")

    assert "secret-marker" not in repr(captured.value)


def test_key_can_be_loaded_from_private_fd_without_closing_it(tmp_path: Path) -> None:
    key_path = tmp_path / "master-key"
    key_path.write_bytes(KEY)
    key_path.chmod(0o400)
    vault_root = tmp_path / "vault"
    descriptor = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        vault = CredentialVault.from_key_fd(vault_root, key_fd=descriptor)
        os.fstat(descriptor)
    finally:
        os.close(descriptor)

    vault.store_projection("openai-one", 1, b"secret")
    lease = vault.lease("openai-one", expected_generation=1, ttl_seconds=30)
    assert vault.consume_lease(lease) == b"secret"


def test_key_fd_rejects_non_private_or_oversized_file(tmp_path: Path) -> None:
    for mode, key in ((0o644, KEY), (0o400, KEY + b"x")):
        key_path = tmp_path / f"key-{mode:o}-{len(key)}"
        key_path.write_bytes(key)
        key_path.chmod(mode)
        descriptor = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with pytest.raises(
                CredentialVaultError, match="credential.vault_key_invalid"
            ):
                CredentialVault.from_key_fd(tmp_path / "vault", key_fd=descriptor)
        finally:
            os.close(descriptor)


@pytest.mark.parametrize("mode", [0o000, 0o100, 0o200])
def test_key_fd_requires_owner_read_only_or_private_read_write_mode(
    tmp_path: Path, mode: int
) -> None:
    key_path = tmp_path / f"key-mode-{mode:o}"
    key_path.write_bytes(KEY)
    descriptor = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        key_path.chmod(mode)
        with pytest.raises(CredentialVaultError, match="credential.vault_key_invalid"):
            CredentialVault.from_key_fd(tmp_path / "vault", key_fd=descriptor)
    finally:
        os.close(descriptor)


def test_account_ref_and_generation_are_bounded(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    for account_ref, generation in (
        ("../escape", 1),
        ("x" * 129, 1),
        ("openai-one", 0),
        ("openai-one", 2**63),
        ("openai-one", True),
    ):
        with pytest.raises(
            CredentialVaultError, match="credential.vault_request_invalid"
        ):
            vault.store_projection(account_ref, generation, b"secret")  # type: ignore[arg-type]


def test_projection_symlink_is_rejected_without_touching_target(tmp_path: Path) -> None:
    target = tmp_path / "outside"
    target.write_bytes(b"outside-marker")
    target.chmod(0o600)
    vault_path(tmp_path).symlink_to(target)
    vault = vault_at(tmp_path)

    with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
        vault.store_projection("openai-one", 1, b"secret")

    assert target.read_bytes() == b"outside-marker"


def test_projection_hardlink_is_rejected(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"secret")
    os.link(vault_path(tmp_path), tmp_path / "extra-link")

    with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
        vault.lease("openai-one", expected_generation=1, ttl_seconds=30)


def test_projection_and_root_permissions_fail_closed(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"secret")
    vault_path(tmp_path).chmod(0o640)

    with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
        vault.lease("openai-one", expected_generation=1, ttl_seconds=30)

    vault_path(tmp_path).chmod(0o600)
    tmp_path.chmod(0o750)
    with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
        vault.lease("openai-one", expected_generation=1, ttl_seconds=30)


def test_truncated_unknown_schema_and_tampered_records_fail_closed(
    tmp_path: Path,
) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"secret-marker")
    original = vault_path(tmp_path).read_bytes()
    corruptions = (
        original[:10],
        original[:8] + bytes([original[8] + 1]) + original[9:],
        original[:-1] + bytes([original[-1] ^ 1]),
    )

    for corrupted in corruptions:
        vault_path(tmp_path).write_bytes(corrupted)
        vault_path(tmp_path).chmod(0o600)
        with pytest.raises(CredentialVaultError) as captured:
            vault.lease("openai-one", expected_generation=1, ttl_seconds=30)
        assert captured.value.code in {
            "credential.vault_schema_invalid",
            "credential.vault_authentication_failed",
        }
        assert "secret-marker" not in repr(captured.value)
        assert "secret-marker" not in str(captured.value)


def test_aad_binds_account_ref(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"secret-marker")
    vault_path(tmp_path, "openai-two").write_bytes(vault_path(tmp_path).read_bytes())
    vault_path(tmp_path, "openai-two").chmod(0o600)

    with pytest.raises(
        CredentialVaultError, match="credential.vault_authentication_failed"
    ):
        vault.lease("openai-two", expected_generation=1, ttl_seconds=30)


def test_failed_atomic_replace_preserves_previous_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.hive.state as state_module

    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"first")

    def fail_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated replace failure")

    with monkeypatch.context() as context:
        context.setattr(state_module.os, "replace", fail_replace)
        with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
            vault.store_projection("openai-one", 2, b"second")

    lease = vault.lease("openai-one", expected_generation=1, ttl_seconds=30)
    assert vault.consume_lease(lease) == b"first"


def test_revoke_is_generation_bound_and_invalidates_lease(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 2, b"secret")
    lease = vault.lease("openai-one", expected_generation=2, ttl_seconds=30)

    with pytest.raises(CredentialVaultError, match="credential.generation_conflict"):
        vault.revoke_account("openai-one", expected_generation=1)

    assert vault.revoke_account("openai-one", expected_generation=2) is True
    with pytest.raises(CredentialVaultError, match="credential.generation_conflict"):
        vault.revoke_account("openai-one", expected_generation=2)
    with pytest.raises(CredentialVaultError, match="credential.lease_consumed"):
        vault.consume_lease(lease)


def test_consume_rejects_forged_handle(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)

    with pytest.raises(CredentialVaultError, match="credential.vault_request_invalid"):
        vault.consume_lease(object())  # type: ignore[arg-type]
