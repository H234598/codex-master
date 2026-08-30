from __future__ import annotations

from array import array
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import threading
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import codex_master.credential_vault as credential_vault
from codex_master.credential_vault import (
    MAX_LEASE_SECONDS,
    MAX_PROJECTION_BYTES,
    CredentialCleanupTarget,
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
    storage_id = hashlib.sha256(account_ref.encode("ascii")).hexdigest()
    return tmp_path / f"{storage_id}.vault"


def legacy_vault_path(tmp_path: Path, account_ref: str = "openai-one") -> Path:
    return tmp_path / f"{account_ref}.vault"


def legacy_vault_record(
    account_ref: str, generation: int, plaintext: bytes, *, nonce: bytes = b"n" * 12
) -> bytes:
    encoded_ref = account_ref.encode("ascii")
    aad = (
        b"codex-master-credential-projection\0"
        + b"\x01"
        + len(encoded_ref).to_bytes(2, "big")
        + encoded_ref
        + generation.to_bytes(8, "big")
    )
    ciphertext = AESGCM(KEY).encrypt(nonce, plaintext, aad)
    return struct.pack(">8sBQ12s", b"CMVAULT\0", 1, generation, nonce) + ciphertext


def test_cleanup_target_repr_and_legacy_temporary_metadata_are_sparse_and_strict(
    tmp_path: Path,
) -> None:
    temporary = tmp_path / ".auth.json.tmp"
    temporary.write_bytes(b"legacy")
    temporary.chmod(0o600)
    target = CredentialCleanupTarget(
        str(tmp_path), CredentialVault._raw_directory_metadata(tmp_path.stat()), temporary.name
    )

    assert repr(target) == "CredentialCleanupTarget(<redacted>)"
    assert str(tmp_path) not in repr(target)
    assert CredentialVault._safe_unbound_legacy_temporary(temporary.stat()) is True
    temporary.chmod(0o644)
    assert CredentialVault._safe_unbound_legacy_temporary(temporary.stat()) is False


def test_materialization_context_releases_local_lease(tmp_path: Path) -> None:
    vault = vault_at(tmp_path / "vault")
    vault.store_projection("openai-one", 1, b"secret")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    temporary = runtime / (".auth.json." + "a" * 64 + ".tmp")
    temporary.write_bytes(b"")
    temporary.chmod(0o600)
    target = CredentialCleanupTarget(
        str(runtime),
        CredentialVault._raw_directory_metadata(runtime.stat()),
        temporary.name,
    )

    with vault.materialization_lease(
        "openai-one",
        expected_generation=1,
        ttl_seconds=30,
        invalidator=lambda: None,
        cleanup_target=target,
        prepare=lambda: CredentialVault._raw_file_metadata(temporary.stat()),
    ) as (lease, plaintext):
        assert plaintext == b"secret"
        with pytest.raises(CredentialVaultError, match="credential.lease_consumed"):
            vault.consume_lease(lease)

    with pytest.raises(CredentialVaultError, match="credential.lease_consumed"):
        vault.consume_lease(lease)


def test_fork_invalidation_rotates_issuer_and_owner_liveness_is_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"secret")
    lease = vault.lease("openai-one", expected_generation=1, ttl_seconds=30)
    current_boot = vault._owner_boot_id
    claim = {
        "owner_boot_id": current_boot,
        "owner_pid": 12345,
        "owner_start_ticks": 7,
    }
    monkeypatch.setattr(CredentialVault, "_process_start_ticks", staticmethod(lambda _pid: 8))

    assert vault._claim_owner_dead(claim) is True
    credential_vault._invalidate_vaults_after_fork()
    with pytest.raises(CredentialVaultError, match="credential.vault_request_invalid"):
        vault.consume_lease(lease)


def write_legacy_vault(
    tmp_path: Path,
    account_ref: str = "openai-one",
    generation: int = 7,
    plaintext: bytes = b"legacy-secret",
) -> bytes:
    raw = legacy_vault_record(account_ref, generation, plaintext)
    path = legacy_vault_path(tmp_path, account_ref)
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


def test_vault_file_does_not_contain_auth_json(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 3, b'{"tokens":{"access_token":"marker"}}')

    raw = vault_path(tmp_path).read_bytes()

    assert b"marker" not in raw
    assert b"access_token" not in raw
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    assert stat.S_IMODE(vault_path(tmp_path).stat().st_mode) == 0o600
    assert vault_path(tmp_path).stat().st_uid == os.geteuid()


def test_projection_metadata_reports_only_state_and_generation(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    secret = bytearray(b"mutable-secret")
    vault.store_projection("openai-one", 3, memoryview(secret))

    assert vault.projection_metadata("openai-one") == ("active", 3)
    vault.revoke_account("openai-one", expected_generation=3)
    assert vault.projection_metadata("openai-one") == ("revoked", 3)
    assert vault.projection_metadata("missing") is None


def test_store_projection_rejects_non_byte_memoryview(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    with pytest.raises(CredentialVaultError, match="credential.vault_request_invalid"):
        vault.store_projection("openai-one", 3, memoryview(array("I", [1])))


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


def test_legacy_v1_is_migrated_before_generation_cas_and_can_be_leased(
    tmp_path: Path,
) -> None:
    write_legacy_vault(tmp_path, generation=7, plaintext=b"legacy-secret")
    restarted = vault_at(tmp_path)

    for generation in (6, 7):
        with pytest.raises(
            CredentialVaultError, match="credential.generation_conflict"
        ):
            restarted.store_projection("openai-one", generation, b"stale")

    lease = restarted.lease("openai-one", expected_generation=7, ttl_seconds=30)
    assert restarted.consume_lease(lease) == b"legacy-secret"
    assert not legacy_vault_path(tmp_path).exists()
    assert vault_path(tmp_path).read_bytes()[8] == 2


def test_legacy_v1_can_be_revoked_after_migration(tmp_path: Path) -> None:
    write_legacy_vault(tmp_path, generation=7)
    restarted = vault_at(tmp_path)

    assert restarted.revoke_account("openai-one", expected_generation=7) is True

    second_restart = vault_at(tmp_path)
    with pytest.raises(CredentialVaultError, match="credential.generation_conflict"):
        second_restart.store_projection("openai-one", 7, b"replay")


def test_migration_recovers_v1_already_moved_to_hashed_path(tmp_path: Path) -> None:
    raw = legacy_vault_record("openai-one", 7, b"legacy-secret")
    vault_path(tmp_path).write_bytes(raw)
    vault_path(tmp_path).chmod(0o600)

    restarted = vault_at(tmp_path)
    lease = restarted.lease("openai-one", expected_generation=7, ttl_seconds=30)

    assert restarted.consume_lease(lease) == b"legacy-secret"
    assert vault_path(tmp_path).read_bytes()[8] == 2


def test_migration_recovers_identical_dual_v1_records(tmp_path: Path) -> None:
    raw = write_legacy_vault(tmp_path, generation=7, plaintext=b"legacy-secret")
    vault_path(tmp_path).write_bytes(raw)
    vault_path(tmp_path).chmod(0o600)

    restarted = vault_at(tmp_path)
    lease = restarted.lease("openai-one", expected_generation=7, ttl_seconds=30)

    assert restarted.consume_lease(lease) == b"legacy-secret"
    assert not legacy_vault_path(tmp_path).exists()
    assert vault_path(tmp_path).read_bytes()[8] == 2


def test_migration_cleans_identical_legacy_record_beside_schema2(
    tmp_path: Path,
) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 7, b"legacy-secret")
    write_legacy_vault(tmp_path, generation=7, plaintext=b"legacy-secret")

    restarted = vault_at(tmp_path)
    lease = restarted.lease("openai-one", expected_generation=7, ttl_seconds=30)

    assert restarted.consume_lease(lease) == b"legacy-secret"
    assert not legacy_vault_path(tmp_path).exists()
    assert vault_path(tmp_path).read_bytes()[8] == 2


def test_migration_recovers_after_crash_before_old_record_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_master.hive.state import HiveStateError, HiveStateStore

    write_legacy_vault(tmp_path, generation=7, plaintext=b"legacy-secret")

    def crash_remove(_state: HiveStateStore, _relative: PurePosixPath) -> None:
        raise HiveStateError("state_unavailable")

    with monkeypatch.context() as context:
        context.setattr(HiveStateStore, "remove_private_bytes", crash_remove)
        with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
            vault_at(tmp_path).lease(
                "openai-one", expected_generation=7, ttl_seconds=30
            )

    assert legacy_vault_path(tmp_path).exists()
    assert vault_path(tmp_path).read_bytes()[8] == 1
    restarted = vault_at(tmp_path)
    lease = restarted.lease("openai-one", expected_generation=7, ttl_seconds=30)
    assert restarted.consume_lease(lease) == b"legacy-secret"


def test_migration_recovers_after_move_before_schema2_rewrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_master.hive.state import HiveStateError, HiveStateStore

    write_legacy_vault(tmp_path, generation=7, plaintext=b"legacy-secret")
    real_replace = HiveStateStore.replace_private_bytes
    calls = 0

    def crash_second_replace(
        state: HiveStateStore, relative: PurePosixPath, payload: bytes
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise HiveStateError("state_write_failed")
        real_replace(state, relative, payload)

    with monkeypatch.context() as context:
        context.setattr(HiveStateStore, "replace_private_bytes", crash_second_replace)
        with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
            vault_at(tmp_path).lease(
                "openai-one", expected_generation=7, ttl_seconds=30
            )

    assert not legacy_vault_path(tmp_path).exists()
    assert vault_path(tmp_path).read_bytes()[8] == 1
    restarted = vault_at(tmp_path)
    with pytest.raises(CredentialVaultError, match="credential.generation_conflict"):
        restarted.store_projection("openai-one", 7, b"replay")
    lease = restarted.lease("openai-one", expected_generation=7, ttl_seconds=30)
    assert restarted.consume_lease(lease) == b"legacy-secret"


@pytest.mark.parametrize("hashed_generation", [6, 8])
def test_divergent_dual_records_fail_closed_without_floor_loss(
    tmp_path: Path, hashed_generation: int
) -> None:
    write_legacy_vault(tmp_path, generation=7, plaintext=b"legacy-secret")
    hashed = legacy_vault_record(
        "openai-one", hashed_generation, b"divergent-secret", nonce=b"h" * 12
    )
    vault_path(tmp_path).write_bytes(hashed)
    vault_path(tmp_path).chmod(0o600)
    before_old = legacy_vault_path(tmp_path).read_bytes()
    before_hashed = vault_path(tmp_path).read_bytes()
    restarted = vault_at(tmp_path)

    with pytest.raises(CredentialVaultError):
        restarted.store_projection("openai-one", 9, b"replacement")

    assert legacy_vault_path(tmp_path).read_bytes() == before_old
    assert vault_path(tmp_path).read_bytes() == before_hashed


def test_divergent_legacy_and_schema2_records_fail_closed(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 8, b"schema2-secret")
    write_legacy_vault(tmp_path, generation=7, plaintext=b"legacy-secret")
    before_old = legacy_vault_path(tmp_path).read_bytes()
    before_hashed = vault_path(tmp_path).read_bytes()

    with pytest.raises(
        CredentialVaultError, match="credential.vault_authentication_failed"
    ):
        vault.store_projection("openai-one", 9, b"replacement")

    assert legacy_vault_path(tmp_path).read_bytes() == before_old
    assert vault_path(tmp_path).read_bytes() == before_hashed


def test_tampered_legacy_beside_schema2_fails_closed_without_cleanup(
    tmp_path: Path,
) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 8, b"schema2-secret")
    raw = write_legacy_vault(tmp_path, generation=8, plaintext=b"schema2-secret")
    tampered = raw[:-1] + bytes([raw[-1] ^ 1])
    legacy_vault_path(tmp_path).write_bytes(tampered)
    legacy_vault_path(tmp_path).chmod(0o600)
    before_hashed = vault_path(tmp_path).read_bytes()

    with pytest.raises(
        CredentialVaultError, match="credential.vault_authentication_failed"
    ):
        vault.lease("openai-one", expected_generation=8, ttl_seconds=30)

    assert legacy_vault_path(tmp_path).read_bytes() == tampered
    assert vault_path(tmp_path).read_bytes() == before_hashed


@pytest.mark.parametrize("corruption", ["truncated", "tampered"])
def test_invalid_legacy_v1_fails_closed_before_migration(
    tmp_path: Path, corruption: str
) -> None:
    raw = write_legacy_vault(tmp_path, generation=7, plaintext=b"legacy-secret")
    invalid = raw[:10] if corruption == "truncated" else raw[:-1] + bytes([raw[-1] ^ 1])
    legacy_vault_path(tmp_path).write_bytes(invalid)
    legacy_vault_path(tmp_path).chmod(0o600)
    restarted = vault_at(tmp_path)

    with pytest.raises(CredentialVaultError) as captured:
        restarted.store_projection("openai-one", 8, b"replacement")

    assert captured.value.code in {
        "credential.vault_authentication_failed",
        "credential.vault_schema_invalid",
    }
    assert not vault_path(tmp_path).exists()


@pytest.mark.parametrize("untrusted", ["permissions", "hardlink", "symlink"])
def test_untrusted_legacy_v1_fails_closed_before_migration(
    tmp_path: Path, untrusted: str
) -> None:
    write_legacy_vault(tmp_path, generation=7)
    if untrusted == "permissions":
        legacy_vault_path(tmp_path).chmod(0o640)
    elif untrusted == "hardlink":
        os.link(legacy_vault_path(tmp_path), tmp_path / "legacy-extra-link")
    else:
        legacy_vault_path(tmp_path).unlink()
        target = tmp_path / "outside-legacy"
        target.write_bytes(legacy_vault_record("openai-one", 7, b"outside"))
        target.chmod(0o600)
        legacy_vault_path(tmp_path).symlink_to(target)
    restarted = vault_at(tmp_path)

    with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
        restarted.store_projection("openai-one", 8, b"replacement")

    assert not vault_path(tmp_path).exists()


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


def test_revoke_persists_generation_floor_across_restart(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 7, b"revoked-marker")
    assert vault.revoke_account("openai-one", expected_generation=7) is True

    restarted = vault_at(tmp_path)
    for generation in (6, 7):
        with pytest.raises(
            CredentialVaultError, match="credential.generation_conflict"
        ):
            restarted.store_projection("openai-one", generation, b"replay-marker")

    restarted.store_projection("openai-one", 8, b"fresh")
    lease = restarted.lease("openai-one", expected_generation=8, ttl_seconds=30)
    assert restarted.consume_lease(lease) == b"fresh"


def test_revoke_writes_private_secret_free_authenticated_tombstone(
    tmp_path: Path,
) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 7, b"revoked-marker")
    assert vault.revoke_account("openai-one", expected_generation=7) is True

    records = list(tmp_path.glob("*.vault"))
    assert len(records) == 1
    raw = records[0].read_bytes()
    assert b"revoked-marker" not in raw
    assert b"openai-one" not in raw
    assert stat.S_IMODE(records[0].stat().st_mode) == 0o600
    with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
        vault.lease("openai-one", expected_generation=7, ttl_seconds=30)


def test_revoke_floor_serializes_concurrent_same_generation_store(
    tmp_path: Path,
) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 7, b"old")
    vault.revoke_account("openai-one", expected_generation=7)
    contenders = (vault_at(tmp_path), vault_at(tmp_path))
    barrier = threading.Barrier(3)
    outcomes: list[tuple[str, bytes]] = []

    def store(candidate: CredentialVault, plaintext: bytes) -> None:
        barrier.wait()
        try:
            candidate.store_projection("openai-one", 8, plaintext)
        except CredentialVaultError as exc:
            outcomes.append((exc.code, b""))
        else:
            outcomes.append(("ok", plaintext))

    threads = [
        threading.Thread(target=store, args=(contenders[0], b"first")),
        threading.Thread(target=store, args=(contenders[1], b"second")),
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)

    assert not any(thread.is_alive() for thread in threads)
    assert [code for code, _value in outcomes].count("ok") == 1
    assert [code for code, _value in outcomes].count(
        "credential.generation_conflict"
    ) == 1
    winner = next(value for code, value in outcomes if code == "ok")
    restarted = vault_at(tmp_path)
    lease = restarted.lease("openai-one", expected_generation=8, ttl_seconds=30)
    assert restarted.consume_lease(lease) == winner


def test_revoke_cas_is_concurrent_and_restart_safe(tmp_path: Path) -> None:
    original = vault_at(tmp_path)
    original.store_projection("openai-one", 7, b"old")
    contenders = (vault_at(tmp_path), vault_at(tmp_path))
    barrier = threading.Barrier(3)
    outcomes: list[str] = []

    def revoke(candidate: CredentialVault) -> None:
        barrier.wait()
        try:
            candidate.revoke_account("openai-one", expected_generation=7)
        except CredentialVaultError as exc:
            outcomes.append(exc.code)
        else:
            outcomes.append("ok")

    threads = [
        threading.Thread(target=revoke, args=(candidate,)) for candidate in contenders
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)

    assert not any(thread.is_alive() for thread in threads)
    assert outcomes.count("ok") == 1
    assert outcomes.count("credential.generation_conflict") == 1
    restarted = vault_at(tmp_path)
    with pytest.raises(CredentialVaultError, match="credential.generation_conflict"):
        restarted.store_projection("openai-one", 7, b"replay")


def test_failed_tombstone_replace_preserves_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.hive.state as state_module

    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 7, b"still-active")

    def fail_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("private failure text")

    with monkeypatch.context() as context:
        context.setattr(state_module.os, "replace", fail_replace)
        with pytest.raises(CredentialVaultError, match="credential.source_unavailable"):
            vault.revoke_account("openai-one", expected_generation=7)

    lease = vault.lease("openai-one", expected_generation=7, ttl_seconds=30)
    assert vault.consume_lease(lease) == b"still-active"


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is POSIX-only")
def test_parent_lease_cannot_be_consumed_in_forked_child(tmp_path: Path) -> None:
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"fork-private-marker")
    lease = vault.lease("openai-one", expected_generation=1, ttl_seconds=30)
    read_fd, write_fd = os.pipe()

    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            vault.consume_lease(lease)
        except CredentialVaultError as exc:
            outcome = f"denied:{exc.code}".encode("ascii")
        except BaseException:
            outcome = b"raw-error"
        else:
            outcome = b"consumed"
        os.write(write_fd, outcome)
        os.close(write_fd)
        os._exit(0)

    os.close(write_fd)
    outcome = os.read(read_fd, 256)
    os.close(read_fd)
    _, status = os.waitpid(child, 0)
    parent_plaintext = vault.consume_lease(lease)

    assert os.waitstatus_to_exitcode(status) == 0
    assert outcome.startswith(b"denied:credential.")
    assert b"fork-private-marker" not in outcome
    assert parent_plaintext == b"fork-private-marker"


@pytest.mark.parametrize("length", [122, 123, 128])
def test_maximum_account_refs_round_trip_after_restart(
    tmp_path: Path, length: int
) -> None:
    account_ref = "a" * length
    vault = vault_at(tmp_path)
    vault.store_projection(account_ref, 1, b"secret")

    records = list(tmp_path.glob("*.vault"))
    assert len(records) == 1
    assert (
        records[0].name
        == hashlib.sha256(account_ref.encode("ascii")).hexdigest() + ".vault"
    )
    assert len(records[0].name) == 70

    restarted = vault_at(tmp_path)
    lease = restarted.lease(account_ref, expected_generation=1, ttl_seconds=30)
    assert restarted.consume_lease(lease) == b"secret"


def test_storage_id_collision_fails_closed_without_clobbering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        CredentialVault,
        "_storage_name",
        staticmethod(lambda _account_ref: "f" * 64 + ".vault"),
        raising=False,
    )
    vault = vault_at(tmp_path)
    vault.store_projection("openai-one", 1, b"first-secret")

    with pytest.raises(
        CredentialVaultError, match="credential.vault_authentication_failed"
    ):
        vault.store_projection("openai-two", 1, b"second-secret")

    restarted = vault_at(tmp_path)
    lease = restarted.lease("openai-one", expected_generation=1, ttl_seconds=30)
    assert restarted.consume_lease(lease) == b"first-secret"


def _changed_stat(info: os.stat_result, **changes: int) -> SimpleNamespace:
    values = {
        "st_mode": info.st_mode,
        "st_nlink": info.st_nlink,
        "st_uid": info.st_uid,
        "st_size": info.st_size,
        "st_dev": info.st_dev,
        "st_ino": info.st_ino,
        "st_mtime_ns": info.st_mtime_ns,
        "st_ctime_ns": info.st_ctime_ns,
    }
    values.update(changes)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("st_mode", 0o100644),
        ("st_mode", stat.S_IFDIR | 0o400),
        ("st_nlink", 2),
        ("st_uid", 2**31 - 1),
    ],
)
def test_key_fd_rejects_post_read_metadata_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: int,
) -> None:
    import codex_master.credential_vault as vault_module

    key_path = tmp_path / "master-key"
    key_path.write_bytes(KEY)
    key_path.chmod(0o400)
    descriptor = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
    real_fstat = vault_module.os.fstat
    calls = 0

    def racing_fstat(fd: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        calls += 1
        observed = real_fstat(fd)
        if calls >= 2:
            return _changed_stat(observed, **{field: replacement})
        return observed

    try:
        monkeypatch.setattr(vault_module.os, "fstat", racing_fstat)
        with pytest.raises(CredentialVaultError, match="credential.vault_key_invalid"):
            CredentialVault.from_key_fd(tmp_path / "vault", key_fd=descriptor)
    finally:
        os.close(descriptor)


def test_key_fd_rejects_equal_length_content_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.credential_vault as vault_module

    key_path = tmp_path / "master-key"
    key_path.write_bytes(KEY)
    key_path.chmod(0o400)
    descriptor = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
    reads = 0

    def racing_pread(_fd: int, size: int, offset: int) -> bytes:
        nonlocal reads
        if offset == 32:
            return b""
        assert size == 33 and offset == 0
        reads += 1
        return KEY if reads == 1 else b"q" * 32

    try:
        monkeypatch.setattr(vault_module.os, "pread", racing_pread)
        with pytest.raises(CredentialVaultError, match="credential.vault_key_invalid"):
            CredentialVault.from_key_fd(tmp_path / "vault", key_fd=descriptor)
    finally:
        os.close(descriptor)


def test_key_fd_rejects_offset_change_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.credential_vault as vault_module

    key_path = tmp_path / "master-key"
    key_path.write_bytes(KEY)
    key_path.chmod(0o400)
    descriptor = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
    offsets = iter((0, 1))
    try:
        monkeypatch.setattr(vault_module.os, "lseek", lambda *_args: next(offsets))
        with pytest.raises(CredentialVaultError, match="credential.vault_key_invalid"):
            CredentialVault.from_key_fd(tmp_path / "vault", key_fd=descriptor)
    finally:
        os.close(descriptor)


def test_key_buffer_is_zeroed_when_post_read_fstat_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.credential_vault as vault_module

    key_path = tmp_path / "master-key"
    key_path.write_bytes(KEY)
    key_path.chmod(0o400)
    descriptor = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
    real_fstat = vault_module.os.fstat
    real_zero = CredentialVault._zero
    fstat_calls = 0
    zeroed: list[bytearray] = []

    def failing_fstat(fd: int) -> os.stat_result:
        nonlocal fstat_calls
        fstat_calls += 1
        if fstat_calls == 2:
            raise OSError("private failure text")
        return real_fstat(fd)

    def recording_zero(value: bytearray) -> None:
        zeroed.append(value)
        real_zero(value)

    try:
        monkeypatch.setattr(vault_module.os, "fstat", failing_fstat)
        monkeypatch.setattr(CredentialVault, "_zero", staticmethod(recording_zero))
        with pytest.raises(CredentialVaultError, match="credential.vault_key_invalid"):
            CredentialVault.from_key_fd(tmp_path / "vault", key_fd=descriptor)
    finally:
        os.close(descriptor)

    assert zeroed
    assert all(not any(buffer) for buffer in zeroed)


def test_entropy_failures_are_code_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.credential_vault as vault_module

    vault = vault_at(tmp_path)
    monkeypatch.setattr(
        vault_module.os,
        "urandom",
        lambda _size: (_ for _ in ()).throw(OSError("private entropy text")),
    )
    with pytest.raises(CredentialVaultError) as store_error:
        vault.store_projection("openai-one", 1, b"secret-marker")
    assert store_error.value.code == "credential.source_unavailable"
    assert "private entropy text" not in str(store_error.value)
    assert store_error.value.__cause__ is None

    monkeypatch.undo()
    vault.store_projection("openai-one", 1, b"secret-marker")
    monkeypatch.setattr(
        vault_module.secrets,
        "token_hex",
        lambda _size: (_ for _ in ()).throw(OSError("private token text")),
    )
    with pytest.raises(CredentialVaultError) as lease_error:
        vault.lease("openai-one", expected_generation=1, ttl_seconds=30)
    assert lease_error.value.code == "credential.source_unavailable"
    assert "private token text" not in str(lease_error.value)
    assert lease_error.value.__cause__ is None
