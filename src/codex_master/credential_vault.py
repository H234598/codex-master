"""Encrypted, generation-bound credential projections and one-shot leases."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import struct
import threading
import time
from typing import Final, cast
import weakref

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .hive.state import HiveStateError, HiveStateStore


MAX_PROJECTION_BYTES: Final[int] = 1024 * 1024
MAX_LEASE_SECONDS: Final[int] = 5 * 60
MAX_ACTIVE_LEASES: Final[int] = 4096

_MAX_GENERATION: Final[int] = 2**63 - 1
_MAX_ACCOUNT_REF_BYTES: Final[int] = 128
_NONCE_BYTES: Final[int] = 12
_TAG_BYTES: Final[int] = 16
_MAGIC: Final[bytes] = b"CMVAULT\0"
_LEGACY_SCHEMA_VERSION: Final[int] = 1
_SCHEMA_VERSION: Final[int] = 2
_STATE_ACTIVE: Final[int] = 1
_STATE_REVOKED: Final[int] = 2
_LEGACY_HEADER: Final[struct.Struct] = struct.Struct(">8sBQ12s")
_HEADER: Final[struct.Struct] = struct.Struct(">8sBBQ12s")
_MAX_LEGACY_FILE_BYTES: Final[int] = (
    _LEGACY_HEADER.size + MAX_PROJECTION_BYTES + _TAG_BYTES
)
_MAX_ENVELOPE_BYTES: Final[int] = 2 + _MAX_ACCOUNT_REF_BYTES + MAX_PROJECTION_BYTES
_MAX_VAULT_FILE_BYTES: Final[int] = _HEADER.size + _MAX_ENVELOPE_BYTES + _TAG_BYTES
_ACCOUNT_REF: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII
)
_MATERIALIZATION_DOCUMENT: Final[PurePosixPath] = PurePosixPath(
    "materialization-claims.json"
)
_MAX_MATERIALIZATION_BYTES: Final[int] = 2 * 1024 * 1024
_MAX_RUNTIME_PATH_BYTES: Final[int] = 4096
_MATERIALIZED_NAME: Final[str] = "auth.json"
_MATERIALIZED_CLAIM_XATTR: Final[str] = "user.codex_master_claim"
_MATERIALIZED_TEMP_NAME: Final[re.Pattern[str]] = re.compile(
    r"\.auth\.json\.[0-9a-f]{64}\.tmp\Z", re.ASCII
)
_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "credential.generation_conflict",
        "credential.lease_consumed",
        "credential.lease_expired",
        "credential.lease_limit",
        "credential.source_unavailable",
        "credential.vault_authentication_failed",
        "credential.vault_key_invalid",
        "credential.vault_request_invalid",
        "credential.vault_schema_invalid",
    }
)
_VAULT_INSTANCES: weakref.WeakSet[CredentialVault] = weakref.WeakSet()


def _invalidate_vaults_after_fork() -> None:
    for vault in tuple(_VAULT_INSTANCES):
        vault._invalidate_after_fork()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_invalidate_vaults_after_fork)


class CredentialVaultError(ValueError):
    """Stable, code-only credential-vault failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            raise TypeError("invalid credential vault error code")
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"CredentialVaultError({self.code!r})"


@dataclass(frozen=True, slots=True, repr=False)
class CredentialLease:
    """Opaque handle; credential bytes remain inside :class:`CredentialVault`."""

    _token: str
    _issuer: object

    def __repr__(self) -> str:
        return "<CredentialLease>"


@dataclass(frozen=True, slots=True, repr=False)
class CredentialCleanupTarget:
    """Attested runtime directory target; never rendered publicly."""

    directory_path: str
    directory_metadata: tuple[int, ...]
    temporary_name: str

    def __repr__(self) -> str:
        return "CredentialCleanupTarget(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class _LeaseState:
    account_ref: str
    generation: int
    expires_at: float
    process_id: int


class CredentialVault:
    """AES-256-GCM vault using bounded private atomic state primitives."""

    __slots__ = (
        "_cipher",
        "_clock",
        "_lease_issuer",
        "_lease_invalidators",
        "_lease_lock",
        "_leases",
        "_active_leases",
        "_process_id",
        "_owner_boot_id",
        "_owner_start_ticks",
        "_state",
        "__weakref__",
    )

    def __init__(
        self,
        state_root: Path,
        *,
        key_fd: int,
        clock: Callable[[], float] | None = None,
    ) -> None:
        key = self._read_key_fd(key_fd)
        self._initialize(state_root, key, clock=clock)

    @classmethod
    def from_key_fd(
        cls,
        state_root: Path,
        *,
        key_fd: int,
        clock: Callable[[], float] | None = None,
    ) -> CredentialVault:
        """Load one exact 256-bit key from an already-open private FD."""

        return cls(state_root, key_fd=key_fd, clock=clock)

    @classmethod
    def for_test(
        cls,
        state_root: Path,
        *,
        key: bytes,
        clock: Callable[[], float] | None = None,
    ) -> CredentialVault:
        """Construct with an explicit test-only key; production accepts only an FD."""

        if type(key) is not bytes or len(key) != 32:
            raise CredentialVaultError("credential.vault_key_invalid")
        vault = cls.__new__(cls)
        vault._initialize(state_root, bytearray(key), clock=clock)
        return vault

    def _initialize(
        self,
        state_root: Path,
        key: bytearray,
        *,
        clock: Callable[[], float] | None,
    ) -> None:
        if (
            not isinstance(state_root, Path)
            or not state_root.is_absolute()
            or (clock is not None and not callable(clock))
        ):
            self._zero(key)
            raise CredentialVaultError("credential.vault_request_invalid")
        try:
            self._cipher = AESGCM(bytes(key))
            self._state = HiveStateStore(state_root)
        except (HiveStateError, OSError, ValueError):
            raise CredentialVaultError("credential.source_unavailable") from None
        finally:
            self._zero(key)
        self._clock = clock or time.monotonic
        self._lease_issuer = object()
        self._lease_lock = threading.Lock()
        self._leases: dict[str, _LeaseState] = {}
        self._active_leases: set[str] = set()
        self._lease_invalidators: dict[str, Callable[[], None]] = {}
        self._process_id = os.getpid()
        self._owner_boot_id = self._boot_id()
        self._owner_start_ticks = self._process_start_ticks(self._process_id)
        if not self._owner_boot_id or self._owner_start_ticks <= 0:
            raise CredentialVaultError("credential.source_unavailable")
        _VAULT_INSTANCES.add(self)

    @staticmethod
    def _read_key_fd(key_fd: int) -> bytearray:
        if isinstance(key_fd, bool) or not isinstance(key_fd, int) or key_fd < 0:
            raise CredentialVaultError("credential.vault_key_invalid")
        key = bytearray()
        verification = bytearray()
        accepted = False
        try:
            before = os.fstat(key_fd)
            if CredentialVault._valid_key_metadata(before):
                offset_before = os.lseek(key_fd, 0, os.SEEK_CUR)
                key = bytearray(os.pread(key_fd, 33, 0))
                eof_after_key = os.pread(key_fd, 1, 32)
                middle = os.fstat(key_fd)
                verification = bytearray(os.pread(key_fd, 33, 0))
                verification_eof = os.pread(key_fd, 1, 32)
                after = os.fstat(key_fd)
                offset_after = os.lseek(key_fd, 0, os.SEEK_CUR)
                accepted = (
                    CredentialVault._valid_key_metadata(middle)
                    and CredentialVault._valid_key_metadata(after)
                    and CredentialVault._key_metadata(before)
                    == CredentialVault._key_metadata(middle)
                    == CredentialVault._key_metadata(after)
                    and len(key) == 32
                    and len(verification) == 32
                    and not eof_after_key
                    and not verification_eof
                    and offset_before == offset_after
                    and hmac.compare_digest(key, verification)
                )
        except OSError:
            accepted = False
        finally:
            CredentialVault._zero(verification)
            if not accepted:
                CredentialVault._zero(key)
        if not accepted:
            raise CredentialVaultError("credential.vault_key_invalid")
        return key

    @staticmethod
    def _valid_key_metadata(info: os.stat_result) -> bool:
        return (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid in {0, os.geteuid()}
            and stat.S_IMODE(info.st_mode) in {0o400, 0o600}
            and info.st_size == 32
        )

    @staticmethod
    def _key_metadata(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_size,
            info.st_uid,
            info.st_nlink,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def store_projection(
        self, account_ref: str, generation: int, plaintext: bytes
    ) -> None:
        self._ensure_current_process()
        account_ref = self._validated_account_ref(account_ref)
        generation = self._validated_generation(generation)
        if (
            type(plaintext) is not bytes
            or not plaintext
            or len(plaintext) > MAX_PROJECTION_BYTES
        ):
            raise CredentialVaultError("credential.vault_request_invalid")

        record = self._encrypt_record(account_ref, generation, _STATE_ACTIVE, plaintext)
        relative = self._relative(account_ref)

        invalidators: tuple[Callable[[], None], ...] = ()
        cleanup_failed = False
        try:
            with self._state.locked():
                current = self._read_or_migrate_locked(account_ref)
                if current is not None and generation <= current[1]:
                    raise CredentialVaultError("credential.generation_conflict")
                self._state.replace_private_bytes(relative, record)
                cleanup_failed = self._invalidate_materializations_locked(account_ref)
                invalidators = self._invalidate_account_leases_locked(
                    account_ref, active_only=True
                )
        except CredentialVaultError:
            raise
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None
        self._invoke_invalidators(invalidators)
        if cleanup_failed:
            raise CredentialVaultError("credential.source_unavailable")

    def lease(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        ttl_seconds: int,
    ) -> CredentialLease:
        self._ensure_current_process()
        account_ref = self._validated_account_ref(account_ref)
        expected_generation = self._validated_generation(expected_generation)
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or not 1 <= ttl_seconds <= MAX_LEASE_SECONDS
        ):
            raise CredentialVaultError("credential.vault_request_invalid")

        generation, _plaintext = self._read_projection(account_ref)
        if generation != expected_generation:
            raise CredentialVaultError("credential.generation_conflict")
        now = self._now()
        state = _LeaseState(
            account_ref=account_ref,
            generation=generation,
            expires_at=now + ttl_seconds,
            process_id=self._process_id,
        )
        with self._lease_lock:
            invalidators = self._prune_expired_locked(now)
        self._invoke_invalidators(invalidators)
        with self._lease_lock:
            if len(self._leases) >= MAX_ACTIVE_LEASES:
                raise CredentialVaultError("credential.lease_limit")
            token = self._new_lease_token_locked()
            self._leases[token] = state
        return CredentialLease(token, self._lease_issuer)

    def consume_lease(self, lease: CredentialLease) -> bytes:
        self._ensure_current_process()
        if (
            not isinstance(lease, CredentialLease)
            or lease._issuer is not self._lease_issuer
        ):
            raise CredentialVaultError("credential.vault_request_invalid")
        with self._lease_lock:
            if lease._token in self._active_leases:
                raise CredentialVaultError("credential.lease_consumed")
            state = self._leases.pop(lease._token, None)
        if state is None:
            raise CredentialVaultError("credential.lease_consumed")
        if self._now() >= state.expires_at:
            raise CredentialVaultError("credential.lease_expired")
        if state.process_id != self._process_id:
            raise CredentialVaultError("credential.lease_consumed")

        generation, plaintext = self._read_projection(state.account_ref)
        if generation != state.generation:
            raise CredentialVaultError("credential.generation_conflict")
        return plaintext

    @contextmanager
    def materialization_lease(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        ttl_seconds: int,
        invalidator: Callable[[], None],
        cleanup_target: CredentialCleanupTarget,
        prepare: Callable[[], tuple[int, ...]],
    ) -> Iterator[tuple[CredentialLease, bytes]]:
        """Issue one durable active lease with exactly one projection read."""

        active, plaintext = self.begin_materialization(
            account_ref,
            expected_generation=expected_generation,
            ttl_seconds=ttl_seconds,
            invalidator=invalidator,
            cleanup_target=cleanup_target,
            prepare=prepare,
        )
        try:
            yield active, plaintext
        finally:
            self.release_materialization(active)

    def begin_materialization(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        ttl_seconds: int,
        invalidator: Callable[[], None],
        cleanup_target: CredentialCleanupTarget,
        prepare: Callable[[], tuple[int, ...]],
    ) -> tuple[CredentialLease, bytes]:
        """Persist one account claim before returning decrypted bytes."""

        self._ensure_current_process()
        account_ref = self._validated_account_ref(account_ref)
        expected_generation = self._validated_generation(expected_generation)
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or not 1 <= ttl_seconds <= MAX_LEASE_SECONDS
            or not callable(invalidator)
            or not callable(prepare)
        ):
            raise CredentialVaultError("credential.vault_request_invalid")
        target = self._validated_cleanup_target(cleanup_target)
        now = self._now()
        try:
            with self._state.locked():
                claims = self._read_materialization_claims_locked()
                if any(claim["account_ref"] == account_ref for claim in claims):
                    raise CredentialVaultError("credential.lease_limit")
                with self._lease_lock:
                    if len(self._leases) >= MAX_ACTIVE_LEASES:
                        raise CredentialVaultError("credential.lease_limit")
                    token = self._new_lease_token_locked()
                    state = _LeaseState(
                        account_ref=account_ref,
                        generation=expected_generation,
                        expires_at=now + ttl_seconds,
                        process_id=self._process_id,
                    )
                    claims.append(
                        {
                            "account_ref": account_ref,
                            "directory_metadata": list(target.directory_metadata),
                            "directory_path": target.directory_path,
                            "expires_at": state.expires_at,
                            "file_metadata": None,
                            "generation": expected_generation,
                            "owner_boot_id": self._owner_boot_id,
                            "owner_pid": self._process_id,
                            "owner_start_ticks": self._owner_start_ticks,
                            "state": "leased",
                            "temporary_name": target.temporary_name,
                            "token": token,
                        }
                    )
                    self._write_materialization_claims_locked(claims)
                    self._leases[token] = state
                    self._active_leases.add(token)
                    self._lease_invalidators[token] = invalidator
                try:
                    prepared_metadata = self._validated_file_metadata(
                        prepare(), allow_empty=True
                    )
                    claim = claims[-1]
                    claim["file_metadata"] = list(prepared_metadata)
                    self._write_materialization_claims_locked(claims)
                    current = self._read_or_migrate_locked(account_ref)
                    if current is None or current[0] != _STATE_ACTIVE:
                        raise CredentialVaultError("credential.source_unavailable")
                    if current[1] != expected_generation:
                        raise CredentialVaultError("credential.generation_conflict")
                    plaintext = current[2]
                except BaseException:
                    with self._lease_lock:
                        self._remove_leases_locked((token,))
                    try:
                        claims[-1]["state"] = "invalidated"
                        if self._cleanup_claim(claims[-1]):
                            claims.pop()
                        self._write_materialization_claims_locked(claims)
                    except BaseException:
                        pass
                    raise
        except CredentialVaultError:
            raise
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None
        active = CredentialLease(token, self._lease_issuer)
        return active, plaintext

    def release_materialization(self, lease: CredentialLease) -> None:
        """Release process-local callback state; durable claim remains authoritative."""

        self._ensure_current_process()
        self._validated_issued_lease(lease)
        with self._lease_lock:
            self._remove_leases_locked((lease._token,))

    def complete_materialization(self, lease: CredentialLease) -> None:
        """Remove durable claim only after caller confirmed runtime cleanup."""

        self._ensure_current_process()
        self._validated_issued_lease(lease)
        try:
            with self._state.locked():
                claims = self._read_materialization_claims_locked()
                matching = [claim for claim in claims if claim["token"] == lease._token]
                if len(matching) > 1:
                    raise CredentialVaultError("credential.vault_schema_invalid")
                if matching:
                    if not self._cleanup_claim(matching[0]):
                        raise CredentialVaultError("credential.source_unavailable")
                    claims.remove(matching[0])
                    self._write_materialization_claims_locked(claims)
        except CredentialVaultError:
            raise
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None

    def abandon_materialization(self, lease: CredentialLease) -> None:
        """Mark cleanup retryable by a restarted service in this process."""

        self._ensure_current_process()
        self._validated_issued_lease(lease)
        try:
            with self._state.locked():
                claims = self._read_materialization_claims_locked()
                claim = self._matching_claim(claims, lease._token)
                claim["state"] = "orphaned"
                self._write_materialization_claims_locked(claims)
        except CredentialVaultError:
            raise
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None

    def publish_active(
        self,
        lease: CredentialLease,
        effect: Callable[
            [Callable[[tuple[int, ...]], None]], tuple[int, tuple[int, ...]]
        ],
    ) -> tuple[int, tuple[int, ...]]:
        """Linearize one runtime publish before revoke/replace can commit."""

        self._ensure_current_process()
        if (
            not isinstance(lease, CredentialLease)
            or lease._issuer is not self._lease_issuer
            or not callable(effect)
        ):
            raise CredentialVaultError("credential.vault_request_invalid")
        try:
            with self._state.locked():
                claims = self._read_materialization_claims_locked()
                claim = self._matching_claim(claims, lease._token)
                with self._lease_lock:
                    state = self._leases.get(lease._token)
                    if state is None or lease._token not in self._active_leases:
                        raise CredentialVaultError("credential.lease_consumed")
                    if self._now() >= state.expires_at:
                        raise CredentialVaultError("credential.lease_expired")
                if claim["state"] != "leased":
                    raise CredentialVaultError("credential.lease_consumed")
                current = self._read_or_migrate_locked(state.account_ref)
                if (
                    current is None
                    or current[0] != _STATE_ACTIVE
                    or current[1] != state.generation
                ):
                    raise CredentialVaultError("credential.generation_conflict")
                claim["state"] = "publishing"
                self._write_materialization_claims_locked(claims)

                def record_file(metadata_value: tuple[int, ...]) -> None:
                    metadata = self._validated_file_metadata(metadata_value)
                    claim["file_metadata"] = list(metadata)
                    self._write_materialization_claims_locked(claims)

                result = effect(record_file)
                metadata = self._validated_file_metadata(result[1])
                recorded = tuple(cast(list[int], claim["file_metadata"]))
                if recorded[:5] != metadata[:5] or recorded[6] != metadata[6]:
                    raise CredentialVaultError("credential.source_unavailable")
                claim["file_metadata"] = list(metadata)
                claim["state"] = "published"
                self._write_materialization_claims_locked(claims)
                return result[0], metadata
        except CredentialVaultError:
            raise
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None

    def reconcile_active_leases(self) -> None:
        """Expire or invalidate live effects after cross-process vault mutation."""

        self._ensure_current_process()
        invalidators: tuple[Callable[[], None], ...] = ()
        try:
            with self._state.locked():
                claims = self._read_materialization_claims_locked()
                retained_claims: list[dict[str, object]] = []
                claims_changed = False
                now = self._now()
                claim_accounts: dict[str, tuple[int, int, bytes] | None] = {}
                for claim in claims:
                    claim_account = cast(str, claim["account_ref"])
                    if claim_account not in claim_accounts:
                        try:
                            claim_accounts[claim_account] = (
                                self._read_or_migrate_locked(claim_account)
                            )
                        except CredentialVaultError:
                            claim_accounts[claim_account] = None
                    current_claim = claim_accounts[claim_account]
                    invalid_claim = (
                        claim["state"] in {"invalidated", "orphaned"}
                        or now >= cast(float, claim["expires_at"])
                        or current_claim is None
                        or current_claim[0] != _STATE_ACTIVE
                        or current_claim[1] != claim["generation"]
                    )
                    if invalid_claim:
                        claim["state"] = "invalidated"
                        claims_changed = True
                        if self._cleanup_claim(claim):
                            continue
                    retained_claims.append(claim)
                if claims_changed:
                    self._write_materialization_claims_locked(retained_claims)
                with self._lease_lock:
                    invalid = {
                        token
                        for token, state in self._leases.items()
                        if now >= state.expires_at
                    }
                    accounts: dict[str, tuple[int, int, bytes] | None] = {}
                    for token in self._active_leases - invalid:
                        state = self._leases.get(token)
                        if state is None:
                            invalid.add(token)
                            continue
                        if state.account_ref not in accounts:
                            try:
                                accounts[state.account_ref] = (
                                    self._read_or_migrate_locked(state.account_ref)
                                )
                            except CredentialVaultError:
                                accounts[state.account_ref] = None
                        current = accounts[state.account_ref]
                        if (
                            current is None
                            or current[0] != _STATE_ACTIVE
                            or current[1] != state.generation
                        ):
                            invalid.add(token)
                    invalidators = self._remove_leases_locked(tuple(invalid))
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None
        self._invoke_invalidators(invalidators)

    def recover_materializations(self) -> None:
        """Retry cleanup for expired, orphaned, or provably dead owners."""

        self._ensure_current_process()
        try:
            with self._state.locked():
                claims = self._read_materialization_claims_locked()
                retained: list[dict[str, object]] = []
                for claim in claims:
                    recoverable = (
                        claim["state"] in {"invalidated", "orphaned"}
                        or self._now() >= cast(float, claim["expires_at"])
                        or self._claim_owner_dead(claim)
                    )
                    if not recoverable or not self._cleanup_claim(claim):
                        retained.append(claim)
                if retained != claims:
                    self._write_materialization_claims_locked(retained)
        except CredentialVaultError:
            raise
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None

    def _invalidate_materializations_locked(self, account_ref: str) -> bool:
        claims = self._read_materialization_claims_locked()
        targets = [claim for claim in claims if claim["account_ref"] == account_ref]
        if not targets:
            return False
        for claim in targets:
            claim["state"] = "invalidated"
        self._write_materialization_claims_locked(claims)
        failed = False
        for claim in targets:
            if self._cleanup_claim(claim):
                claims.remove(claim)
            else:
                failed = True
        self._write_materialization_claims_locked(claims)
        return failed

    def revoke_account(self, account_ref: str, *, expected_generation: int) -> bool:
        self._ensure_current_process()
        account_ref = self._validated_account_ref(account_ref)
        expected_generation = self._validated_generation(expected_generation)
        relative = self._relative(account_ref)
        invalidators: tuple[Callable[[], None], ...] = ()
        cleanup_failed = False
        try:
            with self._state.locked():
                current = self._read_or_migrate_locked(account_ref)
                if current is None or current[0] != _STATE_ACTIVE:
                    raise CredentialVaultError("credential.generation_conflict")
                if current[1] != expected_generation:
                    raise CredentialVaultError("credential.generation_conflict")
                tombstone = self._encrypt_record(
                    account_ref, expected_generation, _STATE_REVOKED, b""
                )
                self._state.replace_private_bytes(relative, tombstone)
                cleanup_failed = self._invalidate_materializations_locked(account_ref)
                invalidators = self._invalidate_account_leases_locked(
                    account_ref, active_only=False
                )
        except CredentialVaultError:
            raise
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None
        self._invoke_invalidators(invalidators)
        if cleanup_failed:
            raise CredentialVaultError("credential.source_unavailable")
        return True

    def _read_projection(self, account_ref: str) -> tuple[int, bytes]:
        try:
            with self._state.locked():
                current = self._read_or_migrate_locked(account_ref)
        except CredentialVaultError:
            raise
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None
        if current is None:
            raise CredentialVaultError("credential.source_unavailable")
        record_state, generation, plaintext = current
        if record_state != _STATE_ACTIVE:
            raise CredentialVaultError("credential.source_unavailable")
        return generation, plaintext

    def _read_or_migrate_locked(
        self, account_ref: str
    ) -> tuple[int, int, bytes] | None:
        relative = self._relative(account_ref)
        legacy_relative = self._legacy_relative(account_ref)
        hashed_raw = self._read_raw_optional_locked(relative)
        legacy_raw = (
            None
            if legacy_relative is None or legacy_relative == relative
            else self._read_raw_optional_locked(legacy_relative)
        )

        hashed: tuple[int, int, bytes] | None = None
        hashed_is_legacy = False
        if hashed_raw is not None:
            schema_version = self._record_schema(hashed_raw)
            if schema_version == _SCHEMA_VERSION:
                hashed = self._decrypt_record(hashed_raw, account_ref)
            elif schema_version == _LEGACY_SCHEMA_VERSION:
                generation, plaintext = self._decrypt_legacy_record(
                    hashed_raw, account_ref
                )
                hashed = _STATE_ACTIVE, generation, plaintext
                hashed_is_legacy = True
            else:
                raise CredentialVaultError("credential.vault_schema_invalid")

        legacy: tuple[int, bytes] | None = None
        if legacy_raw is not None:
            legacy = self._decrypt_legacy_record(legacy_raw, account_ref)

        if hashed is not None and legacy is not None:
            legacy_generation, legacy_plaintext = legacy
            if not self._same_active_projection(
                hashed, legacy_generation, legacy_plaintext
            ):
                raise CredentialVaultError("credential.vault_authentication_failed")
            if legacy_relative is None:
                raise CredentialVaultError("credential.vault_schema_invalid")
            migrated = (
                self._encrypt_record(
                    account_ref, legacy_generation, _STATE_ACTIVE, legacy_plaintext
                )
                if hashed_is_legacy
                else None
            )
            self._state.remove_private_bytes(legacy_relative)
            if migrated is not None:
                self._state.replace_private_bytes(relative, migrated)
            return _STATE_ACTIVE, legacy_generation, legacy_plaintext

        if hashed is not None:
            if hashed_is_legacy:
                state, generation, plaintext = hashed
                migrated = self._encrypt_record(
                    account_ref, generation, state, plaintext
                )
                self._state.replace_private_bytes(relative, migrated)
            return hashed

        if legacy is None or legacy_raw is None or legacy_relative is None:
            return None

        generation, plaintext = legacy
        migrated = self._encrypt_record(
            account_ref, generation, _STATE_ACTIVE, plaintext
        )
        self._state.replace_private_bytes(relative, legacy_raw)
        self._state.remove_private_bytes(legacy_relative)
        self._state.replace_private_bytes(relative, migrated)
        return _STATE_ACTIVE, generation, plaintext

    def _read_raw_optional_locked(self, relative: PurePosixPath) -> bytes | None:
        try:
            raw = self._state.read_private_bytes(
                relative, max_bytes=_MAX_VAULT_FILE_BYTES
            )
        except HiveStateError as exc:
            if str(exc) == "state_not_found":
                return None
            raise
        return raw

    @staticmethod
    def _record_schema(raw: bytes) -> int:
        if len(raw) < len(_MAGIC) + 1 or raw[: len(_MAGIC)] != _MAGIC:
            raise CredentialVaultError("credential.vault_schema_invalid")
        return raw[len(_MAGIC)]

    @staticmethod
    def _same_active_projection(
        hashed: tuple[int, int, bytes], generation: int, plaintext: bytes
    ) -> bool:
        return (
            hashed[0] == _STATE_ACTIVE
            and hashed[1] == generation
            and hmac.compare_digest(hashed[2], plaintext)
        )

    def _decrypt_legacy_record(self, raw: bytes, account_ref: str) -> tuple[int, bytes]:
        if len(raw) < _LEGACY_HEADER.size + _TAG_BYTES:
            raise CredentialVaultError("credential.vault_schema_invalid")
        try:
            magic, schema_version, generation, nonce = _LEGACY_HEADER.unpack_from(raw)
        except struct.error:
            raise CredentialVaultError("credential.vault_schema_invalid") from None
        if (
            magic != _MAGIC
            or schema_version != _LEGACY_SCHEMA_VERSION
            or not 1 <= generation <= _MAX_GENERATION
            or len(raw) > _MAX_LEGACY_FILE_BYTES
        ):
            raise CredentialVaultError("credential.vault_schema_invalid")
        try:
            plaintext = self._cipher.decrypt(
                nonce,
                raw[_LEGACY_HEADER.size :],
                self._legacy_aad(account_ref, generation),
            )
        except InvalidTag:
            raise CredentialVaultError(
                "credential.vault_authentication_failed"
            ) from None
        if not plaintext or len(plaintext) > MAX_PROJECTION_BYTES:
            raise CredentialVaultError("credential.vault_schema_invalid")
        return generation, plaintext

    def _decrypt_record(self, raw: bytes, account_ref: str) -> tuple[int, int, bytes]:
        if len(raw) < _HEADER.size + _TAG_BYTES:
            raise CredentialVaultError("credential.vault_schema_invalid")
        try:
            magic, schema_version, record_state, generation, nonce = (
                _HEADER.unpack_from(raw)
            )
        except struct.error:
            raise CredentialVaultError("credential.vault_schema_invalid") from None
        if (
            magic != _MAGIC
            or schema_version != _SCHEMA_VERSION
            or record_state not in {_STATE_ACTIVE, _STATE_REVOKED}
            or not 1 <= generation <= _MAX_GENERATION
            or len(raw) > _MAX_VAULT_FILE_BYTES
        ):
            raise CredentialVaultError("credential.vault_schema_invalid")
        try:
            envelope = self._cipher.decrypt(
                nonce,
                raw[_HEADER.size :],
                self._aad(account_ref, generation, record_state),
            )
        except InvalidTag:
            raise CredentialVaultError(
                "credential.vault_authentication_failed"
            ) from None
        encoded_ref = account_ref.encode("ascii")
        if len(envelope) < 2 + len(encoded_ref):
            raise CredentialVaultError("credential.vault_schema_invalid")
        ref_size = int.from_bytes(envelope[:2], "big")
        stored_ref = envelope[2 : 2 + ref_size]
        plaintext = envelope[2 + ref_size :]
        if (
            ref_size != len(encoded_ref)
            or not hmac.compare_digest(stored_ref, encoded_ref)
            or (record_state == _STATE_ACTIVE and not plaintext)
            or (record_state == _STATE_REVOKED and plaintext)
            or len(plaintext) > MAX_PROJECTION_BYTES
        ):
            raise CredentialVaultError("credential.vault_schema_invalid")
        return record_state, generation, plaintext

    def _encrypt_record(
        self,
        account_ref: str,
        generation: int,
        record_state: int,
        plaintext: bytes,
    ) -> bytes:
        nonce: bytes | None
        try:
            nonce = os.urandom(_NONCE_BYTES)
        except OSError:
            nonce = None
        if type(nonce) is not bytes or len(nonce) != _NONCE_BYTES:
            raise CredentialVaultError("credential.source_unavailable")
        encoded_ref = account_ref.encode("ascii")
        envelope = len(encoded_ref).to_bytes(2, "big") + encoded_ref + plaintext
        ciphertext = self._cipher.encrypt(
            nonce,
            envelope,
            self._aad(account_ref, generation, record_state),
        )
        return (
            _HEADER.pack(_MAGIC, _SCHEMA_VERSION, record_state, generation, nonce)
            + ciphertext
        )

    @staticmethod
    def _aad(account_ref: str, generation: int, record_state: int) -> bytes:
        encoded = account_ref.encode("ascii")
        return (
            b"codex-master-credential-projection\0"
            + bytes([_SCHEMA_VERSION])
            + bytes([record_state])
            + len(encoded).to_bytes(2, "big")
            + encoded
            + generation.to_bytes(8, "big")
        )

    @staticmethod
    def _legacy_aad(account_ref: str, generation: int) -> bytes:
        encoded = account_ref.encode("ascii")
        return (
            b"codex-master-credential-projection\0"
            + bytes([_LEGACY_SCHEMA_VERSION])
            + len(encoded).to_bytes(2, "big")
            + encoded
            + generation.to_bytes(8, "big")
        )

    @staticmethod
    def _relative(account_ref: str) -> PurePosixPath:
        return PurePosixPath(CredentialVault._storage_name(account_ref))

    @staticmethod
    def _legacy_relative(account_ref: str) -> PurePosixPath | None:
        name = f"{account_ref}.vault"
        if len(name) > 128:
            return None
        return PurePosixPath(name)

    @staticmethod
    def _storage_name(account_ref: str) -> str:
        digest = hashlib.sha256(account_ref.encode("ascii")).hexdigest()
        return f"{digest}.vault"

    @staticmethod
    def _validated_account_ref(account_ref: str) -> str:
        if (
            type(account_ref) is not str
            or len(account_ref.encode("utf-8", errors="replace"))
            > _MAX_ACCOUNT_REF_BYTES
            or _ACCOUNT_REF.fullmatch(account_ref) is None
        ):
            raise CredentialVaultError("credential.vault_request_invalid")
        return account_ref

    @staticmethod
    def _validated_generation(generation: int) -> int:
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or not 1 <= generation <= _MAX_GENERATION
        ):
            raise CredentialVaultError("credential.vault_request_invalid")
        return generation

    def _now(self) -> float:
        try:
            value = self._clock()
        except Exception:
            raise CredentialVaultError("credential.source_unavailable") from None
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise CredentialVaultError("credential.source_unavailable")
        return float(value)

    def _ensure_current_process(self) -> None:
        if self._process_id != os.getpid():
            self._invalidate_after_fork()
            raise CredentialVaultError("credential.source_unavailable")

    @staticmethod
    def _validated_cleanup_target(
        value: CredentialCleanupTarget,
    ) -> CredentialCleanupTarget:
        if (
            not isinstance(value, CredentialCleanupTarget)
            or type(value.directory_path) is not str
            or not value.directory_path.startswith("/")
            or "\x00" in value.directory_path
            or len(value.directory_path.encode("utf-8", errors="replace"))
            > _MAX_RUNTIME_PATH_BYTES
            or type(value.temporary_name) is not str
            or _MATERIALIZED_TEMP_NAME.fullmatch(value.temporary_name) is None
        ):
            raise CredentialVaultError("credential.vault_request_invalid")
        metadata = value.directory_metadata
        if (
            type(metadata) is not tuple
            or len(metadata) != 6
            or any(
                isinstance(item, bool) or not isinstance(item, int) for item in metadata
            )
            or not stat.S_ISDIR(metadata[2])
            or stat.S_IMODE(metadata[2]) != 0o700
            or metadata[3] != os.geteuid()
            or metadata[4] != os.getegid()
            or metadata[5] < 1
        ):
            raise CredentialVaultError("credential.vault_request_invalid")
        return value

    @staticmethod
    def _validated_file_metadata(
        value: object, *, allow_empty: bool = False
    ) -> tuple[int, ...]:
        if (
            type(value) is not tuple
            or len(value) != 9
            or any(
                isinstance(item, bool) or not isinstance(item, int) for item in value
            )
            or not stat.S_ISREG(value[2])
            or stat.S_IMODE(value[2]) != 0o600
            or value[3] != os.geteuid()
            or value[4] != os.getegid()
            or value[5] not in {1, 2}
            or not (0 if allow_empty else 1) <= value[6] <= MAX_PROJECTION_BYTES
        ):
            raise CredentialVaultError("credential.source_unavailable")
        return value

    def _validated_issued_lease(self, lease: CredentialLease) -> None:
        if (
            not isinstance(lease, CredentialLease)
            or lease._issuer is not self._lease_issuer
        ):
            raise CredentialVaultError("credential.vault_request_invalid")

    def _read_materialization_claims_locked(self) -> list[dict[str, object]]:
        try:
            raw = self._state.read_private_bytes(
                _MATERIALIZATION_DOCUMENT, max_bytes=_MAX_MATERIALIZATION_BYTES
            )
        except HiveStateError as exc:
            if exc.args == ("state_not_found",):
                return []
            raise
        try:
            document = json.loads(
                raw.decode("ascii"), object_pairs_hook=self._strict_json_object
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise CredentialVaultError("credential.vault_schema_invalid") from None
        if (
            not isinstance(document, Mapping)
            or set(document) != {"claims", "schema_version"}
            or document.get("schema_version") != 1
            or type(document.get("claims")) is not list
            or len(document["claims"]) > MAX_ACTIVE_LEASES
        ):
            raise CredentialVaultError("credential.vault_schema_invalid")
        claims = [self._validated_claim(value) for value in document["claims"]]
        tokens = [claim["token"] for claim in claims]
        accounts = [claim["account_ref"] for claim in claims]
        if len(set(tokens)) != len(tokens) or len(set(accounts)) != len(accounts):
            raise CredentialVaultError("credential.vault_schema_invalid")
        if raw != self._materialization_document(claims):
            raise CredentialVaultError("credential.vault_schema_invalid")
        return claims

    def _write_materialization_claims_locked(
        self, claims: list[dict[str, object]]
    ) -> None:
        raw = self._materialization_document(claims)
        if len(raw) > _MAX_MATERIALIZATION_BYTES:
            raise CredentialVaultError("credential.lease_limit")
        self._state.replace_private_bytes(_MATERIALIZATION_DOCUMENT, raw)

    def _validated_claim(self, value: object) -> dict[str, object]:
        fields = {
            "account_ref",
            "directory_metadata",
            "directory_path",
            "expires_at",
            "file_metadata",
            "generation",
            "owner_boot_id",
            "owner_pid",
            "owner_start_ticks",
            "state",
            "temporary_name",
            "token",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise CredentialVaultError("credential.vault_schema_invalid")
        claim = dict(value)
        try:
            self._validated_account_ref(claim["account_ref"])
            self._validated_generation(claim["generation"])
            target = CredentialCleanupTarget(
                cast(str, claim["directory_path"]),
                tuple(cast(list[int], claim["directory_metadata"])),
                cast(str, claim["temporary_name"]),
            )
            self._validated_cleanup_target(target)
        except (CredentialVaultError, TypeError):
            raise CredentialVaultError("credential.vault_schema_invalid") from None
        expires_at = claim["expires_at"]
        file_metadata = claim["file_metadata"]
        if (
            isinstance(expires_at, bool)
            or not isinstance(expires_at, (int, float))
            or not math.isfinite(expires_at)
            or type(claim["owner_boot_id"]) is not str
            or re.fullmatch(
                r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                cast(str, claim["owner_boot_id"]),
                re.ASCII,
            )
            is None
            or isinstance(claim["owner_pid"], bool)
            or not isinstance(claim["owner_pid"], int)
            or not 1 <= cast(int, claim["owner_pid"]) <= 2**31 - 1
            or isinstance(claim["owner_start_ticks"], bool)
            or not isinstance(claim["owner_start_ticks"], int)
            or not 1 <= cast(int, claim["owner_start_ticks"]) <= 2**63 - 1
            or claim["state"]
            not in {"leased", "publishing", "published", "invalidated", "orphaned"}
            or type(claim["token"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", cast(str, claim["token"]), re.ASCII)
            is None
            or (file_metadata is not None and type(file_metadata) is not list)
        ):
            raise CredentialVaultError("credential.vault_schema_invalid")
        if file_metadata is not None:
            try:
                self._validated_file_metadata(
                    tuple(cast(list[int], file_metadata)), allow_empty=True
                )
            except CredentialVaultError:
                raise CredentialVaultError("credential.vault_schema_invalid") from None
        claim["expires_at"] = float(expires_at)
        return claim

    @staticmethod
    def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise CredentialVaultError("credential.vault_schema_invalid")
            result[key] = value
        return result

    @staticmethod
    def _materialization_document(claims: list[dict[str, object]]) -> bytes:
        try:
            return (
                json.dumps(
                    {"claims": claims, "schema_version": 1},
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise CredentialVaultError("credential.vault_schema_invalid") from None

    @staticmethod
    def _matching_claim(
        claims: list[dict[str, object]], token: str
    ) -> dict[str, object]:
        matching = [claim for claim in claims if claim["token"] == token]
        if len(matching) != 1:
            raise CredentialVaultError("credential.lease_consumed")
        return matching[0]

    def _cleanup_claim(self, claim: Mapping[str, object]) -> bool:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                cast(str, claim["directory_path"]),
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            observed_directory = self._raw_directory_metadata(os.fstat(descriptor))
            if observed_directory != tuple(
                cast(list[int], claim["directory_metadata"])
            ):
                return False
            temporary_name = cast(str, claim["temporary_name"])
            expected = claim["file_metadata"]
            present: dict[str, os.stat_result] = {}
            for name in (temporary_name, _MATERIALIZED_NAME):
                try:
                    present[name] = os.stat(
                        name, dir_fd=descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    pass
            temporary = present.get(temporary_name)
            final = present.get(_MATERIALIZED_NAME)
            if expected is None:
                if temporary is None:
                    return final is None
                if final is not None or not self._safe_unbound_temporary(temporary):
                    return False
                os.unlink(temporary_name, dir_fd=descriptor)
                os.fsync(descriptor)
                return True
            claim_token = temporary_name.split(".")[-2].encode("ascii")
            if any(
                not self._claim_xattr_matches(descriptor, name, observed, claim_token)
                for name, observed in present.items()
            ):
                return False
            expected_metadata = tuple(cast(list[int], expected))
            if any(
                not self._bound_materialized_file(observed, expected_metadata)
                for observed in present.values()
            ):
                return False
            if (
                temporary is not None
                and final is not None
                and (
                    final.st_dev,
                    final.st_ino,
                )
                != (temporary.st_dev, temporary.st_ino)
            ):
                return False
            if claim["state"] == "published" and final is not None:
                if (
                    temporary is not None
                    or self._raw_file_metadata(final) != expected_metadata
                ):
                    return False
            for name in present:
                os.unlink(name, dir_fd=descriptor)
            if present:
                os.fsync(descriptor)
            return True
        except (CredentialVaultError, OSError, TypeError, ValueError):
            return False
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    @staticmethod
    def _safe_unbound_temporary(value: os.stat_result) -> bool:
        return (
            stat.S_ISREG(value.st_mode)
            and stat.S_IMODE(value.st_mode) == 0o600
            and value.st_uid == os.geteuid()
            and value.st_gid == os.getegid()
            and value.st_nlink == 1
            and value.st_size == 0
        )

    @staticmethod
    def _claim_xattr_matches(
        directory_fd: int,
        name: str,
        named: os.stat_result,
        expected: bytes,
    ) -> bool:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd
            )
            opened = os.fstat(descriptor)
            return (opened.st_dev, opened.st_ino) == (
                named.st_dev,
                named.st_ino,
            ) and hmac.compare_digest(
                os.getxattr(descriptor, _MATERIALIZED_CLAIM_XATTR), expected
            )
        except OSError:
            return False
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    @staticmethod
    def _bound_materialized_file(
        value: os.stat_result, expected: tuple[int, ...]
    ) -> bool:
        return (
            stat.S_ISREG(value.st_mode)
            and stat.S_IMODE(value.st_mode) == 0o600
            and value.st_uid == os.geteuid()
            and value.st_gid == os.getegid()
            and value.st_nlink in {1, 2}
            and (value.st_dev, value.st_ino) == expected[:2]
            and value.st_size <= MAX_PROJECTION_BYTES
        )

    @staticmethod
    def _raw_directory_metadata(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
        )

    @staticmethod
    def _raw_file_metadata(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    @staticmethod
    def _boot_id() -> str:
        try:
            value = (
                Path("/proc/sys/kernel/random/boot_id")
                .read_text(encoding="ascii")
                .strip()
            )
        except (OSError, UnicodeError):
            return ""
        return (
            value
            if re.fullmatch(
                r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                value,
                re.ASCII,
            )
            else ""
        )

    @staticmethod
    def _process_start_ticks(process_id: int) -> int:
        try:
            raw = Path(f"/proc/{process_id}/stat").read_text(encoding="ascii")
            close = raw.rfind(")")
            if close < 0:
                return -1
            fields = raw[close + 2 :].split()
            value = int(fields[19])
            return value if value >= 0 else -1
        except (OSError, UnicodeError, ValueError, IndexError):
            return -1

    def _claim_owner_dead(self, claim: Mapping[str, object]) -> bool:
        owner_boot = cast(str, claim["owner_boot_id"])
        if owner_boot and self._owner_boot_id and owner_boot != self._owner_boot_id:
            return True
        process_id = cast(int, claim["owner_pid"])
        observed = self._process_start_ticks(process_id)
        expected = cast(int, claim["owner_start_ticks"])
        if observed >= 0 and expected >= 0:
            return observed != expected
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return True
        except (OSError, ValueError):
            return False
        return False

    def _invalidate_after_fork(self) -> None:
        self._lease_lock = threading.Lock()
        self._leases = {}
        self._active_leases = set()
        self._lease_invalidators = {}
        self._lease_issuer = object()

    def _prune_expired_locked(self, now: float) -> tuple[Callable[[], None], ...]:
        expired = tuple(
            token for token, state in self._leases.items() if now >= state.expires_at
        )
        return self._remove_leases_locked(expired)

    def _invalidate_account_leases_locked(
        self, account_ref: str, *, active_only: bool
    ) -> tuple[Callable[[], None], ...]:
        with self._lease_lock:
            tokens = tuple(
                token
                for token, state in self._leases.items()
                if state.account_ref == account_ref
                and (not active_only or token in self._active_leases)
            )
            return self._remove_leases_locked(tokens)

    def _remove_leases_locked(
        self, tokens: tuple[str, ...]
    ) -> tuple[Callable[[], None], ...]:
        invalidators: list[Callable[[], None]] = []
        for token in tokens:
            self._leases.pop(token, None)
            self._active_leases.discard(token)
            invalidator = self._lease_invalidators.pop(token, None)
            if invalidator is not None:
                invalidators.append(invalidator)
        return tuple(invalidators)

    @staticmethod
    def _invoke_invalidators(invalidators: tuple[Callable[[], None], ...]) -> None:
        failed = False
        for invalidator in invalidators:
            try:
                invalidator()
            except BaseException:
                failed = True
        if failed:
            raise CredentialVaultError("credential.source_unavailable")

    def _new_lease_token_locked(self) -> str:
        while True:
            token: str | None
            try:
                token = secrets.token_hex(32)
            except OSError:
                token = None
            if type(token) is not str or len(token) != 64:
                raise CredentialVaultError("credential.source_unavailable")
            if token not in self._leases:
                return token

    @staticmethod
    def _zero(value: bytearray) -> None:
        for index in range(len(value)):
            value[index] = 0


__all__ = [
    "MAX_ACTIVE_LEASES",
    "MAX_LEASE_SECONDS",
    "MAX_PROJECTION_BYTES",
    "CredentialCleanupTarget",
    "CredentialLease",
    "CredentialVault",
    "CredentialVaultError",
]
