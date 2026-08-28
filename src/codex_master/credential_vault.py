"""Encrypted, generation-bound credential projections and one-shot leases."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import struct
import threading
import time
from typing import Final

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
_SCHEMA_VERSION: Final[int] = 1
_HEADER: Final[struct.Struct] = struct.Struct(">8sBQ12s")
_MAX_VAULT_FILE_BYTES: Final[int] = _HEADER.size + MAX_PROJECTION_BYTES + _TAG_BYTES
_ACCOUNT_REF: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII
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


@dataclass(frozen=True, slots=True)
class _LeaseState:
    account_ref: str
    generation: int
    expires_at: float


class CredentialVault:
    """AES-256-GCM vault using bounded private atomic state primitives."""

    __slots__ = (
        "_cipher",
        "_clock",
        "_lease_issuer",
        "_lease_lock",
        "_leases",
        "_state",
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

    @staticmethod
    def _read_key_fd(key_fd: int) -> bytearray:
        if isinstance(key_fd, bool) or not isinstance(key_fd, int) or key_fd < 0:
            raise CredentialVaultError("credential.vault_key_invalid")
        try:
            before = os.fstat(key_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
                or before.st_size != 32
            ):
                raise CredentialVaultError("credential.vault_key_invalid")
            key = bytearray(os.pread(key_fd, 33, 0))
            after = os.fstat(key_fd)
            if (
                len(key) != 32
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or before.st_size != after.st_size
            ):
                CredentialVault._zero(key)
                raise CredentialVaultError("credential.vault_key_invalid")
            return key
        except CredentialVaultError:
            raise
        except OSError:
            raise CredentialVaultError("credential.vault_key_invalid") from None

    def store_projection(
        self, account_ref: str, generation: int, plaintext: bytes
    ) -> None:
        account_ref = self._validated_account_ref(account_ref)
        generation = self._validated_generation(generation)
        if (
            type(plaintext) is not bytes
            or not plaintext
            or len(plaintext) > MAX_PROJECTION_BYTES
        ):
            raise CredentialVaultError("credential.vault_request_invalid")

        nonce = os.urandom(_NONCE_BYTES)
        aad = self._aad(account_ref, generation)
        ciphertext = self._cipher.encrypt(nonce, plaintext, aad)
        record = _HEADER.pack(_MAGIC, _SCHEMA_VERSION, generation, nonce) + ciphertext
        relative = self._relative(account_ref)

        try:
            with self._state.locked():
                current = self._read_optional_locked(relative, account_ref)
                if current is not None and generation <= current[0]:
                    raise CredentialVaultError("credential.generation_conflict")
                self._state.replace_private_bytes(relative, record)
        except CredentialVaultError:
            raise
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None

    def lease(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        ttl_seconds: int,
    ) -> CredentialLease:
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
        )
        with self._lease_lock:
            self._prune_expired_locked(now)
            if len(self._leases) >= MAX_ACTIVE_LEASES:
                raise CredentialVaultError("credential.lease_limit")
            token = self._new_lease_token_locked()
            self._leases[token] = state
        return CredentialLease(token, self._lease_issuer)

    def consume_lease(self, lease: CredentialLease) -> bytes:
        if (
            not isinstance(lease, CredentialLease)
            or lease._issuer is not self._lease_issuer
        ):
            raise CredentialVaultError("credential.vault_request_invalid")
        with self._lease_lock:
            state = self._leases.pop(lease._token, None)
        if state is None:
            raise CredentialVaultError("credential.lease_consumed")
        if self._now() >= state.expires_at:
            raise CredentialVaultError("credential.lease_expired")

        generation, plaintext = self._read_projection(state.account_ref)
        if generation != state.generation:
            raise CredentialVaultError("credential.generation_conflict")
        return plaintext

    def revoke_account(self, account_ref: str, *, expected_generation: int) -> bool:
        account_ref = self._validated_account_ref(account_ref)
        expected_generation = self._validated_generation(expected_generation)
        relative = self._relative(account_ref)
        try:
            with self._state.locked():
                current = self._read_optional_locked(relative, account_ref)
                if current is None:
                    raise CredentialVaultError("credential.generation_conflict")
                if current[0] != expected_generation:
                    raise CredentialVaultError("credential.generation_conflict")
                self._state.remove_private_bytes(relative)
        except CredentialVaultError:
            raise
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None
        with self._lease_lock:
            self._leases = {
                token: state
                for token, state in self._leases.items()
                if state.account_ref != account_ref
            }
        return True

    def _read_projection(self, account_ref: str) -> tuple[int, bytes]:
        relative = self._relative(account_ref)
        try:
            with self._state.locked():
                current = self._read_optional_locked(relative, account_ref)
        except CredentialVaultError:
            raise
        except HiveStateError:
            raise CredentialVaultError("credential.source_unavailable") from None
        if current is None:
            raise CredentialVaultError("credential.source_unavailable")
        return current

    def _read_optional_locked(
        self, relative: PurePosixPath, account_ref: str
    ) -> tuple[int, bytes] | None:
        try:
            raw = self._state.read_private_bytes(
                relative, max_bytes=_MAX_VAULT_FILE_BYTES
            )
        except HiveStateError as exc:
            if str(exc) == "state_not_found":
                return None
            raise
        return self._decrypt_record(raw, account_ref)

    def _decrypt_record(self, raw: bytes, account_ref: str) -> tuple[int, bytes]:
        if len(raw) < _HEADER.size + _TAG_BYTES:
            raise CredentialVaultError("credential.vault_schema_invalid")
        try:
            magic, schema_version, generation, nonce = _HEADER.unpack_from(raw)
        except struct.error:
            raise CredentialVaultError("credential.vault_schema_invalid") from None
        if (
            magic != _MAGIC
            or schema_version != _SCHEMA_VERSION
            or not 1 <= generation <= _MAX_GENERATION
            or len(raw) > _MAX_VAULT_FILE_BYTES
        ):
            raise CredentialVaultError("credential.vault_schema_invalid")
        try:
            plaintext = self._cipher.decrypt(
                nonce,
                raw[_HEADER.size :],
                self._aad(account_ref, generation),
            )
        except InvalidTag:
            raise CredentialVaultError(
                "credential.vault_authentication_failed"
            ) from None
        if not plaintext or len(plaintext) > MAX_PROJECTION_BYTES:
            raise CredentialVaultError("credential.vault_schema_invalid")
        return generation, plaintext

    @staticmethod
    def _aad(account_ref: str, generation: int) -> bytes:
        encoded = account_ref.encode("ascii")
        return (
            b"codex-master-credential-projection\0"
            + bytes([_SCHEMA_VERSION])
            + len(encoded).to_bytes(2, "big")
            + encoded
            + generation.to_bytes(8, "big")
        )

    @staticmethod
    def _relative(account_ref: str) -> PurePosixPath:
        return PurePosixPath(f"{account_ref}.vault")

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

    def _prune_expired_locked(self, now: float) -> None:
        self._leases = {
            token: state
            for token, state in self._leases.items()
            if now < state.expires_at
        }

    def _new_lease_token_locked(self) -> str:
        while True:
            token = secrets.token_hex(32)
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
    "CredentialLease",
    "CredentialVault",
    "CredentialVaultError",
]
