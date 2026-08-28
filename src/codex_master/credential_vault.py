"""Encrypted, generation-bound credential projections and one-shot leases."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
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
_SCHEMA_VERSION: Final[int] = 2
_STATE_ACTIVE: Final[int] = 1
_STATE_REVOKED: Final[int] = 2
_HEADER: Final[struct.Struct] = struct.Struct(">8sBBQ12s")
_MAX_ENVELOPE_BYTES: Final[int] = 2 + _MAX_ACCOUNT_REF_BYTES + MAX_PROJECTION_BYTES
_MAX_VAULT_FILE_BYTES: Final[int] = _HEADER.size + _MAX_ENVELOPE_BYTES + _TAG_BYTES
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
        "_lease_lock",
        "_leases",
        "_process_id",
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
        self._process_id = os.getpid()
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

        try:
            with self._state.locked():
                current = self._read_optional_locked(relative, account_ref)
                if current is not None and generation <= current[1]:
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
            self._prune_expired_locked(now)
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

    def revoke_account(self, account_ref: str, *, expected_generation: int) -> bool:
        self._ensure_current_process()
        account_ref = self._validated_account_ref(account_ref)
        expected_generation = self._validated_generation(expected_generation)
        relative = self._relative(account_ref)
        try:
            with self._state.locked():
                current = self._read_optional_locked(relative, account_ref)
                if current is None or current[0] != _STATE_ACTIVE:
                    raise CredentialVaultError("credential.generation_conflict")
                if current[1] != expected_generation:
                    raise CredentialVaultError("credential.generation_conflict")
                tombstone = self._encrypt_record(
                    account_ref, expected_generation, _STATE_REVOKED, b""
                )
                self._state.replace_private_bytes(relative, tombstone)
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
        record_state, generation, plaintext = current
        if record_state != _STATE_ACTIVE:
            raise CredentialVaultError("credential.source_unavailable")
        return generation, plaintext

    def _read_optional_locked(
        self, relative: PurePosixPath, account_ref: str
    ) -> tuple[int, int, bytes] | None:
        try:
            raw = self._state.read_private_bytes(
                relative, max_bytes=_MAX_VAULT_FILE_BYTES
            )
        except HiveStateError as exc:
            if str(exc) == "state_not_found":
                return None
            raise
        return self._decrypt_record(raw, account_ref)

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
    def _relative(account_ref: str) -> PurePosixPath:
        return PurePosixPath(CredentialVault._storage_name(account_ref))

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

    def _invalidate_after_fork(self) -> None:
        self._lease_lock = threading.Lock()
        self._leases = {}
        self._lease_issuer = object()

    def _prune_expired_locked(self, now: float) -> None:
        self._leases = {
            token: state
            for token, state in self._leases.items()
            if now < state.expires_at
        }

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
    "CredentialLease",
    "CredentialVault",
    "CredentialVaultError",
]
