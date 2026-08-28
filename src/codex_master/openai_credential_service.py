"""Account-bound OpenAI auth synchronization and short-lived materialization."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import PurePosixPath
import re
import stat
import threading
import time
from typing import Final

from .codex_usage_credential_authority import (
    CredentialAuthorityError,
    MAX_AUTH_BYTES,
    validate_openai_auth_json,
)
from .credential_vault import CredentialVault, CredentialVaultError


MAX_AUTH_SYNC_PLAN_SECONDS: Final[int] = 5 * 60
_MAX_GENERATION: Final[int] = 2**63 - 1
_ACCOUNT_REF: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII
)
_BACKEND_ACCOUNT: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z", re.ASCII
)
_FINAL_NAME: Final[str] = "auth.json"
_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "control.plan_stale",
        "control.request_invalid",
        "credential.generation_conflict",
        "credential.source_unavailable",
        "credential.upload_expired",
        "oauth.identity_mismatch",
    }
)


class OpenAICredentialError(ValueError):
    """Stable, code-only OpenAI credential-service failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            raise TypeError("invalid OpenAI credential error code")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, repr=False)
class AuthSyncPlanV1:
    account_ref: str
    expected_generation: int
    expires_at: float
    nonce: str
    plan_digest: str
    _issuer: object

    def __repr__(self) -> str:
        return "AuthSyncPlanV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AuthSyncReceiptV1:
    account_ref: str
    generation: int
    plan_digest: str
    state: str = "succeeded"

    def __repr__(self) -> str:
        return "AuthSyncReceiptV1(<redacted>)"


class AuthorizedAuthIngress:
    """Capability-bound one-shot container for authorized raw auth bytes."""

    __slots__ = (
        "_account_ref",
        "_authority",
        "_consumed",
        "_generation",
        "_lock",
        "_nonce",
        "_payload",
        "_plan_digest",
        "_plan_issuer",
        "_process_id",
    )

    _account_ref: str
    _authority: object
    _consumed: bool
    _generation: int
    _lock: threading.Lock
    _nonce: str
    _payload: bytearray
    _plan_digest: str
    _plan_issuer: object
    _process_id: int

    def __init__(self) -> None:
        raise TypeError("AuthorizedAuthIngress requires authorized issuance")

    @classmethod
    def issue(
        cls,
        authority: object,
        plan: object,
        payload: bytes,
    ) -> AuthorizedAuthIngress:
        if (
            authority is None
            or not isinstance(plan, AuthSyncPlanV1)
            or type(payload) is not bytes
            or not 1 <= len(payload) <= MAX_AUTH_BYTES
        ):
            raise OpenAICredentialError("control.request_invalid")
        ingress = cls.__new__(cls)
        ingress._authority = authority
        ingress._plan_issuer = plan._issuer
        ingress._account_ref = plan.account_ref
        ingress._generation = plan.expected_generation
        ingress._nonce = plan.nonce
        ingress._plan_digest = plan.plan_digest
        ingress._payload = bytearray(payload)
        ingress._consumed = False
        ingress._process_id = os.getpid()
        ingress._lock = threading.Lock()
        return ingress

    def _consume(
        self,
        authority: object,
        plan: AuthSyncPlanV1,
        process_id: int,
    ) -> bytes:
        if (
            self._authority is not authority
            or self._plan_issuer is not plan._issuer
            or self._process_id != process_id
            or self._process_id != os.getpid()
            or self._account_ref != plan.account_ref
            or self._generation != plan.expected_generation
            or not hmac.compare_digest(self._nonce, plan.nonce)
            or not hmac.compare_digest(self._plan_digest, plan.plan_digest)
        ):
            raise OpenAICredentialError("credential.upload_expired")
        with self._lock:
            if self._consumed:
                raise OpenAICredentialError("credential.upload_expired")
            self._consumed = True
            try:
                return bytes(self._payload)
            finally:
                _zero(self._payload)

    def __repr__(self) -> str:
        return "AuthorizedAuthIngress(<redacted>)"


class OpenAICredentialService:
    """Synchronize authorized auth uploads and materialize one vault lease."""

    __slots__ = (
        "_applied",
        "_clock",
        "_identities",
        "_ingress_authority",
        "_lock",
        "_nonce_factory",
        "_plan_issuer",
        "_process_id",
        "_vault",
    )

    def __init__(
        self,
        vault: CredentialVault,
        account_identities: Mapping[str, str],
        *,
        ingress_authority: object,
        clock: Callable[[], float] | None = None,
        nonce_factory: Callable[[], bytes] | None = None,
    ) -> None:
        if (
            not isinstance(vault, CredentialVault)
            or not isinstance(account_identities, Mapping)
            or not 1 <= len(account_identities) <= 4096
            or ingress_authority is None
            or (clock is not None and not callable(clock))
            or (nonce_factory is not None and not callable(nonce_factory))
        ):
            raise OpenAICredentialError("control.request_invalid")
        identities: dict[str, str] = {}
        for account_ref, backend_account_id in account_identities.items():
            identities[_account_ref(account_ref)] = _backend_account(backend_account_id)
        self._vault = vault
        self._identities = identities
        self._ingress_authority = ingress_authority
        self._clock = clock or time.monotonic
        self._nonce_factory = nonce_factory or (lambda: os.urandom(32))
        self._plan_issuer = object()
        self._applied: dict[str, AuthSyncReceiptV1] = {}
        self._lock = threading.RLock()
        self._process_id = os.getpid()

    def __repr__(self) -> str:
        return "OpenAICredentialService(<redacted>)"

    def plan_auth_sync(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        ttl_seconds: int = MAX_AUTH_SYNC_PLAN_SECONDS,
    ) -> AuthSyncPlanV1:
        self._ensure_current_process()
        account_ref = self._registered_account(account_ref)
        expected_generation = _generation(expected_generation)
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or not 1 <= ttl_seconds <= MAX_AUTH_SYNC_PLAN_SECONDS
        ):
            raise OpenAICredentialError("control.request_invalid")
        now = self._now()
        nonce = self._new_nonce()
        expires_at = now + ttl_seconds
        plan_digest = _plan_digest(
            account_ref,
            expected_generation,
            expires_at,
            nonce,
        )
        return AuthSyncPlanV1(
            account_ref,
            expected_generation,
            expires_at,
            nonce,
            plan_digest,
            self._plan_issuer,
        )

    def apply_auth_sync(
        self,
        plan: AuthSyncPlanV1,
        upload: AuthorizedAuthIngress,
    ) -> AuthSyncReceiptV1:
        self._ensure_current_process()
        with self._lock:
            plan = self._validated_plan(plan)
            applied = self._applied.get(plan.plan_digest)
            if applied is not None:
                return applied
            if self._now() >= plan.expires_at:
                raise OpenAICredentialError("control.plan_stale")
            if not isinstance(upload, AuthorizedAuthIngress):
                raise OpenAICredentialError("credential.upload_expired")
            raw = upload._consume(self._ingress_authority, plan, self._process_id)
            expected_backend_account = self._identities[plan.account_ref]
            try:
                canonical = validate_openai_auth_json(
                    raw,
                    expected_account_id=expected_backend_account,
                )
            except CredentialAuthorityError as exc:
                if exc.code == "credential_identity_mismatch":
                    raise OpenAICredentialError("oauth.identity_mismatch") from None
                raise OpenAICredentialError("credential.source_unavailable") from None
            try:
                self._vault.store_projection(
                    plan.account_ref,
                    plan.expected_generation,
                    canonical,
                )
            except CredentialVaultError as exc:
                if exc.code == "credential.generation_conflict":
                    raise OpenAICredentialError(
                        "credential.generation_conflict"
                    ) from None
                raise OpenAICredentialError("credential.source_unavailable") from None
            receipt = AuthSyncReceiptV1(
                plan.account_ref,
                plan.expected_generation,
                plan.plan_digest,
            )
            self._applied[plan.plan_digest] = receipt
            return receipt

    @contextmanager
    def materialize_auth_lease(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        runtime_dir_fd: int,
    ) -> Iterator[PurePosixPath]:
        self._ensure_current_process()
        account_ref = self._registered_account(account_ref)
        expected_generation = _generation(expected_generation)
        runtime_fd, runtime_metadata = _duplicate_runtime_dir(runtime_dir_fd)
        materialized_fd: int | None = None
        materialized_metadata: tuple[int, ...] | None = None
        payload = bytearray()
        owner_pid = self._process_id
        published = False
        try:
            try:
                lease = self._vault.lease(
                    account_ref,
                    expected_generation=expected_generation,
                    ttl_seconds=MAX_AUTH_SYNC_PLAN_SECONDS,
                )
                payload = bytearray(self._vault.consume_lease(lease))
            except CredentialVaultError as exc:
                if exc.code == "credential.generation_conflict":
                    raise OpenAICredentialError(
                        "credential.generation_conflict"
                    ) from None
                raise OpenAICredentialError("credential.source_unavailable") from None
            materialized_fd, materialized_metadata = _publish_auth(
                runtime_fd,
                runtime_metadata,
                payload,
            )
            published = True
            try:
                yield PurePosixPath(_FINAL_NAME)
            except BaseException:
                if os.getpid() == owner_pid:
                    try:
                        _remove_auth(
                            runtime_fd,
                            runtime_metadata,
                            materialized_fd,
                            materialized_metadata,
                        )
                    except OpenAICredentialError:
                        pass
                    published = False
                raise
            else:
                if os.getpid() == owner_pid:
                    _remove_auth(
                        runtime_fd,
                        runtime_metadata,
                        materialized_fd,
                        materialized_metadata,
                    )
                    published = False
        finally:
            _zero(payload)
            if (
                published
                and materialized_fd is not None
                and materialized_metadata is not None
                and os.getpid() == owner_pid
            ):
                try:
                    _remove_auth(
                        runtime_fd,
                        runtime_metadata,
                        materialized_fd,
                        materialized_metadata,
                    )
                except OpenAICredentialError:
                    pass
            if materialized_fd is not None:
                _close(materialized_fd)
            _close(runtime_fd)

    def _validated_plan(self, plan: object) -> AuthSyncPlanV1:
        if (
            not isinstance(plan, AuthSyncPlanV1)
            or plan._issuer is not self._plan_issuer
            or plan.account_ref not in self._identities
            or _plan_digest(
                plan.account_ref,
                plan.expected_generation,
                plan.expires_at,
                plan.nonce,
            )
            != plan.plan_digest
        ):
            raise OpenAICredentialError("control.plan_stale")
        return plan

    def _registered_account(self, value: object) -> str:
        account_ref = _account_ref(value)
        if account_ref not in self._identities:
            raise OpenAICredentialError("control.request_invalid")
        return account_ref

    def _new_nonce(self) -> str:
        try:
            value = self._nonce_factory()
        except Exception:
            raise OpenAICredentialError("credential.source_unavailable") from None
        if type(value) is not bytes or len(value) != 32:
            raise OpenAICredentialError("credential.source_unavailable")
        return value.hex()

    def _now(self) -> float:
        try:
            value = self._clock()
        except Exception:
            raise OpenAICredentialError("credential.source_unavailable") from None
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise OpenAICredentialError("credential.source_unavailable")
        return float(value)

    def _ensure_current_process(self) -> None:
        if self._process_id != os.getpid():
            raise OpenAICredentialError("credential.source_unavailable")


def _account_ref(value: object) -> str:
    if type(value) is not str or _ACCOUNT_REF.fullmatch(value) is None:
        raise OpenAICredentialError("control.request_invalid")
    return value


def _backend_account(value: object) -> str:
    if type(value) is not str or _BACKEND_ACCOUNT.fullmatch(value) is None:
        raise OpenAICredentialError("control.request_invalid")
    return value


def _generation(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _MAX_GENERATION
    ):
        raise OpenAICredentialError("control.request_invalid")
    return value


def _plan_digest(
    account_ref: str,
    generation: int,
    expires_at: float,
    nonce: str,
) -> str:
    if (
        _ACCOUNT_REF.fullmatch(account_ref) is None
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= _MAX_GENERATION
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or not math.isfinite(expires_at)
        or type(nonce) is not str
        or re.fullmatch(r"[0-9a-f]{64}", nonce, re.ASCII) is None
    ):
        raise OpenAICredentialError("control.plan_stale")
    document = json.dumps(
        {
            "account_ref": account_ref,
            "expected_generation": generation,
            "expires_at": float(expires_at).hex(),
            "nonce": nonce,
            "schema_version": 1,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(b"codex-master/openai-auth-sync/v1\0" + document).hexdigest()


def _directory_metadata(value: os.stat_result) -> tuple[int, ...]:
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_IMODE(value.st_mode) != 0o700
        or value.st_uid != os.geteuid()
        or value.st_gid != os.getegid()
        or value.st_nlink < 1
    ):
        raise OpenAICredentialError("credential.source_unavailable")
    return _raw_directory_metadata(value)


def _raw_directory_metadata(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
    )


def _file_metadata(value: os.stat_result, expected_size: int) -> tuple[int, ...]:
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_uid != os.geteuid()
        or value.st_gid != os.getegid()
        or value.st_nlink != 1
        or value.st_size != expected_size
    ):
        raise OpenAICredentialError("credential.source_unavailable")
    return _raw_file_metadata(value)


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


def _duplicate_runtime_dir(value: object) -> tuple[int, tuple[int, ...]]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise OpenAICredentialError("credential.source_unavailable")
    duplicate: int | None = None
    try:
        before = _directory_metadata(os.fstat(value))
        duplicate = os.dup(value)
        os.set_inheritable(duplicate, False)
        copied = _directory_metadata(os.fstat(duplicate))
        after = _directory_metadata(os.fstat(value))
        if before != copied or copied != after:
            raise OpenAICredentialError("credential.source_unavailable")
        return duplicate, copied
    except OpenAICredentialError:
        _close(duplicate)
        raise
    except Exception:
        _close(duplicate)
        raise OpenAICredentialError("credential.source_unavailable") from None


def _reattest_directory(fd: int, expected: tuple[int, ...]) -> None:
    try:
        observed = _directory_metadata(os.fstat(fd))
    except OpenAICredentialError:
        raise
    except Exception:
        raise OpenAICredentialError("credential.source_unavailable") from None
    if observed != expected:
        raise OpenAICredentialError("credential.source_unavailable")


def _publish_auth(
    runtime_fd: int,
    runtime_metadata: tuple[int, ...],
    payload: bytearray,
) -> tuple[int, tuple[int, ...]]:
    temporary = ""
    descriptor: int | None = None
    linked = False
    succeeded = False
    try:
        _reattest_directory(runtime_fd, runtime_metadata)
        try:
            random_part = os.urandom(16).hex()
        except Exception:
            raise OpenAICredentialError("credential.source_unavailable") from None
        temporary = f".{_FINAL_NAME}.{random_part}.tmp"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=runtime_fd,
        )
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
        before = _file_metadata(os.fstat(descriptor), len(payload))
        _reattest_directory(runtime_fd, runtime_metadata)
        os.link(
            temporary,
            _FINAL_NAME,
            src_dir_fd=runtime_fd,
            dst_dir_fd=runtime_fd,
            follow_symlinks=False,
        )
        linked = True
        os.unlink(temporary, dir_fd=runtime_fd)
        temporary = ""
        os.fsync(runtime_fd)
        _reattest_directory(runtime_fd, runtime_metadata)
        named = _file_metadata(
            os.stat(_FINAL_NAME, dir_fd=runtime_fd, follow_symlinks=False),
            len(payload),
        )
        opened = _file_metadata(os.fstat(descriptor), len(payload))
        if before[:2] != named[:2] or named != opened:
            raise OpenAICredentialError("credential.source_unavailable")
        succeeded = True
        return descriptor, opened
    except OpenAICredentialError:
        raise
    except Exception:
        raise OpenAICredentialError("credential.source_unavailable") from None
    finally:
        if temporary:
            try:
                os.unlink(temporary, dir_fd=runtime_fd)
                os.fsync(runtime_fd)
            except OSError:
                pass
        if not succeeded and linked and descriptor is not None:
            try:
                named_info = os.stat(
                    _FINAL_NAME,
                    dir_fd=runtime_fd,
                    follow_symlinks=False,
                )
                if (named_info.st_dev, named_info.st_ino) == (
                    os.fstat(descriptor).st_dev,
                    os.fstat(descriptor).st_ino,
                ):
                    os.unlink(_FINAL_NAME, dir_fd=runtime_fd)
                    os.fsync(runtime_fd)
            except OSError:
                pass
        if not succeeded and descriptor is not None:
            _close(descriptor)


def _remove_auth(
    runtime_fd: int,
    runtime_metadata: tuple[int, ...],
    descriptor: int,
    expected_metadata: tuple[int, ...],
) -> None:
    try:
        directory_before = _raw_directory_metadata(os.fstat(runtime_fd))
        if directory_before[:2] != runtime_metadata[:2]:
            raise OpenAICredentialError("credential.source_unavailable")
        directory_drifted = directory_before != runtime_metadata
        opened = _raw_file_metadata(os.fstat(descriptor))
        named_info = os.stat(
            _FINAL_NAME,
            dir_fd=runtime_fd,
            follow_symlinks=False,
        )
        named = _raw_file_metadata(named_info)
        if opened[:2] != named[:2]:
            raise OpenAICredentialError("credential.source_unavailable")
        drifted = opened != expected_metadata or named != expected_metadata
        os.unlink(_FINAL_NAME, dir_fd=runtime_fd)
        os.fsync(runtime_fd)
        directory_after = _raw_directory_metadata(os.fstat(runtime_fd))
        if directory_after[:2] != runtime_metadata[:2]:
            raise OpenAICredentialError("credential.source_unavailable")
        if drifted or directory_drifted or directory_after != runtime_metadata:
            raise OpenAICredentialError("credential.source_unavailable")
    except OpenAICredentialError:
        raise
    except Exception:
        raise OpenAICredentialError("credential.source_unavailable") from None


def _zero(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _close(value: int | None) -> None:
    if value is None:
        return
    try:
        os.close(value)
    except OSError:
        pass


__all__ = (
    "AuthorizedAuthIngress",
    "AuthSyncPlanV1",
    "AuthSyncReceiptV1",
    "MAX_AUTH_SYNC_PLAN_SECONDS",
    "OpenAICredentialError",
    "OpenAICredentialService",
)
