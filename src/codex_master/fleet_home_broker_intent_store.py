"""Root-owned broker intent publication and single-consumer claim boundary.

The public functions in this module deliberately depend only on the narrow
``BrokerIntentStoreOperations`` protocol.  A platform adapter may implement
that protocol, but all filesystem authority remains behind injected
operations; this module never opens paths, sockets, or processes itself.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import re
from typing import Protocol

from codex_master.fleet_home_broker_intent import (
    MAX_BROKER_INTENT_BYTES,
    BrokerIntentCode,
    BrokerIntentError,
    BrokerIntentV1,
    decode_broker_intent,
    encode_broker_intent,
)
from codex_master.fleet_home_broker_identity_contract import ObjectIdentity
from codex_master.fleet_home_broker_linux_contract import (
    LinuxBrokerCode,
    LinuxBrokerError,
    open_beneath_no_symlink,
)


MAX_INTENT_STORE_NAME_BYTES = 256
MAX_INTENT_STORE_CODE_BYTES = 64
MAX_TERMINAL_INTENT_RECORDS = 128
MAX_QUARANTINED_INTENT_RECORDS = 128
INTENT_FILE_MODE = 0o100600
INTENT_PARENT_MODE = 0o40700
INTENT_SELINUX_LABEL = "system_u:object_r:codex_master_home_broker_state_t:s0"

_STORE_NAME = re.compile(r"[A-Za-z0-9.][A-Za-z0-9_.:@+\-]{0,255}\Z", re.ASCII)
_STORE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)
_INTENT_NAME = re.compile(
    r"intent-[0-9]{20}-[A-Za-z0-9][A-Za-z0-9_.:@+\-]{0,255}\.json\Z",
    re.ASCII,
)
_CLAIM_NAME = re.compile(
    r"\.claim-intent-[0-9]{20}-[A-Za-z0-9][A-Za-z0-9_.:@+\-]{0,255}\.json\Z",
    re.ASCII,
)


@dataclass(frozen=True, slots=True)
class BrokerIntentFileIdentity:
    """Identity and mandatory security label observed on one intent file."""

    dev: int
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    selinux_label: str = INTENT_SELINUX_LABEL


@dataclass(frozen=True, slots=True)
class BrokerIntentClaimBytes:
    """Bytes and identity returned after an adapter atomically claims a file."""

    claim_name: str
    payload: bytes
    source_identity: BrokerIntentFileIdentity


class BrokerIntentStoreOperations(Protocol):
    def publish(self, payload: bytes, final_name: str) -> None: ...

    def claim_next(self) -> BrokerIntentClaimBytes | None: ...

    def mark_terminal(self, claim_name: str, payload: bytes) -> None: ...

    def quarantine(self, claim_name: str, code: str) -> None: ...


class _LinuxIntentStoreOperations(Protocol):
    """Injected dirfd operations used by :class:`LinuxBrokerIntentStore`."""

    def openat2(self, parent_fd: int, name: str, how: object) -> object: ...

    def stat_fd(self, fd: int) -> object: ...

    def selinux_label(self, fd: int) -> str: ...

    def list_names(self, parent_fd: int) -> tuple[str, ...]: ...

    def read_all(self, fd: int) -> bytes: ...

    def write_all(self, fd: int, payload: bytes) -> int | None: ...

    def truncate(self, fd: int) -> None: ...

    def fsync(self, fd: int) -> None: ...

    def renameat2_noreplace(
        self, parent_fd: int, old_name: str, new_name: str
    ) -> None: ...

    def unlinkat(self, parent_fd: int, name: str) -> None: ...

    def close(self, fd: int) -> None: ...


def _final_name(intent: BrokerIntentV1) -> str:
    # A0 validates the nonce as one path-safe identifier.  Padding the
    # generation keeps directory enumeration deterministic while retaining a
    # bounded, single-component name.
    return f"intent-{intent.intent_generation:020d}-{intent.nonce}.json"


def _valid_name(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return (
            len(value.encode("ascii", "strict")) <= MAX_INTENT_STORE_NAME_BYTES
            and _STORE_NAME.fullmatch(value) is not None
        )
    except UnicodeEncodeError:
        return False


def _valid_code(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return (
            len(value.encode("ascii", "strict")) <= MAX_INTENT_STORE_CODE_BYTES
            and _STORE_CODE.fullmatch(value) is not None
        )
    except UnicodeEncodeError:
        return False


def _validate_claim(value: object) -> BrokerIntentClaimBytes:
    if type(value) is not BrokerIntentClaimBytes:
        raise BrokerIntentError(BrokerIntentCode.INVALID_TYPE)
    try:
        valid_name = _valid_name(value.claim_name)
    except UnicodeEncodeError:
        valid_name = False
    if not valid_name or type(value.payload) is not bytes:
        raise BrokerIntentError(BrokerIntentCode.INVALID_TYPE)
    if type(value.source_identity) is not BrokerIntentFileIdentity:
        raise BrokerIntentError(BrokerIntentCode.INVALID_TYPE)
    return value


def _public_operation_call(operations: object, method: str, *args: object) -> object:
    try:
        return getattr(operations, method)(*args)
    except BrokerIntentError:
        raise
    except Exception:
        normalized = BrokerIntentError(BrokerIntentCode.INVALID_FIELD)
    raise normalized


def _linux_fail(code: LinuxBrokerCode) -> None:
    raise LinuxBrokerError(code)


def _linux_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except LinuxBrokerError:
        raise
    except (NotImplementedError, OSError) as error:
        if isinstance(error, NotImplementedError) or error.errno in (
            errno.ENOSYS,
            errno.EOPNOTSUPP,
            errno.ENOTSUP,
        ):
            _linux_fail(LinuxBrokerCode.UNSUPPORTED_PLATFORM)
        if error.errno == errno.EEXIST:
            _linux_fail(LinuxBrokerCode.ALREADY_EXISTS)
        if error.errno == errno.ELOOP:
            _linux_fail(LinuxBrokerCode.UNSAFE_PATH)
        if error.errno == errno.EXDEV:
            _linux_fail(LinuxBrokerCode.CROSS_DEVICE)
        _linux_fail(LinuxBrokerCode.IO_FAILURE)
    except Exception:
        _linux_fail(LinuxBrokerCode.IO_FAILURE)
    raise AssertionError("unreachable")


def _object_identity(value: object) -> tuple[int, int, int, int, int, int]:
    if type(value) is not ObjectIdentity:
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    fields = (value.dev, value.ino, value.mode, value.uid, value.gid, value.nlink)
    if any(type(field) is not int for field in fields):
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    if value.dev < 0 or value.ino < 1 or value.mode < 0 or value.nlink < 1:
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    return fields


def _file_identity(value: object, label: str) -> BrokerIntentFileIdentity:
    if type(value) is BrokerIntentFileIdentity:
        identity = value
    elif type(value) is ObjectIdentity:
        dev, ino, mode, uid, gid, nlink = _object_identity(value)
        identity = BrokerIntentFileIdentity(dev, ino, mode, uid, gid, nlink, label)
    else:
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    fields = (
        identity.dev,
        identity.ino,
        identity.mode,
        identity.uid,
        identity.gid,
        identity.nlink,
    )
    if any(type(field) is not int for field in fields):
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    if identity.dev < 0 or identity.ino < 1 or identity.mode < 0 or identity.nlink < 1:
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    if type(identity.selinux_label) is not str or identity.selinux_label != label:
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    return identity


def _same_identity(
    left: BrokerIntentFileIdentity, right: BrokerIntentFileIdentity
) -> bool:
    return left == right


def _validate_parent_identity(
    identity: BrokerIntentFileIdentity, expected: object, label: str
) -> None:
    if identity.mode != INTENT_PARENT_MODE or identity.uid != 0 or identity.gid != 0:
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    if identity.nlink < 2:
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    if identity.selinux_label != label:
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    if type(expected) is BrokerIntentFileIdentity:
        if identity != expected:
            _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    elif type(expected) is ObjectIdentity:
        if identity != BrokerIntentFileIdentity(
            expected.dev,
            expected.ino,
            expected.mode,
            expected.uid,
            expected.gid,
            expected.nlink,
            label,
        ):
            _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    else:
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)


def _validate_regular_identity(identity: BrokerIntentFileIdentity, label: str) -> None:
    if (
        identity.mode != INTENT_FILE_MODE
        or identity.uid != 0
        or identity.gid != 0
        or identity.nlink != 1
        or identity.selinux_label != label
    ):
        _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)


class LinuxBrokerIntentStore:
    """Injected Linux dirfd adapter implementing the intent-store protocol.

    The constructor receives an already-open root parent descriptor and its
    expected identity.  All descendants are opened with ``openat2`` beneath
    that descriptor; no path-based operation is performed here.
    """

    _O_RDONLY = 0o0
    _O_WRONLY = 0o1
    _O_CREAT = 0o100
    _O_EXCL = 0o200

    def __init__(
        self,
        operations: _LinuxIntentStoreOperations,
        parent_fd: int,
        expected_parent_identity: BrokerIntentFileIdentity | ObjectIdentity,
        *,
        selinux_label: str = INTENT_SELINUX_LABEL,
    ) -> None:
        if type(parent_fd) is not int or parent_fd < 0:
            _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
        if type(selinux_label) is not str or not selinux_label:
            _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
        self._operations = operations
        self._parent_fd = parent_fd
        self._expected_parent_identity = expected_parent_identity
        self._selinux_label = selinux_label
        self._verify_parent()

    def _verify_parent(self) -> BrokerIntentFileIdentity:
        observed = _file_identity(
            _linux_call(self._operations.stat_fd, self._parent_fd),
            _linux_call(self._operations.selinux_label, self._parent_fd),
        )
        _validate_parent_identity(
            observed, self._expected_parent_identity, self._selinux_label
        )
        return observed

    def _open_file(self, name: str, flags: int) -> tuple[int, BrokerIntentFileIdentity]:
        if not _valid_name(name):
            _linux_fail(LinuxBrokerCode.UNSAFE_PATH)
        pinned = _linux_call(
            open_beneath_no_symlink,
            self._operations,
            self._parent_fd,
            name,
            flags=flags,
            mode=0o600,
        )
        # open_beneath_no_symlink validates the PinnedFd shape and all
        # openat2 resolve flags before this adapter checks the stronger file
        # policy.
        fd = pinned.fd
        try:
            label = _linux_call(self._operations.selinux_label, fd)
            pinned_identity = _file_identity(pinned.identity, label)
            identity = _file_identity(_linux_call(self._operations.stat_fd, fd), label)
            _validate_regular_identity(pinned_identity, self._selinux_label)
            _validate_regular_identity(identity, self._selinux_label)
            if not _same_identity(pinned_identity, identity):
                _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
            return fd, identity
        except Exception:
            try:
                self._operations.close(fd)
            except Exception:
                pass
            raise

    def _close(self, fd: int) -> None:
        try:
            self._operations.close(fd)
        except Exception:
            # Preserve the operation's primary failure and do not attempt a
            # path-based cleanup or compatibility fallback.
            pass

    def _payload(self, payload: object) -> bytes:
        if type(payload) is not bytes:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        if not payload or len(payload) > MAX_BROKER_INTENT_BYTES:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        return payload

    def _write_and_sync(self, fd: int, payload: bytes) -> None:
        result = _linux_call(self._operations.write_all, fd, payload)
        if result is not None and (type(result) is not int or result != len(payload)):
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        _linux_call(self._operations.fsync, fd)

    def _after_file_identity(
        self, fd: int, before: BrokerIntentFileIdentity
    ) -> BrokerIntentFileIdentity:
        after = _file_identity(
            _linux_call(self._operations.stat_fd, fd),
            _linux_call(self._operations.selinux_label, fd),
        )
        _validate_regular_identity(after, self._selinux_label)
        if not _same_identity(before, after):
            _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
        return after

    def _rename_and_sync(self, old_name: str, new_name: str) -> None:
        _linux_call(
            self._operations.renameat2_noreplace,
            self._parent_fd,
            old_name,
            new_name,
        )
        _linux_call(self._operations.fsync, self._parent_fd)

    def _claim_rename_and_sync(self, old_name: str, new_name: str) -> bool:
        """Claim with one noreplace rename; a source race is a clean loss."""

        try:
            self._operations.renameat2_noreplace(
                self._parent_fd,
                old_name,
                new_name,
            )
        except LinuxBrokerError as error:
            if error.code is LinuxBrokerCode.ALREADY_EXISTS:
                return False
            raise
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.EEXIST):
                return False
            if error.errno == errno.ELOOP:
                _linux_fail(LinuxBrokerCode.UNSAFE_PATH)
            if error.errno == errno.EXDEV:
                _linux_fail(LinuxBrokerCode.CROSS_DEVICE)
            if error.errno in (errno.ENOSYS, errno.EOPNOTSUPP, errno.ENOTSUP):
                _linux_fail(LinuxBrokerCode.UNSUPPORTED_PLATFORM)
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        _linux_call(self._operations.fsync, self._parent_fd)
        return True

    def _cleanup_temp(self, name: str) -> None:
        try:
            self._operations.unlinkat(self._parent_fd, name)
        except Exception:
            pass

    def publish(self, payload: bytes, final_name: str) -> None:
        """Durably publish one regular root-owned intent file."""

        self._payload(payload)
        if type(final_name) is not str or _INTENT_NAME.fullmatch(final_name) is None:
            _linux_fail(LinuxBrokerCode.UNSAFE_PATH)
        self._verify_parent()
        staging_name = f".tmp-{final_name}"
        fd = None
        renamed = False
        try:
            fd, before = self._open_file(
                staging_name,
                self._O_WRONLY | self._O_CREAT | self._O_EXCL,
            )
            self._write_and_sync(fd, payload)
            self._after_file_identity(fd, before)
            self._close(fd)
            fd = None
            self._verify_parent()
            self._rename_and_sync(staging_name, final_name)
            renamed = True
            self._verify_parent()
        finally:
            if fd is not None:
                self._close(fd)
            if not renamed:
                self._cleanup_temp(staging_name)

    def _candidate_names(self) -> tuple[str, ...]:
        names = _linux_call(self._operations.list_names, self._parent_fd)
        if type(names) is not tuple:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        return tuple(
            sorted(
                name
                for name in names
                if type(name) is str and _INTENT_NAME.fullmatch(name)
            )
        )

    def claim_next(self) -> BrokerIntentClaimBytes | None:
        """Read and atomically claim the oldest visible intent."""

        self._verify_parent()
        for name in self._candidate_names():
            fd = None
            try:
                fd, before = self._open_file(name, self._O_RDONLY)
                payload = _linux_call(self._operations.read_all, fd)
                if type(payload) is not bytes or len(payload) > MAX_BROKER_INTENT_BYTES:
                    _linux_fail(LinuxBrokerCode.IO_FAILURE)
                self._after_file_identity(fd, before)
                self._close(fd)
                fd = None
                claim_name = f".claim-{name}"
                self._verify_parent()
                if not self._claim_rename_and_sync(name, claim_name):
                    return None
                self._verify_parent()
                return BrokerIntentClaimBytes(claim_name, payload, before)
            except OSError as error:
                if error.errno in (errno.ENOENT, errno.EEXIST):
                    return None
                raise
            finally:
                if fd is not None:
                    self._close(fd)
        return None

    def _retention_check(self, prefix: str, maximum: int) -> None:
        names = _linux_call(self._operations.list_names, self._parent_fd)
        if type(names) is not tuple:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        if (
            sum(1 for name in names if type(name) is str and name.startswith(prefix))
            >= maximum
        ):
            _linux_fail(LinuxBrokerCode.IO_FAILURE)

    def _claim_name(self, claim_name: object) -> str:
        if type(claim_name) is not str or _CLAIM_NAME.fullmatch(claim_name) is None:
            _linux_fail(LinuxBrokerCode.UNSAFE_PATH)
        return claim_name

    def mark_terminal(self, claim_name: str, payload: bytes) -> None:
        """Overwrite a claimed file with bounded terminal bytes and retain it."""

        claim_name = self._claim_name(claim_name)
        self._payload(payload)
        self._retention_check(".terminal-", MAX_TERMINAL_INTENT_RECORDS)
        self._verify_parent()
        fd = None
        renamed = False
        terminal_name = f".terminal-{claim_name[1:]}"
        try:
            fd, before = self._open_file(claim_name, self._O_WRONLY)
            self._verify_parent()
            _linux_call(self._operations.truncate, fd)
            self._write_and_sync(fd, payload)
            self._after_file_identity(fd, before)
            self._close(fd)
            fd = None
            self._verify_parent()
            self._rename_and_sync(claim_name, terminal_name)
            renamed = True
            self._verify_parent()
        finally:
            if fd is not None:
                self._close(fd)
            if not renamed:
                pass

    def quarantine(self, claim_name: str, code: str) -> None:
        """Move one claimed file to bounded, code-labelled quarantine."""

        claim_name = self._claim_name(claim_name)
        if not _valid_code(code):
            _linux_fail(LinuxBrokerCode.UNSAFE_PATH)
        self._retention_check(".quarantine-", MAX_QUARANTINED_INTENT_RECORDS)
        self._verify_parent()
        quarantine_name = f".quarantine-{code}-{claim_name[1:]}"
        fd = None
        try:
            fd, before = self._open_file(claim_name, self._O_RDONLY)
            self._after_file_identity(fd, before)
            self._close(fd)
            fd = None
            self._verify_parent()
            self._rename_and_sync(claim_name, quarantine_name)
            self._verify_parent()
        finally:
            if fd is not None:
                self._close(fd)


def publish_broker_intent(
    operations: BrokerIntentStoreOperations, intent: BrokerIntentV1
) -> None:
    """Encode and publish one complete intent under its deterministic name."""

    payload = encode_broker_intent(intent)
    result = _public_operation_call(operations, "publish", payload, _final_name(intent))
    if result is not None:
        raise BrokerIntentError(BrokerIntentCode.INVALID_TYPE)


def claim_broker_intent(
    operations: BrokerIntentStoreOperations, *, now_unix_ms: int
) -> ClaimedBrokerIntent | None:
    """Decode one atomically claimed intent or quarantine its invalid bytes."""

    claim = _public_operation_call(operations, "claim_next")
    if claim is None:
        return None
    claim = _validate_claim(claim)
    try:
        intent = decode_broker_intent(claim.payload, now_unix_ms=now_unix_ms)
    except BrokerIntentError as error:
        # Only the stable codec category crosses the quarantine boundary;
        # malformed bytes and their contents never become an error string.
        code = error.code.value
        if not _valid_code(code):
            raise BrokerIntentError(BrokerIntentCode.INVALID_FIELD)
        result = _public_operation_call(
            operations, "quarantine", claim.claim_name, code
        )
        if result is not None:
            raise BrokerIntentError(BrokerIntentCode.INVALID_TYPE)
        return None
    return ClaimedBrokerIntent(intent, claim.claim_name, claim.source_identity)


@dataclass(frozen=True, slots=True)
class ClaimedBrokerIntent:
    intent: BrokerIntentV1
    claim_name: str
    source_identity: BrokerIntentFileIdentity


__all__ = [
    "BrokerIntentClaimBytes",
    "BrokerIntentFileIdentity",
    "BrokerIntentStoreOperations",
    "ClaimedBrokerIntent",
    "claim_broker_intent",
    "publish_broker_intent",
]
