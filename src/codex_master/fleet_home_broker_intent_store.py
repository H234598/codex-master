"""Root-owned broker intent publication and single-consumer claim boundary.

The public functions in this module deliberately depend only on the narrow
``BrokerIntentStoreOperations`` protocol.  A platform adapter may implement
that protocol, but all filesystem authority remains behind injected
operations; this module never opens paths, sockets, or processes itself.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import errno
import hashlib
import json
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
MAX_PENDING_INTENT_RECORDS = 128
MAX_TERMINAL_EVIDENCE_BYTES = MAX_BROKER_INTENT_BYTES * 2
MAX_TERMINAL_COMMIT_BYTES = 256
MAX_TERMINAL_STAGING_RECORDS = 8
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
_RECOVERED_CLAIM_NAME = re.compile(
    r"\.recover-intent-[0-9]{20}-[A-Za-z0-9][A-Za-z0-9_.:@+\-]{0,255}\.json\Z",
    re.ASCII,
)


def _canonical_json_bytes(document: object) -> bytes:
    try:
        return (
            json.dumps(
                document,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError):
        _linux_fail(LinuxBrokerCode.IO_FAILURE)
    raise AssertionError("unreachable")


def _json_object(payload: bytes, maximum: int) -> dict[str, object]:
    if not payload or len(payload) > maximum:
        _linux_fail(LinuxBrokerCode.IO_FAILURE)

    def reject_duplicate_keys(pairs: list[tuple[object, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in document:
                _linux_fail(LinuxBrokerCode.IO_FAILURE)
            document[key] = value
        return document

    try:
        document = json.loads(
            payload.decode("ascii", "strict"), object_pairs_hook=reject_duplicate_keys
        )
    except (TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        _linux_fail(LinuxBrokerCode.IO_FAILURE)
    if type(document) is not dict or _canonical_json_bytes(document) != payload:
        _linux_fail(LinuxBrokerCode.IO_FAILURE)
    return document


def _terminal_result(payload: object) -> str:
    if type(payload) is not bytes:
        _linux_fail(LinuxBrokerCode.IO_FAILURE)
    document = _json_object(payload, MAX_BROKER_INTENT_BYTES)
    if set(document) != {"result"} or not _valid_code(document.get("result")):
        _linux_fail(LinuxBrokerCode.IO_FAILURE)
    result = document["result"]
    assert type(result) is str
    return result


def _terminal_record_names(claim_name: str) -> tuple[str, str]:
    name_digest = hashlib.sha256(claim_name.encode("ascii")).hexdigest()
    return (
        f".terminal-evidence-{name_digest}.json",
        f".terminal-commit-{name_digest}.json",
    )


def _terminal_evidence(claim_name: str, intent_payload: bytes, result: str) -> bytes:
    try:
        intent_b64 = base64.b64encode(intent_payload).decode("ascii")
    except (TypeError, ValueError):
        _linux_fail(LinuxBrokerCode.IO_FAILURE)
    evidence = _canonical_json_bytes(
        {
            "claim_name": claim_name,
            "intent_b64": intent_b64,
            "result": result,
            "schema_version": 1,
        }
    )
    if len(evidence) > MAX_TERMINAL_EVIDENCE_BYTES:
        _linux_fail(LinuxBrokerCode.IO_FAILURE)
    return evidence


def _terminal_commit(evidence: bytes) -> bytes:
    return _canonical_json_bytes(
        {
            "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
            "schema_version": 1,
        }
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
    recovered: bool = False


class BrokerIntentStoreOperations(Protocol):
    def publish(self, payload: bytes, final_name: str) -> None: ...

    def claim_next(self) -> BrokerIntentClaimBytes | None: ...

    def recover_next(self) -> BrokerIntentClaimBytes | None: ...

    def mark_terminal(self, claim_name: str, payload: bytes) -> None: ...

    def quarantine(self, claim_name: str, code: str) -> None: ...

    def release_claim(self, claim_name: str) -> None: ...


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

    def lock_exclusive_nonblocking(self, fd: int) -> None: ...

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
    if type(value.recovered) is not bool:
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
    _O_RDWR = 0o2
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
        self._leases: dict[str, tuple[int, BrokerIntentFileIdentity]] = {}
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

    def _try_lock_claim(self, fd: int) -> bool:
        """Acquire one inode-bound lease without waiting for another broker."""

        try:
            self._operations.lock_exclusive_nonblocking(fd)
        except LinuxBrokerError:
            raise
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                return False
            if error.errno in (errno.ENOSYS, errno.EOPNOTSUPP, errno.ENOTSUP):
                _linux_fail(LinuxBrokerCode.UNSUPPORTED_PLATFORM)
            if error.errno == errno.ELOOP:
                _linux_fail(LinuxBrokerCode.UNSAFE_PATH)
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        except Exception:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        return True

    def _release_lease(self, claim_name: str) -> None:
        lease = self._leases.pop(claim_name, None)
        if lease is not None:
            self._close(lease[0])

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

    def _candidate_names(self, expression: re.Pattern[str]) -> tuple[str, ...]:
        names = _linux_call(self._operations.list_names, self._parent_fd)
        if type(names) is not tuple:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        candidates = tuple(
            sorted(
                name
                for name in names
                if type(name) is str and expression.fullmatch(name)
            )
        )
        if len(candidates) > MAX_PENDING_INTENT_RECORDS:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        return candidates

    def _read_terminal_record(
        self, name: str, visible_names: tuple[object, ...]
    ) -> bytes | None:
        """Read one fixed-name sidecar only when that exact entry is visible."""

        if name not in visible_names:
            return None
        fd = None
        try:
            fd, before = self._open_file(name, self._O_RDONLY)
            payload = _linux_call(self._operations.read_all, fd)
            if type(payload) is not bytes:
                _linux_fail(LinuxBrokerCode.IO_FAILURE)
            self._after_file_identity(fd, before)
            return payload
        finally:
            if fd is not None:
                self._close(fd)

    def _validate_terminal_evidence(
        self, claim_name: str, intent_payload: bytes, evidence: bytes
    ) -> None:
        document = _json_object(evidence, MAX_TERMINAL_EVIDENCE_BYTES)
        if set(document) != {
            "claim_name",
            "intent_b64",
            "result",
            "schema_version",
        }:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        if (
            document["claim_name"] != claim_name
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
        ):
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        if (
            not _valid_code(document["result"])
            or type(document["intent_b64"]) is not str
        ):
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        try:
            bound_intent = base64.b64decode(document["intent_b64"], validate=True)
        except (TypeError, ValueError):
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        if (
            base64.b64encode(bound_intent).decode("ascii") != document["intent_b64"]
            or bound_intent != intent_payload
        ):
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        try:
            decode_broker_intent(bound_intent, now_unix_ms=0)
        except BrokerIntentError:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)

    def _validate_terminal_commit(self, evidence: bytes, commit: bytes) -> None:
        document = _json_object(commit, MAX_TERMINAL_COMMIT_BYTES)
        if set(document) != {"evidence_sha256", "schema_version"}:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or type(document["evidence_sha256"]) is not str
            or document["evidence_sha256"] != hashlib.sha256(evidence).hexdigest()
        ):
            _linux_fail(LinuxBrokerCode.IO_FAILURE)

    def _terminal_state(
        self,
        claim_name: str,
        intent_payload: bytes,
        visible_names: tuple[object, ...],
    ) -> str:
        """Classify one sidecar pair before a recovery rename can alter its key."""

        evidence_name, commit_name = _terminal_record_names(claim_name)
        evidence = self._read_terminal_record(evidence_name, visible_names)
        commit = self._read_terminal_record(commit_name, visible_names)
        if commit is None:
            if evidence is None:
                return "absent"
            try:
                self._validate_terminal_evidence(claim_name, intent_payload, evidence)
            except LinuxBrokerError as error:
                if error.code is LinuxBrokerCode.IO_FAILURE:
                    return "invalid_provisional"
                raise
            return "evidence_only"
        if evidence is None:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        self._validate_terminal_evidence(claim_name, intent_payload, evidence)
        self._validate_terminal_commit(evidence, commit)
        return "committed"

    def _finalize_terminal_claim(
        self,
        claim_name: str,
        fd: int,
        identity: BrokerIntentFileIdentity,
    ) -> None:
        """Remove only the claimed copy after its evidence pair is validated."""

        self._after_file_identity(fd, identity)
        self._verify_parent()
        _linux_call(self._operations.unlinkat, self._parent_fd, claim_name)
        _linux_call(self._operations.fsync, self._parent_fd)
        self._verify_parent()

    def _terminal_staging_name(
        self,
        kind: str,
        final_name: str,
        visible_names: tuple[object, ...],
    ) -> str:
        final_digest = hashlib.sha256(final_name.encode("ascii")).hexdigest()
        for index in range(MAX_TERMINAL_STAGING_RECORDS):
            candidate = f".tmp-terminal-{kind}-{final_digest}-{index}.json"
            if candidate not in visible_names:
                return candidate
        _linux_fail(LinuxBrokerCode.IO_FAILURE)
        raise AssertionError("unreachable")

    def _terminal_staging_names(self, claim_name: str) -> tuple[str, ...]:
        evidence_name, commit_name = _terminal_record_names(claim_name)
        names: list[str] = []
        for kind, final_name in (
            ("evidence", evidence_name),
            ("commit", commit_name),
        ):
            final_digest = hashlib.sha256(final_name.encode("ascii")).hexdigest()
            names.extend(
                f".tmp-terminal-{kind}-{final_digest}-{index}.json"
                for index in range(MAX_TERMINAL_STAGING_RECORDS)
            )
        return tuple(names)

    def _discard_terminal_staging(
        self, claim_name: str, visible_names: tuple[object, ...]
    ) -> None:
        """Remove only this crashed claim's bounded, non-final staging files."""

        for staging_name in self._terminal_staging_names(claim_name):
            self._discard_terminal_provisional(staging_name, visible_names)

    def _discard_terminal_provisional(
        self, name: str, visible_names: tuple[object, ...]
    ) -> None:
        """Identity-check and remove one bounded non-final terminal artifact."""

        if name not in visible_names:
            return
        fd = None
        try:
            fd, before = self._open_file(name, self._O_RDONLY)
            self._after_file_identity(fd, before)
        finally:
            if fd is not None:
                self._close(fd)
        self._verify_parent()
        _linux_call(self._operations.unlinkat, self._parent_fd, name)
        _linux_call(self._operations.fsync, self._parent_fd)
        self._verify_parent()

    def _discard_terminal_evidence(
        self, claim_name: str, visible_names: tuple[object, ...]
    ) -> None:
        evidence_name, _ = _terminal_record_names(claim_name)
        self._discard_terminal_provisional(evidence_name, visible_names)

    def _publish_terminal_record(
        self,
        kind: str,
        final_name: str,
        payload: bytes,
        visible_names: tuple[object, ...],
    ) -> None:
        staging_name = self._terminal_staging_name(kind, final_name, visible_names)
        fd = None
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
            self._verify_parent()
        finally:
            if fd is not None:
                self._close(fd)
            # On any interrupted/error path the exclusive staging file is
            # retained.  A later lease holder removes only its bounded,
            # identity-checked name; this avoids unlinking a raced EEXIST path.

    def _claim_candidate(
        self,
        name: str,
        claim_name: str,
        *,
        recovered: bool,
        rename_claim: bool,
        visible_names: tuple[object, ...] | None = None,
    ) -> BrokerIntentClaimBytes | None:
        fd = None
        try:
            fd, before = self._open_file(name, self._O_RDWR)
            payload = _linux_call(self._operations.read_all, fd)
            if type(payload) is not bytes or len(payload) > MAX_BROKER_INTENT_BYTES:
                _linux_fail(LinuxBrokerCode.IO_FAILURE)
            self._after_file_identity(fd, before)
            if not self._try_lock_claim(fd):
                return None
            self._verify_parent()
            if visible_names is not None:
                terminal_state = self._terminal_state(name, payload, visible_names)
                if terminal_state == "committed":
                    self._finalize_terminal_claim(name, fd, before)
                    return None
                if terminal_state == "invalid_provisional":
                    self._discard_terminal_evidence(name, visible_names)
                self._discard_terminal_staging(name, visible_names)
                if terminal_state == "evidence_only":
                    # The final evidence name hashes the original claim name.
                    # Preserve that name and its FD lease so mark_terminal()
                    # can publish the matching commit rather than orphan it.
                    claim_name = name
                    rename_claim = False
            if rename_claim:
                if not self._claim_rename_and_sync(name, claim_name):
                    return None
            self._verify_parent()
            self._leases[claim_name] = (fd, before)
            fd = None
            return BrokerIntentClaimBytes(claim_name, payload, before, recovered)
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.EEXIST):
                return None
            raise
        finally:
            if fd is not None:
                self._close(fd)

    def claim_next(self) -> BrokerIntentClaimBytes | None:
        """Read and atomically claim the oldest visible intent."""

        self._verify_parent()
        for name in self._candidate_names(_INTENT_NAME):
            return self._claim_candidate(
                name,
                f".claim-{name}",
                recovered=False,
                rename_claim=True,
            )
        return None

    def recover_next(self) -> BrokerIntentClaimBytes | None:
        """Atomically take one crashed claim after acquiring its inode lease."""

        self._verify_parent()
        visible_names = _linux_call(self._operations.list_names, self._parent_fd)
        if type(visible_names) is not tuple:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        candidates = tuple(
            sorted(
                name
                for name in visible_names
                if type(name) is str
                and (
                    _CLAIM_NAME.fullmatch(name) or _RECOVERED_CLAIM_NAME.fullmatch(name)
                )
            )
        )
        if len(candidates) > MAX_PENDING_INTENT_RECORDS:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        for name in candidates:
            claim_name = f".recover-{name[7:]}" if _CLAIM_NAME.fullmatch(name) else name
            claimed = self._claim_candidate(
                name,
                claim_name,
                recovered=True,
                rename_claim=claim_name != name,
                visible_names=visible_names,
            )
            if claimed is not None:
                return claimed
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

    def _terminal_retention_check(self) -> None:
        """Count one evidence record per terminal intent, including legacy data."""

        names = _linux_call(self._operations.list_names, self._parent_fd)
        if type(names) is not tuple:
            _linux_fail(LinuxBrokerCode.IO_FAILURE)
        if (
            sum(
                1
                for name in names
                if type(name) is str
                and (
                    name.startswith(".terminal-evidence-")
                    or name.startswith(".terminal-claim-")
                )
            )
            >= MAX_TERMINAL_INTENT_RECORDS
        ):
            _linux_fail(LinuxBrokerCode.IO_FAILURE)

    def _claim_name(self, claim_name: object) -> str:
        if type(claim_name) is not str or not (
            _CLAIM_NAME.fullmatch(claim_name)
            or _RECOVERED_CLAIM_NAME.fullmatch(claim_name)
        ):
            _linux_fail(LinuxBrokerCode.UNSAFE_PATH)
        return claim_name

    def _claim_fd(
        self, claim_name: str, flags: int
    ) -> tuple[int, BrokerIntentFileIdentity, bool]:
        lease = self._leases.get(claim_name)
        if lease is not None:
            fd, identity = lease
            self._after_file_identity(fd, identity)
            return fd, identity, True
        fd, identity = self._open_file(claim_name, flags)
        return fd, identity, False

    def release_claim(self, claim_name: str) -> None:
        """Release a live normal or recovery lease without path cleanup."""

        claim_name = self._claim_name(claim_name)
        self._release_lease(claim_name)

    def mark_terminal(self, claim_name: str, payload: bytes) -> None:
        """Durably bind a redacted result without overwriting the claimed intent.

        The local, inode-bound lease is mandatory.  A complete evidence record
        is synced before its commit marker, then the original claim is removed
        only after both records are valid and durable.  This leaves a compact
        terminal audit trail containing the exact original intent bytes.
        """

        claim_name = self._claim_name(claim_name)
        lease = self._leases.get(claim_name)
        if lease is None:
            _linux_fail(LinuxBrokerCode.IDENTITY_MISMATCH)
        fd, before = lease
        try:
            result = _terminal_result(payload)
            self._after_file_identity(fd, before)
            intent_payload = _linux_call(self._operations.read_all, fd)
            if (
                type(intent_payload) is not bytes
                or not intent_payload
                or len(intent_payload) > MAX_BROKER_INTENT_BYTES
            ):
                _linux_fail(LinuxBrokerCode.IO_FAILURE)
            self._after_file_identity(fd, before)
            try:
                decode_broker_intent(intent_payload, now_unix_ms=0)
            except BrokerIntentError:
                _linux_fail(LinuxBrokerCode.IO_FAILURE)
            evidence_name, commit_name = _terminal_record_names(claim_name)
            evidence = _terminal_evidence(claim_name, intent_payload, result)
            commit = _terminal_commit(evidence)
            self._verify_parent()
            visible_names = _linux_call(self._operations.list_names, self._parent_fd)
            if type(visible_names) is not tuple:
                _linux_fail(LinuxBrokerCode.IO_FAILURE)
            existing_evidence = self._read_terminal_record(evidence_name, visible_names)
            existing_commit = self._read_terminal_record(commit_name, visible_names)
            if existing_commit is not None:
                if existing_evidence is None:
                    _linux_fail(LinuxBrokerCode.IO_FAILURE)
                self._validate_terminal_evidence(
                    claim_name, intent_payload, existing_evidence
                )
                self._validate_terminal_commit(existing_evidence, existing_commit)
                if existing_evidence != evidence or existing_commit != commit:
                    _linux_fail(LinuxBrokerCode.IO_FAILURE)
            else:
                if existing_evidence is None:
                    self._terminal_retention_check()
                    self._publish_terminal_record(
                        "evidence", evidence_name, evidence, visible_names
                    )
                else:
                    self._validate_terminal_evidence(
                        claim_name, intent_payload, existing_evidence
                    )
                    if existing_evidence != evidence:
                        _linux_fail(LinuxBrokerCode.IO_FAILURE)
                    # A previously published but uncommitted sidecar becomes
                    # durable before its commit marker is created.
                    _linux_call(self._operations.fsync, self._parent_fd)
                visible_names = _linux_call(
                    self._operations.list_names, self._parent_fd
                )
                if type(visible_names) is not tuple:
                    _linux_fail(LinuxBrokerCode.IO_FAILURE)
                self._publish_terminal_record(
                    "commit", commit_name, commit, visible_names
                )
            self._verify_parent()
            self._finalize_terminal_claim(claim_name, fd, before)
        finally:
            self._release_lease(claim_name)

    def quarantine(self, claim_name: str, code: str) -> None:
        """Move one claimed file to bounded, code-labelled quarantine."""

        claim_name = self._claim_name(claim_name)
        fd = None
        leased = False
        try:
            if not _valid_code(code):
                _linux_fail(LinuxBrokerCode.UNSAFE_PATH)
            self._retention_check(".quarantine-", MAX_QUARANTINED_INTENT_RECORDS)
            self._verify_parent()
            quarantine_name = f".quarantine-{code}-{claim_name[1:]}"
            fd, before, leased = self._claim_fd(claim_name, self._O_RDONLY)
            self._after_file_identity(fd, before)
            if not leased:
                self._close(fd)
                fd = None
            self._verify_parent()
            self._rename_and_sync(claim_name, quarantine_name)
            self._verify_parent()
        finally:
            if fd is not None and not leased:
                self._close(fd)
            self._release_lease(claim_name)


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

    return _decode_claim(operations, "claim_next", False, now_unix_ms=now_unix_ms)


def recover_broker_intent(
    operations: BrokerIntentStoreOperations, *, now_unix_ms: int
) -> ClaimedBrokerIntent | None:
    """Decode one atomically recovered orphan claim or quarantine its bytes."""

    return _decode_claim(operations, "recover_next", True, now_unix_ms=now_unix_ms)


def _decode_claim(
    operations: BrokerIntentStoreOperations,
    method: str,
    recovered: bool,
    *,
    now_unix_ms: int,
) -> ClaimedBrokerIntent | None:
    claim = _public_operation_call(operations, method)
    if claim is None:
        return None
    claim = _validate_claim(claim)
    if claim.recovered is not recovered:
        raise BrokerIntentError(BrokerIntentCode.INVALID_FIELD)
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
    return ClaimedBrokerIntent(
        intent, claim.claim_name, claim.source_identity, claim.recovered
    )


@dataclass(frozen=True, slots=True)
class ClaimedBrokerIntent:
    intent: BrokerIntentV1
    claim_name: str
    source_identity: BrokerIntentFileIdentity
    recovered: bool = False


__all__ = [
    "BrokerIntentClaimBytes",
    "BrokerIntentFileIdentity",
    "BrokerIntentStoreOperations",
    "ClaimedBrokerIntent",
    "claim_broker_intent",
    "publish_broker_intent",
    "recover_broker_intent",
]
