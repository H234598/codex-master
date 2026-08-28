"""Private, write-only storage for Google inventory refresh tokens."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import json
import os
import secrets
import stat
import threading
from typing import Final

from .google_account_inventory_manager import GoogleAccountInventoryManager
from .google_oauth_authorization import GoogleOAuthOperationV1
from .google_oauth_authorization import GoogleOAuthProfileIdV1
from .google_oauth_authorization import resolve_google_oauth_profile_v1


_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "credential.inventory_token_vault_request_invalid",
        "credential.inventory_token_vault_binding_invalid",
        "credential.inventory_token_vault_profile_mismatch",
        "credential.inventory_token_vault_generation_conflict",
        "credential.inventory_token_vault_unavailable",
        "credential.inventory_token_vault_permissions",
        "credential.inventory_token_vault_path_invalid",
        "credential.inventory_token_vault_schema_invalid",
        "credential.inventory_token_vault_token_invalid",
        "credential.inventory_token_vault_busy",
        "credential.inventory_token_vault_write_failed",
        "credential.inventory_token_vault_delete_failed",
        "credential.inventory_token_vault_durability_failed",
    }
)
_RECORD_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "format_version",
        "record_kind",
        "vault_generation",
        "account_ref",
        "subject_fingerprint",
        "login_fingerprint",
        "oauth_client_fingerprint",
        "profile_id",
        "scope_fingerprint",
        "refresh_token_b64",
    }
)
_FORMAT_VERSION: Final[int] = 1
_RECORD_KIND: Final[str] = "google_inventory_readonly_refresh_token_v1"
_MAX_FILE_BYTES: Final[int] = 32 * 1024
_MAX_TOKEN_BYTES: Final[int] = 16 * 1024
_MAX_ACCOUNT_REF_BYTES: Final[int] = 128
_MAX_SUBJECT_ID_BYTES: Final[int] = 1024
_MAX_GENERATION: Final[int] = 2**63 - 1
_IN_PROCESS_LOCK_GUARD = threading.Lock()
_IN_PROCESS_LOCKS: dict[str, _ProcessLockEntry] = {}


class GoogleInventoryReadonlyTokenVaultError(Exception):
    """Closed, code-only token-vault failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        super().__init__()
        self.code = "credential.inventory_token_vault_request_invalid"
        valid = type(code) is str and code in _ERROR_CODES
        if not valid:
            code = ""
            raise TypeError("invalid inventory token vault error code")
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"GoogleInventoryReadonlyTokenVaultError({self.code!r})"

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class GoogleInventoryReadonlyTokenVaultStoreReceipt:
    vault_generation: int


@dataclass(frozen=True, slots=True)
class GoogleInventoryReadonlyTokenVaultDeleteReceipt:
    removed: bool


class _LockedRecord:
    __slots__ = (
        "tokens",
        "lock_fd",
        "lock_name",
        "lock_identity",
        "account_ref",
        "process_entry",
    )

    def __init__(
        self,
        tokens: _DirectoryCapability,
        lock_fd: int,
        lock_name: _PrivateName,
        lock_identity: _FileIdentity,
        account_ref: str,
        process_entry: _ProcessLockEntry,
    ) -> None:
        self.tokens = tokens
        self.lock_fd = lock_fd
        self.lock_name = lock_name
        self.lock_identity = lock_identity
        self.account_ref = account_ref
        self.process_entry = process_entry

    def __repr__(self) -> str:
        return "<private inventory token vault locked record>"


class _ProcessLockEntry:
    __slots__ = ("lock", "references")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.references = 0


class _PrivateName:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def __fspath__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<private inventory token vault name>"

    def clear(self) -> None:
        self._value = ""

    def with_suffix(self, suffix: str) -> _PrivateName:
        return _PrivateName(self._value + suffix)


class _PrivateRecord:
    __slots__ = ("_value",)

    def __init__(self, value: dict[str, object]) -> None:
        self._value = value

    def value(self) -> dict[str, object]:
        return self._value

    def __repr__(self) -> str:
        return "<private inventory token vault record>"

    def clear(self) -> None:
        self._value.clear()


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    device: int
    inode: int
    owner: int
    permissions: int
    file_type: int


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    owner: int
    permissions: int
    file_type: int
    links: int


@dataclass(frozen=True, slots=True)
class _MutationThreatBoundary:
    detects_observable_swaps_through_last_attestation: bool
    unsandboxed_same_uid_after_last_attestation_in_scope: bool
    future_isolation: str


_MUTATION_THREAT_BOUNDARY: Final[_MutationThreatBoundary] = _MutationThreatBoundary(
    detects_observable_swaps_through_last_attestation=True,
    unsandboxed_same_uid_after_last_attestation_in_scope=False,
    future_isolation="separate_uid_or_root_broker",
)


class _DirectoryNode:
    __slots__ = (
        "fd",
        "name",
        "identity",
        "expected_owner",
        "exact_mode",
        "reject_group_world_write",
    )

    def __init__(
        self,
        fd: int,
        name: _PrivateName | None,
        identity: _DirectoryIdentity,
        *,
        expected_owner: int,
        exact_mode: int | None,
        reject_group_world_write: bool,
    ) -> None:
        self.fd = fd
        self.name = name
        self.identity = identity
        self.expected_owner = expected_owner
        self.exact_mode = exact_mode
        self.reject_group_world_write = reject_group_world_write

    def __repr__(self) -> str:
        return "<private inventory token vault directory node>"


class _DirectoryCapability:
    __slots__ = ("nodes",)

    def __init__(self, nodes: list[_DirectoryNode]) -> None:
        self.nodes = nodes

    @property
    def fd(self) -> int:
        return self.nodes[-1].fd

    def __repr__(self) -> str:
        return "<private inventory token vault directory capability>"


def _raise(code: str) -> None:
    raise GoogleInventoryReadonlyTokenVaultError(code) from None


def _zero(buffer: bytearray | None) -> None:
    if type(buffer) is bytearray:
        for index in range(len(buffer)):
            buffer[index] = 0


def _is_exact_nonempty_string(value: object, maximum_bytes: int) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return False
    return 0 < len(encoded) <= maximum_bytes and "\x00" not in value


def _is_safe_account_ref(value: object) -> bool:
    if not _is_exact_nonempty_string(value, _MAX_ACCOUNT_REF_BYTES):
        return False
    assert type(value) is str
    return all(
        character.isascii() and (character.isalnum() or character == "-")
        for character in value
    )


def _is_fingerprint(value: object) -> bool:
    if type(value) is not str or len(value) != 71 or not value.startswith("sha256:"):
        return False
    return all(character in "0123456789abcdef" for character in value[7:])


def _fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _acquire_process_lock_reference(account_ref: str) -> _ProcessLockEntry:
    with _IN_PROCESS_LOCK_GUARD:
        entry = _IN_PROCESS_LOCKS.get(account_ref)
        if entry is None:
            entry = _ProcessLockEntry()
            _IN_PROCESS_LOCKS[account_ref] = entry
        entry.references += 1
        return entry


def _release_process_lock_reference(account_ref: str, entry: _ProcessLockEntry) -> None:
    with _IN_PROCESS_LOCK_GUARD:
        entry.references -= 1
        if entry.references == 0 and _IN_PROCESS_LOCKS.get(account_ref) is entry:
            _IN_PROCESS_LOCKS.pop(account_ref, None)


def _classify_oserror(error: OSError) -> str:
    if error.errno in (errno.EACCES, errno.EPERM):
        return "credential.inventory_token_vault_permissions"
    if error.errno in (errno.ELOOP, errno.ENOTDIR):
        return "credential.inventory_token_vault_path_invalid"
    if error.errno in (errno.ENOENT, errno.ENODEV, errno.ESTALE):
        return "credential.inventory_token_vault_unavailable"
    return "credential.inventory_token_vault_unavailable"


def _directory_metadata_code(
    metadata: os.stat_result,
    *,
    expected_owner: int,
    exact_mode: int | None,
    reject_group_world_write: bool,
) -> str | None:
    permissions = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode):
        return "credential.inventory_token_vault_path_invalid"
    if metadata.st_uid != expected_owner:
        return "credential.inventory_token_vault_permissions"
    if exact_mode is not None and permissions != exact_mode:
        return "credential.inventory_token_vault_permissions"
    if reject_group_world_write and permissions & 0o022:
        return "credential.inventory_token_vault_permissions"
    return None


def _directory_identity(metadata: os.stat_result) -> _DirectoryIdentity:
    return _DirectoryIdentity(
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        stat.S_IFMT(metadata.st_mode),
    )


def _directory_identity_code(
    metadata: os.stat_result, identity: _DirectoryIdentity
) -> str | None:
    current = _directory_identity(metadata)
    if (
        current.device != identity.device
        or current.inode != identity.inode
        or current.file_type != identity.file_type
    ):
        return "credential.inventory_token_vault_path_invalid"
    if current.owner != identity.owner or current.permissions != identity.permissions:
        return "credential.inventory_token_vault_permissions"
    return None


def _validated_directory_identity(
    fd: int,
    *,
    expected_owner: int,
    exact_mode: int | None,
    reject_group_world_write: bool,
) -> tuple[str | None, _DirectoryIdentity | None]:
    try:
        metadata = os.fstat(fd)
    except OSError as error:
        return _classify_oserror(error), None
    code = _directory_metadata_code(
        metadata,
        expected_owner=expected_owner,
        exact_mode=exact_mode,
        reject_group_world_write=reject_group_world_write,
    )
    if code is not None:
        return code, None
    return None, _directory_identity(metadata)


def _revalidate_directory_capability(
    capability: _DirectoryCapability,
) -> str | None:
    try:
        for index, node in enumerate(capability.nodes):
            metadata = os.fstat(node.fd)
            code = _directory_metadata_code(
                metadata,
                expected_owner=node.expected_owner,
                exact_mode=node.exact_mode,
                reject_group_world_write=node.reject_group_world_write,
            )
            if code is not None:
                return code
            code = _directory_identity_code(metadata, node.identity)
            if code is not None:
                return code
            if index:
                assert node.name is not None
                named = os.stat(
                    node.name,
                    dir_fd=capability.nodes[index - 1].fd,
                    follow_symlinks=False,
                )
                code = _directory_metadata_code(
                    named,
                    expected_owner=node.expected_owner,
                    exact_mode=node.exact_mode,
                    reject_group_world_write=node.reject_group_world_write,
                )
                if code is not None:
                    return code
                code = _directory_identity_code(named, node.identity)
                if code is not None:
                    return code
        return None
    except OSError as error:
        return _classify_oserror(error)


def _append_directory_component(
    capability: _DirectoryCapability,
    name: str,
    *,
    expected_owner: int,
    exact_mode: int | None,
    reject_group_world_write: bool,
) -> str | None:
    code = _revalidate_directory_capability(capability)
    if code is not None:
        return code
    private_name = _PrivateName(name)
    fd: int | None = None
    try:
        fd = os.open(
            private_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=capability.fd,
        )
        code, identity = _validated_directory_identity(
            fd,
            expected_owner=expected_owner,
            exact_mode=exact_mode,
            reject_group_world_write=reject_group_world_write,
        )
        if code is not None or identity is None:
            close_fd = fd
            fd = None
            _close_fd(close_fd)
            private_name.clear()
            return code
        named = os.stat(private_name, dir_fd=capability.fd, follow_symlinks=False)
        code = _directory_identity_code(named, identity)
        if code is not None:
            close_fd = fd
            fd = None
            _close_fd(close_fd)
            private_name.clear()
            return code
        capability.nodes.append(
            _DirectoryNode(
                fd,
                private_name,
                identity,
                expected_owner=expected_owner,
                exact_mode=exact_mode,
                reject_group_world_write=reject_group_world_write,
            )
        )
        fd = None
        return None
    except OSError as error:
        if fd is not None:
            _close_fd(fd)
        private_name.clear()
        return _classify_oserror(error)


def _append_user_tokens_directory_components(
    capability: _DirectoryCapability, *, effective_uid: int
) -> str | None:
    policies = (
        (".config", None, True),
        ("codex-master-mcp", None, True),
        ("google-oauth", 0o700, False),
        ("tokens", 0o700, False),
    )
    for component, exact_mode, reject_write in policies:
        code = _append_directory_component(
            capability,
            component,
            expected_owner=effective_uid,
            exact_mode=exact_mode,
            reject_group_world_write=reject_write,
        )
        if code is not None:
            return code
    return None


def _close_directory_capability(
    capability: _DirectoryCapability | None,
) -> bool:
    if capability is None:
        return True
    clean = True
    for node in reversed(capability.nodes):
        fd = node.fd
        node.fd = -1
        if not _close_fd(fd):
            clean = False
        if node.name is not None:
            node.name.clear()
    capability.nodes.clear()
    return clean


def _open_production_tokens_directory() -> tuple[
    str | None, _DirectoryCapability | None
]:
    root_fd: int | None = None
    capability: _DirectoryCapability | None = None
    try:
        root_fd = os.open(
            "/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        code, identity = _validated_directory_identity(
            root_fd,
            expected_owner=0,
            exact_mode=None,
            reject_group_world_write=True,
        )
        if code is not None or identity is None:
            _close_fd(root_fd)
            return code, None
        capability = _DirectoryCapability(
            [
                _DirectoryNode(
                    root_fd,
                    None,
                    identity,
                    expected_owner=0,
                    exact_mode=None,
                    reject_group_world_write=True,
                )
            ]
        )
        root_fd = None
        effective_uid = os.geteuid()
        policies = (("home", 0), ("teladi", effective_uid))
        for component, owner in policies:
            code = _append_directory_component(
                capability,
                component,
                expected_owner=owner,
                exact_mode=None,
                reject_group_world_write=True,
            )
            if code is not None:
                _close_directory_capability(capability)
                return code, None
        code = _append_user_tokens_directory_components(
            capability, effective_uid=effective_uid
        )
        if code is not None:
            _close_directory_capability(capability)
            return code, None
        code = _revalidate_directory_capability(capability)
        if code is not None:
            _close_directory_capability(capability)
            return code, None
        return None, capability
    except OSError as error:
        if root_fd is not None:
            _close_fd(root_fd)
        _close_directory_capability(capability)
        return _classify_oserror(error), None


def _private_file_metadata_code(metadata: os.stat_result) -> str | None:
    if not stat.S_ISREG(metadata.st_mode):
        return "credential.inventory_token_vault_path_invalid"
    if metadata.st_nlink == 0:
        return "credential.inventory_token_vault_path_invalid"
    if (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        return "credential.inventory_token_vault_permissions"
    return None


def _file_identity(metadata: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        stat.S_IFMT(metadata.st_mode),
        metadata.st_nlink,
    )


def _file_identity_code(
    metadata: os.stat_result, identity: _FileIdentity
) -> str | None:
    current = _file_identity(metadata)
    if (
        current.device != identity.device
        or current.inode != identity.inode
        or current.file_type != identity.file_type
    ):
        return "credential.inventory_token_vault_path_invalid"
    if (
        current.owner != identity.owner
        or current.permissions != identity.permissions
        or current.links != identity.links
    ):
        return "credential.inventory_token_vault_permissions"
    return None


def _validated_private_file_identity(
    fd: int,
) -> tuple[str | None, _FileIdentity | None]:
    try:
        metadata = os.fstat(fd)
    except OSError as error:
        return _classify_oserror(error), None
    code = _private_file_metadata_code(metadata)
    if code is not None:
        return code, None
    return None, _file_identity(metadata)


def _validate_regular_private_fd(fd: int) -> str | None:
    code, _identity = _validated_private_file_identity(fd)
    return code


def _attest_private_name(
    tokens: _DirectoryCapability,
    name: _PrivateName,
    identity: _FileIdentity,
) -> str | None:
    code = _revalidate_directory_capability(tokens)
    if code is not None:
        return code
    try:
        metadata = os.stat(name, dir_fd=tokens.fd, follow_symlinks=False)
    except OSError as error:
        return _classify_oserror(error)
    code = _private_file_metadata_code(metadata)
    if code is not None:
        return code
    return _file_identity_code(metadata, identity)


def _attest_private_fd_and_name(
    tokens: _DirectoryCapability,
    name: _PrivateName,
    fd: int,
    identity: _FileIdentity,
) -> str | None:
    code = _revalidate_directory_capability(tokens)
    if code is not None:
        return code
    try:
        metadata = os.fstat(fd)
    except OSError as error:
        return _classify_oserror(error)
    code = _private_file_metadata_code(metadata)
    if code is not None:
        return code
    code = _file_identity_code(metadata, identity)
    if code is not None:
        return code
    return _attest_private_name(tokens, name, identity)


def _attest_name_missing(
    tokens: _DirectoryCapability, name: _PrivateName
) -> str | None:
    code = _revalidate_directory_capability(tokens)
    if code is not None:
        return code
    try:
        os.stat(name, dir_fd=tokens.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        return _classify_oserror(error)
    return "credential.inventory_token_vault_path_invalid"


def _open_lock_fd(
    tokens: _DirectoryCapability, account_ref: str
) -> tuple[str | None, int | None, _PrivateName | None, _FileIdentity | None]:
    fd: int | None = None
    name = _PrivateName(f"{account_ref}.lock")
    try:
        code = _revalidate_directory_capability(tokens)
        if code is not None:
            name.clear()
            return code, None, None, None
        fd = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=tokens.fd,
        )
        code, identity = _validated_private_file_identity(fd)
        if code is None and identity is not None:
            code = _attest_private_fd_and_name(tokens, name, fd, identity)
        if code is not None or identity is None:
            close_fd = fd
            fd = None
            _close_fd(close_fd)
            name.clear()
            return code, None, None, None
        return None, fd, name, identity
    except OSError as error:
        if fd is not None:
            _close_fd(fd)
        name.clear()
        return _classify_oserror(error), None, None, None


def _acquire_locked_record(
    tokens: _DirectoryCapability, account_ref: str
) -> tuple[str | None, _LockedRecord | None]:
    lock_fd: int | None = None
    lock_name: _PrivateName | None = None
    lock_identity: _FileIdentity | None = None
    process_entry: _ProcessLockEntry | None = None
    process_lock_acquired = False
    process_reference_acquired = False
    try:
        code, lock_fd, lock_name, lock_identity = _open_lock_fd(tokens, account_ref)
        if (
            code is not None
            or lock_fd is None
            or lock_name is None
            or lock_identity is None
        ):
            return code, None
        process_entry = _acquire_process_lock_reference(account_ref)
        process_reference_acquired = True
        if not process_entry.lock.acquire(blocking=False):
            process_reference_acquired = False
            _release_process_lock_reference(account_ref, process_entry)
            close_fd = lock_fd
            lock_fd = None
            _close_fd(close_fd)
            lock_name.clear()
            lock_name = None
            return "credential.inventory_token_vault_busy", None
        process_lock_acquired = True
        code = _attest_private_fd_and_name(tokens, lock_name, lock_fd, lock_identity)
        if code is not None:
            locked = _LockedRecord(
                tokens,
                lock_fd,
                lock_name,
                lock_identity,
                account_ref,
                process_entry,
            )
            lock_fd = None
            lock_name = None
            process_lock_acquired = False
            process_reference_acquired = False
            _release_locked_record(locked)
            return code, None
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            process_entry.lock.release()
            process_lock_acquired = False
            process_reference_acquired = False
            _release_process_lock_reference(account_ref, process_entry)
            close_fd = lock_fd
            lock_fd = None
            _close_fd(close_fd)
            lock_name.clear()
            lock_name = None
            return "credential.inventory_token_vault_busy", None
        code = _attest_private_fd_and_name(tokens, lock_name, lock_fd, lock_identity)
        locked = _LockedRecord(
            tokens,
            lock_fd,
            lock_name,
            lock_identity,
            account_ref,
            process_entry,
        )
        lock_fd = None
        lock_name = None
        process_lock_acquired = False
        process_reference_acquired = False
        if code is not None:
            _release_locked_record(locked)
            return code, None
        return None, locked
    except OSError as error:
        if process_entry is not None and process_lock_acquired:
            try:
                process_entry.lock.release()
            except RuntimeError:
                pass
        if process_entry is not None and process_reference_acquired:
            _release_process_lock_reference(account_ref, process_entry)
        if lock_fd is not None:
            close_fd = lock_fd
            lock_fd = None
            _close_fd(close_fd)
        if lock_name is not None:
            lock_name.clear()
        return _classify_oserror(error), None


def _release_locked_record(locked: _LockedRecord | None) -> bool:
    if locked is None:
        return True
    clean = True
    if (
        _attest_private_fd_and_name(
            locked.tokens,
            locked.lock_name,
            locked.lock_fd,
            locked.lock_identity,
        )
        is not None
    ):
        clean = False
    try:
        fcntl.flock(locked.lock_fd, fcntl.LOCK_UN)
    except OSError:
        clean = False
    lock_fd = locked.lock_fd
    locked.lock_fd = -1
    try:
        os.close(lock_fd)
    except (OSError, ValueError):
        clean = False
    try:
        locked.process_entry.lock.release()
    except RuntimeError:
        clean = False
    try:
        _release_process_lock_reference(locked.account_ref, locked.process_entry)
    except Exception:
        clean = False
    locked.account_ref = ""
    locked.lock_name.clear()
    return clean


def _close_fd(fd: int | None) -> bool:
    if fd is None:
        return True
    try:
        os.close(fd)
    except OSError:
        return False
    return True


def _read_bounded(fd: int) -> tuple[str | None, bytes | None]:
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            remaining = _MAX_FILE_BYTES + 1 - total
            chunk = os.read(fd, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_FILE_BYTES:
                return "credential.inventory_token_vault_schema_invalid", None
        return None, b"".join(chunks)
    except OSError as error:
        return _classify_oserror(error), None


def _pairs_without_duplicates(
    pairs: list[tuple[object, object]],
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def _parse_record(raw: bytes) -> tuple[str | None, dict[str, object] | None]:
    token_buffer: bytearray | None = None
    text = ""
    decoded: dict[str, object] | object = {}
    refresh_token_b64: object = None
    validated_record: dict[str, object] | None = None
    try:
        if not raw or len(raw) > _MAX_FILE_BYTES:
            return "credential.inventory_token_vault_schema_invalid", None
        text = raw.decode("utf-8")
        if "\x00" in text:
            return "credential.inventory_token_vault_schema_invalid", None
        decoded = json.loads(text, object_pairs_hook=_pairs_without_duplicates)
        if type(decoded) is not dict or set(decoded) != _RECORD_FIELDS:
            return "credential.inventory_token_vault_schema_invalid", None
        if (
            decoded.get("format_version") != _FORMAT_VERSION
            or type(decoded["format_version"]) is not int
        ):
            return "credential.inventory_token_vault_schema_invalid", None
        if (
            decoded.get("record_kind") != _RECORD_KIND
            or type(decoded["record_kind"]) is not str
        ):
            return "credential.inventory_token_vault_schema_invalid", None
        generation = decoded.get("vault_generation")
        if type(generation) is not int or not 1 <= generation <= _MAX_GENERATION:
            return "credential.inventory_token_vault_schema_invalid", None
        if not _is_safe_account_ref(decoded.get("account_ref")):
            return "credential.inventory_token_vault_schema_invalid", None
        if not _is_fingerprint(decoded.get("subject_fingerprint")):
            return "credential.inventory_token_vault_schema_invalid", None
        if not _is_fingerprint(decoded.get("login_fingerprint")):
            return "credential.inventory_token_vault_schema_invalid", None
        if not _is_fingerprint(decoded.get("oauth_client_fingerprint")):
            return "credential.inventory_token_vault_schema_invalid", None
        if not _is_fingerprint(decoded.get("scope_fingerprint")):
            return "credential.inventory_token_vault_schema_invalid", None
        profile_id = decoded.get("profile_id")
        refresh_token_b64 = decoded.get("refresh_token_b64")
        if (
            type(profile_id) is not str
            or not profile_id
            or len(profile_id.encode("utf-8")) > 128
            or type(refresh_token_b64) is not str
            or not refresh_token_b64
            or len(refresh_token_b64) > ((_MAX_TOKEN_BYTES + 2) // 3) * 4
        ):
            return "credential.inventory_token_vault_schema_invalid", None
        try:
            token_buffer = bytearray(base64.b64decode(refresh_token_b64, validate=True))
        except (ValueError, TypeError):
            return "credential.inventory_token_vault_token_invalid", None
        if not 1 <= len(token_buffer) <= _MAX_TOKEN_BYTES:
            return "credential.inventory_token_vault_token_invalid", None
        if base64.b64encode(token_buffer).decode("ascii") != refresh_token_b64:
            return "credential.inventory_token_vault_token_invalid", None
        validated_record = {
            field: decoded[field]
            for field in _RECORD_FIELDS
            if field != "refresh_token_b64"
        }
        return None, validated_record
    except (UnicodeError, ValueError, TypeError):
        return "credential.inventory_token_vault_schema_invalid", None
    finally:
        _zero(token_buffer)
        token_buffer = None
        raw = b""
        text = ""
        if type(decoded) is dict:
            decoded.clear()
        decoded = {}
        refresh_token_b64 = None


def _read_existing_record(
    tokens: _DirectoryCapability, record_name: _PrivateName
) -> tuple[
    str | None,
    dict[str, object] | None,
    bool,
    _FileIdentity | None,
    bool,
]:
    fd: int | None = None
    raw: bytes | None = None
    code: str | None = None
    record: dict[str, object] | None = None
    exists = False
    identity: _FileIdentity | None = None
    cleanup_failed = False
    try:
        code = _revalidate_directory_capability(tokens)
        if code is not None:
            return code, None, False, None, False
        try:
            fd = os.open(
                record_name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=tokens.fd,
            )
        except FileNotFoundError:
            return None, None, False, None, False
        except OSError as error:
            return _classify_oserror(error), None, False, None, False
        exists = True
        code, identity = _validated_private_file_identity(fd)
        if code is None and identity is not None:
            code = _attest_private_fd_and_name(tokens, record_name, fd, identity)
        if code is None:
            code, raw = _read_bounded(fd)
        if code is None and raw is not None and identity is not None:
            code = _attest_private_fd_and_name(tokens, record_name, fd, identity)
        if code is None and raw is not None:
            code, record = _parse_record(raw)
        if code is None and identity is not None:
            code = _attest_private_fd_and_name(tokens, record_name, fd, identity)
        if code is not None:
            record = None
    except OSError as error:
        code = _classify_oserror(error)
        record = None
    finally:
        if fd is not None:
            close_fd = fd
            fd = None
            if not _close_fd(close_fd):
                cleanup_failed = True
        raw = None
    return code, record, exists, identity, cleanup_failed


def _record_binding_code(
    record: dict[str, object],
    *,
    account_ref: str,
    subject_fingerprint: str,
    login_fingerprint: str,
    oauth_client_fingerprint: str,
    profile_id: str,
    scope_fingerprint: str,
) -> str | None:
    if (
        record["profile_id"] != profile_id
        or record["scope_fingerprint"] != scope_fingerprint
    ):
        return "credential.inventory_token_vault_profile_mismatch"
    if (
        record["account_ref"] != account_ref
        or record["subject_fingerprint"] != subject_fingerprint
        or record["login_fingerprint"] != login_fingerprint
        or record["oauth_client_fingerprint"] != oauth_client_fingerprint
    ):
        return "credential.inventory_token_vault_binding_invalid"
    return None


def _write_all(fd: int, payload: bytearray) -> bool:
    offset = 0
    view = memoryview(payload)
    try:
        while offset < len(payload):
            written = os.write(fd, view[offset:])
            if written <= 0:
                return False
            offset += written
        return True
    except OSError:
        return False
    finally:
        view.release()


def _write_record(
    tokens: _DirectoryCapability,
    record_name: _PrivateName,
    temp_prefix: _PrivateName,
    private_record: _PrivateRecord,
    existing_identity: _FileIdentity | None,
) -> str | None:
    temp_fd: int | None = None
    payload: bytearray | None = None
    serialized = b""
    serialized_text = ""
    renamed = False
    code: str | None = None
    temporary_name: _PrivateName | None = None
    temp_identity: _FileIdentity | None = None
    record: dict[str, object] = private_record.value()
    try:
        code = _revalidate_directory_capability(tokens)
        if code is None:
            for _ in range(8):
                temporary_name = temp_prefix.with_suffix(f"{secrets.token_hex(16)}.tmp")
                try:
                    temp_fd = os.open(
                        temporary_name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_CLOEXEC
                        | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=tokens.fd,
                    )
                    break
                except FileExistsError:
                    temporary_name.clear()
                    temporary_name = None
        if temp_fd is None or temporary_name is None:
            if code is None:
                code = "credential.inventory_token_vault_write_failed"
        if code is None:
            os.fchmod(temp_fd, 0o600)
            code, temp_identity = _validated_private_file_identity(temp_fd)
            if code is None and temp_identity is not None:
                code = _attest_private_fd_and_name(
                    tokens, temporary_name, temp_fd, temp_identity
                )
        if code is None:
            serialized_text = json.dumps(record, sort_keys=True, separators=(",", ":"))
            serialized = serialized_text.encode("utf-8")
            serialized_text = ""
            payload = bytearray(serialized)
            serialized = b""
            if len(payload) > _MAX_FILE_BYTES or not _write_all(temp_fd, payload):
                code = "credential.inventory_token_vault_write_failed"
        if code is None:
            try:
                os.fsync(temp_fd)
            except OSError:
                code = "credential.inventory_token_vault_write_failed"
        if code is None and temp_identity is not None:
            code = _attest_private_fd_and_name(
                tokens, temporary_name, temp_fd, temp_identity
            )

        _zero(payload)
        payload = None
        serialized = b""
        serialized_text = ""
        record.clear()
        record = {}
        private_record.clear()
        temp_prefix.clear()

        if temp_fd is not None:
            close_fd = temp_fd
            temp_fd = None
            if not _close_fd(close_fd) and code is None:
                code = "credential.inventory_token_vault_write_failed"
        if code is None and temp_identity is not None:
            code = _attest_private_name(tokens, temporary_name, temp_identity)
        if code is None:
            if existing_identity is None:
                code = _attest_name_missing(tokens, record_name)
            else:
                code = _attest_private_name(tokens, record_name, existing_identity)
        if code is None and temp_identity is not None:
            code = _attest_private_name(tokens, temporary_name, temp_identity)
        if code is None and temp_identity is not None:
            os.replace(
                temporary_name,
                record_name,
                src_dir_fd=tokens.fd,
                dst_dir_fd=tokens.fd,
            )
            renamed = True
            code = _attest_private_name(tokens, record_name, temp_identity)
        if code is None and renamed:
            try:
                os.fsync(tokens.fd)
            except OSError:
                code = "credential.inventory_token_vault_durability_failed"
        return code
    except OSError:
        code = (
            "credential.inventory_token_vault_durability_failed"
            if renamed
            else "credential.inventory_token_vault_write_failed"
        )
        return code
    finally:
        _zero(payload)
        payload = None
        serialized = b""
        serialized_text = ""
        record.clear()
        record = {}
        private_record.clear()
        temp_prefix.clear()
        if temp_fd is not None:
            close_fd = temp_fd
            temp_fd = None
            _close_fd(close_fd)
        if temporary_name is not None and not renamed:
            if (
                temp_identity is not None
                and _attest_private_name(tokens, temporary_name, temp_identity) is None
            ):
                try:
                    os.unlink(temporary_name, dir_fd=tokens.fd)
                except OSError:
                    pass
            temporary_name.clear()
        temporary_name = None
        record_name.clear()


def _delete_record(
    tokens: _DirectoryCapability,
    record_name: _PrivateName,
    record_identity: _FileIdentity,
) -> str | None:
    code = _attest_private_name(tokens, record_name, record_identity)
    if code is not None:
        return code
    try:
        os.unlink(record_name, dir_fd=tokens.fd)
        try:
            os.fsync(tokens.fd)
        except OSError:
            return "credential.inventory_token_vault_durability_failed"
        return None
    except OSError:
        return "credential.inventory_token_vault_delete_failed"


class GoogleInventoryReadonlyTokenVault:
    """Write-only vault bound to GA-I1 identity and GA-I2a readonly policy."""

    __slots__ = ("_test_parent_fd", "_test_parent_identity")

    def __init__(self) -> None:
        self._test_parent_fd: int | None = None
        self._test_parent_identity: _DirectoryIdentity | None = None

    @classmethod
    def _for_test_tokens_parent_directory_fd(
        cls, parent_directory_fd: object
    ) -> GoogleInventoryReadonlyTokenVault:
        if type(parent_directory_fd) is not int:
            raise TypeError("test tokens parent directory fd must be an exact int")
        vault = cls()
        duplicate = os.dup(parent_directory_fd)
        code, identity = _validated_directory_identity(
            duplicate,
            expected_owner=os.geteuid(),
            exact_mode=0o700,
            reject_group_world_write=False,
        )
        if code is not None or identity is None:
            _close_fd(duplicate)
            raise ValueError("test tokens parent directory capability is invalid")
        vault._test_parent_fd = duplicate
        vault._test_parent_identity = identity
        return vault

    def _open_tokens_directory(
        self,
    ) -> tuple[str | None, _DirectoryCapability | None]:
        if self._test_parent_fd is None or self._test_parent_identity is None:
            return _open_production_tokens_directory()
        try:
            fd = os.dup(self._test_parent_fd)
        except OSError as error:
            return _classify_oserror(error), None
        code, identity = _validated_directory_identity(
            fd,
            expected_owner=os.geteuid(),
            exact_mode=0o700,
            reject_group_world_write=False,
        )
        if code is None and identity is not None:
            try:
                current = os.fstat(fd)
            except OSError as error:
                code = _classify_oserror(error)
            else:
                code = _directory_identity_code(current, self._test_parent_identity)
        if code is not None or identity is None:
            _close_fd(fd)
            return code, None
        capability = _DirectoryCapability(
            [
                _DirectoryNode(
                    fd,
                    None,
                    identity,
                    expected_owner=os.geteuid(),
                    exact_mode=0o700,
                    reject_group_world_write=False,
                )
            ]
        )
        code = _append_directory_component(
            capability,
            "tokens",
            expected_owner=os.geteuid(),
            exact_mode=0o700,
            reject_group_world_write=False,
        )
        if code is not None:
            _close_directory_capability(capability)
            return code, None
        return None, capability

    @staticmethod
    def _profile_binding() -> tuple[str | None, str | None, str | None]:
        try:
            profile = resolve_google_oauth_profile_v1(
                GoogleOAuthProfileIdV1.INVENTORY_READONLY,
                GoogleOAuthOperationV1.PROJECTS_SEARCH,
            )
            if (
                profile.profile_id is not GoogleOAuthProfileIdV1.INVENTORY_READONLY
                or tuple(profile.minimal_scopes)
                != (
                    "cloud-billing.readonly",
                    "cloud-platform.read-only",
                    "email",
                    "openid",
                )
                or not _is_fingerprint(profile.scope_fingerprint)
            ):
                return "credential.inventory_token_vault_profile_mismatch", None, None
            return None, profile.profile_id.value, profile.scope_fingerprint
        except Exception:
            return "credential.inventory_token_vault_profile_mismatch", None, None

    @staticmethod
    def _snapshot_binding(
        manager: object, account_ref: str, subject_id: str
    ) -> tuple[str | None, str | None, str | None]:
        snapshot: object | None = None
        account: object | None = None
        try:
            if type(manager) is not GoogleAccountInventoryManager:
                return "credential.inventory_token_vault_request_invalid", None, None
            snapshot = manager._snapshot_for_internal_use()
            account = snapshot.by_account_ref[account_ref]
            snapshot_subject = account.subject_id
            login_email = account.login_email
            if (
                type(snapshot_subject) is not str
                or type(login_email) is not str
                or not snapshot_subject
                or not login_email
                or snapshot_subject != subject_id
            ):
                return "credential.inventory_token_vault_binding_invalid", None, None
            return None, _fingerprint(snapshot_subject), _fingerprint(login_email)
        except Exception:
            return "credential.inventory_token_vault_binding_invalid", None, None
        finally:
            snapshot = None
            account = None
            manager = None
            account_ref = ""
            subject_id = ""

    def store_inventory_refresh_token(
        self,
        manager: object,
        *,
        account_ref: object,
        subject_id: object,
        oauth_client_fingerprint: object,
        refresh_token: object,
        expected_vault_generation: object,
    ) -> GoogleInventoryReadonlyTokenVaultStoreReceipt:
        code: str | None = None
        generation: int | None = None
        tokens: _DirectoryCapability | None = None
        locked: _LockedRecord | None = None
        private_record: _PrivateRecord | None = None
        record_name: _PrivateName | None = None
        temp_prefix: _PrivateName | None = None
        existing_identity: _FileIdentity | None = None
        encoded_bytes = b""
        encoded_token = ""
        try:
            if (
                type(manager) is not GoogleAccountInventoryManager
                or not _is_safe_account_ref(account_ref)
                or not _is_exact_nonempty_string(subject_id, _MAX_SUBJECT_ID_BYTES)
                or not _is_fingerprint(oauth_client_fingerprint)
                or type(refresh_token) is not bytearray
                or not 1 <= len(refresh_token) <= _MAX_TOKEN_BYTES
                or not (
                    expected_vault_generation is None
                    or (
                        type(expected_vault_generation) is int
                        and 1 <= expected_vault_generation <= _MAX_GENERATION
                    )
                )
            ):
                code = "credential.inventory_token_vault_request_invalid"
            if code is None:
                code, profile_id, scope_fingerprint = self._profile_binding()
            else:
                profile_id = None
                scope_fingerprint = None
            if (
                code is None
                and profile_id is not None
                and scope_fingerprint is not None
            ):
                code, subject_fingerprint, login_fingerprint = self._snapshot_binding(
                    manager, account_ref, subject_id
                )
            else:
                subject_fingerprint = None
                login_fingerprint = None
            if (
                code is None
                and subject_fingerprint is not None
                and login_fingerprint is not None
                and profile_id is not None
                and scope_fingerprint is not None
            ):
                record_name = _PrivateName(f"{account_ref}.json")
                code, tokens = self._open_tokens_directory()
            if code is None and tokens is not None:
                code, locked = _acquire_locked_record(tokens, account_ref)
            if code is None and locked is not None and record_name is not None:
                (
                    code,
                    existing,
                    exists,
                    existing_identity,
                    record_cleanup_failed,
                ) = _read_existing_record(tokens, record_name)
                if code is None and record_cleanup_failed:
                    code = "credential.inventory_token_vault_write_failed"
                if code is None and exists and existing is not None:
                    code = _record_binding_code(
                        existing,
                        account_ref=account_ref,
                        subject_fingerprint=subject_fingerprint,
                        login_fingerprint=login_fingerprint,
                        oauth_client_fingerprint=oauth_client_fingerprint,
                        profile_id=profile_id,
                        scope_fingerprint=scope_fingerprint,
                    )
                    if code is None:
                        current_generation = existing["vault_generation"]
                        if expected_vault_generation != current_generation:
                            code = (
                                "credential.inventory_token_vault_generation_conflict"
                            )
                        elif current_generation >= _MAX_GENERATION:
                            code = (
                                "credential.inventory_token_vault_generation_conflict"
                            )
                        else:
                            generation = current_generation + 1
                elif code is None and not exists:
                    if expected_vault_generation is not None:
                        code = "credential.inventory_token_vault_generation_conflict"
                    else:
                        generation = 1
                existing = None
            if code is None and generation is not None:
                encoded_bytes = base64.b64encode(refresh_token)
                encoded_token = encoded_bytes.decode("ascii")
                encoded_bytes = b""
                _zero(refresh_token)
                private_record = _PrivateRecord(
                    {
                        "format_version": _FORMAT_VERSION,
                        "record_kind": _RECORD_KIND,
                        "vault_generation": generation,
                        "account_ref": account_ref,
                        "subject_fingerprint": subject_fingerprint,
                        "login_fingerprint": login_fingerprint,
                        "oauth_client_fingerprint": oauth_client_fingerprint,
                        "profile_id": profile_id,
                        "scope_fingerprint": scope_fingerprint,
                        "refresh_token_b64": encoded_token,
                    }
                )
                temp_prefix = _PrivateName(f".{account_ref}.")
                encoded_token = ""
                encoded_bytes = b""
                manager = None
                account_ref = None
                subject_id = None
                oauth_client_fingerprint = None
                refresh_token = None
                expected_vault_generation = None
                subject_fingerprint = None
                login_fingerprint = None
                profile_id = None
                scope_fingerprint = None
                code = _write_record(
                    tokens,
                    record_name,
                    temp_prefix,
                    private_record,
                    existing_identity,
                )
        except Exception:
            code = "credential.inventory_token_vault_write_failed"
        finally:
            _zero(refresh_token if type(refresh_token) is bytearray else None)
            if private_record is not None:
                private_record.clear()
            private_record = None
            if record_name is not None:
                record_name.clear()
            record_name = None
            if temp_prefix is not None:
                temp_prefix.clear()
            temp_prefix = None
            encoded_bytes = b""
            encoded_token = ""
            manager = None
            account_ref = None
            subject_id = None
            oauth_client_fingerprint = None
            refresh_token = None
            expected_vault_generation = None
            existing = None
            existing_identity = None
            exists = False
            current_generation = None
            profile_id = None
            scope_fingerprint = None
            subject_fingerprint = None
            login_fingerprint = None
            record_cleanup_failed = False
            cleanup_failed = not _release_locked_record(locked)
            locked = None
            if not _close_directory_capability(tokens):
                cleanup_failed = True
            tokens = None
            if code is None and cleanup_failed:
                code = "credential.inventory_token_vault_write_failed"
        if code is not None:
            _raise(code)
        if generation is None:
            _raise("credential.inventory_token_vault_write_failed")
        return GoogleInventoryReadonlyTokenVaultStoreReceipt(generation)

    def delete_inventory_refresh_token(
        self,
        manager: object,
        *,
        account_ref: object,
        subject_id: object,
        oauth_client_fingerprint: object,
        expected_vault_generation: object,
    ) -> GoogleInventoryReadonlyTokenVaultDeleteReceipt:
        code: str | None = None
        removed = False
        tokens: _DirectoryCapability | None = None
        locked: _LockedRecord | None = None
        record: dict[str, object] | None = None
        record_name: _PrivateName | None = None
        record_identity: _FileIdentity | None = None
        try:
            if (
                type(manager) is not GoogleAccountInventoryManager
                or not _is_safe_account_ref(account_ref)
                or not _is_exact_nonempty_string(subject_id, _MAX_SUBJECT_ID_BYTES)
                or not _is_fingerprint(oauth_client_fingerprint)
                or not (
                    expected_vault_generation is None
                    or (
                        type(expected_vault_generation) is int
                        and 1 <= expected_vault_generation <= _MAX_GENERATION
                    )
                )
            ):
                code = "credential.inventory_token_vault_request_invalid"
            if code is None:
                code, profile_id, scope_fingerprint = self._profile_binding()
            else:
                profile_id = None
                scope_fingerprint = None
            if (
                code is None
                and profile_id is not None
                and scope_fingerprint is not None
            ):
                code, subject_fingerprint, login_fingerprint = self._snapshot_binding(
                    manager, account_ref, subject_id
                )
            else:
                subject_fingerprint = None
                login_fingerprint = None
            if (
                code is None
                and subject_fingerprint is not None
                and login_fingerprint is not None
                and profile_id is not None
                and scope_fingerprint is not None
            ):
                record_name = _PrivateName(f"{account_ref}.json")
                code, tokens = self._open_tokens_directory()
            if code is None and tokens is not None:
                code, locked = _acquire_locked_record(tokens, account_ref)
            if code is None and locked is not None and record_name is not None:
                (
                    code,
                    record,
                    exists,
                    record_identity,
                    record_cleanup_failed,
                ) = _read_existing_record(tokens, record_name)
                if code is None and record_cleanup_failed:
                    code = "credential.inventory_token_vault_delete_failed"
                if code is None and not exists:
                    if expected_vault_generation is not None:
                        code = "credential.inventory_token_vault_generation_conflict"
                elif code is None and record is not None:
                    code = _record_binding_code(
                        record,
                        account_ref=account_ref,
                        subject_fingerprint=subject_fingerprint,
                        login_fingerprint=login_fingerprint,
                        oauth_client_fingerprint=oauth_client_fingerprint,
                        profile_id=profile_id,
                        scope_fingerprint=scope_fingerprint,
                    )
                    if (
                        code is None
                        and expected_vault_generation != record["vault_generation"]
                    ):
                        code = "credential.inventory_token_vault_generation_conflict"
                    if code is None and record_identity is not None:
                        code = _delete_record(tokens, record_name, record_identity)
                        removed = code is None
        except Exception:
            code = "credential.inventory_token_vault_delete_failed"
        finally:
            record = None
            if record_name is not None:
                record_name.clear()
            record_name = None
            record_identity = None
            manager = None
            account_ref = None
            subject_id = None
            oauth_client_fingerprint = None
            expected_vault_generation = None
            exists = False
            profile_id = None
            scope_fingerprint = None
            subject_fingerprint = None
            login_fingerprint = None
            record_cleanup_failed = False
            cleanup_failed = not _release_locked_record(locked)
            locked = None
            if not _close_directory_capability(tokens):
                cleanup_failed = True
            tokens = None
            if code is None and cleanup_failed:
                code = "credential.inventory_token_vault_delete_failed"
        if code is not None:
            _raise(code)
        return GoogleInventoryReadonlyTokenVaultDeleteReceipt(removed)
