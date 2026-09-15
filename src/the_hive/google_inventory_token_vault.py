"""Private, write-only storage for Google inventory refresh tokens."""

from __future__ import annotations

import base64
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import http.client as _http_client
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from typing import Final
from urllib.parse import urlencode as _urlencode, urlsplit as _urlsplit

from . import google_account_inventory as _inventory
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
        "credential.inventory_token_vault_legacy_layout",
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
        "inventory_generation",
        "operation_digest",
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
_THE_HIVE_VAULT_ROOT_COMPONENTS: Final[tuple[str, ...]] = ("the-hive-mcp",)
_THE_HIVE_VAULT_SECRET_COMPONENTS: Final[tuple[str, ...]] = (
    "google-oauth",
    "tokens",
)
_LEGACY_VAULT_ROOT_COMPONENT: Final[str] = "codex-master-mcp"
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
    observable_attestation_mismatches_fail_closed: bool
    unsandboxed_same_uid_non_atomic_name_windows_in_scope: bool
    future_isolation: str


_MUTATION_THREAT_BOUNDARY: Final[_MutationThreatBoundary] = _MutationThreatBoundary(
    observable_attestation_mismatches_fail_closed=True,
    unsandboxed_same_uid_non_atomic_name_windows_in_scope=False,
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
        "scan_entries",
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
        scan_entries: bool = True,
    ) -> None:
        self.fd = fd
        self.name = name
        self.identity = identity
        self.expected_owner = expected_owner
        self.exact_mode = exact_mode
        self.reject_group_world_write = reject_group_world_write
        self.scan_entries = scan_entries

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


def _authorization_binding_fingerprint(
    *,
    account_ref: str,
    subject_fingerprint: str,
    login_fingerprint: str,
    oauth_client_fingerprint: str,
    profile_id: str,
    scope_fingerprint: str,
    inventory_generation: int,
) -> str:
    """Return the domain-separated, nonreversible authorization binding."""

    digest = hashlib.sha256(b"the-hive/google-inventory-authorize-binding-v1\x00")
    for value in (
        account_ref,
        subject_fingerprint,
        login_fingerprint,
        oauth_client_fingerprint,
        profile_id,
        scope_fingerprint,
        str(inventory_generation),
    ):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return "sha256:" + digest.hexdigest()


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


def _directory_object_code(
    metadata: os.stat_result, identity: _DirectoryIdentity
) -> str | None:
    current = _directory_identity(metadata)
    if (
        current.device != identity.device
        or current.inode != identity.inode
        or current.file_type != identity.file_type
    ):
        return "credential.inventory_token_vault_path_invalid"
    if current.owner != identity.owner:
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
    expected_identity: _DirectoryIdentity | None = None,
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
        if code is None and expected_identity is not None:
            code = _directory_identity_code(named, expected_identity)
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


def _append_the_hive_vault_root_components(
    capability: _DirectoryCapability, *, effective_uid: int
) -> str | None:
    """Append only the fixed The Hive GA-I2b tree beneath its owner root."""

    for component in _THE_HIVE_VAULT_ROOT_COMPONENTS:
        code = _append_directory_component(
            capability,
            component,
            expected_owner=effective_uid,
            exact_mode=0o700,
            reject_group_world_write=False,
        )
        if code is not None:
            return code
    return None


def _append_the_hive_vault_tokens_directory_components(
    capability: _DirectoryCapability, *, effective_uid: int
) -> str | None:
    code = _append_the_hive_vault_root_components(
        capability, effective_uid=effective_uid
    )
    if code is not None:
        return code
    for component in _THE_HIVE_VAULT_SECRET_COMPONENTS:
        code = _append_directory_component(
            capability,
            component,
            expected_owner=effective_uid,
            exact_mode=0o700,
            reject_group_world_write=False,
        )
        if code is not None:
            return code
    return None


def _fchmod_held_directory(fd: int, mode: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    fchmodat = getattr(libc, "fchmodat", None)
    if fchmodat is None:
        raise OSError(errno.ENOSYS, os.strerror(errno.ENOSYS))
    fchmodat.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
        ctypes.c_int,
    ]
    fchmodat.restype = ctypes.c_int
    if fchmodat(fd, b"", mode, 0x1000) != 0:
        current_errno = ctypes.get_errno()
        raise OSError(current_errno, os.strerror(current_errno))


def _attach_created_directory_node(
    capability: _DirectoryCapability,
    private_name: _PrivateName,
    fd: int,
    identity: _DirectoryIdentity,
    *,
    scan_entries: bool,
) -> tuple[str | None, _DirectoryNode | None]:
    node = _DirectoryNode(
        fd,
        private_name,
        identity,
        expected_owner=os.geteuid(),
        exact_mode=identity.permissions,
        reject_group_world_write=False,
        scan_entries=scan_entries,
    )
    capability.nodes.append(node)
    code = _revalidate_directory_capability(capability)
    if code is not None:
        capability.nodes.pop()
        return code, None
    return None, node


def _rollback_unopened_created_directory(
    capability: _DirectoryCapability, private_name: _PrivateName
) -> bool:
    if _revalidate_directory_capability(capability) is not None:
        return False
    try:
        metadata = os.stat(private_name, dir_fd=capability.fd, follow_symlinks=False)
    except OSError:
        return False
    code = _directory_metadata_code(
        metadata,
        expected_owner=os.geteuid(),
        exact_mode=None,
        reject_group_world_write=False,
    )
    identity = _directory_identity(metadata)
    if code is not None or identity.permissions & ~0o700:
        return False
    if _revalidate_directory_capability(capability) is not None:
        return False
    try:
        current = os.stat(private_name, dir_fd=capability.fd, follow_symlinks=False)
    except OSError:
        return False
    code = _directory_metadata_code(
        current,
        expected_owner=os.geteuid(),
        exact_mode=identity.permissions,
        reject_group_world_write=False,
    )
    if code is not None or _directory_identity_code(current, identity) is not None:
        return False
    try:
        os.rmdir(private_name, dir_fd=capability.fd)
    except OSError:
        return False
    return True


def _ensure_private_directory_component(
    capability: _DirectoryCapability, name: str
) -> tuple[str | None, bool]:
    code = _append_directory_component(
        capability,
        name,
        expected_owner=os.geteuid(),
        exact_mode=0o700,
        reject_group_world_write=False,
    )
    if code is None:
        return None, False
    if code != "credential.inventory_token_vault_unavailable":
        return code, False
    private_name: _PrivateName | None = _PrivateName(name)
    created_fd: int | None = None
    try:
        code = _attest_name_missing(capability, private_name)
        if code is not None:
            return code, False
        try:
            os.mkdir(private_name, mode=0o700, dir_fd=capability.fd)
        except FileExistsError:
            code = _append_directory_component(
                capability,
                name,
                expected_owner=os.geteuid(),
                exact_mode=0o700,
                reject_group_world_write=False,
            )
            return code, False
        except OSError as error:
            if error.errno in (
                errno.EACCES,
                errno.EPERM,
                errno.ELOOP,
                errno.ENOTDIR,
                errno.ENOENT,
                errno.ENODEV,
                errno.ESTALE,
            ):
                return _classify_oserror(error), False
            return "credential.inventory_token_vault_write_failed", False

        primary_code: str | None = None
        try:
            created_fd = os.open(
                private_name,
                os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=capability.fd,
            )
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOTDIR):
                return "credential.inventory_token_vault_path_invalid", False
            primary_code = "credential.inventory_token_vault_write_failed"
            try:
                created_fd = os.open(
                    private_name,
                    os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=capability.fd,
                )
            except OSError as recovery_error:
                if recovery_error.errno in (errno.ELOOP, errno.ENOTDIR):
                    return "credential.inventory_token_vault_path_invalid", False
                _rollback_unopened_created_directory(capability, private_name)
                return primary_code, False

        try:
            created_metadata = os.fstat(created_fd)
        except OSError:
            primary_code = "credential.inventory_token_vault_write_failed"
            try:
                created_metadata = os.fstat(created_fd)
            except OSError:
                return primary_code, False
        code = _directory_metadata_code(
            created_metadata,
            expected_owner=os.geteuid(),
            exact_mode=None,
            reject_group_world_write=False,
        )
        if code is not None:
            return code, False
        initial_identity = _directory_identity(created_metadata)

        try:
            _fchmod_held_directory(created_fd, 0o700)
        except Exception:
            primary_code = "credential.inventory_token_vault_write_failed"

        try:
            current_metadata = os.fstat(created_fd)
        except OSError:
            primary_code = "credential.inventory_token_vault_write_failed"
            try:
                current_metadata = os.fstat(created_fd)
            except OSError:
                return primary_code, False
        code = _directory_object_code(current_metadata, initial_identity)
        if code is not None:
            return code, False
        current_identity = _directory_identity(current_metadata)
        code = _directory_metadata_code(
            current_metadata,
            expected_owner=os.geteuid(),
            exact_mode=None,
            reject_group_world_write=False,
        )
        if code is not None:
            return code, False
        if current_identity.permissions != 0o700 and primary_code is None:
            primary_code = "credential.inventory_token_vault_write_failed"

        node_fd = created_fd
        scan_entries = False
        if current_identity.permissions == 0o700:
            readable_fd: int | None = None
            try:
                readable_fd = os.open(
                    ".",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=created_fd,
                )
                readable_code, readable_identity = _validated_directory_identity(
                    readable_fd,
                    expected_owner=os.geteuid(),
                    exact_mode=0o700,
                    reject_group_world_write=False,
                )
                if readable_code is not None or readable_identity is None:
                    if readable_code in (
                        "credential.inventory_token_vault_path_invalid",
                        "credential.inventory_token_vault_permissions",
                    ):
                        return readable_code, False
                    primary_code = "credential.inventory_token_vault_write_failed"
                else:
                    readable_metadata = os.fstat(readable_fd)
                    code = _directory_identity_code(readable_metadata, current_identity)
                    if code is not None:
                        return code, False
                    node_fd = readable_fd
                    readable_fd = None
                    scan_entries = True
            except OSError:
                primary_code = "credential.inventory_token_vault_write_failed"
            finally:
                if readable_fd is not None:
                    _close_fd(readable_fd)
        if node_fd != created_fd:
            if not _close_fd(created_fd):
                primary_code = "credential.inventory_token_vault_write_failed"
            created_fd = node_fd

        assert private_name is not None
        code, node = _attach_created_directory_node(
            capability,
            private_name,
            created_fd,
            current_identity,
            scan_entries=scan_entries,
        )
        if code == "credential.inventory_token_vault_unavailable":
            primary_code = "credential.inventory_token_vault_write_failed"
            code, node = _attach_created_directory_node(
                capability,
                private_name,
                created_fd,
                current_identity,
                scan_entries=scan_entries,
            )
        if code is not None or node is None:
            if code in (
                "credential.inventory_token_vault_path_invalid",
                "credential.inventory_token_vault_permissions",
            ):
                return code, False
            return "credential.inventory_token_vault_write_failed", False
        created_fd = None
        private_name = None
        return primary_code, True
    finally:
        if created_fd is not None:
            _close_fd(created_fd)
        if private_name is not None:
            private_name.clear()


def _rollback_created_directories(
    capability: _DirectoryCapability,
    created_nodes: list[_DirectoryNode],
) -> bool:
    clean = True
    for node in reversed(created_nodes):
        if len(capability.nodes) < 2 or capability.nodes[-1] is not node:
            clean = False
            continue
        if _revalidate_directory_capability(capability) is not None:
            clean = False
            continue
        if node.scan_entries:
            try:
                with os.scandir(node.fd) as entries:
                    empty = next(entries, None) is None
            except OSError:
                clean = False
                continue
            if not empty:
                clean = False
                continue
        if _revalidate_directory_capability(capability) is not None:
            clean = False
            continue
        assert node.name is not None
        try:
            os.rmdir(node.name, dir_fd=capability.nodes[-2].fd)
        except OSError:
            clean = False
            continue
        capability.nodes.pop()
        fd = node.fd
        node.fd = -1
        if not _close_fd(fd):
            clean = False
        node.name.clear()
    return clean


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


def _duplicate_directory_capability_leaf(
    source: _DirectoryCapability,
) -> tuple[str | None, _DirectoryCapability | None]:
    code = _revalidate_directory_capability(source)
    if code is not None or not source.nodes:
        return code or "credential.inventory_token_vault_path_invalid", None
    source_node = source.nodes[-1]
    try:
        fd = os.dup(source_node.fd)
    except OSError as error:
        return _classify_oserror(error), None
    code, identity = _validated_directory_identity(
        fd,
        expected_owner=source_node.expected_owner,
        exact_mode=source_node.exact_mode,
        reject_group_world_write=source_node.reject_group_world_write,
    )
    if code is None and identity is not None:
        try:
            current = os.fstat(fd)
        except OSError:
            _close_fd(fd)
            return "credential.inventory_token_vault_write_failed", None
        code = _directory_identity_code(current, source_node.identity)
    if code is not None or identity is None:
        _close_fd(fd)
        return code, None
    return (
        None,
        _DirectoryCapability(
            [
                _DirectoryNode(
                    fd,
                    None,
                    identity,
                    expected_owner=source_node.expected_owner,
                    exact_mode=source_node.exact_mode,
                    reject_group_world_write=source_node.reject_group_world_write,
                )
            ]
        ),
    )


def _open_source_owned_inventory_state_directory() -> tuple[
    str | None, _DirectoryCapability | None, Path | None
]:
    """Open the existing systemd state root without caller path selection."""

    descriptor: int | None = None
    try:
        inventory_path = _inventory.systemd_google_account_inventory_path()
        state_root = inventory_path.parent
        descriptor = os.open(
            state_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        code, identity = _validated_directory_identity(
            descriptor,
            expected_owner=os.geteuid(),
            exact_mode=0o700,
            reject_group_world_write=False,
        )
        if code is not None or identity is None:
            _close_fd(descriptor)
            return code, None, None
        capability = _DirectoryCapability(
            [
                _DirectoryNode(
                    descriptor,
                    None,
                    identity,
                    expected_owner=os.geteuid(),
                    exact_mode=0o700,
                    reject_group_world_write=False,
                )
            ]
        )
        descriptor = None
        code = _revalidate_directory_capability(capability)
        if code is not None:
            _close_directory_capability(capability)
            return code, None, None
        return None, capability, state_root
    except _inventory.GoogleAccountInventoryError:
        return "credential.inventory_token_vault_unavailable", None, None
    except OSError as error:
        if descriptor is not None:
            _close_fd(descriptor)
        return _classify_oserror(error), None, None


def _open_production_tokens_directory() -> tuple[
    str | None, _DirectoryCapability | None
]:
    """Reject direct production vault use outside the fixed Authority graph."""

    return "credential.inventory_token_vault_unavailable", None


def _preflight_inventory_oauth_secret_tree(
    _test_state_root_capability: _DirectoryCapability | None = None,
) -> None:
    """Test-only wrapper for the fixed source-owned The Hive preflight."""

    layout: _TheHiveInventoryVaultLayout | None = None
    try:
        if _test_state_root_capability is None:
            code, capability, _state_root_path = (
                _open_source_owned_inventory_state_directory()
            )
        elif type(_test_state_root_capability) is _DirectoryCapability:
            code, capability = _duplicate_directory_capability_leaf(
                _test_state_root_capability
            )
            _state_root_path = None
        else:
            code, capability = "credential.inventory_token_vault_request_invalid", None
            _state_root_path = None
        if code is not None or capability is None:
            _raise(code or "credential.inventory_token_vault_unavailable")
        layout = _TheHiveInventoryVaultLayout(capability, state_root_path=None)
        capability = None
        layout._preflight_for_inventory_authorize()
    finally:
        if layout is not None:
            layout.clear()


def _preflight_the_hive_inventory_oauth_secret_tree(
    capability: _DirectoryCapability,
) -> None:
    """Consume one private state capability to attest/create the fixed tree."""

    code: str | None = None
    created_nodes: list[_DirectoryNode] = []
    try:
        for component in (
            *_THE_HIVE_VAULT_ROOT_COMPONENTS,
            *_THE_HIVE_VAULT_SECRET_COMPONENTS,
        ):
            code, created = _ensure_private_directory_component(capability, component)
            if created:
                created_nodes.append(capability.nodes[-1])
            if code is not None:
                break
        if code is None:
            code = _revalidate_directory_capability(capability)
    except Exception:
        code = "credential.inventory_token_vault_write_failed"
    finally:
        if code is not None and created_nodes:
            _rollback_created_directories(capability, created_nodes)
        created_nodes.clear()
        if not _close_directory_capability(capability) and code is None:
            code = "credential.inventory_token_vault_write_failed"
    if code is not None:
        _raise(code)


class _TheHiveInventoryVaultLayout:
    """One source-resolved state-root capability shared only by fixed GA-I2d ports."""

    __slots__ = ("_state_root", "_state_root_path")

    def __init__(
        self, state_root: _DirectoryCapability, *, state_root_path: Path | None
    ) -> None:
        self._state_root: _DirectoryCapability | None = state_root
        self._state_root_path = state_root_path

    def __repr__(self) -> str:
        return "_TheHiveInventoryVaultLayout(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private inventory vault layout is not serializable")

    def clear(self) -> None:
        state_root = self._state_root
        self._state_root = None
        self._state_root_path = None
        if state_root is not None and not _close_directory_capability(state_root):
            _raise("credential.inventory_token_vault_write_failed")

    def _duplicate_state_root(self) -> _DirectoryCapability:
        state_root = self._state_root
        if state_root is None:
            _raise("credential.inventory_token_vault_unavailable")
        code, duplicate = _duplicate_directory_capability_leaf(state_root)
        if code is not None or duplicate is None:
            _raise(code or "credential.inventory_token_vault_unavailable")
        return duplicate

    @staticmethod
    def _legacy_layout_code(capability: _DirectoryCapability) -> str | None:
        """Attest only a legacy sibling's existence; never open, read or repair it."""

        code = _revalidate_directory_capability(capability)
        if code is not None:
            return code
        try:
            metadata = os.stat(
                _LEGACY_VAULT_ROOT_COMPONENT,
                dir_fd=capability.fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        except OSError as error:
            return _classify_oserror(error)
        if stat.S_ISDIR(metadata.st_mode):
            return "credential.inventory_token_vault_legacy_layout"
        return None

    def _preflight_for_inventory_authorize(self) -> None:
        capability: _DirectoryCapability | None = None
        try:
            capability = self._duplicate_state_root()
            code = self._legacy_layout_code(capability)
            if code is not None:
                _raise(code)
            _preflight_the_hive_inventory_oauth_secret_tree(capability)
            capability = None
        finally:
            if capability is not None and not _close_directory_capability(capability):
                _raise("credential.inventory_token_vault_write_failed")

    def _open_tokens_directory(self) -> tuple[str | None, _DirectoryCapability | None]:
        capability: _DirectoryCapability | None = None
        try:
            capability = self._duplicate_state_root()
            code = self._legacy_layout_code(capability)
            if code is None:
                code = _append_the_hive_vault_tokens_directory_components(
                    capability, effective_uid=os.geteuid()
                )
            if code is None:
                code = _revalidate_directory_capability(capability)
            if code is not None:
                _close_directory_capability(capability)
                return code, None
            result = capability
            capability = None
            return None, result
        except GoogleInventoryReadonlyTokenVaultError as error:
            return error.code, None
        finally:
            if capability is not None:
                _close_directory_capability(capability)

    def _journal_directory_for_authority(self) -> Path:
        state_root_path = self._state_root_path
        if state_root_path is None or self._state_root is None:
            _raise("credential.inventory_token_vault_unavailable")
        return state_root_path / "the-hive-mcp" / "google-oauth"

    def _open_inventory_oauth_directory(self) -> _DirectoryCapability:
        """Open the fixed metadata directory using the same held layout owner."""

        capability = self._duplicate_state_root()
        try:
            code = self._legacy_layout_code(capability)
            if code is not None:
                _raise(code)
            for component in (
                *_THE_HIVE_VAULT_ROOT_COMPONENTS,
                _THE_HIVE_VAULT_SECRET_COMPONENTS[0],
            ):
                code = _append_directory_component(
                    capability,
                    component,
                    expected_owner=os.geteuid(),
                    exact_mode=0o700,
                    reject_group_world_write=False,
                )
                if code is not None:
                    _raise(code)
            code = _revalidate_directory_capability(capability)
            if code is not None:
                _raise(code)
            return capability
        except BaseException:
            _close_directory_capability(capability)
            raise


class _TheHiveInventorySecretTreePreflightCapability:
    """Non-serializable GA-I2c-P preflight gate bound to one private layout."""

    __slots__ = ("_layout", "_cleared")

    def __init__(self, layout: _TheHiveInventoryVaultLayout) -> None:
        self._layout: _TheHiveInventoryVaultLayout | None = layout
        self._cleared = False

    def __repr__(self) -> str:
        return "_TheHiveInventorySecretTreePreflightCapability(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private inventory preflight capability is not serializable")

    def clear(self) -> None:
        self._layout = None
        self._cleared = True

    def _preflight_for_inventory_authorize(self) -> None:
        if self._cleared or self._layout is None:
            _raise("credential.inventory_token_vault_unavailable")
        self._layout._preflight_for_inventory_authorize()


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
        inventory_generation = decoded.get("inventory_generation")
        if (
            type(inventory_generation) is not int
            or not 1 <= inventory_generation <= _MAX_GENERATION
            or not _is_fingerprint(decoded.get("operation_digest"))
        ):
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

    __slots__ = (
        "_authorization_capability",
        "_layout",
        "_test_parent_fd",
        "_test_parent_identity",
    )

    def __init__(self) -> None:
        self._authorization_capability = object()
        self._layout: _TheHiveInventoryVaultLayout | None = None
        self._test_parent_fd: int | None = None
        self._test_parent_identity: _DirectoryIdentity | None = None

    @classmethod
    def _from_fixed_the_hive_layout(
        cls, layout: _TheHiveInventoryVaultLayout
    ) -> GoogleInventoryReadonlyTokenVault:
        if type(layout) is not _TheHiveInventoryVaultLayout:
            raise TypeError("private inventory vault layout is invalid")
        vault = cls()
        vault._layout = layout
        return vault

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
        layout = self._layout
        if layout is not None:
            return layout._open_tokens_directory()
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
    ) -> tuple[str | None, str | None, str | None, int | None]:
        snapshot: object | None = None
        account: object | None = None
        try:
            if type(manager) is not GoogleAccountInventoryManager:
                return (
                    "credential.inventory_token_vault_request_invalid",
                    None,
                    None,
                    None,
                )
            snapshot = manager._snapshot_for_internal_use()
            account = snapshot.by_account_ref[account_ref]
            snapshot_subject = account.subject_id
            login_email = account.login_email
            if (
                type(snapshot.generation) is not int
                or not 1 <= snapshot.generation <= _MAX_GENERATION
                or type(snapshot_subject) is not str
                or type(login_email) is not str
                or not snapshot_subject
                or not login_email
                or snapshot_subject != subject_id
            ):
                return (
                    "credential.inventory_token_vault_binding_invalid",
                    None,
                    None,
                    None,
                )
            return (
                None,
                _fingerprint(snapshot_subject),
                _fingerprint(login_email),
                snapshot.generation,
            )
        except Exception:
            return "credential.inventory_token_vault_binding_invalid", None, None, None
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
        _operation_digest: object = None,
        _inventory_generation: object = None,
        _operation_capability: object = None,
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
                or not (
                    _operation_digest is None
                    or (
                        _is_fingerprint(_operation_digest)
                        and type(_inventory_generation) is int
                        and 1 <= _inventory_generation <= _MAX_GENERATION
                        and _operation_capability is self._authorization_capability
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
                (
                    code,
                    subject_fingerprint,
                    login_fingerprint,
                    snapshot_inventory_generation,
                ) = self._snapshot_binding(manager, account_ref, subject_id)
            else:
                subject_fingerprint = None
                login_fingerprint = None
                snapshot_inventory_generation = None
            if (
                code is None
                and _operation_digest is not None
                and _inventory_generation != snapshot_inventory_generation
            ):
                code = "credential.inventory_token_vault_binding_invalid"
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
                        if (
                            _operation_digest is not None
                            and existing["operation_digest"] == _operation_digest
                            and existing["inventory_generation"]
                            == _inventory_generation
                        ):
                            generation = current_generation
                            _zero(refresh_token)
                        elif expected_vault_generation != current_generation:
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
                if _operation_digest is None:
                    _operation_digest = (
                        "sha256:" + hashlib.sha256(secrets.token_bytes(32)).hexdigest()
                    )
                    _inventory_generation = snapshot_inventory_generation
                if refresh_token:
                    encoded_bytes = base64.b64encode(refresh_token)
                    encoded_token = encoded_bytes.decode("ascii")
                    encoded_bytes = b""
                    _zero(refresh_token)
                    private_record = _PrivateRecord(
                        {
                            "format_version": _FORMAT_VERSION,
                            "record_kind": _RECORD_KIND,
                            "vault_generation": generation,
                            "inventory_generation": _inventory_generation,
                            "operation_digest": _operation_digest,
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

    def _lookup_authorization_operation_generation(
        self,
        manager: object,
        *,
        operation_digest: object,
        binding_fingerprint: object,
        _operation_capability: object,
    ) -> int | None:
        """Recover one exact receipt without accepting caller identity material."""

        code: str | None = None
        result: int | None = None
        tokens: _DirectoryCapability | None = None
        locked: _LockedRecord | None = None
        record: dict[str, object] | None = None
        record_name: _PrivateName | None = None
        snapshot: object | None = None
        try:
            if (
                type(manager) is not GoogleAccountInventoryManager
                or not _is_fingerprint(operation_digest)
                or not _is_fingerprint(binding_fingerprint)
                or _operation_capability is not self._authorization_capability
            ):
                code = "credential.inventory_token_vault_request_invalid"
            if code is None:
                code, profile_id, scope_fingerprint = self._profile_binding()
            else:
                profile_id = None
                scope_fingerprint = None
            if code is None:
                try:
                    snapshot = manager._snapshot_for_internal_use()
                    snapshot_generation = snapshot.generation
                    candidates = tuple(snapshot.by_account_ref.items())
                except Exception:
                    code = "credential.inventory_token_vault_binding_invalid"
                else:
                    if (
                        type(snapshot_generation) is not int
                        or not 1 <= snapshot_generation <= _MAX_GENERATION
                    ):
                        code = "credential.inventory_token_vault_binding_invalid"
            else:
                snapshot_generation = None
                candidates = ()
            if (
                code is None
                and profile_id is not None
                and scope_fingerprint is not None
            ):
                code, tokens = self._open_tokens_directory()
            if (
                code is None
                and tokens is not None
                and profile_id is not None
                and scope_fingerprint is not None
                and snapshot_generation is not None
            ):
                for candidate_account_ref, candidate in candidates:
                    if not _is_safe_account_ref(candidate_account_ref):
                        code = "credential.inventory_token_vault_binding_invalid"
                        break
                    candidate_subject = getattr(candidate, "subject_id", None)
                    candidate_login = getattr(candidate, "login_email", None)
                    if not _is_exact_nonempty_string(
                        candidate_subject, _MAX_SUBJECT_ID_BYTES
                    ) or not _is_exact_nonempty_string(
                        candidate_login, _MAX_SUBJECT_ID_BYTES
                    ):
                        continue
                    assert type(candidate_subject) is str
                    assert type(candidate_login) is str
                    record_name = _PrivateName(f"{candidate_account_ref}.json")
                    code, locked = _acquire_locked_record(tokens, candidate_account_ref)
                    if code is None and locked is not None:
                        (
                            code,
                            record,
                            exists,
                            _record_identity,
                            record_cleanup_failed,
                        ) = _read_existing_record(tokens, record_name)
                        if code is None and record_cleanup_failed:
                            code = "credential.inventory_token_vault_unavailable"
                    else:
                        exists = False
                        record_cleanup_failed = False
                    if code is None and exists and record is not None:
                        subject_fingerprint = _fingerprint(candidate_subject)
                        login_fingerprint = _fingerprint(candidate_login)
                        if (
                            _record_binding_code(
                                record,
                                account_ref=candidate_account_ref,
                                subject_fingerprint=subject_fingerprint,
                                login_fingerprint=login_fingerprint,
                                oauth_client_fingerprint=record[
                                    "oauth_client_fingerprint"
                                ],
                                profile_id=profile_id,
                                scope_fingerprint=scope_fingerprint,
                            )
                            is None
                        ):
                            candidate_binding = _authorization_binding_fingerprint(
                                account_ref=candidate_account_ref,
                                subject_fingerprint=subject_fingerprint,
                                login_fingerprint=login_fingerprint,
                                oauth_client_fingerprint=record[
                                    "oauth_client_fingerprint"
                                ],
                                profile_id=profile_id,
                                scope_fingerprint=scope_fingerprint,
                                inventory_generation=snapshot_generation,
                            )
                            if (
                                record["inventory_generation"] == snapshot_generation
                                and record["operation_digest"] == operation_digest
                                and candidate_binding == binding_fingerprint
                            ):
                                result = record["vault_generation"]
                    if record is not None:
                        record.clear()
                    record = None
                    if record_name is not None:
                        record_name.clear()
                    record_name = None
                    cleanup_failed = not _release_locked_record(locked)
                    locked = None
                    if code is None and cleanup_failed:
                        code = "credential.inventory_token_vault_unavailable"
                    if code is not None or result is not None:
                        break
        except Exception:
            code = "credential.inventory_token_vault_unavailable"
        finally:
            if record is not None:
                record.clear()
            record = None
            if record_name is not None:
                record_name.clear()
            record_name = None
            manager = None
            operation_digest = None
            binding_fingerprint = None
            subject_fingerprint = None
            login_fingerprint = None
            profile_id = None
            scope_fingerprint = None
            snapshot_generation = None
            candidates = ()
            snapshot = None
            exists = False
            _record_identity = None
            record_cleanup_failed = False
            cleanup_failed = not _release_locked_record(locked)
            locked = None
            if not _close_directory_capability(tokens):
                cleanup_failed = True
            tokens = None
            if code is None and cleanup_failed:
                code = "credential.inventory_token_vault_unavailable"
        if code is not None:
            _raise(code)
        return result

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
                (
                    code,
                    subject_fingerprint,
                    login_fingerprint,
                    _snapshot_inventory_generation,
                ) = self._snapshot_binding(manager, account_ref, subject_id)
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


class _InventoryReadonlyAuthorizationTokenReceipt:
    """Secret-free, redacted proof of one exact authorization token effect."""

    __slots__ = ("_binding_fingerprint", "_vault_generation")

    def __init__(
        self,
        *,
        binding_fingerprint: str,
        vault_generation: int,
    ) -> None:
        self._binding_fingerprint = binding_fingerprint
        self._vault_generation = vault_generation

    def __repr__(self) -> str:
        return "_InventoryReadonlyAuthorizationTokenReceipt(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private authorization token receipt is not serializable")

    def __copy__(self) -> object:
        raise TypeError("private authorization token receipt is not copyable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("private authorization token receipt is not copyable")


class _InventoryReadonlyAuthorizationTokenPort:
    """Narrow private GA-I2b capability; it has no token-load operation."""

    __slots__ = ("_capability", "_manager", "_vault")

    def __init__(
        self,
        vault: GoogleInventoryReadonlyTokenVault,
        manager: GoogleAccountInventoryManager,
    ) -> None:
        self._vault = vault
        self._manager = manager
        self._capability = vault._authorization_capability

    def __repr__(self) -> str:
        return "_InventoryReadonlyAuthorizationTokenPort(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private authorization token port is not serializable")

    def __copy__(self) -> object:
        raise TypeError("private authorization token port is not copyable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("private authorization token port is not copyable")

    @staticmethod
    def _scope_fingerprint() -> str:
        code, _profile_id, fingerprint = (
            GoogleInventoryReadonlyTokenVault._profile_binding()
        )
        if code is not None or fingerprint is None:
            _raise("credential.inventory_token_vault_profile_mismatch")
        return fingerprint

    def _authorization_binding_fingerprint(
        self,
        *,
        account_ref: str,
        subject_id: str,
        oauth_client_fingerprint: str,
        inventory_generation: int,
    ) -> str:
        snapshot_code, subject_fingerprint, login_fingerprint, snapshot_generation = (
            self._vault._snapshot_binding(self._manager, account_ref, subject_id)
        )
        profile_code, profile_id, scope_fingerprint = self._vault._profile_binding()
        if (
            snapshot_code is not None
            or profile_code is not None
            or subject_fingerprint is None
            or login_fingerprint is None
            or profile_id is None
            or scope_fingerprint is None
            or snapshot_generation != inventory_generation
        ):
            _raise("credential.inventory_token_vault_binding_invalid")
        return _authorization_binding_fingerprint(
            account_ref=account_ref,
            subject_fingerprint=subject_fingerprint,
            login_fingerprint=login_fingerprint,
            oauth_client_fingerprint=oauth_client_fingerprint,
            profile_id=profile_id,
            scope_fingerprint=scope_fingerprint,
            inventory_generation=inventory_generation,
        )

    def store_authorization_refresh_token(
        self,
        *,
        operation_digest: object,
        account_ref: object,
        subject_id: object,
        oauth_client_fingerprint: object,
        inventory_generation: object,
        expected_vault_generation: object,
        refresh_token: object,
    ) -> _InventoryReadonlyAuthorizationTokenReceipt:
        """Store once or recover the exact existing operation receipt, never its token."""

        try:
            stored = self._vault.store_inventory_refresh_token(
                self._manager,
                account_ref=account_ref,
                subject_id=subject_id,
                oauth_client_fingerprint=oauth_client_fingerprint,
                refresh_token=refresh_token,
                expected_vault_generation=expected_vault_generation,
                _operation_digest=operation_digest,
                _inventory_generation=inventory_generation,
                _operation_capability=self._capability,
            )
            if (
                not _is_fingerprint(operation_digest)
                or not _is_safe_account_ref(account_ref)
                or not _is_exact_nonempty_string(subject_id, _MAX_SUBJECT_ID_BYTES)
                or not _is_fingerprint(oauth_client_fingerprint)
                or type(inventory_generation) is not int
                or not 1 <= inventory_generation <= _MAX_GENERATION
                or type(stored.vault_generation) is not int
                or not 1 <= stored.vault_generation <= _MAX_GENERATION
            ):
                _raise("credential.inventory_token_vault_request_invalid")
            return _InventoryReadonlyAuthorizationTokenReceipt(
                binding_fingerprint=self._authorization_binding_fingerprint(
                    account_ref=account_ref,
                    subject_id=subject_id,
                    oauth_client_fingerprint=oauth_client_fingerprint,
                    inventory_generation=inventory_generation,
                ),
                vault_generation=stored.vault_generation,
            )
        finally:
            _zero(refresh_token if type(refresh_token) is bytearray else None)

    def lookup_authorization_refresh_receipt(
        self,
        *,
        operation_digest: object,
        binding_fingerprint: object,
    ) -> _InventoryReadonlyAuthorizationTokenReceipt | None:
        """Find only this operation's bound receipt; do not expose vault metadata."""

        generation = self._vault._lookup_authorization_operation_generation(
            self._manager,
            operation_digest=operation_digest,
            binding_fingerprint=binding_fingerprint,
            _operation_capability=self._capability,
        )
        if generation is None:
            return None
        if (
            not _is_fingerprint(operation_digest)
            or not _is_fingerprint(binding_fingerprint)
            or type(generation) is not int
            or not 1 <= generation <= _MAX_GENERATION
        ):
            _raise("credential.inventory_token_vault_request_invalid")
        return _InventoryReadonlyAuthorizationTokenReceipt(
            binding_fingerprint=binding_fingerprint,
            vault_generation=generation,
        )


def _new_inventory_readonly_authorization_token_port(
    vault: object,
    manager: object,
) -> _InventoryReadonlyAuthorizationTokenPort:
    """Construct the Authority's fixed-policy GA-I2b port, not a generic vault API."""

    if (
        type(vault) is not GoogleInventoryReadonlyTokenVault
        or type(manager) is not GoogleAccountInventoryManager
    ):
        _raise("credential.inventory_token_vault_request_invalid")
    return _InventoryReadonlyAuthorizationTokenPort(vault, manager)


def _refresh_inventory_scan_access(
    client_id: str, refresh_token: bytearray
) -> tuple[bytearray, float]:
    """One fixed refresh exchange, wholly inside the Vault boundary."""

    connection = None
    payload = None
    access = None
    raw = b""
    value = {}
    token = ""
    failed = True
    deadline = 0.0
    try:
        payload = bytearray(
            _urlencode(
                {
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "refresh_token": bytes(refresh_token),
                }
            ).encode("ascii")
        )
        connection = _http_client.HTTPSConnection("oauth2.googleapis.com", timeout=10)
        connection.request(
            "POST",
            "/token",
            body=payload,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError
        raw = response.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_pairs_without_duplicates)
        if type(value) is not dict:
            raise ValueError
        token = value.get("access_token")
        lifetime = value.get("expires_in")
        if (
            not _is_exact_nonempty_string(token, _MAX_TOKEN_BYTES)
            or any(ord(character) < 33 or ord(character) > 126 for character in token)
            or value.get("token_type") != "Bearer"
            or type(lifetime) is not int
            or not 1 <= lifetime <= 86400
        ):
            raise ValueError
        if "scope" in value:
            scope = value["scope"]
            aliases = {
                "https://www.googleapis.com/auth/cloud-billing.readonly": "cloud-billing.readonly",
                "https://www.googleapis.com/auth/cloud-platform.read-only": "cloud-platform.read-only",
                "https://www.googleapis.com/auth/userinfo.email": "email",
            }
            if type(scope) is not str or {
                aliases.get(part, part) for part in scope.split()
            } != {
                "cloud-billing.readonly",
                "cloud-platform.read-only",
                "email",
                "openid",
            }:
                raise ValueError
        access = bytearray(token.encode("ascii"))
        deadline = time.monotonic() + min(lifetime, 300)
        failed = False
    except Exception:
        failed = True
    finally:
        _zero(payload)
        _zero(refresh_token)
        payload = None
        raw = b""
        token = ""
        if type(value) is dict:
            value.clear()
        value = {}
        if connection is not None:
            try:
                connection.close()
            except Exception:
                failed = True
        if failed:
            _zero(access)
            access = None
    if failed or access is None:
        _raise("credential.inventory_token_vault_unavailable")
    return access, deadline


class _InventoryReadonlyDiscoveryLease:
    """Only fixed discovery reads; the retained bearer never leaves this owner."""

    __slots__ = ("_access", "_deadline", "_target", "_closed")

    def __init__(self, access: bytearray, deadline: float, target: dict[str, object]):
        self._access = access
        self._deadline = deadline
        self._target = target
        self._closed = False

    def __repr__(self) -> str:
        return "_InventoryReadonlyDiscoveryLease(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private inventory discovery lease is not serializable")

    def __copy__(self) -> object:
        raise TypeError("private inventory discovery lease is not copyable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("private inventory discovery lease is not copyable")

    def _target_account_for_discovery(self) -> dict[str, object]:
        if self._closed or time.monotonic() >= self._deadline:
            self._close()
            _raise("credential.inventory_token_vault_unavailable")
        return json.loads(json.dumps(self._target))

    def _read_fixed_page(
        self, operation: object, *, project_number: object, page_token: object
    ) -> dict[str, object]:
        from . import google_inventory_readonly_scan as scan

        connection = None
        headers = {}
        raw = b""
        value = {}
        result = None
        failed = True
        try:
            if self._closed or time.monotonic() >= self._deadline:
                raise ValueError
            request = scan._fixed_discovery_page_request(
                operation, project_number=project_number, page_token=page_token
            )
            endpoint = _urlsplit(request["url"])
            connection = _http_client.HTTPSConnection(endpoint.hostname, timeout=10)
            headers = {
                "Accept": "application/json",
                "Authorization": "Bearer " + self._access.decode("ascii"),
            }
            connection.request(
                "GET",
                endpoint.path + ("?" + endpoint.query if endpoint.query else ""),
                body=None,
                headers=headers,
            )
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024 or self._access in raw:
                raise ValueError
            value = json.loads(raw, object_pairs_hook=_pairs_without_duplicates)
            scan._normalise_fixed_discovery_page(
                operation, value, project_number=project_number
            )
            # Whitelist the provider metadata shape before it crosses the broker.
            collection, fields = {
                GoogleOAuthOperationV1.PROJECTS_SEARCH: (
                    "projects",
                    ("name", "projectId", "state", "displayName"),
                ),
                GoogleOAuthOperationV1.BILLING_ACCOUNTS_LIST: (
                    "billingAccounts",
                    ("name", "displayName"),
                ),
                GoogleOAuthOperationV1.SERVICES_LIST: ("services", ("name", "state")),
                GoogleOAuthOperationV1.KEYS_LIST: (
                    "keys",
                    ("name", "uid", "displayName"),
                ),
            }[operation]
            result = {}
            if collection in value:
                result[collection] = [
                    {key: row[key] for key in fields if key in row}
                    for row in value[collection]
                ]
            if "nextPageToken" in value:
                result["nextPageToken"] = value["nextPageToken"]
            if self._access in json.dumps(result).encode("utf-8"):
                raise ValueError
            failed = False
        except Exception:
            failed = True
        finally:
            headers.clear()
            raw = b""
            if type(value) is dict:
                value.clear()
            value = {}
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    failed = True
            if failed:
                self._close()
                result = None
        if failed or result is None:
            _raise("credential.inventory_token_vault_unavailable")
        return result

    def _close(self) -> None:
        try:
            self._closed = True
            self._target.clear()
        finally:
            _zero(self._access)
            self._access = bytearray()
            self._deadline = 0.0


class _InventoryReadonlyScanBroker:
    """Fixed internal owners, one-shot receipt state, and no token-load API."""

    __slots__ = ("_vault", "_manager", "_issued", "_leases", "_lock")

    def __init__(
        self,
        vault: GoogleInventoryReadonlyTokenVault,
        manager: GoogleAccountInventoryManager,
    ):
        self._vault = vault
        self._manager = manager
        self._issued = {}
        self._leases = {}
        self._lock = threading.RLock()

    def __repr__(self) -> str:
        return "_InventoryReadonlyScanBroker(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private inventory scan broker is not serializable")

    def __copy__(self) -> object:
        raise TypeError("private inventory scan broker is not copyable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("private inventory scan broker is not copyable")

    def _fresh_binding(self, capability: object):
        from .google_inventory_desktop_client_registry import (
            _InventoryDesktopClientRegistryStoreV1,
        )

        snapshot = self._manager._snapshot_for_internal_use()
        # Control owns the Store transaction lock throughout this broker's life.
        # Its manager is rehydrated from that transaction's exact Schema3 bytes.
        active = self._manager._active
        if active is None or active.document is None or active.snapshot is not snapshot:
            raise ValueError
        document = active.document
        if (
            document.schema_version != 3
            or document.authority_generation != capability._inventory_generation
            or document.content_fingerprint != capability._content_fingerprint
            or snapshot.generation != document.authority_generation
            or snapshot.content_fingerprint != document.content_fingerprint
        ):
            raise ValueError
        account = next(
            account
            for account in document.accounts
            if account.ref == capability._account_ref
        )
        if account.subject_id != capability._subject_id:
            raise ValueError
        registry = _InventoryDesktopClientRegistryStoreV1(self._vault._layout).load()
        if registry is None:
            raise ValueError
        client = registry.for_account(account.ref)
        code, profile_id, scope = self._vault._profile_binding()
        if (
            code is not None
            or client.fingerprint != capability._oauth_client_fingerprint
            or scope != capability._scope_fingerprint
        ):
            raise ValueError
        binding = _authorization_binding_fingerprint(
            account_ref=account.ref,
            subject_fingerprint=_fingerprint(account.subject_id),
            login_fingerprint=_fingerprint(account.login_email),
            oauth_client_fingerprint=client.fingerprint,
            profile_id=profile_id,
            scope_fingerprint=scope,
            inventory_generation=document.authority_generation,
        )
        return account, client, binding

    def issue_scan_capability(
        self,
        *,
        account_ref: object,
        subject_id: object,
        inventory_generation: object,
        content_fingerprint: object,
        oauth_client_fingerprint: object,
        scope_fingerprint: object,
        receipt_operation_digest: object,
        receipt_binding_fingerprint: object,
    ) -> object:
        from .google_inventory_readonly_scan import _issue_scan_capability_for_broker

        failed = False
        capability = None
        try:
            with self._lock:
                if (
                    not _is_fingerprint(receipt_operation_digest)
                    or not _is_fingerprint(receipt_binding_fingerprint)
                    or len(self._issued) + len(self._leases) >= 128
                ):
                    raise ValueError
                capability = _issue_scan_capability_for_broker(
                    self,
                    account_ref=account_ref,
                    subject_id=subject_id,
                    inventory_generation=inventory_generation,
                    content_fingerprint=content_fingerprint,
                    oauth_client_fingerprint=oauth_client_fingerprint,
                    scope_fingerprint=scope_fingerprint,
                )
                _, _, binding = self._fresh_binding(capability)
                if binding != receipt_binding_fingerprint:
                    raise ValueError
                generation = self._vault._lookup_authorization_operation_generation(
                    self._manager,
                    operation_digest=receipt_operation_digest,
                    binding_fingerprint=receipt_binding_fingerprint,
                    _operation_capability=self._vault._authorization_capability,
                )
                if type(generation) is not int:
                    raise ValueError
                self._issued[capability] = (
                    receipt_operation_digest,
                    receipt_binding_fingerprint,
                    generation,
                )
        except Exception:
            failed = True
        finally:
            receipt_operation_digest = None
            receipt_binding_fingerprint = None
        if failed or capability is None:
            _raise("credential.inventory_token_vault_binding_invalid")
        return capability

    def _open_readonly_discovery_lease(
        self, capability: object
    ) -> _InventoryReadonlyDiscoveryLease:
        from . import google_inventory_readonly_scan as scan

        fd = None
        tokens = None
        locked = None
        name = None
        raw = None
        record = None
        decoded = None
        refresh = None
        access = None
        lease = None
        failed = True
        receipt = None
        try:
            with self._lock:
                if (
                    type(capability)
                    is not scan._GoogleInventoryReadonlyScanCapabilityV1
                    or capability._broker is not self
                    or capability._consumed is not True
                    or capability._discovery_claimed is not True
                ):
                    raise ValueError
                receipt = self._issued.pop(capability, None)
                if receipt is None:
                    raise ValueError
                account, client, binding = self._fresh_binding(capability)
                if binding != receipt[1]:
                    raise ValueError
                generation = self._vault._lookup_authorization_operation_generation(
                    self._manager,
                    operation_digest=receipt[0],
                    binding_fingerprint=receipt[1],
                    _operation_capability=self._vault._authorization_capability,
                )
                if generation != receipt[2]:
                    raise ValueError
                code, tokens = self._vault._open_tokens_directory()
                if code is not None or tokens is None:
                    raise ValueError
                code, locked = _acquire_locked_record(tokens, account.ref)
                if code is not None or locked is None:
                    raise ValueError
                name = _PrivateName(account.ref + ".json")
                fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=tokens.fd,
                )
                code, identity = _validated_private_file_identity(fd)
                if (
                    code is not None
                    or identity is None
                    or _attest_private_fd_and_name(tokens, name, fd, identity)
                    is not None
                ):
                    raise ValueError
                code, raw = _read_bounded(fd)
                if (
                    code is not None
                    or raw is None
                    or _attest_private_fd_and_name(tokens, name, fd, identity)
                    is not None
                ):
                    raise ValueError
                code, record = _parse_record(raw)
                if (
                    code is not None
                    or record is None
                    or _record_binding_code(
                        record,
                        account_ref=account.ref,
                        subject_fingerprint=_fingerprint(account.subject_id),
                        login_fingerprint=_fingerprint(account.login_email),
                        oauth_client_fingerprint=client.fingerprint,
                        profile_id="inventory_readonly",
                        scope_fingerprint=capability._scope_fingerprint,
                    )
                    is not None
                    or record["operation_digest"] != receipt[0]
                    or record["vault_generation"] != generation
                    or record["inventory_generation"]
                    != capability._inventory_generation
                ):
                    raise ValueError
                decoded = json.loads(raw, object_pairs_hook=_pairs_without_duplicates)
                refresh = bytearray(
                    base64.b64decode(decoded["refresh_token_b64"], validate=True)
                )
                target = {
                    field: getattr(account, field)
                    for field in (
                        "ref",
                        "login_email",
                        "recovery_email",
                        "label",
                        "subject_id",
                    )
                }
                target["billing_accounts"] = [
                    {
                        field: getattr(row, field)
                        for field in ("ref", "billing_account_id", "label")
                    }
                    for row in account.billing_accounts
                ]
                target["projects"] = [
                    {
                        field: getattr(row, field)
                        for field in (
                            "ref",
                            "billing_account_ref",
                            "status",
                            "project_id",
                            "project_number",
                            "key_id",
                            "key_uid",
                            "project_name",
                            "purpose",
                            "key_name",
                        )
                    }
                    for row in account.projects
                ]
                scan._validate_sealed_target_account(
                    target, account_ref=account.ref, subject_id=account.subject_id
                )
                access, deadline = _refresh_inventory_scan_access(
                    client.client_id, refresh
                )
                lease = _InventoryReadonlyDiscoveryLease(access, deadline, target)
                self._leases[capability] = lease
                failed = False
        except Exception:
            failed = True
        finally:
            _zero(refresh)
            refresh = None
            raw = None
            if type(decoded) is dict:
                decoded.clear()
            decoded = None
            if type(record) is dict:
                record.clear()
            record = None
            receipt = None
            if not _close_fd(fd):
                failed = True
            if name is not None:
                name.clear()
            if not _release_locked_record(locked):
                failed = True
            if not _close_directory_capability(tokens):
                failed = True
            if failed:
                _zero(access)
                if lease is not None:
                    lease._close()
                if type(capability) is scan._GoogleInventoryReadonlyScanCapabilityV1:
                    with self._lock:
                        self._leases.pop(capability, None)
        if failed or lease is None:
            _raise("credential.inventory_token_vault_unavailable")
        return lease

    def close_scan_capability(self, capability: object) -> None:
        from .google_inventory_readonly_scan import (
            _GoogleInventoryReadonlyScanCapabilityV1,
        )

        if (
            type(capability) is not _GoogleInventoryReadonlyScanCapabilityV1
            or capability._broker is not self
        ):
            _raise("credential.inventory_token_vault_request_invalid")
        with self._lock:
            self._issued.pop(capability, None)
            lease = self._leases.pop(capability, None)
            if lease is not None:
                lease._close()


def _new_inventory_readonly_scan_broker(
    vault: object, manager: object
) -> _InventoryReadonlyScanBroker:
    """Compose a broker only while Control holds the manager's Store transaction."""

    if (
        type(vault) is not GoogleInventoryReadonlyTokenVault
        or type(manager) is not GoogleAccountInventoryManager
        or type(vault._layout) is not _TheHiveInventoryVaultLayout
    ):
        _raise("credential.inventory_token_vault_request_invalid")
    return _InventoryReadonlyScanBroker(vault, manager)


class _TheHiveInventoryVaultProductionComponents:
    """The Authority's fixed GA-I2c-P/GA-I2b layout composition, never caller-made."""

    __slots__ = ("_layout", "_preflight", "_vault")

    def __init__(self, layout: _TheHiveInventoryVaultLayout) -> None:
        self._layout = layout
        self._preflight = _TheHiveInventorySecretTreePreflightCapability(layout)
        self._vault = GoogleInventoryReadonlyTokenVault._from_fixed_the_hive_layout(
            layout
        )

    def __repr__(self) -> str:
        return "_TheHiveInventoryVaultProductionComponents(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError(
            "private inventory vault production components are not serializable"
        )

    def clear(self) -> None:
        self._preflight.clear()
        self._layout.clear()

    def _preflight_for_inventory_authorize(self) -> None:
        self._preflight._preflight_for_inventory_authorize()

    def _journal_directory_for_authority(self) -> Path:
        return self._layout._journal_directory_for_authority()


def _new_the_hive_inventory_vault_components_from_state_root(
    state_root: _DirectoryCapability, *, state_root_path: Path | None
) -> _TheHiveInventoryVaultProductionComponents:
    layout = _TheHiveInventoryVaultLayout(state_root, state_root_path=state_root_path)
    attestation: _DirectoryCapability | None = None
    try:
        attestation = layout._duplicate_state_root()
        code = layout._legacy_layout_code(attestation)
        if code is not None:
            _raise(code)
        return _TheHiveInventoryVaultProductionComponents(layout)
    except Exception:
        layout.clear()
        raise
    finally:
        if attestation is not None:
            _close_directory_capability(attestation)


def _new_the_hive_inventory_vault_production_components() -> (
    _TheHiveInventoryVaultProductionComponents
):
    """Resolve one fixed systemd state-root resource for the Authority's full lifetime."""

    code, state_root, state_root_path = _open_source_owned_inventory_state_directory()
    if code is not None or state_root is None:
        _raise(code or "credential.inventory_token_vault_unavailable")
    if state_root_path is None:
        _close_directory_capability(state_root)
        _raise("credential.inventory_token_vault_unavailable")
    return _new_the_hive_inventory_vault_components_from_state_root(
        state_root, state_root_path=state_root_path
    )


def _for_test_the_hive_inventory_vault_production_components(
    state_root_capability: object,
) -> _TheHiveInventoryVaultProductionComponents:
    """Narrow test-only injection for the source-owned fixed layout capability."""

    if type(state_root_capability) is not _DirectoryCapability:
        _raise("credential.inventory_token_vault_request_invalid")
    code, duplicate = _duplicate_directory_capability_leaf(state_root_capability)
    if code is not None or duplicate is None:
        _raise(code or "credential.inventory_token_vault_unavailable")
    return _new_the_hive_inventory_vault_components_from_state_root(
        duplicate, state_root_path=None
    )
