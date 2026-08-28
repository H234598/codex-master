"""FD-pinned credential authority for Codex Usage profiles."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from dataclasses import dataclass
from threading import RLock

from codex_master.fleet_home_broker_protocol import MAX_CHPB_GENERATION
from codex_master.fleet_home_broker_runtime import CredentialProjection


MAX_AUTH_BYTES = 1024 * 1024
MAX_BINDING_KEY_BYTES = 1024 * 1024

_BINDING_DOMAIN = b"codex-master/codex-usage-credential-binding/v1\x00"
_PROFILE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_BINDING_ID_RE = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")
_PROVIDER = "openai_chatgpt"
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


class CredentialAuthorityError(ValueError):
    """Sparse failure at the credential authority trust boundary."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ProfileCredentialBinding:
    profile_id: str
    binding_id: str

    def __repr__(self) -> str:
        return "ProfileCredentialBinding(<redacted>)"

    def __str__(self) -> str:
        return repr(self)


def _fail(code: str) -> None:
    raise CredentialAuthorityError(code) from None


def _fd(value: object) -> int:
    if type(value) is not int or value < 0:
        _fail("invalid_authority_configuration")
    return value


def _owner(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 2**32 - 1:
        _fail("invalid_authority_configuration")
    return value


def _profile_id(value: object) -> str:
    if type(value) is not str or _PROFILE_ID_RE.fullmatch(value) is None:
        _fail("invalid_profile_id")
    return value


def _binding_id(value: object) -> str:
    if type(value) is not str or _BINDING_ID_RE.fullmatch(value) is None:
        _fail("invalid_credential_binding")
    return value


def _generation(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_CHPB_GENERATION:
        _fail("invalid_projection_request")
    return value


def _provider(value: object) -> str:
    if type(value) is not str or value != _PROVIDER:
        _fail("invalid_projection_request")
    return value


def _metadata(value: os.stat_result) -> tuple[int, ...]:
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


def _directory_metadata(value: os.stat_result, uid: int, gid: int) -> tuple[int, ...]:
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_IMODE(value.st_mode) != 0o700
        or value.st_uid != uid
        or value.st_gid != gid
    ):
        _fail("unsafe_credential_layout")
    return _metadata(value)


def _file_metadata(
    value: os.stat_result,
    uid: int,
    gid: int,
    maximum: int,
) -> tuple[int, ...]:
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_uid != uid
        or value.st_gid != gid
        or value.st_nlink != 1
        or not 1 <= value.st_size <= maximum
    ):
        _fail("unsafe_credential_layout")
    return _metadata(value)


def _close(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


class CodexUsageCredentialAuthority:
    """Bind and project one canonical profile from already-open trusted FDs."""

    __slots__ = (
        "_binding_key_fd",
        "_closed",
        "_expected_gid",
        "_expected_uid",
        "_lock",
        "_profiles_root_fd",
        "_profiles_root_metadata",
    )

    def __init__(
        self,
        profiles_root_fd: int,
        binding_key_fd: int,
        *,
        expected_uid: int,
        expected_gid: int,
    ) -> None:
        profiles_root_fd = _fd(profiles_root_fd)
        binding_key_fd = _fd(binding_key_fd)
        expected_uid = _owner(expected_uid)
        expected_gid = _owner(expected_gid)
        root_copy = None
        key_copy = None
        try:
            root_copy = os.dup(profiles_root_fd)
            key_copy = os.dup(binding_key_fd)
            os.set_inheritable(root_copy, False)
            os.set_inheritable(key_copy, False)
            root_metadata = _directory_metadata(
                os.fstat(root_copy), expected_uid, expected_gid
            )
            _file_metadata(
                os.fstat(key_copy),
                expected_uid,
                expected_gid,
                MAX_BINDING_KEY_BYTES,
            )
        except CredentialAuthorityError:
            _close(key_copy)
            _close(root_copy)
            raise
        except Exception:
            _close(key_copy)
            _close(root_copy)
            _fail("invalid_authority_configuration")
        self._profiles_root_fd = root_copy
        self._binding_key_fd = key_copy
        self._expected_uid = expected_uid
        self._expected_gid = expected_gid
        self._profiles_root_metadata = root_metadata
        self._closed = False
        self._lock = RLock()

    def _require_open(self) -> None:
        if self._closed:
            _fail("credential_authority_closed")

    def _validate_root(self) -> None:
        observed = _directory_metadata(
            os.fstat(self._profiles_root_fd),
            self._expected_uid,
            self._expected_gid,
        )
        if observed != self._profiles_root_metadata:
            _fail("credential_layout_drifted")

    def _open_directory(self, parent_fd: int, name: str) -> tuple[int, tuple[int, ...]]:
        try:
            fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        except Exception:
            _fail("credential_unavailable")
        try:
            observed = _directory_metadata(
                os.fstat(fd), self._expected_uid, self._expected_gid
            )
            named = _directory_metadata(
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False),
                self._expected_uid,
                self._expected_gid,
            )
            if named != observed:
                _fail("credential_layout_drifted")
            return fd, observed
        except CredentialAuthorityError:
            _close(fd)
            raise
        except Exception:
            _close(fd)
            _fail("credential_unavailable")

    def _read_key(self) -> bytes:
        try:
            before = _file_metadata(
                os.fstat(self._binding_key_fd),
                self._expected_uid,
                self._expected_gid,
                MAX_BINDING_KEY_BYTES,
            )
            value = os.pread(self._binding_key_fd, MAX_BINDING_KEY_BYTES + 1, 0)
            after = _file_metadata(
                os.fstat(self._binding_key_fd),
                self._expected_uid,
                self._expected_gid,
                MAX_BINDING_KEY_BYTES,
            )
        except CredentialAuthorityError:
            raise
        except Exception:
            _fail("credential_unavailable")
        if before != after or len(value) != before[6]:
            _fail("credential_layout_drifted")
        return value

    def _binding_and_fd(self, profile_id: str) -> tuple[str, int]:
        profile_fd = None
        home_fd = None
        auth_fd = None
        try:
            self._validate_root()
            profile_fd, profile_metadata = self._open_directory(
                self._profiles_root_fd, profile_id
            )
            home_fd, home_metadata = self._open_directory(profile_fd, "codex-home")
            try:
                auth_fd = os.open("auth.json", _FILE_FLAGS, dir_fd=home_fd)
            except Exception:
                _fail("credential_unavailable")
            auth_metadata = _file_metadata(
                os.fstat(auth_fd),
                self._expected_uid,
                self._expected_gid,
                MAX_AUTH_BYTES,
            )
            auth_bytes = os.pread(auth_fd, MAX_AUTH_BYTES + 1, 0)
            if len(auth_bytes) != auth_metadata[6]:
                _fail("credential_layout_drifted")
            key_bytes = self._read_key()
            profile_bytes = profile_id.encode("ascii")
            digest = hmac.new(
                key_bytes,
                _BINDING_DOMAIN
                + len(profile_bytes).to_bytes(2, "big")
                + profile_bytes
                + auth_bytes,
                hashlib.sha256,
            ).hexdigest()

            os.lseek(auth_fd, 0, os.SEEK_SET)
            self._validate_root()
            if (
                _directory_metadata(
                    os.fstat(profile_fd), self._expected_uid, self._expected_gid
                )
                != profile_metadata
                or _directory_metadata(
                    os.stat(
                        profile_id,
                        dir_fd=self._profiles_root_fd,
                        follow_symlinks=False,
                    ),
                    self._expected_uid,
                    self._expected_gid,
                )
                != profile_metadata
            ):
                _fail("credential_layout_drifted")
            if (
                _directory_metadata(
                    os.fstat(home_fd), self._expected_uid, self._expected_gid
                )
                != home_metadata
                or _directory_metadata(
                    os.stat("codex-home", dir_fd=profile_fd, follow_symlinks=False),
                    self._expected_uid,
                    self._expected_gid,
                )
                != home_metadata
            ):
                _fail("credential_layout_drifted")
            if (
                _file_metadata(
                    os.fstat(auth_fd),
                    self._expected_uid,
                    self._expected_gid,
                    MAX_AUTH_BYTES,
                )
                != auth_metadata
                or _file_metadata(
                    os.stat("auth.json", dir_fd=home_fd, follow_symlinks=False),
                    self._expected_uid,
                    self._expected_gid,
                    MAX_AUTH_BYTES,
                )
                != auth_metadata
            ):
                _fail("credential_layout_drifted")
            result_fd = auth_fd
            auth_fd = None
            return f"hmac-sha256:{digest}", result_fd
        except CredentialAuthorityError:
            raise
        except Exception:
            _fail("credential_unavailable")
        finally:
            _close(auth_fd)
            _close(home_fd)
            _close(profile_fd)

    def attest(self, profile_id: str) -> ProfileCredentialBinding:
        with self._lock:
            self._require_open()
            profile_id = _profile_id(profile_id)
            binding_id, auth_fd = self._binding_and_fd(profile_id)
            _close(auth_fd)
            return ProfileCredentialBinding(profile_id, binding_id)

    def project(
        self,
        profile_id: str,
        binding_id: str,
        generation: int,
        provider: str,
    ) -> CredentialProjection:
        with self._lock:
            self._require_open()
            profile_id = _profile_id(profile_id)
            binding_id = _binding_id(binding_id)
            generation = _generation(generation)
            provider = _provider(provider)
            observed_binding, auth_fd = self._binding_and_fd(profile_id)
            if not hmac.compare_digest(observed_binding, binding_id):
                _close(auth_fd)
                _fail("credential_binding_mismatch")
            try:
                projection = CredentialProjection(
                    profile_id,
                    binding_id,
                    generation,
                    provider,
                    (auth_fd,),
                )
            except Exception:
                _close(auth_fd)
                _fail("credential_projection_failed")
            return projection

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            _close(self._binding_key_fd)
            _close(self._profiles_root_fd)


__all__ = (
    "CodexUsageCredentialAuthority",
    "CredentialAuthorityError",
    "MAX_AUTH_BYTES",
    "MAX_BINDING_KEY_BYTES",
    "ProfileCredentialBinding",
)
