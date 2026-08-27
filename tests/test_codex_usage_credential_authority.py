from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Callable

import pytest

import codex_master.codex_usage_credential_authority as authority_module
from codex_master.codex_usage_credential_authority import (
    CodexUsageCredentialAuthority,
    CredentialAuthorityError,
    ProfileCredentialBinding,
)


PROFILE_ID = "profile.one"
PROVIDER = "openai_chatgpt"
GENERATION = 9
AUTH_BYTES = b"synthetic-credential-generation-one"
REPLACEMENT_AUTH_BYTES = b"synthetic-credential-generation-two"
KEY_BYTES = bytes(range(1, 33))


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    path.chmod(0o700)


def _private_file(path: Path, value: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, value)
    finally:
        os.close(fd)
    path.chmod(0o600)


def _authority_layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    profiles_root = tmp_path / "profiles"
    _private_directory(profiles_root)
    profile_root = profiles_root / PROFILE_ID
    _private_directory(profile_root)
    codex_home = profile_root / "codex-home"
    _private_directory(codex_home)
    auth_path = codex_home / "auth.json"
    _private_file(auth_path, AUTH_BYTES)
    key_path = tmp_path / "binding.key"
    _private_file(key_path, KEY_BYTES)
    return profiles_root, key_path, auth_path


def _open_authority(profiles_root: Path, key_path: Path):
    root_fd = os.open(
        profiles_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    key_fd = os.open(key_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        authority = CodexUsageCredentialAuthority(
            root_fd,
            key_fd,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
    finally:
        os.close(key_fd)
        os.close(root_fd)
    return authority


def _digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def _assert_error_without_fd_leak(
    authority: CodexUsageCredentialAuthority,
    operation: Callable[[], object],
) -> CredentialAuthorityError:
    before = _fd_count()
    with pytest.raises(CredentialAuthorityError) as raised:
        operation()
    assert _fd_count() == before
    return raised.value


def _assert_constructor_error_without_fd_leak(
    profiles_root: Path,
    key_path: Path,
    *,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> None:
    before = _fd_count()
    root_fd = os.open(
        profiles_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    key_fd = os.open(key_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    authority = None
    try:
        with pytest.raises(CredentialAuthorityError):
            authority = CodexUsageCredentialAuthority(
                root_fd,
                key_fd,
                expected_uid=os.getuid() if expected_uid is None else expected_uid,
                expected_gid=os.getgid() if expected_gid is None else expected_gid,
            )
    finally:
        if authority is not None:
            authority.close()
        os.close(key_fd)
        os.close(root_fd)
    assert _fd_count() == before


def test_attest_and_project_bind_one_real_pinned_credential_fd(tmp_path: Path) -> None:
    profiles_root, key_path, auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    projection_fd = None
    try:
        first = authority.attest(PROFILE_ID)
        second = authority.attest(PROFILE_ID)

        assert first == second
        assert first.profile_id == PROFILE_ID
        assert re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", first.binding_id)

        projection = authority.project(
            PROFILE_ID,
            first.binding_id,
            GENERATION,
            PROVIDER,
        )
        assert projection.profile_id == PROFILE_ID
        assert projection.binding_id == first.binding_id
        assert projection.generation == GENERATION
        assert projection.provider == PROVIDER
        assert type(projection.fds) is tuple
        assert len(projection.fds) == 1
        projection_fd = projection.fds[0]
        assert type(projection_fd) is int
        assert os.lseek(projection_fd, 0, os.SEEK_CUR) == 0
        assert hmac.compare_digest(
            _digest(os.read(projection_fd, 4096)), _digest(AUTH_BYTES)
        )

        replaced_path = auth_path.with_suffix(".replaced")
        auth_path.rename(replaced_path)
        _private_file(auth_path, REPLACEMENT_AUTH_BYTES)
        os.lseek(projection_fd, 0, os.SEEK_SET)
        assert hmac.compare_digest(
            _digest(os.read(projection_fd, 4096)), _digest(AUTH_BYTES)
        )
    finally:
        if projection_fd is not None:
            os.close(projection_fd)
        authority.close()


def test_profile_binding_is_frozen_slotted_and_redacted(tmp_path: Path) -> None:
    profiles_root, key_path, _auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    try:
        binding = authority.attest(PROFILE_ID)
        assert type(binding) is ProfileCredentialBinding
        assert hasattr(ProfileCredentialBinding, "__slots__")
        with pytest.raises(FrozenInstanceError):
            binding.profile_id = "other"  # type: ignore[misc]
        rendered = repr(binding) + str(binding)
        assert PROFILE_ID not in rendered
        assert binding.binding_id not in rendered
    finally:
        authority.close()


@pytest.mark.parametrize(
    "profile_id",
    [
        "",
        ".",
        "..",
        "/absolute",
        "relative/child",
        "relative\\child",
        " leading",
        "trailing ",
        "two words",
        "line\nbreak",
        "nul\x00byte",
        "ä",
        "a" * 129,
        True,
        1,
        None,
    ],
)
def test_invalid_profile_ids_fail_before_open_without_fd_leak(
    tmp_path: Path, profile_id: object
) -> None:
    profiles_root, key_path, _auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    try:
        _assert_error_without_fd_leak(authority, lambda: authority.attest(profile_id))  # type: ignore[arg-type]
    finally:
        authority.close()


@pytest.mark.parametrize("component", ["profile", "codex-home", "auth.json"])
def test_symlink_at_each_named_component_fails_closed_without_fd_leak(
    tmp_path: Path, component: str
) -> None:
    profiles_root, key_path, auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    profile_path = profiles_root / PROFILE_ID
    home_path = profile_path / "codex-home"
    target = {"profile": profile_path, "codex-home": home_path, "auth.json": auth_path}[
        component
    ]
    backup = target.with_name(target.name + ".real")
    target.rename(backup)
    target.symlink_to(backup, target_is_directory=backup.is_dir())
    try:
        _assert_error_without_fd_leak(authority, lambda: authority.attest(PROFILE_ID))
    finally:
        authority.close()


@pytest.mark.parametrize("component", ["profiles", "profile", "codex-home"])
def test_non_private_directory_mode_fails_closed_without_fd_leak(
    tmp_path: Path, component: str
) -> None:
    profiles_root, key_path, auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    target = {
        "profiles": profiles_root,
        "profile": profiles_root / PROFILE_ID,
        "codex-home": auth_path.parent,
    }[component]
    target.chmod(0o755)
    try:
        _assert_error_without_fd_leak(authority, lambda: authority.attest(PROFILE_ID))
    finally:
        authority.close()


@pytest.mark.parametrize("kind", ["mode", "hardlink", "empty", "oversized"])
def test_unsafe_binding_key_fails_at_construction_without_fd_leak(
    tmp_path: Path, kind: str
) -> None:
    profiles_root, key_path, _auth_path = _authority_layout(tmp_path)
    if kind == "mode":
        key_path.chmod(0o640)
    elif kind == "hardlink":
        os.link(key_path, tmp_path / "binding-key-link")
    elif kind == "empty":
        key_path.write_bytes(b"")
        key_path.chmod(0o600)
    else:
        key_path.write_bytes(b"k" * (1024 * 1024 + 1))
        key_path.chmod(0o600)
    _assert_constructor_error_without_fd_leak(profiles_root, key_path)


def test_non_regular_binding_key_fails_at_construction_without_fd_leak(
    tmp_path: Path,
) -> None:
    profiles_root, _key_path, _auth_path = _authority_layout(tmp_path)
    key_directory = tmp_path / "key-directory"
    _private_directory(key_directory)
    before = _fd_count()
    root_fd = os.open(profiles_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    key_fd = os.open(key_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with pytest.raises(CredentialAuthorityError):
            CodexUsageCredentialAuthority(
                root_fd,
                key_fd,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )
    finally:
        os.close(key_fd)
        os.close(root_fd)
    assert _fd_count() == before


@pytest.mark.parametrize("component", ["profiles-root", "binding-key"])
def test_symlink_fd_at_constructor_boundary_fails_without_fd_leak(
    tmp_path: Path, component: str
) -> None:
    profiles_root, key_path, _auth_path = _authority_layout(tmp_path)
    root_link = tmp_path / "profiles-link"
    key_link = tmp_path / "key-link"
    root_link.symlink_to(profiles_root, target_is_directory=True)
    key_link.symlink_to(key_path)
    before = _fd_count()
    root_fd = os.open(
        root_link if component == "profiles-root" else profiles_root,
        os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    key_fd = os.open(
        key_link if component == "binding-key" else key_path,
        os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        with pytest.raises(CredentialAuthorityError):
            CodexUsageCredentialAuthority(
                root_fd,
                key_fd,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )
    finally:
        os.close(key_fd)
        os.close(root_fd)
    assert _fd_count() == before


def test_invalid_binding_key_fd_closes_duplicated_root_fd(tmp_path: Path) -> None:
    profiles_root, key_path, _auth_path = _authority_layout(tmp_path)
    root_fd = os.open(profiles_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    invalid_key_fd = os.open(key_path, os.O_RDONLY | os.O_CLOEXEC)
    os.close(invalid_key_fd)
    before = _fd_count()
    try:
        with pytest.raises(CredentialAuthorityError):
            CodexUsageCredentialAuthority(
                root_fd,
                invalid_key_fd,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )
        assert _fd_count() == before
    finally:
        os.close(root_fd)
    assert _fd_count() == before - 1


@pytest.mark.parametrize("owner_field", ["uid", "gid"])
def test_wrong_expected_owner_fails_at_construction_without_fd_leak(
    tmp_path: Path, owner_field: str
) -> None:
    profiles_root, key_path, _auth_path = _authority_layout(tmp_path)
    wrong_uid = os.getuid() + 1 if os.getuid() < 2**32 - 1 else os.getuid() - 1
    wrong_gid = os.getgid() + 1 if os.getgid() < 2**32 - 1 else os.getgid() - 1
    _assert_constructor_error_without_fd_leak(
        profiles_root,
        key_path,
        expected_uid=wrong_uid if owner_field == "uid" else os.getuid(),
        expected_gid=wrong_gid if owner_field == "gid" else os.getgid(),
    )


@pytest.mark.parametrize(
    "kind", ["mode", "hardlink", "empty", "oversized", "directory"]
)
def test_unsafe_auth_file_fails_closed_without_fd_leak(
    tmp_path: Path, kind: str
) -> None:
    profiles_root, key_path, auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    if kind == "mode":
        auth_path.chmod(0o640)
    elif kind == "hardlink":
        os.link(auth_path, tmp_path / "auth-link")
    elif kind == "empty":
        auth_path.write_bytes(b"")
        auth_path.chmod(0o600)
    elif kind == "oversized":
        auth_path.write_bytes(b"a" * (1024 * 1024 + 1))
        auth_path.chmod(0o600)
    else:
        backup = auth_path.with_suffix(".regular")
        auth_path.rename(backup)
        _private_directory(auth_path)
    try:
        _assert_error_without_fd_leak(authority, lambda: authority.attest(PROFILE_ID))
    finally:
        authority.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("binding_id", "hmac-sha256:" + "0" * 64),
        ("binding_id", "sha256:" + "0" * 64),
        ("binding_id", "hmac-sha256:" + "A" * 64),
        ("provider", "openai_api"),
        ("provider", True),
        ("generation", 0),
        ("generation", -1),
        ("generation", True),
        ("generation", 2**63),
    ],
)
def test_invalid_projection_request_fails_without_fd_leak(
    tmp_path: Path, field: str, value: object
) -> None:
    profiles_root, key_path, _auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    binding = authority.attest(PROFILE_ID)
    values: dict[str, object] = {
        "profile_id": PROFILE_ID,
        "binding_id": binding.binding_id,
        "generation": GENERATION,
        "provider": PROVIDER,
    }
    values[field] = value
    try:
        _assert_error_without_fd_leak(
            authority,
            lambda: authority.project(**values),  # type: ignore[arg-type]
        )
    finally:
        authority.close()


def test_auth_replacement_after_attest_mismatches_without_fd_leak(
    tmp_path: Path,
) -> None:
    profiles_root, key_path, auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    binding = authority.attest(PROFILE_ID)
    old_path = auth_path.with_suffix(".old")
    auth_path.rename(old_path)
    _private_file(auth_path, REPLACEMENT_AUTH_BYTES)
    try:
        _assert_error_without_fd_leak(
            authority,
            lambda: authority.project(
                PROFILE_ID, binding.binding_id, GENERATION, PROVIDER
            ),
        )
    finally:
        authority.close()


def test_key_replacement_during_read_fails_closed_without_fd_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profiles_root, key_path, _auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    key_inode = key_path.stat().st_ino
    real_pread = authority_module.os.pread
    replaced = False

    def replacing_pread(fd: int, length: int, offset: int) -> bytes:
        nonlocal replaced
        value = real_pread(fd, length, offset)
        if not replaced and os.fstat(fd).st_ino == key_inode:
            replaced = True
            replacement_fd = os.open(key_path, os.O_WRONLY | os.O_TRUNC)
            try:
                os.write(replacement_fd, b"r" * len(KEY_BYTES))
            finally:
                os.close(replacement_fd)
        return value

    monkeypatch.setattr(authority_module.os, "pread", replacing_pread)
    try:
        _assert_error_without_fd_leak(authority, lambda: authority.attest(PROFILE_ID))
        assert replaced
    finally:
        authority.close()


def test_auth_rename_at_final_offset_boundary_fails_closed_without_fd_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profiles_root, key_path, auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    binding = authority.attest(PROFILE_ID)
    auth_inode = auth_path.stat().st_ino
    real_lseek = authority_module.os.lseek
    renamed = False

    def renaming_lseek(fd: int, offset: int, whence: int) -> int:
        nonlocal renamed
        if not renamed and os.fstat(fd).st_ino == auth_inode:
            renamed = True
            auth_path.rename(auth_path.with_suffix(".race-old"))
            _private_file(auth_path, REPLACEMENT_AUTH_BYTES)
        return real_lseek(fd, offset, whence)

    monkeypatch.setattr(authority_module.os, "lseek", renaming_lseek)
    before = _fd_count()
    projection = None
    try:
        with pytest.raises(CredentialAuthorityError):
            projection = authority.project(
                PROFILE_ID, binding.binding_id, GENERATION, PROVIDER
            )
    finally:
        if projection is not None:
            os.close(projection.fds[0])
        authority.close()
    assert renamed
    assert _fd_count() == before - 2


def test_errors_and_binding_rendering_do_not_expose_sensitive_values(
    tmp_path: Path,
) -> None:
    profiles_root, key_path, auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    binding = authority.attest(PROFILE_ID)
    try:
        error = _assert_error_without_fd_leak(
            authority,
            lambda: authority.project(
                PROFILE_ID, "hmac-sha256:" + "0" * 64, GENERATION, PROVIDER
            ),
        )
        rendered = repr(error) + str(error) + repr(binding) + str(binding)
        assert binding.binding_id not in rendered
        assert str(profiles_root) not in rendered
        assert str(auth_path) not in rendered
        assert AUTH_BYTES.decode("ascii") not in rendered
        assert KEY_BYTES.hex() not in rendered
    finally:
        authority.close()


def test_close_is_idempotent_and_later_operations_fail_without_fd_leak(
    tmp_path: Path,
) -> None:
    profiles_root, key_path, _auth_path = _authority_layout(tmp_path)
    before = _fd_count()
    authority = _open_authority(profiles_root, key_path)
    assert _fd_count() == before + 2
    authority.close()
    authority.close()
    assert _fd_count() == before
    _assert_error_without_fd_leak(authority, lambda: authority.attest(PROFILE_ID))
    _assert_error_without_fd_leak(
        authority,
        lambda: authority.project(
            PROFILE_ID, "hmac-sha256:" + "0" * 64, GENERATION, PROVIDER
        ),
    )


def test_authority_close_does_not_close_transferred_projection_fd(
    tmp_path: Path,
) -> None:
    profiles_root, key_path, _auth_path = _authority_layout(tmp_path)
    authority = _open_authority(profiles_root, key_path)
    binding = authority.attest(PROFILE_ID)
    projection = authority.project(PROFILE_ID, binding.binding_id, GENERATION, PROVIDER)
    projection_fd = projection.fds[0]
    authority.close()
    try:
        assert os.lseek(projection_fd, 0, os.SEEK_CUR) == 0
        assert hmac.compare_digest(
            _digest(os.read(projection_fd, 4096)), _digest(AUTH_BYTES)
        )
    finally:
        os.close(projection_fd)
