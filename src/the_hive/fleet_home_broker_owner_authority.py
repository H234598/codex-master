"""Closed owner-layout schema and FD-bound broker-owner authority."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
import stat

import selinux

from the_hive.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    RuntimeBoundaryError,
    _validate_release_spec,
)


_LAYOUT_ABI = "TH-ROOT-OWNER-LAYOUT/1"
_LAYOUT_ROLES = (
    "Intentparent",
    "WAL",
    "Lease",
    "Config",
    "ResourceEvidence",
    "Registry",
    "Poolroot",
    "Credentialprofilroot",
    "Bindingkey",
)
_ROLE_FIELDS = (
    "role",
    "path",
    "purpose",
    "object_type",
    "uid",
    "gid",
    "mode",
    "link_count",
    "selinux_type",
    "selinux_mls_range",
    "joint_release_version",
    "release_id",
)
_MAX_LAYOUT_BYTES = 1024 * 1024
_MAX_ID = 2**32 - 1


class OwnerAuthorityError(ValueError):
    """Raised when owner-layout or FD authority evidence is invalid."""

    __slots__ = ()


def _fail(message: str) -> None:
    raise OwnerAuthorityError(message) from None


def _text(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        _fail("owner layout is invalid")
    return value


def _digest(value: object, message: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(message)
    return value


def _canonical_path(value: object) -> str:
    path = _text(value)
    if (
        not path.startswith("/")
        or path == "/"
        or path.endswith("/")
        or any(part in {"", ".", ".."} for part in path.split("/")[1:])
    ):
        _fail("owner layout is invalid")
    return path


def _selinux_type(value: object) -> str:
    label = _text(value)
    if (
        not label.endswith("_t")
        or not label[0].islower()
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in label)
    ):
        _fail("owner layout is invalid")
    return label


def _range(value: object) -> str | None:
    if value is None:
        return None
    return _text(value)


def _integer(value: object, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        _fail("owner layout is invalid")
    return value


def _duplicate_rejecting_object(pairs: list[tuple[object, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            _fail("owner layout is invalid")
        result[key] = value
    return result


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except Exception:
        _fail("owner layout is invalid")


@dataclass(frozen=True, slots=True)
class _RootBrokerOwnerLayoutRoleV1:
    role: str
    path: str
    purpose: str
    object_type: str
    uid: int
    gid: int
    mode: int
    link_count: int
    selinux_type: str
    selinux_mls_range: str | None
    joint_release_version: int
    release_id: str


@dataclass(frozen=True, slots=True, init=False)
class RootBrokerOwnerLayoutV1:
    abi: str
    roles: tuple[_RootBrokerOwnerLayoutRoleV1, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("root_broker_owner_layout_factory_required")

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> RootBrokerOwnerLayoutV1:
        if type(payload) is not bytes or not payload or len(payload) > _MAX_LAYOUT_BYTES:
            _fail("owner layout is invalid")
        try:
            document = json.loads(
                payload.decode("ascii"), object_pairs_hook=_duplicate_rejecting_object
            )
        except OwnerAuthorityError:
            raise
        except Exception:
            _fail("owner layout is invalid")
        if type(document) is not dict or set(document) != {"abi", "roles"}:
            _fail("owner layout is invalid")
        if document["abi"] != _LAYOUT_ABI or type(document["roles"]) is not list:
            _fail("owner layout is invalid")
        if len(document["roles"]) != len(_LAYOUT_ROLES):
            _fail("owner layout is invalid")
        roles: list[_RootBrokerOwnerLayoutRoleV1] = []
        for expected_role, entry in zip(_LAYOUT_ROLES, document["roles"], strict=True):
            if type(entry) is not dict or set(entry) != set(_ROLE_FIELDS):
                _fail("owner layout is invalid")
            if entry["role"] != expected_role or entry["purpose"] != expected_role:
                _fail("owner layout is invalid")
            if entry["object_type"] not in {"directory", "regular_file"}:
                _fail("owner layout is invalid")
            if entry["joint_release_version"] != 1:
                _fail("owner layout is invalid")
            mode = _integer(entry["mode"], 0o7777)
            link_count = _integer(entry["link_count"], _MAX_ID)
            if link_count == 0:
                _fail("owner layout is invalid")
            roles.append(
                _RootBrokerOwnerLayoutRoleV1(
                    expected_role,
                    _canonical_path(entry["path"]),
                    expected_role,
                    entry["object_type"],
                    _integer(entry["uid"], _MAX_ID),
                    _integer(entry["gid"], _MAX_ID),
                    mode,
                    link_count,
                    _selinux_type(entry["selinux_type"]),
                    _range(entry["selinux_mls_range"]),
                    1,
                    _text(entry["release_id"]),
                )
            )
        layout = object.__new__(cls)
        object.__setattr__(layout, "abi", _LAYOUT_ABI)
        object.__setattr__(layout, "roles", tuple(roles))
        if layout.canonical_bytes() != payload:
            _fail("owner layout is invalid")
        return layout

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(
            {
                "abi": self.abi,
                "roles": [
                    {
                        "role": entry.role,
                        "path": entry.path,
                        "purpose": entry.purpose,
                        "object_type": entry.object_type,
                        "uid": entry.uid,
                        "gid": entry.gid,
                        "mode": entry.mode,
                        "link_count": entry.link_count,
                        "selinux_type": entry.selinux_type,
                        "selinux_mls_range": entry.selinux_mls_range,
                        "joint_release_version": entry.joint_release_version,
                        "release_id": entry.release_id,
                    }
                    for entry in self.roles
                ],
            }
        )


def root_broker_owner_layout_digest(payload: bytes) -> str:
    if type(payload) is not bytes:
        _fail("owner layout is invalid")
    return sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class FdSelinuxObjectLabelV1:
    object_type: str
    mls_range: str | None

    @classmethod
    def observe(
        cls,
        fd: int,
        *,
        expected_type: str,
        expected_mls_range: str | None,
    ) -> FdSelinuxObjectLabelV1:
        if type(fd) is not int or fd < 0:
            _fail("SELinux object label is invalid")
        try:
            expected_type = _selinux_type(expected_type)
            expected_mls_range = _range(expected_mls_range)
        except OwnerAuthorityError:
            _fail("SELinux object label is invalid")
        context: object | None = None
        failed = False
        observed_type: object = None
        observed_range: object = None
        try:
            result = selinux.fgetfilecon_raw(fd)
            if type(result) not in {tuple, list} or len(result) != 2:
                raise ValueError
            length, raw_context = result
            if type(length) is not int or length < 0 or type(raw_context) is not str:
                raise ValueError
            if selinux.security_check_context_raw(raw_context) != 0:
                raise ValueError
            context = selinux.context_new(raw_context)
            if context is None:
                raise ValueError
            observed_type = selinux.context_type_get(context)
            observed_range = selinux.context_range_get(context)
        except Exception:
            failed = True
        finally:
            if context is not None:
                try:
                    selinux.context_free(context)
                except Exception:
                    failed = True
        if (
            failed
            or type(observed_type) is not str
            or not observed_type
            or type(observed_range) not in {str, type(None)}
            or observed_type != expected_type
            or observed_range != expected_mls_range
        ):
            _fail("SELinux object label is invalid")
        return cls(observed_type, observed_range)


class _RootBrokerOwnerAuthorityCarrier:
    __slots__ = ("_authority_state",)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RootBrokerOwnerAuthorityV1(_RootBrokerOwnerAuthorityCarrier):
    layout: RootBrokerOwnerLayoutV1
    layout_digest: str
    release: BrokerReleaseSpec

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("root_broker_owner_authority_factory_required")

    def __copy__(self) -> RootBrokerOwnerAuthorityV1:
        raise TypeError("root broker owner authority is not transferable")

    def __deepcopy__(self, _memo: object) -> RootBrokerOwnerAuthorityV1:
        raise TypeError("root broker owner authority is not transferable")

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("root broker owner authority is not transferable")

    def __repr__(self) -> str:
        return "<RootBrokerOwnerAuthorityV1 redacted>"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class _RootBrokerOwnerAuthorityState:
    root_device: int
    root_inode: int
    layout_device: int
    layout_inode: int
    layout_size: int


def _fd_stat(fd: object, predicate) -> os.stat_result:
    if type(fd) is not int or fd < 0:
        _fail("owner layout file descriptor is invalid")
    try:
        value = os.fstat(fd)
    except OSError:
        _fail("owner layout file descriptor is invalid")
    if predicate(value.st_mode) is not True:
        _fail("owner layout file descriptor is invalid")
    return value


def _read_layout_bytes(layout_fd: int, layout_stat: os.stat_result) -> bytes:
    if layout_stat.st_size < 0 or layout_stat.st_size > _MAX_LAYOUT_BYTES:
        _fail("owner layout file descriptor is invalid")
    try:
        payload = os.pread(layout_fd, layout_stat.st_size + 1, 0)
        after = os.fstat(layout_fd)
    except OSError:
        _fail("owner layout file descriptor is invalid")
    if (
        type(payload) is not bytes
        or len(payload) != layout_stat.st_size
        or (after.st_dev, after.st_ino, after.st_mode, after.st_size)
        != (
            layout_stat.st_dev,
            layout_stat.st_ino,
            layout_stat.st_mode,
            layout_stat.st_size,
        )
    ):
        _fail("owner layout file descriptor is invalid")
    return payload


def _validated_release_binding(
    expected_layout_abi: object,
    expected_layout_digest: object,
    release: object,
) -> BrokerReleaseSpec:
    try:
        bound_release = _validate_release_spec(release)
    except RuntimeBoundaryError:
        _fail("owner layout binding is invalid")
    if (
        expected_layout_abi != _LAYOUT_ABI
        or _digest(expected_layout_digest, "owner layout binding is invalid")
        != expected_layout_digest
        or bound_release.owner_layout_abi != expected_layout_abi
        or bound_release.owner_layout_digest != expected_layout_digest
    ):
        _fail("owner layout binding is invalid")
    return bound_release


def load_root_broker_owner_authority_from_open_fds(
    root_dirfd: int,
    layout_fd: int,
    *,
    expected_layout_abi: str,
    expected_layout_digest: str,
    release: BrokerReleaseSpec,
) -> RootBrokerOwnerAuthorityV1:
    """Issue one non-transferable authority from already-opened bound FDs."""

    root_stat = _fd_stat(root_dirfd, stat.S_ISDIR)
    layout_stat = _fd_stat(layout_fd, stat.S_ISREG)
    bound_release = _validated_release_binding(
        expected_layout_abi, expected_layout_digest, release
    )
    payload = _read_layout_bytes(layout_fd, layout_stat)
    layout = RootBrokerOwnerLayoutV1.from_canonical_bytes(payload)
    if (
        root_broker_owner_layout_digest(payload) != expected_layout_digest
        or layout.abi != expected_layout_abi
        or any(entry.release_id != bound_release.release_id for entry in layout.roles)
    ):
        _fail("owner layout binding is invalid")
    authority = object.__new__(RootBrokerOwnerAuthorityV1)
    object.__setattr__(authority, "layout", layout)
    object.__setattr__(authority, "layout_digest", expected_layout_digest)
    object.__setattr__(authority, "release", bound_release)
    object.__setattr__(
        authority,
        "_authority_state",
        _RootBrokerOwnerAuthorityState(
            root_stat.st_dev,
            root_stat.st_ino,
            layout_stat.st_dev,
            layout_stat.st_ino,
            layout_stat.st_size,
        ),
    )
    return authority


__all__ = (
    "FdSelinuxObjectLabelV1",
    "OwnerAuthorityError",
    "RootBrokerOwnerAuthorityV1",
    "RootBrokerOwnerLayoutV1",
    "load_root_broker_owner_authority_from_open_fds",
    "root_broker_owner_layout_digest",
)
