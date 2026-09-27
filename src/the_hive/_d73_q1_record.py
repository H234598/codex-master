"""Private D339 Q1 record codec and one-shot descriptor decoder.

This module deliberately has no path, cache, resolver, or public factory
surface.  Its names are private to the package; the narrow capability helper
exists so the isolated Q1a tests can exercise the FD boundary directly.
"""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
import stat
import struct
import threading
from typing import Any
import weakref


_MAGIC = b"THD73Q1\0"
_TUPLE_MAGIC = b"THD73T1\0"
_NAMESPACE = b"the-hive.d73.execution-policy"
_HEADER_LENGTH = 300
_MIN_TOTAL_LENGTH = 507
_MAX_TOTAL_LENGTH = 533191
_MIN_LEAF_LENGTH = 49
_MAX_LEAF_LENGTH = 8192
_MIN_TUPLE_LENGTH = 157
_MAX_TUPLE_LENGTH = 411
_MIN_MANIFEST_LENGTH = 1
_MAX_MANIFEST_LENGTH = 524288
_REQUIRED_SEALS = 0x0000000F
_REQUIRED_FD_FLAGS = 0x00000001

_LEAF_LABEL = b"the-hive/d73/q1/leaf/v1"
_MANIFEST_LABEL = b"the-hive/d73/q1/manifest/v1"
_TUPLE_LABEL = b"the-hive/d73/q1/tuple-core/v1"
_DESCRIPTOR_LABEL = b"the-hive/d73/q1/descriptor/v1"
_BINDER_LABEL = b"the-hive/d73/q1/binder/v1"
_GENERATION_LABEL = b"the-hive/d73/q1/generation/v1"


class _Reject(ValueError):
    """One fail-closed result for malformed records and FD evidence."""


@dataclass(frozen=True)
class _DescriptorIdentity:
    uid: int
    gid: int
    device: int
    inode: int
    size: int


@dataclass(frozen=True)
class _FDState:
    file_type: int
    mode: int
    nlink: int
    uid: int
    gid: int
    device: int
    inode: int
    size: int
    seals: int
    fd_flags: int

    def identity(self) -> _DescriptorIdentity:
        return _DescriptorIdentity(
            uid=self.uid,
            gid=self.gid,
            device=self.device,
            inode=self.inode,
            size=self.size,
        )


@dataclass(frozen=True)
class _DecodedRecord:
    commit: bytes
    generation: bytes
    expected_uid: int
    bus_name: bytes
    selinux_context: bytes
    polkit_action: bytes
    manifest: bytes


def _unsigned(value: object, bits: int) -> int:
    if (
        type(bits) is not int
        or bits < 0
        or type(value) is not int
        or value < 0
        or value >= 1 << bits
    ):
        raise _Reject()
    return value


def _bytes(value: object) -> bytes:
    if type(value) is not bytes:
        raise _Reject()
    return value


def _u16(value: object) -> bytes:
    return struct.pack(">H", _unsigned(value, 16))


def _u32(value: object) -> bytes:
    return struct.pack(">I", _unsigned(value, 32))


def _u64(value: object) -> bytes:
    return struct.pack(">Q", _unsigned(value, 64))


def _u16_at(raw: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(raw):
        raise _Reject()
    return struct.unpack_from(">H", raw, offset)[0]


def _u32_at(raw: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(raw):
        raise _Reject()
    return struct.unpack_from(">I", raw, offset)[0]


def _u64_at(raw: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(raw):
        raise _Reject()
    return struct.unpack_from(">Q", raw, offset)[0]


def _exact_ascii(value: bytes, *, minimum: int, maximum: int) -> bytes:
    if not minimum <= len(value) <= maximum or any(
        byte < 0x21 or byte > 0x7E for byte in value
    ):
        raise _Reject()
    return value


def _generation(value: object) -> bytes:
    value_bytes = _exact_ascii(_bytes(value), minimum=1, maximum=255)
    if b"/" in value_bytes or value_bytes in {b".", b".."}:
        raise _Reject()
    return value_bytes


def _bus_name(value: object) -> bytes:
    value_bytes = _exact_ascii(_bytes(value), minimum=1, maximum=255)
    if value_bytes.startswith(b":"):
        raise _Reject()
    return value_bytes


def _selinux_context(value: object) -> bytes:
    value_bytes = _bytes(value)
    if not 1 <= len(value_bytes) <= 4096 or b"\0" in value_bytes:
        raise _Reject()
    return value_bytes


def _polkit_action(value: object) -> bytes:
    return _exact_ascii(_bytes(value), minimum=1, maximum=255)


def _commit(value: object) -> bytes:
    value_bytes = _bytes(value)
    if len(value_bytes) != 40 or any(
        byte not in b"0123456789abcdef" for byte in value_bytes
    ):
        raise _Reject()
    return value_bytes


def _identity(value: object) -> _DescriptorIdentity:
    if not isinstance(value, _DescriptorIdentity):
        raise _Reject()
    return _DescriptorIdentity(
        uid=_unsigned(value.uid, 32),
        gid=_unsigned(value.gid, 32),
        device=_unsigned(value.device, 64),
        inode=_unsigned(value.inode, 64),
        size=_unsigned(value.size, 64),
    )


def _digest(label: bytes, payload: bytes) -> bytes:
    if len(payload) >= 1 << 32:
        raise _Reject()
    return hashlib.sha256(label + b"\0" + _u32(len(payload)) + payload).digest()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _Reject()
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise _Reject()


def _exact_object(value: object, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise _Reject()
    return value


def _hex_text(value: object, length: int) -> str:
    if (
        type(value) is not str
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _Reject()
    return value


def _text(value: object) -> str:
    if type(value) is not str or not value or "\0" in value:
        raise _Reject()
    return value


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _Reject()
    return value


def _validate_manifest_grammar(
    value: object, *, commit: bytes, generation: bytes
) -> None:
    manifest = _exact_object(
        value,
        {
            "schema_version", "commit", "generation", "r2_base",
            "historical_lineage", "successor_witness", "release",
            "directories", "files",
        },
    )
    if _bounded_int(manifest["schema_version"], 2, 2) != 2:
        raise _Reject()
    if _hex_text(manifest["commit"], 40) != commit.decode("ascii"):
        raise _Reject()
    if manifest["generation"] != generation.decode("ascii"):
        raise _Reject()

    r2_base = _exact_object(manifest["r2_base"], {"commit", "tree"})
    _hex_text(r2_base["commit"], 40)
    _hex_text(r2_base["tree"], 40)
    lineage = _exact_object(manifest["historical_lineage"], {"d69", "d73"})
    for name, keys in (
        ("d69", {"commit", "tree", "parent", "dynamic_pool_blob"}),
        ("d73", {"commit", "tree", "parent"}),
    ):
        entry = _exact_object(lineage[name], keys)
        for item in entry.values():
            _hex_text(item, 40)
    witness = _exact_object(manifest["successor_witness"], {"path", "sha256"})
    _text(witness["path"])
    _hex_text(witness["sha256"], 64)

    release = _exact_object(
        manifest["release"],
        {
            "stable_launchers", "hook_abi_source", "hook_abi",
            "hook_abi_companion", "hook_abi_core", "hook_entrypoints",
            "plugin_bundle", "root_install_plan", "python_tree",
            "monitor_entrypoint", "h4_units", "bind_sources",
        },
    )
    array_keys = {"stable_launchers", "hook_entrypoints", "h4_units", "bind_sources"}
    for name, item in release.items():
        if name in array_keys:
            if type(item) is not list:
                raise _Reject()
            for member in item:
                _text(member)
        else:
            _text(item)

    directories = manifest["directories"]
    files = manifest["files"]
    if type(directories) is not dict or type(files) is not dict:
        raise _Reject()
    for name, entry in directories.items():
        _text(name)
        item = _exact_object(entry, {"mode", "nlink"})
        _bounded_int(item["mode"], 0, 0o7777)
        _bounded_int(item["nlink"], 0, (1 << 64) - 1)
    for name, entry in files.items():
        _text(name)
        item = _exact_object(entry, {"mode", "nlink", "size", "sha256"})
        _bounded_int(item["mode"], 0, 0o7777)
        _bounded_int(item["nlink"], 0, (1 << 64) - 1)
        _bounded_int(item["size"], 1, 2 * 1024 * 1024)
        _hex_text(item["sha256"], 64)


def _parse_manifest(raw: object, *, commit: bytes, generation: bytes) -> dict[str, Any]:
    manifest = _bytes(raw)
    if not _MIN_MANIFEST_LENGTH <= len(manifest) <= _MAX_MANIFEST_LENGTH:
        raise _Reject()
    try:
        text = manifest.decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, _Reject) as exc:
        raise _Reject() from exc
    _validate_manifest_grammar(value, commit=commit, generation=generation)
    try:
        canonical = (
            json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise _Reject() from exc
    if canonical != manifest:
        raise _Reject()
    return value


def _leaf(
    *,
    expected_uid: int,
    generation: bytes,
    bus_name: bytes,
    selinux_context: bytes,
    polkit_action: bytes,
) -> bytes:
    result = b"".join(
        (
            _NAMESPACE,
            _u16(1),
            _u16(0),
            _u32(expected_uid),
            _u16(len(generation)),
            generation,
            _u16(len(bus_name)),
            bus_name,
            _u16(len(selinux_context)),
            selinux_context,
            _u16(len(polkit_action)),
            polkit_action,
        )
    )
    if not _MIN_LEAF_LENGTH <= len(result) <= _MAX_LEAF_LENGTH:
        raise _Reject()
    return result


def _header_prefix(
    *,
    total: int,
    commit: bytes,
    descriptor: _DescriptorIdentity,
    leaf_length: int,
    tuple_length: int,
    manifest_length: int,
) -> bytes:
    return b"".join(
        (
            _MAGIC,
            _u16(1),
            _u16(_HEADER_LENGTH),
            _u32(total),
            commit,
            _u32(descriptor.uid),
            _u32(descriptor.gid),
            _u32(0o600),
            _u32(0),
            _u64(descriptor.device),
            _u64(descriptor.inode),
            _u32(leaf_length),
            _u32(tuple_length),
            _u32(manifest_length),
            _u32(_REQUIRED_SEALS),
            _u32(_REQUIRED_FD_FLAGS),
        )
    )


def _tuple(
    *,
    commit: bytes,
    generation: bytes,
    manifest_digest: bytes,
    leaf_digest: bytes,
    binder: bytes,
) -> bytes:
    result = b"".join(
        (
            _TUPLE_MAGIC,
            _u16(1),
            _u16(0),
            _u32(156 + len(generation)),
            commit,
            _u16(len(generation)),
            _u16(0),
            manifest_digest,
            leaf_digest,
            binder,
            generation,
        )
    )
    if not _MIN_TUPLE_LENGTH <= len(result) <= _MAX_TUPLE_LENGTH:
        raise _Reject()
    return result


def _encode_record(
    *,
    commit: object,
    descriptor: object,
    expected_uid: object,
    generation: object,
    bus_name: object,
    selinux_context: object,
    polkit_action: object,
    manifest: object,
) -> bytes:
    """Encode the one D339 layout from already selected, private inputs."""

    commit_bytes = _commit(commit)
    descriptor_identity = _identity(descriptor)
    expected_uid_value = _unsigned(expected_uid, 32)
    generation_bytes = _generation(generation)
    bus_name_bytes = _bus_name(bus_name)
    selinux_context_bytes = _selinux_context(selinux_context)
    polkit_action_bytes = _polkit_action(polkit_action)
    manifest_bytes = _bytes(manifest)
    _parse_manifest(
        manifest_bytes, commit=commit_bytes, generation=generation_bytes
    )
    leaf_bytes = _leaf(
        expected_uid=expected_uid_value,
        generation=generation_bytes,
        bus_name=bus_name_bytes,
        selinux_context=selinux_context_bytes,
        polkit_action=polkit_action_bytes,
    )
    tuple_length = 156 + len(generation_bytes)
    total = _HEADER_LENGTH + len(leaf_bytes) + tuple_length + len(manifest_bytes)
    if not _MIN_TOTAL_LENGTH <= total <= _MAX_TOTAL_LENGTH:
        raise _Reject()
    prefix = _header_prefix(
        total=total,
        commit=commit_bytes,
        descriptor=descriptor_identity,
        leaf_length=len(leaf_bytes),
        tuple_length=tuple_length,
        manifest_length=len(manifest_bytes),
    )
    if len(prefix) != 108:
        raise _Reject()
    leaf_digest = _digest(_LEAF_LABEL, leaf_bytes)
    manifest_digest = _digest(_MANIFEST_LABEL, manifest_bytes)
    descriptor_digest = _digest(_DESCRIPTOR_LABEL, prefix)
    tuple_without_binder = _tuple(
        commit=commit_bytes,
        generation=generation_bytes,
        manifest_digest=manifest_digest,
        leaf_digest=leaf_digest,
        binder=bytes(32),
    )
    tuple_digest = _digest(_TUPLE_LABEL, tuple_without_binder)
    binder = _digest(
        _BINDER_LABEL,
        _NAMESPACE
        + _u16(1)
        + commit_bytes
        + leaf_digest
        + manifest_digest
        + tuple_digest
        + descriptor_digest,
    )
    tuple_bytes = _tuple(
        commit=commit_bytes,
        generation=generation_bytes,
        manifest_digest=manifest_digest,
        leaf_digest=leaf_digest,
        binder=binder,
    )
    generation_digest = _digest(
        _GENERATION_LABEL,
        prefix
        + leaf_digest
        + manifest_digest
        + tuple_digest
        + descriptor_digest
        + binder,
    )
    result = (
        prefix
        + leaf_digest
        + manifest_digest
        + tuple_digest
        + descriptor_digest
        + binder
        + generation_digest
        + leaf_bytes
        + tuple_bytes
        + manifest_bytes
    )
    if len(result) != total:
        raise _Reject()
    return result


def _take_sized(raw: bytes, start: int, end: int) -> tuple[bytes, int]:
    length = _u16_at(raw, start)
    start += 2
    if start + length > end:
        raise _Reject()
    return raw[start : start + length], start + length


def _decode_leaf(raw: bytes) -> tuple[int, bytes, bytes, bytes, bytes]:
    if not _MIN_LEAF_LENGTH <= len(raw) <= _MAX_LEAF_LENGTH:
        raise _Reject()
    if raw[:29] != _NAMESPACE or _u16_at(raw, 29) != 1 or _u16_at(raw, 31) != 0:
        raise _Reject()
    expected_uid = _u32_at(raw, 33)
    cursor = 37
    generation, cursor = _take_sized(raw, cursor, len(raw))
    bus_name, cursor = _take_sized(raw, cursor, len(raw))
    selinux_context, cursor = _take_sized(raw, cursor, len(raw))
    polkit_action, cursor = _take_sized(raw, cursor, len(raw))
    if cursor != len(raw):
        raise _Reject()
    return (
        expected_uid,
        _generation(generation),
        _bus_name(bus_name),
        _selinux_context(selinux_context),
        _polkit_action(polkit_action),
    )


def _decode_tuple(
    raw: bytes,
    *,
    commit: bytes,
    generation: bytes,
    manifest_digest: bytes,
    leaf_digest: bytes,
    binder: bytes,
) -> None:
    if not _MIN_TUPLE_LENGTH <= len(raw) <= _MAX_TUPLE_LENGTH:
        raise _Reject()
    if (
        raw[:8] != _TUPLE_MAGIC
        or _u16_at(raw, 8) != 1
        or _u16_at(raw, 10) != 0
        or _u32_at(raw, 12) != len(raw)
        or len(raw) != 156 + len(generation)
        or raw[16:56] != commit
        or _u16_at(raw, 56) != len(generation)
        or _u16_at(raw, 58) != 0
        or raw[60:92] != manifest_digest
        or raw[92:124] != leaf_digest
        or raw[124:156] != binder
        or raw[156:] != generation
    ):
        raise _Reject()


def _decode_record_bytes(raw: object, descriptor: object) -> _DecodedRecord:
    """Decode one complete record after a caller has supplied FD identity."""

    record = _bytes(raw)
    identity = _identity(descriptor)
    if not _MIN_TOTAL_LENGTH <= len(record) <= _MAX_TOTAL_LENGTH:
        raise _Reject()
    if identity.size != len(record) or len(record) < _HEADER_LENGTH:
        raise _Reject()
    prefix = record[:108]
    if (
        record[:8] != _MAGIC
        or _u16_at(record, 8) != 1
        or _u16_at(record, 10) != _HEADER_LENGTH
        or _u32_at(record, 12) != len(record)
    ):
        raise _Reject()
    commit = _commit(record[16:56])
    if (
        _u32_at(record, 56) != identity.uid
        or _u32_at(record, 60) != identity.gid
        or _u32_at(record, 64) != 0o600
        or _u32_at(record, 68) != 0
        or _u64_at(record, 72) != identity.device
        or _u64_at(record, 80) != identity.inode
        or _u32_at(record, 100) != _REQUIRED_SEALS
        or _u32_at(record, 104) != _REQUIRED_FD_FLAGS
    ):
        raise _Reject()
    leaf_length = _u32_at(record, 88)
    tuple_length = _u32_at(record, 92)
    manifest_length = _u32_at(record, 96)
    if not _MIN_LEAF_LENGTH <= leaf_length <= _MAX_LEAF_LENGTH:
        raise _Reject()
    if not _MIN_TUPLE_LENGTH <= tuple_length <= _MAX_TUPLE_LENGTH:
        raise _Reject()
    if not _MIN_MANIFEST_LENGTH <= manifest_length <= _MAX_MANIFEST_LENGTH:
        raise _Reject()
    if _HEADER_LENGTH + leaf_length + tuple_length + manifest_length != len(record):
        raise _Reject()
    leaf_digest = record[108:140]
    manifest_digest = record[140:172]
    tuple_digest = record[172:204]
    descriptor_digest = record[204:236]
    binder = record[236:268]
    generation_digest = record[268:300]
    if any(len(value) != 32 for value in (
        leaf_digest,
        manifest_digest,
        tuple_digest,
        descriptor_digest,
        binder,
        generation_digest,
    )):
        raise _Reject()
    leaf_start = _HEADER_LENGTH
    tuple_start = leaf_start + leaf_length
    manifest_start = tuple_start + tuple_length
    leaf = record[leaf_start:tuple_start]
    tuple_bytes = record[tuple_start:manifest_start]
    manifest = record[manifest_start:]
    expected_uid, generation, bus_name, selinux_context, polkit_action = _decode_leaf(
        leaf
    )
    _decode_tuple(
        tuple_bytes,
        commit=commit,
        generation=generation,
        manifest_digest=manifest_digest,
        leaf_digest=leaf_digest,
        binder=binder,
    )
    _parse_manifest(manifest, commit=commit, generation=generation)
    if leaf_digest != _digest(_LEAF_LABEL, leaf):
        raise _Reject()
    if manifest_digest != _digest(_MANIFEST_LABEL, manifest):
        raise _Reject()
    tuple_preimage = tuple_bytes[:124] + bytes(32) + tuple_bytes[156:]
    if tuple_digest != _digest(_TUPLE_LABEL, tuple_preimage):
        raise _Reject()
    if descriptor_digest != _digest(_DESCRIPTOR_LABEL, prefix):
        raise _Reject()
    expected_binder = _digest(
        _BINDER_LABEL,
        _NAMESPACE
        + _u16(1)
        + commit
        + leaf_digest
        + manifest_digest
        + tuple_digest
        + descriptor_digest,
    )
    if binder != expected_binder:
        raise _Reject()
    if generation_digest != _digest(
        _GENERATION_LABEL,
        prefix
        + leaf_digest
        + manifest_digest
        + tuple_digest
        + descriptor_digest
        + binder,
    ):
        raise _Reject()
    return _DecodedRecord(
        commit=commit,
        generation=generation,
        expected_uid=expected_uid,
        bus_name=bus_name,
        selinux_context=selinux_context,
        polkit_action=polkit_action,
        manifest=manifest,
    )


def _fd_state(fd: object) -> _FDState:
    descriptor = _unsigned(fd, 31)
    try:
        info = os.fstat(descriptor)
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
        fd_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    except OSError as exc:
        raise _Reject() from exc
    return _FDState(
        file_type=stat.S_IFMT(info.st_mode),
        mode=stat.S_IMODE(info.st_mode),
        nlink=info.st_nlink,
        uid=info.st_uid,
        gid=info.st_gid,
        device=info.st_dev,
        inode=info.st_ino,
        size=info.st_size,
        seals=seals,
        fd_flags=fd_flags,
    )


def _validate_fd_state(state: object) -> _FDState:
    if not isinstance(state, _FDState):
        raise _Reject()
    if (
        state.file_type != stat.S_IFREG
        or state.mode != 0o600
        or state.nlink != 0
        or state.seals != _REQUIRED_SEALS
        or state.fd_flags != _REQUIRED_FD_FLAGS
        or not _MIN_TOTAL_LENGTH <= state.size <= _MAX_TOTAL_LENGTH
    ):
        raise _Reject()
    _identity(state.identity())
    return state


def _pread_exact(fd: int, size: int) -> bytes:
    try:
        payload = os.pread(fd, size, 0)
    except OSError as exc:
        raise _Reject() from exc
    if type(payload) is not bytes or len(payload) != size:
        raise _Reject()
    return payload


_CAPABILITY_TOKEN = object()


class D73Q1Capability:
    """Private linear ownership of exactly one already-open record FD."""

    __slots__ = ("_fd", "_consumed", "_descriptor_key", "__weakref__")

    def __init__(
        self,
        fd: int,
        descriptor_key: tuple[int, int] | None = None,
        *,
        _token: object | None = None,
    ) -> None:
        if _token is not _CAPABILITY_TOKEN:
            raise _Reject()
        if descriptor_key is None:
            raise _Reject()
        self._fd = _unsigned(fd, 31)
        self._consumed = False
        self._descriptor_key = descriptor_key

    def __copy__(self) -> None:
        raise _Reject()

    def __deepcopy__(self, memo: object) -> None:
        del memo
        raise _Reject()

_CAPABILITY_REGISTRY: dict[int, weakref.ReferenceType[D73Q1Capability]] = {}
_ISSUED_DESCRIPTOR_IDENTITIES: set[tuple[int, int]] = set()
_ISSUANCE_LOCK = threading.Lock()


def _descriptor_key(fd: object) -> tuple[int, int]:
    descriptor = _unsigned(fd, 31)
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise _Reject() from exc
    return (_unsigned(info.st_dev, 64), _unsigned(info.st_ino, 64))


def _register_capability(capability: D73Q1Capability) -> None:
    key = id(capability)

    def _discard(reference: weakref.ReferenceType[D73Q1Capability]) -> None:
        if _CAPABILITY_REGISTRY.get(key) is reference:
            del _CAPABILITY_REGISTRY[key]

    _CAPABILITY_REGISTRY[key] = weakref.ref(capability, _discard)


def _take_capability(capability: object) -> int:
    if type(capability) is not D73Q1Capability:
        raise _Reject()
    reference = _CAPABILITY_REGISTRY.pop(id(capability), None)
    if reference is None or reference() is not capability or capability._consumed:
        raise _Reject()
    capability._consumed = True
    fd = capability._fd
    capability._fd = -1
    if _descriptor_key(fd) != capability._descriptor_key:
        raise _Reject()
    return fd


def _capability_from_fd(fd: object) -> D73Q1Capability:
    """Private test/producer seam; it neither opens nor duplicates an FD."""

    descriptor = _unsigned(fd, 31)
    with _ISSUANCE_LOCK:
        key = _descriptor_key(descriptor)
        if key in _ISSUED_DESCRIPTOR_IDENTITIES:
            raise _Reject()
        capability = D73Q1Capability(descriptor, key, _token=_CAPABILITY_TOKEN)
        _ISSUED_DESCRIPTOR_IDENTITIES.add(key)
        _register_capability(capability)
        return capability


def _decode_capability(capability: object) -> _DecodedRecord:
    """Consume and close one FD after two complete, offset-zero readbacks."""

    fd = _take_capability(capability)
    result: _DecodedRecord | None = None
    failure: Exception | None = None
    try:
        state0 = _validate_fd_state(_fd_state(fd))
        first = _pread_exact(fd, state0.size)
        result = _decode_record_bytes(first, state0.identity())
        if _fd_state(fd) != state0:
            raise _Reject()
        second = _pread_exact(fd, state0.size)
        if second != first:
            raise _Reject()
        if _fd_state(fd) != state0:
            raise _Reject()
    except Exception as exc:
        failure = exc
    try:
        os.close(fd)
    except Exception as exc:
        raise _Reject() from exc
    if failure is not None:
        if isinstance(failure, _Reject):
            raise failure
        raise _Reject() from failure
    if result is None:
        raise _Reject()
    return result
