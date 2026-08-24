"""Verify trusted payload before any package import."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
from typing import Any, Iterable, Protocol


PAYLOAD_PARENT = "/usr/lib/codex-master-home-broker"
PAYLOAD_VERSION = "0.10.5"
PAYLOAD_ROOT = "/usr/lib/codex-master-home-broker/0.10.5"
MANIFEST_PATH = "/usr/lib/codex-master-home-broker/manifest-v1.json"
BOOTSTRAP_PATH = "/usr/libexec/codex_master_bootstrap.py"
BROKER_VERIFY_PATH = "/usr/libexec/codex-master-broker-verify"
BROKER_PATH = "/usr/libexec/codex-master-home-broker"
AGENT_PATH = "/usr/libexec/codex-master-agent-launcher"
PYTHON = "/usr/bin/python3"
INERT_EXIT_CODE = 78

_FORMAT = "codex-master-home-broker-manifest-v1"
_FAILURE = "codex-master bootstrap verification failed"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MODES = frozenset((0o644, 0o755))


class BootstrapError(ValueError):
    """Raised for every rejected or failed bootstrap operation."""

    __slots__ = ()


def _fail() -> None:
    raise BootstrapError(_FAILURE) from None


def _validate_payload_path(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        _fail()
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _fail()
    if "\x00" in value or "\\" in value or value.startswith("/"):
        _fail()
    if len(value) > 1 and value[1] == ":":
        _fail()
    if any(part in {"", ".", ".."} for part in value.split("/")):
        _fail()
    if value == "manifest-v1.json":
        _fail()
    return value


def _validate_sha256(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail()
    return value


def _validate_mode(value: object) -> int:
    if type(value) is not int or value not in _MODES:
        _fail()
    return value


@dataclass(frozen=True, slots=True)
class FileStat:
    uid: int
    gid: int
    mode: int
    regular: bool
    link_count: int


@dataclass(frozen=True, slots=True)
class PayloadEntry:
    relative_path: str
    sha256: str
    mode: int

    def __post_init__(self) -> None:
        _validate_payload_path(self.relative_path)
        _validate_sha256(self.sha256)
        _validate_mode(self.mode)


def _strict_payload_entries(entries: object) -> tuple[PayloadEntry, ...]:
    try:
        materialized = tuple(entries)  # type: ignore[arg-type]
    except Exception:
        _fail()
    if not materialized or any(
        type(entry) is not PayloadEntry for entry in materialized
    ):
        _fail()
    paths = tuple(entry.relative_path for entry in materialized)
    if len(paths) != len(set(paths)) or paths != tuple(sorted(paths)):
        _fail()
    return materialized


@dataclass(frozen=True, slots=True)
class VersionedManifest:
    payload_version: str
    payload_entries: tuple[PayloadEntry, ...]

    def __post_init__(self) -> None:
        if (
            type(self.payload_version) is not str
            or self.payload_version != PAYLOAD_VERSION
        ):
            _fail()
        object.__setattr__(
            self, "payload_entries", _strict_payload_entries(self.payload_entries)
        )


@dataclass(frozen=True, slots=True)
class VerifiedPayload:
    payload_root: str
    entries: tuple[PayloadEntry, ...]

    def __post_init__(self) -> None:
        if self.payload_root != PAYLOAD_ROOT:
            _fail()
        object.__setattr__(self, "entries", _strict_payload_entries(self.entries))


class BootstrapOperations(Protocol):
    def read_bytes(self, path: str) -> bytes: ...

    def lstat(self, path: str) -> FileStat: ...

    def list_payload_paths(self, payload_root: str) -> Iterable[str]: ...


class SystemOperations:
    """Small stdlib adapter used by installed wrappers."""

    def read_bytes(self, path: str) -> bytes:
        with open(path, "rb") as stream:
            return stream.read()

    def lstat(self, path: str) -> FileStat:
        observed = os.lstat(path)
        return FileStat(
            observed.st_uid,
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
            stat.S_ISREG(observed.st_mode),
            observed.st_nlink,
        )

    def list_payload_paths(self, payload_root: str) -> Iterable[str]:
        def walk(directory: str, relative_directory: str) -> Iterable[str]:
            with os.scandir(directory) as entries:
                for entry in entries:
                    relative_path = (
                        entry.name
                        if not relative_directory
                        else relative_directory + "/" + entry.name
                    )
                    if entry.is_dir(follow_symlinks=False):
                        yield from walk(entry.path, relative_path)
                    else:
                        yield relative_path

        return walk(payload_root, "")


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    _fail()


def _object(value: object) -> dict[str, object]:
    if type(value) is not dict:
        _fail()
    return value


def _array(value: object) -> list[object]:
    if type(value) is not list:
        _fail()
    return value


def _field(mapping: dict[str, object], name: str) -> object:
    if name not in mapping:
        _fail()
    return mapping[name]


def parse_manifest(manifest_bytes: bytes) -> VersionedManifest:
    try:
        if type(manifest_bytes) is not bytes:
            _fail()
        document = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
        top = _object(document)
        if set(top) != {"format", "payload_version", "payload_entries"}:
            _fail()
        if _field(top, "format") != _FORMAT:
            _fail()
        entries: list[PayloadEntry] = []
        for raw_entry in _array(_field(top, "payload_entries")):
            entry = _object(raw_entry)
            if set(entry) != {"path", "sha256", "mode"}:
                _fail()
            entries.append(
                PayloadEntry(
                    _validate_payload_path(_field(entry, "path")),
                    _validate_sha256(_field(entry, "sha256")),
                    _validate_mode(_field(entry, "mode")),
                )
            )
        return VersionedManifest(_field(top, "payload_version"), tuple(entries))
    except BootstrapError:
        raise
    except Exception:
        _fail()


def _validate_operations(operations: BootstrapOperations) -> None:
    try:
        required = ("read_bytes", "lstat", "list_payload_paths")
        if any(not callable(getattr(operations, name, None)) for name in required):
            _fail()
    except BootstrapError:
        raise
    except Exception:
        _fail()


def _verify_stat(observed: object, mode: int) -> None:
    if type(observed) is not FileStat:
        _fail()
    if (
        type(observed.uid) is not int
        or type(observed.gid) is not int
        or type(observed.mode) is not int
        or type(observed.regular) is not bool
        or type(observed.link_count) is not int
    ):
        _fail()
    if (
        observed.uid != 0
        or observed.gid != 0
        or observed.mode != mode
        or not observed.regular
        or observed.link_count != 1
    ):
        _fail()


def _payload_path(path: str) -> str:
    return PAYLOAD_ROOT + "/" + path


def _verify_payload(
    manifest: VersionedManifest, operations: BootstrapOperations
) -> VerifiedPayload:
    try:
        raw_paths = operations.list_payload_paths(PAYLOAD_ROOT)
        if isinstance(raw_paths, (str, bytes)):
            _fail()
        listed = tuple(_validate_payload_path(path) for path in raw_paths)
        if len(listed) != len(set(listed)):
            _fail()
        if set(listed) != {entry.relative_path for entry in manifest.payload_entries}:
            _fail()
        for entry in manifest.payload_entries:
            path = _payload_path(entry.relative_path)
            _verify_stat(operations.lstat(path), entry.mode)
            content = operations.read_bytes(path)
            if type(content) is not bytes:
                _fail()
            if hashlib.sha256(content).hexdigest() != entry.sha256:
                _fail()
        return VerifiedPayload(PAYLOAD_ROOT, manifest.payload_entries)
    except BootstrapError:
        raise
    except Exception:
        _fail()


def dispatch(mode: str, operations: BootstrapOperations) -> VerifiedPayload:
    try:
        if type(mode) is not str or mode not in {"verify", "broker", "agent"}:
            _fail()
        _validate_operations(operations)
        _verify_stat(operations.lstat(MANIFEST_PATH), 0o644)
        manifest_bytes = operations.read_bytes(MANIFEST_PATH)
        manifest = parse_manifest(manifest_bytes)
        verified = _verify_payload(manifest, operations)
        required_path = {
            "broker": "bin/codex-master-home-broker",
            "agent": "python/codex_master/fleet_agent_launcher.py",
        }.get(mode)
        if required_path is not None and required_path not in {
            entry.relative_path for entry in verified.entries
        }:
            _fail()
        return verified
    except BootstrapError:
        raise
    except Exception:
        _fail()


def run_after_verified(
    mode: str, operations: BootstrapOperations, callback: Any
) -> Any:
    try:
        if not callable(callback):
            _fail()
        return callback(dispatch(mode, operations))
    except BootstrapError:
        raise
    except Exception:
        _fail()


__all__ = [
    "AGENT_PATH",
    "BOOTSTRAP_PATH",
    "BROKER_PATH",
    "BROKER_VERIFY_PATH",
    "BootstrapError",
    "BootstrapOperations",
    "FileStat",
    "INERT_EXIT_CODE",
    "MANIFEST_PATH",
    "PAYLOAD_PARENT",
    "PAYLOAD_ROOT",
    "PAYLOAD_VERSION",
    "PYTHON",
    "PayloadEntry",
    "SystemOperations",
    "VersionedManifest",
    "VerifiedPayload",
    "dispatch",
    "parse_manifest",
    "run_after_verified",
]
