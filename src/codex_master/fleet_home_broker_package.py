"""Root-owned broker package closure verification."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable, Protocol

from .fleet_home_broker_identity import ImportClosure


class PackageVerificationError(ValueError):
    """Raised when a broker package is not an exact trusted closure."""

    __slots__ = ()


_MAX_MODE = 0o7777


def _relative_path(value: object, field: str) -> str:
    if type(value) is not str or not value.strip():
        raise PackageVerificationError(f"{field} must be non-empty text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PackageVerificationError(f"{field} must be UTF-8 text") from exc
    if value != value.strip() or "\x00" in value or "\\" in value:
        raise PackageVerificationError(f"{field} is not canonical")
    if value.startswith("/"):
        raise PackageVerificationError(f"{field} must be relative")
    if len(value) > 1 and value[1] == ":":
        raise PackageVerificationError(f"{field} must not contain a drive")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise PackageVerificationError(f"{field} contains traversal or empty segment")
    return value


def _digest(value: object, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PackageVerificationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _mode(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_MODE:
        raise PackageVerificationError("mode must be an exact file mode")
    return value


@dataclass(frozen=True, slots=True)
class PackageEntry:
    """One package file and its exact trusted metadata."""

    relative_path: str
    sha256: str
    mode: int

    def __post_init__(self) -> None:
        _relative_path(self.relative_path, "relative_path")
        _digest(self.sha256, "sha256")
        _mode(self.mode)


def _validated_entries(entries: object) -> tuple[PackageEntry, ...]:
    try:
        materialized = tuple(entries)  # type: ignore[arg-type]
    except TypeError as exc:
        raise PackageVerificationError("package entries are unclear") from exc
    if not materialized:
        raise PackageVerificationError("package entries must be non-empty")
    if any(type(entry) is not PackageEntry for entry in materialized):
        raise PackageVerificationError("package entry identity is unclear")

    paths = [entry.relative_path for entry in materialized]
    if len(paths) != len(set(paths)):
        raise PackageVerificationError("package entries contain duplicate paths")
    return tuple(sorted(materialized, key=lambda entry: entry.relative_path))


@dataclass(frozen=True, slots=True)
class BrokerPackageManifest:
    """Canonical package manifest with a declared Python import subset."""

    version: int
    entries: tuple[PackageEntry, ...]
    python_imports: ImportClosure

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version < 1:
            raise PackageVerificationError("version must be a positive integer")
        object.__setattr__(self, "entries", _validated_entries(self.entries))
        if type(self.python_imports) is not ImportClosure:
            raise PackageVerificationError("python import subset is unclear")

    def canonical_bytes(self) -> bytes:
        entries = b"".join(
            entry.relative_path.encode("utf-8")
            + b"\0"
            + entry.sha256.encode("ascii")
            + b"\0"
            + oct(entry.mode).encode("ascii")
            + b"\n"
            for entry in self.entries
        )
        return (
            b"broker-package-manifest-v1\n"
            + b"version\0"
            + str(self.version).encode("ascii")
            + b"\n"
            + b"entries\n"
            + entries
            + b"python-imports\n"
            + self.python_imports.canonical_bytes()
        )

    def digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class PackageFileStat:
    """Injected file metadata used for package verification."""

    uid: int
    gid: int
    mode: int
    regular: bool
    link_count: int


class PackageVerifierOperations(Protocol):
    def list_paths(self) -> Iterable[str]: ...

    def lstat(self, relative_path: str) -> PackageFileStat: ...

    def read_bytes(self, relative_path: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class VerifiedPackage:
    """Package manifest after every declared file passed verification."""

    manifest: BrokerPackageManifest


def _fail(message: str, cause: Exception | None = None) -> None:
    if cause is None:
        raise PackageVerificationError(message)
    raise PackageVerificationError(message) from cause


def _validate_import_subset(manifest: BrokerPackageManifest) -> None:
    entries = {entry.relative_path: entry for entry in manifest.entries}
    for import_entry in manifest.python_imports.entries:
        package_entry = entries.get(import_entry.path)
        if package_entry is None:
            _fail("declared Python import is missing from package")
        if package_entry.sha256 != import_entry.digest:
            _fail("declared Python import digest drifted from package")


def _listed_paths(
    operations: PackageVerifierOperations,
) -> tuple[str, ...]:
    try:
        raw_paths = operations.list_paths()
    except Exception as exc:
        _fail("package path listing failed", exc)
    if isinstance(raw_paths, (str, bytes)):
        _fail("package path listing must be an iterable of paths")
    try:
        paths = tuple(raw_paths)
    except Exception as exc:
        _fail("package path listing is invalid", exc)
    try:
        canonical = tuple(_relative_path(path, "listed path") for path in paths)
    except PackageVerificationError:
        raise
    except Exception as exc:
        _fail("package path listing is invalid", exc)
    if len(canonical) != len(set(canonical)):
        _fail("package path listing contains duplicate paths")
    return canonical


def verify_broker_package(
    manifest: BrokerPackageManifest,
    operations: PackageVerifierOperations,
) -> VerifiedPackage:
    """Verify one manifest against only injected package operations."""

    if type(manifest) is not BrokerPackageManifest:
        _fail("manifest has wrong type")
    _validate_import_subset(manifest)

    listed = _listed_paths(operations)
    expected = {entry.relative_path for entry in manifest.entries}
    if set(listed) != expected:
        _fail("package paths do not exactly match manifest")

    for entry in manifest.entries:
        try:
            observed = operations.lstat(entry.relative_path)
        except Exception as exc:
            _fail("package file metadata read failed", exc)
        if type(observed) is not PackageFileStat:
            _fail("package file metadata has wrong type")
        if (
            type(observed.uid) is not int
            or type(observed.gid) is not int
            or type(observed.mode) is not int
            or type(observed.regular) is not bool
            or type(observed.link_count) is not int
        ):
            _fail("package file metadata is invalid")
        if observed.uid != 0 or observed.gid != 0:
            _fail("package file is not root-owned")
        if observed.mode != entry.mode:
            _fail("package file mode drifted")
        if not observed.regular:
            _fail("package file is not regular")
        if observed.link_count != 1:
            _fail("package file link count is not one")

        try:
            content = operations.read_bytes(entry.relative_path)
        except Exception as exc:
            _fail("package file read failed", exc)
        if type(content) is not bytes:
            _fail("package file content has wrong type")
        if sha256(content).hexdigest() != entry.sha256:
            _fail("package file SHA-256 drifted")

    return VerifiedPackage(manifest)


__all__ = [
    "BrokerPackageManifest",
    "PackageEntry",
    "PackageFileStat",
    "PackageVerificationError",
    "PackageVerifierOperations",
    "VerifiedPackage",
    "verify_broker_package",
]
