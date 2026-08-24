"""Declarative PB-S2 broker identity and import-closure binding."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Iterable


class IdentityValidationError(ValueError):
    """Raised when a declarative identity or import closure is invalid."""


MAX_CHPB_AGENT_ID_BYTES = 128
MAX_CHPB_GENERATION = 2**63 - 1
MAX_CHPB_MCS_CATEGORY = 1023

_AGENT = re.compile(r"[a-z][a-z0-9_-]{0,127}\Z", re.ASCII)
_MCS = re.compile(r"c(0|[1-9][0-9]{0,3}),c(0|[1-9][0-9]{0,3})\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


def _nonempty_text(value: object, field: str) -> str:
    if type(value) is not str or not value.strip():
        raise IdentityValidationError(f"{field} must be non-empty text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise IdentityValidationError(f"{field} must be UTF-8 text") from exc
    return value


def _bounded_integer(value: object, field: str, low: int) -> int:
    if type(value) is not int or not low <= value <= MAX_CHPB_GENERATION:
        raise IdentityValidationError(
            f"{field} must be an integer in [{low}, {MAX_CHPB_GENERATION}]"
        )
    return value


def _sha256_digest(value: object, field: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise IdentityValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _agent_id(value: object) -> str:
    if type(value) is not str or len(value.encode("utf-8")) > MAX_CHPB_AGENT_ID_BYTES:
        raise IdentityValidationError("agent_id is outside CHPB/2 bounds")
    if _AGENT.fullmatch(value) is None:
        raise IdentityValidationError("agent_id has invalid CHPB/2 grammar")
    return value


def _mcs_pair(value: object) -> str:
    if type(value) is not str or _MCS.fullmatch(value) is None:
        raise IdentityValidationError("mcs_pair has invalid CHPB/2 grammar")
    low, high = (int(part[1:]) for part in value.split(","))
    if not 0 <= low < high <= MAX_CHPB_MCS_CATEGORY:
        raise IdentityValidationError("mcs_pair categories are outside CHPB/2 bounds")
    return value


@dataclass(frozen=True, slots=True)
class BrokerIdentity:
    """Immutable, statically declared identity of one home broker."""

    agent_id: str
    manifest_generation: int
    mcs_pair: str
    slot_snapshot: str
    policy_generation: int
    projection_digest: str
    executable_fingerprint: str
    fencing_epoch: int

    def __post_init__(self) -> None:
        _agent_id(self.agent_id)
        _bounded_integer(self.manifest_generation, "manifest_generation", 1)
        _mcs_pair(self.mcs_pair)
        _nonempty_text(self.slot_snapshot, "slot_snapshot")
        _bounded_integer(self.policy_generation, "policy_generation", 1)
        _sha256_digest(self.projection_digest, "projection_digest")
        _sha256_digest(self.executable_fingerprint, "executable_fingerprint")
        _bounded_integer(self.fencing_epoch, "fencing_epoch", 0)

    def canonical_bytes(self) -> bytes:
        fields = (
            ("agent_id", self.agent_id),
            ("manifest_generation", str(self.manifest_generation)),
            ("mcs_pair", self.mcs_pair),
            ("slot_snapshot", self.slot_snapshot),
            ("policy_generation", str(self.policy_generation)),
            ("projection_digest", self.projection_digest),
            ("executable_fingerprint", self.executable_fingerprint),
            ("fencing_epoch", str(self.fencing_epoch)),
        )
        return b"broker-identity-v1\n" + b"".join(
            key.encode("ascii")
            + b"\0"
            + value.encode("utf-8")
            + b"\n"
            for key, value in fields
        )

    def digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


def _canonical_relative_path(value: object) -> str:
    path = _nonempty_text(value, "import path")
    if path != path.strip() or "\x00" in path or "\\" in path:
        raise IdentityValidationError("import path is not canonical")
    if PurePosixPath(path).is_absolute() or PureWindowsPath(path).is_absolute():
        raise IdentityValidationError("import path must be relative")
    if PureWindowsPath(path).drive:
        raise IdentityValidationError("import path must not contain a drive")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise IdentityValidationError("import path contains traversal or empty segment")
    return path


@dataclass(frozen=True, slots=True)
class ImportClosureEntry:
    """One canonical relative import path and its content digest."""

    path: str
    digest: str

    def __post_init__(self) -> None:
        _canonical_relative_path(self.path)
        _sha256_digest(self.digest, "import digest")


def _validated_entries(entries: object) -> tuple[ImportClosureEntry, ...]:
    try:
        materialized = tuple(entries)  # type: ignore[arg-type]
    except TypeError as exc:
        raise IdentityValidationError("import closure identity is unclear") from exc
    if not materialized:
        raise IdentityValidationError("import closure must be non-empty")
    if any(type(entry) is not ImportClosureEntry for entry in materialized):
        raise IdentityValidationError("import closure entry identity is unclear")

    paths = [entry.path for entry in materialized]
    if len(paths) != len(set(paths)):
        raise IdentityValidationError("import closure contains duplicate paths")
    return tuple(sorted(materialized, key=lambda entry: entry.path))


@dataclass(frozen=True, slots=True)
class ImportClosure:
    """Sorted, non-empty import closure with a deterministic SHA-256 binding."""

    entries: tuple[ImportClosureEntry, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", _validated_entries(self.entries))

    @classmethod
    def from_entries(cls, entries: Iterable[ImportClosureEntry]) -> "ImportClosure":
        return cls(entries)

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(entry.path for entry in self.entries)

    def canonical_bytes(self) -> bytes:
        return b"import-closure-v1\n" + b"".join(
            entry.path.encode("utf-8")
            + b"\0"
            + entry.digest.encode("ascii")
            + b"\n"
            for entry in self.entries
        )

    def digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


def canonical_import_closure(
    entries: Iterable[ImportClosureEntry],
) -> ImportClosure:
    """Validate and bind a declarative import closure."""

    return ImportClosure.from_entries(entries)


__all__ = [
    "BrokerIdentity",
    "IdentityValidationError",
    "ImportClosure",
    "ImportClosureEntry",
    "canonical_import_closure",
]
