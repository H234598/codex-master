"""Immutable identity and root-TCB contract values."""

from dataclasses import dataclass
from enum import Enum
import re

from .fleet_home_broker_protocol import (
    MAX_CHPB_DEVICE,
    MAX_CHPB_GENERATION,
    MAX_CHPB_INODE,
    PrincipalBinding,
    validate_principal_binding,
)


class BrokerIdentityCode(str, Enum):
    INVALID_TYPE = "invalid_type"
    INVALID_FIELD = "invalid_field"
    WRONG_PRINCIPAL = "wrong_principal"
    STALE_PEER = "stale_peer"
    STALE_GENERATION = "stale_generation"
    FENCED = "fenced"
    INVALID_CAPABILITY_MODEL = "invalid_capability_model"
    INVALID_IMPORT_CLOSURE = "invalid_import_closure"


class BrokerIdentityError(ValueError):
    __slots__ = ("code",)
    code: BrokerIdentityCode

    def __init__(self, code: BrokerIdentityCode):
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class ObjectIdentity:
    dev: int
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int


@dataclass(frozen=True, slots=True)
class BrokerManifestV1:
    agent_id: str
    manifest_generation: int
    policy_generation: int
    projection_digest: str
    executable_fingerprint: str
    mcs_pair: str
    slot: ObjectIdentity
    fencing_epoch: int


@dataclass(frozen=True, slots=True)
class PeerCgroupEvidence:
    pid: int
    cgroup: ObjectIdentity
    invocation_id: str
    unit_name: str
    unit_generation: int
    mcs_pair: str


@dataclass(frozen=True, slots=True)
class BrokerCapabilityModel:
    euid: int
    bounding: tuple[str, ...]
    ambient: tuple[str, ...]
    inheritable: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ImportClosureEntry:
    relative_path: str
    sha256: str
    identity: ObjectIdentity


@dataclass(frozen=True, slots=True)
class ImportClosureManifestV1:
    package_version: str
    package_root: ObjectIdentity
    entries: tuple[ImportClosureEntry, ...]


_AGENT = re.compile(r"[a-z][a-z0-9_-]{0,127}\Z", re.ASCII)
_HEX32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MCS = re.compile(r"c(0|[1-9][0-9]{0,3}),c(0|[1-9][0-9]{0,3})\Z", re.ASCII)
_UNIT = re.compile(r"[A-Za-z0-9_.@:-]{1,255}\Z", re.ASCII)
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z", re.ASCII)
_RELATIVE_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z", re.ASCII)
_DIRECTORY_TYPE = 0o040000
_REGULAR_TYPE = 0o100000
_TYPE_MASK = 0o170000
_NO_GROUP_OTHER_WRITE = 0o0022


def _fail(code: BrokerIdentityCode):
    raise BrokerIdentityError(code)


def _integer(value: object, low: int, high: int) -> int:
    if type(value) is not int:
        _fail(BrokerIdentityCode.INVALID_TYPE)
    if not low <= value <= high:
        _fail(BrokerIdentityCode.INVALID_FIELD)
    return value


def _text(value: object, pattern: re.Pattern[str], limit: int = 4096) -> str:
    if type(value) is not str:
        _fail(BrokerIdentityCode.INVALID_TYPE)
    if len(value.encode("utf-8")) > limit or pattern.fullmatch(value) is None:
        _fail(BrokerIdentityCode.INVALID_FIELD)
    return value


def _digest(value: object) -> str:
    return _text(value, _HEX64, 64)


def _invocation(value: object) -> str:
    return _text(value, _HEX32, 32)


def _mcs(value: object) -> str:
    text = _text(value, _MCS, 16)
    left, right = (int(part[1:]) for part in text.split(","))
    if not 0 <= left < right <= 1023:
        _fail(BrokerIdentityCode.INVALID_FIELD)
    return text


def _object_identity(value: object) -> ObjectIdentity:
    if type(value) is not ObjectIdentity:
        _fail(BrokerIdentityCode.INVALID_TYPE)
    _integer(value.dev, 0, MAX_CHPB_DEVICE)
    _integer(value.ino, 1, MAX_CHPB_INODE)
    _integer(value.mode, 0, 0o177777)
    _integer(value.uid, 0, MAX_CHPB_GENERATION)
    _integer(value.gid, 0, MAX_CHPB_GENERATION)
    _integer(value.nlink, 1, MAX_CHPB_INODE)
    return value


def _root_owned(value: ObjectIdentity) -> ObjectIdentity:
    if value.uid != 0 or value.gid != 0 or value.mode & _NO_GROUP_OTHER_WRITE:
        _fail(BrokerIdentityCode.INVALID_FIELD)
    return value


def _directory_identity(value: ObjectIdentity) -> ObjectIdentity:
    _object_identity(value)
    if value.mode & _TYPE_MASK != _DIRECTORY_TYPE or value.nlink < 2:
        _fail(BrokerIdentityCode.INVALID_FIELD)
    return _root_owned(value)


def _regular_identity(value: ObjectIdentity) -> ObjectIdentity:
    _object_identity(value)
    if value.mode & _TYPE_MASK != _REGULAR_TYPE or value.nlink != 1:
        _fail(BrokerIdentityCode.INVALID_FIELD)
    return _root_owned(value)


def validate_broker_manifest(value: object) -> BrokerManifestV1:
    if type(value) is not BrokerManifestV1:
        _fail(BrokerIdentityCode.INVALID_TYPE)
    _text(value.agent_id, _AGENT, 128)
    _integer(value.manifest_generation, 1, MAX_CHPB_GENERATION)
    _integer(value.policy_generation, 1, MAX_CHPB_GENERATION)
    _digest(value.projection_digest)
    _digest(value.executable_fingerprint)
    _mcs(value.mcs_pair)
    _directory_identity(value.slot)
    _integer(value.fencing_epoch, 0, MAX_CHPB_GENERATION)
    return value


def validate_peer_cgroup_evidence(value: object) -> PeerCgroupEvidence:
    if type(value) is not PeerCgroupEvidence:
        _fail(BrokerIdentityCode.INVALID_TYPE)
    _integer(value.pid, 1, MAX_CHPB_GENERATION)
    _directory_identity(value.cgroup)
    _invocation(value.invocation_id)
    _text(value.unit_name, _UNIT, 255)
    _integer(value.unit_generation, 1, MAX_CHPB_GENERATION)
    _mcs(value.mcs_pair)
    return value


def principal_for_attested_peer(manifest: BrokerManifestV1, peer: PeerCgroupEvidence) -> PrincipalBinding:
    validate_broker_manifest(manifest)
    validate_peer_cgroup_evidence(peer)
    if manifest.mcs_pair != peer.mcs_pair:
        _fail(BrokerIdentityCode.WRONG_PRINCIPAL)
    principal = PrincipalBinding(
        manifest.agent_id,
        manifest.manifest_generation,
        peer.unit_generation,
        peer.cgroup.dev,
        peer.cgroup.ino,
        peer.invocation_id,
        peer.mcs_pair,
        manifest.fencing_epoch,
    )
    try:
        return validate_principal_binding(principal)
    except ValueError:
        _fail(BrokerIdentityCode.INVALID_FIELD)


def validate_empty_capability_model(value: object) -> BrokerCapabilityModel:
    if type(value) is not BrokerCapabilityModel:
        _fail(BrokerIdentityCode.INVALID_TYPE)
    if type(value.euid) is not int or value.euid != 0:
        _fail(BrokerIdentityCode.INVALID_CAPABILITY_MODEL)
    if type(value.bounding) is not tuple or type(value.ambient) is not tuple or type(value.inheritable) is not tuple:
        _fail(BrokerIdentityCode.INVALID_TYPE)
    if value.bounding or value.ambient or value.inheritable:
        _fail(BrokerIdentityCode.INVALID_CAPABILITY_MODEL)
    return value


def _relative_path(value: object) -> str:
    path = _text(value, _RELATIVE_PATH, 4096)
    if any(segment in {".", ".."} for segment in path.split("/")):
        _fail(BrokerIdentityCode.INVALID_IMPORT_CLOSURE)
    return path


def validate_import_closure_manifest(value: object) -> ImportClosureManifestV1:
    if type(value) is not ImportClosureManifestV1:
        _fail(BrokerIdentityCode.INVALID_TYPE)
    _text(value.package_version, _VERSION, 64)
    _directory_identity(value.package_root)
    if type(value.entries) is not tuple or not value.entries:
        _fail(BrokerIdentityCode.INVALID_IMPORT_CLOSURE)
    previous = ""
    for entry in value.entries:
        if type(entry) is not ImportClosureEntry:
            _fail(BrokerIdentityCode.INVALID_TYPE)
        path = _relative_path(entry.relative_path)
        if path <= previous:
            _fail(BrokerIdentityCode.INVALID_IMPORT_CLOSURE)
        previous = path
        _digest(entry.sha256)
        _regular_identity(entry.identity)
    return value
