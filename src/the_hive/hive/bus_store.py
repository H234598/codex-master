"""Fail-closed, local Gen-1 persistence for Hive BUS-S1 Slice A."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from threading import RLock
from typing import Final, Literal

from the_hive.diagnostics import (
    DIAGNOSTIC_CODE_SPECS_V2,
    DiagnosticSeverityV2,
    DiagnosticV2,
    diagnostic_for,
)
from the_hive.hive.bus_types import (
    EVENT_TYPE_MATRIX,
    HiveBusContractError,
    HiveBusEventV1,
    MAX_PAYLOAD_BYTES,
    canonical_json_bytes,
    create_hive_bus_event_v1,
    event_id_for_publish_request,
    serialize_hive_bus_event_v1,
    validate_topic_partition,
)
from the_hive.hive.types import Clock, HiveValidationError, validate_identifier


_DATABASE_NAME: Final = "bus_store.sqlite3"
_OWNER_NAME: Final = "bus_store.owner.lock"
_SCHEMA_NAME: Final = "hive_bus_store"
_GENERATION: Final = 2
_MAX_HEADER_BYTES: Final = 4096
_EVENT_ID_RE: Final = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_LEASE_TOKEN_RE: Final = re.compile(r"lease-v1-[A-Za-z0-9_-]{43}\Z", re.ASCII)
_MAX_DELIVERY_HEADERS: Final = 32
_MAX_DELIVERY_HEADER_BYTES: Final = 65536
_MAX_SNAPSHOT_BYTES: Final = 1_048_576
_LEASE_SECONDS: Final = 60
_MAX_SIGNED_SQLITE_INTEGER: Final = (2**63) - 1
_BACKOFF_SECONDS: Final = (5, 15, 60, 300, 900)
_CAPACITY_WARNING_HEADERS: Final = 7_500
_CAPACITY_WARNING_BYTES: Final = 50_331_648
_CAPACITY_HARD_HEADERS: Final = 10_000
_CAPACITY_HARD_BYTES: Final = 67_108_864
_CAPACITY_HARD_EXCEPTIONS: Final = frozenset(
    {
        "authority.revoked",
        "provider.hard_stopped",
        "security.critical",
        "artifact.archived",
    }
)


@dataclass(frozen=True, slots=True)
class DeliveryBatchV1:
    """One bounded, header-only bearer delivery returned by BUS-S1/B."""

    delivery_token: str
    generation: str
    from_seq: int
    scan_through_seq: int
    headers: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class EffectBeginResultV1:
    """The closed durable-effect permission state for one delivered event."""

    state: Literal["apply", "committed", "dead_lettered"]
    attempt_count: int


@dataclass(frozen=True, slots=True)
class CapacityStateV1:
    """Current bounded capacity counters for one partition."""

    header_count: int
    managed_payload_bytes: int
    at_warning_watermark: bool
    at_hard_watermark: bool


@dataclass(frozen=True, slots=True)
class AppendResultV1:
    """One atomically appended event and its post-commit capacity state."""

    event: HiveBusEventV1
    capacity: CapacityStateV1


@dataclass(frozen=True, slots=True)
class DigestAnchorV1:
    """One persisted, header-only digest anchor for a contiguous interval."""

    partition: str
    from_seq: int
    through_seq: int
    event_count: int
    header_bytes: int
    digest: str
    digest_bytes: bytes


@dataclass(frozen=True, slots=True)
class SnapshotAnchorV1:
    """One opaque, immutable S3 snapshot anchor persisted locally by BUS-S1/C."""

    snapshot_id: str
    partition: str
    through_seq: int
    snapshot_digest: str


@dataclass(frozen=True, slots=True)
class CursorGapV1:
    """A leaseless cursor discontinuity that requires one exact snapshot ACK."""

    diagnostic: DiagnosticV2
    snapshot: SnapshotAnchorV1
    gap_from_seq: int
    gap_through_seq: int


@dataclass(frozen=True, slots=True)
class MandatoryWatermarkV1:
    """The opaque, externally-attested retention watermark supplied to C."""

    partition: str
    retention_generation: int
    mandatory_watermark_seq: int
    subscription_generation: str
    attestation_digest: str


@dataclass(frozen=True, slots=True)
class RetentionBasisV1:
    """One replay-safe local retention request basis."""

    run_id: str
    watermark: MandatoryWatermarkV1
    snapshot: SnapshotAnchorV1 | None


@dataclass(frozen=True, slots=True)
class RetentionRunResultV1:
    """The stored result of one atomic local retention run."""

    partition: str
    run_id: str
    retention_generation: int
    compacted_through_seq: int
    first_retained_seq: int
    expired_payload_count: int
    compacted_event_count: int
    snapshot: SnapshotAnchorV1 | None


_GEN1_TABLE_DDL: Final = (
    "CREATE TABLE bus_store_meta (schema_name TEXT PRIMARY KEY CHECK(schema_name='hive_bus_store'),generation INTEGER NOT NULL CHECK(generation>=1),schema_digest TEXT NOT NULL UNIQUE,created_at_utc TEXT NOT NULL)",
    "CREATE TABLE partitions (partition TEXT PRIMARY KEY,next_seq INTEGER NOT NULL CHECK(next_seq>=1),first_retained_seq INTEGER NOT NULL CHECK(first_retained_seq>=1 AND first_retained_seq<=next_seq),state TEXT NOT NULL CHECK(state IN ('active','blocked')),blocked_code TEXT,created_at_utc TEXT NOT NULL,updated_at_utc TEXT NOT NULL)",
    "CREATE TABLE payloads (kind TEXT NOT NULL CHECK(kind IN ('inline','blob','artifact')),digest TEXT NOT NULL,ref TEXT NOT NULL,size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 0 AND 1048576),body BLOB,body_state TEXT NOT NULL CHECK(body_state IN ('present','expired','quarantined','reference')),artifact_id TEXT,quarantine_code TEXT,created_at_utc TEXT NOT NULL,PRIMARY KEY(kind,digest,ref),CHECK((kind IN ('inline','blob') AND body_state='present' AND body IS NOT NULL AND length(body)=size_bytes AND artifact_id IS NULL AND quarantine_code IS NULL) OR (kind='artifact' AND body IS NULL AND body_state='reference' AND artifact_id IS NOT NULL AND quarantine_code IS NULL) OR (body_state IN ('expired','quarantined') AND body IS NULL)))",
    "CREATE TABLE events (event_id TEXT PRIMARY KEY,partition TEXT NOT NULL REFERENCES partitions(partition),partition_seq INTEGER NOT NULL CHECK(partition_seq>=1),schema_version INTEGER NOT NULL,event_type TEXT NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,producer_principal_id TEXT NOT NULL,producer_session_id TEXT NOT NULL,producer_epoch INTEGER NOT NULL,producer_seq INTEGER NOT NULL,repo_id TEXT,topic_id TEXT,workpackage_id TEXT,correlation_id TEXT NOT NULL,causation_ids_bytes BLOB NOT NULL,authority_grant_id TEXT NOT NULL,authority_scope_digest TEXT NOT NULL,authority_principal_version INTEGER NOT NULL,classification TEXT NOT NULL,retention_class TEXT NOT NULL,created_at_utc TEXT NOT NULL,accepted_at_utc TEXT NOT NULL,payload_kind TEXT NOT NULL,payload_digest TEXT NOT NULL,payload_ref TEXT NOT NULL,payload_size_bytes INTEGER NOT NULL CHECK(payload_size_bytes BETWEEN 0 AND 1048576),header_bytes BLOB NOT NULL CHECK(length(header_bytes)<=4096),header_digest TEXT NOT NULL,UNIQUE(partition,partition_seq),UNIQUE(producer_principal_id,producer_epoch,producer_seq),FOREIGN KEY(payload_kind,payload_digest,payload_ref) REFERENCES payloads(kind,digest,ref))",
    "CREATE TABLE producer_epochs (producer_principal_id TEXT NOT NULL,producer_epoch INTEGER NOT NULL,producer_session_id TEXT NOT NULL,last_seq INTEGER NOT NULL CHECK(last_seq>=0),last_event_id TEXT,updated_at_utc TEXT NOT NULL,PRIMARY KEY(producer_principal_id,producer_epoch))",
    "CREATE TABLE idempotency (idempotency_key TEXT PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,canonical_request_digest TEXT NOT NULL,created_at_utc TEXT NOT NULL)",
    "CREATE TABLE subscription_manifests (consumer_group_id TEXT NOT NULL,generation TEXT NOT NULL,manifest_bytes BLOB NOT NULL,manifest_size_bytes INTEGER NOT NULL CHECK(manifest_size_bytes BETWEEN 1 AND 65536 AND length(manifest_bytes)=manifest_size_bytes),created_at_utc TEXT NOT NULL,PRIMARY KEY(consumer_group_id,generation))",
    "CREATE TABLE cursors (consumer_group_id TEXT NOT NULL,partition TEXT NOT NULL,generation TEXT NOT NULL,acked_seq INTEGER NOT NULL CHECK(acked_seq>=0),gap_snapshot_id TEXT,gap_from_seq INTEGER,gap_through_seq INTEGER,updated_at_utc TEXT NOT NULL,PRIMARY KEY(consumer_group_id,partition),FOREIGN KEY(partition) REFERENCES partitions(partition),FOREIGN KEY(consumer_group_id,generation) REFERENCES subscription_manifests(consumer_group_id,generation),CHECK((gap_snapshot_id IS NULL AND gap_from_seq IS NULL AND gap_through_seq IS NULL) OR (gap_snapshot_id IS NOT NULL AND gap_from_seq>=1 AND gap_from_seq<=gap_through_seq)))",
    "CREATE TABLE delivery_leases (consumer_group_id TEXT NOT NULL,partition TEXT NOT NULL,generation TEXT NOT NULL,delivery_token TEXT NOT NULL UNIQUE,from_seq INTEGER NOT NULL,scan_through_seq INTEGER NOT NULL CHECK(from_seq>=1 AND from_seq<=scan_through_seq),leased_at_utc TEXT NOT NULL,expires_at_utc TEXT NOT NULL,created_monotonic REAL NOT NULL,PRIMARY KEY(consumer_group_id,partition),FOREIGN KEY(consumer_group_id,partition) REFERENCES cursors(consumer_group_id,partition),FOREIGN KEY(consumer_group_id,generation) REFERENCES subscription_manifests(consumer_group_id,generation))",
    "CREATE TABLE consumer_effects (consumer_group_id TEXT NOT NULL,event_id TEXT NOT NULL,partition TEXT NOT NULL,partition_seq INTEGER NOT NULL,generation TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','committed','dead_lettered')),effect_digest TEXT,attempt_count INTEGER NOT NULL CHECK(attempt_count BETWEEN 0 AND 5),retry_not_before_utc TEXT,lease_token TEXT,lease_expires_at_utc TEXT,last_error_code TEXT,updated_at_utc TEXT NOT NULL,PRIMARY KEY(consumer_group_id,event_id),FOREIGN KEY(consumer_group_id,partition) REFERENCES cursors(consumer_group_id,partition),FOREIGN KEY(consumer_group_id,generation) REFERENCES subscription_manifests(consumer_group_id,generation))",
    "CREATE TABLE dead_letters (consumer_group_id TEXT NOT NULL,event_id TEXT NOT NULL,partition TEXT NOT NULL,partition_seq INTEGER NOT NULL,generation TEXT NOT NULL,attempt_count INTEGER NOT NULL CHECK(attempt_count=5),error_code TEXT NOT NULL,error_fingerprint TEXT NOT NULL,created_at_utc TEXT NOT NULL,PRIMARY KEY(consumer_group_id,event_id),FOREIGN KEY(consumer_group_id,event_id) REFERENCES consumer_effects(consumer_group_id,event_id))",
    "CREATE TABLE snapshots (snapshot_id TEXT PRIMARY KEY,partition TEXT NOT NULL REFERENCES partitions(partition),through_seq INTEGER NOT NULL CHECK(through_seq>=1),snapshot_digest TEXT NOT NULL UNIQUE,snapshot_bytes BLOB NOT NULL CHECK(length(snapshot_bytes)<=1048576),snapshot_size_bytes INTEGER NOT NULL CHECK(snapshot_size_bytes=length(snapshot_bytes)),created_at_utc TEXT NOT NULL,UNIQUE(partition,through_seq))",
    "CREATE TABLE archive_manifests (archive_manifest_id TEXT PRIMARY KEY,partition TEXT NOT NULL REFERENCES partitions(partition),snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),accepted_event_id TEXT NOT NULL,decision_digest TEXT NOT NULL,manifest_digest TEXT NOT NULL UNIQUE,manifest_bytes BLOB NOT NULL CHECK(length(manifest_bytes)<=1048576),manifest_size_bytes INTEGER NOT NULL CHECK(manifest_size_bytes=length(manifest_bytes)),state TEXT NOT NULL CHECK(state='prepared'),created_at_utc TEXT NOT NULL,UNIQUE(partition,snapshot_id,manifest_digest))",
    "CREATE TABLE outbox (outbox_id TEXT PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,effect_digest TEXT NOT NULL,idempotency_key TEXT NOT NULL,hash_basis_digest TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','leased','acked','blocked')),lease_token TEXT,lease_expires_at_utc TEXT,attempt_count INTEGER NOT NULL CHECK(attempt_count>=0),created_at_utc TEXT NOT NULL,updated_at_utc TEXT NOT NULL)",
)
_GEN1_INDEX_DDL: Final = (
    "CREATE INDEX events_partition_retention_seq_idx ON events(partition,retention_class,partition_seq)",
    "CREATE INDEX events_payload_ref_idx ON events(payload_kind,payload_digest,payload_ref)",
    "CREATE INDEX producer_epochs_principal_epoch_idx ON producer_epochs(producer_principal_id,producer_epoch DESC)",
    "CREATE INDEX delivery_leases_expiry_idx ON delivery_leases(expires_at_utc)",
    "CREATE INDEX consumer_effects_partition_seq_idx ON consumer_effects(consumer_group_id,partition,partition_seq)",
    "CREATE INDEX consumer_effects_retry_idx ON consumer_effects(retry_not_before_utc)",
    "CREATE INDEX dead_letters_partition_seq_idx ON dead_letters(partition,partition_seq)",
    "CREATE INDEX snapshots_partition_through_idx ON snapshots(partition,through_seq DESC)",
    "CREATE INDEX outbox_state_expiry_idx ON outbox(state,lease_expires_at_utc)",
)
_TABLE_DDL: Final = (
    "CREATE TABLE bus_store_meta (schema_name TEXT PRIMARY KEY CHECK(schema_name='hive_bus_store'),generation INTEGER NOT NULL CHECK(generation>=1),schema_digest TEXT NOT NULL UNIQUE,created_at_utc TEXT NOT NULL)",
    "CREATE TABLE partitions (partition TEXT PRIMARY KEY,next_seq INTEGER NOT NULL CHECK(next_seq>=1),first_retained_seq INTEGER NOT NULL CHECK(first_retained_seq>=1 AND first_retained_seq<=next_seq),state TEXT NOT NULL CHECK(state IN ('active','blocked')),blocked_code TEXT,created_at_utc TEXT NOT NULL,updated_at_utc TEXT NOT NULL)",
    "CREATE TABLE payloads (kind TEXT NOT NULL CHECK(kind IN ('inline','blob','artifact')),digest TEXT NOT NULL,ref TEXT NOT NULL,size_bytes INTEGER NOT NULL CHECK((kind='artifact' AND size_bytes BETWEEN 0 AND 9223372036854775807) OR (kind IN ('inline','blob') AND size_bytes BETWEEN 0 AND 1048576)),body BLOB,body_state TEXT NOT NULL CHECK(body_state IN ('present','expired','quarantined','reference')),artifact_id TEXT,quarantine_code TEXT,created_at_utc TEXT NOT NULL,PRIMARY KEY(kind,digest,ref),CHECK((kind IN ('inline','blob') AND body_state='present' AND body IS NOT NULL AND length(body)=size_bytes AND artifact_id IS NULL AND quarantine_code IS NULL) OR (kind='artifact' AND body IS NULL AND body_state='reference' AND artifact_id IS NOT NULL AND quarantine_code IS NULL) OR (body_state IN ('expired','quarantined') AND body IS NULL)))",
    "CREATE TABLE events (event_id TEXT PRIMARY KEY,partition TEXT NOT NULL REFERENCES partitions(partition),partition_seq INTEGER NOT NULL CHECK(partition_seq>=1),schema_version INTEGER NOT NULL,event_type TEXT NOT NULL,idempotency_key TEXT NOT NULL,producer_principal_id TEXT NOT NULL,producer_session_id TEXT NOT NULL,producer_epoch INTEGER NOT NULL,producer_seq INTEGER NOT NULL,repo_id TEXT,topic_id TEXT,workpackage_id TEXT,correlation_id TEXT NOT NULL,causation_ids_bytes BLOB NOT NULL,authority_grant_id TEXT NOT NULL,authority_scope_digest TEXT NOT NULL,authority_principal_version INTEGER NOT NULL,classification TEXT NOT NULL,retention_class TEXT NOT NULL,created_at_utc TEXT NOT NULL,accepted_at_utc TEXT NOT NULL,payload_kind TEXT NOT NULL,payload_digest TEXT NOT NULL,payload_ref TEXT NOT NULL,payload_size_bytes INTEGER NOT NULL CHECK((payload_kind='artifact' AND payload_size_bytes BETWEEN 0 AND 9223372036854775807) OR (payload_kind IN ('inline','blob') AND payload_size_bytes BETWEEN 0 AND 1048576)),header_bytes BLOB NOT NULL CHECK(length(header_bytes)<=4096),header_digest TEXT NOT NULL,UNIQUE(partition,partition_seq),UNIQUE(producer_principal_id,producer_epoch,producer_seq),UNIQUE(producer_principal_id,producer_epoch,idempotency_key),FOREIGN KEY(payload_kind,payload_digest,payload_ref) REFERENCES payloads(kind,digest,ref))",
    "CREATE TABLE producer_epochs (producer_principal_id TEXT NOT NULL,producer_epoch INTEGER NOT NULL,producer_session_id TEXT NOT NULL,last_seq INTEGER NOT NULL CHECK(last_seq>=0),last_event_id TEXT,updated_at_utc TEXT NOT NULL,PRIMARY KEY(producer_principal_id,producer_epoch))",
    "CREATE TABLE idempotency (producer_principal_id TEXT NOT NULL,producer_epoch INTEGER NOT NULL,idempotency_key TEXT NOT NULL,event_id TEXT NOT NULL UNIQUE,canonical_request_digest TEXT NOT NULL,partition_seq INTEGER NOT NULL CHECK(partition_seq>=1),accepted_at_utc TEXT NOT NULL,created_at_utc TEXT NOT NULL,PRIMARY KEY(producer_principal_id,producer_epoch,idempotency_key))",
    "CREATE TABLE subscription_manifests (consumer_group_id TEXT NOT NULL,generation TEXT NOT NULL,manifest_bytes BLOB NOT NULL,manifest_size_bytes INTEGER NOT NULL CHECK(manifest_size_bytes BETWEEN 1 AND 65536 AND length(manifest_bytes)=manifest_size_bytes),created_at_utc TEXT NOT NULL,PRIMARY KEY(consumer_group_id,generation))",
    "CREATE TABLE cursors (consumer_group_id TEXT NOT NULL,partition TEXT NOT NULL,generation TEXT NOT NULL,acked_seq INTEGER NOT NULL CHECK(acked_seq>=0),gap_snapshot_id TEXT,gap_from_seq INTEGER,gap_through_seq INTEGER,updated_at_utc TEXT NOT NULL,PRIMARY KEY(consumer_group_id,partition),FOREIGN KEY(partition) REFERENCES partitions(partition),FOREIGN KEY(consumer_group_id,generation) REFERENCES subscription_manifests(consumer_group_id,generation),CHECK((gap_snapshot_id IS NULL AND gap_from_seq IS NULL AND gap_through_seq IS NULL) OR (gap_snapshot_id IS NOT NULL AND gap_from_seq>=1 AND gap_from_seq<=gap_through_seq)))",
    "CREATE TABLE delivery_leases (consumer_group_id TEXT NOT NULL,partition TEXT NOT NULL,generation TEXT NOT NULL,delivery_token TEXT NOT NULL UNIQUE,from_seq INTEGER NOT NULL,scan_through_seq INTEGER NOT NULL CHECK(from_seq>=1 AND from_seq<=scan_through_seq),leased_at_utc TEXT NOT NULL,expires_at_utc TEXT NOT NULL,created_monotonic REAL NOT NULL,PRIMARY KEY(consumer_group_id,partition),FOREIGN KEY(consumer_group_id,partition) REFERENCES cursors(consumer_group_id,partition),FOREIGN KEY(consumer_group_id,generation) REFERENCES subscription_manifests(consumer_group_id,generation))",
    "CREATE TABLE consumer_effects (consumer_group_id TEXT NOT NULL,event_id TEXT NOT NULL,partition TEXT NOT NULL,partition_seq INTEGER NOT NULL,generation TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','committed','dead_lettered')),effect_digest TEXT,attempt_count INTEGER NOT NULL CHECK(attempt_count BETWEEN 0 AND 5),retry_not_before_utc TEXT,lease_token TEXT,lease_expires_at_utc TEXT,last_error_code TEXT,updated_at_utc TEXT NOT NULL,PRIMARY KEY(consumer_group_id,event_id),FOREIGN KEY(consumer_group_id,partition) REFERENCES cursors(consumer_group_id,partition),FOREIGN KEY(consumer_group_id,generation) REFERENCES subscription_manifests(consumer_group_id,generation))",
    "CREATE TABLE dead_letters (consumer_group_id TEXT NOT NULL,event_id TEXT NOT NULL,partition TEXT NOT NULL,partition_seq INTEGER NOT NULL,generation TEXT NOT NULL,attempt_count INTEGER NOT NULL CHECK(attempt_count=5),error_code TEXT NOT NULL,error_fingerprint TEXT NOT NULL,created_at_utc TEXT NOT NULL,PRIMARY KEY(consumer_group_id,event_id),FOREIGN KEY(consumer_group_id,event_id) REFERENCES consumer_effects(consumer_group_id,event_id))",
    "CREATE TABLE snapshots (snapshot_id TEXT PRIMARY KEY,partition TEXT NOT NULL REFERENCES partitions(partition),through_seq INTEGER NOT NULL CHECK(through_seq>=1),snapshot_digest TEXT NOT NULL UNIQUE,snapshot_bytes BLOB NOT NULL CHECK(length(snapshot_bytes)<=1048576),snapshot_size_bytes INTEGER NOT NULL CHECK(snapshot_size_bytes=length(snapshot_bytes)),created_at_utc TEXT NOT NULL,UNIQUE(partition,through_seq))",
    "CREATE TABLE archive_manifests (archive_manifest_id TEXT PRIMARY KEY,partition TEXT NOT NULL REFERENCES partitions(partition),snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),accepted_event_id TEXT NOT NULL,decision_digest TEXT NOT NULL,manifest_digest TEXT NOT NULL UNIQUE,manifest_bytes BLOB NOT NULL CHECK(length(manifest_bytes)<=1048576),manifest_size_bytes INTEGER NOT NULL CHECK(manifest_size_bytes=length(manifest_bytes)),state TEXT NOT NULL CHECK(state='prepared'),created_at_utc TEXT NOT NULL,UNIQUE(partition,snapshot_id,manifest_digest))",
    "CREATE TABLE outbox (outbox_id TEXT PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,effect_digest TEXT NOT NULL,idempotency_key TEXT NOT NULL,hash_basis_digest TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','leased','acked','blocked')),lease_token TEXT,lease_expires_at_utc TEXT,attempt_count INTEGER NOT NULL CHECK(attempt_count>=0),created_at_utc TEXT NOT NULL,updated_at_utc TEXT NOT NULL)",
    "CREATE TABLE digest_anchors (partition TEXT NOT NULL REFERENCES partitions(partition),from_seq INTEGER NOT NULL CHECK(from_seq>=1),through_seq INTEGER NOT NULL CHECK(through_seq>=from_seq),event_count INTEGER NOT NULL CHECK(event_count BETWEEN 1 AND 32),header_bytes INTEGER NOT NULL CHECK(header_bytes BETWEEN 1 AND 69632),digest TEXT NOT NULL UNIQUE,digest_bytes BLOB NOT NULL CHECK(length(digest_bytes)<=65536),digest_size_bytes INTEGER NOT NULL CHECK(digest_size_bytes=length(digest_bytes)),created_at_utc TEXT NOT NULL,PRIMARY KEY(partition,through_seq),UNIQUE(partition,from_seq))",
    "CREATE TABLE retention_policies (retention_generation INTEGER PRIMARY KEY CHECK(retention_generation>=1),policy_digest TEXT NOT NULL UNIQUE,policy_bytes BLOB NOT NULL CHECK(length(policy_bytes)<=4096),created_at_utc TEXT NOT NULL)",
    "CREATE TABLE retention_checkpoints (partition TEXT NOT NULL REFERENCES partitions(partition),run_id TEXT NOT NULL,request_digest TEXT NOT NULL,retention_generation INTEGER NOT NULL REFERENCES retention_policies(retention_generation),basis_digest TEXT NOT NULL,snapshot_id TEXT REFERENCES snapshots(snapshot_id),compacted_through_seq INTEGER NOT NULL CHECK(compacted_through_seq>=0),first_retained_seq INTEGER NOT NULL CHECK(first_retained_seq>=1),expired_payload_count INTEGER NOT NULL CHECK(expired_payload_count>=0),compacted_event_count INTEGER NOT NULL CHECK(compacted_event_count>=0),completed_at_utc TEXT NOT NULL,PRIMARY KEY(partition,run_id),UNIQUE(partition,request_digest))",
)
_INDEX_DDL: Final = (
    "CREATE INDEX events_partition_retention_accepted_seq_idx ON events(partition,retention_class,accepted_at_utc,partition_seq)",
    "CREATE INDEX events_payload_ref_idx ON events(payload_kind,payload_digest,payload_ref)",
    "CREATE INDEX producer_epochs_principal_epoch_idx ON producer_epochs(producer_principal_id,producer_epoch DESC)",
    "CREATE INDEX cursors_partition_acked_seq_idx ON cursors(partition,acked_seq)",
    "CREATE INDEX delivery_leases_expiry_idx ON delivery_leases(expires_at_utc)",
    "CREATE INDEX consumer_effects_partition_seq_idx ON consumer_effects(consumer_group_id,partition,partition_seq)",
    "CREATE INDEX consumer_effects_retry_idx ON consumer_effects(retry_not_before_utc)",
    "CREATE INDEX dead_letters_partition_seq_idx ON dead_letters(partition,partition_seq)",
    "CREATE INDEX snapshots_partition_through_idx ON snapshots(partition,through_seq DESC)",
    "CREATE INDEX outbox_state_expiry_idx ON outbox(state,lease_expires_at_utc)",
)
_SCHEMA_MANIFEST: Final = {
    "schema_name": _SCHEMA_NAME,
    "generation": _GENERATION,
    "tables": list(_TABLE_DDL),
    "indexes": list(_INDEX_DDL),
    "pragmas": {
        "foreign_keys": 1,
        "journal_mode": "wal",
        "synchronous": "FULL",
        "busy_timeout": 5000,
        "wal_autocheckpoint": 1000,
    },
}
_SCHEMA_DIGEST: Final = (
    "sha256:1554a2ab9908b11262b238fb2906ec2c43b81f7fdf99f120546d415e4b462e11"
)
_GEN1_SCHEMA_DIGEST: Final = (
    "sha256:577d018653c16b9bf92590c1e68931f2ec972ad84a7e35c6f644f4f08aa508ba"
)
_GEN1_RETENTION_POLICY: Final = {
    "schema_version": 1,
    "retention_generation": 1,
    "classes": {
        "transient": {
            "header_retention_seconds": 86400,
            "payload_retention_seconds": 21600,
        },
        "work": {
            "header_retention_seconds": 2592000,
            "payload_retention_seconds": 604800,
        },
        "audit": {
            "header_retention_seconds": 31536000,
            "payload_retention_seconds": 2592000,
        },
        "manifest": {
            "header_retention_seconds": None,
            "payload_retention_seconds": None,
        },
    },
}
_GEN1_RETENTION_POLICY_DIGEST: Final = (
    "sha256:33dc6401f637e0dd7552a606266771f6cdfe5393f9d87d59353957a711324e8f"
)
_GEN1_PERSISTED_PRAGMAS: Final = (("journal_mode", ("wal",)),)
_NFS_SUPER_MAGIC: Final = 0x6969
_SMB_SUPER_MAGIC: Final = 0x517B
_CIFS_SUPER_MAGIC: Final = 0xFF534D42


class _LinuxStatFs(ctypes.Structure):
    _fields_ = [
        ("f_type", ctypes.c_long),
        ("f_bsize", ctypes.c_long),
        ("f_blocks", ctypes.c_ulong),
        ("f_bfree", ctypes.c_ulong),
        ("f_bavail", ctypes.c_ulong),
        ("f_files", ctypes.c_ulong),
        ("f_ffree", ctypes.c_ulong),
        ("f_fsid", ctypes.c_int * 2),
        ("f_namelen", ctypes.c_long),
        ("f_frsize", ctypes.c_long),
        ("f_flags", ctypes.c_long),
        ("f_spare", ctypes.c_long * 4),
    ]


_FSTATFS = ctypes.CDLL(None, use_errno=True).fstatfs
_FSTATFS.argtypes = [ctypes.c_int, ctypes.POINTER(_LinuxStatFs)]
_FSTATFS.restype = ctypes.c_int


def _utc_datetime(clock: Clock) -> datetime:
    value = clock.wall_time_utc()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError
    return value.astimezone(timezone.utc)


def _format_utc(utc: datetime) -> str:
    result = utc.strftime("%Y-%m-%dT%H:%M:%S")
    if utc.microsecond:
        result += "." + f"{utc.microsecond:06d}".rstrip("0")
    return result + "Z"


def _utc_now(clock: Clock) -> str:
    return _format_utc(_utc_datetime(clock))


def _stored_utc(value: object) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ValueError
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ValueError from None
    if parsed.tzinfo is None or _format_utc(parsed.astimezone(timezone.utc)) != value:
        raise ValueError
    return parsed.astimezone(timezone.utc)


def _migration_checkpoint(_stage: str) -> None:
    """Private fault-injection seam; production execution has no side effect."""


def _append_checkpoint(_stage: str) -> None:
    """Private fault-injection seam; production execution has no side effect."""


def _retention_checkpoint(_stage: str) -> None:
    """Private fault-injection seam; production execution has no side effect."""


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _sqlite_is_busy(error: sqlite3.OperationalError) -> bool:
    return getattr(error, "sqlite_errorcode", None) in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }


def _filesystem_type(descriptor: int) -> int | None:
    info = _LinuxStatFs()
    if _FSTATFS(descriptor, ctypes.byref(info)) != 0:
        return None
    return info.f_type & 0xFFFFFFFF


def _is_local_filesystem(descriptor: int) -> bool:
    filesystem_type = _filesystem_type(descriptor)
    return filesystem_type not in {
        None,
        _NFS_SUPER_MAGIC,
        _SMB_SUPER_MAGIC,
        _CIFS_SUPER_MAGIC,
    }


def _is_trusted_directory(info: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700
    )


def _is_trusted_file(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
    )


def _ancestors_are_trusted(parent: Path) -> bool:
    current = parent
    while True:
        try:
            info = current.lstat()
        except OSError:
            return False
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            return False
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022:
            return False
        if current.parent == current:
            return True
        current = current.parent


class HiveBusStore:
    """The sole public BUS-S1 store, with one locally-owned SQLite connection."""

    @classmethod
    def initialize(
        cls, state_root: Path, *, clock: Clock
    ) -> HiveBusStore | DiagnosticV2:
        """Create only a missing final private root and initialize or verify Gen-2."""

        return cls._open_store(state_root, clock=clock, create=True)

    @classmethod
    def open(cls, state_root: Path, *, clock: Clock) -> HiveBusStore | DiagnosticV2:
        """Open an existing complete Gen-2 store without creating any filesystem node."""

        return cls._open_store(state_root, clock=clock, create=False)

    @classmethod
    def _open_store(
        cls, state_root: Path, *, clock: Clock, create: bool
    ) -> HiveBusStore | DiagnosticV2:
        if not isinstance(state_root, Path) or not state_root.is_absolute():
            return diagnostic_for(
                "BUS_E_STORE_ROOT_UNTRUSTED",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        root_fd: int | None = None
        owner_fd: int | None = None
        connection: sqlite3.Connection | None = None
        try:
            try:
                root_fd = cls._open_root(state_root, create=create)
            except (OSError, ValueError):
                return diagnostic_for(
                    "BUS_E_STORE_ROOT_UNTRUSTED",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            try:
                owner_fd = cls._open_owner(root_fd, create=create)
            except BlockingIOError:
                return diagnostic_for(
                    "BUS_E_STORE_OWNER_ACTIVE",
                    severity=DiagnosticSeverityV2.WARNING,
                    retryable=True,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="retry_open",
                    causes=(),
                )
            except (OSError, ValueError):
                return diagnostic_for(
                    "BUS_E_STORE_FILE_UNTRUSTED",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            database = state_root / _DATABASE_NAME
            auxiliary_before = {
                suffix: cls._existing_file(state_root / f"{_DATABASE_NAME}{suffix}")
                for suffix in ("-wal", "-shm")
            }
            if not create and any(info is None for info in auxiliary_before.values()):
                return diagnostic_for(
                    "BUS_E_STORE_FILE_UNTRUSTED",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            if any(
                info is not None and not _is_trusted_file(info)
                for info in auxiliary_before.values()
            ):
                return diagnostic_for(
                    "BUS_E_STORE_FILE_UNTRUSTED",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            existed = cls._existing_file(database)
            if existed is None and not create:
                return diagnostic_for(
                    "BUS_E_STORE_FILE_UNTRUSTED",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            if existed is not None and not _is_trusted_file(existed):
                return diagnostic_for(
                    "BUS_E_STORE_FILE_UNTRUSTED",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            connection = sqlite3.connect(
                database,
                isolation_level=None,
                check_same_thread=False,
            )
            if existed is None:
                os.chmod(database, 0o600)
            if not _is_trusted_file(os.lstat(database)):
                return diagnostic_for(
                    "BUS_E_STORE_FILE_UNTRUSTED",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            schema_result = cls._initialize_or_validate_schema(
                connection,
                create_schema=create and existed is None,
                clock=clock,
            )
            if schema_result is not None:
                return schema_result
            cls._validate_auxiliary_files(
                state_root,
                new_suffixes=frozenset(
                    suffix for suffix, info in auxiliary_before.items() if info is None
                ),
            )
            store = object.__new__(cls)
            store._connection = connection
            store._owner_fd = owner_fd
            store._root = state_root
            store._root_identity = _identity(os.fstat(root_fd))
            store._clock = clock
            store._lock = RLock()
            store._closed = False
            connection = None
            owner_fd = None
            return store
        except FileExistsError:
            return diagnostic_for(
                "BUS_E_STORE_FILE_UNTRUSTED",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        except BlockingIOError:
            return diagnostic_for(
                "BUS_E_STORE_OWNER_ACTIVE",
                severity=DiagnosticSeverityV2.WARNING,
                retryable=True,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="retry_open",
                causes=(),
            )
        except sqlite3.OperationalError as exc:
            if _sqlite_is_busy(exc):
                return diagnostic_for(
                    "BUS_E_STORE_BUSY",
                    severity=DiagnosticSeverityV2.WARNING,
                    retryable=True,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="retry_operation",
                    causes=(),
                )
            return diagnostic_for(
                "BUS_E_STORE_INTEGRITY",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        except (OSError, ValueError, sqlite3.DatabaseError):
            return diagnostic_for(
                "BUS_E_STORE_INTEGRITY",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        finally:
            if connection is not None:
                connection.close()
            if owner_fd is not None:
                os.close(owner_fd)
            if root_fd is not None:
                os.close(root_fd)

    @staticmethod
    def _existing_file(path: Path) -> os.stat_result | None:
        try:
            return path.lstat()
        except FileNotFoundError:
            return None

    @staticmethod
    def _open_root(state_root: Path, *, create: bool) -> int:
        if not _ancestors_are_trusted(state_root.parent):
            raise ValueError
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            parent_fd = os.open(state_root.parent, flags)
        except OSError as exc:
            raise ValueError from exc
        try:
            if not _is_local_filesystem(parent_fd):
                raise ValueError
            try:
                info = os.stat(state_root.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise ValueError
                os.mkdir(state_root.name, 0o700, dir_fd=parent_fd)
                created = True
            else:
                created = False
                if not _is_trusted_directory(info):
                    raise ValueError
            root_fd = os.open(state_root.name, flags, dir_fd=parent_fd)
            try:
                if created:
                    os.fchmod(root_fd, 0o700)
                if not _is_local_filesystem(root_fd) or not _is_trusted_directory(
                    os.fstat(root_fd)
                ):
                    raise ValueError
                return root_fd
            except Exception:
                os.close(root_fd)
                raise
        finally:
            os.close(parent_fd)

    @staticmethod
    def _open_owner(root_fd: int, *, create: bool) -> int:
        try:
            existing = os.stat(_OWNER_NAME, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not _is_trusted_file(existing):
            raise ValueError
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        created = False
        if existing is None:
            if not create:
                raise ValueError
            try:
                fd = os.open(
                    _OWNER_NAME, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root_fd
                )
                created = True
            except FileExistsError:
                existing = os.stat(_OWNER_NAME, dir_fd=root_fd, follow_symlinks=False)
                if not _is_trusted_file(existing):
                    raise ValueError
                fd = os.open(_OWNER_NAME, flags, dir_fd=root_fd)
        else:
            fd = os.open(_OWNER_NAME, flags, dir_fd=root_fd)
        try:
            if created:
                os.fchmod(fd, 0o600)
            opened = os.fstat(fd)
            if not _is_trusted_file(opened):
                raise ValueError
            if existing is not None and _identity(existing) != _identity(opened):
                raise ValueError
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def _configure(connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA foreign_keys=ON")
        if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
            raise sqlite3.DatabaseError
        if connection.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
            raise sqlite3.DatabaseError
        connection.execute("PRAGMA synchronous=FULL")
        if connection.execute("PRAGMA synchronous").fetchone() != (2,):
            raise sqlite3.DatabaseError
        if connection.execute("PRAGMA busy_timeout=5000").fetchone() != (5000,):
            raise sqlite3.DatabaseError
        if connection.execute("PRAGMA wal_autocheckpoint=1000").fetchone() != (1000,):
            raise sqlite3.DatabaseError

    @staticmethod
    def _validate_auxiliary_files(
        root: Path, *, new_suffixes: frozenset[str] = frozenset()
    ) -> None:
        for suffix in ("-wal", "-shm"):
            path = root / f"{_DATABASE_NAME}{suffix}"
            info = HiveBusStore._existing_file(path)
            if info is None:
                continue
            if not _is_trusted_file(info):
                if (
                    suffix in new_suffixes
                    and stat.S_ISREG(info.st_mode)
                    and info.st_uid == os.geteuid()
                    and info.st_nlink == 1
                ):
                    os.chmod(path, 0o600)
                    info = os.lstat(path)
                if not _is_trusted_file(info):
                    raise ValueError

    @staticmethod
    def _initialize_or_validate_schema(
        connection: sqlite3.Connection, *, create_schema: bool, clock: Clock
    ) -> DiagnosticV2 | None:
        entries = connection.execute(
            "SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
        if not entries:
            if not create_schema:
                return diagnostic_for(
                    "BUS_E_STORE_SCHEMA_UNKNOWN",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            HiveBusStore._configure(connection)
            try:
                connection.execute("BEGIN IMMEDIATE")
                for statement in _TABLE_DDL:
                    connection.execute(statement)
                for statement in _INDEX_DDL:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO bus_store_meta(schema_name,generation,schema_digest,created_at_utc) VALUES(?,?,?,?)",
                    (_SCHEMA_NAME, _GENERATION, _SCHEMA_DIGEST, _utc_now(clock)),
                )
                connection.execute("COMMIT")
            except Exception:
                HiveBusStore._rollback(connection)
                raise
            return HiveBusStore._validate_schema(connection)
        if HiveBusStore._schema_surface_matches(connection, _TABLE_DDL, _INDEX_DDL):
            HiveBusStore._configure(connection)
            return HiveBusStore._validate_schema(connection)
        if HiveBusStore._schema_surface_matches(
            connection, _GEN1_TABLE_DDL, _GEN1_INDEX_DDL
        ):
            # SQLite does not persist foreign_keys across connections.  Enable it
            # only as the operational enforcement required for source checks;
            # all other manifest values remain observable before Gen-2 setup.
            connection.execute("PRAGMA foreign_keys=ON")
            if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
                return diagnostic_for(
                    "BUS_E_STORE_SCHEMA_UNKNOWN",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            source_error = HiveBusStore._validate_gen1_source(connection)
            if source_error is not None:
                return source_error
            HiveBusStore._configure(connection)
            HiveBusStore._migrate_gen1(connection, clock=clock)
            HiveBusStore._configure(connection)
            return HiveBusStore._validate_schema(connection)
        generation = HiveBusStore._declared_generation(connection)
        if generation is not None and generation > _GENERATION:
            return diagnostic_for(
                "BUS_E_STORE_SCHEMA_TOO_NEW",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        return diagnostic_for(
            "BUS_E_STORE_SCHEMA_UNKNOWN",
            severity=DiagnosticSeverityV2.CRITICAL,
            retryable=False,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="operator_intervention",
            causes=(),
        )

    @staticmethod
    def _schema_surface_matches(
        connection: sqlite3.Connection,
        tables: tuple[str, ...],
        indexes: tuple[str, ...],
    ) -> bool:
        expected_tables = {statement.split()[2]: statement for statement in tables}
        expected_indexes = {statement.split()[2]: statement for statement in indexes}
        entries = connection.execute(
            "SELECT type,name,sql FROM sqlite_schema"
        ).fetchall()
        explicit_entries = [
            (kind, name, sql)
            for kind, name, sql in entries
            if not name.startswith("sqlite_")
        ]
        actual_tables = {
            name: sql for kind, name, sql in explicit_entries if kind == "table"
        }
        actual_indexes = {
            name: sql for kind, name, sql in explicit_entries if kind == "index"
        }
        return (
            set(actual_tables) == set(expected_tables)
            and set(actual_indexes) == set(expected_indexes)
            and all(
                actual_tables[name] == statement
                for name, statement in expected_tables.items()
            )
            and all(
                actual_indexes[name] == statement
                for name, statement in expected_indexes.items()
            )
            and all(
                kind in {"table", "index"} for kind, _name, _sql in explicit_entries
            )
        )

    @staticmethod
    def _declared_generation(connection: sqlite3.Connection) -> int | None:
        try:
            rows = connection.execute(
                "SELECT generation FROM bus_store_meta"
            ).fetchall()
        except sqlite3.DatabaseError:
            return None
        if len(rows) != 1 or type(rows[0][0]) is not int:
            return None
        return rows[0][0]

    @staticmethod
    def _validate_gen1_source(connection: sqlite3.Connection) -> DiagnosticV2 | None:
        rows = connection.execute(
            "SELECT schema_name,generation,schema_digest FROM bus_store_meta"
        ).fetchall()
        if rows != [(_SCHEMA_NAME, 1, _GEN1_SCHEMA_DIGEST)]:
            return diagnostic_for(
                "BUS_E_STORE_SCHEMA_UNKNOWN",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        for pragma, expected in _GEN1_PERSISTED_PRAGMAS:
            if connection.execute(f"PRAGMA {pragma}").fetchone() != expected:
                return diagnostic_for(
                    "BUS_E_STORE_SCHEMA_UNKNOWN",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            return HiveBusStore._store_integrity()
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            return HiveBusStore._store_integrity()
        return None

    @staticmethod
    def _migrate_gen1(connection: sqlite3.Connection, *, clock: Clock) -> None:
        """Replace only an exact Gen-1 source in one immediate transaction."""

        policy_bytes = canonical_json_bytes(_GEN1_RETENTION_POLICY)
        if (
            len(policy_bytes) != 377
            or _digest(policy_bytes) != _GEN1_RETENTION_POLICY_DIGEST
        ):
            raise sqlite3.DatabaseError
        connection.execute("PRAGMA foreign_keys=OFF")
        if connection.execute("PRAGMA foreign_keys").fetchone() != (0,):
            raise sqlite3.DatabaseError
        connection.execute("BEGIN IMMEDIATE")
        _migration_checkpoint("before_rename")
        try:
            source_names = tuple(statement.split()[2] for statement in _GEN1_TABLE_DDL)
            for name in source_names:
                connection.execute(f"ALTER TABLE {name} RENAME TO legacy_g1_{name}")
            for statement in _GEN1_INDEX_DDL:
                connection.execute(f"DROP INDEX {statement.split()[2]}")
            _migration_checkpoint("after_rename_indexdrop")
            for statement in _TABLE_DDL:
                connection.execute(statement)
            for statement in _INDEX_DDL:
                connection.execute(statement)
            for name in source_names:
                if name not in {"bus_store_meta", "idempotency"}:
                    connection.execute(
                        f"INSERT INTO {name} SELECT * FROM legacy_g1_{name}"
                    )
            connection.execute(
                "INSERT INTO idempotency(producer_principal_id,producer_epoch,idempotency_key,event_id,canonical_request_digest,partition_seq,accepted_at_utc,created_at_utc) SELECT events.producer_principal_id,events.producer_epoch,legacy.idempotency_key,legacy.event_id,legacy.canonical_request_digest,events.partition_seq,events.accepted_at_utc,legacy.created_at_utc FROM legacy_g1_idempotency AS legacy JOIN legacy_g1_events AS events ON events.event_id=legacy.event_id"
            )
            connection.execute(
                "INSERT INTO retention_policies(retention_generation,policy_digest,policy_bytes,created_at_utc) VALUES(?,?,?,?)",
                (1, _GEN1_RETENTION_POLICY_DIGEST, policy_bytes, _utc_now(clock)),
            )
            HiveBusStore._validate_migration_copy(connection, source_names)
            _migration_checkpoint("after_copy")
            for name in reversed(source_names):
                connection.execute(f"DROP TABLE legacy_g1_{name}")
            connection.execute(
                "INSERT INTO bus_store_meta(schema_name,generation,schema_digest,created_at_utc) VALUES(?,?,?,?)",
                (_SCHEMA_NAME, _GENERATION, _SCHEMA_DIGEST, _utc_now(clock)),
            )
            if HiveBusStore._validate_schema(connection) is not None:
                raise sqlite3.DatabaseError
            _migration_checkpoint("after_final_validation_before_commit")
            connection.execute("COMMIT")
        except Exception:
            HiveBusStore._rollback(connection)
            raise
        _migration_checkpoint("after_commit")

    @staticmethod
    def _validate_migration_copy(
        connection: sqlite3.Connection, source_names: tuple[str, ...]
    ) -> None:
        for name in source_names:
            if name in {"bus_store_meta", "idempotency"}:
                continue
            source_count = connection.execute(
                f"SELECT COUNT(*) FROM legacy_g1_{name}"
            ).fetchone()
            target_count = connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()
            if source_count != target_count:
                raise sqlite3.DatabaseError
        source_count = connection.execute(
            "SELECT COUNT(*) FROM legacy_g1_idempotency"
        ).fetchone()
        joined_count = connection.execute(
            "SELECT COUNT(*) FROM legacy_g1_idempotency AS legacy JOIN legacy_g1_events AS events ON events.event_id=legacy.event_id"
        ).fetchone()
        target_count = connection.execute("SELECT COUNT(*) FROM idempotency").fetchone()
        if source_count != joined_count or source_count != target_count:
            raise sqlite3.DatabaseError
        verified_count = connection.execute(
            "SELECT COUNT(*) FROM idempotency AS target JOIN legacy_g1_idempotency AS legacy ON legacy.event_id=target.event_id JOIN legacy_g1_events AS events ON events.event_id=legacy.event_id WHERE target.producer_principal_id=events.producer_principal_id AND target.producer_epoch=events.producer_epoch AND target.idempotency_key=legacy.idempotency_key AND target.canonical_request_digest=legacy.canonical_request_digest AND target.partition_seq=events.partition_seq AND target.accepted_at_utc=events.accepted_at_utc AND target.created_at_utc=legacy.created_at_utc"
        ).fetchone()
        if verified_count != source_count:
            raise sqlite3.DatabaseError
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise sqlite3.DatabaseError
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise sqlite3.DatabaseError

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> DiagnosticV2 | None:
        expected_tables = {statement.split()[2]: statement for statement in _TABLE_DDL}
        expected_indexes = {statement.split()[2]: statement for statement in _INDEX_DDL}
        entries = connection.execute(
            "SELECT type,name,sql FROM sqlite_schema"
        ).fetchall()
        explicit_entries = [
            (kind, name, sql)
            for kind, name, sql in entries
            if not name.startswith("sqlite_")
        ]
        autoindexes = [
            (kind, name, sql)
            for kind, name, sql in entries
            if name.startswith("sqlite_")
        ]
        actual_tables = {
            name: sql for kind, name, sql in explicit_entries if kind == "table"
        }
        actual_indexes = {
            name: sql for kind, name, sql in explicit_entries if kind == "index"
        }
        if (
            set(actual_tables) != set(expected_tables)
            or set(actual_indexes) != set(expected_indexes)
            or any(
                actual_tables[name] != statement
                for name, statement in expected_tables.items()
            )
            or any(
                actual_indexes[name] != statement
                for name, statement in expected_indexes.items()
            )
            or any(
                kind not in {"table", "index"} for kind, _name, _sql in explicit_entries
            )
            or any(
                kind != "index"
                or not name.startswith("sqlite_autoindex_")
                or sql is not None
                for kind, name, sql in autoindexes
            )
        ):
            return diagnostic_for(
                "BUS_E_STORE_SCHEMA_UNKNOWN",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        rows = connection.execute(
            "SELECT schema_name,generation,schema_digest FROM bus_store_meta"
        ).fetchall()
        if len(rows) != 1 or rows[0][0] != _SCHEMA_NAME:
            return diagnostic_for(
                "BUS_E_STORE_SCHEMA_UNKNOWN",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        generation = rows[0][1]
        if type(generation) is not int:
            return diagnostic_for(
                "BUS_E_STORE_SCHEMA_UNKNOWN",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        if generation < _GENERATION:
            return diagnostic_for(
                "BUS_E_STORE_SCHEMA_UNKNOWN",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        if generation > _GENERATION:
            return diagnostic_for(
                "BUS_E_STORE_SCHEMA_TOO_NEW",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        if rows[0][2] != _SCHEMA_DIGEST:
            return diagnostic_for(
                "BUS_E_STORE_SCHEMA_UNKNOWN",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            return diagnostic_for(
                "BUS_E_STORE_INTEGRITY",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            return diagnostic_for(
                "BUS_E_STORE_INTEGRITY",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        return None

    @staticmethod
    def _rollback(connection: sqlite3.Connection) -> None:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.DatabaseError:
            pass

    def _usable(self) -> DiagnosticV2 | None:
        if self._closed:
            return diagnostic_for(
                "BUS_E_STORE_INTEGRITY",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        try:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(self._root, flags)
            try:
                if (
                    not _is_local_filesystem(descriptor)
                    or not _is_trusted_directory(os.fstat(descriptor))
                    or _identity(os.fstat(descriptor)) != self._root_identity
                ):
                    raise ValueError
            finally:
                os.close(descriptor)
            if not _is_trusted_file(os.lstat(self._root / _DATABASE_NAME)):
                raise ValueError
            self._validate_auxiliary_files(self._root)
        except (OSError, ValueError):
            return diagnostic_for(
                "BUS_E_STORE_INTEGRITY",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        return None

    def close(self) -> DiagnosticV2 | None:
        """Release all owned resources after one best-effort WAL truncate checkpoint."""

        with self._lock:
            if self._closed:
                return None
            incomplete = False
            try:
                result = self._connection.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
                incomplete = (
                    not isinstance(result, tuple)
                    or len(result) != 3
                    or result[0] != 0
                    or result[1] != result[2]
                )
            except sqlite3.DatabaseError:
                incomplete = True
            finally:
                self._connection.close()
                os.close(self._owner_fd)
                self._closed = True
            if incomplete:
                return diagnostic_for(
                    "BUS_W_CHECKPOINT_INCOMPLETE",
                    severity=DiagnosticSeverityV2.WARNING,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="inspect_checkpoint",
                    causes=(),
                )
            return None

    @staticmethod
    def _schema_error() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_SCHEMA",
            severity=DiagnosticSeverityV2.ERROR,
            retryable=False,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="reject_request",
            causes=(),
        )

    @staticmethod
    def _subscription_stale() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_SUBSCRIPTION_STALE",
            severity=DiagnosticSeverityV2.ERROR,
            retryable=False,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="refresh_subscription",
            causes=(),
        )

    @staticmethod
    def _cursor_conflict() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_CURSOR_CONFLICT",
            severity=DiagnosticSeverityV2.ERROR,
            retryable=False,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="repoll_headers",
            causes=(),
        )

    @staticmethod
    def _cursor_gap() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_CURSOR_GAP",
            severity=DiagnosticSeverityV2.ERROR,
            retryable=False,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="revalidate_snapshot",
            causes=(),
        )

    @staticmethod
    def _retention_precondition() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_RETENTION_PRECONDITION",
            severity=DiagnosticSeverityV2.ERROR,
            retryable=False,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="revalidate_retention_basis",
            causes=(),
        )

    @staticmethod
    def _snapshot_too_large() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_SNAPSHOT_TOO_LARGE",
            severity=DiagnosticSeverityV2.ERROR,
            retryable=False,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="reduce_snapshot",
            causes=(),
        )

    @staticmethod
    def _delivery_stale() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_DELIVERY_STALE",
            severity=DiagnosticSeverityV2.WARNING,
            retryable=True,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="repoll_headers",
            causes=(),
        )

    @staticmethod
    def _poison() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_POISON",
            severity=DiagnosticSeverityV2.ERROR,
            retryable=False,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="inspect_dead_letter",
            causes=(),
        )

    @staticmethod
    def _effect_conflict() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_EFFECT_CONFLICT",
            severity=DiagnosticSeverityV2.CRITICAL,
            retryable=False,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="operator_intervention",
            causes=(),
        )

    @staticmethod
    def _delivery_active(retry_after_seconds: int) -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_DELIVERY_LEASE_ACTIVE",
            severity=DiagnosticSeverityV2.WARNING,
            retryable=True,
            retry_after_seconds=retry_after_seconds,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="retry_delivery",
            causes=(),
        )

    @staticmethod
    def _delivery_backoff(retry_after_seconds: int) -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_DELIVERY_BACKOFF",
            severity=DiagnosticSeverityV2.WARNING,
            retryable=True,
            retry_after_seconds=retry_after_seconds,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="retry_delivery",
            causes=(),
        )

    @staticmethod
    def _store_integrity() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_STORE_INTEGRITY",
            severity=DiagnosticSeverityV2.CRITICAL,
            retryable=False,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="operator_intervention",
            causes=(),
        )

    @staticmethod
    def _store_busy() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_STORE_BUSY",
            severity=DiagnosticSeverityV2.WARNING,
            retryable=True,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="retry_operation",
            causes=(),
        )

    @staticmethod
    def _backpressure() -> DiagnosticV2:
        return diagnostic_for(
            "BUS_E_BACKPRESSURE",
            severity=DiagnosticSeverityV2.WARNING,
            retryable=True,
            retry_after_seconds=None,
            fallback_applied=False,
            requested_choice=None,
            effective_choice=None,
            action="defer_publish",
            causes=(),
        )

    def _capacity_state(self, partition: str) -> CapacityStateV1:
        row = self._connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(CASE WHEN events.payload_kind IN "
            "('inline','blob') AND payloads.body_state='present' "
            "AND payloads.body IS NOT NULL THEN payloads.size_bytes ELSE 0 END),0) "
            "FROM events LEFT JOIN payloads ON payloads.kind=events.payload_kind "
            "AND payloads.digest=events.payload_digest AND payloads.ref=events.payload_ref "
            "WHERE events.partition=?",
            (partition,),
        ).fetchone()
        if (
            not isinstance(row, tuple)
            or len(row) != 2
            or type(row[0]) is not int
            or type(row[1]) is not int
            or row[0] < 0
            or row[1] < 0
        ):
            raise sqlite3.DatabaseError
        return CapacityStateV1(
            header_count=row[0],
            managed_payload_bytes=row[1],
            at_warning_watermark=(
                row[0] >= _CAPACITY_WARNING_HEADERS or row[1] >= _CAPACITY_WARNING_BYTES
            ),
            at_hard_watermark=(
                row[0] >= _CAPACITY_HARD_HEADERS or row[1] >= _CAPACITY_HARD_BYTES
            ),
        )

    @staticmethod
    def _validate_group_partition_generation(
        consumer_group_id: object, partition: object, generation: object
    ) -> tuple[str, str, str]:
        group = validate_identifier(consumer_group_id, field="consumer_group_id")
        checked_partition = validate_topic_partition(partition)
        if type(generation) is not str or _EVENT_ID_RE.fullmatch(generation) is None:
            raise ValueError
        return group, checked_partition, generation

    @staticmethod
    def _validate_digest(value: object) -> str:
        if type(value) is not str or _EVENT_ID_RE.fullmatch(value) is None:
            raise ValueError
        return value

    @staticmethod
    def _validate_delivery_token(value: object) -> str:
        if type(value) is not str or _LEASE_TOKEN_RE.fullmatch(value) is None:
            raise ValueError
        return value

    @staticmethod
    def _validate_error_code(value: object) -> str:
        if (
            type(value) is not str
            or not value.isascii()
            or len(value) > 128
            or not value.startswith("BUS_E_")
            or value == "BUS_E_POISON"
            or value not in DIAGNOSTIC_CODE_SPECS_V2
        ):
            raise ValueError
        return value

    @staticmethod
    def _remaining_seconds(until: datetime, now: datetime, *, maximum: int) -> int:
        seconds = math.ceil((until - now).total_seconds())
        if not 1 <= seconds <= maximum:
            raise ValueError
        return seconds

    def _valid_current_lease(
        self,
        group: str,
        partition: str,
        generation: str,
        token_digest: str,
        now: datetime,
    ) -> tuple[int, int, datetime] | None:
        row = self._connection.execute(
            "SELECT generation,delivery_token,from_seq,scan_through_seq,expires_at_utc "
            "FROM delivery_leases WHERE consumer_group_id=? AND partition=?",
            (group, partition),
        ).fetchone()
        if row is None:
            return None
        lease_generation, persisted_digest, from_seq, scan_through_seq, expires_at = row
        expiry = _stored_utc(expires_at)
        if (
            lease_generation != generation
            or persisted_digest != token_digest
            or type(from_seq) is not int
            or type(scan_through_seq) is not int
            or not 1 <= from_seq <= scan_through_seq
            or now >= expiry
        ):
            return None
        return from_seq, scan_through_seq, expiry

    def _cursor_generation_matches(
        self, group: str, partition: str, generation: str
    ) -> tuple[int, ...] | None:
        row = self._connection.execute(
            "SELECT acked_seq FROM cursors WHERE consumer_group_id=? AND partition=? AND generation=?",
            (group, partition, generation),
        ).fetchone()
        if row is None or type(row[0]) is not int or row[0] < 0:
            return None
        return row

    def _event_in_lease(
        self,
        group: str,
        partition: str,
        event_id: str,
        from_seq: int,
        scan_through_seq: int,
    ) -> tuple[int, str] | None:
        row = self._connection.execute(
            "SELECT partition_seq,event_type FROM events WHERE event_id=? AND partition=?",
            (event_id, partition),
        ).fetchone()
        if (
            row is None
            or type(row[0]) is not int
            or type(row[1]) is not str
            or not from_seq <= row[0] <= scan_through_seq
        ):
            return None
        return row

    def _earlier_lease_effects_are_settled(
        self,
        group: str,
        partition: str,
        generation: str,
        from_seq: int,
        event_seq: int,
    ) -> bool:
        """Require serial application within one bearer range without policy lookup."""

        rows = self._connection.execute(
            "SELECT events.event_type,consumer_effects.state,consumer_effects.attempt_count "
            "FROM events LEFT JOIN consumer_effects ON "
            "consumer_effects.consumer_group_id=? AND consumer_effects.event_id=events.event_id "
            "AND consumer_effects.generation=? "
            "WHERE events.partition=? AND events.partition_seq BETWEEN ? AND ? "
            "ORDER BY events.partition_seq",
            (group, generation, partition, from_seq, event_seq - 1),
        ).fetchall()
        if len(rows) != event_seq - from_seq:
            raise ValueError
        for event_type, state, attempt_count in rows:
            if type(event_type) is not str or event_type not in EVENT_TYPE_MATRIX:
                raise ValueError
            if state == "committed":
                continue
            if (
                state == "dead_lettered"
                and attempt_count == 5
                and not EVENT_TYPE_MATRIX[event_type].urgent
                and event_type != "artifact.archived"
            ):
                continue
            return False
        return True

    def _materialize_expired_lease(
        self,
        group: str,
        partition: str,
        token_digest: str,
        now: datetime,
    ) -> bool:
        """Close only persisted pending attempts for one expired bearer lease."""

        now_text = _format_utc(now)
        terminal_poisoned = False
        pending = self._connection.execute(
            "SELECT event_id,attempt_count FROM consumer_effects "
            "WHERE consumer_group_id=? AND partition=? AND state='pending' AND lease_token=?",
            (group, partition, token_digest),
        ).fetchall()
        for event_id, attempt_count in pending:
            if (
                type(event_id) is not str
                or type(attempt_count) is not int
                or not 0 <= attempt_count < 5
            ):
                raise ValueError
            next_attempt = attempt_count + 1
            if next_attempt < 5:
                retry_at = _format_utc(
                    now + timedelta(seconds=_BACKOFF_SECONDS[next_attempt - 1])
                )
                changed = self._connection.execute(
                    "UPDATE consumer_effects SET attempt_count=?,retry_not_before_utc=?,"
                    "lease_token=NULL,lease_expires_at_utc=NULL,last_error_code=?,updated_at_utc=? "
                    "WHERE consumer_group_id=? AND event_id=? AND state='pending' AND lease_token=? AND attempt_count=?",
                    (
                        next_attempt,
                        retry_at,
                        "BUS_E_DELIVERY_STALE",
                        now_text,
                        group,
                        event_id,
                        token_digest,
                        attempt_count,
                    ),
                ).rowcount
                if changed != 1:
                    raise sqlite3.DatabaseError
                continue
            changed = self._connection.execute(
                "UPDATE consumer_effects SET state='dead_lettered',attempt_count=5,"
                "retry_not_before_utc=NULL,lease_token=NULL,lease_expires_at_utc=NULL,"
                "last_error_code=?,updated_at_utc=? WHERE consumer_group_id=? AND event_id=? "
                "AND state='pending' AND lease_token=? AND attempt_count=?",
                (
                    "BUS_E_DELIVERY_STALE",
                    now_text,
                    group,
                    event_id,
                    token_digest,
                    attempt_count,
                ),
            ).rowcount
            if changed != 1:
                raise sqlite3.DatabaseError
            effect = self._connection.execute(
                "SELECT partition,partition_seq,generation FROM consumer_effects "
                "WHERE consumer_group_id=? AND event_id=?",
                (group, event_id),
            ).fetchone()
            if (
                effect is None
                or type(effect[0]) is not str
                or type(effect[1]) is not int
                or type(effect[2]) is not str
            ):
                raise ValueError
            self._connection.execute(
                "INSERT INTO dead_letters(consumer_group_id,event_id,partition,partition_seq,"
                "generation,attempt_count,error_code,error_fingerprint,created_at_utc) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    group,
                    event_id,
                    effect[0],
                    effect[1],
                    effect[2],
                    5,
                    "BUS_E_DELIVERY_STALE",
                    _digest(b"delivery_lease_expired_v1"),
                    now_text,
                ),
            )
            terminal_poisoned = True
        self._connection.execute(
            "DELETE FROM delivery_leases WHERE consumer_group_id=? AND partition=? AND delivery_token=?",
            (group, partition, token_digest),
        )
        return terminal_poisoned

    def read_capacity(self, partition: str) -> CapacityStateV1 | None | DiagnosticV2:
        """Read one partition's current noncompacted header and payload counters."""

        try:
            checked_partition = validate_topic_partition(partition)
        except HiveBusContractError:
            return self._schema_error()
        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                exists = self._connection.execute(
                    "SELECT 1 FROM partitions WHERE partition=?",
                    (checked_partition,),
                ).fetchone()
                if exists is None:
                    self._connection.execute("COMMIT")
                    return None
                if exists != (1,):
                    raise sqlite3.DatabaseError
                state = self._capacity_state(checked_partition)
                self._connection.execute("COMMIT")
                return state
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def append(
        self, request: object, *, payload_bytes: bytes | None
    ) -> AppendResultV1 | DiagnosticV2:
        """Atomically persist one validated producer event or return a redacted diagnostic."""

        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                event_id_for_publish_request(request)
                probe = create_hive_bus_event_v1(
                    request, partition_seq=1, accepted_at_utc=_utc_now(self._clock)
                )
            except HiveBusContractError as exc:
                if exc.code == "BUS_E_CANONICALIZATION":
                    return diagnostic_for(
                        "BUS_E_CANONICALIZATION",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                if exc.code == "BUS_E_TOPIC_INVALID":
                    return diagnostic_for(
                        "BUS_E_TOPIC_INVALID",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                if exc.code == "BUS_E_EVENT_TOO_LARGE":
                    return diagnostic_for(
                        "BUS_E_EVENT_TOO_LARGE",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                if exc.code == "BUS_E_SECRET_CLASSIFICATION":
                    return diagnostic_for(
                        "BUS_E_SECRET_CLASSIFICATION",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                if exc.code == "BUS_E_ACL_DENIED":
                    return diagnostic_for(
                        "BUS_E_ACL_DENIED",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                if exc.code == "BUS_E_REPO_SCOPE":
                    return diagnostic_for(
                        "BUS_E_REPO_SCOPE",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                return diagnostic_for(
                    "BUS_E_SCHEMA",
                    severity=DiagnosticSeverityV2.ERROR,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="reject_publish",
                    causes=(),
                )
            except ValueError:
                return diagnostic_for(
                    "BUS_E_SCHEMA",
                    severity=DiagnosticSeverityV2.ERROR,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="reject_publish",
                    causes=(),
                )
            payload = probe.payload
            if payload.kind == "artifact":
                if payload_bytes is not None:
                    return diagnostic_for(
                        "BUS_E_SCHEMA",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                body: bytes | None = None
                artifact_id = payload.ref[len("artifact:") :].split("@", 1)[0]
            else:
                if type(payload_bytes) is not bytes:
                    return diagnostic_for(
                        "BUS_E_SCHEMA",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                if (
                    len(payload_bytes) != payload.size_bytes
                    or len(payload_bytes) > MAX_PAYLOAD_BYTES
                ):
                    return diagnostic_for(
                        "BUS_E_PAYLOAD_DIGEST",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                if _digest(payload_bytes) != payload.digest:
                    return diagnostic_for(
                        "BUS_E_PAYLOAD_DIGEST",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                body = payload_bytes
                artifact_id = None
            try:
                request_digest = _digest(canonical_json_bytes(request))
                self._connection.execute("BEGIN IMMEDIATE")
                retry = self._connection.execute(
                    "SELECT event_id,canonical_request_digest FROM idempotency WHERE producer_principal_id=? AND producer_epoch=? AND idempotency_key=?",
                    (
                        probe.producer_principal_id,
                        probe.producer_epoch,
                        probe.idempotency_key,
                    ),
                ).fetchone()
                if retry is not None:
                    if retry[1] != request_digest:
                        self._connection.execute("ROLLBACK")
                        return diagnostic_for(
                            "BUS_E_IDEMPOTENCY_CONFLICT",
                            severity=DiagnosticSeverityV2.ERROR,
                            retryable=False,
                            retry_after_seconds=None,
                            fallback_applied=False,
                            requested_choice=None,
                            effective_choice=None,
                            action="reject_publish",
                            causes=(),
                        )
                    stored = self._stored_event(request, retry[0])
                    if isinstance(stored, DiagnosticV2):
                        self._rollback(self._connection)
                        return stored
                    capacity = self._capacity_state(probe.partition)
                    self._connection.execute("COMMIT")
                    return AppendResultV1(event=stored, capacity=capacity)
                now = _utc_now(self._clock)
                partition_row = self._connection.execute(
                    "SELECT next_seq,state FROM partitions WHERE partition=?",
                    (probe.partition,),
                ).fetchone()
                if partition_row is not None and partition_row[1] != "active":
                    self._connection.execute("ROLLBACK")
                    return diagnostic_for(
                        "BUS_E_PARTITION_SEQ_CONFLICT",
                        severity=DiagnosticSeverityV2.CRITICAL,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="operator_intervention",
                        causes=(),
                    )
                current_capacity = self._capacity_state(probe.partition)
                managed_payload_delta = (
                    payload.size_bytes if payload.kind in {"inline", "blob"} else 0
                )
                projected_header_count = current_capacity.header_count + 1
                projected_payload_bytes = (
                    current_capacity.managed_payload_bytes + managed_payload_delta
                )
                if probe.event_type not in _CAPACITY_HARD_EXCEPTIONS and (
                    projected_header_count >= _CAPACITY_HARD_HEADERS
                    or projected_payload_bytes >= _CAPACITY_HARD_BYTES
                ):
                    self._connection.execute("ROLLBACK")
                    return self._backpressure()
                if partition_row is None:
                    partition_seq = 1
                    self._connection.execute(
                        "INSERT INTO partitions(partition,next_seq,first_retained_seq,state,blocked_code,created_at_utc,updated_at_utc) VALUES(?,?,?,?,?,?,?)",
                        (probe.partition, 2, 1, "active", None, now, now),
                    )
                else:
                    partition_seq = partition_row[0]
                    changed = self._connection.execute(
                        "UPDATE partitions SET next_seq=?,updated_at_utc=? WHERE partition=? AND next_seq=?",
                        (partition_seq + 1, now, probe.partition, partition_seq),
                    ).rowcount
                    if changed != 1:
                        self._connection.execute("ROLLBACK")
                        self._block_partition(probe.partition, now)
                        return diagnostic_for(
                            "BUS_E_PARTITION_SEQ_CONFLICT",
                            severity=DiagnosticSeverityV2.CRITICAL,
                            retryable=False,
                            retry_after_seconds=None,
                            fallback_applied=False,
                            requested_choice=None,
                            effective_choice=None,
                            action="operator_intervention",
                            causes=(),
                        )
                epoch = self._connection.execute(
                    "SELECT last_seq FROM producer_epochs WHERE producer_principal_id=? AND producer_epoch=?",
                    (probe.producer_principal_id, probe.producer_epoch),
                ).fetchone()
                if epoch is None:
                    if probe.producer_seq != 1:
                        self._connection.execute("ROLLBACK")
                        return diagnostic_for(
                            "BUS_E_PRODUCER_SEQ_GAP",
                            severity=DiagnosticSeverityV2.ERROR,
                            retryable=False,
                            retry_after_seconds=None,
                            fallback_applied=False,
                            requested_choice=None,
                            effective_choice=None,
                            action="reject_publish",
                            causes=(),
                        )
                elif probe.producer_seq < epoch[0] + 1:
                    self._connection.execute("ROLLBACK")
                    return diagnostic_for(
                        "BUS_E_PRODUCER_SEQ_REGRESSION",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                elif probe.producer_seq > epoch[0] + 1:
                    self._connection.execute("ROLLBACK")
                    return diagnostic_for(
                        "BUS_E_PRODUCER_SEQ_GAP",
                        severity=DiagnosticSeverityV2.ERROR,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="reject_publish",
                        causes=(),
                    )
                event = create_hive_bus_event_v1(
                    request, partition_seq=partition_seq, accepted_at_utc=now
                )
                header = canonical_json_bytes(serialize_hive_bus_event_v1(event))
                header_digest = _digest(header)
                self._connection.execute(
                    "INSERT INTO payloads(kind,digest,ref,size_bytes,body,body_state,artifact_id,quarantine_code,created_at_utc) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(kind,digest,ref) DO NOTHING",
                    (
                        payload.kind,
                        payload.digest,
                        payload.ref,
                        payload.size_bytes,
                        body,
                        "reference" if payload.kind == "artifact" else "present",
                        artifact_id,
                        None,
                        now,
                    ),
                )
                persisted_payload = self._connection.execute(
                    "SELECT size_bytes,body,body_state,artifact_id,quarantine_code FROM payloads WHERE kind=? AND digest=? AND ref=?",
                    (payload.kind, payload.digest, payload.ref),
                ).fetchone()
                if persisted_payload != (
                    payload.size_bytes,
                    body,
                    "reference" if payload.kind == "artifact" else "present",
                    artifact_id,
                    None,
                ):
                    raise sqlite3.DatabaseError
                self._connection.execute(
                    "INSERT INTO events(event_id,partition,partition_seq,schema_version,event_type,idempotency_key,producer_principal_id,producer_session_id,producer_epoch,producer_seq,repo_id,topic_id,workpackage_id,correlation_id,causation_ids_bytes,authority_grant_id,authority_scope_digest,authority_principal_version,classification,retention_class,created_at_utc,accepted_at_utc,payload_kind,payload_digest,payload_ref,payload_size_bytes,header_bytes,header_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        event.event_id,
                        event.partition,
                        event.partition_seq,
                        event.schema_version,
                        event.event_type,
                        event.idempotency_key,
                        event.producer_principal_id,
                        event.producer_session_id,
                        event.producer_epoch,
                        event.producer_seq,
                        event.repo_id,
                        event.topic_id,
                        event.workpackage_id,
                        event.correlation_id,
                        canonical_json_bytes(list(event.causation_ids)),
                        event.authority.grant_id,
                        event.authority.scope_digest,
                        event.authority.principal_version,
                        event.classification,
                        event.retention_class,
                        event.created_at_utc,
                        event.accepted_at_utc,
                        payload.kind,
                        payload.digest,
                        payload.ref,
                        payload.size_bytes,
                        header,
                        header_digest,
                    ),
                )
                if epoch is None:
                    self._connection.execute(
                        "INSERT INTO producer_epochs(producer_principal_id,producer_epoch,producer_session_id,last_seq,last_event_id,updated_at_utc) VALUES(?,?,?,?,?,?)",
                        (
                            event.producer_principal_id,
                            event.producer_epoch,
                            event.producer_session_id,
                            event.producer_seq,
                            event.event_id,
                            now,
                        ),
                    )
                else:
                    self._connection.execute(
                        "UPDATE producer_epochs SET last_seq=?,last_event_id=?,updated_at_utc=? WHERE producer_principal_id=? AND producer_epoch=?",
                        (
                            event.producer_seq,
                            event.event_id,
                            now,
                            event.producer_principal_id,
                            event.producer_epoch,
                        ),
                    )
                self._connection.execute(
                    "INSERT INTO idempotency(producer_principal_id,producer_epoch,idempotency_key,event_id,canonical_request_digest,partition_seq,accepted_at_utc,created_at_utc) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        event.producer_principal_id,
                        event.producer_epoch,
                        event.idempotency_key,
                        event.event_id,
                        request_digest,
                        event.partition_seq,
                        event.accepted_at_utc,
                        now,
                    ),
                )
                capacity = self._capacity_state(probe.partition)
                _append_checkpoint("before_commit")
                self._connection.execute("COMMIT")
                _append_checkpoint("after_commit")
                return AppendResultV1(event=event, capacity=capacity)
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                if not _sqlite_is_busy(exc):
                    return diagnostic_for(
                        "BUS_E_STORE_INTEGRITY",
                        severity=DiagnosticSeverityV2.CRITICAL,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="operator_intervention",
                        causes=(),
                    )
                return diagnostic_for(
                    "BUS_E_STORE_BUSY",
                    severity=DiagnosticSeverityV2.WARNING,
                    retryable=True,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="retry_operation",
                    causes=(),
                )
            except sqlite3.IntegrityError:
                self._rollback(self._connection)
                self._block_partition(probe.partition, _utc_now(self._clock))
                return diagnostic_for(
                    "BUS_E_PARTITION_SEQ_CONFLICT",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            except (HiveBusContractError, ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return diagnostic_for(
                    "BUS_E_STORE_INTEGRITY",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )

    @staticmethod
    def _digest_anchor_from_row(row: object) -> DigestAnchorV1 | None:
        if not isinstance(row, tuple) or len(row) != 9:
            return None
        (
            partition,
            from_seq,
            through_seq,
            event_count,
            header_bytes,
            digest,
            digest_bytes,
            digest_size_bytes,
            created_at_utc,
        ) = row
        if (
            type(partition) is not str
            or type(from_seq) is not int
            or type(through_seq) is not int
            or type(event_count) is not int
            or type(header_bytes) is not int
            or type(digest) is not str
            or type(digest_bytes) is not bytes
            or type(digest_size_bytes) is not int
            or type(created_at_utc) is not str
            or _EVENT_ID_RE.fullmatch(digest) is None
            or from_seq < 1
            or through_seq < from_seq
            or event_count != through_seq - from_seq + 1
            or not 1 <= event_count <= _MAX_DELIVERY_HEADERS
            or not 1 <= header_bytes <= 69_632
            or not 1 <= len(digest_bytes) <= 65_536
            or digest_size_bytes != len(digest_bytes)
            or digest != _digest(digest_bytes)
        ):
            return None
        try:
            validate_topic_partition(partition)
            _stored_utc(created_at_utc)
        except (HiveBusContractError, ValueError):
            return None
        return DigestAnchorV1(
            partition=partition,
            from_seq=from_seq,
            through_seq=through_seq,
            event_count=event_count,
            header_bytes=header_bytes,
            digest=digest,
            digest_bytes=digest_bytes,
        )

    @staticmethod
    def _snapshot_id(partition: str, through_seq: int, snapshot_digest: str) -> str:
        return _digest(
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "partition": partition,
                    "through_seq": through_seq,
                    "snapshot_digest": snapshot_digest,
                }
            )
        )

    @staticmethod
    def _snapshot_anchor_from_row(row: object) -> SnapshotAnchorV1 | None:
        if not isinstance(row, tuple) or len(row) != 7:
            return None
        (
            snapshot_id,
            partition,
            through_seq,
            snapshot_digest,
            snapshot_bytes,
            snapshot_size_bytes,
            created_at_utc,
        ) = row
        if (
            type(snapshot_id) is not str
            or type(partition) is not str
            or type(through_seq) is not int
            or type(snapshot_digest) is not str
            or type(snapshot_bytes) is not bytes
            or type(snapshot_size_bytes) is not int
            or type(created_at_utc) is not str
            or _EVENT_ID_RE.fullmatch(snapshot_id) is None
            or _EVENT_ID_RE.fullmatch(snapshot_digest) is None
            or not 1 <= through_seq <= _MAX_SIGNED_SQLITE_INTEGER
            or not 0 <= snapshot_size_bytes <= _MAX_SNAPSHOT_BYTES
            or len(snapshot_bytes) != snapshot_size_bytes
            or _digest(snapshot_bytes) != snapshot_digest
        ):
            return None
        try:
            validate_topic_partition(partition)
            _stored_utc(created_at_utc)
        except (HiveBusContractError, ValueError):
            return None
        if snapshot_id != HiveBusStore._snapshot_id(
            partition, through_seq, snapshot_digest
        ):
            return None
        return SnapshotAnchorV1(
            snapshot_id=snapshot_id,
            partition=partition,
            through_seq=through_seq,
            snapshot_digest=snapshot_digest,
        )

    @staticmethod
    def _validate_snapshot_anchor(value: object) -> SnapshotAnchorV1:
        if type(value) is not SnapshotAnchorV1:
            raise ValueError
        partition = validate_topic_partition(value.partition)
        through_seq = value.through_seq
        snapshot_id = HiveBusStore._validate_digest(value.snapshot_id)
        snapshot_digest = HiveBusStore._validate_digest(value.snapshot_digest)
        if (
            type(through_seq) is not int
            or not 1 <= through_seq <= _MAX_SIGNED_SQLITE_INTEGER
            or snapshot_id
            != HiveBusStore._snapshot_id(partition, through_seq, snapshot_digest)
        ):
            raise ValueError
        return SnapshotAnchorV1(
            snapshot_id=snapshot_id,
            partition=partition,
            through_seq=through_seq,
            snapshot_digest=snapshot_digest,
        )

    def _cursor_gap_from_values(
        self,
        *,
        partition: str,
        acked_seq: object,
        snapshot_id: object,
        gap_from_seq: object,
        gap_through_seq: object,
    ) -> CursorGapV1 | None:
        if (
            type(acked_seq) is not int
            or type(snapshot_id) is not str
            or type(gap_from_seq) is not int
            or type(gap_through_seq) is not int
            or acked_seq < 0
            or gap_from_seq != acked_seq + 1
            or not gap_from_seq <= gap_through_seq
            or _EVENT_ID_RE.fullmatch(snapshot_id) is None
        ):
            return None
        row = self._connection.execute(
            "SELECT snapshot_id,partition,through_seq,snapshot_digest,snapshot_bytes,snapshot_size_bytes,created_at_utc "
            "FROM snapshots WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        snapshot = self._snapshot_anchor_from_row(row)
        if (
            snapshot is None
            or snapshot.partition != partition
            or snapshot.through_seq != gap_through_seq
        ):
            return None
        return CursorGapV1(
            diagnostic=self._cursor_gap(),
            snapshot=snapshot,
            gap_from_seq=gap_from_seq,
            gap_through_seq=gap_through_seq,
        )

    @staticmethod
    def _retention_basis_values(
        basis: object, partition: str
    ) -> tuple[str, MandatoryWatermarkV1, SnapshotAnchorV1 | None, str]:
        if type(basis) is not RetentionBasisV1:
            raise ValueError
        run_id = HiveBusStore._validate_digest(basis.run_id)
        if type(basis.watermark) is not MandatoryWatermarkV1:
            raise ValueError
        watermark = basis.watermark
        watermark_partition = validate_topic_partition(watermark.partition)
        retention_generation = watermark.retention_generation
        mandatory_watermark_seq = watermark.mandatory_watermark_seq
        subscription_generation = HiveBusStore._validate_digest(
            watermark.subscription_generation
        )
        attestation_digest = HiveBusStore._validate_digest(watermark.attestation_digest)
        if (
            watermark_partition != partition
            or type(retention_generation) is not int
            or retention_generation < 1
            or type(mandatory_watermark_seq) is not int
            or not 0 <= mandatory_watermark_seq <= _MAX_SIGNED_SQLITE_INTEGER
        ):
            raise ValueError
        attestation_bytes = canonical_json_bytes(
            {
                "schema_version": 1,
                "partition": watermark_partition,
                "retention_generation": retention_generation,
                "mandatory_watermark_seq": mandatory_watermark_seq,
                "subscription_generation": subscription_generation,
            }
        )
        if _digest(attestation_bytes) != attestation_digest:
            raise LookupError
        checked_watermark = MandatoryWatermarkV1(
            partition=watermark_partition,
            retention_generation=retention_generation,
            mandatory_watermark_seq=mandatory_watermark_seq,
            subscription_generation=subscription_generation,
            attestation_digest=attestation_digest,
        )
        snapshot: SnapshotAnchorV1 | None = None
        if basis.snapshot is not None:
            snapshot = HiveBusStore._validate_snapshot_anchor(basis.snapshot)
            if snapshot.partition != partition:
                raise ValueError
        basis_digest = _digest(
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "run_id": run_id,
                    "watermark": {
                        "partition": checked_watermark.partition,
                        "retention_generation": checked_watermark.retention_generation,
                        "mandatory_watermark_seq": checked_watermark.mandatory_watermark_seq,
                        "subscription_generation": checked_watermark.subscription_generation,
                        "attestation_digest": checked_watermark.attestation_digest,
                    },
                    "snapshot": (
                        None
                        if snapshot is None
                        else {
                            "snapshot_id": snapshot.snapshot_id,
                            "partition": snapshot.partition,
                            "through_seq": snapshot.through_seq,
                            "snapshot_digest": snapshot.snapshot_digest,
                        }
                    ),
                }
            )
        )
        return run_id, checked_watermark, snapshot, basis_digest

    @staticmethod
    def _retention_policy_from_row(
        row: object, retention_generation: int
    ) -> dict[str, tuple[int | None, int | None]] | None:
        if not isinstance(row, tuple) or len(row) != 2:
            return None
        policy_digest, policy_bytes = row
        if (
            type(policy_digest) is not str
            or _EVENT_ID_RE.fullmatch(policy_digest) is None
            or type(policy_bytes) is not bytes
            or not 1 <= len(policy_bytes) <= _MAX_HEADER_BYTES
            or _digest(policy_bytes) != policy_digest
        ):
            return None
        try:
            parsed = json.loads(policy_bytes.decode("utf-8"))
            if canonical_json_bytes(parsed) != policy_bytes or type(parsed) is not dict:
                return None
            if (
                set(parsed) != {"schema_version", "retention_generation", "classes"}
                or parsed["schema_version"] != 1
                or parsed["retention_generation"] != retention_generation
                or type(parsed["classes"]) is not dict
                or set(parsed["classes"]) != {"transient", "work", "audit", "manifest"}
            ):
                return None
            result: dict[str, tuple[int | None, int | None]] = {}
            for retention_class, values in parsed["classes"].items():
                if type(values) is not dict or set(values) != {
                    "header_retention_seconds",
                    "payload_retention_seconds",
                }:
                    return None
                header = values["header_retention_seconds"]
                payload = values["payload_retention_seconds"]
                if (
                    header is not None and (type(header) is not int or header <= 0)
                ) or (
                    payload is not None and (type(payload) is not int or payload <= 0)
                ):
                    return None
                result[retention_class] = (header, payload)
            return result
        except (TypeError, UnicodeDecodeError, ValueError):
            return None

    @staticmethod
    def _canonical_digest_bytes(
        *,
        partition: str,
        from_seq: int,
        through_seq: int,
        event_count: int,
        header_bytes: int,
        entries: list[dict[str, object]],
    ) -> bytes:
        """Compose the canonical digest object within the shared JSON item bound."""

        if not 1 <= len(entries) <= _MAX_DELIVERY_HEADERS:
            raise ValueError
        # Canonicalize the entries independently: 32 entries with three fields
        # exactly consume the existing 128-item canonical JSON budget.  The
        # outer scalar fields are then joined in the canonical sorted-key order.
        encoded_entries = canonical_json_bytes(entries)
        return b"".join(
            (
                b'{"entries":',
                encoded_entries,
                b',"event_count":',
                canonical_json_bytes(event_count),
                b',"from_seq":',
                canonical_json_bytes(from_seq),
                b',"header_bytes":',
                canonical_json_bytes(header_bytes),
                b',"partition":',
                canonical_json_bytes(partition),
                b',"schema_version":',
                canonical_json_bytes(1),
                b',"through_seq":',
                canonical_json_bytes(through_seq),
                b"}",
            )
        )

    def materialize_digest(
        self, partition: str, *, through_seq: int
    ) -> DigestAnchorV1 | DiagnosticV2:
        """Persist the next bounded contiguous header digest interval on demand."""

        try:
            checked_partition = validate_topic_partition(partition)
        except HiveBusContractError:
            return self._schema_error()
        if (
            type(through_seq) is not int
            or not 1 <= through_seq <= _MAX_SIGNED_SQLITE_INTEGER
        ):
            return self._schema_error()
        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                existing_row = self._connection.execute(
                    "SELECT partition,from_seq,through_seq,event_count,header_bytes,digest,digest_bytes,digest_size_bytes,created_at_utc "
                    "FROM digest_anchors WHERE partition=? AND through_seq=?",
                    (checked_partition, through_seq),
                ).fetchone()
                if existing_row is not None:
                    anchor = self._digest_anchor_from_row(existing_row)
                    if anchor is None:
                        self._rollback(self._connection)
                        return self._store_integrity()
                    self._connection.execute("COMMIT")
                    return anchor

                max_row = self._connection.execute(
                    "SELECT MAX(through_seq) FROM digest_anchors WHERE partition=?",
                    (checked_partition,),
                ).fetchone()
                next_seq = (
                    1 if max_row is None or max_row[0] is None else max_row[0] + 1
                )
                if type(next_seq) is not int or through_seq < next_seq:
                    self._rollback(self._connection)
                    return self._schema_error()

                rows = self._connection.execute(
                    "SELECT partition_seq,event_id,header_bytes,header_digest FROM events "
                    "WHERE partition=? AND partition_seq>=? AND partition_seq<=? "
                    "ORDER BY partition_seq,event_id LIMIT 33",
                    (checked_partition, next_seq, through_seq),
                ).fetchall()
                if not rows:
                    self._rollback(self._connection)
                    return self._schema_error()

                selected: list[tuple[int, str, bytes, str]] = []
                expected_seq = next_seq
                total_header_bytes = 0
                for row in rows:
                    if len(selected) >= _MAX_DELIVERY_HEADERS:
                        break
                    if not isinstance(row, tuple) or len(row) != 4:
                        self._rollback(self._connection)
                        return self._store_integrity()
                    sequence, event_id, header, header_digest = row
                    if sequence != expected_seq:
                        self._rollback(self._connection)
                        return self._store_integrity()
                    if (
                        type(sequence) is not int
                        or type(event_id) is not str
                        or _EVENT_ID_RE.fullmatch(event_id) is None
                        or type(header) is not bytes
                        or not 1 <= len(header) <= _MAX_HEADER_BYTES
                        or type(header_digest) is not str
                        or _EVENT_ID_RE.fullmatch(header_digest) is None
                        or _digest(header) != header_digest
                    ):
                        self._rollback(self._connection)
                        return self._store_integrity()
                    if total_header_bytes + len(header) > 69_632:
                        break
                    selected.append((sequence, event_id, header, header_digest))
                    total_header_bytes += len(header)
                    expected_seq += 1

                if not selected:
                    self._rollback(self._connection)
                    return self._store_integrity()
                actual_through_seq = selected[-1][0]
                entries = [
                    {
                        "partition_seq": sequence,
                        "event_id": event_id,
                        "header_digest": header_digest,
                    }
                    for sequence, event_id, _header, header_digest in selected
                ]
                digest_bytes = self._canonical_digest_bytes(
                    partition=checked_partition,
                    from_seq=next_seq,
                    through_seq=actual_through_seq,
                    event_count=len(selected),
                    header_bytes=total_header_bytes,
                    entries=entries,
                )
                if not 1 <= len(digest_bytes) <= 65_536:
                    self._rollback(self._connection)
                    return self._store_integrity()
                digest = _digest(digest_bytes)
                created_at_utc = _utc_now(self._clock)
                self._connection.execute(
                    "INSERT INTO digest_anchors(partition,from_seq,through_seq,event_count,header_bytes,digest,digest_bytes,digest_size_bytes,created_at_utc) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        checked_partition,
                        next_seq,
                        actual_through_seq,
                        len(selected),
                        total_header_bytes,
                        digest,
                        digest_bytes,
                        len(digest_bytes),
                        created_at_utc,
                    ),
                )
                persisted = self._connection.execute(
                    "SELECT partition,from_seq,through_seq,event_count,header_bytes,digest,digest_bytes,digest_size_bytes,created_at_utc "
                    "FROM digest_anchors WHERE partition=? AND through_seq=?",
                    (checked_partition, actual_through_seq),
                ).fetchone()
                anchor = self._digest_anchor_from_row(persisted)
                if anchor is None:
                    raise sqlite3.DatabaseError
                self._connection.execute("COMMIT")
                return anchor
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (HiveBusContractError, ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def record_snapshot(
        self, partition: str, through_seq: int, *, snapshot_bytes: bytes
    ) -> SnapshotAnchorV1 | DiagnosticV2:
        """Persist one bounded opaque snapshot for an existing contiguous prefix."""

        try:
            checked_partition = validate_topic_partition(partition)
            if (
                type(through_seq) is not int
                or not 1 <= through_seq <= _MAX_SIGNED_SQLITE_INTEGER
                or type(snapshot_bytes) is not bytes
            ):
                raise ValueError
        except (HiveBusContractError, ValueError):
            return self._schema_error()
        if len(snapshot_bytes) > _MAX_SNAPSHOT_BYTES:
            return self._snapshot_too_large()
        snapshot_digest = _digest(snapshot_bytes)
        snapshot_id = self._snapshot_id(checked_partition, through_seq, snapshot_digest)
        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                existing_row = self._connection.execute(
                    "SELECT snapshot_id,partition,through_seq,snapshot_digest,snapshot_bytes,snapshot_size_bytes,created_at_utc "
                    "FROM snapshots WHERE partition=? AND through_seq=?",
                    (checked_partition, through_seq),
                ).fetchone()
                if existing_row is not None:
                    existing = self._snapshot_anchor_from_row(existing_row)
                    if existing is None:
                        self._rollback(self._connection)
                        return self._store_integrity()
                    self._connection.execute("COMMIT")
                    if existing.snapshot_digest != snapshot_digest:
                        return self._retention_precondition()
                    return existing
                partition_row = self._connection.execute(
                    "SELECT next_seq,first_retained_seq FROM partitions WHERE partition=?",
                    (checked_partition,),
                ).fetchone()
                if (
                    not isinstance(partition_row, tuple)
                    or len(partition_row) != 2
                    or type(partition_row[0]) is not int
                    or type(partition_row[1]) is not int
                    or not 1 <= partition_row[1] <= through_seq
                    or partition_row[0] <= through_seq
                ):
                    self._rollback(self._connection)
                    return self._schema_error()
                event_span = self._connection.execute(
                    "SELECT COUNT(*),MIN(partition_seq),MAX(partition_seq) FROM events "
                    "WHERE partition=? AND partition_seq BETWEEN ? AND ?",
                    (checked_partition, partition_row[1], through_seq),
                ).fetchone()
                if event_span != (
                    through_seq - partition_row[1] + 1,
                    partition_row[1],
                    through_seq,
                ):
                    self._rollback(self._connection)
                    return self._schema_error()
                now = _utc_now(self._clock)
                self._connection.execute(
                    "INSERT INTO snapshots(snapshot_id,partition,through_seq,snapshot_digest,snapshot_bytes,"
                    "snapshot_size_bytes,created_at_utc) VALUES(?,?,?,?,?,?,?)",
                    (
                        snapshot_id,
                        checked_partition,
                        through_seq,
                        snapshot_digest,
                        snapshot_bytes,
                        len(snapshot_bytes),
                        now,
                    ),
                )
                persisted = self._connection.execute(
                    "SELECT snapshot_id,partition,through_seq,snapshot_digest,snapshot_bytes,snapshot_size_bytes,created_at_utc "
                    "FROM snapshots WHERE snapshot_id=?",
                    (snapshot_id,),
                ).fetchone()
                anchor = self._snapshot_anchor_from_row(persisted)
                if anchor is None or anchor.snapshot_digest != snapshot_digest:
                    raise sqlite3.DatabaseError
                self._connection.execute("COMMIT")
                return anchor
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def compact_retention(
        self, partition: str, *, basis: RetentionBasisV1
    ) -> RetentionRunResultV1 | DiagnosticV2:
        """Atomically compact one due header prefix from an attested local basis."""

        try:
            checked_partition = validate_topic_partition(partition)
            run_id, watermark, requested_snapshot, basis_digest = (
                self._retention_basis_values(basis, checked_partition)
            )
        except LookupError:
            return self._retention_precondition()
        except (HiveBusContractError, HiveValidationError, ValueError):
            return self._schema_error()
        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                now = _utc_datetime(self._clock)
                now_text = _format_utc(now)
                self._connection.execute("BEGIN IMMEDIATE")
                checkpoint = self._connection.execute(
                    "SELECT partition,run_id,request_digest,retention_generation,basis_digest,"
                    "snapshot_id,compacted_through_seq,first_retained_seq,expired_payload_count,"
                    "compacted_event_count,completed_at_utc FROM retention_checkpoints "
                    "WHERE partition=? AND run_id=?",
                    (checked_partition, run_id),
                ).fetchone()
                if checkpoint is not None:
                    if not isinstance(checkpoint, tuple) or len(checkpoint) != 11:
                        raise ValueError
                    (
                        checkpoint_partition,
                        checkpoint_run_id,
                        request_digest,
                        checkpoint_generation,
                        checkpoint_basis_digest,
                        checkpoint_snapshot_id,
                        compacted_through_seq,
                        first_retained_seq,
                        expired_payload_count,
                        compacted_event_count,
                        completed_at_utc,
                    ) = checkpoint
                    if (
                        checkpoint_partition != checked_partition
                        or checkpoint_run_id != run_id
                        or request_digest != basis_digest
                        or checkpoint_basis_digest != basis_digest
                        or checkpoint_generation != watermark.retention_generation
                    ):
                        self._connection.execute("ROLLBACK")
                        return self._retention_precondition()
                    if (
                        type(compacted_through_seq) is not int
                        or type(first_retained_seq) is not int
                        or type(expired_payload_count) is not int
                        or type(compacted_event_count) is not int
                        or type(completed_at_utc) is not str
                        or not 0 <= compacted_through_seq
                        or not 1 <= first_retained_seq
                        or expired_payload_count < 0
                        or compacted_event_count < 0
                    ):
                        raise ValueError
                    _stored_utc(completed_at_utc)
                    snapshot: SnapshotAnchorV1 | None = None
                    if checkpoint_snapshot_id is not None:
                        if type(checkpoint_snapshot_id) is not str:
                            raise ValueError
                        snapshot_row = self._connection.execute(
                            "SELECT snapshot_id,partition,through_seq,snapshot_digest,snapshot_bytes,"
                            "snapshot_size_bytes,created_at_utc FROM snapshots WHERE snapshot_id=?",
                            (checkpoint_snapshot_id,),
                        ).fetchone()
                        snapshot = self._snapshot_anchor_from_row(snapshot_row)
                        if snapshot is None:
                            raise ValueError
                    if snapshot != requested_snapshot:
                        self._connection.execute("ROLLBACK")
                        return self._retention_precondition()
                    self._connection.execute("COMMIT")
                    return RetentionRunResultV1(
                        partition=checked_partition,
                        run_id=run_id,
                        retention_generation=watermark.retention_generation,
                        compacted_through_seq=compacted_through_seq,
                        first_retained_seq=first_retained_seq,
                        expired_payload_count=expired_payload_count,
                        compacted_event_count=compacted_event_count,
                        snapshot=snapshot,
                    )
                _retention_checkpoint("after_checkpoint_lookup")

                partition_row = self._connection.execute(
                    "SELECT next_seq,first_retained_seq FROM partitions WHERE partition=?",
                    (checked_partition,),
                ).fetchone()
                if (
                    not isinstance(partition_row, tuple)
                    or len(partition_row) != 2
                    or type(partition_row[0]) is not int
                    or type(partition_row[1]) is not int
                    or not 1 <= partition_row[1] <= partition_row[0]
                ):
                    self._rollback(self._connection)
                    return self._retention_precondition()
                next_seq, first_retained_seq = partition_row
                if watermark.mandatory_watermark_seq > next_seq - 1:
                    self._rollback(self._connection)
                    return self._retention_precondition()
                policy_row = self._connection.execute(
                    "SELECT policy_digest,policy_bytes FROM retention_policies "
                    "WHERE retention_generation=?",
                    (watermark.retention_generation,),
                ).fetchone()
                policy = self._retention_policy_from_row(
                    policy_row, watermark.retention_generation
                )
                if policy is None:
                    self._rollback(self._connection)
                    return self._retention_precondition()
                prefix_limit = min(watermark.mandatory_watermark_seq, next_seq - 1)
                rows = self._connection.execute(
                    "SELECT partition_seq,retention_class,accepted_at_utc FROM events "
                    "WHERE partition=? AND partition_seq BETWEEN ? AND ? "
                    "ORDER BY partition_seq",
                    (checked_partition, first_retained_seq, prefix_limit),
                ).fetchall()
                expected_seq = first_retained_seq
                compacted_through_seq = first_retained_seq - 1
                prefix_stopped = False
                for row in rows:
                    if not isinstance(row, tuple) or len(row) != 3:
                        raise ValueError
                    sequence, retention_class, accepted_at_utc = row
                    if (
                        type(sequence) is not int
                        or sequence != expected_seq
                        or type(retention_class) is not str
                        or retention_class not in policy
                    ):
                        raise ValueError
                    header_seconds, _payload_seconds = policy[retention_class]
                    accepted_at = _stored_utc(accepted_at_utc)
                    if (
                        header_seconds is None
                        or accepted_at + timedelta(seconds=header_seconds) > now
                    ):
                        prefix_stopped = True
                        break
                    compacted_through_seq = sequence
                    expected_seq += 1
                if not prefix_stopped and expected_seq <= prefix_limit:
                    raise ValueError

                snapshot: SnapshotAnchorV1 | None = None
                if requested_snapshot is not None:
                    snapshot_row = self._connection.execute(
                        "SELECT snapshot_id,partition,through_seq,snapshot_digest,snapshot_bytes,"
                        "snapshot_size_bytes,created_at_utc FROM snapshots WHERE snapshot_id=?",
                        (requested_snapshot.snapshot_id,),
                    ).fetchone()
                    if snapshot_row is None:
                        self._rollback(self._connection)
                        return self._retention_precondition()
                    snapshot = self._snapshot_anchor_from_row(snapshot_row)
                    if snapshot is None:
                        raise ValueError
                    if snapshot != requested_snapshot:
                        self._rollback(self._connection)
                        return self._retention_precondition()
                if compacted_through_seq >= first_retained_seq:
                    anchor_row = self._connection.execute(
                        "SELECT partition,from_seq,through_seq,event_count,header_bytes,digest,"
                        "digest_bytes,digest_size_bytes,created_at_utc FROM digest_anchors "
                        "WHERE partition=? AND through_seq=?",
                        (checked_partition, compacted_through_seq),
                    ).fetchone()
                    anchor = self._digest_anchor_from_row(anchor_row)
                    if anchor is None or anchor.from_seq != first_retained_seq:
                        self._rollback(self._connection)
                        return self._retention_precondition()
                    if (
                        snapshot is not None
                        and snapshot.through_seq != compacted_through_seq
                    ):
                        self._rollback(self._connection)
                        return self._retention_precondition()
                    lagging = self._connection.execute(
                        "SELECT COUNT(*) FROM cursors WHERE partition=? AND acked_seq<?",
                        (checked_partition, compacted_through_seq),
                    ).fetchone()
                    if lagging is None or type(lagging[0]) is not int:
                        raise ValueError
                    if lagging[0] and snapshot is None:
                        self._rollback(self._connection)
                        return self._retention_precondition()
                elif snapshot is not None:
                    self._rollback(self._connection)
                    return self._retention_precondition()
                _retention_checkpoint("after_snapshot_validation")

                if compacted_through_seq >= first_retained_seq:
                    self._connection.execute(
                        "DELETE FROM delivery_leases WHERE partition=? AND consumer_group_id IN "
                        "(SELECT consumer_group_id FROM cursors WHERE partition=? AND acked_seq<?)",
                        (
                            checked_partition,
                            checked_partition,
                            compacted_through_seq,
                        ),
                    )
                    updated_gaps = self._connection.execute(
                        "UPDATE cursors SET gap_snapshot_id=?,gap_from_seq=acked_seq+1,"
                        "gap_through_seq=?,updated_at_utc=? WHERE partition=? AND acked_seq<?",
                        (
                            None if snapshot is None else snapshot.snapshot_id,
                            compacted_through_seq,
                            now_text,
                            checked_partition,
                            compacted_through_seq,
                        ),
                    )
                    if updated_gaps.rowcount and snapshot is None:
                        raise ValueError
                _retention_checkpoint("after_cursor_gaps")

                first_retained_after = compacted_through_seq + 1
                if compacted_through_seq >= first_retained_seq:
                    updated_partition = self._connection.execute(
                        "UPDATE partitions SET first_retained_seq=?,updated_at_utc=? "
                        "WHERE partition=? AND first_retained_seq=?",
                        (
                            first_retained_after,
                            now_text,
                            checked_partition,
                            first_retained_seq,
                        ),
                    )
                    if updated_partition.rowcount != 1:
                        raise ValueError
                else:
                    first_retained_after = first_retained_seq
                _retention_checkpoint("after_partition_advance")

                expired_payload_count = 0
                if compacted_through_seq >= first_retained_seq:
                    candidates = self._connection.execute(
                        "SELECT DISTINCT events.payload_kind,events.payload_digest,events.payload_ref "
                        "FROM events JOIN payloads ON payloads.kind=events.payload_kind "
                        "AND payloads.digest=events.payload_digest AND payloads.ref=events.payload_ref "
                        "WHERE events.partition=? AND events.partition_seq BETWEEN ? AND ? "
                        "AND events.payload_kind IN ('inline','blob') "
                        "AND payloads.body_state='present'",
                        (checked_partition, first_retained_seq, compacted_through_seq),
                    ).fetchall()
                    for candidate in candidates:
                        if not isinstance(candidate, tuple) or len(candidate) != 3:
                            raise ValueError
                        payload_kind, payload_digest, payload_ref = candidate
                        if (
                            type(payload_kind) is not str
                            or payload_kind not in {"inline", "blob"}
                            or type(payload_digest) is not str
                            or _EVENT_ID_RE.fullmatch(payload_digest) is None
                            or type(payload_ref) is not str
                        ):
                            raise ValueError
                        references = self._connection.execute(
                            "SELECT retention_class,accepted_at_utc FROM events WHERE payload_kind=? "
                            "AND payload_digest=? AND payload_ref=?",
                            (payload_kind, payload_digest, payload_ref),
                        ).fetchall()
                        if not references:
                            raise ValueError
                        all_due = True
                        for reference in references:
                            if not isinstance(reference, tuple) or len(reference) != 2:
                                raise ValueError
                            retention_class, accepted_at_utc = reference
                            if (
                                type(retention_class) is not str
                                or retention_class not in policy
                            ):
                                raise ValueError
                            _header_seconds, payload_seconds = policy[retention_class]
                            if (
                                payload_seconds is None
                                or _stored_utc(accepted_at_utc)
                                + timedelta(seconds=payload_seconds)
                                > now
                            ):
                                all_due = False
                                break
                        if all_due:
                            expired = self._connection.execute(
                                "UPDATE payloads SET body=NULL,body_state='expired' WHERE kind=? "
                                "AND digest=? AND ref=? AND body_state='present'",
                                (payload_kind, payload_digest, payload_ref),
                            )
                            if expired.rowcount != 1:
                                raise ValueError
                            expired_payload_count += 1
                _retention_checkpoint("after_payload_expiry")

                compacted_event_count = 0
                if compacted_through_seq >= first_retained_seq:
                    deleted = self._connection.execute(
                        "DELETE FROM events WHERE partition=? AND partition_seq BETWEEN ? AND ?",
                        (checked_partition, first_retained_seq, compacted_through_seq),
                    )
                    compacted_event_count = (
                        compacted_through_seq - first_retained_seq + 1
                    )
                    if deleted.rowcount != compacted_event_count:
                        raise ValueError
                _retention_checkpoint("after_header_delete")

                self._connection.execute(
                    "INSERT INTO retention_checkpoints(partition,run_id,request_digest,"
                    "retention_generation,basis_digest,snapshot_id,compacted_through_seq,"
                    "first_retained_seq,expired_payload_count,compacted_event_count,completed_at_utc) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        checked_partition,
                        run_id,
                        basis_digest,
                        watermark.retention_generation,
                        basis_digest,
                        None if snapshot is None else snapshot.snapshot_id,
                        compacted_through_seq,
                        first_retained_after,
                        expired_payload_count,
                        compacted_event_count,
                        now_text,
                    ),
                )
                _retention_checkpoint("after_checkpoint_insert")
                self._connection.execute("COMMIT")
                return RetentionRunResultV1(
                    partition=checked_partition,
                    run_id=run_id,
                    retention_generation=watermark.retention_generation,
                    compacted_through_seq=compacted_through_seq,
                    first_retained_seq=first_retained_after,
                    expired_payload_count=expired_payload_count,
                    compacted_event_count=compacted_event_count,
                    snapshot=snapshot,
                )
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def record_manifest_bytes(
        self, consumer_group_id: str, *, manifest_bytes: bytes
    ) -> str | DiagnosticV2:
        """Persist one opaque manifest generation without interpreting subscription policy."""

        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                group = validate_identifier(
                    consumer_group_id, field="consumer_group_id"
                )
                if (
                    type(manifest_bytes) is not bytes
                    or not 1 <= len(manifest_bytes) <= 65536
                ):
                    raise ValueError
                generation = _digest(manifest_bytes)
            except (HiveValidationError, ValueError):
                return self._schema_error()
            try:
                now = _utc_now(self._clock)
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    "INSERT INTO subscription_manifests(consumer_group_id,generation,manifest_bytes,"
                    "manifest_size_bytes,created_at_utc) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(consumer_group_id,generation) DO NOTHING",
                    (group, generation, manifest_bytes, len(manifest_bytes), now),
                )
                persisted = self._connection.execute(
                    "SELECT manifest_bytes,manifest_size_bytes FROM subscription_manifests "
                    "WHERE consumer_group_id=? AND generation=?",
                    (group, generation),
                ).fetchone()
                if persisted != (manifest_bytes, len(manifest_bytes)):
                    raise ValueError
                self._connection.execute("COMMIT")
                return generation
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def open_cursor_once(
        self, consumer_group_id: str, partition: str, generation: str
    ) -> int | CursorGapV1 | None | DiagnosticV2:
        """Create a cursor once, or expose its persisted gap without a lease."""

        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                group, checked_partition, checked_generation = (
                    self._validate_group_partition_generation(
                        consumer_group_id, partition, generation
                    )
                )
            except (HiveBusContractError, HiveValidationError, ValueError):
                return self._schema_error()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                manifest = self._connection.execute(
                    "SELECT 1 FROM subscription_manifests WHERE consumer_group_id=? AND generation=?",
                    (group, checked_generation),
                ).fetchone()
                if manifest is None:
                    self._connection.execute("ROLLBACK")
                    return self._subscription_stale()
                partition_row = self._connection.execute(
                    "SELECT 1 FROM partitions WHERE partition=?", (checked_partition,)
                ).fetchone()
                if partition_row is None:
                    self._connection.execute("ROLLBACK")
                    return None
                cursor = self._connection.execute(
                    "SELECT generation,acked_seq,gap_snapshot_id,gap_from_seq,gap_through_seq "
                    "FROM cursors WHERE consumer_group_id=? AND partition=?",
                    (group, checked_partition),
                ).fetchone()
                if cursor is not None:
                    if (
                        cursor[0] != checked_generation
                        or type(cursor[1]) is not int
                        or cursor[1] < 0
                    ):
                        self._connection.execute("ROLLBACK")
                        return self._subscription_stale()
                    if cursor[2:] != (None, None, None):
                        gap = self._cursor_gap_from_values(
                            partition=checked_partition,
                            acked_seq=cursor[1],
                            snapshot_id=cursor[2],
                            gap_from_seq=cursor[3],
                            gap_through_seq=cursor[4],
                        )
                        if gap is None:
                            raise ValueError
                        self._connection.execute("ROLLBACK")
                        return gap
                    self._connection.execute("ROLLBACK")
                    return cursor[1]
                now = _utc_now(self._clock)
                self._connection.execute(
                    "INSERT INTO cursors(consumer_group_id,partition,generation,acked_seq,gap_snapshot_id,"
                    "gap_from_seq,gap_through_seq,updated_at_utc) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        group,
                        checked_partition,
                        checked_generation,
                        0,
                        None,
                        None,
                        None,
                        now,
                    ),
                )
                self._connection.execute("COMMIT")
                return 0
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def poll_headers(
        self, consumer_group_id: str, partition: str, generation: str
    ) -> DeliveryBatchV1 | CursorGapV1 | None | DiagnosticV2:
        """Lease the next headers unless a persisted snapshot gap must be ACKed."""

        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                group, checked_partition, checked_generation = (
                    self._validate_group_partition_generation(
                        consumer_group_id, partition, generation
                    )
                )
            except (HiveBusContractError, HiveValidationError, ValueError):
                return self._schema_error()
            try:
                now = _utc_datetime(self._clock)
                now_text = _format_utc(now)
                self._connection.execute("BEGIN IMMEDIATE")
                cursor = self._cursor_generation_matches(
                    group, checked_partition, checked_generation
                )
                if cursor is None:
                    self._connection.execute("ROLLBACK")
                    return self._subscription_stale()
                gap_row = self._connection.execute(
                    "SELECT gap_snapshot_id,gap_from_seq,gap_through_seq FROM cursors "
                    "WHERE consumer_group_id=? AND partition=? AND generation=?",
                    (group, checked_partition, checked_generation),
                ).fetchone()
                if not isinstance(gap_row, tuple) or len(gap_row) != 3:
                    raise ValueError
                if gap_row != (None, None, None):
                    gap = self._cursor_gap_from_values(
                        partition=checked_partition,
                        acked_seq=cursor[0],
                        snapshot_id=gap_row[0],
                        gap_from_seq=gap_row[1],
                        gap_through_seq=gap_row[2],
                    )
                    if gap is None:
                        raise ValueError
                    self._connection.execute("ROLLBACK")
                    return gap
                expired_lease_materialized = False
                active = self._connection.execute(
                    "SELECT delivery_token,expires_at_utc FROM delivery_leases "
                    "WHERE consumer_group_id=? AND partition=?",
                    (group, checked_partition),
                ).fetchone()
                if active is not None:
                    if type(active[0]) is not str:
                        raise ValueError
                    expires_at = _stored_utc(active[1])
                    if now < expires_at:
                        self._connection.execute("ROLLBACK")
                        return self._delivery_active(
                            self._remaining_seconds(
                                expires_at, now, maximum=_LEASE_SECONDS
                            )
                        )
                    terminal_expiry = self._materialize_expired_lease(
                        group, checked_partition, active[0], now
                    )
                    expired_lease_materialized = True
                    if terminal_expiry:
                        self._connection.execute("COMMIT")
                        return self._poison()
                first_open_seq = cursor[0] + 1
                rows = self._connection.execute(
                    "SELECT partition_seq,header_bytes,header_digest FROM events "
                    "WHERE partition=? AND partition_seq>=? ORDER BY partition_seq LIMIT ?",
                    (checked_partition, first_open_seq, _MAX_DELIVERY_HEADERS),
                ).fetchall()
                headers: list[bytes] = []
                expected_seq = first_open_seq
                total_bytes = 0
                for sequence, header, header_digest in rows:
                    if (
                        type(sequence) is not int
                        or sequence != expected_seq
                        or type(header) is not bytes
                        or not 1 <= len(header) <= _MAX_HEADER_BYTES
                        or type(header_digest) is not str
                        or _digest(header) != header_digest
                    ):
                        raise ValueError
                    if total_bytes + len(header) > _MAX_DELIVERY_HEADER_BYTES:
                        break
                    effect = self._connection.execute(
                        "SELECT state,retry_not_before_utc FROM consumer_effects "
                        "WHERE consumer_group_id=? AND partition=? AND partition_seq=? AND generation=?",
                        (group, checked_partition, sequence, checked_generation),
                    ).fetchone()
                    if effect is not None:
                        if type(effect[0]) is not str or effect[0] not in {
                            "pending",
                            "committed",
                            "dead_lettered",
                        }:
                            raise ValueError
                        if effect[0] == "pending" and effect[1] is not None:
                            retry_at = _stored_utc(effect[1])
                            if now < retry_at:
                                if headers:
                                    break
                                self._connection.execute(
                                    "COMMIT"
                                    if expired_lease_materialized
                                    else "ROLLBACK"
                                )
                                return self._delivery_backoff(
                                    self._remaining_seconds(
                                        retry_at, now, maximum=_BACKOFF_SECONDS[-1]
                                    )
                                )
                    headers.append(header)
                    total_bytes += len(header)
                    expected_seq += 1
                if not headers:
                    self._connection.execute(
                        "COMMIT" if expired_lease_materialized else "ROLLBACK"
                    )
                    return None
                raw_token = "lease-v1-" + secrets.token_urlsafe(32)
                if _LEASE_TOKEN_RE.fullmatch(raw_token) is None:
                    raise ValueError
                token_digest = _digest(raw_token.encode("ascii"))
                scan_through_seq = first_open_seq + len(headers) - 1
                expires_at = now + timedelta(seconds=_LEASE_SECONDS)
                self._connection.execute(
                    "INSERT INTO delivery_leases(consumer_group_id,partition,generation,delivery_token,"
                    "from_seq,scan_through_seq,leased_at_utc,expires_at_utc,created_monotonic) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        group,
                        checked_partition,
                        checked_generation,
                        token_digest,
                        first_open_seq,
                        scan_through_seq,
                        now_text,
                        _format_utc(expires_at),
                        self._clock.monotonic(),
                    ),
                )
                self._connection.execute("COMMIT")
                return DeliveryBatchV1(
                    delivery_token=raw_token,
                    generation=checked_generation,
                    from_seq=first_open_seq,
                    scan_through_seq=scan_through_seq,
                    headers=tuple(headers),
                )
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (OSError, ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def ack_cursor_gap(
        self,
        consumer_group_id: str,
        partition: str,
        generation: str,
        snapshot: SnapshotAnchorV1,
    ) -> int | DiagnosticV2:
        """ACK exactly one persisted cursor gap without acquiring a delivery lease."""

        try:
            group, checked_partition, checked_generation = (
                self._validate_group_partition_generation(
                    consumer_group_id, partition, generation
                )
            )
            checked_snapshot = self._validate_snapshot_anchor(snapshot)
        except (HiveBusContractError, HiveValidationError, ValueError):
            return self._schema_error()
        if checked_snapshot.partition != checked_partition:
            return self._cursor_conflict()
        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                cursor = self._connection.execute(
                    "SELECT generation,acked_seq,gap_snapshot_id,gap_from_seq,gap_through_seq "
                    "FROM cursors WHERE consumer_group_id=? AND partition=?",
                    (group, checked_partition),
                ).fetchone()
                if cursor is None or cursor[0] != checked_generation:
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                gap = self._cursor_gap_from_values(
                    partition=checked_partition,
                    acked_seq=cursor[1],
                    snapshot_id=cursor[2],
                    gap_from_seq=cursor[3],
                    gap_through_seq=cursor[4],
                )
                if gap is None:
                    if cursor[2:] == (None, None, None):
                        self._connection.execute("ROLLBACK")
                        return self._cursor_conflict()
                    raise ValueError
                if gap.snapshot != checked_snapshot:
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                now = _utc_now(self._clock)
                updated = self._connection.execute(
                    "UPDATE cursors SET acked_seq=?,gap_snapshot_id=NULL,gap_from_seq=NULL,"
                    "gap_through_seq=NULL,updated_at_utc=? WHERE consumer_group_id=? AND partition=? "
                    "AND generation=? AND acked_seq=? AND gap_snapshot_id=? AND gap_from_seq=? "
                    "AND gap_through_seq=?",
                    (
                        gap.gap_through_seq,
                        now,
                        group,
                        checked_partition,
                        checked_generation,
                        cursor[1],
                        gap.snapshot.snapshot_id,
                        gap.gap_from_seq,
                        gap.gap_through_seq,
                    ),
                )
                if updated.rowcount != 1:
                    raise ValueError
                self._connection.execute("COMMIT")
                return gap.gap_through_seq
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def begin_effect(
        self,
        consumer_group_id: str,
        partition: str,
        generation: str,
        delivery_token: str,
        event_id: str,
        *,
        effect_digest: str,
    ) -> EffectBeginResultV1 | DiagnosticV2:
        """Durably bind one caller-owned effect digest before external application."""

        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                group, checked_partition, checked_generation = (
                    self._validate_group_partition_generation(
                        consumer_group_id, partition, generation
                    )
                )
                raw_token = self._validate_delivery_token(delivery_token)
                checked_event_id = self._validate_digest(event_id)
                checked_effect_digest = self._validate_digest(effect_digest)
            except (HiveBusContractError, HiveValidationError, ValueError):
                return self._schema_error()
            try:
                now = _utc_datetime(self._clock)
                now_text = _format_utc(now)
                token_digest = _digest(raw_token.encode("ascii"))
                self._connection.execute("BEGIN IMMEDIATE")
                if (
                    self._cursor_generation_matches(
                        group, checked_partition, checked_generation
                    )
                    is None
                ):
                    self._connection.execute("ROLLBACK")
                    return self._subscription_stale()
                lease = self._valid_current_lease(
                    group, checked_partition, checked_generation, token_digest, now
                )
                if lease is None:
                    self._connection.execute("ROLLBACK")
                    return self._delivery_stale()
                event = self._event_in_lease(
                    group,
                    checked_partition,
                    checked_event_id,
                    lease[0],
                    lease[1],
                )
                if event is None:
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                if not self._earlier_lease_effects_are_settled(
                    group,
                    checked_partition,
                    checked_generation,
                    lease[0],
                    event[0],
                ):
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                persisted = self._connection.execute(
                    "SELECT generation,state,effect_digest,attempt_count,retry_not_before_utc,lease_token "
                    "FROM consumer_effects WHERE consumer_group_id=? AND event_id=?",
                    (group, checked_event_id),
                ).fetchone()
                if persisted is None:
                    self._connection.execute(
                        "INSERT INTO consumer_effects(consumer_group_id,event_id,partition,partition_seq,"
                        "generation,state,effect_digest,attempt_count,retry_not_before_utc,lease_token,"
                        "lease_expires_at_utc,last_error_code,updated_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            group,
                            checked_event_id,
                            checked_partition,
                            event[0],
                            checked_generation,
                            "pending",
                            checked_effect_digest,
                            0,
                            None,
                            token_digest,
                            _format_utc(lease[2]),
                            None,
                            now_text,
                        ),
                    )
                    self._connection.execute("COMMIT")
                    return EffectBeginResultV1("apply", 0)
                if (
                    persisted[0] != checked_generation
                    or type(persisted[1]) is not str
                    or type(persisted[2]) is not str
                    or type(persisted[3]) is not int
                    or not 0 <= persisted[3] <= 5
                    or (persisted[5] is not None and type(persisted[5]) is not str)
                ):
                    raise ValueError
                if persisted[2] != checked_effect_digest:
                    self._connection.execute("ROLLBACK")
                    return self._effect_conflict()
                if persisted[1] == "committed":
                    self._connection.execute("ROLLBACK")
                    return EffectBeginResultV1("committed", persisted[3])
                if persisted[1] == "dead_lettered":
                    self._connection.execute("ROLLBACK")
                    return EffectBeginResultV1("dead_lettered", persisted[3])
                if persisted[1] != "pending":
                    raise ValueError
                if persisted[5] == token_digest:
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                if persisted[4] is not None:
                    retry_at = _stored_utc(persisted[4])
                    if now < retry_at:
                        self._connection.execute("ROLLBACK")
                        return self._delivery_backoff(
                            self._remaining_seconds(
                                retry_at, now, maximum=_BACKOFF_SECONDS[-1]
                            )
                        )
                changed = self._connection.execute(
                    "UPDATE consumer_effects SET retry_not_before_utc=NULL,lease_token=?,"
                    "lease_expires_at_utc=?,updated_at_utc=? WHERE consumer_group_id=? AND event_id=? "
                    "AND state='pending' AND effect_digest=? AND attempt_count=?",
                    (
                        token_digest,
                        _format_utc(lease[2]),
                        now_text,
                        group,
                        checked_event_id,
                        checked_effect_digest,
                        persisted[3],
                    ),
                ).rowcount
                if changed != 1:
                    raise sqlite3.DatabaseError
                self._connection.execute("COMMIT")
                return EffectBeginResultV1("apply", persisted[3])
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def commit_effect(
        self,
        consumer_group_id: str,
        partition: str,
        generation: str,
        delivery_token: str,
        event_id: str,
        *,
        effect_digest: str,
    ) -> None | DiagnosticV2:
        """Atomically mark only the current matching pending journal committed."""

        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                group, checked_partition, checked_generation = (
                    self._validate_group_partition_generation(
                        consumer_group_id, partition, generation
                    )
                )
                raw_token = self._validate_delivery_token(delivery_token)
                checked_event_id = self._validate_digest(event_id)
                checked_effect_digest = self._validate_digest(effect_digest)
            except (HiveBusContractError, HiveValidationError, ValueError):
                return self._schema_error()
            try:
                now = _utc_datetime(self._clock)
                now_text = _format_utc(now)
                token_digest = _digest(raw_token.encode("ascii"))
                self._connection.execute("BEGIN IMMEDIATE")
                if (
                    self._cursor_generation_matches(
                        group, checked_partition, checked_generation
                    )
                    is None
                ):
                    self._connection.execute("ROLLBACK")
                    return self._subscription_stale()
                lease = self._valid_current_lease(
                    group, checked_partition, checked_generation, token_digest, now
                )
                if lease is None:
                    self._connection.execute("ROLLBACK")
                    return self._delivery_stale()
                if (
                    self._event_in_lease(
                        group, checked_partition, checked_event_id, lease[0], lease[1]
                    )
                    is None
                ):
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                effect = self._connection.execute(
                    "SELECT generation,state,effect_digest,lease_token FROM consumer_effects "
                    "WHERE consumer_group_id=? AND event_id=?",
                    (group, checked_event_id),
                ).fetchone()
                if effect is None:
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                if (
                    effect[0] != checked_generation
                    or type(effect[1]) is not str
                    or type(effect[2]) is not str
                ):
                    raise ValueError
                if effect[2] != checked_effect_digest:
                    self._connection.execute("ROLLBACK")
                    return self._effect_conflict()
                if effect[1] == "committed":
                    self._connection.execute("ROLLBACK")
                    return None
                if effect[1] != "pending" or effect[3] != token_digest:
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                changed = self._connection.execute(
                    "UPDATE consumer_effects SET state='committed',retry_not_before_utc=NULL,"
                    "updated_at_utc=? WHERE consumer_group_id=? AND event_id=? AND state='pending' "
                    "AND effect_digest=? AND lease_token=?",
                    (
                        now_text,
                        group,
                        checked_event_id,
                        checked_effect_digest,
                        token_digest,
                    ),
                ).rowcount
                if changed != 1:
                    raise sqlite3.DatabaseError
                self._connection.execute("COMMIT")
                return None
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def fail_effect(
        self,
        consumer_group_id: str,
        partition: str,
        generation: str,
        delivery_token: str,
        event_id: str,
        *,
        effect_digest: str,
        error_code: str,
        error_fingerprint: str,
    ) -> DiagnosticV2:
        """Count one valid pending effect failure and persist bounded retry or DLQ evidence."""

        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                group, checked_partition, checked_generation = (
                    self._validate_group_partition_generation(
                        consumer_group_id, partition, generation
                    )
                )
                raw_token = self._validate_delivery_token(delivery_token)
                checked_event_id = self._validate_digest(event_id)
                checked_effect_digest = self._validate_digest(effect_digest)
                checked_error_code = self._validate_error_code(error_code)
                checked_error_fingerprint = self._validate_digest(error_fingerprint)
            except (HiveBusContractError, HiveValidationError, ValueError):
                return self._schema_error()
            try:
                now = _utc_datetime(self._clock)
                now_text = _format_utc(now)
                token_digest = _digest(raw_token.encode("ascii"))
                self._connection.execute("BEGIN IMMEDIATE")
                if (
                    self._cursor_generation_matches(
                        group, checked_partition, checked_generation
                    )
                    is None
                ):
                    self._connection.execute("ROLLBACK")
                    return self._subscription_stale()
                lease = self._valid_current_lease(
                    group, checked_partition, checked_generation, token_digest, now
                )
                if lease is None:
                    self._connection.execute("ROLLBACK")
                    return self._delivery_stale()
                if (
                    self._event_in_lease(
                        group, checked_partition, checked_event_id, lease[0], lease[1]
                    )
                    is None
                ):
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                effect = self._connection.execute(
                    "SELECT generation,state,effect_digest,attempt_count,lease_token "
                    "FROM consumer_effects WHERE consumer_group_id=? AND event_id=?",
                    (group, checked_event_id),
                ).fetchone()
                if effect is None:
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                if (
                    effect[0] != checked_generation
                    or type(effect[1]) is not str
                    or type(effect[2]) is not str
                    or type(effect[3]) is not int
                    or not 0 <= effect[3] <= 5
                ):
                    raise ValueError
                if effect[2] != checked_effect_digest:
                    self._connection.execute("ROLLBACK")
                    return self._effect_conflict()
                if effect[1] == "dead_lettered":
                    self._connection.execute("ROLLBACK")
                    return self._poison()
                if effect[1] != "pending" or effect[4] != token_digest:
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                next_attempt = effect[3] + 1
                if next_attempt < 5:
                    retry_at = now + timedelta(
                        seconds=_BACKOFF_SECONDS[next_attempt - 1]
                    )
                    changed = self._connection.execute(
                        "UPDATE consumer_effects SET attempt_count=?,retry_not_before_utc=?,"
                        "lease_token=NULL,lease_expires_at_utc=NULL,last_error_code=?,updated_at_utc=? "
                        "WHERE consumer_group_id=? AND event_id=? AND state='pending' AND effect_digest=? "
                        "AND lease_token=? AND attempt_count=?",
                        (
                            next_attempt,
                            _format_utc(retry_at),
                            checked_error_code,
                            now_text,
                            group,
                            checked_event_id,
                            checked_effect_digest,
                            token_digest,
                            effect[3],
                        ),
                    ).rowcount
                    if changed != 1:
                        raise sqlite3.DatabaseError
                    deleted = self._connection.execute(
                        "DELETE FROM delivery_leases WHERE consumer_group_id=? AND partition=? "
                        "AND delivery_token=?",
                        (group, checked_partition, token_digest),
                    ).rowcount
                    if deleted != 1:
                        raise sqlite3.DatabaseError
                    self._connection.execute("COMMIT")
                    return self._delivery_backoff(
                        self._remaining_seconds(
                            retry_at, now, maximum=_BACKOFF_SECONDS[-1]
                        )
                    )
                changed = self._connection.execute(
                    "UPDATE consumer_effects SET state='dead_lettered',attempt_count=5,"
                    "retry_not_before_utc=NULL,last_error_code=?,updated_at_utc=? "
                    "WHERE consumer_group_id=? AND event_id=? AND state='pending' AND effect_digest=? "
                    "AND lease_token=? AND attempt_count=?",
                    (
                        checked_error_code,
                        now_text,
                        group,
                        checked_event_id,
                        checked_effect_digest,
                        token_digest,
                        effect[3],
                    ),
                ).rowcount
                if changed != 1:
                    raise sqlite3.DatabaseError
                self._connection.execute(
                    "INSERT INTO dead_letters(consumer_group_id,event_id,partition,partition_seq,generation,"
                    "attempt_count,error_code,error_fingerprint,created_at_utc) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        group,
                        checked_event_id,
                        checked_partition,
                        self._event_in_lease(
                            group,
                            checked_partition,
                            checked_event_id,
                            lease[0],
                            lease[1],
                        )[0],
                        checked_generation,
                        5,
                        checked_error_code,
                        checked_error_fingerprint,
                        now_text,
                    ),
                )
                self._connection.execute("COMMIT")
                return self._poison()
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def ack(
        self,
        consumer_group_id: str,
        partition: str,
        generation: str,
        delivery_token: str,
        scan_through_seq: int,
    ) -> int | DiagnosticV2:
        """CAS-advance a cursor only after every leased effect is durably ACKable."""

        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            try:
                group, checked_partition, checked_generation = (
                    self._validate_group_partition_generation(
                        consumer_group_id, partition, generation
                    )
                )
                raw_token = self._validate_delivery_token(delivery_token)
                if (
                    type(scan_through_seq) is not int
                    or isinstance(scan_through_seq, bool)
                    or not 1 <= scan_through_seq <= _MAX_SIGNED_SQLITE_INTEGER
                ):
                    raise ValueError
            except (HiveBusContractError, HiveValidationError, ValueError):
                return self._schema_error()
            try:
                now = _utc_datetime(self._clock)
                now_text = _format_utc(now)
                token_digest = _digest(raw_token.encode("ascii"))
                self._connection.execute("BEGIN IMMEDIATE")
                cursor = self._cursor_generation_matches(
                    group, checked_partition, checked_generation
                )
                if cursor is None:
                    self._connection.execute("ROLLBACK")
                    return self._subscription_stale()
                lease = self._valid_current_lease(
                    group, checked_partition, checked_generation, token_digest, now
                )
                if lease is None:
                    self._connection.execute("ROLLBACK")
                    return self._delivery_stale()
                if lease[0] != cursor[0] + 1 or lease[1] != scan_through_seq:
                    self._connection.execute("ROLLBACK")
                    return self._cursor_conflict()
                events = self._connection.execute(
                    "SELECT event_id,partition_seq,event_type FROM events WHERE partition=? "
                    "AND partition_seq BETWEEN ? AND ? ORDER BY partition_seq",
                    (checked_partition, lease[0], lease[1]),
                ).fetchall()
                if len(events) != lease[1] - lease[0] + 1:
                    raise ValueError
                for expected_seq, event in enumerate(events, start=lease[0]):
                    event_id, partition_seq, event_type = event
                    if (
                        type(event_id) is not str
                        or type(partition_seq) is not int
                        or partition_seq != expected_seq
                        or type(event_type) is not str
                        or event_type not in EVENT_TYPE_MATRIX
                    ):
                        raise ValueError
                    effect = self._connection.execute(
                        "SELECT generation,state,attempt_count FROM consumer_effects "
                        "WHERE consumer_group_id=? AND event_id=?",
                        (group, event_id),
                    ).fetchone()
                    if (
                        effect is None
                        or effect[0] != checked_generation
                        or type(effect[1]) is not str
                        or type(effect[2]) is not int
                    ):
                        self._connection.execute("ROLLBACK")
                        return self._cursor_conflict()
                    if effect[1] == "committed":
                        continue
                    if effect[1] != "dead_lettered" or effect[2] != 5:
                        self._connection.execute("ROLLBACK")
                        return self._cursor_conflict()
                    dead_letter = self._connection.execute(
                        "SELECT attempt_count,generation FROM dead_letters "
                        "WHERE consumer_group_id=? AND event_id=?",
                        (group, event_id),
                    ).fetchone()
                    if dead_letter != (5, checked_generation):
                        raise ValueError
                    if (
                        EVENT_TYPE_MATRIX[event_type].urgent
                        or event_type == "artifact.archived"
                    ):
                        self._connection.execute("ROLLBACK")
                        return self._poison()
                changed = self._connection.execute(
                    "UPDATE cursors SET acked_seq=?,updated_at_utc=? WHERE consumer_group_id=? "
                    "AND partition=? AND generation=? AND acked_seq=?",
                    (
                        scan_through_seq,
                        now_text,
                        group,
                        checked_partition,
                        checked_generation,
                        cursor[0],
                    ),
                ).rowcount
                if changed != 1:
                    raise sqlite3.DatabaseError
                deleted = self._connection.execute(
                    "DELETE FROM delivery_leases WHERE consumer_group_id=? AND partition=? "
                    "AND delivery_token=? AND generation=?",
                    (group, checked_partition, token_digest, checked_generation),
                ).rowcount
                if deleted != 1:
                    raise sqlite3.DatabaseError
                self._connection.execute("COMMIT")
                return scan_through_seq
            except sqlite3.OperationalError as exc:
                self._rollback(self._connection)
                return (
                    self._store_busy()
                    if _sqlite_is_busy(exc)
                    else self._store_integrity()
                )
            except (ValueError, sqlite3.DatabaseError):
                self._rollback(self._connection)
                return self._store_integrity()

    def _block_partition(self, partition: str, now: str) -> None:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                "UPDATE partitions SET state='blocked',blocked_code=?,updated_at_utc=? WHERE partition=?",
                ("BUS_E_PARTITION_SEQ_CONFLICT", now, partition),
            )
            self._connection.execute("COMMIT")
        except sqlite3.DatabaseError:
            self._rollback(self._connection)

    def _stored_event(
        self, request: object, event_id: object
    ) -> HiveBusEventV1 | DiagnosticV2:
        row = self._connection.execute(
            "SELECT partition_seq,accepted_at_utc FROM events WHERE event_id=?",
            (event_id,),
        ).fetchone()
        if row is None:
            return diagnostic_for(
                "BUS_E_STORE_INTEGRITY",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )
        try:
            event = create_hive_bus_event_v1(
                request, partition_seq=row[0], accepted_at_utc=row[1]
            )
            if event.event_id != event_id:
                raise HiveBusContractError("BUS_E_SCHEMA")
            return event
        except HiveBusContractError:
            return diagnostic_for(
                "BUS_E_STORE_INTEGRITY",
                severity=DiagnosticSeverityV2.CRITICAL,
                retryable=False,
                retry_after_seconds=None,
                fallback_applied=False,
                requested_choice=None,
                effective_choice=None,
                action="operator_intervention",
                causes=(),
            )

    def read_event_header(self, event_id: str) -> bytes | DiagnosticV2 | None:
        """Return only persisted canonical header bytes after digest verification."""

        with self._lock:
            unusable = self._usable()
            if unusable is not None:
                return unusable
            if type(event_id) is not str or _EVENT_ID_RE.fullmatch(event_id) is None:
                return diagnostic_for(
                    "BUS_E_SCHEMA",
                    severity=DiagnosticSeverityV2.ERROR,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="reject_request",
                    causes=(),
                )
            try:
                row = self._connection.execute(
                    "SELECT header_bytes,header_digest FROM events WHERE event_id=?",
                    (event_id,),
                ).fetchone()
            except sqlite3.OperationalError as exc:
                if not _sqlite_is_busy(exc):
                    return diagnostic_for(
                        "BUS_E_STORE_INTEGRITY",
                        severity=DiagnosticSeverityV2.CRITICAL,
                        retryable=False,
                        retry_after_seconds=None,
                        fallback_applied=False,
                        requested_choice=None,
                        effective_choice=None,
                        action="operator_intervention",
                        causes=(),
                    )
                return diagnostic_for(
                    "BUS_E_STORE_BUSY",
                    severity=DiagnosticSeverityV2.WARNING,
                    retryable=True,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="retry_operation",
                    causes=(),
                )
            except sqlite3.DatabaseError:
                return diagnostic_for(
                    "BUS_E_STORE_INTEGRITY",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            if row is None:
                return None
            header, digest = row
            if (
                type(header) is not bytes
                or len(header) > _MAX_HEADER_BYTES
                or type(digest) is not str
                or _digest(header) != digest
            ):
                return diagnostic_for(
                    "BUS_E_STORE_INTEGRITY",
                    severity=DiagnosticSeverityV2.CRITICAL,
                    retryable=False,
                    retry_after_seconds=None,
                    fallback_applied=False,
                    requested_choice=None,
                    effective_choice=None,
                    action="operator_intervention",
                    causes=(),
                )
            return header


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


__all__ = ["HiveBusStore"]
