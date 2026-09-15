"""Fail-closed, local Gen-1 persistence for Hive BUS-S1 Slice A."""

from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
from threading import RLock
from typing import Final

from the_hive.diagnostics import DiagnosticSeverityV2, DiagnosticV2, diagnostic_for
from the_hive.hive.bus_types import (
    HiveBusContractError,
    HiveBusEventV1,
    MAX_PAYLOAD_BYTES,
    canonical_json_bytes,
    create_hive_bus_event_v1,
    event_id_for_publish_request,
    serialize_hive_bus_event_v1,
)
from the_hive.hive.types import Clock


_DATABASE_NAME: Final = "bus_store.sqlite3"
_OWNER_NAME: Final = "bus_store.owner.lock"
_SCHEMA_NAME: Final = "hive_bus_store"
_GENERATION: Final = 1
_MAX_HEADER_BYTES: Final = 4096
_EVENT_ID_RE: Final = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)

_TABLE_DDL: Final = (
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
_INDEX_DDL: Final = (
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
_SCHEMA_DIGEST: Final = "sha256:577d018653c16b9bf92590c1e68931f2ec972ad84a7e35c6f644f4f08aa508ba"
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


def _utc_now(clock: Clock) -> str:
    value = clock.wall_time_utc()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError
    utc = value.astimezone(timezone.utc)
    result = utc.strftime("%Y-%m-%dT%H:%M:%S")
    if utc.microsecond:
        result += "." + f"{utc.microsecond:06d}".rstrip("0")
    return result + "Z"


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
    """The sole public BUS-S1/A store, with one locally-owned SQLite connection."""

    @classmethod
    def initialize(cls, state_root: Path, *, clock: Clock) -> HiveBusStore | DiagnosticV2:
        """Create only a missing final private root and initialize or verify Gen-1."""

        return cls._open_store(state_root, clock=clock, create=True)

    @classmethod
    def open(cls, state_root: Path, *, clock: Clock) -> HiveBusStore | DiagnosticV2:
        """Open an existing complete Gen-1 store without creating any filesystem node."""

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
            cls._configure(connection)
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
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
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
                if (
                    not _is_local_filesystem(root_fd)
                    or not _is_trusted_directory(os.fstat(root_fd))
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
                fd = os.open(_OWNER_NAME, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root_fd)
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
            or any(actual_tables[name] != statement for name, statement in expected_tables.items())
            or any(actual_indexes[name] != statement for name, statement in expected_indexes.items())
            or any(kind not in {"table", "index"} for kind, _name, _sql in explicit_entries)
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
                "BUS_E_STORE_SCHEMA_TOO_OLD",
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
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
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
                result = self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
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

    def append(
        self, request: object, *, payload_bytes: bytes | None
    ) -> HiveBusEventV1 | DiagnosticV2:
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
                    return diagnostic_for("BUS_E_CANONICALIZATION", severity=DiagnosticSeverityV2.ERROR, retryable=False, retry_after_seconds=None, fallback_applied=False, requested_choice=None, effective_choice=None, action="reject_publish", causes=())
                if exc.code == "BUS_E_TOPIC_INVALID":
                    return diagnostic_for("BUS_E_TOPIC_INVALID", severity=DiagnosticSeverityV2.ERROR, retryable=False, retry_after_seconds=None, fallback_applied=False, requested_choice=None, effective_choice=None, action="reject_publish", causes=())
                if exc.code == "BUS_E_EVENT_TOO_LARGE":
                    return diagnostic_for("BUS_E_EVENT_TOO_LARGE", severity=DiagnosticSeverityV2.ERROR, retryable=False, retry_after_seconds=None, fallback_applied=False, requested_choice=None, effective_choice=None, action="reject_publish", causes=())
                if exc.code == "BUS_E_SECRET_CLASSIFICATION":
                    return diagnostic_for("BUS_E_SECRET_CLASSIFICATION", severity=DiagnosticSeverityV2.ERROR, retryable=False, retry_after_seconds=None, fallback_applied=False, requested_choice=None, effective_choice=None, action="reject_publish", causes=())
                if exc.code == "BUS_E_ACL_DENIED":
                    return diagnostic_for("BUS_E_ACL_DENIED", severity=DiagnosticSeverityV2.ERROR, retryable=False, retry_after_seconds=None, fallback_applied=False, requested_choice=None, effective_choice=None, action="reject_publish", causes=())
                if exc.code == "BUS_E_REPO_SCOPE":
                    return diagnostic_for("BUS_E_REPO_SCOPE", severity=DiagnosticSeverityV2.ERROR, retryable=False, retry_after_seconds=None, fallback_applied=False, requested_choice=None, effective_choice=None, action="reject_publish", causes=())
                return diagnostic_for("BUS_E_SCHEMA", severity=DiagnosticSeverityV2.ERROR, retryable=False, retry_after_seconds=None, fallback_applied=False, requested_choice=None, effective_choice=None, action="reject_publish", causes=())
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
                if payload.size_bytes > MAX_PAYLOAD_BYTES:
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
                if len(payload_bytes) != payload.size_bytes or len(payload_bytes) > MAX_PAYLOAD_BYTES:
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
                    "SELECT event_id,canonical_request_digest FROM idempotency WHERE idempotency_key=?",
                    (probe.idempotency_key,),
                ).fetchone()
                if retry is not None:
                    self._connection.execute("ROLLBACK")
                    if retry[1] != request_digest:
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
                    return self._stored_event(request, retry[0])
                now = _utc_now(self._clock)
                partition_row = self._connection.execute(
                    "SELECT next_seq,state FROM partitions WHERE partition=?", (probe.partition,)
                ).fetchone()
                if partition_row is None:
                    partition_seq = 1
                    self._connection.execute(
                        "INSERT INTO partitions(partition,next_seq,first_retained_seq,state,blocked_code,created_at_utc,updated_at_utc) VALUES(?,?,?,?,?,?,?)",
                        (probe.partition, 2, 1, "active", None, now, now),
                    )
                else:
                    if partition_row[1] != "active":
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
                    "INSERT INTO idempotency(idempotency_key,event_id,canonical_request_digest,created_at_utc) VALUES(?,?,?,?)",
                    (event.idempotency_key, event.event_id, request_digest, now),
                )
                self._connection.execute("COMMIT")
                return event
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

    def _stored_event(self, request: object, event_id: object) -> HiveBusEventV1 | DiagnosticV2:
        row = self._connection.execute(
            "SELECT partition_seq,accepted_at_utc FROM events WHERE event_id=?", (event_id,)
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
                    "SELECT header_bytes,header_digest FROM events WHERE event_id=?", (event_id,)
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
