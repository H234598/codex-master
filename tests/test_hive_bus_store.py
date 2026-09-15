"""Focused Gen-1 contract tests for the closed BUS-S1 Slice-A store."""

from __future__ import annotations

from datetime import datetime, timezone
import ast
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import tempfile

import pytest

from the_hive.diagnostics import DiagnosticSeverityV2, DiagnosticV2
from the_hive.hive.bus_types import canonical_json_bytes, serialize_hive_bus_event_v1
from the_hive.hive.bus_store import HiveBusStore
from the_hive.hive import bus_store


EXPECTED_TABLE_DDL = (
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
EXPECTED_INDEX_DDL = (
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
EXPECTED_MANIFEST = {
    "schema_name": "hive_bus_store",
    "generation": 1,
    "tables": list(EXPECTED_TABLE_DDL),
    "indexes": list(EXPECTED_INDEX_DDL),
    "pragmas": {
        "foreign_keys": 1,
        "journal_mode": "wal",
        "synchronous": "FULL",
        "busy_timeout": 5000,
        "wal_autocheckpoint": 1000,
    },
}
EXPECTED_SCHEMA_DIGEST = "sha256:577d018653c16b9bf92590c1e68931f2ec972ad84a7e35c6f644f4f08aa508ba"


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 15, 10, 11, 12, 345000, tzinfo=timezone.utc)

    def wall_time_utc(self) -> datetime:
        return self.now

    def monotonic(self) -> float:
        return 123.5


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _request(
    *,
    idempotency_suffix: str = "0",
    producer_seq: int = 1,
    payload_kind: str = "inline",
    payload_bytes: bytes = b"payload",
) -> dict[str, object]:
    event_type = "result.proposed" if payload_kind in {"blob", "artifact"} else "assignment.created"
    payload_digest = _digest(payload_bytes)
    reference = f"{payload_kind}:{payload_digest}"
    if payload_kind == "artifact":
        reference = f"artifact:artifact-1@{payload_digest}"
    return {
        "schema_version": 1,
        "event_type": event_type,
        "partition": "repo/repo-1/task/task-1",
        "idempotency_key": "idempotency-v1-" + (idempotency_suffix * 32),
        "producer_principal_id": "producer-principal-v1-0123456789abcdef0123456789abcdef",
        "producer_session_id": "producer-session-v1-0123456789abcdef0123456789abcdef",
        "producer_epoch": 1,
        "producer_seq": producer_seq,
        "repo_id": "repo-1",
        "topic_id": None,
        "workpackage_id": "task-1",
        "correlation_id": "correlation-v1-0123456789abcdef0123456789abcdef",
        "causation_ids": [],
        "authority": {
            "grant_id": "authority-grant-v1-0123456789abcdef0123456789abcdef",
            "scope_digest": _digest(b"scope"),
            "principal_version": 1,
        },
        "classification": "internal",
        "payload": {
            "kind": payload_kind,
            "digest": payload_digest,
            "ref": reference,
            "size_bytes": len(payload_bytes),
        },
        "retention_class": "work",
        "created_at_utc": "2026-09-15T10:00:00Z",
    }


def _diagnostic(value: object, code: str, severity: DiagnosticSeverityV2) -> None:
    assert isinstance(value, DiagnosticV2)
    assert value.code == code
    assert value.severity is severity
    assert value.retry_after_seconds is None
    assert value.fallback_applied is False
    assert value.requested_choice is None
    assert value.effective_choice is None
    assert value.causes == ()


def _store(root: Path, clock: FakeClock) -> HiveBusStore:
    result = HiveBusStore.initialize(root, clock=clock)
    assert isinstance(result, HiveBusStore)
    return result


@pytest.fixture
def secure_tmp_path() -> Path:
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
        yield Path(temporary)


def test_foundation_initializes_exact_manifest_and_pragmas(secure_tmp_path: Path) -> None:
    root = secure_tmp_path / "bus-state"
    store = _store(root, FakeClock())
    try:
        expected_digest = "sha256:" + hashlib.sha256(
            canonical_json_bytes(EXPECTED_MANIFEST)
        ).hexdigest()
        assert expected_digest == EXPECTED_SCHEMA_DIGEST
        assert len(EXPECTED_TABLE_DDL) == 14
        assert len(EXPECTED_INDEX_DDL) == 9
        assert all(
            statement.isascii()
            and statement == statement.strip()
            and ";" not in statement
            for statement in (*EXPECTED_TABLE_DDL, *EXPECTED_INDEX_DDL)
        )

        database = root / "bus_store.sqlite3"
        owner = root / "bus_store.owner.lock"
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        for path in (
            database,
            owner,
            root / "bus_store.sqlite3-wal",
            root / "bus_store.sqlite3-shm",
        ):
            info = path.stat()
            assert stat.S_ISREG(info.st_mode)
            assert info.st_uid == os.geteuid()
            assert info.st_nlink == 1
            assert stat.S_IMODE(info.st_mode) == 0o600
        schema = dict(
            store._connection.execute(  # noqa: SLF001 - verifies persisted DDL bytes.
                "SELECT name, sql FROM sqlite_schema "
                "WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%'"
            )
        )
        assert {name for name in schema if name in {sql.split()[2] for sql in EXPECTED_TABLE_DDL}} == {
            sql.split()[2] for sql in EXPECTED_TABLE_DDL
        }
        for statement in (*EXPECTED_TABLE_DDL, *EXPECTED_INDEX_DDL):
            assert schema[statement.split()[2 if statement.startswith("CREATE TABLE") else 2]] == statement
        assert store._connection.execute(  # noqa: SLF001 - verifies independent manifest gold.
            "SELECT schema_name,generation,schema_digest FROM bus_store_meta"
        ).fetchall() == [("hive_bus_store", 1, EXPECTED_SCHEMA_DIGEST)]
        assert store._connection.execute("PRAGMA foreign_keys").fetchone() == (1,)  # noqa: SLF001
        assert store._connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)  # noqa: SLF001
        assert store._connection.execute("PRAGMA synchronous").fetchone() == (2,)  # noqa: SLF001
        assert store._connection.execute("PRAGMA busy_timeout").fetchone() == (5000,)  # noqa: SLF001
        assert store._connection.execute("PRAGMA wal_autocheckpoint").fetchone() == (1000,)  # noqa: SLF001
    finally:
        assert store.close() is None


def test_open_never_creates_and_schema_is_fail_closed(secure_tmp_path: Path) -> None:
    clock = FakeClock()
    missing = secure_tmp_path / "missing"
    result = HiveBusStore.open(missing, clock=clock)
    _diagnostic(result, "BUS_E_STORE_ROOT_UNTRUSTED", DiagnosticSeverityV2.CRITICAL)
    assert not missing.exists()

    root = secure_tmp_path / "bus-state"
    store = _store(root, clock)
    assert store.close() is None
    connection = sqlite3.connect(root / "bus_store.sqlite3")
    try:
        connection.execute("UPDATE bus_store_meta SET generation = 2")
        connection.commit()
    finally:
        connection.close()
    result = HiveBusStore.initialize(root, clock=clock)
    _diagnostic(result, "BUS_E_STORE_SCHEMA_TOO_NEW", DiagnosticSeverityV2.CRITICAL)


def test_initialize_rejects_an_existing_empty_database_without_reinitializing(
    secure_tmp_path: Path,
) -> None:
    root = secure_tmp_path / "bus-state"
    root.mkdir(mode=0o700)
    database = root / "bus_store.sqlite3"
    sqlite3.connect(database).close()
    database.chmod(0o600)
    owner = root / "bus_store.owner.lock"
    owner.write_bytes(b"")
    owner.chmod(0o600)

    result = HiveBusStore.initialize(root, clock=FakeClock())

    _diagnostic(result, "BUS_E_STORE_SCHEMA_UNKNOWN", DiagnosticSeverityV2.CRITICAL)
    connection = sqlite3.connect(database)
    try:
        assert connection.execute(
            "SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall() == []
    finally:
        connection.close()


def test_open_with_missing_wal_or_shm_is_noncreating_and_fail_closed(
    secure_tmp_path: Path,
) -> None:
    root = secure_tmp_path / "bus-state"
    clock = FakeClock()
    store = _store(root, clock)
    assert store.close() is None
    for suffix in ("-wal", "-shm"):
        path = root / f"bus_store.sqlite3{suffix}"
        if path.exists():
            path.unlink()
    before = {path.name for path in root.iterdir()}

    result = HiveBusStore.open(root, clock=clock)

    _diagnostic(result, "BUS_E_STORE_FILE_UNTRUSTED", DiagnosticSeverityV2.CRITICAL)
    assert {path.name for path in root.iterdir()} == before


@pytest.mark.parametrize("filesystem_magic", (0x6969, 0x517B, 0xFF534D42))
def test_network_filesystems_are_rejected_without_mounting(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filesystem_magic: int,
) -> None:
    monkeypatch.setattr(
        "the_hive.hive.bus_store._filesystem_type",
        lambda _descriptor: filesystem_magic,
    )

    result = HiveBusStore.initialize(secure_tmp_path / "network-state", clock=FakeClock())

    _diagnostic(result, "BUS_E_STORE_ROOT_UNTRUSTED", DiagnosticSeverityV2.CRITICAL)
    assert not (secure_tmp_path / "network-state").exists()


def test_linux_fstatfs_probe_masks_the_linux_filesystem_magic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fstatfs(_descriptor: int, pointer: object) -> int:
        pointer._obj.f_type = 0xFF534D42  # type: ignore[attr-defined]
        return 0

    monkeypatch.setattr(bus_store, "_FSTATFS", fstatfs)
    assert bus_store._filesystem_type(7) == 0xFF534D42
    monkeypatch.setattr(bus_store, "_FSTATFS", lambda _descriptor, _pointer: -1)
    assert bus_store._filesystem_type(7) is None


def test_filesystem_owner_and_closed_lifecycle_are_fail_closed(secure_tmp_path: Path) -> None:
    clock = FakeClock()
    relative = HiveBusStore.initialize(Path("relative"), clock=clock)
    _diagnostic(relative, "BUS_E_STORE_ROOT_UNTRUSTED", DiagnosticSeverityV2.CRITICAL)

    target = secure_tmp_path / "target"
    target.mkdir(mode=0o700)
    linked = secure_tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    symlinked = HiveBusStore.initialize(linked, clock=clock)
    _diagnostic(symlinked, "BUS_E_STORE_ROOT_UNTRUSTED", DiagnosticSeverityV2.CRITICAL)

    hardlinked_root = secure_tmp_path / "hardlinked-state"
    hardlinked_root.mkdir(mode=0o700)
    source = secure_tmp_path / "owner-source"
    source.write_bytes(b"")
    source.chmod(0o600)
    os.link(source, hardlinked_root / "bus_store.owner.lock")
    hardlinked = HiveBusStore.initialize(hardlinked_root, clock=clock)
    _diagnostic(hardlinked, "BUS_E_STORE_FILE_UNTRUSTED", DiagnosticSeverityV2.CRITICAL)

    root = secure_tmp_path / "bus-state"
    first = _store(root, clock)
    try:
        second = HiveBusStore.open(root, clock=clock)
        _diagnostic(second, "BUS_E_STORE_OWNER_ACTIVE", DiagnosticSeverityV2.WARNING)
    finally:
        assert first.close() is None
    reopened = HiveBusStore.initialize(root, clock=clock)
    assert isinstance(reopened, HiveBusStore)
    assert reopened.close() is None
    closed = reopened.read_event_header("sha256:" + ("0" * 64))
    _diagnostic(closed, "BUS_E_STORE_INTEGRITY", DiagnosticSeverityV2.CRITICAL)


def test_append_is_atomic_idempotent_and_uses_canonical_header(secure_tmp_path: Path) -> None:
    store = _store(secure_tmp_path / "bus-state", FakeClock())
    request = _request()
    try:
        first = store.append(request, payload_bytes=b"payload")
        assert not isinstance(first, DiagnosticV2)
        assert first.partition_seq == 1
        assert first.accepted_at_utc == "2026-09-15T10:11:12.345Z"
        expected_header = canonical_json_bytes(serialize_hive_bus_event_v1(first))
        assert store.read_event_header(first.event_id) == expected_header

        retried = store.append(request, payload_bytes=b"payload")
        assert retried == first
        assert store._connection.execute("SELECT COUNT(*) FROM events").fetchone() == (1,)  # noqa: SLF001
        assert store._connection.execute("SELECT next_seq FROM partitions").fetchone() == (2,)  # noqa: SLF001
    finally:
        assert store.close() is None


def test_append_rejects_payload_and_sequence_conflicts_without_writing(secure_tmp_path: Path) -> None:
    store = _store(secure_tmp_path / "bus-state", FakeClock())
    try:
        mismatch = store.append(_request(), payload_bytes=b"different")
        _diagnostic(mismatch, "BUS_E_PAYLOAD_DIGEST", DiagnosticSeverityV2.ERROR)
        artifact_with_bytes = store.append(
            _request(payload_kind="artifact"), payload_bytes=b"payload"
        )
        _diagnostic(artifact_with_bytes, "BUS_E_SCHEMA", DiagnosticSeverityV2.ERROR)

        assert not isinstance(store.append(_request(), payload_bytes=b"payload"), DiagnosticV2)
        artifact = store.append(
            _request(
                idempotency_suffix="3", producer_seq=2, payload_kind="artifact"
            ),
            payload_bytes=None,
        )
        assert not isinstance(artifact, DiagnosticV2)
        assert store._connection.execute(  # noqa: SLF001 - verifies no artifact read.
            "SELECT body,body_state FROM payloads WHERE kind='artifact'"
        ).fetchone() == (None, "reference")
        conflict = store.append(
            _request(idempotency_suffix="1", producer_seq=1), payload_bytes=b"payload"
        )
        _diagnostic(conflict, "BUS_E_PRODUCER_SEQ_REGRESSION", DiagnosticSeverityV2.ERROR)
        gap = store.append(
            _request(idempotency_suffix="2", producer_seq=4), payload_bytes=b"payload"
        )
        _diagnostic(gap, "BUS_E_PRODUCER_SEQ_GAP", DiagnosticSeverityV2.ERROR)
        incompatible = store.append(
            _request() | {"created_at_utc": "2026-09-15T10:00:01Z"},
            payload_bytes=b"payload",
        )
        _diagnostic(incompatible, "BUS_E_IDEMPOTENCY_CONFLICT", DiagnosticSeverityV2.ERROR)
    finally:
        assert store.close() is None


def test_large_artifact_is_rejected_before_partition_mutation(secure_tmp_path: Path) -> None:
    store = _store(secure_tmp_path / "bus-state", FakeClock())
    request = _request(payload_kind="artifact")
    payload = request["payload"]
    assert isinstance(payload, dict)
    request["payload"] = payload | {"size_bytes": 1048577}
    try:
        result = store.append(request, payload_bytes=None)

        _diagnostic(result, "BUS_E_EVENT_TOO_LARGE", DiagnosticSeverityV2.ERROR)
        assert isinstance(result, DiagnosticV2)
        assert result.retryable is False
        assert result.action == "reject_publish"
        assert store._connection.execute("SELECT COUNT(*) FROM partitions").fetchone() == (0,)  # noqa: SLF001
    finally:
        assert store.close() is None


def test_open_recovery_and_header_read_fail_closed_on_drift(secure_tmp_path: Path) -> None:
    root = secure_tmp_path / "bus-state"
    clock = FakeClock()
    store = _store(root, clock)
    event = store.append(_request(), payload_bytes=b"payload")
    assert not isinstance(event, DiagnosticV2)
    keeper = sqlite3.connect(root / "bus_store.sqlite3")
    keeper.execute("BEGIN")
    keeper.execute("SELECT event_id FROM events").fetchone()
    assert isinstance(store.close(), DiagnosticV2)

    reopened = HiveBusStore.open(root, clock=clock)
    assert isinstance(reopened, HiveBusStore)
    try:
        invalid = reopened.read_event_header("not-an-event-id")
        _diagnostic(invalid, "BUS_E_SCHEMA", DiagnosticSeverityV2.ERROR)
        assert reopened.read_event_header("sha256:" + ("0" * 64)) is None
    finally:
        assert isinstance(reopened.close(), DiagnosticV2)
    keeper.execute("ROLLBACK")
    keeper.execute("UPDATE events SET header_digest = ?", (_digest(b"wrong"),))
    keeper.commit()
    keeper.execute("BEGIN")
    keeper.execute("SELECT event_id FROM events").fetchone()

    reopened = HiveBusStore.open(root, clock=clock)
    assert isinstance(reopened, HiveBusStore)
    try:
        drift = reopened.read_event_header(event.event_id)
        _diagnostic(drift, "BUS_E_STORE_INTEGRITY", DiagnosticSeverityV2.CRITICAL)
    finally:
        assert isinstance(reopened.close(), DiagnosticV2)
        keeper.close()


def test_close_checkpoint_warning_is_idempotent(secure_tmp_path: Path) -> None:
    class CheckpointCursor:
        def fetchone(self) -> tuple[int, int, int]:
            return (1, 0, 0)

    class CheckpointConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.connection = connection

        def execute(self, statement: str, parameters: object = ()) -> object:
            if statement == "PRAGMA wal_checkpoint(TRUNCATE)":
                return CheckpointCursor()
            return self.connection.execute(statement, parameters)

        def close(self) -> None:
            self.connection.close()

    store = _store(secure_tmp_path / "bus-state", FakeClock())
    store._connection = CheckpointConnection(store._connection)  # type: ignore[assignment]  # noqa: SLF001

    warning = store.close()

    _diagnostic(warning, "BUS_W_CHECKPOINT_INCOMPLETE", DiagnosticSeverityV2.WARNING)
    assert isinstance(warning, DiagnosticV2)
    assert warning.retryable is False
    assert warning.action == "inspect_checkpoint"
    assert store.close() is None


def test_every_store_diagnostic_call_is_direct_and_uses_d135_literals() -> None:
    source = Path("src/the_hive/hive/bus_store.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "diagnostic_for"
    ]
    expected = {
        "BUS_E_STORE_ROOT_UNTRUSTED": ("CRITICAL", False, "operator_intervention"),
        "BUS_E_STORE_FILE_UNTRUSTED": ("CRITICAL", False, "operator_intervention"),
        "BUS_E_STORE_SCHEMA_TOO_OLD": ("CRITICAL", False, "operator_intervention"),
        "BUS_E_STORE_SCHEMA_TOO_NEW": ("CRITICAL", False, "operator_intervention"),
        "BUS_E_STORE_SCHEMA_UNKNOWN": ("CRITICAL", False, "operator_intervention"),
        "BUS_E_STORE_INTEGRITY": ("CRITICAL", False, "operator_intervention"),
        "BUS_E_PARTITION_SEQ_CONFLICT": ("CRITICAL", False, "operator_intervention"),
        "BUS_E_SCHEMA": {
            ("ERROR", False, "reject_publish"),
            ("ERROR", False, "reject_request"),
        },
        "BUS_E_CANONICALIZATION": {("ERROR", False, "reject_publish")},
        "BUS_E_TOPIC_INVALID": {("ERROR", False, "reject_publish")},
        "BUS_E_EVENT_TOO_LARGE": {("ERROR", False, "reject_publish")},
        "BUS_E_SECRET_CLASSIFICATION": {("ERROR", False, "reject_publish")},
        "BUS_E_ACL_DENIED": {("ERROR", False, "reject_publish")},
        "BUS_E_REPO_SCOPE": {("ERROR", False, "reject_publish")},
        "BUS_E_IDEMPOTENCY_CONFLICT": {("ERROR", False, "reject_publish")},
        "BUS_E_PRODUCER_SEQ_GAP": {("ERROR", False, "reject_publish")},
        "BUS_E_PRODUCER_SEQ_REGRESSION": {("ERROR", False, "reject_publish")},
        "BUS_E_PAYLOAD_DIGEST": {("ERROR", False, "reject_publish")},
        "BUS_E_STORE_OWNER_ACTIVE": ("WARNING", True, "retry_open"),
        "BUS_E_STORE_BUSY": ("WARNING", True, "retry_operation"),
        "BUS_W_CHECKPOINT_INCOMPLETE": ("WARNING", False, "inspect_checkpoint"),
    }
    assert "def _diagnostic" not in source
    assert calls
    for call in calls:
        assert isinstance(call.args[0], ast.Constant)
        assert isinstance(call.args[0].value, str)
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        code = call.args[0].value
        assert code in expected
        expected_values = expected[code]
        if isinstance(expected_values, tuple):
            expected_values = {expected_values}
        assert isinstance(keywords["severity"], ast.Attribute)
        severity = keywords["severity"].attr
        assert isinstance(keywords["retryable"], ast.Constant)
        retryable = keywords["retryable"].value
        assert isinstance(keywords["action"], ast.Constant)
        action = keywords["action"].value
        assert (severity, retryable, action) in expected_values
        for name, value in (
            ("retry_after_seconds", None),
            ("fallback_applied", False),
            ("requested_choice", None),
            ("effective_choice", None),
        ):
            literal = keywords[name]
            assert isinstance(literal, ast.Constant)
            assert literal.value == value
        causes = keywords["causes"]
        assert isinstance(causes, ast.Tuple)
        assert causes.elts == []
