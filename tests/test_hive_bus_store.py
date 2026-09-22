"""Focused Gen-1 contract tests for the closed BUS-S1 Slice-A store."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ast
from dataclasses import fields
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import threading
from typing import get_args, get_type_hints

import pytest

from the_hive.diagnostics import DiagnosticSeverityV2, DiagnosticV2
from the_hive.hive.bus_types import (
    canonical_json_bytes,
    create_hive_bus_event_v1,
    serialize_hive_bus_event_v1,
)
from the_hive.hive.bus_store import HiveBusStore
from the_hive.hive import bus_store


GEN1_TABLE_DDL = (
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
GEN1_INDEX_DDL = (
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
GEN1_MANIFEST = {
    "schema_name": "hive_bus_store",
    "generation": 1,
    "tables": list(GEN1_TABLE_DDL),
    "indexes": list(GEN1_INDEX_DDL),
    "pragmas": {
        "foreign_keys": 1,
        "journal_mode": "wal",
        "synchronous": "FULL",
        "busy_timeout": 5000,
        "wal_autocheckpoint": 1000,
    },
}
GEN1_SCHEMA_DIGEST = (
    "sha256:577d018653c16b9bf92590c1e68931f2ec972ad84a7e35c6f644f4f08aa508ba"
)

EXPECTED_TABLE_DDL = (
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
EXPECTED_INDEX_DDL = (
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
EXPECTED_MANIFEST = {
    "schema_name": "hive_bus_store",
    "generation": 2,
    "tables": list(EXPECTED_TABLE_DDL),
    "indexes": list(EXPECTED_INDEX_DDL),
    "pragmas": GEN1_MANIFEST["pragmas"],
}
EXPECTED_SCHEMA_DIGEST = (
    "sha256:1554a2ab9908b11262b238fb2906ec2c43b81f7fdf99f120546d415e4b462e11"
)
GEN1_RETENTION_POLICY = {
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
GEN1_RETENTION_POLICY_DIGEST = (
    "sha256:33dc6401f637e0dd7552a606266771f6cdfe5393f9d87d59353957a711324e8f"
)


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
    producer_principal_hex: str = "0123456789abcdef0123456789abcdef",
    producer_epoch: int = 1,
    payload_kind: str = "inline",
    payload_bytes: bytes = b"payload",
) -> dict[str, object]:
    idempotency_hex = (
        idempotency_suffix * 32 if len(idempotency_suffix) == 1 else idempotency_suffix
    )
    event_type = (
        "result.proposed"
        if payload_kind in {"blob", "artifact"}
        else "assignment.created"
    )
    payload_digest = _digest(payload_bytes)
    reference = f"{payload_kind}:{payload_digest}"
    if payload_kind == "artifact":
        reference = f"artifact:artifact-1@{payload_digest}"
    return {
        "schema_version": 1,
        "event_type": event_type,
        "partition": "repo/repo-1/task/task-1",
        "idempotency_key": "idempotency-v1-" + idempotency_hex,
        "producer_principal_id": "producer-principal-v1-" + producer_principal_hex,
        "producer_session_id": "producer-session-v1-0123456789abcdef0123456789abcdef",
        "producer_epoch": producer_epoch,
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


_GROUP = "consumer-group-1"
_PARTITION = "repo/repo-1/task/task-1"


def _delivery_diagnostic(
    value: object,
    code: str,
    severity: DiagnosticSeverityV2,
    *,
    retryable: bool,
    action: str,
    retry_after_seconds: int | None = None,
) -> None:
    assert isinstance(value, DiagnosticV2)
    assert value.code == code
    assert value.severity is severity
    assert value.retryable is retryable
    assert value.action == action
    assert value.retry_after_seconds == retry_after_seconds
    assert value.fallback_applied is False
    assert value.requested_choice is None
    assert value.effective_choice is None
    assert value.causes == ()


def _append_events(store: HiveBusStore, count: int) -> list[object]:
    events: list[object] = []
    for sequence in range(1, count + 1):
        result = store.append(
            _request(idempotency_suffix=f"{sequence:032x}", producer_seq=sequence),
            payload_bytes=b"payload",
        )
        assert not isinstance(result, DiagnosticV2)
        event = getattr(result, "event", result)
        events.append(event)
    return events


def _prepared_delivery(
    store: HiveBusStore, *, manifest: bytes = b"opaque-manifest"
) -> tuple[str, object]:
    generation = store.record_manifest_bytes(_GROUP, manifest_bytes=manifest)
    assert isinstance(generation, str)
    opened = store.open_cursor_once(_GROUP, _PARTITION, generation)
    assert opened == 0
    return generation, store.poll_headers(_GROUP, _PARTITION, generation)


def _c2_watermark(*, through_seq: int) -> object:
    subscription_generation = _digest(b"c2-subscription-generation")
    attestation = {
        "schema_version": 1,
        "partition": _PARTITION,
        "retention_generation": 1,
        "mandatory_watermark_seq": through_seq,
        "subscription_generation": subscription_generation,
    }
    return bus_store.MandatoryWatermarkV1(
        partition=_PARTITION,
        retention_generation=1,
        mandatory_watermark_seq=through_seq,
        subscription_generation=subscription_generation,
        attestation_digest=_digest(canonical_json_bytes(attestation)),
    )


def _c2_basis(*, run: bytes, through_seq: int, snapshot: object | None) -> object:
    return bus_store.RetentionBasisV1(
        run_id=_digest(run),
        watermark=_c2_watermark(through_seq=through_seq),
        snapshot=snapshot,
    )


def _c2_append(
    store: HiveBusStore,
    *,
    producer_seq: int,
    retention_class: str,
    payload: bytes = b"payload",
) -> None:
    request = _request(
        idempotency_suffix=f"{producer_seq:032x}",
        producer_seq=producer_seq,
        payload_bytes=payload,
    )
    if retention_class == "transient":
        request["event_type"] = "digest.tick"
    request["retention_class"] = retention_class
    _append_result(store, request, payload)


def _c2_seed_retention_policy(store: HiveBusStore) -> None:
    policy_bytes = canonical_json_bytes(GEN1_RETENTION_POLICY)
    store._connection.execute(  # noqa: SLF001 - C2 fixture for the preexisting table.
        "INSERT INTO retention_policies(retention_generation,policy_digest,policy_bytes,created_at_utc) "
        "VALUES(?,?,?,?)",
        (1, _digest(policy_bytes), policy_bytes, "2026-09-15T10:11:12.345Z"),
    )
    store._connection.commit()  # noqa: SLF001 - retain the fixture before C2 begins.


def _c2_mutation_state(store: HiveBusStore) -> tuple[object, ...]:
    """Read the C2-mutated rows without examining manifest contents."""

    return (
        store._connection.execute(  # noqa: SLF001 - no-mutation test oracle.
            "SELECT partition,next_seq,first_retained_seq,state,blocked_code,created_at_utc,updated_at_utc "
            "FROM partitions ORDER BY partition"
        ).fetchall(),
        store._connection.execute(  # noqa: SLF001 - no-mutation test oracle.
            "SELECT event_id,partition,partition_seq,retention_class,accepted_at_utc,payload_kind,"
            "payload_digest,payload_ref FROM events ORDER BY partition,partition_seq"
        ).fetchall(),
        store._connection.execute(  # noqa: SLF001 - no-mutation test oracle.
            "SELECT kind,digest,ref,size_bytes,body,body_state FROM payloads ORDER BY kind,digest,ref"
        ).fetchall(),
        store._connection.execute(  # noqa: SLF001 - no-mutation test oracle.
            "SELECT partition,from_seq,through_seq,digest,digest_bytes FROM digest_anchors "
            "ORDER BY partition,through_seq"
        ).fetchall(),
        store._connection.execute(  # noqa: SLF001 - no-mutation test oracle.
            "SELECT snapshot_id,partition,through_seq,snapshot_digest,snapshot_bytes,snapshot_size_bytes "
            "FROM snapshots ORDER BY partition,through_seq"
        ).fetchall(),
        store._connection.execute(  # noqa: SLF001 - no-mutation test oracle.
            "SELECT consumer_group_id,partition,generation,acked_seq,gap_snapshot_id,gap_from_seq,"
            "gap_through_seq FROM cursors ORDER BY consumer_group_id,partition"
        ).fetchall(),
        store._connection.execute(  # noqa: SLF001 - no-mutation test oracle.
            "SELECT consumer_group_id,partition,generation,delivery_token,from_seq,scan_through_seq "
            "FROM delivery_leases ORDER BY consumer_group_id,partition"
        ).fetchall(),
        store._connection.execute(  # noqa: SLF001 - no-mutation test oracle.
            "SELECT partition,run_id,request_digest,retention_generation,basis_digest,snapshot_id,"
            "compacted_through_seq,first_retained_seq,expired_payload_count,compacted_event_count "
            "FROM retention_checkpoints ORDER BY partition,run_id"
        ).fetchall(),
    )


def _seed_exact_gen1(root: Path, clock: FakeClock) -> None:
    """Create a fully-populated, byte-exact legacy source for migration tests."""

    root.mkdir(mode=0o700)
    database = root / "bus_store.sqlite3"
    connection = sqlite3.connect(database)
    accepted_at_utc = "2026-09-15T10:11:12.345Z"
    created_at_utc = "2026-09-15T10:00:00Z"
    request = _request()
    event = create_hive_bus_event_v1(
        request, partition_seq=1, accepted_at_utc=accepted_at_utc
    )
    header = canonical_json_bytes(serialize_hive_bus_event_v1(event))
    artifact_digest = _digest(b"legacy-artifact")
    artifact_ref = f"artifact:artifact-1@{artifact_digest}"
    manifest_generation = _digest(b"legacy-manifest")
    snapshot_id = _digest(b"legacy-snapshot-id")
    snapshot_digest = _digest(b"legacy-snapshot")
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        for statement in GEN1_TABLE_DDL:
            connection.execute(statement)
        for statement in GEN1_INDEX_DDL:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO bus_store_meta(schema_name,generation,schema_digest,created_at_utc) VALUES(?,?,?,?)",
            ("hive_bus_store", 1, GEN1_SCHEMA_DIGEST, accepted_at_utc),
        )
        connection.execute(
            "INSERT INTO partitions(partition,next_seq,first_retained_seq,state,blocked_code,created_at_utc,updated_at_utc) VALUES(?,?,?,?,?,?,?)",
            (_PARTITION, 2, 1, "active", None, accepted_at_utc, accepted_at_utc),
        )
        connection.execute(
            "INSERT INTO payloads(kind,digest,ref,size_bytes,body,body_state,artifact_id,quarantine_code,created_at_utc) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "inline",
                _digest(b"payload"),
                f"inline:{_digest(b'payload')}",
                7,
                b"payload",
                "present",
                None,
                None,
                accepted_at_utc,
            ),
        )
        connection.execute(
            "INSERT INTO payloads(kind,digest,ref,size_bytes,body,body_state,artifact_id,quarantine_code,created_at_utc) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "artifact",
                artifact_digest,
                artifact_ref,
                0,
                None,
                "reference",
                "artifact-1",
                None,
                accepted_at_utc,
            ),
        )
        connection.execute(
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
                event.payload.kind,
                event.payload.digest,
                event.payload.ref,
                event.payload.size_bytes,
                header,
                _digest(header),
            ),
        )
        connection.execute(
            "INSERT INTO producer_epochs(producer_principal_id,producer_epoch,producer_session_id,last_seq,last_event_id,updated_at_utc) VALUES(?,?,?,?,?,?)",
            (
                event.producer_principal_id,
                event.producer_epoch,
                event.producer_session_id,
                1,
                event.event_id,
                accepted_at_utc,
            ),
        )
        connection.execute(
            "INSERT INTO idempotency(idempotency_key,event_id,canonical_request_digest,created_at_utc) VALUES(?,?,?,?)",
            (
                event.idempotency_key,
                event.event_id,
                _digest(canonical_json_bytes(request)),
                created_at_utc,
            ),
        )
        connection.execute(
            "INSERT INTO subscription_manifests(consumer_group_id,generation,manifest_bytes,manifest_size_bytes,created_at_utc) VALUES(?,?,?,?,?)",
            (_GROUP, manifest_generation, b"legacy-manifest", 15, accepted_at_utc),
        )
        connection.execute(
            "INSERT INTO cursors(consumer_group_id,partition,generation,acked_seq,gap_snapshot_id,gap_from_seq,gap_through_seq,updated_at_utc) VALUES(?,?,?,?,?,?,?,?)",
            (
                _GROUP,
                _PARTITION,
                manifest_generation,
                0,
                None,
                None,
                None,
                accepted_at_utc,
            ),
        )
        connection.execute(
            "INSERT INTO delivery_leases(consumer_group_id,partition,generation,delivery_token,from_seq,scan_through_seq,leased_at_utc,expires_at_utc,created_monotonic) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                _GROUP,
                _PARTITION,
                manifest_generation,
                _digest(b"legacy-lease"),
                1,
                1,
                accepted_at_utc,
                "2026-09-15T10:12:12.345Z",
                123.5,
            ),
        )
        connection.execute(
            "INSERT INTO consumer_effects(consumer_group_id,event_id,partition,partition_seq,generation,state,effect_digest,attempt_count,retry_not_before_utc,lease_token,lease_expires_at_utc,last_error_code,updated_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                _GROUP,
                event.event_id,
                _PARTITION,
                1,
                manifest_generation,
                "dead_lettered",
                None,
                5,
                None,
                None,
                None,
                "BUS_E_SCHEMA",
                accepted_at_utc,
            ),
        )
        connection.execute(
            "INSERT INTO dead_letters(consumer_group_id,event_id,partition,partition_seq,generation,attempt_count,error_code,error_fingerprint,created_at_utc) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                _GROUP,
                event.event_id,
                _PARTITION,
                1,
                manifest_generation,
                5,
                "BUS_E_SCHEMA",
                _digest(b"legacy-error"),
                accepted_at_utc,
            ),
        )
        connection.execute(
            "INSERT INTO snapshots(snapshot_id,partition,through_seq,snapshot_digest,snapshot_bytes,snapshot_size_bytes,created_at_utc) VALUES(?,?,?,?,?,?,?)",
            (
                snapshot_id,
                _PARTITION,
                1,
                snapshot_digest,
                b"legacy-snapshot",
                15,
                accepted_at_utc,
            ),
        )
        connection.execute(
            "INSERT INTO archive_manifests(archive_manifest_id,partition,snapshot_id,accepted_event_id,decision_digest,manifest_digest,manifest_bytes,manifest_size_bytes,state,created_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                _digest(b"legacy-archive-id"),
                _PARTITION,
                snapshot_id,
                event.event_id,
                _digest(b"legacy-decision"),
                _digest(b"legacy-manifest-bytes"),
                b"legacy-manifest",
                15,
                "prepared",
                accepted_at_utc,
            ),
        )
        connection.execute(
            "INSERT INTO outbox(outbox_id,event_id,effect_digest,idempotency_key,hash_basis_digest,state,lease_token,lease_expires_at_utc,attempt_count,created_at_utc,updated_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                _digest(b"legacy-outbox"),
                event.event_id,
                _digest(b"legacy-effect"),
                event.idempotency_key,
                _digest(b"legacy-basis"),
                "pending",
                None,
                None,
                0,
                accepted_at_utc,
                accepted_at_utc,
            ),
        )
        connection.commit()
    finally:
        connection.close()
    database.chmod(0o600)
    owner = root / "bus_store.owner.lock"
    owner.write_bytes(b"")
    owner.chmod(0o600)


def _persisted_schema(root: Path) -> dict[str, str]:
    connection = sqlite3.connect(root / "bus_store.sqlite3")
    try:
        return dict(
            connection.execute(
                "SELECT name,sql FROM sqlite_schema WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%'"
            )
        )
    finally:
        connection.close()


def _append_result(
    store: HiveBusStore, request: dict[str, object], payload_bytes: bytes | None
) -> tuple[object, object, object]:
    """Require the C1 append result and expose its event/capacity pair."""

    result = store.append(request, payload_bytes=payload_bytes)
    assert type(result).__name__ == "AppendResultV1"
    event = getattr(result, "event")
    capacity = getattr(result, "capacity")
    assert type(event).__name__ == "HiveBusEventV1"
    assert type(capacity).__name__ == "CapacityStateV1"
    return result, event, capacity


def _capacity_values(state: object) -> tuple[int, int, bool, bool]:
    assert type(state).__name__ == "CapacityStateV1"
    return (
        getattr(state, "header_count"),
        getattr(state, "managed_payload_bytes"),
        getattr(state, "at_warning_watermark"),
        getattr(state, "at_hard_watermark"),
    )


def _long_header_request(*, producer_seq: int) -> dict[str, object]:
    request = _request(
        idempotency_suffix=f"{producer_seq:032x}", producer_seq=producer_seq
    )
    request["causation_ids"] = [f"sha256:{value:064x}" for value in range(1, 17)]
    return request


def _guard_request(
    event_type: str, *, producer_seq: int
) -> tuple[dict[str, object], bytes | None]:
    payload_kind = "artifact" if event_type == "artifact.archived" else "inline"
    request = _request(
        idempotency_suffix=f"{producer_seq:032x}",
        producer_seq=producer_seq,
        payload_kind=payload_kind,
    )
    request["event_type"] = event_type
    if event_type == "authority.revoked":
        request["retention_class"] = "audit"
    elif event_type == "provider.hard_stopped":
        request.update(
            partition="provider/provider-1/status",
            repo_id=None,
            topic_id=None,
            workpackage_id=None,
            retention_class="transient",
        )
    elif event_type == "security.critical":
        request.update(
            partition="security/repo/repo-1",
            repo_id="repo-1",
            topic_id=None,
            workpackage_id=None,
            retention_class="audit",
        )
    elif event_type == "artifact.archived":
        request.update(
            partition="repo/repo-1/artifact/artifact-1",
            repo_id="repo-1",
            topic_id=None,
            workpackage_id=None,
            retention_class="audit",
        )
    return request, None if payload_kind == "artifact" else b"payload"


def _seed_capacity_rows(
    store: HiveBusStore,
    *,
    partition: str = _PARTITION,
    artifact_count: int = 0,
    payload_count: int = 0,
    payload_size: int = 1_048_576,
    payload_kind: str = "inline",
) -> None:
    """Seed only valid persisted rows for exact capacity boundary tests."""

    assert artifact_count >= 0
    assert payload_count >= 0
    assert payload_kind in {"inline", "blob"}
    total = artifact_count + payload_count
    now = "2026-09-15T10:11:12.345Z"
    principal = "producer-principal-v1-0123456789abcdef0123456789abcdef"
    session = "producer-session-v1-0123456789abcdef0123456789abcdef"
    connection = store._connection  # noqa: SLF001 - bounded capacity fixture.
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        "INSERT INTO partitions(partition,next_seq,first_retained_seq,state,blocked_code,created_at_utc,updated_at_utc) VALUES(?,?,?,?,?,?,?)",
        (partition, total + 1, 1, "active", None, now, now),
    )
    artifact_digest = _digest(b"capacity-artifact")
    artifact_ref = f"artifact:artifact-1@{artifact_digest}"
    if artifact_count:
        connection.execute(
            "INSERT INTO payloads(kind,digest,ref,size_bytes,body,body_state,artifact_id,quarantine_code,created_at_utc) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "artifact",
                artifact_digest,
                artifact_ref,
                0,
                None,
                "reference",
                "artifact-1",
                None,
                now,
            ),
        )
    for index in range(1, total + 1):
        event_id = _digest(f"capacity-event-{index}".encode())
        idempotency_key = f"idempotency-v1-{index:032x}"
        header = b"h"
        if index <= artifact_count:
            kind = "artifact"
            digest = artifact_digest
            reference = artifact_ref
            size_bytes = 0
        else:
            payload_index = index - artifact_count
            kind = payload_kind
            digest = _digest(f"capacity-payload-{payload_index}".encode())
            reference = f"{kind}:{digest}"
            size_bytes = payload_size
            connection.execute(
                "INSERT INTO payloads(kind,digest,ref,size_bytes,body,body_state,artifact_id,quarantine_code,created_at_utc) VALUES(?,?,?,?,zeroblob(?),?,?,?,?)",
                (
                    kind,
                    digest,
                    reference,
                    payload_size,
                    payload_size,
                    "present",
                    None,
                    None,
                    now,
                ),
            )
        connection.execute(
            "INSERT INTO events(event_id,partition,partition_seq,schema_version,event_type,idempotency_key,producer_principal_id,producer_session_id,producer_epoch,producer_seq,repo_id,topic_id,workpackage_id,correlation_id,causation_ids_bytes,authority_grant_id,authority_scope_digest,authority_principal_version,classification,retention_class,created_at_utc,accepted_at_utc,payload_kind,payload_digest,payload_ref,payload_size_bytes,header_bytes,header_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                partition,
                index,
                1,
                "result.proposed" if kind != "inline" else "assignment.created",
                idempotency_key,
                principal,
                session,
                1,
                index,
                "repo-1",
                None,
                "task-1",
                "correlation-v1-0123456789abcdef0123456789abcdef",
                b"[]",
                "authority-grant-v1-0123456789abcdef0123456789abcdef",
                _digest(b"scope"),
                1,
                "internal",
                "work",
                now,
                now,
                kind,
                digest,
                reference,
                size_bytes,
                header,
                _digest(header),
            ),
        )
        connection.execute(
            "INSERT INTO idempotency(producer_principal_id,producer_epoch,idempotency_key,event_id,canonical_request_digest,partition_seq,accepted_at_utc,created_at_utc) VALUES(?,?,?,?,?,?,?,?)",
            (
                principal,
                1,
                idempotency_key,
                event_id,
                _digest(f"capacity-request-{index}".encode()),
                index,
                now,
                now,
            ),
        )
    if total:
        connection.execute(
            "INSERT INTO producer_epochs(producer_principal_id,producer_epoch,producer_session_id,last_seq,last_event_id,updated_at_utc) VALUES(?,?,?,?,?,?)",
            (
                principal,
                1,
                session,
                total,
                _digest(f"capacity-event-{total}".encode()),
                now,
            ),
        )
    connection.commit()


@pytest.fixture
def secure_tmp_path() -> Path:
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
        yield Path(temporary)


def test_foundation_initializes_exact_manifest_and_pragmas(
    secure_tmp_path: Path,
) -> None:
    root = secure_tmp_path / "bus-state"
    store = _store(root, FakeClock())
    try:
        expected_digest = (
            "sha256:"
            + hashlib.sha256(canonical_json_bytes(EXPECTED_MANIFEST)).hexdigest()
        )
        assert expected_digest == EXPECTED_SCHEMA_DIGEST
        assert len(EXPECTED_TABLE_DDL) == 17
        assert len(EXPECTED_INDEX_DDL) == 10
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
        assert {
            name
            for name in schema
            if name in {sql.split()[2] for sql in EXPECTED_TABLE_DDL}
        } == {sql.split()[2] for sql in EXPECTED_TABLE_DDL}
        for statement in (*EXPECTED_TABLE_DDL, *EXPECTED_INDEX_DDL):
            assert (
                schema[
                    statement.split()[2 if statement.startswith("CREATE TABLE") else 2]
                ]
                == statement
            )
        assert store._connection.execute(  # noqa: SLF001 - verifies independent manifest gold.
            "SELECT schema_name,generation,schema_digest FROM bus_store_meta"
        ).fetchall() == [("hive_bus_store", 2, EXPECTED_SCHEMA_DIGEST)]
        assert store._connection.execute("PRAGMA foreign_keys").fetchone() == (1,)  # noqa: SLF001
        assert store._connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)  # noqa: SLF001
        assert store._connection.execute("PRAGMA synchronous").fetchone() == (2,)  # noqa: SLF001
        assert store._connection.execute("PRAGMA busy_timeout").fetchone() == (5000,)  # noqa: SLF001
        assert store._connection.execute("PRAGMA wal_autocheckpoint").fetchone() == (
            1000,
        )  # noqa: SLF001
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
        connection.execute("UPDATE bus_store_meta SET generation = 3")
        connection.commit()
    finally:
        connection.close()
    result = HiveBusStore.initialize(root, clock=clock)
    _diagnostic(result, "BUS_E_STORE_SCHEMA_TOO_NEW", DiagnosticSeverityV2.CRITICAL)


def test_exact_fully_populated_gen1_migrates_once_to_the_gen2_gold_schema(
    secure_tmp_path: Path,
) -> None:
    root = secure_tmp_path / "bus-state"
    clock = FakeClock()
    _seed_exact_gen1(root, clock)

    store = HiveBusStore.initialize(root, clock=clock)

    assert isinstance(store, HiveBusStore)
    try:
        policy_bytes = canonical_json_bytes(GEN1_RETENTION_POLICY)
        assert len(policy_bytes) == 377
        assert _digest(policy_bytes) == GEN1_RETENTION_POLICY_DIGEST
        assert store._connection.execute(  # noqa: SLF001 - exact migration destination.
            "SELECT schema_name,generation,schema_digest FROM bus_store_meta"
        ).fetchall() == [("hive_bus_store", 2, EXPECTED_SCHEMA_DIGEST)]
        assert store._connection.execute(  # noqa: SLF001 - legacy values are preserved.
            "SELECT COUNT(*) FROM payloads"
        ).fetchone() == (2,)
        for table in (
            "partitions",
            "events",
            "producer_epochs",
            "subscription_manifests",
            "cursors",
            "delivery_leases",
            "consumer_effects",
            "dead_letters",
            "snapshots",
            "archive_manifests",
            "outbox",
        ):
            assert store._connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone() == (1,)  # noqa: S608, SLF001 - closed test literals.
        source_idempotency = store._connection.execute(  # noqa: SLF001 - joined columns are migration contract.
            "SELECT producer_principal_id,producer_epoch,idempotency_key,event_id,partition_seq,accepted_at_utc,created_at_utc FROM idempotency"
        ).fetchall()
        assert source_idempotency == [
            (
                "producer-principal-v1-0123456789abcdef0123456789abcdef",
                1,
                "idempotency-v1-00000000000000000000000000000000",
                store._connection.execute("SELECT event_id FROM events").fetchone()[0],  # noqa: SLF001
                1,
                "2026-09-15T10:11:12.345Z",
                "2026-09-15T10:00:00Z",
            )
        ]
        assert store._connection.execute(  # noqa: SLF001 - exact one-time policy seed.
            "SELECT retention_generation,policy_digest,policy_bytes FROM retention_policies"
        ).fetchall() == [(1, GEN1_RETENTION_POLICY_DIGEST, policy_bytes)]
        assert store._connection.execute(
            "SELECT COUNT(*) FROM digest_anchors"
        ).fetchone() == (0,)  # noqa: SLF001
        assert store._connection.execute(
            "SELECT COUNT(*) FROM retention_checkpoints"
        ).fetchone() == (0,)  # noqa: SLF001
    finally:
        assert store.close() is None
    reopened = HiveBusStore.initialize(root, clock=clock)
    assert isinstance(reopened, HiveBusStore)
    assert reopened.close() is None
    schema = _persisted_schema(root)
    assert set(EXPECTED_TABLE_DDL) <= set(schema.values())
    assert set(EXPECTED_INDEX_DDL) <= set(schema.values())
    assert not any(name.startswith("legacy_g1_") for name in schema)


def test_gen1_persisted_journal_mode_is_attested_before_gen2_configuration(
    secure_tmp_path: Path,
) -> None:
    root = secure_tmp_path / "journal-mode-drift"
    _seed_exact_gen1(root, FakeClock())
    connection = sqlite3.connect(root / "bus_store.sqlite3")
    try:
        # A reopen supplies these connection-local defaults, not historical
        # Gen-1 evidence.  Only journal_mode remains persisted in the file.
        # foreign_keys is enabled narrowly later for foreign_key_check.
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (0,)
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        assert connection.execute("PRAGMA synchronous").fetchone() == (2,)
        assert connection.execute("PRAGMA busy_timeout").fetchone() == (5000,)
        assert connection.execute("PRAGMA wal_autocheckpoint").fetchone() == (1000,)
        assert connection.execute("PRAGMA journal_mode=DELETE").fetchone() == (
            "delete",
        )
        connection.commit()
    finally:
        connection.close()

    connection = sqlite3.connect(root / "bus_store.sqlite3")
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    finally:
        connection.close()

    result = HiveBusStore.initialize(root, clock=FakeClock())
    if isinstance(result, HiveBusStore):
        assert result.close() is None

    _diagnostic(result, "BUS_E_STORE_SCHEMA_UNKNOWN", DiagnosticSeverityV2.CRITICAL)
    schema = _persisted_schema(root)
    assert set(GEN1_TABLE_DDL) <= set(schema.values())
    assert set(GEN1_INDEX_DDL) <= set(schema.values())
    assert not any(name.startswith("legacy_g1_") for name in schema)
    connection = sqlite3.connect(root / "bus_store.sqlite3")
    try:
        assert connection.execute(
            "SELECT generation FROM bus_store_meta"
        ).fetchone() == (1,)
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    finally:
        connection.close()


def test_gen1_source_attests_only_persisted_journal_before_operational_configuration(
    secure_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = secure_tmp_path / "connection-local-pragmas"
    _seed_exact_gen1(root, FakeClock())
    database = root / "bus_store.sqlite3"
    original_connect = sqlite3.connect

    def open_with_connection_local_drift(
        path: str | Path, *args: object, **kwargs: object
    ) -> sqlite3.Connection:
        connection = original_connect(path, *args, **kwargs)
        if Path(path) == database:
            assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            connection.execute("PRAGMA busy_timeout=17")
            connection.execute("PRAGMA wal_autocheckpoint=23")
        return connection

    monkeypatch.setattr(bus_store.sqlite3, "connect", open_with_connection_local_drift)
    result = HiveBusStore.initialize(root, clock=FakeClock())

    assert isinstance(result, HiveBusStore)
    try:
        assert result._connection.execute(  # noqa: SLF001 - operational post-migration setup.
            "SELECT generation FROM bus_store_meta"
        ).fetchone() == (2,)
        assert result._connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)  # noqa: SLF001
        assert result._connection.execute("PRAGMA foreign_keys").fetchone() == (1,)  # noqa: SLF001
        assert result._connection.execute("PRAGMA synchronous").fetchone() == (2,)  # noqa: SLF001
        assert result._connection.execute("PRAGMA busy_timeout").fetchone() == (5000,)  # noqa: SLF001
        assert result._connection.execute("PRAGMA wal_autocheckpoint").fetchone() == (
            1000,
        )  # noqa: SLF001
    finally:
        assert result.close() is None


def test_gen1_migration_sets_full_synchronous_before_rename(
    secure_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = secure_tmp_path / "migration-synchronous"
    _seed_exact_gen1(root, FakeClock())
    database = root / "bus_store.sqlite3"
    original_connect = sqlite3.connect
    connections: list[sqlite3.Connection] = []

    def open_with_synchronous_off(
        path: str | Path, *args: object, **kwargs: object
    ) -> sqlite3.Connection:
        connection = original_connect(path, *args, **kwargs)
        if Path(path) == database:
            connection.execute("PRAGMA synchronous=OFF")
            connections.append(connection)
        return connection

    def attest_migration_configuration(stage: str) -> None:
        if stage == "before_rename":
            assert len(connections) == 1
            assert connections[0].in_transaction
            assert connections[0].execute("PRAGMA synchronous").fetchone() == (2,)
            assert connections[0].execute("PRAGMA foreign_keys").fetchone() == (0,)

    monkeypatch.setattr(bus_store.sqlite3, "connect", open_with_synchronous_off)
    monkeypatch.setattr(
        bus_store, "_migration_checkpoint", attest_migration_configuration
    )
    result = HiveBusStore.initialize(root, clock=FakeClock())

    assert isinstance(result, HiveBusStore)
    assert result.close() is None


@pytest.mark.parametrize(
    ("checkpoint", "generation"),
    (
        ("before_rename", 1),
        ("after_rename_indexdrop", 1),
        ("after_copy", 1),
        ("after_final_validation_before_commit", 1),
        ("after_commit", 2),
    ),
)
def test_gen1_migration_crash_boundaries_are_all_or_nothing(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint: str,
    generation: int,
) -> None:
    class SimulatedCrash(BaseException):
        pass

    root = secure_tmp_path / checkpoint
    clock = FakeClock()
    _seed_exact_gen1(root, clock)

    def fault(point: str) -> None:
        if point == checkpoint:
            raise SimulatedCrash

    with monkeypatch.context() as scoped:
        scoped.setattr(bus_store, "_migration_checkpoint", fault)
        with pytest.raises(SimulatedCrash):
            HiveBusStore.initialize(root, clock=clock)

    schema = _persisted_schema(root)
    assert not any(name.startswith("legacy_g1_") for name in schema)
    connection = sqlite3.connect(root / "bus_store.sqlite3")
    try:
        assert connection.execute(
            "SELECT generation FROM bus_store_meta"
        ).fetchone() == (generation,)
    finally:
        connection.close()
    if generation == 1:
        assert set(GEN1_TABLE_DDL) <= set(schema.values())
        assert set(GEN1_INDEX_DDL) <= set(schema.values())
    else:
        assert set(EXPECTED_TABLE_DDL) <= set(schema.values())
        assert set(EXPECTED_INDEX_DDL) <= set(schema.values())

    resumed = HiveBusStore.initialize(root, clock=clock)
    assert isinstance(resumed, HiveBusStore)
    assert resumed.close() is None


def test_gen1_schema_mix_fails_closed_and_owner_stays_active_during_migration(
    secure_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mixed_root = secure_tmp_path / "mixed"
    _seed_exact_gen1(mixed_root, FakeClock())
    connection = sqlite3.connect(mixed_root / "bus_store.sqlite3")
    try:
        connection.execute("CREATE TABLE unrecognized_mix (value TEXT)")
        connection.commit()
    finally:
        connection.close()
    mixed = HiveBusStore.initialize(mixed_root, clock=FakeClock())
    _diagnostic(mixed, "BUS_E_STORE_SCHEMA_UNKNOWN", DiagnosticSeverityV2.CRITICAL)

    root = secure_tmp_path / "owner-active"
    clock = FakeClock()
    _seed_exact_gen1(root, clock)
    entered = threading.Event()
    release = threading.Event()
    results: list[object] = []

    def pause_after_rename(point: str) -> None:
        if point == "after_rename_indexdrop":
            entered.set()
            assert release.wait(timeout=5)

    def migrate() -> None:
        results.append(HiveBusStore.initialize(root, clock=clock))

    monkeypatch.setattr(bus_store, "_migration_checkpoint", pause_after_rename)
    worker = threading.Thread(target=migrate)
    worker.start()
    assert entered.wait(timeout=5)
    parallel = HiveBusStore.open(root, clock=clock)
    _diagnostic(parallel, "BUS_E_STORE_OWNER_ACTIVE", DiagnosticSeverityV2.WARNING)
    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert len(results) == 1 and isinstance(results[0], HiveBusStore)
    assert results[0].close() is None


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
        assert (
            connection.execute(
                "SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
            == []
        )
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

    result = HiveBusStore.initialize(
        secure_tmp_path / "network-state", clock=FakeClock()
    )

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


def test_filesystem_owner_and_closed_lifecycle_are_fail_closed(
    secure_tmp_path: Path,
) -> None:
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


def test_append_is_atomic_idempotent_and_uses_canonical_header(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "bus-state", FakeClock())
    request = _request()
    try:
        first_result = store.append(request, payload_bytes=b"payload")
        assert not isinstance(first_result, DiagnosticV2)
        first = getattr(first_result, "event", first_result)
        assert first.partition_seq == 1
        assert first.accepted_at_utc == "2026-09-15T10:11:12.345Z"
        expected_header = canonical_json_bytes(serialize_hive_bus_event_v1(first))
        assert store.read_event_header(first.event_id) == expected_header

        retried_result = store.append(request, payload_bytes=b"payload")
        assert not isinstance(retried_result, DiagnosticV2)
        assert getattr(retried_result, "event", retried_result) == first
        assert store._connection.execute("SELECT COUNT(*) FROM events").fetchone() == (
            1,
        )  # noqa: SLF001
        assert store._connection.execute(
            "SELECT next_seq FROM partitions"
        ).fetchone() == (2,)  # noqa: SLF001
    finally:
        assert store.close() is None


def test_append_rejects_payload_and_sequence_conflicts_without_writing(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "bus-state", FakeClock())
    try:
        mismatch = store.append(_request(), payload_bytes=b"different")
        _diagnostic(mismatch, "BUS_E_PAYLOAD_DIGEST", DiagnosticSeverityV2.ERROR)
        artifact_with_bytes = store.append(
            _request(payload_kind="artifact"), payload_bytes=b"payload"
        )
        _diagnostic(artifact_with_bytes, "BUS_E_SCHEMA", DiagnosticSeverityV2.ERROR)

        assert not isinstance(
            store.append(_request(), payload_bytes=b"payload"), DiagnosticV2
        )
        artifact = store.append(
            _request(idempotency_suffix="3", producer_seq=2, payload_kind="artifact"),
            payload_bytes=None,
        )
        assert not isinstance(artifact, DiagnosticV2)
        assert store._connection.execute(  # noqa: SLF001 - verifies no artifact read.
            "SELECT body,body_state FROM payloads WHERE kind='artifact'"
        ).fetchone() == (None, "reference")
        conflict = store.append(
            _request(idempotency_suffix="1", producer_seq=1), payload_bytes=b"payload"
        )
        _diagnostic(
            conflict, "BUS_E_PRODUCER_SEQ_REGRESSION", DiagnosticSeverityV2.ERROR
        )
        gap = store.append(
            _request(idempotency_suffix="2", producer_seq=4), payload_bytes=b"payload"
        )
        _diagnostic(gap, "BUS_E_PRODUCER_SEQ_GAP", DiagnosticSeverityV2.ERROR)
        incompatible = store.append(
            _request() | {"created_at_utc": "2026-09-15T10:00:01Z"},
            payload_bytes=b"payload",
        )
        _diagnostic(
            incompatible, "BUS_E_IDEMPOTENCY_CONFLICT", DiagnosticSeverityV2.ERROR
        )
    finally:
        assert store.close() is None


def test_artifact_uses_external_signed64_size_without_body_or_inline_blob_regression(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "bus-state", FakeClock())
    try:
        first_request = _request(payload_kind="artifact")
        first_payload = first_request["payload"]
        assert isinstance(first_payload, dict)
        first_request["payload"] = first_payload | {"size_bytes": 1_048_577}
        first = store.append(first_request, payload_bytes=None)
        assert not isinstance(first, DiagnosticV2)

        maximum_request = _request(
            idempotency_suffix="2",
            producer_seq=2,
            payload_kind="artifact",
            payload_bytes=b"maximum-artifact",
        )
        maximum_payload = maximum_request["payload"]
        assert isinstance(maximum_payload, dict)
        maximum_request["payload"] = maximum_payload | {"size_bytes": (2**63) - 1}
        maximum = store.append(maximum_request, payload_bytes=None)
        assert not isinstance(maximum, DiagnosticV2)
        assert store._connection.execute(  # noqa: SLF001 - artifact bytes are never persisted.
            "SELECT size_bytes,body,body_state FROM payloads WHERE kind='artifact' ORDER BY size_bytes"
        ).fetchall() == [
            (1_048_577, None, "reference"),
            ((2**63) - 1, None, "reference"),
        ]

        before = store._connection.execute(  # noqa: SLF001 - reject is pre-mutation.
            "SELECT COUNT(*) FROM events"
        ).fetchone()
        rejected_request = _request(
            idempotency_suffix="3", producer_seq=3, payload_kind="artifact"
        )
        rejected_payload = rejected_request["payload"]
        assert isinstance(rejected_payload, dict)
        rejected_request["payload"] = rejected_payload | {"size_bytes": 2**63}
        rejected = store.append(rejected_request, payload_bytes=None)
        _diagnostic(rejected, "BUS_E_EVENT_TOO_LARGE", DiagnosticSeverityV2.ERROR)
        assert (
            store._connection.execute("SELECT COUNT(*) FROM events").fetchone()
            == before
        )  # noqa: SLF001

        inline_ok = _request(
            idempotency_suffix="4", producer_seq=3, payload_bytes=b"i" * 2048
        )
        assert not isinstance(
            store.append(inline_ok, payload_bytes=b"i" * 2048), DiagnosticV2
        )
        inline_too_large = _request(
            idempotency_suffix="5", producer_seq=4, payload_bytes=b"i" * 2049
        )
        _diagnostic(
            store.append(inline_too_large, payload_bytes=b"i" * 2049),
            "BUS_E_EVENT_TOO_LARGE",
            DiagnosticSeverityV2.ERROR,
        )
        blob_ok = _request(
            idempotency_suffix="6",
            producer_seq=4,
            payload_kind="blob",
            payload_bytes=b"b" * (256 * 1024),
        )
        assert not isinstance(
            store.append(blob_ok, payload_bytes=b"b" * (256 * 1024)), DiagnosticV2
        )
    finally:
        assert store.close() is None


def test_idempotency_is_scoped_to_producer_principal_epoch_and_conflicts_do_not_mutate(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "bus-state", FakeClock())
    first_request = _request()
    try:
        first_result = store.append(first_request, payload_bytes=b"payload")
        assert not isinstance(first_result, DiagnosticV2)
        first = getattr(first_result, "event", first_result)
        different_principal_result = store.append(
            _request(
                producer_principal_hex="fedcba9876543210fedcba9876543210",
                producer_seq=1,
            ),
            payload_bytes=b"payload",
        )
        assert not isinstance(different_principal_result, DiagnosticV2)
        different_principal = getattr(
            different_principal_result, "event", different_principal_result
        )
        different_epoch_result = store.append(
            _request(producer_epoch=2, producer_seq=1), payload_bytes=b"payload"
        )
        assert not isinstance(different_epoch_result, DiagnosticV2)
        different_epoch = getattr(
            different_epoch_result, "event", different_epoch_result
        )
        assert {
            first.partition_seq,
            different_principal.partition_seq,
            different_epoch.partition_seq,
        } == {
            1,
            2,
            3,
        }
        retried = store.append(first_request, payload_bytes=b"payload")
        assert not isinstance(retried, DiagnosticV2)
        assert getattr(retried, "event", retried) == first
        before = store._connection.execute(  # noqa: SLF001 - conflict writes nothing.
            "SELECT COUNT(*),MAX(partition_seq) FROM events"
        ).fetchone()
        conflict = store.append(
            first_request | {"created_at_utc": "2026-09-15T10:00:01Z"},
            payload_bytes=b"payload",
        )
        _diagnostic(conflict, "BUS_E_IDEMPOTENCY_CONFLICT", DiagnosticSeverityV2.ERROR)
        assert (
            store._connection.execute(
                "SELECT COUNT(*),MAX(partition_seq) FROM events"
            ).fetchone()
            == before
        )  # noqa: SLF001
        assert store._connection.execute(  # noqa: SLF001 - no global key constraint remains.
            "SELECT COUNT(*) FROM idempotency WHERE idempotency_key=?",
            (first_request["idempotency_key"],),
        ).fetchone() == (3,)
    finally:
        assert store.close() is None


def test_append_crashes_rollback_or_commit_all_state_and_parallel_publishes_are_gapless(
    secure_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SimulatedCrash(BaseException):
        pass

    root = secure_tmp_path / "append-crash"
    clock = FakeClock()
    store = _store(root, clock)

    def before_commit(point: str) -> None:
        if point == "before_commit":
            raise SimulatedCrash

    with monkeypatch.context() as scoped:
        scoped.setattr(bus_store, "_append_checkpoint", before_commit)
        with pytest.raises(SimulatedCrash):
            store.append(_request(), payload_bytes=b"payload")
    assert store.close() is not None
    reopened = _store(root, clock)
    try:
        assert reopened._connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone() == (0,)  # noqa: SLF001
        assert reopened._connection.execute(
            "SELECT COUNT(*) FROM payloads"
        ).fetchone() == (0,)  # noqa: SLF001
        assert reopened._connection.execute(
            "SELECT COUNT(*) FROM idempotency"
        ).fetchone() == (0,)  # noqa: SLF001
    finally:
        assert reopened.close() is None

    store = _store(root, clock)

    def after_commit(point: str) -> None:
        if point == "after_commit":
            raise SimulatedCrash

    with monkeypatch.context() as scoped:
        scoped.setattr(bus_store, "_append_checkpoint", after_commit)
        with pytest.raises(SimulatedCrash):
            store.append(_request(), payload_bytes=b"payload")
    assert store.close() is None
    reopened = _store(root, clock)
    try:
        retried = reopened.append(_request(), payload_bytes=b"payload")
        assert not isinstance(retried, DiagnosticV2)
        assert reopened._connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone() == (1,)  # noqa: SLF001
    finally:
        assert reopened.close() is None

    parallel_root = secure_tmp_path / "append-race"
    parallel = _store(parallel_root, clock)
    gate = threading.Barrier(8)
    results: list[object] = []

    def publish(value: int) -> None:
        gate.wait()
        results.append(
            parallel.append(
                _request(
                    idempotency_suffix=f"{value:032x}",
                    producer_principal_hex=f"{value:032x}",
                    producer_seq=1,
                ),
                payload_bytes=b"payload",
            )
        )

    workers = [threading.Thread(target=publish, args=(value,)) for value in range(1, 9)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
        assert not worker.is_alive()
    try:
        assert len(results) == 8
        assert all(not isinstance(result, DiagnosticV2) for result in results)
        assert parallel._connection.execute(  # noqa: SLF001 - no gap, duplication, or partial state.
            "SELECT partition_seq FROM events ORDER BY partition_seq"
        ).fetchall() == [(value,) for value in range(1, 9)]
        assert parallel._connection.execute(
            "SELECT COUNT(*) FROM idempotency"
        ).fetchone() == (8,)  # noqa: SLF001
        assert parallel._connection.execute(
            "SELECT COUNT(*) FROM payloads"
        ).fetchone() == (1,)  # noqa: SLF001
        assert parallel._connection.execute(
            "SELECT next_seq FROM partitions"
        ).fetchone() == (9,)  # noqa: SLF001
    finally:
        assert parallel.close() is None


def test_open_recovery_and_header_read_fail_closed_on_drift(
    secure_tmp_path: Path,
) -> None:
    root = secure_tmp_path / "bus-state"
    clock = FakeClock()
    store = _store(root, clock)
    event_result = store.append(_request(), payload_bytes=b"payload")
    assert not isinstance(event_result, DiagnosticV2)
    event = getattr(event_result, "event", event_result)
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


def test_b_manifest_cursor_and_public_bounds_are_opaque_and_fail_closed(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "bus-state", FakeClock())
    try:
        invalid_manifest = store.record_manifest_bytes(_GROUP, manifest_bytes=b"")
        _delivery_diagnostic(
            invalid_manifest,
            "BUS_E_SCHEMA",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="reject_request",
        )
        invalid_group = store.record_manifest_bytes("Bad", manifest_bytes=b"opaque")
        _delivery_diagnostic(
            invalid_group,
            "BUS_E_SCHEMA",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="reject_request",
        )
        generation = store.record_manifest_bytes(_GROUP, manifest_bytes=b"opaque")
        assert generation == _digest(b"opaque")
        assert (
            store.record_manifest_bytes(_GROUP, manifest_bytes=b"opaque") == generation
        )
        assert store._connection.execute(  # noqa: SLF001 - opaque byte persistence.
            "SELECT manifest_bytes,manifest_size_bytes FROM subscription_manifests"
        ).fetchall() == [(b"opaque", 6)]
        missing = store.open_cursor_once(_GROUP, _PARTITION, _digest(b"missing"))
        _delivery_diagnostic(
            missing,
            "BUS_E_SUBSCRIPTION_STALE",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="refresh_subscription",
        )
        assert store.open_cursor_once(_GROUP, _PARTITION, generation) is None
        assert store._connection.execute("SELECT COUNT(*) FROM cursors").fetchone() == (
            0,
        )  # noqa: SLF001
        _append_events(store, 1)
        assert store.open_cursor_once(_GROUP, _PARTITION, generation) == 0
        alternate = store.record_manifest_bytes(_GROUP, manifest_bytes=b"alternate")
        assert isinstance(alternate, str)
        stale = store.open_cursor_once(_GROUP, _PARTITION, alternate)
        _delivery_diagnostic(
            stale,
            "BUS_E_SUBSCRIPTION_STALE",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="refresh_subscription",
        )
        assert store._connection.execute(  # noqa: SLF001 - stale opening writes nothing.
            "SELECT generation,acked_seq FROM cursors"
        ).fetchall() == [(generation, 0)]
    finally:
        assert store.close() is None


def test_b_poll_is_header_bounded_and_parallel_lease_persists_only_digest(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        _append_events(store, 33)
        generation = store.record_manifest_bytes(_GROUP, manifest_bytes=b"opaque")
        assert isinstance(generation, str)
        assert store.open_cursor_once(_GROUP, _PARTITION, generation) == 0
        gate = threading.Barrier(2)
        results: list[object] = []

        def poll() -> None:
            gate.wait()
            results.append(store.poll_headers(_GROUP, _PARTITION, generation))

        first = threading.Thread(target=poll)
        second = threading.Thread(target=poll)
        first.start()
        second.start()
        first.join()
        second.join()
        batches = [value for value in results if hasattr(value, "delivery_token")]
        active = [value for value in results if isinstance(value, DiagnosticV2)]
        assert len(batches) == 1
        assert len(active) == 1
        batch = batches[0]
        assert batch.from_seq == 1
        assert batch.scan_through_seq == 32
        assert len(batch.headers) == 32
        assert all(
            type(header) is bytes and len(header) <= 4096 for header in batch.headers
        )
        assert sum(map(len, batch.headers)) <= 65536
        assert batch.delivery_token.startswith("lease-v1-")
        persisted = store._connection.execute(  # noqa: SLF001 - bearer never reaches SQLite.
            "SELECT delivery_token,leased_at_utc,expires_at_utc FROM delivery_leases"
        ).fetchone()
        assert persisted is not None
        assert persisted[0] == _digest(batch.delivery_token.encode("ascii"))
        assert persisted[0] != batch.delivery_token
        _delivery_diagnostic(
            active[0],
            "BUS_E_DELIVERY_LEASE_ACTIVE",
            DiagnosticSeverityV2.WARNING,
            retryable=True,
            action="retry_delivery",
            retry_after_seconds=60,
        )
    finally:
        assert store.close() is None


def test_b_cursor_cas_effect_idempotence_and_crash_boundary(
    secure_tmp_path: Path,
) -> None:
    root = secure_tmp_path / "bus-state"
    clock = FakeClock()
    store = _store(root, clock)
    try:
        events = _append_events(store, 1)
        event = events[0]
        generation, delivery = _prepared_delivery(store)
        assert hasattr(delivery, "delivery_token")
        token = delivery.delivery_token
        effect_digest = _digest(b"effect-one")
        stale_generation = store.ack(
            _GROUP,
            _PARTITION,
            _digest(b"other-generation"),
            token,
            delivery.scan_through_seq,
        )
        _delivery_diagnostic(
            stale_generation,
            "BUS_E_SUBSCRIPTION_STALE",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="refresh_subscription",
        )
        other_bearer = "lease-v1-" + ("A" * 43)
        if other_bearer == token:
            other_bearer = "lease-v1-" + ("B" * 43)
        wrong_bearer = store.ack(
            _GROUP, _PARTITION, generation, other_bearer, delivery.scan_through_seq
        )
        _delivery_diagnostic(
            wrong_bearer,
            "BUS_E_DELIVERY_STALE",
            DiagnosticSeverityV2.WARNING,
            retryable=True,
            action="repoll_headers",
        )
        missing = store.ack(
            _GROUP, _PARTITION, generation, token, delivery.scan_through_seq
        )
        _delivery_diagnostic(
            missing,
            "BUS_E_CURSOR_CONFLICT",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="repoll_headers",
        )
        wrong_scan = store.ack(_GROUP, _PARTITION, generation, token, 2)
        _delivery_diagnostic(
            wrong_scan,
            "BUS_E_CURSOR_CONFLICT",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="repoll_headers",
        )
        begin = store.begin_effect(
            _GROUP,
            _PARTITION,
            generation,
            token,
            event.event_id,
            effect_digest=effect_digest,
        )
        assert begin.state == "apply"
        assert begin.attempt_count == 0
        conflict = store.begin_effect(
            _GROUP,
            _PARTITION,
            generation,
            token,
            event.event_id,
            effect_digest=_digest(b"different-effect"),
        )
        _delivery_diagnostic(
            conflict,
            "BUS_E_EFFECT_CONFLICT",
            DiagnosticSeverityV2.CRITICAL,
            retryable=False,
            action="operator_intervention",
        )
        assert (
            store.commit_effect(
                _GROUP,
                _PARTITION,
                generation,
                token,
                event.event_id,
                effect_digest=effect_digest,
            )
            is None
        )
        assert store.close() is None
        reopened = HiveBusStore.initialize(root, clock=clock)
        assert isinstance(reopened, HiveBusStore)
        try:
            replay = reopened.begin_effect(
                _GROUP,
                _PARTITION,
                generation,
                token,
                event.event_id,
                effect_digest=effect_digest,
            )
            assert replay.state == "committed"
            assert replay.attempt_count == 0
            assert (
                reopened.ack(
                    _GROUP, _PARTITION, generation, token, delivery.scan_through_seq
                )
                == 1
            )
            stale = reopened.ack(
                _GROUP, _PARTITION, generation, token, delivery.scan_through_seq
            )
            _delivery_diagnostic(
                stale,
                "BUS_E_DELIVERY_STALE",
                DiagnosticSeverityV2.WARNING,
                retryable=True,
                action="repoll_headers",
            )
        finally:
            assert reopened.close() is None
        store = reopened
    finally:
        assert store.close() is None


def test_b_backoff_expiry_counting_fifth_dlq_and_nonurgent_ack(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        events = _append_events(store, 1)
        event = events[0]
        generation, delivery = _prepared_delivery(store)
        assert hasattr(delivery, "delivery_token")
        effect_digest = _digest(b"effect")
        expected_delays = (5, 15, 60, 300)
        for expected_count, delay in enumerate(expected_delays, start=1):
            begin = store.begin_effect(
                _GROUP,
                _PARTITION,
                generation,
                delivery.delivery_token,
                event.event_id,
                effect_digest=effect_digest,
            )
            assert begin.state == "apply"
            assert begin.attempt_count == expected_count - 1
            backoff = store.fail_effect(
                _GROUP,
                _PARTITION,
                generation,
                delivery.delivery_token,
                event.event_id,
                effect_digest=effect_digest,
                error_code="BUS_E_SCHEMA",
                error_fingerprint=_digest(f"failure-{expected_count}".encode()),
            )
            _delivery_diagnostic(
                backoff,
                "BUS_E_DELIVERY_BACKOFF",
                DiagnosticSeverityV2.WARNING,
                retryable=True,
                action="retry_delivery",
                retry_after_seconds=delay,
            )
            before = store.poll_headers(_GROUP, _PARTITION, generation)
            _delivery_diagnostic(
                before,
                "BUS_E_DELIVERY_BACKOFF",
                DiagnosticSeverityV2.WARNING,
                retryable=True,
                action="retry_delivery",
                retry_after_seconds=delay,
            )
            clock.now += timedelta(seconds=delay)
            delivery = store.poll_headers(_GROUP, _PARTITION, generation)
            assert hasattr(delivery, "delivery_token")
        begin = store.begin_effect(
            _GROUP,
            _PARTITION,
            generation,
            delivery.delivery_token,
            event.event_id,
            effect_digest=effect_digest,
        )
        assert begin.state == "apply"
        assert begin.attempt_count == 4
        poison = store.fail_effect(
            _GROUP,
            _PARTITION,
            generation,
            delivery.delivery_token,
            event.event_id,
            effect_digest=effect_digest,
            error_code="BUS_E_SCHEMA",
            error_fingerprint=_digest(b"failure-5"),
        )
        _delivery_diagnostic(
            poison,
            "BUS_E_POISON",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="inspect_dead_letter",
        )
        assert store._connection.execute(  # noqa: SLF001 - fifth failure is atomic evidence.
            "SELECT state,attempt_count FROM consumer_effects"
        ).fetchall() == [("dead_lettered", 5)]
        assert store._connection.execute(  # noqa: SLF001 - fifth failure is atomic evidence.
            "SELECT attempt_count,error_code FROM dead_letters"
        ).fetchall() == [(5, "BUS_E_SCHEMA")]
        assert (
            store.ack(
                _GROUP,
                _PARTITION,
                generation,
                delivery.delivery_token,
                delivery.scan_through_seq,
            )
            == 1
        )
    finally:
        assert store.close() is None


def test_b_fifth_pending_lease_expiry_persists_dlq_and_returns_poison(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        event = _append_events(store, 1)[0]
        generation, delivery = _prepared_delivery(store)
        assert hasattr(delivery, "delivery_token")
        effect_digest = _digest(b"fifth-expiry-effect")
        for count, delay in enumerate((5, 15, 60, 300), start=1):
            assert (
                store.begin_effect(
                    _GROUP,
                    _PARTITION,
                    generation,
                    delivery.delivery_token,
                    event.event_id,
                    effect_digest=effect_digest,
                ).state
                == "apply"
            )
            _delivery_diagnostic(
                store.fail_effect(
                    _GROUP,
                    _PARTITION,
                    generation,
                    delivery.delivery_token,
                    event.event_id,
                    effect_digest=effect_digest,
                    error_code="BUS_E_SCHEMA",
                    error_fingerprint=_digest(f"fifth-expiry-{count}".encode()),
                ),
                "BUS_E_DELIVERY_BACKOFF",
                DiagnosticSeverityV2.WARNING,
                retryable=True,
                action="retry_delivery",
                retry_after_seconds=delay,
            )
            clock.now += timedelta(seconds=delay)
            delivery = store.poll_headers(_GROUP, _PARTITION, generation)
            assert hasattr(delivery, "delivery_token")
        assert (
            store.begin_effect(
                _GROUP,
                _PARTITION,
                generation,
                delivery.delivery_token,
                event.event_id,
                effect_digest=effect_digest,
            ).attempt_count
            == 4
        )
        clock.now += timedelta(seconds=60)

        terminal = store.poll_headers(_GROUP, _PARTITION, generation)

        _delivery_diagnostic(
            terminal,
            "BUS_E_POISON",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="inspect_dead_letter",
        )
        assert store._connection.execute(  # noqa: SLF001 - terminal expiry is durable.
            "SELECT state,attempt_count,last_error_code FROM consumer_effects"
        ).fetchone() == ("dead_lettered", 5, "BUS_E_DELIVERY_STALE")
        assert store._connection.execute(  # noqa: SLF001 - terminal expiry is durable.
            "SELECT attempt_count,error_code,error_fingerprint FROM dead_letters"
        ).fetchone() == (
            5,
            "BUS_E_DELIVERY_STALE",
            _digest(b"delivery_lease_expired_v1"),
        )
        assert store._connection.execute(
            "SELECT COUNT(*) FROM delivery_leases"
        ).fetchone() == (0,)  # noqa: SLF001
    finally:
        assert store.close() is None


def test_b_poll_leases_committed_prefix_before_later_effect_backoff(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        first_event, second_event = _append_events(store, 2)
        generation, initial = _prepared_delivery(store)
        assert hasattr(initial, "delivery_token")
        assert initial.scan_through_seq == 2
        first_digest = _digest(b"prefix-first")
        second_digest = _digest(b"prefix-second")
        assert (
            store.begin_effect(
                _GROUP,
                _PARTITION,
                generation,
                initial.delivery_token,
                first_event.event_id,
                effect_digest=first_digest,
            ).state
            == "apply"
        )
        assert (
            store.commit_effect(
                _GROUP,
                _PARTITION,
                generation,
                initial.delivery_token,
                first_event.event_id,
                effect_digest=first_digest,
            )
            is None
        )
        assert (
            store.begin_effect(
                _GROUP,
                _PARTITION,
                generation,
                initial.delivery_token,
                second_event.event_id,
                effect_digest=second_digest,
            ).state
            == "apply"
        )
        _delivery_diagnostic(
            store.fail_effect(
                _GROUP,
                _PARTITION,
                generation,
                initial.delivery_token,
                second_event.event_id,
                effect_digest=second_digest,
                error_code="BUS_E_SCHEMA",
                error_fingerprint=_digest(b"prefix-failure"),
            ),
            "BUS_E_DELIVERY_BACKOFF",
            DiagnosticSeverityV2.WARNING,
            retryable=True,
            action="retry_delivery",
            retry_after_seconds=5,
        )

        prefix = store.poll_headers(_GROUP, _PARTITION, generation)

        assert hasattr(prefix, "delivery_token")
        assert (prefix.from_seq, prefix.scan_through_seq, len(prefix.headers)) == (
            1,
            1,
            1,
        )
        assert (
            store.ack(
                _GROUP,
                _PARTITION,
                generation,
                prefix.delivery_token,
                prefix.scan_through_seq,
            )
            == 1
        )
        blocked = store.poll_headers(_GROUP, _PARTITION, generation)
        _delivery_diagnostic(
            blocked,
            "BUS_E_DELIVERY_BACKOFF",
            DiagnosticSeverityV2.WARNING,
            retryable=True,
            action="retry_delivery",
            retry_after_seconds=5,
        )
        assert store._connection.execute(
            "SELECT COUNT(*) FROM delivery_leases"
        ).fetchone() == (0,)  # noqa: SLF001
    finally:
        assert store.close() is None


def test_b_begin_effect_serializes_pending_attempts_within_a_lease(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        first_event, second_event = _append_events(store, 2)
        generation, initial = _prepared_delivery(store)
        assert hasattr(initial, "delivery_token")
        first_digest = _digest(b"serialized-first")
        second_digest = _digest(b"serialized-second")
        assert (
            store.begin_effect(
                _GROUP,
                _PARTITION,
                generation,
                initial.delivery_token,
                first_event.event_id,
                effect_digest=first_digest,
            ).state
            == "apply"
        )
        blocked_peer = store.begin_effect(
            _GROUP,
            _PARTITION,
            generation,
            initial.delivery_token,
            second_event.event_id,
            effect_digest=second_digest,
        )
        _delivery_diagnostic(
            blocked_peer,
            "BUS_E_CURSOR_CONFLICT",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="repoll_headers",
        )
        assert store._connection.execute(  # noqa: SLF001 - peer start made no journal row.
            "SELECT event_id,attempt_count FROM consumer_effects"
        ).fetchall() == [(first_event.event_id, 0)]
        _delivery_diagnostic(
            store.fail_effect(
                _GROUP,
                _PARTITION,
                generation,
                initial.delivery_token,
                first_event.event_id,
                effect_digest=first_digest,
                error_code="BUS_E_SCHEMA",
                error_fingerprint=_digest(b"serialized-failure"),
            ),
            "BUS_E_DELIVERY_BACKOFF",
            DiagnosticSeverityV2.WARNING,
            retryable=True,
            action="retry_delivery",
            retry_after_seconds=5,
        )
        _delivery_diagnostic(
            store.poll_headers(_GROUP, _PARTITION, generation),
            "BUS_E_DELIVERY_BACKOFF",
            DiagnosticSeverityV2.WARNING,
            retryable=True,
            action="retry_delivery",
            retry_after_seconds=5,
        )
        clock.now += timedelta(seconds=5)
        retry = store.poll_headers(_GROUP, _PARTITION, generation)
        assert hasattr(retry, "delivery_token")
        replay = store.begin_effect(
            _GROUP,
            _PARTITION,
            generation,
            retry.delivery_token,
            first_event.event_id,
            effect_digest=first_digest,
        )
        assert (replay.state, replay.attempt_count) == ("apply", 1)
        assert store._connection.execute(  # noqa: SLF001 - peer never became uncounted pending.
            "SELECT COUNT(*) FROM consumer_effects WHERE event_id=?",
            (second_event.event_id,),
        ).fetchone() == (0,)
    finally:
        assert store.close() is None


def test_b_begin_effect_rejects_duplicate_live_bearer_without_reauthorizing(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        event = _append_events(store, 1)[0]
        generation, delivery = _prepared_delivery(store)
        assert hasattr(delivery, "delivery_token")
        effect_digest = _digest(b"duplicate-live-bearer")
        first = store.begin_effect(
            _GROUP,
            _PARTITION,
            generation,
            delivery.delivery_token,
            event.event_id,
            effect_digest=effect_digest,
        )
        assert (first.state, first.attempt_count) == ("apply", 0)
        before = store._connection.execute(  # noqa: SLF001 - duplicate begin must not mutate.
            "SELECT state,attempt_count,lease_token FROM consumer_effects"
        ).fetchone()

        duplicate = store.begin_effect(
            _GROUP,
            _PARTITION,
            generation,
            delivery.delivery_token,
            event.event_id,
            effect_digest=effect_digest,
        )

        _delivery_diagnostic(
            duplicate,
            "BUS_E_CURSOR_CONFLICT",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="repoll_headers",
        )
        assert (
            store._connection.execute(  # noqa: SLF001 - duplicate begin must not mutate.
                "SELECT state,attempt_count,lease_token FROM consumer_effects"
            ).fetchone()
            == before
        )
        _delivery_diagnostic(
            store.fail_effect(
                _GROUP,
                _PARTITION,
                generation,
                delivery.delivery_token,
                event.event_id,
                effect_digest=effect_digest,
                error_code="BUS_E_SCHEMA",
                error_fingerprint=_digest(b"duplicate-live-bearer-failure"),
            ),
            "BUS_E_DELIVERY_BACKOFF",
            DiagnosticSeverityV2.WARNING,
            retryable=True,
            action="retry_delivery",
            retry_after_seconds=5,
        )
        clock.now += timedelta(seconds=5)
        retry = store.poll_headers(_GROUP, _PARTITION, generation)
        assert hasattr(retry, "delivery_token")
        resumed = store.begin_effect(
            _GROUP,
            _PARTITION,
            generation,
            retry.delivery_token,
            event.event_id,
            effect_digest=effect_digest,
        )
        assert (resumed.state, resumed.attempt_count) == ("apply", 1)
    finally:
        assert store.close() is None


def test_b_expired_pending_effect_counts_once_and_old_bearer_cannot_ack(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        events = _append_events(store, 1)
        event = events[0]
        generation, delivery = _prepared_delivery(store)
        assert hasattr(delivery, "delivery_token")
        assert (
            store.begin_effect(
                _GROUP,
                _PARTITION,
                generation,
                delivery.delivery_token,
                event.event_id,
                effect_digest=_digest(b"pending-expiry"),
            ).state
            == "apply"
        )
        clock.now += timedelta(seconds=60)
        materialized = store.poll_headers(_GROUP, _PARTITION, generation)
        _delivery_diagnostic(
            materialized,
            "BUS_E_DELIVERY_BACKOFF",
            DiagnosticSeverityV2.WARNING,
            retryable=True,
            action="retry_delivery",
            retry_after_seconds=5,
        )
        stale = store.ack(
            _GROUP,
            _PARTITION,
            generation,
            delivery.delivery_token,
            delivery.scan_through_seq,
        )
        _delivery_diagnostic(
            stale,
            "BUS_E_DELIVERY_STALE",
            DiagnosticSeverityV2.WARNING,
            retryable=True,
            action="repoll_headers",
        )
        assert store._connection.execute(  # noqa: SLF001 - one expiry creates one failure.
            "SELECT state,attempt_count,retry_not_before_utc FROM consumer_effects"
        ).fetchone() == ("pending", 1, "2026-09-15T10:12:17.345Z")
        assert store._connection.execute(
            "SELECT acked_seq FROM cursors"
        ).fetchone() == (0,)  # noqa: SLF001
        clock.now += timedelta(seconds=5)
        retry = store.poll_headers(_GROUP, _PARTITION, generation)
        assert hasattr(retry, "delivery_token")
        replay = store.begin_effect(
            _GROUP,
            _PARTITION,
            generation,
            retry.delivery_token,
            event.event_id,
            effect_digest=_digest(b"pending-expiry"),
        )
        assert (replay.state, replay.attempt_count) == ("apply", 1)
    finally:
        assert store.close() is None


@pytest.mark.parametrize("event_type", ("assignment.cancelled", "artifact.archived"))
def test_b_lease_expiry_counts_only_pending_and_poison_blocks_static_ack(
    secure_tmp_path: Path,
    event_type: str,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        if event_type == "artifact.archived":
            request = _request(payload_kind="artifact") | {
                "event_type": event_type,
                "partition": "repo/repo-1/artifact/artifact-1",
                "workpackage_id": None,
                "retention_class": "audit",
            }
            event = store.append(request, payload_bytes=None)
        else:
            request = _request() | {"event_type": event_type}
            event = store.append(request, payload_bytes=b"payload")
        assert not isinstance(event, DiagnosticV2)
        event = getattr(event, "event", event)
        partition = event.partition
        generation = store.record_manifest_bytes(
            _GROUP, manifest_bytes=b"opaque-manifest"
        )
        assert isinstance(generation, str)
        assert store.open_cursor_once(_GROUP, partition, generation) == 0
        untouched = store.poll_headers(_GROUP, partition, generation)
        assert hasattr(untouched, "delivery_token")
        clock.now += timedelta(seconds=60)
        replacement = store.poll_headers(_GROUP, partition, generation)
        assert hasattr(replacement, "delivery_token")
        first = store.begin_effect(
            _GROUP,
            partition,
            generation,
            replacement.delivery_token,
            event.event_id,
            effect_digest=_digest(b"urgent-effect"),
        )
        assert first.state == "apply"
        for count, delay in enumerate((5, 15, 60, 300), start=1):
            result = store.fail_effect(
                _GROUP,
                partition,
                generation,
                replacement.delivery_token,
                event.event_id,
                effect_digest=_digest(b"urgent-effect"),
                error_code="BUS_E_SCHEMA",
                error_fingerprint=_digest(f"urgent-{count}".encode()),
            )
            _delivery_diagnostic(
                result,
                "BUS_E_DELIVERY_BACKOFF",
                DiagnosticSeverityV2.WARNING,
                retryable=True,
                action="retry_delivery",
                retry_after_seconds=delay,
            )
            clock.now += timedelta(seconds=delay)
            replacement = store.poll_headers(_GROUP, partition, generation)
            assert hasattr(replacement, "delivery_token")
            begun = store.begin_effect(
                _GROUP,
                partition,
                generation,
                replacement.delivery_token,
                event.event_id,
                effect_digest=_digest(b"urgent-effect"),
            )
            assert begun.state == "apply"
        poison = store.fail_effect(
            _GROUP,
            partition,
            generation,
            replacement.delivery_token,
            event.event_id,
            effect_digest=_digest(b"urgent-effect"),
            error_code="BUS_E_SCHEMA",
            error_fingerprint=_digest(b"urgent-5"),
        )
        _delivery_diagnostic(
            poison,
            "BUS_E_POISON",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="inspect_dead_letter",
        )
        blocked = store.ack(
            _GROUP,
            partition,
            generation,
            replacement.delivery_token,
            replacement.scan_through_seq,
        )
        _delivery_diagnostic(
            blocked,
            "BUS_E_POISON",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="inspect_dead_letter",
        )
        assert store._connection.execute(
            "SELECT acked_seq FROM cursors"
        ).fetchone() == (0,)  # noqa: SLF001
    finally:
        assert store.close() is None


def test_b_manifest_exact_65536_bytes_persists_with_full_digest(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "bus-state", FakeClock())
    try:
        manifest_bytes = b"m" * 65536

        generation = store.record_manifest_bytes(_GROUP, manifest_bytes=manifest_bytes)

        assert generation == _digest(manifest_bytes)
        assert store._connection.execute(  # noqa: SLF001 - exact manifest boundary persistence.
            "SELECT manifest_bytes,manifest_size_bytes FROM subscription_manifests "
            "WHERE consumer_group_id=? AND generation=?",
            (_GROUP, generation),
        ).fetchone() == (manifest_bytes, 65536)
    finally:
        assert store.close() is None


def test_b_poll_empty_cursor_returns_none_without_creating_a_lease(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        event = _append_events(store, 1)[0]
        generation, delivery = _prepared_delivery(store)
        assert hasattr(delivery, "delivery_token")
        effect_digest = _digest(b"empty-poll-effect")
        assert (
            store.begin_effect(
                _GROUP,
                _PARTITION,
                generation,
                delivery.delivery_token,
                event.event_id,
                effect_digest=effect_digest,
            ).state
            == "apply"
        )
        assert (
            store.commit_effect(
                _GROUP,
                _PARTITION,
                generation,
                delivery.delivery_token,
                event.event_id,
                effect_digest=effect_digest,
            )
            is None
        )
        assert (
            store.ack(
                _GROUP,
                _PARTITION,
                generation,
                delivery.delivery_token,
                delivery.scan_through_seq,
            )
            == 1
        )
        assert store._connection.execute(
            "SELECT COUNT(*) FROM delivery_leases"
        ).fetchone() == (0,)  # noqa: SLF001

        empty = store.poll_headers(_GROUP, _PARTITION, generation)

        assert empty is None
        assert store._connection.execute(
            "SELECT COUNT(*) FROM delivery_leases"
        ).fetchone() == (0,)  # noqa: SLF001
    finally:
        assert store.close() is None


def test_b_poll_stops_before_65536_cumulative_header_bytes(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        repo_id = "r" * 64
        workpackage_id = "w" * 64
        partition = f"repo/{repo_id}/task/{workpackage_id}"
        causation_ids = [f"sha256:{value:064x}" for value in range(1, 17)]
        for sequence in range(1, 33):
            request = _request(
                idempotency_suffix=f"{sequence:032x}", producer_seq=sequence
            ) | {
                "partition": partition,
                "repo_id": repo_id,
                "workpackage_id": workpackage_id,
                "causation_ids": causation_ids,
            }
            assert not isinstance(
                store.append(request, payload_bytes=b"payload"), DiagnosticV2
            )
        generation = store.record_manifest_bytes(
            _GROUP, manifest_bytes=b"bounded-headers"
        )
        assert isinstance(generation, str)
        assert store.open_cursor_once(_GROUP, partition, generation) == 0
        all_headers = store._connection.execute(  # noqa: SLF001 - real stored canonical headers.
            "SELECT partition_seq,header_bytes FROM events WHERE partition=? ORDER BY partition_seq",
            (partition,),
        ).fetchall()
        assert len(all_headers) == 32

        delivery = store.poll_headers(_GROUP, partition, generation)

        assert hasattr(delivery, "delivery_token")
        assert len(delivery.headers) < 32
        prefix_length = len(delivery.headers)
        assert delivery.headers == tuple(
            header for _, header in all_headers[:prefix_length]
        )
        assert sum(map(len, delivery.headers)) <= 65536
        next_header = all_headers[prefix_length][1]
        assert sum(map(len, delivery.headers)) + len(next_header) > 65536
        assert delivery.scan_through_seq == all_headers[prefix_length - 1][0]
        assert next_header not in delivery.headers
    finally:
        assert store.close() is None


def test_b_partial_ack_of_committed_multi_header_lease_preserves_state(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        first_event, second_event = _append_events(store, 2)
        generation, delivery = _prepared_delivery(store)
        assert hasattr(delivery, "delivery_token")
        assert delivery.scan_through_seq == 2
        for event, effect_digest in (
            (first_event, _digest(b"partial-ack-first")),
            (second_event, _digest(b"partial-ack-second")),
        ):
            assert (
                store.begin_effect(
                    _GROUP,
                    _PARTITION,
                    generation,
                    delivery.delivery_token,
                    event.event_id,
                    effect_digest=effect_digest,
                ).state
                == "apply"
            )
            assert (
                store.commit_effect(
                    _GROUP,
                    _PARTITION,
                    generation,
                    delivery.delivery_token,
                    event.event_id,
                    effect_digest=effect_digest,
                )
                is None
            )
        cursor_before = store._connection.execute(  # noqa: SLF001 - rejected partial ACK is read-only.
            "SELECT consumer_group_id,partition,generation,acked_seq,gap_snapshot_id,gap_from_seq,"
            "gap_through_seq,updated_at_utc FROM cursors"
        ).fetchall()
        lease_before = store._connection.execute(  # noqa: SLF001 - rejected partial ACK retains lease.
            "SELECT consumer_group_id,partition,generation,delivery_token,from_seq,scan_through_seq,"
            "leased_at_utc,expires_at_utc,created_monotonic FROM delivery_leases"
        ).fetchall()
        effects_before = store._connection.execute(  # noqa: SLF001 - all effects are ACKable and unchanged.
            "SELECT event_id,state,effect_digest,attempt_count,retry_not_before_utc,lease_token,"
            "lease_expires_at_utc,last_error_code,updated_at_utc FROM consumer_effects ORDER BY partition_seq"
        ).fetchall()

        partial = store.ack(
            _GROUP,
            _PARTITION,
            generation,
            delivery.delivery_token,
            delivery.scan_through_seq - 1,
        )

        _delivery_diagnostic(
            partial,
            "BUS_E_CURSOR_CONFLICT",
            DiagnosticSeverityV2.ERROR,
            retryable=False,
            action="repoll_headers",
        )
        assert (
            store._connection.execute(  # noqa: SLF001 - rejected partial ACK is read-only.
                "SELECT consumer_group_id,partition,generation,acked_seq,gap_snapshot_id,gap_from_seq,"
                "gap_through_seq,updated_at_utc FROM cursors"
            ).fetchall()
            == cursor_before
        )
        assert (
            store._connection.execute(  # noqa: SLF001 - rejected partial ACK retains lease.
                "SELECT consumer_group_id,partition,generation,delivery_token,from_seq,scan_through_seq,"
                "leased_at_utc,expires_at_utc,created_monotonic FROM delivery_leases"
            ).fetchall()
            == lease_before
        )
        assert (
            store._connection.execute(  # noqa: SLF001 - rejected partial ACK retains effect state.
                "SELECT event_id,state,effect_digest,attempt_count,retry_not_before_utc,lease_token,"
                "lease_expires_at_utc,last_error_code,updated_at_utc FROM consumer_effects ORDER BY partition_seq"
            ).fetchall()
            == effects_before
        )
    finally:
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
        "BUS_E_CURSOR_CONFLICT": ("ERROR", False, "repoll_headers"),
        "BUS_E_CURSOR_GAP": ("ERROR", False, "revalidate_snapshot"),
        "BUS_E_SUBSCRIPTION_STALE": ("ERROR", False, "refresh_subscription"),
        "BUS_E_RETENTION_PRECONDITION": (
            "ERROR",
            False,
            "revalidate_retention_basis",
        ),
        "BUS_E_SNAPSHOT_TOO_LARGE": ("ERROR", False, "reduce_snapshot"),
        "BUS_E_DELIVERY_LEASE_ACTIVE": ("WARNING", True, "retry_delivery"),
        "BUS_E_DELIVERY_STALE": ("WARNING", True, "repoll_headers"),
        "BUS_E_DELIVERY_BACKOFF": ("WARNING", True, "retry_delivery"),
        "BUS_E_POISON": ("ERROR", False, "inspect_dead_letter"),
        "BUS_E_EFFECT_CONFLICT": ("CRITICAL", False, "operator_intervention"),
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
        "BUS_E_BACKPRESSURE": ("WARNING", True, "defer_publish"),
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
            ("fallback_applied", False),
            ("requested_choice", None),
            ("effective_choice", None),
        ):
            literal = keywords[name]
            assert isinstance(literal, ast.Constant)
            assert literal.value == value
        retry_after = keywords["retry_after_seconds"]
        if code in {"BUS_E_DELIVERY_LEASE_ACTIVE", "BUS_E_DELIVERY_BACKOFF"}:
            assert not isinstance(retry_after, ast.Constant)
        else:
            assert isinstance(retry_after, ast.Constant)
            assert retry_after.value is None
        causes = keywords["causes"]
        assert isinstance(causes, ast.Tuple)
        assert causes.elts == []


def test_c1_digest_materializes_only_on_explicit_call_at_31_to_32_boundary(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "bus-state", clock)
    try:
        for sequence in range(1, 32):
            _append_result(
                store,
                _request(
                    idempotency_suffix=f"{sequence:032x}",
                    producer_seq=sequence,
                ),
                b"payload",
            )
        assert store._connection.execute(  # noqa: SLF001 - explicit tick boundary.
            "SELECT COUNT(*) FROM digest_anchors"
        ).fetchone() == (0,)

        clock.now += timedelta(days=1)
        assert store._connection.execute(  # noqa: SLF001 - FakeClock is not a scheduler.
            "SELECT COUNT(*) FROM digest_anchors"
        ).fetchone() == (0,)

        first_anchor = store.materialize_digest(_PARTITION, through_seq=31)
        assert type(first_anchor).__name__ == "DigestAnchorV1"
        rows = store._connection.execute(  # noqa: SLF001 - persisted anchor contract.
            "SELECT from_seq,through_seq,event_count,header_bytes,digest,digest_bytes,digest_size_bytes "
            "FROM digest_anchors ORDER BY through_seq"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0:3] == (1, 31, 31)
        assert rows[0][3] == sum(
            len(header)
            for _, header in store._connection.execute(  # noqa: SLF001
                "SELECT partition_seq,header_bytes FROM events WHERE partition=? ORDER BY partition_seq",
                (_PARTITION,),
            ).fetchall()
        )
        assert rows[0][3] <= 69_632
        assert isinstance(rows[0][4], str) and rows[0][4].startswith("sha256:")
        assert isinstance(rows[0][5], bytes)
        assert rows[0][6] == len(rows[0][5])
        assert b"payload" not in rows[0][5]

        _append_result(
            store,
            _request(idempotency_suffix=f"{32:032x}", producer_seq=32),
            b"payload",
        )
        assert store._connection.execute(  # noqa: SLF001 - append never auto-anchors.
            "SELECT COUNT(*) FROM digest_anchors"
        ).fetchone() == (1,)

        second_anchor = store.materialize_digest(_PARTITION, through_seq=32)
        assert type(second_anchor).__name__ == "DigestAnchorV1"
        assert store.materialize_digest(_PARTITION, through_seq=32) is not None
        rows = store._connection.execute(  # noqa: SLF001 - idempotent endpoint.
            "SELECT from_seq,through_seq,event_count FROM digest_anchors ORDER BY through_seq"
        ).fetchall()
        assert rows == [(1, 31, 31), (32, 32, 1)]
    finally:
        assert store.close() is None


def test_c1_digest_stops_before_header_cap_and_covers_64k_crossing_without_overlap(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "bus-state", FakeClock())
    try:
        for sequence in range(1, 33):
            _append_result(
                store,
                _long_header_request(producer_seq=sequence),
                b"payload",
            )
        headers = store._connection.execute(  # noqa: SLF001 - cap fixture.
            "SELECT partition_seq,header_bytes FROM events WHERE partition=? ORDER BY partition_seq",
            (_PARTITION,),
        ).fetchall()
        total_header_bytes = sum(len(header) for _, header in headers)
        assert total_header_bytes > 65_536

        first = store.materialize_digest(_PARTITION, through_seq=32)
        assert type(first).__name__ == "DigestAnchorV1"
        rows = store._connection.execute(  # noqa: SLF001 - persisted anchor bounds.
            "SELECT from_seq,through_seq,event_count,header_bytes,digest_bytes FROM digest_anchors ORDER BY through_seq"
        ).fetchall()
        assert rows
        first_from, first_through, first_count, first_bytes, first_digest_bytes = rows[
            0
        ]
        assert (first_from, first_count) == (1, first_through)
        assert first_through < 33
        assert 1 <= first_count <= 32
        assert 1 <= first_bytes <= 69_632
        assert first_bytes == sum(
            len(header) for sequence, header in headers if sequence <= first_through
        )
        assert (
            first_through == 32 or first_bytes + len(headers[first_through][1]) > 69_632
        )
        assert b"payload" not in first_digest_bytes

        second = store.materialize_digest(_PARTITION, through_seq=32)
        assert type(second).__name__ == "DigestAnchorV1"
        rows = store._connection.execute(  # noqa: SLF001 - contiguous anchor coverage.
            "SELECT from_seq,through_seq,event_count,header_bytes FROM digest_anchors ORDER BY through_seq"
        ).fetchall()
        expected_from = 1
        for from_seq, through_seq, event_count, header_bytes in rows:
            assert from_seq == expected_from
            assert through_seq >= from_seq
            assert event_count == through_seq - from_seq + 1
            assert 1 <= header_bytes <= 69_632
            expected_from = through_seq + 1
        assert expected_from == 33
    finally:
        assert store.close() is None


def test_c1_digest_reopen_resumes_after_max_through_and_is_idempotent(
    secure_tmp_path: Path,
) -> None:
    root = secure_tmp_path / "bus-state"
    clock = FakeClock()
    store = _store(root, clock)
    for sequence in range(1, 3):
        _append_result(
            store,
            _request(idempotency_suffix=f"{sequence:032x}", producer_seq=sequence),
            b"payload",
        )
    try:
        assert type(store.materialize_digest(_PARTITION, through_seq=2)).__name__ == (
            "DigestAnchorV1"
        )
        assert store._connection.execute(  # noqa: SLF001 - idempotency count.
            "SELECT COUNT(*) FROM digest_anchors"
        ).fetchone() == (1,)
        assert store.close() is None
        reopened = HiveBusStore.initialize(root, clock=clock)
        assert isinstance(reopened, HiveBusStore)
        store = reopened
        assert type(store.materialize_digest(_PARTITION, through_seq=2)).__name__ == (
            "DigestAnchorV1"
        )
        assert store._connection.execute(  # noqa: SLF001 - reopen does not duplicate.
            "SELECT COUNT(*) FROM digest_anchors"
        ).fetchone() == (1,)
        _append_result(
            store,
            _request(idempotency_suffix=f"{3:032x}", producer_seq=3),
            b"payload",
        )
        assert type(store.materialize_digest(_PARTITION, through_seq=3)).__name__ == (
            "DigestAnchorV1"
        )
        assert store._connection.execute(  # noqa: SLF001 - MAX(through_seq)+1.
            "SELECT from_seq,through_seq FROM digest_anchors ORDER BY through_seq"
        ).fetchall() == [(1, 2), (3, 3)]
    finally:
        assert store.close() is None


def test_c1_materialize_append_race_is_gapless_and_non_overlapping(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "bus-state", FakeClock())
    try:
        for sequence in range(1, 32):
            _append_result(
                store,
                _request(
                    idempotency_suffix=f"{sequence:032x}",
                    producer_seq=sequence,
                ),
                b"payload",
            )
        barrier = threading.Barrier(2)
        outcomes: list[object] = []
        failures: list[BaseException] = []

        def materialize() -> None:
            try:
                barrier.wait()
                outcomes.append(store.materialize_digest(_PARTITION, through_seq=32))
            except BaseException as exc:  # pragma: no cover - diagnostic evidence.
                failures.append(exc)

        def append() -> None:
            try:
                barrier.wait()
                outcomes.append(
                    store.append(
                        _request(idempotency_suffix=f"{32:032x}", producer_seq=32),
                        payload_bytes=b"payload",
                    )
                )
            except BaseException as exc:  # pragma: no cover - diagnostic evidence.
                failures.append(exc)

        materializer = threading.Thread(target=materialize)
        appender = threading.Thread(target=append)
        materializer.start()
        appender.start()
        materializer.join()
        appender.join()
        assert failures == []
        assert len(outcomes) == 2
        assert any(type(value).__name__ == "AppendResultV1" for value in outcomes)
        assert any(type(value).__name__ == "DigestAnchorV1" for value in outcomes)

        store.materialize_digest(_PARTITION, through_seq=32)
        rows = store._connection.execute(  # noqa: SLF001 - race coverage.
            "SELECT from_seq,through_seq,event_count FROM digest_anchors ORDER BY through_seq"
        ).fetchall()
        assert rows[0][0] == 1
        expected_from = 1
        for from_seq, through_seq, event_count in rows:
            assert from_seq == expected_from
            assert event_count == through_seq - from_seq + 1
            expected_from = through_seq + 1
        assert expected_from == 33
    finally:
        assert store.close() is None


@pytest.mark.parametrize(
    ("header_count", "expected_warning", "expected_hard"),
    ((7_500, True, False), (10_000, True, True)),
)
def test_c1_capacity_header_count_warning_and_hard_boundaries(
    secure_tmp_path: Path,
    header_count: int,
    expected_warning: bool,
    expected_hard: bool,
) -> None:
    store = _store(secure_tmp_path / f"headers-{header_count}", FakeClock())
    try:
        _seed_capacity_rows(store, artifact_count=header_count)
        state = store.read_capacity(_PARTITION)
        assert _capacity_values(state) == (
            header_count,
            0,
            expected_warning,
            expected_hard,
        )
    finally:
        assert store.close() is None


@pytest.mark.parametrize(
    ("payload_count", "expected_warning", "expected_hard"),
    ((48, True, False), (64, True, True)),
)
def test_c1_capacity_managed_bytes_warning_and_hard_boundaries(
    secure_tmp_path: Path,
    payload_count: int,
    expected_warning: bool,
    expected_hard: bool,
) -> None:
    store = _store(secure_tmp_path / f"payload-{payload_count}", FakeClock())
    try:
        _seed_capacity_rows(
            store,
            payload_count=payload_count,
            payload_size=1_048_576,
            payload_kind="inline",
        )
        state = store.read_capacity(_PARTITION)
        assert _capacity_values(state) == (
            payload_count,
            payload_count * 1_048_576,
            expected_warning,
            expected_hard,
        )
    finally:
        assert store.close() is None


def test_c1_noncritical_count_hard_projection_is_rejected_without_mutation(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "count-hard", FakeClock())
    try:
        _seed_capacity_rows(store, artifact_count=9_999)
        before = store._connection.execute(  # noqa: SLF001 - pre-mutation snapshot.
            "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM payloads),"
            "(SELECT COUNT(*) FROM idempotency),(SELECT next_seq FROM partitions WHERE partition=?)",
            (_PARTITION,),
        ).fetchone()
        result = store.append(_request(producer_seq=10_000), payload_bytes=b"payload")
        assert isinstance(result, DiagnosticV2)
        assert (
            store._connection.execute(  # noqa: SLF001 - rejection must be atomic.
                "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM payloads),"
                "(SELECT COUNT(*) FROM idempotency),(SELECT next_seq FROM partitions WHERE partition=?)",
                (_PARTITION,),
            ).fetchone()
            == before
        )
    finally:
        assert store.close() is None


def test_c1_noncritical_byte_hard_projection_is_rejected_without_mutation(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "bytes-hard", FakeClock())
    try:
        _seed_capacity_rows(
            store,
            payload_count=255,
            payload_size=262_144,
            payload_kind="blob",
        )
        request = _request(
            idempotency_suffix=f"{256:032x}",
            producer_seq=256,
            payload_kind="blob",
            payload_bytes=b"b" * 262_144,
        )
        before = store._connection.execute(  # noqa: SLF001 - pre-mutation snapshot.
            "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM payloads),"
            "(SELECT COUNT(*) FROM idempotency),(SELECT next_seq FROM partitions WHERE partition=?)",
            (_PARTITION,),
        ).fetchone()
        result = store.append(request, payload_bytes=b"b" * 262_144)
        assert isinstance(result, DiagnosticV2)
        assert (
            store._connection.execute(  # noqa: SLF001 - rejection must be atomic.
                "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM payloads),"
                "(SELECT COUNT(*) FROM idempotency),(SELECT next_seq FROM partitions WHERE partition=?)",
                (_PARTITION,),
            ).fetchone()
            == before
        )
    finally:
        assert store.close() is None


@pytest.mark.parametrize(
    "event_type",
    (
        "authority.revoked",
        "provider.hard_stopped",
        "security.critical",
        "artifact.archived",
    ),
)
def test_c1_exact_four_hard_capacity_exceptions_append_at_projection(
    secure_tmp_path: Path, event_type: str
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / event_type.replace(".", "-"), clock)
    request, payload_bytes = _guard_request(event_type, producer_seq=10_000)
    partition = request["partition"]
    assert isinstance(partition, str)
    try:
        _seed_capacity_rows(store, partition=partition, artifact_count=9_999)
        result, event, _ = _append_result(store, request, payload_bytes)
        assert type(result).__name__ == "AppendResultV1"
        assert getattr(event, "partition_seq") == 10_000
        assert store._connection.execute(  # noqa: SLF001 - exception is the only bypass.
            "SELECT COUNT(*) FROM events WHERE partition=?", (partition,)
        ).fetchone() == (10_000,)
    finally:
        assert store.close() is None


def test_c1_urgency_does_not_widen_hard_capacity_exception_set(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "urgent-nonexception", FakeClock())
    try:
        _seed_capacity_rows(store, artifact_count=9_999)
        request = _request(producer_seq=10_000) | {"event_type": "assignment.cancelled"}
        before = store._connection.execute(  # noqa: SLF001 - pre-mutation snapshot.
            "SELECT COUNT(*),next_seq FROM events JOIN partitions ON partitions.partition=events.partition "
            "WHERE events.partition=?",
            (_PARTITION,),
        ).fetchone()
        result = store.append(request, payload_bytes=b"payload")
        assert isinstance(result, DiagnosticV2)
        assert (
            store._connection.execute(  # noqa: SLF001 - urgent remains noncritical.
                "SELECT COUNT(*),next_seq FROM events JOIN partitions ON partitions.partition=events.partition "
                "WHERE events.partition=?",
                (_PARTITION,),
            ).fetchone()
            == before
        )
    finally:
        assert store.close() is None


def test_c1_idempotent_retry_returns_stored_event_and_current_capacity(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "idempotent-capacity", FakeClock())
    try:
        request = _request()
        first_result, first_event, _ = _append_result(store, request, b"payload")
        _append_result(
            store,
            _request(idempotency_suffix=f"{2:032x}", producer_seq=2),
            b"payload",
        )
        retried_result, retried_event, retry_capacity = _append_result(
            store, request, b"payload"
        )
        assert type(first_result).__name__ == "AppendResultV1"
        assert type(retried_result).__name__ == "AppendResultV1"
        assert getattr(retried_event, "event_id") == getattr(first_event, "event_id")
        current = store.read_capacity(_PARTITION)
        assert _capacity_values(retry_capacity) == _capacity_values(current)
        assert _capacity_values(retry_capacity) == (2, 14, False, False)
    finally:
        assert store.close() is None


def test_c1_artifact_is_zero_managed_bytes_and_shared_payload_refs_are_logical(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "logical-payload-refs", FakeClock())
    try:
        _append_result(store, _request(producer_seq=1), b"payload")
        _append_result(
            store,
            _request(idempotency_suffix=f"{2:032x}", producer_seq=2),
            b"payload",
        )
        _append_result(
            store,
            _request(
                idempotency_suffix=f"{3:032x}",
                producer_seq=3,
                payload_kind="blob",
                payload_bytes=b"blob",
            ),
            b"blob",
        )
        artifact_request = _request(
            idempotency_suffix=f"{4:032x}",
            producer_seq=4,
            payload_kind="artifact",
            payload_bytes=b"external-artifact",
        )
        artifact_payload = artifact_request["payload"]
        assert isinstance(artifact_payload, dict)
        artifact_request["payload"] = artifact_payload | {"size_bytes": 1_048_577}
        _append_result(store, artifact_request, None)

        state = store.read_capacity(_PARTITION)
        assert _capacity_values(state) == (4, 7 + 7 + 4, False, False)
        assert store._connection.execute(  # noqa: SLF001 - artifact body is external.
            "SELECT size_bytes,body,body_state FROM payloads WHERE kind='artifact'"
        ).fetchone() == (1_048_577, None, "reference")
    finally:
        assert store.close() is None


def test_c1_spec_digest_anchor_exposes_exactly_the_seven_plan_fields() -> None:
    assert tuple(field.name for field in fields(bus_store.DigestAnchorV1)) == (
        "partition",
        "from_seq",
        "through_seq",
        "event_count",
        "header_bytes",
        "digest",
        "digest_bytes",
    )


def test_c1_spec_read_capacity_returns_none_for_unknown_partition_but_not_empty_known_partition(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "capacity-partitions", FakeClock())
    unknown_partition = "repo/repo-1/task/task-unknown"
    try:
        assert store.read_capacity(unknown_partition) is None
        store._connection.execute(  # noqa: SLF001 - existing empty partition fixture.
            "INSERT INTO partitions(partition,next_seq,first_retained_seq,state,blocked_code,created_at_utc,updated_at_utc) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                _PARTITION,
                1,
                1,
                "active",
                None,
                "2026-09-15T10:11:12.345Z",
                "2026-09-15T10:11:12.345Z",
            ),
        )
        store._connection.commit()  # noqa: SLF001 - existing empty partition fixture.
        assert _capacity_values(store.read_capacity(_PARTITION)) == (0, 0, False, False)
    finally:
        assert store.close() is None


def test_c1_spec_digest_bytes_are_exact_canonical_mapping_and_sha256(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "digest-gold", FakeClock())
    body = b"body-freetext-must-not-enter-digest"
    try:
        for sequence in range(1, 3):
            _append_result(
                store,
                _request(
                    idempotency_suffix=f"{sequence:032x}",
                    producer_seq=sequence,
                    payload_bytes=body,
                ),
                body,
            )
        anchor = store.materialize_digest(_PARTITION, through_seq=2)
        assert type(anchor).__name__ == "DigestAnchorV1"
        rows = store._connection.execute(  # noqa: SLF001 - independent mapping inputs.
            "SELECT partition_seq,event_id,header_digest FROM events "
            "WHERE partition=? ORDER BY partition_seq,event_id",
            (_PARTITION,),
        ).fetchall()
        entries = [
            {
                "partition_seq": sequence,
                "event_id": event_id,
                "header_digest": header_digest,
            }
            for sequence, event_id, header_digest in rows
        ]
        expected_mapping = {
            "entries": entries,
            "event_count": 2,
            "from_seq": 1,
            "header_bytes": store._connection.execute(  # noqa: SLF001
                "SELECT SUM(length(header_bytes)) FROM events WHERE partition=?",
                (_PARTITION,),
            ).fetchone()[0],
            "partition": _PARTITION,
            "schema_version": 1,
            "through_seq": 2,
        }
        expected_bytes = canonical_json_bytes(expected_mapping)
        assert set(expected_mapping) == {
            "entries",
            "event_count",
            "from_seq",
            "header_bytes",
            "partition",
            "schema_version",
            "through_seq",
        }
        assert all(
            set(entry) == {"partition_seq", "event_id", "header_digest"}
            for entry in entries
        )
        assert body not in expected_bytes
        assert getattr(anchor, "digest_bytes") == expected_bytes
        assert getattr(anchor, "digest") == _digest(expected_bytes)
    finally:
        assert store.close() is None


def test_c1_spec_materialize_digest_return_annotation_is_anchor_or_diagnostic() -> None:
    return_annotation = get_type_hints(bus_store.HiveBusStore.materialize_digest)[
        "return"
    ]

    assert return_annotation == bus_store.DigestAnchorV1 | DiagnosticV2
    assert type(None) not in get_args(return_annotation)


def test_c1_materialize_empty_next_interval_returns_schema_diagnostic(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "empty-digest", FakeClock())
    try:
        _seed_capacity_rows(store)
        result = store.materialize_digest(_PARTITION, through_seq=1)
        _diagnostic(result, "BUS_E_SCHEMA", DiagnosticSeverityV2.ERROR)
    finally:
        assert store.close() is None


def test_c2_snapshot_is_opaque_bounded_canonical_and_idempotent(
    secure_tmp_path: Path,
) -> None:
    store = _store(secure_tmp_path / "c2-snapshot", FakeClock())
    snapshot_bytes = b"s" * 1_048_576
    try:
        _c2_append(store, producer_seq=1, retention_class="transient")
        snapshot = store.record_snapshot(_PARTITION, 1, snapshot_bytes=snapshot_bytes)
        assert type(snapshot).__name__ == "SnapshotAnchorV1"
        snapshot_digest = _digest(snapshot_bytes)
        expected_id = _digest(
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "partition": _PARTITION,
                    "through_seq": 1,
                    "snapshot_digest": snapshot_digest,
                }
            )
        )
        assert getattr(snapshot, "snapshot_id") == expected_id
        assert getattr(snapshot, "snapshot_digest") == snapshot_digest
        assert (
            store.record_snapshot(_PARTITION, 1, snapshot_bytes=snapshot_bytes)
            == snapshot
        )
        conflict = store.record_snapshot(_PARTITION, 1, snapshot_bytes=b"other")
        _diagnostic(
            conflict, "BUS_E_RETENTION_PRECONDITION", DiagnosticSeverityV2.ERROR
        )
        too_large = store.record_snapshot(
            _PARTITION, 1, snapshot_bytes=b"x" * 1_048_577
        )
        _diagnostic(too_large, "BUS_E_SNAPSHOT_TOO_LARGE", DiagnosticSeverityV2.ERROR)
        assert store._connection.execute(  # noqa: SLF001 - no failed insert.
            "SELECT COUNT(*) FROM snapshots"
        ).fetchone() == (1,)
    finally:
        assert store.close() is None


@pytest.mark.parametrize("corruption", ("digest", "size", "type"))
def test_c2_snapshot_persisted_bytes_are_verified_before_idempotency_or_use(
    secure_tmp_path: Path, corruption: str
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "c2-snapshot-integrity", clock)
    try:
        _c2_seed_retention_policy(store)
        _c2_append(store, producer_seq=1, retention_class="transient")
        assert store.materialize_digest(_PARTITION, through_seq=1) is not None
        snapshot_bytes = b"opaque-snapshot"
        snapshot = store.record_snapshot(_PARTITION, 1, snapshot_bytes=snapshot_bytes)
        assert type(snapshot).__name__ == "SnapshotAnchorV1"
        snapshot_id = getattr(snapshot, "snapshot_id")
        if corruption == "digest":
            store._connection.execute(  # noqa: SLF001 - post-open tamper fixture.
                "UPDATE snapshots SET snapshot_bytes=? WHERE snapshot_id=?",
                (b"x" * len(snapshot_bytes), snapshot_id),
            )
        elif corruption == "size":
            store._connection.execute(  # noqa: SLF001 - post-open tamper fixture.
                "PRAGMA ignore_check_constraints=ON"
            )
            store._connection.execute(
                "UPDATE snapshots SET snapshot_size_bytes=? WHERE snapshot_id=?",
                (len(snapshot_bytes) + 1, snapshot_id),
            )
            store._connection.execute("PRAGMA ignore_check_constraints=OFF")
        else:
            store._connection.execute(  # noqa: SLF001 - post-open tamper fixture.
                "UPDATE snapshots SET snapshot_bytes=CAST(? AS TEXT) WHERE snapshot_id=?",
                (snapshot_bytes.decode("ascii"), snapshot_id),
            )
        store._connection.commit()  # noqa: SLF001 - preserve tamper fixture.
        clock.now += timedelta(days=2)
        before = _c2_mutation_state(store)

        repeated = store.record_snapshot(_PARTITION, 1, snapshot_bytes=snapshot_bytes)
        compacted = store.compact_retention(
            _PARTITION,
            basis=_c2_basis(run=b"corrupt-snapshot", through_seq=1, snapshot=snapshot),
        )

        _diagnostic(repeated, "BUS_E_STORE_INTEGRITY", DiagnosticSeverityV2.CRITICAL)
        _diagnostic(compacted, "BUS_E_STORE_INTEGRITY", DiagnosticSeverityV2.CRITICAL)
        assert _c2_mutation_state(store) == before
    finally:
        assert store.close() is None


def test_c2_snapshot_can_start_at_current_retained_head_then_prove_later_gap(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "c2-post-compaction-snapshot", clock)
    try:
        _c2_seed_retention_policy(store)
        _c2_append(store, producer_seq=1, retention_class="transient")
        _c2_append(store, producer_seq=2, retention_class="transient")
        assert store.materialize_digest(_PARTITION, through_seq=2) is not None
        clock.now += timedelta(days=2)
        first = store.compact_retention(
            _PARTITION,
            basis=_c2_basis(run=b"first-prefix", through_seq=2, snapshot=None),
        )
        assert getattr(first, "first_retained_seq") == 3

        _c2_append(
            store, producer_seq=3, retention_class="transient", payload=b"payload-3"
        )
        _c2_append(
            store, producer_seq=4, retention_class="transient", payload=b"payload-4"
        )
        assert store.materialize_digest(_PARTITION, through_seq=4) is not None
        snapshot = store.record_snapshot(_PARTITION, 4, snapshot_bytes=b"new-head")
        assert type(snapshot).__name__ == "SnapshotAnchorV1"
        clock.now += timedelta(days=2)
        generation = store.record_manifest_bytes(_GROUP, manifest_bytes=b"c2-new-head")
        assert isinstance(generation, str)
        assert store.open_cursor_once(_GROUP, _PARTITION, generation) == 0

        second = store.compact_retention(
            _PARTITION,
            basis=_c2_basis(run=b"second-prefix", through_seq=4, snapshot=snapshot),
        )
        gap = store.poll_headers(_GROUP, _PARTITION, generation)

        assert getattr(second, "compacted_through_seq") == 4
        assert type(gap).__name__ == "CursorGapV1"
        assert getattr(gap, "snapshot") == snapshot
        assert getattr(gap, "gap_through_seq") == 4
    finally:
        assert store.close() is None


def test_c2_retention_gap_is_leaseless_until_exact_snapshot_ack(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "c2-gap", clock)
    try:
        _c2_seed_retention_policy(store)
        _c2_append(store, producer_seq=1, retention_class="transient")
        _c2_append(store, producer_seq=2, retention_class="transient")
        _c2_append(store, producer_seq=3, retention_class="work")
        assert store.materialize_digest(_PARTITION, through_seq=2) is not None
        snapshot = store.record_snapshot(_PARTITION, 2, snapshot_bytes=b"opaque")
        assert type(snapshot).__name__ == "SnapshotAnchorV1"
        generation = store.record_manifest_bytes(_GROUP, manifest_bytes=b"c2-gap")
        assert isinstance(generation, str)
        assert store.open_cursor_once(_GROUP, _PARTITION, generation) == 0
        delivery = store.poll_headers(_GROUP, _PARTITION, generation)
        assert type(delivery).__name__ == "DeliveryBatchV1"
        clock.now += timedelta(days=2)
        result = store.compact_retention(
            _PARTITION,
            basis=_c2_basis(run=b"gap", through_seq=2, snapshot=snapshot),
        )
        assert type(result).__name__ == "RetentionRunResultV1"
        opened = store.open_cursor_once(_GROUP, _PARTITION, generation)
        polled = store.poll_headers(_GROUP, _PARTITION, generation)
        assert type(opened).__name__ == "CursorGapV1"
        assert type(polled).__name__ == "CursorGapV1"
        assert getattr(opened, "snapshot") == snapshot
        assert getattr(opened, "gap_from_seq") == 1
        assert getattr(opened, "gap_through_seq") == 2
        assert store._connection.execute(  # noqa: SLF001 - a gap never leases.
            "SELECT COUNT(*) FROM delivery_leases"
        ).fetchone() == (0,)
        wrong_digest = _digest(b"wrong-digest")
        wrong = bus_store.SnapshotAnchorV1(
            snapshot_id=_digest(
                canonical_json_bytes(
                    {
                        "schema_version": 1,
                        "partition": _PARTITION,
                        "through_seq": 2,
                        "snapshot_digest": wrong_digest,
                    }
                )
            ),
            partition=_PARTITION,
            through_seq=2,
            snapshot_digest=wrong_digest,
        )
        before = _c2_mutation_state(store)
        stale = store.ack_cursor_gap(_GROUP, _PARTITION, generation, wrong)
        _diagnostic(stale, "BUS_E_CURSOR_CONFLICT", DiagnosticSeverityV2.ERROR)
        assert _c2_mutation_state(store) == before
        stale_generation = store.ack_cursor_gap(
            _GROUP, _PARTITION, _digest(b"c2-stale-generation"), snapshot
        )
        _diagnostic(
            stale_generation, "BUS_E_CURSOR_CONFLICT", DiagnosticSeverityV2.ERROR
        )
        assert _c2_mutation_state(store) == before
        assert store.ack_cursor_gap(_GROUP, _PARTITION, generation, snapshot) == 2
        assert store._connection.execute(  # noqa: SLF001 - exact ACK clears only gap.
            "SELECT acked_seq,gap_snapshot_id,gap_from_seq,gap_through_seq FROM cursors"
        ).fetchone() == (2, None, None, None)
        after_ack = store.poll_headers(_GROUP, _PARTITION, generation)
        assert type(after_ack).__name__ == "DeliveryBatchV1"
        assert getattr(after_ack, "from_seq") == 3
    finally:
        assert store.close() is None


def test_c2_invalid_retention_basis_has_no_mutation_and_no_manifest_read(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "c2-basis", clock)
    try:
        _c2_seed_retention_policy(store)
        _c2_append(store, producer_seq=1, retention_class="transient")
        assert store.materialize_digest(_PARTITION, through_seq=1) is not None
        clock.now += timedelta(days=2)
        basis = _c2_basis(run=b"invalid", through_seq=1, snapshot=None)
        watermark = getattr(basis, "watermark")
        invalid = bus_store.RetentionBasisV1(
            run_id=getattr(basis, "run_id"),
            watermark=bus_store.MandatoryWatermarkV1(
                partition=getattr(watermark, "partition"),
                retention_generation=getattr(watermark, "retention_generation"),
                mandatory_watermark_seq=getattr(watermark, "mandatory_watermark_seq"),
                subscription_generation=getattr(watermark, "subscription_generation"),
                attestation_digest=_digest(b"invalid-attestation"),
            ),
            snapshot=None,
        )
        before = store._connection.execute(  # noqa: SLF001 - failed basis writes nothing.
            "SELECT COUNT(*) FROM events"
        ).fetchone()
        result = store.compact_retention(_PARTITION, basis=invalid)
        _diagnostic(result, "BUS_E_RETENTION_PRECONDITION", DiagnosticSeverityV2.ERROR)
        assert (
            store._connection.execute("SELECT COUNT(*) FROM events").fetchone()
            == before
        )  # noqa: SLF001

        statements: list[str] = []
        store._connection.set_trace_callback(statements.append)  # noqa: SLF001
        valid = store.compact_retention(_PARTITION, basis=basis)
        store._connection.set_trace_callback(None)  # noqa: SLF001
        assert type(valid).__name__ == "RetentionRunResultV1"
        assert not any("manifest_bytes" in statement for statement in statements)
    finally:
        assert store.close() is None


@pytest.mark.parametrize("anchor_state", ("missing", "wrong"))
def test_c2_missing_or_wrong_digest_anchor_is_precondition_without_mutation(
    secure_tmp_path: Path, anchor_state: str
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / f"c2-anchor-{anchor_state}", clock)
    try:
        _c2_seed_retention_policy(store)
        _c2_append(store, producer_seq=1, retention_class="transient")
        assert store.materialize_digest(_PARTITION, through_seq=1) is not None
        if anchor_state == "missing":
            store._connection.execute(  # noqa: SLF001 - missing-anchor fixture.
                "DELETE FROM digest_anchors WHERE partition=? AND through_seq=?",
                (_PARTITION, 1),
            )
        else:
            store._connection.execute(  # noqa: SLF001 - wrong-anchor fixture.
                "UPDATE digest_anchors SET digest=? WHERE partition=? AND through_seq=?",
                (_digest(b"wrong-anchor"), _PARTITION, 1),
            )
        store._connection.commit()  # noqa: SLF001 - retain corruption fixture.
        clock.now += timedelta(days=2)
        before = _c2_mutation_state(store)

        result = store.compact_retention(
            _PARTITION,
            basis=_c2_basis(
                run=anchor_state.encode("ascii"), through_seq=1, snapshot=None
            ),
        )

        _diagnostic(result, "BUS_E_RETENTION_PRECONDITION", DiagnosticSeverityV2.ERROR)
        assert _c2_mutation_state(store) == before
    finally:
        assert store.close() is None


def test_c2_missing_snapshot_and_cursor_basis_are_preconditions_without_mutation(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "c2-snapshot-cursor-basis", clock)
    try:
        _c2_seed_retention_policy(store)
        _c2_append(store, producer_seq=1, retention_class="transient")
        assert store.materialize_digest(_PARTITION, through_seq=1) is not None
        snapshot = store.record_snapshot(_PARTITION, 1, snapshot_bytes=b"missing")
        assert type(snapshot).__name__ == "SnapshotAnchorV1"
        store._connection.execute(  # noqa: SLF001 - missing-snapshot fixture.
            "DELETE FROM snapshots WHERE snapshot_id=?",
            (getattr(snapshot, "snapshot_id"),),
        )
        store._connection.commit()  # noqa: SLF001 - retain missing-snapshot fixture.
        clock.now += timedelta(days=2)
        before_snapshot = _c2_mutation_state(store)

        missing_snapshot = store.compact_retention(
            _PARTITION,
            basis=_c2_basis(run=b"missing-snapshot", through_seq=1, snapshot=snapshot),
        )

        _diagnostic(
            missing_snapshot,
            "BUS_E_RETENTION_PRECONDITION",
            DiagnosticSeverityV2.ERROR,
        )
        assert _c2_mutation_state(store) == before_snapshot

        generation = store.record_manifest_bytes(
            _GROUP, manifest_bytes=b"c2-cursor-basis"
        )
        assert isinstance(generation, str)
        assert store.open_cursor_once(_GROUP, _PARTITION, generation) == 0
        before_cursor = _c2_mutation_state(store)

        missing_cursor_basis = store.compact_retention(
            _PARTITION,
            basis=_c2_basis(run=b"missing-cursor-basis", through_seq=1, snapshot=None),
        )

        _diagnostic(
            missing_cursor_basis,
            "BUS_E_RETENTION_PRECONDITION",
            DiagnosticSeverityV2.ERROR,
        )
        assert _c2_mutation_state(store) == before_cursor
    finally:
        assert store.close() is None


def test_c2_duplicate_run_with_different_basis_is_precondition_without_mutation(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "c2-duplicate-run", clock)
    try:
        _c2_seed_retention_policy(store)
        _c2_append(store, producer_seq=1, retention_class="transient")
        assert store.materialize_digest(_PARTITION, through_seq=1) is not None
        clock.now += timedelta(days=2)
        first_basis = _c2_basis(run=b"duplicate-run", through_seq=1, snapshot=None)
        assert type(
            store.compact_retention(_PARTITION, basis=first_basis)
        ).__name__ == ("RetentionRunResultV1")
        before = _c2_mutation_state(store)

        different_basis = _c2_basis(run=b"duplicate-run", through_seq=0, snapshot=None)
        duplicate = store.compact_retention(_PARTITION, basis=different_basis)

        _diagnostic(
            duplicate, "BUS_E_RETENTION_PRECONDITION", DiagnosticSeverityV2.ERROR
        )
        assert _c2_mutation_state(store) == before
    finally:
        assert store.close() is None


def test_c2_shared_payload_expires_only_after_last_due_reference(
    secure_tmp_path: Path,
) -> None:
    clock = FakeClock()
    store = _store(secure_tmp_path / "c2-shared", clock)
    try:
        _c2_seed_retention_policy(store)
        _c2_append(
            store, producer_seq=1, retention_class="transient", payload=b"shared"
        )
        _c2_append(store, producer_seq=2, retention_class="work", payload=b"shared")
        assert store.materialize_digest(_PARTITION, through_seq=1) is not None
        clock.now += timedelta(days=2)
        first = store.compact_retention(
            _PARTITION,
            basis=_c2_basis(run=b"shared-first", through_seq=2, snapshot=None),
        )
        assert type(first).__name__ == "RetentionRunResultV1"
        assert getattr(first, "compacted_through_seq") == 1
        assert getattr(first, "expired_payload_count") == 0
        assert store._connection.execute(  # noqa: SLF001 - remaining reference retains body.
            "SELECT body_state,body FROM payloads WHERE kind='inline'"
        ).fetchone() == ("present", b"shared")

        assert store.materialize_digest(_PARTITION, through_seq=2) is not None
        clock.now += timedelta(days=31)
        second = store.compact_retention(
            _PARTITION,
            basis=_c2_basis(run=b"shared-second", through_seq=2, snapshot=None),
        )
        assert type(second).__name__ == "RetentionRunResultV1"
        assert getattr(second, "expired_payload_count") == 1
        assert store._connection.execute(  # noqa: SLF001 - final reference expires once.
            "SELECT body_state,body FROM payloads WHERE kind='inline'"
        ).fetchone() == ("expired", None)
    finally:
        assert store.close() is None


@pytest.mark.parametrize(
    "point",
    (
        "after_checkpoint_lookup",
        "after_snapshot_validation",
        "after_cursor_gaps",
        "after_partition_advance",
        "after_payload_expiry",
        "after_header_delete",
        "after_checkpoint_insert",
    ),
)
def test_c2_retention_crash_boundaries_rollback_then_replay(
    secure_tmp_path: Path, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    class SimulatedCrash(BaseException):
        pass

    root = secure_tmp_path / point
    clock = FakeClock()
    store = _store(root, clock)
    _c2_seed_retention_policy(store)
    _c2_append(store, producer_seq=1, retention_class="transient")
    _c2_append(store, producer_seq=2, retention_class="transient")
    assert store.materialize_digest(_PARTITION, through_seq=2) is not None
    snapshot = store.record_snapshot(_PARTITION, 2, snapshot_bytes=b"crash-opaque")
    generation = store.record_manifest_bytes(_GROUP, manifest_bytes=b"c2-crash")
    assert isinstance(generation, str)
    assert store.open_cursor_once(_GROUP, _PARTITION, generation) == 0
    clock.now += timedelta(days=2)
    basis = _c2_basis(run=point.encode("ascii"), through_seq=2, snapshot=snapshot)

    def fault(stage: str) -> None:
        if stage == point:
            raise SimulatedCrash

    with monkeypatch.context() as scoped:
        scoped.setattr(bus_store, "_retention_checkpoint", fault)
        with pytest.raises(SimulatedCrash):
            store.compact_retention(_PARTITION, basis=basis)
    assert store.close() is not None

    reopened = _store(root, clock)
    try:
        assert reopened._connection.execute(  # noqa: SLF001 - one transaction rolls back.
            "SELECT COUNT(*) FROM events"
        ).fetchone() == (2,)
        assert reopened._connection.execute(
            "SELECT first_retained_seq FROM partitions"
        ).fetchone() == (1,)
        assert reopened._connection.execute(
            "SELECT gap_snapshot_id FROM cursors"
        ).fetchone() == (None,)
        assert reopened._connection.execute(
            "SELECT COUNT(*) FROM retention_checkpoints"
        ).fetchone() == (0,)
        assert reopened._connection.execute(
            "SELECT body_state,body FROM payloads"
        ).fetchone() == ("present", b"payload")
        replay = reopened.compact_retention(_PARTITION, basis=basis)
        assert type(replay).__name__ == "RetentionRunResultV1"
        assert reopened.compact_retention(_PARTITION, basis=basis) == replay
    finally:
        assert reopened.close() is None
