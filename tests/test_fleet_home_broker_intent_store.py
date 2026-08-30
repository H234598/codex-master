from __future__ import annotations

import dataclasses
from dataclasses import FrozenInstanceError
import base64
import errno
import hashlib
import inspect
import json
import threading
import traceback

import pytest

import codex_master.fleet_home_broker_intent_store as intent_store_module
from codex_master.fleet_home_broker_intent import (
    BrokerIntentCode,
    BrokerIntentError,
    BrokerIntentOperation,
    BrokerIntentV1,
    canonical_intent_payload,
    encode_broker_intent,
)
from codex_master.fleet_home_broker_intent_store import (
    BrokerIntentClaimBytes,
    BrokerIntentFileIdentity,
    BrokerIntentStoreOperations,
    ClaimedBrokerIntent,
    LinuxBrokerIntentStore,
    claim_broker_intent,
    publish_broker_intent,
)
from codex_master.fleet_home_broker_identity_contract import ObjectIdentity
from codex_master.fleet_home_broker_linux_contract import (
    LinuxBrokerCode,
    LinuxBrokerError,
    PinnedFd,
)


def _intent(**changes: object) -> BrokerIntentV1:
    values: dict[str, object] = {
        "schema_version": 1,
        "intent_generation": 7,
        "operation": BrokerIntentOperation.PROVISION,
        "transaction_id": "2" * 32,
        "request_id": "1" * 32,
        "agent_id": "bee_1",
        "manifest_generation": 3,
        "unit_generation": 9,
        "policy_generation": 7,
        "fencing_epoch": 4,
        "store_uuid": "3" * 32,
        "slot_id": "slot-01",
        "mcs_pair": "c0,c1",
        "projection_digest": "a" * 64,
        "joint_release_id": "release-0.11.0",
        "server_digest": "b" * 64,
        "broker_manifest_digest": "c" * 64,
        "credential_binding_ref": "cred-bind-01",
        "credential_generation": 2,
        "created_at_unix_ms": 1_700_000_000_000,
        "expires_at_unix_ms": 1_700_000_030_000,
        "nonce": "d" * 32,
        "digest": "0" * 64,
    }
    values.update(changes)
    unsigned = BrokerIntentV1(**values)
    digest = hashlib.sha256(canonical_intent_payload(unsigned)).hexdigest()
    return dataclasses.replace(unsigned, digest=digest)


INTENT = _intent()
IDENTITY = BrokerIntentFileIdentity(
    8, 101, 0o100600, 0, 0, 1, "system_u:object_r:codex_master_home_broker_state_t:s0"
)
PARENT_IDENTITY = BrokerIntentFileIdentity(
    8,
    100,
    0o40700,
    0,
    0,
    2,
    "system_u:object_r:codex_master_home_broker_state_t:s0",
)


def _active_intent_name(kind: str, index: int) -> str:
    suffix = f"intent-{index:020d}-{index:032x}.json"
    if kind == "pending":
        return suffix
    if kind == "claim":
        return f".claim-{suffix}"
    if kind == "recover":
        return f".recover-{suffix}"
    raise AssertionError("unknown active intent kind")


def _add_active_intent(
    operations: FakeLinuxOperations, name: str, payload: bytes | None = None
) -> None:
    operations.files[name] = (
        encode_broker_intent(INTENT) if payload is None else payload
    )
    operations.identities[name] = ObjectIdentity(
        8, 2000 + len(operations.files), 0o100600, 0, 0, 1
    )
    operations.labels[name] = PARENT_IDENTITY.selinux_label


def _active_intent_count(operations: FakeLinuxOperations) -> int:
    return sum(
        name.startswith("intent-")
        or name.startswith(".claim-intent-")
        or name.startswith(".recover-intent-")
        for name in operations.files
    )


def _admission_observation_ceiling() -> int:
    return intent_store_module.MAX_INTENT_STORE_ADMISSION_OBSERVATION_RECORDS


def _bounded_observation(
    names: tuple[str, ...], complete: bool, overflow: bool
) -> object:
    return intent_store_module._BoundedIntentNameObservation(  # type: ignore[attr-defined]
        names, complete, overflow
    )


def _terminal_evidence_records(
    claim_name: str, intent_payload: bytes
) -> tuple[str, bytes, str, bytes]:
    """Build the independently verified terminal sidecar expected by recovery."""

    name_digest = hashlib.sha256(claim_name.encode("ascii")).hexdigest()
    evidence_name = f".terminal-evidence-{name_digest}.json"
    evidence = (
        json.dumps(
            {
                "claim_name": claim_name,
                "intent_b64": base64.b64encode(intent_payload).decode("ascii"),
                "result": "succeeded",
                "schema_version": 1,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    commit_name = f".terminal-commit-{name_digest}.json"
    commit = (
        json.dumps(
            {
                "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
                "schema_version": 1,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    return evidence_name, evidence, commit_name, commit


def _terminal_staging_name(kind: str, final_name: str, index: int = 0) -> str:
    return (
        f".tmp-terminal-{kind}-"
        f"{hashlib.sha256(final_name.encode('ascii')).hexdigest()}-{index}.json"
    )


class FakeStore:
    def __init__(
        self,
        claim: BrokerIntentClaimBytes | None = None,
        *,
        recovery: BrokerIntentClaimBytes | None = None,
    ) -> None:
        self.published: list[tuple[bytes, str]] = []
        self.claims = [claim] if claim is not None else []
        self.recoveries = [recovery] if recovery is not None else []
        self.terminals: list[tuple[str, bytes]] = []
        self.quarantines: list[tuple[str, str]] = []

    def publish(self, payload: bytes, final_name: str) -> None:
        self.published.append((payload, final_name))

    def claim_next(self) -> BrokerIntentClaimBytes | None:
        if not self.claims:
            return None
        return self.claims.pop(0)

    def recover_next(self) -> BrokerIntentClaimBytes | None:
        if not self.recoveries:
            return None
        return self.recoveries.pop(0)

    def mark_terminal(self, claim_name: str, payload: bytes) -> None:
        self.terminals.append((claim_name, payload))

    def quarantine(self, claim_name: str, code: str) -> None:
        self.quarantines.append((claim_name, code))

    def release_claim(self, claim_name: str) -> None:
        return None


class FakeLinuxOperations:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.files: dict[str, bytes] = {}
        self.identities: dict[str, ObjectIdentity] = {}
        self.labels: dict[str, str] = {}
        self.fd_names: dict[int, str] = {}
        self.open_flags: dict[int, int] = {}
        self.next_fd = 10
        self.parent_stat = ObjectIdentity(8, 100, 0o40700, 0, 0, 2)
        self.parent_label = PARENT_IDENTITY.selinux_label
        self.write_result: int | None = None
        self.write_error: BaseException | None = None
        self.fsync_error: BaseException | None = None
        self.rename_error: BaseException | None = None
        self.stat_sequences: dict[str, list[ObjectIdentity]] = {}
        self.parent_stat_sequence: list[ObjectIdentity] = []
        self.pinned_identity_overrides: dict[str, ObjectIdentity] = {}
        self.locked_fds: dict[int, tuple[int, int]] = {}
        self._locked_identities: set[tuple[int, int]] = set()
        self.observed_entries = 0

    def openat2(self, parent_fd: int, name: str, how: object) -> PinnedFd:
        self.calls.append(("openat2", parent_fd, name, how))
        if name not in self.files:
            if not (getattr(how, "flags", 0) & 0o200):
                raise FileNotFoundError(errno.ENOENT, "missing")
            self.files[name] = b""
            self.identities[name] = ObjectIdentity(
                8, 1000 + self.next_fd, 0o100600, 0, 0, 1
            )
            self.labels[name] = PARENT_IDENTITY.selinux_label
        elif getattr(how, "flags", 0) & 0o200:
            raise FileExistsError(errno.EEXIST, "exists")
        if getattr(how, "flags", 0) & 0o1000:
            self.files[name] = b""
        fd = self.next_fd
        self.next_fd += 1
        self.fd_names[fd] = name
        self.open_flags[fd] = getattr(how, "flags", 0)
        return PinnedFd(
            fd, self.pinned_identity_overrides.get(name, self.identities[name])
        )

    def stat_fd(self, fd: int) -> ObjectIdentity:
        self.calls.append(("stat_fd", fd))
        if fd == 7:
            if self.parent_stat_sequence:
                return self.parent_stat_sequence.pop(0)
            return self.parent_stat
        name = self.fd_names[fd]
        sequence = self.stat_sequences.get(name)
        if sequence:
            result = sequence.pop(0)
            self.identities[name] = result
            return result
        return self.identities[name]

    def selinux_label(self, fd: int) -> str:
        self.calls.append(("selinux_label", fd))
        return self.parent_label if fd == 7 else self.labels[self.fd_names[fd]]

    def list_names(self, parent_fd: int) -> tuple[str, ...]:
        self.calls.append(("list_names", parent_fd))
        return tuple(sorted(self.files))

    def observe_names_bounded(self, parent_fd: int, maximum: int) -> object:
        self.calls.append(("observe_names_bounded", parent_fd, maximum))
        names: list[str] = []
        for name in self.files:
            self.observed_entries += 1
            if len(names) >= maximum:
                return _bounded_observation((), False, True)
            names.append(name)
        return _bounded_observation(tuple(names), True, False)

    def read_all(self, fd: int) -> bytes:
        self.calls.append(("read_all", fd))
        return self.files[self.fd_names[fd]]

    def write_all(self, fd: int, payload: bytes) -> int | None:
        self.calls.append(("write_all", fd, payload))
        if self.write_error is not None:
            raise self.write_error
        name = self.fd_names[fd]
        if self.write_result is not None:
            written = payload[: self.write_result]
            if self.open_flags[fd] & 0o1000:
                self.files[name] = written
            else:
                self.files[name] = written + self.files[name][len(written) :]
            return self.write_result
        if self.open_flags[fd] & 0o1000:
            self.files[name] = payload
        else:
            self.files[name] = payload + self.files[name][len(payload) :]
        return None

    def fsync(self, fd: int) -> None:
        self.calls.append(("fsync", fd))
        if self.fsync_error is not None:
            raise self.fsync_error

    def truncate(self, fd: int) -> None:
        self.calls.append(("truncate", fd))
        self.files[self.fd_names[fd]] = b""

    def renameat2_noreplace(self, parent_fd: int, old_name: str, new_name: str) -> None:
        self.calls.append(("renameat2_noreplace", parent_fd, old_name, new_name))
        if self.rename_error is not None:
            raise self.rename_error
        if new_name in self.files:
            raise FileExistsError(errno.EEXIST, "exists")
        if old_name not in self.files:
            raise FileNotFoundError(errno.ENOENT, "missing")
        self.files[new_name] = self.files.pop(old_name)
        self.identities[new_name] = self.identities.pop(old_name)
        self.labels[new_name] = self.labels.pop(old_name)
        for fd, name in self.fd_names.items():
            if name == old_name:
                self.fd_names[fd] = new_name

    def unlinkat(self, parent_fd: int, name: str) -> None:
        self.calls.append(("unlinkat", parent_fd, name))
        if name not in self.files:
            raise FileNotFoundError(errno.ENOENT, "missing")
        self.files.pop(name)
        self.identities.pop(name)
        self.labels.pop(name)

    def lock_exclusive_nonblocking(self, fd: int) -> None:
        self.calls.append(("lock_exclusive_nonblocking", fd))
        pinned = getattr(self, "_fd_identities", None)
        if fd == 7:
            identity = self.parent_stat
        else:
            identity = (
                pinned[fd]
                if type(pinned) is dict and fd in pinned
                else self.identities[self.fd_names[fd]]
            )
        key = (identity.dev, identity.ino)
        if key in self._locked_identities:
            raise BlockingIOError(errno.EAGAIN, "leased")
        self._locked_identities.add(key)
        self.locked_fds[fd] = key

    def unlock_exclusive(self, fd: int) -> None:
        self.calls.append(("unlock_exclusive", fd))
        key = self.locked_fds.pop(fd, None)
        if key is None:
            raise OSError(errno.EINVAL, "not locked")
        self._locked_identities.remove(key)

    def close(self, fd: int) -> None:
        self.calls.append(("close", fd))
        key = self.locked_fds.pop(fd, None)
        if key is not None:
            self._locked_identities.remove(key)
        self.fd_names.pop(fd, None)
        self.open_flags.pop(fd, None)

    def crash(self) -> None:
        for fd in tuple(self.locked_fds):
            self.close(fd)


class AtomicClaimLinuxOperations(FakeLinuxOperations):
    def __init__(self) -> None:
        super().__init__()
        self._state_lock = threading.Lock()
        self._read_barrier = threading.Barrier(2)
        self._fd_identities: dict[int, ObjectIdentity] = {}
        self._fd_labels: dict[int, str] = {}

    def openat2(self, parent_fd: int, name: str, how: object) -> PinnedFd:
        with self._state_lock:
            pinned = super().openat2(parent_fd, name, how)
            self._fd_identities[pinned.fd] = pinned.identity
            self._fd_labels[pinned.fd] = self.labels[name]
            return pinned

    def stat_fd(self, fd: int) -> ObjectIdentity:
        if fd in self._fd_identities:
            self.calls.append(("stat_fd", fd))
            return self._fd_identities[fd]
        return super().stat_fd(fd)

    def selinux_label(self, fd: int) -> str:
        if fd in self._fd_labels:
            self.calls.append(("selinux_label", fd))
            return self._fd_labels[fd]
        return super().selinux_label(fd)

    def read_all(self, fd: int) -> bytes:
        with self._state_lock:
            payload = super().read_all(fd)
        self._read_barrier.wait(timeout=5)
        return payload

    def renameat2_noreplace(self, parent_fd: int, old_name: str, new_name: str) -> None:
        with self._state_lock:
            super().renameat2_noreplace(parent_fd, old_name, new_name)

    def close(self, fd: int) -> None:
        super().close(fd)
        self._fd_identities.pop(fd, None)
        self._fd_labels.pop(fd, None)


class AtomicRecoveryLinuxOperations(FakeLinuxOperations):
    """Shared fake directory where FDs remain pinned across a rename."""

    def __init__(self) -> None:
        super().__init__()
        self._state_lock = threading.Lock()
        self._fd_identities: dict[int, ObjectIdentity] = {}
        self._fd_labels: dict[int, str] = {}

    def openat2(self, parent_fd: int, name: str, how: object) -> PinnedFd:
        with self._state_lock:
            pinned = super().openat2(parent_fd, name, how)
            self._fd_identities[pinned.fd] = pinned.identity
            self._fd_labels[pinned.fd] = self.labels[name]
            return pinned

    def stat_fd(self, fd: int) -> ObjectIdentity:
        if fd in self._fd_identities:
            self.calls.append(("stat_fd", fd))
            return self._fd_identities[fd]
        return super().stat_fd(fd)

    def selinux_label(self, fd: int) -> str:
        if fd in self._fd_labels:
            self.calls.append(("selinux_label", fd))
            return self._fd_labels[fd]
        return super().selinux_label(fd)

    def lock_exclusive_nonblocking(self, fd: int) -> None:
        with self._state_lock:
            super().lock_exclusive_nonblocking(fd)

    def renameat2_noreplace(self, parent_fd: int, old_name: str, new_name: str) -> None:
        with self._state_lock:
            super().renameat2_noreplace(parent_fd, old_name, new_name)

    def close(self, fd: int) -> None:
        with self._state_lock:
            super().close(fd)
            self._fd_identities.pop(fd, None)
            self._fd_labels.pop(fd, None)


class AtomicPublishLinuxOperations(FakeLinuxOperations):
    """Shared fake directory that serializes the parent-descriptor lease."""

    def __init__(self) -> None:
        super().__init__()
        self._state_lock = threading.Lock()

    def lock_exclusive_nonblocking(self, fd: int) -> None:
        with self._state_lock:
            super().lock_exclusive_nonblocking(fd)

    def unlock_exclusive(self, fd: int) -> None:
        with self._state_lock:
            super().unlock_exclusive(fd)


def test_public_store_types_are_frozen_slotted_and_protocol_is_narrow() -> None:
    for type_ in (
        BrokerIntentFileIdentity,
        BrokerIntentClaimBytes,
        ClaimedBrokerIntent,
    ):
        assert dataclasses.is_dataclass(type_)
        assert type_.__dataclass_params__.frozen
        assert hasattr(type_, "__slots__")
    with pytest.raises(FrozenInstanceError):
        IDENTITY.selinux_label = "other"  # type: ignore[misc]
    assert getattr(BrokerIntentStoreOperations, "_is_protocol", False)
    assert tuple(inspect.signature(BrokerIntentStoreOperations.publish).parameters) == (
        "self",
        "payload",
        "final_name",
    )
    assert tuple(
        inspect.signature(BrokerIntentStoreOperations.claim_next).parameters
    ) == ("self",)
    assert tuple(
        inspect.signature(BrokerIntentStoreOperations.recover_next).parameters
    ) == ("self",)
    assert tuple(
        inspect.signature(BrokerIntentStoreOperations.mark_terminal).parameters
    ) == (
        "self",
        "claim_name",
        "payload",
    )
    assert tuple(
        inspect.signature(BrokerIntentStoreOperations.quarantine).parameters
    ) == (
        "self",
        "claim_name",
        "code",
    )
    assert tuple(
        inspect.signature(BrokerIntentStoreOperations.release_claim).parameters
    ) == ("self", "claim_name")


def test_publish_encodes_once_and_uses_safe_nonce_bound_final_name() -> None:
    store = FakeStore()
    assert publish_broker_intent(store, INTENT) is None
    assert store.published == [
        (
            encode_broker_intent(INTENT),
            "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json",
        )
    ]


def test_public_publish_preserves_value_free_queue_full_without_details() -> None:
    class FullStore(FakeStore):
        def publish(self, payload: bytes, final_name: str) -> None:
            raise BrokerIntentError(BrokerIntentCode.QUEUE_FULL)

    with pytest.raises(BrokerIntentError) as raised:
        publish_broker_intent(FullStore(), INTENT)

    assert raised.value.code is BrokerIntentCode.QUEUE_FULL
    assert str(raised.value) == "queue_full"
    assert raised.value.__context__ is None


def test_claim_decodes_one_claim_and_preserves_source_identity() -> None:
    payload = encode_broker_intent(INTENT)
    store = FakeStore(BrokerIntentClaimBytes("claim-01", payload, IDENTITY))
    claimed = claim_broker_intent(store, now_unix_ms=1_700_000_001_000)
    assert claimed == ClaimedBrokerIntent(INTENT, "claim-01", IDENTITY)
    assert store.quarantines == []


def test_empty_store_returns_none_without_mutation() -> None:
    store = FakeStore()
    assert claim_broker_intent(store, now_unix_ms=1_700_000_001_000) is None
    assert store.quarantines == []
    assert store.terminals == []


def test_invalid_or_expired_claim_is_quarantined_without_retry() -> None:
    expired = _intent(expires_at_unix_ms=1_700_000_001_000)
    store = FakeStore(
        BrokerIntentClaimBytes("claim-expired", encode_broker_intent(expired), IDENTITY)
    )
    assert claim_broker_intent(store, now_unix_ms=1_700_000_001_000) is None
    assert store.quarantines == [("claim-expired", "expired")]
    assert claim_broker_intent(store, now_unix_ms=1_700_000_001_000) is None
    assert store.quarantines == [("claim-expired", "expired")]


def test_public_publish_maps_malformed_operation_return_to_stable_error() -> None:
    class MalformedPublish(FakeStore):
        def publish(self, payload: bytes, final_name: str) -> object:
            return object()

    with pytest.raises(BrokerIntentError) as raised:
        publish_broker_intent(MalformedPublish(), INTENT)

    assert raised.value.code is BrokerIntentCode.INVALID_TYPE


def test_public_claim_maps_malformed_operation_return_to_stable_error() -> None:
    class MalformedClaim(FakeStore):
        def claim_next(self) -> object:
            return object()

    with pytest.raises(BrokerIntentError) as raised:
        claim_broker_intent(MalformedClaim(), now_unix_ms=1_700_000_001_000)

    assert raised.value.code is BrokerIntentCode.INVALID_TYPE


def test_public_publish_maps_platform_error_without_leaking_details() -> None:
    class BrokenPublish(FakeStore):
        def publish(self, payload: bytes, final_name: str) -> None:
            raise OSError(errno.EIO, "host-path-secret")

    with pytest.raises(BrokerIntentError) as raised:
        publish_broker_intent(BrokenPublish(), INTENT)

    assert raised.value.code is BrokerIntentCode.INVALID_FIELD
    assert str(raised.value) == BrokerIntentCode.INVALID_FIELD.value
    assert "host-path-secret" not in str(raised.value)


def test_public_publish_clears_operation_error_context() -> None:
    class BrokenPublish(FakeStore):
        def publish(self, payload: bytes, final_name: str) -> None:
            raise OSError(errno.EIO, "context-operation-secret")

    with pytest.raises(BrokerIntentError) as caught:
        publish_broker_intent(BrokenPublish(), INTENT)

    assert caught.value.__context__ is None
    assert "context-operation-secret" not in "".join(
        traceback.format_exception(caught.value)
    )


def test_public_claim_maps_linux_error_without_leaking_details() -> None:
    class BrokenClaim(FakeStore):
        def claim_next(self) -> None:
            raise LinuxBrokerError(LinuxBrokerCode.IO_FAILURE)

    with pytest.raises(BrokerIntentError) as raised:
        claim_broker_intent(BrokenClaim(), now_unix_ms=1_700_000_001_000)

    assert raised.value.code is BrokerIntentCode.INVALID_FIELD


def test_public_quarantine_maps_operation_error_and_return_to_stable_errors() -> None:
    expired = _intent(expires_at_unix_ms=1_700_000_001_000)

    class BrokenQuarantine(FakeStore):
        def quarantine(self, claim_name: str, code: str) -> None:
            raise ValueError("quarantine-path-secret")

    broken = BrokenQuarantine(
        BrokerIntentClaimBytes("claim-expired", encode_broker_intent(expired), IDENTITY)
    )
    with pytest.raises(BrokerIntentError) as raised:
        claim_broker_intent(broken, now_unix_ms=1_700_000_001_000)
    assert raised.value.code is BrokerIntentCode.INVALID_FIELD
    assert "quarantine-path-secret" not in str(raised.value)

    class MalformedQuarantine(FakeStore):
        def quarantine(self, claim_name: str, code: str) -> object:
            return object()

    malformed = MalformedQuarantine(
        BrokerIntentClaimBytes("claim-expired", encode_broker_intent(expired), IDENTITY)
    )
    with pytest.raises(BrokerIntentError) as raised:
        claim_broker_intent(malformed, now_unix_ms=1_700_000_001_000)
    assert raised.value.code is BrokerIntentCode.INVALID_TYPE


def test_public_claim_maps_unexpected_codec_category_to_stable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claim = BrokerIntentClaimBytes("claim-expired", b"payload", IDENTITY)

    class UnexpectedCode:
        value = "not-a-stable-code"

    def unexpected_decode(payload: bytes, *, now_unix_ms: int) -> BrokerIntentV1:
        raise BrokerIntentError(UnexpectedCode())  # type: ignore[arg-type]

    monkeypatch.setattr(intent_store_module, "decode_broker_intent", unexpected_decode)
    with pytest.raises(BrokerIntentError) as raised:
        claim_broker_intent(FakeStore(claim), now_unix_ms=1_700_000_001_000)

    assert raised.value.code is BrokerIntentCode.INVALID_FIELD


def test_linux_publish_admission_allows_128th_then_rejects_full_before_file_io() -> (
    None
):
    operations = FakeLinuxOperations()
    for index in range(127):
        _add_active_intent(operations, _active_intent_name("pending", index))
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    payload = encode_broker_intent(INTENT)
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"

    adapter.publish(payload, final_name)

    assert _active_intent_count(operations) == 128
    calls_before_rejection = len(operations.calls)
    with pytest.raises(BrokerIntentError) as raised:
        adapter.publish(
            payload, "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json"
        )

    assert raised.value.code is BrokerIntentCode.QUEUE_FULL
    assert str(raised.value) == "queue_full"
    assert _active_intent_count(operations) == 128
    rejected_calls = operations.calls[calls_before_rejection:]
    assert not any(
        call[0] in {"write_all", "renameat2_noreplace", "fsync"}
        or (call[0] == "openat2" and str(call[2]).startswith(".tmp-intent-"))
        for call in rejected_calls
    )
    assert not any(name.startswith(".tmp-intent-") for name in operations.files)


def test_linux_publish_admission_reports_queue_full_for_129_safe_active_entries() -> (
    None
):
    operations = FakeLinuxOperations()
    for index in range(129):
        _add_active_intent(operations, _active_intent_name("pending", index))
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    calls_before_publish = len(operations.calls)

    with pytest.raises(BrokerIntentError) as raised:
        adapter.publish(
            encode_broker_intent(INTENT),
            "intent-00000000000000000129-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        )

    assert raised.value.code is BrokerIntentCode.QUEUE_FULL
    assert str(raised.value) == "queue_full"
    assert _active_intent_count(operations) == 129
    publication_calls = operations.calls[calls_before_publish:]
    assert not any(
        call[0] in {"write_all", "renameat2_noreplace", "fsync"}
        or (call[0] == "openat2" and str(call[2]).startswith(".tmp-intent-"))
        for call in publication_calls
    )
    assert not any(name.startswith(".tmp-intent-") for name in operations.files)


def test_linux_publish_admission_ceiling_is_bounded_before_active_scan() -> None:
    operations = FakeLinuxOperations()
    for index in range(128):
        _add_active_intent(operations, _active_intent_name("pending", index))
    for index in range(128):
        _add_active_intent(operations, f".terminal-evidence-{index:032x}.json")
        _add_active_intent(operations, f".terminal-commit-{index:032x}.json")
        _add_active_intent(operations, f".quarantine-invalid-{index:032x}.json")
    ceiling = _admission_observation_ceiling()
    assert len(operations.files) == (
        intent_store_module.MAX_PENDING_INTENT_RECORDS
        + intent_store_module.MAX_TERMINAL_INTENT_RECORDS * 2
        + intent_store_module.MAX_QUARANTINED_INTENT_RECORDS
    )
    assert _active_intent_count(operations) == 128
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    calls_before_publish = len(operations.calls)

    with pytest.raises(BrokerIntentError) as raised:
        adapter.publish(
            encode_broker_intent(INTENT),
            "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        )

    assert raised.value.code is BrokerIntentCode.QUEUE_FULL
    admission_calls = operations.calls[calls_before_publish:]
    assert [call for call in admission_calls if call[0] == "observe_names_bounded"] == [
        ("observe_names_bounded", 7, ceiling)
    ]
    assert not any(call[0] == "list_names" for call in admission_calls)
    assert sum(call[0] == "openat2" for call in admission_calls) == 128
    assert sum(call[0] == "close" for call in admission_calls) == 128
    assert not any(
        call[0] in {"write_all", "renameat2_noreplace", "fsync"}
        or (call[0] == "openat2" and str(call[2]).startswith(".tmp-intent-"))
        for call in admission_calls
    )


def test_linux_publish_admission_ignores_unbounded_failed_staging_attempts() -> None:
    operations = FakeLinuxOperations()
    active_before = intent_store_module.MAX_PENDING_INTENT_RECORDS - 1
    staging_classes = intent_store_module.MAX_INTENT_PUBLISH_STAGING_RECORDS + 2
    staging_attempts = (
        _admission_observation_ceiling() - active_before
    ) // staging_classes
    for index in range(active_before):
        _add_active_intent(operations, _active_intent_name("pending", index))
    for index in range(staging_attempts):
        _add_active_intent(operations, f".tmp-intent-crash-{index:032x}.json")
        _add_active_intent(
            operations,
            f".tmp-terminal-evidence-crash-{index:032x}-0.json",
        )
        _add_active_intent(
            operations,
            f".tmp-terminal-commit-crash-{index:032x}-0.json",
        )
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    calls_before_publish = len(operations.calls)

    adapter.publish(
        encode_broker_intent(INTENT),
        "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
    )

    admission_calls = operations.calls[calls_before_publish:]
    observe_index = next(
        index
        for index, call in enumerate(admission_calls)
        if call[0] == "observe_names_bounded"
    )
    assert admission_calls[observe_index] == (
        "observe_names_bounded",
        7,
        _admission_observation_ceiling(),
    )
    assert not any(
        call[0] == "openat2"
        and (
            str(call[2]).startswith(".tmp-intent-")
            or str(call[2]).startswith(".tmp-terminal-")
        )
        for call in admission_calls[: observe_index + 1]
    )
    assert (
        _active_intent_count(operations)
        == intent_store_module.MAX_PENDING_INTENT_RECORDS
    )
    assert sum(name.startswith(".tmp-intent-") for name in operations.files) == 0
    assert sum(name.startswith(".tmp-terminal-") for name in operations.files) == (
        staging_attempts * 2
    )


def test_linux_admission_ceiling_covers_each_bounded_store_name_class() -> None:
    assert _admission_observation_ceiling() == (
        intent_store_module.MAX_PENDING_INTENT_RECORDS
        + intent_store_module.MAX_TERMINAL_INTENT_RECORDS
        * len(intent_store_module._TERMINAL_STAGING_KINDS)
        + intent_store_module.MAX_QUARANTINED_INTENT_RECORDS
        + intent_store_module.MAX_INTENT_PUBLISH_STAGING_RECORDS
        + intent_store_module.MAX_PENDING_INTENT_RECORDS
        * len(intent_store_module._TERMINAL_STAGING_KINDS)
        * intent_store_module.MAX_TERMINAL_STAGING_RECORDS
    )


def test_linux_admission_overflows_at_first_name_beyond_all_class_budgets() -> None:
    operations = FakeLinuxOperations()
    for index in range(intent_store_module.MAX_PENDING_INTENT_RECORDS):
        _add_active_intent(operations, _active_intent_name("claim", index))
    for index in range(intent_store_module.MAX_TERMINAL_INTENT_RECORDS):
        _add_active_intent(operations, f".terminal-evidence-{index:032x}.json")
        _add_active_intent(operations, f".terminal-commit-{index:032x}.json")
        _add_active_intent(operations, f".quarantine-invalid-{index:032x}.json")
    _add_active_intent(operations, intent_store_module._PUBLISH_STAGING_NAME)
    for index in range(intent_store_module.MAX_PENDING_INTENT_RECORDS):
        claim_name = _active_intent_name("claim", index)
        evidence_name, _, commit_name, _ = _terminal_evidence_records(claim_name, b"")
        for kind, final_name in zip(
            intent_store_module._TERMINAL_STAGING_KINDS,
            (evidence_name, commit_name),
        ):
            for staging_index in range(
                intent_store_module.MAX_TERMINAL_STAGING_RECORDS
            ):
                _add_active_intent(
                    operations,
                    _terminal_staging_name(kind, final_name, staging_index),
                )
    _add_active_intent(operations, ".tmp-terminal-overflow.json")

    ceiling = _admission_observation_ceiling()
    assert len(operations.files) == ceiling + 1
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(
            encode_broker_intent(INTENT),
            "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        )

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    assert operations.observed_entries == (
        ceiling + intent_store_module.MAX_INTENT_STORE_ADMISSION_SENTINEL_RECORDS
    )
    assert not any(
        call[0] in {"openat2", "write_all", "renameat2_noreplace", "fsync"}
        for call in operations.calls
    )


@pytest.mark.parametrize("kind", ("overflow", "incomplete"))
def test_linux_publish_admission_rejects_nonfinal_bounded_observation(
    kind: str,
) -> None:
    ceiling = _admission_observation_ceiling()

    if kind == "overflow":
        operations = FakeLinuxOperations()
        for index in range(ceiling + 1):
            _add_active_intent(operations, _active_intent_name("pending", index))
    else:

        class IncompleteObservationOperations(FakeLinuxOperations):
            def observe_names_bounded(self, parent_fd: int, maximum: int) -> object:
                self.calls.append(("observe_names_bounded", parent_fd, maximum))
                return _bounded_observation((), False, False)

        operations = IncompleteObservationOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    calls_before_publish = len(operations.calls)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(
            encode_broker_intent(INTENT),
            "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        )

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    admission_calls = operations.calls[calls_before_publish:]
    assert [call for call in admission_calls if call[0] == "observe_names_bounded"] == [
        ("observe_names_bounded", 7, ceiling)
    ]
    if kind == "overflow":
        assert operations.observed_entries == ceiling + 1
    else:
        assert operations.observed_entries == 0
    assert not any(
        call[0]
        in {"list_names", "openat2", "write_all", "renameat2_noreplace", "fsync"}
        for call in admission_calls
    )


def test_linux_publish_admission_rejects_duplicate_bounded_observation() -> None:
    name = _active_intent_name("pending", 0)

    class DuplicateObservationOperations(FakeLinuxOperations):
        def observe_names_bounded(self, parent_fd: int, maximum: int) -> object:
            self.calls.append(("observe_names_bounded", parent_fd, maximum))
            return _bounded_observation((name, name), True, False)

    operations = DuplicateObservationOperations()
    _add_active_intent(operations, name)
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    calls_before_publish = len(operations.calls)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(
            encode_broker_intent(INTENT),
            "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        )

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    admission_calls = operations.calls[calls_before_publish:]
    assert not any(
        call[0]
        in {"list_names", "openat2", "write_all", "renameat2_noreplace", "fsync"}
        for call in admission_calls
    )


def test_linux_publish_admission_rejects_nonactive_bounded_name() -> None:
    class LeakingObservationOperations(FakeLinuxOperations):
        def observe_names_bounded(self, parent_fd: int, maximum: int) -> object:
            self.calls.append(("observe_names_bounded", parent_fd, maximum))
            return _bounded_observation(("unrelated",), True, False)

    operations = LeakingObservationOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    calls_before_publish = len(operations.calls)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(
            encode_broker_intent(INTENT),
            "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        )

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    admission_calls = operations.calls[calls_before_publish:]
    assert not any(
        call[0]
        in {"list_names", "openat2", "write_all", "renameat2_noreplace", "fsync"}
        for call in admission_calls
    )


def test_linux_publish_admission_close_failure_is_not_queue_full() -> None:
    class CloseFailureOperations(FakeLinuxOperations):
        def close(self, fd: int) -> None:
            self.calls.append(("close", fd))
            raise OSError(errno.EIO, "admission-close-secret")

    operations = CloseFailureOperations()
    for index in range(128):
        _add_active_intent(operations, _active_intent_name("pending", index))
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(
            encode_broker_intent(INTENT),
            "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        )

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    assert not any(name.startswith(".tmp-intent-") for name in operations.files)


def test_linux_publish_admission_preserves_identity_failure_when_active_close_fails() -> (
    None
):
    class CloseFailureOperations(FakeLinuxOperations):
        def close(self, fd: int) -> None:
            self.calls.append(("close", fd))
            raise OSError(errno.EIO, "admission-close-secret")

    operations = CloseFailureOperations()
    for index in range(128):
        _add_active_intent(operations, _active_intent_name("pending", index))
    unsafe_name = _active_intent_name("pending", 0)
    safe_identity = operations.identities[unsafe_name]
    operations.stat_sequences[unsafe_name] = [
        safe_identity,
        ObjectIdentity(8, safe_identity.ino, 0o100600, 0, 0, 2),
    ]
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(
            encode_broker_intent(INTENT),
            "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        )

    assert raised.value.code is LinuxBrokerCode.IDENTITY_MISMATCH


@pytest.mark.parametrize(
    "mutate",
    (
        lambda operations, name: operations.identities.__setitem__(
            name, ObjectIdentity(8, 2065, 0o100600, 0, 0, 2)
        ),
        lambda operations, name: operations.identities.__setitem__(
            name, ObjectIdentity(8, 2065, 0o100666, 0, 0, 1)
        ),
        lambda operations, name: operations.labels.__setitem__(
            name, "system_u:object_r:tmp_t:s0"
        ),
    ),
    ids=("hardlink", "mode", "selinux_label"),
)
def test_linux_publish_admission_rejects_unsafe_active_entry_before_queue_full(
    mutate,
) -> None:
    operations = FakeLinuxOperations()
    for index in range(128):
        _add_active_intent(operations, _active_intent_name("pending", index))
    unsafe_name = _active_intent_name("pending", 64)
    mutate(operations, unsafe_name)
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    calls_before_publish = len(operations.calls)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(
            encode_broker_intent(INTENT),
            "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        )

    assert raised.value.code is LinuxBrokerCode.IDENTITY_MISMATCH
    publication_calls = operations.calls[calls_before_publish:]
    assert not any(
        call[0] in {"write_all", "renameat2_noreplace", "fsync"}
        or (call[0] == "openat2" and str(call[2]).startswith(".tmp-intent-"))
        for call in publication_calls
    )


def test_linux_publish_admission_rejects_active_entry_missing_after_listing() -> None:
    missing_name = _active_intent_name("pending", 128)

    class MissingActiveEntryOperations(FakeLinuxOperations):
        def observe_names_bounded(self, parent_fd: int, maximum: int) -> object:
            observation = super().observe_names_bounded(parent_fd, maximum)
            return _bounded_observation(
                (*observation.names, missing_name),
                True,
                False,  # type: ignore[attr-defined]
            )

    operations = MissingActiveEntryOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    calls_before_publish = len(operations.calls)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(
            encode_broker_intent(INTENT),
            "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        )

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    publication_calls = operations.calls[calls_before_publish:]
    assert not any(
        call[0] in {"write_all", "renameat2_noreplace", "fsync"}
        or (call[0] == "openat2" and str(call[2]).startswith(".tmp-intent-"))
        for call in publication_calls
    )


def test_linux_publish_admission_counts_pending_claim_and_recover_until_claim_removed() -> (
    None
):
    operations = FakeLinuxOperations()
    for index in range(42):
        _add_active_intent(operations, _active_intent_name("pending", index))
    terminal_claim = _active_intent_name("claim", 0)
    intent_payload = encode_broker_intent(INTENT)
    _add_active_intent(operations, terminal_claim, intent_payload)
    for index in range(1, 43):
        _add_active_intent(operations, _active_intent_name("claim", index))
    for index in range(43):
        _add_active_intent(operations, _active_intent_name("recover", index))
    evidence_name, evidence, commit_name, commit = _terminal_evidence_records(
        terminal_claim, intent_payload
    )
    _add_active_intent(operations, evidence_name, evidence)
    _add_active_intent(operations, commit_name, commit)
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    payload = encode_broker_intent(INTENT)
    final_name = "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json"

    assert _active_intent_count(operations) == 128
    with pytest.raises(BrokerIntentError) as raised:
        adapter.publish(payload, final_name)
    assert raised.value.code is BrokerIntentCode.QUEUE_FULL
    assert terminal_claim in operations.files

    assert adapter.recover_next() is not None
    assert terminal_claim not in operations.files
    assert _active_intent_count(operations) == 127

    adapter.publish(payload, final_name)

    assert _active_intent_count(operations) == 128
    assert evidence_name in operations.files
    assert commit_name in operations.files


def test_two_linux_publishers_at_boundary_admit_at_most_one_then_report_full() -> None:
    operations = AtomicPublishLinuxOperations()
    for index in range(127):
        _add_active_intent(operations, _active_intent_name("pending", index))
    adapters = [
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY),
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY),
    ]
    payloads = (
        encode_broker_intent(_intent(intent_generation=128, nonce="e" * 32)),
        encode_broker_intent(_intent(intent_generation=129, nonce="f" * 32)),
    )
    names = (
        "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        "intent-00000000000000000129-ffffffffffffffffffffffffffffffff.json",
    )
    start = threading.Barrier(2)
    successes: list[int] = []
    failures: list[BaseException] = []

    def publish(index: int) -> None:
        try:
            start.wait(timeout=5)
            adapters[index].publish(payloads[index], names[index])
            successes.append(index)
        except BaseException as error:  # pragma: no cover - assertions report it
            failures.append(error)

    workers = [threading.Thread(target=publish, args=(index,)) for index in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert not any(worker.is_alive() for worker in workers)
    assert len(successes) == 1
    assert len(failures) == 1
    assert _active_intent_count(operations) == 128
    failure = failures[0]
    if type(failure) is BrokerIntentError:
        assert failure.code is BrokerIntentCode.QUEUE_FULL
    else:
        assert type(failure) is LinuxBrokerError
        assert failure.code is LinuxBrokerCode.IO_FAILURE

    with pytest.raises(BrokerIntentError) as raised:
        adapters[0].publish(
            encode_broker_intent(_intent(intent_generation=130, nonce="a" * 32)),
            "intent-00000000000000000130-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json",
        )
    assert raised.value.code is BrokerIntentCode.QUEUE_FULL
    assert _active_intent_count(operations) == 128


def test_linux_publish_admission_lock_failure_is_not_queue_full() -> None:
    class LockFailureOperations(FakeLinuxOperations):
        def lock_exclusive_nonblocking(self, fd: int) -> None:
            raise OSError(errno.EIO, "lock-failure-secret")

    operations = LockFailureOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(
            encode_broker_intent(INTENT),
            "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json",
        )

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    assert operations.files == {}


def test_linux_publish_admission_unlock_failure_is_fail_closed_not_queue_full() -> None:
    class UnlockFailureOperations(FakeLinuxOperations):
        def unlock_exclusive(self, fd: int) -> None:
            raise OSError(errno.EIO, "unlock-failure-secret")

    operations = UnlockFailureOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(encode_broker_intent(INTENT), final_name)

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    assert final_name in operations.files
    with pytest.raises(LinuxBrokerError) as repeated:
        adapter.publish(
            encode_broker_intent(_intent(intent_generation=8, nonce="e" * 32)),
            "intent-00000000000000000008-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json",
        )
    assert repeated.value.code is LinuxBrokerCode.IO_FAILURE


def test_two_linux_consumers_claim_shared_intent_once_atomically() -> None:
    operations = AtomicClaimLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    payload = encode_broker_intent(INTENT)
    operations.files[final_name] = payload
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    adapters = [
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY),
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY),
    ]
    results: list[BrokerIntentClaimBytes | None] = [None, None]
    errors: list[BaseException] = []

    def consume(index: int) -> None:
        try:
            results[index] = adapters[index].claim_next()
        except Exception as error:  # pragma: no cover - assertion below reports it
            errors.append(error)

    workers = [threading.Thread(target=consume, args=(index,)) for index in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert not any(worker.is_alive() for worker in workers)
    assert errors == []
    assert sorted(result is not None for result in results) == [False, True]
    winner = next(result for result in results if result is not None)
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    expected_identity = BrokerIntentFileIdentity(
        8, 1001, 0o100600, 0, 0, 1, PARENT_IDENTITY.selinux_label
    )
    assert winner == BrokerIntentClaimBytes(claim_name, payload, expected_identity)
    assert operations.files == {claim_name: payload}
    assert final_name not in operations.files
    assert [call for call in operations.calls if call[0] == "renameat2_noreplace"] == [
        ("renameat2_noreplace", 7, final_name, claim_name)
    ]


def test_linux_recovery_takes_a_crashed_claim_with_a_new_store_and_retains_one_lease() -> (
    None
):
    operations = AtomicRecoveryLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    payload = encode_broker_intent(INTENT)
    operations.files[final_name] = payload
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label

    crashed_store = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    claimed = crashed_store.claim_next()
    assert claimed is not None
    assert claimed.claim_name == ".claim-" + final_name
    assert len(operations.locked_fds) == 1

    operations.crash()
    recovered_store = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    recovered = recovered_store.recover_next()

    assert recovered is not None
    assert recovered.claim_name == ".recover-" + final_name
    assert recovered.payload == payload
    assert recovered.source_identity == BrokerIntentFileIdentity(
        8, 1001, 0o100600, 0, 0, 1, PARENT_IDENTITY.selinux_label
    )
    assert getattr(recovered, "recovered") is True
    assert operations.files == {recovered.claim_name: payload}
    assert len(operations.locked_fds) == 1


def test_linux_terminal_evidence_preserves_intent_binding_before_cleanup() -> None:
    operations = AtomicRecoveryLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    intent_payload = encode_broker_intent(INTENT)
    operations.files[final_name] = intent_payload
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    store = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    claim = store.claim_next()
    assert claim is not None
    store.mark_terminal(claim.claim_name, b'{"result":"succeeded"}\n')

    evidence_name, evidence, commit_name, commit = _terminal_evidence_records(
        claim.claim_name, intent_payload
    )
    assert operations.files == {evidence_name: evidence, commit_name: commit}
    assert "truncate" not in [call[0] for call in operations.calls]
    assert base64.b64decode(json.loads(evidence)["intent_b64"]) == intent_payload


def test_linux_recovery_finalizes_bound_terminal_evidence_without_resuming() -> None:
    operations = AtomicRecoveryLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    intent_payload = encode_broker_intent(INTENT)
    evidence_name, evidence, commit_name, commit = _terminal_evidence_records(
        claim_name, intent_payload
    )
    operations.files.update(
        {claim_name: intent_payload, evidence_name: evidence, commit_name: commit}
    )
    operations.identities.update(
        {
            claim_name: ObjectIdentity(8, 1001, 0o100600, 0, 0, 1),
            evidence_name: ObjectIdentity(8, 1002, 0o100600, 0, 0, 1),
            commit_name: ObjectIdentity(8, 1003, 0o100600, 0, 0, 1),
        }
    )
    operations.labels.update(
        {
            claim_name: PARENT_IDENTITY.selinux_label,
            evidence_name: PARENT_IDENTITY.selinux_label,
            commit_name: PARENT_IDENTITY.selinux_label,
        }
    )

    recovered = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY).recover_next()

    assert recovered is None
    assert operations.files == {evidence_name: evidence, commit_name: commit}
    assert operations.locked_fds == {}


def test_linux_recovery_reuses_valid_evidence_only_without_renaming_claim() -> None:
    operations = AtomicRecoveryLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    intent_payload = encode_broker_intent(INTENT)
    evidence_name, evidence, commit_name, commit = _terminal_evidence_records(
        claim_name, intent_payload
    )
    operations.files.update({claim_name: intent_payload, evidence_name: evidence})
    operations.identities.update(
        {
            claim_name: ObjectIdentity(8, 1001, 0o100600, 0, 0, 1),
            evidence_name: ObjectIdentity(8, 1002, 0o100600, 0, 0, 1),
        }
    )
    operations.labels.update(
        {
            claim_name: PARENT_IDENTITY.selinux_label,
            evidence_name: PARENT_IDENTITY.selinux_label,
        }
    )
    store = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    recovered = store.recover_next()

    assert recovered == BrokerIntentClaimBytes(
        claim_name,
        intent_payload,
        BrokerIntentFileIdentity(
            8, 1001, 0o100600, 0, 0, 1, PARENT_IDENTITY.selinux_label
        ),
        recovered=True,
    )
    assert operations.files == {claim_name: intent_payload, evidence_name: evidence}

    store.mark_terminal(claim_name, b'{"result":"succeeded"}\n')

    assert operations.files == {evidence_name: evidence, commit_name: commit}
    assert not any("recover" in name for name in operations.files)


@pytest.mark.parametrize("bool_record", ("evidence", "commit"))
def test_linux_recovery_rejects_boolean_terminal_schema_version(
    bool_record: str,
) -> None:
    operations = AtomicRecoveryLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    intent_payload = encode_broker_intent(INTENT)
    evidence_name, evidence, commit_name, commit = _terminal_evidence_records(
        claim_name, intent_payload
    )
    if bool_record == "evidence":
        evidence_document = json.loads(evidence)
        evidence_document["schema_version"] = True
        evidence = (
            json.dumps(
                evidence_document,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
        commit = (
            json.dumps(
                {
                    "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
                    "schema_version": 1,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    else:
        commit_document = json.loads(commit)
        commit_document["schema_version"] = True
        commit = (
            json.dumps(
                commit_document,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    operations.files.update(
        {claim_name: intent_payload, evidence_name: evidence, commit_name: commit}
    )
    for index, name in enumerate(operations.files, start=1001):
        operations.identities[name] = ObjectIdentity(8, index, 0o100600, 0, 0, 1)
        operations.labels[name] = PARENT_IDENTITY.selinux_label

    with pytest.raises(LinuxBrokerError) as raised:
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY).recover_next()

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    assert operations.files[claim_name] == intent_payload


def test_linux_recovery_discards_invalid_provisional_evidence_without_quarantine() -> (
    None
):
    operations = AtomicRecoveryLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    intent_payload = encode_broker_intent(INTENT)
    evidence_name, _, _, _ = _terminal_evidence_records(claim_name, intent_payload)
    operations.files.update({claim_name: intent_payload, evidence_name: b"corrupt"})
    operations.identities.update(
        {
            claim_name: ObjectIdentity(8, 1001, 0o100600, 0, 0, 1),
            evidence_name: ObjectIdentity(8, 1002, 0o100600, 0, 0, 1),
        }
    )
    operations.labels.update(
        {
            claim_name: PARENT_IDENTITY.selinux_label,
            evidence_name: PARENT_IDENTITY.selinux_label,
        }
    )

    recovered = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY).recover_next()

    assert recovered is not None
    assert recovered.claim_name == ".recover-" + claim_name[7:]
    assert recovered.payload == intent_payload
    assert evidence_name not in operations.files
    assert not any(name.startswith(".quarantine-") for name in operations.files)


def test_linux_recovery_cleans_all_terminal_staging_slots_before_admission() -> None:
    operations = AtomicRecoveryLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    intent_payload = encode_broker_intent(INTENT)
    evidence_name, _, commit_name, _ = _terminal_evidence_records(
        claim_name, intent_payload
    )
    operations.files[claim_name] = intent_payload
    operations.identities[claim_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
    staging_names: list[str] = []
    for kind, final_name in zip(
        intent_store_module._TERMINAL_STAGING_KINDS,
        (evidence_name, commit_name),
    ):
        for index in range(intent_store_module.MAX_TERMINAL_STAGING_RECORDS):
            staging_name = _terminal_staging_name(kind, final_name, index)
            staging_names.append(staging_name)
            operations.files[staging_name] = b"crashed"
            operations.identities[staging_name] = ObjectIdentity(
                8, 1001 + len(staging_names), 0o100600, 0, 0, 1
            )
            operations.labels[staging_name] = PARENT_IDENTITY.selinux_label

    store = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    recovered = store.recover_next()

    assert recovered is not None
    assert recovered.claim_name == ".recover-" + claim_name[7:]
    assert all(name not in operations.files for name in staging_names)
    assert operations.files[recovered.claim_name] == intent_payload

    store.quarantine(recovered.claim_name, "invalid_field")
    assert recovered.claim_name not in operations.files

    final_name = "intent-00000000000000000008-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json"
    LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY).publish(
        intent_payload, final_name
    )
    assert operations.files[final_name] == intent_payload
    assert operations.observed_entries <= (2 * (_admission_observation_ceiling() + 1))


def test_linux_terminal_does_not_unlink_a_raced_staging_path() -> None:
    class RacingStagingOperations(FakeLinuxOperations):
        def __init__(self) -> None:
            super().__init__()
            self.raced_staging_name: str | None = None

        def openat2(self, parent_fd: int, name: str, how: object) -> PinnedFd:
            if (
                name.startswith(".tmp-terminal-evidence-")
                and self.raced_staging_name is None
            ):
                self.raced_staging_name = name
                self.files[name] = b"raced"
                self.identities[name] = ObjectIdentity(8, 9001, 0o100600, 0, 0, 1)
                self.labels[name] = PARENT_IDENTITY.selinux_label
            return super().openat2(parent_fd, name, how)

    operations = RacingStagingOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    payload = encode_broker_intent(INTENT)
    operations.files[final_name] = payload
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    store = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    claim = store.claim_next()
    assert claim is not None

    with pytest.raises(LinuxBrokerError) as raised:
        store.mark_terminal(claim.claim_name, b'{"result":"succeeded"}\n')

    assert raised.value.code is LinuxBrokerCode.ALREADY_EXISTS
    assert operations.raced_staging_name is not None
    assert operations.files[operations.raced_staging_name] == b"raced"
    assert (
        "unlinkat",
        7,
        operations.raced_staging_name,
    ) not in operations.calls


@pytest.mark.parametrize(
    ("crash_point", "record_kind", "record_payload", "terminal"),
    (
        ("after_temp_create", "evidence-staging", b"", False),
        ("before_evidence_write", "evidence-staging", b"", False),
        ("after_partial_evidence_write", "evidence-staging", b"partial", False),
        ("after_evidence_file_fsync", "evidence-staging", b"evidence", False),
        ("after_evidence_publish_before_parent_fsync", "evidence", b"evidence", False),
        ("after_evidence_parent_fsync_before_commit", "evidence", b"evidence", False),
        ("after_commit_temp_create", "commit-staging", b"", False),
        ("after_partial_commit_write", "commit-staging", b"partial", False),
        ("after_commit_file_fsync", "commit-staging", b"commit", False),
        ("after_commit_publish_before_parent_fsync", "commit", b"commit", True),
        ("after_commit_parent_fsync_before_claim_cleanup", "commit", b"commit", True),
    ),
)
def test_linux_recovery_handles_each_terminal_publication_crash_point(
    crash_point: str, record_kind: str, record_payload: bytes, terminal: bool
) -> None:
    operations = AtomicRecoveryLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    intent_payload = encode_broker_intent(INTENT)
    evidence_name, evidence, commit_name, commit = _terminal_evidence_records(
        claim_name, intent_payload
    )
    files: dict[str, bytes] = {claim_name: intent_payload}
    if record_kind == "evidence-staging":
        files[_terminal_staging_name("evidence", evidence_name)] = (
            evidence if record_payload == b"evidence" else record_payload
        )
    elif record_kind == "evidence":
        files[evidence_name] = evidence
    elif record_kind == "commit-staging":
        files[evidence_name] = evidence
        files[_terminal_staging_name("commit", commit_name)] = (
            commit if record_payload == b"commit" else record_payload
        )
    else:
        assert record_kind == "commit"
        files.update({evidence_name: evidence, commit_name: commit})
    operations.files.update(files)
    for index, name in enumerate(files, start=1001):
        operations.identities[name] = ObjectIdentity(8, index, 0o100600, 0, 0, 1)
        operations.labels[name] = PARENT_IDENTITY.selinux_label

    recovered = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY).recover_next()

    if terminal:
        assert recovered is None, crash_point
        assert operations.files == {evidence_name: evidence, commit_name: commit}
        return
    assert recovered is not None, crash_point
    assert recovered.recovered is True
    assert recovered.payload == intent_payload
    evidence_only = record_kind in {"evidence", "commit-staging"}
    assert recovered.claim_name == (
        claim_name if evidence_only else ".recover-" + claim_name[7:]
    )
    assert operations.files[recovered.claim_name] == intent_payload
    if record_kind == "evidence-staging":
        assert _terminal_staging_name("evidence", evidence_name) not in operations.files
    if record_kind == "commit-staging":
        assert _terminal_staging_name("commit", commit_name) not in operations.files


def test_linux_recovery_rejects_contradictory_committed_terminal_evidence() -> None:
    operations = AtomicRecoveryLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    intent_payload = encode_broker_intent(INTENT)
    evidence_name, evidence, commit_name, _ = _terminal_evidence_records(
        claim_name, intent_payload
    )
    conflicting_commit = (
        json.dumps(
            {"evidence_sha256": "0" * 64, "schema_version": 1},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    operations.files.update(
        {
            claim_name: intent_payload,
            evidence_name: evidence,
            commit_name: conflicting_commit,
        }
    )
    for index, name in enumerate(operations.files, start=1001):
        operations.identities[name] = ObjectIdentity(8, index, 0o100600, 0, 0, 1)
        operations.labels[name] = PARENT_IDENTITY.selinux_label

    with pytest.raises(LinuxBrokerError) as raised:
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY).recover_next()

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    assert operations.files[claim_name] == intent_payload
    assert not any(name.startswith(".recover-") for name in operations.files)


def test_two_linux_recoverers_cannot_own_a_committed_terminal_claim_together() -> None:
    class TerminalRaceOperations(AtomicRecoveryLinuxOperations):
        def __init__(self) -> None:
            super().__init__()
            self.lock_barrier = threading.Barrier(2)

        def lock_exclusive_nonblocking(self, fd: int) -> None:
            try:
                super().lock_exclusive_nonblocking(fd)
            except BlockingIOError:
                self.lock_barrier.wait(timeout=5)
                raise
            self.lock_barrier.wait(timeout=5)

    operations = TerminalRaceOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    intent_payload = encode_broker_intent(INTENT)
    evidence_name, evidence, commit_name, commit = _terminal_evidence_records(
        claim_name, intent_payload
    )
    operations.files.update(
        {claim_name: intent_payload, evidence_name: evidence, commit_name: commit}
    )
    for index, name in enumerate(operations.files, start=1001):
        operations.identities[name] = ObjectIdentity(8, index, 0o100600, 0, 0, 1)
        operations.labels[name] = PARENT_IDENTITY.selinux_label
    stores = [
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY),
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY),
    ]
    results: list[BrokerIntentClaimBytes | None] = [None, None]
    errors: list[BaseException] = []

    def recover(index: int) -> None:
        try:
            results[index] = stores[index].recover_next()
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)

    workers = [threading.Thread(target=recover, args=(index,)) for index in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert not any(worker.is_alive() for worker in workers)
    assert errors == []
    assert results == [None, None]
    assert operations.files == {evidence_name: evidence, commit_name: commit}
    assert operations.locked_fds == {}


def test_linux_terminal_requires_the_local_inode_lease() -> None:
    operations = FakeLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    original = encode_broker_intent(INTENT)
    operations.files[claim_name] = original
    operations.identities[claim_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[claim_name] = PARENT_IDENTITY.selinux_label

    with pytest.raises(LinuxBrokerError) as raised:
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY).mark_terminal(
            claim_name, b'{"result":"succeeded"}\n'
        )

    assert raised.value.code is LinuxBrokerCode.IDENTITY_MISMATCH
    assert operations.files == {claim_name: original}


def test_two_linux_terminalizers_cannot_publish_divergent_evidence() -> None:
    operations = AtomicRecoveryLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    intent_payload = encode_broker_intent(INTENT)
    operations.files[final_name] = intent_payload
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    owner = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    claim = owner.claim_next()
    assert claim is not None
    rival = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    assert rival.recover_next() is None
    with pytest.raises(LinuxBrokerError) as raised:
        rival.mark_terminal(claim.claim_name, b'{"result":"execution_failed"}\n')

    assert raised.value.code is LinuxBrokerCode.IDENTITY_MISMATCH
    assert operations.files == {claim.claim_name: intent_payload}
    owner.mark_terminal(claim.claim_name, b'{"result":"succeeded"}\n')
    evidence_name, evidence, commit_name, commit = _terminal_evidence_records(
        claim.claim_name, intent_payload
    )

    assert operations.files == {evidence_name: evidence, commit_name: commit}
    assert LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY).recover_next() is None
    assert operations.files == {evidence_name: evidence, commit_name: commit}


def test_linux_recovery_reclaims_recovered_orphans_without_starving_later_claims() -> (
    None
):
    operations = AtomicRecoveryLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    payload = encode_broker_intent(INTENT)
    operations.files[claim_name] = payload
    operations.identities[claim_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[claim_name] = PARENT_IDENTITY.selinux_label

    first = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY).recover_next()
    assert first is not None
    assert first.claim_name == ".recover-" + claim_name[7:]
    operations.crash()

    second = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY).recover_next()
    assert second is not None
    assert second.claim_name == first.claim_name
    assert second.recovered is True
    operations.crash()

    recoverers = [
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY),
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY),
    ]
    start = threading.Barrier(3)
    results: list[BrokerIntentClaimBytes | None] = [None, None]

    def resume(index: int) -> None:
        start.wait()
        results[index] = recoverers[index].recover_next()

    workers = [threading.Thread(target=resume, args=(index,)) for index in range(2)]
    for worker in workers:
        worker.start()
    start.wait()
    for worker in workers:
        worker.join(timeout=10)

    assert not any(worker.is_alive() for worker in workers)
    assert sorted(result is not None for result in results) == [False, True]
    assert next(result for result in results if result is not None) == second

    operations = AtomicRecoveryLinuxOperations()
    live_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    orphan_name = (
        ".recover-intent-00000000000000000008-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json"
    )
    operations.files[live_name] = payload
    operations.files[orphan_name] = payload
    operations.identities[live_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.identities[orphan_name] = ObjectIdentity(8, 1002, 0o100600, 0, 0, 1)
    operations.labels[live_name] = PARENT_IDENTITY.selinux_label
    operations.labels[orphan_name] = PARENT_IDENTITY.selinux_label
    active_store = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    active = active_store.recover_next()
    assert active is not None
    assert active.claim_name == ".recover-" + live_name[7:]

    later = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY).recover_next()
    assert later is not None
    assert later.claim_name == orphan_name
    assert active_store.recover_next() is None


def test_linux_recovery_does_not_overtake_a_live_normal_claim() -> None:
    operations = AtomicRecoveryLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    operations.files[final_name] = encode_broker_intent(INTENT)
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label

    active_store = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    active_claim = active_store.claim_next()
    assert active_claim is not None

    recovering_store = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    assert recovering_store.recover_next() is None
    assert operations.files == {active_claim.claim_name: encode_broker_intent(INTENT)}

    active_store.mark_terminal(active_claim.claim_name, b'{"result":"succeeded"}\n')
    assert operations.locked_fds == {}


def test_two_linux_recoverers_take_one_crashed_claim_atomically() -> None:
    operations = AtomicRecoveryLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    payload = encode_broker_intent(INTENT)
    operations.files[claim_name] = payload
    operations.identities[claim_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
    stores = [
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY),
        LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY),
    ]
    start = threading.Barrier(3)
    results: list[BrokerIntentClaimBytes | None] = [None, None]
    errors: list[BaseException] = []

    def recover(index: int) -> None:
        try:
            start.wait()
            results[index] = stores[index].recover_next()
        except BaseException as error:  # pragma: no cover - reported below
            errors.append(error)

    workers = [threading.Thread(target=recover, args=(index,)) for index in range(2)]
    for worker in workers:
        worker.start()
    start.wait()
    for worker in workers:
        worker.join(timeout=10)

    assert not any(worker.is_alive() for worker in workers)
    assert errors == []
    assert sorted(result is not None for result in results) == [False, True]
    winner = next(result for result in results if result is not None)
    assert (
        winner.claim_name
        == ".recover-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    assert operations.files == {winner.claim_name: payload}
    assert len(operations.locked_fds) == 1


def test_linux_terminal_failure_releases_the_claim_lease() -> None:
    operations = AtomicRecoveryLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    operations.files[final_name] = encode_broker_intent(INTENT)
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    store = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    claim = store.claim_next()
    assert claim is not None
    operations.write_error = OSError(errno.EIO, "write failure")

    with pytest.raises(LinuxBrokerError):
        store.mark_terminal(claim.claim_name, b'{"result":"succeeded"}\n')

    assert operations.locked_fds == {}
    assert operations.files[claim.claim_name] == encode_broker_intent(INTENT)
    assert not any(name.startswith(".terminal-") for name in operations.files)
    assert "truncate" not in [call[0] for call in operations.calls]


def test_linux_terminal_or_quarantine_validation_failure_releases_the_claim_lease() -> (
    None
):
    for operation in ("terminal", "quarantine"):
        operations = AtomicRecoveryLinuxOperations()
        final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
        operations.files[final_name] = encode_broker_intent(INTENT)
        operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
        operations.labels[final_name] = PARENT_IDENTITY.selinux_label
        store = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
        claim = store.claim_next()
        assert claim is not None

        if operation == "terminal":
            operations.files.update(
                {f".terminal-evidence-retained-{index}": b"x" for index in range(128)}
            )
            with pytest.raises(LinuxBrokerError):
                store.mark_terminal(claim.claim_name, b'{"result":"succeeded"}\n')
        else:
            with pytest.raises(LinuxBrokerError):
                store.quarantine(claim.claim_name, "not a valid code")

        assert operations.locked_fds == {}


def test_linux_publish_uses_openat2_exclusive_write_fsync_and_noreplace_rename() -> (
    None
):
    operations = FakeLinuxOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    adapter.publish(encode_broker_intent(INTENT), final_name)
    open_call = next(call for call in operations.calls if call[0] == "openat2")
    how = open_call[3]
    assert getattr(how, "flags") & 0o200
    assert getattr(how, "flags") & 0o100
    assert getattr(how, "resolve") & 0x08
    assert getattr(how, "resolve") & 0x04
    assert [call[0] for call in operations.calls] == [
        "stat_fd",
        "selinux_label",
        "stat_fd",
        "selinux_label",
        "lock_exclusive_nonblocking",
        "stat_fd",
        "selinux_label",
        "stat_fd",
        "selinux_label",
        "observe_names_bounded",
        "stat_fd",
        "selinux_label",
        "openat2",
        "selinux_label",
        "stat_fd",
        "write_all",
        "fsync",
        "stat_fd",
        "selinux_label",
        "close",
        "stat_fd",
        "selinux_label",
        "renameat2_noreplace",
        "fsync",
        "stat_fd",
        "selinux_label",
        "unlock_exclusive",
    ]


def test_linux_publish_rejects_regex_valid_overlong_final_name_before_file_io() -> None:
    operations = FakeLinuxOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    final_name = f"intent-{'0' * 20}-{'a' * 256}.json"

    assert intent_store_module._INTENT_NAME.fullmatch(final_name) is not None
    assert not intent_store_module._valid_name(final_name)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(encode_broker_intent(INTENT), final_name)

    assert raised.value.code is LinuxBrokerCode.UNSAFE_PATH
    assert not any(
        call[0] in {"openat2", "write_all", "renameat2_noreplace"}
        for call in operations.calls
    )
    assert final_name not in operations.files


def test_linux_claim_rechecks_identity_after_read_and_claims_once() -> None:
    operations = FakeLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    payload = encode_broker_intent(INTENT)
    operations.files[final_name] = payload
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    claimed = adapter.claim_next()
    assert claimed == BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json",
        payload,
        BrokerIntentFileIdentity(
            8, 1001, 0o100600, 0, 0, 1, PARENT_IDENTITY.selinux_label
        ),
    )
    assert adapter.claim_next() is None


def test_linux_claim_loser_gets_none_when_atomic_rename_reports_source_race() -> None:
    operations = FakeLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    operations.files[final_name] = encode_broker_intent(INTENT)
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    operations.rename_error = FileNotFoundError(errno.ENOENT, "raced")
    assert adapter.claim_next() is None
    assert not any(call[0] == "fsync" for call in operations.calls[4:])


def test_linux_parent_swap_is_rejected_before_claim_visibility() -> None:
    operations = FakeLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    operations.files[final_name] = encode_broker_intent(INTENT)
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    operations.parent_stat_sequence = [
        ObjectIdentity(8, 100, 0o40700, 0, 0, 2),
        ObjectIdentity(8, 999, 0o40700, 0, 0, 2),
    ]
    with pytest.raises(Exception):
        adapter.claim_next()
    assert final_name in operations.files
    assert not any(call[0] == "renameat2_noreplace" for call in operations.calls)


def test_linux_post_open_identity_drift_is_rejected_before_claim_visibility() -> None:
    operations = FakeLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    operations.files[final_name] = encode_broker_intent(INTENT)
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    operations.stat_sequences[final_name] = [
        ObjectIdentity(8, 1001, 0o100600, 0, 0, 1),
        ObjectIdentity(8, 1002, 0o100600, 0, 0, 1),
    ]
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    with pytest.raises(Exception):
        adapter.claim_next()
    assert final_name in operations.files
    assert not any(call[0] == "renameat2_noreplace" for call in operations.calls)


def test_linux_rejects_pinned_identity_that_disagrees_with_post_open_fstat() -> None:
    operations = FakeLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    operations.files[final_name] = encode_broker_intent(INTENT)
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    operations.pinned_identity_overrides[final_name] = ObjectIdentity(
        8, 1002, 0o100600, 0, 0, 1
    )
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    with pytest.raises(LinuxBrokerError) as raised:
        adapter.claim_next()
    assert raised.value.code is LinuxBrokerCode.IDENTITY_MISMATCH
    assert not any(call[0] == "renameat2_noreplace" for call in operations.calls)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda ops, name: ops.identities.__setitem__(
            name, ObjectIdentity(8, 1001, 0o100600, 0, 0, 2)
        ),
        lambda ops, name: ops.identities.__setitem__(
            name, ObjectIdentity(8, 1001, 0o100666, 0, 0, 1)
        ),
        lambda ops, name: ops.identities.__setitem__(
            name, ObjectIdentity(8, 1001, 0o100600, 1000, 0, 1)
        ),
        lambda ops, name: ops.labels.__setitem__(name, "system_u:object_r:tmp_t:s0"),
    ],
)
def test_linux_claim_rejects_hardlink_owner_mode_and_label_drift_before_rename(
    mutation,
) -> None:
    operations = FakeLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    operations.files[final_name] = encode_broker_intent(INTENT)
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    mutation(operations, final_name)
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    with pytest.raises(LinuxBrokerError) as raised:
        adapter.claim_next()
    assert raised.value.code is LinuxBrokerCode.IDENTITY_MISMATCH
    assert not any(call[0] == "renameat2_noreplace" for call in operations.calls)


def test_linux_claim_rejects_symlink_without_claiming() -> None:
    operations = FakeLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    operations.files[final_name] = encode_broker_intent(INTENT)
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o120777, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    with pytest.raises(LinuxBrokerError) as raised:
        adapter.claim_next()
    assert raised.value.code is LinuxBrokerCode.IDENTITY_MISMATCH
    assert not any(call[0] == "renameat2_noreplace" for call in operations.calls)


@pytest.mark.parametrize(
    ("identity", "label"),
    (
        (ObjectIdentity(8, 1001, 0o120777, 0, 0, 1), PARENT_IDENTITY.selinux_label),
        (ObjectIdentity(8, 1001, 0o100600, 0, 0, 2), PARENT_IDENTITY.selinux_label),
        (ObjectIdentity(8, 1001, 0o100600, 1000, 0, 1), PARENT_IDENTITY.selinux_label),
        (ObjectIdentity(8, 1001, 0o100666, 0, 0, 1), PARENT_IDENTITY.selinux_label),
        (ObjectIdentity(8, 1001, 0o100600, 0, 0, 1), "system_u:object_r:tmp_t:s0"),
    ),
    ids=("symlink", "hardlink", "owner", "mode", "label"),
)
def test_linux_quarantine_rejects_invalid_identity_before_rename(
    identity: ObjectIdentity, label: str
) -> None:
    operations = FakeLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    original = b"claimed-payload"
    operations.files[claim_name] = original
    operations.identities[claim_name] = identity
    operations.labels[claim_name] = label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.quarantine(claim_name, "invalid_field")

    assert raised.value.code is LinuxBrokerCode.IDENTITY_MISMATCH
    assert operations.files[claim_name] == original
    assert any(call[0] == "openat2" for call in operations.calls)
    assert not any(
        call[0] in {"truncate", "write_all", "renameat2_noreplace"}
        for call in operations.calls
    )


def test_linux_quarantine_binds_valid_claim_before_rename_and_closes_fd() -> None:
    operations = FakeLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    operations.files[claim_name] = b"claimed-payload"
    operations.identities[claim_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    adapter.quarantine(claim_name, "invalid_field")

    quarantine_name = (
        ".quarantine-invalid_field-claim-intent-00000000000000000007-"
        "dddddddddddddddddddddddddddddddd.json"
    )
    assert operations.files == {quarantine_name: b"claimed-payload"}
    names = [call[0] for call in operations.calls]
    assert (
        names.index("openat2")
        < names.index("close")
        < names.index("renameat2_noreplace")
    )


def test_linux_quarantine_rejects_overlong_destination_before_rename() -> None:
    operations = FakeLinuxOperations()
    claim_name = ".claim-intent-00000000000000000007-" + "d" * 216 + ".json"
    code = "a" * intent_store_module.MAX_INTENT_STORE_CODE_BYTES
    operations.files[claim_name] = b"claimed-payload"
    operations.identities[claim_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    quarantine_name = f".quarantine-{code}-{claim_name[1:]}"

    assert (
        len(claim_name.encode("ascii"))
        == intent_store_module.MAX_INTENT_STORE_NAME_BYTES
    )
    assert intent_store_module._CLAIM_NAME.fullmatch(claim_name) is not None
    assert intent_store_module._valid_name(claim_name)
    assert intent_store_module._valid_code(code)
    assert not intent_store_module._valid_name(quarantine_name)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.quarantine(claim_name, code)

    assert raised.value.code is LinuxBrokerCode.UNSAFE_PATH
    assert operations.files[claim_name] == b"claimed-payload"
    assert not any(
        call[0] in {"write_all", "renameat2_noreplace"} for call in operations.calls
    )
    assert quarantine_name not in operations.files


def test_linux_quarantine_rejects_valid_but_missing_claim_before_rename() -> None:
    operations = FakeLinuxOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    claim_name = (
        ".claim-intent-00000000000000000008-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json"
    )

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.quarantine(claim_name, "invalid_field")

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    assert any(call[0] == "openat2" for call in operations.calls)
    assert not any(call[0] == "renameat2_noreplace" for call in operations.calls)


def test_linux_publish_fails_closed_on_parent_swap_short_write_fsync_and_rename_collision() -> (
    None
):
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    payload = encode_broker_intent(INTENT)
    for configure in (
        lambda ops: setattr(
            ops, "parent_stat", ObjectIdentity(8, 999, 0o40700, 0, 0, 2)
        ),
        lambda ops: setattr(ops, "write_result", len(payload) - 1),
        lambda ops: setattr(ops, "fsync_error", OSError(errno.EIO, "fsync")),
        lambda ops: setattr(
            ops, "rename_error", FileExistsError(errno.EEXIST, "exists")
        ),
    ):
        operations = FakeLinuxOperations()
        adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
        configure(operations)
        with pytest.raises(LinuxBrokerError):
            adapter.publish(payload, final_name)
        assert final_name not in operations.files


def test_linux_unknown_claim_names_are_rejected_before_adapter_mutation() -> None:
    operations = FakeLinuxOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    with pytest.raises(LinuxBrokerError) as raised:
        adapter.mark_terminal("unknown", b"x")
    assert raised.value.code is LinuxBrokerCode.UNSAFE_PATH
    with pytest.raises(LinuxBrokerError) as raised:
        adapter.quarantine("unknown", "invalid")
    assert raised.value.code is LinuxBrokerCode.UNSAFE_PATH
    assert not any(
        call[0] in {"openat2", "truncate", "write_all", "renameat2_noreplace"}
        for call in operations.calls
    )


def test_linux_quarantine_retention_allows_128_then_rejects_129_without_mutation() -> (
    None
):
    operations = FakeLinuxOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    for index in range(128):
        claim_name = f".claim-intent-{index:020d}-{'d' * 32}.json"
        operations.files[claim_name] = b"claimed-payload"
        operations.identities[claim_name] = ObjectIdentity(
            8, 2000 + index, 0o100600, 0, 0, 1
        )
        operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
        adapter.quarantine(claim_name, "invalid_field")

    assert (
        len([name for name in operations.files if name.startswith(".quarantine-")])
        == 128
    )
    claim_name = (
        ".claim-intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json"
    )
    operations.files[claim_name] = b"claimed-payload"
    operations.identities[claim_name] = ObjectIdentity(8, 3000, 0o100600, 0, 0, 1)
    operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
    files_before = dict(operations.files)
    calls_before = len(operations.calls)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.quarantine(claim_name, "invalid_field")

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    assert operations.files == files_before
    assert [call[0] for call in operations.calls[calls_before:]] == [
        "observe_names_bounded"
    ]
    assert not any(
        call[0] == "renameat2_noreplace" for call in operations.calls[calls_before:]
    )


def test_linux_mark_terminal_writes_bound_evidence_then_removes_claim_atomically() -> (
    None
):
    operations = FakeLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    intent_payload = encode_broker_intent(INTENT)
    operations.files[final_name] = intent_payload
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    claim = adapter.claim_next()
    assert claim is not None
    terminal_payload = b'{"result":"succeeded"}\n'
    adapter.mark_terminal(claim.claim_name, terminal_payload)
    evidence_name, evidence, commit_name, commit = _terminal_evidence_records(
        claim.claim_name, intent_payload
    )
    assert operations.files == {evidence_name: evidence, commit_name: commit}
    assert "truncate" not in [call[0] for call in operations.calls]


def test_linux_mark_terminal_rejects_noncanonical_result_without_mutating_intent() -> (
    None
):
    operations = FakeLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    intent_payload = encode_broker_intent(INTENT)
    operations.files[final_name] = intent_payload
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    claim = adapter.claim_next()
    assert claim is not None

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.mark_terminal(claim.claim_name, b"done")

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    assert operations.files == {claim.claim_name: intent_payload}
    assert "truncate" not in [call[0] for call in operations.calls]


@pytest.mark.parametrize(
    ("identity", "label"),
    (
        (ObjectIdentity(8, 1001, 0o120777, 0, 0, 1), PARENT_IDENTITY.selinux_label),
        (ObjectIdentity(8, 1001, 0o100600, 0, 0, 2), PARENT_IDENTITY.selinux_label),
        (ObjectIdentity(8, 1001, 0o100600, 1000, 0, 1), PARENT_IDENTITY.selinux_label),
        (ObjectIdentity(8, 1001, 0o100666, 0, 0, 1), PARENT_IDENTITY.selinux_label),
        (ObjectIdentity(8, 1001, 0o100600, 0, 0, 1), "system_u:object_r:tmp_t:s0"),
    ),
    ids=("symlink", "hardlink", "owner", "mode", "label"),
)
def test_linux_terminal_rejects_invalid_identity_before_mutation(
    identity: ObjectIdentity, label: str
) -> None:
    operations = FakeLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    original = b"original-claim-payload"
    operations.files[claim_name] = original
    operations.identities[claim_name] = identity
    operations.labels[claim_name] = label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.mark_terminal(claim_name, b"done")

    assert raised.value.code is LinuxBrokerCode.IDENTITY_MISMATCH
    assert operations.files[claim_name] == original
    assert not any(
        call[0] in {"truncate", "write_all", "renameat2_noreplace"}
        for call in operations.calls
    )


def test_linux_terminal_retention_allows_limit_then_fails_without_mutation() -> None:
    operations = FakeLinuxOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    payload = encode_broker_intent(INTENT)

    for index in range(128):
        final_name = f"intent-{index:020d}-{'d' * 32}.json"
        operations.files[final_name] = payload
        operations.identities[final_name] = ObjectIdentity(
            8, 2000 + index, 0o100600, 0, 0, 1
        )
        operations.labels[final_name] = PARENT_IDENTITY.selinux_label
        claim = adapter.claim_next()
        assert claim is not None
        adapter.mark_terminal(claim.claim_name, b'{"result":"succeeded"}\n')

    assert (
        len(
            [
                name
                for name in operations.files
                if name.startswith(".terminal-evidence-")
            ]
        )
        == 128
    )
    final_name = "intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json"
    operations.files[final_name] = payload
    operations.identities[final_name] = ObjectIdentity(8, 3000, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    claim = adapter.claim_next()
    assert claim is not None
    calls_before = tuple(operations.calls)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.mark_terminal(claim.claim_name, b'{"result":"succeeded"}\n')

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    new_calls = operations.calls[len(calls_before) :]
    assert [call[0] for call in new_calls][:3] == [
        "stat_fd",
        "selinux_label",
        "read_all",
    ]
    assert claim.claim_name in operations.files
    evidence_name, _, _, _ = _terminal_evidence_records(claim.claim_name, payload)
    assert evidence_name not in operations.files


def test_linux_terminal_parent_swap_is_rejected_before_evidence_publication() -> None:
    operations = FakeLinuxOperations()
    final_name = "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    payload = encode_broker_intent(INTENT)
    operations.files[final_name] = payload
    operations.identities[final_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[final_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    claim = adapter.claim_next()
    assert claim is not None
    operations.parent_stat_sequence = [
        ObjectIdentity(8, 100, 0o40700, 0, 0, 2),
        ObjectIdentity(8, 999, 0o40700, 0, 0, 2),
    ]
    with pytest.raises(LinuxBrokerError):
        adapter.mark_terminal(claim.claim_name, b'{"result":"succeeded"}\n')
    assert operations.files[claim.claim_name] == payload
    assert not any(name.startswith(".terminal-") for name in operations.files)


def test_linux_rejects_non_text_names_before_regex_or_adapter_mutation() -> None:
    operations = FakeLinuxOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    with pytest.raises(LinuxBrokerError) as raised:
        adapter.publish(encode_broker_intent(INTENT), object())  # type: ignore[arg-type]
    assert raised.value.code is LinuxBrokerCode.UNSAFE_PATH
    with pytest.raises(LinuxBrokerError) as raised:
        adapter.quarantine(object(), "invalid_field")  # type: ignore[arg-type]
    assert raised.value.code is LinuxBrokerCode.UNSAFE_PATH


def test_linux_skips_non_text_directory_entries_without_opening_them() -> None:
    class NonTextEntries(FakeLinuxOperations):
        def list_names(self, parent_fd: int) -> tuple[object, ...]:  # type: ignore[override]
            self.calls.append(("list_names", parent_fd))
            return (object(), "unrelated")

    operations = NonTextEntries()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    assert adapter.claim_next() is None
    assert not any(call[0] == "openat2" for call in operations.calls)
