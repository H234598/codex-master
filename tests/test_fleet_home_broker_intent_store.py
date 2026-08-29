from __future__ import annotations

import dataclasses
from dataclasses import FrozenInstanceError
import errno
import hashlib
import inspect
import threading

import pytest

from codex_master.fleet_home_broker_intent import (
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


class FakeStore:
    def __init__(self, claim: BrokerIntentClaimBytes | None = None) -> None:
        self.published: list[tuple[bytes, str]] = []
        self.claims = [claim] if claim is not None else []
        self.terminals: list[tuple[str, bytes]] = []
        self.quarantines: list[tuple[str, str]] = []

    def publish(self, payload: bytes, final_name: str) -> None:
        self.published.append((payload, final_name))

    def claim_next(self) -> BrokerIntentClaimBytes | None:
        if not self.claims:
            return None
        return self.claims.pop(0)

    def mark_terminal(self, claim_name: str, payload: bytes) -> None:
        self.terminals.append((claim_name, payload))

    def quarantine(self, claim_name: str, code: str) -> None:
        self.quarantines.append((claim_name, code))


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

    def close(self, fd: int) -> None:
        self.calls.append(("close", fd))
        self.fd_names.pop(fd, None)
        self.open_flags.pop(fd, None)


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


def test_publish_encodes_once_and_uses_safe_nonce_bound_final_name() -> None:
    store = FakeStore()
    assert publish_broker_intent(store, INTENT) is None
    assert store.published == [
        (
            encode_broker_intent(INTENT),
            "intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json",
        )
    ]


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


def test_two_consumers_have_exactly_one_claim_and_loser_does_not_mutate() -> None:
    class OneShotStore(FakeStore):
        def __init__(self) -> None:
            super().__init__(
                BrokerIntentClaimBytes(
                    "claim-race", encode_broker_intent(INTENT), IDENTITY
                )
            )
            self._lock = threading.Lock()

        def claim_next(self) -> BrokerIntentClaimBytes | None:
            with self._lock:
                return super().claim_next()

    store = OneShotStore()
    results: list[ClaimedBrokerIntent | None] = []

    def consume() -> None:
        results.append(claim_broker_intent(store, now_unix_ms=1_700_000_001_000))

    workers = [threading.Thread(target=consume) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert sorted(result is not None for result in results) == [False, True]
    assert store.quarantines == []


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
    ]


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


def test_linux_terminal_and_quarantine_reject_unknown_claim_and_bound_retention() -> (
    None
):
    operations = FakeLinuxOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    with pytest.raises(LinuxBrokerError) as raised:
        adapter.mark_terminal("unknown", b"x")
    assert raised.value.code is LinuxBrokerCode.UNSAFE_PATH
    with pytest.raises(LinuxBrokerError) as raised:
        adapter.quarantine("unknown", "invalid")
    assert raised.value.code is LinuxBrokerCode.UNSAFE_PATH
    for index in range(130):
        claim_name = f".claim-intent-{index:020d}-{'d' * 32}.json"
        operations.files[claim_name] = encode_broker_intent(INTENT)
        operations.identities[claim_name] = ObjectIdentity(
            8, 2000 + index, 0o100600, 0, 0, 1
        )
        operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
        try:
            adapter.quarantine(claim_name, "invalid_field")
        except Exception:
            break
    assert (
        len([name for name in operations.files if name.startswith(".quarantine-")])
        <= 128
    )


def test_linux_mark_terminal_writes_bounded_payload_then_retains_claim_atomically() -> (
    None
):
    operations = FakeLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    operations.files[claim_name] = encode_broker_intent(INTENT)
    operations.identities[claim_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    terminal_payload = b'{"result":"committed"}\n'
    adapter.mark_terminal(claim_name, terminal_payload)
    terminal_name = ".terminal-claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    assert operations.files == {terminal_name: terminal_payload}


def test_linux_mark_terminal_truncates_before_retention_rename() -> None:
    operations = FakeLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    operations.files[claim_name] = b"original-intent-payload-that-is-longer"
    operations.identities[claim_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    terminal_payload = b"done"
    adapter.mark_terminal(claim_name, terminal_payload)

    terminal_name = ".terminal-claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    assert operations.files[terminal_name] == terminal_payload
    open_call = next(
        call
        for call in operations.calls
        if call[0] == "openat2" and call[2] == claim_name
    )
    assert getattr(open_call[3], "flags") & 0o1000


def test_linux_terminal_retention_allows_limit_then_fails_without_mutation() -> None:
    operations = FakeLinuxOperations()
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)

    for index in range(128):
        claim_name = f".claim-intent-{index:020d}-{'d' * 32}.json"
        operations.files[claim_name] = b"intent"
        operations.identities[claim_name] = ObjectIdentity(
            8, 2000 + index, 0o100600, 0, 0, 1
        )
        operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
        adapter.mark_terminal(claim_name, b"done")

    assert (
        len([name for name in operations.files if name.startswith(".terminal-")]) == 128
    )
    claim_name = (
        ".claim-intent-00000000000000000128-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json"
    )
    operations.files[claim_name] = b"intent"
    operations.identities[claim_name] = ObjectIdentity(8, 3000, 0o100600, 0, 0, 1)
    operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
    calls_before = tuple(operations.calls)

    with pytest.raises(LinuxBrokerError) as raised:
        adapter.mark_terminal(claim_name, b"done")

    assert raised.value.code is LinuxBrokerCode.IO_FAILURE
    new_calls = operations.calls[len(calls_before) :]
    assert [call[0] for call in new_calls] == ["list_names"]
    assert claim_name in operations.files
    assert not any(
        name.endswith("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json")
        and name.startswith(".terminal-")
        for name in operations.files
    )


def test_linux_terminal_parent_swap_is_rejected_before_retention_rename() -> None:
    operations = FakeLinuxOperations()
    claim_name = (
        ".claim-intent-00000000000000000007-dddddddddddddddddddddddddddddddd.json"
    )
    operations.files[claim_name] = encode_broker_intent(INTENT)
    operations.identities[claim_name] = ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)
    operations.labels[claim_name] = PARENT_IDENTITY.selinux_label
    adapter = LinuxBrokerIntentStore(operations, 7, PARENT_IDENTITY)
    operations.parent_stat_sequence = [
        ObjectIdentity(8, 100, 0o40700, 0, 0, 2),
        ObjectIdentity(8, 999, 0o40700, 0, 0, 2),
    ]
    with pytest.raises(LinuxBrokerError):
        adapter.mark_terminal(claim_name, b'{"result":"committed"}\n')
    assert claim_name in operations.files
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
