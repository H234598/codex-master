"""Synthetic D355 S5a checks for the inert D73 authority core."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import copy
import json
import os

import pytest

from the_hive import _d73_authority as authority
from the_hive import _d73_q1_record as record
from the_hive import runtime_layout
from the_hive._d73_ingress_policy import D73IngressPolicyV1


COMMIT = "0123456789abcdef0123456789abcdef01234567"
GENERATION = "g"
BUS_NAME = "org.example.D73Policy"
SELINUX_CONTEXT = "synthetic_u:synthetic_r:synthetic_t:s0"
POLKIT_ACTION = "org.example.d73.publish"

def _manifest() -> bytes:
    value: dict[str, object] = {
        "schema_version": 2,
        "commit": COMMIT,
        "generation": GENERATION,
        "r2_base": {"commit": "a" * 40, "tree": "b" * 40},
        "historical_lineage": {
            "d69": {
                "commit": "c" * 40,
                "tree": "d" * 40,
                "parent": "e" * 40,
                "dynamic_pool_blob": "f" * 40,
            },
            "d73": {"commit": "1" * 40, "tree": "2" * 40, "parent": "3" * 40},
        },
        "successor_witness": {"path": "synthetic-witness", "sha256": "4" * 64},
        "release": {
            "stable_launchers": [],
            "hook_abi_source": "x",
            "hook_abi": "x",
            "hook_abi_companion": "x",
            "hook_abi_core": "x",
            "hook_entrypoints": [],
            "plugin_bundle": "x",
            "root_install_plan": "x",
            "python_tree": "x",
            "monitor_entrypoint": "x",
            "h4_units": [],
            "bind_sources": [],
        },
        "directories": {},
        "files": {"x": {"mode": 0o600, "nlink": 1, "size": 1, "sha256": "5" * 64}},
    }
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


MANIFEST = _manifest()


def _policy() -> D73IngressPolicyV1:
    return D73IngressPolicyV1(
        account_name="synthetic-control",
        bus_name=BUS_NAME,
        expected_uid=2001,
        polkit_action=POLKIT_ACTION,
        schema_version=1,
        selinux_context=SELINUX_CONTEXT,
    )


def _attestation() -> runtime_layout._RuntimeLayoutAttestation:
    return runtime_layout._RuntimeLayoutAttestation(
        target=object(),  # type: ignore[arg-type]
        target_device=0,
        target_inode=0,
        layout=object(),  # type: ignore[arg-type]
        manifest_bytes=MANIFEST,
        manifest_digest=sha256(MANIFEST).hexdigest(),
        commit=COMMIT,
        generation=GENERATION,
    )


def _peer(**changes: object) -> authority.D73DirectPeerV1:
    values: dict[str, object] = {
        "unique_sender": ":1.23",
        "pid": 4242,
        "uid": 2001,
        "selinux_context": SELINUX_CONTEXT.encode("ascii"),
        "available_mask": authority.D73_REQUIRED_PEER_MASK,
        "requested_mask": authority.D73_REQUIRED_PEER_MASK,
        "augmented_mask": 0,
        "has_direct_pidfd": False,
    }
    values.update(changes)
    return authority.D73DirectPeerV1(**values)  # type: ignore[arg-type]


def _owner(
    policy: D73IngressPolicyV1, **changes: object
) -> authority.D73PolicyBusOwnerV1:
    values: dict[str, object] = {
        "bus_name": policy.bus_name,
        "unique_sender": ":1.23",
    }
    values.update(changes)
    return authority.D73PolicyBusOwnerV1(**values)  # type: ignore[arg-type]


def _capability(
    policy: D73IngressPolicyV1, attestation: runtime_layout._RuntimeLayoutAttestation
) -> record.D73Q1Capability:
    return record._materialize_q1_capability(policy, attestation)


def _authorized_transaction(
    policy: D73IngressPolicyV1 | None = None,
    attestation: runtime_layout._RuntimeLayoutAttestation | None = None,
) -> tuple[
    authority.D73IngressTransactionV1,
    D73IngressPolicyV1,
    runtime_layout._RuntimeLayoutAttestation,
]:
    selected_policy = policy or _policy()
    selected_attestation = attestation or _attestation()
    transaction = authority.D73IngressTransactionV1(selected_policy)
    transaction.verify_a(_peer(), _owner(selected_policy))
    transaction.authorize()
    return transaction, selected_policy, selected_attestation


def _decoded_transaction() -> tuple[
    authority.D73IngressTransactionV1,
    D73IngressPolicyV1,
    runtime_layout._RuntimeLayoutAttestation,
]:
    transaction, policy, attestation = _authorized_transaction()
    transaction.move_capability(attestation, _capability(policy, attestation))
    transaction.decode()
    return transaction, policy, attestation


def _transaction_at(
    state: authority.D73IngressTransactionStateV1,
) -> tuple[
    authority.D73IngressTransactionV1,
    D73IngressPolicyV1,
    runtime_layout._RuntimeLayoutAttestation,
]:
    policy = _policy()
    attestation = _attestation()
    transaction = authority.D73IngressTransactionV1(policy)
    if state is authority.D73IngressTransactionStateV1.NEW:
        return transaction, policy, attestation
    transaction.verify_a(_peer(), _owner(policy))
    if state is authority.D73IngressTransactionStateV1.A_VERIFIED:
        return transaction, policy, attestation
    transaction.authorize()
    if state is authority.D73IngressTransactionStateV1.AUTHORIZED:
        return transaction, policy, attestation
    transaction.move_capability(attestation, _capability(policy, attestation))
    if state is authority.D73IngressTransactionStateV1.CAPABILITY_MOVED:
        return transaction, policy, attestation
    transaction.decode()
    if state is authority.D73IngressTransactionStateV1.DECODED_BOUND:
        return transaction, policy, attestation
    transaction.verify_b(_peer(), _owner(policy))
    if state is authority.D73IngressTransactionStateV1.B_VERIFIED:
        return transaction, policy, attestation
    transaction.verify_c(_peer(), _owner(policy))
    if state is authority.D73IngressTransactionStateV1.C_VERIFIED:
        return transaction, policy, attestation
    transaction.close()
    assert state is authority.D73IngressTransactionStateV1.CLOSED
    return transaction, policy, attestation


def test_s5a_abi_literals_and_rejection_are_exact() -> None:
    assert authority.D73_AUTHORITY_BUS_NAME == "org.the_hive.D73Authority1"
    assert authority.D73_AUTHORITY_OBJECT_PATH == "/org/the_hive/D73Authority1"
    assert authority.D73_AUTHORITY_INTERFACE == "org.the_hive.D73Authority1"
    assert authority.D73_AUTHORITY_MEMBER == "PublishAndMaterialize"
    assert authority.D73_AUTHORITY_INPUT_SIGNATURE == ""
    assert authority.D73_AUTHORITY_OUTPUT_SIGNATURE == ""
    assert (
        authority.D73_AUTHORITY_REJECTED_ERROR_NAME
        == "org.the_hive.D73Authority1.Error.Rejected"
    )
    assert authority.D73_AUTHORITY_REJECTED_ERROR_TEXT == "request rejected"
    assert authority.D73_AUTHORITY_ABI_V1.bus_name == authority.D73_AUTHORITY_BUS_NAME
    assert (
        authority.D73_AUTHORITY_ABI_V1.object_path
        == authority.D73_AUTHORITY_OBJECT_PATH
    )
    with pytest.raises(authority.D73AuthorityRejected) as caught:
        raise authority.D73AuthorityRejected()
    assert str(caught.value) == "request rejected"
    assert caught.value.error_name == authority.D73_AUTHORITY_REJECTED_ERROR_NAME


def test_s5a_abi_value_is_exact_frozen_and_slotted() -> None:
    assert not hasattr(authority.D73_AUTHORITY_ABI_V1, "__dict__")
    with pytest.raises((AttributeError, TypeError)):
        authority.D73_AUTHORITY_ABI_V1.member = "other"  # type: ignore[misc]
    with pytest.raises(authority.D73AuthorityRejected):
        authority.D73AuthorityAbiV1(
            bus_name="other",
            object_path=authority.D73_AUTHORITY_OBJECT_PATH,
            interface=authority.D73_AUTHORITY_INTERFACE,
            member=authority.D73_AUTHORITY_MEMBER,
            input_signature="",
            output_signature="",
            rejected_error_name=authority.D73_AUTHORITY_REJECTED_ERROR_NAME,
            rejected_error_text=authority.D73_AUTHORITY_REJECTED_ERROR_TEXT,
        )
    with pytest.raises(authority.D73AuthorityRejected):
        authority.D73AuthorityAbiV1(
            bus_name=authority.D73_AUTHORITY_BUS_NAME.encode("ascii"),
            object_path=authority.D73_AUTHORITY_OBJECT_PATH,
            interface=authority.D73_AUTHORITY_INTERFACE,
            member=authority.D73_AUTHORITY_MEMBER,
            input_signature="",
            output_signature="",
            rejected_error_name=authority.D73_AUTHORITY_REJECTED_ERROR_NAME,
            rejected_error_text=authority.D73_AUTHORITY_REJECTED_ERROR_TEXT,
        )  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("unique_sender", b":1.23"),
        ("unique_sender", ""),
        ("unique_sender", "x" * 256),
        ("pid", True),
        ("pid", 0),
        ("pid", 2**32),
        ("uid", True),
        ("uid", -1),
        ("uid", 2**32),
        ("selinux_context", "not-bytes"),
        ("selinux_context", b""),
        ("selinux_context", b"x" * 4097),
        ("available_mask", True),
        ("requested_mask", -1),
        ("augmented_mask", 2**32),
        ("has_direct_pidfd", 1),
    ),
)
def test_s5a_direct_peer_requires_exact_builtin_types_and_bounds(
    field: str, value: object
) -> None:
    with pytest.raises(authority.D73AuthorityRejected):
        _peer(**{field: value})


@pytest.mark.parametrize(
    "changes",
    (
        {"available_mask": authority.D73_REQUIRED_PEER_MASK ^ authority.D73_PEER_PID},
        {"requested_mask": authority.D73_REQUIRED_PEER_MASK ^ authority.D73_PEER_UID},
        {
            "available_mask": (
                authority.D73_REQUIRED_PEER_MASK | authority.D73_PEER_AUGMENT
            )
        },
        {
            "requested_mask": (
                authority.D73_REQUIRED_PEER_MASK | authority.D73_PEER_AUGMENT
            )
        },
        {"augmented_mask": authority.D73_REQUIRED_PEER_MASK},
        {"augmented_mask": authority.D73_PEER_AUGMENT},
    ),
)
def test_s5a_direct_peer_rejects_missing_or_augmented_required_bits(
    changes: dict[str, int]
) -> None:
    with pytest.raises(authority.D73AuthorityRejected):
        _peer(**changes)


def test_s5a_peer_and_owner_values_are_exact_frozen_and_slotted() -> None:
    peer = _peer()
    owner = _owner(_policy())
    assert not hasattr(peer, "__dict__")
    assert not hasattr(owner, "__dict__")
    with pytest.raises((AttributeError, TypeError)):
        peer.pid = 1  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        owner.unique_sender = ":1.24"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("peer_changes", "owner_changes"),
    (
        ({"unique_sender": ":1.24"}, {}),
        ({"pid": 4243}, {}),
        ({"uid": 2002}, {}),
        ({"selinux_context": b"other_u:other_r:other_t:s0"}, {}),
        ({}, {"unique_sender": ":1.24"}),
        ({}, {"bus_name": "org.example.other"}),
    ),
)
def test_s5a_pure_continuity_requires_same_peer_and_fresh_policy_owner(
    peer_changes: dict[str, object], owner_changes: dict[str, object]
) -> None:
    policy = _policy()
    with pytest.raises(authority.D73AuthorityRejected):
        authority._verify_peer_continuity_v1(
            _peer(), _peer(**peer_changes), _owner(policy, **owner_changes), policy
        )


def test_s5a_pure_continuity_accepts_equal_peer_and_owner() -> None:
    policy = _policy()
    assert (
        authority._verify_peer_continuity_v1(
            _peer(), _peer(), _owner(policy), policy
        )
        is None
    )


def test_s5a_transaction_requires_exact_existing_policy_and_attestation_types() -> None:
    class PolicySubclass(D73IngressPolicyV1):
        pass

    class AttestationSubclass(runtime_layout._RuntimeLayoutAttestation):
        pass

    policy = _policy()
    attestation = _attestation()
    with pytest.raises(authority.D73AuthorityRejected):
        authority.D73IngressTransactionV1(
            PolicySubclass(
                policy.account_name,
                policy.bus_name,
                policy.expected_uid,
                policy.polkit_action,
                policy.schema_version,
                policy.selinux_context,
            )
        )
    with pytest.raises(authority.D73AuthorityRejected):
        authority.D73IngressTransactionV1(object())  # type: ignore[arg-type]
    transaction = authority.D73IngressTransactionV1(policy)
    transaction.verify_a(_peer(), _owner(policy))
    transaction.authorize()
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.move_capability(
            AttestationSubclass(
                attestation.target,
                attestation.target_device,
                attestation.target_inode,
                attestation.layout,
                attestation.manifest_bytes,
                attestation.manifest_digest,
                attestation.commit,
                attestation.generation,
            ),
            _capability(policy, attestation),
        )


def test_s5a_transaction_follows_the_only_successful_state_sequence() -> None:
    transaction, policy, attestation = _authorized_transaction()
    assert transaction.state is authority.D73IngressTransactionStateV1.AUTHORIZED
    authorization = transaction.authorization
    assert type(authorization) is authority._D73AuthorizationV1
    assert authorization.polkit_action == policy.polkit_action
    assert authorization.noninteractive is True
    assert not hasattr(authorization, "__dict__")
    with pytest.raises(authority.D73AuthorityRejected):
        authority._D73AuthorizationV1(policy.polkit_action, True)
    transaction.move_capability(attestation, _capability(policy, attestation))
    transaction.decode()
    transaction.verify_b(_peer(), _owner(policy))
    transaction.verify_c(_peer(), _owner(policy))
    transaction.close()
    assert transaction.state is authority.D73IngressTransactionStateV1.CLOSED


@pytest.mark.parametrize(
    "operation",
    (
        lambda transaction, policy, attestation: transaction.authorize(),
        lambda transaction, policy, attestation: transaction.move_capability(
            attestation, _capability(policy, attestation)
        ),
        lambda transaction, policy, attestation: transaction.decode(),
        lambda transaction, policy, attestation: transaction.verify_b(
            _peer(), _owner(policy)
        ),
        lambda transaction, policy, attestation: transaction.verify_c(
            _peer(), _owner(policy)
        ),
        lambda transaction, policy, attestation: transaction.close(),
    ),
)
def test_s5a_skipped_or_out_of_order_transition_is_terminal(
    operation: object,
) -> None:
    transaction = authority.D73IngressTransactionV1(_policy())
    with pytest.raises(authority.D73AuthorityRejected):
        operation(transaction, _policy(), _attestation())  # type: ignore[operator]
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.verify_a(_peer(), _owner(_policy()))
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_a_rejects_owner_sender_drift_terminally() -> None:
    transaction = authority.D73IngressTransactionV1(_policy())
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.verify_a(_peer(), _owner(_policy(), unique_sender=":1.24"))
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_a_rejects_peer_uid_that_differs_from_policy_terminally() -> None:
    policy = _policy()
    transaction = authority.D73IngressTransactionV1(policy)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.verify_a(_peer(uid=policy.expected_uid + 1), _owner(policy))
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_a_rejects_peer_selinux_that_differs_from_policy_terminally() -> None:
    policy = _policy()
    transaction = authority.D73IngressTransactionV1(policy)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.verify_a(
            _peer(selinux_context=b"other_u:other_r:other_t:s0"), _owner(policy)
        )
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_second_move_aborts_and_discards_the_first_capability() -> None:
    transaction, policy, attestation = _authorized_transaction()
    capability = _capability(policy, attestation)
    descriptor = capability._fd
    transaction.move_capability(attestation, capability)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.move_capability(attestation, capability)
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_s5a_second_decode_is_terminal() -> None:
    transaction, _policy_value, _attestation_value = _decoded_transaction()
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.decode()
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_abort_discards_a_moved_capability_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction, policy, attestation = _authorized_transaction()
    capability = _capability(policy, attestation)
    descriptor = capability._fd
    original_discard = record._discard_capability
    discarded: list[record.D73Q1Capability] = []

    def tracking_discard(value: object) -> None:
        assert type(value) is record.D73Q1Capability
        discarded.append(value)
        original_discard(value)

    monkeypatch.setattr(record, "_discard_capability", tracking_discard)
    transaction.move_capability(attestation, capability)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.verify_b(_peer(), _owner(policy))
    assert discarded == [capability]
    with pytest.raises(OSError):
        os.fstat(descriptor)
    transaction.abort()
    assert discarded == [capability]


def test_s5a_decode_uses_the_q1_decoder_once_and_the_decoder_closes_the_fd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction, policy, attestation = _authorized_transaction()
    capability = _capability(policy, attestation)
    descriptor = capability._fd
    original_decode = record._decode_capability
    decoded: list[record.D73Q1Capability] = []

    def tracking_decode(value: object) -> record._DecodedRecord:
        assert type(value) is record.D73Q1Capability
        decoded.append(value)
        return original_decode(value)

    monkeypatch.setattr(record, "_decode_capability", tracking_decode)
    transaction.move_capability(attestation, capability)
    transaction.decode()
    assert decoded == [capability]
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_s5a_reentry_is_terminal_and_never_resumes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction, policy, attestation = _authorized_transaction()
    capability = _capability(policy, attestation)
    descriptor = capability._fd
    original_decode = record._decode_capability

    def reentrant_decode(value: object) -> record._DecodedRecord:
        with pytest.raises(authority.D73AuthorityRejected):
            transaction.decode()
        return original_decode(value)

    monkeypatch.setattr(record, "_decode_capability", reentrant_decode)
    transaction.move_capability(attestation, capability)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.decode()
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED
    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.parametrize(
    "field",
    ("expected_uid", "bus_name", "selinux_context", "polkit_action"),
)
def test_s5a_decode_rejects_each_q1_policy_leaf_drift(field: str) -> None:
    transaction, policy, attestation = _authorized_transaction()
    replacements: dict[str, object] = {
        "expected_uid": 2002,
        "bus_name": "org.example.OtherPolicy",
        "selinux_context": "other_u:other_r:other_t:s0",
        "polkit_action": "org.example.d73.other",
    }
    drifting_policy = replace(policy, **{field: replacements[field]})
    transaction.move_capability(attestation, _capability(drifting_policy, attestation))
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.decode()
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("manifest_bytes", b"different"),
        ("manifest_digest", "f" * 64),
        ("commit", "f" * 40),
        ("generation", "different"),
    ),
)
def test_s5a_decode_rejects_each_attestation_binding_drift(
    field: str, value: object
) -> None:
    policy = _policy()
    attestation = _attestation()
    transaction, _unused_policy, held_attestation = _authorized_transaction(
        policy, replace(attestation, **{field: value})
    )
    transaction.move_capability(held_attestation, _capability(policy, attestation))
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.decode()
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


@pytest.mark.parametrize(
    ("stage", "changes"),
    (
        ("b", {"unique_sender": ":1.24"}),
        ("b", {"pid": 4243}),
        ("b", {"uid": 2002}),
        ("b", {"selinux_context": b"other_u:other_r:other_t:s0"}),
        ("c", {"unique_sender": ":1.24"}),
        ("c", {"pid": 4243}),
        ("c", {"uid": 2002}),
        ("c", {"selinux_context": b"other_u:other_r:other_t:s0"}),
    ),
)
def test_s5a_b_and_c_reject_every_peer_drift(
    stage: str, changes: dict[str, object]
) -> None:
    transaction, policy, attestation = _decoded_transaction()
    if stage == "c":
        transaction.verify_b(_peer(), _owner(policy))
    verifier = transaction.verify_b if stage == "b" else transaction.verify_c
    with pytest.raises(authority.D73AuthorityRejected):
        verifier(_peer(**changes), _owner(policy))
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_b_rejects_owner_drift_and_has_no_target_argument() -> None:
    transaction, policy, attestation = _decoded_transaction()
    with pytest.raises(TypeError):
        transaction.verify_b(_peer(), _owner(policy), attestation)  # type: ignore[call-arg]
    assert transaction.state is authority.D73IngressTransactionStateV1.DECODED_BOUND
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.verify_b(_peer(), _owner(policy, unique_sender=":1.24"))
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_transaction_is_not_copyable_serializable_or_resumable() -> None:
    transaction, _policy_value, _attestation_value = _authorized_transaction()
    with pytest.raises(authority.D73AuthorityRejected):
        copy.copy(transaction)
    with pytest.raises(authority.D73AuthorityRejected):
        copy.deepcopy(transaction)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.__reduce_ex__(4)
    transaction.abort()
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.authorize()
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


@pytest.mark.parametrize(
    ("field", "bit"),
    tuple(
        (field, bit)
        for field in ("available_mask", "requested_mask")
        for bit in (
            authority.D73_PEER_PID,
            authority.D73_PEER_UID,
            authority.D73_PEER_SELINUX_CONTEXT,
            authority.D73_PEER_UNIQUE_NAME,
        )
    ),
)
def test_s5a_each_available_and_requested_required_bit_is_individually_required(
    field: str, bit: int
) -> None:
    with pytest.raises(authority.D73AuthorityRejected):
        _peer(**{field: authority.D73_REQUIRED_PEER_MASK ^ bit})


def test_s5a_direct_pidfd_adapter_value_is_positive_and_inert() -> None:
    policy = _policy()
    peer = _peer(has_direct_pidfd=True)
    transaction = authority.D73IngressTransactionV1(policy)
    transaction.verify_a(peer, _owner(policy))
    assert transaction.state is authority.D73IngressTransactionStateV1.A_VERIFIED
    transaction.authorize()
    assert transaction.state is authority.D73IngressTransactionStateV1.AUTHORIZED
    transaction.abort()
    assert peer.has_direct_pidfd is True
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("bus_name", b"org.example.D73Policy"),
        ("bus_name", ""),
        ("bus_name", "x" * 256),
        ("bus_name", "bad\nname"),
        ("unique_sender", b":1.23"),
        ("unique_sender", ""),
        ("unique_sender", "x" * 256),
        ("unique_sender", "bad\nname"),
    ),
)
def test_s5a_owner_adapter_rejects_type_empty_control_and_bound_failures(
    field: str, value: object
) -> None:
    values: dict[str, object] = {"bus_name": BUS_NAME, "unique_sender": ":1.23"}
    values[field] = value
    with pytest.raises(authority.D73AuthorityRejected):
        authority.D73PolicyBusOwnerV1(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("noninteractive", (False, 0, 1, None))
def test_s5a_authorization_rejects_nonpositive_or_nonboolean_values(
    noninteractive: object,
) -> None:
    with pytest.raises(authority.D73AuthorityRejected):
        authority._D73AuthorizationV1(
            POLKIT_ACTION,
            noninteractive,
            _token=authority._AUTHORIZATION_TOKEN,
        )


def test_s5a_reachable_authorized_state_rejects_wrong_capability_type() -> None:
    transaction, _policy_value, _attestation_value = _authorized_transaction()
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.move_capability(_attestation(), object())
    assert transaction._capability is None
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_decoder_wrong_type_aborts_after_the_q1_decoder_closed_the_fd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction, policy, attestation = _authorized_transaction()
    capability = _capability(policy, attestation)
    descriptor = capability._fd
    original_decode = record._decode_capability

    def decode_then_return_wrong_type(value: object) -> object:
        original_decode(value)
        return object()

    monkeypatch.setattr(record, "_decode_capability", decode_then_return_wrong_type)
    transaction.move_capability(attestation, capability)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.decode()
    assert transaction._capability is None
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_s5a_decoder_exception_aborts_after_the_q1_decoder_closed_the_fd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction, policy, attestation = _authorized_transaction()
    capability = _capability(policy, attestation)
    descriptor = capability._fd
    original_decode = record._decode_capability

    def decode_then_raise(value: object) -> record._DecodedRecord:
        original_decode(value)
        raise RuntimeError("synthetic decoder failure")

    monkeypatch.setattr(record, "_decode_capability", decode_then_raise)
    transaction.move_capability(attestation, capability)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.decode()
    assert transaction._capability is None
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED
    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.parametrize("stage", ("b", "c"))
@pytest.mark.parametrize("kind", ("owner_sender", "owner_bus"))
def test_s5a_b_and_c_reject_owner_drift(
    stage: str, kind: str
) -> None:
    transaction, policy, _attestation_value = _decoded_transaction()
    if stage == "c":
        transaction.verify_b(_peer(), _owner(policy))
    owner = _owner(policy)
    if kind == "owner_sender":
        owner = _owner(policy, unique_sender=":1.24")
    else:
        owner = _owner(policy, bus_name="org.example.OtherPolicy")
    verifier = transaction.verify_b if stage == "b" else transaction.verify_c
    with pytest.raises(authority.D73AuthorityRejected):
        verifier(_peer(), owner)
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


@pytest.mark.parametrize("stage", ("b", "c"))
def test_d359_b_and_c_revalidate_without_caller_attestation(stage: str) -> None:
    transaction, policy, _attestation_value = _decoded_transaction()
    if stage == "c":
        transaction.verify_b(_peer(), _owner(policy))
        transaction.verify_c(_peer(), _owner(policy))
        assert transaction.state is authority.D73IngressTransactionStateV1.C_VERIFIED
    else:
        transaction.verify_b(_peer(), _owner(policy))
        assert transaction.state is authority.D73IngressTransactionStateV1.B_VERIFIED


@pytest.mark.parametrize(
    ("state", "operation"),
    (
        (
            authority.D73IngressTransactionStateV1.A_VERIFIED,
            lambda transaction, policy, attestation: transaction.verify_a(
                _peer(), _owner(policy)
            ),
        ),
        (
            authority.D73IngressTransactionStateV1.AUTHORIZED,
            lambda transaction, policy, attestation: transaction.authorize(),
        ),
        (
            authority.D73IngressTransactionStateV1.CAPABILITY_MOVED,
            lambda transaction, policy, attestation: transaction.move_capability(
                attestation, object()
            ),
        ),
        (
            authority.D73IngressTransactionStateV1.DECODED_BOUND,
            lambda transaction, policy, attestation: transaction.decode(),
        ),
        (
            authority.D73IngressTransactionStateV1.B_VERIFIED,
            lambda transaction, policy, attestation: transaction.verify_b(
                _peer(), _owner(policy)
            ),
        ),
        (
            authority.D73IngressTransactionStateV1.C_VERIFIED,
            lambda transaction, policy, attestation: transaction.verify_c(
                _peer(), _owner(policy)
            ),
        ),
        (
            authority.D73IngressTransactionStateV1.CLOSED,
            lambda transaction, policy, attestation: transaction.close(),
        ),
    ),
)
def test_s5a_repeated_expected_transition_is_terminal(
    state: authority.D73IngressTransactionStateV1, operation: object
) -> None:
    transaction, policy, attestation = _transaction_at(state)
    with pytest.raises(authority.D73AuthorityRejected):
        operation(transaction, policy, attestation)  # type: ignore[operator]
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


@pytest.mark.parametrize(
    ("state", "operation"),
    (
        (
            authority.D73IngressTransactionStateV1.A_VERIFIED,
            lambda transaction, policy, attestation: transaction.decode(),
        ),
        (
            authority.D73IngressTransactionStateV1.AUTHORIZED,
            lambda transaction, policy, attestation: transaction.verify_c(
                _peer(), _owner(policy)
            ),
        ),
        (
            authority.D73IngressTransactionStateV1.CAPABILITY_MOVED,
            lambda transaction, policy, attestation: transaction.close(),
        ),
        (
            authority.D73IngressTransactionStateV1.DECODED_BOUND,
            lambda transaction, policy, attestation: transaction.authorize(),
        ),
        (
            authority.D73IngressTransactionStateV1.B_VERIFIED,
            lambda transaction, policy, attestation: transaction.move_capability(
                attestation, object()
            ),
        ),
        (
            authority.D73IngressTransactionStateV1.C_VERIFIED,
            lambda transaction, policy, attestation: transaction.verify_a(
                _peer(), _owner(policy)
            ),
        ),
    ),
)
def test_s5a_unexpected_transition_from_each_live_intermediate_state_is_terminal(
    state: authority.D73IngressTransactionStateV1, operation: object
) -> None:
    transaction, policy, attestation = _transaction_at(state)
    with pytest.raises(authority.D73AuthorityRejected):
        operation(transaction, policy, attestation)  # type: ignore[operator]
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


@pytest.mark.parametrize(
    "state",
    (
        authority.D73IngressTransactionStateV1.NEW,
        authority.D73IngressTransactionStateV1.A_VERIFIED,
        authority.D73IngressTransactionStateV1.AUTHORIZED,
        authority.D73IngressTransactionStateV1.CAPABILITY_MOVED,
        authority.D73IngressTransactionStateV1.DECODED_BOUND,
        authority.D73IngressTransactionStateV1.B_VERIFIED,
        authority.D73IngressTransactionStateV1.C_VERIFIED,
    ),
)
def test_s5a_abort_from_each_live_state_is_terminal(
    state: authority.D73IngressTransactionStateV1,
) -> None:
    transaction, _policy_value, _attestation_value = _transaction_at(state)
    transaction.abort()
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_abort_from_closed_rejects_and_is_terminal() -> None:
    transaction, _policy_value, _attestation_value = _transaction_at(
        authority.D73IngressTransactionStateV1.CLOSED
    )
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.abort()
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_discard_exception_is_terminal_and_attempts_discard_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction, policy, attestation = _authorized_transaction()
    capability = _capability(policy, attestation)
    discarded: list[object] = []

    def discard_then_raise(value: object) -> None:
        discarded.append(value)
        raise OSError("synthetic discard failure before close")

    monkeypatch.setattr(record, "_discard_capability", discard_then_raise)
    transaction.move_capability(attestation, capability)
    transaction.abort()
    assert discarded == [capability]
    assert transaction._capability is None
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_peer_and_decoded_record_are_held_through_c_and_cleared_on_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    attestation = _attestation()
    peer = _peer()
    transaction = authority.D73IngressTransactionV1(policy)
    transaction.verify_a(peer, _owner(policy))
    transaction.authorize()
    original_decode = record._decode_capability
    decoded: list[record._DecodedRecord] = []

    def tracking_decode(value: object) -> record._DecodedRecord:
        result = original_decode(value)
        decoded.append(result)
        return result

    monkeypatch.setattr(record, "_decode_capability", tracking_decode)
    transaction.move_capability(attestation, _capability(policy, attestation))
    transaction.decode()
    assert transaction._peer is peer
    assert transaction._decoded_record is decoded[0]
    transaction.verify_b(peer, _owner(policy))
    transaction.verify_c(peer, _owner(policy))
    assert transaction._peer is peer
    assert transaction._decoded_record is decoded[0]
    transaction.close()
    assert transaction._attestation is None
    assert transaction._peer is None
    assert transaction._decoded_record is None


def test_s5a_peer_and_decoded_record_are_cleared_on_abort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    attestation = _attestation()
    peer = _peer()
    transaction = authority.D73IngressTransactionV1(policy)
    transaction.verify_a(peer, _owner(policy))
    transaction.authorize()
    original_decode = record._decode_capability
    decoded: list[record._DecodedRecord] = []

    def tracking_decode(value: object) -> record._DecodedRecord:
        result = original_decode(value)
        decoded.append(result)
        return result

    monkeypatch.setattr(record, "_decode_capability", tracking_decode)
    transaction.move_capability(attestation, _capability(policy, attestation))
    transaction.decode()
    assert transaction._peer is peer
    assert transaction._decoded_record is decoded[0]
    transaction.abort()
    assert transaction._attestation is None
    assert transaction._peer is None
    assert transaction._decoded_record is None
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_s5a_peer_is_cleared_when_a_verified_transaction_aborts() -> None:
    policy = _policy()
    peer = _peer()
    transaction = authority.D73IngressTransactionV1(policy)
    transaction.verify_a(peer, _owner(policy))
    assert transaction._peer is peer
    transaction.abort()
    assert transaction._peer is None
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


@pytest.mark.parametrize(
    "operation",
    (copy.copy, copy.deepcopy, lambda transaction: transaction.__reduce_ex__(4)),
)
def test_s5a_copy_operations_after_move_abort_and_discard_the_capability(
    operation: object,
) -> None:
    transaction, policy, attestation = _authorized_transaction()
    capability = _capability(policy, attestation)
    descriptor = capability._fd
    transaction.move_capability(attestation, capability)
    with pytest.raises(authority.D73AuthorityRejected):
        operation(transaction)  # type: ignore[operator]
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_s5a_negative_q1_leaf_binding_closes_the_capability_fd() -> None:
    transaction, policy, attestation = _authorized_transaction()
    capability = _capability(
        replace(policy, expected_uid=policy.expected_uid + 1), attestation
    )
    descriptor = capability._fd
    transaction.move_capability(attestation, capability)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.decode()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_s5a_negative_q1_manifest_binding_closes_the_capability_fd() -> None:
    policy = _policy()
    attestation = _attestation()
    transaction, _unused_policy, held_attestation = _authorized_transaction(
        policy, replace(attestation, manifest_digest="f" * 64)
    )
    capability = _capability(policy, attestation)
    descriptor = capability._fd
    transaction.move_capability(held_attestation, capability)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.decode()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_s5a_rejected_transition_uses_the_fixed_external_error_contract() -> None:
    transaction = authority.D73IngressTransactionV1(_policy())
    with pytest.raises(authority.D73AuthorityRejected) as caught:
        transaction.authorize()
    assert caught.value.error_name == authority.D73_AUTHORITY_REJECTED_ERROR_NAME
    assert str(caught.value) == authority.D73_AUTHORITY_REJECTED_ERROR_TEXT
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED


def test_d359_constructor_binds_only_policy_before_gate_a() -> None:
    transaction = authority.D73IngressTransactionV1(_policy())
    assert transaction.state is authority.D73IngressTransactionStateV1.NEW
    assert transaction._attestation is None
    assert transaction._capability is None


def test_d359_attestation_is_absent_through_authorization() -> None:
    policy = _policy()
    transaction = authority.D73IngressTransactionV1(policy)
    transaction.verify_a(_peer(), _owner(policy))
    assert transaction._attestation is None
    transaction.authorize()
    assert transaction._attestation is None
    assert transaction._capability is None


def test_d359_capability_before_authorization_is_discarded() -> None:
    policy = _policy()
    attestation = _attestation()
    capability = _capability(policy, attestation)
    descriptor = capability._fd
    transaction = authority.D73IngressTransactionV1(policy)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.move_capability(attestation, capability)
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_d359_move_binds_exact_attestation_and_discards_on_invalid_handoff() -> None:
    policy = _policy()
    attestation = _attestation()
    transaction = authority.D73IngressTransactionV1(policy)
    transaction.verify_a(_peer(), _owner(policy))
    transaction.authorize()
    capability = _capability(policy, attestation)
    descriptor = capability._fd
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.move_capability(object(), capability)
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED
    assert transaction._attestation is None
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_d359_decode_uses_the_attestation_held_by_move() -> None:
    policy = _policy()
    attestation = _attestation()
    transaction = authority.D73IngressTransactionV1(policy)
    peer = _peer()
    transaction.verify_a(peer, _owner(policy))
    transaction.authorize()
    transaction.move_capability(attestation, _capability(policy, attestation))
    assert transaction._attestation is attestation
    transaction.decode()
    transaction.verify_b(peer, _owner(policy))
    transaction.verify_c(peer, _owner(policy))
    assert transaction.state is authority.D73IngressTransactionStateV1.C_VERIFIED


def test_d359_second_move_discards_the_new_capability_and_clears_attestation() -> None:
    policy = _policy()
    attestation = _attestation()
    transaction = authority.D73IngressTransactionV1(policy)
    transaction.verify_a(_peer(), _owner(policy))
    transaction.authorize()
    first = _capability(policy, attestation)
    second_attestation = _attestation()
    second = _capability(policy, attestation)
    first_descriptor = first._fd
    second_descriptor = second._fd
    transaction.move_capability(attestation, first)
    with pytest.raises(authority.D73AuthorityRejected):
        transaction.move_capability(second_attestation, second)
    assert transaction.state is authority.D73IngressTransactionStateV1.ABORTED
    assert transaction._attestation is None
    with pytest.raises(OSError):
        os.fstat(first_descriptor)
    with pytest.raises(OSError):
        os.fstat(second_descriptor)


def test_d359_terminal_transitions_clear_the_held_attestation() -> None:
    policy = _policy()
    attestation = _attestation()
    transaction = authority.D73IngressTransactionV1(policy)
    transaction.verify_a(_peer(), _owner(policy))
    transaction.authorize()
    transaction.move_capability(attestation, _capability(policy, attestation))
    transaction.abort()
    assert transaction._attestation is None

    closed = authority.D73IngressTransactionV1(policy)
    closed.verify_a(_peer(), _owner(policy))
    closed.authorize()
    closed.move_capability(attestation, _capability(policy, attestation))
    closed.decode()
    closed.verify_b(_peer(), _owner(policy))
    closed.verify_c(_peer(), _owner(policy))
    closed.close()
    assert closed._attestation is None
