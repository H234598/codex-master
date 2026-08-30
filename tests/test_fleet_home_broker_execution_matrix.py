"""Handwritten, operation-aware checkpoint/action matrix for the one executor."""

import pytest

from codex_master.fleet_home_broker_protocol import (
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRecoveryAction,
    BrokerRegistryState,
    BrokerResultCode,
    ChpbTransactionOperation,
    PolicyBinding,
    PrincipalBinding,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
    decide_broker_recovery,
    is_checkpoint_transition_allowed,
    validate_transaction_status,
)


_PRINCIPAL = PrincipalBinding("bee_1", 3, 9, 0, 1, "1" * 32, "c0,c1", 4)
_POLICY = PolicyBinding(7, "a" * 64)


def _observation(
    obj: BrokerObjectState, reg: BrokerRegistryState, index: int = 0
) -> BrokerObservation:
    return BrokerObservation(obj, reg, index)


def _status(
    operation: ChpbTransactionOperation,
    checkpoint: BrokerCheckpoint,
    observation: BrokerObservation,
) -> TransactionStatus:
    terminal = {
        BrokerCheckpoint.COMMITTED: BrokerResultCode.COMMITTED,
        BrokerCheckpoint.DEPROVISIONED: BrokerResultCode.COMMITTED,
        BrokerCheckpoint.ROLLED_BACK: BrokerResultCode.ROLLED_BACK,
        BrokerCheckpoint.BLOCKED_DRIFT: BrokerResultCode.BLOCKED_DRIFT,
    }.get(checkpoint)
    return TransactionStatus(
        TransactionBinding(operation, "2" * 32, "3" * 32, _PRINCIPAL, _POLICY),
        b2a_phase_for_checkpoint(checkpoint),
        checkpoint,
        observation,
        1,
        terminal,
    )


# Every normal action is a literal test vector, not a projection of production
# dispatch data: (operation, durable checkpoint, attested observation, action,
# next durable checkpoint).
ROWS = (
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.CREATE_INTENT,
        _observation(BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE),
        BrokerRecoveryAction.CREATE_STAGING,
        None,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.CREATE_INTENT,
        _observation(
            BrokerObjectState.STAGING_EMPTY, BrokerRegistryState.NOT_APPLICABLE
        ),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.STAGING_PINNED,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.STAGING_PINNED,
        _observation(
            BrokerObjectState.STAGING_EMPTY, BrokerRegistryState.NOT_APPLICABLE
        ),
        BrokerRecoveryAction.POPULATE_NEXT,
        None,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.STAGING_PINNED,
        _observation(
            BrokerObjectState.STAGING_PREFIX, BrokerRegistryState.NOT_APPLICABLE, 1
        ),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.POPULATE_PENDING,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.POPULATE_PENDING,
        _observation(
            BrokerObjectState.STAGING_PREFIX, BrokerRegistryState.NOT_APPLICABLE, 0
        ),
        BrokerRecoveryAction.POPULATE_NEXT,
        None,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.POPULATE_PENDING,
        _observation(
            BrokerObjectState.STAGING_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1
        ),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.PUBLISH_INTENT,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.PUBLISH_INTENT,
        _observation(
            BrokerObjectState.STAGING_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1
        ),
        BrokerRecoveryAction.PUBLISH_HOME,
        None,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.PUBLISH_INTENT,
        _observation(
            BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.NOT_APPLICABLE, 1
        ),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.PUBLISHED,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.PUBLISHED,
        _observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.OLD, 1),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
    ),
    (
        ChpbTransactionOperation.REPLACE,
        BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
        _observation(
            BrokerObjectState.REPLACEMENT_ORIGINAL, BrokerRegistryState.NOT_APPLICABLE
        ),
        BrokerRecoveryAction.PREPARE_REPLACEMENT,
        None,
    ),
    (
        ChpbTransactionOperation.REPLACE,
        BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
        _observation(
            BrokerObjectState.REPLACEMENT_PREPARED, BrokerRegistryState.NOT_APPLICABLE
        ),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.REPLACEMENT_PREPARED,
    ),
    (
        ChpbTransactionOperation.REPLACE,
        BrokerCheckpoint.REPLACEMENT_PREPARED,
        _observation(
            BrokerObjectState.REPLACEMENT_PREPARED, BrokerRegistryState.NOT_APPLICABLE
        ),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.SWITCH_INTENT,
    ),
    (
        ChpbTransactionOperation.REPLACE,
        BrokerCheckpoint.SWITCH_INTENT,
        _observation(
            BrokerObjectState.REPLACEMENT_PREPARED, BrokerRegistryState.NOT_APPLICABLE
        ),
        BrokerRecoveryAction.SWITCH_REPLACEMENT,
        None,
    ),
    (
        ChpbTransactionOperation.REPLACE,
        BrokerCheckpoint.SWITCH_INTENT,
        _observation(
            BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.NOT_APPLICABLE
        ),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.SWITCHED,
    ),
    (
        ChpbTransactionOperation.REPLACE,
        BrokerCheckpoint.SWITCHED,
        _observation(BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.OLD),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        _observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.OLD, 1),
        BrokerRecoveryAction.CAS_REGISTRY,
        None,
    ),
    (
        ChpbTransactionOperation.REPLACE,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        _observation(BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.OLD),
        BrokerRecoveryAction.CAS_REGISTRY,
        None,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        _observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.FINALIZE_INTENT,
    ),
    (
        ChpbTransactionOperation.REPLACE,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        _observation(
            BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.CURRENT
        ),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.FINALIZE_INTENT,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.FINALIZE_INTENT,
        _observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.COMMITTED,
    ),
    (
        ChpbTransactionOperation.REPLACE,
        BrokerCheckpoint.FINALIZE_INTENT,
        _observation(
            BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.CURRENT
        ),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.COMMITTED,
    ),
    (
        ChpbTransactionOperation.DEPROVISION,
        BrokerCheckpoint.DEPROVISION_INTENT,
        _observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
    ),
    (
        ChpbTransactionOperation.DEPROVISION,
        BrokerCheckpoint.DEPROVISION_INTENT,
        _observation(BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.DEPROVISIONED,
    ),
    (
        ChpbTransactionOperation.DEPROVISION,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        _observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT),
        BrokerRecoveryAction.CAS_REGISTRY,
        None,
    ),
    (
        ChpbTransactionOperation.DEPROVISION,
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        _observation(
            BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.NOT_APPLICABLE
        ),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.FINALIZE_INTENT,
    ),
    (
        ChpbTransactionOperation.DEPROVISION,
        BrokerCheckpoint.FINALIZE_INTENT,
        _observation(
            BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.NOT_APPLICABLE
        ),
        BrokerRecoveryAction.DEPROVISION_HOME,
        None,
    ),
    (
        ChpbTransactionOperation.DEPROVISION,
        BrokerCheckpoint.FINALIZE_INTENT,
        _observation(BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE),
        BrokerRecoveryAction.PERSIST_CHECKPOINT,
        BrokerCheckpoint.DEPROVISIONED,
    ),
    (
        ChpbTransactionOperation.PROVISION,
        BrokerCheckpoint.COMMITTED,
        _observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1),
        BrokerRecoveryAction.RETURN_COMMITTED,
        BrokerCheckpoint.COMMITTED,
    ),
    (
        ChpbTransactionOperation.REPLACE,
        BrokerCheckpoint.COMMITTED,
        _observation(
            BrokerObjectState.REPLACEMENT_SWITCHED, BrokerRegistryState.CURRENT
        ),
        BrokerRecoveryAction.RETURN_COMMITTED,
        BrokerCheckpoint.COMMITTED,
    ),
    (
        ChpbTransactionOperation.DEPROVISION,
        BrokerCheckpoint.DEPROVISIONED,
        _observation(BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE),
        BrokerRecoveryAction.RETURN_COMMITTED,
        BrokerCheckpoint.DEPROVISIONED,
    ),
)


@pytest.mark.parametrize("operation,checkpoint,observation,action,target", ROWS)
def test_every_handwritten_canonical_action_row(
    operation: ChpbTransactionOperation,
    checkpoint: BrokerCheckpoint,
    observation: BrokerObservation,
    action: BrokerRecoveryAction,
    target: BrokerCheckpoint | None,
) -> None:
    decision = decide_broker_recovery(
        _status(operation, checkpoint, observation), observation
    )
    assert decision.action is action
    assert decision.next_checkpoint is target


OPERATION_EDGES = {
    ChpbTransactionOperation.PROVISION: {
        BrokerCheckpoint.CREATE_INTENT: {
            BrokerCheckpoint.STAGING_PINNED,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.STAGING_PINNED: {
            BrokerCheckpoint.POPULATE_PENDING,
            BrokerCheckpoint.ROLLBACK_INTENT,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.POPULATE_PENDING: {
            BrokerCheckpoint.POPULATE_PENDING,
            BrokerCheckpoint.PUBLISH_INTENT,
            BrokerCheckpoint.ROLLBACK_INTENT,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.PUBLISH_INTENT: {
            BrokerCheckpoint.PUBLISHED,
            BrokerCheckpoint.ROLLBACK_INTENT,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.PUBLISHED: {
            BrokerCheckpoint.REGISTRY_CAS_INTENT,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.REGISTRY_CAS_INTENT: {
            BrokerCheckpoint.FINALIZE_INTENT,
            BrokerCheckpoint.ROLLBACK_INTENT,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.FINALIZE_INTENT: {
            BrokerCheckpoint.COMMITTED,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.ROLLBACK_INTENT: {
            BrokerCheckpoint.ROLLED_BACK,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.COMMITTED: {BrokerCheckpoint.COMMITTED},
        BrokerCheckpoint.ROLLED_BACK: {BrokerCheckpoint.ROLLED_BACK},
        BrokerCheckpoint.BLOCKED_DRIFT: {BrokerCheckpoint.BLOCKED_DRIFT},
    },
    ChpbTransactionOperation.REPLACE: {
        BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT: {
            BrokerCheckpoint.REPLACEMENT_PREPARED,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.REPLACEMENT_PREPARED: {
            BrokerCheckpoint.SWITCH_INTENT,
            BrokerCheckpoint.ROLLBACK_INTENT,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.SWITCH_INTENT: {
            BrokerCheckpoint.SWITCHED,
            BrokerCheckpoint.ROLLBACK_INTENT,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.SWITCHED: {
            BrokerCheckpoint.REGISTRY_CAS_INTENT,
            BrokerCheckpoint.ROLLBACK_INTENT,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.REGISTRY_CAS_INTENT: {
            BrokerCheckpoint.FINALIZE_INTENT,
            BrokerCheckpoint.ROLLBACK_INTENT,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.FINALIZE_INTENT: {
            BrokerCheckpoint.COMMITTED,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.ROLLBACK_INTENT: {
            BrokerCheckpoint.ROLLED_BACK,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.COMMITTED: {BrokerCheckpoint.COMMITTED},
        BrokerCheckpoint.ROLLED_BACK: {BrokerCheckpoint.ROLLED_BACK},
        BrokerCheckpoint.BLOCKED_DRIFT: {BrokerCheckpoint.BLOCKED_DRIFT},
    },
    ChpbTransactionOperation.DEPROVISION: {
        BrokerCheckpoint.DEPROVISION_INTENT: {
            BrokerCheckpoint.REGISTRY_CAS_INTENT,
            BrokerCheckpoint.DEPROVISIONED,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.REGISTRY_CAS_INTENT: {
            BrokerCheckpoint.FINALIZE_INTENT,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.FINALIZE_INTENT: {
            BrokerCheckpoint.DEPROVISIONED,
            BrokerCheckpoint.BLOCKED_DRIFT,
        },
        BrokerCheckpoint.DEPROVISIONED: {BrokerCheckpoint.DEPROVISIONED},
        BrokerCheckpoint.BLOCKED_DRIFT: {BrokerCheckpoint.BLOCKED_DRIFT},
    },
}


def test_operation_checkpoint_edges_are_exact_and_no_shortcut_is_allowed() -> None:
    for operation, edges in OPERATION_EDGES.items():
        for source, expected in edges.items():
            actual = {
                target
                for target in BrokerCheckpoint
                if is_checkpoint_transition_allowed(source, target)
                and _valid_checkpoint(operation, target)
            }
            assert actual == expected
    assert not is_checkpoint_transition_allowed(
        BrokerCheckpoint.DEPROVISION_INTENT, BrokerCheckpoint.FINALIZE_INTENT
    )
    assert not is_checkpoint_transition_allowed(
        BrokerCheckpoint.REGISTRY_CAS_INTENT, BrokerCheckpoint.DEPROVISIONED
    )


def _valid_checkpoint(
    operation: ChpbTransactionOperation, checkpoint: BrokerCheckpoint
) -> bool:
    try:
        validate_transaction_status(
            _status(
                operation,
                checkpoint,
                _observation(
                    BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE
                ),
            )
        )
    except Exception:
        return False
    return True


@pytest.mark.parametrize(
    "checkpoint,observation",
    (
        (
            BrokerCheckpoint.DEPROVISION_INTENT,
            _observation(
                BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.NOT_APPLICABLE
            ),
        ),
        (
            BrokerCheckpoint.REGISTRY_CAS_INTENT,
            _observation(BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE),
        ),
        (
            BrokerCheckpoint.FINALIZE_INTENT,
            _observation(BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT),
        ),
    ),
)
def test_unlisted_deprovision_observation_rows_are_blocked(
    checkpoint: BrokerCheckpoint, observation: BrokerObservation
) -> None:
    assert (
        decide_broker_recovery(
            _status(ChpbTransactionOperation.DEPROVISION, checkpoint, observation),
            observation,
        ).action
        is BrokerRecoveryAction.RETURN_BLOCKED
    )
